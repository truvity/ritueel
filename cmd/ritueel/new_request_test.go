//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

// The commands "ritueel new" and "ritueel check request", run as the program that the release builds: the exit
// code, standard output and standard error, with a folder of the process that is not the folder of the test. The
// default folder of check request is the current one, so these runs set the folder of the process. The clock is
// the real one here, so the requests that these runs use are refused or accepted by rules that do not read a time.

func runProgramIn(t *testing.T, exe, workDir string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), exe, args...)
	cmd.Dir = workDir
	var out, errOut bytes.Buffer
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
	default:
		t.Fatalf("running the program: %v", err)
	}
	return code, out.String(), errOut.String()
}

func vectorFile(t *testing.T, rel ...string) string {
	t.Helper()
	return string(testrepo.Read(t, append([]string{"testdata"}, rel...)...))
}

func TestProgramNewAndCheckRequest(t *testing.T) {
	exe := buildForCheck(t)

	// A bundle that new makes in the working folder, under a relative name.
	parent := t.TempDir()
	code, stdout, stderr := runProgramIn(t, exe, parent, "new", "--test-root", "acme")
	if code != 0 || stderr != "" || !strings.HasPrefix(stdout, "made the bundle acme\n") || !strings.HasSuffix(stdout, "this is a test bundle: its roots are marked TEST ONLY\n") {
		t.Fatalf("new: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	dir := filepath.Join(parent, "acme")
	for _, p := range []string{"ritueel.yaml", "want/roots/x509.yaml", "want/roots/openpgp.yaml"} {
		if info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(p))); err != nil || !info.Mode().IsRegular() {
			t.Errorf("new did not make %s: %v", p, err)
		}
	}

	// The same name again: nothing is written into what is there.
	code, stdout, stderr = runProgramIn(t, exe, parent, "new", "--test-root", "acme")
	if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "ritueel: ") {
		t.Errorf("new again: exit %d, stdout %q, stderr %q; want 1 and one line of error", code, stdout, stderr)
	}

	// The working folder holds the manifest, and no trust set yet.
	code, stdout, stderr = runProgramIn(t, exe, dir, "check", "request", "x509-csr-bad-signature")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "no trust set") {
		t.Errorf("no trust set: exit %d, stdout %q, stderr %q; want 1 and the words no trust set", code, stdout, stderr)
	}

	// A trust set, a delegation and a request of the vectors: a request whose signature is wrong is refused
	// with the code, in both output modes, and the working folder is the one that was read.
	putFile(t, dir, "trust/7-3fa9c1d2/root-list.json", vectorFile(t, "root-list", "v1", "lists", "seq7-a.json"))
	putFile(t, dir, "trust/7-3fa9c1d2/root-list.jws", vectorFile(t, "root-list", "v1", "lists", "seq7-a.jws"))
	putFile(t, dir, "trust/7-3fa9c1d2/ca-bundle.pem", vectorFile(t, "root-list", "v1", "bundles", "ca-bundle-7.pem"))
	// The list pins two OpenPGP primaries, so the trust set holds the keyring file of both, in the order of the list.
	putFile(t, dir, "trust/7-3fa9c1d2/keyring.gpg", vectorFile(t, "root-list", "v1", "pki", "test-primary-a.pgp")+vectorFile(t, "root-list", "v1", "pki", "test-primary-b.pgp"))
	putFile(t, dir, "want/delegations/example-intermediate.yaml", "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_uri_hosts: [example.org, \".example.org\"]\npermitted_dns_names: [example.org]\n")
	for _, ext := range []string{"csr.pem", "proof.json"} {
		putFile(t, dir, "requests/x509-csr-bad-signature/x509-csr-bad-signature."+ext, vectorFile(t, "hand-off", "v1", "requests", "x509-csr-bad-signature."+ext))
	}
	const trustSetWarning = "ritueel: warning: trust-set-unchecked: this command did not check the signature and the expiry of the trust set that the roots and the OpenPGP primaries were read from\n"
	code, stdout, stderr = runProgramIn(t, exe, dir, "check", "request", "x509-csr-bad-signature", "--delegation", "example-intermediate")
	if code != 3 || !strings.HasSuffix(stdout, "request x509-csr-bad-signature: refused: possession-invalid\n") || !strings.HasPrefix(stderr, trustSetWarning+"ritueel: refused: possession-invalid (check 5: ") {
		t.Errorf("a bad signature: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout2, stderr2 := runProgramIn(t, exe, dir, "check", "request", "x509-csr-bad-signature", "--delegation", "example-intermediate", "--output", "json")
	if code != 3 || stderr2 != stderr {
		t.Errorf("a bad signature as JSON: exit %d, stderr %q, want the same line %q", code, stderr2, stderr)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(stdout2), &obj); err != nil || strings.Count(stdout2, "\n") != 1 {
		t.Fatalf("standard output is not one JSON object: %v: %q", err, stdout2)
	}
	if obj["command"] != "check" || obj["outcome"] != "refused" || obj["exit_code"] != float64(3) {
		t.Errorf("object = %#v", obj)
	}
	if checks, _ := obj["checks"].([]any); len(checks) != 9 {
		t.Errorf("checks = %#v, want nine", obj["checks"])
	}
	if w, _ := obj["warnings"].([]any); len(w) != 1 || w[0] != strings.TrimSuffix(strings.TrimPrefix(trustSetWarning, "ritueel: warning: "), "\n") {
		t.Errorf("warnings = %#v, want the one warning about the trust set", obj["warnings"])
	}

	// The same request in another working folder with no --dir: a usage error that names the flag.
	code, stdout, stderr = runProgramIn(t, exe, parent, "check", "request", "x509-csr-bad-signature")
	if code != 2 || stdout != "" || !strings.Contains(stderr, "--dir") {
		t.Errorf("no manifest here: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	// A software request that is valid is accepted with a delegation and is not complete without one.
	for _, ext := range []string{"csr.pem", "proof.json"} {
		putFile(t, dir, "requests/x509-software-valid/x509-software-valid."+ext, vectorFile(t, "hand-off", "v1", "requests", "x509-software-valid."+ext))
	}
	code, stdout, stderr = runProgramIn(t, exe, dir, "check", "request", "x509-software-valid", "--delegation", "example-intermediate")
	if code != 0 || stderr != trustSetWarning || !strings.HasSuffix(stdout, "request x509-software-valid: accepted\n") {
		t.Errorf("a valid request: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, stderr = runProgramIn(t, exe, dir, "check", "request", "x509-software-valid")
	const noDelegation = "request x509-software-valid: not complete: check 9 needs a delegation; give --delegation NAME\n"
	if code != 1 || !strings.HasSuffix(stdout, noDelegation) || strings.Contains(stdout, "accepted") ||
		!strings.HasPrefix(stderr, "ritueel: warning: check 9: rules not run:") ||
		!strings.HasSuffix(stderr, trustSetWarning+"ritueel: request x509-software-valid is not accepted and not refused: check 9 needs a delegation; give --delegation NAME\n") ||
		strings.Count(stderr, "trust-set-unchecked") != 1 {
		t.Errorf("no delegation: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	code, stdout, _ = runProgramIn(t, exe, dir, "check", "request", "x509-software-valid", "--output", "json")
	var obj2 map[string]any
	if err := json.Unmarshal([]byte(stdout), &obj2); err != nil || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("standard output is not one JSON object: %v: %q", err, stdout)
	}
	if code != 1 || obj2["outcome"] != "failed" || obj2["exit_code"] != float64(1) || obj2["error"] == nil {
		t.Errorf("no delegation as JSON: exit %d, object %#v", code, obj2)
	}
	if checks, _ := obj2["checks"].([]any); len(checks) != 9 {
		t.Errorf("checks = %#v, want nine", obj2["checks"])
	}

	// A trust set whose list pins primaries and that holds no keyring file stops the program with one sentence, for
	// a request of any type that is run with no delegation: nothing is accepted and nothing is refused.
	if err := os.Remove(filepath.Join(dir, "trust", "7-3fa9c1d2", "keyring.gpg")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runProgramIn(t, exe, dir, "check", "request", "x509-software-valid")
	const noKeyring = "ritueel: request x509-software-valid is not accepted and not refused: the newest trust set 7-3fa9c1d2 pins OpenPGP primaries and holds no keyring.gpg\n"
	if code != 1 || stdout != "" || stderr != noKeyring {
		t.Errorf("no keyring file: exit %d, stdout %q, stderr %q, want exit 1 and %q", code, stdout, stderr, noKeyring)
	}
	// A request under a delegation of the type x509-intermediate does not read the keyring file at all.
	code, _, _ = runProgramIn(t, exe, dir, "check", "request", "x509-software-valid", "--delegation", "example-intermediate")
	if code != 0 {
		t.Errorf("no keyring file, x509 delegation: exit %d, want 0", code)
	}
}
