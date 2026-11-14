package verifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jsonset"
)

// gpgvStatusPrefix starts every line that gpgv writes to the status descriptor.
const gpgvStatusPrefix = "[GNUPG:] "

// GPGVVerify runs `gpgv --status-fd 1 --keyring KEYRING SIG DATA` and returns nil when gpgv reports
// a good signature by a key of the certificate that is meant, which is neither revoked nor expired,
// and an error with its output when it does not. keyring is a file of OpenPGP packets
// (certificates one after the other, binary), sig is a detached signature (binary or armoured),
// data is the signed data, and fingerprint is the version 4 fingerprint of the primary key of the
// certificate that is meant: 40 lower-case hexadecimal digits. The test is skipped, or fails, when
// gpgv is missing (see [Require]).
//
// The verdict is read from the status lines, never from the exit status: the exit status of the
// GnuPG family is not a trust decision (record 0009, rule 20). It is an acceptance when the status
// has GOODSIG and exactly one VALIDSIG, that line names the primary key of the certificate that is
// meant as the key that the signing key belongs to (its last field: the signing key is a subkey of
// that certificate, or is that primary itself), none of REVKEYSIG, EXPKEYSIG, EXPSIG, BADSIG,
// ERRSIG, NO_PUBKEY or ERROR is there, and the exit status is 0. A signature by a key of another
// certificate of the same keyring is refused.
//
// What an acceptance proves, by a tool that did not build the packets: gpgv reads the certificate
// as a relying party does (the self-signature, the user ID, the key expiry, the subkey binding and
// its back-signature), the signature verifies with the signing key, and the key is valid at the
// present time. gpgv has no option for another time. It runs with no agent, no socket and no home
// folder of the user: it is given a folder of its own to use as its home, made in the test's
// temporary folder.
func GPGVVerify(t testing.TB, keyring, sig, data []byte, fingerprint string) error {
	t.Helper()
	if err := checkFingerprint(fingerprint); err != nil {
		return err
	}
	status, out, exit := gpgv(t, keyring, sig, data)
	have := map[string]bool{}
	var valid []string
	for _, line := range status {
		word, _, _ := strings.Cut(line, " ")
		have[word] = true
		if word == "VALIDSIG" {
			valid = append(valid, line)
		}
	}
	for _, bad := range []string{"REVKEYSIG", "EXPKEYSIG", "EXPSIG", "BADSIG", "ERRSIG", "NO_PUBKEY", "ERROR"} {
		if have[bad] {
			return fmt.Errorf("verifier: gpgv reported %s: %s", bad, jsonset.Escape(out))
		}
	}
	if !have["GOODSIG"] || len(valid) == 0 {
		return fmt.Errorf("verifier: gpgv did not report GOODSIG and VALIDSIG: %s", jsonset.Escape(out))
	}
	// VALIDSIG <signing key> <date> <time> <expiry> <version> <reserved> <algorithm> <hash> <class>
	// <primary key>: the last field is the primary of the certificate that the signing key is in.
	// Without it, the signing key must itself be the primary.
	fields := strings.Fields(valid[0])
	var primary string
	switch len(fields) {
	case 11:
		primary = fields[10]
	case 10:
		primary = fields[1]
	}
	if len(valid) != 1 || primary != strings.ToUpper(fingerprint) {
		return fmt.Errorf("verifier: gpgv reported a signature by a key of another certificate than %s: %s", fingerprint, jsonset.Escape(out))
	}
	if exit != nil {
		return fmt.Errorf("verifier: gpgv: %w: %s", exit, jsonset.Escape(out))
	}
	return nil
}

// checkFingerprint refuses a fingerprint that is not 40 lower-case hexadecimal digits.
func checkFingerprint(fingerprint string) error {
	if len(fingerprint) != 40 {
		return fmt.Errorf("verifier: the fingerprint is not 40 lower-case hexadecimal digits: %s", jsonset.Escape(fingerprint))
	}
	for _, c := range []byte(fingerprint) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("verifier: the fingerprint is not 40 lower-case hexadecimal digits: %s", jsonset.Escape(fingerprint))
		}
	}
	return nil
}

// GPGVStatus runs gpgv like [GPGVVerify] and returns the status lines that gpgv wrote, each without
// its "[GNUPG:] " prefix (for example "GOODSIG 0123456789ABCDEF name" or "REVKEYSIG ..."), and the
// error of the exit status, which is nil for an exit of 0. A test that wants to assert on one
// status, such as REVKEYSIG, reads the lines and not the error. The text of a line comes from the
// certificate and the signature: a test must not act on it.
func GPGVStatus(t testing.TB, keyring, sig, data []byte) (status []string, exit error) {
	t.Helper()
	status, _, exit = gpgv(t, keyring, sig, data)
	return status, exit
}

// gpgv writes the three inputs to files in a folder of the test and runs gpgv on them.
func gpgv(t testing.TB, keyring, sig, data []byte) (status []string, combined string, exit error) {
	t.Helper()
	bin := Require(t, "gpgv")
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatalf("verifier: %v", err)
	}
	files := map[string][]byte{"keyring.pgp": keyring, "message.sig": sig, "message": data}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatalf("verifier: %v", err)
		}
	}
	env := []string{"HOME=" + home, "GNUPGHOME=" + home, "LC_ALL=C", "LANGUAGE=C", "TZ=UTC"}
	stdout, stderr, err := runSplit(env, bin, "--status-fd", "1", "--keyring", filepath.Join(dir, "keyring.pgp"),
		filepath.Join(dir, "message.sig"), filepath.Join(dir, "message"))
	for _, line := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(line, gpgvStatusPrefix); ok {
			status = append(status, rest)
		}
	}
	return status, stdout + stderr, err
}

// runSplit runs a tool with a time limit, with exactly the environment given, and returns its
// standard output and its standard error apart. An exit with a code other than 0 is an error.
func runSplit(env []string, bin string, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	if ctx.Err() != nil {
		err = errors.Join(err, ctx.Err())
	}
	return o.String(), e.String(), err
}
