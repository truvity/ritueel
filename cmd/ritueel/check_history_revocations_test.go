//go:build linux || darwin

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The command "ritueel check history", run as the program that the release builds, on a bundle whose
// record lists the digests of the revocation material that its ceremony made, and whose root.json
// holds the digests of the revocation signatures of the OpenPGP primary (docs/reference/ceremony-record.md,
// "The record"; docs/reference/bundle.md, "root.json"). The files are spelled out by hand.

func bundleWithRevocations(t *testing.T, list string) (dir, end string) {
	t.Helper()
	dir, _, _ = makeBundle(t, 1)
	rootJSON := `{"created_at":"2026-11-20T10:00:00Z","label":"A","openpgp_created":"2026-11-20T09:00:00Z",` +
		`"openpgp_fingerprint":"` + strings.Repeat("c", 40) + `","removal_sha256":"` + strings.Repeat("1", 64) + `",` +
		`"revocations":{"compromised":"` + strings.Repeat("2", 64) + `","superseded":"` + strings.Repeat("3", 64) + `"},` +
		`"store":"software","test":true,"version":1,"x509_spki_sha256":"` + strings.Repeat("a", 64) + `"}`
	putFile(t, dir, "roots/A/root.json", rootJSON)
	recPath := filepath.Join(dir, "history", "20260001T100000Z-apply", "record.json")
	old, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	rec := strings.Replace(string(old), `"artifacts":[`, `"artifacts":[{"path":"roots/A/root.json","sha256":"`+sumOf(rootJSON)+`"},`, 1)
	rec = strings.Replace(rec, `"transcript_sha256"`, `"revocations":`+list+`,"transcript_sha256"`, 1)
	if err := os.WriteFile(recPath, []byte(rec), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, sumOf(rec)
}

func runCheckHistory(t *testing.T, exe, dir string, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), exe, append([]string{"check", "history", "--dir", dir}, extra...)...)
	cmd.Dir = t.TempDir()
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

func TestProgramCheckHistoryReadsARecordWithRevocations(t *testing.T) {
	exe := buildForCheck(t)
	entries := func(label string) string {
		return `[{"label":"` + label + `","reason":"root-removal","sha256":"` + strings.Repeat("1", 64) + `"},` +
			`{"label":"` + label + `","reason":"compromised","sha256":"` + strings.Repeat("2", 64) + `"},` +
			`{"label":"` + label + `","reason":"superseded","sha256":"` + strings.Repeat("3", 64) + `"}]`
	}
	t.Run("a list in its form is clean", func(t *testing.T) {
		dir, end := bundleWithRevocations(t, entries("A"))
		want := "history: 1 ceremony records, end " + end[:8] + "\n"
		code, stdout, stderr := runCheckHistory(t, exe, dir)
		if code != 0 || stdout != want || stderr != "" {
			t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q and nothing", code, stdout, stderr, want)
		}
	})
	t.Run("a label that is not one upper-case letter is record-invalid", func(t *testing.T) {
		dir, _ := bundleWithRevocations(t, entries("a"))
		code, stdout, stderr := runCheckHistory(t, exe, dir)
		if code != 3 || stdout != "" {
			t.Errorf("exit %d, stdout %q; want 3 and nothing on standard output", code, stdout)
		}
		if !strings.Contains(stderr, "record-invalid history/20260001T100000Z-apply/record.json") || !strings.Contains(stderr, "member revocations[0].label") || !strings.Contains(stderr, "ritueel: refused: ") {
			t.Errorf("stderr = %q", stderr)
		}
	})
	t.Run("an empty list is record-invalid", func(t *testing.T) {
		dir, _ := bundleWithRevocations(t, `[]`)
		code, _, stderr := runCheckHistory(t, exe, dir)
		if code != 3 || !strings.Contains(stderr, "record-invalid") {
			t.Errorf("exit %d, stderr %q", code, stderr)
		}
	})
}
