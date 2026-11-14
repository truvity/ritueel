package wanted_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The files of a bundle that the tests start from. Each is accepted by its reader; a test changes one thing.

const goodSettings = `version: 1
name: Example
release_address: release@example.org
policy:
  stores: [piv, openpgp-card, aws-kms]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`

const goodPersonal = `version: 1
kind: personal
person:
  name: Example Person
  address: person@example.org
policy:
  stores: [piv]
  min_firmware: 5.7.0
  pin_policy: [once]
  require_name_constraints: true
  validity_months: 13
`

const goodX509Delegation = `version: 1
type: x509-intermediate
root: acme-tls
permitted_uri_hosts: [example.org]
permitted_dns_names: [example.org]
`

const goodOpenPGPDelegation = `version: 1
type: openpgp-subkey
root: acme-release
capability: sign
kms_read_roles:
  "111122223333": arn:aws:iam::111122223333:role/example-certifier-read
`

const goodSSHDelegation = `version: 1
type: ssh-ca-key
root: acme-ssh
use: user
`

const goodRoot = `version: 1
kind: x509
test: false
`

// settingsPath is the path that the errors of ParseSettings carry.
const settingsPath = wanted.SettingsPath

// mustSettings parses text and fails the test when the reader refuses it.
func mustSettings(t testing.TB, text string) *wanted.Settings {
	t.Helper()
	s, err := wanted.ParseSettings(settingsPath, []byte(text))
	if err != nil {
		t.Fatalf("the reader refuses a file that must be accepted: %v\n%s", err, text)
	}
	if s == nil || !s.Valid() {
		t.Fatalf("no error, and the settings are %v", s)
	}
	return s
}

// mustDelegation parses a delegation against good settings.
func mustDelegation(t testing.TB, name, text string) *wanted.Delegation {
	t.Helper()
	d, err := wanted.ParseDelegation(name, []byte(text), mustSettings(t, goodSettings))
	if err != nil {
		t.Fatalf("the reader refuses a delegation that must be accepted: %v\n%s", err, text)
	}
	if d == nil || !d.Valid() {
		t.Fatalf("no error, and the delegation is %v", d)
	}
	return d
}

// printable reports whether s holds only printable ASCII and no line break.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// wantFault checks that err is a *wanted.Error for the path (an empty path is not checked), that its text is printable ASCII, that it is at the
// line (a negative line is not checked), and that its message holds every word. It returns the error.
func wantFault(t testing.TB, err error, path string, line int, words ...string) *wanted.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want a fault with %q", words)
	}
	var e *wanted.Error
	if !errors.As(err, &e) {
		t.Fatalf("the error is %T (%v), want a *wanted.Error", err, err)
	}
	if path != "" && e.Path != path {
		t.Errorf("path %q, want %q", e.Path, path)
	}
	if line >= 0 && e.Line != line {
		t.Errorf("line %d, want %d (%s)", e.Line, line, e.Msg)
	}
	for _, w := range words {
		if !strings.Contains(e.Msg, w) {
			t.Errorf("message %q lacks %q", e.Msg, w)
		}
	}
	if !printable(err.Error()) {
		t.Errorf("the text of the error is not printable ASCII: %q", err.Error())
	}
	if e.Msg == "" {
		t.Error("an empty message")
	}
	return e
}

// refuseSettings parses text and checks the fault.
func refuseSettings(t testing.TB, text string, line int, words ...string) *wanted.Error {
	t.Helper()
	s, err := wanted.ParseSettings(settingsPath, []byte(text))
	if s != nil {
		t.Errorf("a value beside the error %v", err)
	}
	return wantFault(t, err, settingsPath, line, words...)
}

// refuseDelegation parses text as the delegation "example" against good settings and checks the fault.
func refuseDelegation(t testing.TB, text string, line int, words ...string) *wanted.Error {
	t.Helper()
	d, err := wanted.ParseDelegation("example", []byte(text), mustSettings(t, goodSettings))
	if d != nil {
		t.Errorf("a value beside the error %v", err)
	}
	return wantFault(t, err, "want/delegations/example.yaml", line, words...)
}

// replaceOnce changes the first occurrence of old in s and fails when there is none, so that a table row cannot
// quietly stop changing anything.
func replaceOnce(t testing.TB, s, old, repl string) string {
	t.Helper()
	if !strings.Contains(s, old) {
		t.Fatalf("the text %q is not in the starting file", old)
	}
	return strings.Replace(s, old, repl, 1)
}

// bundleDir makes a folder with the files given (path to text), through the operating system, and opens it
// through package fsx.
func bundleDir(t testing.TB, files map[string]string) (string, fsx.FS) {
	t.Helper()
	dir := t.TempDir()
	for p, text := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsys.Close() })
	return dir, fsys
}

// sha256hex is the digest of b as `sha256sum` writes it.
func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
