package verifier_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// The OpenPGP material of these tests is made by go-crypto, which is not the code that the builders
// of internal/openpgp use: the helpers of this package are tested against bytes that they were not
// written for.

var pgpMessage = []byte("the release of example.org version 1.2.3\n")

func nowSecond() time.Time { return time.Now().UTC().Truncate(time.Second) }

func pgpConfig(at time.Time) *packet.Config {
	return &packet.Config{
		Algorithm:   packet.PubKeyAlgoECDSA,
		Curve:       packet.CurveNistP384,
		DefaultHash: crypto.SHA384,
		Time:        func() time.Time { return at },
	}
}

// entity makes a key created at the given time, with a lifetime of ten years.
func entity(t testing.TB, created time.Time) *pgp.Entity {
	t.Helper()
	cfg := pgpConfig(created)
	cfg.KeyLifetimeSecs = 10 * 365 * 24 * 3600
	e, err := pgp.NewEntity("Example Test", "", "release@example.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// signingSubkeyEntity makes a key like [entity] with a signing subkey, which signs in place of the
// primary.
func signingSubkeyEntity(t testing.TB, created time.Time) *pgp.Entity {
	t.Helper()
	e := entity(t, created)
	cfg := pgpConfig(created)
	cfg.KeyLifetimeSecs = 10 * 365 * 24 * 3600
	if err := e.AddSigningSubkey(cfg); err != nil {
		t.Fatal(err)
	}
	return e
}

// fingerprintOf is the fingerprint of the primary key of a certificate: 40 lower-case digits.
func fingerprintOf(e *pgp.Entity) string { return hex.EncodeToString(e.PrimaryKey.Fingerprint) }

func publicOf(t testing.TB, e *pgp.Entity) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := e.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// detach signs the message with the key, as of the given time.
func detach(t testing.TB, e *pgp.Entity, msg []byte, at time.Time) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := pgp.DetachSign(&b, e, bytes.NewReader(msg), pgpConfig(at)); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// fakeTool puts a program called name on PATH. It writes stdout and stderr as given, records its
// arguments, the files it was given and a few variables of its environment in a folder, and exits
// with the code. It uses shell builtins only, because it runs with the small environment of the
// helpers, which has no PATH.
type fakeTool struct {
	name   string
	stdout string
	stderr string
	exit   int
	// capture is the folder that holds what the tool saw.
	capture string
}

func (f *fakeTool) install(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	f.capture = t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("stdout.txt", f.stdout)
	write("stderr.txt", f.stderr)
	script := strings.Join([]string{
		"#!/bin/sh",
		`printf '%s\n' "$@" > '` + f.capture + `/args'`,
		`printf 'HOME=%s\nGNUPGHOME=%s\nLC_ALL=%s\nTZ=%s\nCANARY=%s\nPOLICY=%s\n' "$HOME" "$GNUPGHOME" "$LC_ALL" "${TZ-unset}" "${RITUEEL_CANARY-unset}" "${SEQUOIA_CRYPTO_POLICY-unset}" > '` + f.capture + `/env'`,
		`pwd > '` + f.capture + `/cwd'`,
		`for n in "$@"; do if [ -f "$n" ]; then while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l"; done < "$n" > '` + f.capture + `/file-'"${n##*/}"; fi; done`,
		`while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l"; done < '` + filepath.Join(dir, "stdout.txt") + `'`,
		`while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l" >&2; done < '` + filepath.Join(dir, "stderr.txt") + `'`,
		"exit " + itoa(f.exit),
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, f.name), []byte(script), 0o755); err != nil { //nolint:gosec // a test tool has to be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for ; n > 0; n /= 10 {
		s = string(rune('0'+n%10)) + s
	}
	return s
}

func (f *fakeTool) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.capture, name))
	if err != nil {
		t.Fatalf("the fake tool did not record %s: %v", name, err)
	}
	return string(b)
}
