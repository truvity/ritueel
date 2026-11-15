//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// FuzzCheckRequestKeyringFile runs the command on a request that the keyring file decides, with the keyring file
// replaced by fuzzed bytes. The folder is made once. Whatever the bytes are, the command ends with exit code 0, 1 or
// 3, writes only printable ASCII, and changes nothing in the bundle. A file that is refused is exit code 1 and one
// sentence of the form of the page. Exit code 0 or 3 means the file was accepted, and a second reader (go-crypto)
// then reads it with the two fingerprints of the list in its order; exit code 0 means the file is read as the
// good file is. The command starts no program.
func FuzzCheckRequestKeyringFile(f *testing.F) {
	m := crqManifestOf(f)
	c := m.byID(f, "pgp-software-valid")
	a, b, z := crqKeyring(f, "a"), crqKeyring(f, "b"), crqKeyring(f, "z")
	good := append(append([]byte(nil), a...), b...)
	for _, seed := range [][]byte{
		good, a, b, z, append(append([]byte(nil), b...), a...), append(append([]byte(nil), a...), z...),
		append(append([]byte(nil), good...), 0), good[:len(good)/2], nil, {0},
		[]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"), {0xc6, 0xff, 0xff, 0xff, 0xff}, {0xe0},
	} {
		f.Add(seed)
	}
	for _, at := range []int{0, 5, 40, 100, len(good) / 2, len(good) - 1} {
		flipped := append([]byte(nil), good...)
		flipped[at] ^= 0x01
		f.Add(flipped)
	}
	dir := t0Dir(f, m, c)
	path := filepath.Join(dir, filepath.FromSlash(keyringAt))
	now := m.clock(f)
	stem := c.stem(f)
	before := crqSnapshot(f, dir)
	wantPrints := []string{"6df387de63525c9dc0ec1174bd138d2c4889b79b", "c4288657012230588b51fa66e0831b9c6e084f39"}
	f.Fuzz(func(t *testing.T, file []byte) {
		if err := os.WriteFile(path, file, 0o644); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := os.WriteFile(path, good, 0o644); err != nil {
				t.Fatal(err)
			}
			crqSame(t, "the command", before, crqSnapshot(t, dir))
		}()
		r := crqRun(t, now, "check", "request", stem, "--dir", dir, "--delegation", crqDelegation)
		if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Fatalf("a byte that is not printable ASCII: %q %q", r.stdout, r.stderr)
		}
		switch r.code {
		case ExitFailure:
			if strings.Contains(r.stderr, "keyring.gpg") && !strings.HasPrefix(r.stderr, "ritueel: request "+stem+" is not accepted and not refused: "+refusedSentence) {
				t.Fatalf("the sentence of a refused file is %q", r.stderr)
			}
		case ExitOK, ExitRefused:
			if ring := crqRingPrimariesOrNil(file); !slices.Equal(ring, wantPrints) {
				t.Fatalf("exit code %d for a file that go-crypto reads as %v", int(r.code), ring)
			}
			if r.code == ExitOK && strings.Contains(r.stderr, "keyring") {
				t.Fatalf("accepted with a word about the keyring: %q", r.stderr)
			}
		default:
			t.Fatalf("exit code %d\n%s%s", int(r.code), r.stdout, r.stderr)
		}
	})
}

// t0Dir is the bundle of a case, written once.
func t0Dir(f testing.TB, m crqManifest, c crqCase) string {
	f.Helper()
	dir := f.TempDir()
	crqWrite(f, dir, crqBundleTree(f, m, c))
	return dir
}
