//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// FuzzCheckRequestKeyringFileOfTheMostPrimaries runs the command on a bundle whose newest root list pins the most
// primaries (26), with the keyring file replaced by fuzzed bytes. The folder is made once. Whatever the bytes are, the
// command ends with exit code 1 or 3 (the request names two primaries, so it is never accepted beside a list of 26),
// writes only printable ASCII, and changes nothing in the bundle; it never says that the checks take fewer primaries.
// Exit code 3 means the file was accepted, and a second reader (go-crypto) then reads it with the 26 fingerprints of
// the list in its order.
func FuzzCheckRequestKeyringFileOfTheMostPrimaries(f *testing.F) {
	m := crqManifestOf(f)
	c := m.byID(f, "pgp-software-valid")
	roots := theMostRoots(f)
	trust := memTrustOf(roots)
	good := trust[keyringAt]
	for _, seed := range [][]byte{
		good, nil, {0}, good[:len(good)/2], good[:len(good)-1], append(slices.Clone(good), 0),
		append(slices.Clone(good), roots[0].cert...),
	} {
		f.Add(seed)
	}
	for _, at := range []int{0, 5, 100, len(good) / 3, len(good) - 1} {
		flipped := slices.Clone(good)
		flipped[at] ^= 0x01
		f.Add(flipped)
	}
	dir := f.TempDir()
	crqWrite(f, dir, crqWithTrust(crqBundleTree(f, m, c), trust))
	path := filepath.Join(dir, filepath.FromSlash(keyringAt))
	now := m.clock(f)
	stem := c.stem(f)
	before := crqSnapshot(f, dir)
	var want []string
	for _, r := range roots {
		want = append(want, r.fp)
	}
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
		if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) || strings.Contains(r.stderr, "checks take") {
			t.Fatalf("a byte that is not printable ASCII, or a count of primaries: %q %q", r.stdout, r.stderr)
		}
		switch r.code {
		case ExitFailure:
			if strings.Contains(r.stderr, "keyring.gpg") && !strings.HasPrefix(r.stderr, "ritueel: request "+stem+" is not accepted and not refused: "+refusedSentence) {
				t.Fatalf("the sentence of a refused file is %q", r.stderr)
			}
		case ExitRefused:
			if ring := crqRingPrimariesOrNil(file); !slices.Equal(ring, want) {
				t.Fatalf("exit code 3 for a file that go-crypto reads as %v", ring)
			}
		default:
			t.Fatalf("exit code %d\n%s%s", int(r.code), r.stdout, r.stderr)
		}
	})
}
