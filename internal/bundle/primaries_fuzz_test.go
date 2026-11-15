package bundle_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/openpgp"
)

// FuzzPrimariesKeyringFile reads a trust set whose keyring file is fuzzed bytes. The folder is made once and the file
// is replaced at every run. Neither Primaries nor Checker panics or hangs; an error comes with no primary and no set,
// in printable ASCII, as the error of a refused file; a success holds the two primaries of the list in its order, and
// a second reader (go-crypto) reads the file with the same fingerprints; Checker and Primaries agree; and the file
// is the only thing that a run could have changed, and no run changes it.
func FuzzPrimariesKeyringFile(f *testing.F) {
	a, b, z := keyringOf(f, "a"), keyringOf(f, "b"), keyringOf(f, "z")
	good := append(append([]byte(nil), a...), b...)
	for _, seed := range [][]byte{
		good, a, b, z, append(append([]byte(nil), b...), a...), append(append([]byte(nil), a...), z...),
		append(append([]byte(nil), good...), 0), good[:len(good)/2], good[:len(good)-1], nil, {0},
		[]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"),
		{0xc6, 0xff, 0xff, 0xff, 0xff}, {0xc6, 0x00}, {0xe0},
	} {
		f.Add(seed)
	}
	for _, at := range []int{0, 1, 5, 20, 100, len(good) / 2, len(good) - 1} {
		flipped := append([]byte(nil), good...)
		flipped[at] ^= 0x80
		f.Add(flipped)
	}
	dir := makeBundle(f, merge(tree{"ritueel.yaml": []byte(settingsText(developmentStores))}, inSet(setDir, trustAB(f, 7))))
	bun, err := bundle.Open(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = bun.Close() })
	path := filepath.Join(dir, filepath.FromSlash(keyringPathInSet))
	wantPrints := []string{"6df387de63525c9dc0ec1174bd138d2c4889b79b", "c4288657012230588b51fa66e0831b9c6e084f39"}
	f.Fuzz(func(t *testing.T, file []byte) {
		if err := os.WriteFile(path, file, 0o644); err != nil {
			t.Fatal(err)
		}
		refs, set, err := bun.Primaries()
		chk, d, cerr := bun.Checker("", fixedNow, nil)
		if (err == nil) != (cerr == nil && chk != nil) || d != nil {
			t.Fatalf("Primaries gave %v and Checker (%v, %v, %v)", err, chk, d, cerr)
		}
		if err != nil {
			if refs != nil || set != (bundle.TrustSet{}) || chk != nil {
				t.Fatalf("a part beside the error: %v %+v %v", refs, set, chk)
			}
			if !printableText(err.Error()) || !errors.Is(err, openpgp.ErrKeyring) || !errors.Is(err, bundle.ErrPrimaries) || errors.Is(err, bundle.ErrNoKeyring) || !errors.Is(cerr, bundle.ErrPrimaries) || cerr.Error() != err.Error() {
				t.Fatalf("error %q (%v) for a refused file, Checker says %q", err.Error(), err, cerr.Error())
			}
			return
		}
		got := fingerprintsOf(refs)
		if !slices.Equal(got, wantPrints) || set.Name != setDir {
			t.Fatalf("a success with %v in %+v, want %v", got, set, wantPrints)
		}
		// The second reader reads the same file with the same fingerprints.
		if ring := ringRefs(t, file); !slices.Equal(fingerprintsOf(ring), wantPrints) {
			t.Fatalf("go-crypto reads %v from a file that the reader accepted", fingerprintsOf(ring))
		}
		for _, r := range refs {
			if r.Key == nil || r.Created.IsZero() {
				t.Fatalf("a primary with no key or no time: %+v", r)
			}
		}
	})
}
