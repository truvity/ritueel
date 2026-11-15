//go:build linux || darwin

package bundle_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/openpgp"
)

// FuzzPrimariesKeyringFileOfTheMostPrimaries reads a trust set whose root list pins the most primaries (26) and whose
// keyring file is fuzzed bytes. The folder is made once and the file is replaced at every run. Neither Primaries nor
// Checker panics or hangs; an error is of the kind ErrPrimaries, comes with no primary and no set, in printable ASCII,
// and is never a count of the primaries (the list is one that the reader accepts); a success holds the 26 primaries
// in the order of the list, and a second reader (go-crypto) reads the file with the same fingerprints.
func FuzzPrimariesKeyringFileOfTheMostPrimaries(f *testing.F) {
	ps := memPrimaries(f, handoff.MaxPrimaries)
	set := memSet(7, ps)
	good := set[keyringName]
	for _, seed := range [][]byte{
		good, memKeyring(ps[:handoff.MaxPrimaries-1]), memKeyring(ps[1:]), append(bytes.Clone(good), ps[0].cert...),
		good[:len(good)/2], good[:len(good)-1], nil, {0},
		append(memKeyring(ps[1:2]), memKeyring(ps[:1])...),
	} {
		f.Add(seed)
	}
	for _, at := range []int{0, 5, 100, len(good) / 3, len(good) / 2, len(good) - 1} {
		flipped := bytes.Clone(good)
		flipped[at] ^= 0x80
		f.Add(flipped)
	}
	dir := makeBundle(f, merge(tree{"ritueel.yaml": []byte(settingsText(developmentStores))}, inSet(setDir, set)))
	bun, err := bundle.Open(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = bun.Close() })
	path := filepath.Join(dir, filepath.FromSlash(keyringPathInSet))
	var want []string
	for _, p := range ps {
		want = append(want, p.fp)
	}
	f.Fuzz(func(t *testing.T, file []byte) {
		if err := os.WriteFile(path, file, 0o644); err != nil {
			t.Fatal(err)
		}
		refs, ts, err := bun.Primaries()
		chk, d, cerr := bun.Checker("", fixedNow, nil)
		if (err == nil) != (cerr == nil && chk != nil) || d != nil {
			t.Fatalf("Primaries gave %v and Checker (%v, %v, %v)", err, chk, d, cerr)
		}
		if err != nil {
			if refs != nil || ts != (bundle.TrustSet{}) || chk != nil {
				t.Fatalf("a part beside the error: %v %+v %v", refs, ts, chk)
			}
			if !printableText(err.Error()) || !errors.Is(err, bundle.ErrPrimaries) || errors.Is(err, bundle.ErrNoKeyring) || !errors.Is(err, openpgp.ErrKeyring) || cerr.Error() != err.Error() {
				t.Fatalf("error %q (%v) for a refused file, Checker says %q", err.Error(), err, cerr.Error())
			}
			if bytes.Contains([]byte(err.Error()), []byte("checks take at most")) {
				t.Fatalf("the count of the primaries is judged for a list of %d: %q", handoff.MaxPrimaries, err.Error())
			}
			return
		}
		if got := fingerprintsOf(refs); !slices.Equal(got, want) || ts.Name != setDir {
			t.Fatalf("a success with %v in %+v, want the %d of the list", got, ts, handoff.MaxPrimaries)
		}
		if ring := ringRefs(t, file); !slices.Equal(fingerprintsOf(ring), want) {
			t.Fatalf("go-crypto reads %v from a file that the reader accepted", fingerprintsOf(ring))
		}
	})
}
