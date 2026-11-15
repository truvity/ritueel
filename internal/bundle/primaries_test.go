//go:build linux || darwin

package bundle_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/strictjson"
)

// Bundle.Primaries and the primaries that Bundle.Checker gives: the keyring file of the newest trust set, read with
// the entries of its root list that have a fingerprint, in the order of the list (docs/reference/keyring-package.md,
// "The first form of the keyring file"; docs/reference/root-list.md, "openpgp_fingerprint").

const (
	setDir = "7-3fa9c1d2"

	// The two sentences of a keyring file that cannot be used. They name the newest set and the file.
	noKeyringText    = "the newest trust set " + setDir + " pins OpenPGP primaries and holds no keyring.gpg"
	refusedPrefix    = "keyring.gpg of the newest trust set " + setDir + " is refused: "
	keyringPathInSet = "trust/" + setDir + "/" + keyringName
)

// digestTree is every file under dir with its mode and its digest, and every folder, links not followed: a change of
// any byte, name or mode is a change of the result.
func digestTree(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		line := rel + " " + info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += " " + sha256hex(data)
		}
		out = append(out, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameDigest(t testing.TB, what string, before, after []string) {
	t.Helper()
	if !slices.Equal(before, after) {
		t.Errorf("%s changed the bundle:\nbefore %q\nafter  %q", what, before, after)
	}
}

// bundleWith is a bundle of the test settings with one trust set, opened.
func bundleWith(t testing.TB, set tree) (*bundle.Bundle, string) {
	t.Helper()
	dir := makeBundle(t, merge(tree{"ritueel.yaml": []byte(settingsText(developmentStores))}, inSet(setDir, set)))
	return openBundle(t, dir), dir
}

func fingerprintsOf(refs []handoff.PrimaryRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.Fingerprint)
	}
	return out
}

func TestPrimariesAreTheOnesOfTheKeyringFileInTheOrderOfTheList(t *testing.T) {
	b, dir := bundleWith(t, trustAB(t, 7))
	before := digestTree(t, dir)
	refs, set, err := b.Primaries()
	if err != nil {
		t.Fatal(err)
	}
	if set != (bundle.TrustSet{Name: setDir, Number: 7}) {
		t.Errorf("set = %+v", set)
	}
	// The second reader: go-crypto reads the file, and the primaries must be the ones that it gives.
	want := ringRefs(t, keyringOf(t, "a", "b"))
	if len(refs) != 2 || len(want) != 2 {
		t.Fatalf("%d primaries, the second reader gives %d", len(refs), len(want))
	}
	for i := range refs {
		if refs[i].Fingerprint != want[i].Fingerprint || !sameKey(refs[i].Key, want[i].Key) || !refs[i].Created.Equal(want[i].Created) {
			t.Errorf("primary %d = %+v, the second reader gives %+v", i, refs[i], want[i])
		}
	}
	// The list of the vectors: A with 6df387de..., then B with c4288657....
	if got := fingerprintsOf(refs); !slices.Equal(got, []string{"6df387de63525c9dc0ec1174bd138d2c4889b79b", "c4288657012230588b51fa66e0831b9c6e084f39"}) {
		t.Errorf("fingerprints = %v, want the two of the list in its order", got)
	}
	if refs[0].Created.IsZero() || !refs[0].Created.Before(vectorNow) {
		t.Errorf("created = %v, want the time of the key packet, before the clock", refs[0].Created)
	}
	sameDigest(t, "Primaries", before, digestTree(t, dir))

	// The one-entry list of the vectors has the one primary.
	b1, _ := bundleWith(t, trustA(t, 7))
	refs, _, err = b1.Primaries()
	if err != nil || len(refs) != 1 || refs[0].Fingerprint != "6df387de63525c9dc0ec1174bd138d2c4889b79b" {
		t.Errorf("one root: (%v, %v)", fingerprintsOf(refs), err)
	}
}

// The order is the order of the list, never the order of the labels and never the order of the fingerprints.
func TestPrimariesFollowTheOrderOfTheListAndNotOfTheLabels(t *testing.T) {
	ps := memPrimaries(t, 3) // A, B, C
	order := []memPrimary{ps[2], ps[0], ps[1]}
	b, _ := bundleWith(t, memSet(7, order))
	refs, _, err := b.Primaries()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fingerprintsOf(refs), []string{ps[2].fp, ps[0].fp, ps[1].fp}; !slices.Equal(got, want) {
		t.Errorf("fingerprints = %v, want %v", got, want)
	}
	// The same file for the list in label order is a file out of order.
	set := memSet(7, ps)
	set[keyringName] = memKeyring(order)
	b2, _ := bundleWith(t, set)
	if refs, _, err := b2.Primaries(); err == nil || refs != nil || !errors.Is(err, openpgp.ErrKeyringPrimaries) || !strings.Contains(err.Error(), "out of order") {
		t.Errorf("a file out of the order of the list: (%v, %v)", refs, err)
	}
}

// A list in which only some entries have a fingerprint is read as it is: the entries that have one are the entries of
// the reader, in the order of the list.
func TestAListWithSomeFingerprintsGivesThePrimariesOfThoseEntries(t *testing.T) {
	ps := memPrimaries(t, 3)
	set := tree{"root-list.json": memList(7, ps, map[string]bool{"B": true}), "ca-bundle.pem": memBundlePEM(7, ps), keyringName: memKeyring([]memPrimary{ps[0], ps[2]})}
	b, _ := bundleWith(t, set)
	refs, _, err := b.Primaries()
	if err != nil || !slices.Equal(fingerprintsOf(refs), []string{ps[0].fp, ps[2].fp}) {
		t.Fatalf("(%v, %v), want the primaries of A and C", fingerprintsOf(refs), err)
	}
	// A file that holds all three is a certificate too many for the two entries that have a fingerprint.
	set[keyringName] = memKeyring(ps)
	b2, _ := bundleWith(t, set)
	if refs, _, err := b2.Primaries(); refs != nil || !errors.Is(err, openpgp.ErrKeyringPrimaries) || !strings.Contains(err.Error(), "one too many") {
		t.Errorf("(%v, %v), want one too many", refs, err)
	}
}

// A list that pins no primary has no keyring file: no file is an empty list and no error, and a file is an error,
// because it holds a primary that is not on the list.
func TestAListThatPinsNoPrimaryHasNoKeyringFile(t *testing.T) {
	ps := memPrimaries(t, 2)
	noPrints := map[string]bool{"A": true, "B": true}
	plain := tree{"root-list.json": memList(7, ps, noPrints), "ca-bundle.pem": memBundlePEM(7, ps)}

	b, dir := bundleWith(t, plain)
	before := digestTree(t, dir)
	refs, set, err := b.Primaries()
	if err != nil || len(refs) != 0 || set.Name != setDir {
		t.Errorf("no file: (%v, %+v, %v), want no primary, the set and no error", refs, set, err)
	}
	sameDigest(t, "Primaries", before, digestTree(t, dir))

	withFile := merge(plain, tree{keyringName: memKeyring(ps)})
	b2, _ := bundleWith(t, withFile)
	refs, set, err = b2.Primaries()
	if err == nil || refs != nil || set != (bundle.TrustSet{}) {
		t.Fatalf("a file: (%v, %+v, %v), want an error and nothing else", refs, set, err)
	}
	if !errors.Is(err, openpgp.ErrKeyringPrimaries) || !errors.Is(err, openpgp.ErrKeyring) || errors.Is(err, bundle.ErrNoKeyring) {
		t.Errorf("error %v: wrong kind", err)
	}
	if !strings.HasPrefix(err.Error(), refusedPrefix) || !strings.Contains(err.Error(), "pins no OpenPGP primary") {
		t.Errorf("error text = %q", err.Error())
	}
	// A file that is a link, a folder or a file that cannot be read is refused in the same way, also with no entry.
	dirFile := merge(plain, tree{keyringName + "/x": []byte("x")})
	b3, _ := bundleWith(t, dirFile)
	if _, _, err := b3.Primaries(); !errors.Is(err, openpgp.ErrKeyring) || errors.Is(err, bundle.ErrNoKeyring) || !strings.HasPrefix(err.Error(), refusedPrefix) {
		t.Errorf("a folder where the file is: %v", err)
	}
}

func TestAListThatPinsPrimariesAndASetWithNoKeyringFileIsErrNoKeyring(t *testing.T) {
	b, dir := bundleWith(t, without(trustAB(t, 7), keyringName))
	before := digestTree(t, dir)
	refs, set, err := b.Primaries()
	if refs != nil || set != (bundle.TrustSet{}) || !errors.Is(err, bundle.ErrNoKeyring) {
		t.Fatalf("(%v, %+v, %v), want no primary and ErrNoKeyring", refs, set, err)
	}
	if !errors.Is(err, fs.ErrNotExist) || errors.Is(err, openpgp.ErrKeyring) {
		t.Errorf("error %v: the read error is kept, and the file was not refused by the reader", err)
	}
	if err.Error() != noKeyringText {
		t.Errorf("error text = %q, want %q", err.Error(), noKeyringText)
	}
	sameDigest(t, "Primaries", before, digestTree(t, dir))
}

// A keyring file that is not a plain file, or that fsx will not read, is a refused file: never "absent".
func TestAKeyringFileThatIsNotAPlainFileIsRefusedAndNotAbsentAndNotWaitedOn(t *testing.T) {
	good := keyringOf(t, "a", "b")
	for name, place := range map[string]func(t *testing.T, at string){
		"a link to a good file": func(t *testing.T, at string) {
			real := filepath.Join(filepath.Dir(at), "real.gpg")
			if err := os.WriteFile(real, good, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("real.gpg", at); err != nil {
				t.Fatal(err)
			}
		},
		"a dangling link": func(t *testing.T, at string) {
			if err := os.Symlink("nowhere.gpg", at); err != nil {
				t.Fatal(err)
			}
		},
		"a link to a folder": func(t *testing.T, at string) {
			if err := os.Symlink(".", at); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func(t *testing.T, at string) {
			if err := os.Mkdir(at, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a pipe": func(t *testing.T, at string) {
			if err := syscall.Mkfifo(at, 0o644); err != nil {
				t.Skipf("no pipe here: %v", err)
			}
		},
		"a file over what fsx reads": func(t *testing.T, at string) {
			if err := os.WriteFile(at, make8MiBPlusOne(), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, dir := bundleWith(t, without(trustAB(t, 7), keyringName))
			place(t, filepath.Join(dir, filepath.FromSlash(keyringPathInSet)))
			before := digestTree(t, dir)
			for _, call := range []struct {
				name string
				run  func() error
			}{
				{"Primaries", func() error { _, _, err := b.Primaries(); return err }},
				{"Checker", func() error { _, _, err := b.Checker("", fixedNow, nil); return err }},
			} {
				err := call.run()
				if err == nil {
					t.Fatalf("%s: no error", call.name)
				}
				if errors.Is(err, bundle.ErrNoKeyring) || !errors.Is(err, openpgp.ErrKeyring) {
					t.Errorf("%s: error %v: a file that cannot be read is a refused file, never an absent one", call.name, err)
				}
				if !strings.HasPrefix(err.Error(), refusedPrefix) || !printableText(err.Error()) {
					t.Errorf("%s: error text = %q", call.name, err.Error())
				}
			}
			sameDigest(t, "a read", before, digestTree(t, dir))
		})
	}
}

func make8MiBPlusOne() []byte { return make([]byte, fsx.MaxReadSize+1) }

// Each refusal of the reader of the file is an error of Primaries and of Checker, with the words of the reader, and
// no primary comes with it.
func TestEachRefusalOfTheKeyringReaderIsAnErrorWithNoPrimary(t *testing.T) {
	a, bb, z := keyringOf(t, "a"), keyringOf(t, "b"), keyringOf(t, "z")
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	flip := func(file []byte, at int) []byte {
		out := bytes.Clone(file)
		out[at] ^= 0x01
		return out
	}
	for _, tc := range []struct {
		name string
		file []byte
		kind error
		want string
	}{
		{"b then a (swapped)", cat(bb, a), openpgp.ErrKeyringPrimaries, "out of order"},
		{"a alone for two entries", a, openpgp.ErrKeyringPrimaries, "missing"},
		{"b alone for two entries", bb, openpgp.ErrKeyringPrimaries, ""},
		{"z where b is wanted", cat(a, z), openpgp.ErrKeyringPrimaries, "not on the list"},
		{"a, b and z", cat(a, bb, z), openpgp.ErrKeyringPrimaries, "one too many"},
		{"a twice", cat(a, a), openpgp.ErrKeyringPrimaries, ""},
		{"an empty file", nil, openpgp.ErrKeyringForm, "empty"},
		{"armour", []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n"), openpgp.ErrKeyringForm, "armour"},
		{"text", []byte("hello\n"), openpgp.ErrKeyringForm, ""},
		{"one byte after the last packet", cat(a, bb, []byte{0}), openpgp.ErrKeyringForm, ""},
		{"a cut file", cat(a, bb)[:len(a)+len(bb)-3], openpgp.ErrKeyringForm, ""},
		{"a byte of a signature changed", flip(cat(a, bb), len(a)+len(bb)-5), openpgp.ErrKeyringForm, ""},
		{"a byte of a key changed", flip(cat(a, bb), 12), openpgp.ErrKeyringForm, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := trustAB(t, 7)
			set[keyringName] = tc.file
			b, dir := bundleWith(t, set)
			before := digestTree(t, dir)
			refs, ts, err := b.Primaries()
			if err == nil || refs != nil || ts != (bundle.TrustSet{}) {
				t.Fatalf("Primaries = (%v, %+v, %v), want an error and nothing else", refs, ts, err)
			}
			if !errors.Is(err, openpgp.ErrKeyring) || !errors.Is(err, tc.kind) || errors.Is(err, bundle.ErrNoKeyring) {
				t.Errorf("error %v: wrong kind, want %v", err, tc.kind)
			}
			if !strings.HasPrefix(err.Error(), refusedPrefix) || !strings.Contains(err.Error(), tc.want) || !printableText(err.Error()) || strings.Contains(err.Error(), "\n") {
				t.Errorf("error text = %q, want %q and %q in it", err.Error(), refusedPrefix, tc.want)
			}
			// Checker, with no delegation, stops in the same way; no checker comes with the error.
			chk, d, cerr := b.Checker("", fixedNow, nil)
			if chk != nil || d != nil || cerr == nil || cerr.Error() != err.Error() {
				t.Errorf("Checker = (%v, %v, %v), want no checker and the error %q", chk, d, cerr, err.Error())
			}
			sameDigest(t, "a read", before, digestTree(t, dir))
		})
	}
}

// A user ID that holds a control character is shown only as an escape in the error, whatever the file holds.
func TestAHostileUserIDReachesTheErrorOnlyAsAnEscape(t *testing.T) {
	ps := memPrimaries(t, 1)
	cert := bytes.Clone(ps[0].cert)
	at := bytes.Index(cert, []byte("Example Test Release Root"))
	if at < 0 {
		t.Fatal("the user ID is not in the certificate")
	}
	for _, evil := range []byte{0x1b, 0x0a, 0x7f, 0x80, 0xff} {
		c := bytes.Clone(cert)
		c[at] = evil
		set := memSet(7, ps)
		set[keyringName] = c
		b, _ := bundleWith(t, set)
		_, _, err := b.Primaries()
		if err == nil {
			t.Fatalf("0x%02x: a keyring file with a hostile user ID is accepted", evil)
		}
		if !printableText(err.Error()) || strings.Contains(err.Error(), "\n") || !errors.Is(err, openpgp.ErrKeyring) {
			t.Errorf("0x%02x: error text %q", evil, err.Error())
		}
	}
}

// The newest set is read and no older one is used when its keyring file is bad.
func TestTheNewestSetIsNeverReplacedByAnOlderOneWhenItsKeyringFileIsBad(t *testing.T) {
	bad := trustAB(t, 8)
	bad[keyringName] = keyringOf(t, "b", "a")
	b := openBundle(t, makeBundle(t, merge(
		tree{"ritueel.yaml": []byte(settingsText(developmentStores))},
		inSet("6-aaaaaaaa", trustAB(t, 6)), inSet("8-bbbbbbbb", bad),
	)))
	refs, set, err := b.Primaries()
	if refs != nil || set != (bundle.TrustSet{}) || !errors.Is(err, openpgp.ErrKeyringPrimaries) {
		t.Fatalf("(%v, %+v, %v), want the error of the newest set", refs, set, err)
	}
	if want := "keyring.gpg of the newest trust set 8-bbbbbbbb is refused: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error text = %q, want it to start with %q", err.Error(), want)
	}
	// And the reverse: a bad older set is never read.
	oldBad := trustAB(t, 6)
	oldBad[keyringName] = []byte("garbage")
	b2 := openBundle(t, makeBundle(t, merge(
		tree{"ritueel.yaml": []byte(settingsText(developmentStores))},
		inSet("6-aaaaaaaa", oldBad), inSet("8-bbbbbbbb", trustAB(t, 8)),
	)))
	if refs, set, err := b2.Primaries(); err != nil || len(refs) != 2 || set.Name != "8-bbbbbbbb" {
		t.Errorf("(%v, %+v, %v), want the two primaries of set 8", fingerprintsOf(refs), set, err)
	}
}

// A bad CA bundle or root list of the newest set is an error of Primaries, as it is of Roots: one reading of the set.
func TestPrimariesAndRootsReadTheSameSetWithTheSameRules(t *testing.T) {
	for name, set := range map[string]tree{
		"a CA bundle of another list": merge(trustAB(t, 7), tree{"ca-bundle.pem": trustA(t, 7)["ca-bundle.pem"]}),
		"no CA bundle":                without(trustAB(t, 7), "ca-bundle.pem"),
		"no root list":                without(trustAB(t, 7), "root-list.json"),
		"a list of another sequence":  merge(trustAB(t, 7), tree{"root-list.json": trustAB(t, 9)["root-list.json"]}),
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := bundleWith(t, set)
			_, _, rerr := b.Roots()
			refs, ts, perr := b.Primaries()
			if rerr == nil || perr == nil || refs != nil || ts != (bundle.TrustSet{}) {
				t.Fatalf("Roots error %v, Primaries (%v, %+v, %v)", rerr, refs, ts, perr)
			}
			if rerr.Error() != perr.Error() {
				t.Errorf("Roots says %q and Primaries says %q", rerr.Error(), perr.Error())
			}
		})
	}
	// No trust set at all.
	b := openBundle(t, makeBundle(t, tree{"ritueel.yaml": []byte(settingsText(developmentStores))}))
	if _, _, err := b.Primaries(); !errors.Is(err, bundle.ErrNoTrustSet) {
		t.Errorf("no trust set: %v", err)
	}
}

// Roots keeps its behaviour: it reads no keyring file, so a set with none and a set with a bad one give the roots.
func TestRootsReadsNoKeyringFile(t *testing.T) {
	for name, set := range map[string]tree{
		"no keyring file":     without(trustAB(t, 7), keyringName),
		"a bad keyring":       merge(trustAB(t, 7), tree{keyringName: []byte("garbage")}),
		"a folder":            merge(without(trustAB(t, 7), keyringName), tree{keyringName + "/x": []byte("x")}),
		"a keyring of z":      merge(trustAB(t, 7), tree{keyringName: keyringOf(t, "z")}),
		"seventeen primaries": merge(memSet(7, memPrimaries(t, 17)), tree{keyringName: []byte("garbage")}),
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := bundleWith(t, set)
			roots, ts, err := b.Roots()
			if err != nil || len(roots) == 0 || ts.Name != setDir {
				t.Fatalf("Roots = (%d, %+v, %v)", len(roots), ts, err)
			}
		})
	}
}

// countText is the shape of the error for too many primaries: the number that the list pins comes first, and the
// number that the checks take comes after it.
var countText = regexp.MustCompile(`pins 17 OpenPGP primaries.*at most 16`)

// The checker takes at most handoff.MaxPrimaries (16): 16 are given, 17 are an error that names both numbers and no
// file is read for it.
func TestMoreThanSixteenPinnedPrimariesAreAnErrorWithBothNumbers(t *testing.T) {
	ps := memPrimaries(t, 17)
	b16, _ := bundleWith(t, memSet(7, ps[:16]))
	refs, _, err := b16.Primaries()
	if err != nil || len(refs) != 16 {
		t.Fatalf("sixteen: (%d, %v)", len(refs), err)
	}
	if chk, _, err := b16.Checker("", fixedNow, nil); err != nil || chk == nil {
		t.Errorf("sixteen: Checker (%v, %v)", chk, err)
	}
	// The keyring file of the 17 is garbage: the count is judged before the file is read, so the error is the count.
	set := memSet(7, ps)
	set[keyringName] = []byte("garbage")
	b17, _ := bundleWith(t, set)
	for name, call := range map[string]func() error{
		"Primaries": func() error { _, _, err := b17.Primaries(); return err },
		"Checker":   func() error { _, _, err := b17.Checker("", fixedNow, nil); return err },
	} {
		err := call()
		if err == nil || !countText.MatchString(err.Error()) || !strings.Contains(err.Error(), setDir) {
			t.Errorf("%s: error %v, want the 17 that the list pins, then the 16 that the checks take, and the set", name, err)
		} else if errors.Is(err, openpgp.ErrKeyring) || strings.Contains(err.Error(), "garbage") {
			t.Errorf("%s: the file was judged: %v", name, err)
		}
	}
}

// A primary created after the clock of the checker is an error of the configuration (exit code 1 in the command),
// never a refusal and never a file that is refused.
func TestAPrimaryCreatedAfterTheClockIsAConfigurationError(t *testing.T) {
	late := newMemPrimary(t, "A", vectorNow.AddDate(0, 0, 1), true)
	b, _ := bundleWith(t, memSet(7, []memPrimary{late}))
	refs, _, err := b.Primaries()
	if err != nil || len(refs) != 1 {
		t.Fatalf("Primaries: (%d, %v): the file is a good file", len(refs), err)
	}
	chk, d, err := b.Checker("", fixedNow, nil)
	if chk != nil || d != nil || !errors.Is(err, handoff.ErrConfig) || !strings.Contains(err.Error(), late.fp) {
		t.Fatalf("Checker = (%v, %v, %v), want no checker and an ErrConfig that names the fingerprint", chk, d, err)
	}
	if errors.Is(err, openpgp.ErrKeyring) || errors.Is(err, bundle.ErrNoKeyring) {
		t.Errorf("error %v is taken for a fault of the file", err)
	}
	// Before the clock it is fine.
	early := newMemPrimary(t, "A", vectorNow.AddDate(0, 0, -1), true)
	b2, _ := bundleWith(t, memSet(7, []memPrimary{early}))
	if chk, _, err := b2.Checker("", fixedNow, nil); err != nil || chk == nil {
		t.Errorf("a primary before the clock: (%v, %v)", chk, err)
	}
}

// A test primary and a real primary are never in one file.
func TestAKeyringThatMixesTestAndRealPrimariesIsRefused(t *testing.T) {
	test := newMemPrimary(t, "A", memTime, true)
	real := newMemPrimary(t, "B", memTime, false)
	otherReal := newMemPrimary(t, "B", memTime, false)
	b, _ := bundleWith(t, memSet(7, []memPrimary{test, real}))
	if refs, _, err := b.Primaries(); refs != nil || !errors.Is(err, openpgp.ErrKeyringForm) || !strings.Contains(err.Error(), "mixes test and real primaries") {
		t.Errorf("a mix: (%v, %v)", refs, err)
	}
	// The negative control: two real primaries are one kind.
	b2, _ := bundleWith(t, memSet(7, []memPrimary{newMemPrimary(t, "A", memTime, false), otherReal}))
	if refs, _, err := b2.Primaries(); err != nil || len(refs) != 2 {
		t.Errorf("two real primaries: (%d, %v)", len(refs), err)
	}
}

// ---- Primaries and Checker on bundles that Open did not make ----------------------------------------

func TestPrimariesOfANilClosedOrHandMadeBundleIsErrBundle(t *testing.T) {
	var nilBundle *bundle.Bundle
	closed, _ := bundleWith(t, trustAB(t, 7))
	_ = closed.Close()
	for name, b := range map[string]*bundle.Bundle{"nil": nilBundle, "zero": {}, "closed": closed} {
		refs, set, err := b.Primaries()
		if refs != nil || set != (bundle.TrustSet{}) || !errors.Is(err, bundle.ErrBundle) {
			t.Errorf("%s: (%v, %+v, %v), want ErrBundle", name, refs, set, err)
		}
	}
}

// A list that gives one fingerprint to two entries is a list that no host can use: the file cannot be held to it.
// The fault is the list's, found by the reader of the list before the keyring file is asked for: the error is a
// malformed-JSON error of the list, not of the kind ErrPrimaries and not an error of the keyring file; it names the
// list and the place of the second entry and the two labels; no primary comes with it.
func TestAListThatPinsOneFingerprintTwiceIsAnErrorOfTheListNotOfTheKeyringFile(t *testing.T) {
	list := bytes.Replace(trustAB(t, 7)["root-list.json"], []byte("c4288657012230588b51fa66e0831b9c6e084f39"), []byte("6df387de63525c9dc0ec1174bd138d2c4889b79b"), 1)
	if bytes.Equal(list, trustAB(t, 7)["root-list.json"]) {
		t.Fatal("the list was not changed")
	}
	b, _ := bundleWith(t, merge(trustAB(t, 7), tree{"root-list.json": list}))
	refs, set, err := b.Primaries()
	if refs != nil || set != (bundle.TrustSet{}) || err == nil {
		t.Fatalf("(%v, %+v, %v), want an error and nothing else", refs, set, err)
	}
	if !strings.HasPrefix(err.Error(), "bundle: the newest trust set "+setDir+": root-list.json: malformed JSON: ") || !strings.Contains(err.Error(), "the entries with the labels A and B have the same one") || !printableText(err.Error()) {
		t.Errorf("error text = %q", err.Error())
	}
	if errors.Is(err, bundle.ErrPrimaries) || errors.Is(err, openpgp.ErrKeyring) || !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("kind: ErrPrimaries=%v ErrKeyring=%v ErrMalformed=%v, want only the last", errors.Is(err, bundle.ErrPrimaries), errors.Is(err, openpgp.ErrKeyring), errors.Is(err, strictjson.ErrMalformed))
	}
	if chk, _, cerr := b.Checker("", fixedNow, nil); chk != nil || cerr == nil || cerr.Error() != err.Error() {
		t.Errorf("Checker = (%v, %v)", chk, cerr)
	}
}

// Which requests get the primaries: no delegation, and a delegation of the type openpgp-subkey; never a delegation of
// the type x509-intermediate or ssh-ca-key, beside which the checker refuses them. The test reads the effect: a request
// whose back-signature is missing is refused at check 5 by a checker that holds the primaries, and is not judged
// (the error of a checker with none) by one that does not. A keyring file that is bad or missing is an error only
// when the checker is to be given the primaries.
func TestTheCheckerIsGivenThePrimariesByTheTypeOfTheDelegation(t *testing.T) {
	extra := tree{
		"want/roots/pgp-root.yaml":       []byte("version: 1\nkind: openpgp\ntest: true\n"),
		"want/roots/ssh-root.yaml":       []byte("version: 1\nkind: ssh\ntest: true\n"),
		"want/delegations/pgp-sign.yaml": []byte("version: 1\ntype: openpgp-subkey\nroot: pgp-root\ncapability: sign\n"),
		"want/delegations/ssh-user.yaml": []byte("version: 1\ntype: ssh-ca-key\nroot: ssh-root\nuse: user\n"),
	}
	stem, request := requestCase(t, "pgp-backsig-missing")
	states := map[string][]byte{"good": keyringOf(t, "a", "b"), "missing": nil, "swapped": keyringOf(t, "b", "a")}
	for _, delegation := range []struct {
		name       string
		takesFile  bool
		hasPrimary bool
	}{
		{"", true, true},
		{"pgp-sign", true, true},
		{delegationName, false, false},
		{"ssh-user", false, false},
	} {
		for state, file := range states {
			t.Run("delegation="+delegation.name+"/keyring="+state, func(t *testing.T) {
				set := trustAB(t, 7)
				if file == nil {
					delete(set, keyringName)
				} else {
					set[keyringName] = file
				}
				files := merge(withoutPrefix(baseBundle(t), "trust/"), extra, request, inSet(setDir, set))
				b := openBundle(t, makeBundle(t, files))
				chk, d, err := b.Checker(delegation.name, fixedNow, nil)
				if delegation.takesFile && state != "good" {
					if chk != nil || d != nil || err == nil {
						t.Fatalf("(%v, %v, %v), want no checker and an error", chk, d, err)
					}
					if (state == "missing") != errors.Is(err, bundle.ErrNoKeyring) || (state == "swapped") != errors.Is(err, openpgp.ErrKeyringPrimaries) {
						t.Errorf("error %v: wrong kind for a %s keyring", err, state)
					}
					return
				}
				if err != nil || chk == nil {
					t.Fatalf("(%v, %v, %v), want a checker", chk, d, err)
				}
				req, err := b.Request(stem)
				if err != nil {
					t.Fatal(err)
				}
				v, err := chk.Check(t.Context(), req)
				if delegation.hasPrimary {
					if err != nil || !v.Refused() || v.Code != handoff.CodePossessionInvalid {
						t.Errorf("a checker that holds the primaries gave (%+v, %v), want a refusal at check 5 with possession-invalid", v, err)
					}
				} else if !errors.Is(err, handoff.ErrNoPrimaries) {
					t.Errorf("a checker that holds none gave (%+v, %v), want an error that wraps ErrNoPrimaries", v, err)
				}
			})
		}
	}
}

// Each primary has its own key, its own creation time and its own fingerprint, taken from its own key packet: the
// creation times differ here, so a primary that is given the time or the key of another is seen.
func TestEachPrimaryIsGivenItsOwnKeyAndCreationTime(t *testing.T) {
	times := []time.Time{memTime, memTime.AddDate(0, 0, 3).Add(7 * time.Second), memTime.AddDate(0, -1, 0)}
	var ps []memPrimary
	for i, at := range times {
		ps = append(ps, newMemPrimary(t, string(rune('A'+i)), at, true))
	}
	b, _ := bundleWith(t, memSet(7, ps))
	refs, _, err := b.Primaries()
	if err != nil || len(refs) != 3 {
		t.Fatalf("(%d, %v)", len(refs), err)
	}
	second := ringRefs(t, memKeyring(ps))
	for i := range refs {
		if !refs[i].Created.Equal(times[i]) || refs[i].Fingerprint != ps[i].fp || !sameKey(refs[i].Key, second[i].Key) {
			t.Errorf("primary %d: created %v (want %v), fingerprint %s (want %s)", i, refs[i].Created, times[i], refs[i].Fingerprint, ps[i].fp)
		}
		for j := range refs {
			if i != j && sameKey(refs[i].Key, refs[j].Key) {
				t.Errorf("primaries %d and %d have one key", i, j)
			}
		}
	}
}
