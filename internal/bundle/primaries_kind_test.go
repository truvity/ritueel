//go:build linux || darwin

package bundle_test

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/testrepo"
)

// Every fault of the OpenPGP primaries of the newest trust set is one error kind, bundle.ErrPrimaries, so that a
// caller (the command check request) asks for one kind and finds all of them. The faults of the set that Roots also
// finds, a bad list, a bad CA bundle or no trust set, are not of this kind.

// replaceOnce changes the first occurrence of old in the file and fails when there is none.
func replaceOnce(t testing.TB, file []byte, old, new string) []byte {
	t.Helper()
	if !bytes.Contains(file, []byte(old)) {
		t.Fatalf("%q is not in the file", old)
	}
	return bytes.Replace(file, []byte(old), []byte(new), 1)
}

// withList is the files of trustAB with the root list replaced by one made from it.
func withList(t testing.TB, change func(list []byte) []byte) tree {
	t.Helper()
	set := trustAB(t, 7)
	set["root-list.json"] = change(set["root-list.json"])
	return set
}

const (
	fingerprintA = "6df387de63525c9dc0ec1174bd138d2c4889b79b"
	fingerprintB = "c4288657012230588b51fa66e0831b9c6e084f39"
)

// primariesFaults are the faults of the primaries, each as the files of a trust set and, for a keyring file that is
// not a plain file, the way to put it in place.
func primariesFaults(t *testing.T) []struct {
	name string
	set  tree
	put  func(t *testing.T, at string) // places a keyring file that is not a plain file; set has none then
	want string                        // a word in the text
} {
	t.Helper()
	a, b, z := keyringOf(t, "a"), keyringOf(t, "b"), keyringOf(t, "z")
	armour := []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n")
	two := trustAB(t, 7)
	return []struct {
		name string
		set  tree
		put  func(t *testing.T, at string)
		want string
	}{
		{"no keyring file", without(two, keyringName), nil, "holds no keyring.gpg"},
		{"a link", without(two, keyringName), func(t *testing.T, at string) {
			mustSymlink(t, "real.gpg", at)
			mustWrite(t, filepath.Join(filepath.Dir(at), "real.gpg"), keyringOf(t, "a", "b"))
		}, "refused"},
		{"a dangling link", without(two, keyringName), func(t *testing.T, at string) { mustSymlink(t, "nowhere.gpg", at) }, "refused"},
		{"a folder", without(two, keyringName), func(t *testing.T, at string) {
			if err := os.Mkdir(at, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "refused"},
		{"a file over what fsx reads", without(two, keyringName), func(t *testing.T, at string) { mustWrite(t, at, make8MiBPlusOne()) }, "refused"},
		{"an empty file", merge(two, tree{keyringName: nil}), nil, "empty"},
		{"armour", merge(two, tree{keyringName: armour}), nil, "armour"},
		{"text", merge(two, tree{keyringName: []byte("hello\n")}), nil, "refused"},
		{"b then a", merge(two, tree{keyringName: append(bytes.Clone(b), a...)}), nil, "out of order"},
		{"a alone", merge(two, tree{keyringName: a}), nil, "missing"},
		{"a, b and z", merge(two, tree{keyringName: bytes.Join([][]byte{a, b, z}, nil)}), nil, "one too many"},
		{"a twice", merge(two, tree{keyringName: append(bytes.Clone(a), a...)}), nil, "refused"},
		{"a keyring file and a list that pins none", func() tree {
			ps := memPrimaries(t, 2)
			return tree{"root-list.json": memList(7, ps, map[string]bool{"A": true, "B": true}), "ca-bundle.pem": memBundlePEM(7, ps), keyringName: memKeyring(ps)}
		}(), nil, "pins no OpenPGP primary"},
	}
}

func mustSymlink(t *testing.T, target, at string) {
	t.Helper()
	if err := os.Symlink(target, at); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, at string, data []byte) {
	t.Helper()
	if err := os.WriteFile(at, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Every error of Primaries that comes from the primaries is of the kind ErrPrimaries, with no primary and no set
// beside it, in one plain line. Checker gives the same error, except when it does not read the file (a list that
// pins none).
func TestEveryFaultOfThePrimariesIsOfTheKindErrPrimaries(t *testing.T) {
	for _, tc := range primariesFaults(t) {
		t.Run(tc.name, func(t *testing.T) {
			b, dir := bundleWith(t, tc.set)
			if tc.put != nil {
				tc.put(t, filepath.Join(dir, filepath.FromSlash(keyringPathInSet)))
			}
			before := digestTree(t, dir)
			refs, set, err := b.Primaries()
			if err == nil || refs != nil || set != (bundle.TrustSet{}) {
				t.Fatalf("Primaries = (%v, %+v, %v), want an error and nothing else", refs, set, err)
			}
			if !errors.Is(err, bundle.ErrPrimaries) {
				t.Errorf("error %q is not of the kind ErrPrimaries", err)
			}
			if errors.Is(err, bundle.ErrBundle) || errors.Is(err, bundle.ErrNoTrustSet) || errors.Is(err, bundle.ErrNoSettings) {
				t.Errorf("error %q is also of another kind of the bundle", err)
			}
			// Only a missing file is an error of the kind ErrNoKeyring, and only it wraps the error of the read.
			if missing := tc.want == "holds no keyring.gpg"; errors.Is(err, bundle.ErrNoKeyring) != missing || errors.Is(err, fs.ErrNotExist) != missing {
				t.Errorf("error %q: ErrNoKeyring=%v ErrNotExist=%v, want both %v", err, errors.Is(err, bundle.ErrNoKeyring), errors.Is(err, fs.ErrNotExist), missing)
			}
			text := err.Error()
			if text == "" || !printableText(text) || strings.Contains(text, "\n") || len(text) > 600 || !strings.Contains(text, tc.want) {
				t.Errorf("error text = %q, want one printable line with %q in it", text, tc.want)
			}
			if !strings.Contains(text, setDir) {
				t.Errorf("error text = %q, want the newest trust set %s named", text, setDir)
			}
			if strings.Contains(tc.name, "list that pins none") {
				// Checker does not read the file of a set that pins none: it makes the checker.
				if chk, _, cerr := b.Checker("", fixedNow, nil); cerr != nil || chk == nil {
					t.Errorf("Checker = (%v, %v), want a checker", chk, cerr)
				}
			} else {
				chk, d, cerr := b.Checker("", fixedNow, nil)
				if chk != nil || d != nil || cerr == nil || !errors.Is(cerr, bundle.ErrPrimaries) || cerr.Error() != text {
					t.Errorf("Checker = (%v, %v, %v), want no checker and the error %q of the kind ErrPrimaries", chk, d, cerr, text)
				}
			}
			sameDigest(t, "a read", before, digestTree(t, dir))
		})
	}
}

// The faults that are not of the primaries are not of the kind: the list, the CA bundle, no trust set, a closed
// bundle, and a primary that was created after the clock (a fault of the configuration of the clock).
func TestTheFaultsOfTheSetThatAreNotOfThePrimariesAreNotOfTheKindErrPrimaries(t *testing.T) {
	ps := memPrimaries(t, 2)
	late := newMemPrimary(t, "A", vectorNow.AddDate(0, 0, 1), true)
	closed, _ := bundleWith(t, trustAB(t, 7))
	_ = closed.Close()
	noSet, _ := bundleWith(t, nil)
	for _, tc := range []struct {
		name string
		call func() error
		want error
	}{
		{"a list that is not JSON", func() error {
			b, _ := bundleWith(t, merge(trustAB(t, 7), tree{"root-list.json": []byte("{")}))
			_, _, err := b.Primaries()
			return err
		}, nil},
		{"a bad CA bundle", func() error {
			b, _ := bundleWith(t, merge(trustAB(t, 7), tree{"ca-bundle.pem": []byte("not a bundle")}))
			_, _, err := b.Primaries()
			return err
		}, nil},
		{"a CA bundle of another sequence", func() error {
			b, _ := bundleWith(t, merge(trustAB(t, 7), tree{"ca-bundle.pem": memBundlePEM(8, ps)}))
			_, _, err := b.Primaries()
			return err
		}, nil},
		{"a label twice (the list is refused before the reader)", func() error {
			b, _ := bundleWith(t, withList(t, func(l []byte) []byte { return replaceOnce(t, l, `"label":"B"`, `"label":"A"`) }))
			_, _, err := b.Primaries()
			return err
		}, nil},
		{"one fingerprint on two entries (the list is refused before the reader)", func() error {
			b, _ := bundleWith(t, withList(t, func(l []byte) []byte { return replaceOnce(t, l, fingerprintB, fingerprintA) }))
			_, _, err := b.Primaries()
			return err
		}, strictjson.ErrMalformed},
		{"a label that is not a capital letter", func() error {
			b, _ := bundleWith(t, withList(t, func(l []byte) []byte { return replaceOnce(t, l, `"label":"B"`, `"label":"b"`) }))
			_, _, err := b.Primaries()
			return err
		}, nil},
		{"a fingerprint that is not 40 hexadecimal digits", func() error {
			b, _ := bundleWith(t, withList(t, func(l []byte) []byte { return replaceOnce(t, l, fingerprintB, "ABC") }))
			_, _, err := b.Primaries()
			return err
		}, nil},
		{"no root list", func() error {
			b, _ := bundleWith(t, without(trustAB(t, 7), "root-list.json"))
			_, _, err := b.Primaries()
			return err
		}, nil},
		{"no trust set", func() error { _, _, err := noSet.Primaries(); return err }, bundle.ErrNoTrustSet},
		{"a closed bundle", func() error { _, _, err := closed.Primaries(); return err }, bundle.ErrBundle},
		{"a primary created after the clock (Checker)", func() error {
			b, _ := bundleWith(t, memSet(7, []memPrimary{late}))
			_, _, err := b.Checker("", fixedNow, nil)
			return err
		}, handoff.ErrConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("no error")
			}
			if errors.Is(err, bundle.ErrPrimaries) || errors.Is(err, bundle.ErrNoKeyring) {
				t.Errorf("error %q is of the kind of the primaries", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("error %q does not wrap %v", err, tc.want)
			}
		})
	}
}

// ErrNoKeyring is a kind of its own, and it is also of the kind ErrPrimaries; no other error of the bundle is.
func TestAMissingKeyringFileIsBothErrNoKeyringAndErrPrimaries(t *testing.T) {
	b, _ := bundleWith(t, without(trustAB(t, 7), keyringName))
	_, _, err := b.Primaries()
	if !errors.Is(err, bundle.ErrNoKeyring) || !errors.Is(err, bundle.ErrPrimaries) {
		t.Errorf("error %v: want both ErrNoKeyring and ErrPrimaries", err)
	}
	// The kind does not match by its text: another error with the same words is not of the kind.
	if errors.Is(errors.New(bundle.ErrPrimaries.Error()), bundle.ErrPrimaries) {
		t.Error("an error with the same words is of the kind")
	}
	if errors.Is(bundle.ErrPrimaries, bundle.ErrNoKeyring) || errors.Is(bundle.ErrNoKeyring, bundle.ErrPrimaries) {
		t.Error("the two exported kinds are taken for one another")
	}
}

// exportedErrors are the names of the exported variables Err* that the non-test files of a package declare.
func exportedErrors(t *testing.T, dir string, prefix string) []string {
	t.Helper()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				for _, n := range s.(*ast.ValueSpec).Names {
					if n.IsExported() && strings.HasPrefix(n.Name, prefix) {
						out = append(out, n.Name)
					}
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// Every error kind that the bundle or the keyring reader exports is classified here, so that a new kind that is not
// classified fails this test: it is either a fault of the primaries (and then it is of the kind ErrPrimaries when it
// comes through Primaries) or it is not.
func TestEveryErrorKindOfThePrimariesPathIsClassified(t *testing.T) {
	// The kinds of package bundle: those of the primaries and the others.
	primaries := []string{"ErrNoKeyring", "ErrPrimaries"}
	others := []string{"ErrBundle", "ErrNoSettings", "ErrNoTrustSet"}
	got := exportedErrors(t, testrepo.Path(t, "internal", "bundle"), "Err")
	want := slices.Sorted(slices.Values(append(slices.Clone(primaries), others...)))
	if !slices.Equal(got, want) {
		t.Fatalf("the exported kinds of package bundle are %v, the test knows %v: a new kind must be classified here and in the command's test", got, want)
	}
	// The kinds of the keyring reader that a refusal of the file can carry. ErrParams is the kind of a refused entry.
	reader := exportedErrors(t, testrepo.Path(t, "internal", "openpgp"), "ErrKeyring")
	if !slices.Equal(reader, []string{"ErrKeyring", "ErrKeyringForm", "ErrKeyringPrimaries"}) {
		t.Fatalf("the kinds of the keyring reader are %v: a new kind must be given a case in TestEveryFaultOfThePrimariesIsOfTheKindErrPrimaries", reader)
	}
	// Each one is met by a fault of the table, and the error that carries it is of the kind ErrPrimaries.
	met := map[error]bool{}
	for _, tc := range primariesFaults(t) {
		b, dir := bundleWith(t, tc.set)
		if tc.put != nil {
			tc.put(t, filepath.Join(dir, filepath.FromSlash(keyringPathInSet)))
		}
		_, _, err := b.Primaries()
		for _, k := range []error{openpgp.ErrKeyring, openpgp.ErrKeyringForm, openpgp.ErrKeyringPrimaries, openpgp.ErrParams, bundle.ErrNoKeyring} {
			if errors.Is(err, k) {
				met[k] = true
				if !errors.Is(err, bundle.ErrPrimaries) {
					t.Errorf("%s carries %v and is not of the kind ErrPrimaries", tc.name, k)
				}
			}
		}
	}
	for _, k := range []error{openpgp.ErrKeyring, openpgp.ErrKeyringForm, openpgp.ErrKeyringPrimaries, bundle.ErrNoKeyring} {
		if !met[k] {
			t.Errorf("no fault of the table carries %v", k)
		}
	}
	// The list is held to its rules (a label twice, a label that is not a capital letter, a fingerprint of another
	// form) by its own reader before the keyring reader is asked, so no fault of the table is an ErrParams of the
	// keyring reader.
	if met[openpgp.ErrParams] {
		t.Error("a fault of the table is an ErrParams of the keyring reader: add the case to the command's test")
	}
}

// listRepeatText is the error of the bundle for a root list in which two entries have one openpgp_fingerprint: the
// reader of the list refuses the list, naming the place of the second entry and the two labels.
func listRepeatText(first, second string, at int) string {
	return "bundle: the newest trust set " + setDir + ": root-list.json: malformed JSON: $.roots[" + strconv.Itoa(at) + "].openpgp_fingerprint: the fingerprint appears twice: the entries with the labels " + first + " and " + second + " have the same one"
}

// One fingerprint on two entries is a fault of the list, found by the reader of the list: the error is not of the
// kind ErrPrimaries (the list is refused before the primaries are asked for), it is a malformed-JSON error of the list,
// it names the newest trust set, the file and the two labels, and the fingerprint itself is not in it. Exact text.
func TestAListThatPinsOneFingerprintTwiceIsAFaultOfTheListNamedByTheTwoLabels(t *testing.T) {
	want := listRepeatText("A", "B", 1)
	b, dir := bundleWith(t, withList(t, func(l []byte) []byte { return replaceOnce(t, l, fingerprintB, fingerprintA) }))
	before := digestTree(t, dir)
	refs, set, err := b.Primaries()
	if refs != nil || set != (bundle.TrustSet{}) || err == nil || err.Error() != want {
		t.Fatalf("(%v, %+v, %v), want an error with the text %q", refs, set, err, want)
	}
	if !errors.Is(err, strictjson.ErrMalformed) || errors.Is(err, bundle.ErrPrimaries) || errors.Is(err, openpgp.ErrKeyring) || errors.Is(err, openpgp.ErrParams) || errors.Is(err, bundle.ErrNoKeyring) {
		t.Errorf("kind of %q: want the malformed-JSON error of the list and no kind of the primaries", err)
	}
	if strings.Contains(err.Error(), fingerprintA) || strings.Contains(err.Error(), "keyring.gpg") {
		t.Errorf("the sentence names the fingerprint or the file: %q", err)
	}
	if _, _, cerr := b.Checker("", fixedNow, nil); cerr == nil || cerr.Error() != want {
		t.Errorf("Checker: %v, want the same sentence", cerr)
	}
	if _, _, cerr := b.Roots(); cerr == nil || cerr.Error() != want {
		t.Errorf("Roots: %v, want the same sentence", cerr)
	}
	// The text of the sentence does not depend on the keyring file: a missing file and a file of garbage give it too.
	for name, file := range map[string][]byte{"no file": nil, "garbage": []byte("garbage")} {
		set := withList(t, func(l []byte) []byte { return replaceOnce(t, l, fingerprintB, fingerprintA) })
		if file == nil {
			delete(set, keyringName)
		} else {
			set[keyringName] = file
		}
		b2, _ := bundleWith(t, set)
		if _, _, err := b2.Primaries(); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
	}
	sameDigest(t, "a read", before, digestTree(t, dir))
}

// The repeat is found whatever the places of the two entries: first and second, first and last of 16 and of 26, a
// fingerprint on three entries (the first pair is named), and two repeats (the first one met is named). The error
// names the place of the second entry of the pair.
func TestTheRepeatedFingerprintNamesTheFirstPairWhereverTheEntriesAre(t *testing.T) {
	ps := memPrimaries(t, handoff.MaxPrimaries)
	for _, tc := range []struct {
		name  string
		copy  map[int]int // entry i takes the fingerprint of entry j
		n     int
		wantA string
		wantB string
		at    int
	}{
		{"first and second of two", map[int]int{1: 0}, 2, "A", "B", 1},
		{"first and last of sixteen", map[int]int{15: 0}, 16, "A", "P", 15},
		{"second and last of sixteen", map[int]int{15: 1}, 16, "B", "P", 15},
		{"last two of sixteen", map[int]int{15: 14}, 16, "O", "P", 15},
		{"first and last of the most entries", map[int]int{25: 0}, 26, "A", "Z", 25},
		{"second and last of the most entries", map[int]int{25: 1}, 26, "B", "Z", 25},
		{"last two of the most entries", map[int]int{25: 24}, 26, "Y", "Z", 25},
		{"two in the middle of the most entries", map[int]int{13: 12}, 26, "M", "N", 13},
		{"one fingerprint on three entries", map[int]int{1: 0, 2: 0}, 3, "A", "B", 1},
		{"two repeats: the first met is named", map[int]int{4: 1, 2: 0}, 6, "A", "C", 2},
		{"two repeats, the later pair first in the list", map[int]int{5: 3, 3: 2}, 6, "C", "D", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := slices.Clone(ps[:tc.n])
			for i, j := range tc.copy {
				roots[i].fp = roots[j].fp
			}
			b, _ := bundleWith(t, memSet(7, roots))
			_, _, err := b.Primaries()
			if want := listRepeatText(tc.wantA, tc.wantB, tc.at); err == nil || err.Error() != want || errors.Is(err, bundle.ErrPrimaries) {
				t.Errorf("error %v, want %q", err, want)
			}
		})
	}
}

// A repeat among entries that have no fingerprint is no repeat: only the entries that pin one are held to it.
func TestEntriesWithNoFingerprintAreNotARepeat(t *testing.T) {
	ps := memPrimaries(t, 3)
	b, _ := bundleWith(t, tree{
		"root-list.json": memList(7, ps, map[string]bool{"B": true, "C": true}),
		"ca-bundle.pem":  memBundlePEM(7, ps),
		keyringName:      ps[0].cert,
	})
	refs, _, err := b.Primaries()
	if err != nil || len(refs) != 1 {
		t.Errorf("(%d, %v), want one primary", len(refs), err)
	}
}

// A list of the most entries (26, one for each label A to Z) is read: with a repeat the reader of the list refuses it
// for the repeat, and with none its primaries are taken. A list of more entries than that is no list of this program:
// a label is one capital letter and is not given twice, so the reader of the list refuses it before the primaries are
// asked for, and the error is not of the kind ErrPrimaries. The count of the primaries is then a second guard that no
// bundle reaches (it is held on its own in the tests of the package).
func TestAListOfTheMostEntriesIsReadAndMoreThanTheMostIsRefusedByTheReaderOfTheList(t *testing.T) {
	ps := memPrimaries(t, handoff.MaxPrimaries)
	repeated := slices.Clone(ps)
	repeated[len(repeated)-1].fp = repeated[0].fp
	b, _ := bundleWith(t, memSet(7, repeated))
	_, _, err := b.Primaries()
	if want := listRepeatText("A", "Z", handoff.MaxPrimaries-1); err == nil || err.Error() != want || errors.Is(err, bundle.ErrPrimaries) {
		t.Errorf("%d entries with a repeat: %v, want %q", handoff.MaxPrimaries, err, want)
	}
	b, _ = bundleWith(t, memSet(7, ps))
	if refs, _, err := b.Primaries(); err != nil || len(refs) != handoff.MaxPrimaries {
		t.Errorf("%d entries with no repeat: (%d, %v), want them all", handoff.MaxPrimaries, len(refs), err)
	}
	// One entry more: the label of the 27th is not a capital letter, or it is a label that the list has already.
	extra := newMemPrimary(t, "A", memTime, true)
	again := append(slices.Clone(ps), extra)
	extra.label = "["
	more := append(slices.Clone(ps), extra)
	for name, roots := range map[string][]memPrimary{"a label that is not a capital letter": more, "a label twice": again} {
		set := memSet(7, roots)
		bb, _ := bundleWith(t, set)
		for call, f := range map[string]func() error{
			"Primaries": func() error { _, _, err := bb.Primaries(); return err },
			"Roots":     func() error { _, _, err := bb.Roots(); return err },
			"Checker":   func() error { _, _, err := bb.Checker("", fixedNow, nil); return err },
		} {
			err := f()
			if err == nil || errors.Is(err, bundle.ErrPrimaries) || errors.Is(err, bundle.ErrNoKeyring) || !strings.Contains(err.Error(), "root-list.json") {
				t.Errorf("%d entries, %s, %s: %v, want a fault of the list and not of the primaries", handoff.MaxPrimaries+1, name, call, err)
			}
		}
	}
}
