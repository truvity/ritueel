package bundle_test

import (
	"bytes"
	"crypto"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/wanted"
)

func openBundle(t testing.TB, dir string) *bundle.Bundle {
	t.Helper()
	b, err := bundle.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestOpenReadsTheSettingsOfAFolder(t *testing.T) {
	dir := makeBundle(t, baseBundle(t))
	b := openBundle(t, dir)
	s := b.Settings()
	if !s.Valid() || s.Name != "Example" || s.File.Path != wanted.SettingsPath || string(s.File.Data) != settingsText(developmentStores) {
		t.Errorf("settings %+v", s)
	}
}

func TestAFolderWithNoSettingsIsNotAWorkstationBundle(t *testing.T) {
	dir := t.TempDir()
	b, err := bundle.Open(dir)
	if b != nil || !errors.Is(err, bundle.ErrNoSettings) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("bundle %v, error %v", b, err)
	}
	// The text says so, and holds nothing from outside.
	if !strings.Contains(err.Error(), "not a bundle on a workstation") {
		t.Errorf("error text %q", err.Error())
	}
	// A bundle of a stick: the history and the trust sets, with no wanted files.
	dir = makeBundle(t, inSet("7-3fa9c1d2", trustAB(t, 7)))
	if _, err := bundle.Open(dir); !errors.Is(err, bundle.ErrNoSettings) {
		t.Errorf("a folder with trust sets and no ritueel.yaml: %v", err)
	}
}

func TestASettingsFileThatFailsItsReaderIsItsError(t *testing.T) {
	for name, text := range map[string]string{
		"a refusal":      strings.Replace(settingsText(productionStores), "require_name_constraints: true", "require_name_constraints: false", 1),
		"two documents":  settingsText(productionStores) + "---\n" + settingsText(productionStores),
		"an empty file":  "",
		"a bad byte":     "version: 1\n\xff\n",
		"not a mapping":  "- a\n",
		"a long comment": settingsText(productionStores) + "# " + strings.Repeat("x", wanted.MaxBytes),
	} {
		t.Run(name, func(t *testing.T) {
			dir := makeBundle(t, tree{"ritueel.yaml": []byte(text)})
			b, err := bundle.Open(dir)
			if b != nil || err == nil {
				t.Fatalf("Open accepts: %v", b)
			}
			if errors.Is(err, bundle.ErrNoSettings) {
				t.Errorf("a file that is there but wrong is reported as missing: %v", err)
			}
			var e *wanted.Error
			if !errors.As(err, &e) || e.Path != "ritueel.yaml" {
				t.Errorf("error %T %v", err, err)
			}
		})
	}
}

func TestOpenFollowsNoLinkAndTakesNothingButAFolder(t *testing.T) {
	real := makeBundle(t, baseBundle(t))
	parent := t.TempDir()
	// The folder as a link.
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if b, err := bundle.Open(link); b != nil || err == nil {
		t.Errorf("a link as the folder: %v %v", b, err)
	}
	// A file as the folder, a missing folder, an empty name.
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"a file": file, "a missing folder": filepath.Join(parent, "nothing"), "an empty name": ""} {
		if b, err := bundle.Open(path); b != nil || err == nil {
			t.Errorf("%s: %v %v", name, b, err)
		}
	}
	// ritueel.yaml as a link, as a folder and as a pipe.
	for name, make := range map[string]func(dir string) error{
		"a link": func(dir string) error {
			return os.Symlink(filepath.Join(real, "ritueel.yaml"), filepath.Join(dir, "ritueel.yaml"))
		},
		"a folder": func(dir string) error { return os.Mkdir(filepath.Join(dir, "ritueel.yaml"), 0o755) },
	} {
		dir := t.TempDir()
		if err := make(dir); err != nil {
			t.Fatal(err)
		}
		b, err := bundle.Open(dir)
		if b != nil || err == nil || errors.Is(err, bundle.ErrNoSettings) {
			t.Errorf("ritueel.yaml as %s: %v %v", name, b, err)
		}
	}
}

func TestCloseIsSafeOnNilAndTwice(t *testing.T) {
	var none *bundle.Bundle
	if err := none.Close(); err != nil {
		t.Errorf("Close on nil: %v", err)
	}
	b := openBundle(t, makeBundle(t, baseBundle(t)))
	if err := b.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// A closed bundle refuses what needs the folder.
	if _, err := b.Request("x509-software-valid"); !errors.Is(err, bundle.ErrBundle) {
		t.Errorf("Request after Close: %v", err)
	}
	if _, _, err := b.Roots(); !errors.Is(err, bundle.ErrBundle) {
		t.Errorf("Roots after Close: %v", err)
	}
	if _, _, err := b.Checker("", fixedNow, nil); !errors.Is(err, bundle.ErrBundle) {
		t.Errorf("Checker after Close: %v", err)
	}
}

func TestANilOrHandMadeBundleRefusesEveryCallAndNeverPanics(t *testing.T) {
	for name, b := range map[string]*bundle.Bundle{"nil": nil, "zero": {}, "new": new(bundle.Bundle)} {
		t.Run(name, func(t *testing.T) {
			if got := b.Settings(); got != nil {
				t.Errorf("Settings() = %v", got)
			}
			if r, err := b.Request("x509-software-valid"); r != nil || !errors.Is(err, bundle.ErrBundle) {
				t.Errorf("Request: %v %v", r, err)
			}
			if refs, set, err := b.Roots(); refs != nil || set != (bundle.TrustSet{}) || !errors.Is(err, bundle.ErrBundle) {
				t.Errorf("Roots: %v %v %v", refs, set, err)
			}
			for _, d := range []string{"", delegationName} {
				if c, dl, err := b.Checker(d, fixedNow, nil); c != nil || dl != nil || !errors.Is(err, bundle.ErrBundle) {
					t.Errorf("Checker(%q): %v %v %v", d, c, dl, err)
				}
			}
			if err := b.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

func TestRequestLoadsTheFilesOfOneStem(t *testing.T) {
	files := merge(baseBundle(t), requestFiles(t, "x509-software-valid"))
	// An answer file and a file of another request are not read.
	files["requests/x509-software-valid/x509-software-valid.result.json"] = []byte("not json at all")
	files["requests/other/other.proof.json"] = []byte("{")
	b := openBundle(t, makeBundle(t, files))
	r, err := b.Request("x509-software-valid")
	if err != nil {
		t.Fatal(err)
	}
	if r.Stem != "x509-software-valid" || len(r.Files[handoff.FileProof]) == 0 || len(r.Files[handoff.FileCSR]) == 0 {
		t.Errorf("request %+v", r)
	}
	if _, ok := r.Files["result.json"]; ok {
		t.Error("an answer file was read")
	}
}

func TestRequestRefusesWhatLoadRequestRefuses(t *testing.T) {
	b := openBundle(t, makeBundle(t, merge(baseBundle(t), requestFiles(t, "x509-software-valid"))))
	for _, stem := range []string{"", "A", "a_b", "-a", "a/b", "../x509-software-valid", ".", "..", strings.Repeat("a", 64), "a b", "\u0430"} {
		r, err := b.Request(stem)
		if r != nil || !errors.Is(err, handoff.ErrLoad) {
			t.Errorf("stem %q: %v %v", stem, r, err)
		}
	}
	if r, err := b.Request("nothing"); r != nil || !errors.Is(err, handoff.ErrNoProof) {
		t.Errorf("a stem with no folder: %v %v", r, err)
	}
	// A proof file that is a link, and a request that is a link to a folder.
	dir := makeBundle(t, merge(baseBundle(t), requestFiles(t, "x509-software-valid")))
	if err := os.Remove(filepath.Join(dir, "requests/x509-software-valid/x509-software-valid.proof.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "ritueel.yaml"), filepath.Join(dir, "requests/x509-software-valid/x509-software-valid.proof.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "requests/x509-software-valid"), filepath.Join(dir, "requests/linked")); err != nil {
		t.Fatal(err)
	}
	b2 := openBundle(t, dir)
	if r, err := b2.Request("x509-software-valid"); r != nil || err == nil {
		t.Errorf("a proof file that is a link: %v %v", r, err)
	}
	if r, err := b2.Request("linked"); r != nil || err == nil {
		t.Errorf("a request folder that is a link: %v %v", r, err)
	}
}

// Roots: record 0006, rules 12 and 14; the newest trust set holds the certificates.

func TestRootsAreTheKeysOfTheNewestTrustSet(t *testing.T) {
	b := openBundle(t, makeBundle(t, baseBundle(t)))
	refs, set, err := b.Roots()
	if err != nil {
		t.Fatal(err)
	}
	if set != (bundle.TrustSet{Name: "7-3fa9c1d2", Number: 7}) {
		t.Errorf("set %+v", set)
	}
	want := testRoots(t)
	if len(refs) != 2 {
		t.Fatalf("%d roots", len(refs))
	}
	for i := range refs {
		if !bytes.Equal(refs[i].Subject, want[i].Subject) || !sameKey(refs[i].Key, want[i].Key) {
			t.Errorf("root %d is not the test root of the vectors", i)
		}
	}
	// The subjects are the names of the test roots A and B, in the order of the list.
	if !bytes.Contains(refs[0].Subject, []byte("Example Test Root A (TEST ONLY)")) || !bytes.Contains(refs[1].Subject, []byte("Example Test Root B (TEST ONLY)")) {
		t.Error("the subjects are not Root A and Root B")
	}
}

func TestTheNewestTrustSetIsTheLargestNumberAndNotTheLargestName(t *testing.T) {
	files := baseBundle(t)
	delete(files, "trust/7-3fa9c1d2/root-list.json")
	delete(files, "trust/7-3fa9c1d2/ca-bundle.pem")
	// 9 has two roots, 13 has one: the number 13 is newer than 9 although "9-" sorts after "13-" as text.
	files = merge(files, inSet("9-aaaaaaaa", trustAB(t, 9)), inSet("13-bbbbbbbb", trustA(t, 13)))
	b := openBundle(t, makeBundle(t, files))
	refs, set, err := b.Roots()
	if err != nil {
		t.Fatal(err)
	}
	if set.Number != 13 || set.Name != "13-bbbbbbbb" || len(refs) != 1 {
		t.Errorf("set %+v with %d roots", set, len(refs))
	}
	// And the same with the names in reverse.
	files = merge(baseBundle(t), inSet("100-bbbbbbbb", trustA(t, 100)), inSet("99-ffffffff", trustAB(t, 99)))
	b2 := openBundle(t, makeBundle(t, files))
	if refs, set, err := b2.Roots(); err != nil || set.Number != 100 || len(refs) != 1 {
		t.Errorf("100 against 99: %+v %d %v", set, len(refs), err)
	}
}

func TestNoTrustSetIsAnErrorThatSaysTheFirstApplyMakesOne(t *testing.T) {
	for name, files := range map[string]tree{
		"no trust folder":                {"ritueel.yaml": []byte(settingsText(productionStores))},
		"an empty trust set folder tree": {"ritueel.yaml": []byte(settingsText(productionStores)), "trust/readme.txt": []byte("x")},
		"only names that are no set": merge(tree{"ritueel.yaml": []byte(settingsText(productionStores))},
			inSet("07-aaaaaaaa", trustAB(t, 7)), inSet("7-AAAAAAAA", trustAB(t, 7)), inSet("7-aaa", trustAB(t, 7)), inSet("7-aaaaaaaaa", trustAB(t, 7)),
			inSet("0-aaaaaaaa", trustAB(t, 1)), inSet("-1-aaaaaaaa", trustAB(t, 1)), inSet("7-gaaaaaaa", trustAB(t, 7)), inSet("x", trustAB(t, 7)),
			inSet(".rt-aaaaaaaaaaa", trustAB(t, 7)), inSet(".RT-aaaaaaaaaaa", trustAB(t, 7)), inSet("7-aaaaaaaa.bak", trustAB(t, 7))),
	} {
		t.Run(name, func(t *testing.T) {
			dir := makeBundle(t, files)
			if name == "an empty trust set folder tree" {
				if err := os.MkdirAll(filepath.Join(dir, "trust"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			b := openBundle(t, dir)
			refs, set, err := b.Roots()
			if refs != nil || set != (bundle.TrustSet{}) || !errors.Is(err, bundle.ErrNoTrustSet) {
				t.Fatalf("%v %v %v", refs, set, err)
			}
			if !strings.Contains(err.Error(), "first apply") {
				t.Errorf("text %q", err.Error())
			}
		})
	}
	// An empty trust folder is no set either.
	dir := makeBundle(t, tree{"ritueel.yaml": []byte(settingsText(productionStores))})
	if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openBundle(t, dir).Roots(); !errors.Is(err, bundle.ErrNoTrustSet) {
		t.Errorf("an empty trust folder: %v", err)
	}
}

func TestANameThatIsNotATrustSetIsIgnoredAndALeftoverIsSkipped(t *testing.T) {
	files := merge(baseBundle(t),
		// Names of other forms, with a higher number or a bad content: none of them is a set.
		inSet("07-aaaaaaaa", trustAB(t, 99)), inSet("8-AAAAAAAA", trustAB(t, 8)), inSet("9-aaa", trustAB(t, 9)), inSet("1000-aaaaaaaaa", trustAB(t, 1000)),
		inSet(".rt-abcdefghijk", trustAB(t, 99)), inSet(".RT-abcdefghijk", trustAB(t, 99)),
		tree{"trust/20-cccccccc": nil}, // a file of a name that is a set name: see below
	)
	delete(files, "trust/20-cccccccc")
	dir := makeBundle(t, files)
	b := openBundle(t, dir)
	_, set, err := b.Roots()
	if err != nil || set.Number != 7 {
		t.Fatalf("set %+v, error %v", set, err)
	}
}

func TestTwoFoldersWithOneNumberAreAnError(t *testing.T) {
	// The pair is the newest.
	files := merge(baseBundle(t), inSet("13-aaaaaaaa", trustAB(t, 13)), inSet("13-bbbbbbbb", trustAB(t, 13)))
	b := openBundle(t, makeBundle(t, files))
	refs, set, err := b.Roots()
	if refs != nil || set != (bundle.TrustSet{}) || err == nil {
		t.Fatalf("%v %v %v", refs, set, err)
	}
	for _, w := range []string{"13", "13-aaaaaaaa", "13-bbbbbbbb"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the error does not name %q: %v", w, err)
		}
	}
	// The pair is not the newest: it is an error all the same.
	files = merge(baseBundle(t), inSet("5-aaaaaaaa", trustAB(t, 5)), inSet("5-bbbbbbbb", trustAB(t, 5)))
	b = openBundle(t, makeBundle(t, files))
	if _, _, err := b.Roots(); err == nil || !strings.Contains(err.Error(), "5-aaaaaaaa") {
		t.Errorf("a pair that is not the newest: %v", err)
	}
	// Same number, written with a leading zero, is not a set and is no pair.
	files = merge(baseBundle(t), inSet("07-bbbbbbbb", trustAB(t, 7)))
	if _, set, err := openBundle(t, makeBundle(t, files)).Roots(); err != nil || set.Name != "7-3fa9c1d2" {
		t.Errorf("07 beside 7: %+v %v", set, err)
	}
}

func TestTheNewestSetIsNeverReplacedByAnOlderOneWhenItsFilesAreBad(t *testing.T) {
	good := inSet("7-3fa9c1d2", trustAB(t, 7))
	newer := func(change func(tr tree)) tree {
		tr := trustAB(t, 8)
		change(tr)
		return merge(tree{"ritueel.yaml": []byte(settingsText(productionStores))}, good, inSet("8-bbbbbbbb", tr))
	}
	badBundleOfAnotherList := vector(t, "root-list", "v1", "bundles", "ca-bundle-8.pem")
	for name, tc := range map[string]struct {
		files tree
		words string
	}{
		"no root-list.json":       {newer(func(tr tree) { delete(tr, "root-list.json") }), "8-bbbbbbbb"},
		"no ca-bundle.pem":        {newer(func(tr tree) { delete(tr, "ca-bundle.pem") }), "8-bbbbbbbb"},
		"a list that is not JSON": {newer(func(tr tree) { tr["root-list.json"] = []byte("not json") }), "root-list.json"},
		"an empty list":           {newer(func(tr tree) { tr["root-list.json"] = nil }), "root-list.json"},
		"a list of another sequence": {newer(func(tr tree) {
			tr["root-list.json"] = bytes.Replace(tr["root-list.json"], []byte(`"sequence":8`), []byte(`"sequence":9`), 1)
		}), "sequence"},
		"the list of sequence 7":   {newer(func(tr tree) { tr["root-list.json"] = vector(t, "root-list", "v1", "lists", "seq7-a.json") }), "sequence of root-list.json is 7"},
		"a bundle of another list": {newer(func(tr tree) { tr["ca-bundle.pem"] = vector(t, "root-list", "v1", "bundles", "ca-bundle-7.pem") }), "ca-bundle.pem"},
		"a bundle with a certificate gone": {newer(func(tr tree) {
			tr["ca-bundle.pem"] = vector(t, "root-list", "v1", "bundles", "ca-bundle-7-missing-certificate.pem")
		}), "ca-bundle.pem"},
		"a bundle in the wrong order": {newer(func(tr tree) {
			tr["ca-bundle.pem"] = vector(t, "root-list", "v1", "bundles", "ca-bundle-7-wrong-order.pem")
		}), "ca-bundle.pem"},
		"a bundle with an extra certificate": {newer(func(tr tree) {
			tr["ca-bundle.pem"] = vector(t, "root-list", "v1", "bundles", "ca-bundle-7-extra-certificate.pem")
		}), "ca-bundle.pem"},
		"a bundle with a certificate that is no CA": {newer(func(tr tree) {
			tr["ca-bundle.pem"] = vector(t, "root-list", "v1", "bundles", "ca-bundle-7-not-a-ca.pem")
		}), "ca-bundle.pem"},
		"an empty bundle":                 {newer(func(tr tree) { tr["ca-bundle.pem"] = nil }), "ca-bundle.pem"},
		"a bundle that is another bundle": {newer(func(tr tree) { tr["ca-bundle.pem"] = badBundleOfAnotherList }), ""},
		"a bundle over the limit":         {newer(func(tr tree) { tr["ca-bundle.pem"] = bytes.Repeat([]byte("#"), 300<<10) }), "ca-bundle.pem"},
	} {
		t.Run(name, func(t *testing.T) {
			b := openBundle(t, makeBundle(t, tc.files))
			refs, set, err := b.Roots()
			if refs != nil || set != (bundle.TrustSet{}) || err == nil {
				t.Fatalf("an older set was used or no error: %v %v %v", refs, set, err)
			}
			if errors.Is(err, bundle.ErrNoTrustSet) {
				t.Errorf("a bad set is reported as no set: %v", err)
			}
			if tc.words != "" && !strings.Contains(err.Error(), tc.words) {
				t.Errorf("the error %q does not hold %q", err, tc.words)
			}
			if !strings.Contains(err.Error(), "8-bbbbbbbb") {
				t.Errorf("the error does not name the newest set: %v", err)
			}
		})
	}
}

func TestTheNewestSetOfAnotherKindOfFileIsAnError(t *testing.T) {
	// A trust set that is a file, a link to a good set, and a list that is a link.
	dir := makeBundle(t, merge(baseBundle(t)))
	if err := os.Symlink(filepath.Join(dir, "trust/7-3fa9c1d2"), filepath.Join(dir, "trust/9-aaaaaaaa")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openBundle(t, dir).Roots(); err == nil || errors.Is(err, bundle.ErrNoTrustSet) {
		t.Errorf("a link as the newest set: %v", err)
	}
	dir = makeBundle(t, baseBundle(t))
	if err := os.WriteFile(filepath.Join(dir, "trust/9-aaaaaaaa"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, set, err := openBundle(t, dir).Roots(); err == nil {
		t.Errorf("a file as the newest set: %+v", set)
	}
	dir = makeBundle(t, baseBundle(t))
	list := filepath.Join(dir, "trust/7-3fa9c1d2/root-list.json")
	if err := os.Rename(list, filepath.Join(dir, "elsewhere.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere.json"), list); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openBundle(t, dir).Roots(); !errors.Is(err, fsx.ErrLink) {
		t.Errorf("a list that is a link: %v", err)
	}
	// trust itself as a link to a folder.
	dir = makeBundle(t, tree{"ritueel.yaml": []byte(settingsText(productionStores))})
	other := makeBundle(t, inSet("7-3fa9c1d2", trustAB(t, 7)))
	if err := os.Symlink(filepath.Join(other, "trust"), filepath.Join(dir, "trust")); err != nil {
		t.Fatal(err)
	}
	if refs, _, err := openBundle(t, dir).Roots(); err == nil || refs != nil {
		t.Errorf("trust as a link: %v %v", refs, err)
	}
}

func TestACertificateThatIsNotAnEcdsaKeyOnP384IsRefused(t *testing.T) {
	for name, kind := range map[string]string{"P-256": "p256", "P-521": "p521", "Ed25519": "ed25519", "RSA": "rsa"} {
		t.Run(name, func(t *testing.T) {
			files := merge(tree{"ritueel.yaml": []byte(settingsText(productionStores))}, inSet("7-3fa9c1d2", selfSignedSet(t, kind, 7)))
			refs, set, err := openBundle(t, makeBundle(t, files)).Roots()
			if refs != nil || set != (bundle.TrustSet{}) || err == nil {
				t.Fatalf("%v %v %v", refs, set, err)
			}
			if !strings.Contains(err.Error(), "P-384") {
				t.Errorf("the error does not say P-384: %v", err)
			}
		})
	}
	// The same builder with a P-384 key is accepted: the set is well made and the only fault is the curve.
	files := merge(tree{"ritueel.yaml": []byte(settingsText(productionStores))}, inSet("7-3fa9c1d2", selfSignedSet(t, "p384", 7)))
	refs, _, err := openBundle(t, makeBundle(t, files)).Roots()
	if err != nil || len(refs) != 1 {
		t.Fatalf("a well-made set with a P-384 key: %v %v", refs, err)
	}
}

func TestTheSignatureAndTheDateOfAListAreNotChecked(t *testing.T) {
	// An expired list, and a list with no signature file or a wrong one, are read: an expired set must not stop a
	// person from reading a request (the verify and history commands judge them).
	tr := trustAB(t, 7)
	tr["root-list.json"] = bytes.Replace(tr["root-list.json"], []byte("2027-12-15T12:00:00Z"), []byte("2020-01-01T00:00:00Z"), 1)
	tr["root-list.jws"] = []byte("not a signature")
	files := merge(tree{"ritueel.yaml": []byte(settingsText(productionStores))}, inSet("7-3fa9c1d2", tr))
	refs, _, err := openBundle(t, makeBundle(t, files)).Roots()
	if err != nil || len(refs) != 2 {
		t.Errorf("an expired list with a bad signature: %d roots, %v", len(refs), err)
	}
}

// Checker.

func TestACheckerWithADelegationAcceptsAGoodRequest(t *testing.T) {
	files := merge(baseBundle(t), requestFiles(t, "x509-software-valid"))
	b := openBundle(t, makeBundle(t, files))
	chk, d, err := b.Checker(delegationName, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Valid() || d.Name != delegationName || d.Root != rootName || d.Type != wanted.TypeX509Intermediate {
		t.Errorf("delegation %+v", d)
	}
	req, err := b.Request("x509-software-valid")
	if err != nil {
		t.Fatal(err)
	}
	v, err := chk.Check(t.Context(), req)
	if err != nil || !v.Accepted() || v.Refused() || !v.Complete() {
		t.Fatalf("verdict %+v, error %v", v, err)
	}
	for i, c := range v.Checks {
		if c.Status != handoff.StatusPassed {
			t.Errorf("check %d is %s", i+1, c.Status)
		}
	}
}

func TestACheckerWithNoDelegationNamedDoesNotAcceptAndSaysWhatItDidNotRun(t *testing.T) {
	files := merge(baseBundle(t), requestFiles(t, "x509-software-valid"))
	// With no delegation named, no delegation file is read: the bundle needs none.
	delete(files, "want/delegations/"+delegationName+".yaml")
	delete(files, "want/roots/"+rootName+".yaml")
	b := openBundle(t, makeBundle(t, files))
	chk, d, err := b.Checker("", fixedNow, nil)
	if err != nil || d != nil {
		t.Fatalf("delegation %v, error %v", d, err)
	}
	req, err := b.Request("x509-software-valid")
	if err != nil {
		t.Fatal(err)
	}
	v, err := chk.Check(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if v.Accepted() || v.Refused() || v.Complete() {
		t.Errorf("accepted %v refused %v complete %v", v.Accepted(), v.Refused(), v.Complete())
	}
	got := v.Checks[8]
	if got.Status != handoff.StatusNotRun || !slices.Equal(got.NotRun, []string{"delegation-type", "name-constraints"}) {
		t.Errorf("check 9: %+v", got)
	}
}

func TestTheCheckerReadsOnlyWhatItUses(t *testing.T) {
	files := merge(baseBundle(t), tree{
		"want/delegations/broken.yaml": []byte("not: [valid"),
		"want/roots/broken.yaml":       []byte("- a"),
		"want/delegations/other.yaml":  []byte(x509DelegationText + "extra: 1\n"),
	})
	b := openBundle(t, makeBundle(t, files))
	if _, _, err := b.Checker(delegationName, fixedNow, nil); err != nil {
		t.Errorf("a bad file that the command does not use stopped it: %v", err)
	}
	if _, _, err := b.Checker("other", fixedNow, nil); err == nil {
		t.Error("a delegation that is bad is accepted")
	}
}

func TestTheCheckerRefusesWhatItCannotMake(t *testing.T) {
	ok := baseBundle(t)
	for name, tc := range map[string]struct {
		files      tree
		delegation string
		is         error
		words      string
	}{
		"a delegation with no file":      {ok, "nosuch", fs.ErrNotExist, "nosuch"},
		"a delegation name with a slash": {ok, "../ritueel", nil, ""},
		"a break-glass delegation name":  {ok, "break-glass-x", nil, ""},
		"an upper-case name":             {ok, "Example", nil, ""},
		"a root with no file":            {without(ok, "want/roots/"+rootName+".yaml"), delegationName, fs.ErrNotExist, "the root of the delegation " + delegationName},
		"a root of another kind":         {merge(ok, tree{"want/roots/" + rootName + ".yaml": []byte("version: 1\nkind: ssh\n")}), delegationName, nil, "needs the kind x509"},
		"a root that fails its check":    {merge(ok, tree{"want/roots/" + rootName + ".yaml": []byte("version: 1\nkind: x509\nkeys: []\n")}), delegationName, nil, "not read yet"},
		"a delegation that fails":        {merge(ok, tree{"want/delegations/" + delegationName + ".yaml": []byte("version: 1\ntype: x509-intermediate\nroot: example-root\n")}), delegationName, nil, "name constraints"},
		"no trust set":                   {withoutPrefix(ok, "trust/"), delegationName, bundle.ErrNoTrustSet, ""},
		"no trust set and no delegation": {withoutPrefix(ok, "trust/"), "", bundle.ErrNoTrustSet, ""},
		"a bad trust set":                {merge(ok, inSet("8-bbbbbbbb", tree{"root-list.json": []byte("{}"), "ca-bundle.pem": nil})), delegationName, nil, "8-bbbbbbbb"},
	} {
		t.Run(name, func(t *testing.T) {
			b := openBundle(t, makeBundle(t, tc.files))
			chk, d, err := b.Checker(tc.delegation, fixedNow, nil)
			if chk != nil || d != nil || err == nil {
				t.Fatalf("a part beside the error: %v %v %v", chk, d, err)
			}
			if tc.is != nil && !errors.Is(err, tc.is) {
				t.Errorf("error %v is not %v", err, tc.is)
			}
			if tc.words != "" && !strings.Contains(err.Error(), tc.words) {
				t.Errorf("error %q does not hold %q", err, tc.words)
			}
		})
	}
	// No clock is a configuration fault, and so is a nil verifier.
	b := openBundle(t, makeBundle(t, ok))
	if chk, d, err := b.Checker(delegationName, nil, nil); chk != nil || d != nil || !errors.Is(err, handoff.ErrConfig) {
		t.Errorf("no clock: %v %v %v", chk, d, err)
	}
	if chk, d, err := b.Checker(delegationName, fixedNow, map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: nil}); chk != nil || d != nil || !errors.Is(err, handoff.ErrConfig) {
		t.Errorf("a nil verifier: %v %v %v", chk, d, err)
	}
}

// without returns a copy of the tree with one path taken out.
func without(tr tree, path string) tree {
	out := merge(tr)
	delete(out, path)
	return out
}

// withoutPrefix returns a copy of the tree without the paths under a prefix.
func withoutPrefix(tr tree, prefix string) tree {
	out := tree{}
	for p, data := range tr {
		if !strings.HasPrefix(p, prefix) {
			out[p] = data
		}
	}
	return out
}

// What the policy and the delegation of the files do to a verdict: every request below is the one case of the
// vectors, in a bundle whose files differ in the one thing.
func TestThePolicyAndTheDelegationOfTheFilesDecideTheVerdict(t *testing.T) {
	type outcome struct {
		code    handoff.Code
		checkAt int // the check that refuses; 0 for accepted
	}
	cases := []struct {
		name  string
		id    string
		files func(tr tree) tree
		want  outcome
	}{
		{"development policy accepts a software key", "x509-software-valid", func(tr tree) tree { return tr }, outcome{}},
		{"a policy with no software store refuses it", "x509-software-valid", func(tr tree) tree {
			return merge(tr, tree{"ritueel.yaml": []byte(settingsText(productionStores))})
		}, outcome{handoff.CodeStoreNotAllowed, 6}},
		{"the production vector under the production policy", "x509-software-in-production", func(tr tree) tree {
			return merge(tr, tree{"ritueel.yaml": []byte(settingsText(productionStores))})
		}, outcome{handoff.CodeStoreNotAllowed, 6}},
		{"the key of root A", "x509-request-root-key", func(tr tree) tree { return tr }, outcome{handoff.CodePolicy, 9}},
		{"the key of root B", "x509-request-root-b-key", func(tr tree) tree { return tr }, outcome{handoff.CodePolicy, 9}},
		{"the name of root A", "x509-subject-root-name", func(tr tree) tree { return tr }, outcome{handoff.CodePolicy, 9}},
		{"the name of root B", "x509-subject-root-b-name", func(tr tree) tree { return tr }, outcome{handoff.CodePolicy, 9}},
		{"the key of root B when the newest set has root A only", "x509-request-root-b-key", func(tr tree) tree {
			return merge(withoutPrefix(tr, "trust/"), inSet("7-3fa9c1d2", trustA(t, 7)))
		}, outcome{}},
		{"the key of root B when an older set has both and the newest has root A only", "x509-request-root-b-key", func(tr tree) tree {
			return merge(withoutPrefix(tr, "trust/"), inSet("7-3fa9c1d2", trustAB(t, 7)), inSet("8-bbbbbbbb", trustA(t, 8)))
		}, outcome{}},
		{"the key of root B when the newest set is older in name and has both", "x509-request-root-b-key", func(tr tree) tree {
			return merge(withoutPrefix(tr, "trust/"), inSet("8-bbbbbbbb", trustA(t, 8)), inSet("20-aaaaaaaa", trustAB(t, 20)))
		}, outcome{handoff.CodePolicy, 9}},
		{"a delegation that lists no host the request names", "x509-software-valid", func(tr tree) tree {
			return merge(tr, tree{"want/delegations/" + delegationName + ".yaml": []byte("version: 1\ntype: x509-intermediate\nroot: example-root\npermitted_dns_names: [example.net]\n")})
		}, outcome{handoff.CodePolicy, 9}},
		{"a delegation of another type", "x509-software-valid", func(tr tree) tree {
			return merge(tr, tree{
				"want/delegations/" + delegationName + ".yaml": []byte("version: 1\ntype: ssh-ca-key\nroot: example-root\nuse: user\n"),
				"want/roots/" + rootName + ".yaml":             []byte("version: 1\nkind: ssh\ntest: true\n"),
			})
		}, outcome{handoff.CodePolicy, 9}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stem, reqFiles := requestCase(t, tc.id)
			files := merge(tc.files(baseBundle(t)), reqFiles)
			b := openBundle(t, makeBundle(t, files))
			chk, _, err := b.Checker(delegationName, fixedNow, nil)
			if err != nil {
				t.Fatal(err)
			}
			req, err := b.Request(stem)
			if err != nil {
				t.Fatal(err)
			}
			v, err := chk.Check(t.Context(), req)
			if err != nil {
				t.Fatalf("error %v", err)
			}
			if tc.want.code == "" {
				if !v.Accepted() {
					t.Errorf("not accepted: code %q (%s)", v.Code, v.Detail)
				}
				return
			}
			if v.Code != tc.want.code || !v.Refused() || v.Accepted() {
				t.Fatalf("code %q (%s), refused %v", v.Code, v.Detail, v.Refused())
			}
			if v.Checks[tc.want.checkAt-1].Status != handoff.StatusFailed {
				t.Errorf("check %d is %s", tc.want.checkAt, v.Checks[tc.want.checkAt-1].Status)
			}
		})
	}
}

func TestTheClockOfTheCallReachesTheVerifier(t *testing.T) {
	files := merge(baseBundle(t), requestFiles(t, "x509-piv-valid"))
	b := openBundle(t, makeBundle(t, files))
	other := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	v := &countingVerifier{}
	chk, _, err := b.Checker(delegationName, func() time.Time { return other }, map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: v})
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.Request("x509-piv-valid")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = chk.Check(t.Context(), req)
	if v.calls != 1 || !v.at.Equal(other) {
		t.Errorf("the verifier was called %d times, at %v; want once, at %v", v.calls, v.at, other)
	}
}

func TestTheVerifiersOfTheCallerReachTheChecker(t *testing.T) {
	files := merge(baseBundle(t), requestFiles(t, "x509-piv-valid"))
	b := openBundle(t, makeBundle(t, files))
	// No verifier: a PIV request stops at check 7.
	chk, _, err := b.Checker(delegationName, fixedNow, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := b.Request("x509-piv-valid")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chk.Check(t.Context(), req); !errors.Is(err, handoff.ErrNoVerifier) {
		t.Errorf("no verifier: %v", err)
	}
	// With one, it is called.
	v := &countingVerifier{}
	chk, _, err = b.Checker(delegationName, fixedNow, map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: v})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = chk.Check(t.Context(), req)
	if v.calls != 1 {
		t.Errorf("the verifier was called %d times", v.calls)
	}
}

// sameKey compares two public keys with the method that the standard keys have.
func sameKey(a, b crypto.PublicKey) bool {
	k, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(b)
}

// A bundle holds no OpenPGP primaries, so a delegation of the type openpgp-subkey cannot make a checker: the error is
// the configuration error of the library and its words say "primaries", which is what a command tells a person by.
// A delegation of another type, and no delegation, make one.
func TestACheckerForAnOpenPGPSubkeyDelegationIsRefusedForWantOfPrimaries(t *testing.T) {
	files := merge(baseBundle(t), tree{
		"want/roots/pgp-root.yaml":               []byte("version: 1\nkind: openpgp\ntest: true\n"),
		"want/delegations/pgp-sign.yaml":         []byte("version: 1\ntype: openpgp-subkey\nroot: pgp-root\ncapability: sign\n"),
		"want/delegations/pgp-authenticate.yaml": []byte("version: 1\ntype: openpgp-subkey\nroot: pgp-root\ncapability: authenticate\n"),
	})
	b := openBundle(t, makeBundle(t, files))
	for _, name := range []string{"pgp-sign", "pgp-authenticate"} {
		chk, d, err := b.Checker(name, fixedNow, nil)
		if chk != nil || d != nil || !errors.Is(err, handoff.ErrConfig) || !strings.Contains(err.Error(), "primaries") {
			t.Errorf("%s: (%v, %v, %v), want no checker and ErrConfig that names the primaries", name, chk, d, err)
		}
	}
	for _, name := range []string{delegationName, ""} {
		if chk, _, err := b.Checker(name, fixedNow, nil); err != nil || chk == nil {
			t.Errorf("%q: (%v, %v), want a checker", name, chk, err)
		}
	}
}
