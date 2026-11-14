package bundle_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/fsx"
)

// Hostile files and folders under trust/: they are refused with an error, and never crash or hang the reader.

func TestAHostileListOrBundleIsRefusedAndNeverCrashes(t *testing.T) {
	settings := tree{"ritueel.yaml": []byte(settingsText(productionStores))}
	good := trustAB(t, 7)
	for name, tr := range map[string]tree{
		"a list of nesting 100000":            {"root-list.json": []byte(strings.Repeat("[", 100000)), "ca-bundle.pem": good["ca-bundle.pem"]},
		"a list that is a number":             {"root-list.json": []byte("7"), "ca-bundle.pem": good["ca-bundle.pem"]},
		"a list with bytes that are no UTF-8": {"root-list.json": []byte("{\"sequence\":7,\"x\":\"\xff\"}"), "ca-bundle.pem": good["ca-bundle.pem"]},
		"a list over the limit":               {"root-list.json": []byte("{\"x\":\"" + strings.Repeat("a", 300<<10) + "\"}"), "ca-bundle.pem": good["ca-bundle.pem"]},
		"a list with a repeated member":       {"root-list.json": []byte(`{"sequence":7,"sequence":7}`), "ca-bundle.pem": good["ca-bundle.pem"]},
		"a list with sequence 0":              {"root-list.json": []byte(strings.Replace(string(good["root-list.json"]), `"sequence":7`, `"sequence":0`, 1)), "ca-bundle.pem": good["ca-bundle.pem"]},
		"a list with a huge sequence":         {"root-list.json": []byte(strings.Replace(string(good["root-list.json"]), `"sequence":7`, `"sequence":99999999999999999999`, 1)), "ca-bundle.pem": good["ca-bundle.pem"]},
		"a bundle of one NUL":                 {"root-list.json": good["root-list.json"], "ca-bundle.pem": []byte{0}},
		"a bundle of garbage PEM":             {"root-list.json": good["root-list.json"], "ca-bundle.pem": []byte(header(7) + "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")},
		"a bundle of an empty block":          {"root-list.json": good["root-list.json"], "ca-bundle.pem": []byte(header(7) + "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")},
		"a bundle of only the header":         {"root-list.json": good["root-list.json"], "ca-bundle.pem": []byte(header(7))},
		"a bundle with CRLF line ends":        {"root-list.json": good["root-list.json"], "ca-bundle.pem": []byte(strings.ReplaceAll(string(good["ca-bundle.pem"]), "\n", "\r\n"))},
		"a bundle with a BOM":                 {"root-list.json": good["root-list.json"], "ca-bundle.pem": append([]byte("\xef\xbb\xbf"), good["ca-bundle.pem"]...)},
		"a bundle with text after":            {"root-list.json": good["root-list.json"], "ca-bundle.pem": append(append([]byte(nil), good["ca-bundle.pem"]...), "\n# more\n"...)},
		"a list that is the bundle":           {"root-list.json": good["ca-bundle.pem"], "ca-bundle.pem": good["root-list.json"]},
	} {
		t.Run(name, func(t *testing.T) {
			b := openBundle(t, makeBundle(t, merge(settings, inSet("7-3fa9c1d2", tr))))
			refs, set, err := b.Roots()
			if refs != nil || set != (bundle.TrustSet{}) || err == nil {
				t.Fatalf("accepted: %v %v %v", refs, set, err)
			}
			if !printableText(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII: %q", err.Error())
			}
		})
	}
}

func TestAFileOverWhatFsxReadsIsRefused(t *testing.T) {
	settings := tree{"ritueel.yaml": []byte(settingsText(productionStores))}
	good := trustAB(t, 7)
	big := make([]byte, fsx.MaxReadSize+1)
	for name, tr := range map[string]tree{
		"a list":   {"root-list.json": big, "ca-bundle.pem": good["ca-bundle.pem"]},
		"a bundle": {"root-list.json": good["root-list.json"], "ca-bundle.pem": big},
	} {
		t.Run(name, func(t *testing.T) {
			b := openBundle(t, makeBundle(t, merge(settings, inSet("7-3fa9c1d2", tr))))
			if _, _, err := b.Roots(); !errors.Is(err, fsx.ErrTooLarge) {
				t.Errorf("error %v", err)
			}
		})
	}
}

func TestAPipeOrAFolderInPlaceOfAFileOfASetIsRefusedAndNotWaitedOn(t *testing.T) {
	for name, make := range map[string]func(path string) error{
		"a pipe":   func(p string) error { return syscall.Mkfifo(p, 0o644) },
		"a folder": func(p string) error { return os.Mkdir(p, 0o755) },
	} {
		for _, file := range []string{"root-list.json", "ca-bundle.pem"} {
			t.Run(name+" as "+file, func(t *testing.T) {
				files := merge(tree{"ritueel.yaml": []byte(settingsText(productionStores))}, inSet("7-3fa9c1d2", trustAB(t, 7)))
				delete(files, "trust/7-3fa9c1d2/"+file)
				dir := makeBundle(t, files)
				if err := make(filepath.Join(dir, "trust/7-3fa9c1d2", file)); err != nil {
					t.Skipf("cannot make it: %v", err)
				}
				b := openBundle(t, dir)
				if _, _, err := b.Roots(); !errors.Is(err, fsx.ErrNotRegular) {
					t.Errorf("error %v", err)
				}
			})
		}
	}
}

func TestAFolderOfTooManyNamesIsRefusedAndNeverListedInFull(t *testing.T) {
	dir := makeBundle(t, tree{"ritueel.yaml": []byte(settingsText(productionStores))})
	trust := filepath.Join(dir, "trust")
	if err := os.Mkdir(trust, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= fsx.MaxDirEntries; i++ {
		f, err := os.Create(filepath.Join(trust, "x"+strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	b := openBundle(t, dir)
	refs, _, err := b.Roots()
	if refs != nil || !errors.Is(err, fsx.ErrTooMany) {
		t.Fatalf("%v %v", refs, err)
	}
	if errors.Is(err, bundle.ErrNoTrustSet) {
		t.Error("a folder that is too big is reported as holding no set")
	}
}

func TestManyTrustSetsAreReadByNumberAndTheLargestWins(t *testing.T) {
	files := tree{"ritueel.yaml": []byte(settingsText(productionStores))}
	dir := makeBundle(t, files)
	for i := 1; i <= 500; i++ {
		// Folders with the form of a set and nothing in them: only the newest is opened.
		if err := os.MkdirAll(filepath.Join(dir, "trust", strconv.Itoa(i)+"-0000abcd"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeTree(t, dir, inSet("501-bbbbbbbb", trustA(t, 501)))
	b := openBundle(t, dir)
	refs, set, err := b.Roots()
	if err != nil || set.Number != 501 || len(refs) != 1 {
		t.Fatalf("set %+v, %d roots, %v", set, len(refs), err)
	}
}

func TestEveryKeyOfTheRootsIsAnEcdsaKeyOnP384(t *testing.T) {
	b := openBundle(t, makeBundle(t, baseBundle(t)))
	refs, _, err := b.Roots()
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range refs {
		key, ok := r.Key.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P384() || len(r.Subject) == 0 {
			t.Errorf("root %d: %T", i, r.Key)
		}
	}
	// The subjects are copies: a change to one is not seen by the next call.
	refs[0].Subject[0] ^= 0xff
	again, _, err := b.Roots()
	if err != nil || again[0].Subject[0] == refs[0].Subject[0] {
		t.Errorf("two calls share the bytes of a subject: %v", err)
	}
}

// FuzzRoots reads a trust set made of fuzzed bytes, and a second folder with a fuzzed name. The folder is made
// once and its content is replaced at every run. Roots never panics, returns roots or an error and not both, and
// the roots it returns are keys on P-384 with a subject.
func FuzzRoots(f *testing.F) {
	good := trustAB(f, 7)
	f.Add(good["root-list.json"], good["ca-bundle.pem"], "")
	f.Add(good["root-list.json"], good["ca-bundle.pem"], "7-aaaaaaaa")
	f.Add(good["root-list.json"], good["ca-bundle.pem"], "9-aaaaaaaa")
	f.Add(good["root-list.json"], good["ca-bundle.pem"], ".rt-aaaaaaaaaaa")
	one := trustA(f, 7)
	f.Add(one["root-list.json"], one["ca-bundle.pem"], "8-bbbbbbbb")
	f.Add([]byte("{}"), []byte(nil), "7-3fa9c1d2")
	f.Add([]byte(nil), good["ca-bundle.pem"], "x")
	for _, kind := range []string{"p256", "ed25519"} {
		tr := selfSignedSet(f, kind, 7)
		f.Add(tr["root-list.json"], tr["ca-bundle.pem"], "")
	}
	dir := f.TempDir()
	writeTree(f, dir, tree{"ritueel.yaml": []byte(settingsText(productionStores))})
	b, err := bundle.Open(dir)
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(func() { _ = b.Close() })
	f.Fuzz(func(t *testing.T, list, pem []byte, other string) {
		trust := filepath.Join(dir, "trust")
		_ = os.RemoveAll(trust)
		set := filepath.Join(trust, "7-3fa9c1d2")
		if err := os.MkdirAll(set, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(set, "root-list.json"), list, 0o644)
		_ = os.WriteFile(filepath.Join(set, "ca-bundle.pem"), pem, 0o644)
		if other != "" && other == filepath.Base(other) && !strings.ContainsAny(other, "\x00/") && other != "." && other != ".." {
			_ = os.MkdirAll(filepath.Join(trust, other), 0o755)
		}
		refs, got, err := b.Roots()
		if err != nil {
			if refs != nil || got != (bundle.TrustSet{}) {
				t.Fatalf("a part beside the error: %v %v", refs, got)
			}
			return
		}
		if len(refs) == 0 || got.Number < 1 {
			t.Fatalf("no root and no error: %v %+v", refs, got)
		}
		for i, r := range refs {
			key, ok := r.Key.(*ecdsa.PublicKey)
			if !ok || key == nil || key.Curve != elliptic.P384() || len(r.Subject) == 0 {
				t.Fatalf("root %d is not a key on P-384 with a subject: %T", i, r.Key)
			}
		}
	})
}

func TestFolderNamesThatAreNotUTF8OrHoldControlCharactersAreIgnored(t *testing.T) {
	dir := makeBundle(t, baseBundle(t))
	for _, name := range []string{"\xff7-aaaaaaaa", "9-\xc3\x28aaaaaa", "99-aaaaaaaa\n", "\u202e99-aaaaaaaa", "99-aaaaaaaa\t"} {
		if err := os.Mkdir(filepath.Join(dir, "trust", name), 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", name, err)
		}
	}
	_, set, err := openBundle(t, dir).Roots()
	if err != nil || set.Number != 7 {
		t.Fatalf("set %+v, error %v", set, err)
	}
}
