//go:build linux || darwin

package cli

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/testrepo"
)

// Every fault of the OpenPGP primaries of the newest trust set gives the command one form: exit code 1 and one line
// that starts with "request STEM is not accepted and not refused: ", in text mode and in JSON mode. The faults are
// the faults of the list (more primaries than the checks take, one fingerprint on two entries) and of the keyring
// file (missing, not a plain file, refused by the reader).

const (
	fingerprintOfA = "6df387de63525c9dc0ec1174bd138d2c4889b79b"
	fingerprintOfB = "c4288657012230588b51fa66e0831b9c6e084f39"
	listAt         = "trust/" + crqTrustSet + "/root-list.json"
)

// primariesFault is one fault of the primaries: how to change the files of the bundle, how to place a keyring file
// that is not a plain file, the kind of the bundle's error that it comes from, and what the sentence holds.
type primariesFault struct {
	name   string
	kind   string // the exported kind of package bundle that the error is of, besides ErrPrimaries
	change func(t *testing.T, files crqTree)
	place  func(t *testing.T, at string)
	// sentence is the exact sentence, or its beginning when prefix is set.
	sentence string
	prefix   bool
}

func primariesFaultsOfTheCommand(t *testing.T) []primariesFault {
	t.Helper()
	a, b, z := crqKeyring(t, "a"), crqKeyring(t, "b"), crqKeyring(t, "z")
	keyring := func(file []byte) func(t *testing.T, files crqTree) {
		return func(t *testing.T, files crqTree) { files[keyringAt] = file }
	}
	trust := func(roots func(t *testing.T) []memRoot) func(t *testing.T, files crqTree) {
		return func(t *testing.T, files crqTree) {
			for p, d := range memTrustOf(roots(t)) {
				files[p] = d
			}
		}
	}
	noFile := func(t *testing.T, files crqTree) { delete(files, keyringAt) }
	repeat := func(t *testing.T, files crqTree) {
		files[listAt] = bytes.Replace(files[listAt], []byte(fingerprintOfB), []byte(fingerprintOfA), 1)
	}
	repeatsOf := func(n, i, j int) func(t *testing.T) []memRoot {
		return func(t *testing.T) []memRoot {
			roots := memRoots(t, n)
			roots[i].fp = roots[j].fp
			return roots
		}
	}
	listSentence := func(first, second string) string {
		return "the root list of the newest trust set " + crqTrustSet + " gives one openpgp_fingerprint to two entries: the entry with the label " + first + " and the entry with the label " + second
	}
	symlink := func(target string, real []byte) func(t *testing.T, at string) {
		return func(t *testing.T, at string) {
			if real != nil {
				if err := os.WriteFile(filepath.Join(filepath.Dir(at), target), real, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, at); err != nil {
				t.Fatal(err)
			}
		}
	}
	return []primariesFault{
		{name: "17 pinned", kind: "ErrPrimaries", change: trust(func(t *testing.T) []memRoot { return memRoots(t, 17) }),
			sentence: "the root list of the newest trust set " + crqTrustSet + " pins 17 OpenPGP primaries, and the checks take at most 16"},
		{name: "26 pinned", kind: "ErrPrimaries", change: trust(func(t *testing.T) []memRoot { return memRoots(t, 26) }),
			sentence: "the root list of the newest trust set " + crqTrustSet + " pins 26 OpenPGP primaries, and the checks take at most 16"},
		{name: "one fingerprint on the first two entries", kind: "ErrPrimaries", change: repeat, sentence: listSentence("A", "B")},
		{name: "one fingerprint on the first and the last of 16", kind: "ErrPrimaries", change: trust(repeatsOf(16, 15, 0)), sentence: listSentence("A", "P")},
		{name: "one fingerprint on the last two of 16", kind: "ErrPrimaries", change: trust(repeatsOf(16, 15, 14)), sentence: listSentence("O", "P")},
		{name: "no keyring file", kind: "ErrNoKeyring", change: noFile, sentence: noKeyringSentence},
		{name: "a link", kind: "ErrPrimaries", change: noFile, place: symlink("real.gpg", append(bytes.Clone(a), b...)), sentence: refusedSentence, prefix: true},
		{name: "a dangling link", kind: "ErrPrimaries", change: noFile, place: symlink("nowhere.gpg", nil), sentence: refusedSentence, prefix: true},
		{name: "a folder", kind: "ErrPrimaries", change: noFile, place: func(t *testing.T, at string) {
			if err := os.Mkdir(at, 0o755); err != nil {
				t.Fatal(err)
			}
		}, sentence: refusedSentence, prefix: true},
		{name: "a file over what the bundle reads", kind: "ErrPrimaries", change: keyring(make([]byte, fsx.MaxReadSize+1)), sentence: refusedSentence, prefix: true},
		{name: "an empty file", kind: "ErrPrimaries", change: keyring([]byte{}), sentence: refusedSentence, prefix: true},
		{name: "text", kind: "ErrPrimaries", change: keyring([]byte("not a keyring\n")), sentence: refusedSentence, prefix: true},
		{name: "b then a", kind: "ErrPrimaries", change: keyring(append(bytes.Clone(b), a...)), sentence: refusedSentence, prefix: true},
		{name: "a alone", kind: "ErrPrimaries", change: keyring(a), sentence: refusedSentence, prefix: true},
		{name: "a, b and z", kind: "ErrPrimaries", change: keyring(bytes.Join([][]byte{a, b, z}, nil)), sentence: refusedSentence, prefix: true},
		{name: "a test primary and a real one", kind: "ErrPrimaries", change: trust(func(t *testing.T) []memRoot {
			return []memRoot{newMemRoot(t, "A", memCreated, true), newMemRoot(t, "B", memCreated, false)}
		}), sentence: refusedSentence, prefix: true},
	}
}

func (f primariesFault) bundle(t *testing.T, m crqManifest, c crqCase) string {
	t.Helper()
	files := crqBundleTree(t, m, c)
	f.change(t, files)
	dir := t.TempDir()
	crqWrite(t, dir, files)
	if f.place != nil {
		f.place(t, filepath.Join(dir, filepath.FromSlash(keyringAt)))
	}
	return dir
}

// For every fault, an OpenPGP request with no delegation and with an openpgp-subkey delegation, and an x509 request
// with no delegation (which reads the same newest trust set), in text and in JSON: exit code 1, one printable line that
// starts with the words of a request that is not judged, nothing on standard output in text mode, and no result in
// the object in JSON mode.
func TestEveryFaultOfThePrimariesIsTheSentenceOfARequestThatIsNotJudgedInBothModes(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, f := range primariesFaultsOfTheCommand(t) {
		for _, run := range []struct {
			id       string
			delegate bool
		}{{"pgp-software-valid", false}, {"pgp-software-valid", true}, {"x509-software-valid", false}} {
			t.Run(f.name+"/"+run.id+"/delegation="+map[bool]string{true: "yes", false: "no"}[run.delegate], func(t *testing.T) {
				c := m.byID(t, run.id)
				dir := f.bundle(t, m, c)
				before := crqSnapshot(t, dir)
				args := []string{"check", "request", c.stem(t), "--dir", dir}
				if run.delegate {
					args = append(args, "--delegation", crqDelegation)
				}
				prefix := "ritueel: request " + c.stem(t) + " is not accepted and not refused: "
				for _, mode := range [][]string{nil, {"--output", "json"}} {
					r := crqRun(t, now, append(slices.Clone(args), mode...)...)
					want := prefix + f.sentence
					if r.code != ExitFailure || strings.Count(r.stderr, "\n") != 1 || !strings.HasSuffix(r.stderr, "\n") || !onlyPrintable(r.stderr) || len(r.stderr) > 700 ||
						(!f.prefix && r.stderr != want+"\n") || (f.prefix && !strings.HasPrefix(r.stderr, want)) {
						t.Fatalf("%v: (%d, %q), want exit code 1 and the one line %q", mode, int(r.code), r.stderr, want)
					}
					if mode == nil {
						if r.stdout != "" {
							t.Errorf("text mode: standard output = %q, want nothing", r.stdout)
						}
						continue
					}
					obj := object(t, r.stdout)
					msg, _ := obj["error"].(string)
					if msg != strings.TrimSuffix(strings.TrimPrefix(r.stderr, "ritueel: "), "\n") || obj["outcome"] != "failed" || obj["exit_code"] != jsonNumber("1") {
						t.Errorf("object = %s", r.stdout)
					}
					for _, k := range []string{"checks", "reasons"} {
						if _, ok := obj[k]; ok {
							t.Errorf("the object has %s: %s", k, r.stdout)
						}
					}
					if w, _ := obj["warnings"].([]any); len(w) != 0 {
						t.Errorf("the object has warnings: %s", r.stdout)
					}
				}
				crqSame(t, "check request", before, crqSnapshot(t, dir))
			})
		}
	}
}

// A fault of the list is found before any keyring file is read: the sentence is the same whether the file is good,
// missing or garbage. For a repeated fingerprint it names the list and never the file, and never the fingerprint.
func TestARepeatedFingerprintGivesTheSentenceOfTheListWhateverTheKeyringFileIs(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	want := "ritueel: request " + c.stem(t) + " is not accepted and not refused: the root list of the newest trust set " + crqTrustSet +
		" gives one openpgp_fingerprint to two entries: the entry with the label A and the entry with the label B\n"
	for name, file := range map[string][]byte{"good": crqKeyring(t, "a", "b"), "none": nil, "garbage": []byte("x"), "swapped": crqKeyring(t, "b", "a")} {
		files := crqBundleTree(t, m, c)
		files[listAt] = bytes.Replace(files[listAt], []byte(fingerprintOfB), []byte(fingerprintOfA), 1)
		if file == nil {
			delete(files, keyringAt)
		} else {
			files[keyringAt] = file
		}
		dir := t.TempDir()
		crqWrite(t, dir, files)
		for _, args := range [][]string{{"--delegation", crqDelegation}, nil} {
			r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--dir", dir}, args...)...)
			if r.code != ExitFailure || r.stderr != want || r.stdout != "" {
				t.Errorf("%s %v: (%d, %q, %q), want exit code 1 and %q", name, args, int(r.code), r.stdout, r.stderr, want)
			}
		}
	}
}

// Beside an x509-intermediate delegation the command gives no primaries and does not judge them: a repeated
// fingerprint, 17 pins or a missing file stop nothing there.
func TestAFaultOfThePrimariesDoesNotStopARunBesideAnX509Delegation(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "x509-software-valid")
	for _, f := range primariesFaultsOfTheCommand(t) {
		t.Run(f.name, func(t *testing.T) {
			dir := f.bundle(t, m, c)
			r := crqRun(t, now, "check", "request", c.stem(t), "--dir", dir, "--delegation", crqDelegation)
			// The run is judged as it was before the fault: the request is accepted, and the only line is the warning.
			if r.code != ExitOK || r.stderr != trustSetStderrLine {
				t.Errorf("(%d, %q), want exit code 0 and only the warning about the trust set: the primaries were judged beside an x509 delegation", int(r.code), r.stderr)
			}
		})
	}
}

// exportedErrorKinds are the exported variables Err* that the non-test files of a package declare.
func exportedErrorKinds(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.VAR {
				for _, s := range gd.Specs {
					for _, n := range s.(*ast.ValueSpec).Names {
						if n.IsExported() && strings.HasPrefix(n.Name, "Err") {
							out = append(out, n.Name)
						}
					}
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// Every error kind that package bundle exports is classified here: the kinds of the primaries each have a fault in the
// table above (and so the sentence), and the others are not faults of the primaries. A new kind that is not in one
// of the two lists fails this test, so no kind comes out of the command without the sentence by being forgotten.
func TestEveryErrorKindOfTheBundleHasTheSentenceOrIsNotAFaultOfThePrimaries(t *testing.T) {
	ofThePrimaries := []string{"ErrNoKeyring", "ErrPrimaries"}
	others := []string{"ErrBundle", "ErrNoSettings", "ErrNoTrustSet"}
	got := exportedErrorKinds(t, testrepo.Path(t, "internal", "bundle"))
	want := slices.Sorted(slices.Values(append(slices.Clone(ofThePrimaries), others...)))
	if !slices.Equal(got, want) {
		t.Fatalf("package bundle exports the kinds %v, this test knows %v: a new kind is a fault of the primaries or it is not; add it to a list and, for the first, give it a fault in the table", got, want)
	}
	have := map[string]bool{}
	for _, f := range primariesFaultsOfTheCommand(t) {
		have[f.kind] = true
	}
	for _, k := range ofThePrimaries {
		if !have[k] {
			t.Errorf("the kind %s has no fault in the table of the sentence", k)
		}
	}
	// The command's own list of kinds to ask for is one: it asks for ErrPrimaries only.
	src := string(testrepo.Read(t, "internal", "cli", "checkrequest.go"))
	if strings.Count(src, "bundle.ErrPrimaries") == 0 || strings.Contains(src, "bundle.ErrNoKeyring") || strings.Contains(src, "openpgp.ErrKeyring") {
		t.Errorf("check request must ask for the one kind bundle.ErrPrimaries and for no other kind of the primaries")
	}
}

// The sentence of an openpgp-subkey request under a delegation of another type says only what is always true: the
// command cannot judge the request under that delegation, which is of that type, because the checks take the primaries
// only for a delegation of the type openpgp-subkey. It says nothing of what the list pins, in the same words for a list
// that pins primaries and for one that pins none, in text and in JSON.
func TestTheSentenceForAnotherTypeOfDelegationIsTheSameForAListThatPinsAndOneThatPinsNone(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	const name = crqDelegation
	for _, d := range []struct {
		typ  string
		root string // the kind of the wanted root
		body string
	}{
		{"x509-intermediate", "x509", "permitted_uri_hosts: [example.org]\n"},
		{"ssh-ca-key", "ssh", "use: user\n"},
	} {
		for _, pins := range []bool{true, false} {
			t.Run(d.typ+"/pins="+map[bool]string{true: "yes", false: "no"}[pins], func(t *testing.T) {
				files := crqBundleTree(t, m, c)
				if !pins {
					files = crqWithTrust(files, crqTrustWithoutPrimaries(t))
				}
				files["want/roots/"+crqRoot+".yaml"] = []byte("version: 1\nkind: " + d.root + "\ntest: true\n")
				files["want/delegations/"+name+".yaml"] = []byte("version: 1\ntype: " + d.typ + "\nroot: " + crqRoot + "\n" + d.body)
				dir := t.TempDir()
				crqWrite(t, dir, files)
				const sentence = "this command cannot judge an openpgp-subkey request under the delegation " + name + ", which is of the type "
				want := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + sentence + d.typ +
					": the checks take the OpenPGP primaries only for a delegation of the type openpgp-subkey (the first check that did not run is check 3)\n"
				for _, mode := range [][]string{nil, {"--output", "json"}} {
					r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--delegation", name, "--dir", dir}, mode...)...)
					if r.code != ExitFailure || r.stderr != want {
						t.Fatalf("%v: (%d, %q), want exit code 1 and %q", mode, int(r.code), r.stderr, want)
					}
					if strings.Contains(r.stderr, "or none") || strings.Contains(r.stderr, "pins") {
						t.Errorf("the sentence says what the list pins: %q", r.stderr)
					}
					if mode != nil {
						if msg, _ := object(t, r.stdout)["error"].(string); msg != strings.TrimSuffix(strings.TrimPrefix(want, "ritueel: "), "\n") {
							t.Errorf("error member = %q", msg)
						}
					}
				}
			})
		}
	}
	// The neighbours keep their own sentences: the same request under no delegation, and under a delegation of the
	// type openpgp-subkey, for a list that pins none.
	files := crqWithTrust(crqBundleTree(t, m, c), crqTrustWithoutPrimaries(t))
	dir := t.TempDir()
	crqWrite(t, dir, files)
	none := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--dir", dir)
	if !strings.Contains(none.stderr, primariesText) || strings.Contains(none.stderr, "which is of the type x509") || strings.Contains(none.stderr, "the checks take") {
		t.Errorf("no delegation: %q", none.stderr)
	}
	sub := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--dir", dir, "--delegation", crqDelegation)
	if want := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + delegationPrimariesText + "\n"; sub.stderr != want {
		t.Errorf("openpgp-subkey delegation: %q, want %q", sub.stderr, want)
	}
}
