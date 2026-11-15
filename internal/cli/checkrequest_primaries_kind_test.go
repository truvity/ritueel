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
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/testrepo"
)

// Every fault of the OpenPGP primaries of the newest trust set gives the command one form: exit code 1 and one line
// that starts with "request STEM is not accepted and not refused: ", in text mode and in JSON mode. The faults are
// the faults of the keyring file (missing, not a plain file, refused by the reader). A list that pins more primaries
// than the checks take is not one of them: the checks take as many as a list holds, so no list that the reader accepts
// pins more. One fingerprint on two entries is not one of them either: the reader of the list refuses such a list
// first, as it refuses a label twice, and the command says so in the sentence of the bundle (see
// TestARepeatedFingerprintStopsTheCommandWithTheRefusalOfTheList).

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

// listRepeatLine is the line of the command for a bundle whose newest root list gives one fingerprint to two entries:
// the reader of the list refuses the list, and the error of the bundle says where and which entries. It is not the line
// of a request that is not judged.
func listRepeatLine(first, second string, at int) string {
	return "ritueel: bundle: the newest trust set " + crqTrustSet + ": root-list.json: malformed JSON: $.roots[" + strconv.Itoa(at) +
		"].openpgp_fingerprint: the fingerprint appears twice: the entries with the labels " + first + " and " + second + " have the same one\n"
}

// A list that gives one fingerprint to two entries is refused by the reader of the list before any keyring file is read:
// the line is the same whether the file is good, missing or garbage, and with every delegation and none. It names the
// list, the place and the two labels, and never the file and never the fingerprint. The exit code is 1, nothing is
// written on standard output in text mode, and the bundle is not changed.
func TestARepeatedFingerprintStopsTheCommandWithTheRefusalOfTheList(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	want := listRepeatLine("A", "B", 1)
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
		before := crqSnapshot(t, dir)
		for _, args := range [][]string{{"--delegation", crqDelegation}, nil} {
			r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--dir", dir}, args...)...)
			if r.code != ExitFailure || r.stderr != want || r.stdout != "" {
				t.Errorf("%s %v: (%d, %q, %q), want exit code 1 and %q", name, args, int(r.code), r.stdout, r.stderr, want)
			}
			if strings.Contains(r.stderr, fingerprintOfA) || strings.Contains(r.stderr, "keyring.gpg") {
				t.Errorf("%s %v: the line names the fingerprint or the file: %q", name, args, r.stderr)
			}
		}
		crqSame(t, "check request", before, crqSnapshot(t, dir))
	}
}

// The line, in both modes, for the places that the two entries can have, for each kind of request: the same line in
// text and in the member error of the object in JSON mode, with no result, no checks and no reasons.
func TestARepeatedFingerprintGivesTheSameLineInBothModesWhereverTheEntriesAre(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, tc := range []struct {
		name         string
		n, i, j      int
		first, other string
	}{
		{"the first two of 2", 2, 1, 0, "A", "B"},
		{"the first and the last of 16", 16, 15, 0, "A", "P"},
		{"the last two of 16", 16, 15, 14, "O", "P"},
	} {
		for _, id := range []string{"pgp-software-valid", "x509-software-valid"} {
			t.Run(tc.name+"/"+id, func(t *testing.T) {
				c := m.byID(t, id)
				roots := memRoots(t, tc.n)
				roots[tc.i].fp = roots[tc.j].fp
				files := crqWithTrust(crqBundleTree(t, m, c), memTrustOf(roots))
				dir := t.TempDir()
				crqWrite(t, dir, files)
				before := crqSnapshot(t, dir)
				want := listRepeatLine(tc.first, tc.other, tc.i)
				for _, mode := range [][]string{nil, {"--output", "json"}} {
					r := crqRun(t, now, append([]string{"check", "request", c.stem(t), "--dir", dir}, mode...)...)
					if r.code != ExitFailure || r.stderr != want || !onlyPrintable(r.stderr) {
						t.Fatalf("%v: (%d, %q), want exit code 1 and %q", mode, int(r.code), r.stderr, want)
					}
					if mode == nil {
						if r.stdout != "" {
							t.Errorf("text mode: standard output = %q", r.stdout)
						}
						continue
					}
					obj := object(t, r.stdout)
					if msg, _ := obj["error"].(string); msg != strings.TrimSuffix(strings.TrimPrefix(want, "ritueel: "), "\n") || obj["outcome"] != "failed" || obj["exit_code"] != jsonNumber("1") {
						t.Errorf("object = %s", r.stdout)
					}
					for _, k := range []string{"checks", "reasons"} {
						if _, ok := obj[k]; ok {
							t.Errorf("the object has %s: %s", k, r.stdout)
						}
					}
				}
				crqSame(t, "check request", before, crqSnapshot(t, dir))
			})
		}
	}
}

// Beside an x509-intermediate or an ssh-ca-key delegation the run is stopped too: the list is refused first, whatever the
// delegation takes, as it is for a label twice. (Before the reader of the list refused the repeat, such a run passed
// it, because it judged no primaries.)
func TestARepeatedFingerprintStopsTheCommandBesideEveryDelegation(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "x509-software-valid")
	for name, args := range map[string][]string{"x509 delegation": {"--delegation", crqDelegation}, "no delegation": nil} {
		t.Run(name, func(t *testing.T) {
			files := crqBundleTree(t, m, c)
			files[listAt] = bytes.Replace(files[listAt], []byte(fingerprintOfB), []byte(fingerprintOfA), 1)
			dir := t.TempDir()
			crqWrite(t, dir, files)
			r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--dir", dir}, args...)...)
			if want := listRepeatLine("A", "B", 1); r.code != ExitFailure || r.stderr != want || r.stdout != "" {
				t.Errorf("(%d, %q, %q), want exit code 1 and %q", int(r.code), r.stdout, r.stderr, want)
			}
		})
	}
	t.Run("a label twice gives the same kind of line", func(t *testing.T) {
		files := crqBundleTree(t, m, c)
		files[listAt] = bytes.Replace(files[listAt], []byte(`"label":"B"`), []byte(`"label":"A"`), 1)
		dir := t.TempDir()
		crqWrite(t, dir, files)
		r := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--dir", dir, "--delegation", crqDelegation)
		if want := "ritueel: bundle: the newest trust set " + crqTrustSet + ": root-list.json: malformed JSON: $.roots[1].label: the label appears twice\n"; r.code != ExitFailure || r.stderr != want {
			t.Errorf("(%d, %q), want exit code 1 and %q", int(r.code), r.stderr, want)
		}
	})
}

// Beside an x509-intermediate delegation the command gives no primaries and does not judge them: 17 pins or a missing
// file stop nothing there. (A list that the reader of the list refuses, one fingerprint on two entries among them,
// stops every run: see TestARepeatedFingerprintStopsTheCommandBesideEveryDelegation.)
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
