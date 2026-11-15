package software

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// passphraseCanaries is every form of a passphrase that a leak could take: the bytes and each
// window of eight bytes.
func passphraseCanaries(passes ...string) canaries {
	var out canaries
	for _, p := range passes {
		out = append(out, canary{"passphrase", []byte(p)})
		for i := 0; i+8 <= len(p); i++ {
			out = append(out, canary{"passphrase window", []byte(p[i : i+8])})
		}
	}
	return out
}

// passLeakScenario runs the operations of a passphrase root, in success and in failure, and returns
// every error that a call gave. The passphrases are testPass (the right one) and testPass2 (the wrong one).
func passLeakScenario(t *testing.T, s *Store, src *passSource, keys string) ([]error, canaries) {
	t.Helper()
	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	k, other := mustGenerate(t), mustGenerate(t)
	cert, otherCert := certFor(t, k), certFor(t, other)
	secrets := keysOf(t, k, cert).with(keysOf(t, other, otherCert)).with(passphraseCanaries(testPass, testPass2))

	for name, err := range map[string]error{
		"SaveX509": s.SaveX509("A", k), "SaveOpenPGP": s.SaveOpenPGP("A", k, cert),
		"SaveRevocation": s.SaveRevocation("A", "compromised", revocationFor(t, k, openpgp.Compromised)),
		"SaveRemoval":    s.SaveRemoval("A", jwsOf("a", "b", "c")),
	} {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if got, err := s.OpenX509(bg(), "A"); err != nil {
		t.Fatal(err)
	} else {
		_ = got.Close()
	}

	// a wrong passphrase, a refused one, a source that fails, and no passphrase at all
	src.def = testPass2
	_, e := s.OpenX509(bg(), "A")
	note(e)
	_, e = s.OpenOpenPGP(bg(), "A")
	note(e)
	src.def = "short"
	_, e = s.OpenX509(bg(), "A")
	note(e)
	note(s.SaveX509("B", other))
	src.def = testPass + "\x00"
	note(s.SaveX509("B", other))
	src.def = testPass
	src.err = errors.New("the source failed")
	_, e = s.OpenX509(bg(), "A")
	note(e)
	note(s.SaveX509("B", other))
	src.err = nil
	src.raw = func(Purpose) []byte { return nil }
	note(s.SaveX509("B", other))
	src.raw = nil

	// the refusals of the caller and of the folder
	note(s.SaveX509("a", k))
	note(s.SaveX509("A", nil))
	note(s.SaveOpenPGP("B", k, otherCert))
	note(s.SaveRevocation("B", "stolen", revocationFor(t, k, openpgp.Retired)))
	note(s.SaveRemoval("B", []byte("no dots")))
	note(s.SaveX509("A", other))
	note(s.SaveOpenPGP("A", other, otherCert))

	// damaged and wrong files, made from the real file
	file := readKeyFile(t, keys, "A.x509.key.age")
	hl := headerLen(t, file)
	flip := func(i int) []byte { d := bytes.Clone(file); d[i] ^= 1; return d }
	for _, d := range [][]byte{
		flip(hl + 20), flip(hl - 4), flip(30), file[:len(file)-1], file[:hl], file[:20],
		append(bytes.Clone(file), 1), headerOf(scryptStanza("23")), headerOf(scryptStanza("17")),
		x509File(t, k), []byte(armourLine("BEGIN", "AGE ENCRYPTED FILE") + "\n"),
		bytes.Repeat([]byte{0xA5}, MaxKeyFileSize+1),
	} {
		writeKeyFile(t, keys, "C.x509.key.age", d)
		_, e = s.OpenX509(bg(), "C")
		note(e)
		_ = os.Remove(filepath.Join(keys, "C.x509.key.age"))
	}
	_, e = s.OpenX509(bg(), "D") // missing
	note(e)
	writeKeyFile(t, keys, "E.x509.key.pem", x509File(t, k))
	_, e = s.OpenX509(bg(), "E") // the other mode
	note(e)
	_ = os.Remove(filepath.Join(keys, "E.x509.key.pem"))
	return errs, secrets
}

func TestNoKeyByteNoPassphraseAndNoPathReachesAnErrorOfAPassphraseRoot(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, bundle, keys := openPassStore(t, src)
	errs, ring := passLeakScenario(t, s, src, keys)
	if len(errs) < 25 {
		t.Fatalf("only %d errors were collected", len(errs))
	}
	paths := []string{keys, bundle, filepath.Dir(keys)}
	for i, err := range errs {
		for _, text := range errorTexts(err) {
			if f := ring.findText(text); f != "" {
				t.Errorf("error %d holds a canary (%s): %q", i, f, text)
			}
			for _, p := range paths {
				if strings.Contains(text, p) {
					t.Errorf("error %d holds the path %s: %q", i, p, text)
				}
			}
			// the text of the library quotes lines of the file
			if strings.Contains(text, "age-encryption") || strings.Contains(text, "-> scrypt") || strings.Contains(text, "failed to") {
				t.Errorf("error %d repeats the text of the file or of the library: %q", i, text)
			}
		}
	}
}

func TestWrongPassphraseDamagedFileAndWorkFactorRefusalLeaveTheSameMarksAndNoTemporaryFile(t *testing.T) {
	lowWork(t)
	bundle, keys := newBundle(t)
	tmp, work := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Chdir(work)
	src := newPassSource(testPass)
	s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: src})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	_, ring := passLeakScenario(t, s, src, keys)
	for _, dir := range []string{tmp, work} {
		if names := dirNames(t, dir); len(names) != 0 {
			t.Errorf("%s holds %v", filepath.Base(dir), names)
		}
	}
	got := dirNames(t, bundle)
	sort.Strings(got)
	if strings.Join(got, " ") != "history ritueel.yaml" {
		t.Errorf("the bundle holds %v", got)
	}
	// the key folder holds the four files of label A and nothing else: no temporary file, no plain file
	want := []string{"A.openpgp.key.age", "A.removal.jws.age", "A.revocation.compromised.pgp.age", "A.x509.key.age"}
	names := dirNames(t, keys)
	sort.Strings(names)
	if strings.Join(names, " ") != strings.Join(want, " ") {
		t.Errorf("the key folder holds %v", names)
	}
	// and what stands there holds no key byte and no passphrase
	for _, n := range names {
		if c := ring.find(readKeyFile(t, keys, n)); c != "" {
			t.Errorf("%s holds a canary: %s", n, c)
		}
	}
}

func TestTheWriterOfAPassphraseRootSeesOnlyAgeCiphertextAndNeverTheSameBytesTwice(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	rec := record(s)
	k := mustGenerate(t)
	cert := certFor(t, k)
	ring := keysOf(t, k, cert).with(passphraseCanaries(testPass))
	f := fourFiles{k: k, cert: cert, x509: pemOf(t, k), pgp: secretOf(t, k, cert), revoke: revocationFor(t, k, openpgp.Superseded), removal: jwsOf("YQ", "Yg", "Yw")}
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveX509("B", k); err != nil { // the same key and passphrase: another file
		t.Fatal(err)
	}
	if err := s.SaveOpenPGP("A", k, cert); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRevocation("A", "superseded", f.revoke); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRemoval("A", f.removal); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 5 {
		t.Fatalf("%d writes", len(rec.writes))
	}
	seen := map[string]string{}
	for _, w := range rec.writes {
		if !bytes.HasPrefix(w.data, []byte("age-encryption.org/v1\n")) {
			t.Errorf("%s does not start with the age header line", w.name)
		}
		if c := ring.find(w.data); c != "" {
			t.Errorf("%s holds a canary: %s", w.name, c)
		}
		for _, plain := range [][]byte{f.revoke, f.removal, []byte("TEST ONLY"), []byte("PRIVATE KEY"), []byte("PGP")} {
			if bytes.Contains(w.data, plain) {
				t.Errorf("%s holds the plain text %q", w.name, plain[:min(len(plain), 8)])
			}
		}
		if w.perm != 0o600 {
			t.Errorf("%s: mode %v", w.name, w.perm)
		}
		if other, ok := seen[string(w.data)]; ok {
			t.Errorf("%s and %s are the same bytes", w.name, other)
		}
		seen[string(w.data)] = w.name
		// the file on disk is what the writer was given
		if !bytes.Equal(readKeyFile(t, keys, w.name), w.data) {
			t.Errorf("%s: the file is not what the writer was given", w.name)
		}
	}
	if rec.writes[0].name != "A.x509.key.age" || rec.writes[1].name != "B.x509.key.age" {
		t.Errorf("the names %q %q", rec.writes[0].name, rec.writes[1].name)
	}
}

func TestAFailedWriteOfAPassphraseRootLeavesOnlyCiphertextAndTheErrorHoldsNoSecret(t *testing.T) {
	lowWork(t)
	for _, step := range []fsx.Step{fsx.StepCreate, fsx.StepWrite, fsx.StepSyncFile, fsx.StepRename, fsx.StepSyncDir} {
		t.Run(string(step), func(t *testing.T) {
			src := newPassSource(testPass)
			s, bundle, keys := openPassStore(t, src)
			failAt(t, s, keys, step)
			k := mustGenerate(t)
			cert := certFor(t, k)
			ring := keysOf(t, k, cert).with(passphraseCanaries(testPass))
			for _, save := range []func() error{
				func() error { return s.SaveX509("A", k) },
				func() error { return s.SaveOpenPGP("A", k, cert) },
			} {
				err := save()
				if err == nil {
					t.Fatal("the save succeeded with a failing writer")
				}
				for _, text := range errorTexts(err) {
					if f := ring.findText(text); f != "" {
						t.Errorf("the error holds a canary (%s): %q", f, text)
					}
					if strings.Contains(text, keys) || strings.Contains(text, bundle) {
						t.Errorf("the error holds a path: %q", text)
					}
				}
			}
			if k.Saved() {
				t.Error("Saved")
			}
			for _, n := range dirNames(t, keys) {
				data := readKeyFile(t, keys, n)
				if c := ring.find(data); c != "" {
					t.Errorf("%s holds a canary: %s", n, c)
				}
				if len(data) > 0 && !bytes.HasPrefix(data, []byte("age-encryption.org/v1\n")) && len(data) > 8 {
					t.Errorf("%s does not start with the age header", n)
				}
			}
			// the writer is stopped: a later save asks for nothing more and writes nothing more
			asked := src.calls()
			err := s.SaveX509("B", k)
			if err == nil {
				t.Error("a save after the stop succeeded")
			}
			if src.calls() != asked {
				t.Error("a stopped writer asked for a passphrase")
			}
		})
	}
}

// ---- what the package imports ----

func sourceFilesOfSoftware(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	path := testrepo.Path(t, "internal", "keystore", "software")
	ents, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(path, e.Name()), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files[e.Name()] = f
	}
	if len(files) < 8 {
		t.Fatalf("only %d source files: the check checked nothing", len(files))
	}
	return fset, files
}

func TestOfTheAgeLibraryThePackageImportsOnlyThePackageAge(t *testing.T) {
	_, files := sourceFilesOfSoftware(t)
	ageImported := false
	for name, f := range files {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == "filippo.io/age" {
				ageImported = true
				continue
			}
			if strings.HasPrefix(p, "filippo.io/") {
				t.Errorf("%s imports %s: only filippo.io/age (no plugin, no armour, no ssh recipients) is allowed", name, p)
			}
			if strings.HasPrefix(p, "golang.org/x/term") || strings.HasPrefix(p, "golang.org/x/crypto/ssh") {
				t.Errorf("%s imports %s: the package reads no terminal", name, p)
			}
		}
	}
	if !ageImported {
		t.Error("no file imports filippo.io/age")
	}
	// the package is a library of the base build: no program, no network, no log
	for name, f := range files {
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			switch p {
			case "os/exec", "net", "net/http", "log", "log/slog", "syscall", "unsafe", "plugin", "C":
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
}

func TestNoSourceFileSetsTheTwoWorkFactorVariables(t *testing.T) {
	fset, files := sourceFilesOfSoftware(t)
	assigned := 0
	for name, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.AssignStmt:
				for _, l := range v.Lhs {
					if id, ok := l.(*ast.Ident); ok && (id.Name == "workFactorWritten" || id.Name == "workFactorLowest") {
						t.Errorf("%s: %s assigns %s", name, fset.Position(id.Pos()), id.Name)
					}
				}
			case *ast.IncDecStmt:
				if id, ok := v.X.(*ast.Ident); ok && (id.Name == "workFactorWritten" || id.Name == "workFactorLowest") {
					t.Errorf("%s: %s changes %s", name, fset.Position(id.Pos()), id.Name)
				}
			case *ast.UnaryExpr:
				if id, ok := v.X.(*ast.Ident); ok && v.Op == token.AND && (id.Name == "workFactorWritten" || id.Name == "workFactorLowest") {
					t.Errorf("%s: %s takes the address of %s", name, fset.Position(id.Pos()), id.Name)
				}
			case *ast.ValueSpec:
				for i, id := range v.Names {
					if id.Name != "workFactorWritten" && id.Name != "workFactorLowest" {
						continue
					}
					assigned++
					lit := ""
					if i < len(v.Values) {
						if x, ok := v.Values[i].(*ast.Ident); ok {
							lit = x.Name
						}
					}
					want := map[string]string{"workFactorWritten": "WriteWorkFactor", "workFactorLowest": "MinWorkFactor"}[id.Name]
					if lit != want {
						t.Errorf("%s is set from %q, want %s", id.Name, lit, want)
					}
				}
			}
			return true
		})
	}
	if assigned != 2 {
		t.Errorf("%d declarations of the work factor variables, want 2", assigned)
	}
}

func TestGoModPinsTheAgeLibraryExactlyWithItsComment(t *testing.T) {
	mod := string(testrepo.Read(t, "go.mod"))
	re := regexp.MustCompile(`(?m)^\s*filippo\.io/age (v\d+\.\d+\.\d+) // pinned exactly: .*record 0002.*$`)
	if !re.MatchString(mod) {
		t.Errorf("go.mod has no line of filippo.io/age with an exact version and the comment of go-crypto's form")
	}
	for _, bad := range []string{"filippo.io/age/plugin", "filippo.io/age/armor", "filippo.io/age/agessh"} {
		if strings.Contains(mod, bad) {
			t.Errorf("go.mod names %s", bad)
		}
	}
	if strings.Count(mod, "filippo.io/age ") != 1 {
		t.Error("filippo.io/age is not required exactly once")
	}
	// the comment of go-crypto stands beside it, so the two are alike
	if !strings.Contains(mod, "github.com/ProtonMail/go-crypto") || !strings.Contains(mod, "// pinned exactly: an upgrade is a reviewed change") {
		t.Error("the pin comment of go-crypto is missing")
	}
}
