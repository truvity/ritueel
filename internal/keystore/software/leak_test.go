package software

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// A leak test runs the operations of the package, in success and in failure, with a made-up key,
// and looks for any form of the key in everything that comes out, and for the paths of the key
// folder and the bundle (the title of the test is the plan's: no key bytes leak into logs, errors
// or temporary files).

// errorTexts is every text that an error can show: its Error, the verbs %v %+v %#v %q, and the
// same for each error in its chain (Unwrap and Unwrap() []error).
func errorTexts(err error) []string {
	var out []string
	var walk func(e error, depth int)
	walk = func(e error, depth int) {
		if e == nil || depth > 20 {
			return
		}
		out = append(out, e.Error(), fmt.Sprintf("%v", e), fmt.Sprintf("%+v", e), fmt.Sprintf("%#v", e), fmt.Sprintf("%q", e), fmt.Sprintf("%s", e))
		//nolint:errorlint // the chain is walked by hand on purpose, to read every link
		switch u := e.(type) {
		case interface{ Unwrap() error }:
			walk(u.Unwrap(), depth+1)
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				walk(c, depth+1)
			}
		}
	}
	walk(err, 0)
	return out
}

// leakScenario is the set of operations that the leak tests run. It returns every error that a
// call gave, and the errors that a call that should not fail gave are test failures.
func leakScenario(t *testing.T, s *Store, bundle, keys string) ([]error, canaries) {
	t.Helper()
	var errs []error
	note := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}
	k, other := mustGenerate(t), mustGenerate(t)
	cert := certFor(t, k)
	otherCert := certFor(t, other)
	secrets := keysOf(t, k, cert).with(keysOf(t, other, otherCert))
	jws := jwsOf("a", "b", "c")

	// success
	for name, err := range map[string]error{
		"SaveX509":       s.SaveX509("A", k),
		"SaveOpenPGP":    s.SaveOpenPGP("A", k, cert),
		"SaveRevocation": s.SaveRevocation("A", "compromised", revocationFor(t, k, openpgp.Compromised)),
		"SaveRemoval":    s.SaveRemoval("A", jws),
	} {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := s.HasKeyFiles(); err != nil {
		t.Fatal(err)
	}
	got, err := s.OpenX509(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Close()
	pg, err := s.OpenOpenPGP(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	_ = pg.Key.Close()

	// the refusals of the caller
	note(s.SaveX509("a", k))
	note(s.SaveX509("A", nil))
	note(s.SaveOpenPGP("B", k, otherCert))
	note(s.SaveOpenPGP("B", k, nil))
	note(s.SaveRevocation("B", "stolen", revocationFor(t, k, openpgp.Retired)))
	note(s.SaveRevocation("B", "retired", []byte("junk")))
	note(s.SaveRemoval("B", []byte("no dots")))
	note(CheckKeyDir(bundle, bundle))
	note(CheckKeyDir(filepath.Join(bundle, "history"), bundle))
	note(CheckKeyDir(keys, ""))
	note(CheckKeyDir(filepath.Join(keys, "nowhere"), bundle))
	_, e := Open(Config{KeyDir: keys, BundleDir: bundle})
	note(e)
	_, e = Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase}) // a passphrase root with no source
	note(e)
	_, e = Open(Config{KeyDir: bundle, BundleDir: bundle, Mode: ModeTest})
	note(e)

	// a second save of the same names: the files exist, and the writer stops
	note(s.SaveX509("A", other))
	note(s.SaveOpenPGP("A", other, otherCert))

	// the reads of damaged files, made from the real key files
	x := readKeyFile(t, keys, "A.x509.key.pem")
	p := readKeyFile(t, keys, "A.openpgp.key.asc")
	r := readKeyFile(t, keys, "A.revocation.compromised.asc")
	srcs := map[string][]byte{"x509.key.pem": x, "openpgp.key.asc": p, "revocation.compromised.asc": r}
	for _, edit := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:len(b)-5] },
		func(b []byte) []byte { b = bytes.Clone(b); b[len(b)/2] ^= 1; return b },
		func(b []byte) []byte { return append(bytes.Clone(b), "trailing text\n"...) },
		func(b []byte) []byte { return append(bytes.Clone(b), bytes.Repeat([]byte("\n"), MaxKeyFileSize)...) },
		func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")) },
	} {
		for suffix, src := range srcs {
			writeKeyFile(t, keys, "B."+suffix, edit(src))
		}
		_, e1 := s.OpenX509(bg(), "B")
		_, e2 := s.OpenOpenPGP(bg(), "B")
		_, e3 := s.ReadRevocation(bg(), "B", "compromised")
		note(e1)
		note(e2)
		note(e3)
	}
	_, e = s.OpenX509(bg(), "C") // missing
	note(e)
	_, e = s.ReadRemoval(bg(), "C")
	note(e)
	writeKeyFile(t, keys, "D.x509.key.age", x)
	_, e = s.OpenX509(bg(), "D") // the other mode, holding the key bytes
	note(e)
	note(s.SaveX509("E", other)) // refused: a file of the other mode stands there
	return errs, secrets
}

func TestNoKeyByteAndNoPathReachesAnErrorOrItsText(t *testing.T) {
	s, bundle, keys := openStore(t)
	root := filepath.Dir(keys)
	errs, ring := leakScenario(t, s, bundle, keys)
	if len(errs) < 20 {
		t.Fatalf("only %d errors were collected", len(errs))
	}
	paths := []string{keys, bundle, root}
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
			if strings.Contains(text, "/tmp") || strings.Contains(text, "TestNo") {
				t.Errorf("error %d holds a path: %q", i, text)
			}
		}
	}
}

func TestNoKeyByteReachesAFileOrFolderOutsideTheKeyFolder(t *testing.T) {
	bundle, keys := newBundle(t)
	tmp, work := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Chdir(work)
	s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModeTest})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	_, _ = leakScenario(t, s, bundle, keys)
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
	if h := dirNames(t, filepath.Join(bundle, "history")); len(h) != 0 {
		t.Errorf("history holds %v", h)
	}
	// Every name in the key folder is a key file that the scenario made or put there. The second
	// save of a name that exists is refused before a byte is written, so no temporary file stands
	// in the folder (the file of a test root is plain by nature, and nothing is deleted).
	for _, n := range dirNames(t, keys) {
		if strings.HasPrefix(n, fsx.TempPrefix) {
			t.Errorf("a temporary file %s stands in the key folder", n)
			continue
		}
		if _, ok := isKeyFileName(n); !ok {
			t.Errorf("%s is not the name of a key file", n)
		}
	}
}

// A key file of a test root is plain by nature: the bytes that the writer is given are exactly the
// expected file, and no other file receives a key byte.
func TestTheWriterIsGivenFileNamesAndTheExpectedFilesOnly(t *testing.T) {
	s, bundle, keys := openStore(t)
	rec := record(s)
	_, _ = leakScenario(t, s, bundle, keys)
	if len(rec.writes) < 4 {
		t.Fatalf("%d writes", len(rec.writes))
	}
	for _, w := range rec.writes {
		if strings.ContainsAny(w.name, `/\`) || strings.Contains(w.name, keys) {
			t.Errorf("the writer is given a path: %q", w.name)
		}
		if _, ok := isKeyFileName(w.name); !ok {
			t.Errorf("the writer is given %q, which is not the name of a key file", w.name)
		}
		if w.perm != 0o600 {
			t.Errorf("%s: mode %v", w.name, w.perm)
		}
		if len(w.data) > MaxKeyFileSize {
			t.Errorf("%s: %d bytes", w.name, len(w.data))
		}
	}
}

func TestWrappedAndJoinedErrorsOfSignHoldNoKeyByte(t *testing.T) {
	k := mustGenerate(t)
	secrets := keysOf(t, k, certFor(t, k))
	closed := mustGenerate(t)
	_ = closed.Close()
	_, e1 := k.Sign(nil, []byte("short"), crypto.SHA384)
	_, e2 := closed.Sign(nil, digest48(), crypto.SHA384)
	k.s.tamper = func(b []byte) []byte { return b[:len(b)-1] }
	_, e3 := k.Sign(nil, digest48(), crypto.SHA384)
	for name, err := range map[string]error{
		"wrapped":                fmt.Errorf("sign: %w", e1),
		"wrapped 2":              fmt.Errorf("sign %v: %w", k, e2),
		"joined":                 errors.Join(e1, e2, e3),
		"joined in":              fmt.Errorf("ceremony: %w", errors.Join(fmt.Errorf("a: %w", e1), fmt.Errorf("b: %w", e3))),
		"the key in the message": fmt.Errorf("key %v %+v %#v %s: %w", k, k, k, k, e3),
	} {
		for _, text := range errorTexts(err) {
			if f := secrets.findText(text); f != "" {
				t.Errorf("%s holds a canary (%s): %q", name, f, text)
			}
		}
	}
}

// The sources of the two packages import no logger, no program runner, no network and no
// standard stream, and read no environment variable (the package says so in its comment).
func TestTheSourcesImportNoLogNoProgramNoNetworkAndTouchNoStreamOrEnvironment(t *testing.T) {
	forbiddenImports := map[string]bool{
		"log": true, "log/slog": true, "os/exec": true, "net": true, "net/http": true, "expvar": true,
		"runtime/debug": true, "testing": true, "os/signal": true, "net/rpc": true, "net/smtp": true,
	}
	forbiddenSelectors := map[string]bool{
		"os.Getenv": true, "os.LookupEnv": true, "os.Environ": true, "os.Stdout": true, "os.Stderr": true, "os.Stdin": true,
		"os.Setenv": true, "os.Exit": true, "fmt.Print": true, "fmt.Printf": true, "fmt.Println": true,
		"fmt.Fprint": true, "fmt.Fprintf": true, "fmt.Fprintln": true,
	}
	files := 0
	for _, dir := range [][]string{{"internal", "keystore"}, {"internal", "keystore", "software"}} {
		path := testrepo.Path(t, dir...)
		ents, err := os.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			files++
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, filepath.Join(path, e.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if forbiddenImports[p] {
					t.Errorf("%s imports %s", e.Name(), p)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && forbiddenSelectors[id.Name+"."+sel.Sel.Name] {
					t.Errorf("%s uses %s.%s", e.Name(), id.Name, sel.Sel.Name)
				}
				return true
			})
		}
	}
	if files < 8 {
		t.Fatalf("only %d source files were found: the check checked nothing", files)
	}
}
