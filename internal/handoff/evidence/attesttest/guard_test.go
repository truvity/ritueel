package attesttest_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

const attesttestPath = "ritueel.id/ritueel/internal/handoff/evidence/attesttest"

// importsAttesttest reports whether the Go source (read from src, or from the file when src is nil) imports
// the test support package, in any spelling: plain, renamed, blank or dot.
func importsAttesttest(t testing.TB, path string, src any) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err == nil && p == attesttestPath {
			return true
		}
	}
	return false
}

// The package builds attestation chains with keys that are made in memory, and shipped code must never link
// it: the test fails when a Go file of the module that is not a test file imports it. A package of the module
// that several test packages share cannot be a _test.go file, so the walk is the guard at build time (the
// init of guard.go is the one at run time).
func TestNoNonTestFileOfTheModuleImportsTheTestSupport(t *testing.T) {
	root := testrepo.Root(t)
	var seen, importers int
	looked := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		seen++
		rel, _ := filepath.Rel(root, path)
		looked[filepath.ToSlash(rel)] = true
		if importsAttesttest(t, path, nil) {
			t.Errorf("%s imports the test support package %s", rel, attesttestPath)
			importers++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A walk that does not reach the program and the package itself proves nothing.
	for _, want := range []string{"cmd/ritueel/main.go", "internal/handoff/evidence/attesttest/maker.go", "internal/handoff/evidence/attest/bundle.go"} {
		if !looked[want] {
			t.Errorf("%s was not looked at (%d files were)", want, seen)
		}
	}
	if importers != 0 {
		t.Logf("%d files import it", importers)
	}
}

// The check sees the import in every spelling, and a test file may import the package.
func TestTheImportCheckSeesEverySpelling(t *testing.T) {
	src := func(spec string) string {
		return "package p\n\nimport (\n\t\"fmt\"\n\t" + spec + "\n)\n\nvar _ = fmt.Sprint\n"
	}
	q := strconv.Quote(attesttestPath)
	for name, spec := range map[string]string{
		"plain":   q,
		"renamed": "at " + q,
		"blank":   "_ " + q,
		"dot":     ". " + q,
	} {
		if !importsAttesttest(t, "p.go", src(spec)) {
			t.Errorf("%s import not seen", name)
		}
	}
	// A package whose path only starts or ends like it is another package.
	for _, other := range []string{
		strconv.Quote(attesttestPath + "x"),
		strconv.Quote(attesttestPath + "/sub"),
		strconv.Quote("example.org/" + attesttestPath),
		strconv.Quote("ritueel.id/ritueel/internal/handoff/evidence/attest"),
	} {
		if importsAttesttest(t, "p.go", src(other)) {
			t.Errorf("%s taken for the test support", other)
		}
	}
	if importsAttesttest(t, "p.go", "package p\n") {
		t.Error("a file with no import")
	}
}

// guard.go holds an init that panics unless testing.Testing() is true. The check reads the source, because
// a program that links the package cannot be started from a test.
func TestTheGuardPanicsUnlessTheProgramIsATest(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "guard.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "init" || fn.Recv != nil || fn.Body == nil {
			continue
		}
		found = true
		if len(fn.Body.List) != 1 {
			t.Fatalf("the init holds %d statements, want the one test", len(fn.Body.List))
		}
		cond, ok := fn.Body.List[0].(*ast.IfStmt)
		if !ok {
			t.Fatal("the init is not a single if")
		}
		// The condition is `!testing.Testing()`.
		not, ok := cond.Cond.(*ast.UnaryExpr)
		if !ok || not.Op != token.NOT {
			t.Fatal("the condition is not a negation")
		}
		call, ok := not.X.(*ast.CallExpr)
		if !ok {
			t.Fatal("the condition does not call a function")
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			t.Fatal("the condition does not call a package function")
		}
		if id, isID := sel.X.(*ast.Ident); !isID || id.Name != "testing" || sel.Sel.Name != "Testing" {
			t.Fatal("the condition is not testing.Testing()")
		}
		if cond.Else != nil || len(cond.Body.List) != 1 {
			t.Fatal("the if has an else or more than one statement")
		}
		stmt, ok := cond.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Fatal("the body is not a call")
		}
		pc, ok := stmt.X.(*ast.CallExpr)
		if !ok {
			t.Fatal("the body is not a call")
		}
		if id, ok := pc.Fun.(*ast.Ident); !ok || id.Name != "panic" {
			t.Fatal("the body does not panic")
		}
	}
	if !found {
		t.Fatal("guard.go holds no init")
	}
}
