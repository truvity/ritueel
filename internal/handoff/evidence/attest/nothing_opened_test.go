package attest_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The shipped packages read bytes that they are given: they open no file (so there is no link to follow and
// no pipe to block on), make no network call, start no program and no goroutine, and hold no state that a
// call changes. This test reads their sources and fails on an import or a statement that would do any of it.
// The test-support package is not one of them: it reads the vectors through internal/testrepo.
func TestTheShippedPackagesOpenNothingAndStartNothing(t *testing.T) {
	forbidden := []string{
		"os", "os/exec", "os/signal", "os/user", "io/ioutil", "io/fs", "path/filepath", "net", "net/http", "net/url", "net/rpc",
		"syscall", "unsafe", "plugin", "runtime/debug", "internal/fsx", "internal/testrepo", "testing",
	}
	var files int
	for _, pkg := range []string{"../attest", "../piv", "../openpgpcard"} {
		entries, err := os.ReadDir(pkg)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			files++
			path := filepath.Join(pkg, name)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				for _, bad := range forbidden {
					if p == bad || strings.HasSuffix(p, "/"+bad) {
						t.Errorf("%s imports %q", path, p)
					}
				}
			}
			full, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(full, func(n ast.Node) bool {
				if g, ok := n.(*ast.GoStmt); ok {
					t.Errorf("%s: a goroutine at %s", path, fset.Position(g.Pos()))
				}
				return true
			})
			// A package variable that holds state: only the errors and the object identifiers are allowed.
			for _, d := range full.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, s := range gd.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, id := range vs.Names {
						if !slices.Contains([]string{"_", "ErrBundle", "oidFirmware", "oidSerial", "oidPolicy", "oidFormFactor", "oidCommonName"}, id.Name) {
							t.Errorf("%s: the package variable %s", path, id.Name)
						}
					}
				}
			}
		}
	}
	if files < 4 {
		t.Errorf("found %d source files in the three packages, want at least 4", files)
	}
}
