package ceremonytest_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const supportPath = "ritueel.id/ritueel/internal/ceremony/ceremonytest"

// moduleRoot is the folder that holds go.mod, found upward from the folder of the test.
func moduleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

// importers returns the .go files under root that are not test files and import the package of
// the support, with the number of files that were looked at. Only the imports are parsed. A folder
// named testdata, vendor or starting with a dot is not compiled and is not entered.
func importers(t testing.TB, root string) (found []string, looked int) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		looked++
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, "\"`") == supportPath {
				rel, _ := filepath.Rel(root, p)
				found = append(found, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found, looked
}

// The support package is for tests only: no non-test file of the module imports it, so the program
// never links it (and never links the package testing through it).
func TestNoFileOfTheProgramImportsTheSupport(t *testing.T) {
	root := moduleRoot(t)
	found, looked := importers(t, root)
	if looked < 100 {
		t.Fatalf("only %d files were looked at: the scan finds nothing to check", looked)
	}
	if len(found) != 0 {
		t.Errorf("non-test files import %s: %v", supportPath, found)
	}
}

// The program is under cmd/ and the packages it links are under internal/: the scan reaches both, so
// a file of the program that imports the support would be seen.
func TestTheScanReachesTheProgramAndItsPackages(t *testing.T) {
	root := moduleRoot(t)
	for _, dir := range []string{"cmd", "internal"} {
		if _, looked := importers(t, filepath.Join(root, dir)); looked == 0 {
			t.Errorf("no non-test file under %s was looked at", dir)
		}
	}
	if found, _ := importers(t, filepath.Join(root, "cmd")); len(found) != 0 {
		t.Errorf("the program imports the support: %v", found)
	}
}

// The scan sees what it is meant to see: a non-test file that imports the package, in any folder,
// with any alias, in a group or alone; and no test file and no file under testdata.
func TestTheScanFindsAnImport(t *testing.T) {
	root := t.TempDir()
	put := func(rel, src string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("go.mod", "module ritueel.id/ritueel\n")
	put("a/a.go", "package a\n\nimport \"ritueel.id/ritueel/internal/ceremony/ceremonytest\"\n\nvar _ = ceremonytest.Bundle\n")
	put("b/deep/b.go", "package b\n\nimport (\n\t\"fmt\"\n\tct \"ritueel.id/ritueel/internal/ceremony/ceremonytest\"\n)\n\nvar _ = ct.Bundle\nvar _ = fmt.Sprint\n")
	put("c/c.go", "package c\n\nimport _ \"ritueel.id/ritueel/internal/ceremony/ceremonytest\"\n")
	put("d/d.go", "package d\n\nimport \"fmt\"\n\nvar _ = fmt.Sprint\n")
	put("e/e_test.go", "package e\n\nimport \"ritueel.id/ritueel/internal/ceremony/ceremonytest\"\n\nvar _ = ceremonytest.Bundle\n")
	put("f/testdata/f.go", "package f\n\nimport \"ritueel.id/ritueel/internal/ceremony/ceremonytest\"\n")
	put("g/g.go", "package g\n\nimport \"ritueel.id/ritueel/internal/ceremony/ceremonytestx\"\n")
	put("h/h.go", "package h\n\n// import \"ritueel.id/ritueel/internal/ceremony/ceremonytest\"\n")
	found, looked := importers(t, root)
	want := []string{"a/a.go", "b/deep/b.go", "c/c.go"}
	if strings.Join(found, " ") != strings.Join(want, " ") {
		t.Errorf("found %v, want %v", found, want)
	}
	if looked != 6 {
		t.Errorf("looked at %d files, want 6", looked)
	}
}
