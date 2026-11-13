// Package testrepo finds the repository for tests that read files outside their own package,
// such as the fixtures under testdata/ at the top of the module. It is for _test.go files only.
package testrepo

import (
	"os"
	"path/filepath"
	"testing"
)

// Root returns the module root: the nearest parent of the working directory (or the working
// directory itself) that holds go.mod. It fails the test when there is none.
func Root(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("testrepo: working directory: %v", err)
	}
	for {
		if info, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("testrepo: no go.mod in any parent of the working directory")
		}
		dir = parent
	}
}

// Path returns filepath.Join(Root(t), elem...).
func Path(t testing.TB, elem ...string) string {
	t.Helper()
	return filepath.Join(append([]string{Root(t)}, elem...)...)
}

// Read returns the content of the file at Path(t, elem...) and fails the test when it cannot be read.
func Read(t testing.TB, elem ...string) []byte {
	t.Helper()
	p := Path(t, elem...)
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("testrepo: %v", err)
	}
	return data
}
