package keydir

import (
	"os"
	"path/filepath"
	"testing"
)

// insideWorkTree says whether dir or a folder above it holds a .git entry. It is written here, apart
// from the function under test, so that a fault in that function cannot make a test skip itself.
func insideWorkTree(dir string) bool {
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(filepath.Join(cur, ".git")); err == nil {
			return true
		}
		if filepath.Dir(cur) == cur {
			return false
		}
	}
}

func TestTheRepositoryOfTheBundleIsFoundAtTheBundleItselfAndAboveIt(t *testing.T) {
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if got, ok := repositoryRoot(deep); ok {
		t.Fatalf("a repository is found at %q where there is none", got)
	}
	for _, at := range []string{deep, filepath.Join(root, "a", "b"), root} {
		if err := os.Mkdir(filepath.Join(at, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		got, ok := repositoryRoot(deep)
		if !ok || got != at {
			t.Errorf("the repository is %q (%v), want %q", got, ok, at)
		}
		if err := os.Remove(filepath.Join(at, ".git")); err != nil {
			t.Fatal(err)
		}
	}
	// The nearest one wins.
	for _, at := range []string{root, filepath.Join(root, "a", "b")} {
		if err := os.Mkdir(filepath.Join(at, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := repositoryRoot(deep); got != filepath.Join(root, "a", "b") {
		t.Errorf("the nearest repository is not found first: %q", got)
	}
}
