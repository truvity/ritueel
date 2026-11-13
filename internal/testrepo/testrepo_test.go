package testrepo

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeTB records a call that fails the test and stops the goroutine it was made in, as a real
// test does, so that a failure of Root, Path or Read can be asserted instead of failing this test.
type fakeTB struct {
	testing.TB
	failed  bool
	message string
}

func (f *fakeTB) Helper() {}

func (f *fakeTB) Fatalf(format string, args ...any) {
	f.failed = true
	f.message = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func (f *fakeTB) Fatal(args ...any) {
	f.failed = true
	f.message = fmt.Sprint(args...)
	runtime.Goexit()
}

func (f *fakeTB) Errorf(format string, args ...any) {
	f.failed = true
	f.message = fmt.Sprintf(format, args...)
}

func (f *fakeTB) FailNow() {
	f.failed = true
	runtime.Goexit()
}

// runFake runs fn against a fake test in its own goroutine and returns what the fake saw.
func runFake(fn func(tb testing.TB)) *fakeTB {
	f := &fakeTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(f)
	}()
	<-done
	return f
}

// samePath reports whether two paths name the same folder, whatever symbolic links lead to it.
func samePath(t *testing.T, a, b string) bool {
	t.Helper()
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		t.Fatal(err)
	}
	return ra == rb
}

func TestRootFindsTheFolderOfGoMod(t *testing.T) {
	// This package is at depth 2 (internal/testrepo), so the root is two folders up.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := Root(t)
	if want := filepath.Dir(filepath.Dir(wd)); !samePath(t, root, want) {
		t.Errorf("Root = %q, want the folder two levels above %q", root, wd)
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("no go.mod in the root %q: %v", root, err)
	}
	if !bytes.HasPrefix(mod, []byte("module ritueel.id/ritueel\n")) {
		t.Errorf("go.mod of the root starts %q, want the module of this repository", firstLine(mod))
	}
}

func firstLine(b []byte) string {
	line, _, _ := strings.Cut(string(b), "\n")
	return line
}

func TestRootIsTheNearestGoMod(t *testing.T) {
	outer := t.TempDir()
	inner := filepath.Join(outer, "inner")
	deep := filepath.Join(inner, "a", "b")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{outer, inner} {
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(deep)
	if got := Root(t); !samePath(t, got, inner) {
		t.Errorf("Root = %q, want the nearest folder with go.mod, %q", got, inner)
	}
	t.Chdir(inner)
	if got := Root(t); !samePath(t, got, inner) {
		t.Errorf("Root from the folder of go.mod itself = %q, want %q", got, inner)
	}
}

func TestRootIgnoresAFolderNamedGoMod(t *testing.T) {
	// A directory called go.mod is not the file; the search goes on above it.
	outer := t.TempDir()
	if err := os.WriteFile(filepath.Join(outer, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(outer, "sub")
	if err := os.MkdirAll(filepath.Join(sub, "go.mod"), 0o750); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	if got := Root(t); !samePath(t, got, outer) {
		t.Errorf("Root = %q, want %q (a folder named go.mod is not a module file)", got, outer)
	}
}

// noGoModAbove changes into a fresh folder that has no go.mod in it or above it. It skips the
// test when the machine's temporary folder is itself inside a module.
func noGoModAbove(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			t.Skipf("the temporary folder is inside a module (%s)", d)
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	t.Chdir(dir)
}

func TestRootFailsTheTestWithoutGoMod(t *testing.T) {
	noGoModAbove(t)
	var got string
	f := runFake(func(tb testing.TB) { got = Root(tb) })
	if !f.failed {
		t.Fatalf("Root did not fail the test and returned %q", got)
	}
	if !strings.Contains(f.message, "go.mod") {
		t.Errorf("the failure does not name go.mod: %q", f.message)
	}
}

func TestPathJoinsToTheRoot(t *testing.T) {
	root := Root(t)
	if got, want := Path(t, "testdata", "root-list"), filepath.Join(root, "testdata", "root-list"); got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
	if got := Path(t); got != root {
		t.Errorf("Path with no element = %q, want the root %q", got, root)
	}
	if _, err := os.Stat(Path(t, "testdata", "root-list", "README.md")); err != nil {
		t.Errorf("a file that exists is not found at its Path: %v", err)
	}
}

func TestPathFailsTheTestWithoutGoMod(t *testing.T) {
	noGoModAbove(t)
	f := runFake(func(tb testing.TB) { _ = Path(tb, "x") })
	if !f.failed {
		t.Error("Path did not fail the test")
	}
}

func TestReadReturnsTheFile(t *testing.T) {
	got := Read(t, "go.mod")
	want, err := os.ReadFile(filepath.Join(Root(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || !bytes.Equal(got, want) {
		t.Errorf("Read(go.mod) = %q, want the content of the file (%d bytes)", got, len(want))
	}
	if !bytes.HasPrefix(got, []byte("module ritueel.id/ritueel")) {
		t.Errorf("Read(go.mod) starts %q", firstLine(got))
	}
	// More than one element is joined.
	if readme := Read(t, "testdata", "root-list", "README.md"); !bytes.HasPrefix(readme, []byte("# Root list test vectors")) {
		t.Errorf("Read with several elements returned %q", firstLine(readme))
	}
}

func TestReadFailsTheTestOnAMissingFile(t *testing.T) {
	var got []byte
	f := runFake(func(tb testing.TB) { got = Read(tb, "testdata", "no-such-file.json") })
	if !f.failed {
		t.Fatalf("Read of a missing file did not fail the test and returned %q", got)
	}
	if !strings.Contains(f.message, "no-such-file.json") {
		t.Errorf("the failure does not name the file: %q", f.message)
	}
}
