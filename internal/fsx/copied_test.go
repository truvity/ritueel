package fsx_test

// A Writer that is copied by value after its first use: a call on the copy answers ErrCopied before it
// reaches the file system, and the copy's Close does not release the root. The copy is made with
// reflect, because go vet refuses a plain copy of a value that holds a mutex (which is its point).

import (
	"errors"
	"io/fs"
	"reflect"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func copyOf(w *fsx.Writer) *fsx.Writer {
	src := reflect.ValueOf(w).Elem()
	dst := reflect.New(src.Type())
	dst.Elem().Set(src)
	return dst.Interface().(*fsx.Writer)
}

func TestACopyOfAUsedWriterIsRefusedForEveryMethod(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	if err := w.WriteFile("b/d/first", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := w.CreateJournal("b/d/j")
	if err != nil {
		t.Fatal(err)
	}
	c := copyOf(w)
	n := f.opCount()
	for name, call := range map[string]func() error{
		"WriteFile":     func() error { return c.WriteFile("b/d/x", []byte("x"), 0o600) },
		"WriteSet":      func() error { return c.WriteSet("b/d/s", []fsx.NewFile{{Name: "a", Perm: 0o600}}) },
		"Mkdir":         func() error { return c.Mkdir("b/d/m", 0o700) },
		"CreateJournal": func() error { j2, err := c.CreateJournal("b/d/j2"); _ = j2; return err },
		"TempName":      func() error { _, err := c.TempName(); return err },
		"Close":         func() error { return c.Close() },
		// the argument is not looked at first
		"WriteFile with an invalid path": func() error { return c.WriteFile("", nil, 0o600) },
		"WriteFile with a bad mode":      func() error { return c.WriteFile("b/d/y", nil, 0) },
		"WriteSet with a bad name":       func() error { return c.WriteSet("b/d/s", []fsx.NewFile{{Name: "a b"}}) },
	} {
		err := call()
		if !errors.Is(err, fsx.ErrCopied) {
			t.Errorf("%s on the copy: %v, want ErrCopied", name, err)
		}
		if errors.Is(err, fsx.ErrInvalid) || errors.Is(err, fsx.ErrStopped) || errors.Is(err, fsx.ErrWriterClosed) {
			t.Errorf("%s on the copy: %v, want only ErrCopied", name, err)
		}
	}
	if j2, err := c.CreateJournal("b/d/j3"); j2 != nil || !errors.Is(err, fsx.ErrCopied) {
		t.Errorf("CreateJournal on the copy: %v, %v", j2, err)
	}
	if f.opCount() != n {
		t.Fatalf("a call on the copy reached the file system: %v", f.opsAfter(n))
	}
	// the original is unaffected: its calls, its journal, and the root that its Close releases
	if err := w.WriteFile("b/d/second", []byte("2"), 0o600); err != nil {
		t.Fatalf("the original after the calls on the copy: %v", err)
	}
	if err := j.Append([]byte("line")); err != nil {
		t.Fatalf("the journal of the original: %v", err)
	}
	requireOpen(t, f, 1)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.TempName(); err != nil {
		t.Fatalf("the original: %v", err)
	}
	// the copy's Close did not release the root: it is open until the original's Close
	if d, _ := f.handles(); d != 1 {
		t.Fatalf("%d folders open after the copy's Close, want the root", d)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	requireClean(t, f)
	if err := c.Close(); !errors.Is(err, fsx.ErrCopied) {
		t.Fatalf("the copy's Close after the original's: %v, want ErrCopied again", err)
	}
}

// A copy of a writer that stopped, or was closed, still answers ErrCopied: the copy is not the writer.
func TestACopyAnswersErrCopiedBeforeTheStopAndBeforeClose(t *testing.T) {
	s := stopWith(t, causeNamed("a failed create"))
	c := copyOf(s.w)
	if err := c.Mkdir("b/d/x", 0o700); !errors.Is(err, fsx.ErrCopied) || errors.Is(err, fsx.ErrStopped) {
		t.Fatalf("the copy of a stopped writer: %v", err)
	}
	requireStoppedBy(t, s.w.Mkdir("b/d/x", 0o700), s.first)
	f := newMemFS("b")
	w := newWriter(t, f, 1)
	if err := w.Mkdir("b/a", 0o700); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if err := copyOf(w).Mkdir("b/b", 0o700); !errors.Is(err, fsx.ErrCopied) {
		t.Fatalf("the copy of a closed writer: %v", err)
	}
	if err := w.Mkdir("b/b", 0o700); !errors.Is(err, fsx.ErrWriterClosed) {
		t.Fatalf("the closed original: %v", err)
	}
}

// A copy made before the first call is two writers over one FS (only go vet sees it): each works,
// and the root that is released by the Close of one is released for the other.
func TestACopyMadeBeforeTheFirstCallIsAnotherWriterOverTheSameFS(t *testing.T) {
	f := newMemFS("b")
	w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}
	c := copyOf(w) // before any call
	if err := w.WriteFile("b/from-original", []byte("1"), 0o600); err != nil {
		t.Fatalf("the original: %v", err)
	}
	if err := c.WriteFile("b/from-copy", []byte("2"), 0o600); err != nil {
		t.Fatalf("a copy made before the first call is a writer of its own: %v", err)
	}
	live := f.Live()
	if mustFile(t, live, "b/from-original")[0] != '1' || mustFile(t, live, "b/from-copy")[0] != '2' {
		t.Fatal("a file is missing")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// the shared root is closed: the copy's next call that reaches it fails with fs.ErrClosed
	err := c.WriteFile("b2", nil, 0o600)
	if !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("the copy after the original's Close: %v, want an error that wraps fs.ErrClosed", err)
	}
	f.violations = nil
	_ = c.Close()
}
