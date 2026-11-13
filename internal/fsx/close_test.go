package fsx_test

// Writer.Close, Journal, and a writer with no root: what is open, what each call returns after
// a close, and what a copy of a Journal is.

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func TestWriterCloseClosesTheJournalsThenTheRoot(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}
	var js []*fsx.Journal
	for _, n := range []string{"j1", "j2", "j3"} {
		j, err := w.CreateJournal("b/d/" + n)
		if err != nil {
			t.Fatal(err)
		}
		js = append(js, j)
	}
	if err := js[1].Close(); err != nil { // one of them closed by its owner before
		t.Fatal(err)
	}
	if d, fl := f.handles(); d != 1 || fl != 2 {
		t.Fatalf("before Close: %d folders and %d files open, want the root and two journals", d, fl)
	}
	n := f.opCount()
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	got := f.opsAfter(n)
	if len(got) != 3 {
		t.Fatalf("Close made %v, want the close of the two open journals and of the root", got)
	}
	closed := map[string]bool{}
	for _, o := range got[:2] {
		if o.Kind != kClose {
			t.Fatalf("Close made %v before the root: want the close of a journal", o)
		}
		closed[o.Path] = true
	}
	if !closed["b/d/j1"] || !closed["b/d/j3"] || closed["b/d/j2"] {
		t.Fatalf("Close closed %v, want j1 and j3 (j2 was closed already)", closed)
	}
	if got[2].Kind != kCloseDir || got[2].Path != "." {
		t.Fatalf("Close made %v last, want the close of the root", got[2])
	}
	requireClean(t, f)

	// a second Close does nothing and returns nil, through the writer and through a journal
	n = f.opCount()
	if err := w.Close(); err != nil {
		t.Fatalf("a second Close: %v", err)
	}
	for _, j := range js {
		if err := j.Close(); err != nil {
			t.Fatalf("Close of a journal after the writer's Close: %v", err)
		}
	}
	if f.opCount() != n {
		t.Fatalf("a second Close reached the file system: %v", f.opsAfter(n))
	}
}

func TestEveryCallAfterCloseReturnsErrWriterClosedOrErrClosed(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}
	open, err := w.CreateJournal("b/d/open")
	if err != nil {
		t.Fatal(err)
	}
	closed, err := w.CreateJournal("b/d/closed")
	if err != nil {
		t.Fatal(err)
	}
	_ = closed.Close()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	n := f.opCount()
	calls := map[string]func() error{
		"WriteFile":     func() error { return w.WriteFile("b/d/f", []byte("x"), 0o600) },
		"WriteSet":      func() error { return w.WriteSet("b/d/s", nil) },
		"Mkdir":         func() error { return w.Mkdir("b/d/m", 0o700) },
		"CreateJournal": func() error { _, err := w.CreateJournal("b/d/j"); return err },
		"TempName":      func() error { _, err := w.TempName(); return err },
		// the closed writer answers before the arguments are looked at
		"WriteFile with an invalid path": func() error { return w.WriteFile("", nil, 0o600) },
		"WriteFile with a bad mode":      func() error { return w.WriteFile("b/d/f", nil, fs.ModeDir) },
		"WriteSet with a bad name":       func() error { return w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a b"}}) },
		"Mkdir with an invalid path":     func() error { return w.Mkdir("/x", 0o700) },
	}
	for name, call := range calls {
		err := call()
		if !errors.Is(err, fsx.ErrWriterClosed) {
			t.Errorf("%s after Close: %v, want ErrWriterClosed", name, err)
		}
		if errors.Is(err, fsx.ErrStopped) || errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("%s after Close: %v, a closed writer is not stopped, and its answer is not about the arguments", name, err)
		}
	}
	for name, j := range map[string]*fsx.Journal{"open": open, "closed": closed} {
		if err := j.Append([]byte("x")); !errors.Is(err, fsx.ErrClosed) {
			t.Errorf("Append to the %s journal after the writer's Close: %v, want ErrClosed", name, err)
		}
		if err := j.Append([]byte("a\nb")); !errors.Is(err, fsx.ErrClosed) {
			t.Errorf("Append of an invalid line to the %s journal after the writer's Close: %v, want ErrClosed", name, err)
		}
	}
	if f.opCount() != n {
		t.Errorf("calls after Close reached the file system: %v", f.opsAfter(n))
	}
	// the readers still read through a handle of their own, and not through the closed root
	if _, err := fsx.ReadFile(w.FS, "b/d/open"); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("ReadFile through the closed root: %v, want fs.ErrClosed", err)
	}
	if _, err := fsx.ReadDir(w.FS, "."); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("ReadDir through the closed root: %v, want fs.ErrClosed", err)
	}
	if _, _, err := fsx.ReadJournal(w.FS, "b/d/open"); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("ReadJournal through the closed root: %v, want fs.ErrClosed", err)
	}
	// the three reads above are calls on a closed folder, which the model records on purpose
	if got := len(f.violationList()); got != 3 {
		t.Errorf("%d violations, want the 3 reads through the closed root: %q", got, f.violationList())
	}
	f.violations = nil
	requireClean(t, f)
}

// TestCloseReportsTheFirstErrorAndStillClosesEverything: an error of the close of a journal or of
// the root is the answer of Close, the first of them; every handle is closed all the same; and
// the writer is closed and not stopped (it is done).
func TestCloseReportsTheFirstErrorAndStillClosesEverything(t *testing.T) {
	boom := errors.New("the stick would not let go")
	t.Run("a journal", func(t *testing.T) {
		f := newMemFS("b")
		w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}
		if _, err := w.CreateJournal("b/j"); err != nil {
			t.Fatal(err)
		}
		f.failOn(kClose, 1, boom)
		err := w.Close()
		fe := requireFailed(t, err)
		if fe.Step != fsx.StepSyncFile || fe.Path != "b/j" || !errors.Is(err, boom) {
			t.Fatalf("Close = %v, want a sync-file error at the journal wrapping the cause", err)
		}
		requireClean(t, f)
		if err := w.WriteFile("x", nil, 0o600); !errors.Is(err, fsx.ErrWriterClosed) || errors.Is(err, fsx.ErrStopped) {
			t.Fatalf("a call after a Close that failed: %v, want ErrWriterClosed and no stop", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("a second Close after one that failed: %v", err)
		}
	})
	t.Run("the root", func(t *testing.T) {
		f := newMemFS("b")
		w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}
		f.failOn(kCloseDir, 1, boom)
		err := w.Close()
		if !errors.Is(err, boom) || !strings.Contains(err.Error(), "close the root folder") {
			t.Fatalf("Close = %v, want an error that names the root and wraps the cause", err)
		}
		requireClean(t, f)
	})
	t.Run("a journal and the root: the journal's error comes first", func(t *testing.T) {
		f := newMemFS("b")
		w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}
		if _, err := w.CreateJournal("b/j"); err != nil {
			t.Fatal(err)
		}
		f.failAt, f.failErr = f.opCount()+1, boom
		first := w.Close()
		fe := asError(t, first)
		if fe.Path != "b/j" {
			t.Fatalf("Close = %v, want the error of the journal", first)
		}
		requireClean(t, f)
	})
	t.Run("a stopped writer returns the stop and still closes", func(t *testing.T) {
		s := stopWith(t, causeNamed("a failed create"))
		err := s.w.Close()
		requireStoppedBy(t, err, s.first)
		requireClean(t, s.f)
	})
}

func TestAWriterWithNoRootAnswersErrNoRootAndDoesNotStop(t *testing.T) {
	w := &fsx.Writer{Rand: newDetRand(1)}
	calls := map[string]func() error{
		"WriteFile":     func() error { return w.WriteFile("f", nil, 0o600) },
		"WriteSet":      func() error { return w.WriteSet("s", nil) },
		"Mkdir":         func() error { return w.Mkdir("m", 0o700) },
		"CreateJournal": func() error { _, err := w.CreateJournal("j"); return err },
		// the missing root answers before the arguments are looked at
		"WriteFile with an invalid path": func() error { return w.WriteFile("", nil, 0o600) },
		"WriteSet with a bad name":       func() error { return w.WriteSet("s", []fsx.NewFile{{Name: "a b"}}) },
	}
	for name, call := range calls {
		err := call()
		if !errors.Is(err, fsx.ErrNoRoot) {
			t.Errorf("%s: %v, want ErrNoRoot", name, err)
		}
		if errors.Is(err, fsx.ErrInvalid) || errors.Is(err, fsx.ErrStopped) {
			t.Errorf("%s: %v, a writer with no root is neither stopped nor refusing the arguments", name, err)
		}
	}
	if n, err := w.TempName(); err != nil || len(n) != 15 {
		t.Errorf("TempName of a writer with no root: %q, %v, want a name: it needs no root", n, err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Close of a writer with no root: %v", err)
	}
	if err := w.WriteFile("f", nil, 0o600); !errors.Is(err, fsx.ErrWriterClosed) {
		t.Errorf("a call of a closed writer with no root: %v, want ErrWriterClosed", err)
	}
	// the readers: no root, no reading
	if _, err := fsx.ReadFile(nil, "f"); !errors.Is(err, fsx.ErrNoRoot) {
		t.Errorf("ReadFile(nil): %v, want ErrNoRoot", err)
	}
	if _, err := fsx.ReadDir(nil, "."); !errors.Is(err, fsx.ErrNoRoot) {
		t.Errorf("ReadDir(nil): %v, want ErrNoRoot", err)
	}
	if _, _, err := fsx.ReadJournal(nil, "j"); !errors.Is(err, fsx.ErrNoRoot) {
		t.Errorf("ReadJournal(nil): %v, want ErrNoRoot", err)
	}
	// a root put in later works: ErrNoRoot is not a stop
	f := newMemFS("b")
	w2 := &fsx.Writer{Rand: newDetRand(1)}
	if err := w2.Mkdir("b/x", 0o700); !errors.Is(err, fsx.ErrNoRoot) {
		t.Fatal(err)
	}
	w2.FS = f.Root()
	t.Cleanup(func() { _ = w2.Close(); requireClean(t, f) })
	if err := w2.Mkdir("b/x", 0o700); err != nil {
		t.Fatalf("a root put in after ErrNoRoot: %v", err)
	}
}

func TestACopyOfAJournalIsTheSameJournal(t *testing.T) {
	f := newMemFS("b")
	w := newWriter(t, f, 1)
	j, err := w.CreateJournal("b/j")
	if err != nil {
		t.Fatal(err)
	}
	c := *j // copied by value
	if err := j.Append([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := c.Append([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if lines, _, _ := f.Live().readJournal("b/j"); len(lines) != 2 || string(lines[0]) != "one" || string(lines[1]) != "two" {
		t.Fatalf("the journal holds %q, want both lines, in order", lines)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Append([]byte("three")); !errors.Is(err, fsx.ErrClosed) {
		t.Fatalf("Append through the original after Close through the copy: %v, want ErrClosed", err)
	}
	n := f.opCount()
	if err := j.Close(); err != nil {
		t.Fatalf("a second Close, through the original: %v, want nil", err)
	}
	c2 := c // a copy of a closed one
	if err := c2.Close(); err != nil {
		t.Fatalf("Close through a copy of a closed journal: %v", err)
	}
	if f.opCount() != n {
		t.Fatalf("a second Close reached the file system: %v", f.opsAfter(n))
	}
	closes := 0
	for _, o := range f.opList() {
		if o.Kind == kClose {
			closes++
		}
	}
	if closes != 1 {
		t.Fatalf("the file of the journal was closed %d times, want once", closes)
	}
	requireOpen(t, f, 0)

	// closed from the other side, and by the writer
	j2, _ := w.CreateJournal("b/j2")
	c3 := *j2
	if err := j2.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c3.Append([]byte("x")); !errors.Is(err, fsx.ErrClosed) {
		t.Fatalf("Append through a copy after Close through the original: %v", err)
	}
	j3, _ := w.CreateJournal("b/j3")
	c4 := *j3
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, x := range []*fsx.Journal{j3, &c4} {
		if err := x.Append([]byte("x")); !errors.Is(err, fsx.ErrClosed) {
			t.Fatalf("Append after the writer's Close: %v", err)
		}
		if err := x.Close(); err != nil {
			t.Fatalf("Close after the writer's Close: %v", err)
		}
	}
}

// A Journal that CreateJournal did not make has no writer and no file. It is a closed
// journal: Append refuses with ErrClosed, Close has nothing to release and returns nil. Neither
// panics (Close did, on a nil file).
func TestZeroValueJournalIsClosed(t *testing.T) {
	var j fsx.Journal
	for _, line := range []string{"", "one", "two\nlines"} {
		if err := j.Append([]byte(line)); !errors.Is(err, fsx.ErrClosed) {
			t.Errorf("Append(%q) on a zero-value journal = %v, want ErrClosed", line, err)
		}
	}
	if err := j.Append(nil); !errors.Is(err, fsx.ErrClosed) {
		t.Errorf("Append(nil) on a zero-value journal = %v, want ErrClosed", err)
	}
	for i := 0; i < 2; i++ {
		if err := j.Close(); err != nil {
			t.Errorf("Close #%d on a zero-value journal = %v, want nil", i+1, err)
		}
	}
	if err := j.Append([]byte("after Close")); !errors.Is(err, fsx.ErrClosed) {
		t.Errorf("Append after Close on a zero-value journal = %v, want ErrClosed", err)
	}
	c := j // a copy of the zero value is the zero value
	if err := c.Append([]byte("x")); !errors.Is(err, fsx.ErrClosed) {
		t.Errorf("Append on a copy of the zero value = %v", err)
	}
}

func TestNilJournalIsClosed(t *testing.T) {
	var j *fsx.Journal
	if err := j.Append([]byte("one")); !errors.Is(err, fsx.ErrClosed) {
		t.Errorf("Append on a nil journal = %v, want ErrClosed", err)
	}
	if err := j.Close(); err != nil {
		t.Errorf("Close on a nil journal = %v, want nil", err)
	}
}

// TestZeroValueJournalBesideARealWriterTouchesNothing: the zero value is not tied to any writer,
// so a call on it makes no file system call and does not disturb a writer that exists, one that
// has stopped included (it has no writer to say so).
func TestZeroValueJournalBesideARealWriterTouchesNothing(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	var j fsx.Journal
	_ = j.Append([]byte("x"))
	_ = j.Close()
	if f.opCount() != 0 {
		t.Fatalf("a zero-value journal reached the file system: %v", f.opList())
	}
	if err := w.WriteFile("b/d/ok.json", []byte("ok"), 0o600); err != nil {
		t.Fatalf("the writer stopped: %v", err)
	}
	s := stopWith(t, causeNamed("a failed create"))
	if err := j.Append([]byte("x")); !errors.Is(err, fsx.ErrClosed) {
		t.Fatalf("a zero-value journal after a stop of another writer: %v", err)
	}
	_ = s
}

// TestWriterCloseAppendAndStopAtTheSameTime: the lock covers Close, Append and the stop. Only the
// race run (CGO_ENABLED=1 go test -race) proves it: without a lock these are data races on the
// writer's fields. Every call ends with nil or with one of the errors that the state it met
// calls for.
func TestWriterCloseAppendAndStopAtTheSameTime(t *testing.T) {
	for round := 0; round < 30; round++ {
		f := newMemFS("b", "b/d")
		w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(byte(round))}
		const nj = 3
		js := make([]*fsx.Journal, nj)
		for i := range js {
			j, err := w.CreateJournal(fmt.Sprintf("b/d/j%d", i))
			if err != nil {
				t.Fatal(err)
			}
			js[i] = j
		}
		var wg sync.WaitGroup
		bad := make(chan error, 1000)
		allowed := func(err error) bool {
			return err == nil || errors.Is(err, fsx.ErrClosed) || errors.Is(err, fsx.ErrStopped) || errors.Is(err, fsx.ErrWriterClosed) || errors.Is(err, fs.ErrExist)
		}
		for i := range js {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 40; k++ {
					if err := js[i].Append([]byte("line")); !allowed(err) {
						bad <- err
						return
					}
				}
			}()
		}
		wg.Add(3)
		go func() { // the stop: the second write of one path is refused
			defer wg.Done()
			for k := 0; k < 2; k++ {
				if err := w.WriteFile("b/d/same", []byte("x"), 0o600); !allowed(err) {
					bad <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 40; k++ {
				if _, err := w.TempName(); !allowed(err) {
					bad <- err
				}
			}
		}()
		go func() {
			defer wg.Done()
			if err := w.Close(); !allowed(err) {
				bad <- err
			}
		}()
		wg.Wait()
		close(bad)
		for err := range bad {
			t.Errorf("round %d: an unexpected error: %v", round, err)
		}
		_ = w.Close()
		requireClean(t, f)
	}
}
