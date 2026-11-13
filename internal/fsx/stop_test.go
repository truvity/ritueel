package fsx_test

// The stop (record 0006, rule 33): the first error of the file system stops the writer. The call
// that failed returns the plain *fsx.Error; every later call of every method, of every journal of
// that writer, whatever its arguments, returns an error that satisfies ErrStopped, holds that
// first *Error and does not reach the file system or the random source. TempName beside the other
// methods of one writer: after a stop, on a failure of the random source, and at the same time as
// a write.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// switchReader reads from r, counts its reads, and can be told to fail: with err, or by giving
// only bytes that a temporary name cannot use. It is for one goroutine at a time.
type switchReader struct {
	r        io.Reader
	fail     error
	unusable bool
	reads    int
}

func (s *switchReader) Read(p []byte) (int, error) {
	s.reads++
	if s.fail != nil {
		return 0, s.fail
	}
	if s.unusable {
		for i := range p {
			p[i] = 0xff
		}
		return len(p), nil
	}
	return s.r.Read(p)
}

func wellFormedTempName(t *testing.T, n string) {
	t.Helper()
	if len(n) != 15 || !strings.HasPrefix(n, fsx.TempPrefix) {
		t.Fatalf("temporary name %q is not %d characters that start with %q", n, 15, fsx.TempPrefix)
	}
}

// stopCause makes a writer stop, in a way that names the step.
type stopCause struct {
	name string
	step fsx.Step
	do   func(t *testing.T, f *memFS, w *fsx.Writer, r *switchReader) error
}

var errStick = errors.New("the stick rejected the command")

var stopCauses = []stopCause{
	{"a failed walk", fsx.StepOpenDir, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kOpenDir, 2, errStick) // the second element
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a failed create", fsx.StepCreate, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kCreate, 1, errStick)
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a failed write", fsx.StepWrite, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kWrite, 1, errStick)
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a failed flush of a file", fsx.StepSyncFile, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kSync, 1, errStick)
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a failed close of a file", fsx.StepSyncFile, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kClose, 1, errStick)
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a failed rename", fsx.StepRename, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kRename, 1, errStick)
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a rename that refuses to replace", fsx.StepRename, func(_ *testing.T, _ *memFS, w *fsx.Writer, _ *switchReader) error {
		if err := w.WriteFile("b/d/f.json", []byte("x"), 0o600); err != nil {
			return err
		}
		return w.WriteFile("b/d/f.json", []byte("y"), 0o600)
	}},
	{"a failed flush of a folder", fsx.StepSyncDir, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kSyncDir, 1, errStick)
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a failed mkdir", fsx.StepMkdir, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kMkdir, 1, errStick)
		return w.Mkdir("b/d/new", 0o700)
	}},
	{"a failed mkdir of the temporary folder of a set", fsx.StepMkdir, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kMkdir, 1, errStick)
		return w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
	}},
	{"a failed walk into the temporary folder of a set", fsx.StepOpenDir, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		f.failOn(kOpenDir, 3, errStick)
		return w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
	}},
	{"a failed line of a journal", fsx.StepWrite, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		j, err := w.CreateJournal("b/d/j.jsonl")
		if err != nil {
			return err
		}
		f.failOn(kWrite, 1, errStick)
		return j.Append([]byte("one"))
	}},
	{"a failed flush of a journal", fsx.StepSyncFile, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		j, err := w.CreateJournal("b/d/j.jsonl")
		if err != nil {
			return err
		}
		f.failOn(kSync, 1, errStick)
		return j.Append([]byte("one"))
	}},
	{"a failed close of a journal", fsx.StepSyncFile, func(_ *testing.T, f *memFS, w *fsx.Writer, _ *switchReader) error {
		j, err := w.CreateJournal("b/d/j.jsonl")
		if err != nil {
			return err
		}
		f.failOn(kClose, 1, errStick)
		return j.Close()
	}},
	{"a random source that fails inside a write", fsx.StepCreate, func(_ *testing.T, _ *memFS, w *fsx.Writer, r *switchReader) error {
		r.fail = errStick
		return w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	}},
	{"a random source of unusable bytes inside a set", fsx.StepCreate, func(_ *testing.T, _ *memFS, w *fsx.Writer, r *switchReader) error {
		r.unusable = true
		return w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
	}},
}

// stoppedWriter makes a writer that has two journals (one open, one closed) and then stops for
// the cause. It returns the first *Error and what is needed to call it again.
type stopped struct {
	f      *memFS
	w      *fsx.Writer
	r      *switchReader
	first  *fsx.Error
	open   *fsx.Journal // a journal made before the stop and still open
	closed *fsx.Journal // a journal made before the stop and closed
	cause  error
}

func stopWith(t *testing.T, c stopCause) *stopped {
	t.Helper()
	f := newMemFS("b", "b/d", "b/t")
	r := &switchReader{r: newDetRand(1)}
	w := &fsx.Writer{FS: f.Root(), Rand: r}
	t.Cleanup(func() {
		_ = w.Close()
		requireClean(t, f)
	})
	s := &stopped{f: f, w: w, r: r}
	var err error
	if s.open, err = w.CreateJournal("b/t/open.jsonl"); err != nil {
		t.Fatal(err)
	}
	if s.closed, err = w.CreateJournal("b/t/closed.jsonl"); err != nil {
		t.Fatal(err)
	}
	if err := s.closed.Close(); err != nil {
		t.Fatal(err)
	}
	f.clearFail()
	s.cause = c.do(t, f, w, r)
	s.first = requireFailed(t, s.cause)
	if s.first.Step != c.step {
		t.Fatalf("the writer stopped at the step %q, want %q: %v", s.first.Step, c.step, s.cause)
	}
	f.clearFail()
	r.fail, r.unusable = nil, false
	return s
}

func causeNamed(name string) stopCause {
	for _, c := range stopCauses {
		if c.name == name {
			return c
		}
	}
	panic("no stop cause " + name)
}

// laterCalls is every method of the writer and of its journals, with valid arguments.
func laterCalls(s *stopped) map[string]func() error {
	w := s.w
	return map[string]func() error{
		"WriteFile": func() error { return w.WriteFile("b/d/other.json", []byte("x"), 0o600) },
		"WriteSet": func() error {
			return w.WriteSet("b/t/other", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
		},
		"Mkdir": func() error { return w.Mkdir("b/d/other", 0o700) },
		"CreateJournal": func() error {
			j, err := w.CreateJournal("b/d/other.jsonl")
			if j != nil {
				return fmt.Errorf("a journal came back after the stop: %w", err)
			}
			return err
		},
		"TempName": func() error {
			n, err := w.TempName()
			if n != "" {
				return fmt.Errorf("the name %q came back after the stop: %w", n, err)
			}
			return err
		},
		"Append to an open journal":   func() error { return s.open.Append([]byte("late")) },
		"Append to a closed journal":  func() error { return s.closed.Append([]byte("late")) },
		"WriteFile in the root":       func() error { return w.WriteFile("r.json", []byte("x"), 0o600) },
		"Mkdir in the root":           func() error { return w.Mkdir("r", 0o700) },
		"WriteSet in the root":        func() error { return w.WriteSet("r", nil) },
		"CreateJournal in the root":   func() error { _, err := w.CreateJournal("r.jsonl"); return err },
		"WriteFile into a bad folder": func() error { return w.WriteFile("b/missing/f.json", nil, 0o600) },
	}
}

// invalidCalls are the calls with an argument that the writer refuses before it touches the file
// system when it has not stopped; after a stop they answer with the stop.
func invalidCalls(s *stopped) map[string]func() error {
	w := s.w
	return map[string]func() error{
		"WriteFile with an empty path":      func() error { return w.WriteFile("", nil, 0o600) },
		"WriteFile with an absolute path":   func() error { return w.WriteFile("/b/d/f", nil, 0o600) },
		"WriteFile with a dotdot":           func() error { return w.WriteFile("b/../f", nil, 0o600) },
		"WriteFile with a bad name":         func() error { return w.WriteFile("b/d/a b", nil, 0o600) },
		"WriteFile with a temporary prefix": func() error { return w.WriteFile("b/d/.rt-abc", nil, 0o600) },
		"WriteFile with a bad mode":         func() error { return w.WriteFile("b/d/f", nil, fs.ModeSetuid|0o600) },
		"Mkdir with a bad mode":             func() error { return w.Mkdir("b/d/f", fs.ModeDir|0o700) },
		"Mkdir with an empty path":          func() error { return w.Mkdir("", 0o700) },
		"WriteSet with a bad name": func() error {
			return w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a/b", Perm: 0o600}})
		},
		"WriteSet with a doubled name": func() error {
			return w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a", Perm: 0o600}, {Name: "A", Perm: 0o600}})
		},
		"CreateJournal with a bad path": func() error { _, err := w.CreateJournal("../j"); return err },
		"Append of a line with a newline": func() error {
			return s.open.Append([]byte("a\nb"))
		},
		"Append of a line with a newline to a closed journal": func() error {
			return s.closed.Append([]byte("a\nb"))
		},
	}
}

func TestEveryCallAfterAStopReturnsTheStopAndTouchesNothing(t *testing.T) {
	for _, c := range stopCauses {
		t.Run(c.name, func(t *testing.T) {
			s := stopWith(t, c)
			rand0, ops := s.r.reads, s.f.opCount()
			all := laterCalls(s)
			for name, call := range invalidCalls(s) {
				all[name] = call
			}
			var prev error
			for name, call := range all {
				err := call()
				if err == nil {
					t.Errorf("%s after the stop returned nil", name)
					continue
				}
				requireStoppedBy(t, err, s.first)
				if errors.Is(err, fsx.ErrInvalid) || errors.Is(err, fsx.ErrClosed) || errors.Is(err, fsx.ErrWriterClosed) {
					t.Errorf("%s after the stop returned %v: the stop must answer, not the argument or the journal", name, err)
				}
				if prev != nil && err != prev { //nolint:errorlint // the one value that the stop made
					t.Errorf("%s after the stop returned another value than the other calls did: %v and %v", name, err, prev)
				}
				prev = err
			}
			if got := s.r.reads; got != rand0 {
				t.Errorf("calls after the stop read the random source %d times", got-rand0)
			}
			if got := s.f.opCount(); got != ops {
				t.Errorf("calls after the stop reached the file system: %v", s.f.opsAfter(ops))
			}
			// the text says what happened and where
			msg := prev.Error()
			if !strings.Contains(msg, "stopped earlier") || !strings.Contains(msg, string(s.first.Step)) {
				t.Errorf("the text of the stop %q does not say that the writer stopped, and at what", msg)
			}
			if !errors.Is(prev, s.first.Err) {
				t.Errorf("errors.Is does not see the cause %v through %v", s.first.Err, prev)
			}
		})
	}
}

// TestTheStopWinsOverAClosedWriterAndANilFS: the writer stopped, then it was closed, or its FS
// was taken away: the stop still answers.
func TestTheStopWinsOverAClosedWriterAndANilFS(t *testing.T) {
	for _, c := range stopCauses {
		t.Run(c.name+"/closed writer", func(t *testing.T) {
			s := stopWith(t, c)
			if err := s.w.Close(); err == nil {
				t.Fatal("Close of a stopped writer returned nil, want the stop")
			} else {
				requireStoppedBy(t, err, s.first)
			}
			ops := s.f.opCount()
			for name, call := range laterCalls(s) {
				err := call()
				if errors.Is(err, fsx.ErrWriterClosed) || errors.Is(err, fsx.ErrClosed) {
					t.Errorf("%s on a stopped and closed writer returned %v, want the stop", name, err)
				}
				requireStoppedBy(t, err, s.first)
			}
			for name, call := range invalidCalls(s) {
				requireStoppedBy(t, call(), s.first)
				_ = name
			}
			if got := s.f.opCount(); got != ops {
				t.Errorf("calls after the stop reached the file system: %v", s.f.opsAfter(ops))
			}
		})
		t.Run(c.name+"/nil FS", func(t *testing.T) {
			s := stopWith(t, c)
			orig := s.w.FS
			s.w.FS = nil
			for name, call := range laterCalls(s) {
				err := call()
				if errors.Is(err, fsx.ErrNoRoot) {
					t.Errorf("%s on a stopped writer with no FS returned %v, want the stop", name, err)
				}
				requireStoppedBy(t, err, s.first)
			}
			s.w.FS = orig // so that the writer's own cleanup closes the root
		})
	}
}

// TestTheReadersWorkAfterAStop: they reach no writer.
func TestTheReadersWorkAfterAStop(t *testing.T) {
	s := stopWith(t, causeNamed("a failed line of a journal"))
	root := s.f.Root()
	defer func() { _ = root.Close() }()
	if _, err := fsx.ReadFile(root, "b/t/closed.jsonl"); err != nil {
		t.Fatalf("ReadFile after a stop: %v", err)
	}
	if _, _, err := fsx.ReadJournal(root, "b/t/open.jsonl"); err != nil {
		t.Fatalf("ReadJournal after a stop: %v", err)
	}
	if ents, err := fsx.ReadDir(root, "b/t"); err != nil || len(ents) != 2 {
		t.Fatalf("ReadDir after a stop: %v, %v", ents, err)
	}
}

// TestAJournalThatWasOpenAtTheStopIsClosedByItsCloseAndThenByNothing: Close of a journal after a
// stop closes its file and returns the stop; a second Close returns nil (a second Close does
// nothing, whatever happened to the writer).
func TestAJournalThatWasOpenAtTheStopIsClosedByItsCloseAndThenByNothing(t *testing.T) {
	s := stopWith(t, causeNamed("a failed create"))
	if _, fl := s.f.handles(); fl != 1 {
		t.Fatalf("%d files open before Close of the open journal, want 1", fl)
	}
	requireStoppedBy(t, s.open.Close(), s.first)
	if _, fl := s.f.handles(); fl != 0 {
		t.Fatalf("%d files open after Close of the open journal, want 0", fl)
	}
	if err := s.open.Close(); err != nil {
		t.Fatalf("a second Close of a journal after a stop returned %v, want nil", err)
	}
	if err := s.closed.Close(); err != nil {
		t.Fatalf("a second Close of a journal that was closed before the stop returned %v, want nil", err)
	}
}

// TestTempNameAfterAStopReturnsTheStopAndReadsNothing: whatever stopped the writer, TempName
// returns that stop, no name, and does not read the random source or touch the file system. The
// source is set to work again before the call, so that a read would succeed and show itself in
// the count.
func TestTempNameAfterAStopReturnsTheStopAndReadsNothing(t *testing.T) {
	for _, c := range stopCauses {
		t.Run(c.name, func(t *testing.T) {
			s := stopWith(t, c)
			reads, ops := s.r.reads, s.f.opCount()
			var first error
			for i := 0; i < 3; i++ {
				name, err := s.w.TempName()
				requireStoppedBy(t, err, s.first)
				if first != nil && err != first { //nolint:errorlint // the same value
					t.Fatalf("TempName returned two different values: %v and %v", first, err)
				}
				first = err
				if name != "" {
					t.Fatalf("TempName after the stop returned the name %q", name)
				}
			}
			if s.r.reads != reads {
				t.Fatalf("TempName after the stop read the random source %d times", s.r.reads-reads)
			}
			if s.f.opCount() != ops {
				t.Fatalf("TempName after the stop reached the file system: %v", s.f.opsAfter(ops))
			}
		})
	}
}

// TestTempNameBeforeAnyStopReadsTheSource is the other side of the test above: the
// same writer, not stopped, does read the source (so the count in that test can show a read).
func TestTempNameBeforeAnyStopReadsTheSource(t *testing.T) {
	r := &switchReader{r: newDetRand(1)}
	w := &fsx.Writer{FS: newMemFS("b").Root(), Rand: r}
	n, err := w.TempName()
	if err != nil {
		t.Fatal(err)
	}
	wellFormedTempName(t, n)
	if r.reads == 0 {
		t.Fatal("TempName did not read the random source")
	}
}

// TestRandomSourceFailureInTempNameIsAPlainErrorAndDoesNotStop: no step of a write has failed,
// so the writer is not stopped and the next call works once the source does. The same failure
// inside a write stops the writer (TestRandomSourceFailureIsACreateErrorAndStops, and the
// last cases of stopCauses).
func TestRandomSourceFailureInTempNameIsAPlainErrorAndDoesNotStop(t *testing.T) {
	boom := errors.New("no entropy")
	for _, c := range []struct {
		name    string
		breakIt func(r *switchReader)
		is      error
	}{
		{"the source returns an error", func(r *switchReader) { r.fail = boom }, boom},
		{"the source ends early", func(r *switchReader) { r.fail = io.ErrUnexpectedEOF }, io.ErrUnexpectedEOF},
		{"the source gives only unusable bytes", func(r *switchReader) { r.unusable = true }, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("b", "b/d")
			r := &switchReader{r: newDetRand(1)}
			w := &fsx.Writer{FS: f.Root(), Rand: r}
			t.Cleanup(func() { _ = w.Close(); requireClean(t, f) })
			c.breakIt(r)
			name, err := w.TempName()
			if err == nil || name != "" {
				t.Fatalf("TempName = %q, %v, want an error and no name", name, err)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Fatalf("TempName = %v, want an error that wraps %v", err, c.is)
			}
			var fe *fsx.Error
			if errors.As(err, &fe) || errors.Is(err, fsx.ErrStopped) {
				t.Fatalf("a failure of the random source in TempName is a stop: %v", err)
			}
			if errors.Is(err, fsx.ErrInvalid) {
				t.Fatalf("a failure of the random source is not an invalid argument: %v", err)
			}
			// the writer is not stopped: the source works again, and so does the writer
			r.fail, r.unusable = nil, false
			n, err := w.TempName()
			if err != nil {
				t.Fatalf("TempName after a failed draw: %v", err)
			}
			wellFormedTempName(t, n)
			if err := w.WriteFile("b/d/f.json", []byte("x"), 0o600); err != nil {
				t.Fatalf("WriteFile after a failed draw in TempName: %v", err)
			}
			if got := mustFile(t, f.Live(), "b/d/f.json"); string(got) != "x" {
				t.Fatalf("the file holds %q", got)
			}
		})
	}
}

// racyRand is a random source that is not safe for concurrent use, and says so when it is
// used concurrently. Its counter is a plain int: a read of it from two goroutines with no lock
// between them is a data race, which the race detector reports. ChaCha8 is not safe either.
//
// ONLY THE RACE RUN PROVES THE LOCK. Under `go test -race` an unlocked TempName beside a
// write is reported as a data race on reads (and the test fails). Without -race the test
// passes whether TempName takes the lock or not, unless two reads happen to overlap in time,
// which the overlap flag then shows: that is a matter of luck, so a pass without -race says
// nothing about the lock.
type racyRand struct {
	src     io.Reader
	reads   int // a plain field on purpose
	inside  atomic.Int32
	overlap atomic.Bool
}

func (r *racyRand) Read(p []byte) (int, error) {
	if r.inside.Add(1) != 1 {
		r.overlap.Store(true)
	}
	defer r.inside.Add(-1)
	r.reads++
	runtime.Gosched() // leave the read open for a moment, so that another goroutine can enter
	return r.src.Read(p)
}

// TestTempNameBesideWriteFileOnOneWriterIsSerialised: goroutines that call WriteFile and
// goroutines that call TempName on one Writer, with a random source that is not safe for
// concurrent use. Both kinds of call read the source, so the lock must cover both. See racyRand:
// run it with -race (CGO_ENABLED=1 go test -race ./internal/fsx); that run is the proof.
func TestTempNameBesideWriteFileOnOneWriterIsSerialised(t *testing.T) {
	f := newMemFS("b", "b/d")
	r := &racyRand{src: newDetRand(11)}
	w := &fsx.Writer{FS: f.Root(), Rand: r}
	t.Cleanup(func() { _ = w.Close(); requireClean(t, f) })
	const writers, drawers, per = 4, 4, 50
	var wg sync.WaitGroup
	errs := make(chan error, (writers+drawers)*per)
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := w.WriteFile(fmt.Sprintf("b/d/f-%d-%d.json", g, i), []byte(fmt.Sprintf("%d/%d", g, i)), 0o600); err != nil {
					errs <- fmt.Errorf("WriteFile %d/%d: %w", g, i, err)
					return
				}
			}
		}()
	}
	for g := 0; g < drawers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				n, err := w.TempName()
				if err != nil {
					errs <- fmt.Errorf("TempName: %w", err)
					return
				}
				if len(n) != 15 || !strings.HasPrefix(n, fsx.TempPrefix) {
					errs <- fmt.Errorf("TempName gave %q", n)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if r.overlap.Load() {
		t.Error("two reads of the random source were open at the same time")
	}
	if r.reads < writers*per+drawers*per {
		t.Errorf("the source was read %d times, want at least one per call", r.reads)
	}
	live := f.Live()
	for g := 0; g < writers; g++ {
		for i := 0; i < per; i++ {
			if got := mustFile(t, live, fmt.Sprintf("b/d/f-%d-%d.json", g, i)); string(got) != fmt.Sprintf("%d/%d", g, i) {
				t.Fatalf("file %d-%d holds %q", g, i, got)
			}
		}
	}
}
