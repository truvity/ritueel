package fsx_test

// TempName beside the other methods of one writer: after a stop, on a failure of the random
// source, and at the same time as a write.

import (
	"errors"
	"fmt"
	"io"
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

// TestTempNameAfterAStopReturnsTheStopAndReadsNothing: whatever stopped the writer, TempName
// returns that same error value, no name, and does not read the random source or touch the
// file system. The source is set to work again before the call, so that a read would succeed
// and show itself in the count.
func TestTempNameAfterAStopReturnsTheStopAndReadsNothing(t *testing.T) {
	boom := errors.New("the stick rejected the command")
	for _, c := range []struct {
		name string
		stop func(f *memFS, w *fsx.Writer, r *switchReader) error
	}{
		{"a failed create", func(f *memFS, w *fsx.Writer, _ *switchReader) error {
			f.failAt, f.failErr = 1, boom
			return w.WriteFile("/b/d/f.json", []byte("x"), 0o600)
		}},
		{"a failed mkdir", func(f *memFS, w *fsx.Writer, _ *switchReader) error {
			f.failAt, f.failErr = 1, boom
			return w.Mkdir("/b/d/new", 0o700)
		}},
		{"a failed flush of a folder", func(f *memFS, w *fsx.Writer, _ *switchReader) error {
			f.failAt, f.failErr = 2, boom // the mkdir, then the flush of the parent
			return w.Mkdir("/b/d/new", 0o700)
		}},
		{"a rename that refuses to replace", func(_ *memFS, w *fsx.Writer, _ *switchReader) error {
			if err := w.WriteFile("/b/d/f.json", []byte("x"), 0o600); err != nil {
				return err
			}
			return w.WriteFile("/b/d/f.json", []byte("y"), 0o600)
		}},
		{"a failed line of a journal", func(f *memFS, w *fsx.Writer, _ *switchReader) error {
			j, err := w.CreateJournal("/b/d/j.jsonl")
			if err != nil {
				return err
			}
			f.failAt, f.failErr = f.opCount()+1, boom
			return j.Append([]byte("one"))
		}},
		{"a random source that fails inside a write", func(_ *memFS, w *fsx.Writer, r *switchReader) error {
			r.fail = boom
			return w.WriteFile("/b/d/f.json", []byte("x"), 0o600)
		}},
		{"a random source of unusable bytes inside a set", func(_ *memFS, w *fsx.Writer, r *switchReader) error {
			r.unusable = true
			return w.WriteSet("/b/d/s", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("/b", "/b/d")
			r := &switchReader{r: newDetRand(1)}
			w := &fsx.Writer{FS: f, Rand: r}
			stopErr := c.stop(f, w, r)
			var fe *fsx.Error
			if !errors.As(stopErr, &fe) {
				t.Fatalf("the writer did not stop: %v", stopErr)
			}
			r.fail, r.unusable = nil, false
			f.failAt = 0
			reads, ops := r.reads, f.opCount()
			for i := 0; i < 3; i++ {
				name, err := w.TempName()
				if err != stopErr { //nolint:errorlint // the same value, not an error that wraps it
					t.Fatalf("TempName after the stop returned %v, want the stop %v itself (not a copy or a wrapper)", err, stopErr)
				}
				if name != "" {
					t.Fatalf("TempName after the stop returned the name %q", name)
				}
			}
			if r.reads != reads {
				t.Fatalf("TempName after the stop read the random source %d times", r.reads-reads)
			}
			if f.opCount() != ops {
				t.Fatalf("TempName after the stop reached the file system: %v", f.opList()[ops:])
			}
		})
	}
}

// TestTempNameBeforeAnyStopReadsTheSource is the other side of the test above: the
// same writer, not stopped, does read the source (so the count in that test can show a read).
func TestTempNameBeforeAnyStopReadsTheSource(t *testing.T) {
	r := &switchReader{r: newDetRand(1)}
	w := &fsx.Writer{FS: newMemFS("/b"), Rand: r}
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
// last case of the test above).
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
			f := newMemFS("/b", "/b/d")
			r := &switchReader{r: newDetRand(1)}
			w := &fsx.Writer{FS: f, Rand: r}
			c.breakIt(r)
			name, err := w.TempName()
			if err == nil || name != "" {
				t.Fatalf("TempName = %q, %v, want an error and no name", name, err)
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Fatalf("TempName = %v, want an error that wraps %v", err, c.is)
			}
			var fe *fsx.Error
			if errors.As(err, &fe) {
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
			if err := w.WriteFile("/b/d/f.json", []byte("x"), 0o600); err != nil {
				t.Fatalf("WriteFile after a failed draw in TempName: %v", err)
			}
			if got := mustFile(t, f.Live(), "/b/d/f.json"); string(got) != "x" {
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
	f := newMemFS("/b", "/b/d")
	r := &racyRand{src: newDetRand(11)}
	w := &fsx.Writer{FS: f, Rand: r}
	const writers, drawers, per = 4, 4, 50
	var wg sync.WaitGroup
	errs := make(chan error, (writers+drawers)*per)
	for g := 0; g < writers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := w.WriteFile(fmt.Sprintf("/b/d/f-%d-%d.json", g, i), []byte(fmt.Sprintf("%d/%d", g, i)), 0o600); err != nil {
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
			if got := mustFile(t, live, fmt.Sprintf("/b/d/f-%d-%d.json", g, i)); string(got) != fmt.Sprintf("%d/%d", g, i) {
				t.Fatalf("file %d-%d holds %q", g, i, got)
			}
		}
	}
}
