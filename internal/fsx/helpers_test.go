package fsx_test

import (
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// newDetRand is a random source that repeats from run to run.
func newDetRand(seed byte) io.Reader {
	var k [32]byte
	k[0] = seed
	return rand.NewChaCha8(k)
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

type constReader struct {
	b     byte
	reads int
}

func (r *constReader) Read(p []byte) (int, error) {
	r.reads++
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// requireClean fails when a handle of f is open or a call that no correct caller makes was seen.
func requireClean(t testing.TB, f *memFS) {
	t.Helper()
	if d, fl := f.handles(); d != 0 || fl != 0 {
		t.Errorf("%d folders and %d files are left open: %s", d, fl, f.describeOpen())
	}
	if v := f.violationList(); len(v) > 0 {
		t.Errorf("calls that no correct caller makes: %q", v)
	}
}

// requireOpen is the oracle of the handles for a writer that is not closed: the root folder, and
// one file for each journal that is open, and nothing else; and no violation was seen.
func requireOpen(t testing.TB, f *memFS, journals int) {
	t.Helper()
	d, fl := f.handles()
	if d != 1 || fl != journals {
		t.Errorf("%d folders and %d files are open (%s), want the root and %d journal files", d, fl, f.describeOpen(), journals)
	}
	if v := f.violationList(); len(v) > 0 {
		t.Errorf("calls that no correct caller makes: %q", v)
	}
}

// newWriter makes a writer over a fresh root handle of f. When the test ends it closes the writer
// and requires that no handle of f is open and no call that no correct caller makes was seen: so
// every test that uses it is a test of the handles too. A test that opens a handle of its own
// closes it itself.
func newWriter(t testing.TB, f *memFS, seed byte) *fsx.Writer {
	t.Helper()
	if !f.watched { // registered first, so it runs last: after the Close of every writer of f
		f.watched = true
		t.Cleanup(func() { requireClean(t, f) })
	}
	w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(seed)}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// asError returns the *fsx.Error that err is or holds, and fails when there is none.
func asError(t testing.TB, err error) *fsx.Error {
	t.Helper()
	var fe *fsx.Error
	if !errors.As(err, &fe) {
		t.Fatalf("got %v (%T), want an *fsx.Error or an error that holds one", err, err)
	}
	return fe
}

// requireFailed requires that err is the plain *fsx.Error of the call that failed: not a later
// call's error, so it does not satisfy ErrStopped.
func requireFailed(t testing.TB, err error) *fsx.Error {
	t.Helper()
	if got := fmt.Sprintf("%T", err); got != "*fsx.Error" {
		t.Fatalf("the failing call returned %v (%s), want the plain *fsx.Error", err, got)
	}
	if errors.Is(err, fsx.ErrStopped) {
		t.Fatalf("the failing call returned an error that satisfies ErrStopped: %v", err)
	}
	return asError(t, err)
}

// requireStoppedBy requires that err is what a call after the stop returns: it satisfies
// ErrStopped, errors.As gives the very *fsx.Error of the first failure, and errors.Is still sees
// what that one wraps.
func requireStoppedBy(t testing.TB, err error, first *fsx.Error) {
	t.Helper()
	if !errors.Is(err, fsx.ErrStopped) {
		t.Fatalf("a call after the stop returned %v (%T), want an error that satisfies ErrStopped", err, err)
	}
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe != first {
		t.Fatalf("a call after the stop returned %v, errors.As gives %v, want the first *fsx.Error %v itself", err, fe, first)
	}
	if first.Err != nil && !errors.Is(err, first.Err) {
		t.Fatalf("a call after the stop returned %v, which does not wrap the cause %v", err, first.Err)
	}
}
