package fsx_test

import (
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

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
// so a call on it makes no file system call and does not disturb a writer that exists.
func TestZeroValueJournalBesideARealWriterTouchesNothing(t *testing.T) {
	f := newMemFS("/b", "/b/d")
	w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
	var j fsx.Journal
	_ = j.Append([]byte("x"))
	_ = j.Close()
	if f.opCount() != 0 {
		t.Fatalf("a zero-value journal reached the file system: %v", f.opList())
	}
	if err := w.WriteFile("/b/d/ok.json", []byte("ok"), 0o600); err != nil {
		t.Fatalf("the writer stopped: %v", err)
	}
}
