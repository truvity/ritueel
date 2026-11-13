//go:build linux

package fsx_test

// No handle leaks, on the real file system: the descriptors of the process are counted before and
// after a few hundred rounds of successes and failures, with the garbage collector off, so that
// the finalizer of an os.File cannot close what the package forgot to close.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func countDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	return len(entries)
}

// oneRound uses every call that opens a handle, on the success path and on a failure path of
// each. The names are made from i, so that every round makes something new, and the failures are
// the ones the real file system gives: a name that exists, a folder that is not there, a link.
func oneRound(t *testing.T, wd *world, i int, heavy bool) {
	t.Helper()
	w, err := fsx.Open(wd.root)
	if err != nil {
		t.Fatal(err)
	}
	n := func(s string) string { return fmt.Sprintf("%s-%d", s, i) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
	}
	// success paths. A write flushes (fsync) the file and its folder, which costs on a real disk, so
	// the full set of successes is made in one round of ten (heavy); the other rounds make the same
	// names by hand and look at the failures and the reads, which cost nothing.
	if heavy {
		must(w.Mkdir(n("d"), 0o700))
		must(os.Symlink(filepath.Join("..", "..", "outside"), filepath.Join(wd.root, n("d"), "link"))) // a link in it, for the walk
		must(w.WriteFile(n("d")+"/f", []byte("x"), 0o600))
		must(w.WriteFile(n("empty"), nil, 0o600))
		must(w.WriteSet(n("set"), []fsx.NewFile{{Name: "a", Data: []byte("a"), Perm: 0o600}, {Name: "b", Perm: 0o600}}))
		j, err := w.CreateJournal(n("d") + "/j")
		must(err)
		must(j.Append([]byte("one")))
		must(j.Close())
		j2, err := w.CreateJournal(n("j2")) // left open: the writer's Close closes it
		must(err)
		must(j2.Append([]byte("two")))
	} else {
		must(os.Mkdir(filepath.Join(wd.root, n("d")), 0o700))
		must(os.Symlink(filepath.Join("..", "..", "outside"), filepath.Join(wd.root, n("d"), "link")))
		must(os.WriteFile(filepath.Join(wd.root, n("d"), "f"), []byte("x"), 0o600))
		must(os.WriteFile(filepath.Join(wd.root, n("d"), "j"), []byte("one\n"), 0o600))
		must(os.Mkdir(filepath.Join(wd.root, n("set")), 0o700))
		must(os.WriteFile(filepath.Join(wd.root, n("set"), "a"), []byte("a"), 0o600))
	}
	root, err := fsx.OpenFS(wd.root)
	must(err)
	_, err = fsx.ReadFile(root, n("d")+"/f")
	must(err)
	_, _, err = fsx.ReadJournal(root, n("d")+"/j")
	must(err)
	_, err = fsx.ReadDir(root, n("d"))
	must(err)
	_, err = fsx.ReadDir(root, ".")
	must(err)
	// failure paths of the readers
	if _, err := fsx.ReadFile(root, n("d")+"/missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("round %d: %v", i, err)
	}
	if _, err := fsx.ReadFile(root, "none/f"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("round %d: %v", i, err)
	}
	if _, err := fsx.ReadFile(root, n("d")+"/f/x"); err == nil {
		t.Fatalf("round %d: a read through a file", i)
	}
	if _, err := fsx.ReadFile(root, "link/x"); !errors.Is(err, fsx.ErrLink) {
		t.Fatalf("round %d: %v", i, err)
	}
	if _, err := fsx.ReadFile(root, n("d")+"/link"); !errors.Is(err, fsx.ErrLink) {
		t.Fatalf("round %d: %v", i, err)
	}
	if _, err := fsx.ReadFile(root, "fifo"); !errors.Is(err, fsx.ErrNotRegular) {
		t.Fatalf("round %d: %v", i, err)
	}
	if _, err := fsx.ReadFile(root, "over"); !errors.Is(err, fsx.ErrTooLarge) {
		t.Fatalf("round %d: %v", i, err)
	}
	if _, err := fsx.ReadFile(root, n("d")); !errors.Is(err, fsx.ErrNotRegular) {
		t.Fatalf("round %d: %v", i, err)
	}
	if _, err := fsx.ReadDir(root, "link"); !errors.Is(err, fsx.ErrLink) {
		t.Fatalf("round %d: %v", i, err)
	}
	must(root.Close())

	// the failures of the writer, each on a writer of its own (each stops it)
	fail := func(what string, call func(w *fsx.Writer) error, is error) {
		t.Helper()
		w2, err := fsx.Open(wd.root)
		must(err)
		if heavy {
			_, err := w2.CreateJournal(n("fail-" + what)) // an open journal at the stop
			must(err)
		}
		if err := call(w2); !errors.Is(err, is) {
			t.Fatalf("round %d, %s: %v, want %v", i, what, err, is)
		}
		if err := w2.Close(); !errors.Is(err, fsx.ErrStopped) {
			t.Fatalf("round %d, %s: Close = %v, want the stop", i, what, err)
		}
	}
	fail("walk-missing", func(w *fsx.Writer) error { return w.WriteFile("none/deep/f", nil, 0o600) }, os.ErrNotExist)
	fail("walk-link-first", func(w *fsx.Writer) error { return w.WriteFile("link/f", nil, 0o600) }, fsx.ErrLink)
	fail("walk-link-last", func(w *fsx.Writer) error { return w.WriteFile(n("d")+"/link/f", nil, 0o600) }, fsx.ErrLink)
	fail("walk-link-mkdir", func(w *fsx.Writer) error { return w.Mkdir(n("d")+"/link/x", 0o700) }, fsx.ErrLink)
	fail("walk-link-set", func(w *fsx.Writer) error { return w.WriteSet(n("d")+"/link/x", nil) }, fsx.ErrLink)
	fail("walk-link-journal", func(w *fsx.Writer) error { _, err := w.CreateJournal(n("d") + "/link/j"); return err }, fsx.ErrLink)
	if heavy {
		fail("write-exists", func(w *fsx.Writer) error { return w.WriteFile(n("d")+"/f", []byte("again"), 0o600) }, os.ErrExist)
		fail("set-exists", func(w *fsx.Writer) error {
			return w.WriteSet(n("set"), []fsx.NewFile{{Name: "a", Data: []byte("a"), Perm: 0o600}, {Name: "b", Perm: 0o600}})
		}, os.ErrExist)
	}
	fail("mkdir-exists", func(w *fsx.Writer) error { return w.Mkdir(n("d"), 0o700) }, os.ErrExist)
	fail("journal-exists", func(w *fsx.Writer) error { _, err := w.CreateJournal(n("d") + "/j"); return err }, os.ErrExist)

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOSNoDescriptorLeaksInHundredsOfRoundsOfSuccessAndFailure(t *testing.T) {
	debug.SetGCPercent(-1) // so that no finalizer closes what the package left open
	t.Cleanup(func() { debug.SetGCPercent(100) })
	wd := newWorld(t)
	wd.symlink(filepath.Join("..", "outside"), "link")
	wd.mkfifo("fifo")
	f, err := os.Create(filepath.Join(wd.root, "over"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(fsx.MaxReadSize + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	oneRound(t, wd, 0, true) // a warm-up: the runtime may open a descriptor of its own on first use
	before := countDescriptors(t)
	for i := 1; i <= 300; i++ {
		oneRound(t, wd, i, i%10 == 0)
		if i%50 == 0 {
			if got := countDescriptors(t); got != before {
				t.Fatalf("after %d rounds %d descriptors are open, want %d: a handle was not closed", i, got, before)
			}
		}
	}
	if got := countDescriptors(t); got != before {
		t.Fatalf("after 300 rounds %d descriptors are open, want %d: a handle was not closed", got, before)
	}
}
