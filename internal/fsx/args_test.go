package fsx_test

import (
	"errors"
	"io/fs"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// Arguments are checked before any file system call. A refused argument wraps ErrInvalid,
// touches nothing and does not stop the writer.

func TestInvalidArgumentsTouchNothingAndDoNotStopTheWriter(t *testing.T) {
	type call struct {
		name string
		do   func(w *fsx.Writer) error
	}
	file := func(p string, perm fs.FileMode) call {
		return call{"WriteFile " + p + " " + perm.String(), func(w *fsx.Writer) error { return w.WriteFile(p, []byte("x"), perm) }}
	}
	dir := func(p string, perm fs.FileMode) call {
		return call{"Mkdir " + p + " " + perm.String(), func(w *fsx.Writer) error { return w.Mkdir(p, perm) }}
	}
	set := func(p string, files ...fsx.NewFile) call {
		return call{"WriteSet " + p, func(w *fsx.Writer) error { return w.WriteSet(p, files) }}
	}
	nf := func(name string) fsx.NewFile { return fsx.NewFile{Name: name, Data: []byte("x"), Perm: 0o600} }
	journalAt := func(p string) call {
		return call{"CreateJournal " + p, func(w *fsx.Writer) error {
			j, err := w.CreateJournal(p)
			if j != nil {
				t.Errorf("CreateJournal %q returned a journal with an error", p)
			}
			return err
		}}
	}

	calls := []call{
		// paths
		file("", 0o600),
		file("b/../x", 0o600),
		file("..", 0o600),
		file("b/d/..", 0o600),
		file("b/d/../../x", 0o600),
		file("b/d/.", 0o600),
		file("/", 0o600),
		file("/b/d/f", 0o600),
		file("b/d/.rt-abcdefghijk", 0o600),
		file("b/d/.rt-x", 0o600),
		dir("", 0o700),
		dir("b/../x", 0o700),
		dir("/b/d/new", 0o700),
		dir("b/d/.rt-abcdefghijk", 0o700),
		set("", nf("a")),
		set("b/../s", nf("a")),
		set("/b/d/s", nf("a")),
		set("b/d/.rt-abcdefghijk", nf("a")),
		journalAt(""),
		journalAt("b/../j"),
		journalAt("/b/d/j"),
		journalAt("b/d/.rt-abcdefghijk"),
		// modes with bits beyond the permission bits
		file("b/d/f", fs.ModeDir|0o700),
		file("b/d/f", fs.ModeSetuid|0o600),
		file("b/d/f", fs.ModeSticky|0o600),
		file("b/d/f", fs.ModeSymlink|0o600),
		file("b/d/f", 0o1000),
		dir("b/d/new", fs.ModeSetgid|0o700),
		dir("b/d/new", 0o1700),
		set("b/d/s", fsx.NewFile{Name: "a", Data: []byte("x"), Perm: fs.ModeSetuid | 0o600}),
		// names of a set
		set("b/d/s", nf("")),
		set("b/d/s", nf(".")),
		set("b/d/s", nf("..")),
		set("b/d/s", nf("a/b")),
		set("b/d/s", nf("/a")),
		set("b/d/s", nf(`a\b`)),
		set("b/d/s", nf("a\x00b")),
		set("b/d/s", nf(".rt-abcdefghijk")),
		set("b/d/s", nf("a"), nf("a")),
		set("b/d/s", nf("Keys.json"), nf("keys.json")),
		set("b/d/s", nf("ok"), nf("")),
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("b", "b/d")
			w := newWriter(t, f, 1)
			err := c.do(w)
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Fatalf("got %v, want an error that wraps ErrInvalid", err)
			}
			var fe *fsx.Error
			if errors.As(err, &fe) || errors.Is(err, fsx.ErrStopped) {
				t.Fatalf("an argument error is an *fsx.Error (a stop): %v", err)
			}
			if f.opCount() != 0 {
				t.Fatalf("a refused argument reached the file system: %v", f.opList())
			}
			requireOpen(t, f, 0)
			// not stopped
			if err := w.WriteFile("b/d/ok.json", []byte("ok"), 0o600); err != nil {
				t.Fatalf("the writer stopped after a refused argument: %v", err)
			}
			if got := mustFile(t, f.Live(), "b/d/ok.json"); string(got) != "ok" {
				t.Fatalf("the following write holds %q", got)
			}
		})
	}
}

func TestPermissionBitsAreAccepted(t *testing.T) {
	for _, perm := range []fs.FileMode{0o400, 0o600, 0o640, 0o644, 0o444, 0o700, 0o777} {
		f := newMemFS("b", "b/d")
		w := newWriter(t, f, 1)
		if err := w.WriteFile("b/d/f", []byte("x"), perm); err != nil {
			t.Errorf("WriteFile mode %v: %v", perm, err)
		}
		for _, o := range f.opList() {
			if o.Kind == kCreate && o.Mode != perm {
				t.Errorf("%v was made with mode %v, want %v", o, o.Mode, perm)
			}
		}
	}
	for _, perm := range []fs.FileMode{0o700, 0o755, 0o750, 0o777} {
		f := newMemFS("b", "b/d")
		w := newWriter(t, f, 1)
		if err := w.Mkdir("b/d/m", perm); err != nil {
			t.Errorf("Mkdir mode %v: %v", perm, err)
		}
		for _, o := range f.opList() {
			if o.Kind == kMkdir && o.Mode != perm {
				t.Errorf("%v was made with mode %v, want %v", o, o.Mode, perm)
			}
		}
	}
}

// TestModesOfWhatTheWriterMakesItself: a folder of a set is made with 0700, a journal with 0600.
func TestModesOfWhatTheWriterMakesItself(t *testing.T) {
	f := newMemFS("b")
	w := newWriter(t, f, 1)
	if err := w.WriteSet("b/s", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o640}}); err != nil {
		t.Fatal(err)
	}
	j, err := w.CreateJournal("b/j")
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	var modes []fs.FileMode
	for _, o := range f.opList() {
		if o.Kind == kMkdir || o.Kind == kCreate {
			modes = append(modes, o.Mode)
		}
	}
	if len(modes) != 3 || modes[0] != 0o700 || modes[1] != 0o640 || modes[2] != 0o600 {
		t.Fatalf("modes of the folder of a set, its file and a journal: %v, want 0700, 0640 and 0600", modes)
	}
}

func TestJournalLineWithANewlineIsRefusedAndTheJournalStaysUsable(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	j, err := w.CreateJournal("b/d/j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	before := f.opCount()
	for _, line := range []string{"a\nb", "\n", "tail\n", "\nhead", "a\n\nb"} {
		err := j.Append([]byte(line))
		if !errors.Is(err, fsx.ErrInvalid) || errors.Is(err, fsx.ErrStopped) {
			t.Errorf("Append(%q) = %v, want ErrInvalid and no stop", line, err)
		}
	}
	if f.opCount() != before {
		t.Fatalf("a refused line reached the file system: %v", f.opsAfter(before))
	}
	if err := j.Append([]byte("good")); err != nil {
		t.Fatalf("the journal does not accept a line after refusing one: %v", err)
	}
	whole, partial, err := f.Live().readJournal("b/d/j.jsonl")
	if err != nil || len(whole) != 1 || string(whole[0]) != "good" || partial != nil {
		t.Fatalf("the journal holds %q and %q (%v)", whole, partial, err)
	}
}

func TestJournalAppendAfterCloseIsErrClosedAndSecondCloseIsNil(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	j, err := w.CreateJournal("b/d/j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Append([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	requireOpen(t, f, 0)
	before := f.opCount()
	if err := j.Append([]byte("two")); !errors.Is(err, fsx.ErrClosed) {
		t.Fatalf("Append after Close = %v, want ErrClosed", err)
	}
	if err := j.Append([]byte("a\nb")); !errors.Is(err, fsx.ErrClosed) {
		t.Fatalf("Append of an invalid line after Close = %v, want ErrClosed (the journal is closed, first)", err)
	}
	if err := j.Close(); err != nil {
		t.Fatalf("a second Close = %v, want nil", err)
	}
	if f.opCount() != before {
		t.Fatalf("a call on a closed journal reached the file system: %v", f.opsAfter(before))
	}
	// ErrClosed is not a stop: the writer goes on.
	if err := w.WriteFile("b/d/after.json", []byte("x"), 0o600); err != nil {
		t.Fatalf("the writer stopped after Append on a closed journal: %v", err)
	}
}

// TestJournalCloseMakesNoFlush: every line was flushed by its Append.
func TestJournalCloseMakesNoFlush(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	j, _ := w.CreateJournal("b/d/j.jsonl")
	_ = j.Append([]byte("one"))
	before := f.opCount()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if got := f.opsAfter(before); len(got) != 1 || got[0].Kind != kClose {
		t.Fatalf("Close made %v, want one close", got)
	}
}
