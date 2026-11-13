package fsx_test

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// Error injection: the n-th call to the file system returns an error, for every n of every
// scenario (record 0006, rule 33: stop at once, no retry, nothing after a failure).

type scenarioCtx struct{ j *fsx.Journal }

type scenario struct {
	name string
	dirs []string
	run  func(w *fsx.Writer, c *scenarioCtx) error
}

var scenarios = []scenario{
	{
		name: "WriteFile",
		dirs: []string{"/b", "/b/d"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteFile("/b/d/f.json", []byte("content"), 0o600)
		},
	},
	{
		name: "WriteFile with no data",
		dirs: []string{"/b", "/b/d"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteFile("/b/d/f.json", nil, 0o600)
		},
	},
	{
		name: "WriteSet",
		dirs: []string{"/b", "/b/t"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteSet("/b/t/0007-acme", []fsx.NewFile{
				{Name: "keys.json", Data: []byte("keys"), Perm: 0o600},
				{Name: "root.json", Data: []byte("root"), Perm: 0o600},
			})
		},
	},
	{
		name: "Mkdir",
		dirs: []string{"/b", "/b/d"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.Mkdir("/b/d/new", 0o700)
		},
	},
	{
		name: "journal: create, three Appends, Close",
		dirs: []string{"/b", "/b/d"},
		run: func(w *fsx.Writer, c *scenarioCtx) error {
			j, err := w.CreateJournal("/b/d/j.jsonl")
			if err != nil {
				return err
			}
			c.j = j
			defer func() { _ = j.Close() }() // a caller closes what it opened, whatever happened
			for _, l := range []string{"one", "two", "three"} {
				if err := j.Append([]byte(l)); err != nil {
					return err
				}
			}
			return j.Close()
		},
	},
}

// sameError reports whether both are the one *fsx.Error value: after a stop, every later call
// returns the stop itself and not a copy or a new error.
func sameError(a, b error) bool {
	var x, y *fsx.Error
	return errors.As(a, &x) && errors.As(b, &y) && x == y
}

func stepOf(k opKind) fsx.Step {
	switch k {
	case kMkdir:
		return fsx.StepMkdir
	case kCreate:
		return fsx.StepCreate
	case kWrite:
		return fsx.StepWrite
	case kSync, kClose:
		return fsx.StepSyncFile
	case kRename:
		return fsx.StepRename
	case kSyncDir:
		return fsx.StepSyncDir
	}
	panic("no step for " + string(k))
}

func errPath(o opRec) string {
	if o.Kind == kRename {
		return o.New
	}
	return o.Path
}

// TestInjectEveryCallFailsOnce makes each file system call of each scenario fail, once, with
// an ordinary error and with fs.ErrExist (which must stop the writer like any other).
func TestInjectEveryCallFailsOnce(t *testing.T) {
	for _, sc := range scenarios {
		for _, inj := range []error{errors.New("the stick rejected the command"), fs.ErrExist} {
			t.Run(sc.name+"/"+inj.Error(), func(t *testing.T) {
				clean := newMemFS(sc.dirs...)
				if err := sc.run(&fsx.Writer{FS: clean, Rand: newDetRand(3)}, &scenarioCtx{}); err != nil {
					t.Fatalf("the clean run failed: %v", err)
				}
				cleanOps := clean.opList()
				if len(cleanOps) < 2 {
					t.Fatalf("the clean run made %d calls", len(cleanOps))
				}
				for n := 1; n <= len(cleanOps); n++ {
					injectAt(t, sc, inj, cleanOps, n)
				}
			})
		}
	}
}

func injectAt(t *testing.T, sc scenario, inj error, cleanOps []opRec, n int) {
	t.Helper()
	f := newMemFS(sc.dirs...)
	f.failAt, f.failErr = n, inj
	w := &fsx.Writer{FS: f, Rand: newDetRand(3)}
	c := &scenarioCtx{}
	err := sc.run(w, c)
	failed := cleanOps[n-1]
	where := "the failure of " + failed.String() + ": "

	var fe *fsx.Error
	if !errors.As(err, &fe) {
		t.Fatalf("%sgot %v (%T), want an *fsx.Error", where, err, err)
	}
	if want := stepOf(failed.Kind); fe.Step != want {
		t.Errorf("%sStep %q, want %q", where, fe.Step, want)
	}
	if want := errPath(failed); fe.Path != want {
		t.Errorf("%sPath %q, want %q", where, fe.Path, want)
	}
	if !errors.Is(err, inj) {
		t.Errorf("%sthe error does not wrap what the file system returned: %v", where, err)
	}
	if !strings.Contains(err.Error(), fe.Path) || !strings.Contains(err.Error(), string(fe.Step)) {
		t.Errorf("%sthe message %q names neither the step nor the path", where, err.Error())
	}

	// The same calls up to the failure, the failure attempted once, and then nothing but the
	// close of a file that was open (which is not a later operation).
	ops := f.opList()
	if len(ops) < n {
		t.Fatalf("%sonly %d calls were made", where, len(ops))
	}
	for i := 0; i < n; i++ {
		if ops[i].Kind != cleanOps[i].Kind || ops[i].Path != cleanOps[i].Path || ops[i].New != cleanOps[i].New {
			t.Fatalf("%scall %d was %v, the clean run made %v", where, i+1, ops[i], cleanOps[i])
		}
	}
	if ops[n-1].Err == nil {
		t.Errorf("%sthe injection did not fire", where)
	}
	tail := ops[n:]
	if len(tail) > 1 || (len(tail) == 1 && tail[0].Kind != kClose) {
		t.Errorf("%scalls after the failure: %v (a retry or a later step)", where, tail)
	}
	if got := f.openFiles(); got != 0 {
		t.Errorf("%s%d files are left open", where, got)
	}

	// The writer is stopped: every later call returns the identical error and touches nothing.
	before := f.opCount()
	later := map[string]error{
		"WriteFile": w.WriteFile("/b/d/other.json", []byte("x"), 0o600),
		"WriteSet":  w.WriteSet("/b/t/other", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}}),
		"Mkdir":     w.Mkdir("/b/d/other", 0o700),
	}
	if j, err := w.CreateJournal("/b/d/other.jsonl"); j != nil {
		t.Errorf("%sCreateJournal after the stop returned a journal", where)
	} else {
		later["CreateJournal"] = err
	}
	if c.j != nil && failed.Kind != kClose {
		later["Append"] = c.j.Append([]byte("late"))
	}
	for name, e := range later {
		if !sameError(e, err) {
			t.Errorf("%s%s after the stop returned %v, want the identical error %v", where, name, e, err)
		}
	}
	if after := f.opCount(); after != before {
		t.Errorf("%scalls after the stop reached the file system: %v", where, f.opList()[before:])
	}
}

// TestSecondWriteToTheSamePathFailsAndKeepsTheFirst: rule 31, a name is never replaced.
func TestSecondWriteToTheSamePathFailsAndKeepsTheFirst(t *testing.T) {
	f := newMemFS("/b", "/b/d")
	w := &fsx.Writer{FS: f, Rand: newDetRand(4)}
	p := "/b/d/attempt.json"
	if err := w.WriteFile(p, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := w.WriteFile(p, []byte("second"), 0o600)
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe.Step != fsx.StepRename || fe.Path != p || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("the second write returned %v, want a rename error at %s that wraps fs.ErrExist", err, p)
	}
	live := f.Live()
	if got := mustFile(t, live, p); string(got) != "first" {
		t.Fatalf("the first content is %q after the second write", got)
	}
	// Nothing is deleted: the second content stays under its temporary name.
	var left []string
	for _, q := range live.paths() {
		if strings.HasPrefix(path.Base(q), fsx.TempPrefix) {
			left = append(left, q)
		}
	}
	if len(left) != 1 || string(mustFile(t, live, left[0])) != "second" {
		t.Fatalf("the temporary file of the refused write: %v", left)
	}
	before := f.opCount()
	if err2 := w.WriteFile("/b/d/other.json", []byte("x"), 0o600); !sameError(err2, err) {
		t.Fatalf("a later write returned %v, want the same error", err2)
	}
	if f.opCount() != before {
		t.Fatal("a later write reached the file system after the stop")
	}
}

func TestSecondWriteSetMkdirAndJournalOnTheSameNameFail(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *fsx.Writer) error
		step fsx.Step
		path string
	}{
		{"WriteSet", func(w *fsx.Writer) error {
			return w.WriteSet("/b/t/0007-acme", []fsx.NewFile{{Name: "a", Data: []byte("two"), Perm: 0o600}})
		}, fsx.StepRename, "/b/t/0007-acme"},
		{"Mkdir", func(w *fsx.Writer) error { return w.Mkdir("/b/t/c1", 0o700) }, fsx.StepMkdir, "/b/t/c1"},
		{"CreateJournal", func(w *fsx.Writer) error {
			j, err := w.CreateJournal("/b/t/j.jsonl")
			if j != nil {
				t.Error("a journal came back with an error")
			}
			return err
		}, fsx.StepCreate, "/b/t/j.jsonl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("/b", "/b/t")
			w1 := &fsx.Writer{FS: f, Rand: newDetRand(4)}
			if err := w1.WriteSet("/b/t/0007-acme", []fsx.NewFile{{Name: "a", Data: []byte("one"), Perm: 0o600}}); err != nil {
				t.Fatal(err)
			}
			if err := w1.Mkdir("/b/t/c1", 0o700); err != nil {
				t.Fatal(err)
			}
			j, err := w1.CreateJournal("/b/t/j.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			w := &fsx.Writer{FS: f, Rand: newDetRand(5)}
			err = c.do(w)
			var fe *fsx.Error
			if !errors.As(err, &fe) || fe.Step != c.step || fe.Path != c.path || !errors.Is(err, fs.ErrExist) {
				t.Fatalf("got %v, want %s at %s wrapping fs.ErrExist", err, c.step, c.path)
			}
			if got := mustFile(t, f.Live(), "/b/t/0007-acme/a"); string(got) != "one" {
				t.Fatalf("the first set was changed: %q", got)
			}
			before := f.opCount()
			if err2 := w.Mkdir("/b/t/other", 0o700); !sameError(err2, err) {
				t.Fatalf("a later call returned %v, want the same error", err2)
			}
			if f.opCount() != before {
				t.Fatal("a later call reached the file system after the stop")
			}
		})
	}
}

// TestTemporaryNameCollisionStopsAndDoesNotRetry: the draw is the only thing a retry could
// vary, and rule 33 says there is none.
func TestTemporaryNameCollisionStopsAndDoesNotRetry(t *testing.T) {
	f := newMemFS("/b", "/b/d")
	name, err := (&fsx.Writer{Rand: newDetRand(6)}).TempName()
	if err != nil {
		t.Fatal(err)
	}
	h, err := f.CreateExcl("/b/d/"+name, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	base := f.opCount()

	w := &fsx.Writer{FS: f, Rand: newDetRand(6)}
	err = w.WriteFile("/b/d/f.json", []byte("x"), 0o600)
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe.Step != fsx.StepCreate || fe.Path != "/b/d/"+name || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want a create error at the temporary name wrapping fs.ErrExist", err)
	}
	if got := f.opList()[base:]; len(got) != 1 {
		t.Fatalf("calls after the collision: %v, want the one create", got)
	}
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

// TestRandomSourceFailureIsACreateErrorAndStops: a name that cannot be drawn is a failed
// create with a path that ends in the bare prefix; no file system call is made.
func TestRandomSourceFailureIsACreateErrorAndStops(t *testing.T) {
	boom := errors.New("no entropy")
	for name, src := range map[string]io.Reader{
		"reader error":      failingReader{boom},
		"only unusable":     &constReader{b: 0xff},
		"short then at end": strings.NewReader("abc"),
	} {
		for _, call := range []string{"WriteFile", "WriteSet"} {
			t.Run(name+"/"+call, func(t *testing.T) {
				f := newMemFS("/b", "/b/d")
				w := &fsx.Writer{FS: f, Rand: src}
				var err error
				if call == "WriteFile" {
					err = w.WriteFile("/b/d/f.json", []byte("x"), 0o600)
				} else {
					err = w.WriteSet("/b/d/set", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
				}
				var fe *fsx.Error
				if !errors.As(err, &fe) || fe.Step != fsx.StepCreate || !strings.HasSuffix(fe.Path, "/"+fsx.TempPrefix) {
					t.Fatalf("got %v, want a create error with a path that ends in %q", err, fsx.TempPrefix)
				}
				if name == "reader error" && !errors.Is(err, boom) {
					t.Fatalf("the error does not wrap the reader's error: %v", err)
				}
				if f.opCount() != 0 {
					t.Fatalf("a failed draw reached the file system: %v", f.opList())
				}
				if err2 := w.Mkdir("/b/d/x", 0o700); !sameError(err2, err) {
					t.Fatalf("a later call returned %v, want the same error", err2)
				}
				if f.opCount() != 0 {
					t.Fatal("a later call reached the file system after the stop")
				}
			})
		}
	}
}

// TestShortWriteWithNoErrorIsAnErrorAtTheWrite: io.Writer may return n < len with a nil
// error; the writer must not take that as written.
func TestShortWriteWithNoErrorIsAnErrorAtTheWrite(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		f := newMemFS("/b", "/b/d")
		f.shortAt = 2 // create, then the write
		w := &fsx.Writer{FS: f, Rand: newDetRand(7)}
		err := w.WriteFile("/b/d/f.json", []byte("0123456789"), 0o600)
		var fe *fsx.Error
		if !errors.As(err, &fe) || fe.Step != fsx.StepWrite || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("got %v, want a write error wrapping io.ErrShortWrite", err)
		}
		if !strings.HasPrefix(path.Base(fe.Path), fsx.TempPrefix) {
			t.Fatalf("Path %q is not the temporary name", fe.Path)
		}
		for _, p := range f.Live().paths() {
			if path.Base(p) == "f.json" {
				t.Fatalf("a final name exists after a short write: %s", p)
			}
		}
		if got := f.opList(); got[len(got)-1].Kind == kSync || got[len(got)-1].Kind == kRename {
			t.Fatalf("a step followed the short write: %v", got)
		}
	})
	t.Run("journal line", func(t *testing.T) {
		f := newMemFS("/b", "/b/d")
		f.shortAt = 4 // create, sync, syncdir, then the write of the first line
		w := &fsx.Writer{FS: f, Rand: newDetRand(7)}
		j, err := w.CreateJournal("/b/d/j.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		err = j.Append([]byte("line one"))
		var fe *fsx.Error
		if !errors.As(err, &fe) || fe.Step != fsx.StepWrite || fe.Path != "/b/d/j.jsonl" || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("got %v, want a write error at the journal wrapping io.ErrShortWrite", err)
		}
		before := f.opCount()
		if err2 := j.Append([]byte("line two")); !sameError(err2, err) {
			t.Fatalf("the next Append returned %v, want the same error", err2)
		}
		if f.opCount() != before {
			t.Fatalf("the next Append reached the file system: %v", f.opList()[before:])
		}
		if err2 := j.Close(); !sameError(err2, err) {
			t.Fatalf("Close of a stopped journal returned %v, want the stop", err2)
		}
		if got := f.openFiles(); got != 0 {
			t.Fatalf("Close of a stopped journal left %d files open", got)
		}
	})
}

func TestAFailedAppendMakesTheNextAppendFailWithoutAWrite(t *testing.T) {
	boom := errors.New("write failed")
	f := newMemFS("/b", "/b/d")
	f.failAt, f.failErr = 4, boom // create, sync, syncdir, then the first write
	w := &fsx.Writer{FS: f, Rand: newDetRand(8)}
	j, err := w.CreateJournal("/b/d/j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	err1 := j.Append([]byte("one"))
	var fe *fsx.Error
	if !errors.As(err1, &fe) || fe.Step != fsx.StepWrite || !errors.Is(err1, boom) {
		t.Fatalf("got %v", err1)
	}
	before := f.opCount()
	for i := 0; i < 3; i++ {
		if err := j.Append([]byte("again")); !sameError(err, err1) {
			t.Fatalf("Append %d after the failure returned %v, want the identical error", i, err)
		}
	}
	if f.opCount() != before {
		t.Fatalf("an Append after the failure reached the file system: %v", f.opList()[before:])
	}
	whole, partial, rerr := fsx.ReadJournal(f.Live(), "/b/d/j.jsonl")
	if rerr != nil || len(whole) != 0 || partial != nil {
		t.Fatalf("the journal holds %q and %q (%v) after a write that failed", whole, partial, rerr)
	}
}

func TestWriteIntoAMissingFolderFailsAtTheCreateAndStops(t *testing.T) {
	f := newMemFS("/b")
	w := &fsx.Writer{FS: f, Rand: newDetRand(9)}
	err := w.WriteFile("/b/missing/f.json", []byte("x"), 0o600)
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe.Step != fsx.StepCreate || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want a create error wrapping fs.ErrNotExist", err)
	}
	if ops := f.opList(); len(ops) != 1 {
		t.Fatalf("calls: %v, want the one create", ops)
	}
}

func TestZeroLengthDataMakesNoWriteCall(t *testing.T) {
	for _, data := range [][]byte{nil, {}} {
		f := newMemFS("/b", "/b/d")
		w := &fsx.Writer{FS: f, Rand: newDetRand(9)}
		if err := w.WriteFile("/b/d/empty.json", data, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, o := range f.opList() {
			if o.Kind == kWrite {
				t.Fatalf("a write call for no data: %v", o)
			}
		}
		if got := mustFile(t, f.Live(), "/b/d/empty.json"); len(got) != 0 {
			t.Fatalf("the file holds %d bytes", len(got))
		}
	}
}

// TestTheCallsEachStepMakesAreTheStepsOfThePage pins the order of the file system calls of
// each operation on a clean run, against the table "How a file is written" of
// docs/reference/bundle.md: write, flush the file, rename, flush the folder.
func TestTheCallsEachStepMakesAreTheStepsOfThePage(t *testing.T) {
	seq := func(f *memFS, from int) []string {
		var out []string
		for _, o := range f.opList()[from:] {
			s := string(o.Kind)
			switch o.Kind {
			case kRename:
				s += " " + path.Base(o.Path) + "->" + o.New
			case kSyncDir, kMkdir:
				s += " " + o.Path
			default:
				s += " " + path.Base(o.Path)
			}
			out = append(out, s)
		}
		return out
	}
	f := newMemFS("/b", "/b/d")
	w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
	draws := &fsx.Writer{Rand: newDetRand(1)} // the same names, in the same order
	name := func() string {
		n, _ := draws.TempName()
		return n
	}

	if err := w.WriteFile("/b/d/f.json", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t1 := name()
	want := []string{"create " + t1, "write " + t1, "sync " + t1, "close " + t1, "rename " + t1 + "->/b/d/f.json", "syncdir /b/d"}
	if got := seq(f, 0); !slices.Equal(got, want) {
		t.Fatalf("WriteFile made\n  %v\nwant\n  %v", got, want)
	}

	n := f.opCount()
	if err := w.WriteSet("/b/d/s", []fsx.NewFile{{Name: "a", Data: []byte("1"), Perm: 0o600}, {Name: "b", Data: []byte("2"), Perm: 0o600}}); err != nil {
		t.Fatal(err)
	}
	t2 := name()
	want = []string{
		"mkdir /b/d/" + t2,
		"create a", "write a", "sync a", "close a",
		"create b", "write b", "sync b", "close b",
		"syncdir /b/d/" + t2,
		"rename " + t2 + "->/b/d/s",
		"syncdir /b/d",
	}
	if got := seq(f, n); !slices.Equal(got, want) {
		t.Fatalf("WriteSet made\n  %v\nwant\n  %v", got, want)
	}

	n = f.opCount()
	if err := w.Mkdir("/b/d/c", 0o700); err != nil {
		t.Fatal(err)
	}
	if got, want := seq(f, n), []string{"mkdir /b/d/c", "syncdir /b/d"}; !slices.Equal(got, want) {
		t.Fatalf("Mkdir made %v, want %v", got, want)
	}

	n = f.opCount()
	j, err := w.CreateJournal("/b/d/j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := seq(f, n), []string{"create j.jsonl", "sync j.jsonl", "syncdir /b/d"}; !slices.Equal(got, want) {
		t.Fatalf("CreateJournal made %v, want %v", got, want)
	}
	n = f.opCount()
	if err := j.Append([]byte("line")); err != nil {
		t.Fatal(err)
	}
	if got, want := seq(f, n), []string{"write j.jsonl", "sync j.jsonl"}; !slices.Equal(got, want) {
		t.Fatalf("Append made %v, want %v (one write of the line and its newline, then a flush)", got, want)
	}
	if o := f.opList()[n]; string(o.Data) != "line\n" {
		t.Fatalf("Append wrote %q, want the line and one newline in a single write", o.Data)
	}
}
