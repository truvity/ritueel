package fsx_test

import (
	"errors"
	"io"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// Error injection: the n-th call to the file system returns an error, for every n of every
// scenario (record 0006, rule 33: stop at once, no retry, nothing after a failure).
//
// The calls are counted as the model counts them: the walk (OpenDir) and the close of a folder
// are calls like the others, with no durable effect. An error of OpenDir stops the writer, at the
// step open-dir. An error of the close of a folder does not: the writer drops it, because nothing
// was written through that handle and what it flushed it flushed with Sync, whose error it keeps;
// the test says so and requires that the call then succeeds with the same calls as a clean run.

type scenarioCtx struct {
	j *fsx.Journal
}

type scenario struct {
	name string
	dirs []string
	run  func(w *fsx.Writer, c *scenarioCtx) error
	// journals is how many journal files stay open when the scenario returns without a
	// failure; with a failure, a journal that was made stays open unless the scenario closed it.
	leaveOpen bool
}

var scenarios = []scenario{
	{
		name: "WriteFile",
		dirs: []string{"b", "b/d"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteFile("b/d/f.json", []byte("content"), 0o600)
		},
	},
	{
		name: "WriteFile three folders deep",
		dirs: []string{"b", "b/d", "b/d/e"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteFile("b/d/e/f.json", []byte("content"), 0o600)
		},
	},
	{
		name: "WriteFile in the root",
		dirs: []string{"b"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteFile("f.json", []byte("content"), 0o600)
		},
	},
	{
		name: "WriteFile with no data",
		dirs: []string{"b", "b/d"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteFile("b/d/f.json", nil, 0o600)
		},
	},
	{
		name: "WriteSet",
		dirs: []string{"b", "b/t"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteSet("b/t/0007-acme", []fsx.NewFile{
				{Name: "keys.json", Data: []byte("keys"), Perm: 0o600},
				{Name: "root.json", Data: []byte("root"), Perm: 0o600},
			})
		},
	},
	{
		name: "WriteSet with no file, in the root",
		dirs: []string{"b"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.WriteSet("s", nil)
		},
	},
	{
		name: "Mkdir",
		dirs: []string{"b", "b/d"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.Mkdir("b/d/new", 0o700)
		},
	},
	{
		name: "Mkdir in the root",
		dirs: []string{"b"},
		run: func(w *fsx.Writer, _ *scenarioCtx) error {
			return w.Mkdir("new", 0o700)
		},
	},
	{
		name: "journal: create, three Appends, Close",
		dirs: []string{"b", "b/d"},
		run: func(w *fsx.Writer, c *scenarioCtx) error {
			j, err := w.CreateJournal("b/d/j.jsonl")
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
	{
		name: "journal: create and three Appends, left open for the writer to close",
		dirs: []string{"b", "b/d"},
		run: func(w *fsx.Writer, c *scenarioCtx) error {
			j, err := w.CreateJournal("b/d/j.jsonl")
			if err != nil {
				return err
			}
			c.j = j
			for _, l := range []string{"one", "two", "three"} {
				if err := j.Append([]byte(l)); err != nil {
					return err
				}
			}
			return nil
		},
		leaveOpen: true,
	},
}

func stepOf(k opKind) fsx.Step {
	switch k {
	case kOpenDir, kReadDir: // the listing of a temporary folder that was just opened is a step of the walk
		return fsx.StepOpenDir
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

// journalsOpen is how many journal files a scenario leaves open when it returns.
func journalsOpen(sc scenario, c *scenarioCtx) int {
	if sc.leaveOpen && c.j != nil {
		return 1
	}
	return 0
}

// TestInjectEveryCallFailsOnce makes each file system call of each scenario fail, once, with
// an ordinary error and with fs.ErrExist (which must stop the writer like any other).
func TestInjectEveryCallFailsOnce(t *testing.T) {
	for _, sc := range scenarios {
		for _, inj := range []error{errors.New("the stick rejected the command"), fs.ErrExist} {
			t.Run(sc.name+"/"+inj.Error(), func(t *testing.T) {
				clean := newMemFS(sc.dirs...)
				c := &scenarioCtx{}
				cw := newWriter(t, clean, 3)
				if err := sc.run(cw, c); err != nil {
					t.Fatalf("the clean run failed: %v", err)
				}
				requireOpen(t, clean, journalsOpen(sc, c))
				cleanOps := clean.opList()
				if len(cleanOps) < 2 {
					t.Fatalf("the clean run made %d calls", len(cleanOps))
				}
				sawFolderClose, sawWalk := false, false
				for n := 1; n <= len(cleanOps); n++ {
					sawFolderClose = sawFolderClose || cleanOps[n-1].Kind == kCloseDir
					sawWalk = sawWalk || cleanOps[n-1].Kind == kOpenDir
					injectAt(t, sc, inj, cleanOps, n)
				}
				if !sawFolderClose && !strings.Contains(sc.name, "root") {
					t.Fatalf("the scenario never closed a folder: the injection at a folder's close is not tried")
				}
				if !sawWalk && !strings.Contains(sc.name, "root") {
					t.Fatalf("the scenario never walked: the injection at OpenDir is not tried")
				}
			})
		}
	}
}

func injectAt(t *testing.T, sc scenario, inj error, cleanOps []opRec, n int) {
	t.Helper()
	f := newMemFS(sc.dirs...)
	f.failAt, f.failErr = n, inj
	w := newWriter(t, f, 3)
	c := &scenarioCtx{}
	err := sc.run(w, c)
	failed := cleanOps[n-1]
	where := "the failure of " + failed.String() + ": "

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

	if failed.Kind == kCloseDir {
		// The error of the close of a folder is dropped: nothing was written through that handle.
		if err != nil {
			t.Errorf("%sthe writer returned %v: an error of the close of a folder must not fail the call", where, err)
		}
		if len(ops) != len(cleanOps) {
			t.Errorf("%sthe calls after it are not those of the clean run: %v", where, ops[n:])
		}
		requireOpen(t, f, journalsOpen(sc, c))
		before := f.opCount()
		f.failAt = 0
		if err := w.WriteFile("b/after.json", []byte("x"), 0o600); err != nil {
			t.Errorf("%sthe writer is stopped after a failed close of a folder: %v", where, err)
		}
		if f.opCount() == before {
			t.Errorf("%sthe write after it made no call", where)
		}
		return
	}

	fe := requireFailed(t, err)
	if want := stepOf(failed.Kind); fe.Step != want {
		t.Errorf("%sStep %q, want %q", where, fe.Step, want)
	}
	if want := errPath(failed); fe.Path != want {
		t.Errorf("%sPath %q, want %q", where, fe.Path, want)
	}
	if !errors.Is(err, inj) {
		t.Errorf("%sthe error does not wrap what the file system returned: %v", where, err)
	}
	if !strings.Contains(err.Error(), strconv.Quote(fe.Path)) || !strings.Contains(err.Error(), string(fe.Step)) {
		t.Errorf("%sthe message %q names neither the step nor the quoted path", where, err.Error())
	}

	// The same calls up to the failure, the failure attempted once, and then nothing but the
	// close of what was open (a file, the folders of the walk): not a retry, not a later step.
	for _, o := range ops[n:] {
		if o.Kind != kClose && o.Kind != kCloseDir {
			t.Errorf("%sa call after the failure that is not a close: %v (a retry or a later step)", where, o)
		}
		if o.Err != nil {
			t.Errorf("%sa close after the failure failed: %v", where, o)
		}
	}
	// The oracle of the handles: the root, and the journal that was made and not closed.
	requireOpen(t, f, journalsOpen(sc, c))

	// The writer is stopped: every later call returns an error that satisfies ErrStopped, holds
	// the first *Error, and touches nothing.
	before := f.opCount()
	later := map[string]error{
		"WriteFile": w.WriteFile("b/d/other.json", []byte("x"), 0o600),
		"WriteSet":  w.WriteSet("b/t/other", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}}),
		"Mkdir":     w.Mkdir("b/d/other", 0o700),
	}
	if j, err := w.CreateJournal("b/d/other.jsonl"); j != nil {
		t.Errorf("%sCreateJournal after the stop returned a journal", where)
	} else {
		later["CreateJournal"] = err
	}
	if _, err := w.TempName(); err != nil {
		later["TempName"] = err
	} else {
		t.Errorf("%sTempName after the stop returned no error", where)
	}
	if c.j != nil {
		later["Append"] = c.j.Append([]byte("late"))
	}
	for name, e := range later {
		if e == nil {
			t.Errorf("%s%s after the stop returned nil", where, name)
			continue
		}
		requireStoppedBy(t, e, fe)
	}
	if after := f.opCount(); after != before {
		t.Errorf("%scalls after the stop reached the file system: %v", where, f.opsAfter(before))
	}
	requireOpen(t, f, journalsOpen(sc, c))
}

// TestInjectEveryCallOfTheWholeCeremony runs the ceremony of cut_test.go with a failure at every
// call of it, and at the failure the run ends (the steps after it are the stop's to refuse): the
// handles are the root and the open journals after every call, and nothing after the closing of
// the writer. This is the oracle of the handles at every point of a whole bundle.
func TestInjectEveryCallOfTheWholeCeremony(t *testing.T) {
	clean := runCeremony(t, realMaker, defaultOrder)
	total := clean.fs.opCount() - 1 // the call that closes the root is not a step of the ceremony
	boom := errors.New("the stick rejected the command")
	for n := 1; n <= total; n++ {
		f := newMemFS("b", "b/history", "b/sealed", "b/trust")
		f.failAt, f.failErr = n, boom
		r := &run{t: t, fs: f, w: realMaker(f), in: newIntent()}
		var first error
		for _, step := range defaultOrder {
			err := r.step(step)
			if err == nil {
				continue
			}
			if first == nil {
				first = err
				fe := requireFailed(t, err)
				if !errors.Is(err, boom) {
					t.Fatalf("failure at call %d: %v does not wrap the injected error", n, err)
				}
				r.w.(realWriter).leakCheckAfterStop(t, f, fe)
				break
			}
		}
		if first == nil {
			// the failure was at a call whose error is dropped: a close of a folder
			if o := f.opList()[n-1]; o.Kind != kCloseDir {
				t.Fatalf("failure at call %d (%v): the ceremony went through", n, o)
			}
		}
		_ = r.w.(realWriter).Close()
		requireClean(t, f)
	}
}

// leakCheckAfterStop: after a stop the root is open, and so is the file of a journal that was
// made and not closed by the caller (the ceremony closes it on a failed Append; a failed Close
// leaves nothing), and no call that a correct caller never makes was seen.
func (r realWriter) leakCheckAfterStop(t *testing.T, f *memFS, first *fsx.Error) {
	t.Helper()
	d, _ := f.handles()
	if d != 1 {
		t.Errorf("after the stop %d folders are open (%s), want the root only", d, f.describeOpen())
	}
	if v := f.violationList(); len(v) > 0 {
		t.Errorf("calls that no correct caller makes: %q", v)
	}
	before := f.opCount()
	err := r.WriteFile("b/history/after-stop.json", []byte("x"), 0o600)
	requireStoppedBy(t, err, first)
	if f.opCount() != before {
		t.Errorf("a call after the stop reached the file system: %v", f.opsAfter(before))
	}
}

// TestSecondWriteToTheSamePathFailsAndKeepsTheFirst: rule 31, a name is never replaced.
func TestSecondWriteToTheSamePathFailsAndKeepsTheFirst(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 4)
	p := "b/d/attempt.json"
	if err := w.WriteFile(p, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := w.WriteFile(p, []byte("second"), 0o600)
	fe := requireFailed(t, err)
	if fe.Step != fsx.StepRename || fe.Path != p || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("the second write returned %v, want a rename error at %s that wraps fs.ErrExist", err, p)
	}
	live := f.Live()
	if got := mustFile(t, live, p); string(got) != "first" {
		t.Fatalf("the first content is %q after the second write", got)
	}
	// Nothing is deleted: the second content stays under its temporary name.
	var left []string
	for _, q := range live.list() {
		if strings.HasPrefix(q[strings.LastIndex(q, "/")+1:], fsx.TempPrefix) {
			left = append(left, q)
		}
	}
	if len(left) != 1 || string(mustFile(t, live, left[0])) != "second" {
		t.Fatalf("the temporary file of the refused write: %v", left)
	}
	before := f.opCount()
	requireStoppedBy(t, w.WriteFile("b/d/other.json", []byte("x"), 0o600), fe)
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
			return w.WriteSet("b/t/0007-acme", []fsx.NewFile{{Name: "a", Data: []byte("two"), Perm: 0o600}})
		}, fsx.StepRename, "b/t/0007-acme"},
		{"Mkdir", func(w *fsx.Writer) error { return w.Mkdir("b/t/c1", 0o700) }, fsx.StepMkdir, "b/t/c1"},
		{"CreateJournal", func(w *fsx.Writer) error {
			j, err := w.CreateJournal("b/t/j.jsonl")
			if j != nil {
				t.Error("a journal came back with an error")
			}
			return err
		}, fsx.StepCreate, "b/t/j.jsonl"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newMemFS("b", "b/t")
			w1 := newWriter(t, f, 4)
			if err := w1.WriteSet("b/t/0007-acme", []fsx.NewFile{{Name: "a", Data: []byte("one"), Perm: 0o600}}); err != nil {
				t.Fatal(err)
			}
			if err := w1.Mkdir("b/t/c1", 0o700); err != nil {
				t.Fatal(err)
			}
			j, err := w1.CreateJournal("b/t/j.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			w := newWriter(t, f, 5)
			err = c.do(w)
			fe := requireFailed(t, err)
			if fe.Step != c.step || fe.Path != c.path || !errors.Is(err, fs.ErrExist) {
				t.Fatalf("got %v, want %s at %s wrapping fs.ErrExist", err, c.step, c.path)
			}
			if got := mustFile(t, f.Live(), "b/t/0007-acme/a"); string(got) != "one" {
				t.Fatalf("the first set was changed: %q", got)
			}
			before := f.opCount()
			requireStoppedBy(t, w.Mkdir("b/t/other", 0o700), fe)
			if f.opCount() != before {
				t.Fatal("a later call reached the file system after the stop")
			}
		})
	}
}

// TestTemporaryNameCollisionStopsAndDoesNotRetry: the draw is the only thing a retry could
// vary, and rule 33 says there is none.
func TestTemporaryNameCollisionStopsAndDoesNotRetry(t *testing.T) {
	f := newMemFS("b", "b/d")
	name, err := (&fsx.Writer{Rand: newDetRand(6)}).TempName()
	if err != nil {
		t.Fatal(err)
	}
	root := f.Root()
	b := mustOpen(t, root, "b")
	d := mustOpen(t, b, "d")
	_ = mustCreate(t, d, name).Close()
	for _, h := range []fsx.FS{d, b, root} {
		_ = h.Close()
	}
	base := f.opCount()

	w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(6)}
	defer func() { _ = w.Close() }()
	err = w.WriteFile("b/d/f.json", []byte("x"), 0o600)
	fe := requireFailed(t, err)
	if fe.Step != fsx.StepCreate || fe.Path != "b/d/"+name || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want a create error at the temporary name wrapping fs.ErrExist", err)
	}
	var creates int
	for _, o := range f.opsAfter(base) {
		if o.Kind == kCreate {
			creates++
		}
	}
	if creates != 1 {
		t.Fatalf("%d creates after the collision, want the one", creates)
	}
}

// TestRandomSourceFailureIsACreateErrorAndStops: a name that cannot be drawn is a failed
// create with a path that ends in the bare prefix; no file system call is made but the walk.
func TestRandomSourceFailureIsACreateErrorAndStops(t *testing.T) {
	boom := errors.New("no entropy")
	for name, src := range map[string]io.Reader{
		"reader error":      failingReader{boom},
		"only unusable":     &constReader{b: 0xff},
		"short then at end": strings.NewReader("abc"),
	} {
		for _, call := range []string{"WriteFile", "WriteSet"} {
			t.Run(name+"/"+call, func(t *testing.T) {
				f := newMemFS("b", "b/d")
				w := &fsx.Writer{FS: f.Root(), Rand: src}
				defer func() { _ = w.Close() }()
				var err error
				if call == "WriteFile" {
					err = w.WriteFile("b/d/f.json", []byte("x"), 0o600)
				} else {
					err = w.WriteSet("b/d/set", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
				}
				fe := requireFailed(t, err)
				if fe.Step != fsx.StepCreate || !strings.HasSuffix(fe.Path, "/"+fsx.TempPrefix) {
					t.Fatalf("got %v, want a create error with a path that ends in %q", err, fsx.TempPrefix)
				}
				if name == "reader error" && !errors.Is(err, boom) {
					t.Fatalf("the error does not wrap the reader's error: %v", err)
				}
				for _, o := range f.opList() {
					if o.Kind != kOpenDir && o.Kind != kCloseDir {
						t.Fatalf("a failed draw reached the file system: %v", o)
					}
				}
				n := f.opCount()
				requireStoppedBy(t, w.Mkdir("b/d/x", 0o700), fe)
				if f.opCount() != n {
					t.Fatal("a later call reached the file system after the stop")
				}
				requireOpen(t, f, 0)
			})
		}
	}
}

// TestShortWriteWithNoErrorIsAnErrorAtTheWrite: io.Writer may return n < len with a nil
// error; the writer must not take that as written.
func TestShortWriteWithNoErrorIsAnErrorAtTheWrite(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		f := newMemFS("b", "b/d")
		w := newWriter(t, f, 7)
		f.shortAt = 5 // two walks, the close of the first folder, the create, then the write
		err := w.WriteFile("b/d/f.json", []byte("0123456789"), 0o600)
		fe := requireFailed(t, err)
		if fe.Step != fsx.StepWrite || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("got %v, want a write error wrapping io.ErrShortWrite", err)
		}
		if !strings.HasPrefix(fe.Path[strings.LastIndex(fe.Path, "/")+1:], fsx.TempPrefix) {
			t.Fatalf("Path %q is not the temporary name", fe.Path)
		}
		for _, p := range f.Live().list() {
			if strings.HasSuffix(p, "/f.json") {
				t.Fatalf("a final name exists after a short write: %s", p)
			}
		}
		for _, o := range f.opList() {
			if o.Kind == kSync || o.Kind == kRename {
				t.Fatalf("a step followed the short write: %v", o)
			}
		}
		requireOpen(t, f, 0)
	})
	t.Run("journal line", func(t *testing.T) {
		f := newMemFS("b", "b/d")
		w := newWriter(t, f, 7)
		j, err := w.CreateJournal("b/d/j.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		f.shortAt = f.opCount() + 1
		err = j.Append([]byte("line one"))
		fe := requireFailed(t, err)
		if fe.Step != fsx.StepWrite || fe.Path != "b/d/j.jsonl" || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("got %v, want a write error at the journal wrapping io.ErrShortWrite", err)
		}
		before := f.opCount()
		requireStoppedBy(t, j.Append([]byte("line two")), fe)
		if f.opCount() != before {
			t.Fatalf("the next Append reached the file system: %v", f.opsAfter(before))
		}
		if err2 := j.Close(); !errors.Is(err2, fsx.ErrStopped) {
			t.Fatalf("Close of a stopped journal returned %v, want the stop", err2)
		} else {
			requireStoppedBy(t, err2, fe)
		}
		if got := f.openFiles(); got != 0 {
			t.Fatalf("Close of a stopped journal left %d files open", got)
		}
	})
}

func TestAFailedAppendMakesTheNextAppendFailWithoutAWrite(t *testing.T) {
	boom := errors.New("write failed")
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 8)
	j, err := w.CreateJournal("b/d/j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	f.failAt, f.failErr = f.opCount()+1, boom // the first write
	err1 := j.Append([]byte("one"))
	fe := requireFailed(t, err1)
	if fe.Step != fsx.StepWrite || !errors.Is(err1, boom) {
		t.Fatalf("got %v", err1)
	}
	before := f.opCount()
	for i := 0; i < 3; i++ {
		requireStoppedBy(t, j.Append([]byte("again")), fe)
	}
	if f.opCount() != before {
		t.Fatalf("an Append after the failure reached the file system: %v", f.opsAfter(before))
	}
	root := f.Live()
	whole, partial, rerr := root.readJournal("b/d/j.jsonl")
	if rerr != nil || len(whole) != 0 || partial != nil {
		t.Fatalf("the journal holds %q and %q (%v) after a write that failed", whole, partial, rerr)
	}
}

func TestWriteIntoAMissingFolderFailsAtTheWalkAndStops(t *testing.T) {
	f := newMemFS("b")
	w := newWriter(t, f, 9)
	err := w.WriteFile("b/missing/f.json", []byte("x"), 0o600)
	fe := requireFailed(t, err)
	if fe.Step != fsx.StepOpenDir || fe.Path != "b/missing" || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want an open-dir error at b/missing wrapping fs.ErrNotExist", err)
	}
	var kinds []opKind
	for _, o := range f.opList() {
		kinds = append(kinds, o.Kind)
	}
	if want := []opKind{kOpenDir, kOpenDir, kCloseDir}; !slices.Equal(kinds, want) {
		t.Fatalf("calls: %v, want the walk to b, the failed walk to missing, and the close of b", kinds)
	}
	requireOpen(t, f, 0)
}

func TestZeroLengthDataMakesNoWriteCall(t *testing.T) {
	for _, data := range [][]byte{nil, {}} {
		f := newMemFS("b", "b/d")
		w := newWriter(t, f, 9)
		if err := w.WriteFile("b/d/empty.json", data, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, o := range f.opList() {
			if o.Kind == kWrite {
				t.Fatalf("a write call for no data: %v", o)
			}
		}
		if got := mustFile(t, f.Live(), "b/d/empty.json"); len(got) != 0 {
			t.Fatalf("the file holds %d bytes", len(got))
		}
	}
}

// seq lists the calls from the n-th on, each as its kind and its path (a rename as old to new).
func seq(f *memFS, from int) []string {
	var out []string
	for _, o := range f.opsAfter(from) {
		s := string(o.Kind) + " " + o.Path
		if o.Kind == kRename {
			s += " -> " + o.New
		}
		out = append(out, s)
	}
	return out
}

// TestTheCallsEachStepMakesAreTheStepsOfThePage pins the order of the file system calls of
// each operation on a clean run, against the table "How a file is written" of
// docs/reference/bundle.md: write, flush the file, rename, flush the folder; and, around them,
// the walk to the folder and the close of every folder the walk opened.
func TestTheCallsEachStepMakesAreTheStepsOfThePage(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	draws := &fsx.Writer{Rand: newDetRand(1)} // the same names, in the same order
	name := func() string {
		n, _ := draws.TempName()
		return n
	}

	if err := w.WriteFile("b/d/f.json", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t1 := name()
	want := []string{
		"opendir b", "opendir b/d", "closedir b",
		"create b/d/" + t1, "write b/d/" + t1, "sync b/d/" + t1, "close b/d/" + t1,
		"rename b/d/" + t1 + " -> b/d/f.json", "syncdir b/d", "closedir b/d",
	}
	if got := seq(f, 0); !slices.Equal(got, want) {
		t.Fatalf("WriteFile made\n  %v\nwant\n  %v", got, want)
	}

	n := f.opCount()
	if err := w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a", Data: []byte("1"), Perm: 0o600}, {Name: "b", Data: []byte("2"), Perm: 0o600}}); err != nil {
		t.Fatal(err)
	}
	t2 := name()
	want = []string{
		"opendir b", "opendir b/d", "closedir b",
		"mkdir b/d/" + t2, "opendir b/d/" + t2, "readdir b/d/" + t2,
		"create b/d/" + t2 + "/a", "write b/d/" + t2 + "/a", "sync b/d/" + t2 + "/a", "close b/d/" + t2 + "/a",
		"create b/d/" + t2 + "/b", "write b/d/" + t2 + "/b", "sync b/d/" + t2 + "/b", "close b/d/" + t2 + "/b",
		"syncdir b/d/" + t2, "closedir b/d/" + t2,
		"rename b/d/" + t2 + " -> b/d/s", "syncdir b/d", "closedir b/d",
	}
	if got := seq(f, n); !slices.Equal(got, want) {
		t.Fatalf("WriteSet made\n  %v\nwant\n  %v", got, want)
	}

	n = f.opCount()
	if err := w.Mkdir("b/d/c", 0o700); err != nil {
		t.Fatal(err)
	}
	want = []string{"opendir b", "opendir b/d", "closedir b", "mkdir b/d/c", "syncdir b/d", "closedir b/d"}
	if got := seq(f, n); !slices.Equal(got, want) {
		t.Fatalf("Mkdir made %v, want %v", got, want)
	}

	n = f.opCount()
	j, err := w.CreateJournal("b/d/j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"opendir b", "opendir b/d", "closedir b", "create b/d/j.jsonl", "sync b/d/j.jsonl", "syncdir b/d", "closedir b/d"}
	if got := seq(f, n); !slices.Equal(got, want) {
		t.Fatalf("CreateJournal made %v, want %v", got, want)
	}
	n = f.opCount()
	if err := j.Append([]byte("line")); err != nil {
		t.Fatal(err)
	}
	want = []string{"write b/d/j.jsonl", "sync b/d/j.jsonl"}
	if got := seq(f, n); !slices.Equal(got, want) {
		t.Fatalf("Append made %v, want %v (one write of the line and its newline, then a flush)", got, want)
	}
	if o := f.opList()[n]; string(o.Data) != "line\n" {
		t.Fatalf("Append wrote %q, want the line and one newline in a single write", o.Data)
	}
	n = f.opCount()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := seq(f, n), []string{"close b/d/j.jsonl"}; !slices.Equal(got, want) {
		t.Fatalf("Journal.Close made %v, want %v (no flush: every line was flushed)", got, want)
	}

	// a path with no folder works in the root, with no walk and no close of it
	n = f.opCount()
	if err := w.WriteFile("r.json", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t3 := name()
	_ = t3 // the draws of the earlier calls were made in this order, one for each temporary name
	for _, s := range seq(f, n) {
		if strings.HasPrefix(s, "opendir") || strings.HasPrefix(s, "closedir") {
			t.Fatalf("a write in the root walked or closed a folder: %v", seq(f, n))
		}
	}
	if got := seq(f, n); got[len(got)-1] != "syncdir ." {
		t.Fatalf("a write in the root ended with %q, want the flush of the root %q", got[len(got)-1], "syncdir .")
	}
}
