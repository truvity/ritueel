package fsx_test

import (
	"bytes"
	"errors"
	"io/fs"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// These tests check the model that the cut tests stand on. If the model were too kind, every
// negative control would pass the oracle for the wrong reason; and if it let a link through, or
// forgot a handle, the tests of the links and of the handles would show nothing.

func mustCreate(t *testing.T, d fsx.FS, name string) fsx.File {
	t.Helper()
	h, err := d.CreateExcl(name, 0o600)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	return h
}

func mustOpen(t *testing.T, d fsx.FS, name string) fsx.FS {
	t.Helper()
	h, err := d.OpenDir(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	return h
}

func TestMemFSBehavesLikeAFileSystem(t *testing.T) {
	f := newMemFS("a")
	root := f.Root()
	a := mustOpen(t, root, "a")
	if err := a.Mkdir("d", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.Mkdir("d", 0o700); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second mkdir: %v, want ErrExist", err)
	}
	d := mustOpen(t, a, "d")
	h := mustCreate(t, d, "x")
	if _, err := d.CreateExcl("x", 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second create: %v, want ErrExist", err)
	}
	if _, err := h.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.RenameNoReplace("x", "y"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ReadFile("x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the old name after a rename: %v", err)
	}
	got, err := d.ReadFile("y")
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadFile: %q, %v", got, err)
	}
	_ = mustCreate(t, d, "z").Close()
	if err := d.RenameNoReplace("z", "y"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a rename onto an existing name: %v, want ErrExist", err)
	}
	if err := d.RenameNoReplace("nope", "q"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a rename of a missing file: %v, want ErrNotExist", err)
	}
	if _, err := a.OpenDir("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("open of a missing folder: %v, want ErrNotExist", err)
	}
	if _, err := d.OpenDir("y"); err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, fsx.ErrLink) {
		t.Fatalf("open of a file as a folder: %v, want an error that is neither ErrNotExist nor ErrLink", err)
	}
	ents, err := d.ReadDir()
	if err != nil || len(ents) != 2 || ents[0].Name() != "y" || ents[1].Name() != "z" {
		t.Fatalf("ReadDir: %v, %v", ents, err)
	}
	if v := f.violationList(); len(v) != 0 {
		t.Fatalf("a correct use of the model was called a violation: %q", v)
	}
}

func TestMemFSAllPolicyIsTheLiveTreeAndEveryReplayAgrees(t *testing.T) {
	f := newMemFS("a")
	root := f.Root()
	a := mustOpen(t, root, "a")
	_ = a.Mkdir("d", 0o700)
	d := mustOpen(t, a, "d")
	h := mustCreate(t, d, "x")
	_, _ = h.Write([]byte("abc"))
	_ = h.Sync()
	_ = h.Close()
	_ = d.RenameNoReplace("x", "y")
	_ = d.Sync()
	h2 := mustCreate(t, d, "w")
	_, _ = h2.Write([]byte("tail"))
	n := f.opCount()
	live := f.Live().paths()
	if all := f.CrashAfter(n, policyAll).paths(); !slices.Equal(live, all) {
		t.Fatalf("all policy %v, live %v", all, live)
	}
	for _, p := range policies(12) {
		_ = f.CrashAfter(n, p) // a divergence of the replay panics
	}
}

// TestMemFSAFolderThatWasRenamedIsStillTheSameFolderForItsHandle: a handle stands for a node, as
// a descriptor does, so a rename of the folder does not move what is made through the handle, and
// the replay finds the folder by its id.
func TestMemFSAFolderThatWasRenamedIsStillTheSameFolderForItsHandle(t *testing.T) {
	f := newMemFS("a")
	root := f.Root()
	a := mustOpen(t, root, "a")
	if err := root.RenameNoReplace("a", "b"); err != nil {
		t.Fatal(err)
	}
	_ = mustCreate(t, a, "x").Close()
	_ = a.Sync()
	_ = root.Sync()
	n := f.opCount()
	for _, p := range policies(6) {
		img := f.CrashAfter(n, p)
		if _, ok := img.file("b/x"); !ok {
			t.Fatalf("policy %v: %v, want the file made through the handle of the renamed folder at b/x", p, img.list())
		}
	}
}

func TestMemFSUnflushedDataMayBeLostFlushedDataIsKept(t *testing.T) {
	f := newMemFS("a")
	a := mustOpen(t, f.Root(), "a")
	h := mustCreate(t, a, "x")
	_, _ = h.Write(bytes.Repeat([]byte("A"), 100))
	_ = h.Sync()
	_, _ = h.Write(bytes.Repeat([]byte("B"), 100))
	_ = a.Sync()
	n := f.opCount()

	got := func(p policy) []byte {
		b, ok := f.CrashAfter(n, p).file("a/x")
		if !ok {
			t.Fatalf("policy %v: the file is gone though its folder was flushed", p)
		}
		return b
	}
	if b := got(policyFlushed); len(b) != 100 {
		t.Fatalf("flushed-only keeps %d bytes, want exactly the 100 that a Sync covered", len(b))
	}
	if b := got(policyAll); len(b) != 200 {
		t.Fatalf("everything keeps %d bytes, want 200", len(b))
	}
	lengths := map[int]bool{}
	for s := uint64(1); s <= 60; s++ {
		b := got(seedPolicy(s))
		if len(b) < 100 || len(b) > 200 {
			t.Fatalf("seed %d keeps %d bytes: less than what was flushed or more than was written", s, len(b))
		}
		if !bytes.Equal(b[:100], bytes.Repeat([]byte("A"), 100)) || !bytes.Equal(b[100:], bytes.Repeat([]byte("B"), len(b)-100)) {
			t.Fatalf("seed %d: a surviving file is not a prefix of what was written", s)
		}
		lengths[len(b)] = true
	}
	if !lengths[100] || !lengths[200] {
		t.Fatalf("the seeds never gave the two ends (%v): the model cannot lose a whole write or keep it", sortedLens(lengths))
	}
	if len(lengths) < 4 {
		t.Fatalf("the seeds gave only the lengths %v: no torn write in between", sortedLens(lengths))
	}
}

func sortedLens(m map[int]bool) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestMemFSUnflushedFolderEntriesMayBeLost(t *testing.T) {
	f := newMemFS("a")
	a := mustOpen(t, f.Root(), "a")
	h := mustCreate(t, a, "x")
	_ = h.Sync() // the data is flushed, the entry is not
	n := f.opCount()
	if _, ok := f.CrashAfter(n, policyFlushed).file("a/x"); ok {
		t.Fatal("a file whose folder was never flushed survived the flushed-only policy")
	}
	if _, ok := f.CrashAfter(n, policyAll).file("a/x"); !ok {
		t.Fatal("the all policy lost a created file")
	}
	present, absent := 0, 0
	for s := uint64(1); s <= 40; s++ {
		if _, ok := f.CrashAfter(n, seedPolicy(s)).file("a/x"); ok {
			present++
		} else {
			absent++
		}
	}
	if present == 0 || absent == 0 {
		t.Fatalf("the seeds gave %d present and %d absent: they do not vary the loss of an entry", present, absent)
	}

	_ = a.Sync()
	n = f.opCount()
	for _, p := range policies(12) {
		if _, ok := f.CrashAfter(n, p).file("a/x"); !ok {
			t.Fatalf("policy %v lost a file whose folder was flushed", p)
		}
	}
}

func TestMemFSAnUnflushedRenameMayBeLostAndKeepsTheOldName(t *testing.T) {
	f := newMemFS("a")
	a := mustOpen(t, f.Root(), "a")
	h := mustCreate(t, a, "old")
	_, _ = h.Write([]byte("data"))
	_ = h.Sync()
	_ = h.Close()
	_ = a.Sync()
	_ = a.RenameNoReplace("old", "new")
	n := f.opCount()
	img := f.CrashAfter(n, policyFlushed)
	if _, ok := img.file("a/old"); !ok {
		t.Fatal("an unflushed rename took effect under the flushed-only policy")
	}
	if _, ok := img.file("a/new"); ok {
		t.Fatal("the new name exists under the flushed-only policy")
	}
	img = f.CrashAfter(n, policyAll)
	if _, ok := img.file("a/old"); ok {
		t.Fatal("the old name survived a rename under the all policy")
	}
	if b, ok := img.file("a/new"); !ok || string(b) != "data" {
		t.Fatal("the new name is missing under the all policy")
	}
	_ = a.Sync()
	img = f.CrashAfter(f.opCount(), policyFlushed)
	if _, ok := img.file("a/new"); !ok {
		t.Fatal("a rename followed by a folder flush is not durable")
	}
}

func TestMemFSACutIsAfterTheCallItNames(t *testing.T) {
	f := newMemFS("a")
	a := mustOpen(t, f.Root(), "a") // call 1: the walk
	h := mustCreate(t, a, "x")      // call 2
	_, _ = h.Write([]byte("abc"))   // call 3
	_ = a.Sync()
	if _, ok := f.CrashAfter(0, policyAll).file("a/x"); ok {
		t.Fatal("a cut after 0 calls shows a file")
	}
	if _, ok := f.CrashAfter(1, policyAll).file("a/x"); ok {
		t.Fatal("a cut after the walk shows a file: a walk has no effect")
	}
	if _, ok := f.CrashAfter(2, policyAll).file("a/x"); !ok {
		t.Fatal("a cut after the create does not show the file")
	}
	if b, _ := f.CrashAfter(2, policyAll).file("a/x"); len(b) != 0 {
		t.Fatalf("a cut after the create shows %d bytes", len(b))
	}
	if b, _ := f.CrashAfter(3, policyAll).file("a/x"); string(b) != "abc" {
		t.Fatalf("a cut after the write shows %q", b)
	}
}

func TestMemFSInjectionAndShortWrite(t *testing.T) {
	boom := errors.New("boom")
	f := newMemFS("a")
	a := mustOpen(t, f.Root(), "a")
	h := mustCreate(t, a, "x")
	f.failAt, f.failErr = f.opCount()+1, boom
	if n, err := h.Write([]byte("abc")); n != 0 || !errors.Is(err, boom) {
		t.Fatalf("the injected write returned %d, %v", n, err)
	}
	if got := f.CrashAfter(f.opCount(), policyAll); len(mustFile(t, got, "a/x")) != 0 {
		t.Fatal("a failed write had an effect")
	}

	g := newMemFS("a")
	a = mustOpen(t, g.Root(), "a")
	h = mustCreate(t, a, "x")
	g.shortAt = g.opCount() + 1
	n, err := h.Write([]byte("abcd"))
	if n != 2 || err != nil {
		t.Fatalf("the short write returned %d, %v, want 2, nil", n, err)
	}
	if got := mustFile(t, g.CrashAfter(g.opCount(), policyAll), "a/x"); string(got) != "ab" {
		t.Fatalf("a short write left %q", got)
	}
}

// TestMemFSInjectionReachesTheWalkAndTheCloseOfAFolder: every call is a call that can fail, the
// calls with no durable effect too. A close that fails still closes.
func TestMemFSInjectionReachesTheWalkAndTheCloseOfAFolder(t *testing.T) {
	boom := errors.New("boom")
	f := newMemFS("a")
	root := f.Root()
	f.failAt, f.failErr = 1, boom
	if _, err := root.OpenDir("a"); !errors.Is(err, boom) {
		t.Fatalf("the injected walk returned %v", err)
	}
	if d, _ := f.handles(); d != 1 {
		t.Fatalf("a failed OpenDir opened a handle: %d folders open", d)
	}
	a := mustOpen(t, root, "a")
	f.failAt = f.opCount() + 1
	if err := a.Close(); !errors.Is(err, boom) {
		t.Fatalf("the injected close returned %v", err)
	}
	if d, _ := f.handles(); d != 1 {
		t.Fatalf("a close that failed left the folder open: %d folders open", d)
	}
	if _, err := a.ReadDir(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("a call on a folder whose close failed: %v, want fs.ErrClosed", err)
	}
	f.violations = nil
}

// TestMemFSLinksFifosAndLongFilesAreNamesTheModelDoesNotFollow: what the interface says of each
// kind of name, on the model, so that the tests that use them mean something.
func TestMemFSLinksFifosAndLongFilesAreNamesTheModelDoesNotFollow(t *testing.T) {
	f := newMemFS("a", "outside")
	f.addFile("outside/secret", []byte("secret"))
	f.addLink("a/linkdir", "../outside")
	f.addLink("a/linkfile", "../outside/secret")
	f.addLink("a/dangling", "../nowhere")
	f.addFifo("a/pipe")
	f.addFile("a/regular", []byte("data"))
	f.addVirtual("a/exact", fsx.MaxReadSize)
	f.addVirtual("a/over", fsx.MaxReadSize+1)
	root := f.Root()
	a := mustOpen(t, root, "a")

	for _, name := range []string{"linkdir", "linkfile", "dangling"} {
		if _, err := a.OpenDir(name); !errors.Is(err, fsx.ErrLink) || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("OpenDir of the link %s: %v, want ErrLink and not ErrNotExist", name, err)
		}
		if _, err := a.ReadFile(name); !errors.Is(err, fsx.ErrLink) {
			t.Errorf("ReadFile of the link %s: %v, want ErrLink", name, err)
		}
	}
	for _, name := range []string{"linkdir", "linkfile", "dangling", "pipe", "regular", "exact"} {
		if err := a.Mkdir(name, 0o700); !errors.Is(err, fs.ErrExist) {
			t.Errorf("Mkdir over %s: %v, want ErrExist", name, err)
		}
		if _, err := a.CreateExcl(name, 0o600); !errors.Is(err, fs.ErrExist) {
			t.Errorf("CreateExcl over %s: %v, want ErrExist", name, err)
		}
		_ = mustCreate(t, a, "src-"+name).Close()
		if err := a.RenameNoReplace("src-"+name, name); !errors.Is(err, fs.ErrExist) {
			t.Errorf("RenameNoReplace onto %s: %v, want ErrExist", name, err)
		}
	}
	if _, err := a.OpenDir("pipe"); err == nil || errors.Is(err, fsx.ErrLink) {
		t.Errorf("OpenDir of a FIFO: %v, want an error that is not ErrLink", err)
	}
	if _, err := a.ReadFile("pipe"); !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("ReadFile of a FIFO: %v, want ErrNotRegular", err)
	}
	if _, err := root.ReadFile("a"); !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("ReadFile of a folder: %v, want ErrNotRegular", err)
	}
	if got, err := a.ReadFile("regular"); err != nil || string(got) != "data" {
		t.Errorf("ReadFile of a regular file: %q, %v", got, err)
	}
	if got, err := a.ReadFile("exact"); err != nil || len(got) != fsx.MaxReadSize {
		t.Errorf("ReadFile of a file of exactly MaxReadSize: %d bytes, %v", len(got), err)
	}
	if _, err := a.ReadFile("over"); !errors.Is(err, fsx.ErrTooLarge) {
		t.Errorf("ReadFile of a file one byte over: %v, want ErrTooLarge", err)
	}
	if _, err := a.ReadFile("none"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile of a missing name: %v, want ErrNotExist", err)
	}

	ents, err := a.ReadDir()
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]fs.FileMode{}
	for _, e := range ents {
		kinds[e.Name()] = e.Type()
	}
	for name, want := range map[string]fs.FileMode{"linkdir": fs.ModeSymlink, "dangling": fs.ModeSymlink, "pipe": fs.ModeNamedPipe, "regular": 0, "exact": 0} {
		if got := kinds[name]; got != want {
			t.Errorf("ReadDir lists %s as %v, want %v", name, got, want)
		}
	}
	// nothing outside was touched, and the link is a name that renames like any other
	if got, ok := f.Live().file("outside/secret"); !ok || string(got) != "secret" {
		t.Error("the file behind a link changed")
	}
	f.violations = nil
}

// TestMemFSClosedHandlesAndTheCount: a method after Close fails with fs.ErrClosed and is a
// violation; a second Close does nothing (and is a violation too); a Close of a folder closes
// nothing that was opened from it.
func TestMemFSClosedHandlesAndTheCount(t *testing.T) {
	f := newMemFS("a")
	root := f.Root()
	a := mustOpen(t, root, "a")
	h := mustCreate(t, a, "x")
	if d, fl := f.handles(); d != 2 || fl != 1 {
		t.Fatalf("%d folders and %d files open, want 2 and 1", d, fl)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadDir(); err != nil {
		t.Fatalf("a folder opened from a closed folder is not usable: %v", err)
	}
	if d, _ := f.handles(); d != 1 {
		t.Fatalf("closing a folder closed another: %d folders open", d)
	}
	if _, err := root.OpenDir("a"); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("OpenDir after Close: %v, want fs.ErrClosed", err)
	}
	if err := root.Mkdir("q", 0o700); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("Mkdir after Close: %v", err)
	}
	if _, err := root.CreateExcl("q", 0o600); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("CreateExcl after Close: %v", err)
	}
	if err := root.RenameNoReplace("a", "q"); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("RenameNoReplace after Close: %v", err)
	}
	if err := root.Sync(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("Sync after Close: %v", err)
	}
	if _, err := root.ReadFile("a"); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("ReadFile after Close: %v", err)
	}
	if _, err := root.ReadDir(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("ReadDir after Close: %v", err)
	}
	if got := len(f.violationList()); got != 7 {
		t.Fatalf("%d violations for 7 calls on a closed folder: %q", got, f.violationList())
	}
	if err := root.Close(); err != nil {
		t.Fatalf("a second Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write([]byte("x")); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("Write after Close: %v", err)
	}
	if err := h.Sync(); !errors.Is(err, fs.ErrClosed) {
		t.Fatalf("file Sync after Close: %v", err)
	}
	_ = a.Close()
	if d, fl := f.handles(); d != 0 || fl != 0 {
		t.Fatalf("%d folders and %d files open after every close", d, fl)
	}
}

// TestMemFSRecordsANameThatIsNotOnePlainName: the model is the place to see what the package
// hands to an FS: one plain name of the name rule, never a path.
func TestMemFSRecordsANameThatIsNotOnePlainName(t *testing.T) {
	f := newMemFS("a")
	a := mustOpen(t, f.Root(), "a")
	for _, name := range []string{"", ".", "..", "x/y", "a b", "é", "x\x00"} {
		_ = a.Mkdir(name, 0o700)
	}
	if got := len(f.violationList()); got != 7 {
		t.Fatalf("%d violations for 7 bad names: %q", got, f.violationList())
	}
}

func mustFile(t *testing.T, img *image, p string) []byte {
	t.Helper()
	b, ok := img.file(p)
	if !ok {
		t.Fatalf("%s is not in the image (have %v)", p, img.list())
	}
	return b
}
