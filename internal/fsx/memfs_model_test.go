package fsx_test

import (
	"bytes"
	"errors"
	"io/fs"
	"slices"
	"testing"
)

// These tests check the model that the cut tests stand on. If the model were too kind, every
// negative control would pass the oracle for the wrong reason.

func mustCreate(t *testing.T, f *memFS, p string) interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
} {
	t.Helper()
	h, err := f.CreateExcl(p, 0o600)
	if err != nil {
		t.Fatalf("create %s: %v", p, err)
	}
	return h
}

func TestMemFSBehavesLikeAFileSystem(t *testing.T) {
	f := newMemFS("/a")
	if err := f.Mkdir("/a/d", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.Mkdir("/a/d", 0o700); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second mkdir: %v, want ErrExist", err)
	}
	h := mustCreate(t, f, "/a/d/x")
	if _, err := f.CreateExcl("/a/d/x", 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second create: %v, want ErrExist", err)
	}
	if _, err := h.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.RenameNoReplace("/a/d/x", "/a/d/y"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadFile("/a/d/x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the old name after a rename: %v", err)
	}
	got, err := f.ReadFile("/a/d/y")
	if err != nil || string(got) != "hello" {
		t.Fatalf("ReadFile: %q, %v", got, err)
	}
	mustCreate(t, f, "/a/d/z")
	if err := f.RenameNoReplace("/a/d/z", "/a/d/y"); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a rename onto an existing name: %v, want ErrExist", err)
	}
	if err := f.RenameNoReplace("/a/d/nope", "/a/d/q"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a rename of a missing file: %v, want ErrNotExist", err)
	}
	if _, err := f.CreateExcl("/a/missing/x", 0o600); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("create in a missing folder: %v, want ErrNotExist", err)
	}
	ents, err := f.ReadDir("/a/d")
	if err != nil || len(ents) != 2 || ents[0].Name() != "y" || ents[1].Name() != "z" {
		t.Fatalf("ReadDir: %v, %v", ents, err)
	}
}

func TestMemFSAllPolicyIsTheLiveTreeAndEveryReplayAgrees(t *testing.T) {
	f := newMemFS("/a")
	_ = f.Mkdir("/a/d", 0o700)
	h := mustCreate(t, f, "/a/d/x")
	_, _ = h.Write([]byte("abc"))
	_ = h.Sync()
	_ = h.Close()
	_ = f.RenameNoReplace("/a/d/x", "/a/d/y")
	_ = f.SyncDir("/a/d")
	h2 := mustCreate(t, f, "/a/d/w")
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

func TestMemFSUnflushedDataMayBeLostFlushedDataIsKept(t *testing.T) {
	f := newMemFS("/a")
	h := mustCreate(t, f, "/a/x")
	_, _ = h.Write(bytes.Repeat([]byte("A"), 100))
	_ = h.Sync()
	_, _ = h.Write(bytes.Repeat([]byte("B"), 100))
	_ = f.SyncDir("/a")
	n := f.opCount()

	got := func(p policy) []byte {
		b, ok := f.CrashAfter(n, p).file("/a/x")
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
	f := newMemFS("/a")
	h := mustCreate(t, f, "/a/x")
	_ = h.Sync() // the data is flushed, the entry is not
	n := f.opCount()
	if _, ok := f.CrashAfter(n, policyFlushed).file("/a/x"); ok {
		t.Fatal("a file whose folder was never flushed survived the flushed-only policy")
	}
	if _, ok := f.CrashAfter(n, policyAll).file("/a/x"); !ok {
		t.Fatal("the all policy lost a created file")
	}
	present, absent := 0, 0
	for s := uint64(1); s <= 40; s++ {
		if _, ok := f.CrashAfter(n, seedPolicy(s)).file("/a/x"); ok {
			present++
		} else {
			absent++
		}
	}
	if present == 0 || absent == 0 {
		t.Fatalf("the seeds gave %d present and %d absent: they do not vary the loss of an entry", present, absent)
	}

	_ = f.SyncDir("/a")
	n = f.opCount()
	for _, p := range policies(12) {
		if _, ok := f.CrashAfter(n, p).file("/a/x"); !ok {
			t.Fatalf("policy %v lost a file whose folder was flushed", p)
		}
	}
}

func TestMemFSAnUnflushedRenameMayBeLostAndKeepsTheOldName(t *testing.T) {
	f := newMemFS("/a")
	h := mustCreate(t, f, "/a/old")
	_, _ = h.Write([]byte("data"))
	_ = h.Sync()
	_ = h.Close()
	_ = f.SyncDir("/a")
	_ = f.RenameNoReplace("/a/old", "/a/new")
	n := f.opCount()
	img := f.CrashAfter(n, policyFlushed)
	if _, ok := img.file("/a/old"); !ok {
		t.Fatal("an unflushed rename took effect under the flushed-only policy")
	}
	if _, ok := img.file("/a/new"); ok {
		t.Fatal("the new name exists under the flushed-only policy")
	}
	img = f.CrashAfter(n, policyAll)
	if _, ok := img.file("/a/old"); ok {
		t.Fatal("the old name survived a rename under the all policy")
	}
	if b, ok := img.file("/a/new"); !ok || string(b) != "data" {
		t.Fatal("the new name is missing under the all policy")
	}
	_ = f.SyncDir("/a")
	img = f.CrashAfter(f.opCount(), policyFlushed)
	if _, ok := img.file("/a/new"); !ok {
		t.Fatal("a rename followed by a folder flush is not durable")
	}
}

func TestMemFSACutIsBeforeTheCallItNames(t *testing.T) {
	f := newMemFS("/a")
	h := mustCreate(t, f, "/a/x")
	_, _ = h.Write([]byte("abc"))
	_ = f.SyncDir("/a")
	if _, ok := f.CrashAfter(0, policyAll).file("/a/x"); ok {
		t.Fatal("a cut after 0 calls shows a file")
	}
	if _, ok := f.CrashAfter(1, policyAll).file("/a/x"); !ok {
		t.Fatal("a cut after the create does not show the file")
	}
	if b, _ := f.CrashAfter(1, policyAll).file("/a/x"); len(b) != 0 {
		t.Fatalf("a cut after the create shows %d bytes", len(b))
	}
	if b, _ := f.CrashAfter(2, policyAll).file("/a/x"); string(b) != "abc" {
		t.Fatalf("a cut after the write shows %q", b)
	}
}

func TestMemFSInjectionAndShortWrite(t *testing.T) {
	boom := errors.New("boom")
	f := newMemFS("/a")
	f.failAt, f.failErr = 2, boom
	h := mustCreate(t, f, "/a/x")
	if n, err := h.Write([]byte("abc")); n != 0 || !errors.Is(err, boom) {
		t.Fatalf("the injected write returned %d, %v", n, err)
	}
	if got := f.CrashAfter(f.opCount(), policyAll); len(mustFile(t, got, "/a/x")) != 0 {
		t.Fatal("a failed write had an effect")
	}

	g := newMemFS("/a")
	g.shortAt = 2
	h = mustCreate(t, g, "/a/x")
	n, err := h.Write([]byte("abcd"))
	if n != 2 || err != nil {
		t.Fatalf("the short write returned %d, %v, want 2, nil", n, err)
	}
	if got := mustFile(t, g.CrashAfter(g.opCount(), policyAll), "/a/x"); string(got) != "ab" {
		t.Fatalf("a short write left %q", got)
	}
}

func mustFile(t *testing.T, img *image, p string) []byte {
	t.Helper()
	b, ok := img.file(p)
	if !ok {
		t.Fatalf("%s is not in the image (have %v)", p, img.paths())
	}
	return b
}
