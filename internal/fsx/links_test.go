package fsx_test

// Symbolic links, FIFOs and the other names that are not plain files and folders, on the model: a
// link in the first, a middle and the last folder element of a path, for every method that takes
// a path; a link, a dangling link and a FIFO at a final name and at a journal path; and the
// reads. The model follows no link and says so with fsx.ErrLink (see memfs_test.go), so these
// tests prove what the package does with such an answer: which step it names, which path, that
// it stops, that it opens no more handle, and that it makes no call that creates or reads
// anything. The same cases on the real file system, with an outside folder to look at, are in
// os_links_test.go.

import (
	"errors"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
)

// linkMethod is one call that takes a path.
type linkMethod struct {
	name  string
	write bool
	do    func(t *testing.T, w *fsx.Writer, root fsx.FS, p string) error
}

var linkMethods = []linkMethod{
	{"WriteFile", true, func(_ *testing.T, w *fsx.Writer, _ fsx.FS, p string) error {
		return w.WriteFile(p, []byte("x"), 0o600)
	}},
	{"WriteSet", true, func(_ *testing.T, w *fsx.Writer, _ fsx.FS, p string) error {
		return w.WriteSet(p, []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
	}},
	{"Mkdir", true, func(_ *testing.T, w *fsx.Writer, _ fsx.FS, p string) error {
		return w.Mkdir(p, 0o700)
	}},
	{"CreateJournal", true, func(t *testing.T, w *fsx.Writer, _ fsx.FS, p string) error {
		j, err := w.CreateJournal(p)
		if j != nil {
			t.Errorf("CreateJournal returned a journal with an error")
		}
		return err
	}},
	{"ReadFile", false, func(_ *testing.T, _ *fsx.Writer, root fsx.FS, p string) error {
		_, err := fsx.ReadFile(root, p)
		return err
	}},
	{"ReadDir", false, func(_ *testing.T, _ *fsx.Writer, root fsx.FS, p string) error {
		_, err := fsx.ReadDir(root, p)
		return err
	}},
	{"ReadJournal", false, func(_ *testing.T, _ *fsx.Writer, root fsx.FS, p string) error {
		_, _, err := fsx.ReadJournal(root, p)
		return err
	}},
}

func requireNothingMadeOrRead(t *testing.T, f *memFS) {
	t.Helper()
	for _, o := range f.opList() {
		switch o.Kind {
		case kOpenDir, kCloseDir:
		default:
			t.Errorf("a call that creates, writes or reads was made: %v", o)
		}
	}
}

// TestALinkInAFolderElementIsNeverFollowed: the path x/y/z/f with a link at x, at y and at z, for
// every method. The walk stops at the link: the error is at the step open-dir, names the path up
// to and including the link, wraps ErrLink; a write stops the writer; nothing is made or read;
// no handle stays open; the tree is as it was.
func TestALinkInAFolderElementIsNeverFollowed(t *testing.T) {
	elems := []string{"x", "y", "z"}
	for _, m := range linkMethods {
		for at := range elems {
			for _, target := range []string{"../outside", "/etc", "nowhere"} {
				name := m.name + "/link at " + elems[at] + " to " + target
				t.Run(name, func(t *testing.T) {
					f := newMemFS("outside")
					f.addFile("outside/secret", []byte("secret"))
					dir := ""
					for i := 0; i < at; i++ {
						dir += elems[i]
						f.addDir(dir)
						dir += "/"
					}
					f.addLink(dir+elems[at], target)
					before := f.Live().list()
					w := newWriter(t, f, 1)
					root := f.Root()
					defer func() { _ = root.Close() }()
					p := "x/y/z/f"
					err := m.do(t, w, root, p)
					fe := asError(t, err)
					wantPath := ""
					for i := 0; i <= at; i++ {
						if i > 0 {
							wantPath += "/"
						}
						wantPath += elems[i]
					}
					if fe.Step != fsx.StepOpenDir || fe.Path != wantPath {
						t.Fatalf("got %v, want an open-dir error at %q", err, wantPath)
					}
					if !errors.Is(err, fsx.ErrLink) {
						t.Fatalf("got %v, want an error that wraps ErrLink", err)
					}
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("got %v: a link is not 'not found'", err)
					}
					if m.write {
						_ = requireFailed(t, err)
						requireStoppedBy(t, w.Mkdir("other", 0o700), fe)
					}
					requireNothingMadeOrRead(t, f)
					if got := f.Live().list(); !slices.Equal(got, before) {
						t.Fatalf("the tree changed: %v, was %v", got, before)
					}
					if got, _ := f.Live().file("outside/secret"); string(got) != "secret" {
						t.Fatal("what stands behind a link changed")
					}
					// the root of the writer and the root of the reader, and nothing else
					if d, fl := f.handles(); d != 2 || fl != 0 {
						t.Fatalf("%d folders and %d files open (%s), want the two roots", d, fl, f.describeOpen())
					}
				})
			}
		}
	}
}

// TestALinkAtAFinalNameIsATakenNameForAWrite: a link (also a dangling one), a FIFO, a folder or a
// file at the name of a write: the name is taken, the error is the refusal of an existing name at
// the step that makes it (never ErrLink, never a write through the link), nothing at that name
// changed, and the temporary name is left.
func TestALinkAtAFinalNameIsATakenNameForAWrite(t *testing.T) {
	kinds := []struct {
		name  string
		setup func(f *memFS, p string)
	}{
		{"a link to a file", func(f *memFS, p string) { f.addLink(p, "../outside/secret") }},
		{"a link to a folder", func(f *memFS, p string) { f.addLink(p, "../outside") }},
		{"a dangling link", func(f *memFS, p string) { f.addLink(p, "../nowhere") }},
		{"a link to itself", func(f *memFS, p string) { f.addLink(p, "name") }},
		{"a FIFO", func(f *memFS, p string) { f.addFifo(p) }},
		{"a folder", func(f *memFS, p string) { f.addDir(p) }},
		{"a file", func(f *memFS, p string) { f.addFile(p, []byte("old")) }},
	}
	calls := []struct {
		name string
		do   func(w *fsx.Writer, p string) error
		step fsx.Step
	}{
		{"WriteFile", func(w *fsx.Writer, p string) error { return w.WriteFile(p, []byte("new"), 0o600) }, fsx.StepRename},
		{"WriteSet", func(w *fsx.Writer, p string) error {
			return w.WriteSet(p, []fsx.NewFile{{Name: "a", Data: []byte("new"), Perm: 0o600}})
		}, fsx.StepRename},
		{"Mkdir", func(w *fsx.Writer, p string) error { return w.Mkdir(p, 0o700) }, fsx.StepMkdir},
		{"CreateJournal", func(w *fsx.Writer, p string) error { _, err := w.CreateJournal(p); return err }, fsx.StepCreate},
	}
	for _, k := range kinds {
		for _, c := range calls {
			t.Run(c.name+"/"+k.name, func(t *testing.T) {
				f := newMemFS("b", "outside")
				f.addFile("outside/secret", []byte("secret"))
				k.setup(f, "b/name")
				before := f.Live()
				w := newWriter(t, f, 1)
				err := c.do(w, "b/name")
				fe := requireFailed(t, err)
				if fe.Step != c.step || fe.Path != "b/name" || !errors.Is(err, fs.ErrExist) || errors.Is(err, fsx.ErrLink) {
					t.Fatalf("got %v, want %s at b/name wrapping fs.ErrExist and not ErrLink", err, c.step)
				}
				requireStoppedBy(t, w.Mkdir("b/other", 0o700), fe)
				after := f.Live()
				for _, p := range before.list() {
					if p == "b" {
						continue
					}
					if before.nodes[abs(p)].kind != after.nodes[abs(p)].kind || string(before.nodes[abs(p)].data) != string(after.nodes[abs(p)].data) {
						t.Errorf("%s changed", p)
					}
				}
				if got, _ := after.file("outside/secret"); string(got) != "secret" {
					t.Error("what stands behind a link changed")
				}
				// the temporary name is left (nothing is deleted), except where no temporary name was made
				var left int
				for _, p := range after.list() {
					if strings.HasPrefix(p, "b/"+fsx.TempPrefix) && strings.Count(p, "/") == 1 {
						left++
					}
				}
				if c.name != "Mkdir" && c.name != "CreateJournal" && left != 1 {
					t.Errorf("%d temporary names left, want 1: %v", left, after.list())
				}
			})
		}
	}
}

// ---- reads ---------------------------------------------------------------------------------------

// TestReadFileOfEachKindOfName: a regular file, a link, a dangling link, a FIFO, a folder, a
// missing name, a file of exactly MaxReadSize and one of a byte more.
func TestReadFileOfEachKindOfName(t *testing.T) {
	f := newMemFS("b", "b/dir", "outside")
	f.addFile("outside/secret", []byte("secret"))
	f.addFile("b/regular", []byte("data"))
	f.addFile("b/empty", nil)
	f.addLink("b/link", "../outside/secret")
	f.addLink("b/dangling", "../nowhere")
	f.addFifo("b/pipe")
	f.addVirtual("b/exact", fsx.MaxReadSize)
	f.addVirtual("b/over", fsx.MaxReadSize+1)
	f.addVirtual("b/huge", 1<<40)
	root := f.Root()
	defer func() { _ = root.Close() }()

	cases := []struct {
		name string
		is   error // nil: success
		not  []error
		want int // length of the data on success
	}{
		{"regular", nil, nil, 4},
		{"empty", nil, nil, 0},
		{"exact", nil, nil, fsx.MaxReadSize},
		{"link", fsx.ErrLink, []error{fs.ErrNotExist, fsx.ErrNotRegular}, 0},
		{"dangling", fsx.ErrLink, []error{fs.ErrNotExist}, 0},
		{"pipe", fsx.ErrNotRegular, []error{fsx.ErrLink}, 0},
		{"dir", fsx.ErrNotRegular, []error{fsx.ErrLink}, 0},
		{"over", fsx.ErrTooLarge, []error{fsx.ErrNotRegular}, 0},
		{"huge", fsx.ErrTooLarge, nil, 0},
		{"missing", fs.ErrNotExist, []error{fsx.ErrLink}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, read := range []struct {
				name string
				do   func() ([]byte, error)
			}{
				{"ReadFile", func() ([]byte, error) { return fsx.ReadFile(root, "b/"+c.name) }},
				{"ReadJournal", func() ([]byte, error) {
					lines, partial, err := fsx.ReadJournal(root, "b/"+c.name)
					if err != nil {
						return nil, err
					}
					var n int
					for _, l := range lines {
						n += len(l) + 1
					}
					return make([]byte, n+len(partial)), nil
				}},
			} {
				data, err := read.do()
				if c.is == nil {
					if err != nil || len(data) != c.want {
						t.Errorf("%s: %d bytes, %v, want %d bytes", read.name, len(data), err, c.want)
					}
					continue
				}
				if !errors.Is(err, c.is) {
					t.Errorf("%s: %v, want %v", read.name, err, c.is)
				}
				for _, n := range c.not {
					if errors.Is(err, n) {
						t.Errorf("%s: %v must not be %v", read.name, err, n)
					}
				}
				if data != nil {
					t.Errorf("%s: %d bytes came back with an error", read.name, len(data))
				}
				fe := asError(t, err)
				if fe.Step != fsx.StepRead || fe.Path != "b/"+c.name {
					t.Errorf("%s: %v, want a read error at b/%s", read.name, err, c.name)
				}
			}
		})
	}
	for _, v := range f.violationList() {
		t.Error(v)
	}
}

func TestMaxReadSizeIsEightMebibytes(t *testing.T) {
	if fsx.MaxReadSize != 8*1024*1024 {
		t.Fatalf("MaxReadSize is %d, want 8 MiB", fsx.MaxReadSize)
	}
}

// TestReadDirListsLinksAndFifosAsWhatTheyAre: the list says what the folder holds, never what a
// link points at, and the root itself can be listed with ".".
func TestReadDirListsLinksAndFifosAsWhatTheyAre(t *testing.T) {
	f := newMemFS("b", "b/dir", "outside")
	f.addFile("b/regular", []byte("data"))
	f.addLink("b/link", "../outside")
	f.addLink("b/dangling", "../nowhere")
	f.addFifo("b/pipe")
	root := f.Root()
	defer func() { _ = root.Close() }()
	ents, err := fsx.ReadDir(root, "b")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	types := map[string]fs.FileMode{}
	for _, e := range ents {
		got = append(got, e.Name())
		types[e.Name()] = e.Type()
	}
	if want := []string{"dangling", "dir", "link", "pipe", "regular"}; !slices.Equal(got, want) {
		t.Fatalf("ReadDir lists %v, want %v, sorted", got, want)
	}
	for name, want := range map[string]fs.FileMode{"link": fs.ModeSymlink, "dangling": fs.ModeSymlink, "pipe": fs.ModeNamedPipe, "dir": fs.ModeDir, "regular": 0} {
		if types[name] != want {
			t.Errorf("%s is listed as %v, want %v", name, types[name], want)
		}
	}
	rootList, err := fsx.ReadDir(root, ".")
	if err != nil || len(rootList) != 2 || rootList[0].Name() != "b" || rootList[1].Name() != "outside" {
		t.Fatalf("ReadDir of the root: %v, %v", rootList, err)
	}
	// a link, a file and a missing name are not folders to list
	for _, c := range []struct {
		p  string
		is error
	}{{"b/link", fsx.ErrLink}, {"b/dangling", fsx.ErrLink}, {"b/missing", fs.ErrNotExist}} {
		_, err := fsx.ReadDir(root, c.p)
		fe := asError(t, err)
		if !errors.Is(err, c.is) || fe.Step != fsx.StepOpenDir || fe.Path != c.p {
			t.Errorf("ReadDir(%s) = %v, want an open-dir error wrapping %v", c.p, err, c.is)
		}
	}
	for _, p := range []string{"b/regular", "b/pipe"} {
		_, err := fsx.ReadDir(root, p)
		if err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, fsx.ErrLink) {
			t.Errorf("ReadDir(%s) = %v, want an error that is neither not-found nor a link", p, err)
		}
	}
}

// TestAReadMayNameALeftoverTemporaryNameAndAWriteMayNot: the stop that left a temporary folder is
// read by a person or a checker through its name, and nothing writes to such a name.
func TestAReadMayNameALeftoverTemporaryNameAndAWriteMayNot(t *testing.T) {
	f := newMemFS("b", "b/.rt-abcdefghijk", "b/.RT-abcdefghijk")
	f.addFile("b/.rt-file", []byte("left\n"))
	f.addFile("b/.RT-file", []byte("LEFT\n"))
	f.addFile("b/.rt-abcdefghijk/inside", []byte("in\n"))
	root := f.Root()
	defer func() { _ = root.Close() }()
	if got, err := fsx.ReadFile(root, "b/.rt-file"); err != nil || string(got) != "left\n" {
		t.Errorf("ReadFile of a leftover: %q, %v", got, err)
	}
	if got, err := fsx.ReadFile(root, "b/.RT-file"); err != nil || string(got) != "LEFT\n" {
		t.Errorf("ReadFile of a leftover in capitals: %q, %v", got, err)
	}
	if lines, _, err := fsx.ReadJournal(root, "b/.rt-abcdefghijk/inside"); err != nil || len(lines) != 1 {
		t.Errorf("ReadJournal inside a leftover folder: %v, %v", lines, err)
	}
	if ents, err := fsx.ReadDir(root, "b/.rt-abcdefghijk"); err != nil || len(ents) != 1 {
		t.Errorf("ReadDir of a leftover folder: %v, %v", ents, err)
	}
	if ents, err := fsx.ReadDir(root, "b"); err != nil || len(ents) != 4 {
		t.Errorf("ReadDir lists the leftovers: %d entries, %v, want 4 (the skipping is the caller's)", len(ents), err)
	}
	w := newWriter(t, f, 1)
	for _, p := range []string{"b/.rt-file", "b/.RT-new", "b/.Rt-x"} {
		for what, err := range map[string]error{
			"WriteFile": w.WriteFile(p, nil, 0o600),
			"Mkdir":     w.Mkdir(p, 0o700),
			"WriteSet":  w.WriteSet(p, nil),
		} {
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s %s: %v, want ErrInvalid", what, p, err)
			}
		}
		if _, err := w.CreateJournal(p); !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("CreateJournal %s: %v, want ErrInvalid", p, err)
		}
	}
	if err := w.WriteSet("b/s", []fsx.NewFile{{Name: ".rt-x"}}); !errors.Is(err, fsx.ErrInvalid) {
		t.Errorf("a set file with the temporary prefix: %v", err)
	}
	// a write into a leftover folder is refused too: the prefix is refused in every element
	if err := w.WriteFile("b/.rt-abcdefghijk/new", []byte("x"), 0o600); !errors.Is(err, fsx.ErrInvalid) {
		t.Errorf("a write into a folder that has the prefix: %v, want ErrInvalid", err)
	}
}

// TestReadsRefuseWhatTheWritersRefuse: an absolute path, "..", ".", a backslash, an empty
// element, a bad name: ErrInvalid before the file system is touched, from every reader.
func TestReadsRefuseWhatTheWritersRefuse(t *testing.T) {
	f := newMemFS("b", "b/d")
	root := f.Root()
	defer func() { _ = root.Close() }()
	for _, p := range []string{
		"", "/", "/b", "/b/d", "b/../b", "..", "../b", "b/..", "b/d/..", "./b", "b/./d", "b/d/.", "b//d", "b/d/",
		`b\d`, `\b`, `b\..\b`, "C:b", "b/a b", "b/a:b", "b/\xff", "b/é", "b/aux", "b/a.", "b/" + rep("a", 256),
	} {
		_, e1 := fsx.ReadFile(root, p)
		_, e2 := fsx.ReadDir(root, p)
		_, _, e3 := fsx.ReadJournal(root, p)
		for what, err := range map[string]error{"ReadFile": e1, "ReadDir": e2, "ReadJournal": e3} {
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s(%q) = %v, want ErrInvalid", what, p, err)
			}
		}
	}
	if f.opCount() != 0 {
		t.Fatalf("a refused path reached the file system: %v", f.opList())
	}
	// "." is the root, for ReadDir alone
	if _, err := fsx.ReadDir(root, "."); err != nil {
		t.Errorf("ReadDir(.) = %v", err)
	}
	if _, err := fsx.ReadFile(root, "."); !errors.Is(err, fsx.ErrInvalid) {
		t.Errorf("ReadFile(.) = %v, want ErrInvalid", err)
	}
}

// TestReadsAndTheHandlesTheyOpen: a read closes every folder it opened, on success and on every
// error, and never the root that it was given.
func TestReadsAndTheHandlesTheyOpen(t *testing.T) {
	f := newMemFS("b", "b/d")
	f.addFile("b/d/f", []byte("x\n"))
	f.addLink("b/d/l", "f")
	root := f.Root()
	defer func() { _ = root.Close() }()
	for _, c := range []struct {
		name string
		do   func() error
		ok   bool
	}{
		{"ReadFile", func() error { _, err := fsx.ReadFile(root, "b/d/f"); return err }, true},
		{"ReadFile of a link", func() error { _, err := fsx.ReadFile(root, "b/d/l"); return err }, false},
		{"ReadFile of a missing file", func() error { _, err := fsx.ReadFile(root, "b/d/none"); return err }, false},
		{"ReadFile through a missing folder", func() error { _, err := fsx.ReadFile(root, "b/none/f"); return err }, false},
		{"ReadFile through a file", func() error { _, err := fsx.ReadFile(root, "b/d/f/x"); return err }, false},
		{"ReadDir", func() error { _, err := fsx.ReadDir(root, "b/d"); return err }, true},
		{"ReadDir of the root", func() error { _, err := fsx.ReadDir(root, "."); return err }, true},
		{"ReadDir of a link", func() error { _, err := fsx.ReadDir(root, "b/d/l"); return err }, false},
		{"ReadJournal", func() error { _, _, err := fsx.ReadJournal(root, "b/d/f"); return err }, true},
		{"ReadJournal of a link", func() error { _, _, err := fsx.ReadJournal(root, "b/d/l"); return err }, false},
	} {
		err := c.do()
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if d, fl := f.handles(); d != 1 || fl != 0 {
			t.Errorf("%s: %d folders and %d files open (%s), want the root alone", c.name, d, fl, f.describeOpen())
		}
	}
	// and an error injected at every call of a read: the handles are closed all the same
	boom := errors.New("boom")
	for n := 1; n <= 8; n++ {
		g := newMemFS("b", "b/d")
		g.addFile("b/d/f", []byte("x\n"))
		r := g.Root()
		g.failAt, g.failErr = n, boom
		_, err := fsx.ReadFile(r, "b/d/f")
		if d, fl := g.handles(); d != 1 || fl != 0 {
			t.Errorf("a failure at call %d (%v): %d folders and %d files open (%s)", n, err, d, fl, g.describeOpen())
		}
		_ = r.Close()
	}
}

// TestAFifoIsNotWaitedOnByARead: the model never blocks, so this is the check of the caller's
// side: ReadFile of a FIFO returns at once with ErrNotRegular. The real FIFO, which blocks if the
// open is wrong, is in os_read_test.go.
func TestAFifoIsNotWaitedOnByARead(t *testing.T) {
	f := newMemFS("b")
	f.addFifo("b/pipe")
	root := f.Root()
	defer func() { _ = root.Close() }()
	done := make(chan error, 1)
	go func() { _, err := fsx.ReadFile(root, "b/pipe"); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, fsx.ErrNotRegular) {
			t.Fatalf("got %v, want ErrNotRegular", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadFile of a FIFO did not return")
	}
}
