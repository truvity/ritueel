//go:build linux || darwin

package fsx_test

// Symbolic links and FIFOs on the real file system: below the root no link is followed, in any
// element of a path and at the final name, for any operation, a write or a read; and nothing is
// ever created or read outside the root. Each case has an outside folder with a file in it, and
// looks at the outside folder after the call.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
)

// world is a temporary folder with a root, where the writer works, and an outside folder, which it
// must never touch.
type world struct {
	t       *testing.T
	base    string
	root    string
	outside string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	base := t.TempDir()
	wd := &world{t: t, base: base, root: filepath.Join(base, "root"), outside: filepath.Join(base, "outside")}
	for _, d := range []string{wd.root, wd.outside, filepath.Join(wd.outside, "sub")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for p, c := range map[string]string{"secret": "secret\n", "sub/inner": "inner\n"} {
		if err := os.WriteFile(filepath.Join(wd.outside, p), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return wd
}

func (wd *world) mkdir(rel string) {
	wd.t.Helper()
	if err := os.MkdirAll(filepath.Join(wd.root, rel), 0o700); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) symlink(target, rel string) {
	wd.t.Helper()
	if err := os.Symlink(target, filepath.Join(wd.root, rel)); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) mkfifo(rel string) {
	wd.t.Helper()
	if err := syscall.Mkfifo(filepath.Join(wd.root, rel), 0o600); err != nil {
		wd.t.Fatal(err)
	}
}

func (wd *world) open() *fsx.Writer {
	wd.t.Helper()
	w, err := fsx.Open(wd.root)
	if err != nil {
		wd.t.Fatal(err)
	}
	// closed in the background: a call that hangs (a FIFO opened without care) holds the lock that
	// Close waits for, and the test must fail by its deadline and not wait for that call
	wd.t.Cleanup(func() { go func() { _ = w.Close() }() })
	return w
}

// snapshot is every path below dir with its type and, for a file, its content, as one list.
func snapshot(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		line := rel + " " + d.Type().String()
		switch {
		case d.Type().IsRegular():
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += " " + string(b)
		case d.Type()&fs.ModeSymlink != 0:
			tgt, _ := os.Readlink(p)
			line += " -> " + tgt
		}
		out = append(out, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (wd *world) requireOutsideUntouched(before []string) {
	wd.t.Helper()
	if got := snapshot(wd.t, wd.outside); !slices.Equal(got, before) {
		wd.t.Fatalf("the folder outside the root changed:\n  before %q\n  after  %q", before, got)
	}
}

// targetNames are the places a link can point at: a folder outside, a file outside, a folder
// inside the root, a dangling one, an absolute one and one that climbs out with "..".
var targetNames = []string{
	"a folder outside, relative",
	"a folder outside, absolute",
	"a file outside",
	"a folder inside the root",
	"a dangling link",
	"the folder outside by a climb",
}

func (wd *world) target(name string) string {
	switch name {
	case "a folder outside, relative":
		return filepath.Join("..", "outside")
	case "a folder outside, absolute":
		return wd.outside
	case "a file outside":
		return filepath.Join("..", "outside", "secret")
	case "a folder inside the root":
		return "real"
	case "a dangling link":
		return filepath.Join("..", "outside", "nothing-here")
	case "the folder outside by a climb":
		return filepath.Join("..", "..", filepath.Base(wd.base), "outside")
	}
	panic("no target " + name)
}

func TestOSALinkInAFolderElementIsNeverFollowed(t *testing.T) {
	elems := []string{"x", "y", "z"}
	for _, m := range linkMethods {
		for at := range elems {
			for _, tname := range targetNames {
				t.Run(m.name+"/link at "+elems[at]+"/"+tname, func(t *testing.T) {
					wd := newWorld(t)
					wd.mkdir("real")
					dir := ""
					for i := 0; i < at; i++ {
						dir += elems[i]
						wd.mkdir(dir)
						dir += "/"
					}
					wd.symlink(wd.target(tname), dir+elems[at])
					beforeOut := snapshot(t, wd.outside)
					beforeRoot := snapshot(t, wd.root)
					w := wd.open()
					root := openFSIn(t, wd.root)
					err := m.do(t, w, root, "x/y/z/f")
					fe := asError(t, err)
					wantPath := strings.Join(elems[:at+1], "/")
					if fe.Step != fsx.StepOpenDir || fe.Path != wantPath || !errors.Is(err, fsx.ErrLink) {
						t.Fatalf("got %v, want an open-dir error at %q that wraps ErrLink", err, wantPath)
					}
					if errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("got %v: a link is not 'not found'", err)
					}
					if m.write {
						_ = requireFailed(t, err)
						requireStoppedBy(t, w.Mkdir("other", 0o700), fe)
					}
					wd.requireOutsideUntouched(beforeOut)
					if got := snapshot(t, wd.root); !slices.Equal(got, beforeRoot) {
						t.Fatalf("the root changed:\n  before %q\n  after  %q", beforeRoot, got)
					}
				})
			}
		}
	}
}

// TestOSALinkAtAFinalNameIsATakenNameForAWrite: a link (a dangling one too, one that points
// outside), a FIFO, a folder or a file at the name of a write: the name is taken, the error is
// that of an existing name, and nothing behind the link was made, written or opened. A FIFO is
// never opened (the open would wait for a reader), so no call blocks.
func TestOSALinkAtAFinalNameIsATakenNameForAWrite(t *testing.T) {
	// each kind is made at the path rel of the root
	kinds := []struct {
		name  string
		setup func(wd *world, rel string)
	}{
		{"a link to a file outside", func(wd *world, rel string) { wd.symlink(wd.up(rel, "secret"), rel) }},
		{"a link to a folder outside", func(wd *world, rel string) { wd.symlink(wd.up(rel, ""), rel) }},
		{"a dangling link that points outside", func(wd *world, rel string) { wd.symlink(wd.up(rel, "new"), rel) }},
		{"a dangling absolute link", func(wd *world, rel string) { wd.symlink(filepath.Join(wd.outside, "new"), rel) }},
		{"a link to itself", func(wd *world, rel string) { wd.symlink(filepath.Base(rel), rel) }},
		{"a FIFO", func(wd *world, rel string) { wd.mkfifo(rel) }},
		{"a folder", func(wd *world, rel string) { wd.mkdir(rel) }},
	}
	calls := []struct {
		name string
		rel  string // where the name stands
		do   func(w *fsx.Writer) error
		step fsx.Step
	}{
		{"WriteFile", "name", func(w *fsx.Writer) error { return w.WriteFile("name", []byte("new"), 0o600) }, fsx.StepRename},
		{"WriteFile in a folder", "d/name", func(w *fsx.Writer) error { return w.WriteFile("d/name", []byte("new"), 0o600) }, fsx.StepRename},
		{"WriteSet", "name", func(w *fsx.Writer) error {
			return w.WriteSet("name", []fsx.NewFile{{Name: "a", Data: []byte("new"), Perm: 0o600}})
		}, fsx.StepRename},
		{"Mkdir", "name", func(w *fsx.Writer) error { return w.Mkdir("name", 0o700) }, fsx.StepMkdir},
		{"CreateJournal", "name", func(w *fsx.Writer) error {
			j, err := w.CreateJournal("name")
			if j != nil {
				t.Error("a journal came back with an error")
			}
			return err
		}, fsx.StepCreate},
	}
	for _, k := range kinds {
		for _, c := range calls {
			t.Run(c.name+"/"+k.name, func(t *testing.T) {
				wd := newWorld(t)
				wd.mkdir("d")
				k.setup(wd, c.rel)
				beforeOut := snapshot(t, wd.outside)
				w := wd.open()
				done := make(chan error, 1)
				go func() { done <- c.do(w) }()
				var err error
				select {
				case err = <-done:
				case <-time.After(10 * time.Second):
					t.Fatal("the call did not return: it waited on a FIFO or followed a link")
				}
				fe := requireFailed(t, err)
				if !errors.Is(err, fs.ErrExist) || errors.Is(err, fsx.ErrLink) {
					t.Fatalf("got %v, want an error that wraps fs.ErrExist and not ErrLink", err)
				}
				if fe.Step != c.step {
					t.Fatalf("got %v, want the step %s", err, c.step)
				}
				if _, err := os.Lstat(filepath.Join(wd.outside, "new")); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("a file was made behind the link: %v", err)
				}
				wd.requireOutsideUntouched(beforeOut)
			})
		}
	}
}

// up is the relative path from the folder of rel to a name in the outside folder.
func (wd *world) up(rel, name string) string {
	return filepath.Join(strings.Repeat("../", strings.Count(rel, "/")+1), "outside", name)
}

// TestOSTheRootItselfIsALink: Open of a path whose last element is a link is refused, with or
// without a trailing slash, and the folder behind it is not touched. A link in an earlier
// element is the caller's own path and is followed.
func TestOSTheRootItselfIsALink(t *testing.T) {
	wd := newWorld(t)
	link := filepath.Join(wd.base, "rootlink")
	if err := os.Symlink(wd.outside, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(wd.base, "dangling")
	if err := os.Symlink(filepath.Join(wd.base, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, wd.outside)
	for _, p := range []string{link, link + "/", link + "//", dangling, dangling + "/"} {
		w, err := fsx.Open(p)
		if err == nil {
			_ = w.Close()
			t.Fatalf("Open(%q) followed the link", p)
		}
		if !errors.Is(err, fsx.ErrLink) {
			t.Errorf("Open(%q) = %v, want an error that wraps ErrLink", p, err)
		}
		fsys, err := fsx.OpenFS(p)
		if err == nil {
			_ = fsys.Close()
			t.Fatalf("OpenFS(%q) followed the link", p)
		}
		if !errors.Is(err, fsx.ErrLink) {
			t.Errorf("OpenFS(%q) = %v, want an error that wraps ErrLink", p, err)
		}
	}
	wd.requireOutsideUntouched(before)

	// a link in an earlier element is followed, as the caller wrote the path
	parent := filepath.Join(wd.base, "parentlink")
	if err := os.Symlink(wd.root, parent); err != nil {
		t.Fatal(err)
	}
	w, err := fsx.Open(parent + "/")
	if err == nil {
		_ = w.Close()
		t.Fatal("a root that is a link with a trailing slash was opened")
	}
	if err := os.Mkdir(filepath.Join(wd.root, "inner"), 0o700); err != nil {
		t.Fatal(err)
	}
	w, err = fsx.Open(filepath.Join(parent, "inner") + "/")
	if err != nil {
		t.Fatalf("a root below a link in an earlier element: %v", err)
	}
	defer func() { _ = w.Close() }()
	if err := w.WriteFile("f", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(wd.root, "inner", "f")); string(got) != "x" {
		t.Fatalf("holds %q", got)
	}
}

func TestOSOpenRefusesWhatIsNotAFolder(t *testing.T) {
	wd := newWorld(t)
	for _, c := range []struct {
		name string
		path string
		is   error
		not  error
	}{
		{"empty", "", fsx.ErrInvalid, nil},
		{"missing", filepath.Join(wd.base, "missing"), fs.ErrNotExist, fsx.ErrLink},
		{"a file", filepath.Join(wd.outside, "secret"), nil, fsx.ErrLink},
		{"a file with a trailing slash", filepath.Join(wd.outside, "secret") + "/", nil, fsx.ErrLink},
	} {
		w, err := fsx.Open(c.path)
		if err == nil {
			_ = w.Close()
			t.Errorf("%s: Open(%q) succeeded", c.name, c.path)
			continue
		}
		if c.is != nil && !errors.Is(err, c.is) {
			t.Errorf("%s: %v, want %v", c.name, err, c.is)
		}
		if c.not != nil && errors.Is(err, c.not) {
			t.Errorf("%s: %v must not be %v", c.name, err, c.not)
		}
	}
	// the root "/" itself and a root with trailing slashes are folders
	for _, p := range []string{wd.root + "/", wd.root + "//", "/"} {
		w, err := fsx.Open(p)
		if err != nil {
			t.Errorf("Open(%q): %v", p, err)
			continue
		}
		_ = w.Close()
	}
}

// TestOSNothingIsEverMadeOrReadOutsideTheRoot: the paths that name a place outside: an absolute
// path, "..", a backslash, an empty element, a link; every method, and then the outside folder.
func TestOSNothingIsEverMadeOrReadOutsideTheRoot(t *testing.T) {
	wd := newWorld(t)
	wd.symlink(filepath.Join("..", "outside"), "out")
	before := snapshot(t, wd.outside)
	beforeRoot := snapshot(t, wd.root)
	w := wd.open()
	root := openFSIn(t, wd.root)
	paths := []string{
		filepath.Join(wd.outside, "new"), wd.outside + "/sub/new", "/etc/passwd-new",
		"../outside/new", "..", "../outside", "a/../../outside/new", "./../outside/new",
		`..\outside\new`, `..\\outside\new`, `\outside\new`, `sub\..\..\outside\new`,
		"out/new", "out/sub/new", "out", "out/",
	}
	for _, p := range paths {
		for _, m := range linkMethods {
			err := m.do(t, w, root, p)
			if err == nil {
				t.Errorf("%s(%q) succeeded", m.name, p)
			}
			if m.write && err != nil && !errors.Is(err, fsx.ErrInvalid) && !errors.Is(err, fsx.ErrStopped) {
				// "out/new" and "out": the first writes meet the link; the writer then stops
				if !errors.Is(err, fsx.ErrLink) && !errors.Is(err, fs.ErrExist) {
					t.Errorf("%s(%q) = %v", m.name, p, err)
				}
			}
		}
	}
	wd.requireOutsideUntouched(before)
	if got := snapshot(t, wd.root); !slices.Equal(got, beforeRoot) {
		t.Fatalf("the root changed:\n  before %q\n  after  %q", beforeRoot, got)
	}
}

// TestOSALinkAtAJournalPathOrAFinalNameIsNeverReadThrough: the reads of a link, of a dangling link
// and of a link to a file outside never return what stands behind them.
func TestOSReadsNeverGoThroughALink(t *testing.T) {
	wd := newWorld(t)
	wd.mkdir("d")
	wd.symlink(filepath.Join("..", "outside", "secret"), "d/link")
	wd.symlink(filepath.Join("..", "..", "outside", "secret"), "d/link2")
	wd.symlink(filepath.Join("..", "outside", "nothing"), "d/dangling")
	wd.symlink(filepath.Join("..", "outside"), "d/dirlink")
	wd.symlink("..", "d/up")
	wd.mkfifo("d/pipe")
	wd.mkdir("d/sub")
	if err := os.WriteFile(filepath.Join(wd.root, "d/regular"), []byte("one\ntwo"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, wd.outside)
	root := openFSIn(t, wd.root)
	run := func(name string, f func() error) error {
		done := make(chan error, 1)
		go func() { done <- f() }()
		select {
		case err := <-done:
			return err
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not return", name)
			return nil
		}
	}
	for _, name := range []string{"link", "link2", "dangling", "dirlink", "up"} {
		for what, f := range map[string]func() error{
			"ReadFile": func() error { b, err := fsx.ReadFile(root, "d/"+name); return withData(b, err) },
			"ReadJournal": func() error {
				l, p, err := fsx.ReadJournal(root, "d/"+name)
				return withData(slices.Concat(p, slices.Concat(l...)), err)
			},
		} {
			err := run(what+" "+name, f)
			if !errors.Is(err, fsx.ErrLink) {
				t.Errorf("%s of the link %s: %v, want ErrLink", what, name, err)
			}
			if errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%s of the link %s: %v is not 'not found'", what, name, err)
			}
			fe := asError(t, err)
			if fe.Step != fsx.StepRead || fe.Path != "d/"+name {
				t.Errorf("%s of the link %s: %v, want a read error at d/%s", what, name, err, name)
			}
		}
		// the folder reads: the link is not a folder to enter
		err := run("ReadDir "+name, func() error { _, err := fsx.ReadDir(root, "d/"+name); return err })
		fe := asError(t, err)
		if !errors.Is(err, fsx.ErrLink) || fe.Step != fsx.StepOpenDir || fe.Path != "d/"+name {
			t.Errorf("ReadDir of the link %s: %v, want an open-dir error at d/%s that wraps ErrLink", name, err, name)
		}
		// and a read through it as a folder
		err = run("ReadFile through "+name, func() error { _, err := fsx.ReadFile(root, "d/"+name+"/secret"); return err })
		if !errors.Is(err, fsx.ErrLink) {
			t.Errorf("ReadFile through the link %s: %v, want ErrLink", name, err)
		}
	}
	// a FIFO: not a regular file, and not waited on
	err := run("ReadFile of a FIFO", func() error { _, err := fsx.ReadFile(root, "d/pipe"); return err })
	if !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("ReadFile of a FIFO: %v, want ErrNotRegular", err)
	}
	err = run("ReadJournal of a FIFO", func() error { _, _, err := fsx.ReadJournal(root, "d/pipe"); return err })
	if !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("ReadJournal of a FIFO: %v, want ErrNotRegular", err)
	}
	err = run("ReadDir of a FIFO", func() error { _, err := fsx.ReadDir(root, "d/pipe"); return err })
	if err == nil || errors.Is(err, fsx.ErrLink) {
		t.Errorf("ReadDir of a FIFO: %v", err)
	}
	// the folder and the regular file
	if err := run("ReadFile of a folder", func() error { _, err := fsx.ReadFile(root, "d/sub"); return err }); !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("ReadFile of a folder: %v, want ErrNotRegular", err)
	}
	if err := run("ReadFile of a missing name", func() error { _, err := fsx.ReadFile(root, "d/none"); return err }); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile of a missing name: %v, want ErrNotExist", err)
	}
	lines, partial, err := fsx.ReadJournal(root, "d/regular")
	if err != nil || len(lines) != 1 || string(lines[0]) != "one" || string(partial) != "two" {
		t.Errorf("ReadJournal of a regular file: %q, %q, %v", lines, partial, err)
	}
	// ReadDir lists a link and a FIFO as what they are
	ents, err := fsx.ReadDir(root, "d")
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]fs.FileMode{}
	for _, e := range ents {
		types[e.Name()] = e.Type()
	}
	for name, want := range map[string]fs.FileMode{
		"link": fs.ModeSymlink, "dangling": fs.ModeSymlink, "dirlink": fs.ModeSymlink, "up": fs.ModeSymlink,
		"pipe": fs.ModeNamedPipe, "sub": fs.ModeDir, "regular": 0,
	} {
		if types[name] != want {
			t.Errorf("ReadDir lists %s as %v, want %v", name, types[name], want)
		}
	}
	wd.requireOutsideUntouched(before)
}

// withData turns "data and an error" into the error, and fails a read that gave data with an error.
func withData(data []byte, err error) error {
	if err != nil && len(data) != 0 {
		return errors.New("data came back with an error")
	}
	return err
}
