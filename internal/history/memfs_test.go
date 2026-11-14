//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// A folder of a bundle in memory, as an fsx.FS, for what a real file system cannot hold or what
// is too slow to make on disk: a name of 256 bytes, 65,537 entries in a folder, a read that fails
// with a refused permission. It is read only: every call that changes something fails.

type mnode struct {
	kind    string // "dir", "file", "link", "fifo"
	data    []byte
	long    bool // a file longer than fsx.MaxReadSize
	kids    map[string]*mnode
	readErr error // what ReadFile, ReadDir and OpenDir of this node fail with
}

type memFS struct{ n *mnode }

func newMem() *mnode { return &mnode{kind: "dir", kids: map[string]*mnode{}} }

// loadMem reads a bundle from disk into memory.
func loadMem(t testing.TB, dir string) *mnode {
	t.Helper()
	root := newMem()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if rel == "." {
			return nil
		}
		switch {
		case d.IsDir():
			root.put(filepath.ToSlash(rel), &mnode{kind: "dir", kids: map[string]*mnode{}})
		case d.Type().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			root.put(filepath.ToSlash(rel), &mnode{kind: "file", data: data})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// put places a node at a "/" separated path, making the folders on the way.
func (m *mnode) put(p string, n *mnode) {
	elems := strings.Split(p, "/")
	cur := m
	for _, e := range elems[:len(elems)-1] {
		next, ok := cur.kids[e]
		if !ok {
			next = &mnode{kind: "dir", kids: map[string]*mnode{}}
			cur.kids[e] = next
		}
		cur = next
	}
	cur.kids[elems[len(elems)-1]] = n
}

func (m *mnode) file(p string, data string) { m.put(p, &mnode{kind: "file", data: []byte(data)}) }

func (m *mnode) get(p string) *mnode {
	cur := m
	for _, e := range strings.Split(p, "/") {
		cur = cur.kids[e]
		if cur == nil {
			return nil
		}
	}
	return cur
}

func (m *mnode) remove(p string) {
	elems := strings.Split(p, "/")
	parent := m
	if len(elems) > 1 {
		parent = m.get(strings.Join(elems[:len(elems)-1], "/"))
	}
	delete(parent.kids, elems[len(elems)-1])
}

var errRead = errors.New("the memory file system is read only")

func (f memFS) OpenDir(name string) (fsx.FS, error) {
	k, ok := f.n.kids[name]
	switch {
	case !ok:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	case k.readErr != nil:
		return nil, k.readErr
	case k.kind == "link":
		return nil, fmt.Errorf("%w: %s", fsx.ErrLink, name)
	case k.kind != "dir":
		return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.ENOTDIR}
	}
	return memFS{k}, nil
}

func (f memFS) ReadFile(name string) ([]byte, error) {
	k, ok := f.n.kids[name]
	switch {
	case !ok:
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	case k.readErr != nil:
		return nil, k.readErr
	case k.kind == "link":
		return nil, fmt.Errorf("%w: %s", fsx.ErrLink, name)
	case k.kind != "file":
		return nil, fmt.Errorf("%w: %s", fsx.ErrNotRegular, name)
	case k.long:
		return nil, fmt.Errorf("%w: %s", fsx.ErrTooLarge, name)
	}
	return slices.Clone(k.data), nil
}

type ment struct {
	name string
	kind string
}

func (e ment) Name() string { return e.name }
func (e ment) IsDir() bool  { return e.kind == "dir" }
func (e ment) Type() fs.FileMode {
	switch e.kind {
	case "dir":
		return fs.ModeDir
	case "link":
		return fs.ModeSymlink
	case "fifo":
		return fs.ModeNamedPipe
	}
	return 0
}
func (e ment) Info() (fs.FileInfo, error) { return nil, errors.New("no info") }

func (f memFS) ReadDir() ([]fs.DirEntry, error) {
	if f.n.readErr != nil {
		return nil, f.n.readErr
	}
	if len(f.n.kids) > fsx.MaxDirEntries {
		return nil, fmt.Errorf("%w: %d names", fsx.ErrTooMany, len(f.n.kids))
	}
	names := make([]string, 0, len(f.n.kids))
	for n := range f.n.kids {
		names = append(names, n)
	}
	slices.Sort(names)
	out := make([]fs.DirEntry, 0, len(names))
	for _, n := range names {
		out = append(out, ment{n, f.n.kids[n].kind})
	}
	return out, nil
}

func (f memFS) Mkdir(string, fs.FileMode) error                  { return errRead }
func (f memFS) CreateExcl(string, fs.FileMode) (fsx.File, error) { return nil, errRead }
func (f memFS) RenameNoReplace(string, string) error             { return errRead }
func (f memFS) Sync() error                                      { return errRead }
func (f memFS) Close() error                                     { return nil }

func runMem(t testing.TB, m *mnode) (*Report, error) {
	t.Helper()
	return runFS(t, memFS{m}, nil)
}

// The memory file system itself, so that a result below is the check's and not the model's.
func TestMemoryFileSystemTellsTheSameAsTheDisk(t *testing.T) {
	b, _ := threeRecords(t)
	disk := b.run()
	mem, err := runMem(t, loadMem(t, b.dir))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(mem.Findings, mem.Records, mem.Ends), fmt.Sprint(disk.Findings, disk.Records, disk.Ends); got != want {
		t.Errorf("memory: %s\n disk: %s", got, want)
	}
	if mem.Records != 3 {
		t.Errorf("Records = %d", mem.Records)
	}
}
