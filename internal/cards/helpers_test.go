package cards_test

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/fsx"
)

// The card files of the tests. Each is accepted by its reader. The serials are made-up values.

const (
	cardRootA = `# root-a
version: 1
serial: "10000001"
kind: root
applications: [piv, fido2]
other_rows: [3]
`
	cardRootB = `# root-b
version: 1
serial: "10000002"
kind: root
applications: [piv, fido2]
`
	cardDayOne = `# day-one
version: 1
serial: "10000003"
kind: day-to-day
applications: [openpgp, fido2]
`
	cardServerOne = `# server-one
version: 1
serial: "10000004"
kind: server
applications: [piv]
`
	cardPracticeOne = `# practice-one
version: 1
serial: "10000005"
kind: rehearsal
applications: [piv]
`
)

// goodNames are the names of the good set in the order that Inspect returns the cards in.
var goodNames = []string{"day-one", "practice-one", "root-a", "root-b", "server-one"}

// cardFile is the path of the card file of a name.
func cardFile(name string) string { return "want/cards/" + name + ".yaml" }

// goodSet is the five good files of the set, by path.
func goodSet() map[string]string {
	return map[string]string{
		cardFile("root-a"):       cardRootA,
		cardFile("root-b"):       cardRootB,
		cardFile("day-one"):      cardDayOne,
		cardFile("server-one"):   cardServerOne,
		cardFile("practice-one"): cardPracticeOne,
	}
}

// with returns a copy of files with the given paths set (an empty text is a file with no bytes).
func with(files map[string]string, more map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range files {
		out[k] = v
	}
	for k, v := range more {
		out[k] = v
	}
	return out
}

// cardText makes a good card file of one serial and one kind.
func cardText(serial, kind string) string {
	apps := "[piv]"
	if kind == "day-to-day" {
		apps = "[openpgp, fido2]"
	}
	return fmt.Sprintf("version: 1\nserial: %q\nkind: %s\napplications: %s\n", serial, kind, apps)
}

// numbered makes n good card files c0000, c0001, ... with their own serials.
func numbered(n int) map[string]string {
	files := map[string]string{}
	for i := range n {
		files[fmt.Sprintf("want/cards/c%04d.yaml", i)] = cardText(fmt.Sprint(i+1), "server")
	}
	return files
}

// printable reports whether s holds only printable ASCII and no line break.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// paths returns the Path of each finding.
func paths(list []cards.Finding) []string {
	out := make([]string, len(list))
	for i, f := range list {
		out[i] = f.Path
	}
	return out
}

// names returns the names of the cards of a report.
func names(r *cards.Report) []string {
	out := make([]string, len(r.Cards))
	for i, c := range r.Cards {
		out[i] = c.Name
	}
	return out
}

// mustInspect runs Inspect and fails the test when it gives an error or a report that is not valid.
func mustInspect(t testing.TB, fsys fsx.FS) *cards.Report {
	t.Helper()
	rep, err := cards.Inspect(t.Context(), fsys)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !rep.Valid() {
		t.Fatal("Inspect returned a report that is not valid")
	}
	return rep
}

// A bundle folder in memory, as an fsx.FS that can be read and never changed. It is for what a real
// file system cannot hold or what is too slow to make on disk (a name with a control code, a file that
// fails on a read, a probe that counts), and for the fuzz targets.

// node is one entry of a memory bundle.
type node struct {
	kind string // "dir", "file", "link", "fifo"
	data []byte
	long bool  // a file longer than fsx.MaxReadSize
	err  error // what a read of this entry returns, in place of its content
	kids map[string]*node
}

func newDir() *node { return &node{kind: "dir", kids: map[string]*node{}} }

// put sets the entry at path, making the folders above it.
func (n *node) put(path string, e *node) {
	elems := strings.Split(path, "/")
	cur := n
	for _, el := range elems[:len(elems)-1] {
		next, ok := cur.kids[el]
		if !ok || next.kind != "dir" {
			next = newDir()
			cur.kids[el] = next
		}
		cur = next
	}
	cur.kids[elems[len(elems)-1]] = e
}

// memBundle makes a memory bundle from a map of paths to text.
func memBundle(files map[string]string) *node {
	root := newDir()
	for p, text := range files {
		root.put(p, &node{kind: "file", data: []byte(text)})
	}
	return root
}

// probe records what is done to a memory bundle, in order.
type probe struct {
	opened []string // every folder opened, by its path from the root
	listed []string // every folder listed
	read   []string // every file read
	// onRead is called before a file is read; the error it returns is the error of the read.
	onRead func(path string) error
	// onList is called before a folder is listed.
	onList func(path string)
}

func (p *probe) count(list []string, path string) int {
	n := 0
	for _, x := range list {
		if x == path {
			n++
		}
	}
	return n
}

// readsUnder is the number of files read below the folder dir.
func (p *probe) readsUnder(dir string) int {
	n := 0
	for _, x := range p.read {
		if strings.HasPrefix(x, dir+"/") {
			n++
		}
	}
	return n
}

// memFS is a folder of a memory bundle.
type memFS struct {
	n      *node
	path   string
	p      *probe
	closed *bool
}

// open opens the root of a memory bundle. The probe may be nil.
func (n *node) open(p *probe) fsx.FS {
	if p == nil {
		p = &probe{}
	}
	return &memFS{n: n, p: p, closed: new(bool)}
}

func (f *memFS) join(name string) string {
	if f.path == "" {
		return name
	}
	return f.path + "/" + name
}

func (f *memFS) OpenDir(name string) (fsx.FS, error) {
	if *f.closed {
		return nil, fs.ErrClosed
	}
	f.p.opened = append(f.p.opened, f.join(name))
	k, ok := f.n.kids[name]
	switch {
	case !ok:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	case k.err != nil:
		return nil, k.err
	case k.kind == "link":
		return nil, fmt.Errorf("%w: %s", fsx.ErrLink, name)
	case k.kind != "dir":
		return nil, &fs.PathError{Op: "open", Path: name, Err: syscall.ENOTDIR}
	}
	return &memFS{n: k, path: f.join(name), p: f.p, closed: f.closed}, nil
}

func (f *memFS) ReadFile(name string) ([]byte, error) {
	if *f.closed {
		return nil, fs.ErrClosed
	}
	full := f.join(name)
	f.p.read = append(f.p.read, full)
	if f.p.onRead != nil {
		if err := f.p.onRead(full); err != nil {
			return nil, err
		}
	}
	k, ok := f.n.kids[name]
	switch {
	case !ok:
		return nil, &fs.PathError{Op: "read", Path: name, Err: fs.ErrNotExist}
	case k.err != nil:
		return nil, k.err
	case k.kind == "link":
		return nil, fmt.Errorf("%w: %s", fsx.ErrLink, name)
	case k.kind != "file":
		return nil, fmt.Errorf("%w: %s", fsx.ErrNotRegular, name)
	case k.long:
		return nil, fmt.Errorf("%w: %s", fsx.ErrTooLarge, name)
	}
	return slices.Clone(k.data), nil
}

type entry struct{ name, kind string }

func (e entry) Name() string { return e.name }
func (e entry) IsDir() bool  { return e.kind == "dir" }
func (e entry) Type() fs.FileMode {
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
func (e entry) Info() (fs.FileInfo, error) { return nil, errors.New("no info") }

func (f *memFS) ReadDir() ([]fs.DirEntry, error) {
	if *f.closed {
		return nil, fs.ErrClosed
	}
	f.p.listed = append(f.p.listed, f.path)
	if f.p.onList != nil {
		f.p.onList(f.path)
	}
	if f.n.err != nil {
		return nil, f.n.err
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
		out = append(out, entry{n, f.n.kids[n].kind})
	}
	return out, nil
}

var errReadOnly = errors.New("the memory file system is read only")

func (f *memFS) Mkdir(string, fs.FileMode) error                  { return errReadOnly }
func (f *memFS) CreateExcl(string, fs.FileMode) (fsx.File, error) { return nil, errReadOnly }
func (f *memFS) RenameNoReplace(string, string) error             { return errReadOnly }
func (f *memFS) Sync() error                                      { return errReadOnly }
func (f *memFS) Close() error {
	// Only the root closes the whole bundle: the handles of folders that fsx opens along a path are
	// released after every call.
	if f.path == "" {
		*f.closed = true
	}
	return nil
}

// flipCtx is a context whose error is set by a test at a place that the test chooses, so that a run is
// stopped in the middle with no goroutine and no timer.
type flipCtx struct {
	parentDone <-chan struct{}
	err        error
}

func (c *flipCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *flipCtx) Done() <-chan struct{}       { return c.parentDone }
func (c *flipCtx) Err() error                  { return c.err }
func (c *flipCtx) Value(any) any               { return nil }
