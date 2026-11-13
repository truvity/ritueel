package fsx_test

// An in-memory file system with a model of what survives a cut.
//
// The model is deliberately pessimistic and small:
//
//   - A data write that no later Sync of the same file covered may survive with any prefix of
//     its bytes, including none.
//   - A folder entry (a create, a mkdir, a rename) that no later SyncDir of its folder covered
//     may be lost.
//   - A SyncDir covers every entry change made in that folder before it. A Sync covers every
//     byte written to that file before it.
//
// It says nothing about a real stick. A sector here is written whole or not at all, so the
// model cannot show a sector that kept the content of the write before it (issue 181). What
// the cut tests prove with it is the order of the steps and what a cut between two steps
// leaves.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"ritueel.id/ritueel/internal/fsx"
)

var errReadOnly = errors.New("memfs: a crash image is read-only")

// ---- the model -------------------------------------------------------------------------

type entryEvent struct {
	old  string // the name a rename moved away from; empty for a new entry
	name string
	n    *node
}

type node struct {
	id      int
	dir     bool
	mode    fs.FileMode
	data    []byte // everything written
	synced  int    // how many bytes a Sync covered
	live    map[string]*node
	durable map[string]*node
	pending []entryEvent
}

type model struct {
	root *node
	next int
	byID map[int]*node
}

func newModel() *model {
	m := &model{next: 1, byID: map[int]*node{}}
	m.root = m.newNode(0, true, 0o755)
	return m
}

func (m *model) newNode(id int, dir bool, mode fs.FileMode) *node {
	if id == 0 {
		id = m.next
	}
	if id >= m.next {
		m.next = id + 1
	}
	n := &node{id: id, dir: dir, mode: mode}
	if dir {
		n.live = map[string]*node{}
		n.durable = map[string]*node{}
	}
	m.byID[id] = n
	return n
}

func (m *model) walk(p string) (*node, error) {
	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		return nil, &fs.PathError{Op: "open", Path: p, Err: errors.New("memfs: relative path")}
	}
	n := m.root
	if p == "/" {
		return n, nil
	}
	for _, e := range strings.Split(p[1:], "/") {
		if !n.dir {
			return nil, &fs.PathError{Op: "open", Path: p, Err: errNotADir}
		}
		c, ok := n.live[e]
		if !ok {
			return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
		}
		n = c
	}
	return n, nil
}

var errNotADir = errors.New("not a directory")

func (m *model) parent(p string) (*node, string, error) {
	p = path.Clean(p)
	dir, base := path.Split(p)
	d, err := m.walk(dir)
	if err != nil {
		return nil, "", err
	}
	if !d.dir {
		return nil, "", &fs.PathError{Op: "open", Path: p, Err: errNotADir}
	}
	return d, base, nil
}

func (m *model) add(p string, id int, dir bool, mode fs.FileMode) (*node, error) {
	d, base, err := m.parent(p)
	if err != nil {
		return nil, err
	}
	if _, ok := d.live[base]; ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrExist}
	}
	n := m.newNode(id, dir, mode)
	d.live[base] = n
	d.pending = append(d.pending, entryEvent{name: base, n: n})
	return n, nil
}

func (m *model) rename(oldp, newp string) error {
	od, ob, err := m.parent(oldp)
	if err != nil {
		return err
	}
	nd, nb, err := m.parent(newp)
	if err != nil {
		return err
	}
	if od != nd {
		return &os.LinkError{Op: "rename", Old: oldp, New: newp, Err: errors.New("memfs: a rename across folders is not modelled")}
	}
	n, ok := od.live[ob]
	if !ok {
		return &os.LinkError{Op: "rename", Old: oldp, New: newp, Err: fs.ErrNotExist}
	}
	if _, ok := nd.live[nb]; ok {
		return &os.LinkError{Op: "rename", Old: oldp, New: newp, Err: fs.ErrExist}
	}
	delete(od.live, ob)
	nd.live[nb] = n
	nd.pending = append(nd.pending, entryEvent{old: ob, name: nb, n: n})
	return nil
}

func (m *model) syncDir(p string) error {
	d, err := m.walk(p)
	if err != nil {
		return err
	}
	if !d.dir {
		return &fs.PathError{Op: "sync", Path: p, Err: errNotADir}
	}
	d.durable = maps.Clone(d.live)
	d.pending = nil
	return nil
}

// syncAll makes every folder entry and every byte durable: the state before the writer starts.
func (m *model) syncAll() {
	for _, n := range m.byID {
		if n.dir {
			n.durable = maps.Clone(n.live)
			n.pending = nil
		} else {
			n.synced = len(n.data)
		}
	}
}

func (m *model) clone() *model {
	c := &model{next: m.next, byID: map[int]*node{}}
	memo := map[*node]*node{}
	var cp func(n *node) *node
	cp = func(n *node) *node {
		if n == nil {
			return nil
		}
		if x, ok := memo[n]; ok {
			return x
		}
		x := &node{id: n.id, dir: n.dir, mode: n.mode, data: slices.Clone(n.data), synced: n.synced}
		memo[n] = x
		c.byID[x.id] = x
		if n.dir {
			x.live = map[string]*node{}
			for k, v := range n.live {
				x.live[k] = cp(v)
			}
			x.durable = map[string]*node{}
			for k, v := range n.durable {
				x.durable[k] = cp(v)
			}
			for _, ev := range n.pending {
				x.pending = append(x.pending, entryEvent{old: ev.old, name: ev.name, n: cp(ev.n)})
			}
		}
		return x
	}
	c.root = cp(m.root)
	return c
}

// replay applies one logged operation that had an effect.
func (m *model) replay(o opRec) {
	var err error
	switch o.Kind {
	case kMkdir:
		_, err = m.add(o.Path, o.Node, true, o.Mode)
	case kCreate:
		_, err = m.add(o.Path, o.Node, false, o.Mode)
	case kWrite:
		n := m.byID[o.Node]
		n.data = append(n.data, o.Data...)
	case kSync:
		n := m.byID[o.Node]
		n.synced = len(n.data)
	case kRename:
		err = m.rename(o.Path, o.New)
	case kSyncDir:
		err = m.syncDir(o.Path)
	}
	if err != nil {
		panic(fmt.Sprintf("memfs: the replay of %v diverged from the run: %v", o, err))
	}
}

// ---- cut policies and the crash image ---------------------------------------------------

type policy struct {
	kind string // "flushed", "all" or "seed"
	seed uint64
}

var (
	policyFlushed = policy{kind: "flushed"}
	policyAll     = policy{kind: "all"}
)

func seedPolicy(seed uint64) policy { return policy{kind: "seed", seed: seed} }

func (p policy) String() string {
	if p.kind == "seed" {
		return fmt.Sprintf("seed-%d", p.seed)
	}
	return p.kind
}

// policies returns the three policies; the third is run with seeds 1 to nSeeds.
func policies(nSeeds int) []policy {
	out := []policy{policyFlushed, policyAll}
	for s := 1; s <= nSeeds; s++ {
		out = append(out, seedPolicy(uint64(s)))
	}
	return out
}

type imgNode struct {
	dir  bool
	mode fs.FileMode
	data []byte
}

// image is what remains after a cut. It is a read-only FS.
type image struct {
	nodes map[string]*imgNode // by absolute path; "/" is the root
}

func (m *model) crash(p policy) *image {
	rng := rand.New(rand.NewPCG(p.seed, 0x5eed))
	survives := func() bool {
		switch p.kind {
		case "all":
			return true
		case "seed":
			return rng.IntN(2) == 0
		default:
			return false
		}
	}
	prefix := func(n *node) int {
		tail := len(n.data) - n.synced
		switch p.kind {
		case "all":
			return len(n.data)
		case "seed":
			switch rng.IntN(3) {
			case 0:
				return n.synced
			case 1:
				return len(n.data)
			default:
				return n.synced + rng.IntN(tail+1)
			}
		default:
			return n.synced
		}
	}
	img := &image{nodes: map[string]*imgNode{}}
	var walk func(p string, n *node)
	walk = func(p string, n *node) {
		if !n.dir {
			img.nodes[p] = &imgNode{mode: n.mode, data: slices.Clone(n.data[:prefix(n)])}
			return
		}
		img.nodes[p] = &imgNode{dir: true, mode: n.mode}
		entries := maps.Clone(n.durable)
		for _, ev := range n.pending {
			if !survives() {
				continue
			}
			if ev.old == "" {
				if _, ok := entries[ev.name]; !ok {
					entries[ev.name] = ev.n
				}
				continue
			}
			if entries[ev.old] != ev.n {
				continue
			}
			if _, ok := entries[ev.name]; ok {
				continue
			}
			delete(entries, ev.old)
			entries[ev.name] = ev.n
		}
		names := slices.Sorted(maps.Keys(entries))
		for _, name := range names {
			walk(path.Join(p, name), entries[name])
		}
	}
	walk("/", m.root)
	return img
}

// paths lists every path of the image, sorted.
func (img *image) paths() []string { return slices.Sorted(maps.Keys(img.nodes)) }

func (img *image) file(p string) ([]byte, bool) {
	n, ok := img.nodes[path.Clean(p)]
	if !ok || n.dir {
		return nil, false
	}
	return n.data, true
}

func (img *image) isDir(p string) bool {
	n, ok := img.nodes[path.Clean(p)]
	return ok && n.dir
}

// fsx.FS, read side only.

func (img *image) Mkdir(string, fs.FileMode) error                  { return errReadOnly }
func (img *image) CreateExcl(string, fs.FileMode) (fsx.File, error) { return nil, errReadOnly }
func (img *image) RenameNoReplace(_, _ string) error                { return errReadOnly }
func (img *image) SyncDir(string) error                             { return errReadOnly }

func (img *image) ReadFile(p string) ([]byte, error) {
	n, ok := img.nodes[path.Clean(p)]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
	}
	if n.dir {
		return nil, &fs.PathError{Op: "read", Path: p, Err: errors.New("is a directory")}
	}
	return slices.Clone(n.data), nil
}

func (img *image) Stat(p string) (fs.FileInfo, error) {
	p = path.Clean(p)
	n, ok := img.nodes[p]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
	}
	return memInfo{name: path.Base(p), n: n}, nil
}

func (img *image) ReadDir(p string) ([]fs.DirEntry, error) {
	p = path.Clean(p)
	n, ok := img.nodes[p]
	if !ok || !n.dir {
		return nil, &fs.PathError{Op: "readdir", Path: p, Err: fs.ErrNotExist}
	}
	var out []fs.DirEntry
	for _, q := range img.paths() {
		if q != "/" && path.Dir(q) == p {
			out = append(out, fs.FileInfoToDirEntry(memInfo{name: path.Base(q), n: img.nodes[q]}))
		}
	}
	return out, nil
}

type memInfo struct {
	name string
	n    *imgNode
}

func (i memInfo) Name() string { return i.name }
func (i memInfo) Size() int64  { return int64(len(i.n.data)) }
func (i memInfo) Mode() fs.FileMode {
	if i.n.dir {
		return i.n.mode | fs.ModeDir
	}
	return i.n.mode
}
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return i.n.dir }
func (i memInfo) Sys() any           { return nil }

// ---- the file system the writer runs on ---------------------------------------------------

type opKind string

const (
	kMkdir    opKind = "mkdir"
	kCreate   opKind = "create"
	kWrite    opKind = "write"
	kSync     opKind = "sync"
	kClose    opKind = "close"
	kRename   opKind = "rename"
	kSyncDir  opKind = "syncdir"
	kReadDir  opKind = "readdir"
	kReadFile opKind = "readfile"
	kStat     opKind = "stat"
)

// opRec is one call that reached the file system, in order. N counts from 1.
type opRec struct {
	N    int
	Kind opKind
	Path string // the path given; for a file call, the path the file was created under
	New  string // rename: the new path
	Node int
	Mode fs.FileMode
	Data []byte // write: the bytes taken
	Err  error  // what the call returned (nil: it had its effect)
}

func (o opRec) String() string {
	s := fmt.Sprintf("#%d %s %s", o.N, o.Kind, o.Path)
	if o.New != "" {
		s += " -> " + o.New
	}
	if o.Kind == kWrite {
		s += fmt.Sprintf(" (%d bytes)", len(o.Data))
	}
	if o.Err != nil {
		s += " = " + o.Err.Error()
	}
	return s
}

// memFS is the FS the tests run the writer on. Every call is logged; the n-th call can be made
// to fail (failAt) and the n-th write can be made short (shortAt).
type memFS struct {
	mu      sync.Mutex
	m       *model
	initial *model
	ops     []opRec
	open    int // files created and not yet closed

	failAt  int
	failErr error
	shortAt int
}

// newMemFS makes the folders (parents first) as they stand, durable, before the run.
func newMemFS(dirs ...string) *memFS {
	f := &memFS{m: newModel()}
	for _, d := range dirs {
		if _, err := f.m.add(d, 0, true, 0o755); err != nil {
			panic(err)
		}
	}
	f.m.syncAll()
	f.initial = f.m.clone()
	return f
}

func (f *memFS) enter(kind opKind, p, np string) (int, error) {
	f.ops = append(f.ops, opRec{N: len(f.ops) + 1, Kind: kind, Path: p, New: np})
	i := len(f.ops) - 1
	if f.failAt == f.ops[i].N {
		f.ops[i].Err = f.failErr
		return i, f.failErr
	}
	return i, nil
}

func (f *memFS) opCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ops)
}

func (f *memFS) opList() []opRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ops)
}

func (f *memFS) openFiles() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

func (f *memFS) Mkdir(p string, perm fs.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kMkdir, p, "")
	if err != nil {
		return err
	}
	n, err := f.m.add(p, 0, true, perm)
	if err != nil {
		f.ops[i].Err = err
		return err
	}
	f.ops[i].Node, f.ops[i].Mode = n.id, perm
	return nil
}

func (f *memFS) CreateExcl(p string, perm fs.FileMode) (fsx.File, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kCreate, p, "")
	if err != nil {
		return nil, err
	}
	n, err := f.m.add(p, 0, false, perm)
	if err != nil {
		f.ops[i].Err = err
		return nil, err
	}
	f.ops[i].Node, f.ops[i].Mode = n.id, perm
	f.open++
	return &memFile{fs: f, n: n, path: p}, nil
}

func (f *memFS) RenameNoReplace(oldp, newp string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kRename, oldp, newp)
	if err != nil {
		return err
	}
	if err := f.m.rename(oldp, newp); err != nil {
		f.ops[i].Err = err
		return err
	}
	return nil
}

func (f *memFS) SyncDir(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kSyncDir, p, "")
	if err != nil {
		return err
	}
	if err := f.m.syncDir(p); err != nil {
		f.ops[i].Err = err
		return err
	}
	return nil
}

func (f *memFS) ReadDir(p string) ([]fs.DirEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kReadDir, p, "")
	if err != nil {
		return nil, err
	}
	d, err := f.m.walk(p)
	if err == nil && !d.dir {
		err = &fs.PathError{Op: "readdir", Path: p, Err: errNotADir}
	}
	if err != nil {
		f.ops[i].Err = err
		return nil, err
	}
	var out []fs.DirEntry
	for _, name := range slices.Sorted(maps.Keys(d.live)) {
		out = append(out, fs.FileInfoToDirEntry(memInfo{name: name, n: &imgNode{dir: d.live[name].dir, mode: d.live[name].mode, data: d.live[name].data}}))
	}
	return out, nil
}

func (f *memFS) ReadFile(p string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kReadFile, p, "")
	if err != nil {
		return nil, err
	}
	n, err := f.m.walk(p)
	if err == nil && n.dir {
		err = &fs.PathError{Op: "read", Path: p, Err: errors.New("is a directory")}
	}
	if err != nil {
		f.ops[i].Err = err
		return nil, err
	}
	return slices.Clone(n.data), nil
}

func (f *memFS) Stat(p string) (fs.FileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kStat, p, "")
	if err != nil {
		return nil, err
	}
	n, err := f.m.walk(p)
	if err != nil {
		f.ops[i].Err = err
		return nil, err
	}
	return memInfo{name: path.Base(p), n: &imgNode{dir: n.dir, mode: n.mode, data: n.data}}, nil
}

// CrashAfter returns what remains when the process ends after the first n calls, under the
// policy. n counts every call (a failed one included), so a cut never lies inside a call.
func (f *memFS) CrashAfter(n int, p policy) *image {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.initial.clone()
	for _, o := range f.ops {
		if o.N > n {
			break
		}
		if o.Err != nil {
			continue
		}
		m.replay(o)
	}
	return m.crash(p)
}

// Live returns the tree as the process sees it now (every effect applied).
func (f *memFS) Live() *image {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m.clone().crash(policyAll)
}

type memFile struct {
	fs     *memFS
	n      *node
	path   string
	closed bool
}

func (mf *memFile) Write(p []byte) (int, error) {
	f := mf.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kWrite, mf.path, "")
	if err != nil {
		return 0, err
	}
	take := len(p)
	if f.shortAt == f.ops[i].N {
		take = len(p) / 2
	}
	data := slices.Clone(p[:take])
	f.ops[i].Node, f.ops[i].Data = mf.n.id, data
	mf.n.data = append(mf.n.data, data...)
	return take, nil
}

func (mf *memFile) Sync() error {
	f := mf.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := f.enter(kSync, mf.path, "")
	if err != nil {
		return err
	}
	f.ops[i].Node = mf.n.id
	mf.n.synced = len(mf.n.data)
	return nil
}

func (mf *memFile) Close() error {
	f := mf.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.enter(kClose, mf.path, "")
	if !mf.closed {
		mf.closed = true
		f.open--
	}
	return err
}

var _ fsx.FS = (*memFS)(nil)
var _ fsx.FS = (*image)(nil)
var _ io.Writer = (*memFile)(nil)
