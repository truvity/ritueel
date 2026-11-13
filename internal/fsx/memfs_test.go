package fsx_test

// An in-memory file system with a model of what survives a cut.
//
// The model is a tree of folder handles, as fsx.FS is: every call works on one name inside the
// folder that the handle stands for. It is deliberately pessimistic and small:
//
//   - A data write that no later Sync of the same file covered may survive with any prefix of
//     its bytes, including none.
//   - A folder entry (a create, a mkdir, a rename) that no later Sync of its folder covered may
//     be lost.
//   - A Sync of a folder covers every entry change made in that folder before it. A Sync of a
//     file covers every byte written to that file before it.
//
// It says nothing about a real stick. A sector here is written whole or not at all, so the model
// cannot show a sector that kept the content of the write before it (issue 181). What the cut
// tests prove with it is the order of the steps and what a cut between two steps leaves.
//
// What the model keeps for the other tests:
//
//   - Every call that reaches it is logged and numbered, in order, and is a call to cut after or
//     to make fail: that includes OpenDir and the close of a folder, which have no durable effect.
//     A cut after such a call leaves the same image as the cut before it (the replay skips them),
//     so the sweep looks at a few duplicate images and, in exchange, at every point between a walk
//     and the first effect that follows it. An injected error reaches OpenDir too (a failed walk
//     is a stop) and the close of a folder (whose error the writer drops: the injection must not
//     change the result).
//   - Every handle (folder or file) that is open is counted, so a test can say what must be open
//     (the root, and the files of open journals) and nothing else.
//   - Calls that a correct caller never makes are recorded as violations: a method on a closed
//     handle, a second Close of one, a name that is not one plain name of the name rule.
//   - It follows no link: a link is a name that OpenDir, ReadFile refuse (ErrLink), and that
//     Mkdir, CreateExcl and RenameNoReplace see as taken, a dangling one too, as the real file
//     system does. A FIFO, a folder or a file longer than the limit is refused by ReadFile as the
//     interface says.

import (
	"errors"
	"fmt"
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

// ---- the model -------------------------------------------------------------------------

type nodeKind int

const (
	nodeFile nodeKind = iota
	nodeDir
	nodeLink
	nodeFifo
)

func (k nodeKind) String() string {
	return [...]string{"file", "folder", "link", "FIFO"}[k]
}

type entryEvent struct {
	old  string // the name a rename moved away from; empty for a new entry
	name string
	n    *node
}

type node struct {
	id      int
	kind    nodeKind
	mode    fs.FileMode
	data    []byte // everything written
	synced  int    // how many bytes a Sync covered
	virtual int64  // a regular file that reads as this long without holding the bytes (0: none)
	target  string // a link: where it points (never followed)
	live    map[string]*node
	durable map[string]*node
	pending []entryEvent
}

func (n *node) size() int64 {
	if n.virtual > 0 {
		return n.virtual
	}
	return int64(len(n.data))
}

type model struct {
	root *node
	next int
	byID map[int]*node
}

func newModel() *model {
	m := &model{next: 1, byID: map[int]*node{}}
	m.root = m.newNode(0, nodeDir, 0o755)
	return m
}

func (m *model) newNode(id int, kind nodeKind, mode fs.FileMode) *node {
	if id == 0 {
		id = m.next
	}
	if id >= m.next {
		m.next = id + 1
	}
	n := &node{id: id, kind: kind, mode: mode}
	if kind == nodeDir {
		n.live = map[string]*node{}
		n.durable = map[string]*node{}
	}
	m.byID[id] = n
	return n
}

// add puts a new entry in the folder d. It fails when anything holds the name.
func (m *model) add(d *node, name string, id int, kind nodeKind, mode fs.FileMode) (*node, error) {
	if _, ok := d.live[name]; ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrExist}
	}
	n := m.newNode(id, kind, mode)
	d.live[name] = n
	d.pending = append(d.pending, entryEvent{name: name, n: n})
	return n, nil
}

func (m *model) rename(d *node, oldName, newName string) error {
	n, ok := d.live[oldName]
	if !ok {
		return &os.LinkError{Op: "rename", Old: oldName, New: newName, Err: fs.ErrNotExist}
	}
	if _, ok := d.live[newName]; ok {
		return &os.LinkError{Op: "rename", Old: oldName, New: newName, Err: fs.ErrExist}
	}
	delete(d.live, oldName)
	d.live[newName] = n
	d.pending = append(d.pending, entryEvent{old: oldName, name: newName, n: n})
	return nil
}

func syncDirNode(d *node) {
	d.durable = maps.Clone(d.live)
	d.pending = nil
}

// syncAll makes every folder entry and every byte durable: the state before the writer starts.
func (m *model) syncAll() {
	for _, n := range m.byID {
		if n.kind == nodeDir {
			syncDirNode(n)
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
		x := &node{id: n.id, kind: n.kind, mode: n.mode, data: slices.Clone(n.data), synced: n.synced, virtual: n.virtual, target: n.target}
		memo[n] = x
		c.byID[x.id] = x
		if n.kind == nodeDir {
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

// replay applies one logged call that had an effect. The calls are found by the ids of the
// folders and files they were made on, never by a path, so a folder that a rename moved is still
// the same folder.
func (m *model) replay(o opRec) {
	var err error
	switch o.Kind {
	case kMkdir:
		_, err = m.add(m.byID[o.Dir], o.Name, o.Node, nodeDir, o.Mode)
	case kCreate:
		_, err = m.add(m.byID[o.Dir], o.Name, o.Node, nodeFile, o.Mode)
	case kWrite:
		n := m.byID[o.Node]
		n.data = append(n.data, o.Data...)
	case kSync:
		n := m.byID[o.Node]
		n.synced = len(n.data)
	case kRename:
		err = m.rename(m.byID[o.Dir], o.Name, o.NewName)
	case kSyncDir:
		syncDirNode(m.byID[o.Dir])
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
	kind   nodeKind
	mode   fs.FileMode
	data   []byte
	target string
}

func (n *imgNode) dir() bool { return n.kind == nodeDir }

// image is what remains after a cut, keyed by "/" and the path from the root. root() makes it a
// read-only file system to read through the package's helpers.
type image struct {
	nodes map[string]*imgNode // by "/"-rooted path; "/" is the root
	fsys  *memFS
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
		if n.kind != nodeDir {
			in := &imgNode{kind: n.kind, mode: n.mode, target: n.target}
			if n.kind == nodeFile {
				in.data = slices.Clone(n.data[:prefix(n)])
			}
			img.nodes[p] = in
			return
		}
		img.nodes[p] = &imgNode{kind: nodeDir, mode: n.mode}
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

func abs(p string) string { return path.Clean("/" + p) }

// paths lists every path of the image with its "/" in front, sorted: "/" is the root.
func (img *image) paths() []string { return slices.Sorted(maps.Keys(img.nodes)) }

// list is every path below the root, without the "/" in front, sorted.
func (img *image) list() []string {
	var out []string
	for _, p := range img.paths() {
		if p != "/" {
			out = append(out, p[1:])
		}
	}
	return out
}

func (img *image) file(p string) ([]byte, bool) {
	n, ok := img.nodes[abs(p)]
	if !ok || n.kind != nodeFile {
		return nil, false
	}
	return n.data, true
}

func (img *image) isDir(p string) bool {
	n, ok := img.nodes[abs(p)]
	return ok && n.dir()
}

// root is a fresh root handle on a read-write copy of the image (a recovered stick). Every call
// makes its own, and the caller closes it.
func (img *image) root() *memDir {
	if img.fsys == nil {
		f := &memFS{m: newModel()}
		for _, p := range img.paths() {
			if p == "/" {
				continue
			}
			f.put(p[1:], img.nodes[p])
		}
		f.snapshot()
		img.fsys = f
	}
	return img.fsys.Root()
}

// ---- the file system the writer runs on ---------------------------------------------------

type opKind string

const (
	kOpenDir  opKind = "opendir"
	kCloseDir opKind = "closedir"
	kMkdir    opKind = "mkdir"
	kCreate   opKind = "create"
	kWrite    opKind = "write"
	kSync     opKind = "sync"
	kClose    opKind = "close"
	kRename   opKind = "rename"
	kSyncDir  opKind = "syncdir"
	kReadDir  opKind = "readdir"
	kReadFile opKind = "readfile"
)

// opRec is one call that reached the file system, in order. N counts from 1.
type opRec struct {
	N       int
	Kind    opKind
	Path    string // the path of the thing called, from the root ("." for the root itself)
	New     string // rename: the path of the new name
	Dir     int    // the folder the call was made on
	Name    string // the name given
	NewName string // rename: the new name given
	Node    int    // the node a create or mkdir made, or a write or a flush of a file reached
	Mode    fs.FileMode
	Data    []byte // write: the bytes taken
	Err     error  // what the call returned (nil: it had its effect)
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

// memFS is the file system the tests run the writer on. Every call is logged; the n-th call can
// be made to fail (failAt) and the n-th write can be made short (shortAt).
type memFS struct {
	mu      sync.Mutex
	m       *model
	initial *model
	ops     []opRec
	dirs    map[*memDir]struct{}  // folder handles that are open
	files   map[*memFile]struct{} // files that are open
	opened  int                   // every handle ever made
	watched bool                  // a test cleanup that checks the handles is registered

	// violations are calls that a correct caller never makes.
	violations []string

	failAt   int    // the n-th call fails (0: none)
	failErr  error  // what a failing call returns
	failKind opKind // the failNth-th call of this kind fails, counting from now (empty: none)
	failNth  int
	kindSeen int
	shortAt  int // the n-th call, if it is a write, takes half of its bytes
}

// failOn makes the nth call of the kind from now on fail with err.
func (f *memFS) failOn(kind opKind, nth int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failKind, f.failNth, f.kindSeen, f.failErr = kind, nth, 0, err
}

// clearFail takes every injection away.
func (f *memFS) clearFail() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failAt, f.failKind, f.failNth, f.kindSeen = 0, "", 0, 0
}

// newMemFS makes the folders (parents first, paths relative to the root) as they stand, durable,
// before the run.
func newMemFS(dirs ...string) *memFS {
	f := &memFS{m: newModel()}
	for _, d := range dirs {
		f.addDir(d)
	}
	f.snapshot()
	return f
}

// snapshot makes everything made so far durable and the state that the replays start from.
func (f *memFS) snapshot() {
	if len(f.ops) != 0 {
		panic("memfs: the file system was changed by a setup call after the run began")
	}
	f.m.syncAll()
	f.initial = f.m.clone()
}

// lookup walks the live tree without following a link; the last element may be anything.
func (f *memFS) lookup(p string) (*node, bool) {
	n := f.m.root
	if p == "." || p == "" {
		return n, true
	}
	for _, e := range strings.Split(p, "/") {
		if n.kind != nodeDir {
			return nil, false
		}
		c, ok := n.live[e]
		if !ok {
			return nil, false
		}
		n = c
	}
	return n, true
}

func (f *memFS) setupAdd(p string, kind nodeKind, mode fs.FileMode) *node {
	dir, base := path.Split(p)
	d, ok := f.lookup(strings.TrimSuffix(dir, "/"))
	if !ok || d.kind != nodeDir {
		panic("memfs: setup of " + p + ": no folder")
	}
	n, err := f.m.add(d, base, 0, kind, mode)
	if err != nil {
		panic(err)
	}
	return n
}

// The setup calls make part of the state before the run, with no effect on the log, and are made
// durable by snapshot (newMemFS does it for the folders; call f.snapshot() after the others).

func (f *memFS) addDir(p string) { f.setupAdd(p, nodeDir, 0o755) }
func (f *memFS) addFile(p string, data []byte) {
	f.setupAdd(p, nodeFile, 0o644).data = slices.Clone(data)
	f.snapshot()
}

// addLink makes a symbolic link. The model never follows it: target is only what it says.
func (f *memFS) addLink(p, target string) {
	f.setupAdd(p, nodeLink, 0o777).target = target
	f.snapshot()
}
func (f *memFS) addFifo(p string) {
	f.setupAdd(p, nodeFifo, 0o644)
	f.snapshot()
}

// addVirtual makes a regular file that reads as size bytes long without holding them.
func (f *memFS) addVirtual(p string, size int64) {
	f.setupAdd(p, nodeFile, 0o644).virtual = size
	f.snapshot()
}

// put makes a node as an image holds it (used to build a file system from an image).
func (f *memFS) put(p string, in *imgNode) {
	n := f.setupAdd(p, in.kind, in.mode)
	n.data = slices.Clone(in.data)
	n.target = in.target
}

// Root returns a new handle on the root folder. The caller closes it (a writer does, in Close).
func (f *memFS) Root() *memDir {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newDir(f.m.root, ".")
}

func (f *memFS) newDir(n *node, p string) *memDir {
	d := &memDir{fs: f, n: n, path: p}
	if f.dirs == nil {
		f.dirs = map[*memDir]struct{}{}
	}
	f.dirs[d] = struct{}{}
	f.opened++
	return d
}

func (f *memFS) violate(format string, a ...any) {
	f.violations = append(f.violations, fmt.Sprintf(format, a...))
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

// opsAfter is the list of calls after the first n.
func (f *memFS) opsAfter(n int) []opRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ops[n:])
}

// handles says how many folder handles and how many files are open.
func (f *memFS) handles() (dirs, files int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dirs), len(f.files)
}

// openFiles is how many files are open.
func (f *memFS) openFiles() int {
	_, n := f.handles()
	return n
}

// describeOpen names what is open, for a message.
func (f *memFS) describeOpen() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for d := range f.dirs {
		out = append(out, "folder "+d.path)
	}
	for h := range f.files {
		out = append(out, "file "+h.path)
	}
	slices.Sort(out)
	return fmt.Sprint(out)
}

func (f *memFS) violationList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.violations)
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

// ---- the folder handle -----------------------------------------------------------------------

// memDir is an open folder. It stands for a node, not for a path, as a descriptor does.
type memDir struct {
	fs     *memFS
	n      *node
	path   string
	closed bool
}

func closedErr(op, p string) error {
	return &fs.PathError{Op: op, Path: p, Err: fs.ErrClosed}
}

func joinP(dir, name string) string {
	if dir == "." {
		return name
	}
	return dir + "/" + name
}

func plainName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		ok := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// enter logs a call on the folder, under the lock the caller holds, and applies the injection.
// It returns the index of the log entry.
func (d *memDir) enter(kind opKind, name, newName string) (int, error) {
	f := d.fs
	if d.closed {
		f.violate("%s %q on the closed folder %s", kind, name, d.path)
		return -1, closedErr(string(kind), joinP(d.path, name))
	}
	names := []string{}
	switch kind {
	case kOpenDir, kMkdir, kCreate, kReadFile:
		names = []string{name}
	case kRename:
		names = []string{name, newName}
	}
	for _, nm := range names {
		if !plainName(nm) {
			f.violate("%s was given %q, which is not one plain name of the name rule", kind, nm)
		}
	}
	rec := opRec{N: len(f.ops) + 1, Kind: kind, Path: d.path, Dir: d.n.id, Name: name, NewName: newName}
	if name != "" {
		rec.Path = joinP(d.path, name)
	}
	if newName != "" {
		rec.New = joinP(d.path, newName)
	}
	return f.record(rec)
}

// record logs a call, and makes it fail when it is the one that an injection names.
func (f *memFS) record(rec opRec) (int, error) {
	f.ops = append(f.ops, rec)
	i := len(f.ops) - 1
	hit := f.failAt == rec.N
	if f.failKind != "" && f.failKind == rec.Kind {
		f.kindSeen++
		hit = hit || f.kindSeen == f.failNth
	}
	if hit {
		f.ops[i].Err = f.failErr
		return i, f.failErr
	}
	return i, nil
}

func (d *memDir) fail(i int, err error) error {
	d.fs.ops[i].Err = err
	return err
}

func (d *memDir) OpenDir(name string) (fsx.FS, error) {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := d.enter(kOpenDir, name, "")
	if err != nil {
		return nil, err
	}
	c, ok := d.n.live[name]
	switch {
	case !ok:
		return nil, d.fail(i, &fs.PathError{Op: "openat", Path: name, Err: fs.ErrNotExist})
	case c.kind == nodeLink:
		return nil, d.fail(i, fmt.Errorf("%w: %w", fsx.ErrLink, &fs.PathError{Op: "openat", Path: name, Err: errors.New("too many levels of symbolic links")}))
	case c.kind != nodeDir:
		return nil, d.fail(i, &fs.PathError{Op: "openat", Path: name, Err: errNotADir})
	}
	return f.newDir(c, joinP(d.path, name)), nil
}

var errNotADir = errors.New("not a directory")

func (d *memDir) Mkdir(name string, perm fs.FileMode) error {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := d.enter(kMkdir, name, "")
	if err != nil {
		return err
	}
	n, err := f.m.add(d.n, name, 0, nodeDir, perm)
	if err != nil {
		return d.fail(i, err)
	}
	f.ops[i].Node, f.ops[i].Mode = n.id, perm
	return nil
}

func (d *memDir) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := d.enter(kCreate, name, "")
	if err != nil {
		return nil, err
	}
	n, err := f.m.add(d.n, name, 0, nodeFile, perm)
	if err != nil {
		return nil, d.fail(i, err)
	}
	f.ops[i].Node, f.ops[i].Mode = n.id, perm
	h := &memFile{fs: f, n: n, path: joinP(d.path, name)}
	if f.files == nil {
		f.files = map[*memFile]struct{}{}
	}
	f.files[h] = struct{}{}
	f.opened++
	return h, nil
}

func (d *memDir) RenameNoReplace(oldName, newName string) error {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := d.enter(kRename, oldName, newName)
	if err != nil {
		return err
	}
	if err := f.m.rename(d.n, oldName, newName); err != nil {
		return d.fail(i, err)
	}
	return nil
}

func (d *memDir) Sync() error {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := d.enter(kSyncDir, "", ""); err != nil {
		return err
	}
	syncDirNode(d.n)
	return nil
}

func entryInfo(name string, n *node) memInfo {
	mode := n.mode & fs.ModePerm
	switch n.kind {
	case nodeDir:
		mode |= fs.ModeDir
	case nodeLink:
		mode |= fs.ModeSymlink
	case nodeFifo:
		mode |= fs.ModeNamedPipe
	}
	return memInfo{name: name, mode: mode, size: n.size()}
}

func (d *memDir) ReadDir() ([]fs.DirEntry, error) {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := d.enter(kReadDir, "", ""); err != nil {
		return nil, err
	}
	var out []fs.DirEntry
	for _, name := range slices.Sorted(maps.Keys(d.n.live)) {
		out = append(out, fs.FileInfoToDirEntry(entryInfo(name, d.n.live[name])))
	}
	return out, nil
}

func (d *memDir) ReadFile(name string) ([]byte, error) {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := d.enter(kReadFile, name, "")
	if err != nil {
		return nil, err
	}
	n, ok := d.n.live[name]
	switch {
	case !ok:
		return nil, d.fail(i, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist})
	case n.kind == nodeLink:
		return nil, d.fail(i, &fs.PathError{Op: "open", Path: name, Err: fsx.ErrLink})
	case n.kind != nodeFile:
		return nil, d.fail(i, &fs.PathError{Op: "read", Path: name, Err: fmt.Errorf("%w: a %v", fsx.ErrNotRegular, n.kind)})
	case n.size() > fsx.MaxReadSize:
		return nil, d.fail(i, &fs.PathError{Op: "read", Path: name, Err: fmt.Errorf("%w: %d bytes", fsx.ErrTooLarge, n.size())})
	}
	if n.virtual > 0 {
		return make([]byte, n.virtual), nil
	}
	return slices.Clone(n.data), nil
}

func (d *memDir) Close() error {
	f := d.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	if d.closed {
		f.violate("a second Close of the folder %s", d.path)
		return nil
	}
	_, err := d.enter(kCloseDir, "", "")
	d.closed = true
	delete(f.dirs, d)
	return err
}

// ---- the file ------------------------------------------------------------------------------

type memFile struct {
	fs     *memFS
	n      *node
	path   string
	closed bool
}

func (mf *memFile) enter(kind opKind) (int, error) {
	f := mf.fs
	if mf.closed {
		f.violate("%s on the closed file %s", kind, mf.path)
		return -1, closedErr(string(kind), mf.path)
	}
	return f.record(opRec{N: len(f.ops) + 1, Kind: kind, Path: mf.path, Node: mf.n.id})
}

func (mf *memFile) Write(p []byte) (int, error) {
	f := mf.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	i, err := mf.enter(kWrite)
	if err != nil {
		return 0, err
	}
	take := len(p)
	if f.shortAt == f.ops[i].N {
		take = len(p) / 2
	}
	data := slices.Clone(p[:take])
	f.ops[i].Data = data
	mf.n.data = append(mf.n.data, data...)
	return take, nil
}

func (mf *memFile) Sync() error {
	f := mf.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := mf.enter(kSync); err != nil {
		return err
	}
	mf.n.synced = len(mf.n.data)
	return nil
}

func (mf *memFile) Close() error {
	f := mf.fs
	f.mu.Lock()
	defer f.mu.Unlock()
	if mf.closed {
		f.violate("a second Close of the file %s", mf.path)
		return nil
	}
	_, err := mf.enter(kClose)
	mf.closed = true
	delete(f.files, mf)
	return err
}

// ---- the entries of a listing ------------------------------------------------------------------

type memInfo struct {
	name string
	mode fs.FileMode
	size int64
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return i.mode }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return i.mode.IsDir() }
func (i memInfo) Sys() any           { return nil }

var (
	_ fsx.FS   = (*memDir)(nil)
	_ fsx.File = (*memFile)(nil)
)
