package ceremonytest

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"sync"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/keystore"
)

// errStop is the error that the wrappers of this file return at the place where a run is to stop.
// A run that meets it expects it; a run that meets any other error fails the test.
var errStop = errors.New("ceremonytest: the run was stopped here on purpose")

// counter counts the changing calls of the file system of a run, and fails the Nth. It is shared by
// the folders that one file system opens.
type counter struct {
	mu     sync.Mutex
	n      int
	failAt int // the call that fails; 0 fails none
	fired  bool
}

// op counts one changing call and returns errStop at the one that failAt names.
func (c *counter) op() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	if c.failAt > 0 && c.n == c.failAt && !c.fired {
		c.fired = true
		return errStop
	}
	return nil
}

// count is the number of changing calls so far.
func (c *counter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// hit says whether the call that failAt names was made.
func (c *counter) hit() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fired
}

// cutFS wraps a folder of a file system and fails the Nth changing call that is made through it or
// through any folder opened from it: Mkdir, CreateExcl, RenameNoReplace, Sync of a folder, Write and
// Sync of a file. A failed Write leaves the first half of the data, as a cut in the middle of a
// write does. Reads and the closing of a handle are not counted. The in-memory file systems of fsx
// and of history are in _test.go files and cannot be imported, so this is the small wrapper that a
// test of a stop needs, over the real file system.
type cutFS struct {
	in fsx.FS
	c  *counter
}

// OpenDir opens the folder and wraps it, with the same counter.
func (f *cutFS) OpenDir(name string) (fsx.FS, error) {
	d, err := f.in.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &cutFS{in: d, c: f.c}, nil
}

// Mkdir counts the call, then makes the folder.
func (f *cutFS) Mkdir(name string, perm fs.FileMode) error {
	if err := f.c.op(); err != nil {
		return err
	}
	return f.in.Mkdir(name, perm)
}

// CreateExcl counts the call, then creates the file.
func (f *cutFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	if err := f.c.op(); err != nil {
		return nil, err
	}
	file, err := f.in.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}
	return &cutFile{File: file, c: f.c}, nil
}

// RenameNoReplace counts the call, then renames.
func (f *cutFS) RenameNoReplace(oldName, newName string) error {
	if err := f.c.op(); err != nil {
		return err
	}
	return f.in.RenameNoReplace(oldName, newName)
}

// Sync counts the call, then flushes the folder.
func (f *cutFS) Sync() error {
	if err := f.c.op(); err != nil {
		return err
	}
	return f.in.Sync()
}

// ReadFile reads and counts nothing.
func (f *cutFS) ReadFile(name string) ([]byte, error) { return f.in.ReadFile(name) }

// ReadDir lists and counts nothing.
func (f *cutFS) ReadDir() ([]fs.DirEntry, error) { return f.in.ReadDir() }

// Close releases the folder and counts nothing.
func (f *cutFS) Close() error { return f.in.Close() }

// cutFile is a file of a cutFS.
type cutFile struct {
	fsx.File
	c *counter
}

// Write counts the call. At the cut it writes the first half of the data and fails.
func (f *cutFile) Write(p []byte) (int, error) {
	if err := f.c.op(); err != nil {
		n, _ := f.File.Write(p[:len(p)/2])
		return n, err
	}
	return f.File.Write(p)
}

// Sync counts the call, then flushes the file.
func (f *cutFile) Sync() error {
	if err := f.c.op(); err != nil {
		return err
	}
	return f.File.Sync()
}

// stopStore wraps a RootStore and fails the Nth Birth with errStop before the key is made.
type stopStore struct {
	ceremony.RootStore
	birthAt int // the Birth that fails; 0 fails none

	mu    sync.Mutex
	n     int
	fired bool
}

// Birth counts the call and fails the one that birthAt names; every other call is the store's.
func (s *stopStore) Birth(ctx context.Context, label string) (keystore.Key, error) {
	s.mu.Lock()
	s.n++
	stop := s.birthAt > 0 && s.n == s.birthAt
	if stop {
		s.fired = true
	}
	s.mu.Unlock()
	if stop {
		return nil, errStop
	}
	return s.RootStore.Birth(ctx, label)
}

// hit says whether the Birth that birthAt names was made.
func (s *stopStore) hit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fired
}

// stopTrace wraps the two journals of a ceremony folder, keeps a copy of each line that a journal
// accepted, and fails the Nth line of the journal of signatures with errStop.
type stopTrace struct {
	births, sigs *stopJournal
}

func newStopTrace(sigsFailAt int) *stopTrace {
	return &stopTrace{births: &stopJournal{}, sigs: &stopJournal{failAt: sigsFailAt}}
}

// use sets the journals that the lines go to: the trace that Folder.Start returned.
func (t *stopTrace) use(tr ceremony.Trace) {
	t.births.inner, t.sigs.inner = tr.Births(), tr.Signatures()
}

// Births is the birth journal.
func (t *stopTrace) Births() ceremony.Journal { return t.births }

// Signatures is the journal of signatures.
func (t *stopTrace) Signatures() ceremony.Journal { return t.sigs }

// stopJournal is one journal of a stopTrace.
type stopJournal struct {
	inner  ceremony.Journal
	failAt int // the line that fails; 0 fails none

	mu    sync.Mutex
	n     int
	lines [][]byte
	fired bool
}

// Append counts the line and fails the one that failAt names; the other lines go to the journal,
// and a copy of each that it accepted is kept.
func (j *stopJournal) Append(line []byte) error {
	j.mu.Lock()
	j.n++
	stop := j.failAt > 0 && j.n == j.failAt
	if stop {
		j.fired = true
	}
	inner := j.inner
	j.mu.Unlock()
	if stop {
		return errStop
	}
	if inner == nil {
		return errors.New("ceremonytest: the journal has no file behind it")
	}
	if err := inner.Append(line); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.lines = append(j.lines, slices.Clone(line))
	return nil
}

// accepted are the lines that the journal accepted.
func (j *stopJournal) accepted() [][]byte {
	j.mu.Lock()
	defer j.mu.Unlock()
	return slices.Clone(j.lines)
}

// hit says whether the line that failAt names was made.
func (j *stopJournal) hit() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.fired
}
