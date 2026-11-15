//go:build linux || darwin

package ceremony_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/keystore"
)

// Helpers of the tests of the second set of points: a file system that lies about one write, the names
// of the files that the writes of a whole run reach, and a store that counts births. The names of this
// file start with fx.

// fxMode is how a write that reaches the disk changed is changed. Each mode returns the full length to
// the caller, so only a read back can tell.
type fxMode string

const (
	fxFirst    fxMode = "first byte changed"
	fxMiddle   fxMode = "middle byte changed"
	fxLast     fxMode = "last byte changed"
	fxAppend   fxMode = "one byte added"
	fxTruncate fxMode = "last byte dropped"
)

var fxModes = []fxMode{fxFirst, fxMiddle, fxLast, fxAppend, fxTruncate}

// fxState is the one write that is changed: the nth write of file data (1 is the first) that goes
// through the file system.
type fxState struct {
	mu     sync.Mutex
	n      int
	target int
	mode   fxMode
	hit    bool
}

// change returns what reaches the disk for the write p.
func (s *fxState) change(p []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 0 {
		return p
	}
	s.n++
	if s.n != s.target {
		return p
	}
	s.hit = true
	q := append([]byte(nil), p...)
	switch s.mode {
	case fxFirst:
		q[0] ^= 1
	case fxMiddle:
		q[len(q)/2] ^= 1
	case fxLast:
		q[len(q)-1] ^= 1
	case fxAppend:
		q = append(q, 'x')
	case fxTruncate:
		q = q[:len(q)-1]
	}
	return q
}

// fxFS wraps a folder and changes the nth write of file data on its way to the disk.
type fxFS struct {
	in fsx.FS
	st *fxState
}

func (f *fxFS) OpenDir(name string) (fsx.FS, error) {
	d, err := f.in.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &fxFS{in: d, st: f.st}, nil
}
func (f *fxFS) Mkdir(name string, perm fs.FileMode) error { return f.in.Mkdir(name, perm) }
func (f *fxFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	file, err := f.in.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}
	return &fxFile{File: file, st: f.st}, nil
}
func (f *fxFS) RenameNoReplace(o, n string) error    { return f.in.RenameNoReplace(o, n) }
func (f *fxFS) Sync() error                          { return f.in.Sync() }
func (f *fxFS) ReadFile(name string) ([]byte, error) { return f.in.ReadFile(name) }
func (f *fxFS) ReadDir() ([]fs.DirEntry, error)      { return f.in.ReadDir() }
func (f *fxFS) Close() error                         { return f.in.Close() }

type fxFile struct {
	fsx.File
	st *fxState
}

func (f *fxFile) Write(p []byte) (int, error) {
	q := f.st.change(p)
	if _, err := f.File.Write(q); err != nil {
		return 0, err
	}
	// The caller is told that the whole write was made.
	return len(p), nil
}

// fxLie makes the run write through a file system that changes the nth write of file data, and returns
// the state that says whether the write was met.
func fxLie(t *testing.T, r *rt, target int, mode fxMode) *fxState {
	t.Helper()
	inner, err := fsx.OpenFS(r.bundleDir)
	if err != nil {
		t.Fatal(err)
	}
	rc := &rec{}
	st := &fxState{target: target, mode: mode}
	w := &fsx.Writer{FS: &fxFS{in: &spyFS{in: inner, r: rc}, st: st}}
	t.Cleanup(func() { _ = w.Close() })
	r.b = &bundle{t: t, dir: r.bundleDir, w: w, r: rc, raw: r.b.raw}
	return st
}

var fxTmpName = regexp.MustCompile(`\.rt-[a-z0-9]+`)

// fxTargets are the files that the writes of file data of a whole run reach, in order: the name of the
// file that the nth write fills (the name that its rename gives, for a temporary file).
func fxTargets(ev []string) []string {
	var out []string
	for i, e := range ev {
		if !strings.HasPrefix(e, "write ") {
			continue
		}
		path := strings.TrimPrefix(e, "write ")
		if strings.HasSuffix(path, "/(tmp)") {
			path = ""
			for _, later := range ev[i+1:] {
				if strings.HasPrefix(later, "rename ") {
					path = strings.TrimPrefix(later, "rename ")
					break
				}
			}
		}
		out = append(out, fxTmpName.ReplaceAllString(path, ".rt-X"))
	}
	return out
}

// fxBirths is a store that counts births and saves of removal files.
type fxBirths struct {
	ceremony.RootStore
	mu     sync.Mutex
	births int
	saves  int
}

func (s *fxBirths) Birth(ctx context.Context, label string) (keystore.Key, error) {
	s.mu.Lock()
	s.births++
	s.mu.Unlock()
	return s.RootStore.Birth(ctx, label)
}

func (s *fxBirths) SaveRemoval(label string, jws []byte) error {
	s.mu.Lock()
	s.saves++
	s.mu.Unlock()
	return s.RootStore.SaveRemoval(label, jws)
}

func (s *fxBirths) counts() (births, saves int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.births, s.saves
}

// fxCount makes the run open the software store wrapped in a counting store.
func fxCount(r *rt) *fxBirths {
	c := &fxBirths{}
	r.open = func(keyDir, bundleDir string) (ceremony.RootStore, error) {
		st, err := ceremony.NewSoftwareStore(keyDir, bundleDir)
		if err != nil {
			return nil, err
		}
		c.RootStore = st
		return c, nil
	}
	return c
}

// fxCopyTree copies the folder src into dst (dst is made when it is absent).
func fxCopyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// attemptOf is the attempt of a plan, as the run writes it.
func attemptOf(p *ceremony.PlanOut) files.Attempt {
	return files.Attempt{Version: files.FormatVersion, Ceremony: p.Name, PlanSHA256: p.SHA256, Root: p.Plan.Root.Label, StartedAt: "2026-11-20T10:00:03Z"}
}
