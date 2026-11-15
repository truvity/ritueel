//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// Helpers of the tests of Find, MakePlan and ReadPlanOut. The names of this file start with pf.

// The wanted files of a bundle that the first apply of a test root starts from. Each is accepted by
// its reader.
const (
	pfSettings = `version: 1
name: Example
release_address: release@example.org
policy:
  stores: [piv, openpgp-card, aws-kms, software]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`
	pfPersonal = `version: 1
kind: personal
person:
  name: Example Person
  address: person@example.org
policy:
  stores: [piv]
  min_firmware: 5.7.0
  pin_policy: [once]
  require_name_constraints: true
  validity_months: 13
`
	pfX509Test    = "version: 1\nkind: x509\ntest: true\n"
	pfX509Real    = "version: 1\nkind: x509\ntest: false\n"
	pfX509NoTest  = "version: 1\nkind: x509\n"
	pfOpenPGPTest = "version: 1\nkind: openpgp\ntest: true\n"
	pfSSHTest     = "version: 1\nkind: ssh\ntest: true\n"
)

// pfLeftOutReason is the reason that a request has in leaves_out, spelled out here.
const pfLeftOutReason = "a change of the root keys runs alone (record 0007, rule 9)"

// pfClock is the instant of the golden plan: 2026-11-20 at 10:00:00 UTC.
var pfClock = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

const pfName = "20261120T100000Z-apply"

// pfFiles is the file set of a first-apply bundle with one X.509 test root.
func pfFiles() map[string]string {
	return map[string]string{
		"ritueel.yaml":         pfSettings,
		"want/roots/x509.yaml": pfX509Test,
	}
}

// pfWrite makes a bundle folder with the files given, through the operating system, and returns it.
func pfWrite(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, text := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// pfOpen opens a folder through package fsx and closes it at the end of the test.
func pfOpen(t testing.TB, dir string) fsx.FS {
	t.Helper()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsys.Close() })
	return fsys
}

// pfFind runs Find on a folder of the disk.
func pfFind(t testing.TB, dir string) (*ceremony.Found, error) {
	t.Helper()
	return ceremony.Find(context.Background(), ceremony.FindInput{FS: pfOpen(t, dir)})
}

// pfMustFind runs Find on a first-apply bundle and fails when it does not give changes.
func pfMustFind(t testing.TB, files map[string]string) *ceremony.Found {
	t.Helper()
	f, err := pfFind(t, pfWrite(t, files))
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if f.Nothing() {
		t.Fatal("Find found nothing to apply")
	}
	return f
}

// pfEnv is the Env of the golden plan: the fixed clock, a counter for the serials and a fixed program.
func pfEnv() ceremony.Env {
	return ceremony.Env{
		Now:  func() time.Time { return pfClock },
		Rand: &pfCounter{},
		Self: pfSelf,
	}
}

// pfProgram is the program of the golden plan.
var pfProgram = buildinfo.Program{Version: "v0.0.0-test", OSArch: "linux/amd64", SHA256: strings.Repeat("ab", 32)}

func pfSelf() (buildinfo.Program, error) { return pfProgram, nil }

// pfCounter is a source of random bytes that counts: byte i of the stream is the number of bytes read
// before it, plus one, modulo 251. Every read gives the same bytes in the same order.
type pfCounter struct{ n int }

func (c *pfCounter) Read(p []byte) (int, error) {
	for i := range p {
		c.n++
		p[i] = byte(c.n%251) + 1
	}
	return len(p), nil
}

// pfPlan makes the plan of a first-apply bundle.
func pfPlan(t testing.TB, files map[string]string) *ceremony.PlanOut {
	t.Helper()
	f := pfMustFind(t, files)
	p, err := ceremony.MakePlan(f, pfEnv())
	if err != nil {
		t.Fatalf("MakePlan: %v", err)
	}
	return p
}

// pfKind says which of the errors of the package an error is.
func pfKind(err error) string {
	var usage *ceremony.UsageError
	var refused *ceremony.RefusedError
	var backend *ceremony.BackendError
	switch {
	case err == nil:
		return "none"
	case errors.As(err, &usage):
		return "usage"
	case errors.As(err, &refused):
		return "refused"
	case errors.As(err, &backend):
		return "backend"
	case errors.Is(err, ceremony.ErrNotConfirmed):
		return "not-confirmed"
	case errors.Is(err, ceremony.ErrNotBuilt):
		return "not-built"
	case errors.Is(err, ceremony.ErrNotFirst):
		return "not-first"
	}
	return "failure"
}

// pfPrintable reports whether s is printable ASCII on one line.
func pfPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// pfHistoryReasons are the reasons that the check of the history gives for a folder.
func pfHistoryReasons(t testing.TB, dir string) []string {
	t.Helper()
	rep, err := history.Check(context.Background(), pfOpen(t, dir))
	if err != nil {
		t.Fatalf("history.Check: %v", err)
	}
	var out []string
	for _, c := range rep.Reasons() {
		out = append(out, string(c))
	}
	return out
}

// pfFIFO makes a FIFO at path.
func pfFIFO(t testing.TB, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A bundle folder in memory, as an fsx.FS that can be read and never changed, for what a real file
// system cannot hold or what is too slow to make on disk, and for the fuzz targets.

type pfNode struct {
	kind    string // "dir", "file", "link", "fifo"
	data    []byte
	long    bool // a file longer than fsx.MaxReadSize
	kids    map[string]*pfNode
	readErr error
}

func pfNewDir() *pfNode { return &pfNode{kind: "dir", kids: map[string]*pfNode{}} }

// pfMem builds a memory bundle from a map of paths to text.
func pfMem(files map[string]string) *pfNode {
	root := pfNewDir()
	for p, text := range files {
		root.put(p, &pfNode{kind: "file", data: []byte(text)})
	}
	return root
}

func (m *pfNode) put(p string, n *pfNode) {
	elems := strings.Split(p, "/")
	cur := m
	for _, e := range elems[:len(elems)-1] {
		next, ok := cur.kids[e]
		if !ok {
			next = pfNewDir()
			cur.kids[e] = next
		}
		cur = next
	}
	cur.kids[elems[len(elems)-1]] = n
}

type pfFS struct{ n *pfNode }

var errPfReadOnly = errors.New("the memory file system is read only")

func (f pfFS) OpenDir(name string) (fsx.FS, error) {
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
	return pfFS{k}, nil
}

func (f pfFS) ReadFile(name string) ([]byte, error) {
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

type pfEntry struct{ name, kind string }

func (e pfEntry) Name() string { return e.name }
func (e pfEntry) IsDir() bool  { return e.kind == "dir" }
func (e pfEntry) Type() fs.FileMode {
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
func (e pfEntry) Info() (fs.FileInfo, error) { return nil, errors.New("no info") }

func (f pfFS) ReadDir() ([]fs.DirEntry, error) {
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
		out = append(out, pfEntry{n, f.n.kids[n].kind})
	}
	return out, nil
}

func (f pfFS) Mkdir(string, fs.FileMode) error                  { return errPfReadOnly }
func (f pfFS) CreateExcl(string, fs.FileMode) (fsx.File, error) { return nil, errPfReadOnly }
func (f pfFS) RenameNoReplace(string, string) error             { return errPfReadOnly }
func (f pfFS) Sync() error                                      { return errPfReadOnly }
func (f pfFS) Close() error                                     { return nil }

var _ io.Reader = (*pfCounter)(nil)
