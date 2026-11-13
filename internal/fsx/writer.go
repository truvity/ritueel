package fsx

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
)

// TempPrefix starts every temporary name. The records say "a fixed prefix" and not which
// one (record 0006, rule 32); this one is proposed (issue 8). The name starts with a dot,
// so a listing that hides dot files hides it.
const TempPrefix = ".rt-"

// tempLen is the length of a temporary name: record 0006, rule 32, says at most 15, so
// that the rename never shortens a folder entry on exFAT.
const tempLen = 15

const tempAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// A byte below tempSpan maps to the alphabet without bias (252 is 7 times 36).
const tempSpan = 252

// tempDraws bounds the reads of one temporary name, so that a reader that never gives a
// usable byte ends in an error and not in a loop.
const tempDraws = 64

// dirPerm is the mode of a folder made by WriteSet: the owner only.
const dirPerm fs.FileMode = 0o700

// journalPerm is the mode of a journal: the owner only.
const journalPerm fs.FileMode = 0o600

// Writer adds files to a bundle. The first error stops it: every later operation of the
// writer and of its journals returns that same error and does not reach the file system
// (record 0006, rule 33; the reading that nothing may follow a failed write is proposed).
// An argument that the writer refuses before any file system call (see [ErrInvalid]) is not
// an error of that kind and does not stop it. The writer never retries and never deletes
// a temporary file or folder.
//
// A Writer is safe for use by several goroutines: every method, and every method of its
// journals, takes the writer's lock, so the operations run one at a time and the stop is read
// and set under it. The lock belongs to one Writer and covers the FS and the Rand it reads: a
// Rand that is shared with another Writer or another goroutine needs a lock of its own, and FS
// and Rand are set before the first call and are not changed after it.
type Writer struct {
	// FS is the file system; nil means [OS].
	FS FS
	// Rand supplies the random part of temporary names; nil means crypto/rand. The writer reads
	// it only while it holds its lock.
	Rand io.Reader

	mu  sync.Mutex
	err error // the stop; set once
}

// NewFile is one file of a set written by [Writer.WriteSet]. Name is one plain name.
type NewFile struct {
	Name string
	Data []byte
	Perm fs.FileMode
}

func (w *Writer) fsys() FS {
	if w.FS == nil {
		return OS
	}
	return w.FS
}

func (w *Writer) rand() io.Reader {
	if w.Rand == nil {
		return rand.Reader
	}
	return w.Rand
}

// stop records the first error and returns it.
func (w *Writer) stop(step Step, path string, err error) error {
	e := &Error{Step: step, Path: path, Err: err}
	w.err = e
	return e
}

// TempName draws one temporary name: TempPrefix and lower-case letters and digits, 15
// characters in all. It does not carry any final name. It reads only the random source and
// does not reach the file system. Like every other method it takes the writer's lock, so a
// call beside a write on the same writer does not read the random source at the same time.
func (w *Writer) TempName() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tempName()
}

// tempName is TempName for a caller that holds the lock.
func (w *Writer) tempName() (string, error) {
	n := tempLen - len(TempPrefix)
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for draws := 0; len(out) < n; draws++ {
		if draws == tempDraws {
			return "", errors.New("fsx: the random source gave no usable bytes for a temporary name")
		}
		if _, err := io.ReadFull(w.rand(), buf); err != nil {
			return "", fmt.Errorf("fsx: random part of a temporary name: %w", err)
		}
		for _, b := range buf {
			if b < tempSpan && len(out) < n {
				out = append(out, tempAlphabet[int(b)%len(tempAlphabet)])
			}
		}
	}
	return TempPrefix + string(out), nil
}

// WriteFile adds one file (steps 1 to 4 of "How a file is written"): the whole content under
// a temporary name in the same folder, a flush of the file, a rename to path that refuses to
// replace, a flush of the folder. path must not exist: when it does, the error wraps
// fs.ErrExist (Step rename), the file at path is unchanged and the temporary file is left.
// A cut before the rename leaves nothing at path; a cut after it leaves the whole content.
func (w *Writer) WriteFile(path string, data []byte, perm fs.FileMode) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if err := checkPath(path); err != nil {
		return err
	}
	if err := checkPerm(perm); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := w.tempPath(dir)
	if err != nil {
		return err
	}
	if err := w.writeNew(tmp, data, perm); err != nil {
		return err
	}
	if err := w.fsys().RenameNoReplace(tmp, path); err != nil {
		return w.stop(StepRename, path, err)
	}
	if err := w.fsys().SyncDir(dir); err != nil {
		return w.stop(StepSyncDir, dir, err)
	}
	return nil
}

// WriteSet adds a folder of files (step 5): the folder is made beside finalDir under one
// temporary name, each file is written and flushed in it, the folder is flushed, it is
// renamed to finalDir by a rename that refuses to replace, and the parent is flushed. The
// files are written at their own names inside the temporary folder; the folder becomes
// visible under finalDir only after every file is whole. When finalDir exists the error
// wraps fs.ErrExist (Step rename) and the temporary folder is left. The folder is made with
// mode 0700.
func (w *Writer) WriteSet(finalDir string, files []NewFile) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if err := checkPath(finalDir); err != nil {
		return err
	}
	if err := checkFiles(files); err != nil {
		return err
	}
	parent := filepath.Dir(finalDir)
	tmp, err := w.tempPath(parent)
	if err != nil {
		return err
	}
	if err := w.fsys().Mkdir(tmp, dirPerm); err != nil {
		return w.stop(StepMkdir, tmp, err)
	}
	for _, f := range files {
		if err := w.writeNew(filepath.Join(tmp, f.Name), f.Data, f.Perm); err != nil {
			return err
		}
	}
	if err := w.fsys().SyncDir(tmp); err != nil {
		return w.stop(StepSyncDir, tmp, err)
	}
	if err := w.fsys().RenameNoReplace(tmp, finalDir); err != nil {
		return w.stop(StepRename, finalDir, err)
	}
	if err := w.fsys().SyncDir(parent); err != nil {
		return w.stop(StepSyncDir, parent, err)
	}
	return nil
}

// Mkdir makes a folder at its final name (a ceremony folder) and flushes the parent. The
// folder is empty and complete at once, so it needs no temporary name. It fails when the
// folder exists.
func (w *Writer) Mkdir(path string, perm fs.FileMode) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if err := checkPath(path); err != nil {
		return err
	}
	if err := checkPerm(perm); err != nil {
		return err
	}
	if err := w.fsys().Mkdir(path, perm); err != nil {
		return w.stop(StepMkdir, path, err)
	}
	parent := filepath.Dir(path)
	if err := w.fsys().SyncDir(parent); err != nil {
		return w.stop(StepSyncDir, parent, err)
	}
	return nil
}

// tempPath draws a temporary name in dir. The error of the draw stops the writer. A final
// name never starts with TempPrefix (checkPath), so the two cannot be equal.
func (w *Writer) tempPath(dir string) (string, error) {
	name, err := w.tempName()
	if err != nil {
		return "", w.stop(StepCreate, filepath.Join(dir, TempPrefix), err)
	}
	return filepath.Join(dir, name), nil
}

// writeNew creates path exclusively, writes data, flushes and closes it. Each failure
// stops the writer. After a failure the open file is closed without a further flush.
func (w *Writer) writeNew(path string, data []byte, perm fs.FileMode) error {
	f, err := w.fsys().CreateExcl(path, perm)
	if err != nil {
		return w.stop(StepCreate, path, err)
	}
	if len(data) > 0 {
		n, err := f.Write(data)
		if err == nil && n < len(data) {
			err = io.ErrShortWrite
		}
		if err != nil {
			_ = f.Close()
			return w.stop(StepWrite, path, err)
		}
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return w.stop(StepSyncFile, path, err)
	}
	if err := f.Close(); err != nil {
		return w.stop(StepSyncFile, path, err)
	}
	return nil
}

// checkPath refuses a path that can mean more than one thing, or something other than a name
// the caller can point at. The forms, all refused with [ErrInvalid]: an empty path; a NUL byte;
// a trailing separator (filepath.Dir and filepath.Base of "dir/x/" both give "x", so the file
// would be made inside x); an element that is "." or ".." ; an empty element between two
// separators ("a//b", and a leading "//", which some systems read as a network name); on a
// system whose separator is not a backslash, a backslash (a separator to Windows and to a
// FAT or exFAT stick, a plain character here) and a leading drive ("C:", "C:x"); a final
// element that starts with [TempPrefix]. One leading separator, an absolute path, is
// accepted: the writer has no root (see the package comment). Other forms pass as they are,
// among them a relative path with no folder ("x", whose folder is ".").
func checkPath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrInvalid)
	}
	if strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("%w: path %q has a NUL byte", ErrInvalid, path)
	}
	rest := path[len(filepath.VolumeName(path)):]
	if filepath.Separator != '\\' {
		if strings.IndexByte(rest, '\\') >= 0 {
			return fmt.Errorf("%w: path %q has a backslash", ErrInvalid, path)
		}
		if len(rest) >= 2 && rest[1] == ':' && (rest[0]|0x20 >= 'a' && rest[0]|0x20 <= 'z') {
			return fmt.Errorf("%w: path %q starts with a drive", ErrInvalid, path)
		}
	}
	elems := strings.Split(filepath.ToSlash(rest), "/")
	last := len(elems) - 1
	if last == 0 && elems[0] == "" {
		return fmt.Errorf("%w: path %q does not name a file or a folder", ErrInvalid, path)
	}
	if last > 0 && elems[last] == "" {
		return fmt.Errorf("%w: path %q ends with a separator", ErrInvalid, path)
	}
	for i, e := range elems {
		switch e {
		case "":
			if i != 0 { // a leading separator is the one empty element that is allowed
				return fmt.Errorf("%w: path %q has an empty element (a doubled separator)", ErrInvalid, path)
			}
		case ".":
			return fmt.Errorf("%w: path %q has a \".\" element", ErrInvalid, path)
		case "..":
			return fmt.Errorf("%w: path %q has a \"..\" element", ErrInvalid, path)
		}
	}
	if strings.HasPrefix(elems[last], TempPrefix) {
		return fmt.Errorf("%w: path %q has the prefix of a temporary name", ErrInvalid, path)
	}
	return nil
}

func checkPerm(perm fs.FileMode) error {
	if perm&^fs.ModePerm != 0 {
		return fmt.Errorf("%w: mode %v has bits beyond the permission bits", ErrInvalid, perm)
	}
	return nil
}

func checkFiles(files []NewFile) error {
	seen := make(map[string]bool, len(files))
	for _, f := range files {
		if f.Name == "" || f.Name == "." || f.Name == ".." ||
			strings.ContainsAny(f.Name, "/\\\x00") || strings.HasPrefix(f.Name, TempPrefix) {
			return fmt.Errorf("%w: file name %q is not one plain name", ErrInvalid, f.Name)
		}
		// Case-folded, because a name that differs only by case is one entry on exFAT.
		key := strings.ToLower(f.Name)
		if seen[key] {
			return fmt.Errorf("%w: file name %q is given twice", ErrInvalid, f.Name)
		}
		seen[key] = true
		if err := checkPerm(f.Perm); err != nil {
			return err
		}
	}
	return nil
}
