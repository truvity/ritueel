package fsx_test

// Writers that are wrong on purpose. Each does the steps of a file in a wrong order (or
// leaves one out) over the same fsx.FS as the real writer. They are the negative controls of
// the cut test: the oracle must fail for every one of them.

import (
	"io"
	"io/fs"
	"math/rand/v2"
	"path"
	"path/filepath"

	"ritueel.id/ritueel/internal/fsx"
)

// newDetRand is a random source that repeats from run to run.
func newDetRand(seed byte) io.Reader {
	var k [32]byte
	k[0] = seed
	return rand.NewChaCha8(k)
}

type wrongMode int

const (
	// The file is renamed to its final name before it is flushed; the folder is flushed last.
	wrongRenameBeforeFileSync wrongMode = iota + 1
	// The rename and the flush of the folder both come before the flush of the file.
	wrongFolderFlushBeforeFileFlush
	// The folder is not flushed after the rename.
	wrongNoFolderFlush
	// Every file is written straight at its final name.
	wrongDirectFinal
	// Only the attempt is written straight at its final name; the rest use the real steps.
	wrongDirectAttempt
	// The temporary name is the final name and a suffix, longer than 15 characters.
	wrongTempIsFinalPlusSuffix
	// A set is built in place at its final name, file by file.
	wrongSetInPlace
	// A journal line is written and not flushed.
	wrongJournalNoFlush
)

type wrongWriter struct {
	fsys fsx.FS
	good *fsx.Writer
	mode wrongMode
}

func newWrongMaker(mode wrongMode) func(*memFS) bundleWriter {
	return func(f *memFS) bundleWriter {
		return &wrongWriter{fsys: f, good: &fsx.Writer{FS: f, Rand: newDetRand(2)}, mode: mode}
	}
}

func (w *wrongWriter) Mkdir(p string, perm fs.FileMode) error { return w.good.Mkdir(p, perm) }

func (w *wrongWriter) WriteFile(p string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(p)
	temp := func() string {
		n, err := w.good.TempName()
		if err != nil {
			panic(err)
		}
		return path.Join(dir, n)
	}
	switch w.mode {
	case wrongRenameBeforeFileSync:
		return w.exec(temp(), p, data, perm, "write", "rename", "sync", "close", "syncdir")
	case wrongFolderFlushBeforeFileFlush:
		return w.exec(temp(), p, data, perm, "write", "rename", "syncdir", "sync", "close")
	case wrongNoFolderFlush:
		return w.exec(temp(), p, data, perm, "write", "sync", "close", "rename")
	case wrongDirectFinal:
		return w.exec(p, p, data, perm, "write", "sync", "close", "syncdir")
	case wrongDirectAttempt:
		if path.Base(p) == "attempt.json" {
			return w.exec(p, p, data, perm, "write", "sync", "close", "syncdir")
		}
		return w.good.WriteFile(p, data, perm)
	case wrongTempIsFinalPlusSuffix:
		suffix := temp()
		suffix = "." + path.Base(suffix)[len(fsx.TempPrefix):] // eleven characters
		return w.exec(p+suffix, p, data, perm, "write", "sync", "close", "rename", "syncdir")
	}
	return w.good.WriteFile(p, data, perm)
}

// exec creates first, then does the listed steps in that order. A rename moves first to final.
func (w *wrongWriter) exec(first, final string, data []byte, perm fs.FileMode, steps ...string) error {
	f, err := w.fsys.CreateExcl(first, perm)
	if err != nil {
		return err
	}
	for _, s := range steps {
		switch s {
		case "write":
			_, err = f.Write(data)
		case "sync":
			err = f.Sync()
		case "close":
			err = f.Close()
		case "rename":
			err = w.fsys.RenameNoReplace(first, final)
		case "syncdir":
			err = w.fsys.SyncDir(filepath.Dir(final))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (w *wrongWriter) WriteSet(finalDir string, files []fsx.NewFile) error {
	if w.mode != wrongSetInPlace {
		return w.good.WriteSet(finalDir, files)
	}
	if err := w.good.Mkdir(finalDir, 0o700); err != nil {
		return err
	}
	for _, f := range files {
		if err := w.good.WriteFile(path.Join(finalDir, f.Name), f.Data, f.Perm); err != nil {
			return err
		}
	}
	return nil
}

func (w *wrongWriter) CreateJournal(p string) (journal, error) {
	if w.mode != wrongJournalNoFlush {
		return realWriter{w.good}.CreateJournal(p)
	}
	f, err := w.fsys.CreateExcl(p, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := w.fsys.SyncDir(filepath.Dir(p)); err != nil {
		return nil, err
	}
	return &unflushedJournal{f: f}, nil
}

type unflushedJournal struct{ f fsx.File }

func (j *unflushedJournal) Append(line []byte) error {
	_, err := j.f.Write(append(append([]byte{}, line...), '\n'))
	return err
}

func (j *unflushedJournal) Close() error { return j.f.Close() }
