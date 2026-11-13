package fsx_test

// Writers that are wrong on purpose. Each does the steps of a file in a wrong order (or
// leaves one out) over the same fsx.FS as the real writer. They are the negative controls of
// the cut test: the oracle must fail for every one of them.

import (
	"io/fs"
	"path"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
)

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
	root fsx.FS      // its own root handle: the wrong steps are done through folder handles
	good *fsx.Writer // the real writer, over another root handle of the same file system
	mode wrongMode
}

func newWrongMaker(mode wrongMode) func(*memFS) bundleWriter {
	return func(f *memFS) bundleWriter {
		return &wrongWriter{root: f.Root(), good: &fsx.Writer{FS: f.Root(), Rand: newDetRand(2)}, mode: mode}
	}
}

// in walks to the folder dir of the root, one element at a time, and leaves the handles open
// (a wrong writer is allowed to).
func (w *wrongWriter) in(dir string) fsx.FS {
	d := w.root
	if dir == "." || dir == "" {
		return d
	}
	for _, e := range strings.Split(dir, "/") {
		n, err := d.OpenDir(e)
		if err != nil {
			panic(err)
		}
		d = n
	}
	return d
}

func splitPath(p string) (dir, base string) {
	dir, base = path.Split(p)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		dir = "."
	}
	return dir, base
}

func (w *wrongWriter) Mkdir(p string, perm fs.FileMode) error { return w.good.Mkdir(p, perm) }

func (w *wrongWriter) WriteFile(p string, data []byte, perm fs.FileMode) error {
	dir, base := splitPath(p)
	d := w.in(dir)
	temp := func() string {
		n, err := w.good.TempName()
		if err != nil {
			panic(err)
		}
		return n
	}
	switch w.mode {
	case wrongRenameBeforeFileSync:
		return w.exec(d, temp(), base, data, perm, "write", "rename", "sync", "close", "syncdir")
	case wrongFolderFlushBeforeFileFlush:
		return w.exec(d, temp(), base, data, perm, "write", "rename", "syncdir", "sync", "close")
	case wrongNoFolderFlush:
		return w.exec(d, temp(), base, data, perm, "write", "sync", "close", "rename")
	case wrongDirectFinal:
		return w.exec(d, base, base, data, perm, "write", "sync", "close", "syncdir")
	case wrongDirectAttempt:
		if base == "attempt.json" {
			return w.exec(d, base, base, data, perm, "write", "sync", "close", "syncdir")
		}
		return w.good.WriteFile(p, data, perm)
	case wrongTempIsFinalPlusSuffix:
		suffix := "." + temp()[len(fsx.TempPrefix):] // eleven characters
		return w.exec(d, base+suffix, base, data, perm, "write", "sync", "close", "rename", "syncdir")
	}
	return w.good.WriteFile(p, data, perm)
}

// exec creates first, then does the listed steps in that order. A rename moves first to final.
func (w *wrongWriter) exec(d fsx.FS, first, final string, data []byte, perm fs.FileMode, steps ...string) error {
	f, err := d.CreateExcl(first, perm)
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
			err = d.RenameNoReplace(first, final)
		case "syncdir":
			err = d.Sync()
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
		j, err := w.good.CreateJournal(p)
		if err != nil {
			return nil, err
		}
		return j, nil
	}
	dir, base := splitPath(p)
	d := w.in(dir)
	f, err := d.CreateExcl(base, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	if err := d.Sync(); err != nil {
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
