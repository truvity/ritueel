package fsx

import (
	"errors"
	"io"
	"io/fs"
)

// FS is the part of a file system the writer uses. [OS] is the real one; tests wrap it or
// replace it.
type FS interface {
	// Mkdir makes one folder and fails when it exists.
	Mkdir(path string, perm fs.FileMode) error
	// CreateExcl creates a file that must not exist (O_CREATE|O_EXCL|O_WRONLY).
	CreateExcl(path string, perm fs.FileMode) (File, error)
	// RenameNoReplace renames a file or a folder and returns an error that wraps
	// fs.ErrExist when newpath exists. It never falls back to a rename that replaces.
	RenameNoReplace(oldpath, newpath string) error
	// SyncDir opens the folder and flushes it.
	SyncDir(path string) error
	// ReadDir lists a folder.
	ReadDir(path string) ([]fs.DirEntry, error)
	// ReadFile reads a whole file.
	ReadFile(path string) ([]byte, error)
	// Stat describes a file or a folder.
	Stat(path string) (fs.FileInfo, error)
}

// File is a file opened for writing by [FS.CreateExcl].
type File interface {
	io.Writer
	// Sync flushes the data of the file.
	Sync() error
	// Close releases the file.
	Close() error
}

// Step names the step of the write that failed.
type Step string

// The steps. They follow the table of "How a file is written" in docs/reference/bundle.md.
const (
	// StepMkdir is the making of a folder.
	StepMkdir Step = "mkdir"
	// StepCreate is the exclusive creation of a file (or the draw of a temporary name).
	StepCreate Step = "create"
	// StepWrite is the write of the content, or of a journal line.
	StepWrite Step = "write"
	// StepSyncFile is the flush of a file, and the close that ends it.
	StepSyncFile Step = "sync-file"
	// StepRename is the rename of a temporary name to the final name.
	StepRename Step = "rename"
	// StepSyncDir is the flush of a folder.
	StepSyncDir Step = "sync-dir"
)

// Error is the error of a failed step. Path is the path given to the failed call: the
// temporary name for a create, a write and a flush of a file, the final name for a rename
// (the temporary name is then the path that was left behind), the folder for a folder
// flush. Err is what the file system returned; errors.Is(err, fs.ErrExist) works through
// Unwrap.
type Error struct {
	Step Step
	Path string
	Err  error
}

// Error describes the failed step.
func (e *Error) Error() string {
	return "fsx: " + string(e.Step) + " " + e.Path + ": " + e.Err.Error()
}

// Unwrap returns Err.
func (e *Error) Unwrap() error { return e.Err }

// ErrNoReplaceUnsupported is returned by a rename that refuses to replace when the system
// or the file system cannot refuse. There is no fallback to a rename that replaces.
var ErrNoReplaceUnsupported = errors.New("the file system does not support a rename that refuses to replace")

// ErrInvalid is wrapped by the error returned for an argument the writer refuses before it
// touches the file system. For a path: it is empty, ends with a separator, has a "." or ".."
// element or an empty element ("a//b"), or its final element has the prefix of a temporary
// name (compared without case). For a name (any element of a path, and the name of a file of
// a set): the exFAT file system of a stick cannot hold it or holds it under another name (a
// control code or one of the characters " * / : < > ? \ |; an end with a dot or a space; a
// length over 255 bytes; bytes that are not UTF-8), or no person can see or type a
// character of it (U+007F, U+0080 to U+009F, U+FFFE, U+FFFF), or a desktop system cannot open
// it (a device name of Windows, "aux" or "Aux.json"). A name of a set must also be one plain
// name; a mode must have no bits beyond the permission bits; a journal line must hold no
// newline. Such an error does not stop the writer.
var ErrInvalid = errors.New("fsx: invalid argument")

// ErrClosed is returned by a journal that was closed.
var ErrClosed = errors.New("fsx: journal is closed")
