package fsx

import (
	"errors"
	"io"
	"io/fs"
)

// FS is an open folder of a file system. The root of a [Writer] is one, and so is every folder
// that [FS.OpenDir] returns. Every method works on a name inside this folder: one plain
// element, never a path and never "." or "..". The package walks a path by calling OpenDir one
// element at a time, so no implementation sees a path, and none has to refuse one.
//
// No method follows a symbolic link. [OpenFS] is the real file system; a test replaces it with
// a model that keeps the same promises, and every method says what a real file system promises
// and what a cut (a power loss, a pulled stick, a killed process) can leave.
type FS interface {
	// OpenDir opens the folder name of this folder and returns a handle on it, which the
	// caller closes. It creates nothing, writes nothing and flushes nothing, so a cut leaves
	// everything as it was. It fails with an error that wraps fs.ErrNotExist when name does
	// not exist, and with one that is not fs.ErrNotExist when name is a file, or a symbolic
	// link (the link is not followed, and the error wraps [ErrLink]).
	OpenDir(name string) (FS, error)
	// Mkdir makes the empty folder name in this folder. It fails with an error that wraps
	// fs.ErrExist when anything holds that name: a file, a folder, a symbolic link, also a
	// dangling one. The folder is there for the processes that run, whole (empty) or not
	// at all; the name is in the folder's list on the disk only after [FS.Sync] of this
	// folder, so a cut before that flush can lose the new folder.
	Mkdir(name string, perm fs.FileMode) error
	// CreateExcl creates the empty file name in this folder for writing, and fails with an
	// error that wraps fs.ErrExist when anything holds that name: a file, a folder, a
	// symbolic link, also a dangling one (it never follows a link to create the file behind
	// it). The name is in the folder's list on the disk only after [FS.Sync] of this folder,
	// and the data written through the returned [File] is on the disk only after the file's
	// Sync: a cut before the flush of the data can leave the name with any prefix of the
	// bytes written, none of them included, and a cut before the flush of the folder can
	// lose the name.
	CreateExcl(name string, perm fs.FileMode) (File, error)
	// RenameNoReplace renames oldName to newName, both in this folder, and fails with an
	// error that wraps fs.ErrExist when anything holds newName (nothing then changes: both
	// names stay as they were), and with one that wraps fs.ErrNotExist when oldName does not
	// exist. It never falls back to a rename that replaces: when the system or the file
	// system cannot refuse to replace, it changes nothing and returns an error that wraps
	// [ErrNoReplaceUnsupported]. Seen by the processes that run, the rename is one step. What
	// a cut leaves depends on the file system: the file under the old name or under the new
	// one, and, until [FS.Sync] of this folder has returned, either of the two; on a file
	// system without an atomic rename (the package comment says what is not proven for a
	// stick) another state can remain.
	RenameNoReplace(oldName, newName string) error
	// Sync flushes this folder: the names that were made or renamed in it before the call
	// are on the disk when it returns without an error. A cut before it can lose any of
	// those names, each on its own. After an error nothing is known about what reached the
	// disk.
	Sync() error
	// ReadFile returns the whole content of the regular file name of this folder, as the
	// running system shows it, flushed or not. It fails for a name that is a symbolic link (the
	// error wraps [ErrLink]), for anything that is not a regular file (a folder, a FIFO, a
	// device, a socket: the error wraps [ErrNotRegular], and a FIFO is not waited on), and for a
	// file longer than [MaxReadSize] (the error wraps [ErrTooLarge]); it never returns a part
	// of a file. A name that does not exist gives an error that wraps fs.ErrNotExist.
	ReadFile(name string) ([]byte, error)
	// ReadDir lists this folder: one entry for each name in it, ordered by name, without "."
	// and "..", and including the names of temporary files and folders that a stop left. An
	// entry is described as the folder holds it, never as what a link points at: a symbolic
	// link is an entry with the type fs.ModeSymlink, a folder one with fs.ModeDir. The Info of
	// an entry carries the name, the type and permission bits and the size at the time of the
	// call; its ModTime is the zero time. It lists what the running system shows, flushed or
	// not.
	ReadDir() ([]fs.DirEntry, error)
	// Close releases this handle. A method called after Close returns an error that wraps
	// fs.ErrClosed, and a second Close returns nil. Closing a folder closes nothing that
	// was opened from it.
	Close() error
}

// MaxReadSize is the longest file that [FS.ReadFile], [ReadFile] and [ReadJournal] read: 8 MiB.
// The files that the package reads are the journals of a ceremony, one line for each event, a
// few hundred bytes a line and a few dozen lines for a whole ceremony, so some tens of
// kilobytes. 8 MiB is hundreds of times that, and still small enough to hold in memory at once
// on any machine that can run a ceremony. A file beyond it is not a journal of this program, a
// longer file is an error and never a cut-off read, and the limit stops a file that grows
// without end (a device, a file on a full-speed writer) from filling the memory.
const MaxReadSize = 8 << 20

// File is a file opened for writing by [FS.CreateExcl]. The file is empty when it is created,
// and a Write adds to the end of it.
type File interface {
	io.Writer
	// Sync flushes the data of the file.
	Sync() error
	// Close releases the file.
	Close() error
}

// Step names the step of the write that failed.
type Step string

// The steps. They follow the table of "How a file is written" in docs/reference/bundle.md,
// with one before them, the walk to the folder, and one beside them, the read.
const (
	// StepOpenDir is the walk from the root to the folder of a path, one element at a
	// time. Path is the path up to and including the element that failed.
	StepOpenDir Step = "open-dir"
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
	// StepRead is the read of a file or of a folder's list. A failed read does not stop a
	// writer: it changes nothing.
	StepRead Step = "read"
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
// or the file system cannot refuse. There is no fallback to a rename that replaces. On a
// system that has no rooted file system at all, [OpenFS] returns it too: the writer cannot do
// its steps there.
var ErrNoReplaceUnsupported = errors.New("the file system does not support a rename that refuses to replace")

// ErrLink is wrapped by the error of a walk or a read that met a symbolic link where the writer
// needs a folder or a file. The package follows no symbolic link below the root, in any element
// of a path and at the final name, for any operation.
var ErrLink = errors.New("a symbolic link is not followed")

// ErrNotRegular is wrapped by the error of a read of anything that is not a regular file: a
// folder, a FIFO, a device, a socket. A symbolic link is [ErrLink].
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge is wrapped by the error of a read of a file longer than [MaxReadSize].
var ErrTooLarge = errors.New("the file is longer than the limit of a read")

// ErrNoRoot is returned by a [Writer] that has no [FS], that is by a Writer that was not made
// by [Open] and whose FS field is nil: there is no root to work in, and the writer does not
// reach for another one.
var ErrNoRoot = errors.New("fsx: the writer has no root folder")

// ErrWriterClosed is returned by every call of a [Writer] after [Writer.Close].
var ErrWriterClosed = errors.New("fsx: the writer is closed")

// ErrInvalid is wrapped by the error returned for an argument the writer refuses before it
// touches the file system. A path is relative to the root and has "/" as its separator. For a
// path: it is empty, it is absolute (it starts with a separator), ends with a separator, has a
// "." or ".." element or an empty element ("a//b"), or its final element has the prefix of a
// temporary name (compared without case; a path that is only read may have it). For a name (any
// element of a path, and the name of a file of a set): the exFAT file system of a stick cannot
// hold it or holds it under another name (a control code or one of the characters " * / : < > ?
// \ |; an end with a dot or a space; a length over 255 bytes; bytes that are not UTF-8), or it
// has a character that is not printable in the sense of unicode.IsPrint (U+007F, a format
// character such as U+200B, a space such as U+00A0, a private use or unassigned code point), or
// a desktop system cannot open it (a device name of Windows, "aux" or "Aux.json"). A name of a
// set must also be one plain name; a mode must have no bits beyond the permission bits; a
// journal line must hold no newline. Such an error does not stop the writer, and every text of
// it quotes the path or the name it names, so that a control code in it cannot reach a terminal.
var ErrInvalid = errors.New("fsx: invalid argument")

// ErrClosed is returned by a journal that was closed.
var ErrClosed = errors.New("fsx: journal is closed")
