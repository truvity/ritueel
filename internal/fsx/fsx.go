package fsx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"unicode/utf8"
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
	// not. A folder with more than [MaxDirEntries] names is an error that wraps [ErrTooMany],
	// and no part of the list is returned.
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

// MaxJournalLines is the most lines that [ReadJournal] returns: 65,536. A journal of a ceremony has
// a line for each event, a few dozen in all; 65,536 is a thousand times that. The limit is on the
// number of lines and not only on the bytes, because each line costs a slice header of 24
// bytes in the result: a file of [MaxReadSize] bytes that is nothing but line breaks would be
// 8.4 million lines and over half a gigabyte. With the limit the worst case of a call is the buffer of
// the file (at most [MaxReadSize], and up to twice that while the read grows it) and 24 bytes for
// each of the [MaxJournalLines] lines, 1.5 MiB. A journal with more lines is an error that wraps
// [ErrTooMany], and nothing of it is returned.
const MaxJournalLines = 1 << 16

// MaxDirEntries is the most names that [FS.ReadDir] and [ReadDir] list: 65,536. A folder of a
// bundle holds some hundreds of names at most; 65,536 is hundreds of times that. A name is at
// most 255 bytes on any file system that the package meets, so the worst case of a list is about
// 18 MiB for the names (255 bytes and a 16-byte string header each) and about 7 MiB for the
// entries built from them, some 25 MiB in all, whatever the folder holds. A folder with more
// names is an error that wraps [ErrTooMany], and no part of the list is returned.
const MaxDirEntries = 1 << 16

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

// Error is the error of a failed step. Path is the path given to the failed call, relative to
// the root: the temporary name for a create, a write and a flush of a file, the final name for
// a rename (the temporary name is then the path that was left behind), the folder for a folder
// flush, the path up to the element that failed for a walk. Err is what the file system
// returned; errors.Is(err, fs.ErrExist) works through Unwrap.
//
// The text of an Error is safe to print: it holds only printable ASCII (0x20 to 0x7E). Path is
// quoted with strconv.QuoteToASCII (a control code shows as an escape, and so does every
// character beyond ASCII, as \uXXXX or \UXXXXXXXX), and the text of Err, which may hold a path
// that a system library or a model of the file system wrote, goes through [printable]: every
// byte that is not printable ASCII is written as an escape, in one form: \xNN for an ASCII
// control code and for a byte that is not valid UTF-8, \uXXXX for any other character up to
// U+FFFF and \UXXXXXXXX above it (a letter that looks like a Latin one is shown by its code
// point, never as itself). Err itself is not changed, so errors.Is and errors.As see through
// the Error as before.
type Error struct {
	Step Step
	Path string
	Err  error
}

// Error describes the failed step.
func (e *Error) Error() string {
	return "fsx: " + string(e.Step) + " " + strconv.QuoteToASCII(e.Path) + ": " + printable(e.Err.Error())
}

// Unwrap returns Err.
func (e *Error) Unwrap() error { return e.Err }

// printable returns s with every byte that is not printable ASCII written as an escape, so that
// the text cannot carry a control code, a terminal sequence, a character that reorders the text
// to a terminal or a letter that looks like another. One form: \xNN for an ASCII control code (and
// 0x7F) and for a byte that is not valid UTF-8, \uXXXX for every other character up to U+FFFF,
// \UXXXXXXXX above it, in lower case.
func printable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r >= 0x20 && r < 0x7f:
			b.WriteByte(byte(r))
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
		i += size
	}
	return b.String()
}

// safeError is an error whose text has every character that is not printable escaped, as
// [printable] does; Unwrap returns the error it holds, so errors.Is and errors.As see through it.
type safeError struct{ err error }

func (e *safeError) Error() string { return printable(e.err.Error()) }
func (e *safeError) Unwrap() error { return e.err }

// stoppedError is what every call after a stop returns. It says that the writer stopped on an
// earlier call, and it holds the *Error of that call: errors.Is(err, ErrStopped) is true, and
// errors.As gives the first *Error (so does errors.Is for an error that the first one wraps,
// fs.ErrExist for instance). The call that failed returns the *Error itself, which is not a
// stoppedError: that is how a caller tells "this call failed" from "stopped earlier" without
// comparing pointers. The one value is made at the stop and returned by every later call.
type stoppedError struct{ first *Error }

func (e *stoppedError) Error() string { return "fsx: the writer stopped earlier: " + e.first.Error() }

// Unwrap returns ErrStopped and the first error.
func (e *stoppedError) Unwrap() []error { return []error{ErrStopped, e.first} }

// ErrStopped is satisfied (errors.Is) by the error of every call that is made after the writer
// stopped, and not by the error of the call that stopped it. errors.As gives the first *[Error]
// from either. After a stop every call returns this error, whatever its arguments are, an
// invalid one included: the writer is done, and the stop is the answer. The same holds for a
// journal of the writer and for [Writer.TempName].
var ErrStopped = errors.New("fsx: the writer stopped earlier")

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

// ErrTooMany is wrapped by the error of a read that finds more lines in a journal than
// [MaxJournalLines], or more names in a folder than [MaxDirEntries].
var ErrTooMany = errors.New("the file or folder holds more lines or names than the limit of a read")

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
// element of a path, and the name of a file of a set): it is empty; it holds a byte that is not
// an ASCII letter, a digit, a dot, a hyphen or an underscore (a space, a control code, a
// separator, a character of another script, and any byte that is not UTF-8 are such bytes); it
// is longer than 255 bytes; it ends with a dot; or it is a device name of Windows, with or
// without an extension ("aux", "Aux.json"). A name of a set must also be one plain name; a mode
// must have no bits beyond the permission bits; a journal line must hold no newline. Such an
// error does not stop the writer, and every text of it quotes the path or the name it names in
// ASCII only (%+q: a control code, and every character beyond ASCII, shows as an escape), so that
// neither a control code nor a look-alike letter reaches a terminal.
var ErrInvalid = errors.New("fsx: invalid argument")

// ErrClosed is returned by a journal that was closed.
var ErrClosed = errors.New("fsx: journal is closed")
