package fsx

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
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

// Writer adds files to a bundle inside one root folder, which it holds open for its whole life.
// The first error stops it: every later operation of the writer and of its journals returns an
// error and does not reach the file system (record 0006, rule 33; the reading that nothing may
// follow a failed write is proposed). An argument that the writer refuses before any file system
// call (see [ErrInvalid]) is not an error of that kind and does not stop it. The writer never
// retries and never deletes a temporary file or folder.
//
// Every path given to a method is relative to the root, with "/" as its separator, and the
// writer walks it from the root, one element at a time, without following a symbolic link. A
// walk is made once for each operation, and the folder handles it opens are closed when the
// operation ends, on every path out of it (see the package comment).
//
// [Open] makes a Writer for a folder of the real file system. A test, or a caller that has an
// [FS] of its own, sets the FS field of a Writer before the first call. [Writer.Close] releases
// the root, and the writer owns its FS from the first call to that Close.
//
// A Writer is safe for use by several goroutines: every method, and every method of its
// journals, takes the writer's lock, so the operations run one at a time and the stop is read
// and set under it. The lock belongs to one Writer and covers the FS and the Rand it reads: a
// Rand that is shared with another Writer or another goroutine needs a lock of its own, and FS
// and Rand are set before the first call and are not changed after it.
type Writer struct {
	// FS is the root folder. [Open] sets it; a nil FS makes every method that needs the file
	// system return [ErrNoRoot].
	FS FS
	// Rand supplies the random part of temporary names; nil means crypto/rand. The writer reads
	// it only while it holds its lock.
	Rand io.Reader

	mu       sync.Mutex
	err      error // the stop; set once
	closed   bool
	journals map[*journalState]struct{} // the journals that are open
}

// NewFile is one file of a set written by [Writer.WriteSet]. Name is one plain name.
type NewFile struct {
	Name string
	Data []byte
	Perm fs.FileMode
}

// Open opens the folder root and returns a Writer that works inside it. root is resolved by the
// operating system as the caller gives it, and its last element must be a folder and must not
// be a symbolic link (see [OpenFS]). There is one constructor for the real file system and the
// FS field for any other, so that a test can stand an in-memory file system in for the root
// without a second way to make a Writer. The caller closes the Writer with [Writer.Close].
func Open(root string) (*Writer, error) {
	fsys, err := OpenFS(root)
	if err != nil {
		return nil, err
	}
	return &Writer{FS: fsys}, nil
}

// Close closes every journal that is still open, as [Journal.Close] does, and releases the root
// folder, so that no handle outlives the writer. Every call of the writer after it, and of its
// journals, returns [ErrWriterClosed] (a journal returns [ErrClosed]), or the stop when the writer
// had stopped: the stop comes first. A second Close does nothing and returns nil. Close returns
// the stop when the writer had stopped, as [Journal.Close] does, and otherwise the first error
// of the close of a journal or of the release of the root, if any; it does not stop the writer
// for such an error, because the writer is done. A call of [ReadFile], [ReadDir] or
// [ReadJournal] with the FS of a closed writer fails with an error that wraps fs.ErrClosed.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var first error
	for s := range w.journals {
		if err := w.closeJournal(s); err != nil && first == nil {
			first = &Error{Step: StepSyncFile, Path: s.path, Err: err}
		}
	}
	if w.FS != nil {
		if err := w.FS.Close(); err != nil && first == nil {
			first = fmt.Errorf("fsx: close the root folder: %w", err)
		}
	}
	if w.err != nil {
		return w.err
	}
	return first
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

// begin is the start of every operation that reaches the file system, made under the lock: a
// writer that has stopped, then a writer that is closed, then a writer with no root answer
// before anything else, and so before the check of the arguments.
func (w *Writer) begin() error {
	if err := w.beginNoFS(); err != nil {
		return err
	}
	if w.FS == nil {
		return ErrNoRoot
	}
	return nil
}

// beginNoFS is begin for an operation that does not reach the file system.
func (w *Writer) beginNoFS() error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return ErrWriterClosed
	}
	return nil
}

// enter walks to the folder dir. A failed walk stops the writer: the file system, or a link
// where a folder should be, refused the step.
func (w *Writer) enter(dir []string) (*folder, error) {
	f, upto, err := openFolder(w.FS, dir)
	if err != nil {
		return nil, w.stop(StepOpenDir, upto, err)
	}
	return f, nil
}

// TempName draws one temporary name: TempPrefix and lower-case letters and digits, 15
// characters in all. It does not carry any final name. It reads only the random source and
// does not reach the file system. Like every other method it takes the writer's lock, so a
// call beside a write on the same writer does not read the random source at the same time,
// and after a stop it returns the stop error and draws nothing. A failure of the random
// source is returned as it is and does not stop the writer: no step of a write has failed.
func (w *Writer) TempName() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.beginNoFS(); err != nil {
		return "", err
	}
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

// WriteFile adds one file (steps 1 to 4 of "How a file is written"): the whole content under a
// temporary name in the same folder, a flush of the file, a rename to path that refuses to
// replace, a flush of the folder. path must not exist: when it does, the error wraps
// fs.ErrExist (Step rename), the file at path is unchanged and the temporary file is left.
// A cut before the rename leaves nothing at path; a cut after it leaves the whole content.
// The folder of path is walked once, and the create, the rename and the flush work through
// that one handle.
func (w *Writer) WriteFile(path string, data []byte, perm fs.FileMode) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.begin(); err != nil {
		return err
	}
	elems, err := parsePath(path, true)
	if err != nil {
		return err
	}
	if err := checkPerm(perm); err != nil {
		return err
	}
	dir, name := elems[:len(elems)-1], elems[len(elems)-1]
	dp := dirPath(dir)
	d, err := w.enter(dir)
	if err != nil {
		return err
	}
	defer d.release()
	tmp, err := w.tempIn(dp)
	if err != nil {
		return err
	}
	if err := w.writeNew(d.fs, dp, tmp, data, perm); err != nil {
		return err
	}
	if err := d.fs.RenameNoReplace(tmp, name); err != nil {
		return w.stop(StepRename, joinPath(dp, name), err)
	}
	if err := d.fs.Sync(); err != nil {
		return w.stop(StepSyncDir, dp, err)
	}
	return nil
}

// WriteSet adds a folder of files (step 5): the folder is made beside finalDir under one
// temporary name, each file is written and flushed in it, the folder is flushed, it is
// renamed to finalDir by a rename that refuses to replace, and the parent is flushed. The
// files are written at their own names inside the temporary folder; the folder becomes
// visible under finalDir only after every file is whole. When finalDir exists the error
// wraps fs.ErrExist (Step rename) and the temporary folder is left. The folder is made with
// mode 0700. The parent is walked once, and the temporary folder is opened from it, so the
// files, the rename and the flush of the parent all work through handles that the walk
// opened.
func (w *Writer) WriteSet(finalDir string, files []NewFile) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.begin(); err != nil {
		return err
	}
	elems, err := parsePath(finalDir, true)
	if err != nil {
		return err
	}
	if err := checkFiles(files); err != nil {
		return err
	}
	parent, name := elems[:len(elems)-1], elems[len(elems)-1]
	pp := dirPath(parent)
	p, err := w.enter(parent)
	if err != nil {
		return err
	}
	defer p.release()
	tmp, err := w.tempIn(pp)
	if err != nil {
		return err
	}
	tmpPath := joinPath(pp, tmp)
	if err := p.fs.Mkdir(tmp, dirPerm); err != nil {
		return w.stop(StepMkdir, tmpPath, err)
	}
	t, err := p.fs.OpenDir(tmp)
	if err != nil {
		return w.stop(StepOpenDir, tmpPath, err)
	}
	td := &folder{fs: t, owned: true}
	defer td.release()
	for _, f := range files {
		if err := w.writeNew(td.fs, tmpPath, f.Name, f.Data, f.Perm); err != nil {
			return err
		}
	}
	if err := td.fs.Sync(); err != nil {
		return w.stop(StepSyncDir, tmpPath, err)
	}
	td.release()
	if err := p.fs.RenameNoReplace(tmp, name); err != nil {
		return w.stop(StepRename, joinPath(pp, name), err)
	}
	if err := p.fs.Sync(); err != nil {
		return w.stop(StepSyncDir, pp, err)
	}
	return nil
}

// Mkdir makes a folder at its final name (a ceremony folder) and flushes the parent. The
// folder is empty and complete at once, so it needs no temporary name. It fails when the
// folder exists.
func (w *Writer) Mkdir(path string, perm fs.FileMode) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.begin(); err != nil {
		return err
	}
	elems, err := parsePath(path, true)
	if err != nil {
		return err
	}
	if err := checkPerm(perm); err != nil {
		return err
	}
	parent, name := elems[:len(elems)-1], elems[len(elems)-1]
	pp := dirPath(parent)
	p, err := w.enter(parent)
	if err != nil {
		return err
	}
	defer p.release()
	if err := p.fs.Mkdir(name, perm); err != nil {
		return w.stop(StepMkdir, joinPath(pp, name), err)
	}
	if err := p.fs.Sync(); err != nil {
		return w.stop(StepSyncDir, pp, err)
	}
	return nil
}

// tempIn draws a temporary name for the folder at dir (as dirPath gives it). The error of the
// draw stops the writer. A final name never starts with TempPrefix (parsePath), so the two
// cannot be equal.
func (w *Writer) tempIn(dir string) (string, error) {
	name, err := w.tempName()
	if err != nil {
		return "", w.stop(StepCreate, joinPath(dir, TempPrefix), err)
	}
	return name, nil
}

// writeNew creates name in d exclusively, writes data, flushes and closes it. dir is the path of
// d, for the errors. Each failure stops the writer. After a failure the open file is closed
// without a further flush.
func (w *Writer) writeNew(d FS, dir, name string, data []byte, perm fs.FileMode) error {
	path := joinPath(dir, name)
	f, err := d.CreateExcl(name, perm)
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

// maxNameBytes is the longest name, in bytes, that the file system of a workstation holds
// (NAME_MAX, 255, on Linux and macOS). It is also enough for exFAT, which holds at most 255
// UTF-16 code units: in UTF-8 a character takes at least as many bytes as it takes UTF-16
// code units (one byte for one unit, two or three bytes for one unit, four bytes for two
// units), so a name of at most 255 bytes has at most 255 units. 128 times "é" is 128 units
// and 256 bytes, and is refused for its bytes.
const maxNameBytes = 255

// exfatBad holds the characters of Table 35, "Invalid FileName Characters", of the exFAT
// specification, besides the control codes U+0000 to U+001F: the quotation mark, the
// asterisk, the forward slash, the colon, the less-than and greater-than signs, the question
// mark, the back slash and the vertical bar.
const exfatBad = "\"*/:<>?\\|"

// charText names a character of a name for an error text: the code point as U+XXXX, and, for
// a printable ASCII character, the character itself. A character that a terminal may not draw
// is never put into a text as itself.
func charText(r rune) string {
	if r > 0x20 && r < 0x7f {
		return fmt.Sprintf("U+%04X (%c)", r, r)
	}
	return fmt.Sprintf("U+%04X", r)
}

// windowsDevice reports a name that Windows reserves for a device, so that the holder of the
// stick cannot open a file of that name on a Windows system. The list is that of Microsoft's
// page "Naming Files, Paths, and Namespaces", which says: "Do not use the following reserved
// names for the name of a file: CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7,
// COM8, COM9, COM¹, COM², COM³, LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9, LPT¹,
// LPT², and LPT³. Also avoid these names followed immediately by an extension; for example,
// NUL.txt and NUL.tar.gz are both equivalent to NUL." The page does not list COM0, LPT0,
// CONIN$ or CONOUT$, and so neither does this function. It says nothing about spaces before
// the extension; that Windows removes the trailing spaces of a part of a name, so that
// "nul .txt" is "nul.txt", is an inference, and the function refuses it because that only
// narrows. So the part of the name before its first dot, with its trailing spaces removed, is
// compared without case. "auxiliary" and "com10" are names.
func windowsDevice(name string) bool {
	stem, _, _ := strings.Cut(name, ".")
	up := strings.ToUpper(strings.TrimRight(stem, " "))
	switch up {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(up) > 3 && (up[:3] == "COM" || up[:3] == "LPT") {
		switch up[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
			return true
		}
	}
	return false
}

// nameProblem says why one name (one element of a path, or the name of a file of a set) cannot
// be used on the stick (exFAT) and on the desktop systems that read it, or is held there under
// another name; it returns "" when the name is fine. The reasons: it is empty (checkFiles
// relies on this answer for the name of a file of a set; parsePath refuses an empty element
// itself); it is not valid UTF-8; it has a control code or a character of exFAT's list of
// invalid characters (the colon is on that list, so a drive, "C:x", is refused by it and needs
// no rule of its own); it has a character that is not printable; it is longer than 255 bytes (see [maxNameBytes]); it
// is a device name of Windows, see [windowsDevice]; it ends with a dot or a space (Windows
// removes both, and the Linux exFAT driver removes trailing dots unless the mount option
// keep_last_dots is given, so the name on the stick would not be the name asked for).
//
// Printable is the sense of [unicode.IsPrint]: a letter, a mark, a number, a punctuation mark,
// a symbol, or the plain space U+0020. A control code, a format character (U+00AD, U+200B,
// U+200D, U+200E, U+200F, U+FEFF), a space of another kind (U+00A0, U+2028, U+2029), a private
// use or unassigned code point and a noncharacter (U+FFFE, U+FFFF) are not. The rule goes beyond
// the table of exFAT because a name with such a character cannot be told from another name that
// looks the same, or cannot be typed by the holder of the stick. A combining mark is a mark and
// prints, so an accented letter is accepted composed and decomposed. An emoji joined with the
// format character U+200D is refused, and so is every emoji sequence that needs it. The rule
// follows the Unicode tables of the Go version that the program is built with, so a code point
// that a later version assigns may be refused by an earlier build.
func nameProblem(name string) string {
	if name == "" {
		return "is not one plain name"
	}
	if !utf8.ValidString(name) {
		return "is not valid UTF-8"
	}
	for _, r := range name {
		switch {
		case r < 0x20 || strings.ContainsRune(exfatBad, r):
			return fmt.Sprintf("has the character %s, which the stick's file system cannot hold", charText(r))
		case !unicode.IsPrint(r):
			return fmt.Sprintf("has the character %s, which is not a printable character", charText(r))
		}
	}
	if len(name) > maxNameBytes {
		return fmt.Sprintf("is %d bytes long, more than the %d a workstation file system holds", len(name), maxNameBytes)
	}
	if windowsDevice(name) {
		return "is a device name that Windows reserves"
	}
	if last := name[len(name)-1]; last == '.' || last == ' ' {
		return "ends with a dot or a space, which the stick's file system can remove"
	}
	return ""
}

// hasTempPrefix reports whether name starts with [TempPrefix], compared without case. exFAT
// compares names without case, so a final name ".RT-abcdefghijk" would meet a live temporary
// name. Folding the ASCII letters is enough: the prefix is ASCII, and no letter outside ASCII
// has a case mapping to "r" or "t".
func hasTempPrefix(name string) bool {
	if len(name) < len(TempPrefix) {
		return false
	}
	for i := 0; i < len(TempPrefix); i++ {
		c := name[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != TempPrefix[i] {
			return false
		}
	}
	return true
}

// parsePath splits a path that is relative to the root into its elements, or refuses it with
// [ErrInvalid]. The separator is "/" and no other character, so a backslash is not a separator
// on any system: it is a character of exFAT's invalid list and [nameProblem] refuses it. All
// forms are refused: an empty path; an absolute path (a leading separator, which is also what a
// leading "//" is: some systems read it as a network name; the writer works inside its root
// and a path says where below it); a trailing separator (the file would be made inside the
// folder the last element names); an element that is "." or ".."; an empty element between two
// separators ("a//b"); and, for every element and not only the last, whatever [nameProblem]
// finds (control codes, the characters of exFAT's invalid list including the backslash and the
// colon, a trailing dot or space, a length over 255 bytes, bytes that are not UTF-8). When
// forWrite is set, the final element must not start with [TempPrefix] either: a name to be
// written is never a temporary one. A path that is only read may name one, because the caller
// lists the temporary folders a stop left behind. A relative path with no folder ("x", whose
// folder is the root) passes. A path with a drive or a volume ("C:x", "\\host\share") has a
// colon or a backslash and is refused by those rules, so no code looks at a volume name. Every
// text quotes the path.
//
// Some rules overlap, and each stays because it gives the caller the clearer text for its own
// case: the trailing separator and the empty element, and "." and ".." and the trailing dot.
func parsePath(path string, forWrite bool) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: empty path", ErrInvalid)
	}
	if path[0] == '/' {
		return nil, fmt.Errorf("%w: path %q is absolute; a path is relative to the root", ErrInvalid, path)
	}
	elems := strings.Split(path, "/")
	last := len(elems) - 1
	if last > 0 && elems[last] == "" {
		return nil, fmt.Errorf("%w: path %q ends with a separator", ErrInvalid, path)
	}
	for _, e := range elems {
		switch e {
		case "":
			return nil, fmt.Errorf("%w: path %q has an empty element (a doubled separator)", ErrInvalid, path)
		case ".":
			return nil, fmt.Errorf("%w: path %q has a \".\" element", ErrInvalid, path)
		case "..":
			return nil, fmt.Errorf("%w: path %q has a \"..\" element", ErrInvalid, path)
		default:
			if why := nameProblem(e); why != "" {
				return nil, fmt.Errorf("%w: path %q has an element that %s", ErrInvalid, path, why)
			}
		}
	}
	if forWrite && hasTempPrefix(elems[last]) {
		return nil, fmt.Errorf("%w: path %q has the prefix of a temporary name", ErrInvalid, path)
	}
	return elems, nil
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
		// "." and ".." end with a dot, but "not one plain name" says more than "ends with a dot".
		if f.Name == "." || f.Name == ".." || hasTempPrefix(f.Name) {
			return fmt.Errorf("%w: file name %q is not one plain name", ErrInvalid, f.Name)
		}
		if why := nameProblem(f.Name); why != "" { // a separator in the name is on exFAT's list
			return fmt.Errorf("%w: file name %q %s", ErrInvalid, f.Name, why)
		}
		// Up-cased, because exFAT compares names after up-casing, and a name that differs only
		// by case is one entry there.
		key := strings.ToUpper(f.Name)
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
