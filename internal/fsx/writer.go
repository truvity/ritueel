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
// call beside a write on the same writer does not read the random source at the same time,
// and after a stop it returns the stop error and draws nothing. A failure of the random
// source is returned as it is and does not stop the writer: no step of a write has failed.
func (w *Writer) TempName() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return "", w.err
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
// another name; it returns "" when the name is fine. The reasons: it is empty (the callers
// refuse an empty name before they call it, so this is a guard that no caller reaches); it is not
// valid UTF-8; it has a control code or a character of exFAT's list of invalid characters (the
// colon is on that list, so a drive, "C:x", is refused by it and needs no rule of its own); it
// has a character that is not printable; it is longer than 255 bytes (see [maxNameBytes]); it
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

// checkPath refuses a path that can mean more than one thing, that something other than a
// name the caller can point at, or that the stick's file system cannot hold. All forms are
// refused with [ErrInvalid]: an empty path; a trailing separator (filepath.Dir and
// filepath.Base of "dir/x/" both give "x", so the file would be made inside x); an element
// that is "." or ".."; an empty element between two separators ("a//b", and a leading "//",
// which some systems read as a network name); and, for every element and not only the last,
// whatever [nameProblem] finds (control codes, the characters of exFAT's invalid list
// including the backslash and the colon, a trailing dot or space, a length over 255 bytes,
// bytes that are not UTF-8). The final element must not start with [TempPrefix]. One leading
// separator, an absolute path, is accepted: the writer has no root (see the package
// comment). A relative path with no folder ("x", whose folder is ".") passes. A path with a
// drive or a volume ("C:x", "\\host\share") has a colon or a doubled separator and is refused
// by those rules, so no code looks at a volume name.
//
// Some rules overlap, and each stays because it gives the caller the clearer text for its own
// case: the trailing separator and the empty element, and "." and ".." and the trailing dot.
func checkPath(path string) error {
	if path == "" {
		return fmt.Errorf("%w: empty path", ErrInvalid)
	}
	elems := strings.Split(filepath.ToSlash(path), "/")
	last := len(elems) - 1
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
		default:
			if why := nameProblem(e); why != "" {
				return fmt.Errorf("%w: path %q has an element that %s", ErrInvalid, path, why)
			}
		}
	}
	if hasTempPrefix(elems[last]) {
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
		// "." and ".." end with a dot, but "not one plain name" says more than "ends with a dot".
		if f.Name == "" || f.Name == "." || f.Name == ".." || hasTempPrefix(f.Name) {
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
