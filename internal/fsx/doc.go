// Package fsx writes the files of a bundle in the order of the steps of
// docs/reference/bundle.md, "How a file is written" (record 0006, rules 31 to 33;
// record 0005, rule 10).
//
// What the write steps guarantee is an order, and what a cut between two steps leaves:
//
//   - A file is written under a temporary name in its own folder (a fixed prefix and a
//     random part, 15 characters in all, never the final name), flushed, renamed to its
//     final name by a rename that refuses to replace, and its folder is flushed. A cut
//     before the rename leaves no file at the final name; a cut after it leaves the
//     whole file there, as far as the flush of the file reached the disk before the
//     rename.
//   - A set of files (a trust set) is built in a folder under a temporary name, each file
//     flushed and the folder flushed, and the folder is renamed into place.
//   - A journal grows by one line and one flush at a time. A line without its newline is
//     not a line: [ReadJournal] returns it apart.
//   - The first error stops the [Writer]. It is not retried, and no later operation of
//     the writer or of its journals reaches the file system (record 0006, rule 33). The call
//     that failed returns its *[Error]; every later call returns an error that satisfies
//     [ErrStopped] and holds that first one, also a call with an invalid argument.
//   - No file except a journal stands at its final name before it is whole. The attempt is
//     written with [Writer.WriteFile] like every other file: the rename refuses an
//     existing name, so the name is taken once, and an error that wraps fs.ErrExist at
//     [StepRename] means the attempt exists already.
//   - Nothing is deleted. A temporary file or folder left by a stop stays where it is.
//
// What they do not guarantee is that a removable stick keeps a bundle whole. A measurement
// on a real stick found damage that no order of writes prevents: a folder's list of names
// lost, and a sector that kept the content of the previous write (record 0005, "Not yet
// proven"; issue 181). The code here does not claim to cure that, and a flush that
// returns without an error is only the stick's report that it flushed.
//
// The writer is rooted. It works inside one folder, the root, that [Open] opens once and the
// writer holds open until [Writer.Close]. Every path that the writer or a read helper
// ([ReadFile], [ReadDir], [ReadJournal]) is given is relative to the root, with "/" as the
// separator; an absolute path is refused with [ErrInvalid]. Each operation walks its path from
// the root's handle, one element at a time, with openat and O_NOFOLLOW|O_DIRECTORY, and works in
// the folder it reached through that handle: the file is created there with O_EXCL and
// O_NOFOLLOW, the folder is made there, the rename is renameat2 with RENAME_NOREPLACE (Linux) or
// renameatx_np with RENAME_EXCL (macOS) with both names in that folder, and the folder is
// flushed through the same handle. So below the root no symbolic link is followed, in any
// element of a path and at the final name, for any operation, a write or a read: an element that
// is a link, or is not a folder, is an error that names the element, and wraps [ErrLink] when it
// is a link. The writer walks again for each operation and closes every handle it opened when the
// operation ends, on every path out of it, so no handle outlives the operation that opened it
// (the root's, and the file of an open [Journal], are the two it keeps, until Close). The root's
// own path is resolved by the operating system as the caller gave it; only its last element
// must be a folder and must not be a link. On a system without the calls above,
// [OpenFS] returns an error that wraps [ErrNoReplaceUnsupported].
//
// A read opens a file without following a link and without waiting (a FIFO is not waited on),
// looks at the open file, and reads only a regular file of at most [MaxReadSize] bytes; a
// longer file, or anything else, is an error and never a cut-off read.
//
// What is still the caller's part:
//
//   - Choosing the root. The package keeps every write inside the folder it was given and cannot
//     tell whether that folder is the right one: a folder of a workstation, a mounted stick, a
//     copy that came from elsewhere.
//   - A root on a file system that is not exFAT. The rules for names are those of an exFAT stick
//     and the desktop systems that read it, and the order of the steps is what a cut is proved
//     against in memory only. Another file system may hold a name that is refused here or refuse
//     a name that is accepted (case, normalisation), and what a cut leaves there is that file
//     system's own. The writer does not look at what the root is mounted on.
//   - Skipping every name that starts with [TempPrefix] when reading a folder, compared without
//     case. A temporary folder that a stop left holds whole files under ordinary names, and a
//     reader that lists it would take them for files of the bundle. [ReadDir] lists every name and
//     leaves the skipping to the caller.
//
// A process that can write into the root while the writer runs is outside what this package
// defends against. It can move a folder that the writer has open (the writer's next steps in
// this operation then work in the folder where it went), swap a name between two steps, and add
// or remove names. What it cannot do by planting a link, a "..", or an absolute path is make the
// writer follow it or write through it, and it cannot make the writer replace a file: the only
// ways in are an exclusive create and a rename that refuses an existing name.
//
// Names are checked against the stick and the desktop systems that read it. Every element of
// a path, and every name of a set, is refused (with [ErrInvalid]) when the exFAT file system
// cannot hold it or would hold it under another name: a control code or one of the characters
// of the specification's table of invalid file name characters, an end with a dot or a space
// (Windows removes both, and the Linux exFAT driver removes trailing dots unless the mount
// option keep_last_dots is given), more than 255 bytes (which is also at most 255 UTF-16 code
// units, the limit of exFAT), and bytes that are not UTF-8. It is also refused when it has a
// character that is not printable in the sense of unicode.IsPrint (a letter, a mark, a
// number, a punctuation mark, a symbol or the plain space are printable; a control code, a
// format character such as U+200B or U+200D, a space such as U+00A0 and a code point that is
// unassigned or for private use are not), so that a name does not hide a character that the
// holder cannot see, and when it is a device name of Windows ("aux", "Aux.json"), which a
// Windows system cannot open.
//
// A name that the holder chooses, a label, can be refused by these rules (a device name, a
// name that ends with a dot or a space, a character that is not printable). The code that turns
// a label into a name must check the label when the holder types it and say why it is refused,
// and must not leave the refusal to the write.
//
// What the writer does not check:
//
//   - Case between two separate calls. exFAT keeps the case of a name and compares names
//     without it, and the writer cannot know which names exist, so it cannot refuse a second
//     name that differs only by case from an existing one: the file system's own refusal
//     catches it on the stick, the exclusive create or the rename that never replaces, and on
//     a case-sensitive file system both names would exist. Within one set the writer refuses
//     such a pair itself.
//   - The table that exFAT uses to compare names without case lives on the stick and may
//     differ from the one in Go for rare letters; then the refusal of the stick catches the
//     pair, not the writer.
//   - Unicode normalisation. A file system of macOS treats two spellings of one accented
//     letter as one name; the writer does not. The layer that chooses names keeps them simple.
//   - The depth of the folders and the number of open files the operating system allows. The
//     walk opens one element at a time, so the length of a whole path is no limit (each name is
//     checked for its own 255 bytes); a limit of the system stops the writer with its error.
//
// The package confines every path to the root (see above) and cannot be given a path outside it:
// there is no way to name one. Whether a bundle folder inside the root is the right one is the
// caller's to say.
package fsx
