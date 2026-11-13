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
// writer holds open until [Writer.Close]. Every statement below that something stays inside the
// root, or cannot reach outside it, holds on one condition, stated once in the paragraph on "a
// process that can write into the root" below: that no such process moves a folder that the
// writer has open. Every path that the writer or a read helper
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
//   - Choosing the root. The package keeps every write inside the folder it was given (on the
//     condition stated below) and cannot tell whether that folder is the right one: a folder of a workstation, a mounted stick, a
//     copy that came from elsewhere.
//   - A root on a file system that is not exFAT. The rule for names fits any file system that
//     holds ASCII, but the order of the steps is what a cut is proved against in memory only,
//     and what a cut leaves on another file system is that file system's own. The writer does
//     not look at what the root is mounted on.
//   - Skipping every name that starts with [TempPrefix] when reading a folder, compared without
//     case. A temporary folder that a stop left holds whole files under ordinary names, and a
//     reader that lists it would take them for files of the bundle. [ReadDir] lists every name and
//     leaves the skipping to the caller.
//   - Checking a listed name before it is shown or used. A name that [ReadDir] returns is data
//     from the stick, not a name that the writer made: it may hold a control code, bytes that are
//     not UTF-8 or a character that reorders a text, and it may break the rule for names, so
//     that [ReadFile] refuses it. [CheckName] applies the writer's own rule to one name; a caller
//     checks each listed name with it, and never prints a name as it is (%+q shows it safely).
//
// A process that can write into the root while the writer runs is outside what this package
// defends against. It can move a folder that the writer has open, the root included: the writer's
// next steps in this operation then work in the folder where it went, which can be outside the
// root. It can swap a name between two steps, and add or remove names. [Writer.WriteSet] makes
// its temporary folder and then opens it by name, and a process that can write into the root
// at that moment can put a folder of its own under that name: the files of the set are then
// written into that folder, and it is renamed into place with whatever else it holds. What such
// a process cannot do, by planting a link, a "..", or an absolute path, is make the writer follow
// it or write through it, and it cannot make the writer replace a file: the only ways in are an
// exclusive create and a rename that refuses an existing name. Nothing in the next paragraphs
// holds against the move of a folder that the writer has open.
//
// A name holds only the ASCII letters, the digits, the dot, the hyphen and the underscore
// (A-Z a-z 0-9 . - _): every element of a path, and every name of a set, is refused (with
// [ErrInvalid]) when it holds any other byte, is empty, is longer than 255 bytes, ends with a dot,
// or is a device name of Windows ("aux", "Aux.json"). One short rule, and a reason for it: a person
// can tell any two names apart (nothing is invisible, nothing looks like another letter, nothing
// folds or normalises into another name), and every file system the bundle meets, an exFAT stick
// and the systems that read it, can hold them. It costs something: a label cannot be written in
// another script or with a space, and the names of people and organisations live inside the
// files, not in the names of files. The layer above that turns a label into a name must check the
// label when the holder types it and say why it is refused, and must not leave the refusal to the
// write.
//
// What the writer does not check:
//
//   - Case between two separate calls. exFAT keeps the case of a name and compares names
//     without it, and the writer cannot know which names exist, so it cannot refuse a second
//     name that differs only by case from an existing one: the file system's own refusal
//     catches it on the stick, the exclusive create or the rename that never replaces, and on
//     a case-sensitive file system both names would exist. Within one set the writer refuses
//     such a pair itself (folding the ASCII letters is enough, since a name holds nothing else).
//   - The depth of the folders and the number of open files the operating system allows. The
//     walk opens one element at a time, so the length of a whole path is no limit (each name is
//     checked for its own 255 bytes); a limit of the system stops the writer with its error.
//
// Every path is confined to the root, and the package cannot be given a path outside it: there
// is no way to name one, as long as no process moves a folder that the writer has open (see
// above). Whether a bundle folder inside the root is the right one is the
// caller's to say.
package fsx
