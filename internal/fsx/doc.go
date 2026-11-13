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
//     the writer or of its journals reaches the file system (record 0006, rule 33).
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
// The package does not confine paths. The caller passes paths that it built under a
// bundle it has opened, and a symlink inside the bundle is not looked at here.
package fsx
