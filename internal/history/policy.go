package history

import "strings"

// Choices of the check that the pages do not settle yet. Each is one name in this file, so that
// another answer is a small change here and not a search through the walk.

// codeUnlistedInSet is the code of a file inside a trust set that no ceremony record lists: a
// file that a consumer of the set reads and that no digest covers. It fails.
const codeUnlistedInSet = FileUnlisted

// codeUnlistedInWanted is the code of a file inside the folder of copies (wanted/) of a ceremony
// folder that its record does not list. The copies are read by no consumer, so it is a notice.
const codeUnlistedInWanted = UnexpectedFile

// codeTempInSet is the code of a name that starts with the prefix of a temporary name inside a
// trust set that a record lists, a file or a folder (the folder is not entered). It fails: a set
// is written whole under a temporary name and renamed into place, so a finished set holds none.
// In history/, in trust/ itself, in a ceremony folder and in a wanted/ folder such a name stays a
// notice.
const codeTempInSet = FileUnlisted

// codeDropping is the code of a regular file that a desktop system writes when a person opens a
// folder (see [isDropping]) and that is found inside a trust set. It is a notice, and not the
// failing finding of [codeUnlistedInSet]. A link, a FIFO, a socket, a device or a folder with
// one of those names is not a dropping: it is [codeUnlistedInSet] like any other entry.
const codeDropping = UnexpectedFile

// codeOddEntry is the code of a link, a FIFO, a socket or a device where a ceremony folder or a
// trust set belongs: ritueel never writes one, and the entry hides what a folder would hold. It
// fails. A plain file with an allowed name in that place stays a notice.
const codeOddEntry = UnexpectedName

// codeOddFile is the code of an entry that is not a regular file where attempt.json, births.jsonl
// or signatures.jsonl belongs: a link, a FIFO, a socket, a device or a folder. ritueel never
// writes one of these, and the file it hides is not covered by a digest unless the record names
// it. It fails. When a record does name the file, the finding of that digest says it and this
// code is not given besides. The plan and the transcript are not in this class: they are always
// named by their record, and one that is not a regular file is a notice only when no record
// reads it.
const codeOddFile = UnexpectedName

// recordCeremonyMustMatchFolder says that the "ceremony" member of a record must be the name of
// the folder that holds it; a record that is found in another folder is record-invalid.
const recordCeremonyMustMatchFolder = true

// isDropping reports whether name is one of the names that a desktop system writes beside the
// files of a folder: .DS_Store, Thumbs.db, desktop.ini, and any name that starts with "._".
func isDropping(name string) bool {
	switch name {
	case ".DS_Store", "Thumbs.db", "desktop.ini":
		return true
	}
	return strings.HasPrefix(name, "._")
}
