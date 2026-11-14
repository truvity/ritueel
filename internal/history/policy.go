package history

// Choices of the check that the pages do not settle yet. Each is one name in this file, so that
// another answer is a small change here and not a search through the walk.

// codeUnlistedInSet is the code of a file inside a trust set that no ceremony record lists: a
// file that a consumer of the set reads and that no digest covers. It fails, whatever the name:
// a name that a desktop system writes (.DS_Store, Thumbs.db, desktop.ini, ._*) is no exception,
// because a consumer may read the whole folder and nobody has checked the bytes of such a file.
// Outside a trust set such a name is a name like any other, and the notice for it stays.
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
