// Package history checks the history of a bundle: the chain of its ceremony records, and that
// every file a record lists still has its digest. It is the library behind "ritueel check
// history" (docs/reference/ceremony-record.md, "The hash chain"; docs/reference/cli.md). It reads
// a bundle through a rooted fsx.FS and writes nothing.
//
// # What it reads
//
// The folder history/ (one ceremony folder for each ceremony), each ceremony folder (its
// record.json, and the names in it), the files that each record lists (the transcript, the copies
// under wanted/, the artifacts, the plan, the attempt and the two journals when the record names
// their digests, and for a closing record the attempt it closes), the
// folder trust/ (one folder for each trust set), the one member last_record_sha256 of each
// trust set's root-list.json, and, only to link a trust set that no record lists to an open
// ceremony, the attempt.json and plan.json of each ceremony folder that has no record. It also
// lists the names inside each trust set that a record lists, and inside the wanted/ folder of
// each ceremony folder that has a record, to find files that no record lists; it reads none of
// them. It does not read the want/ files, the journals, the trace area of a stick, or the clock.
//
// # What it finds
//
// A [Finding] has a [Code], a path and a detail. The codes are the thirteen names of the page
// and three more, for what the check did not expect. A code that [Code.Fails] ends the command
// with exit code 3; the two notices (UnfinishedCeremony and UnexpectedFile) do not. [Check] returns
// the findings in one fixed order: the order of [Codes], then by path, then by detail.
//
//   - chain-broken: a record's prev_record_sha256 is not the digest of a record; or a record
//     has none and so does another one (only the first has none).
//   - fork: two record files name the same record. A byte-identical copy of a record in a second
//     folder is a fork too.
//   - record-off-chain: a record.json that is not on the chain, that is, not reached from the one
//     record without a predecessor through the names; a record that could not be read is not.
//   - record-not-canonical, record-version-unknown, record-invalid: the record's own faults. A
//     record of such a kind is still a record: it has a digest and is counted, and a record that
//     names it is not chain-broken for that. A record that passed no read names no predecessor, so
//     it and what follows it are off the chain, and it lists no file. A record whose "ceremony"
//     is not the name of its folder is record-invalid, and still on the chain.
//   - transcript-digest, file-digest, file-missing: the files a record lists (the copies, the
//     artifacts, the plan, and the attempt and journals that it names by digest). A listed file that
//     is there and is not a regular file of at most 8 MiB (a folder, a link, a FIFO) is
//     file-digest; only a name that does not exist is file-missing (record 0006, rule 31).
//   - file-unlisted: a file inside a trust set that a record lists, which no record lists. A name
//     that a desktop system writes (.DS_Store, Thumbs.db, desktop.ini, ._*) is this finding too,
//     for a regular file as for any other entry: a consumer may read the whole folder, and
//     nobody has checked the bytes of such a file. Outside a trust set such a name is a name like
//     any other, and the notice unexpected-file stays.
//   - trust-set-unlisted, unfinished-ceremony: a trust set that no record lists. With an open
//     attempt linked to it, it is an unfinished ceremony. An attempt is linked when its plan is
//     the plan of this history: the plan's trust_sequence is the set's number, and its
//     last_record_sha256 is the digest of the one end of the chain (or absent, in a history
//     with no record at all). Anything else is the finding trust-set-unlisted.
//   - anchor-unknown: the last_record_sha256 of a root list is not the record before the
//     ceremony that wrote the set (the prev_record_sha256 of the record that lists the set, or
//     the end the plan of an unfinished ceremony names; for a set that a closing record lists, the
//     ceremony that wrote it is the closed one, so it is the end named by the plan of that
//     ceremony, found through the attempt the closing record names, and when that plan cannot be
//     read the anchor is not accepted; absent exactly for the first ceremony),
//     or is not a record on the chain; or the root list cannot be read.
//   - root-returns: a root list holds a root key that left the root list (record 0006, rule 54):
//     an earlier list held its pin and the list directly before it did not, or an earlier list
//     held its OpenPGP fingerprint, under any pin, and the list directly before it does not hold
//     it under this pin. An entry with a fingerprint and no pin is a key held by its fingerprint,
//     and counts as its own pin. A key that stays is reported once, at the list that brings it
//     back. The check reads the root list of every trust set, also a set that no record lists.
//     The order is the order of the hash chain of the ceremony records, not the names that the
//     writer of the newest ceremony chooses: a set that a record lists stands at the place of that
//     record, for a closing record too (the closing record is a record of the chain like any
//     other, so its place is not the end that the plan of the closed ceremony names, which the
//     writer of the closing record can make), and a set that more than one record lists stands
//     at the place of each and is judged at each. A set that no record lists stands at the place
//     of the record that its last_record_sha256 names (none when it names none). Sets at the same
//     place are ordered by the member sequence of their lists and then by the number in the
//     folder name; where these tie, are missing or disagree, each reading is judged, and an entry
//     that any of them shows as a return is a finding. Where more than one set that a record
//     lists stands at one place (records that fork, or one record that lists two sets), the
//     names and sequences of its sets are not believed: every order of them is judged. The detail of a finding says that the order is not sure when a group of sets that tie
//     is around the entry, or when the readings differ for it (the other reading does not show it,
//     or has another list before it), and names up to two of the sets of the places whose order
//     is not sure and how many more. The reason comes first in the detail and the names of sets
//     last, so that its bound cuts a name and never the reason. A set whose place cannot be told (it is anchor-unknown or chain-broken)
//     is judged as a list after one that cannot be read: an entry
//     of it is a return when any other list held the key. The entries are read in one form, the
//     bytes the digits stand for, so the case of a digit makes no difference, and a 0x prefix,
//     white space and the separators space, colon and hyphen are dropped. One finding is given for
//     each entry, whose detail names the label and the case. A list that cannot be read (it is
//     anchor-unknown) adds nothing, and an entry of the list after it that an earlier list held
//     is a return, because the list before it is not known. A list with an entry whose pin or
//     fingerprint cannot be read in that form, or an entry with neither, is such a list.
//     [FindReturns] is the same rule for one list and the lists before it.
//   - unexpected-name: a name that breaks the rule for names (record 0006, rule 38), or a link,
//     a FIFO, a socket or a device where a ceremony folder or a trust set belongs.
//   - unexpected-file: a name that the check does not expect, a plain file where a ceremony
//     folder or a trust set belongs, a leftover temporary name, and a file inside wanted/ that
//     the record does not list.
//
// # What it never does
//
// Everything that comes from the bundle is hostile data: a name, a type, a size, a digest, the
// JSON, the order of things. So: it follows no symbolic link and reads only regular files
// (fsx); a name from a list is checked by fsx.CheckName before it is used in a path, and a name
// that starts with the prefix of a temporary name, in any case, is skipped and said; every path
// in a record is checked by files.CheckPath before it is read; a path that records list is read
// once for its digest (a cache by the hash of its path; the root list is parsed from that same
// read), the attempt and the plan of a ceremony with no record are read once for their content,
// and the records keep only a few strings each; nothing it prints holds a raw byte
// ([Finding.Line] escapes, and in a name from the stick a backslash is doubled, a space is shown as
// \x20 and a byte that is not UTF-8 as \xNN). An error from [Check] is "the check was not
// done", never a finding, and never a clean history.
//
// # Limits
//
// Each loop and each read has a named limit: the file limits of fsx (8 MiB for a file, 65,536
// names for a folder), those of strictjson (256 KiB and 10,000 levels for a record, a plan, an
// attempt and a root list), files.MaxPathElements (12) for a path in
// a record, [MaxReadBytes], [MaxFileReads], [MaxWalkEntries], [MaxRootEntries] (with [MaxRootsPerList] for one list),
// [MaxFindingsPerCode] and [MaxNamesShown]. A command that prints the findings prints [Report.Omitted] too.
package history
