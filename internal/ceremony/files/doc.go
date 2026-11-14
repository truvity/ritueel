// Package files holds the names of the files of a ceremony folder and the strict readers of the
// three that are JSON and that a check needs: the ceremony record (record.json), the attempt
// (attempt.json) and the plan (plan.json), as docs/reference/ceremony-record.md describes them
// (version 1) under the rules of record 0006.
//
// Each reader works on the bytes of one file, under the rules of the page's "Common rules": one
// JSON object of at most 256 KiB (strictjson.DefaultMaxBytes) and at most 10,000 levels deep,
// UTF-8 with no byte order mark, a member once, an unknown member an error, integers only and
// within strictjson.MinSafeInt to strictjson.MaxSafeInt, no null. The version is read first and
// alone: a file of a version other than 1 is a *[VersionError] that carries the number, and
// nothing else in it is read, so a member that version 1 does not know is not an error then
// (the page: a reader that meets a version it does not know refuses it and names it). Every
// other fault is an error that wraps strictjson.ErrMalformed or is a *[FormatError].
//
// What a reader requires is "what a check of the history reads", and nothing more; the longer
// list comes with the writer of the record. The members a reader requires are listed on each type. A member whose shape the page
// leaves open or Proposed is read as any, a list of any, or strictjson.Raw, and is not looked
// into. A digest is 64 lower-case hexadecimal characters, a time is exactly YYYY-MM-DDThh:mm:ssZ,
// and every path in a file passes [CheckPath] (at most [MaxPathElements] elements). An optional
// digest, time, name or word is left out or has a value: an empty text is a fault of the file,
// in a plan and an attempt as in a record, and it makes the file unreadable.
//
// Reading never trusts a file: every text in an error is written with characters beyond printable
// ASCII as escapes, and no error repeats a long input. The readers do not read a file from disk.
// The caller reads it with fsx and bounds the read before it calls a reader.
package files
