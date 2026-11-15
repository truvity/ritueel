// Package ceremony is the engine of a ceremony: the files of one ceremony folder, the order in
// which they are written, and what a person reads while it runs (docs/reference/ceremony-record.md,
// "The order of writes"; record 0005, rules 9 to 13; record 0006, rules 8, 9 and 31 to 45).
//
// The package holds, so far, what writes the ceremony folder history/<ceremony>/ and
// nothing that makes a key or a signature:
//
//   - [Folder] is one ceremony folder and its state: new, planned, started, ended, transcribed,
//     recorded. [Folder.WritePlan] (or [Folder.Adopt] for a plan that an earlier run wrote)
//     comes first, then [Folder.Start] writes the attempt and creates the two journals, then
//     [Folder.End] closes them, then [Folder.WriteTranscript], then [Folder.Record] writes the
//     ceremony record last. A call out of order is an error and writes nothing. The first write
//     that fails stops the folder for good: nothing is retried and nothing is deleted (record
//     0006, rules 33 and 45).
//   - [Trace] is the place of the attempt and the two journals while the ceremony runs. The
//     file implementation is the one [Folder.Start] returns. The trace area of the stick (record
//     0005, rules 36 to 41) is a second implementation that a later version adds; the order of the
//     writes does not change with it.
//   - [Console] prints what a person reads and keeps the same lines, so that the transcript is
//     what was printed and nothing else (record 0006, rule 9). It writes no file: the caller
//     hands [Console.Transcript] to [Folder.WriteTranscript] after [Folder.End].
//
// The package also holds what comes before the folder, the find and the plan of the first apply of a
// software test root (docs/reference/ceremony-record.md, "The plan"; record 0005, rules 4 to 8, 13, 19
// and 20):
//
//   - [Find] reads the wanted files and the state of the bundle, through fsx, and says what is not
//     applied yet. It writes nothing and stores nothing. It knows one case, the first apply: a bundle
//     with no ceremony record, no trust set and no entry under roots/, with one wanted root file of the
//     kind x509 that is a test root. Every other state, and every root of a kind that is not built, is
//     refused with a text that says what to do. An open attempt is refused with the reason
//     [ReasonUnfinishedCeremony] (exit code 3), so apply makes no plan and runs none until it is closed.
//   - [MakePlan] builds the plan of a [Found]: it reads the clock once, draws the serials from
//     [Env].Rand, and writes the canonical bytes, the digest and the words ([PlanOut.Words]). The name
//     of the ceremony is its time and the command, 20261120T100000Z-apply. [ReadPlanOut] is the one way
//     a saved plan is taken: a strict reader of exactly the shape that MakePlan writes, which writes the
//     typed value again and requires the same bytes, so that the words a person confirms and the values
//     that a run executes come from one reading.
//   - [CheckKeyDir] is every refusal about the key directory that needs no key.
//
// Every write goes through fsx.Writer, so a name that exists, a link and a temporary name are
// refused by the one place that knows the rules (record 0006, rules 31 to 33 and 44). A folder
// that may exist already (history/) is read first and made only when it is absent. Every file
// the package writes is read back by the strict reader of internal/ceremony/files that judges it,
// and compared with what was written. The ceremony record lists what the package read back from
// the disk, never what a caller says is there.
//
// The package returns its own error types. A caller maps them to an exit code; the package
// imports nothing of internal/cli.
//
// What a stop leaves behind is what the order of the writes leaves: a folder with a plan and
// copies is "planned", one with an attempt and no ceremony record is "started", and only the
// ceremony record makes a ceremony "recorded" (docs/reference/ceremony-record.md, "The states of
// a ceremony folder"). A zero or a nil [Folder], [Console] or [Trace] writes nothing and returns
// an error.
package ceremony
