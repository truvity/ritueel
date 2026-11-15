package ceremony

import (
	"errors"

	"ritueel.id/ritueel/internal/fsx"
)

// Trace is the place of the attempt and the two journals while a ceremony runs. It is one
// interface: the file implementation is the one [Folder.Start] returns, and the trace area of the
// stick (record 0005, rules 36 to 41) is a second implementation that a later version adds, under the
// same order of the writes.
type Trace interface {
	// Births is the birth journal: one line after each key exists (record 0005, rule 10).
	Births() Journal
	// Signatures is the journal of signatures: one line after each signature is made.
	Signatures() Journal
}

// Journal is one journal of a ceremony. Append writes one whole line and flushes it before it
// returns nil. A line that is refused is an error and writes nothing.
type Journal interface {
	// Append writes line, which holds no line feed, as one line of the journal.
	Append(line []byte) error
}

// fileTrace is the file implementation of [Trace]: births.jsonl and signatures.jsonl of the
// ceremony folder.
type fileTrace struct {
	births, sigs *fileJournal
}

func newFileTrace(births, sigs *fsx.Journal) *fileTrace {
	return &fileTrace{
		births: &fileJournal{j: births, kind: kindBirths, op: "births.jsonl"},
		sigs:   &fileJournal{j: sigs, kind: kindSignatures, op: "signatures.jsonl"},
	}
}

// Births returns the birth journal.
func (t *fileTrace) Births() Journal {
	if t == nil {
		return unusableJournal{}
	}
	return t.births
}

// Signatures returns the journal of signatures.
func (t *fileTrace) Signatures() Journal {
	if t == nil {
		return unusableJournal{}
	}
	return t.sigs
}

// close closes both journals and returns the first error. Both are closed even when the first
// fails.
func (t *fileTrace) close() error {
	var errs []error
	if t == nil {
		return errors.New("there is no trace")
	}
	for _, j := range []*fileJournal{t.births, t.sigs} {
		if err := j.j.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// unusableJournal is the journal of a nil trace: every line is refused.
type unusableJournal struct{}

// Append refuses the line.
func (unusableJournal) Append([]byte) error {
	return newError("journal", ErrOutOfOrder, nil, "there is no journal")
}
