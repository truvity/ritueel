package ceremony

import (
	"bytes"
	"errors"
	"sync"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// MaxJournalLines is the most lines that a journal of one ceremony takes: [files.MaxJournalLines].
const MaxJournalLines = files.MaxJournalLines

type journalKind uint8

const (
	kindBirths journalKind = iota + 1
	kindSignatures
)

// fileJournal is one journal of the file trace. It checks each line with the strict reader that
// judges the file, and appends it only when the reader accepts it and the line is the canonical
// form of what it read; so a journal holds nothing that [files.ReadBirthLine] or
// [files.ReadSignatureLine] would refuse. The lines of the journal of signatures are numbered
// from 1 without a gap, and a key is born once: the unit is the pair of label and purpose, because
// one label names an X.509 key and an OpenPGP primary together (docs/reference/bundle.md, "root.json"),
// and the two are two births. The state is behind a lock, so two goroutines
// that append keep every line whole and in one order.
type fileJournal struct {
	j    *fsx.Journal
	kind journalKind
	op   string

	mu    sync.Mutex
	count int
	born  map[birthKey]bool
}

// birthKey is the unit of a birth: a label and the purpose of the key.
type birthKey struct{ label, purpose string }

// Append checks line and writes it. It copies the line first, so a caller that changes its bytes
// after the call cannot change what was checked.
func (j *fileJournal) Append(line []byte) error {
	if j == nil || j.j == nil || j.kind == 0 {
		return newError("journal", ErrOutOfOrder, nil, "there is no journal")
	}
	own := bytes.Clone(line)
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.count >= MaxJournalLines {
		return newError(j.op, ErrInvalidInput, nil, "a journal takes at most %d lines", MaxJournalLines)
	}
	key, err := j.checkKey(own)
	if err != nil {
		return err
	}
	if err := j.j.Append(own); err != nil {
		if errors.Is(err, fsx.ErrClosed) {
			return newError(j.op, ErrOutOfOrder, err, "the journal is closed")
		}
		if errors.Is(err, fsx.ErrInvalid) && !errors.Is(err, fsx.ErrStopped) {
			return newError(j.op, ErrInvalidInput, err, "the line is refused")
		}
		return newError(j.op, ErrFolderStopped, err, "the line could not be written")
	}
	j.count++
	if key != (birthKey{}) {
		if j.born == nil {
			j.born = make(map[birthKey]bool)
		}
		j.born[key] = true
	}
	return nil
}

// check judges a line and returns the label of a birth line, "" for a line of the other journal.
func (j *fileJournal) check(line []byte) (label string, err error) {
	k, err := j.checkKey(line)
	return k.label, err
}

// checkKey judges a line and returns the key of a birth line, and the zero key for a line of the
// other journal.
func (j *fileJournal) checkKey(line []byte) (key birthKey, err error) {
	switch j.kind {
	case kindBirths:
		l, err := files.ReadBirthLine(line)
		if err != nil {
			return birthKey{}, newError(j.op, ErrInvalidInput, err, "the line is refused by its reader")
		}
		k := birthKey{l.Label, l.Purpose}
		if j.born[k] {
			return birthKey{}, newError(j.op, ErrInvalidInput, nil, "the key %s is born twice for the purpose %s", l.Label, l.Purpose)
		}
		return k, nil
	case kindSignatures:
		l, err := files.ReadSignatureLine(line)
		if err != nil {
			return birthKey{}, newError(j.op, ErrInvalidInput, err, "the line is refused by its reader")
		}
		if l.N != int64(j.count)+1 {
			return birthKey{}, newError(j.op, ErrInvalidInput, nil, "the signature n=%d comes after %d lines; the next is n=%d", l.N, j.count, j.count+1)
		}
		return birthKey{}, nil
	}
	return birthKey{}, newError(j.op, ErrOutOfOrder, nil, "there is no journal")
}

// journalLines splits the bytes of a journal into its whole lines. ok is false when the file ends
// with a line that has no line feed, or holds an empty line, or more than [MaxJournalLines] lines:
// such a file is not a journal that a record can list as a whole.
func journalLines(data []byte) (lines [][]byte, ok bool) {
	if len(data) == 0 {
		return nil, true
	}
	if data[len(data)-1] != '\n' {
		return nil, false
	}
	if bytes.Count(data, []byte{'\n'}) > MaxJournalLines {
		return nil, false
	}
	lines = bytes.Split(data[:len(data)-1], []byte{'\n'})
	for _, l := range lines {
		if len(l) == 0 {
			return nil, false
		}
	}
	return lines, true
}
