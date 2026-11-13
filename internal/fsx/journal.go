package fsx

import (
	"bytes"
	"fmt"
	"io"
)

// Journal is a file that grows by one flushed line at a time: the birth journal and the
// journal of signatures (record 0005, rule 10). Its file is hidden behind this type, so
// that a second copy of the journals can be added later without a change of the surface
// (issue 181). It belongs to the [Writer] that made it: the stop of the writer is the stop
// of the journal, and [Writer.Close] closes every journal that is still open.
//
// The state of a journal (its file and whether it is closed) lives behind a pointer that the
// copies of a Journal share, so a Journal that is copied by value (j2 := *j) is the same
// journal: a Close through one copy closes it for the other, and a second Close through the
// other is a second Close, which does nothing. A Journal that is not made by
// [Writer.CreateJournal] (the zero value) has no state; it is closed already.
type Journal struct {
	s *journalState
}

// journalState is what the copies of a Journal share. The writer's lock guards every field.
type journalState struct {
	w      *Writer
	f      File
	path   string
	closed bool
}

// CreateJournal makes an empty journal by an exclusive create (mode 0600) at path, which is
// relative to the root, flushes it and then its folder, and keeps it open for
// [Journal.Append]. A second create of the same path fails with an error that wraps
// fs.ErrExist (Step create). The folder is walked once, and the create and the flush of the
// folder work through that handle, which is closed before the call returns; the journal's own
// file stays open until [Journal.Close] or [Writer.Close].
func (w *Writer) CreateJournal(path string) (*Journal, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.begin(); err != nil {
		return nil, err
	}
	elems, err := parsePath(path, true)
	if err != nil {
		return nil, err
	}
	dir, name := elems[:len(elems)-1], elems[len(elems)-1]
	dp := dirPath(dir)
	d, err := w.enter(dir)
	if err != nil {
		return nil, err
	}
	defer d.release()
	f, err := d.fs.CreateExcl(name, journalPerm)
	if err != nil {
		return nil, w.stop(StepCreate, path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return nil, w.stop(StepSyncFile, path, err)
	}
	if err := d.fs.Sync(); err != nil {
		_ = f.Close()
		return nil, w.stop(StepSyncDir, dp, err)
	}
	s := &journalState{w: w, f: f, path: path}
	if w.journals == nil {
		w.journals = make(map[*journalState]struct{})
	}
	w.journals[s] = struct{}{}
	return &Journal{s: s}, nil
}

// Append writes line and a newline in one write, then flushes. line holds no '\n'; a line
// that does is refused with [ErrInvalid] before anything is written, and the journal stays
// usable. When the write or the flush fails, the writer stops (and with it every journal it
// made); the caller must not report the line as written. A returned nil means that the file
// system took the flush, nothing more. After a stop Append returns the stop, whatever the
// line is; on a closed journal it returns [ErrClosed], and a journal that the closing of its
// writer closed is closed.
func (j *Journal) Append(line []byte) error {
	if j == nil || j.s == nil {
		return ErrClosed // not made by CreateJournal: there is no writer and no file
	}
	s := j.s
	w := s.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if s.closed {
		return ErrClosed
	}
	if bytes.IndexByte(line, '\n') >= 0 {
		return fmt.Errorf("%w: a journal line holds no newline", ErrInvalid)
	}
	buf := make([]byte, 0, len(line)+1)
	buf = append(buf, line...)
	buf = append(buf, '\n')
	n, err := s.f.Write(buf)
	if err == nil && n < len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return w.stop(StepWrite, s.path, err)
	}
	if err := s.f.Sync(); err != nil {
		return w.stop(StepSyncFile, s.path, err)
	}
	return nil
}

// Close releases the file. Every line was flushed by its Append, so Close flushes nothing
// more. It closes the file even when the writer has stopped, and returns the stop in that
// case; a second Close, through this Journal or through a copy of it, does nothing and returns
// nil. A Journal that CreateJournal did not make (a zero value) is closed already: Append
// returns [ErrClosed] and Close returns nil.
func (j *Journal) Close() error {
	if j == nil || j.s == nil {
		return nil // not made by CreateJournal: nothing is open
	}
	s := j.s
	w := s.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if s.closed {
		return nil
	}
	err := w.closeJournal(s)
	if w.err != nil {
		return w.err
	}
	if err != nil {
		return w.stop(StepSyncFile, s.path, err)
	}
	return nil
}

// closeJournal closes the file of a journal that is open, under the writer's lock, and forgets
// the journal. It returns the error of the close of the file.
func (w *Writer) closeJournal(s *journalState) error {
	s.closed = true
	delete(w.journals, s)
	return s.f.Close()
}

// ReadJournal returns the whole lines of a journal (each ended by a newline, without it)
// and, apart, the bytes after the last newline. A last line with no newline does not parse
// and counts as not written; it is for a person to read. partial is nil when the file ends
// with a newline or is empty. The slices alias one buffer. path is relative to the root of fsys
// and is read as [ReadFile] reads: walked from the root without following a link, and only a
// regular file no longer than [MaxReadSize]. A journal with more than [MaxJournalLines] lines is
// refused with an *[Error] (step read, with the path) that wraps [ErrTooMany], and nothing of it
// is returned. The lines are counted first and the result is allocated once, so the memory of a
// call is bounded: the buffer of the file (at most [MaxReadSize], up to twice that while it is
// read) and 24 bytes for each of at most [MaxJournalLines] lines, 1.5 MiB. ReadJournal reaches no
// writer, so it works after a stop.
func ReadJournal(fsys FS, path string) (lines [][]byte, partial []byte, err error) {
	data, err := ReadFile(fsys, path)
	if err != nil {
		return nil, nil, err
	}
	n := bytes.Count(data, []byte{'\n'})
	if n > MaxJournalLines {
		return nil, nil, &Error{Step: StepRead, Path: path, Err: fmt.Errorf("%w: %d lines, more than %d", ErrTooMany, n, MaxJournalLines)}
	}
	if n > 0 {
		lines = make([][]byte, 0, n)
	}
	for len(lines) < n {
		i := bytes.IndexByte(data, '\n')
		lines = append(lines, data[:i:i])
		data = data[i+1:]
	}
	if len(data) > 0 {
		partial = data[:len(data):len(data)]
	}
	return lines, partial, nil
}
