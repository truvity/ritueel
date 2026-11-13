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
// of the journal.
type Journal struct {
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
	return &Journal{w: w, f: f, path: path}, nil
}

// Append writes line and a newline in one write, then flushes. line holds no '\n'; a line
// that does is refused with [ErrInvalid] before anything is written, and the journal stays
// usable. When the write or the flush fails, the writer stops (and with it every journal it
// made); the caller must not report the line as written. A returned nil means that the file
// system took the flush, nothing more.
func (j *Journal) Append(line []byte) error {
	if j == nil || j.w == nil {
		return ErrClosed // not made by CreateJournal: there is no writer and no file
	}
	w := j.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	if j.closed {
		return ErrClosed
	}
	if bytes.IndexByte(line, '\n') >= 0 {
		return fmt.Errorf("%w: a journal line holds no newline", ErrInvalid)
	}
	buf := make([]byte, 0, len(line)+1)
	buf = append(buf, line...)
	buf = append(buf, '\n')
	n, err := j.f.Write(buf)
	if err == nil && n < len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return w.stop(StepWrite, j.path, err)
	}
	if err := j.f.Sync(); err != nil {
		return w.stop(StepSyncFile, j.path, err)
	}
	return nil
}

// Close releases the file. Every line was flushed by its Append, so Close flushes nothing
// more. It closes the file even when the writer has stopped, and returns the stop in that
// case; a second Close does nothing and returns nil. A Journal that CreateJournal did not
// make (a zero value) is closed already: Append returns [ErrClosed] and Close returns nil.
func (j *Journal) Close() error {
	if j == nil || j.w == nil {
		return nil // not made by CreateJournal: nothing is open
	}
	w := j.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	err := j.f.Close()
	if w.err != nil {
		return w.err
	}
	if err != nil {
		return w.stop(StepSyncFile, j.path, err)
	}
	return nil
}

// ReadJournal returns the whole lines of a journal (each ended by a newline, without it)
// and, apart, the bytes after the last newline. A last line with no newline does not parse
// and counts as not written; it is for a person to read. partial is nil when the file ends
// with a newline or is empty. The slices alias one buffer. path is relative to the root of fsys
// and is walked from it without following a link; the journal itself is read as [FS.ReadFile]
// reads a file. ReadJournal reaches no writer, so it works after a stop.
func ReadJournal(fsys FS, path string) (lines [][]byte, partial []byte, err error) {
	if fsys == nil {
		return nil, nil, ErrNoRoot
	}
	elems, err := parsePath(path, false)
	if err != nil {
		return nil, nil, err
	}
	dir, name := elems[:len(elems)-1], elems[len(elems)-1]
	d, upto, err := openFolder(fsys, dir)
	if err != nil {
		return nil, nil, &Error{Step: StepOpenDir, Path: upto, Err: err}
	}
	defer d.release()
	data, err := d.fs.ReadFile(name)
	if err != nil {
		return nil, nil, &Error{Step: StepRead, Path: path, Err: err}
	}
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		lines = append(lines, data[:i:i])
		data = data[i+1:]
	}
	if len(data) > 0 {
		partial = data[:len(data):len(data)]
	}
	return lines, partial, nil
}
