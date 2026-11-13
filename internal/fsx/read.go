package fsx

import (
	"fmt"
	"io/fs"
)

// ReadFile returns the whole content of the regular file at path, which is relative to the
// root of fsys, with "/" as the separator, and is walked from it one element at a time without
// following a link. A file that is not a regular file (a folder, a FIFO, a device) or that is a
// link is an error, and so is a file longer than [MaxReadSize]. The rules for the names of a
// path are those of the writer, except that a read may name a temporary name. The error of a
// failed read is an *[Error] with [StepOpenDir] (a failed walk) or [StepRead]; it does not
// stop any writer.
func ReadFile(fsys FS, path string) ([]byte, error) {
	if fsys == nil {
		return nil, ErrNoRoot
	}
	elems, err := parsePath(path, false)
	if err != nil {
		return nil, err
	}
	dir, name := elems[:len(elems)-1], elems[len(elems)-1]
	d, upto, err := openFolder(fsys, dir)
	if err != nil {
		return nil, &Error{Step: StepOpenDir, Path: upto, Err: err}
	}
	defer d.release()
	data, err := d.fs.ReadFile(name)
	if err != nil {
		return nil, &Error{Step: StepRead, Path: path, Err: err}
	}
	return data, nil
}

// ReadDir lists the folder at path, which is relative to the root of fsys and walked as
// [ReadFile] walks; the path "." is the root itself. The list holds every name in the folder,
// the temporary names that a stop left too. The caller that reads a bundle skips every name
// with the prefix [TempPrefix], compared without case, because a temporary folder holds whole
// files under ordinary names. A folder with more than [MaxDirEntries] names is an error that wraps
// [ErrTooMany], and nothing is returned in part. The error of a failed read is an *[Error] as for
// [ReadFile].
func ReadDir(fsys FS, path string) ([]fs.DirEntry, error) {
	if fsys == nil {
		return nil, ErrNoRoot
	}
	var elems []string
	if path != "." {
		var err error
		if elems, err = parsePath(path, false); err != nil {
			return nil, err
		}
	}
	d, upto, err := openFolder(fsys, elems)
	if err != nil {
		return nil, &Error{Step: StepOpenDir, Path: upto, Err: err}
	}
	defer d.release()
	ents, err := d.fs.ReadDir()
	if err != nil {
		return nil, &Error{Step: StepRead, Path: path, Err: err}
	}
	if len(ents) > MaxDirEntries { // an FS that did not keep its promise
		return nil, &Error{Step: StepRead, Path: path, Err: fmt.Errorf("%w: %d names, more than %d", ErrTooMany, len(ents), MaxDirEntries)}
	}
	return ents, nil
}
