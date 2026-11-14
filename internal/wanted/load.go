package wanted

import (
	"errors"
	"fmt"
	"io/fs"

	"ritueel.id/ritueel/internal/fsx"
)

// readFile reads one wanted file through package fsx, which follows no link in any element of the path,
// opens without waiting and reads only a regular file. A file over [MaxBytes] is an error. The read itself is
// bounded by [fsx.MaxReadSize] (8 MiB), not by [MaxBytes]: the longer file is read into memory and then
// refused. The error is an [*Error] that wraps the error of the file system, so that
// errors.Is(err, fs.ErrNotExist) tells a missing file.
func readFile(fsys fsx.FS, path string) ([]byte, error) {
	if fsys == nil {
		return nil, errorf(path, 0, "there is no folder to read it from")
	}
	data, err := fsx.ReadFile(fsys, path)
	if err != nil {
		e := errorf(path, 0, "the file cannot be read: "+readFault(err))
		e.cause = err
		return nil, e
	}
	if len(data) > MaxBytes {
		return nil, errorf(path, 0, fmt.Sprintf("the file is longer than %d bytes", MaxBytes))
	}
	return data, nil
}

// readFault is the short text for the error of a read: fixed words for the faults that are told apart.
func readFault(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "it does not exist"
	case errors.Is(err, fsx.ErrLink):
		return "a link is not followed"
	case errors.Is(err, fsx.ErrNotRegular):
		return "it is not a regular file"
	case errors.Is(err, fsx.ErrTooLarge):
		return "it is too long"
	}
	return "the system refused to read it"
}
