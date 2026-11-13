//go:build darwin

package fsx

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func (osFS) RenameNoReplace(oldpath, newpath string) error {
	err := unix.RenamexNp(oldpath, newpath, unix.RENAME_EXCL)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) {
		err = fmt.Errorf("%w: %w", ErrNoReplaceUnsupported, err)
	}
	return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
}
