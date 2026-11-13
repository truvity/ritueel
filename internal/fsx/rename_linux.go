//go:build linux

package fsx

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func (osFS) RenameNoReplace(oldpath, newpath string) error {
	err := unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) {
		err = fmt.Errorf("%w: %w", ErrNoReplaceUnsupported, err)
	}
	return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
}
