//go:build linux

package fsx

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldName to newName in the folder dirfd with renameat2 and
// RENAME_NOREPLACE, so that the call fails with EEXIST when newName exists. An error that says
// the system or the file system does not know the flag wraps ErrNoReplaceUnsupported; nothing
// is renamed then, and no other call is tried.
func renameNoReplace(dirfd int, oldName, newName string) error {
	err := unix.Renameat2(dirfd, oldName, dirfd, newName, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) {
		err = fmt.Errorf("%w: %w", ErrNoReplaceUnsupported, err)
	}
	return err
}
