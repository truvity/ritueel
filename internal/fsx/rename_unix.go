//go:build linux || darwin

package fsx

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// renameNoReplace renames oldName to newName in the folder dirfd with the one system call that
// refuses to replace (see [renameNoReplaceCall]). The call fails with EEXIST when newName
// exists. An error that says the system or the file system does not know the call or its flag
// (EINVAL, ENOSYS, ENOTSUP) wraps [ErrNoReplaceUnsupported]; nothing is renamed then, and no
// other call is tried: there is no fallback to a rename that replaces, here or anywhere in the
// package.
func renameNoReplace(dirfd int, oldName, newName string) error {
	err := renameNoReplaceCall(dirfd, oldName, newName)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP) {
		err = fmt.Errorf("%w: %w", ErrNoReplaceUnsupported, err)
	}
	return err
}
