//go:build linux

package fsx

import "golang.org/x/sys/unix"

// renameNoReplaceCall is the one system call of the rename that refuses to replace: renameat2
// with RENAME_NOREPLACE, both names in the folder dirfd. It is a variable so that a test that
// lives in this package can put a call in its place that fails with EINVAL, ENOSYS or ENOTSUP,
// the answers of a system or a file system that does not know the flag, and check that the
// writer then returns [ErrNoReplaceUnsupported], replaces nothing and leaves the temporary
// name. Nothing but a test assigns it, and a test that does restores it, and does not run in
// parallel with another that reaches the rename.
var renameNoReplaceCall = func(dirfd int, oldName, newName string) error {
	return unix.Renameat2(dirfd, oldName, dirfd, newName, unix.RENAME_NOREPLACE)
}
