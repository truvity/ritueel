//go:build !linux && !darwin

package fsx

import "os"

// No system call that refuses to replace is wired for this system, and there is no
// fallback to a rename that replaces.
func (osFS) RenameNoReplace(oldpath, newpath string) error {
	return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: ErrNoReplaceUnsupported}
}
