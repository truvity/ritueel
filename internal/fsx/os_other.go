//go:build !linux && !darwin

package fsx

import (
	"fmt"
	"runtime"
)

// OpenFS has no rooted file system on this system: the calls that make it safe (openat with
// O_NOFOLLOW, and a rename that refuses to replace) are wired for Linux and macOS only, and
// there is no fallback to a path-based file system that follows links or to a rename that
// replaces.
func OpenFS(root string) (FS, error) {
	return nil, fmt.Errorf("fsx: no rooted file system on %s: %w", runtime.GOOS, ErrNoReplaceUnsupported)
}
