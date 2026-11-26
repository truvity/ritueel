//go:build !linux && !darwin

package keydir

import "io/fs"

// ownedByMe is false where the owner of a file cannot be read, so that a folder of the key driver is
// never taken as fit there.
func ownedByMe(fs.FileInfo) bool { return false }
