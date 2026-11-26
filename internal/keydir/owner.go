//go:build linux || darwin

package keydir

import (
	"io/fs"
	"os"
	"syscall"
)

// ownedByMe reports whether the owner of the file is the user of this process, as the key driver of atom
// tests it.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
