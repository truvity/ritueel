package fsx

import (
	"io/fs"
	"os"
)

// OS is the real file system. Its rename that refuses to replace is renameat2 with
// RENAME_NOREPLACE on Linux and renamex_np with RENAME_EXCL on macOS; on any other system
// RenameNoReplace returns ErrNoReplaceUnsupported. The permission bits of a new file or
// folder are the ones given, less the umask of the process.
var OS FS = osFS{}

type osFS struct{}

func (osFS) Mkdir(path string, perm fs.FileMode) error { return os.Mkdir(path, perm) }

func (osFS) CreateExcl(path string, perm fs.FileMode) (File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
}

// SyncDir opens the folder and calls Sync on it (on macOS the Go runtime asks for a full
// flush of the device).
func (osFS) SyncDir(path string) (err error) {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := d.Close(); err == nil {
			err = cerr
		}
	}()
	return d.Sync()
}

func (osFS) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }
func (osFS) ReadFile(path string) ([]byte, error)       { return os.ReadFile(path) }
func (osFS) Stat(path string) (fs.FileInfo, error)      { return os.Stat(path) }
