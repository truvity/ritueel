//go:build linux || darwin

package fsx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// The flags of the calls. Every open is relative to a folder handle, never follows a link at its
// last element (O_NOFOLLOW; the elements before it are not walked at all, see [FS]) and is
// closed when the process runs another program (O_CLOEXEC).
const (
	// openFolderFlags opens a folder for the walk, for the flush and for the list. O_DIRECTORY
	// makes the open fail when the element is not a folder.
	openFolderFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	// createFlags creates a file that does not exist: a file or a link of that name makes the
	// call fail, and a dangling link is not followed to create the file behind it.
	createFlags = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC
	// readFlags opens a file to read it. O_NONBLOCK keeps the open of a FIFO from waiting for a
	// writer, and O_NOCTTY keeps a terminal device from becoming the terminal of the process.
	readFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC
)

// OpenFS opens the folder root and returns the real file system rooted there: every path the
// writer or a reader gives it is walked from that folder, one element at a time, with no link
// followed. root is resolved by the operating system as it is given (a link in any element
// before the last one is followed, as the caller wrote it), with one exception: its last
// element must be a folder and must not be a symbolic link, and a trailing separator does not
// hide that (the path "link/" is read as "link"). The handle stays open until its Close, and the
// root is the one folder that the writer holds for its whole life.
//
// A rename that refuses to replace is renameat2 with RENAME_NOREPLACE on Linux and renameatx_np
// with RENAME_EXCL on macOS; on any other system OpenFS returns an error that wraps
// [ErrNoReplaceUnsupported]. The permission bits of a new file or folder are the ones given,
// less the umask of the process.
func OpenFS(root string) (FS, error) {
	if root == "" {
		return nil, fmt.Errorf("%w: empty root", ErrInvalid)
	}
	clean := strings.TrimRight(root, "/")
	if clean == "" {
		clean = "/"
	}
	fd, err := unix.Open(clean, openFolderFlags, 0)
	if err != nil {
		if isLinkErrno(err) {
			var st unix.Stat_t
			if unix.Lstat(clean, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				err = fmt.Errorf("%w: %w", ErrLink, err)
			}
		}
		return nil, fmt.Errorf("fsx: open the root %q: %w", root, err)
	}
	return newDir(fd, "root"), nil
}

// osDir is an open folder of the real file system. Its calls share a read lock and Close takes the
// write lock, so a Close never closes the descriptor under a call that uses it, and a call
// after Close never reaches a descriptor number that another file has taken since.
type osDir struct {
	mu     sync.RWMutex
	f      *os.File
	closed bool
}

// newDir wraps an open folder descriptor. The name is only a label for the texts of the os
// package; it is a fixed word, never a name from a path.
func newDir(fd int, label string) *osDir {
	return &osDir{f: os.NewFile(uintptr(fd), label)}
}

// with runs fn with the descriptor of the folder, or returns fs.ErrClosed.
func (d *osDir) with(fn func(fd int) error) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return fs.ErrClosed
	}
	return fn(int(d.f.Fd()))
}

// checkElem refuses what is not one plain element: the package passes only such names, and a
// caller of an FS that skips the package must not be able to walk with one call.
func checkElem(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("%w: %q is not one plain element", ErrInvalid, name)
	}
	return nil
}

// isLinkErrno reports the errors that an open with O_NOFOLLOW (and O_DIRECTORY) gives for a
// symbolic link: Linux answers ELOOP, or ENOTDIR when O_DIRECTORY is set too, and macOS ELOOP.
func isLinkErrno(err error) bool {
	return errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR)
}

// classify says that an element is a link when the open failed in the way a link fails. It asks
// the folder, without following, what the name is.
func classify(dirfd int, name string, err error) error {
	if !isLinkErrno(err) {
		return err
	}
	var st unix.Stat_t
	if unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("%w: %w", ErrLink, err)
	}
	return err
}

func (d *osDir) OpenDir(name string) (FS, error) {
	if err := checkElem(name); err != nil {
		return nil, err
	}
	var child *osDir
	err := d.with(func(fd int) error {
		nfd, err := unix.Openat(fd, name, openFolderFlags, 0)
		if err != nil {
			return classify(fd, name, err)
		}
		child = newDir(nfd, "folder")
		return nil
	})
	if err != nil {
		return nil, err
	}
	return child, nil
}

func (d *osDir) Mkdir(name string, perm fs.FileMode) error {
	if err := checkElem(name); err != nil {
		return err
	}
	return d.with(func(fd int) error { return unix.Mkdirat(fd, name, uint32(perm&fs.ModePerm)) })
}

func (d *osDir) CreateExcl(name string, perm fs.FileMode) (File, error) {
	if err := checkElem(name); err != nil {
		return nil, err
	}
	var f *os.File
	err := d.with(func(fd int) error {
		nfd, err := unix.Openat(fd, name, createFlags, uint32(perm&fs.ModePerm))
		if err != nil {
			return err
		}
		f = os.NewFile(uintptr(nfd), "file")
		return nil
	})
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (d *osDir) RenameNoReplace(oldName, newName string) error {
	if err := checkElem(oldName); err != nil {
		return err
	}
	if err := checkElem(newName); err != nil {
		return err
	}
	return d.with(func(fd int) error { return renameNoReplace(fd, oldName, newName) })
}

// Sync flushes the folder through its handle (on macOS the Go runtime asks for a full flush of
// the device).
func (d *osDir) Sync() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return fs.ErrClosed
	}
	return d.f.Sync()
}

// ReadFile reads the regular file name.
func (d *osDir) ReadFile(name string) ([]byte, error) {
	if err := checkElem(name); err != nil {
		return nil, err
	}
	var data []byte
	err := d.with(func(fd int) error {
		nfd, err := unix.Openat(fd, name, readFlags, 0)
		if err != nil {
			return classify(fd, name, err)
		}
		f := os.NewFile(uintptr(nfd), "file")
		defer f.Close()
		data, err = io.ReadAll(f)
		return err
	})
	return data, err
}

func (d *osDir) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	return d.f.Close()
}
