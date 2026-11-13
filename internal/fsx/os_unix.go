//go:build linux || darwin

package fsx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

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

// ReadFile reads the regular file name. It asks the folder what the name is before it opens it
// (a link, a FIFO or a device is refused without being opened, so a FIFO is not waited on and
// a device is not touched), opens it without following a link and without waiting, and asks
// the open file again, because the name can be swapped between the two: only a regular file is
// read, and at most [MaxReadSize] bytes of it.
func (d *osDir) ReadFile(name string) ([]byte, error) {
	if err := checkElem(name); err != nil {
		return nil, err
	}
	var data []byte
	err := d.with(func(fd int) error {
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if err := regularOrRefuse(uint32(st.Mode)); err != nil {
			return err
		}
		nfd, err := unix.Openat(fd, name, readFlags, 0)
		if err != nil {
			return classify(fd, name, err)
		}
		if err := unix.Fstat(nfd, &st); err != nil {
			_ = unix.Close(nfd)
			return err
		}
		if err := regularOrRefuse(uint32(st.Mode)); err != nil {
			_ = unix.Close(nfd)
			return err
		}
		if st.Size > MaxReadSize {
			_ = unix.Close(nfd)
			return fmt.Errorf("%w: %d bytes, more than %d", ErrTooLarge, st.Size, MaxReadSize)
		}
		// It is a regular file: the read does not wait, and the descriptor can be a plain one.
		if err := unix.SetNonblock(nfd, false); err != nil {
			_ = unix.Close(nfd)
			return err
		}
		f := os.NewFile(uintptr(nfd), "file")
		defer func() { _ = f.Close() }() // a read-only handle: its close says nothing the read did not
		// The size can have grown since the stat: read one byte more than the limit to see it.
		data, err = io.ReadAll(io.LimitReader(f, MaxReadSize+1))
		if err != nil {
			return err
		}
		if len(data) > MaxReadSize {
			data = nil
			return fmt.Errorf("%w: more than %d bytes", ErrTooLarge, MaxReadSize)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return data, nil
}

// regularOrRefuse says why a file of this mode is not read: a symbolic link, or not a regular
// file.
func regularOrRefuse(mode uint32) error {
	switch mode & unix.S_IFMT {
	case unix.S_IFREG:
		return nil
	case unix.S_IFLNK:
		return ErrLink
	default:
		return ErrNotRegular
	}
}

// ReadDir lists the folder. It reads the names through a second handle on the same folder (the
// open of "." cannot be a link), so that a list never shares an offset with another one, and
// describes each name with a stat of the folder that does not follow a link. A name that is
// gone between the two is left out: a list shows what the folder held while it was read.
func (d *osDir) ReadDir() ([]fs.DirEntry, error) {
	var out []fs.DirEntry
	err := d.with(func(fd int) error {
		nfd, err := unix.Openat(fd, ".", openFolderFlags, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(nfd), "folder")
		defer func() { _ = f.Close() }() // a read-only handle: its close says nothing the read did not
		names, err := f.Readdirnames(-1)
		if err != nil {
			return err
		}
		sort.Strings(names)
		for _, name := range names {
			var st unix.Stat_t
			if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return err
			}
			out = append(out, fs.FileInfoToDirEntry(&entryInfo{name: name, size: st.Size, mode: modeOf(uint32(st.Mode))}))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// entryInfo is the fs.FileInfo of an entry of a listing: what a stat that does not follow a link
// said, without the time.
type entryInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (i *entryInfo) Name() string       { return i.name }
func (i *entryInfo) Size() int64        { return i.size }
func (i *entryInfo) Mode() fs.FileMode  { return i.mode }
func (i *entryInfo) ModTime() time.Time { return time.Time{} }
func (i *entryInfo) IsDir() bool        { return i.mode.IsDir() }
func (i *entryInfo) Sys() any           { return nil }

// modeOf maps the mode of a stat to the type and permission bits of an fs.FileMode.
func modeOf(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & unix.S_IFMT {
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFIFO:
		mode |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		mode |= fs.ModeSocket
	case unix.S_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFBLK:
		mode |= fs.ModeDevice
	}
	return mode
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
