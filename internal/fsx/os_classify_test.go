//go:build linux || darwin

package fsx_test

// How a failed open is told from a link: after every failed open of a folder element, of a file to
// read and of the root, the package asks, with a look that does not follow, what the name is. A
// link wraps ErrLink and keeps the original error number in the chain; a failed look, and a name
// that is not a link, leave the original error as it came.
//
// What these tests cannot do: make the open fail with an error number other than ELOOP and
// ENOTDIR on a name that is a link. Linux answers ENOTDIR (with O_DIRECTORY) or ELOOP, and a
// failed look as well as the failed open on a name that the process may not search both fail alike,
// so no real case gives another number. That needs a seam like the one of the rename: a package
// variable `openatCall func(dirfd int, name string, flags int, mode uint32) (int, error)`, which
// OpenDir and ReadFile use in place of unix.Openat, so that a test can answer EACCES, EIO, EMLINK
// or any other number for a name that is a link, and require ErrLink beside that number. The
// source does not have one, and none is added here. The break "classify looks at the error number
// again" is therefore shown only as far as Linux's own numbers go: a break that gates classify on
// ELOOP alone is killed (Linux gives ENOTDIR for a folder element), one that gates it on ELOOP or
// ENOTDIR is not.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func requireBareErrno(t *testing.T, err error, want syscall.Errno) {
	t.Helper()
	if got := fmt.Sprintf("%T", err); got != "syscall.Errno" {
		t.Fatalf("got %v (%s), want the error number %v itself, unchanged", err, got, want)
	}
	if got, ok := err.(syscall.Errno); !ok || got != want { //nolint:errorlint // the bare number, not an error that wraps it
		t.Fatalf("got %v, want %v", err, want)
	}
	if errors.Is(err, fsx.ErrLink) {
		t.Fatalf("got %v: a name that is not a link must not be named one", err)
	}
}

func TestOSAnErrorNumberIsStillFoundBesideErrLink(t *testing.T) {
	wd := newWorld(t)
	wd.mkdir("d")
	wd.symlink(filepath.Join("..", "outside"), "d/dirlink")
	wd.symlink("nothing", "d/dangling")
	wd.symlink("d", "filelink")
	root := openFSIn(t, wd.root)
	d, err := root.OpenDir("d")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	for _, c := range []struct {
		name string
		open func() error
	}{
		{"OpenDir of a link to a folder", func() error { _, err := d.OpenDir("dirlink"); return err }},
		{"OpenDir of a dangling link", func() error { _, err := d.OpenDir("dangling"); return err }},
		{"OpenDir of a link at the root", func() error { _, err := root.OpenDir("filelink"); return err }},
		{"OpenFS of a link", func() error { _, err := fsx.OpenFS(filepath.Join(wd.root, "filelink")); return err }},
		{"OpenFS of a link with a slash", func() error { _, err := fsx.OpenFS(filepath.Join(wd.root, "filelink") + "/"); return err }},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.open()
			if !errors.Is(err, fsx.ErrLink) {
				t.Fatalf("got %v, want an error that wraps ErrLink", err)
			}
			var errno syscall.Errno
			if !errors.As(err, &errno) {
				t.Fatalf("got %v: the error number of the open is not in the chain", err)
			}
			// the number is the system's own for this open, and it is found by errors.Is as well
			if !errors.Is(err, errno) || (errno != syscall.ELOOP && errno != syscall.ENOTDIR) {
				t.Fatalf("got %v with the number %v, want ELOOP or ENOTDIR (what this system gives)", err, errno)
			}
		})
	}
}

func TestOSAFailedOpenOfANameThatIsNotALinkIsLeftAsItCame(t *testing.T) {
	wd := newWorld(t)
	wd.mkdir("d")
	if err := os.WriteFile(filepath.Join(wd.root, "d", "file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wd.mkfifo("d/pipe")
	root := openFSIn(t, wd.root)
	d, err := root.OpenDir("d")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()

	// the open fails and the look fails too (the name is not there): the original number, bare
	_, err = d.OpenDir("missing")
	requireBareErrno(t, err, syscall.ENOENT)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want fs.ErrNotExist", err)
	}
	// the open fails, the look succeeds and finds a file or a FIFO: not a link, the number as it came
	_, err = d.OpenDir("file")
	requireBareErrno(t, err, syscall.ENOTDIR)
	_, err = d.OpenDir("pipe")
	requireBareErrno(t, err, syscall.ENOTDIR)
	// and the root
	for _, p := range []string{filepath.Join(wd.root, "missing"), filepath.Join(wd.root, "d", "file"), filepath.Join(wd.root, "d", "pipe")} {
		_, err := fsx.OpenFS(p)
		if err == nil || errors.Is(err, fsx.ErrLink) {
			t.Errorf("OpenFS(%s): %v, want an error that is not ErrLink", p, err)
		}
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			t.Errorf("OpenFS(%s): %v: the error number is not in the chain", p, err)
		}
	}
	if _, err := fsx.OpenFS(filepath.Join(wd.root, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("OpenFS of a missing root: %v, want fs.ErrNotExist", err)
	}
}

// The two texts of the real file system that quote what the caller gave, with a character beyond
// ASCII in it: the root, and an element that is not one plain element.
func TestOSTheTextsThatQuoteTheCallersNameHoldNoRawCharacter(t *testing.T) {
	base := t.TempDir()
	_, err := fsx.OpenFS(filepath.Join(base, "no-such-\u00e9-\U0001f600"))
	if err == nil {
		t.Fatal("OpenFS of a missing root succeeded")
	}
	want := `fsx: open the root "` + base + `/no-such-\u00e9-\U0001f600": no such file or directory`
	if err.Error() != want {
		t.Fatalf("OpenFS: %s, want\n  %s", err.Error(), want)
	}
	if _, err := fsx.OpenFS(""); err == nil || err.Error() != "fsx: invalid argument: empty root" {
		t.Fatalf("OpenFS(\"\"): %v", err)
	}
	root := openFSIn(t, base)
	_, err = root.OpenDir("a/\u00e9\x07")
	const wantElem = `fsx: invalid argument: "a/\u00e9\a" is not one plain element`
	if err == nil || err.Error() != wantElem {
		t.Fatalf("OpenDir: %v, want\n  %s", err, wantElem)
	}
}
