//go:build linux || darwin

package fsx_test

// The one system call of the rename that refuses to replace is behind a variable (export_test.go),
// so that the answers of a system or a file system that does not know the flag can be made. These
// tests do not run in parallel with any other: they replace the variable, and restore it.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

var unsupportedErrnos = []syscall.Errno{syscall.EINVAL, syscall.ENOSYS, syscall.ENOTSUP}

// replaceRename puts a call that counts and returns err in the place of the system call, and puts
// the original back when the test ends.
func replaceRename(t *testing.T, ret error) *int {
	t.Helper()
	calls := 0
	restore := fsx.SetRenameNoReplaceCall(func(dirfd int, oldName, newName string) error {
		calls++
		if dirfd < 0 || oldName == "" || newName == "" || strings.Contains(oldName+newName, "/") {
			t.Errorf("the rename got the folder %d and the names %q and %q: want a folder handle and two plain names", dirfd, oldName, newName)
		}
		return ret
	})
	t.Cleanup(restore)
	return &calls
}

func TestUnsupportedRenameStopsWritesAndReplacesNothing(t *testing.T) {
	for _, errno := range unsupportedErrnos {
		for _, op := range []string{"WriteFile", "WriteSet"} {
			t.Run(errno.Error()+"/"+op, func(t *testing.T) {
				w, dir := openIn(t)
				// something stands at the final name, and a plain rename would replace it
				switch op {
				case "WriteFile":
					if err := os.WriteFile(filepath.Join(dir, "final"), []byte("old"), 0o600); err != nil {
						t.Fatal(err)
					}
				default:
					if err := os.Mkdir(filepath.Join(dir, "final"), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, "final", "old"), []byte("old"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				calls := replaceRename(t, errno)
				var err error
				if op == "WriteFile" {
					err = w.WriteFile("final", []byte("new"), 0o600)
				} else {
					err = w.WriteSet("final", []fsx.NewFile{{Name: "new", Data: []byte("new"), Perm: 0o600}})
				}
				fe := requireFailed(t, err)
				if fe.Step != fsx.StepRename || fe.Path != "final" {
					t.Fatalf("got %v, want a rename error at final", err)
				}
				if !errors.Is(err, fsx.ErrNoReplaceUnsupported) {
					t.Fatalf("got %v, want an error that satisfies ErrNoReplaceUnsupported", err)
				}
				if !errors.Is(err, errno) {
					t.Fatalf("got %v, want an error that carries the errno %v", err, errno)
				}
				var got syscall.Errno
				if !errors.As(err, &got) || got != errno {
					t.Fatalf("errors.As gives %v, want %v", got, errno)
				}
				if errors.Is(err, fs.ErrExist) || errors.Is(err, fsx.ErrInvalid) {
					t.Fatalf("got %v: an unsupported rename is not an existing name and not an invalid argument", err)
				}
				if *calls != 1 {
					t.Fatalf("the rename call was made %d times, want once: no second try, no fallback", *calls)
				}
				// what stood at the final name is as it was
				if op == "WriteFile" {
					if got := readFile(t, filepath.Join(dir, "final")); string(got) != "old" {
						t.Fatalf("the file at the final name holds %q: it was replaced", got)
					}
				} else {
					if got := names(t, filepath.Join(dir, "final")); len(got) != 1 || got[0] != "old" {
						t.Fatalf("the folder at the final name holds %v: it was replaced", got)
					}
				}
				// the temporary name is left, whole, and nothing else was made
				left := tempNamed(names(t, dir))
				if len(left) != 1 || len(names(t, dir)) != 2 {
					t.Fatalf("the folder holds %v, want the final name and one temporary name", names(t, dir))
				}
				if op == "WriteFile" {
					if got := readFile(t, filepath.Join(dir, left[0])); string(got) != "new" {
						t.Fatalf("the temporary file holds %q, want the new content whole", got)
					}
				} else if got := names(t, filepath.Join(dir, left[0])); len(got) != 1 || got[0] != "new" {
					t.Fatalf("the temporary folder holds %v", got)
				}
				// the writer is stopped, and no later call renames, writes or makes anything
				requireStoppedBy(t, w.WriteFile("later", []byte("x"), 0o600), fe)
				requireStoppedBy(t, w.Mkdir("later-dir", 0o700), fe)
				if *calls != 1 || len(names(t, dir)) != 2 {
					t.Fatalf("a call after the stop did something: %d rename calls, %v", *calls, names(t, dir))
				}
			})
		}
	}
}

// TestOtherAnswersOfTheRenameAreNotUnsupported: an existing name is an existing name, and any other
// error stays what it is.
func TestOtherAnswersOfTheRenameAreNotUnsupported(t *testing.T) {
	for _, c := range []struct {
		errno       syscall.Errno
		unsupported bool
		exist       bool
	}{
		{syscall.EEXIST, false, true},
		{syscall.ENOTEMPTY, false, true}, // Go: ENOTEMPTY is fs.ErrExist
		{syscall.EPERM, false, false},
		{syscall.EACCES, false, false},
		{syscall.EIO, false, false},
		{syscall.ENOENT, false, false},
		{syscall.EXDEV, false, false},
		{syscall.EBUSY, false, false},
		{syscall.EOPNOTSUPP, true, false}, // the same number as ENOTSUP on Linux, a different one on macOS
	} {
		if c.errno == syscall.EOPNOTSUPP && syscall.EOPNOTSUPP != syscall.ENOTSUP {
			c.unsupported = false // a different errno: not one of the three
		}
		t.Run(c.errno.Error(), func(t *testing.T) {
			w, dir := openIn(t)
			replaceRename(t, c.errno)
			err := w.WriteFile("final", []byte("new"), 0o600)
			fe := requireFailed(t, err)
			if fe.Step != fsx.StepRename || !errors.Is(err, c.errno) {
				t.Fatalf("got %v, want a rename error that carries %v", err, c.errno)
			}
			if got := errors.Is(err, fsx.ErrNoReplaceUnsupported); got != c.unsupported {
				t.Errorf("errors.Is(err, ErrNoReplaceUnsupported) = %v, want %v for %v", got, c.unsupported, c.errno)
			}
			if got := errors.Is(err, fs.ErrExist); got != c.exist {
				t.Errorf("errors.Is(err, fs.ErrExist) = %v, want %v for %v", got, c.exist, c.errno)
			}
			if len(tempNamed(names(t, dir))) != 1 {
				t.Errorf("the folder holds %v, want the temporary name left", names(t, dir))
			}
		})
	}
}

// TestUnsupportedRenameOnAFolderHandle: the same through the handle, the call that the writer
// makes: the error satisfies ErrNoReplaceUnsupported and carries the errno, nothing is renamed, the
// handle goes on.
func TestUnsupportedRenameOnAFolderHandle(t *testing.T) {
	for _, errno := range unsupportedErrnos {
		t.Run(errno.Error(), func(t *testing.T) {
			dir := t.TempDir()
			root := openFSIn(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "a"), []byte("a"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "b"), []byte("b"), 0o600); err != nil {
				t.Fatal(err)
			}
			calls := replaceRename(t, errno)
			err := root.RenameNoReplace("a", "b")
			if !errors.Is(err, fsx.ErrNoReplaceUnsupported) || !errors.Is(err, errno) || *calls != 1 {
				t.Fatalf("got %v after %d calls", err, *calls)
			}
			if got := readFile(t, filepath.Join(dir, "a")); string(got) != "a" {
				t.Fatalf("a holds %q", got)
			}
			if got := readFile(t, filepath.Join(dir, "b")); string(got) != "b" {
				t.Fatalf("b holds %q: it was replaced", got)
			}
			if err := root.Sync(); err != nil {
				t.Fatalf("the handle does not go on: %v", err)
			}
		})
	}
}

// TestTheSeamIsRestoredAndTheRealCallRefuses: after a replacement is put back, the system call is
// in place again: a rename onto an existing name is refused by it, and one onto a free name works.
func TestTheSeamIsRestoredAndTheRealCallRefuses(t *testing.T) {
	dir := t.TempDir()
	root := openFSIn(t, dir)
	for _, n := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	restore := fsx.SetRenameNoReplaceCall(func(int, string, string) error { return syscall.ENOSYS })
	if err := root.RenameNoReplace("a", "b"); !errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		restore()
		t.Fatalf("the replacement was not used: %v", err)
	}
	restore()
	err := root.RenameNoReplace("a", "b")
	skipIfNoNoReplace(t, err)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("after the restore a rename onto an existing name gave %v, want fs.ErrExist", err)
	}
	if err := root.RenameNoReplace("a", "c"); err != nil {
		t.Fatalf("after the restore a rename onto a free name gave %v", err)
	}
}
