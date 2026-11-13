//go:build linux || darwin

package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The rename of one folder handle: both names are in the folder, and the error is the bare errno
// of the system call (a syscall.Errno), which satisfies the error of the package that its kind
// calls for.

// skipIfNoNoReplace skips on a file system that cannot refuse to replace.
func skipIfNoNoReplace(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("this file system has no rename that refuses to replace: %v", err)
	}
}

func TestRenameNoReplaceOntoAnExistingFileLeavesBothUntouched(t *testing.T) {
	dir := t.TempDir()
	root := openFSIn(t, dir)
	for n, c := range map[string]string{"a": "content of a", "b": "content of b"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := root.RenameNoReplace("a", "b")
	skipIfNoNoReplace(t, err)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want fs.ErrExist", err)
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno != syscall.EEXIST {
		t.Fatalf("got %v (%T), want the bare errno EEXIST", err, err)
	}
	if got := readFile(t, filepath.Join(dir, "a")); string(got) != "content of a" {
		t.Fatalf("the source holds %q after a refused rename", got)
	}
	if got := readFile(t, filepath.Join(dir, "b")); string(got) != "content of b" {
		t.Fatalf("the target holds %q after a refused rename", got)
	}
}

func TestRenameNoReplaceMovesWhenTheTargetIsFree(t *testing.T) {
	dir := t.TempDir()
	root := openFSIn(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := root.RenameNoReplace("a", "b")
	skipIfNoNoReplace(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "a")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the old name is still there: %v", err)
	}
	if got := readFile(t, filepath.Join(dir, "b")); string(got) != "x" {
		t.Fatalf("the new name holds %q", got)
	}
}

func TestRenameNoReplaceOfAMissingSourceIsErrNotExist(t *testing.T) {
	dir := t.TempDir()
	root := openFSIn(t, dir)
	err := root.RenameNoReplace("nope", "b")
	skipIfNoNoReplace(t, err)
	var errno syscall.Errno
	if !errors.Is(err, fs.ErrNotExist) || !errors.As(err, &errno) || errno != syscall.ENOENT {
		t.Fatalf("got %v, want the errno ENOENT, which is fs.ErrNotExist", err)
	}
}

func TestRenameNoReplaceOfAFolderOntoAFolderIsRefused(t *testing.T) {
	dir := t.TempDir()
	root := openFSIn(t, dir)
	for _, d := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "a", "inner"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := root.RenameNoReplace("a", "b") // b is empty: a plain rename would replace it
	skipIfNoNoReplace(t, err)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want fs.ErrExist (an empty target folder is still a name taken)", err)
	}
	if got := readFile(t, filepath.Join(dir, "a", "inner")); string(got) != "x" {
		t.Fatalf("the source folder changed: %q", got)
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "b")); len(ents) != 0 {
		t.Fatalf("the target folder changed: %v", ents)
	}
}

// TestRenameNoReplaceMovesALinkAsAName and refuses to replace one: the rename never follows a link,
// at the old name or at the new.
func TestRenameNoReplaceNeverFollowsALink(t *testing.T) {
	wd := newWorld(t)
	wd.symlink(filepath.Join("..", "outside", "secret"), "src")
	wd.symlink(filepath.Join("..", "outside", "nowhere"), "taken")
	if err := os.WriteFile(filepath.Join(wd.root, "plain"), []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, wd.outside)
	root := openFSIn(t, wd.root)

	err := root.RenameNoReplace("plain", "taken") // onto a dangling link: the name is taken
	skipIfNoNoReplace(t, err)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a rename onto a dangling link: %v, want fs.ErrExist", err)
	}
	if _, err := os.Lstat(filepath.Join(wd.outside, "nowhere")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a file was made behind the dangling link: %v", err)
	}
	if err := root.RenameNoReplace("src", "moved"); err != nil { // the link itself moves
		t.Fatal(err)
	}
	if tgt, err := os.Readlink(filepath.Join(wd.root, "moved")); err != nil || tgt != filepath.Join("..", "outside", "secret") {
		t.Fatalf("the moved link: %q, %v", tgt, err)
	}
	wd.requireOutsideUntouched(before)
}
