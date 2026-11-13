//go:build linux

package fsx_test

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The Linux path is renameat2 with RENAME_NOREPLACE. On the file system of the test machine
// (a temporary folder) it must be supported: a skip here would hide a writer that cannot
// refuse to replace.
func TestLinuxRenameatTwoIsSupportedOnTheTestFilesystem(t *testing.T) {
	dir := t.TempDir()
	root := openFSIn(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600); err != nil {
		t.Skipf("cannot write a file: %v", err)
	}
	err := root.RenameNoReplace("a", "b")
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("renameat2 with RENAME_NOREPLACE is not supported on the file system of %s: %v", dir, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	// And the refusal, through the same call.
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = root.RenameNoReplace("a", "b")
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno != syscall.EEXIST {
		t.Fatalf("got %v, want the errno EEXIST", err)
	}
	if got := readFile(t, filepath.Join(dir, "b")); string(got) != "x" {
		t.Fatalf("the target was replaced: %q", got)
	}
}

func TestLinuxRenameNoReplaceDoesNotFallBackToAReplacingRename(t *testing.T) {
	// The target is a file that a plain rename would replace silently.
	dir := t.TempDir()
	root := openFSIn(t, dir)
	_ = os.WriteFile(filepath.Join(dir, "a"), []byte("new"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "b"), []byte("old"), 0o600)
	err := root.RenameNoReplace("a", "b")
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("unsupported here: %v", err)
	}
	if err == nil {
		t.Fatal("RenameNoReplace replaced an existing file")
	}
	if got := readFile(t, filepath.Join(dir, "b")); string(got) != "old" {
		t.Fatalf("the target holds %q", got)
	}
}
