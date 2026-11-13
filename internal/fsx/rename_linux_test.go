//go:build linux

package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The Linux path is renameat2 with RENAME_NOREPLACE. On the file system of the test machine
// (a temporary folder) it must be supported: a skip here would hide a writer that cannot
// refuse to replace.
func TestLinuxRenameatTwoIsSupportedOnTheTestFilesystem(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Skipf("cannot write a file: %v", err)
	}
	err := fsx.OS.RenameNoReplace(a, b)
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("renameat2 with RENAME_NOREPLACE is not supported on the file system of %s: %v", dir, err)
	}
	if err != nil {
		t.Fatal(err)
	}
	// And the refusal, through the same call.
	if err := os.WriteFile(a, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	var le *os.LinkError
	err = fsx.OS.RenameNoReplace(a, b)
	if !errors.As(err, &le) || le.Op != "rename" || le.Old != a || le.New != b || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want an *os.LinkError for a rename of %s to %s wrapping fs.ErrExist", err, a, b)
	}
	if got := readFile(t, b); string(got) != "x" {
		t.Fatalf("the target was replaced: %q", got)
	}
}

func TestLinuxRenameNoReplaceDoesNotFallBackToAReplacingRename(t *testing.T) {
	// The target is a file that a plain os.Rename would replace silently.
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	_ = os.WriteFile(a, []byte("new"), 0o600)
	_ = os.WriteFile(b, []byte("old"), 0o600)
	err := fsx.OS.RenameNoReplace(a, b)
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("unsupported here: %v", err)
	}
	if err == nil {
		t.Fatal("RenameNoReplace replaced an existing file")
	}
	if got := readFile(t, b); string(got) != "old" {
		t.Fatalf("the target holds %q", got)
	}
}
