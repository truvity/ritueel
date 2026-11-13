package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// skipIfNoNoReplace skips on a file system that cannot refuse to replace.
func skipIfNoNoReplace(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("this file system has no rename that refuses to replace: %v", err)
	}
}

func TestRenameNoReplaceOntoAnExistingFileLeavesBothUntouched(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for p, c := range map[string]string{a: "content of a", b: "content of b"} {
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := fsx.OS.RenameNoReplace(a, b)
	skipIfNoNoReplace(t, err)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want fs.ErrExist", err)
	}
	if got := readFile(t, a); string(got) != "content of a" {
		t.Fatalf("the source holds %q after a refused rename", got)
	}
	if got := readFile(t, b); string(got) != "content of b" {
		t.Fatalf("the target holds %q after a refused rename", got)
	}
}

func TestRenameNoReplaceMovesWhenTheTargetIsFree(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(a, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := fsx.OS.RenameNoReplace(a, b)
	skipIfNoNoReplace(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the old name is still there: %v", err)
	}
	if got := readFile(t, b); string(got) != "x" {
		t.Fatalf("the new name holds %q", got)
	}
}

func TestRenameNoReplaceOfAMissingSourceIsErrNotExist(t *testing.T) {
	dir := t.TempDir()
	err := fsx.OS.RenameNoReplace(filepath.Join(dir, "nope"), filepath.Join(dir, "b"))
	skipIfNoNoReplace(t, err)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want fs.ErrNotExist", err)
	}
}

func TestRenameNoReplaceOfAFolderOntoAFolderIsRefused(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, d := range []string{a, b} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(a, "inner"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := fsx.OS.RenameNoReplace(a, b) // b is empty: a plain rename would replace it
	skipIfNoNoReplace(t, err)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("got %v, want fs.ErrExist (an empty target folder is still a name taken)", err)
	}
	if got := readFile(t, filepath.Join(a, "inner")); string(got) != "x" {
		t.Fatalf("the source folder changed: %q", got)
	}
	if ents, _ := os.ReadDir(b); len(ents) != 0 {
		t.Fatalf("the target folder changed: %v", ents)
	}
}
