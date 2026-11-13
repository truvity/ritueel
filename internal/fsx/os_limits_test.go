//go:build linux || darwin

package fsx_test

// The two limits on the real file system.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func TestOSReadJournalAtTheLimitOfLines(t *testing.T) {
	wd := newWorld(t)
	root := openFSIn(t, wd.root)
	for _, c := range []struct {
		name    string
		lines   int
		tooMany bool
	}{{"exactly the limit", fsx.MaxJournalLines, false}, {"one above", fsx.MaxJournalLines + 1, true}, {"line breaks only, 8 MiB", fsx.MaxReadSize, true}} {
		content := bytes.Repeat([]byte("x\n"), c.lines)
		if c.lines == fsx.MaxReadSize {
			content = bytes.Repeat([]byte{'\n'}, c.lines)
		}
		if err := os.WriteFile(filepath.Join(wd.root, "j"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		lines, partial, err := fsx.ReadJournal(root, "j")
		if !c.tooMany {
			if err != nil || len(lines) != c.lines || partial != nil {
				t.Fatalf("%s: %d lines, %v", c.name, len(lines), err)
			}
			continue
		}
		want := fmt.Sprintf(`fsx: read "j": %s: %d lines, more than 65536`, textTooMany, c.lines)
		if !errors.Is(err, fsx.ErrTooMany) || err.Error() != want || lines != nil || partial != nil {
			t.Fatalf("%s: %v, want ErrTooMany with the text\n  %s", c.name, err, want)
		}
	}
}

func TestOSReadDirAtTheLimitOfNames(t *testing.T) {
	wd := newWorld(t)
	wd.mkdir("d")
	// empty files, one for each name (a hard link would do, but a file system takes only about
	// 65,000 links to one file)
	for i := 0; i < fsx.MaxDirEntries; i++ {
		f, err := os.OpenFile(filepath.Join(wd.root, "d", fmt.Sprintf("n%06d", i)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatalf("cannot make the name %d: %v", i, err)
		}
		_ = f.Close()
	}
	root := openFSIn(t, wd.root)
	ents, err := fsx.ReadDir(root, "d")
	if err != nil || len(ents) != fsx.MaxDirEntries {
		t.Fatalf("exactly the limit: %d entries, %v", len(ents), err)
	}
	for i, e := range ents {
		if e.Name() != fmt.Sprintf("n%06d", i) {
			t.Fatalf("entry %d is %s: the order is by name", i, e.Name())
		}
	}
	if err := os.WriteFile(filepath.Join(wd.root, "d", "n999999"), nil, 0o600); err != nil {
		t.Fatalf("cannot make one more name: %v", err)
	}
	ents, err = fsx.ReadDir(root, "d")
	want := fmt.Sprintf(`fsx: read "d": %s: more than 65536 names`, textTooMany)
	if !errors.Is(err, fsx.ErrTooMany) || err.Error() != want || ents != nil {
		t.Fatalf("one above: %d entries, %v, want ErrTooMany with the text\n  %s", len(ents), err, want)
	}
}
