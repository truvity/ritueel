//go:build linux || darwin

package fsx_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// TestAListedHostileNameIsRefusedByCheckName: the names in a folder are data from the stick. A
// folder of the real file system holds names with an escape code, a line break, a byte that is not
// UTF-8 and U+202E; ReadDir lists them as they are, and CheckName refuses each, in printable ASCII.
func TestAListedHostileNameIsRefusedByCheckName(t *testing.T) {
	wd := newWorld(t)
	wd.mkdir("d")
	hostile := []string{"\x1b[31mred\x1b[0m", "a\nb", "a\xffb", "a‮b", "a\x07b", "é", "a b", "COM1", "nul.txt", "ok.json", ".rt-x", "trailing."}
	for _, n := range hostile {
		if err := os.WriteFile(filepath.Join(wd.root, "d", n), nil, 0o600); err != nil {
			t.Skipf("this file system does not take the name %q: %v", n, err)
		}
	}
	root := openFSIn(t, wd.root)
	ents, err := fsx.ReadDir(root, "d")
	if err != nil || len(ents) != len(hostile) {
		t.Fatalf("ReadDir: %d entries, %v", len(ents), err)
	}
	accepted := 0
	for _, e := range ents {
		err := fsx.CheckName(e.Name())
		if e.Name() == "ok.json" {
			if err != nil {
				t.Errorf("CheckName(ok.json) = %v", err)
			}
			accepted++
			continue
		}
		if !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("CheckName(%q) = %v, want ErrInvalid", e.Name(), err)
			continue
		}
		requirePrintableASCII(t, err.Error())
	}
	if accepted != 1 {
		t.Fatalf("%d names accepted, want the one", accepted)
	}
}
