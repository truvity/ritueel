//go:build linux || darwin

package trustset_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A set is written to a name that does not exist. A name that is already a pipe, a link, a file or a
// folder is refused with fs.ErrExist, and nothing is written into it or through it: the keyring file
// does not land in the folder that a link points to.
func TestSetWriteToAPlaceThatIsNotFree(t *testing.T) {
	_, s := aSet(t)
	for _, kind := range []string{"pipe", "link to a folder", "link to nothing", "file", "folder"} {
		t.Run(kind, func(t *testing.T) {
			w, dir := setDir(t)
			outside := t.TempDir()
			place := filepath.Join(dir, "trust", s.Name())
			switch kind {
			case "pipe":
				if err := syscall.Mkfifo(place, 0o600); err != nil {
					t.Skipf("no pipe here: %v", err)
				}
			case "link to a folder":
				if err := os.Symlink(outside, place); err != nil {
					t.Fatal(err)
				}
			case "link to nothing":
				if err := os.Symlink(filepath.Join(outside, "nowhere"), place); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(place, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "folder":
				if err := os.Mkdir(place, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			err := s.Write(w, "trust/"+s.Name())
			if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("Write gave %v, want fs.ErrExist", err)
			}
			if ents, _ := os.ReadDir(outside); len(ents) != 0 {
				t.Errorf("something was written through the link: %d entries", len(ents))
			}
			if kind == "folder" {
				if ents, _ := os.ReadDir(place); len(ents) != 0 {
					t.Errorf("something was written into the folder: %d entries", len(ents))
				}
			}
			info, err := os.Lstat(place)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "pipe" && info.Mode()&fs.ModeNamedPipe == 0 {
				t.Error("the pipe was replaced")
			}
		})
	}
}
