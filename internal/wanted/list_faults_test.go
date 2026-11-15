//go:build linux || darwin

package wanted_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The words of the faults of a read and of a listing are fixed: each fault that is told apart has its
// own words, and the error wraps the error of the file system. The names of this file start with fw.

func TestTheWordsOfAFailedReadOfOneFileTellTheFaultsApart(t *testing.T) {
	big := filepath.Join(t.TempDir(), "big")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(fsx.MaxReadSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, roots string)
		words string
		wrap  error
	}{
		{"a missing file", func(*testing.T, string) {}, "the file cannot be read: it does not exist", fs.ErrNotExist},
		{"a link", func(t *testing.T, roots string) {
			if err := os.Symlink("elsewhere.yaml", filepath.Join(roots, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "the file cannot be read: a link is not followed", fsx.ErrLink},
		{"a folder", func(t *testing.T, roots string) {
			if err := os.Mkdir(filepath.Join(roots, "a.yaml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "the file cannot be read: it is not a regular file", fsx.ErrNotRegular},
		{"a FIFO", func(t *testing.T, roots string) {
			if err := syscall.Mkfifo(filepath.Join(roots, "a.yaml"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "the file cannot be read: it is not a regular file", fsx.ErrNotRegular},
		{"a file over the limit of a read", func(t *testing.T, roots string) {
			if err := os.Rename(big, filepath.Join(roots, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "the file cannot be read: it is too long", fsx.ErrTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, fsys := bundleDir(t, map[string]string{"want/roots/other.yaml": lstRootText})
			c.setup(t, filepath.Join(dir, "want", "roots"))
			r, err := wanted.LoadRoot(fsys, "a")
			if r != nil {
				t.Errorf("a root beside the error %v", err)
			}
			e := wantFault(t, err, "want/roots/a.yaml", 0, c.words)
			if !errors.Is(err, c.wrap) {
				t.Errorf("the error does not wrap %v: %v", c.wrap, err)
			}
			if e.Msg != c.words {
				t.Errorf("the message is %q, want %q", e.Msg, c.words)
			}
		})
	}
}

func TestTheWordsOfAFailedListingTellTheFaultsApart(t *testing.T) {
	t.Run("a link in place of the folder", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"elsewhere/a.yaml": lstRootText})
		if err := os.MkdirAll(filepath.Join(dir, "want"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../elsewhere", filepath.Join(dir, "want", "roots")); err != nil {
			t.Fatal(err)
		}
		_, err := wanted.ListRootNames(fsys)
		e := wantFault(t, err, "want/roots", 0)
		if e.Msg != "the folder cannot be listed: a link is not followed" {
			t.Errorf("the message is %q", e.Msg)
		}
		if !errors.Is(err, fsx.ErrLink) {
			t.Errorf("the error does not wrap fsx.ErrLink: %v", err)
		}
	})
	t.Run("a file in place of the folder", func(t *testing.T) {
		_, fsys := bundleDir(t, map[string]string{"want/cards": "x"})
		_, err := wanted.ListCardNames(fsys)
		e := wantFault(t, err, "want/cards", 0)
		if e.Msg != "the folder cannot be listed: the system refused to list it" {
			t.Errorf("the message is %q", e.Msg)
		}
		if errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a file in place of the folder was told as a missing folder: %v", err)
		}
	})
	t.Run("too many names", func(t *testing.T) {
		fsys := tlInjected(t, wanted.DelegationsDir, func() []fs.DirEntry {
			out := make([]fs.DirEntry, 0, fsx.MaxDirEntries)
			for i := range fsx.MaxDirEntries {
				out = append(out, tlEntry{fmt.Sprintf("n%06d.yaml", i), 0})
			}
			return out
		})
		err := wanted.CheckDelegations(fsys, lstSettings(t))
		e := wantFault(t, err, "want/delegations", 0)
		if e.Msg != "the folder cannot be listed: it holds too many names" {
			t.Errorf("the message is %q", e.Msg)
		}
		if !errors.Is(err, fsx.ErrTooMany) {
			t.Errorf("the error does not wrap fsx.ErrTooMany: %v", err)
		}
	})
	t.Run("more files than the limit", func(t *testing.T) {
		_, fsys := bundleDir(t, nmRoots(wanted.MaxFiles+1))
		_, err := wanted.ListRootNames(fsys)
		e := wantFault(t, err, "want/roots", 0)
		if want := fmt.Sprintf("the folder holds more than %d files", wanted.MaxFiles); e.Msg != want {
			t.Errorf("the message is %q, want %q", e.Msg, want)
		}
	})
	t.Run("an entry that is not NAME.yaml", func(t *testing.T) {
		_, fsys := bundleDir(t, map[string]string{"want/roots/a.txt": "x"})
		_, err := wanted.ListRootNames(fsys)
		e := wantFault(t, err, "want/roots/a.txt", 0)
		if e.Msg != "the name is not NAME.yaml" {
			t.Errorf("the message is %q", e.Msg)
		}
	})
	t.Run("an entry that is not a file", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"want/roots/other.yaml": lstRootText})
		if err := os.Mkdir(filepath.Join(dir, "want", "roots", "a.yaml"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := wanted.ListRootNames(fsys)
		e := wantFault(t, err, "want/roots/a.yaml", 0)
		if !strings.HasPrefix(e.Msg, "it is not a regular file") {
			t.Errorf("the message is %q", e.Msg)
		}
	})
	t.Run("no folder to read from", func(t *testing.T) {
		_, err := wanted.ListCardNames(nil)
		e := wantFault(t, err, "want/cards", 0)
		if e.Msg != "there is no folder to read it from" {
			t.Errorf("the message is %q", e.Msg)
		}
	})
}
