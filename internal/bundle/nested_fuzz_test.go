//go:build linux || darwin

package bundle

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The path of a parent folder is any bytes: bundleAbove reads the folders above it, never panics, and returns a
// folder that is above the path on the disk and holds a name ritueel.yaml, or nothing. It writes nothing.
func FuzzBundleAbove(f *testing.F) {
	root := f.TempDir()
	holder := filepath.Join(root, "holder")
	if err := os.MkdirAll(filepath.Join(holder, "a", "b"), 0o755); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(holder, "ritueel.yaml"), nil, 0o644); err != nil {
		f.Fatal(err)
	}
	if err := os.Symlink(holder, filepath.Join(root, "link")); err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"", ".", "..", "/", "//", root, holder, filepath.Join(holder, "a", "b"), filepath.Join(root, "link", "a"),
		filepath.Join(holder, "a", "..", "a"), holder + "/./a/", "a\x00b", "\xff\xfe", "/no/such", filepath.Join(holder, "ritueel.yaml"), filepath.Join(holder, "ritueel.yaml", "x")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, parent string) {
		got, err := bundleAbove(parent)
		if err != nil {
			return
		}
		if got == "" {
			return
		}
		if !filepath.IsAbs(got) || filepath.Clean(got) != got {
			t.Fatalf("bundleAbove(%q) = %q, want an absolute clean path", parent, got)
		}
		if _, err := os.Lstat(filepath.Join(got, "ritueel.yaml")); err != nil && os.IsNotExist(err) {
			t.Fatalf("bundleAbove(%q) = %q, which holds no name ritueel.yaml", parent, got)
		}
	})
}

// The path of a folder is any bytes: holdsSettings never panics, writes nothing, and answers one of three things that
// follow from the disk. A name that exists is "true" with no error; a name that does not exist is "false" with no
// error; anything else is "false" with an error that says the folder cannot be examined, and is not a "does not
// exist". The answer is never "true" and an error together.
func FuzzHoldsSettings(f *testing.F) {
	root := f.TempDir()
	holder := filepath.Join(root, "holder")
	if err := os.MkdirAll(filepath.Join(holder, "a"), 0o755); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(holder, "ritueel.yaml"), nil, 0o644); err != nil {
		f.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o644); err != nil {
		f.Fatal(err)
	}
	if err := os.Symlink("loop", filepath.Join(root, "loop")); err != nil {
		f.Fatal(err)
	}
	if err := os.Symlink(holder, filepath.Join(root, "link")); err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"", ".", "..", "/", "//", root, holder, filepath.Join(holder, "a"), filepath.Join(root, "file"),
		filepath.Join(root, "loop"), filepath.Join(root, "link"), "a\x00b", "\xff\xfe", "/no/such", holder + "/./a/..", strings.Repeat("a/", 3000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		held, err := holdsSettings(p)
		_, statErr := os.Lstat(filepath.Join(p, "ritueel.yaml"))
		switch {
		case err != nil && held:
			t.Fatalf("holdsSettings(%q) = (true, %v)", p, err)
		case err != nil && errors.Is(err, fs.ErrNotExist):
			t.Fatalf("holdsSettings(%q): an error that says the name does not exist: %v", p, err)
		case err != nil && statErr == nil, err != nil && errors.Is(statErr, fs.ErrNotExist):
			t.Fatalf("holdsSettings(%q) gave the error %v where the disk says %v", p, err, statErr)
		case err == nil && held != (statErr == nil):
			t.Fatalf("holdsSettings(%q) = %v, the disk says %v", p, held, statErr)
		case err == nil && !held && !errors.Is(statErr, fs.ErrNotExist):
			t.Fatalf("holdsSettings(%q) = (false, nil) where the disk says %v", p, statErr)
		}
	})
}
