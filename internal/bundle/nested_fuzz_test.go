//go:build linux || darwin

package bundle

import (
	"os"
	"path/filepath"
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
