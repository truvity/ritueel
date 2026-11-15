//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A parent whose links cannot be followed (a link that leads to itself, a link to nothing, a name that is not there, a
// plain file in the middle) stops "new": exit code 1, nothing is written, the person is not told to remove a folder that
// was never made, and the folder is named by the exact escape. The command opens the parent first, so for these paths it
// says that the parent cannot be opened; the sentence of a parent that opens and does not resolve is in
// TestNewStopsWhenAFolderAboveCannotBeExaminedAndNamesIt.
func TestNewStopsAtAParentWhoseLinksCannotBeFollowedAndWritesNothing(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	hostile := "a b\\c\n\xff"
	must(t, os.Symlink(filepath.Join(root, "loop"), filepath.Join(root, "loop")))
	must(t, os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(root, "dangling")))
	if err := os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(root, hostile)); err != nil {
		t.Skipf("this file system does not take the name: %v", err)
	}
	must(t, os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644))
	for name, parent := range map[string]string{
		"a link that leads to itself":               filepath.Join(root, "loop"),
		"a link that leads to itself in the middle": filepath.Join(root, "loop", "sub"),
		"a link to nothing":                         filepath.Join(root, "dangling"),
		"a link to nothing in the middle":           filepath.Join(root, "dangling", "a", "b"),
		"a name that is not there":                  filepath.Join(root, "missing", "sub"),
		"a plain file in the middle":                filepath.Join(root, "file", "sub"),
		"a link with a hostile name":                filepath.Join(root, hostile, "sub"),
		"a name that is not there and hostile":      filepath.Join(root, "miss "+hostile, "sub"),
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(parent, "dir")
			before := crqShape(t, root)
			for _, args := range [][]string{{"new", dir}, {"--output", "json", "new", dir}, {"new", "--test-root", dir}} {
				r := run(t, args...)
				if r.code != ExitFailure {
					t.Fatalf("%v: (%d, %q, %q), want exit code 1", args, int(r.code), r.stdout, r.stderr)
				}
				if strings.Count(r.stderr, "\n") != 1 || !onlyPrintable(r.stderr) {
					t.Errorf("%v: standard error = %q, want one printable line", args, r.stderr)
				}
				if want := "cannot make the bundle " + exact.Replace(dir); !strings.Contains(r.stderr, want) {
					t.Errorf("%v: standard error %q does not name the folder by the exact escape: %q", args, r.stderr, want)
				}
				if !strings.Contains(r.stderr, "the folder was not made") || strings.Contains(r.stderr, "remove it") {
					t.Errorf("%v: standard error = %q, want the folder to be said not made", args, r.stderr)
				}
				if strings.Contains(r.stdout, "ritueel") && args[0] != "--output" {
					t.Errorf("%v: standard output = %q", args, r.stdout)
				}
			}
			crqSame(t, "new", before, crqShape(t, root))
		})
	}
}

// A parent that is reached through good links is as it was: the bundle is made in the folder on the disk.
func TestNewMakesTheBundleInAParentReachedThroughLinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	real := filepath.Join(root, "real")
	must(t, os.MkdirAll(filepath.Join(real, "inner"), 0o755))
	must(t, os.Symlink(real, filepath.Join(root, "one")))
	must(t, os.Symlink("one", filepath.Join(root, "two")))
	// A link as the last element of the parent is refused; a link in the middle is followed.
	r := run(t, "new", filepath.Join(root, "two", "inner", "acme"))
	if r.code != ExitOK {
		t.Fatalf("(%d, %q, %q), want exit code 0", int(r.code), r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(real, "inner", "acme", "ritueel.yaml")); err != nil {
		t.Errorf("the bundle is not in the folder that the links lead to: %v", err)
	}
}
