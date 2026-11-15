//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// "ritueel new" with a relative DIR, run from a folder of a bundle: the folders above are read as they are on the
// disk, from the working folder of the process, so a bundle is not made inside a bundle by a short name either.
func TestProgramNewWithARelativeNameInsideABundleIsRefused(t *testing.T) {
	exe := buildForCheck(t)
	parent := t.TempDir()
	if code, _, stderr := runProgramIn(t, exe, parent, "new", "outer"); code != 0 {
		t.Fatalf("new: exit %d, stderr %q", code, stderr)
	}
	outer, err := filepath.EvalSymlinks(filepath.Join(parent, "outer"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, workDir string
		args          []string
	}{
		{"in the folder of the bundle", outer, []string{"new", "inner"}},
		{"in a folder of the bundle", filepath.Join(outer, "want"), []string{"new", "inner"}},
		{"a longer relative name", outer, []string{"new", "want/roots/inner"}},
		{"a name that goes down and up", outer, []string{"new", "./want/./inner"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runProgramIn(t, exe, tc.workDir, tc.args...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, "the folder "+outer+" holds ritueel.yaml: a bundle is not made inside a bundle") {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 1 and the folder that holds ritueel.yaml", code, stdout, stderr)
			}
		})
	}
	if _, err := os.Lstat(filepath.Join(outer, "inner")); err == nil {
		t.Error("a folder was made")
	}
	if _, err := os.Lstat(filepath.Join(outer, "want", "inner")); err == nil {
		t.Error("a folder was made")
	}

	// Outside any bundle the same short name is made.
	elsewhere := t.TempDir()
	if code, _, stderr := runProgramIn(t, exe, elsewhere, "new", "inner"); code != 0 {
		t.Errorf("new outside a bundle: exit %d, stderr %q", code, stderr)
	}
}
