//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A stop in the middle of "new": the text names the folder twice (what was not made whole, and what to remove), each
// time written one to one.
func TestAFailedNewWritesTheNameOfTheFolderToRemoveOneToOne(t *testing.T) {
	g := newGolden(false)
	parent := filepath.Join(t.TempDir(), "a b\\c")
	must(t, os.Mkdir(parent, 0o755))
	dir := filepath.Join(parent, "acme")
	r := runLimited(t, len(g[0][1])-1, "new", dir)
	if r.code != ExitFailure {
		t.Fatalf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	for _, want := range []string{"bundle: cannot make the bundle " + exact.Replace(dir) + ": ", "the folder " + exact.Replace(dir) + " is left as it is; remove it and run new again"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("standard error = %q, want %q", r.stderr, want)
		}
	}
	if strings.Contains(r.stderr, "the folder "+dir+" is left") {
		t.Errorf("the folder to remove is written with a raw space: %q", r.stderr)
	}
}
