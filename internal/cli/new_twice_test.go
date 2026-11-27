//go:build linux || darwin

package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// A flag of new that is given twice is a usage error, as it is for apply, and nothing is written.
func TestNewRefusesAFlagGivenTwice(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "ada")
	for name, args := range map[string][]string{
		"--template twice, the last is personal": {"new", "--template", "cloud", "--template", "personal", dir},
		"--template twice, the same":             {"new", "--template", "personal", "--template", "personal", dir},
		"--test-root twice":                      {"new", "--test-root", "--test-root", dir},
	} {
		t.Run(name, func(t *testing.T) {
			before := crqSnapshot(t, root)
			r := apRun(t, apClock, args...)
			if r.code != ExitUsage || r.stdout != "" || !strings.Contains(r.stderr, " is given once") {
				t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
			}
			crqSame(t, "new", before, crqSnapshot(t, root))
		})
	}
}
