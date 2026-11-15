//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

// openFiles is how many files the process holds open.
func openFiles(t testing.TB) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot list the open files: %v", err)
	}
	return len(ents)
}

// Each run of a command closes the folder of the bundle it opened, whether it ends with an acceptance, a refusal
// or a fault. A command that keeps one open for each run would run a long session out of files.
func TestTheCommandsCloseWhatTheyOpen(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	good := m.byID(t, "x509-software-valid")
	bad := m.byID(t, "x509-csr-bad-signature")
	goodDir, badDir := crqBundle(t, m, good), crqBundle(t, m, bad)
	parent := t.TempDir()
	// A file that is left open is closed by the runtime when its owner is collected, which hides the leak.
	// The collector is off for the length of the test; no test of this package runs beside this one.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	const runs = 30
	before := openFiles(t)
	for i := 0; i < runs; i++ {
		crqRun(t, now, "check", "request", good.stem(t), "--delegation", crqDelegation, "--dir", goodDir)
		crqRun(t, now, "check", "request", bad.stem(t), "--delegation", crqDelegation, "--dir", badDir)
		crqRun(t, now, "check", "request", good.stem(t), "--delegation", "nosuch", "--dir", goodDir)
		crqRun(t, now, "check", "request", good.stem(t), "--dir", filepath.Join(parent, "none"))
		crqRun(t, now, "new", filepath.Join(parent, "acme"+string(rune('a'+i%26))+string(rune('a'+i/26%26))))
	}
	// A slack for the files that the runtime itself opens and closes later; a leak of one file for each run is
	// 30 or more.
	if after := openFiles(t); after-before > 10 {
		t.Errorf("the process holds %d files open after %d runs and held %d before", after, runs*5, before)
	}
}
