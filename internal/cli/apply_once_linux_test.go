//go:build linux

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// aoOpenFolders is the number of file descriptors of this process that stand on the folder dir.
func aoOpenFolders(t testing.TB, dir string) int {
	t.Helper()
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}
	n := 0
	for _, e := range entries {
		if target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && target == want {
			n++
		}
	}
	return n
}

// aoSpyCtx is a context that counts the open handles on a folder when Find looks at it, the first
// thing that Find does after it is given its folder.
type aoSpyCtx struct {
	context.Context
	t    testing.TB
	dir  string
	seen []int
}

func (c *aoSpyCtx) Err() error {
	c.seen = append(c.seen, aoOpenFolders(c.t, c.dir))
	return c.Context.Err()
}

// The folder is opened once for the whole run: while Find reads it and while the plan is made, one
// handle of this process stands on it, and none after the command has returned.
func TestApplyPlanOnlyHoldsOneOpenHandleOnTheBundleFromTheFindToTheWrite(t *testing.T) {
	dir := apBundle(t, apFiles())
	if n := aoOpenFolders(t, dir); n != 0 {
		t.Fatalf("%d handles stand on the folder before the command", n)
	}
	spy := &aoSpyCtx{Context: context.Background(), t: t, dir: dir}
	var atClock []int
	var stdout, stderr bytes.Buffer
	env := Env{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
		Build:  testBuild,
		Now: func() time.Time {
			atClock = append(atClock, aoOpenFolders(t, dir))
			return apClock
		},
	}
	code := Run(spy, []string{"--dir", dir, "apply", "--plan-only"}, env)
	if code != ExitOK {
		t.Fatalf("exit code %d; stderr %q", code, stderr.String())
	}
	if len(spy.seen) == 0 || len(atClock) == 0 {
		t.Fatalf("the spies did not run: %v %v", spy.seen, atClock)
	}
	for _, n := range spy.seen {
		if n != 1 {
			t.Errorf("%d handles stand on the bundle folder while Find reads it, want 1 (the one open)", n)
		}
	}
	for _, n := range atClock {
		if n != 1 {
			t.Errorf("%d handles stand on the bundle folder while the plan is made, want 1", n)
		}
	}
	if n := aoOpenFolders(t, dir); n != 0 {
		t.Errorf("%d handles still stand on the folder after the command", n)
	}
}

func TestApplyPlanOnlyReleasesTheFolderOnEveryPathOut(t *testing.T) {
	cases := map[string]map[string]string{
		"nothing to apply":              {"ritueel.yaml": newSettingsTestText},
		"a wanted file that fails":      {"ritueel.yaml": newSettingsTestText, "want/roots/x509.yaml": "kind: nonsense\n"},
		"a root that is not built":      {"ritueel.yaml": newSettingsTestText, "want/roots/x509.yaml": newX509Text},
		"a bundle that is not a bundle": {"README": "x"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			dir := apBundle(t, files)
			r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
			if n := aoOpenFolders(t, dir); n != 0 {
				t.Errorf("exit code %d, and %d handles still stand on the folder", r.code, n)
			}
		})
	}
	t.Run("a plan that is written", func(t *testing.T) {
		dir := apBundle(t, apFiles())
		if r := apPlanOnly(t, apClock, dir); r.code != ExitOK || aoOpenFolders(t, dir) != 0 {
			t.Errorf("exit code %d, %d handles", r.code, aoOpenFolders(t, dir))
		}
	})
	t.Run("a plan that is made twice in one second", func(t *testing.T) {
		dir := apBundle(t, apFiles())
		apPlanOnly(t, apClock, dir)
		r := apPlanOnly(t, apClock, dir)
		if r.code != ExitFailure || aoOpenFolders(t, dir) != 0 {
			t.Errorf("exit code %d, %d handles", r.code, aoOpenFolders(t, dir))
		}
	})
	t.Run("a key directory that is refused", func(t *testing.T) {
		dir := apBundle(t, apFiles())
		r := apPlanOnly(t, apClock, dir, "--key-dir", filepath.Join(dir, "keys"))
		if r.code != ExitBackend || aoOpenFolders(t, dir) != 0 {
			t.Errorf("exit code %d, %d handles", r.code, aoOpenFolders(t, dir))
		}
	})
}
