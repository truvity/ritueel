//go:build linux || darwin

package ceremonytest_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
)

// Copy makes a second bundle with the same files, the same modes and the same end of the history.
func TestCopyMakesTheSameBundle(t *testing.T) {
	m := ceremonytest.More(t, ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded}), 1)
	dst := filepath.Join(t.TempDir(), "stick")
	ceremonytest.Copy(t, m.Dir, dst)
	want, got := treeOf(t, m.Dir), treeOf(t, dst)
	if len(want) != len(got) {
		t.Errorf("%d entries, want %d", len(got), len(want))
	}
	for p, w := range want {
		if g, ok := got[p]; !ok || g != w {
			t.Errorf("%s: %+v, want %+v", p, g, w)
		}
	}
	a, _ := check(t, m.Dir)
	b, in := check(t, dst)
	if a.EndLine() != b.EndLine() || len(b.Findings) != 0 || b.Records != 2 || in.State == nil {
		t.Errorf("end lines %q and %q, findings %v", a.EndLine(), b.EndLine(), b.Findings)
	}
	// A copy is a copy: a file written into it is not in the source.
	if err := os.WriteFile(filepath.Join(dst, "extra.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "extra.txt")); err == nil {
		t.Error("the copy shares a folder with the source")
	}
	// The journals keep their mode.
	if fi, err := os.Stat(filepath.Join(dst, "history", m.Ceremony, "births.jsonl")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("births.jsonl: %v %v", fi, err)
	}
}

// A copy of a stopped ceremony is as stopped as the source.
func TestCopyOfAStoppedBundle(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtSet})
	dst := filepath.Join(t.TempDir(), "workstation")
	ceremonytest.Copy(t, m.Dir, dst)
	if x, y := shape(treeOf(t, m.Dir)), shape(treeOf(t, dst)); !slices.Equal(x, y) {
		t.Errorf("%v != %v", x, y)
	}
	if _, in := check(t, dst); len(in.Unfinished) != 1 {
		t.Errorf("Unfinished = %v", in.Unfinished)
	}
}

func TestCopyTargets(t *testing.T) {
	m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan})
	t.Run("a folder that is empty", func(t *testing.T) {
		dst := t.TempDir()
		ceremonytest.Copy(t, m.Dir, dst)
		if x, y := shape(treeOf(t, m.Dir)), shape(treeOf(t, dst)); !slices.Equal(x, y) {
			t.Errorf("%v != %v", x, y)
		}
	})
	t.Run("a folder that is not empty", func(t *testing.T) {
		dst := t.TempDir()
		if err := os.WriteFile(filepath.Join(dst, "x"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.Copy(tb, m.Dir, dst) })
		if !strings.Contains(msg, "not empty") {
			t.Errorf("message %q", msg)
		}
		if ents, _ := os.ReadDir(dst); len(ents) != 1 {
			t.Errorf("a refusal wrote into the folder: %v", ents)
		}
	})
	t.Run("a parent that is missing", func(t *testing.T) {
		failsWith(t, func(tb testing.TB) { ceremonytest.Copy(tb, m.Dir, filepath.Join(t.TempDir(), "no", "dst")) })
	})
	t.Run("a source that is missing", func(t *testing.T) {
		msg := failsWith(t, func(tb testing.TB) {
			ceremonytest.Copy(tb, filepath.Join(t.TempDir(), "gone"), filepath.Join(t.TempDir(), "dst"))
		})
		if !strings.Contains(msg, "cannot be looked at") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a source that is a file", func(t *testing.T) {
		src := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.Copy(tb, src, filepath.Join(t.TempDir(), "dst")) })
		if !strings.Contains(msg, "not a folder") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a source that is a link to a folder", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(m.Dir, link); err != nil {
			t.Fatal(err)
		}
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.Copy(tb, link, filepath.Join(t.TempDir(), "dst")) })
		if !strings.Contains(msg, "not a folder") {
			t.Errorf("message %q", msg)
		}
	})
}

// A bundle with a link, a FIFO or any special file is not copied: a copy that left it out would not
// be what it says, so the test fails.
func TestCopyRefusesWhatIsNotAPlainFileOrFolder(t *testing.T) {
	kinds := map[string]func(p string) error{
		"a link to a file":    func(p string) error { return os.Symlink("ritueel.yaml", p) },
		"a link to a folder":  func(p string) error { return os.Symlink("history", p) },
		"a link that is dead": func(p string) error { return os.Symlink("nowhere", p) },
		"a FIFO":              func(p string) error { return syscall.Mkfifo(p, 0o600) },
	}
	for name, make := range kinds {
		for _, where := range []string{"", "history"} {
			t.Run(name+" at "+where, func(t *testing.T) {
				m := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.AtPlan})
				if err := make(filepath.Join(m.Dir, where, "odd")); err != nil {
					t.Skipf("cannot make it here: %v", err)
				}
				dst := filepath.Join(t.TempDir(), "dst")
				msg := failsWith(t, func(tb testing.TB) { ceremonytest.Copy(tb, m.Dir, dst) })
				if !strings.Contains(msg, "odd") || !strings.Contains(msg, "neither a plain file nor a folder") {
					t.Errorf("message %q", msg)
				}
			})
		}
	}
}
