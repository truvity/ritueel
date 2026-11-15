//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/wanted"
)

// "apply --plan-only" opens the bundle folder once: what Find judged and what the writer writes are
// one folder, even when a parent folder is swapped for another between the two steps. The clock is
// read after Find and before the plan folder is written, so a test can swap a parent in that gap.
// The names of this file start with ao.

// aoWrite writes the files into dir.
func aoWrite(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for p, text := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// aoHasPlan reports whether the folder holds a plan folder of the ceremony.
func aoHasPlan(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, "history", apName, "plan.json"))
	return err == nil
}

func aoDigest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestApplyPlanOnlyWritesTheFolderThatItJudgedWhenAParentIsSwappedBetweenTheTwoSteps(t *testing.T) {
	for _, mode := range []string{"a parent is renamed and another is made", "a parent is replaced by a link to another folder"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "parent")
			original := filepath.Join(parent, "bundle")
			files := apFiles()
			aoWrite(t, original, files)
			// The other bundle is a valid bundle that is not the one that was judged: another name in
			// ritueel.yaml, so that its files are other bytes.
			impostorFiles := apFiles()
			impostorFiles["ritueel.yaml"] = newSettingsTestText + "# the other bundle\n"
			if impostorFiles["ritueel.yaml"] == newSettingsTestText {
				t.Fatal("the other settings are the same bytes")
			}
			moved := filepath.Join(base, "moved")
			elsewhere := filepath.Join(base, "elsewhere")
			aoWrite(t, filepath.Join(elsewhere, "bundle"), impostorFiles)

			swaps := 0
			swap := func() {
				swaps++
				if err := os.Rename(parent, moved); err != nil {
					t.Error(err)
					return
				}
				switch mode {
				case "a parent is renamed and another is made":
					aoWrite(t, filepath.Join(parent, "bundle"), impostorFiles)
				default:
					if err := os.Symlink(elsewhere, parent); err != nil {
						t.Error(err)
					}
				}
			}
			var stdout, stderr bytes.Buffer
			env := Env{
				Stdin:  strings.NewReader(""),
				Stdout: &stdout,
				Stderr: &stderr,
				Build:  testBuild,
				Now: func() time.Time {
					if swaps == 0 {
						swap()
					}
					return apClock
				},
			}
			code := Run(context.Background(), []string{"--dir", original, "apply", "--plan-only"}, env)
			if swaps != 1 {
				t.Fatalf("the clock was read after Find %d times; the test could not swap once", swaps)
			}
			if code != ExitOK {
				t.Fatalf("exit code %d; stderr %q", code, stderr.String())
			}
			judged := filepath.Join(moved, "bundle")
			if !aoHasPlan(judged) {
				t.Errorf("the plan was not written into the folder that was judged")
			}
			if aoHasPlan(filepath.Join(parent, "bundle")) || aoHasPlan(filepath.Join(elsewhere, "bundle")) {
				t.Errorf("the plan was written into the folder that stands at the path now, which was not judged")
			}
			if entries, err := os.ReadDir(filepath.Join(elsewhere, "bundle")); err == nil {
				for _, e := range entries {
					if e.Name() == "history" {
						t.Errorf("the other folder has a history folder")
					}
				}
			}
			// The plan lists the digests of the files of the folder that it stands in.
			plan, err := os.ReadFile(filepath.Join(judged, "history", apName, "plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(plan), aoDigest([]byte(files["ritueel.yaml"]))) {
				t.Errorf("the plan does not list the digest of the ritueel.yaml that it was made from")
			}
			if strings.Contains(string(plan), aoDigest([]byte(impostorFiles["ritueel.yaml"]))) {
				t.Errorf("the plan lists the digest of the other ritueel.yaml")
			}
		})
	}
}

func TestApplyPlanOnlyOfAThousandRootFilesIsRefusedWithExitCode1AndWritesNothing(t *testing.T) {
	dir := apBundle(t, map[string]string{"ritueel.yaml": newSettingsTestText})
	roots := filepath.Join(dir, "want", "roots")
	if err := os.MkdirAll(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range wanted.MaxFiles {
		f, err := os.Create(filepath.Join(roots, fmt.Sprintf("r%04d.yaml", i)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(newX509TestText); err != nil {
			t.Fatal(err)
		}
		// A hole up to the largest size: a read of it would fail its check.
		if err := f.Truncate(wanted.MaxBytes); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	before := apSnapshot(t, dir)
	start := time.Now()
	r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
	if time.Since(start) > 10*time.Second {
		t.Errorf("the refusal took %v", time.Since(start))
	}
	if r.code != ExitFailure || r.stdout != "" || !strings.Contains(r.stderr, "1000 root files") || !strings.Contains(r.stderr, "nothing was written") {
		t.Errorf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	if strings.Contains(r.stderr, "cannot be read") || strings.Contains(r.stderr, "NUL") {
		t.Errorf("a root file was read: %q", r.stderr)
	}
	crqSame(t, "apply", before, apSnapshot(t, dir))
}
