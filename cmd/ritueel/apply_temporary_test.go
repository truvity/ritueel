//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A leftover of a stopped write, a name that starts with ".rt-" in any case, in a wanted folder does
// not stop "apply": the program makes the plan and runs it as it does without the leftover, and the
// leftover stays where it is (record 0006, rule 45).
func TestProgramApplyRunsWithLeftoversInTheWantedFoldersAndLeavesThemAlone(t *testing.T) {
	p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
	root := t.TempDir()
	ca, keys := filepath.Join(root, "ca"), filepath.Join(root, "keys")
	if code, _, stderr := p.run(nil, "new", "--test-root", ca); code != 0 {
		t.Fatalf("new: %d %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(ca, "want", "roots", "openpgp.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, folder := range []string{"roots", "delegations", "cards"} {
		base := filepath.Join(ca, "want", folder)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{".rt-k3j9x0a1b2c", ".RT-k3j9x0a1b2d.yaml", ".Rt-x"} {
			if err := os.WriteFile(filepath.Join(base, name), []byte("not a record: ["), 0o644); err != nil {
				t.Fatal(err)
			}
			left = append(left, filepath.Join(base, name))
		}
		if err := os.Symlink("x509.yaml", filepath.Join(base, ".rT-link")); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(filepath.Join(base, ".rt-fifo"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(base, ".rt-folder"), 0o755); err != nil {
			t.Fatal(err)
		}
		left = append(left, filepath.Join(base, ".rT-link"), filepath.Join(base, ".rt-fifo"), filepath.Join(base, ".rt-folder"))
	}
	code, stdout, stderr := p.run(nil, "--dir", ca, "apply", "--plan-only", "--key-dir", keys, "--output", "json")
	if code != 0 {
		t.Fatalf("apply --plan-only with leftovers: exit %d, stderr %s", code, stderr)
	}
	if strings.Contains(strings.ToLower(stdout+stderr), ".rt-") {
		t.Errorf("the words name a leftover: %q %q", stdout, stderr)
	}
	obj := struct{ Plan struct{ Path, SHA256 string } }{}
	if err := json.Unmarshal([]byte(stdout), &obj); err != nil || len(obj.Plan.SHA256) != 64 {
		t.Fatalf("plan: %s, %v", stdout, err)
	}
	code, _, stderr = p.run(nil, "--dir", ca, "apply", obj.Plan.Path, "--key-dir", keys, "--confirm", obj.Plan.SHA256)
	if code != 0 {
		t.Fatalf("apply PLAN with leftovers: exit %d, stderr %s", code, stderr)
	}
	if code, hist, _ := p.run(nil, "--dir", ca, "check", "history"); code != 0 || !strings.HasPrefix(hist, "history: 1 ceremony records") {
		t.Errorf("check history: exit %d, %q", code, hist)
	}
	for _, l := range left {
		if _, err := os.Lstat(l); err != nil {
			t.Errorf("a leftover is gone: %v", err)
		}
	}
}
