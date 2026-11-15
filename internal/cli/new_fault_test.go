//go:build linux

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A write that fails in the middle of "new". The command has no place where a test can put a file system of its
// own, so the fault is made by the operating system: the test runs the command in a second process of the test
// binary whose largest file is limited (RLIMIT_FSIZE, with the signal that a write over the limit raises
// ignored), so that the write of a file longer than the limit fails with an error, at the same call every time.
// Nothing here waits for the scheduling of a goroutine. The library has its own test that fails each call in turn.

const (
	faultChildEnv = "RITUEL_CLI_TEST_FAULT_CHILD"
	faultLimitEnv = "RITUEL_CLI_TEST_FAULT_LIMIT"
)

// TestFaultChild is the second process. It does nothing in the first one.
func TestFaultChild(t *testing.T) {
	raw := os.Getenv(faultChildEnv)
	if raw == "" {
		return // the first process: this is not a test of its own
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		os.Exit(99)
	}
	var limit uint64
	if _, err := fmt.Sscan(os.Getenv(faultLimitEnv), &limit); err != nil {
		os.Exit(98)
	}
	signal.Ignore(syscall.SIGXFSZ)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: limit, Max: limit}); err != nil {
		os.Exit(97)
	}
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, Env{Stdout: &stdout, Stderr: &stderr, Build: testBuild})
	// The answer goes through a pipe that the first process gave as its third file: a pipe is not a file that
	// the limit applies to, and the output of a test is mixed with its own.
	out, _ := json.Marshal(map[string]any{"code": int(code), "stdout": stdout.String(), "stderr": stderr.String()})
	pipe := os.NewFile(3, "answer")
	if _, err := pipe.Write(out); err != nil {
		os.Exit(96)
	}
	_ = pipe.Close()
	os.Exit(0)
}

// runLimited runs the command line in a second process whose files may not grow past limit bytes.
func runLimited(t *testing.T, limit int, args ...string) result {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), exe, "-test.run=^TestFaultChild$")
	cmd.Env = append(os.Environ(), faultChildEnv+"="+string(enc), fmt.Sprintf("%s=%d", faultLimitEnv, limit))
	cmd.ExtraFiles = []*os.File{wr}
	var combined bytes.Buffer
	cmd.Stdout, cmd.Stderr = &combined, &combined
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = wr.Close()
	raw, err := io.ReadAll(rd)
	_ = rd.Close()
	if werr := cmd.Wait(); werr != nil || err != nil {
		t.Fatalf("the second process: %v %v\n%s", werr, err, combined.String())
	}
	var ans struct {
		Code           int
		Stdout, Stderr string
	}
	if err := json.Unmarshal(raw, &ans); err != nil {
		t.Fatal(err)
	}
	return result{code: ExitCode(ans.Code), stdout: ans.Stdout, stderr: ans.Stderr}
}

func TestAWriteThatFailsStopsNewAndTellsWhichFolderToRemove(t *testing.T) {
	for _, testRoot := range []bool{false, true} {
		g := newGolden(testRoot)
		// Each file fails in turn: the limit is one byte less than the file, and the files before it are shorter.
		type step struct {
			name  string
			limit int
			// written is what exists after the stop, as paths of files.
			written []string
		}
		x509, openpgp, settings := len(g[0][1]), len(g[1][1]), len(g[2][1])
		if x509 >= openpgp || openpgp >= settings {
			t.Fatalf("the starter files are not of growing size (%d, %d, %d): the test cannot fail them one by one", x509, openpgp, settings)
		}
		for _, s := range []step{
			{"the first root file", x509 - 1, nil},
			{"the second root file", openpgp - 1, []string{"want/roots/x509.yaml"}},
			{"ritueel.yaml, the last", settings - 1, []string{"want/roots/x509.yaml", "want/roots/openpgp.yaml"}},
		} {
			t.Run(fmt.Sprintf("test root %v, %s", testRoot, s.name), func(t *testing.T) {
				parent := t.TempDir()
				dir := filepath.Join(parent, "acme")
				args := []string{"new"}
				if testRoot {
					args = append(args, "--test-root")
				}
				r := runLimited(t, s.limit, append(args, dir)...)
				if ExitCode(r.code) != ExitFailure || r.stdout != "" {
					t.Fatalf("(%d, %q, %q), want exit code 1 and nothing on standard output", int(r.code), r.stdout, r.stderr)
				}
				want := "the folder " + dir + " is left as it is; remove it and run new again"
				if !strings.Contains(r.stderr, want) || strings.Count(r.stderr, "\n") != 1 || !onlyPrintable(r.stderr) {
					t.Errorf("standard error = %q, want one line that holds %q", r.stderr, want)
				}
				// What is on disk: the folder, what was written before the fault, and never ritueel.yaml.
				got := entriesOf(t, dir)
				if _, ok := got["ritueel.yaml"]; ok {
					t.Error("ritueel.yaml exists after a fault that stopped before it: the half-made folder would be taken for a bundle")
				}
				for _, f := range s.written {
					if m, ok := got[f]; !ok || !m.IsRegular() {
						t.Errorf("%s was written before the fault and is not there: %v", f, got)
					}
				}
				for p := range got {
					known := p == "want/" || p == "want/roots/" || strings.HasPrefix(p, ".rt-")
					for _, f := range s.written {
						known = known || p == f
					}
					if !known && !strings.Contains(p, ".rt-") {
						t.Errorf("%s exists after the fault and was not written before it", p)
					}
				}
				entries, err := os.ReadDir(parent)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 {
					t.Errorf("the parent holds %d entries, want only the folder", len(entries))
				}
				// A command that reads a bundle takes the half-made folder for none.
				c := run(t, "check", "request", "x", "--dir", dir)
				if c.code != ExitFailure || !strings.Contains(c.stderr, "ritueel.yaml") {
					t.Errorf("check request on the half-made folder: (%d, %q)", int(c.code), c.stderr)
				}
			})
		}
	}
}

// With no fault the same process, limited to more than the largest file, makes the bundle: the limit alone is
// not what fails the other cases.
func TestTheSameProcessWithAHighEnoughLimitMakesTheBundle(t *testing.T) {
	g := newGolden(false)
	parent := t.TempDir()
	dir := filepath.Join(parent, "acme")
	r := runLimited(t, len(g[2][1]), "new", dir)
	if r.code != ExitOK {
		t.Fatalf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	if _, ok := entriesOf(t, dir)["ritueel.yaml"]; !ok {
		t.Error("no ritueel.yaml")
	}
}

// A parent that nothing can be made in: the folder is not made, so there is nothing to remove, and the error says
// nothing of a folder that is left.
func TestAParentThatRefusesTheFolderIsAFailureWithNoFolderToRemove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a process of the superuser makes a folder anywhere")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o755) })
	r := run(t, "new", filepath.Join(parent, "acme"))
	if r.code != ExitFailure || strings.Contains(r.stderr, "left as it is") || !strings.HasPrefix(r.stderr, "ritueel: ") {
		t.Errorf("(%d, %q)", int(r.code), r.stderr)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 0 {
		t.Errorf("the parent holds %d entries", len(entries))
	}
}

// The text says what was already written: new stops at the first error (record 0006, rule 33) and the person must
// be able to tell what is there before removing it. A count is not that. The
// path of the file that failed is left out of what is searched, because it holds the folder names by itself.
func TestAFailedNewNamesWhatItAlreadyWrote(t *testing.T) {
	g := newGolden(false)
	x509, openpgp, settings := len(g[0][1]), len(g[1][1]), len(g[2][1])
	for _, s := range []struct {
		name    string
		limit   int
		written []string
	}{
		{"the first root file", x509 - 1, nil},
		{"the second root file", openpgp - 1, []string{"want/roots/x509.yaml"}},
		{"ritueel.yaml, the last", settings - 1, []string{"want/roots/x509.yaml", "want/roots/openpgp.yaml"}},
	} {
		t.Run(s.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "acme")
			r := runLimited(t, s.limit, "new", dir)
			if r.code != ExitFailure {
				t.Fatalf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
			}
			said := r.stderr
			if i := strings.Index(said, "fsx: "); i >= 0 {
				if j := strings.Index(said[i:], "; the folder"); j >= 0 {
					said = said[:i] + said[i+j:]
				}
			}
			all := append([]string{"want/", "want/roots/"}, s.written...)
			for _, p := range all {
				if !strings.Contains(said, p) {
					t.Errorf("standard error does not name %q, which was written before the fault:\n%s", p, r.stderr)
				}
			}
			// The count and the names, in the order they were written, in the words "N things were written in it".
			want := fmt.Sprintf("the folder was made and %d things were written in it (%s): ", len(all), strings.Join(all, ", "))
			if !strings.Contains(r.stderr, want) {
				t.Errorf("standard error does not hold %q:\n%s", want, r.stderr)
			}
			if strings.Contains(r.stderr, "1 things") || strings.Contains(strings.Join(all, ", "), "ritueel.yaml") {
				t.Errorf("the list holds a file that was not written, or the grammar is wrong:\n%s", r.stderr)
			}
		})
	}
}
