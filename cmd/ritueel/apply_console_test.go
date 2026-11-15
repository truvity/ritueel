//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The built program with standard error as a pipe whose reader closes after the plan was shown: the plan is
// confirmed by typing at a terminal, so the line of the confirmation is the first line that the program
// cannot show, and no timing of the reader decides the case. The program ends with exit code 1 and writes
// nothing: no attempt, no key.

var acDigestRe = regexp.MustCompile(`plan digest ([0-9a-f]{64})`)

// acFresh makes a bundle of one test root with the OpenPGP root file removed and a key directory beside
// it, and no plan folder.
func acFresh(t *testing.T, p apProgram) (ca, keys string) {
	t.Helper()
	root := t.TempDir()
	ca, keys = filepath.Join(root, "ca"), filepath.Join(root, "keys")
	if code, _, stderr := p.run(nil, "new", "--test-root", ca); code != 0 {
		t.Fatalf("new: %d %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(ca, "want", "roots", "openpgp.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	return ca, keys
}

// acTypedRun runs the program with standard input at a terminal and standard error as a pipe. The reader of
// the pipe takes the lines up to the prompt, closes, and only then is the digest typed.
func acTypedRun(t *testing.T, exe, dir string, args ...string) (spOutcome, string) {
	t.Helper()
	master, slave := openPty(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, &out, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The program holds the only write end now.
	_ = w.Close()
	var seen strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(seen.String(), "press Enter:") {
		n, err := r.Read(buf)
		seen.Write(buf[:n])
		if err != nil {
			_ = r.Close()
			_ = cmd.Wait()
			t.Fatalf("standard error ended before the prompt: %v, %q", err, seen.String())
		}
	}
	m := acDigestRe.FindStringSubmatch(seen.String())
	if m == nil {
		_ = r.Close()
		_ = cmd.Wait()
		t.Fatalf("no digest before the prompt: %q", seen.String())
	}
	// The reader goes away: every write of the program to standard error fails from here on.
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(master, m[1][:8]+"\n"); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("running the program: %v", err)
	}
	st, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatal("no wait status")
	}
	o := spOutcome{stdout: out.String(), code: cmd.ProcessState.ExitCode(), signaled: st.Signaled()}
	if o.signaled {
		o.signal = st.Signal()
	}
	return o, seen.String()
}

func TestProgramWithStandardErrorThatClosesAfterThePlanWordsEndsWithExitCode1AndWritesNothing(t *testing.T) {
	for _, form := range []string{"a saved plan", "a direct apply"} {
		t.Run(form, func(t *testing.T) {
			p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
			var ca, keys string
			args := func(ca, keys string) []string {
				return []string{"--dir", ca, "--output", "json", "apply", "--key-dir", keys}
			}
			var a []string
			if form == "a saved plan" {
				var planPath string
				ca, keys, planPath, _ = apFirst(t, p)
				a = append(args(ca, keys), planPath)
			} else {
				ca, keys = acFresh(t, p)
				a = args(ca, keys)
			}
			before, keysBefore := apTreeOf(t, ca), apTreeOf(t, keys)
			o, shown := acTypedRun(t, p.exe, p.dir, a...)
			o.inTable(t, form)
			if !strings.Contains(shown, "plan digest") {
				t.Errorf("the plan words did not reach the reader: %q", shown)
			}
			if o.code != 1 {
				t.Errorf("exit code %d, want 1 (a confirmation that the person gave is not a refused confirmation)", o.code)
			}
			var obj map[string]any
			if err := json.Unmarshal([]byte(o.stdout), &obj); err != nil {
				t.Fatalf("standard output is not the object: %q, %v", o.stdout, err)
			}
			msg, _ := obj["error"].(string)
			if obj["outcome"] != "failed" || !strings.Contains(msg, "a line could not be shown") || !strings.Contains(msg, "nothing was written") {
				t.Errorf("the object does not say what happened: %v", obj)
			}
			if apTreeOf(t, ca) != before || apTreeOf(t, keys) != keysBefore {
				t.Error("the bundle or the key directory changed: an attempt or a key was written before the console was judged")
			}
			if _, err := os.Stat(filepath.Join(ca, "roots")); err == nil {
				t.Error("roots/ exists")
			}
			if form == "a direct apply" {
				if _, err := os.Stat(filepath.Join(ca, "history")); err == nil {
					t.Error("history/ exists after a direct apply that wrote nothing")
				}
			}
		})
	}
}
