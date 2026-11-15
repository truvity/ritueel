//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A write to a pipe whose reader has closed is an error of the write and not the end of the process: the
// Go runtime ends a program on that write to standard output or standard error unless the signal is
// ignored. The built program runs with a stream that is such a pipe, and ends with an exit code of the
// table of the cli page, and never by a signal.

// spOutcome is how a run of the program ended.
type spOutcome struct {
	code     int
	signaled bool
	signal   syscall.Signal
	stdout   string
	stderr   string
}

// brokenPipe is a pipe whose reader is closed already: a write to it fails at once.
func brokenPipe(t *testing.T) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w
}

// spRun runs the program with the given streams (nil is a buffer that is returned).
func spRun(t *testing.T, exe string, stdout, stderr *os.File, args ...string) spOutcome {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), exe, args...)
	cmd.Dir = t.TempDir()
	cmd.Stdin = strings.NewReader("")
	var out, errOut bytes.Buffer
	if stdout != nil {
		cmd.Stdout = stdout
	} else {
		cmd.Stdout = &out
	}
	if stderr != nil {
		cmd.Stderr = stderr
	} else {
		cmd.Stderr = &errOut
	}
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("running the program: %v", err)
	}
	o := spOutcome{stdout: out.String(), stderr: errOut.String()}
	st, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatal("no wait status")
	}
	o.signaled = st.Signaled()
	if o.signaled {
		o.signal = st.Signal()
	}
	o.code = cmd.ProcessState.ExitCode()
	return o
}

// inTable fails the test when the process was ended by a signal or its exit code is not one of the table.
func (o spOutcome) inTable(t *testing.T, what string) {
	t.Helper()
	if o.signaled {
		t.Fatalf("%s: the program was ended by the signal %v", what, o.signal)
	}
	if o.code < 0 || o.code > 5 {
		t.Fatalf("%s: exit code %d is not in the table of the cli page", what, o.code)
	}
}

func TestProgramWithStandardErrorAsAPipeWhoseReaderClosedEndsWithAnExitCodeAndWritesNothing(t *testing.T) {
	p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
	ca, keys, planPath, digest := apFirst(t, p)
	before, keysBefore := apTreeOf(t, ca), apTreeOf(t, keys)
	for name, args := range map[string][]string{
		"a saved plan":   {"--dir", ca, "--output", "json", "apply", planPath, "--key-dir", keys, "--confirm", digest},
		"a direct apply": {"--dir", ca, "--output", "json", "apply", "--key-dir", keys, "--confirm", digest},
	} {
		t.Run(name, func(t *testing.T) {
			o := spRun(t, p.exe, nil, brokenPipe(t), args...)
			o.inTable(t, name)
			// The plan cannot be shown, so it is not asked for and nothing is written: exit code 1, and the
			// stop line goes to the stream that still takes it, standard output, as the object of the page.
			if o.code != 1 {
				t.Errorf("exit code %d, want 1", o.code)
			}
			var obj map[string]any
			if err := json.Unmarshal([]byte(o.stdout), &obj); err != nil {
				t.Fatalf("standard output is not the object: %q, %v", o.stdout, err)
			}
			msg, _ := obj["error"].(string)
			if obj["outcome"] != "failed" || !strings.Contains(msg, "could not be shown") || !strings.Contains(msg, "nothing was written") {
				t.Errorf("the object does not say what happened: %v", obj)
			}
			if apTreeOf(t, ca) != before || apTreeOf(t, keys) != keysBefore {
				t.Error("the bundle or the key directory changed: a signature or a key was made before the plan was shown")
			}
		})
	}
}

func TestProgramWithStandardOutputAsAPipeWhoseReaderClosedRecordsTheCeremonyAndSaysSo(t *testing.T) {
	// In the text form the end line of the history is the only line on standard output, and it follows the
	// record. A broken pipe there is exit code 1 with a line that says the ceremony is recorded.
	p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
	ca, keys, planPath, digest := apFirst(t, p)
	o := spRun(t, p.exe, brokenPipe(t), nil, "--dir", ca, "apply", planPath, "--key-dir", keys, "--confirm", digest)
	o.inTable(t, "standard output closed")
	if o.code != 1 || !strings.Contains(o.stderr, "is recorded, but a line of it could not be shown") {
		t.Errorf("exit %d, stderr tail %q; want 1 and a line that says the ceremony is recorded", o.code, o.stderr[max(0, len(o.stderr)-400):])
	}
	code, hist, herr := p.run(nil, "--dir", ca, "check", "history")
	if code != 0 || !strings.HasPrefix(hist, "history: 1 ceremony records, end ") {
		t.Errorf("check history after the run: exit %d, %q, %s", code, hist, herr)
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 4 {
		t.Errorf("the key directory holds %d files, want 4", len(ents))
	}
}

func TestProgramWithBothStreamsAsPipesWhoseReadersClosedEndsWithAnExitCode(t *testing.T) {
	p := apProgram{t: t, exe: buildForCheck(t), dir: t.TempDir()}
	ca, keys, planPath, digest := apFirst(t, p)
	before, keysBefore := apTreeOf(t, ca), apTreeOf(t, keys)
	o := spRun(t, p.exe, brokenPipe(t), brokenPipe(t), "--dir", ca, "apply", planPath, "--key-dir", keys, "--confirm", digest)
	o.inTable(t, "both streams closed")
	if o.code != 1 {
		t.Errorf("exit code %d, want 1", o.code)
	}
	if apTreeOf(t, ca) != before || apTreeOf(t, keys) != keysBefore {
		t.Error("the bundle or the key directory changed although the plan could not be shown")
	}
}

func TestProgramThatWritesALongOutputToAPipeThatEndedEarlyIsNotEndedBySignal(t *testing.T) {
	// "ritueel --help | head -1": the reader closed after the first line, the program is not ended by a
	// signal and its exit code is one of the table.
	exe := buildForCheck(t)
	for _, args := range [][]string{{"--help"}, {"version"}, {"apply", "--help"}} {
		for _, stream := range []string{"stdout", "stderr"} {
			o := func() spOutcome {
				if stream == "stdout" {
					return spRun(t, exe, brokenPipe(t), nil, args...)
				}
				return spRun(t, exe, nil, brokenPipe(t), args...)
			}()
			o.inTable(t, strings.Join(args, " ")+" with "+stream+" closed")
		}
	}
}

func TestProgramWhoseStandardErrorBreaksWhileACeremonyRunsLeavesAStateThatTheHistoryCheckAccepts(t *testing.T) {
	// The reader of standard error reads the first line of the plan and closes. What the process has
	// written by then is in the pipe, so how far the ceremony goes depends on the process and not on the
	// test; for every length the program ends with an exit code and not by a signal, and the bundle is in a
	// state that the table of the stops names: untouched, an open attempt with no record, or recorded.
	exe := buildForCheck(t)
	for try := 0; try < 4; try++ {
		p := apProgram{t: t, exe: exe, dir: t.TempDir()}
		ca, keys, planPath, digest := apFirst(t, p)
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), exe, "--dir", ca, "apply", planPath, "--key-dir", keys, "--confirm", digest)
		cmd.Dir = p.dir
		cmd.Stdin = strings.NewReader("")
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, w
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		one := make([]byte, 1)
		if _, err := io.ReadFull(r, one); err != nil {
			t.Fatal(err)
		}
		_ = r.Close()
		werr := cmd.Wait()
		var ee *exec.ExitError
		if werr != nil && !errors.As(werr, &ee) {
			t.Fatal(werr)
		}
		st := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if st.Signaled() {
			t.Fatalf("try %d: the program was ended by the signal %v", try, st.Signal())
		}
		code := cmd.ProcessState.ExitCode()
		if code < 0 || code > 5 {
			t.Fatalf("try %d: exit code %d is not in the table", try, code)
		}
		attempt := exists(filepath.Join(ca, strings.TrimSuffix(planPath, "plan.json")+"attempt.json"))
		record := exists(filepath.Join(ca, strings.TrimSuffix(planPath, "plan.json")+"record.json"))
		sigs := countLines(filepath.Join(ca, strings.TrimSuffix(planPath, "plan.json")+"signatures.jsonl"))
		switch {
		case code == 0 && !record:
			t.Errorf("try %d: exit code 0 and no record", try)
		case record && code != 0 && code != 1:
			t.Errorf("try %d: a record and exit code %d", try, code)
		case !attempt && (record || sigs > 0):
			t.Errorf("try %d: a record or a signature and no attempt", try)
		case !record && attempt && code != 1:
			t.Errorf("try %d: an open attempt and exit code %d, want a stop (1)", try, code)
		case !attempt && code != 1:
			t.Errorf("try %d: no attempt and exit code %d, want 1", try, code)
		}
		// The check of the history is what a person runs next: it does not fail on what a stop left.
		hc, hist, herr := p.run(nil, "--dir", ca, "check", "history")
		if hc != 0 {
			t.Errorf("try %d: check history exit %d: %q %s", try, hc, hist, herr)
		}
		if record {
			if !strings.HasPrefix(hist, "history: 1 ceremony records, end ") {
				t.Errorf("try %d: check history says %q", try, hist)
			}
		}
	}
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func countLines(p string) int {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	return bytes.Count(b, []byte("\n"))
}
