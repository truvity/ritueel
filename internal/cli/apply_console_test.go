//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// A standard error that breaks after the plan was shown and the plan was confirmed: the command ends with
// exit code 1 and nothing is written. The names of this file start with ac.

// acBreak is a standard error that keeps the lines it takes until one holds marker, and refuses that line and
// every later one, as a pipe whose reader has gone does.
type acBreak struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	marker  string
	broken  bool
	refused int
}

func (s *acBreak) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.broken && strings.Contains(string(p), s.marker) {
		s.broken = true
	}
	if s.broken {
		s.refused++
		return 0, errors.New("test: the stream is closed")
	}
	return s.buf.Write(p)
}

func (s *acBreak) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (s *acBreak) refusals() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

var acDigest = regexp.MustCompile(`plan digest ([0-9a-f]{64})`)

// acTyper is the standard input of a person who reads the digest on standard error and types its first
// eight characters: the line is made at the first read, when the plan is already shown.
type acTyper struct {
	from  *acBreak
	reads int
	line  *strings.Reader
}

func (r *acTyper) Read(p []byte) (int, error) {
	r.reads++
	if r.line == nil {
		m := acDigest.FindStringSubmatch(r.from.text())
		if m == nil {
			return 0, errors.New("test: the plan was not shown before the line was asked for")
		}
		r.line = strings.NewReader(m[1][:8] + "\n")
	}
	return r.line.Read(p)
}

func TestApplyWithAStandardErrorThatBreaksAtTheConfirmationIsExitCode1AndWritesNothing(t *testing.T) {
	cases := []struct {
		name   string
		saved  bool
		typed  bool
		marker string
	}{
		{"saved plan, flag", true, false, "confirmed with --confirm"},
		{"saved plan, typed", true, true, "confirmed by typing"},
		// The digest of a direct apply cannot be known before the plan is made, so a script cannot confirm
		// it by flag: only the typed form reaches the confirmation of a direct apply.
		{"direct, typed", false, true, "confirmed by typing"},
	}
	for _, c := range cases {
		for _, output := range []string{"json", "text"} {
			t.Run(c.name+", "+output, func(t *testing.T) {
				dir, keys := arBundle(t)
				args := []string{"--dir", dir, "apply", "--key-dir", keys}
				if output == "json" {
					args = []string{"--dir", dir, "--output", "json", "apply", "--key-dir", keys}
				}
				if c.saved {
					path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
					args = append(args, path)
					if !c.typed {
						args = append(args, "--confirm", digest)
					}
				}
				before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
				stderr := &acBreak{marker: c.marker}
				var in io.Reader = strings.NewReader("")
				var typer *acTyper
				if c.typed {
					typer = &acTyper{from: stderr}
					in = typer
				}
				var stdout bytes.Buffer
				code := Run(context.Background(), args, Env{
					Stdin: in, Stdout: &stdout, Stderr: stderr, Build: testBuild,
					Now: newTicker(apClock).now, StdinIsTerminal: c.typed,
				})
				if stderr.refusals() == 0 {
					t.Fatal("the stream was never broken: the case does not reach the line of the confirmation")
				}
				if code != ExitFailure {
					t.Errorf("exit code %d, want %d (not %d, which is a confirmation that was refused)", code, ExitFailure, ExitNotConfirmed)
				}
				crqSame(t, "the bundle", before, apSnapshot(t, dir))
				crqSame(t, "the key directory", keysBefore, apSnapshot(t, keys))
				if !c.saved {
					if _, err := os.Stat(filepath.Join(dir, "history")); err == nil {
						t.Error("history/ exists: a direct apply wrote its plan folder")
					}
				}
				if output == "json" {
					obj := apObject(t, stdout.String())
					msg, _ := obj["error"].(string)
					if obj["outcome"] != "failed" || obj["exit_code"].(json.Number).String() != "1" {
						t.Errorf("the object: %v", obj)
					}
					if !strings.Contains(msg, "a line could not be shown") || !strings.Contains(msg, "nothing was written") {
						t.Errorf("the error does not say what happened: %q", msg)
					}
					if _, ok := obj["reasons"]; ok {
						t.Errorf("a failure has reasons: %v", obj)
					}
				} else if stdout.String() != "" {
					t.Errorf("standard output holds %q", stdout.String())
				}
				if typer != nil && typer.reads == 0 {
					t.Error("the typed line was not read")
				}
			})
		}
	}
}
