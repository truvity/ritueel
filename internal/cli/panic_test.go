package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A panic in a command ends the run like any other failure: exit code 1 (not 2, the code of
// a usage error), the outcome failed, the message on standard error and no stack trace.
func TestPanicEndsWithTheFailureCode(t *testing.T) {
	tests := []struct {
		name  string
		value any
		text  string
	}{
		{"string", "x", "internal error: x"},
		{"error value", errors.New("x"), "internal error: x"},
		// The error is shown, not passed on: a panic with a usage error is still a failure.
		{"usage error value", UsageError{Msg: "x"}, "internal error: x"},
		{"refusal value", Refusal{Reasons: []string{"policy"}, Msg: "x"}, "internal error: x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withSpecs(t, spec{name: "boom", usage: "a test command", run: func(context.Context, *Call) (*Result, error) {
				panic(tt.value)
			}})

			t.Run("text", func(t *testing.T) {
				r := run(t, "boom")
				if r.code != ExitFailure {
					t.Errorf("exit code = %d, want 1", int(r.code))
				}
				if r.stdout != "" {
					t.Errorf("stdout = %q, want empty", r.stdout)
				}
				if want := "ritueel: " + tt.text + "\n"; r.stderr != want {
					t.Errorf("stderr = %q, want %q", r.stderr, want)
				}
			})

			t.Run("json", func(t *testing.T) {
				r := run(t, "--output", "json", "boom")
				if r.code != ExitFailure {
					t.Errorf("exit code = %d, want 1", int(r.code))
				}
				wantObject(t, object(t, r.stdout), map[string]any{
					"output":    1,
					"command":   "boom",
					"exit_code": 1,
					"outcome":   "failed",
					"error":     tt.text,
				})
				if want := "ritueel: " + tt.text + "\n"; r.stderr != want {
					t.Errorf("stderr = %q, want %q", r.stderr, want)
				}
			})
		})
	}
}

// No stack trace goes to either stream, and a run after a panic starts clean.
func TestPanicPrintsNoStackTrace(t *testing.T) {
	withSpecs(t, spec{name: "boom", usage: "a test command", run: func(context.Context, *Call) (*Result, error) {
		panic("x")
	}})
	for _, args := range [][]string{{"boom"}, {"--output", "json", "boom"}} {
		r := run(t, args...)
		for _, s := range []string{r.stdout, r.stderr} {
			for _, bad := range []string{"goroutine", "panic:", ".go:", "runtime."} {
				if strings.Contains(s, bad) {
					t.Errorf("%v: output %q holds %q", args, s, bad)
				}
			}
		}
	}
}

// A panic does not leave state behind: the next run on the same table is normal.
func TestPanicLeavesNoStateBehind(t *testing.T) {
	withSpecs(t,
		spec{name: "boom", usage: "a test command", run: func(context.Context, *Call) (*Result, error) {
			panic("x")
		}},
		spec{name: "fine", usage: "a test command", run: func(context.Context, *Call) (*Result, error) {
			return &Result{Text: "ok\n"}, nil
		}},
	)
	if r := run(t, "boom"); r.code != ExitFailure {
		t.Fatalf("boom: exit code = %d, want 1", int(r.code))
	}
	r := run(t, "fine")
	if r.code != ExitOK || r.stdout != "ok\n" || r.stderr != "" {
		t.Errorf("after the panic: (%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
}
