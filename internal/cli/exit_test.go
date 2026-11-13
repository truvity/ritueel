package cli

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// Compile-time: every error type is a Coded, as a value and as a pointer.
var (
	_ Coded = UsageError{}
	_ Coded = &UsageError{}
	_ Coded = Refusal{}
	_ Coded = &Refusal{}
	_ Coded = BackendRefusal{}
	_ Coded = &BackendRefusal{}
	_ Coded = NotConfirmed{}
	_ Coded = &NotConfirmed{}
)

// The exit codes of the table "Exit codes" in docs/reference/cli.md, written out. This test is
// a copy of that table: a change to a number must change the page and this test together.
func TestExitCodeValues(t *testing.T) {
	tests := []struct {
		name string
		got  ExitCode
		want int
	}{
		{"ExitOK", ExitOK, 0},
		{"ExitFailure", ExitFailure, 1},
		{"ExitUsage", ExitUsage, 2},
		{"ExitRefused", ExitRefused, 3},
		{"ExitBackend", ExitBackend, 4},
		{"ExitNotConfirmed", ExitNotConfirmed, 5},
		{"ExitNotice", ExitNotice, 10},
		{"ExitAlert", ExitAlert, 11},
		{"ExitCritical", ExitCritical, 12},
	}
	seen := map[int]string{}
	for _, tt := range tests {
		if int(tt.got) != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, int(tt.got), tt.want)
		}
		if other, dup := seen[tt.want]; dup {
			t.Errorf("%s and %s share the number %d", tt.name, other, tt.want)
		}
		seen[tt.want] = tt.name
	}
}

// The words of the "outcome" member: done, refused, not-confirmed, usage, failed.
func TestOutcomeWords(t *testing.T) {
	tests := []struct {
		got  Outcome
		want string
	}{
		{OutcomeDone, "done"},
		{OutcomeRefused, "refused"},
		{OutcomeNotConfirmed, "not-confirmed"},
		{OutcomeUsage, "usage"},
		{OutcomeFailed, "failed"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("outcome %q, want %q", string(tt.got), tt.want)
		}
	}
}

func TestExitFor(t *testing.T) {
	coded := []struct {
		name    string
		err     error
		code    ExitCode
		outcome Outcome
	}{
		{"UsageError value", UsageError{Msg: "m"}, 2, "usage"},
		{"UsageError pointer", &UsageError{Msg: "m"}, 2, "usage"},
		{"Refusal value", Refusal{Reasons: []string{"policy"}}, 3, "refused"},
		{"Refusal pointer", &Refusal{Reasons: []string{"policy"}}, 3, "refused"},
		{"BackendRefusal value", BackendRefusal{Reasons: []string{"pin-locked"}}, 4, "refused"},
		{"BackendRefusal pointer", &BackendRefusal{Reasons: []string{"pin-locked"}}, 4, "refused"},
		{"NotConfirmed value", NotConfirmed{}, 5, "not-confirmed"},
		{"NotConfirmed pointer", &NotConfirmed{}, 5, "not-confirmed"},
	}
	for _, tt := range coded {
		t.Run(tt.name, func(t *testing.T) {
			code, outcome := ExitFor(tt.err)
			if int(code) != int(tt.code) || outcome != tt.outcome {
				t.Errorf("ExitFor = (%d, %q), want (%d, %q)", int(code), outcome, int(tt.code), tt.outcome)
			}
			// A wrapped one gives the same answer.
			wrapped := fmt.Errorf("while doing something: %w", tt.err)
			code, outcome = ExitFor(wrapped)
			if int(code) != int(tt.code) || outcome != tt.outcome {
				t.Errorf("ExitFor(wrapped) = (%d, %q), want (%d, %q)", int(code), outcome, int(tt.code), tt.outcome)
			}
			// Twice wrapped, with errors.Join in between.
			twice := fmt.Errorf("outer: %w", errors.Join(errors.New("other"), wrapped))
			code, outcome = ExitFor(twice)
			if int(code) != int(tt.code) || outcome != tt.outcome {
				t.Errorf("ExitFor(wrapped twice) = (%d, %q), want (%d, %q)", int(code), outcome, int(tt.code), tt.outcome)
			}
		})
	}

	t.Run("nil", func(t *testing.T) {
		code, outcome := ExitFor(nil)
		if code != ExitOK || outcome != OutcomeDone {
			t.Errorf("ExitFor(nil) = (%d, %q), want (0, done)", int(code), outcome)
		}
	})
	t.Run("plain error", func(t *testing.T) {
		code, outcome := ExitFor(errors.New("boom"))
		if code != ExitFailure || outcome != OutcomeFailed {
			t.Errorf("ExitFor(plain) = (%d, %q), want (1, failed)", int(code), outcome)
		}
	})
	t.Run("wrapped plain error", func(t *testing.T) {
		code, outcome := ExitFor(fmt.Errorf("context: %w", errors.New("boom")))
		if code != ExitFailure || outcome != OutcomeFailed {
			t.Errorf("ExitFor(wrapped plain) = (%d, %q), want (1, failed)", int(code), outcome)
		}
	})
}

func TestReasonsOf(t *testing.T) {
	if got := reasonsOf(nil); len(got) != 0 {
		t.Errorf("reasonsOf(nil) = %v, want none", got)
	}
	if got := reasonsOf(errors.New("boom")); len(got) != 0 {
		t.Errorf("reasonsOf(plain) = %v, want none", got)
	}
	if got := reasonsOf(UsageError{Msg: "x"}); len(got) != 0 {
		t.Errorf("reasonsOf(usage) = %v, want none", got)
	}
	if got := reasonsOf(NotConfirmed{}); len(got) != 0 {
		t.Errorf("reasonsOf(not confirmed) = %v, want none", got)
	}
	want := []string{"policy", "plan-stale"}
	for name, err := range map[string]error{
		"refusal":         Refusal{Reasons: want},
		"backend":         BackendRefusal{Reasons: want},
		"wrapped refusal": fmt.Errorf("x: %w", Refusal{Reasons: want}),
	} {
		if got := reasonsOf(err); !slices.Equal(got, want) {
			t.Errorf("%s: reasonsOf = %v, want %v", name, got, want)
		}
	}
}

func TestErrorTexts(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"usage", UsageError{Msg: "bad flag"}, "bad flag"},
		{"refusal with a message", Refusal{Reasons: []string{"a"}, Msg: "no, because"}, "no, because"},
		{"refusal with reasons only", Refusal{Reasons: []string{"a", "b"}}, "refused: a, b"},
		{"refusal with nothing", Refusal{}, "refused"},
		{"backend with a message", BackendRefusal{Reasons: []string{"a"}, Msg: "card says no"}, "card says no"},
		{"backend with reasons only", BackendRefusal{Reasons: []string{"a", "b"}}, "refused by the card or the backend: a, b"},
		{"backend with nothing", BackendRefusal{}, "refused by the card or the backend"},
		{"not confirmed", NotConfirmed{}, "not confirmed"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("%s: Error() = %q, want %q", tt.name, got, tt.want)
		}
	}
}
