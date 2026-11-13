package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// A reason is a code that a command chooses, and no page states its shape, so one that holds a
// character outside printable ASCII is escaped, not refused: finish writes it as \uXXXX in the
// "reasons" member, for a refusal and for a Result that ended well. A plain code is unchanged, a nil
// or an empty list leaves the member out. No escape is written out here: u builds one.

// reasonsOdd are reasons that hold what a terminal must not get raw, and what Escape writes for them.
func reasonsOdd() (in, want []string) {
	in = []string{
		"plan-stale",
		"v" + string(rune(0x0435)) + "rsion",
		"esc\x1b[31m",
		"bad\xffbyte",
		"line\nbreak",
		"emoji" + string(rune(0x1F600)),
		"",
	}
	want = []string{
		"plan-stale",
		"v" + u(0x0435) + "rsion",
		"esc" + u(0x1b) + "[31m",
		"bad" + u(0xFFFD) + "byte",
		"line" + u(10) + "break",
		"emoji" + u(0xD83D) + u(0xDE00),
		"",
	}
	return in, want
}

// jsonList is a list of strings as the program writes it: each in quotes, a backslash doubled (the
// reasons have no quote and no other character that JSON escapes).
func jsonList(ss []string) string {
	var parts []string
	for _, s := range ss {
		parts = append(parts, `"`+strings.ReplaceAll(s, `\`, `\\`)+`"`)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func TestTheReasonsAreEscapedForARefusalAndForAResult(t *testing.T) {
	in, want := reasonsOdd()
	cases := []struct {
		name    string
		run     commandFunc
		code    ExitCode
		outcome string
		stdout  string // in the text mode
		stderr  string // in the text mode
	}{
		{"a refusal with a message", func(context.Context, *Call) (*Result, error) { return nil, Refusal{Reasons: in, Msg: "no"} }, ExitRefused, "refused", "", "ritueel: no\n"},
		{"a refusal with no message: the reasons stand in", func(context.Context, *Call) (*Result, error) { return nil, Refusal{Reasons: in} }, ExitRefused, "refused", "", "ritueel: refused: " + strings.Join(want, ", ") + "\n"},
		{"a refusal by the backend", func(context.Context, *Call) (*Result, error) { return nil, BackendRefusal{Reasons: in, Msg: "no"} }, ExitBackend, "refused", "", "ritueel: no\n"},
		{"a result with the code 3", func(context.Context, *Call) (*Result, error) {
			return &Result{ExitCode: ExitRefused, Reasons: in, Text: "no\n"}, nil
		}, ExitRefused, "refused", "no\n", ""},
		{"a result with the code 4", func(context.Context, *Call) (*Result, error) {
			return &Result{ExitCode: ExitBackend, Reasons: in, Text: "no\n"}, nil
		}, ExitBackend, "refused", "no\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, spec2 := range []spec{
				{name: "fake", usage: "u", run: tc.run},
				// A second word is the same.
				{name: "fake", usage: "u", subs: []spec{{name: "two", usage: "u", run: tc.run}}},
			} {
				withSpecs(t, spec2)
				args := []string{"fake"}
				if len(spec2.subs) > 0 {
					args = []string{"fake", "two"}
				}
				text := run(t, args...)
				if text.code != tc.code || text.stdout != tc.stdout || text.stderr != tc.stderr {
					t.Errorf("text: (%d, %q, %q)\nwant (%d, %q, %q)", int(text.code), text.stdout, text.stderr, int(tc.code), tc.stdout, tc.stderr)
				}
				if !onlyPrintable(text.stdout) || !onlyPrintable(text.stderr) {
					t.Errorf("text mode: a byte that is not printable ASCII or a line break: %q %q", text.stdout, text.stderr)
				}
				js := run(t, append([]string{"--output", "json"}, args...)...)
				if js.code != tc.code {
					t.Errorf("json: exit code %d", int(js.code))
				}
				// A refusal has "reasons" and "warnings" and no "error": its message is for standard
				// error alone.
				wantObj := fmt.Sprintf(`{"output":1,"command":"fake","exit_code":%d,"outcome":%q,"reasons":%s,"warnings":[]}`+"\n", int(tc.code), tc.outcome, jsonList(want))
				if js.stdout != wantObj {
					t.Errorf("json stdout =\n  %q\nwant\n  %q", js.stdout, wantObj)
				}
				if !onlyPrintable(js.stdout) || strings.Count(js.stdout, "\n") != 1 {
					t.Errorf("json stdout holds a byte that is not printable ASCII, or more than one line break: %q", js.stdout)
				}
				if js.stderr != tc.stderr {
					t.Errorf("json stderr = %q, want the line of the text mode, %q", js.stderr, tc.stderr)
				}
				// The command's own list is not changed behind its back: a command that keeps it and
				// runs again gets the same output.
				again := run(t, append([]string{"--output", "json"}, args...)...)
				if again.stdout != js.stdout {
					t.Errorf("a second run differs: %q", again.stdout)
				}
			}
		})
	}
}

func TestAPlainReasonCodeIsUnchangedAndAMissingListLeavesTheMemberOut(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reasons []string
		member  string // what follows "outcome"
	}{
		{"one plain code", []string{"plan-stale"}, `"reasons":["plan-stale"]`},
		{"several plain codes", []string{"plan-stale", "key-mismatch", "version-unsupported"}, `"reasons":["plan-stale","key-mismatch","version-unsupported"]`},
		{"a code with a backslash is unchanged by the escape", []string{`a\b`}, `"reasons":["a\\b"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				return &Result{ExitCode: ExitRefused, Reasons: tc.reasons}, nil
			}})
			js := run(t, "--output", "json", "fake")
			want := `{"output":1,"command":"fake","exit_code":3,"outcome":"refused",` + tc.member + `,"warnings":[]}` + "\n"
			if js.code != ExitRefused || js.stdout != want || js.stderr != "" {
				t.Errorf("result: (%d, %q, %q)\nwant %q", int(js.code), js.stdout, js.stderr, want)
			}
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				return nil, Refusal{Reasons: tc.reasons, Msg: "m"}
			}})
			js = run(t, "--output", "json", "fake")
			want = `{"output":1,"command":"fake","exit_code":3,"outcome":"refused",` + tc.member + `,"warnings":[]}` + "\n"
			if js.code != ExitRefused || js.stdout != want || js.stderr != "ritueel: m\n" {
				t.Errorf("refusal: (%d, %q, %q)\nwant %q", int(js.code), js.stdout, js.stderr, want)
			}
		})
	}
	// A command that did not refuse has no list of reasons, nil or empty: the member is left out. (A
	// refusal with no code, and a code with another outcome, are faults of the programmer: see
	// TestARefusalWithNoReasonCodeIsAProgrammerError and TestReasonCodesWithAnotherOutcome...)
	for _, reasons := range [][]string{nil, {}} {
		t.Run(fmt.Sprintf("a result that ended well, with the list %#v, has no reasons member", reasons), func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				return &Result{Reasons: reasons}, nil
			}})
			js := run(t, "--output", "json", "fake")
			want := `{"output":1,"command":"fake","exit_code":0,"outcome":"done","warnings":[]}` + "\n"
			if js.code != ExitOK || js.stdout != want || js.stderr != "" {
				t.Errorf("(%d, %q, %q)\nwant %q", int(js.code), js.stdout, js.stderr, want)
			}
		})
	}
	t.Run("a plain code on the line of a refusal with no message", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, Refusal{Reasons: []string{"plan-stale", "key-mismatch"}}
		}})
		if r := run(t, "fake"); r.code != ExitRefused || r.stderr != "ritueel: refused: plan-stale, key-mismatch\n" {
			t.Errorf("(%d, %q)", int(r.code), r.stderr)
		}
	})
}

// An error that carries the exit code 0 reports success, which an error must not: ExitFor panics, and
// a run turns it into the exit code 1 and the text, whatever the outcome that the error names.
func TestAnErrorWithTheExitCodeZeroIsAProgrammerError(t *testing.T) {
	msg := "cli: the error cli.oddCoded carries the exit code 0, which reports success; an error ends a command with a code of 1 or more"
	for _, o := range []Outcome{"", OutcomeDone, OutcomeFailed, OutcomeRefused} {
		t.Run("the outcome "+string(o), func(t *testing.T) {
			bad := func(context.Context, *Call) (*Result, error) { return nil, oddCoded{code: ExitOK, outcome: o} }
			withSpecs(t, spec{name: "fake", usage: "u", run: bad})
			ranFailed(t, "fake", msg, "fake")
			withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{{name: "crl", usage: "u", run: bad}}})
			ranFailed(t, "verify", msg, "verify", "crl")
		})
	}
	t.Run("a wrapped error that carries it", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, fmt.Errorf("while checking: %w", oddCoded{code: ExitOK, outcome: OutcomeDone})
		}})
		ranFailed(t, "fake", msg, "fake")
	})
	t.Run("another type is named by its own name", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, zeroCoded{} }})
		ranFailed(t, "fake", "cli: the error cli.zeroCoded carries the exit code 0, which reports success; an error ends a command with a code of 1 or more", "fake")
	})
	t.Run("ExitFor itself", func(t *testing.T) {
		if got := recoverText(t, func() { ExitFor(oddCoded{code: ExitOK}) }); got != msg {
			t.Errorf("%q, want %q", got, msg)
		}
		if got := recoverText(t, func() { ExitFor(fmt.Errorf("x: %w", oddCoded{code: ExitOK})) }); got != msg {
			t.Errorf("wrapped: %q", got)
		}
	})
	t.Run("the errors of the package and the other codes do not panic", func(t *testing.T) {
		for _, err := range []error{UsageError{Msg: "u"}, Refusal{}, BackendRefusal{}, NotConfirmed{}, oddCoded{code: ExitFailure, outcome: OutcomeFailed}, fmt.Errorf("plain")} {
			if got := recoverText(t, func() { ExitFor(err) }); got != "" {
				t.Errorf("%T: panic %q", err, got)
			}
		}
	})
}

type zeroCoded struct{}

func (zeroCoded) Error() string         { return "zero" }
func (zeroCoded) ExitCode() ExitCode    { return ExitOK }
func (zeroCoded) Outcome() Outcome      { return OutcomeDone }
func (zeroCoded) ReasonCodes() []string { return nil }
