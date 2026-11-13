package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// The warnings of a command (docs/reference/cli.md, "Machine-readable output"): the member
// "warnings" is a list of strings, one for each warning, empty when there is none; a warning does not
// change the exit code; each warning is a line on standard error in both output modes. A command that
// ended well gives them in Result.Warnings, and one that ended with an error with WithWarnings. No
// escape is written out here: u builds one.

// oddWarnings are warnings that hold what a terminal must not get raw: an escape, a line break, a
// byte that is not UTF-8, a letter that looks like a Latin one, an emoji, and a quote and a backslash
// that stay what they are. wantOdd is what the program writes for each.
func oddWarnings() (in, want []string) {
	in = []string{
		"held-expired",
		"esc\x1b[31m",
		"line\nbreak",
		"bad\xffbyte",
		"v" + string(rune(0x0435)) + "rsion",
		"emoji" + string(rune(0x1F600)),
		`quote"and\backslash`,
		"nul\x00",
		"del\x7f",
	}
	want = []string{
		"held-expired",
		"esc" + u(0x1b) + "[31m",
		"line" + u(10) + "break",
		"bad" + u(0xFFFD) + "byte",
		"v" + u(0x0435) + "rsion",
		"emoji" + u(0xD83D) + u(0xDE00),
		`quote"and\backslash`,
		"nul" + u(0),
		"del" + u(0x7f),
	}
	return in, want
}

func TestWarningsOfAResultAreOnStandardErrorAndInTheObject(t *testing.T) {
	in, wantEsc := oddWarnings()
	cases := []outcomeCase{
		{"one warning", func() (*Result, error) { return &Result{Warnings: []string{"held-expired"}, Text: "ok\n"}, nil }, ExitOK, "ok\n", warnLines("held-expired"),
			members(ExitOK, "done", map[string]any{"warnings": []string{"held-expired"}})},
		{"the order is the order given", func() (*Result, error) { return &Result{Warnings: []string{"b", "a", "c"}}, nil }, ExitOK, "", warnLines("b", "a", "c"),
			members(ExitOK, "done", map[string]any{"warnings": []string{"b", "a", "c"}})},
		{"a repeated warning is repeated", func() (*Result, error) { return &Result{Warnings: []string{"a", "b", "a", "a"}}, nil }, ExitOK, "", warnLines("a", "b", "a", "a"),
			members(ExitOK, "done", map[string]any{"warnings": []string{"a", "b", "a", "a"}})},
		{"every odd warning is printable ASCII, on standard error and in the object", func() (*Result, error) {
			return &Result{Warnings: slices.Clone(in)}, nil
		}, ExitOK, "", warnLines(wantEsc...),
			members(ExitOK, "done", map[string]any{"warnings": wantEsc})},
		{"warnings with a refusal by a result", func() (*Result, error) {
			return &Result{ExitCode: ExitRefused, Reasons: []string{"declined"}, Warnings: []string{"w1", "w2"}}, nil
		}, ExitRefused, "", warnLines("w1", "w2"),
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"declined"}, "warnings": []string{"w1", "w2"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
	}
}

// The warnings of a command that ended with an error: one table for every kind of error.
func TestWarningsWithEveryKindOfError(t *testing.T) {
	in, wantEsc := oddWarnings()
	plain := errors.New("disk on fire")
	refusal := func() error { return Refusal{Reasons: []string{"policy"}, Msg: "no"} }
	cases := []outcomeCase{
		{"a refusal", func() (*Result, error) { return nil, WithWarnings(refusal(), "w1", "w2") }, ExitRefused, "", warnLines("w1", "w2") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"w1", "w2"}})},
		{"a refusal by pointer", func() (*Result, error) {
			return nil, WithWarnings(&Refusal{Reasons: []string{"policy"}, Msg: "no"}, "w1")
		}, ExitRefused, "", warnLines("w1") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"w1"}})},
		{"a refusal with no message: the reasons stand in", func() (*Result, error) {
			return nil, WithWarnings(Refusal{Reasons: []string{"declined"}}, "w1")
		}, ExitRefused, "", warnLines("w1") + "ritueel: refused: declined\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"declined"}, "warnings": []string{"w1"}})},
		{"a backend refusal", func() (*Result, error) {
			return nil, WithWarnings(BackendRefusal{Reasons: []string{"pin-locked"}, Msg: "locked"}, "w1", "w2")
		}, ExitBackend, "", warnLines("w1", "w2") + "ritueel: locked\n",
			members(ExitBackend, "refused", map[string]any{"reasons": []string{"pin-locked"}, "warnings": []string{"w1", "w2"}})},
		{"not confirmed", func() (*Result, error) { return nil, WithWarnings(NotConfirmed{}, "w1") }, ExitNotConfirmed, "", warnLines("w1") + "ritueel: not confirmed\n",
			members(ExitNotConfirmed, "not-confirmed", map[string]any{"warnings": []string{"w1"}})},
		{"a usage error: before the error line, and before the help line", func() (*Result, error) {
			return nil, WithWarnings(UsageError{Msg: "wrong form"}, "w1", "w2")
		}, ExitUsage, "", warnLines("w1", "w2") + "ritueel: wrong form\n" + helpLine,
			members(ExitUsage, "usage", map[string]any{"error": "wrong form", "warnings": []string{"w1", "w2"}})},
		{"a plain error", func() (*Result, error) { return nil, WithWarnings(plain, "w1") }, ExitFailure, "", warnLines("w1") + "ritueel: disk on fire\n",
			members(ExitFailure, "failed", map[string]any{"error": "disk on fire", "warnings": []string{"w1"}})},
		{"the odd warnings with a refusal", func() (*Result, error) {
			return nil, WithWarnings(refusal(), in...)
		}, ExitRefused, "", warnLines(wantEsc...) + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": wantEsc})},
		{"the odd warnings with a plain error", func() (*Result, error) {
			return nil, WithWarnings(plain, in...)
		}, ExitFailure, "", warnLines(wantEsc...) + "ritueel: disk on fire\n",
			members(ExitFailure, "failed", map[string]any{"error": "disk on fire", "warnings": wantEsc})},
		{"a repeated warning is repeated", func() (*Result, error) { return nil, WithWarnings(plain, "a", "b", "a") }, ExitFailure, "", warnLines("a", "b", "a") + "ritueel: disk on fire\n",
			members(ExitFailure, "failed", map[string]any{"error": "disk on fire", "warnings": []string{"a", "b", "a"}})},
		{"no warning: the error is as it was", func() (*Result, error) { return nil, WithWarnings(refusal()) }, ExitRefused, "", "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}})},
		{"the message with an odd character is escaped after the warnings", func() (*Result, error) {
			return nil, WithWarnings(errors.New("bad\x1b"), "w\x1b")
		}, ExitFailure, "", warnLines("w"+u(0x1b)) + "ritueel: bad" + u(0x1b) + "\n",
			members(ExitFailure, "failed", map[string]any{"error": "bad" + u(0x1b), "warnings": []string{"w" + u(0x1b)}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
	}
}

func TestWarningsKeepTheirOrderThroughWrappingAndCopies(t *testing.T) {
	refusal := Refusal{Reasons: []string{"policy"}, Msg: "no"}
	cases := []outcomeCase{
		{"wrapped twice: a, then b", func() (*Result, error) { return nil, WithWarnings(WithWarnings(refusal, "a"), "b") }, ExitRefused, "", warnLines("a", "b") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a", "b"}})},
		{"wrapped twice, with several each", func() (*Result, error) { return nil, WithWarnings(WithWarnings(refusal, "a", "b"), "c", "d") }, ExitRefused, "", warnLines("a", "b", "c", "d") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a", "b", "c", "d"}})},
		{"wrapped three times", func() (*Result, error) {
			return nil, WithWarnings(WithWarnings(WithWarnings(refusal, "a"), "b"), "c")
		}, ExitRefused, "", warnLines("a", "b", "c") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a", "b", "c"}})},
		{"wrapped by fmt.Errorf in between: none is lost", func() (*Result, error) {
			return nil, WithWarnings(fmt.Errorf("apply: %w", WithWarnings(refusal, "a")), "b")
		}, ExitRefused, "", warnLines("a", "b") + "ritueel: apply: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a", "b"}})},
		{"wrapped by fmt.Errorf after", func() (*Result, error) {
			return nil, fmt.Errorf("apply: %w", WithWarnings(refusal, "a"))
		}, ExitRefused, "", warnLines("a") + "ritueel: apply: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a"}})},
		{"wrapped by fmt.Errorf twice after", func() (*Result, error) {
			return nil, fmt.Errorf("b: %w", fmt.Errorf("a: %w", WithWarnings(errors.New("c"), "w")))
		}, ExitFailure, "", warnLines("w") + "ritueel: b: a: c\n",
			members(ExitFailure, "failed", map[string]any{"error": "b: a: c", "warnings": []string{"w"}})},
		{"wrapping with none after wrapping with some keeps the first", func() (*Result, error) {
			return nil, WithWarnings(WithWarnings(refusal, "a"))
		}, ExitRefused, "", warnLines("a") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a"}})},
		{"the warnings given in the call are copied", func() (*Result, error) {
			given := []string{"a", "b"}
			err := WithWarnings(refusal, given...)
			given[0], given[1] = "changed", "changed"
			return nil, err
		}, ExitRefused, "", warnLines("a", "b") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a", "b"}})},
		{"the wrapped error's own warnings are not changed by a second wrap", func() (*Result, error) {
			first := WithWarnings(refusal, "a")
			_ = WithWarnings(first, "other")
			return nil, WithWarnings(first, "b")
		}, ExitRefused, "", warnLines("a", "b") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}, "warnings": []string{"a", "b"}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
	}
}

// WithWarnings changes nothing but the warnings: the message, the exit code, the outcome, the
// reasons, and what errors.Is and errors.As find.
func TestWithWarningsChangesOnlyTheWarnings(t *testing.T) {
	sentinel := errors.New("sentinel")
	plain := fmt.Errorf("wrapped: %w", sentinel)
	for _, tc := range []struct {
		name string
		err  error
		code ExitCode
		out  Outcome
		rsn  []string
	}{
		{"a refusal", Refusal{Reasons: []string{"a", "b"}, Msg: "m"}, ExitRefused, OutcomeRefused, []string{"a", "b"}},
		{"a backend refusal", BackendRefusal{Reasons: []string{"a"}}, ExitBackend, OutcomeRefused, []string{"a"}},
		{"not confirmed", NotConfirmed{}, ExitNotConfirmed, OutcomeNotConfirmed, nil},
		{"a usage error", UsageError{Msg: "u"}, ExitUsage, OutcomeUsage, nil},
		{"a plain error", plain, ExitFailure, OutcomeFailed, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := WithWarnings(tc.err, "w1", "w2")
			if w.Error() != tc.err.Error() {
				t.Errorf("Error() = %q, want %q", w.Error(), tc.err.Error())
			}
			code, outcome := ExitFor(w)
			if code != tc.code || outcome != tc.out {
				t.Errorf("ExitFor = (%d, %q), want (%d, %q)", int(code), outcome, int(tc.code), tc.out)
			}
			if got := reasonsOf(w); !slices.Equal(got, tc.rsn) {
				t.Errorf("reasons = %q, want %q", got, tc.rsn)
			}
			if got := errors.Unwrap(w); got == nil || got.Error() != tc.err.Error() {
				t.Errorf("Unwrap = %v, want the wrapped error %v", got, tc.err)
			}
			if got := warningsOf(w); !slices.Equal(got, []string{"w1", "w2"}) {
				t.Errorf("warnings = %q", got)
			}
			// What the wrapped chain is, errors.As still finds it.
			var c Coded
			if tc.code != ExitFailure {
				if !errors.As(w, &c) || c.ExitCode() != tc.code {
					t.Errorf("errors.As(Coded) = %v, %v", errors.As(w, &c), c)
				}
			}
		})
	}
	t.Run("errors.Is sees a sentinel through the wrapper", func(t *testing.T) {
		if !errors.Is(WithWarnings(plain, "w"), sentinel) {
			t.Error("errors.Is(sentinel) = false")
		}
	})
	t.Run("errors.As finds a concrete type through the wrapper", func(t *testing.T) {
		var ref Refusal
		if !errors.As(WithWarnings(fmt.Errorf("x: %w", Refusal{Reasons: []string{"a"}, Msg: "m"}), "w"), &ref) || ref.Msg != "m" {
			t.Errorf("errors.As(Refusal) = %+v", ref)
		}
	})
	t.Run("with no warnings it returns the error itself", func(t *testing.T) {
		if got := WithWarnings(plain); got != plain { //nolint:errorlint // the identity is what is tested
			t.Errorf("WithWarnings(err) = %v, want the same error", got)
		}
		if got := WithWarnings(plain, []string{}...); got != plain { //nolint:errorlint // the identity is what is tested
			t.Errorf("WithWarnings(err, empty...) = %v, want the same error", got)
		}
		if got := warningsOf(plain); len(got) != 0 {
			t.Errorf("warningsOf(plain) = %q", got)
		}
	})
	t.Run("a nil error is a fault of the programmer", func(t *testing.T) {
		want := "cli: WithWarnings was given no error; a command that ended well gives its warnings in Result.Warnings"
		if got := recoverText(t, func() { WithWarnings(nil, "w") }); got != want {
			t.Errorf("panic = %q, want %q", got, want)
		}
		if got := recoverText(t, func() { WithWarnings(nil) }); got != want {
			t.Errorf("panic with no warnings = %q, want %q", got, want)
		}
	})
	t.Run("a nil error in a command ends the run with the exit code 1", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, WithWarnings(nil, "w") }})
		ranFailed(t, "fake", "cli: WithWarnings was given no error; a command that ended well gives its warnings in Result.Warnings", "fake")
	})
}

// The command's own list is not changed by the run, and the run does not keep it: a command that
// gives the same list twice gets the same output twice.
func TestTheWarningsOfTheCommandAreNotChangedBehindItsBack(t *testing.T) {
	in, wantEsc := oddWarnings()
	mine := slices.Clone(in)
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return &Result{Warnings: mine}, nil
	}})
	first := run(t, "--output", "json", "fake")
	second := run(t, "--output", "json", "fake")
	if first.stdout != second.stdout || first.stderr != second.stderr {
		t.Errorf("two runs differ:\n%q %q\n%q %q", first.stdout, first.stderr, second.stdout, second.stderr)
	}
	if !slices.Equal(mine, in) {
		t.Errorf("the list of the command was changed: %q, want %q", mine, in)
	}
	if want := strings.Repeat(warnLines(wantEsc...), 1); first.stderr != want {
		t.Errorf("stderr = %q, want %q", first.stderr, want)
	}
	// The text mode, after the JSON mode, on the same list.
	text := run(t, "fake")
	if text.stderr != first.stderr {
		t.Errorf("text stderr = %q, want %q", text.stderr, first.stderr)
	}
	// A nil list and an empty one: the same [], and the command's empty list is not made into null.
	for _, ws := range [][]string{nil, {}} {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return &Result{Warnings: ws}, nil }})
		r := run(t, "--output", "json", "fake")
		if want := `{"output":1,"command":"fake","exit_code":0,"outcome":"done","warnings":[]}` + "\n"; r.stdout != want {
			t.Errorf("warnings %#v: stdout = %q, want %q", ws, r.stdout, want)
		}
	}
}

// Many warnings keep their order, in the object and on standard error, in both output modes.
func TestManyWarningsKeepTheirOrder(t *testing.T) {
	const n = 1000
	many := make([]string, n)
	for i := range many {
		many[i] = fmt.Sprintf("w-%04d", (i*7919)%n) // an order that is not sorted
	}
	many[10] = many[3] // a repeat in the middle
	cases := []outcomeCase{
		{"a result", func() (*Result, error) { return &Result{Warnings: slices.Clone(many)}, nil }, ExitOK, "", warnLines(many...),
			members(ExitOK, "done", map[string]any{"warnings": many})},
		{"a refusal", func() (*Result, error) { return nil, WithWarnings(Refusal{Reasons: []string{"p"}, Msg: "no"}, many...) }, ExitRefused, "", warnLines(many...) + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"p"}, "warnings": many})},
		{"a plain error, raised in two steps", func() (*Result, error) {
			return nil, WithWarnings(WithWarnings(errors.New("e"), many[:400]...), many[400:]...)
		}, ExitFailure, "", warnLines(many...) + "ritueel: e\n",
			members(ExitFailure, "failed", map[string]any{"error": "e", "warnings": many})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
	}
}

// A usage error that the library raises, before a command runs, has no warnings: [] and no line.
func TestAUsageErrorOfTheLibraryHasNoWarnings(t *testing.T) {
	r := run(t, "--output", "json", "nosuch")
	wantObject(t, object(t, r.stdout), map[string]any{"output": 1, "command": "", "exit_code": 2, "outcome": "usage", "error": "<any>", "warnings": []string{}})
	if strings.Contains(r.stderr, "warning") {
		t.Errorf("stderr = %q", r.stderr)
	}
}

// The warnings of a command that returns both a result and an error are those of the error: the
// error is the answer, and the Result is not shown.
func TestAResultAndAnErrorBothGiven(t *testing.T) {
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return &Result{Warnings: []string{"from-result"}, Text: "ignored\n"}, WithWarnings(errors.New("boom"), "from-error")
	}})
	r := run(t, "--output", "json", "fake")
	if r.code != ExitFailure || r.stderr != warnLines("from-error")+"ritueel: boom\n" {
		t.Errorf("(%d, %q)", int(r.code), r.stderr)
	}
	wantObject(t, object(t, r.stdout), members(ExitFailure, "failed", map[string]any{"error": "boom", "warnings": []string{"from-error"}}))
	text := run(t, "fake")
	if text.code != ExitFailure || text.stdout != "" || text.stderr != r.stderr {
		t.Errorf("text: (%d, %q, %q)", int(text.code), text.stdout, text.stderr)
	}
}

// The result does not reach the caller: the warnings are on standard error, then the line that says
// so, and the exit code is 1, whatever the exit code of the command.
func TestAFailedWriteOfTheResultKeepsTheWarnings(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		res  *Result
	}{
		{"the JSON mode", []string{"--output", "json", "fake"}, &Result{Warnings: []string{"w1", "w2"}}},
		{"the text mode", []string{"fake"}, &Result{Warnings: []string{"w1", "w2"}, Text: "t\n"}},
		{"the JSON mode, a refusal", []string{"--output", "json", "fake"}, &Result{ExitCode: ExitRefused, Reasons: []string{"r"}, Warnings: []string{"w1", "w2"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				res := *tc.res
				return &res, nil
			}})
			var stderr strings.Builder
			code := Run(t.Context(), tc.args, Env{Stdout: brokenWriter{errors.New("disk full")}, Stderr: &stderr, Build: testBuild})
			if want := warnLines("w1", "w2") + "ritueel: write the result: disk full\n"; code != ExitFailure || stderr.String() != want {
				t.Errorf("(%d, %q), want (1, %q)", int(code), stderr.String(), want)
			}
		})
	}
	t.Run("the error object does not reach the caller either: the exit code of the command stays", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, WithWarnings(Refusal{Reasons: []string{"r"}, Msg: "no"}, "w1")
		}})
		var stderr strings.Builder
		code := Run(t.Context(), []string{"--output", "json", "fake"}, Env{Stdout: brokenWriter{errors.New("disk full")}, Stderr: &stderr, Build: testBuild})
		if want := warnLines("w1") + "ritueel: no\n"; code != ExitRefused || stderr.String() != want {
			t.Errorf("(%d, %q), want (3, %q)", int(code), stderr.String(), want)
		}
	})
}

// A warning goes to standard error only, never to standard output in the text mode, and a run with
// warnings leaves nothing behind for the next one.
func TestWarningsLeaveNoStateBehind(t *testing.T) {
	calls := 0
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		calls++
		if calls == 1 {
			return &Result{Warnings: []string{"only-the-first"}}, nil
		}
		return &Result{}, nil
	}})
	first := run(t, "--output", "json", "fake")
	second := run(t, "--output", "json", "fake")
	if !strings.Contains(first.stdout, `"warnings":["only-the-first"]`) || first.stderr != warnLines("only-the-first") {
		t.Errorf("first: %q %q", first.stdout, first.stderr)
	}
	if !strings.Contains(second.stdout, `"warnings":[]`) || second.stderr != "" {
		t.Errorf("second: %q %q", second.stdout, second.stderr)
	}
	// An error with warnings, then a run that ended well.
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		calls++
		if calls%2 == 1 {
			return nil, WithWarnings(errors.New("e"), "w")
		}
		return &Result{}, nil
	}})
	calls = 0
	_ = run(t, "fake")
	after := run(t, "--output", "json", "fake")
	if after.code != ExitOK || after.stderr != "" || !strings.Contains(after.stdout, `"warnings":[]`) {
		t.Errorf("after: (%d, %q, %q)", int(after.code), after.stdout, after.stderr)
	}
}

// ---- nothing reaches the real streams ------------------------------------------------------------

const nilEnvWarnVar = "RITUEEL_CLI_TEST_NIL_ENV_WARN_ARGS"

// nilEnvWarnSpecs are the commands the child process runs for TestNilEnvWithWarningsWritesNothing.
func nilEnvWarnSpecs() []spec {
	return []spec{
		{name: "warn", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return &Result{Warnings: []string{"w1", "w2"}, Text: "t\n"}, nil
		}},
		{name: "warnfail", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, WithWarnings(Refusal{Reasons: []string{"r"}, Msg: "no"}, "w1")
		}},
		{name: "warnuse", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, WithWarnings(UsageError{Msg: "wrong"}, "w1")
		}},
	}
}

func init() {
	// The child process of TestNilEnvWithWarningsWritesNothing replaces the table before TestMain
	// reads its argument list; the parent never sets the variable.
	if os.Getenv(nilEnvWarnVar) != "" {
		specs = nilEnvWarnSpecs()
		raw := os.Getenv(nilEnvWarnVar)
		_ = os.Unsetenv(nilEnvWarnVar)
		_ = os.Setenv(nilEnvVar, raw)
	}
}

// With every stream nil, a run that has warnings still writes nothing to the real standard streams
// and returns the right code. It runs in a separate process (the test binary itself, see TestMain).
func TestNilEnvWithWarningsWritesNothing(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot find the test binary: %v", err)
	}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"warn"}, 0},
		{[]string{"--output", "json", "warn"}, 0},
		{[]string{"warnfail"}, 3},
		{[]string{"--output", "json", "warnfail"}, 3},
		{[]string{"warnuse"}, 2},
		{[]string{"--output", "json", "warnuse"}, 2},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			raw, err := json.Marshal(tc.args)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(t.Context(), exe)
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), nilEnvWarnVar+"="+string(raw))
			var stdout, stderr bytes.Buffer
			cmd.Stdin = strings.NewReader("")
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			code := 0
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if !errors.As(err, &ee) {
					t.Fatalf("running the test binary: %v", err)
				}
				code = ee.ExitCode()
			}
			if code != tc.code {
				t.Errorf("exit code = %d, want %d", code, tc.code)
			}
			if stdout.Len() != 0 {
				t.Errorf("wrote to the real standard output: %q", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("wrote to the real standard error: %q", stderr.String())
			}
		})
	}
}
