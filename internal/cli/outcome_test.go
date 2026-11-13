package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// The JSON object of a command follows docs/reference/cli.md, "Machine-readable output":
//
//   - every object has output, command, exit_code, outcome and warnings (a list, [] when there is
//     none), and each warning is also a line on standard error in both output modes;
//   - reasons is there when the command was refused, and in no other object;
//   - error is there when the command failed or was misused, and in no other object.
//
// The tests below run the command line in process, with fake commands, in the text mode and in the
// JSON mode, and compare the exact set of members, the exact lines of standard error and the exit
// code.

// outcomeCase is one run of the fake command "fake", in both output modes.
type outcomeCase struct {
	name string
	// make is called once for each run, so that a run never sees the Result of the run before it.
	make   func() (*Result, error)
	code   ExitCode
	stdout string         // standard output in the text mode
	stderr string         // standard error, the same in both output modes
	object map[string]any // the JSON object, every member; "warnings" is [] when it is not given
}

// members is the object of the command "fake" with the given outcome and the members given.
func members(code ExitCode, outcome string, more map[string]any) map[string]any {
	m := map[string]any{"output": 1, "command": "fake", "exit_code": int(code), "outcome": outcome}
	for k, v := range more {
		m[k] = v
	}
	return m
}

// warnLines is the standard error that the warnings make: one line each, in the order given.
func warnLines(warnings ...string) string {
	var b strings.Builder
	for _, w := range warnings {
		b.WriteString("ritueel: warning: " + w + "\n")
	}
	return b.String()
}

// checkOutcome runs the case in both output modes and compares the exit code, standard output,
// standard error and the exact members of the object. Whatever reaches the terminal is printable
// ASCII.
func checkOutcome(t *testing.T, tc outcomeCase) {
	t.Helper()
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.make() }})

	text := run(t, "fake")
	if text.code != tc.code || text.stdout != tc.stdout || text.stderr != tc.stderr {
		t.Errorf("text: (%d, %q, %q)\nwant (%d, %q, %q)", int(text.code), text.stdout, text.stderr, int(tc.code), tc.stdout, tc.stderr)
	}
	if !onlyPrintable(text.stdout) || !onlyPrintable(text.stderr) {
		t.Errorf("text mode: a byte that is not printable ASCII or a line break: %q %q", text.stdout, text.stderr)
	}

	js := run(t, "--output", "json", "fake")
	if js.code != tc.code || js.stderr != tc.stderr {
		t.Errorf("json: (%d, %q)\nwant (%d, %q)", int(js.code), js.stderr, int(tc.code), tc.stderr)
	}
	if !onlyPrintable(js.stdout) || !onlyPrintable(js.stderr) {
		t.Errorf("json mode: a byte that is not printable ASCII or a line break: %q %q", js.stdout, js.stderr)
	}
	wantObject(t, object(t, js.stdout), tc.object)
}

func TestTheObjectOfEveryOutcome(t *testing.T) {
	plain := errors.New("disk on fire")
	cases := []outcomeCase{
		// done: no reasons, no error.
		{"done", func() (*Result, error) { return &Result{Text: "ok\n"}, nil }, ExitOK, "ok\n", "",
			members(ExitOK, "done", nil)},
		{"done, an empty list of warnings is []", func() (*Result, error) { return &Result{Warnings: []string{}}, nil }, ExitOK, "", "",
			members(ExitOK, "done", nil)},
		{"done with warnings: the exit code stays 0", func() (*Result, error) { return &Result{Warnings: []string{"held-expired"}}, nil }, ExitOK, "", warnLines("held-expired"),
			members(ExitOK, "done", map[string]any{"warnings": []string{"held-expired"}})},

		// failed: error, no reasons.
		{"failed", func() (*Result, error) { return nil, plain }, ExitFailure, "", "ritueel: disk on fire\n",
			members(ExitFailure, "failed", map[string]any{"error": "disk on fire"})},
		{"failed with warnings", func() (*Result, error) { return nil, WithWarnings(plain, "w1", "w2") }, ExitFailure, "", warnLines("w1", "w2") + "ritueel: disk on fire\n",
			members(ExitFailure, "failed", map[string]any{"error": "disk on fire", "warnings": []string{"w1", "w2"}})},

		// usage: error, no reasons, and the help line after the error.
		{"usage", func() (*Result, error) { return nil, UsageError{Msg: "wrong form"} }, ExitUsage, "", "ritueel: wrong form\n" + helpLine,
			members(ExitUsage, "usage", map[string]any{"error": "wrong form"})},
		{"usage with warnings: before the error line and before the help line", func() (*Result, error) {
			return nil, WithWarnings(UsageError{Msg: "wrong form"}, "w1")
		}, ExitUsage, "", warnLines("w1") + "ritueel: wrong form\n" + helpLine,
			members(ExitUsage, "usage", map[string]any{"error": "wrong form", "warnings": []string{"w1"}})},

		// refused by a check: reasons, no error.
		{"refused by a check", func() (*Result, error) { return nil, Refusal{Reasons: []string{"policy"}, Msg: "no"} }, ExitRefused, "", "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy"}})},
		{"refused by a check, with warnings", func() (*Result, error) {
			return nil, WithWarnings(Refusal{Reasons: []string{"policy", "plan-stale"}, Msg: "no"}, "w1")
		}, ExitRefused, "", warnLines("w1") + "ritueel: no\n",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"policy", "plan-stale"}, "warnings": []string{"w1"}})},

		// refused by the backend: reasons, no error.
		{"refused by the backend", func() (*Result, error) {
			return nil, BackendRefusal{Reasons: []string{"pin-locked"}, Msg: "the card said no"}
		}, ExitBackend, "", "ritueel: the card said no\n",
			members(ExitBackend, "refused", map[string]any{"reasons": []string{"pin-locked"}})},
		{"refused by the backend, with warnings", func() (*Result, error) {
			return nil, WithWarnings(BackendRefusal{Reasons: []string{"pin-locked"}, Msg: "locked"}, "w1")
		}, ExitBackend, "", warnLines("w1") + "ritueel: locked\n",
			members(ExitBackend, "refused", map[string]any{"reasons": []string{"pin-locked"}, "warnings": []string{"w1"}})},

		// refused by a Result with the exit code 3 or 4: reasons, no error, nothing on standard error.
		{"refused, a result with the code 3", func() (*Result, error) {
			return &Result{ExitCode: ExitRefused, Reasons: []string{"declined"}, Text: "data\n"}, nil
		}, ExitRefused, "data\n", "",
			members(ExitRefused, "refused", map[string]any{"reasons": []string{"declined"}})},
		{"refused, a result with the code 4 and warnings", func() (*Result, error) {
			return &Result{ExitCode: ExitBackend, Reasons: []string{"kms-session"}, Warnings: []string{"w1"}}, nil
		}, ExitBackend, "", warnLines("w1"),
			members(ExitBackend, "refused", map[string]any{"reasons": []string{"kms-session"}, "warnings": []string{"w1"}})},

		// not confirmed: no reasons, no error.
		{"not confirmed", func() (*Result, error) { return nil, NotConfirmed{} }, ExitNotConfirmed, "", "ritueel: not confirmed\n",
			members(ExitNotConfirmed, "not-confirmed", nil)},
		{"not confirmed, with warnings", func() (*Result, error) { return nil, WithWarnings(NotConfirmed{}, "w1") }, ExitNotConfirmed, "", warnLines("w1") + "ritueel: not confirmed\n",
			members(ExitNotConfirmed, "not-confirmed", map[string]any{"warnings": []string{"w1"}})},
		{"not confirmed, a result with the code 5", func() (*Result, error) { return &Result{ExitCode: ExitNotConfirmed}, nil }, ExitNotConfirmed, "", "",
			members(ExitNotConfirmed, "not-confirmed", nil)},

		// a panic: failed, error, no reasons, and no warnings (a command that panics has none to give).
		{"a panic", func() (*Result, error) { panic("boom") }, ExitFailure, "", "ritueel: internal error: boom\n",
			members(ExitFailure, "failed", map[string]any{"error": "internal error: boom"})},
		{"a panic with a refusal as the value is still a failure, with no reasons", func() (*Result, error) {
			panic(Refusal{Reasons: []string{"policy"}, Msg: "x"})
		}, ExitFailure, "", "ritueel: internal error: x\n",
			members(ExitFailure, "failed", map[string]any{"error": "internal error: x"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkOutcome(t, tc) })
	}
}

// Each outcome carries exactly the members the page gives it: "reasons" only when refused, "error"
// only when failed or misused. This is the same table written once more, as the two predicates.
func TestReasonsAndErrorBelongToTheirOutcomes(t *testing.T) {
	plain := errors.New("x")
	runs := []struct {
		name    string
		make    func() (*Result, error)
		reasons bool
		err     bool
	}{
		{"done", func() (*Result, error) { return &Result{}, nil }, false, false},
		{"failed", func() (*Result, error) { return nil, plain }, false, true},
		{"usage", func() (*Result, error) { return nil, UsageError{Msg: "u"} }, false, true},
		{"refused by a check", func() (*Result, error) { return nil, Refusal{Reasons: []string{"a"}} }, true, false},
		{"refused by the backend", func() (*Result, error) { return nil, BackendRefusal{Reasons: []string{"a"}} }, true, false},
		{"refused by a result", func() (*Result, error) { return &Result{ExitCode: ExitRefused, Reasons: []string{"a"}}, nil }, true, false},
		{"not confirmed", func() (*Result, error) { return nil, NotConfirmed{} }, false, false},
		{"a panic", func() (*Result, error) { panic("p") }, false, true},
	}
	for _, tc := range runs {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.make() }})
			obj := object(t, run(t, "--output", "json", "fake").stdout)
			if _, has := obj["reasons"]; has != tc.reasons {
				t.Errorf("reasons present = %v, want %v: %v", has, tc.reasons, obj)
			}
			if _, has := obj["error"]; has != tc.err {
				t.Errorf("error present = %v, want %v: %v", has, tc.err, obj)
			}
			if ws, ok := stringList(obj["warnings"]); !ok || len(ws) != 0 {
				t.Errorf("warnings = %#v, want the empty list", obj["warnings"])
			}
		})
	}
}

// The refusal and the not-confirmed object have no "error" member, though their message is on
// standard error: the message is for a person and the page gives "error" to a failed command and a
// usage error only.
func TestTheMessageOfARefusalIsOnStandardErrorAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		line string
	}{
		{"a refusal", Refusal{Reasons: []string{"policy"}, Msg: "the policy says no"}, "ritueel: the policy says no\n"},
		{"a refusal by the backend", BackendRefusal{Reasons: []string{"pin-locked"}, Msg: "the card said no"}, "ritueel: the card said no\n"},
		{"not confirmed", NotConfirmed{}, "ritueel: not confirmed\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, tc.err }})
			r := run(t, "--output", "json", "fake")
			if r.stderr != tc.line {
				t.Errorf("stderr = %q, want %q", r.stderr, tc.line)
			}
			if strings.Contains(r.stdout, "error") || strings.Contains(r.stdout, "says no") {
				t.Errorf("the object holds the message: %q", r.stdout)
			}
		})
	}
}

// ---- a refusal with no reason code, and reason codes with another outcome -----------------------

// noCode is the text of the panic of a refusal that names no reason code.
func noCode(word string, code int) string {
	return fmt.Sprintf("cli: the command %q refused (exit code %d) and gave no reason code; a refusal names at least one code, in the Reasons of its Refusal or BackendRefusal or of its Result", word, code)
}

// codesWithOutcome is the text of the panic of reason codes with an outcome that is not refused.
func codesWithOutcome(word, outcome string, code int) string {
	return fmt.Sprintf("cli: the command %q gave reason codes with the outcome %q (exit code %d); only a refusal (exit code 3 or 4) has reasons, so a command that did not refuse leaves Reasons empty", word, outcome, code)
}

func TestARefusalWithNoReasonCodeIsAProgrammerError(t *testing.T) {
	cases := []struct {
		name string
		make func() (*Result, error)
		code int
	}{
		{"a refusal with a message and no list", func() (*Result, error) { return nil, Refusal{Msg: "no"} }, 3},
		{"an empty refusal", func() (*Result, error) { return nil, Refusal{} }, 3},
		{"a refusal by pointer", func() (*Result, error) { return nil, &Refusal{Msg: "no"} }, 3},
		{"a refusal with a nil list", func() (*Result, error) { return nil, Refusal{Reasons: nil, Msg: "no"} }, 3},
		{"a refusal with an empty list", func() (*Result, error) { return nil, Refusal{Reasons: []string{}, Msg: "no"} }, 3},
		{"a refusal wrapped by fmt.Errorf", func() (*Result, error) { return nil, fmt.Errorf("apply: %w", Refusal{Msg: "no"}) }, 3},
		{"a refusal with warnings", func() (*Result, error) { return nil, WithWarnings(Refusal{}, "w") }, 3},
		{"a result with the code 3", func() (*Result, error) { return &Result{ExitCode: ExitRefused}, nil }, 3},
		{"a result with the code 3 and an empty list", func() (*Result, error) { return &Result{ExitCode: ExitRefused, Reasons: []string{}}, nil }, 3},
		{"a result with the code 3, text and warnings", func() (*Result, error) {
			return &Result{ExitCode: ExitRefused, Text: "t\n", Warnings: []string{"w"}}, nil
		}, 3},
		{"a backend refusal", func() (*Result, error) { return nil, BackendRefusal{} }, 4},
		{"a backend refusal with a message", func() (*Result, error) { return nil, BackendRefusal{Msg: "locked"} }, 4},
		{"a backend refusal by pointer", func() (*Result, error) { return nil, &BackendRefusal{} }, 4},
		{"a backend refusal wrapped", func() (*Result, error) { return nil, fmt.Errorf("sign: %w", BackendRefusal{}) }, 4},
		{"a backend refusal with warnings", func() (*Result, error) { return nil, WithWarnings(BackendRefusal{}, "w") }, 4},
		{"a result with the code 4", func() (*Result, error) { return &Result{ExitCode: ExitBackend}, nil }, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.make() }})
			ranFailed(t, "fake", noCode("fake", tc.code), "fake")
			// A second word names its path in the text.
			withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{{name: "crl", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.make() }}}})
			ranFailed(t, "verify", noCode("verify crl", tc.code), "verify", "crl")
		})
	}
}

func TestReasonCodesWithAnotherOutcomeAreAProgrammerError(t *testing.T) {
	codes := []string{"policy"}
	cases := []struct {
		name    string
		make    func() (*Result, error)
		outcome string
		code    int
	}{
		{"a result that ended well", func() (*Result, error) { return &Result{Reasons: codes}, nil }, "done", 0},
		{"a result with the code 1", func() (*Result, error) { return &Result{ExitCode: ExitFailure, Reasons: codes}, nil }, "failed", 1},
		{"a result with the code 2", func() (*Result, error) { return &Result{ExitCode: ExitUsage, Reasons: codes}, nil }, "usage", 2},
		{"a result with the code 5", func() (*Result, error) { return &Result{ExitCode: ExitNotConfirmed, Reasons: codes}, nil }, "not-confirmed", 5},
		{"a result that ended well, with an empty-looking code", func() (*Result, error) { return &Result{Reasons: []string{""}}, nil }, "done", 0},
		{"an error with the code 1", func() (*Result, error) {
			return nil, oddCoded{code: ExitFailure, outcome: OutcomeFailed, reasons: codes}
		}, "failed", 1},
		{"an error with the code 2", func() (*Result, error) {
			return nil, oddCoded{code: ExitUsage, outcome: OutcomeUsage, reasons: codes}
		}, "usage", 2},
		{"an error with the code 5", func() (*Result, error) {
			return nil, oddCoded{code: ExitNotConfirmed, outcome: OutcomeNotConfirmed, reasons: codes}
		}, "not-confirmed", 5},
		{"an error with the code 5, wrapped", func() (*Result, error) {
			return nil, fmt.Errorf("x: %w", oddCoded{code: ExitNotConfirmed, outcome: OutcomeNotConfirmed, reasons: codes})
		}, "not-confirmed", 5},
		{"an error with the code 5, with warnings", func() (*Result, error) {
			return nil, WithWarnings(oddCoded{code: ExitNotConfirmed, outcome: OutcomeNotConfirmed, reasons: codes}, "w")
		}, "not-confirmed", 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.make() }})
			ranFailed(t, "fake", codesWithOutcome("fake", tc.outcome, tc.code), "fake")
			withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{{name: "crl", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.make() }}}})
			ranFailed(t, "verify", codesWithOutcome("verify crl", tc.outcome, tc.code), "verify", "crl")
		})
	}

	// The check of the outcome against the exit code comes first: a result that names the wrong
	// outcome gets that text, not the one of the reasons.
	t.Run("the outcome that disagrees with the code is reported first, for a result", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return &Result{ExitCode: ExitOK, Outcome: OutcomeRefused, Reasons: codes}, nil
		}})
		ranFailed(t, "fake", `cli: the exit code 0 goes with the outcome "done", and the command gave "refused"`, "fake")
	})
	t.Run("the outcome that disagrees with the code is reported first, for an error", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, oddCoded{code: ExitFailure, outcome: OutcomeRefused, reasons: codes}
		}})
		ranFailed(t, "fake", `cli: the exit code 1 goes with the outcome "failed", and the command gave "refused"`, "fake")
	})
	t.Run("the exit code 0 of an error is reported before the reasons", func(t *testing.T) {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return nil, oddCoded{code: ExitOK, outcome: OutcomeDone, reasons: codes}
		}})
		ranFailed(t, "fake", "cli: the error cli.oddCoded carries the exit code 0, which reports success; an error ends a command with a code of 1 or more", "fake")
	})
}

// A refusal with at least one code is the correct case: the guard lets it through, with a code that
// is only a space or is escaped, because a page has not decided what a code looks like.
func TestARefusalWithACodeIsNotAFault(t *testing.T) {
	for _, tc := range []struct {
		name  string
		codes []string
	}{
		{"one code", []string{"a"}},
		{"a code that is the empty string counts as a code", []string{""}},
		{"a code that is odd", []string{"v" + string(rune(0x0435)) + "rsion"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mk := range []func() (*Result, error){
				func() (*Result, error) { return nil, Refusal{Reasons: tc.codes, Msg: "m"} },
				func() (*Result, error) { return nil, BackendRefusal{Reasons: tc.codes, Msg: "m"} },
				func() (*Result, error) { return &Result{ExitCode: ExitRefused, Reasons: tc.codes}, nil },
				func() (*Result, error) { return &Result{ExitCode: ExitBackend, Reasons: tc.codes}, nil },
			} {
				withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return mk() }})
				r := run(t, "--output", "json", "fake")
				if r.code != ExitRefused && r.code != ExitBackend {
					t.Errorf("exit code = %d, want 3 or 4 (stderr %q)", int(r.code), r.stderr)
				}
				obj := object(t, r.stdout)
				if obj["outcome"] != "refused" {
					t.Errorf("object = %v", obj)
				}
				if got, ok := stringList(obj["reasons"]); !ok || len(got) != 1 {
					t.Errorf("reasons = %#v, want one code", obj["reasons"])
				}
			}
		})
	}
}

// A command that sets Result.Error has made a mistake: the text of a failure comes from the error it
// returns, and a refusal's message is the Msg of its error.
func TestSettingResultErrorIsAProgrammerError(t *testing.T) {
	msg := func(word string) string {
		return fmt.Sprintf("cli: the command %q put a text in Result.Error; a command that failed returns an error, and the text of a refusal is the Msg of its error", word)
	}
	for _, tc := range []struct {
		name string
		res  func() *Result
	}{
		{"a result that ended well", func() *Result { return &Result{Error: "boom"} }},
		{"a result of the code 1", func() *Result { return &Result{ExitCode: ExitFailure, Error: "boom"} }},
		{"a result of the code 3 with a reason", func() *Result { return &Result{ExitCode: ExitRefused, Reasons: []string{"a"}, Error: "boom"} }},
		{"a result with warnings", func() *Result { return &Result{Warnings: []string{"w"}, Error: "boom"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.res(), nil }})
			ranFailed(t, "fake", msg("fake"), "fake")
			withSpecs(t, spec{name: "verify", usage: "u", subs: []spec{{name: "crl", usage: "u", run: func(context.Context, *Call) (*Result, error) { return tc.res(), nil }}}})
			ranFailed(t, "verify", msg("verify crl"), "verify", "crl")
		})
	}
}
