package cli

import (
	"context"
	"strings"
	"testing"
)

// A refused Result may carry a Message: Run writes it on standard error as "ritueel: MESSAGE", after the warning
// lines, in both output modes, and never in the JSON object (the page of the commands, "The first version's
// commands": a refused request prints its line on standard error in both output modes). With no Message the
// codes stand in, as for a Refusal, and the exit code 4 has the words of the card or the backend.

func TestTheMessageOfARefusedResultIsTheLineOnStandardError(t *testing.T) {
	for _, tc := range []struct {
		name string
		res  Result
		want string // the whole of standard error, in both modes
	}{
		{"code 3 with a message", Result{ExitCode: ExitRefused, Reasons: []string{"policy"}, Message: "refused: policy (check 9: no)"},
			"ritueel: refused: policy (check 9: no)\n"},
		{"code 4 with a message: the message is the line as it is", Result{ExitCode: ExitBackend, Reasons: []string{"pin-locked"}, Message: "the card said no"},
			"ritueel: the card said no\n"},
		{"code 3 with no message: the codes stand in", Result{ExitCode: ExitRefused, Reasons: []string{"policy", "malformed"}},
			"ritueel: refused: policy, malformed\n"},
		{"code 4 with no message: the words of the card or the backend", Result{ExitCode: ExitBackend, Reasons: []string{"pin-locked"}},
			"ritueel: refused by the card or the backend: pin-locked\n"},
		{"the message is after the warning lines", Result{ExitCode: ExitRefused, Reasons: []string{"policy"}, Warnings: []string{"w1", "w2"}, Message: "line for a person"},
			warnLines("w1", "w2") + "ritueel: line for a person\n"},
		{"a message with a line break, a control character and a letter of another script is escaped", Result{ExitCode: ExitRefused, Reasons: []string{"policy"},
			Message: "a" + "\n" + "b" + "\x1b" + "[31m" + "е"},
			"ritueel: a" + bs + "u000ab" + bs + "u001b[31m" + bs + "u0435\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
				res := tc.res
				return &res, nil
			}})
			text := run(t, "fake")
			js := run(t, "--output", "json", "fake")
			for mode, r := range map[string]result{"text": text, "json": js} {
				if r.code != tc.res.ExitCode || r.stderr != tc.want {
					t.Errorf("%s: (%d, %q), want (%d, %q)", mode, int(r.code), r.stderr, int(tc.res.ExitCode), tc.want)
				}
				if !onlyPrintable(r.stderr) {
					t.Errorf("%s: standard error holds a byte that is not printable ASCII: %q", mode, r.stderr)
				}
			}
			if strings.Contains(js.stdout, "message") || (tc.res.Message != "" && strings.Contains(js.stdout, tc.res.Message)) {
				t.Errorf("the message is in the object: %q", js.stdout)
			}
			obj := object(t, js.stdout)
			if _, ok := obj["message"]; ok {
				t.Errorf("the object has a member message: %v", obj)
			}
			if text.stdout != "" {
				t.Errorf("text mode wrote %q on standard output, want nothing (the Result has no Text)", text.stdout)
			}
		})
	}
}

// A Result that did not refuse never prints a refusal line, whatever its Message holds: the exit code decides.
func TestAMessageOfAResultThatDidNotRefuseIsNotPrinted(t *testing.T) {
	for _, code := range []ExitCode{ExitOK} {
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return &Result{ExitCode: code, Message: "must not show"}, nil
		}})
		for _, args := range [][]string{{"fake"}, {"--output", "json", "fake"}} {
			if r := run(t, args...); r.code != code || r.stderr != "" || strings.Contains(r.stdout, "must not show") {
				t.Errorf("%v: (%d, %q, %q)", args, int(r.code), r.stdout, r.stderr)
			}
		}
	}
}
