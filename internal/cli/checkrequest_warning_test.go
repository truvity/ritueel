//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The warning that the trust set was not checked, in every run of "check request" that prints the nine results:
// an accepted run, a refused run and a run that is not complete. In a run that is not complete it comes last,
// after the warnings that say which check did not run. A run that stops before it has nine results has none.
// The verdicts here are made by hand, so that every check can refuse and every shape of a run that is not
// complete is reached; the runs on bundles are in checkrequest_test.go and checkrequest_primaries_test.go.

const trustSetStderrPrefix = "ritueel: warning: "

// A refusal at each of the nine checks has the warning, and only that one.
func TestARefusalAtEachOfTheNineChecksHasTheWarningAboutTheTrustSetAndOnlyThat(t *testing.T) {
	for n := 1; n <= 9; n++ {
		t.Run("check "+strconv.Itoa(n), func(t *testing.T) {
			v := verdictOf(append(passed(n-1), handoff.StatusFailed)...)
			v.Code, v.Detail = handoff.Code("policy"), "the detail"
			for _, delegation := range []string{"", "d"} {
				res, err := requestOutcome("stem", delegation, v)
				if err != nil || res == nil || res.ExitCode != ExitRefused {
					t.Fatalf("delegation %q: (%v, %v), want a refusal", delegation, res, err)
				}
				if !slices.Equal(res.Warnings, []string{trustSetWarningText}) {
					t.Errorf("delegation %q: warnings = %q, want the one warning about the trust set", delegation, res.Warnings)
				}
				if len(res.Checks) != 9 {
					t.Errorf("delegation %q: %d results, want nine", delegation, len(res.Checks))
				}
			}
		})
	}
}

// The refusal is also carried by the program: in text mode the warning is a line of standard error before the
// refusal line, in JSON mode it is in the member warnings and on standard error the same way. The exit code is 3
// in both, and the warning is not on standard output.
func TestTheWarningOfARefusalIsOnStandardErrorInTextModeAndInTheMemberWarningsInJSONMode(t *testing.T) {
	v := verdictOf(append(passed(4), handoff.StatusFailed)...)
	v.Code, v.Detail = handoff.Code("possession-invalid"), "the signature does not verify"
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return requestOutcome("stem", "d", v)
	}})
	const refusal = "ritueel: refused: possession-invalid (check 5: the signature does not verify)\n"
	text := run(t, "fake")
	js := run(t, "--output", "json", "fake")
	for name, r := range map[string]result{"text": text, "json": js} {
		if r.code != ExitRefused {
			t.Errorf("%s: exit code %d, want 3", name, int(r.code))
		}
		if r.stderr != trustSetStderrLine+refusal {
			t.Errorf("%s: standard error = %q, want the warning and then the refusal", name, r.stderr)
		}
		if strings.Contains(r.stdout, "trust-set-unchecked") && name == "text" {
			t.Errorf("text mode: the warning is on standard output: %q", r.stdout)
		}
	}
	obj := object(t, js.stdout)
	wantObject(t, withoutChecks(obj), map[string]any{
		"output": 1, "command": "fake", "exit_code": 3, "outcome": "refused",
		"reasons": []string{"possession-invalid"}, "warnings": []string{trustSetWarningText},
	})
	if len(crqChecks(t, obj)) != 9 {
		t.Errorf("checks = %v, want nine", obj["checks"])
	}
}

// A refused verdict with fewer than nine results is not a run that prints the nine results: it has no warning.
// The library never gives one; the command does not invent the warning for it.
func TestARefusedVerdictWithFewerThanNineResultsHasNoWarning(t *testing.T) {
	for _, n := range []int{0, 1, 5, 8} {
		v := verdictOf(append(passed(n), handoff.StatusFailed)...)
		v.Checks = v.Checks[:n]
		v.Code, v.Detail = handoff.Code("policy"), "x"
		res, err := requestOutcome("stem", "d", v)
		if err != nil || res == nil || res.ExitCode != ExitRefused {
			t.Fatalf("%d results: (%v, %v), want a refusal", n, res, err)
		}
		if len(res.Warnings) != 0 || len(res.Checks) != n {
			t.Errorf("%d results: warnings = %q, results = %d, want no warning", n, res.Warnings, len(res.Checks))
		}
	}
	// And a verdict with more than nine results and a code is not either.
	v := verdictOf(append(passed(2), handoff.StatusFailed)...)
	v.Checks = append(v.Checks, handoff.CheckResult{N: 10, Status: handoff.StatusNotRun})
	v.Code, v.Detail = handoff.Code("policy"), "x"
	res, err := requestOutcome("stem", "d", v)
	if err != nil || res == nil || len(res.Warnings) != 0 {
		t.Errorf("ten results: (%v, %v), want a refusal with no warning", res, err)
	}
}

// A run that is not complete has the warning last, however many warnings say which check did not run, with a
// delegation or without, and whatever check it is.
func TestARunThatIsNotCompleteHasTheWarningAboutTheTrustSetLast(t *testing.T) {
	type spot struct {
		n     int
		rules []string
	}
	for _, tc := range []struct {
		name  string
		spots []spot
		want  []string // the warnings before the last one, with no delegation
	}{
		{"check 9 with the two rules of a delegation", []spot{{9, []string{"delegation-type", "name-constraints"}}},
			[]string{"check 9: rules not run: delegation-type, name-constraints; give --delegation NAME"}},
		{"check 3 with a rule that is not one of a delegation", []spot{{3, []string{"primaries"}}},
			[]string{"check 3: rules not run: primaries"}},
		{"two checks with rules not run", []spot{{3, []string{"primaries"}}, {9, []string{"delegation-type"}}},
			[]string{"check 3: rules not run: primaries", "check 9: rules not run: delegation-type; give --delegation NAME"}},
		{"three checks with rules not run", []spot{{2, []string{"a"}}, {5, []string{"b", "c"}}, {9, []string{"capability"}}},
			[]string{"check 2: rules not run: a", "check 5: rules not run: b, c", "check 9: rules not run: capability; give --delegation NAME"}},
		{"a check that passed with a rule not run", []spot{{4, []string{"x"}}},
			[]string{"check 4: rules not run: x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verdictOf(passed(9)...)
			for _, s := range tc.spots {
				v.Checks[s.n-1].NotRun = s.rules
			}
			// A check with a rule not run and the status passed is the case of one; the others did not run.
			for _, s := range tc.spots {
				if s.n != 4 {
					v.Checks[s.n-1].Status = handoff.StatusNotRun
				}
			}
			for _, delegation := range []string{"", "d"} {
				res, err := requestOutcome("stem", delegation, v)
				_ = notJudgedOf(t, res, err)
				w := warningsOf(err)
				if len(w) != len(tc.want)+1 || w[len(w)-1] != trustSetWarningText {
					t.Fatalf("delegation %q: warnings = %q, want %d with the warning about the trust set last", delegation, w, len(tc.want)+1)
				}
				for i, line := range w[:len(w)-1] {
					want := tc.want[i]
					if delegation != "" {
						want = strings.TrimSuffix(want, "; give --delegation NAME")
					}
					if line != want {
						t.Errorf("delegation %q: warning %d = %q, want %q", delegation, i+1, line, want)
					}
				}
				if n := strings.Count(strings.Join(w, "\n"), "trust-set-unchecked"); n != 1 {
					t.Errorf("delegation %q: the warning about the trust set is given %d times", delegation, n)
				}
			}
		})
	}
}

// The order is the same in the program: standard error has the warnings of the rules, then the warning about the
// trust set, then the line of the error; the member warnings has the same order. Standard output holds the nine
// results and the last line, and none of the warnings.
func TestARunThatIsNotCompleteGivesTheWarningsInOrderOnStandardErrorAndInTheObject(t *testing.T) {
	v := verdictOf(passed(2)...)
	v.Checks[2].NotRun = []string{"primaries"}
	v.Checks[8].NotRun = []string{"delegation-type", "name-constraints"}
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return requestOutcome("stem", "", v)
	}})
	const (
		first  = "check 3: rules not run: primaries"
		second = "check 9: rules not run: delegation-type, name-constraints; give --delegation NAME"
		last   = "ritueel: request stem is not accepted and not refused: check 3 did not run these rules: primaries\n"
	)
	text := run(t, "fake")
	js := run(t, "--output", "json", "fake")
	for name, r := range map[string]result{"text": text, "json": js} {
		want := trustSetStderrPrefix + first + "\n" + trustSetStderrPrefix + second + "\n" + trustSetStderrLine + last
		if r.code != ExitFailure || r.stderr != want {
			t.Errorf("%s: (%d, %q), want exit code 1 and %q", name, int(r.code), r.stderr, want)
		}
	}
	if strings.Contains(text.stdout, "trust-set-unchecked") || strings.Contains(text.stdout, "warning:") {
		t.Errorf("text mode: a warning is on standard output: %q", text.stdout)
	}
	if lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n"); len(lines) != 11 || !strings.HasPrefix(lines[10], "request stem: not complete: ") {
		t.Errorf("text mode: standard output = %q, want the nine results, check 10 and the last line", text.stdout)
	}
	obj := object(t, js.stdout)
	if w := stringsOf(obj["warnings"]); !slices.Equal(w, []string{first, second, trustSetWarningText}) {
		t.Errorf("warnings = %q, want the two of the rules and the one about the trust set last", w)
	}
	if obj["outcome"] != "failed" || obj["exit_code"] != jsonNumber("1") || len(crqChecks(t, obj)) != 9 {
		t.Errorf("object = %v", obj)
	}
}

// A check that did not run and names no rule gives no warning of its own: the one about the trust set is alone.
func TestARunThatIsNotCompleteAndNamesNoRuleHasOnlyTheWarningAboutTheTrustSet(t *testing.T) {
	for _, delegation := range []string{"", "d"} {
		v := verdictOf(passed(6)...)
		res, err := requestOutcome("stem", delegation, v)
		_ = notJudgedOf(t, res, err)
		if w := warningsOf(err); !slices.Equal(w, []string{trustSetWarningText}) {
			t.Errorf("delegation %q: warnings = %q, want only the warning about the trust set", delegation, w)
		}
	}
}

// A run that stops before it has nine results has no warning about the trust set, whatever stops it: a verdict
// that is a fault of the program, an error of the checker of each kind, and a delegation that the command cannot
// give primaries for.
func TestARunThatStopsBeforeTheNineResultsHasNoWarningAboutTheTrustSet(t *testing.T) {
	// The faults of requestOutcome: no result and an error that carries no warning.
	for name, v := range map[string]handoff.Verdict{
		"no check at all":                         {},
		"eight checks":                            {Checks: verdictOf(passed(9)...).Checks[:8]},
		"ten checks":                              {Checks: append(verdictOf(passed(9)...).Checks, handoff.CheckResult{N: 10, Status: handoff.StatusNotRun})},
		"nine checks that passed, made by hand":   verdictOf(passed(9)...),
		"a check that failed and gave no code":    verdictOf(append(passed(8), handoff.StatusFailed)...),
		"a status that is none of the three":      verdictOf(append(passed(8), handoff.CheckStatus("maybe"))...),
		"a failed check and one that did not run": withStatus(verdictOf(passed(4)...), 2, handoff.StatusFailed),
		"eight results that name a rule not run":  {Checks: withNotRun(verdictOf(passed(8)...), 7, "x").Checks[:8]},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := requestOutcome("stem", "d", v)
			if res != nil || err == nil {
				t.Fatalf("(%v, %v), want an error and no result", res, err)
			}
			if w := warningsOf(err); len(w) != 0 {
				t.Errorf("warnings = %q, want none", w)
			}
			if strings.Contains(err.Error(), "trust-set-unchecked") {
				t.Errorf("the error holds the warning: %v", err)
			}
		})
	}
	// The errors of the checker, as the command turns them into its error.
	for name, cause := range map[string]error{
		"no verifier":    handoff.ErrNoVerifier,
		"type not built": handoff.ErrTypeNotBuilt,
		"no primaries":   handoff.ErrNoPrimaries,
		"internal":       handoff.ErrInternal,
		"config":         handoff.ErrConfig,
		"plain":          errors.New("the verifier broke"),
	} {
		t.Run("checker: "+name, func(t *testing.T) {
			err := checkRequestError("stem", verdictOf(passed(2)...), cause)
			if w := warningsOf(err); len(w) != 0 {
				t.Errorf("warnings = %q, want none", w)
			}
			withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) { return nil, err }})
			text := run(t, "fake")
			js := run(t, "--output", "json", "fake")
			if text.code != ExitFailure || js.code != ExitFailure || strings.Contains(text.stderr+js.stderr, "trust-set-unchecked") {
				t.Errorf("text (%d, %q), json (%d, %q), want exit code 1 and no warning", int(text.code), text.stderr, int(js.code), js.stderr)
			}
			if w := stringsOf(object(t, js.stdout)["warnings"]); len(w) != 0 {
				t.Errorf("warnings = %q, want none", w)
			}
		})
	}
}

// The same on bundles, through the command: a run that is stopped before nine results by a bundle that is not
// whole, a request that cannot be read, a store with no verifier, a type that is not built and a delegation of the
// type openpgp-subkey has no warning in either mode; a run that has nine results has it once, last.
func TestTheWarningAboutTheTrustSetOnBundlesFollowsTheNineResults(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	good := m.byID(t, "x509-software-valid")
	stem := good.stem(t)
	for _, tc := range []struct {
		name   string
		change func(tree crqTree)
		args   []string
		code   ExitCode
		nine   bool
	}{
		{"accepted", nil, []string{"--delegation", crqDelegation}, ExitOK, true},
		{"not complete for want of a delegation", nil, nil, ExitFailure, true},
		{"no proof file", func(tree crqTree) { delete(tree, "requests/"+stem+"/"+stem+".proof.json") }, []string{"--delegation", crqDelegation}, ExitFailure, false},
		{"no trust set", func(tree crqTree) {
			for p := range tree {
				if strings.HasPrefix(p, "trust/") {
					delete(tree, p)
				}
			}
		}, []string{"--delegation", crqDelegation}, ExitFailure, false},
		{"a delegation that is not there", nil, []string{"--delegation", "nosuch"}, ExitFailure, false},
		{"a proof file that is not json", func(tree crqTree) { tree["requests/"+stem+"/"+stem+".proof.json"] = []byte("{") }, []string{"--delegation", crqDelegation}, ExitRefused, true},
		{"an empty signed request", func(tree crqTree) { tree["requests/"+stem+"/"+stem+".csr.pem"] = nil }, []string{"--delegation", crqDelegation}, ExitRefused, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := crqBundleTree(t, m, good)
			if tc.change != nil {
				tc.change(tree)
			}
			dir := t.TempDir()
			crqWrite(t, dir, tree)
			base := append([]string{"check", "request", stem, "--dir", dir}, tc.args...)
			text := crqRun(t, now, base...)
			js := crqRun(t, now, append(base, "--output", "json")...)
			for name, r := range map[string]result{"text": text, "json": js} {
				if r.code != tc.code {
					t.Fatalf("%s: exit code %d, want %d\n%s%s", name, int(r.code), int(tc.code), r.stdout, r.stderr)
				}
				if got := strings.Count(r.stderr, "trust-set-unchecked"); got != map[bool]int{true: 1, false: 0}[tc.nine] {
					t.Errorf("%s: the warning is given %d times: %q", name, got, r.stderr)
				}
				if strings.Contains(r.stdout, "trust-set-unchecked") && name == "text" {
					t.Errorf("text: the warning is on standard output: %q", r.stdout)
				}
			}
			w := stringsOf(object(t, js.stdout)["warnings"])
			if tc.nine != (len(w) > 0 && w[len(w)-1] == trustSetWarningText) {
				t.Errorf("warnings = %q, want the warning about the trust set last: %v", w, tc.nine)
			}
			if !tc.nine && len(w) != 0 {
				t.Errorf("warnings = %q, want none", w)
			}
			// On standard error the warning is a line that comes before the line of the refusal or of the error.
			if tc.nine {
				i := strings.Index(text.stderr, trustSetStderrLine)
				rest := text.stderr[i+len(trustSetStderrLine):]
				if i < 0 || strings.Contains(rest, "warning:") || !strings.HasPrefix(rest, "ritueel: ") && rest != "" {
					t.Errorf("standard error = %q, want the warning about the trust set as the last warning", text.stderr)
				}
				if tc.code == ExitOK && rest != "" {
					t.Errorf("standard error = %q, want nothing after the warning of an accepted run", text.stderr)
				}
			}
		})
	}
}

// Whatever verdict is made by hand (any number of results, any status, any rules not run, any code), the
// warning about the trust set follows one rule: a result or a request that was not judged that has the nine
// results carries it once, and last; anything else carries none.
func FuzzTheWarningAboutTheTrustSetFollowsTheNineResults(f *testing.F) {
	f.Add(uint8(9), []byte{1, 1, 1, 1, 1, 1, 1, 1, 0}, "rule", "policy", true)
	f.Add(uint8(9), []byte{1, 1, 1, 1, 2, 0, 0, 0, 0}, "", "policy", false)
	f.Add(uint8(8), []byte{1, 1, 1, 1, 2, 0, 0, 0}, "", "policy", true)
	f.Add(uint8(0), []byte{}, "", "", false)
	f.Add(uint8(10), []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 0}, "x\x1b[31m", "a\nb", true)
	f.Add(uint8(9), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}, "delegation-type", "", false)
	f.Fuzz(func(t *testing.T, count uint8, kinds []byte, rule, code string, withDelegation bool) {
		n := int(count) % 12
		v := handoff.Verdict{}
		for i := 0; i < n; i++ {
			ch := handoff.CheckResult{N: i + 1, Name: "c"}
			k := byte(0)
			if i < len(kinds) {
				k = kinds[i]
			}
			switch k % 5 {
			case 0:
				ch.Status = handoff.StatusNotRun
			case 1:
				ch.Status = handoff.StatusPassed
			case 2:
				ch.Status = handoff.StatusFailed
			case 3:
				ch.Status = handoff.StatusNotRun
				ch.NotRun = []string{rule}
			default:
				ch.Status = handoff.StatusPassed
				ch.NotRun = []string{rule, "name-constraints"}
			}
			v.Checks = append(v.Checks, ch)
		}
		v.Code = handoff.Code(code)
		delegation := ""
		if withDelegation {
			delegation = "d"
		}
		res, err := requestOutcome("stem", delegation, v)
		var warnings []string
		switch {
		case res != nil:
			if err != nil {
				t.Fatalf("a result and an error: %v, %v", res, err)
			}
			if res.ExitCode != ExitRefused {
				t.Fatalf("exit code %d for a verdict that was made by hand", int(res.ExitCode))
			}
			warnings = res.Warnings
		default:
			if err == nil {
				t.Fatal("no result and no error")
			}
			warnings = warningsOf(err)
		}
		var nj *notJudged
		hasNine := (res != nil && len(res.Checks) == 9) || errors.As(err, &nj)
		times := strings.Count(strings.Join(warnings, "\n"), "trust-set-unchecked")
		switch {
		case hasNine:
			if times != 1 || warnings[len(warnings)-1] != trustSetWarningText {
				t.Fatalf("%d results: warnings = %q, want the warning about the trust set once and last", n, warnings)
			}
		default:
			if len(warnings) != 0 {
				t.Fatalf("%d results: warnings = %q, want none", n, warnings)
			}
		}
		if res != nil && len(res.Checks) != 9 && len(warnings) != 0 {
			t.Fatalf("a refusal with %d results has the warnings %q", len(res.Checks), warnings)
		}
	})
}

// Every reason code that the contract page gives to a check is exit code 3 with that code in reasons, the checks
// before it passed and the ones after it not run, and the warning about the trust set. The names and the numbers
// of the codes are read from the contract page; the codes that the page gives to the evidence (proof-invalid,
// key-mismatch) and to an OpenPGP primary are reached here by hand, because this command registers no verifier
// and gives the checker no primaries.
func TestEveryReasonCodeOfTheContractIsExitThreeWithItsCodeAndTheWarningAboutTheTrustSet(t *testing.T) {
	for _, c := range contractChecks(t) {
		t.Run(c.code, func(t *testing.T) {
			v := verdictOf(append(passed(c.n-1), handoff.StatusFailed)...)
			v.Code, v.Detail = handoff.Code(c.code), "the detail"
			res, err := requestOutcome("stem", "d", v)
			if err != nil || res == nil || res.ExitCode != ExitRefused {
				t.Fatalf("(%v, %v), want a refusal", res, err)
			}
			if !slices.Equal(res.Reasons, []string{c.code}) || !slices.Equal(res.Warnings, []string{trustSetWarningText}) {
				t.Errorf("reasons = %q, warnings = %q", res.Reasons, res.Warnings)
			}
			if want := "refused: " + c.code + " (check " + strconv.Itoa(c.n) + ": the detail)"; res.Message != want {
				t.Errorf("message = %q, want %q", res.Message, want)
			}
			for i, ch := range res.Checks {
				want := "not-run"
				switch {
				case i+1 < c.n:
					want = "passed"
				case i+1 == c.n:
					want = "failed"
				}
				if ch.Result != want {
					t.Errorf("check %d = %s, want %s", i+1, ch.Result, want)
				}
			}
		})
	}
	// A code that the page does not give to any check is still a refusal that has the nine results: the command
	// reports what the checker says and does not judge the code.
	v := verdictOf(append(passed(2), handoff.StatusFailed)...)
	v.Code = "unknown-primary"
	res, err := requestOutcome("stem", "d", v)
	if err != nil || res == nil || res.ExitCode != ExitRefused || !slices.Equal(res.Reasons, []string{"unknown-primary"}) || len(res.Warnings) != 1 {
		t.Errorf("(%v, %v)", res, err)
	}
}
