package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The meaning of a verdict, tested on verdicts made by hand. A verdict that was not returned by the checker is
// never accepted (only Check can set that), so these tests reach every branch that tells a refusal, a request that
// is not complete and a fault of the program apart, without a bundle.

var checkNamesForTests = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}

// verdictOf is a verdict with nine checks: results[i] is the status of check i+1.
func verdictOf(statuses ...handoff.CheckStatus) handoff.Verdict {
	v := handoff.Verdict{}
	for i := 0; i < 9; i++ {
		st := handoff.StatusNotRun
		if i < len(statuses) {
			st = statuses[i]
		}
		v.Checks = append(v.Checks, handoff.CheckResult{N: i + 1, Name: checkNamesForTests[i], Status: st})
	}
	return v
}

func passed(n int) []handoff.CheckStatus {
	out := make([]handoff.CheckStatus, n)
	for i := range out {
		out[i] = handoff.StatusPassed
	}
	return out
}

func TestEvidenceVerifiersRegistersNoVerifierAndIsNotNil(t *testing.T) {
	if got := evidenceVerifiers(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("evidenceVerifiers = %#v, want an empty map that is not nil", got)
	}
	for _, store := range []handoff.Store{"piv", "openpgp-card", "aws-kms", "software"} {
		if _, ok := evidenceVerifiers(&Call{}, nil)[store]; ok {
			t.Errorf("a verifier is registered for the store %s", store)
		}
	}
}

func TestAVerdictThatNoCheckAcceptedIsNeverAcceptedWhateverItsChecksSay(t *testing.T) {
	// Nine checks that all read "passed", made by hand: not accepted, because only Check accepts. The command
	// has no right to call it accepted, and it is a fault of the program, exit code 1.
	v := verdictOf(passed(9)...)
	if v.Accepted() {
		t.Fatal("a hand-made verdict is accepted")
	}
	for _, delegation := range []string{"", "d"} {
		res, err := requestOutcome("stem", delegation, v)
		if res != nil || err == nil {
			t.Fatalf("delegation %q: (%v, %v), want an error and no result", delegation, res, err)
		}
		if strings.Contains(err.Error(), "accepted") && !strings.Contains(err.Error(), "neither an acceptance") {
			t.Errorf("the error calls the request accepted: %v", err)
		}
	}
}

func TestARefusedVerdictIsExitThreeWithTheCodeTheFailedCheckAndTheDetail(t *testing.T) {
	v := verdictOf(append(passed(4), handoff.StatusFailed)...)
	v.Code, v.Detail = handoff.Code("possession-invalid"), "the signature does not verify"
	res, err := requestOutcome("stem", "d", v)
	if err != nil || res == nil {
		t.Fatalf("(%v, %v)", res, err)
	}
	if res.ExitCode != ExitRefused || len(res.Reasons) != 1 || res.Reasons[0] != "possession-invalid" {
		t.Errorf("exit code %d, reasons %v", int(res.ExitCode), res.Reasons)
	}
	if want := "refused: possession-invalid (check 5: the signature does not verify)"; res.Message != want {
		t.Errorf("message = %q, want %q", res.Message, want)
	}
	if len(res.Checks) != 9 || res.Checks[4] != (CheckState{N: 5, Result: "failed"}) || res.Checks[5] != (CheckState{N: 6, Result: "not-run"}) || res.Checks[0] != (CheckState{N: 1, Result: "passed"}) {
		t.Errorf("checks = %v", res.Checks)
	}
	if !strings.HasSuffix(res.Text, "request stem: refused: possession-invalid\n") || strings.Contains(res.Text, "accepted") {
		t.Errorf("text = %q", res.Text)
	}
	if len(res.Warnings) != 1 || res.Warnings[0] != trustSetWarningText {
		t.Errorf("warnings = %q, want the one warning about the trust set: a refusal has the nine results", res.Warnings)
	}
}

// A refusal whose code or detail holds bytes that a terminal would obey: the line of the person is printable ASCII.
func TestAHostileCodeAndDetailReachNoTerminal(t *testing.T) {
	hostile := "a" + "\x1b[31m" + "\u202e" + "\n" + "b"
	v := verdictOf(append(passed(8), handoff.StatusFailed)...)
	v.Code, v.Detail = handoff.Code(hostile), hostile
	v.Checks[0].Name = hostile
	v.Checks[1].NotRun = []string{hostile}
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return requestOutcome("stem", "d", v)
	}})
	for _, args := range [][]string{{"fake"}, {"--output", "json", "fake"}} {
		r := run(t, args...)
		if r.code != ExitRefused || !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Errorf("%v: (%d, %q, %q)", args, int(r.code), r.stdout, r.stderr)
		}
		if strings.Contains(r.stdout+r.stderr, "\x1b") || strings.Contains(r.stdout+r.stderr, "\u202e") {
			t.Errorf("%v: a control character got through: %q %q", args, r.stdout, r.stderr)
		}
	}
}

// notJudgedOf returns the error of requestOutcome as a *notJudged, or fails the test.
func notJudgedOf(t *testing.T, res *Result, err error) *notJudged {
	t.Helper()
	if res != nil || err == nil {
		t.Fatalf("(%v, %v), want an error and no result", res, err)
	}
	var nj *notJudged
	if !errors.As(err, &nj) {
		t.Fatalf("the error is not a request that was not judged: %v", err)
	}
	if got, outcome := ExitFor(err); got != ExitFailure || outcome != OutcomeFailed {
		t.Fatalf("exit code %d and outcome %q, want 1 and failed", int(got), outcome)
	}
	return nj
}

func TestACheckThatDidNotRunIsNotJudgedAndExitOneWithTheNineResultsAndTheReason(t *testing.T) {
	v := verdictOf(passed(8)...)
	v.Checks[8].NotRun = []string{"delegation-type", "name-constraints"}
	res, err := requestOutcome("stem", "", v)
	nj := notJudgedOf(t, res, err)
	if want := "request stem is not accepted and not refused: check 9 needs a delegation; give --delegation NAME"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if want := []string{"check 9: rules not run: delegation-type, name-constraints; give --delegation NAME", trustSetWarningText}; fmt.Sprint(warningsOf(err)) != fmt.Sprint(want) {
		t.Errorf("warnings = %q, want %q", warningsOf(err), want)
	}
	if !strings.HasSuffix(nj.text, "request stem: not complete: check 9 needs a delegation; give --delegation NAME\n") || strings.Contains(nj.text, "accepted") {
		t.Errorf("text = %q", nj.text)
	}
	if !strings.Contains(nj.text, "check 9: not-run: i (rules not run: delegation-type, name-constraints)\n") {
		t.Errorf("text = %q, want the clause of the rules that were not run", nj.text)
	}
	if len(nj.checks) != 9 || nj.checks[8] != (CheckState{N: 9, Result: "not-run"}) || nj.checks[0] != (CheckState{N: 1, Result: "passed"}) {
		t.Errorf("checks = %v", nj.checks)
	}

	// With a delegation named the hint to name one is not given, and the reason names the rules.
	res, err = requestOutcome("stem", "d", v)
	nj = notJudgedOf(t, res, err)
	if w := warningsOf(err); len(w) != 2 || strings.Contains(w[0], "give --delegation") || w[0] != "check 9: rules not run: delegation-type, name-constraints" || w[1] != trustSetWarningText {
		t.Errorf("warnings = %q: the hint to give a delegation is shown to someone who gave one, or the warning about the trust set is not last", w)
	}
	if want := "request stem is not accepted and not refused: check 9 did not run these rules: delegation-type, name-constraints"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if !strings.HasSuffix(nj.text, "request stem: not complete: check 9 did not run these rules: delegation-type, name-constraints\n") {
		t.Errorf("text = %q", nj.text)
	}

	// Two checks with rules not run give a warning each, in the order of the checks, and the reason names the
	// first of them.
	v.Checks[6].Status = handoff.StatusNotRun
	v.Checks[6].NotRun = []string{"primaries"}
	for _, delegation := range []string{"", "d"} {
		res, err = requestOutcome("stem", delegation, v)
		_ = notJudgedOf(t, res, err)
		w := warningsOf(err)
		if len(w) != 3 || !strings.HasPrefix(w[0], "check 7:") || !strings.HasPrefix(w[1], "check 9:") || w[2] != trustSetWarningText {
			t.Errorf("delegation %q: warnings = %q", delegation, w)
		}
		if want := "request stem is not accepted and not refused: check 7 did not run these rules: primaries"; err.Error() != want {
			t.Errorf("delegation %q: error = %q, want %q", delegation, err.Error(), want)
		}
		// The hint to name a delegation belongs to the warning of check 9 alone, and only when none was named.
		if strings.Contains(w[0], "give --delegation") || strings.Contains(w[1], "give --delegation") != (delegation == "") || strings.Contains(w[2], "give --delegation") {
			t.Errorf("delegation %q: the hint is on the wrong warning: %q", delegation, w)
		}
	}
}

// A check that did not run and names no rule, and a check that passed with a rule not run, are not judged either.
func TestACheckThatDidNotRunAndNamesNoRuleIsNotJudgedAndHasOnlyTheWarningAboutTheTrustSet(t *testing.T) {
	v := verdictOf(passed(8)...)
	res, err := requestOutcome("stem", "d", v)
	nj := notJudgedOf(t, res, err)
	if want := "request stem is not accepted and not refused: check 9 did not run"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if w := warningsOf(err); len(w) != 1 || w[0] != trustSetWarningText {
		t.Errorf("warnings = %q, want only the warning about the trust set: no rule was named", w)
	}
	if !strings.HasSuffix(nj.text, "request stem: not complete: check 9 did not run\n") {
		t.Errorf("text = %q", nj.text)
	}

	v = withNotRun(verdictOf(passed(9)...), 4, "x")
	res, err = requestOutcome("stem", "d", v)
	nj = notJudgedOf(t, res, err)
	if want := "request stem is not accepted and not refused: check 5 did not run these rules: x"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	if nj.checks[4] != (CheckState{N: 5, Result: "passed"}) {
		t.Errorf("checks = %v: a check that passed is shown as passed", nj.checks)
	}
	if want := "check 5: passed: e (rules not run: x)\n"; !strings.Contains(nj.text, want) {
		t.Errorf("text = %q, want %q", nj.text, want)
	}
}

// The first check that did not run is the one named, also when a later check is the delegation's.
func TestTheReasonNamesTheFirstCheckThatDidNotRun(t *testing.T) {
	v := verdictOf(passed(2)...) // checks 3 to 9 did not run
	v.Checks[2].NotRun = []string{"primaries"}
	v.Checks[8].NotRun = []string{"delegation-type", "name-constraints"}
	res, err := requestOutcome("stem", "", v)
	_ = notJudgedOf(t, res, err)
	if want := "request stem is not accepted and not refused: check 3 did not run these rules: primaries"; err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// Everything else that is not accepted and not refused is either a request that was not judged (exit code 1, with
// the nine results) or a fault of the program (exit code 1 too, with no results): never exit code 0.
func TestAVerdictThatIsNeitherAcceptedNorRefusedNorExplainedIsAFault(t *testing.T) {
	for name, tc := range map[string]struct {
		v        handoff.Verdict
		notJudge bool
	}{
		"a check that did not run and names no rule":       {verdictOf(passed(8)...), true},
		"a check that did not run, after one that did":     {verdictOf(passed(3)...), true},
		"a check that passed with rules not run":           {withNotRun(verdictOf(passed(9)...), 8, "x"), true},
		"a check that failed and gave no code":             {verdictOf(append(passed(8), handoff.StatusFailed)...), false},
		"no check at all":                                  {handoff.Verdict{}, false},
		"eight checks":                                     {handoff.Verdict{Checks: verdictOf(passed(9)...).Checks[:8]}, false},
		"ten checks":                                       {handoff.Verdict{Checks: append(verdictOf(passed(9)...).Checks, handoff.CheckResult{N: 10, Status: handoff.StatusPassed})}, false},
		"ten checks, the last did not run":                 {handoff.Verdict{Checks: append(verdictOf(passed(9)...).Checks, handoff.CheckResult{N: 10, Status: handoff.StatusNotRun, NotRun: []string{"x"}})}, false},
		"a status of no kind and a check that did not run": {withStatus(verdictOf(passed(4)...), 8, "maybe"), false},
		"a failed check and a check that did not run":      {withStatus(verdictOf(passed(4)...), 2, handoff.StatusFailed), false},
		"a status that is none of the three":               {verdictOf(append(passed(8), handoff.CheckStatus("maybe"))...), false},
		"nine checks that passed, made by hand":            {verdictOf(passed(9)...), false},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := requestOutcome("stem", "d", tc.v)
			if res != nil || err == nil {
				t.Fatalf("(%v, %v), want an error and no result", res, err)
			}
			if code, outcome := ExitFor(err); code != ExitFailure || outcome != OutcomeFailed {
				t.Errorf("the error has the exit code %d and the outcome %q, want 1 and failed", int(code), outcome)
			}
			var nj *notJudged
			if got := errors.As(err, &nj); got != tc.notJudge {
				t.Errorf("not judged = %v, want %v: %v", got, tc.notJudge, err)
			}
			if !tc.notJudge && strings.Contains(err.Error(), "not accepted and not refused") {
				t.Errorf("a fault of the program is told as a request that was not judged: %v", err)
			}
		})
	}
}

func withStatus(v handoff.Verdict, i int, st handoff.CheckStatus) handoff.Verdict {
	v.Checks[i].Status = st
	return v
}

func withNotRun(v handoff.Verdict, i int, rules ...string) handoff.Verdict {
	v.Checks[i].NotRun = rules
	return v
}

func TestTheErrorOfACheckThatCouldNotDecideSaysWhichCheckDidNotRunFirst(t *testing.T) {
	v := verdictOf(append(passed(6), handoff.StatusNotRun)...)
	v.Checks[6].Status = handoff.StatusNotRun
	for _, tc := range []struct {
		name    string
		err     error
		verdict handoff.Verdict
		want    []string
		wantNot []string
	}{
		{"no verifier", fmt.Errorf("%w: store piv", handoff.ErrNoVerifier), v,
			[]string{"request stem is not accepted and not refused", "no evidence verifier", "only a request with a software key", "check 7"}, []string{"openpgp"}},
		{"a type that is not built", fmt.Errorf("%w", handoff.ErrTypeNotBuilt), v,
			[]string{"cannot judge a request of this type yet", "check 7"}, []string{"openpgp", "primaries"}},
		{"an openpgp request", fmt.Errorf("%w", handoff.ErrNoPrimaries), verdictOf(passed(2)...),
			[]string{"cannot judge an openpgp-subkey request", "OpenPGP primaries", "not decided", "check 3"}, []string{"software key", "yet"}},
		{"a type that is not built, with a check that names primaries", fmt.Errorf("%w", handoff.ErrTypeNotBuilt), withNotRun(verdictOf(passed(2)...), 2, "primaries"),
			[]string{"cannot judge a request of this type yet", "check 3"}, []string{"openpgp", "OpenPGP primaries"}},
		{"an internal error", handoff.ErrInternal, v, []string{"not accepted and not refused", "check 7"}, []string{"software key", "cannot judge"}},
		{"a config error", handoff.ErrConfig, v, []string{"not accepted and not refused"}, []string{"software key", "cannot judge"}},
		{"a config error that names the clock", fmt.Errorf("%w: the clock is wrong", handoff.ErrConfig), v, []string{"the clock is wrong"}, []string{"OpenPGP primaries", "cannot judge"}},
		{"a plain error", errors.New("the verifier broke"), v, []string{"the verifier broke"}, []string{"software key"}},
		{"no check that did not run", errors.New("x"), verdictOf(passed(9)...), []string{"not accepted and not refused"}, []string{"first check that did not run"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRequestError("stem", tc.verdict, tc.err)
			if !errors.Is(err, tc.err) {
				t.Errorf("the error does not wrap its cause: %v", err)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("%q does not hold %q", err.Error(), w)
				}
			}
			for _, w := range tc.wantNot {
				if strings.Contains(err.Error(), w) {
					t.Errorf("%q holds %q", err.Error(), w)
				}
			}
		})
	}
}

// No verdict that is not an acceptance is exit code 0, whatever rule it names or check it is in. Only the one case
// of the page, no delegation named and check 9 with only the rules of one delegation, is told as "needs a
// delegation"; any other check that did not run says which rules it did not run.
func TestNoRequestThatWasNotAcceptedIsExitZeroAndOnlyTheDelegationCaseAsksForADelegation(t *testing.T) {
	for _, tc := range []struct {
		name       string
		check      int
		rules      []string
		delegation string
		reason     string
		hint       bool
	}{
		{"the two rules of one delegation, in check 9", 9, []string{"delegation-type", "name-constraints"}, "", "check 9 needs a delegation; give --delegation NAME", true},
		{"the name constraints alone, in check 9", 9, []string{"name-constraints"}, "", "check 9 needs a delegation; give --delegation NAME", true},
		{"the delegation type alone, in check 9", 9, []string{"delegation-type"}, "", "check 9 needs a delegation; give --delegation NAME", true},
		{"the two rules, with a delegation named", 9, []string{"delegation-type", "name-constraints"}, "d", "check 9 did not run these rules: delegation-type, name-constraints", false},
		{"the primaries of an OpenPGP request, in check 3", 3, []string{"primaries"}, "", "check 3 did not run these rules: primaries", false},
		{"the primaries in check 9", 9, []string{"primaries"}, "", "check 9 did not run these rules: primaries", false},
		{"a rule that the page does not name, in check 9", 9, []string{"something-else"}, "", "check 9 did not run these rules: something-else", false},
		{"a delegation rule and a rule of another kind", 9, []string{"name-constraints", "primaries"}, "", "check 9 did not run these rules: name-constraints, primaries", false},
		{"a rule of another kind and a delegation rule", 9, []string{"primaries", "name-constraints"}, "", "check 9 did not run these rules: primaries, name-constraints", false},
		{"a rule that only starts like a delegation rule", 9, []string{"name-constraints-x"}, "", "check 9 did not run these rules: name-constraints-x", false},
		{"a rule that is a delegation rule in other case", 9, []string{"Name-Constraints"}, "", "check 9 did not run these rules: Name-Constraints", false},
		{"the same with a delegation named", 3, []string{"primaries"}, "d", "check 3 did not run these rules: primaries", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := verdictOf(passed(tc.check - 1)...)
			v.Checks[tc.check-1].NotRun = tc.rules
			res, err := requestOutcome("stem", tc.delegation, v)
			_ = notJudgedOf(t, res, err)
			if want := "request stem is not accepted and not refused: " + tc.reason; err.Error() != want {
				t.Errorf("error = %q, want %q", err.Error(), want)
			}
			w := warningsOf(err)
			if len(w) != 2 || strings.Contains(w[0], "give --delegation") != tc.hint || w[1] != trustSetWarningText {
				t.Errorf("warnings = %q, hint wanted: %v, and the warning about the trust set last", w, tc.hint)
			}
		})
	}
}

// onlyDelegationRules is the test for "only the rules of one delegation".
func TestOnlyDelegationRulesIsTrueForTheTwoRulesOfOneDelegationAndNothingElse(t *testing.T) {
	for _, tc := range []struct {
		rules []string
		want  bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"delegation-type"}, true},
		{[]string{"name-constraints"}, true},
		{[]string{"name-constraints", "delegation-type"}, true},
		{[]string{"delegation-type", "delegation-type"}, true},
		{[]string{"delegation-type", "primaries"}, false},
		{[]string{"primaries"}, false},
		{[]string{""}, false},
		{[]string{"delegation-type "}, false},
	} {
		if got := onlyDelegationRules(handoff.CheckResult{NotRun: tc.rules}); got != tc.want {
			t.Errorf("onlyDelegationRules(%q) = %v, want %v", tc.rules, got, tc.want)
		}
	}
}

// An accepted verdict is the only one that is exit 0, and it carries the one warning about the trust set.
func TestOnlyAVerdictThatWasAcceptedIsExitZero(t *testing.T) {
	// A verdict can be accepted only by Check, so this uses the library on a real case: x509-software-valid.
	m := crqManifestOf(t)
	c := m.byID(t, "x509-software-valid")
	v, err := crqLibrary(t, m, c)
	if err != nil || !v.Accepted() {
		t.Fatalf("(%+v, %v), want an accepted verdict", v, err)
	}
	res, err := requestOutcome(c.stem(t), crqDelegation, v)
	if err != nil || res == nil || res.ExitCode != ExitOK {
		t.Fatalf("(%v, %v), want exit code 0", res, err)
	}
	if len(res.Warnings) != 1 || res.Warnings[0] != trustSetWarningText {
		t.Errorf("warnings = %q, want the one warning about the trust set", res.Warnings)
	}
	if len(res.Checks) != 9 || res.Message != "" || len(res.Reasons) != 0 {
		t.Errorf("(%v, %q, %v)", res.Checks, res.Message, res.Reasons)
	}
	// A refusal of the same request is not exit 0, has no message of an acceptance, and has the same warning.
	refused := verdictOf(append(passed(2), handoff.StatusFailed)...)
	refused.Code, refused.Detail = "policy", "x"
	res, err = requestOutcome("stem", "d", refused)
	if err != nil || res.ExitCode != ExitRefused || len(res.Warnings) != 1 || res.Warnings[0] != trustSetWarningText {
		t.Errorf("(%v, %v): a refusal has the nine results and so the warning about the trust set", res, err)
	}
}

// One check that is neither explained nor passed makes the whole verdict a fault, whatever else is in it: a
// request is never "not complete" because one check named a rule while another failed with no code.
func TestAFaultInOneCheckIsNotHiddenByAnExplainedNotRunInAnother(t *testing.T) {
	v := verdictOf(append(passed(2), handoff.StatusFailed)...) // check 3 failed and no code was given
	v.Checks[8].NotRun = []string{"delegation-type", "name-constraints"}
	var nj *notJudged
	for _, delegation := range []string{"", "d"} {
		res, err := requestOutcome("stem", delegation, v)
		if err == nil || res != nil || errors.As(err, &nj) {
			t.Errorf("delegation %q: (%v, %v), want a fault of the program and not a request that was not judged", delegation, res, err)
		}
	}
	v = verdictOf(passed(4)...) // checks 5 to 8 did not run and say nothing; check 9 names the rules of a delegation
	v.Checks[8].NotRun = []string{"delegation-type", "name-constraints"}
	res, err := requestOutcome("stem", "", v)
	if err == nil || res != nil || !errors.As(err, &nj) {
		t.Errorf("(%v, %v), want a request that was not judged, the first check of which that did not run is check 5", res, err)
	} else if !strings.Contains(err.Error(), "check 5 did not run") || strings.Contains(err.Error(), "needs a delegation") {
		t.Errorf("error = %q: the first check that did not run is check 5, and it is not about a delegation", err)
	}
}

func TestOnlyTheErrorOfAnOpenPGPRequestWithNoPrimariesIsTheSentenceAboutThePrimaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the error value of the checker", handoff.ErrNoPrimaries, true},
		{"the error value, wrapped", fmt.Errorf("a: %w", handoff.ErrNoPrimaries), true},
		{"wrapped twice", fmt.Errorf("a: %w", fmt.Errorf("b: %w", handoff.ErrNoPrimaries)), true},
		{"joined with another error", errors.Join(errors.New("x"), handoff.ErrNoPrimaries), true},
		// A match on the words is gone: an error that says primaries is not the error of a checker with none.
		{"an ErrConfig that says the words of Check", fmt.Errorf("%w: the checker holds no primaries", handoff.ErrConfig), false},
		{"an ErrConfig that says the words of New", fmt.Errorf("%w: an openpgp-subkey delegation needs primaries", handoff.ErrConfig), false},
		{"an ErrConfig that says only primaries", fmt.Errorf("%w: needs primaries", handoff.ErrConfig), false},
		{"a primary created after the clock", fmt.Errorf("%w: the primary 0123456789abcdef0123456789abcdef01234567 was created after the clock that this check read", handoff.ErrConfig), false},
		{"a primary created after the clock of the checker", fmt.Errorf("%w: the primary 0123456789abcdef0123456789abcdef01234567 was created after the clock of the checker", handoff.ErrConfig), false},
		{"a clock that could not be read", fmt.Errorf("%w: the clock of the checker could not be read (it panicked), so its primaries cannot be held to it", handoff.ErrConfig), false},
		{"a clock outside the years", fmt.Errorf("%w: the clock of the checker could not be read as a time in the years 1970 to 2106, so its primaries cannot be held to it", handoff.ErrConfig), false},
		{"the bare config error", handoff.ErrConfig, false},
		{"a config error about something else", fmt.Errorf("%w: no roots", handoff.ErrConfig), false},
		{"the words and no config error", errors.New("the checker holds no primaries"), false},
		{"an internal error that says primaries", fmt.Errorf("%w: primaries", handoff.ErrInternal), false},
		{"no verifier", fmt.Errorf("%w: store piv", handoff.ErrNoVerifier), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := needsPrimaries(tc.err); got != tc.want {
				t.Errorf("needsPrimaries = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTheSentenceAboutThePrimariesIsOneLineThatStillWrapsTheCheckersError(t *testing.T) {
	cause := fmt.Errorf("%w", handoff.ErrNoPrimaries)
	err := checkRequestError("stem", verdictOf(passed(2)...), cause)
	if !errors.Is(err, handoff.ErrConfig) || !errors.Is(err, cause) {
		t.Errorf("the error does not wrap the checker's error: %v", err)
	}
	for _, w := range []string{"request stem is not accepted and not refused", "this command cannot judge an openpgp-subkey request", "primaries", "where they are read from is not decided"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("%q does not hold %q", err.Error(), w)
		}
	}
	if strings.Contains(err.Error(), "the checker holds no primaries") || strings.Contains(err.Error(), "\n") {
		t.Errorf("the plain sentence carries the words of the library or a line break: %q", err.Error())
	}
	if code, outcome := ExitFor(err); code != ExitFailure || outcome != OutcomeFailed {
		t.Errorf("exit code %d, outcome %q, want 1 and failed", int(code), outcome)
	}
	// The error text is the same sentence whatever the library says in its own words.
	other := primariesError{err: errors.New("x")}
	if other.Error() != primariesSentence {
		t.Errorf("Error() = %q, want %q", other.Error(), primariesSentence)
	}
}

// The name of a check and the name of a rule that did not run come from the library, but every text of a request
// goes through the escape all the same: a hostile name reaches no terminal in the text of a request that was not
// judged, in its error, in its warning or in the object.
func TestAHostileRuleNameReachesNoTerminalInARequestThatWasNotJudged(t *testing.T) {
	hostile := "a\x1b[31m\u202e\nb"
	for _, delegation := range []string{"", "d"} {
		v := verdictOf(passed(8)...)
		v.Checks[0].Name = hostile
		v.Checks[8].NotRun = []string{hostile, "name-constraints"}
		withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
			return requestOutcome("stem", delegation, v)
		}})
		text := run(t, "fake")
		js := run(t, "--output", "json", "fake")
		for _, r := range []result{text, js} {
			if r.code != ExitFailure || !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
				t.Errorf("delegation %q: (%d, %q, %q)", delegation, int(r.code), r.stdout, r.stderr)
			}
			if strings.ContainsAny(r.stdout+r.stderr, "\x1b\u202e") {
				t.Errorf("delegation %q: a control character got through: %q %q", delegation, r.stdout, r.stderr)
			}
		}
		// The text mode keeps the nine lines and the line 10 and ends with the last line; no line is forged by the
		// line break in the name.
		lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n")
		if len(lines) != 11 || !strings.HasPrefix(lines[10], "request stem: not complete: check 9 did not run these rules: ") {
			t.Errorf("delegation %q: standard output has %d lines: %q", delegation, len(lines), text.stdout)
		}
		if strings.Count(text.stderr, "\n") != 3 {
			t.Errorf("delegation %q: standard error = %q, want two warnings and the line of the error", delegation, text.stderr)
		}
		obj := object(t, js.stdout)
		if w, _ := stringList(obj["warnings"]); len(w) != 2 || strings.Contains(w[0], "\n") || w[1] != trustSetWarningText {
			t.Errorf("delegation %q: warnings = %v, want the one of the rules and, last, the one about the trust set", delegation, obj["warnings"])
		}
		if len(crqChecks(t, obj)) != 9 {
			t.Errorf("delegation %q: checks = %v", delegation, obj["checks"])
		}
	}
}

// The object of a request that was not judged carries the error and the nine results, and the same fields as the
// object of a failure; the text mode has nothing on standard output for a failure that is not this one.
func TestTheObjectOfARequestThatWasNotJudgedIsAFailureWithTheNineResults(t *testing.T) {
	v := verdictOf(passed(8)...)
	v.Checks[8].NotRun = []string{"delegation-type", "name-constraints"}
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return requestOutcome("stem", "", v)
	}})
	js := run(t, "--output", "json", "fake")
	obj := object(t, js.stdout)
	wantObject(t, withoutChecks(obj), map[string]any{
		"output": 1, "command": "fake", "exit_code": 1, "outcome": "failed",
		"error":    "request stem is not accepted and not refused: check 9 needs a delegation; give --delegation NAME",
		"warnings": []string{"check 9: rules not run: delegation-type, name-constraints; give --delegation NAME", trustSetWarningText},
	})
	if got := crqChecks(t, obj); len(got) != 9 || got[8] != [2]string{"9", "not-run"} || got[0] != [2]string{"1", "passed"} {
		t.Errorf("checks = %v", got)
	}

	// A failure that is not a request that was not judged has no standard output in the text mode and no checks.
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		return nil, errors.New("plain")
	}})
	if r := run(t, "fake"); r.code != ExitFailure || r.stdout != "" {
		t.Errorf("(%d, %q)", int(r.code), r.stdout)
	}
	if obj := object(t, run(t, "--output", "json", "fake").stdout); obj["checks"] != nil {
		t.Errorf("a plain failure has checks: %v", obj)
	}

	// A request that was not judged and then wrapped by another error still shows the nine results.
	withSpecs(t, spec{name: "fake", usage: "u", run: func(context.Context, *Call) (*Result, error) {
		_, err := requestOutcome("stem", "", v)
		return nil, fmt.Errorf("outer: %w", err)
	}})
	r := run(t, "fake")
	if r.code != ExitFailure || !strings.HasSuffix(r.stdout, "request stem: not complete: check 9 needs a delegation; give --delegation NAME\n") {
		t.Errorf("(%d, %q)", int(r.code), r.stdout)
	}
}
