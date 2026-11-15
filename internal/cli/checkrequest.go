package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	ucli "github.com/urfave/cli/v3"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/wanted"
)

// flagDelegation is the name of the flag of check request that names the delegation to check the request under.
const flagDelegation = "delegation"

// checkRequestSpec is the second word request of check: the checks 1 to 9 of the hand-off contract on one
// request of the bundle, with the policy of ritueel.yaml and, when one is named, a delegation. It signs and
// writes nothing.
var checkRequestSpec = spec{
	name:      "request",
	usage:     "run the checks 1 to 9 of the hand-off contract on requests/STEM, and sign and write nothing",
	argsUsage: "STEM [--delegation NAME]",
	flags:     checkRequestFlags,
	run:       runCheckRequest,
}

func checkRequestFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.StringFlag{Name: flagDelegation, Usage: "check the request under the delegation `NAME` of want/delegations; without it the rules of one delegation are not run"},
	}
}

// ceremonyLine is the line for check 10, which the person at the ceremony makes and this command does not.
const ceremonyLine = "check 10: not made here; the person at the ceremony confirms"

// evidenceVerifiers returns the verifiers of check 7 that a command may use, one for each store. It is the one
// place where a verifier is registered for a command, and apply (a later command) calls it too. It returns an
// empty map for now: no verifier of a card or of a cloud key is wired, so a request of the stores piv,
// openpgp-card and aws-kms stops at check 7 with handoff.ErrNoVerifier, and the command accepts only a request
// with a software key.
func evidenceVerifiers(_ *Call, _ *bundle.Bundle) map[handoff.Store]handoff.EvidenceVerifier {
	return map[handoff.Store]handoff.EvidenceVerifier{}
}

// runCheckRequest checks the request STEM of the bundle. A wrong command line is a usage error (exit code 2).
// What stops the command from judging the request is a failure (exit code 1): a folder that is not a
// bundle, a wanted file that fails its own check, a delegation with no file, no trust set, a request whose
// files cannot be read, an error of the checker (no verifier for the store, a type whose checks are not
// built, an openpgp-subkey request, for which the command has no primaries to give), and a check that did not
// run, whatever the reason and whatever rule it names, with no delegation named among them (check 9 needs
// one). A request that a check refuses is exit code 3, with the code. Exit code 0 is a request that all nine
// checks passed and that Verdict.Accepted says is accepted, and no other. Nothing is written to the bundle.
func runCheckRequest(ctx context.Context, c *Call) (*Result, error) {
	if len(c.Args) != 1 {
		return nil, UsageError{Msg: "check request takes exactly one STEM, the name of a folder of requests/"}
	}
	stem := c.Args[0]
	if !handoff.ValidStem(stem) {
		return nil, UsageError{Msg: "STEM is not 1 to 63 lower-case letters, digits and hyphens, starting with a letter or a digit"}
	}
	name := ""
	if c.FlagCount(flagDelegation) > 1 {
		return nil, UsageError{Msg: "--delegation is given once: it names the one delegation to check the request under"}
	}
	if c.FlagSet(flagDelegation) {
		name = c.FlagString(flagDelegation)
		if name == "" {
			return nil, UsageError{Msg: "--delegation needs a name; leave the flag out to run no delegation rule"}
		}
		if err := wanted.ValidName(name); err != nil {
			return nil, UsageError{Msg: "--delegation: " + err.Error()}
		}
	}
	dir, err := bundleDir(c)
	if err != nil {
		return nil, err
	}
	b, err := bundle.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		// The folder was opened to read it only; nothing was written, so a failed close loses nothing.
		_ = b.Close()
	}()
	checker, _, err := b.Checker(name, c.Env.Now, evidenceVerifiers(c, b))
	if err != nil {
		if needsPrimaries(err) {
			// No request has been read yet, so the fault is the delegation: it is of the type openpgp-subkey,
			// and the checker holds no primaries for it. The request may be of any type.
			return nil, fmt.Errorf("request %s is not accepted and not refused: %w", stem, delegationPrimariesError{name: name, err: err})
		}
		return nil, err
	}
	req, err := b.Request(stem)
	if err != nil {
		return nil, err
	}
	v, err := checker.Check(ctx, req)
	if err != nil {
		return nil, checkRequestError(stem, v, err)
	}
	return requestOutcome(stem, name, v)
}

// trustSetWarning is the one warning of an accepted request: the roots of the checks were read from the newest
// trust set of the bundle, and this command does not check that set's signature file or its expiry.
const trustSetWarning = "trust-set-unchecked: this command did not check the signature and the expiry of the trust set that the roots were read from"

// primariesSentence is the plain sentence for what this command cannot do for an openpgp-subkey request:
// the checker judges one only when it holds the OpenPGP primaries of the root list, and where the command
// should read them from is not decided.
const primariesSentence = "this command cannot judge an openpgp-subkey request: it cannot give the checker the OpenPGP primaries, because where they are read from is not decided"

// primariesError is the error of a request or a delegation that needs the primaries. It reads as the one
// plain sentence and still carries the error of the checker, for errors.Is.
type primariesError struct{ err error }

func (e primariesError) Error() string { return primariesSentence }
func (e primariesError) Unwrap() error { return e.err }

// delegationPrimariesError is the error of a delegation of the type openpgp-subkey that the checker refuses
// because it holds no primaries. The request is not named as the cause: it may be of any type, and it is the
// delegation that this command cannot give primaries for.
type delegationPrimariesError struct {
	name string
	err  error
}

func (e delegationPrimariesError) Error() string {
	return "this command cannot judge a request under the delegation " + jsonset.EscapeExact(e.name) +
		", which is of the type openpgp-subkey: it cannot give the checker the OpenPGP primaries, because where they are read from is not decided"
}
func (e delegationPrimariesError) Unwrap() error { return e.err }

// needsPrimaries tells whether err is the error of the checker that holds no primaries: an openpgp-subkey
// request on a checker with none (Check), or an openpgp-subkey delegation that New refuses without them
// (Checker). Both are handoff.ErrNoPrimaries; no other error is, so a clock that cannot be read, or a primary
// created after the clock, is not taken for it.
func needsPrimaries(err error) bool {
	return errors.Is(err, handoff.ErrNoPrimaries)
}

// checkRequestError is the error of a check that could not decide. The request is not accepted. The text says
// which check did not run first, and, for a request that waits for a part that is not built or not given,
// says so plainly.
func checkRequestError(stem string, v handoff.Verdict, err error) error {
	where := ""
	for _, c := range v.Checks {
		if c.Status == handoff.StatusNotRun {
			where = fmt.Sprintf(" (the first check that did not run is check %d)", c.N)
			break
		}
	}
	var extra string
	switch {
	case needsPrimaries(err):
		return fmt.Errorf("request %s is not accepted and not refused: %w%s", stem, primariesError{err: err}, where)
	case errors.Is(err, handoff.ErrNoVerifier):
		extra = "; this command registers no verifier of a card or of a cloud key, so it accepts only a request with a software key"
	case errors.Is(err, handoff.ErrTypeNotBuilt):
		extra = "; this command cannot judge a request of this type yet"
	}
	return fmt.Errorf("request %s is not accepted and not refused: %w%s%s", stem, err, extra, where)
}

// notJudged is the error of a request that no check refused and that the checks did not all pass: some check
// did not run. It is exit code 1. It carries what a person needs to see all the same: the nine lines and the
// last line on standard output, and the nine results in the member checks of the object. text is for the
// text mode, checks for the JSON mode; the message is the one line of standard error and the member error.
type notJudged struct {
	msg    string
	text   string
	checks []CheckState
}

func (e *notJudged) Error() string { return e.msg }

// requestOutcome turns a verdict that came with no error into the result. It is the one place that decides
// what the verdict means: accepted only when Verdict.Accepted says so (never from Refused or Complete), a
// refusal when a check refused, and otherwise a request that was not judged in full: exit code 1, whatever
// check did not run and whatever rule it names. A verdict that is none of these and has no check that did
// not run is a fault of the program, and exit code 1 too.
func requestOutcome(stem, delegation string, v handoff.Verdict) (*Result, error) {
	checks := make([]CheckState, len(v.Checks))
	for i, ch := range v.Checks {
		checks[i] = CheckState{N: ch.N, Result: string(ch.Status)}
	}
	switch {
	case v.Accepted():
		return &Result{
			ExitCode: ExitOK,
			Warnings: []string{trustSetWarning},
			Checks:   checks,
			Text:     checkLines(v) + "request " + stem + ": accepted\n",
		}, nil
	case v.Refused():
		code := jsonset.Escape(string(v.Code))
		n := 0
		for _, ch := range v.Checks {
			if ch.Status == handoff.StatusFailed {
				n = ch.N
				break
			}
		}
		return &Result{
			ExitCode: ExitRefused,
			Reasons:  []string{string(v.Code)},
			Checks:   checks,
			Message:  fmt.Sprintf("refused: %s (check %d: %s)", v.Code, n, v.Detail),
			Text:     checkLines(v) + "request " + stem + ": refused: " + code + "\n",
		}, nil
	}
	if len(v.Checks) != 9 {
		return nil, fmt.Errorf("request %s: the checks gave neither an acceptance nor a refusal, and %d checks are not nine", stem, len(v.Checks))
	}
	var warnings []string
	var first *handoff.CheckResult
	delegationOnly := true
	for i, ch := range v.Checks {
		switch {
		case ch.Status == handoff.StatusPassed && len(ch.NotRun) == 0:
			continue
		case ch.Status != handoff.StatusNotRun && ch.Status != handoff.StatusPassed:
			return nil, fmt.Errorf("request %s: the checks gave neither an acceptance nor a refusal, and check %d did not pass or was not run", stem, ch.N)
		}
		if first == nil {
			first = &v.Checks[i]
		}
		if len(ch.NotRun) > 0 {
			w := fmt.Sprintf("check %d: rules not run: %s", ch.N, strings.Join(ch.NotRun, ", "))
			if delegation == "" && onlyDelegationRules(ch) {
				w += "; give --delegation NAME"
			}
			warnings = append(warnings, w)
		}
		if delegation != "" || !onlyDelegationRules(ch) {
			delegationOnly = false
		}
	}
	if first == nil {
		return nil, fmt.Errorf("request %s: the checks gave neither an acceptance nor a refusal", stem)
	}
	reason := fmt.Sprintf("check %d did not run", first.N)
	if len(first.NotRun) > 0 {
		reason = fmt.Sprintf("check %d did not run these rules: %s", first.N, strings.Join(first.NotRun, ", "))
	}
	if delegationOnly {
		reason = fmt.Sprintf("check %d needs a delegation; give --delegation NAME", first.N)
	}
	return nil, WithWarnings(&notJudged{
		msg:    "request " + stem + " is not accepted and not refused: " + reason,
		text:   checkLines(v) + "request " + stem + ": not complete: " + jsonset.Escape(reason) + "\n",
		checks: checks,
	}, warnings...)
}

// delegationRules are the rules of check 9 that the library leaves out when no delegation is given, for every
// type of request that has one: "delegation-type" and "name-constraints" for an x509-intermediate request,
// "delegation-type" and "capability" for an openpgp-subkey request. The library does not export them
// (handoff.notRunWithoutDelegation is its one list), so this list is kept here and a test compares it with the
// names that the library returns for each type.
var delegationRules = []string{"delegation-type", "name-constraints", "capability"}

// onlyDelegationRules tells whether the rules a check did not run are all rules of one delegation, which the
// library leaves out when no delegation is given ([delegationRules]).
func onlyDelegationRules(ch handoff.CheckResult) bool {
	if len(ch.NotRun) == 0 {
		return false
	}
	for _, r := range ch.NotRun {
		if !slices.Contains(delegationRules, r) {
			return false
		}
	}
	return true
}

// checkLines is one line for each of the nine checks, in the form "check N: RESULT: NAME" with a clause for
// the rules that did not run, and then the line of check 10. The names are the fixed words of the library; the
// text goes through the escape all the same, as every text of a request does.
func checkLines(v handoff.Verdict) string {
	var b strings.Builder
	for _, ch := range v.Checks {
		fmt.Fprintf(&b, "check %d: %s: %s", ch.N, jsonset.Escape(string(ch.Status)), jsonset.Escape(ch.Name))
		if len(ch.NotRun) > 0 {
			rules := make([]string, len(ch.NotRun))
			for i, r := range ch.NotRun {
				rules[i] = jsonset.Escape(r)
			}
			fmt.Fprintf(&b, " (rules not run: %s)", strings.Join(rules, ", "))
		}
		b.WriteByte('\n')
	}
	b.WriteString(ceremonyLine)
	b.WriteByte('\n')
	return b.String()
}
