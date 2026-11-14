package handoff

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"maps"
	"slices"
)

// CheckStatus is the result of one check.
type CheckStatus string

// The three results of a check. They are never mixed: a check that did not run, or in which a rule did
// not run, is never passed.
const (
	// StatusPassed means every rule of the check ran and none refused.
	StatusPassed CheckStatus = "passed"
	// StatusFailed means a rule of the check refused the request. Its code is the verdict's.
	StatusFailed CheckStatus = "failed"
	// StatusNotRun means the check did not run, or a rule inside it did not (see CheckResult.NotRun).
	StatusNotRun CheckStatus = "not-run"
)

// The names of the nine checks, in the words of "What the certifier checks".
var checkNames = [9]string{
	"The contract version is known",
	"The files parse, with no unknown or repeated member",
	"request_sha256 is the digest of the request",
	"The key is ECDSA P-384",
	"The request's signature verifies with its own key",
	"The store is allowed by the policy",
	"The evidence is valid",
	"The key in the evidence is the key in the request",
	"The policy accepts the request",
}

// CheckResult is the result of one of the nine checks.
type CheckResult struct {
	// N is the number of the check, 1 to 9.
	N int
	// Name is the check in the words of the contract.
	Name string
	// Status is the result.
	Status CheckStatus
	// NotRun names the rules inside the check that could not run. In this package that is "primaries" of
	// check 3 for an openpgp-subkey, whose rule needs the signed root list, which is not built, and
	// "delegation-type" and "name-constraints" of check 9 when the configuration holds no delegation. It is
	// empty when every rule ran, and always empty for a check that failed or passed.
	NotRun []string
}

// Verdict is what the nine checks found for one request, and it is not an answer by itself: read it
// with the error that [Checker.Check] returned beside it. Only [Verdict.Accepted] means that the request
// is accepted. Code, Refused, Complete and the results of the checks say what was found and never that
// the request is accepted: a verdict that [Verdict.Refused] says no, and one that is not refused says
// nothing until every check has passed (see [Verdict.Accepted]). An error that Check returned always means
// that the request is not accepted, whatever the verdict beside it holds.
type Verdict struct {
	// Code is the reason code of the first check that refused, and empty when no check refused.
	Code Code
	// Detail says what the refusing check found, in fixed words that are safe to print: every text that
	// came from the request or from a verifier is escaped. It is empty when no check refused. The answer
	// file does not carry it ("The answer"); the ceremony's output does.
	Detail string
	// Checks are the nine results, always nine and in order.
	Checks []CheckResult
	// Key is the key of the request, and it is set only in an accepted verdict: a verdict that is not
	// accepted holds no key, so that no key that has not passed all nine checks is taken for one that has.
	// It is a copy.
	Key *ecdsa.PublicKey
	// Evidence is what the verifier of the store read, and it is set only in an accepted verdict, for the
	// same reason as Key. It is a copy of what the verifier returned, so a later write by the verifier
	// changes nothing here. A software key has the evidence {Unprotected: true}.
	Evidence *Evidence

	// accepted is set by Checker.Check and by nothing else, when it returned no error and every check
	// passed. No other package can set it, so a Verdict that was made or changed by hand is never accepted.
	accepted bool
}

// Accepted reports whether the request is accepted, and it is the only call that does. It is true when
// [Checker.Check] returned no error, no check refused (Code is empty), and all nine checks ran and passed,
// each with every rule in it. It is false for a refusal, for a check that did not run or ran in part
// (not-run), for a request of a type that is not built, for a store with no verifier, and for any error of
// Check, and it is false for a Verdict that was not returned by Check. Test it, and not [Verdict.Refused]
// or [Verdict.Complete], which each say less.
func (v Verdict) Accepted() bool {
	if !v.accepted || v.Code != "" || len(v.Checks) != 9 {
		return false
	}
	for _, c := range v.Checks {
		if c.Status != StatusPassed || len(c.NotRun) != 0 {
			return false
		}
	}
	return true
}

// Refused reports whether a check refused the request. It does not say that the request is accepted when
// it is false: a request of a type that is not built, a store with no verifier and every error of
// [Checker.Check] give a verdict that is not refused. Only [Verdict.Accepted] means accepted.
func (v Verdict) Refused() bool { return v.Code != "" }

// Complete reports whether every check ran: no check is not-run. It is true for a verdict that check 9
// refused (all nine ran, the ninth failed), so it is not an acceptance, and it says nothing about the error
// that [Checker.Check] returned beside the verdict. Only [Verdict.Accepted] means accepted.
func (v Verdict) Complete() bool {
	if len(v.Checks) != 9 {
		return false
	}
	for _, c := range v.Checks {
		if c.Status == StatusNotRun {
			return false
		}
	}
	return true
}

// newVerdict returns a verdict with the nine checks, all not-run.
func newVerdict() Verdict {
	v := Verdict{Checks: make([]CheckResult, 9)}
	for i := range v.Checks {
		v.Checks[i] = CheckResult{N: i + 1, Name: checkNames[i], Status: StatusNotRun}
	}
	return v
}

// pass marks check n passed.
func (v *Verdict) pass(n int) { v.Checks[n-1].Status = StatusPassed }

// partial marks check n not-run because the rules in notRun could not run; the rules that could run
// have passed.
func (v *Verdict) partial(n int, notRun []string) {
	v.Checks[n-1].Status = StatusNotRun
	v.Checks[n-1].NotRun = slices.Clone(notRun)
}

// fail marks check n failed with the code and the detail, and the verdict refused. A check after it stays not-run.
func (v *Verdict) fail(n int, code Code, detail string) {
	v.Checks[n-1].Status = StatusFailed
	v.Code = code
	v.Detail = detail
}

// accept marks the verdict accepted, with copies of the key of the request and of the evidence. It is the
// last thing Check does, and only when no check refused and no error is returned.
func (v *Verdict) accept(key *ecdsa.PublicKey, ev *Evidence) {
	v.accepted = true
	v.Key = copyKey(key)
	v.Evidence = copyEvidence(ev)
}

// pointOf returns the bytes of an uncompressed point of k. It reports false for a key that has no point to
// write: a nil key, a key with no curve, or with no X or no Y, and a key that is not a point of its curve.
// It never panics: a key that a verifier or the configuration gives is not trusted to be whole.
func pointOf(k *ecdsa.PublicKey) (point []byte, ok bool) {
	if k == nil || k.Curve == nil {
		return nil, false
	}
	// A key with a curve and no X or no Y makes Bytes panic, and X and Y are not read here (the standard
	// library marks them as deprecated), so the panic is taken and is the answer "no point".
	defer func() {
		if recover() != nil {
			point, ok = nil, false
		}
	}()
	b, err := k.Bytes()
	if err != nil {
		return nil, false
	}
	return b, true
}

// copyKey returns a key that shares nothing with k, or nil when k is nil, has no point, or is not a point
// of P-384.
func copyKey(k *ecdsa.PublicKey) *ecdsa.PublicKey {
	b, ok := pointOf(k)
	if !ok {
		return nil
	}
	c, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), b)
	if err != nil {
		return nil
	}
	return c
}

// copyEvidence returns evidence that shares nothing with e.
func copyEvidence(e *Evidence) *Evidence {
	if e == nil {
		return nil
	}
	c := *e
	c.Key = copyKey(e.Key)
	c.SignPrincipals = slices.Clone(e.SignPrincipals)
	c.Details = maps.Clone(e.Details)
	return &c
}
