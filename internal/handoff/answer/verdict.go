package answer

import (
	"slices"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// The names of the checks, in the words of the requester's tables ("What the requester checks before it
// installs"). The full contract has nine checks for X.509 and eight for OpenPGP, the floor has nine slots.
var (
	x509Names = [9]string{
		"The version of the answer is the one that was sent",
		"The files parse",
		"The answer is for this request",
		"The certificate verifies to an anchor of the root list that the requester holds",
		"The public key is its own key",
		"The profile is what was asked",
		"The validity is the length that was expected and has not ended",
		"The certificate is exactly the form of the page",
		"The digests and dates of result.json match the files",
	}
	floorNames = [9]string{
		"The version of the answer is the one that was sent",
		"The files parse",
		"The answer is for this request",
		"The certificate verifies to a CA certificate that the operator installed",
		"The public key is its own key",
		"The profile is what was asked",
		"The validity is the length that was expected and has not ended",
		"The certificate is exactly the form of the page",
		"The digests and dates of result.json match the files",
	}
	pgpNames = [8]string{
		"The version of the answer is the one that was sent",
		"The files parse",
		"The answer is for this request",
		"The first packet is its own subkey",
		"The binding verifies, and the primary is one that the requester named",
		"The profile is what was asked",
		"The expiry is the length that was expected and has not passed",
		"The digests and dates of result.json match the files",
	}
)

// The reasons of a check that is not-run. They are fixed words.
const (
	reasonEarlier     = "a check before it did not pass"
	reasonNoVersion   = "the version could not be read"
	reasonRefused     = "the certifier refused the request"
	reasonNoKey       = "the checker holds no key for the primary of the answer"
	reasonFloorResult = "the floor has no result file"
	reasonFloorForm   = "the floor does not ask a foreign CA for the form of ritueel's certificates"
)

// floorFixed gives the reason of each slot of the floor that is always not-run, by slot number (1 to 9), and
// the empty string for a slot that is run.
var floorFixed = [10]string{
	1: reasonFloorResult,
	3: reasonFloorResult,
	8: reasonFloorForm,
	9: reasonFloorResult,
}

// CheckResult is one check and its result.
type CheckResult struct {
	// N is the number of the check, from 1.
	N int
	// Name is the check in the words of the contract.
	Name string
	// Status is [handoff.StatusPassed], [handoff.StatusFailed] or [handoff.StatusNotRun], the same type and
	// constants as the certifier's.
	Status handoff.CheckStatus
	// Reason says why a check is not-run, in fixed words; it is empty for a check that ran.
	Reason string
}

// Info is what an installer needs from an accepted answer.
type Info struct {
	// Type is the type of the request that was answered.
	Type handoff.Type
	// Stem is the stem of the answer.
	Stem string
	// ValidFrom is the notBefore of the certificate, or the creation time of the binding.
	ValidFrom time.Time
	// ValidUntil is the notAfter of the certificate, or the end of the subkey.
	ValidUntil time.Time
	// Issuer is the pin of the issuing root (64 digits) or the fingerprint of the primary (40 digits); on the
	// floor it is the pin of the installed CA certificate that verified the answer.
	Issuer string
	// TrustSequence is the trust_sequence of the answer, and 0 on the floor, which has none.
	TrustSequence int64
}

// Verdict is what the checks found for one answer. Only [Verdict.Accepted] says that the requester may install
// it. Read it with the error that [Checker.Check] returned: an error always means that the answer is not
// accepted, whatever the verdict beside it holds.
type Verdict struct {
	// Code is the code of the first check that refused the answer, and empty when none did.
	Code Code
	// Detail says what the refusing check found, in fixed words that are safe to print: a byte of the answer
	// is never in it without the escape of package jsonset.
	Detail string
	// Checks are the results, nine for X.509 (full or floor) and eight for OpenPGP, always in order. A zero
	// Verdict has none.
	Checks []CheckResult
	// Warnings holds "held-expired" ([rootlist.WarningHeldExpired]) when the expires_at of the root list that
	// the requester holds has passed.
	Warnings []string
	// CertifierReasons holds the reasons of the certifier when the answer is a well-formed refusal by the
	// certifier (outcome refused), and is empty otherwise.
	CertifierReasons []handoff.Code
	// Info is set only in an accepted verdict, and holds copies.
	Info *Info

	accepted bool
	floor    bool
}

// Accepted reports whether the requester may install the answer, and it is the one call that does. It is true
// when [Checker.Check] returned no error, Code is empty, [Verdict.CertifierReasons] is empty, Info is set, and
// every check passed, each with no reason for not running. For a verdict of a floor checker the four slots that
// the floor cannot run (1, 3, 8 and 9) are the one exception: they are not-run, and every other slot passed.
// A zero Verdict, a Verdict that was made or changed by hand, and a Verdict that came with an error are never
// accepted: the flag that this call reads is set by Check and by nothing else.
//
// A floor verdict is accepted with four checks that were not run: the floor has no result file and no root
// list, so the version, the request digest and the two checks of the digests and dates are not made. A checker is
// a floor checker or a full one for its whole life ([New] refuses a [Config] that has both FloorAnchors and Held), so the same answer can be accepted by one and refused by the other. A caller that needs the full
// contract makes a full checker, and does not test Accepted of a floor checker; a caller that holds both kinds
// reads [Verdict.Floor] beside Accepted.
func (v Verdict) Accepted() bool {
	if !v.accepted || v.Code != "" || len(v.CertifierReasons) != 0 || v.Info == nil {
		return false
	}
	want := 9
	if v.Info.Type == handoff.TypeOpenPGP {
		want = 8
	}
	if len(v.Checks) != want || (v.floor && want != 9) {
		return false
	}
	for i, c := range v.Checks {
		if v.floor && floorFixed[i+1] != "" {
			if c.Status != handoff.StatusNotRun {
				return false
			}
			continue
		}
		if c.Status != handoff.StatusPassed {
			return false
		}
	}
	return true
}

// Floor reports whether the verdict is one of a floor checker. A floor verdict is accepted on its own terms,
// with four checks that were not run: slots 1, 3, 8 and 9 are not-run, named with their reasons in Checks,
// and never passed. Accepted is true for it all the same, so a caller that needs the full contract must not
// take Accepted alone from a floor checker: a checker is a floor checker or a full one for its whole life, and
// that caller makes a full checker. The floor says
// nothing of the certifier's checks 6 to 8, the checks of where the key lives (the evidence of the key store
// and the key in it), which a floor requester does not see: nobody but the requester itself checked where
// its key lives.
func (v Verdict) Floor() bool { return v.floor }

// AnswerRefused reports whether the requester refuses the answer: a check failed, and Code says which.
func (v Verdict) AnswerRefused() bool { return v.Code != "" }

// RequestRefused reports whether the answer is whole and says that the certifier refused the request:
// [Verdict.CertifierReasons] holds its reasons. It is not an acceptance and not a fault of the answer.
func (v Verdict) RequestRefused() bool { return len(v.CertifierReasons) != 0 }

// newVerdict returns a verdict with the given checks, all not-run for the reason that a check before it did not
// pass.
func newVerdict(names []string, floor bool) Verdict {
	v := Verdict{Checks: make([]CheckResult, len(names)), floor: floor}
	for i, name := range names {
		v.Checks[i] = CheckResult{N: i + 1, Name: name, Status: handoff.StatusNotRun, Reason: reasonEarlier}
		if floor && floorFixed[i+1] != "" {
			v.Checks[i].Reason = floorFixed[i+1]
		}
	}
	return v
}

// pass marks check n passed.
func (v *Verdict) pass(n int) {
	v.Checks[n-1].Status = handoff.StatusPassed
	v.Checks[n-1].Reason = ""
}

// skip gives a not-run check the reason why it did not run.
func (v *Verdict) skip(n int, reason string) { v.Checks[n-1].Reason = reason }

// skipFrom gives the reason to check n and every check after it that is not-run and has no fixed reason.
func (v *Verdict) skipFrom(n int, reason string) {
	for i := n - 1; i < len(v.Checks); i++ {
		if v.Checks[i].Status == handoff.StatusNotRun && (!v.floor || floorFixed[i+1] == "") {
			v.Checks[i].Reason = reason
		}
	}
}

// fail marks check n failed with the code and the detail. The checks after it stay not-run.
func (v *Verdict) fail(n int, code Code, detail string) {
	v.Checks[n-1].Status = handoff.StatusFailed
	v.Checks[n-1].Reason = ""
	v.Code = code
	v.Detail = detail
}

// accept marks the verdict accepted with the information of the answer. It is the last thing a check does, and
// only when every check passed and no error is returned.
func (v *Verdict) accept(info Info) {
	v.accepted = true
	c := info
	v.Info = &c
}

// refusedByCertifier sets the verdict of a well-formed answer in which the certifier refused the request: it
// is not accepted, no check failed, and the checks after the checks of the form are not-run for that reason.
func (v *Verdict) refusedByCertifier(after int, reasons []handoff.Code) {
	v.CertifierReasons = slices.Clone(reasons)
	v.skipFrom(after+1, reasonRefused)
}
