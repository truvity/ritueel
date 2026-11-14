// Package attest is what the evidence verifiers of the key stores piv and openpgp-card share: the pinned
// set of the maker's certificates ([Bundle]), the list of two certificates that a proof carries
// ([Attestation]) and the rule that leads that list to a pinned root ([Bundle.Verify]). It is check 7 of
// "What the certifier checks" in docs/reference/hand-off-contract.md for the two stores that stand on an
// attestation certificate; the packages piv and openpgpcard read the values of the key's certificate once
// this package has verified the chain.
//
// The package reads untrusted bytes only. It opens no file, makes no network call, starts no program and
// no goroutine, and holds no state that a call changes: a [Bundle] is immutable and serves any number of
// calls at the same time. No real maker's certificate is shipped with it. The caller builds the pinned set
// with [NewBundle], and the only sets in this repository are the made-up "Example Test" roots of
// testdata/hand-off/v1/pki and the ones that tests make in memory.
//
// A refusal of the evidence is a *[handoff.CodeError] whose Detail is a fixed sentence: no text, name or
// time of a certificate is ever copied into it. An error that is not a *[handoff.CodeError] is a fault of
// the caller (a nil bundle, a clock that was not set, a store that is not the verifier's own) and is never
// a verdict on the evidence.
package attest
