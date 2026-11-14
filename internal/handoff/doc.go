// Package handoff is the certifier's side of the hand-off contract (docs/reference/hand-off-contract.md):
// it loads the files of one request and runs the checks of "What the certifier checks", in order, and
// returns a [Verdict] with the result of each of the nine checks. Check 10, the confirmation of the
// person at the ceremony, is the ceremony's and is not made here.
//
// What is built. A request of type x509-intermediate whose key is in software is judged by all nine
// checks. A request of type x509-intermediate whose key is in a card or in a cloud service is judged by
// all nine checks too, with the evidence verifier of its store, which the caller supplies in
// [Config.Evidence] (check 7); with none registered the verdict stops at check 7 and the error is
// [ErrNoVerifier]. A request of type openpgp-subkey or ssh-ca-key is judged by checks 1 to 3 (for an
// openpgp-subkey only the digest part of check 3) and then the error is [ErrTypeNotBuilt]: the rest of
// those types is not built.
//
// A [Checker] is made by [New] from a [Config], and a Checker that was not made by New refuses every
// request with [ErrConfig]. New refuses a configuration with no policy (stores, a minimum firmware, the PIN
// policies that are allowed), no delegation, no roots or no clock, or with a verifier that is nil: no rule
// is switched off by a field that was left empty. The Checker keeps its own copy of the configuration.
//
// The package reads an untrusted request. It reads each file once, copies what it needs at the top of
// a call, and gives the same bytes of a certificate request to every function of package pki that reads
// it, in the order that package asks for: first the key ([pki.RequestKeyFile]; checks 2, 4 and 5), then
// the content ([pki.ParseRequestFile]), whose two readings are compared with each other before the result
// of any of checks 6 to 8 is used, then the checks that need only the key (3, 6, 7 and 8), and at last the
// refusal of the content and the policy, which the contract counts in check 9. It does not read a
// certificate request a second time by a reader of its own: the only thing it does with the PEM text is
// take the DER out of a file that package pki has already accepted as one block, to hash it (check 3).
//
// A check has one of three results, and the three are never mixed: passed (every rule of the check ran
// and none refused), failed (a rule refused; the code of the refusal is the verdict's), and not-run
// (the check, or a rule inside it, could not run). Every check after a failed one is not-run. A rule
// that could not run is not-run and is named in [CheckResult.NotRun]; it is never reported as passed.
//
// Only [Verdict.Accepted] means that a request is accepted: it is true when no error was returned, no check
// refused and all nine checks ran and passed. [Verdict.Refused] and [Verdict.Complete] say less, and a
// caller that reads a request as accepted from either of them accepts a request that check 9 refused or
// that was never judged.
//
// A [Checker] returns an error, besides a verdict, only when it cannot decide: the type is not built,
// no verifier is registered, a verifier failed for a reason that is not a refusal of the evidence or
// panicked, the checker was not made by [New] ([ErrConfig]), or two readers disagreed about one request
// ([ErrInternal]). An error always means that the request is not accepted, and is never a refusal of
// the request.
//
// A malformed or hostile request never panics here: every length is bounded before it is used (a file is
// at most [MaxFileSize] bytes, as for a JSON file in the contract), every refusal text is fixed words
// and numbers, and any text that came from a request goes through [jsonset.Escape] before it is
// put into an error.
//
// The evidence verifiers for the key stores piv and openpgp-card are in the packages under
// internal/handoff/evidence: attest (the pinned set of the maker's certificates and the chain rule),
// piv, openpgpcard and, for tests, attesttest. Each verifier is an [EvidenceVerifier] that the caller puts
// in [Config.Evidence]; no command registers one yet, because no real maker bundle is shipped.
package handoff
