// Package answer is the requester's side of the hand-off contract (docs/reference/hand-off-contract.md):
// it judges an answer that came back from a certifier by the tables "What the requester checks before it
// installs", and says whether the requester may install it. Package handoff is the certifier's side and
// judges a request; this package judges what the certifier sent back. It is a library with no command.
//
// What is built. An answer for an x509-intermediate request is judged by nine checks on the full
// contract (the files `<stem>.result.json` and `<stem>.cert.pem`) or, with a [Config] that holds installed
// CA certificates and no root list, by the floor: the one file `<stem>.cert.pem`, nine slots of which four
// are fixed as not-run and named so. An answer for an openpgp-subkey request is judged by eight checks (the
// files `<stem>.result.json` and `<stem>.bound.pgp`). An answer for an ssh-ca-key request is not judged:
// its checks need the reader of the signed SSH CA key list, which is not built, and [Checker.Check] returns
// [ErrTypeNotBuilt] for it.
//
// A [Checker] is made by [New] from a [Config], holds its own copy of everything in it, and changes nothing
// afterwards, so one Checker serves any number of calls at the same time. The zero value was not made by
// New and refuses every call with [ErrConfig]. [New] refuses a configuration with a part left empty: no
// rule is switched off by a field that was left out. The trust of the requester is the root list it holds
// and the CA bundle of that list (the full contract), or the CA certificates it installed (the floor), and
// never anything that the answer carries: the anchor of an X.509 answer is the certificate of the bundle
// whose key has the pin that the answer names and that is on the held list, not one chosen by an issuer
// name or by the order of the bundle, and the primary of an OpenPGP answer is one that the requester named
// in its own request and holds in its configuration, whose fingerprint is on the held list.
//
// What the requester asked is an [Asked], made from the files of its own request ([AskedFromRequest],
// [AskedX509]); what came back is an [Answer], read by [LoadAnswer] or made by hand. [Checker.Check] runs
// the checks in the order of the table of the answer's type, and stops at the first that fails: the checks
// before it are passed and the checks after it are not-run, and a verdict never reads a check that did not
// run as passed. A refusal is in the [Verdict]; the error is non-nil only when the checker cannot decide
// ([ErrConfig], [ErrTypeNotBuilt], [ErrUnsupported], [ErrFloorHasResult], [ErrNoPrimaryKey], [ErrInternal]),
// and an error always means that the answer is not accepted.
//
// Only [Verdict.Accepted] means that the requester may install the answer. A zero Verdict, a verdict made
// or changed by hand, a verdict that came with an error, and a verdict that holds a failed check or a check
// that did not run (but the four fixed slots of the floor) are never accepted. [Verdict.Info] is set only in
// an accepted verdict. A well-formed answer in which the certifier refused the request is not accepted and
// is not a fault of the answer: [Verdict.RequestRefused] says so and [Verdict.CertifierReasons] holds the
// reasons.
//
// The floor holds the installed CA certificate and the answer to a named list, set down in one place
// (floorListFault): a CA key that is ECDSA on P-256, P-384 or P-521, Ed25519, or RSA of 2048 bits or more, and a
// signature of ECDSA or RSA (PKCS #1 version 1.5 or PSS) with SHA-256, SHA-384 or SHA-512, or Ed25519. The list is
// applied before the signature is verified; anything else, a SHA-1 or MD5 signature included, is refused with the
// code issuer. The full contract keeps ECDSA on P-384 with SHA-384 only.
//
// The signature is verified more than once on the full X.509 contract. An accepted X.509 answer is verified
// twice: once by the issuer check (check 4) against the anchor, and once more by the comparison with the exact
// form that the builder of package pki writes (check 8, pki.Assemble), which verifies the signature again before
// it hands back the certificate. A refused answer is verified at most once, by check 4, with one exception: an
// answer that passes check 4 and is refused at check 8 only because its bytes differ from the builder's, with the
// body and the signature in order, has been verified by both. Both verifications stay: the first gives the code
// issuer to a signature that does not verify, and the second gives the code profile to a certificate that is
// not the exact form. An OpenPGP answer is verified once. A floor answer is verified once for each installed
// certificate that has the name of its issuer, at most [MaxAnchors].
//
// The package reads untrusted files. Each file is at most [MaxFileSize] bytes, each list in the result file
// has a bound that is checked before an entry is read, every loop over a certificate or a packet has a
// named limit, no link is followed on a path ([LoadAnswer] reads by package fsx), every refusal text is
// fixed words and numbers, and any text that came from a file goes through package jsonset before it is
// shown. A panic in a call is turned into [ErrInternal], and never into an acceptance. The clock is read
// once for each call, cut to whole seconds, and a time outside the years 1970 to 2106 is an [ErrInternal].
package answer
