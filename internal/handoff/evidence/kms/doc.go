// Package kms is check 7 of the hand-off contract for the store aws-kms (docs/reference/hand-off-contract.md,
// "aws-kms" and "Evidence for KMS (check 7)"), as a library that needs no AWS client.
//
// A KMS key has no attestation. The evidence for it is what the certifier reads from the service itself
// (record 0004, rules 7 and 12): the description of the key, its public key and its key policy. The proof's
// own copy of the public key is a claim and is never used as evidence; check 8 of package handoff compares
// it with the key that KMS returns.
//
// The package asks the service through two small interfaces. An [API] makes the three read calls for one
// role (or for the certifier's own credentials), and a [Connector] opens an API, assuming a role first when
// it is given one. The AWS client is not part of this package: it implements both interfaces and is
// registered by the caller. Package kmsreplay answers the same interfaces from a recorded file, for the
// test vectors and for tests.
//
// [Verifier] is the plug that package handoff calls (handoff.EvidenceVerifier). [Read] is the read of one
// key, and [SignPrincipals] reads a key policy and returns the principals of every statement that allows
// kms:Sign, which check 9 counts (the single-principal rule).
//
// What the package never does. It never takes the role to assume from a request: the roles come from the
// delegation's list of read roles, by the account of the key, and the proof has no member that could name
// one. It never makes a call after a rule has refused, and it returns evidence only when every rule ran
// and passed. It never reads the audit trail of a key. It never reads a file, opens a connection or starts
// a program. Text that comes from the service or from a key policy is bounded and escaped before it is put
// into an error or into the evidence.
//
// Two kinds of failure are told apart. A [Refusal] (wrapped by the verifier into a handoff.CodeError with
// the code proof-invalid) says that the key or its policy is not what the contract needs. [ErrUndecided]
// says that the service could not be asked or did not answer; it is never a refusal and never an
// acceptance.
package kms
