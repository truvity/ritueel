// Package openpgpcard is check 7 of the hand-off contract for the key store openpgp-card: the evidence of
// a key in the OpenPGP applet of a card, which is the certificate the card returns for the key and the
// card's own certificate ("Evidence for an OpenPGP-card key (check 7)" and the section openpgp-card of
// docs/reference/hand-off-contract.md). [Verifier] verifies that the chain leads to a pinned maker root
// through the maker's OpenPGP intermediates, and returns the attested key.
//
// The encoding of the extensions of the OpenPGP attestation is not measured yet (record 0003, "Not yet
// proven"), and the page gives the key's certificate no subject to read. So the subject and the extensions
// are not read, and the evidence holds no firmware, no PIN policy and no touch policy: check 9 enforces none
// for this store, and Details["policy_read"] is "false" so that the ceremony can say that the policy was not
// read.
package openpgpcard

import (
	"context"
	"errors"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
)

// Verifier is check 7 for the store openpgp-card. It is made by [New], is immutable and is safe for
// concurrent use. The zero Verifier refuses every call (with an error that is not a verdict on the
// evidence).
type Verifier struct {
	b *attest.Bundle
}

var _ handoff.EvidenceVerifier = (*Verifier)(nil)

// New returns the verifier of openpgp-card evidence that trusts the pinned set b. A nil bundle is an error.
func New(b *attest.Bundle) (*Verifier, error) {
	if b == nil {
		return nil, errors.New("openpgpcard: no attestation bundle")
	}
	return &Verifier{b: b}, nil
}

// Verify implements [handoff.EvidenceVerifier] for the store openpgp-card. r is not read. The chain runs
// through the OpenPGP intermediates of the bundle and never through the piv ones. It returns the attested
// key and Details with "policy_read" = "false" and the version and the digest of the bundle; Firmware,
// PINPolicy and TouchPolicy are empty. A refusal is a *[handoff.CodeError] with proof-invalid or
// malformed. A done or nil context, a nil proof, a proof of another store, a zero now and a zero Verifier
// are errors that are not a refusal.
func (v *Verifier) Verify(ctx context.Context, r *handoff.Request, p *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
	if v == nil || v.b == nil {
		return nil, errors.New("openpgpcard: the verifier was not made by New")
	}
	att, err := v.b.Attest(ctx, attest.AppletOpenPGP, p, now)
	if err != nil {
		return nil, err
	}
	key, err := attest.KeyOf(att.Leaf)
	if err != nil {
		return nil, err
	}
	return &handoff.Evidence{
		Key: key,
		Details: map[string]string{
			attest.DetailPolicyRead:    "false",
			attest.DetailBundleVersion: v.b.Version(),
			attest.DetailBundleSHA256:  v.b.SHA256(),
		},
	}, nil
}
