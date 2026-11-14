package attest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// A fault of the caller is an error that is not a verdict on the evidence: no refusal code, no result.
func TestAttestFaultsOfTheCallerAreNotRefusals(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	good := proofOf(handoff.StorePIV, ev)
	var noCtx context.Context

	cases := []struct {
		name   string
		b      *attest.Bundle
		ctx    context.Context
		applet attest.Applet
		p      *handoff.Proof
		now    time.Time
	}{
		{"nil bundle", nil, t.Context(), attest.AppletPIV, good, clock},
		{"zero bundle", &attest.Bundle{}, t.Context(), attest.AppletPIV, good, clock},
		{"nil context", b, noCtx, attest.AppletPIV, good, clock},
		{"done context", b, done(), attest.AppletPIV, good, clock},
		{"nil proof", b, t.Context(), attest.AppletPIV, nil, clock},
		{"a proof of another store", b, t.Context(), attest.AppletPIV, proofOf(handoff.StoreOpenPGPCard, ev), clock},
		{"a proof of the store software", b, t.Context(), attest.AppletPIV, proofOf(handoff.StoreSoftware, ev), clock},
		{"a proof of the store aws-kms", b, t.Context(), attest.AppletPIV, proofOf(handoff.StoreKMS, ev), clock},
		{"an empty store", b, t.Context(), attest.AppletPIV, proofOf("", ev), clock},
		{"an openpgp applet with a piv proof", b, t.Context(), attest.AppletOpenPGP, good, clock},
		{"an unknown applet", b, t.Context(), "tpm", good, clock},
		{"an empty applet", b, t.Context(), "", good, clock},
		{"the zero time", b, t.Context(), attest.AppletPIV, good, time.Time{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			att, err := c.b.Attest(c.ctx, c.applet, c.p, c.now)
			if att != nil {
				t.Error("a result beside an error")
			}
			wantPlainError(t, err)
		})
		// A fault of the caller is found before the evidence is read: with evidence that would be refused,
		// the answer is still a fault and not a refusal.
		if c.p != nil {
			bad := *c.p
			bad.Evidence = []byte("not json")
			t.Run(c.name+", with evidence that is not JSON", func(t *testing.T) {
				att, err := c.b.Attest(c.ctx, c.applet, &bad, c.now)
				if att != nil {
					t.Error("a result beside an error")
				}
				wantPlainError(t, err)
			})
		}
	}
}

// The same checks hold for Verify: a fault of the caller is never a refusal.
func TestVerifyFaultsOfTheCallerAreNotRefusals(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	att := pivChain(t, m, attesttest.Slot{})
	var nilB *attest.Bundle
	wantPlainError(t, nilB.Verify(attest.AppletPIV, att, clock))
	wantPlainError(t, (&attest.Bundle{}).Verify(attest.AppletPIV, att, clock))
	wantPlainError(t, b.Verify(attest.AppletPIV, att, time.Time{}))
	wantPlainError(t, b.Verify("tpm", att, clock))
	wantPlainError(t, b.Verify("", att, clock))
	wantPlainError(t, b.Verify(attest.AppletPIV, nil, clock))
	if err := b.Verify(attest.AppletPIV, att, clock); err != nil {
		t.Errorf("the good call after the faults: %v", err)
	}
}

// Attest returns the attestation only when the chain verified, and the refusals of its two halves are the
// refusals of ParseAttestation and Verify.
func TestAttestReadsThenVerifies(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	good := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	att, err := b.Attest(t.Context(), attest.AppletPIV, proofOf(handoff.StorePIV, good), clock)
	if err != nil || att == nil || att.Leaf == nil || att.Token == nil {
		t.Fatalf("a good proof: %v %+v", err, att)
	}
	if err := b.Verify(attest.AppletPIV, att, clock); err != nil {
		t.Errorf("the attestation that Attest returned does not verify: %v", err)
	}

	for name, c := range map[string]struct {
		store    handoff.Store
		applet   attest.Applet
		evidence []byte
		code     handoff.Code
	}{
		"a shape that is not the page's":       {handoff.StorePIV, attest.AppletPIV, []byte(`{"attestation":["AA=="]}`), handoff.CodeMalformed},
		"an unpinned chain":                    {handoff.StorePIV, attest.AppletPIV, m.PIVEvidence(t, p384(t), attesttest.Slot{UnpinnedIssuer: true}), handoff.CodeProofInvalid},
		"a piv chain for the openpgp applet":   {handoff.StoreOpenPGPCard, attest.AppletOpenPGP, good, handoff.CodeProofInvalid},
		"an openpgp chain for the piv applet":  {handoff.StorePIV, attest.AppletPIV, m.OpenPGPEvidence(t, p384(t)), handoff.CodeProofInvalid},
		"an empty evidence":                    {handoff.StorePIV, attest.AppletPIV, nil, handoff.CodeMalformed},
		"a certificate that does not parse":    {handoff.StorePIV, attest.AppletPIV, []byte(`{"attestation":["AAAA","AAAA"]}`), handoff.CodeProofInvalid},
		"the token and the leaf in this order": {handoff.StorePIV, attest.AppletPIV, attesttest.EvidenceJSON(t, att.Token.Raw, att.Leaf.Raw), handoff.CodeProofInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			a, err := b.Attest(t.Context(), c.applet, proofOf(c.store, c.evidence), clock)
			if a != nil {
				t.Error("an attestation beside a refusal: values of a certificate whose chain failed")
			}
			wantRefusal(t, err, c.code)
		})
	}
}

// The context is looked at before the proof is read: a done context gives no verdict even for evidence
// that would be refused, and the proof is not read.
func TestADoneContextIsAFaultNotAVerdict(t *testing.T) {
	b := newMaker(t).Bundle(t)
	_, err := b.Attest(done(), attest.AppletPIV, proofOf(handoff.StorePIV, []byte("not json")), clock)
	wantPlainError(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not wrap the context error", err)
	}
}
