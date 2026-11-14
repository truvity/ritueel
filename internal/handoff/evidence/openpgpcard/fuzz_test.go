package openpgpcard_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

func checkRefusalOrEvidence(t *testing.T, ev *handoff.Evidence, err error) {
	t.Helper()
	if err != nil {
		if ev != nil {
			t.Fatalf("evidence beside an error: %+v", ev)
		}
		var ce *handoff.CodeError
		if !errors.As(err, &ce) || (ce.Code != handoff.CodeMalformed && ce.Code != handoff.CodeProofInvalid) || ce.Detail == "" {
			t.Fatalf("error %v is not a refusal of the evidence", err)
		}
		return
	}
	if ev == nil || ev.Key == nil || ev.Key.Curve.Params().Name != "P-384" {
		t.Fatalf("evidence %+v", ev)
	}
	if ev.Firmware != "" || ev.PINPolicy != "" || ev.TouchPolicy != "" || ev.Unprotected || len(ev.SignPrincipals) != 0 {
		t.Fatalf("a policy was read: %+v", ev)
	}
	if len(ev.Details) != 3 || ev.Details[attest.DetailPolicyRead] != "false" {
		t.Fatalf("details %v", ev.Details)
	}
	for k, v := range ev.Details {
		for _, s := range []string{k, v} {
			for i := 0; i < len(s); i++ {
				if s[i] < 0x20 || s[i] > 0x7e {
					t.Fatalf("detail %q = %q is not printable ASCII", k, v)
				}
			}
		}
	}
}

// FuzzVerifyOpenPGPCard runs the verifier on any evidence bytes at the clock of the vectors, against the
// bundle of the vectors. Seeds: the evidence of the 36 vector cases and the made-up ones.
func FuzzVerifyOpenPGPCard(f *testing.F) {
	for _, stem := range attesttest.VectorEvidenceStems(f) {
		f.Add([]byte(attesttest.VectorProof(f, stem).Evidence))
	}
	m := newMaker(f, false)
	leaf, token := m.OpenPGPChain(f, p384(f), attesttest.Slot{})
	f.Add(attesttest.EvidenceJSON(f, leaf, token))
	f.Add(attesttest.EvidenceJSON(f, leaf, token, leaf))
	f.Add(attesttest.EvidenceJSON(f, token, leaf))
	f.Add([]byte(`{"attestation":["AA==","AA=="]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte{})
	v := newVerifier(f, attesttest.VectorBundle(f))
	f.Fuzz(func(t *testing.T, evidence []byte) {
		ev, err := v.Verify(t.Context(), nil, proofOf(handoff.StoreOpenPGPCard, evidence), clock)
		checkRefusalOrEvidence(t, ev, err)
	})
}

// FuzzVerifyOpenPGPCardCertificate makes a key certificate whose subject, extension and validity are the
// fuzzed bytes, signed by a token that chains to a pinned root: the subject and the extensions are not read,
// so no input is refused for them, and a refusal is for the certificate itself.
func FuzzVerifyOpenPGPCardCertificate(f *testing.F) {
	m := newMaker(f, false)
	v := newVerifier(f, m.Bundle(f))
	key := p384(f)
	f.Add([]byte("YubiKey OPGP Attestation SIG"), []byte{1, 2, 3}, false)
	f.Add([]byte{}, []byte{}, true)
	f.Add([]byte{0xff, 0xfe}, []byte{0x30, 0x00}, false)
	f.Fuzz(func(t *testing.T, subject, value []byte, critical bool) {
		ev, err := v.Verify(t.Context(), nil, proofOf(handoff.StoreOpenPGPCard, m.OpenPGPEvidenceWith(t, key, attesttest.Slot{
			PIVExtensions: true, Firmware: nonNil(value), Serial: nonNil(value), Policy: nonNil(value), Form: nonNil(value),
			Critical: map[string]bool{attesttest.ExtSerial: critical},
			Tweak:    func(c *x509.Certificate) { c.RawSubject = nameOf(subject) },
			Check:    attesttest.CheckNone,
		})), clock)
		checkRefusalOrEvidence(t, ev, err)
		if err == nil && critical {
			t.Fatal("a critical extension that is not known was accepted")
		}
	})
}

// nameOf writes a DER name of one common name whose UTF8String holds the bytes, valid or not.
func nameOf(cn []byte) []byte {
	b, err := asn1.Marshal(pkix.RDNSequence{{pkix.AttributeTypeAndValue{
		Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTF8String, Bytes: cn},
	}}})
	if err != nil {
		panic(err)
	}
	return b
}

func nonNil(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
