package attest_test

import (
	"bytes"
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// seedEvidence adds the evidence of every vector case that has a card, and the made-up cases of the other
// tests, to a fuzz corpus.
func seedEvidence(f *testing.F) {
	f.Helper()
	for _, stem := range attesttest.VectorEvidenceStems(f) {
		f.Add([]byte(attesttest.VectorProof(f, stem).Evidence))
	}
	m := newMaker(f)
	leaf, token := m.PIVChain(f, p384(f), attesttest.Slot{})
	oleaf, otoken := m.OpenPGPChain(f, p384(f), attesttest.Slot{})
	for _, ev := range [][]byte{
		attesttest.EvidenceJSON(f, leaf, token),
		attesttest.EvidenceJSON(f, oleaf, otoken),
		attesttest.EvidenceJSON(f, leaf, token, leaf, token),
		attesttest.EvidenceJSON(f, token, leaf),
		attesttest.EvidenceJSON(f, leaf, leaf),
		attesttest.EvidenceJSON(f, leaf[:len(leaf)-1], token),
		attesttest.EvidenceJSON(f, append(bytes.Clone(leaf), 0), token),
		[]byte(`{"attestation":["AA==","AA=="]}`),
		[]byte(`{"attestation":[]}`),
		[]byte(`{"attestation":null}`),
		[]byte(`not json`),
		{},
	} {
		f.Add(ev)
	}
}

// No input is a panic; a refusal is a *handoff.CodeError of the two codes that the shape and the
// certificates give, and a result never comes beside an error; a result is whole and has the roles.
func FuzzParseAttestation(f *testing.F) {
	seedEvidence(f)
	f.Fuzz(func(t *testing.T, evidence []byte) {
		att, err := attest.ParseAttestation(evidence)
		if err != nil {
			if att != nil {
				t.Fatal("a result beside an error")
			}
			var ce *handoff.CodeError
			if !errors.As(err, &ce) || (ce.Code != handoff.CodeMalformed && ce.Code != handoff.CodeProofInvalid) || ce.Detail == "" {
				t.Fatalf("error %v is not a refusal of the evidence", err)
			}
			return
		}
		if att == nil || att.Leaf == nil || att.Token == nil {
			t.Fatal("no error and no whole attestation")
		}
		if len(evidence) > handoff.MaxFileSize {
			t.Fatal("an evidence over the size of a file was read")
		}
		if bytes.Equal(att.Leaf.Raw, att.Token.Raw) || att.Leaf.IsCA || !att.Token.IsCA || att.Token.MaxPathLen != 0 || !att.Token.MaxPathLenZero {
			t.Fatal("the roles are not the ones the page gives")
		}
		if len(att.Leaf.Raw) > attest.MaxCertificateSize || len(att.Token.Raw) > attest.MaxCertificateSize {
			t.Fatal("a certificate over the limit was read")
		}
	})
}

// FuzzVerify runs the whole chain rule on evidence bytes against a bundle of the vectors, at the vector
// clock, for both applets. Whatever comes in, there is no panic and the result is a refusal or nil.
func FuzzVerify(f *testing.F) {
	seedEvidence(f)
	b := attesttest.VectorBundle(f)
	f.Fuzz(func(t *testing.T, evidence []byte) {
		for _, a := range []attest.Applet{attest.AppletPIV, attest.AppletOpenPGP} {
			att, err := attest.ParseAttestation(evidence)
			if err != nil {
				return
			}
			if err := b.Verify(a, att, clock); err != nil {
				var ce *handoff.CodeError
				if !errors.As(err, &ce) || ce.Code != handoff.CodeProofInvalid || ce.Detail == "" {
					t.Fatalf("error %v is not a refusal of the evidence", err)
				}
			}
		}
	})
}

// FuzzNewBundle builds a bundle from bytes in each place of the spec: no panic, and an error wraps ErrBundle.
func FuzzNewBundle(f *testing.F) {
	m := newMaker(f)
	s := m.Spec()
	f.Add(s.Roots[0], s.PIVIntermediates[0], s.OpenPGPIntermediates[0], "v1")
	f.Add(s.Roots[0], []byte(nil), []byte{}, "")
	f.Add([]byte{0x30, 0x00}, s.Roots[0], s.Roots[0], "\xff")
	f.Add(s.PIVIntermediates[0], s.Roots[0], s.Roots[0], "a-version-that-is-longer-than-thirty-two-characters")
	f.Fuzz(func(t *testing.T, root, piv, opgp []byte, version string) {
		for _, spec := range []attest.BundleSpec{
			{Version: version, Roots: [][]byte{root}, PIVIntermediates: [][]byte{piv}, OpenPGPIntermediates: [][]byte{opgp}},
			{Version: "v", Roots: [][]byte{root, s.Roots[0]}, PIVIntermediates: [][]byte{piv}},
			{Version: "v", Roots: [][]byte{s.Roots[0]}, PIVIntermediates: [][]byte{piv, opgp}},
		} {
			b, err := attest.NewBundle(spec)
			if err != nil {
				if b != nil || !errors.Is(err, attest.ErrBundle) {
					t.Fatalf("bundle %v, error %v", b, err)
				}
				continue
			}
			if b.SHA256() == "" || b.Version() != spec.Version {
				t.Fatalf("version %q, digest %q", b.Version(), b.SHA256())
			}
		}
	})
}

// FuzzCertificatesFromPEM reads any text: no panic, and every block that comes back is a copy of bytes that
// were in the text, at most MaxPinned of them.
func FuzzCertificatesFromPEM(f *testing.F) {
	m := newMaker(f)
	s := m.Spec()
	one := pemOf("CERTIFICATE", s.Roots[0])
	f.Add(one)
	f.Add(append(bytes.Clone(one), pemOf("CERTIFICATE", s.PIVIntermediates[0])...))
	f.Add(pemOf("PRIVATE KEY", []byte{1, 2, 3}))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAAAA\n-----END CERTIFICATE-----\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, text []byte) {
		got, err := attest.CertificatesFromPEM(text)
		if err != nil {
			if got != nil {
				t.Fatal("a result beside an error")
			}
			return
		}
		if len(got) == 0 || len(got) > attest.MaxPinned || len(text) > 1<<20 {
			t.Fatalf("%d blocks from %d bytes", len(got), len(text))
		}
	})
}
