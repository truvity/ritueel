package attesttest_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/handoff/evidence/openpgpcard"
	"ritueel.id/ritueel/internal/handoff/evidence/piv"
)

var clock = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

// The vectors hold 36 cases whose proof is of the store piv or openpgp-card: 10 X.509 piv, 13 OpenPGP piv,
// 3 OpenPGP openpgp-card, 9 SSH piv and 1 SSH openpgp-card. A check that finds nothing to check fails.
func TestTheVectorsHoldThirtySixCardCases(t *testing.T) {
	stems := attesttest.VectorEvidenceStems(t)
	if len(stems) != 36 {
		t.Fatalf("%d stems, want 36: %v", len(stems), stems)
	}
	if !slices.IsSorted(stems) {
		t.Error("the stems are not sorted")
	}
	if len(slices.Compact(slices.Clone(stems))) != len(stems) {
		t.Error("a stem is listed twice")
	}
	byStore := map[handoff.Store]int{}
	byPrefix := map[string]int{}
	for _, s := range stems {
		p := attesttest.VectorProof(t, s)
		byStore[p.Store]++
		if p.RequestSHA256 == "" || len(p.Evidence) == 0 {
			t.Errorf("%s: proof %+v", s, p)
		}
		switch {
		case len(s) > 5 && s[:5] == "x509-":
			byPrefix["x509"]++
		case len(s) > 4 && s[:4] == "pgp-":
			byPrefix["pgp"]++
		case len(s) > 4 && s[:4] == "ssh-":
			byPrefix["ssh"]++
		}
	}
	if byStore[handoff.StorePIV] != 32 || byStore[handoff.StoreOpenPGPCard] != 4 {
		t.Errorf("by store: %v", byStore)
	}
	if byPrefix["x509"] != 10 || byPrefix["pgp"] != 16 || byPrefix["ssh"] != 10 {
		t.Errorf("by type: %v", byPrefix)
	}
}

// Together the two verifiers decide the 36 cases as the names of the cases say: 3 refused with proof-invalid,
// 33 with evidence of a P-384 key.
func TestTheTwoVerifiersSplitTheCardCasesThreeAndThirtyThree(t *testing.T) {
	b := attesttest.VectorBundle(t)
	pv, err := piv.New(b)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := openpgpcard.New(b)
	if err != nil {
		t.Fatal(err)
	}
	refused, given := 0, 0
	for _, stem := range attesttest.VectorEvidenceStems(t) {
		p := attesttest.VectorProof(t, stem)
		var v handoff.EvidenceVerifier = pv
		if p.Store == handoff.StoreOpenPGPCard {
			v = ov
		}
		ev, err := v.Verify(t.Context(), nil, p, clock)
		if err != nil {
			refused++
			var ce *handoff.CodeError
			if !asCodeError(err, &ce) || ce.Code != handoff.CodeProofInvalid || ev != nil {
				t.Errorf("%s: %v, %v", stem, err, ev)
			}
			continue
		}
		given++
		if ev.Key == nil {
			t.Errorf("%s: no key", stem)
		}
	}
	if refused != 3 || given != 33 {
		t.Errorf("%d refused and %d with evidence, want 3 and 33", refused, given)
	}
}

func asCodeError(err error, target **handoff.CodeError) bool { return errors.As(err, target) }

// The vector bundle pins the root and the two intermediates of the manifest, each in its own group.
func TestTheVectorBundleKeepsTheTwoIntermediatesApart(t *testing.T) {
	b := attesttest.VectorBundle(t)
	if b.Version() != "example-test" {
		t.Errorf("version %q", b.Version())
	}
	// The PIV vector chain does not verify as an OpenPGP chain and the reverse.
	for _, stem := range []string{"x509-piv-valid", "pgp-openpgp-card-valid"} {
		p := attesttest.VectorProof(t, stem)
		att, err := attest.ParseAttestation(p.Evidence)
		if err != nil {
			t.Fatal(err)
		}
		own, other := attest.AppletPIV, attest.AppletOpenPGP
		if p.Store == handoff.StoreOpenPGPCard {
			own, other = other, own
		}
		if err := b.Verify(own, att, clock); err != nil {
			t.Errorf("%s in its own applet: %v", stem, err)
		}
		if err := b.Verify(other, att, clock); err == nil {
			t.Errorf("%s in the other applet verifies", stem)
		}
	}
}

// A maker's pieces fit together: the root signs the intermediates, the intermediates sign the tokens, the
// token signs the slot certificate, and the windows are nested around Now.
func TestTheMakersCertificatesFormTheHierarchyTheyClaim(t *testing.T) {
	for _, shared := range []bool{false, true} {
		m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, SharedIntermediate: shared})
		if !m.Now().Equal(clock) {
			t.Errorf("the default Now %v, want the clock of the vectors", m.Now())
		}
		root, pivI, opgI, stray := m.Root(), m.PIVIntermediate(), m.OpenPGPIntermediate(), m.StrayIntermediate()
		for name, c := range map[string]*x509.Certificate{"piv": pivI, "openpgp": opgI, "stray": stray} {
			if err := c.CheckSignatureFrom(root); err != nil {
				t.Errorf("%s intermediate: %v", name, err)
			}
			if !c.IsCA || c.MaxPathLen != 1 {
				t.Errorf("%s intermediate: CA %v path length %d", name, c.IsCA, c.MaxPathLen)
			}
		}
		if err := root.CheckSignatureFrom(root); err != nil || !root.IsCA {
			t.Errorf("the root: %v", err)
		}
		if shared != bytes.Equal(pivI.Raw, opgI.Raw) {
			t.Errorf("shared %v, but the two intermediates are equal: %v", shared, bytes.Equal(pivI.Raw, opgI.Raw))
		}
		if bytes.Equal(pivI.Raw, stray.Raw) {
			t.Error("the stray intermediate is the piv one")
		}
		if err := m.Token(t).CheckSignatureFrom(pivI); err != nil {
			t.Errorf("the piv token: %v", err)
		}
		if err := m.OpenPGPToken(t).CheckSignatureFrom(opgI); err != nil {
			t.Errorf("the openpgp token: %v", err)
		}
		for _, tok := range []*x509.Certificate{m.Token(t), m.OpenPGPToken(t)} {
			if !tok.IsCA || tok.MaxPathLen != 0 || !tok.MaxPathLenZero {
				t.Errorf("a token certificate: CA %v path length %d", tok.IsCA, tok.MaxPathLen)
			}
		}
		// Each window holds the next one.
		for _, c := range [][2]*x509.Certificate{{root, pivI}, {pivI, m.Token(t)}} {
			if !c[0].NotBefore.Before(c[1].NotBefore) || !c[0].NotAfter.After(c[1].NotAfter) {
				t.Errorf("the window of %s does not hold the window of %s", c[0].Subject, c[1].Subject)
			}
		}
		if !m.Token(t).NotBefore.Before(clock) || !m.Token(t).NotAfter.After(clock) {
			t.Error("the token's window does not hold Now")
		}
	}
	// Now moves every window.
	later := clock.AddDate(3, 0, 0)
	m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: later})
	if !m.Now().Equal(later) || !m.Root().NotBefore.Before(later) || !m.Root().NotAfter.After(later) {
		t.Error("Now does not move the windows")
	}
}

// Spec gives a new copy at each call, and the bundle of a maker pins the root and the intermediates it made.
func TestTheMakersSpecIsACopy(t *testing.T) {
	m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true})
	a, b := m.Spec(), m.Spec()
	clear(a.Roots[0])
	clear(a.PIVIntermediates[0])
	clear(a.OpenPGPIntermediates[0])
	if !bytes.Equal(b.Roots[0], m.Root().Raw) || !bytes.Equal(b.PIVIntermediates[0], m.PIVIntermediate().Raw) || !bytes.Equal(b.OpenPGPIntermediates[0], m.OpenPGPIntermediate().Raw) {
		t.Error("a change to one spec reached another")
	}
	if len(b.Roots) != 1 || len(b.PIVIntermediates) != 1 || len(b.OpenPGPIntermediates) != 1 || b.Version != "example-maker" {
		t.Errorf("spec %+v", b)
	}
	if m.Bundle(t).SHA256() == "" {
		t.Error("no digest")
	}
}

// The defaults of a slot are the values of the vectors, and every field the page's table names can be
// changed: a check on the support itself, so that a test that relies on a default is not fooled.
func TestTheDefaultsOfASlotAreTheValuesOfTheVectors(t *testing.T) {
	m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true})
	key := attesttest.P384(t)
	leaf, token := m.PIVChain(t, key.Public(), attesttest.Slot{})
	lc, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if lc.Subject.CommonName != "YubiKey PIV Attestation 9c" || len(arcOf(lc)) != 4 {
		t.Errorf("subject %q, %d extensions of the arc", lc.Subject.CommonName, len(arcOf(lc)))
	}
	if !bytes.Equal(token, m.Token(t).Raw) {
		t.Error("the token of the chain is not the maker's")
	}
	want := map[string][]byte{
		"1.3.6.1.4.1.41482.3.3": {5, 8, 0},
		"1.3.6.1.4.1.41482.3.7": {0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e},
		"1.3.6.1.4.1.41482.3.8": {2, 1},
		"1.3.6.1.4.1.41482.3.9": {2},
	}
	for _, e := range arcOf(lc) {
		w, ok := want[e.Id.String()]
		if !ok || !bytes.Equal(w, e.Value) || e.Critical {
			t.Errorf("extension %v = %x (critical %v)", e.Id, e.Value, e.Critical)
		}
	}
	// An OpenPGP key certificate has the subject of a signature key and no extension.
	oleaf, otoken := m.OpenPGPChain(t, key.Public(), attesttest.Slot{})
	oc, err := x509.ParseCertificate(oleaf)
	if err != nil {
		t.Fatal(err)
	}
	if oc.Subject.CommonName != "YubiKey OPGP Attestation SIG" || len(arcOf(oc)) != 0 {
		t.Errorf("subject %q, %d extensions of the arc", oc.Subject.CommonName, len(arcOf(oc)))
	}
	if !bytes.Equal(otoken, m.OpenPGPToken(t).Raw) || bytes.Equal(otoken, token) {
		t.Error("the openpgp token")
	}
	// With the piv extensions, the openpgp key certificate has the four.
	oleaf, _ = m.OpenPGPChain(t, key.Public(), attesttest.Slot{PIVExtensions: true})
	if oc, _ = x509.ParseCertificate(oleaf); len(arcOf(oc)) != 4 {
		t.Errorf("%d extensions of the arc", len(arcOf(oc)))
	}
	// A slot that omits and one that critical-marks.
	leaf, _ = m.PIVChain(t, key.Public(), attesttest.Slot{Omit: map[string]bool{attesttest.ExtForm: true}, Critical: map[string]bool{attesttest.ExtSerial: true}})
	lc, _ = x509.ParseCertificate(leaf)
	if len(arcOf(lc)) != 3 || len(lc.UnhandledCriticalExtensions) != 1 {
		t.Errorf("%d extensions of the arc, %d critical", len(arcOf(lc)), len(lc.UnhandledCriticalExtensions))
	}
	// A key certificate that is made with an RSA token and one with an ECDSA token.
	rsaMaker := attesttest.NewMaker(t, attesttest.MakerOptions{})
	if rsaMaker.Token(t).PublicKeyAlgorithm != x509.RSA || m.Token(t).PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("token key algorithms: %v and %v", rsaMaker.Token(t).PublicKeyAlgorithm, m.Token(t).PublicKeyAlgorithm)
	}
}

// EvidenceJSON writes the list in the canonical spelling that the strict reader accepts, and the evidence of
// the maker is read back into the pieces it was made from.
func TestEvidenceJSONRoundTrips(t *testing.T) {
	m := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true})
	leaf, token := m.PIVChain(t, attesttest.P384(t).Public(), attesttest.Slot{})
	att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, leaf, token))
	if err != nil || !bytes.Equal(att.Leaf.Raw, leaf) || !bytes.Equal(att.Token.Raw, token) {
		t.Fatalf("round trip: %v", err)
	}
	att, err = attest.ParseAttestation(m.PIVEvidence(t, attesttest.P384(t).Public(), attesttest.Slot{}))
	if err != nil || att == nil {
		t.Fatal(err)
	}
	att, err = attest.ParseAttestation(m.OpenPGPEvidence(t, attesttest.P384(t).Public()))
	if err != nil || att == nil {
		t.Fatal(err)
	}
}

// arcOf returns the extensions of the maker's arc 1.3.6.1.4.1.41482 (the builder adds the key identifiers
// of its own).
func arcOf(c *x509.Certificate) []pkix.Extension {
	var out []pkix.Extension
	for _, e := range c.Extensions {
		if strings.HasPrefix(e.Id.String(), "1.3.6.1.4.1.41482.") {
			out = append(out, e)
		}
	}
	return out
}
