package openpgpcard_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/handoff/evidence/openpgpcard"
)

// clock is the time of the vectors.
var clock = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

func newMaker(t testing.TB, shared bool) *attesttest.Maker {
	t.Helper()
	return attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock, SharedIntermediate: shared})
}

func newVerifier(t testing.TB, b *attest.Bundle) *openpgpcard.Verifier {
	t.Helper()
	v, err := openpgpcard.New(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func p384(t testing.TB) *ecdsa.PublicKey {
	t.Helper()
	k, ok := attesttest.P384(t).Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	return k
}

func proofOf(store handoff.Store, evidence []byte) *handoff.Proof {
	return &handoff.Proof{Handoff: 1, Type: handoff.TypeOpenPGP, Store: store, Evidence: evidence}
}

func verifyCard(t testing.TB, v *openpgpcard.Verifier, evidence []byte) (*handoff.Evidence, error) {
	t.Helper()
	return v.Verify(t.Context(), nil, proofOf(handoff.StoreOpenPGPCard, evidence), clock)
}

func wantRefusal(t testing.TB, ev *handoff.Evidence, err error, code handoff.Code) string {
	t.Helper()
	if ev != nil {
		t.Errorf("evidence beside an error: %+v", ev)
	}
	var ce *handoff.CodeError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *handoff.CodeError", err)
	}
	if ce.Code != code {
		t.Fatalf("code %q (%s), want %q", ce.Code, ce.Detail, code)
	}
	for _, w := range []string{"Example", "acme", "YubiKey", "OPGP", "Intermediate", "x509:", "2026", "CN="} {
		if strings.Contains(ce.Detail, w) {
			t.Errorf("the detail %q holds %q, which comes from a certificate or from Go", ce.Detail, w)
		}
	}
	if ce.Detail == "" {
		t.Error("a refusal with no detail")
	}
	return ce.Detail
}

func wantPlainError(t testing.TB, ev *handoff.Evidence, err error) {
	t.Helper()
	if ev != nil {
		t.Errorf("evidence beside an error: %+v", ev)
	}
	if err == nil {
		t.Fatal("no error, want a fault of the caller")
	}
	var ce *handoff.CodeError
	if errors.As(err, &ce) {
		t.Fatalf("a fault of the caller is a refusal: %v", err)
	}
}

func done() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// The page, section openpgp-card: the key's certificate and the card's own certificate chain to a pinned
// root of the maker through the maker's OpenPGP intermediates. A good chain gives the key and nothing about
// the firmware or the policy ("a certifier that cannot read them records the key as attested and does not
// enforce a PIN or touch policy"), and says so in Details["policy_read"].
func TestAGoodChainGivesTheKeyAndNoPolicy(t *testing.T) {
	m := newMaker(t, false)
	b := m.Bundle(t)
	v := newVerifier(t, b)
	key := p384(t)
	ev, err := verifyCard(t, v, m.OpenPGPEvidence(t, key))
	if err != nil {
		t.Fatal(err)
	}
	if !ev.Key.Equal(key) {
		t.Error("the key is not the attested key")
	}
	if ev.Firmware != "" || ev.PINPolicy != "" || ev.TouchPolicy != "" || ev.Unprotected || len(ev.SignPrincipals) != 0 {
		t.Errorf("a policy was read: %+v", ev)
	}
	want := map[string]string{
		attest.DetailPolicyRead:    "false",
		attest.DetailBundleVersion: b.Version(),
		attest.DetailBundleSHA256:  b.SHA256(),
	}
	if !maps.Equal(ev.Details, want) {
		t.Errorf("details %v, want %v", ev.Details, want)
	}
}

// Neither the subject nor the extensions of the key's certificate are read, because the page gives this store
// no subject and no extension to read: the subject "SIG" serves the authentication key of a vector, a piv
// subject and the four piv extensions leave the firmware empty, and the extensions of the arc .5 (not yet
// measured) are ignored.
func TestNeitherTheSubjectNorTheExtensionsAreRead(t *testing.T) {
	m := newMaker(t, false)
	v := newVerifier(t, m.Bundle(t))
	for name, slot := range map[string]attesttest.Slot{
		"the signature subject":            {Subject: "YubiKey OPGP Attestation SIG"},
		"the authentication subject":       {Subject: "YubiKey OPGP Attestation AUT"},
		"a piv subject with a slot":        {Subject: "YubiKey PIV Attestation 9c"},
		"a subject that is nonsense":       {Subject: "nonsense"},
		"the piv extensions":               {PIVExtensions: true},
		"the piv extensions with a policy": {PIVExtensions: true, Policy: []byte{1, 1}, Firmware: []byte{5, 0, 0}},
		"piv extensions that are garbage":  {PIVExtensions: true, Firmware: []byte{1}, Serial: []byte{9}, Policy: []byte{0}, Form: []byte{}},
		"an extension of the arc .5": {Tweak: func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 41482, 5, 2}, Value: []byte{1, 2, 3}})
		}},
		"an empty subject": {Tweak: func(c *x509.Certificate) {
			c.RawSubject = []byte{0x30, 0x00}
		}, Check: attesttest.CheckNone},
		"two subjects": {Tweak: func(c *x509.Certificate) {
			c.Subject = pkix.Name{CommonName: "a", Organization: []string{"b"}, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "c"}}}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			ev, err := verifyCard(t, v, m.OpenPGPEvidenceWith(t, p384(t), slot))
			if err != nil {
				t.Fatal(err)
			}
			if ev.Firmware != "" || ev.PINPolicy != "" || ev.TouchPolicy != "" {
				t.Errorf("firmware %q PIN %q touch %q", ev.Firmware, ev.PINPolicy, ev.TouchPolicy)
			}
			if len(ev.Details) != 3 || ev.Details[attest.DetailPolicyRead] != "false" {
				t.Errorf("details %v", ev.Details)
			}
		})
	}
}

// The chain uses the OpenPGP intermediates only. A piv chain offered as openpgp-card evidence is refused when
// the maker has one intermediate for each applet; the opposite is refused too.
func TestAPIVChainIsNotAnOpenPGPCardChain(t *testing.T) {
	m := newMaker(t, false)
	v := newVerifier(t, m.Bundle(t))
	ev, err := verifyCard(t, v, m.PIVEvidence(t, p384(t), attesttest.Slot{}))
	wantRefusal(t, ev, err, handoff.CodeProofInvalid)

	// Only the piv intermediate pinned for openpgp-card: the card's own chain does not pass.
	s := m.Spec()
	s.OpenPGPIntermediates = nil
	b, err := attest.NewBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	ev, err = verifyCard(t, newVerifier(t, b), m.OpenPGPEvidence(t, p384(t)))
	wantRefusal(t, ev, err, handoff.CodeProofInvalid)
	// And the piv intermediate in the openpgp group alone does not serve the openpgp chain.
	s = m.Spec()
	s.OpenPGPIntermediates = s.PIVIntermediates
	s.PIVIntermediates = nil // a bundle that holds one in both groups is refused
	b, err = attest.NewBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	ev, err = verifyCard(t, newVerifier(t, b), m.OpenPGPEvidence(t, p384(t)))
	wantRefusal(t, ev, err, handoff.CodeProofInvalid)
}

// With one intermediate that serves both applets and is pinned for both, the other applet's chain would
// pass for this one. The bundle refuses such a spec, so no verifier is made from it.
func TestASharedIntermediateIsRefusedBeforeAVerifierExists(t *testing.T) {
	m := newMaker(t, true)
	b, err := attest.NewBundle(m.Spec())
	if b != nil || !errors.Is(err, attest.ErrBundle) {
		t.Fatalf("bundle %v, error %v", b, err)
	}
	if v, err := openpgpcard.New(b); err == nil || v != nil {
		t.Errorf("a verifier from no bundle: %v, %v", v, err)
	}
}

// Every failure of the chain of the piv verifier is a failure here: an unpinned issuer, an expired or a not
// yet valid certificate, and the key that is not P-384.
func TestTheChainAndTheKeyAreChecked(t *testing.T) {
	m := newMaker(t, false)
	v := newVerifier(t, m.Bundle(t))
	day := 24 * time.Hour
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := map[string][]byte{
		"an unpinned issuer": m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{UnpinnedIssuer: true}),
		"an expired leaf": m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{Tweak: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = clock.Add(-2*day), clock.Add(-day)
		}}),
		"a leaf that is not yet valid": m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{Tweak: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = clock.Add(day), clock.Add(2*day)
		}}),
		"an expired token": m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{TokenTweak: func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = clock.Add(-2*day), clock.Add(-day)
		}}),
		"signed by another key": m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{OtherSigner: true}),
		"a critical extension":  m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{PIVExtensions: true, Critical: map[string]bool{attesttest.ExtSerial: true}}),
		"a P-256 key":           m.OpenPGPEvidence(t, p256.Public()),
		"an RSA key":            m.OpenPGPEvidence(t, rsaKey.Public()),
		"a token with path length 1": m.OpenPGPEvidenceWith(t, p384(t), attesttest.Slot{
			TokenTweak: func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 1, false },
		}),
		"a shape that is not the page's": []byte(`{"attestation":["AA=="]}`),
		"no evidence":                    nil,
	}
	for name, ev := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := verifyCard(t, v, ev)
			code := handoff.CodeProofInvalid
			if name == "a shape that is not the page's" || name == "no evidence" {
				code = handoff.CodeMalformed
			}
			wantRefusal(t, got, err, code)
		})
	}
}

// A chain that the evidence completes is refused: the entries from the third are not helpers.
func TestExtraEntriesAreNotHelpers(t *testing.T) {
	m := newMaker(t, false)
	s := m.Spec()
	opgp := s.OpenPGPIntermediates[0]
	s.OpenPGPIntermediates = nil
	b, err := attest.NewBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	leaf, token := m.OpenPGPChain(t, p384(t), attesttest.Slot{})
	ev, err := verifyCard(t, newVerifier(t, b), attesttest.EvidenceJSON(t, leaf, token, opgp, s.Roots[0]))
	wantRefusal(t, ev, err, handoff.CodeProofInvalid)
	// With the right bundle an extra entry changes nothing.
	good, err := verifyCard(t, newVerifier(t, m.Bundle(t)), attesttest.EvidenceJSON(t, leaf, token, opgp))
	if err != nil || good == nil {
		t.Errorf("a good chain with an extra entry: %v", err)
	}
}

// The result is a copy.
func TestTheResultSharesNothing(t *testing.T) {
	m := newMaker(t, false)
	v := newVerifier(t, m.Bundle(t))
	key := p384(t)
	evid := m.OpenPGPEvidence(t, key)
	first, err := verifyCard(t, v, evid)
	if err != nil {
		t.Fatal(err)
	}
	first.Key.X.SetInt64(1) //nolint:staticcheck // the coordinates are the only way to change a key in place
	first.Details[attest.DetailPolicyRead] = "true"
	second, err := verifyCard(t, v, evid)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Key.Equal(key) || second.Details[attest.DetailPolicyRead] != "false" {
		t.Errorf("a change to a returned value reached the next answer: %+v", second)
	}
}

// The faults of the caller are errors that are not refusals.
func TestFaultsOfTheCaller(t *testing.T) {
	m := newMaker(t, false)
	v := newVerifier(t, m.Bundle(t))
	ev := m.OpenPGPEvidence(t, p384(t))
	var nilV *openpgpcard.Verifier
	var noCtx context.Context
	got, err := nilV.Verify(t.Context(), nil, proofOf(handoff.StoreOpenPGPCard, ev), clock)
	wantPlainError(t, got, err)
	got, err = (&openpgpcard.Verifier{}).Verify(t.Context(), nil, proofOf(handoff.StoreOpenPGPCard, ev), clock)
	wantPlainError(t, got, err)
	got, err = v.Verify(noCtx, nil, proofOf(handoff.StoreOpenPGPCard, ev), clock)
	wantPlainError(t, got, err)
	got, err = v.Verify(done(), nil, proofOf(handoff.StoreOpenPGPCard, ev), clock)
	wantPlainError(t, got, err)
	got, err = v.Verify(t.Context(), nil, nil, clock)
	wantPlainError(t, got, err)
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreKMS, handoff.StoreSoftware, ""} {
		got, err = v.Verify(t.Context(), nil, proofOf(store, ev), clock)
		wantPlainError(t, got, err)
	}
	got, err = v.Verify(t.Context(), nil, proofOf(handoff.StoreOpenPGPCard, ev), time.Time{})
	wantPlainError(t, got, err)
	if got, err := verifyCard(t, v, ev); err != nil || got == nil {
		t.Errorf("the good call after the faults: %v", err)
	}
}

func TestNewRefusesNoBundle(t *testing.T) {
	if v, err := openpgpcard.New(nil); err == nil || v != nil {
		t.Errorf("New(nil): %v, %v", v, err)
	}
	if zero, err := openpgpcard.New(&attest.Bundle{}); err == nil {
		ev := newMaker(t, false).OpenPGPEvidence(t, p384(t))
		got, err := verifyCard(t, zero, ev)
		wantPlainError(t, got, err)
	}
}

// 32 goroutines call one verifier on the same input; the results are compared with the first.
func TestConcurrentUse(t *testing.T) {
	m := newMaker(t, false)
	v := newVerifier(t, m.Bundle(t))
	evid := m.OpenPGPEvidence(t, p384(t))
	const n = 32
	results := make([]*handoff.Evidence, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = v.Verify(t.Context(), nil, proofOf(handoff.StoreOpenPGPCard, evid), clock)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if !results[0].Key.Equal(results[i].Key) || !maps.Equal(results[0].Details, results[i].Details) {
			t.Errorf("goroutine %d got %+v, the first got %+v", i, results[i], results[0])
		}
	}
}

// The vectors: the evidence of every openpgp-card case is read with no checker and no request, at the
// clock of the vectors. The one about an untrusted chain is refused with proof-invalid; the other three
// give the key and no policy, whatever the subject says (the vector for an authentication key has the
// subject of a signature key).
func TestTheEvidenceOfEveryOpenPGPCardVectorCase(t *testing.T) {
	v := newVerifier(t, attesttest.VectorBundle(t))
	vectorClock, err := time.Parse(time.RFC3339, "2026-11-15T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	var stems []string
	for _, stem := range attesttest.VectorEvidenceStems(t) {
		if attesttest.VectorProof(t, stem).Store == handoff.StoreOpenPGPCard {
			stems = append(stems, stem)
		}
	}
	if len(stems) != 4 {
		t.Fatalf("%d openpgp-card cases in the vectors, want 4: %v", len(stems), stems)
	}
	refused, given := 0, 0
	for _, stem := range stems {
		t.Run(stem, func(t *testing.T) {
			ev, err := v.Verify(t.Context(), nil, attesttest.VectorProof(t, stem), vectorClock)
			if strings.Contains(stem, "untrusted-chain") {
				refused++
				wantRefusal(t, ev, err, handoff.CodeProofInvalid)
				return
			}
			given++
			if err != nil {
				t.Fatal(err)
			}
			if ev.Key == nil || ev.Key.Curve.Params().Name != "P-384" {
				t.Fatalf("key %v", ev.Key)
			}
			if ev.Firmware != "" || ev.PINPolicy != "" || ev.TouchPolicy != "" {
				t.Errorf("a policy was read: %+v", ev)
			}
			if ev.Details[attest.DetailPolicyRead] != "false" || ev.Details[attest.DetailBundleVersion] != "example-test" {
				t.Errorf("details %v", ev.Details)
			}
		})
	}
	if refused != 1 || given != 3 {
		t.Errorf("%d refused and %d with evidence, want 1 and 3", refused, given)
	}
}

// The evidence of a piv vector offered as openpgp-card evidence: the other applet's chain does not pass.
func TestAPIVVectorIsNotAnOpenPGPCardVector(t *testing.T) {
	v := newVerifier(t, attesttest.VectorBundle(t))
	for _, stem := range attesttest.VectorEvidenceStems(t) {
		p := attesttest.VectorProof(t, stem)
		if p.Store != handoff.StorePIV {
			continue
		}
		p.Store = handoff.StoreOpenPGPCard
		ev, err := v.Verify(t.Context(), nil, p, clock)
		wantRefusal(t, ev, err, handoff.CodeProofInvalid)
	}
}
