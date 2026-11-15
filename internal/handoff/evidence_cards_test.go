package handoff_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/handoff/evidence/openpgpcard"
	"ritueel.id/ritueel/internal/handoff/evidence/piv"
)

// These tests run a made-up X.509 request through the whole checker, with the two verifiers of the card
// stores registered and a maker whose clock is the test clock. The evidence is made in memory for the key of
// the fixture.

func cardMaker(t testing.TB, shared bool) *attesttest.Maker {
	t.Helper()
	return attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: testNow, SharedIntermediate: shared})
}

// cardChecker is the checker of the default configuration with the two verifiers of the bundle.
func cardChecker(t testing.TB, b *attest.Bundle, change func(c *handoff.Config)) *handoff.Checker {
	t.Helper()
	pv, err := piv.New(b)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := openpgpcard.New(b)
	if err != nil {
		t.Fatal(err)
	}
	return newCheckerWith(t, func(c *handoff.Config) {
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: pv, handoff.StoreOpenPGPCard: ov}
		if change != nil {
			change(c)
		}
	})
}

// cardFixture is a request of the store with the evidence that the function makes for the request's key.
func cardFixture(t testing.TB, store handoff.Store, evidence func(key *fixture) []byte) *fixture {
	t.Helper()
	f := newFixture(t, store, csrSpec{})
	f.proof["evidence"] = json.RawMessage(evidence(f))
	return f
}

// cardPGPChecker is the checker of a request of type openpgp-subkey for the fixture, with the two verifiers
// of the bundle. The store openpgp-card is the store of a subkey; an x509-intermediate request with it is
// refused at check 6 (cardstore_test.go).
func cardPGPChecker(t testing.TB, f *pgpFixture, b *attest.Bundle, change func(c *handoff.Config)) *handoff.Checker {
	t.Helper()
	pv, err := piv.New(b)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := openpgpcard.New(b)
	if err != nil {
		t.Fatal(err)
	}
	return f.checker(func(c *handoff.Config) {
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: pv, handoff.StoreOpenPGPCard: ov}
		if change != nil {
			change(c)
		}
	})
}

func pivSlot(m *attesttest.Maker, t testing.TB, s attesttest.Slot) func(f *fixture) []byte {
	return func(f *fixture) []byte { return m.PIVEvidence(t, f.publicKey(), s) }
}

// A request with a key in a PIV slot is accepted when the chain is pinned and the attested key is the
// request's, and what the verifier read is in the accepted verdict.
func TestAPIVRequestIsAcceptedWithAGoodChain(t *testing.T) {
	m := cardMaker(t, false)
	chk := cardChecker(t, m.Bundle(t), nil)
	f := cardFixture(t, handoff.StorePIV, pivSlot(m, t, attesttest.Slot{}))
	v, err := chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	ev := v.Evidence
	if ev.Firmware != "5.8.0" || ev.PINPolicy != handoff.PINOnce || ev.TouchPolicy != "never" || ev.Unprotected {
		t.Errorf("evidence %+v", ev)
	}
	if ev.Details[attest.DetailSlot] != "9c" || ev.Details[attest.DetailPolicyRead] != "true" {
		t.Errorf("details %v", ev.Details)
	}
	if !v.Key.Equal(f.publicKey()) || !ev.Key.Equal(f.publicKey()) {
		t.Error("the key of the verdict is not the request's")
	}
}

// Check 8: a chain that is good for another key is a key-mismatch, and the verdict stops there.
func TestAPIVKeyThatIsNotTheRequestsIsAKeyMismatch(t *testing.T) {
	m := cardMaker(t, false)
	chk := cardChecker(t, m.Bundle(t), nil)
	other := newP384(t)
	f := cardFixture(t, handoff.StorePIV, func(*fixture) []byte {
		return m.PIVEvidence(t, other.Public(), attesttest.Slot{})
	})
	v, err := chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
}

// Check 9: the policy refuses a PIN policy that is not allowed and a firmware that is older than the minimum;
// the policy accepts the edge and the other allowed PIN policy. A slot certificate with no policy extension
// does not reach check 9: the evidence is not valid (check 7).
func TestThePolicyReadsWhatTheVerifierReturned(t *testing.T) {
	m := cardMaker(t, false)
	chk := cardChecker(t, m.Bundle(t), nil)
	for _, c := range []struct {
		name string
		slot attesttest.Slot
		code handoff.Code
		n    int
	}{
		{"PIN never", attesttest.Slot{Policy: []byte{1, 1}}, handoff.CodePolicy, 9},
		{"firmware 5.6.9", attesttest.Slot{Firmware: []byte{5, 6, 9}}, handoff.CodePolicy, 9},
		{"firmware 5.4.3", attesttest.Slot{Firmware: []byte{5, 4, 3}}, handoff.CodePolicy, 9},
		{"firmware 4.99.99", attesttest.Slot{Firmware: []byte{4, 99, 99}}, handoff.CodePolicy, 9},
		{"no policy extension", attesttest.Slot{Omit: map[string]bool{attesttest.ExtPolicy: true}}, handoff.CodeProofInvalid, 7},
		{"no firmware extension", attesttest.Slot{Omit: map[string]bool{attesttest.ExtFirmware: true}}, handoff.CodeProofInvalid, 7},
		{"a PIN policy that is not known", attesttest.Slot{Policy: []byte{9, 1}}, handoff.CodeProofInvalid, 7},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := cardFixture(t, handoff.StorePIV, pivSlot(m, t, c.slot))
			v, err := chk.Check(t.Context(), f.request())
			wantRefusal(t, v, err, c.code, c.n)
		})
	}
	for name, slot := range map[string]attesttest.Slot{
		"firmware 5.7.0, the minimum": {Firmware: []byte{5, 7, 0}},
		"firmware 5.10.0":             {Firmware: []byte{5, 10, 0}},
		"PIN always":                  {Policy: []byte{3, 1}},
		"touch always":                {Policy: []byte{2, 2}},
		"touch cached":                {Policy: []byte{2, 3}},
	} {
		t.Run(name, func(t *testing.T) {
			f := cardFixture(t, handoff.StorePIV, pivSlot(m, t, slot))
			v, err := chk.Check(t.Context(), f.request())
			wantAccepted(t, v, err)
		})
	}
}

// Check 7: a chain that ends nowhere pinned, a certificate that is not valid at the time of the checker's
// clock, and a chain of the other applet are refused with proof-invalid.
func TestAChainThatIsNotPinnedIsProofInvalid(t *testing.T) {
	m := cardMaker(t, false)
	chk := cardChecker(t, m.Bundle(t), nil)
	foreign := cardMaker(t, false) // a maker whose roots the bundle does not hold
	expired := attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: testNow.AddDate(-20, 0, 0)})
	for name, ev := range map[string]func(f *fixture) []byte{
		"an unpinned intermediate":  pivSlot(m, t, attesttest.Slot{UnpinnedIssuer: true}),
		"another maker's chain":     pivSlot(foreign, t, attesttest.Slot{}),
		"a chain from long ago":     pivSlot(expired, t, attesttest.Slot{}),
		"the other applet's chain":  func(f *fixture) []byte { return m.OpenPGPEvidence(t, f.publicKey()) },
		"not signed by the token":   pivSlot(m, t, attesttest.Slot{OtherSigner: true}),
		"a subject that is no slot": pivSlot(m, t, attesttest.Slot{Subject: "YubiKey PIV Attestation f9"}),
		"an attestation of one": func(*fixture) []byte {
			return []byte(`{"attestation":["AA=="]}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := cardFixture(t, handoff.StorePIV, ev)
			v, err := chk.Check(t.Context(), f.request())
			if name == "an attestation of one" {
				// The shape of the evidence is read by check 2, before the evidence is verified.
				wantRefusal(t, v, err, handoff.CodeMalformed, 2)
				return
			}
			wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
		})
	}
}

// A subkey request with the store openpgp-card is accepted with the policy not read, whatever the policy's
// minimum firmware and PIN policies are: the page says that the certifier then records the key as attested
// and enforces no PIN or touch policy. The accepted evidence says "false" in policy_read, so that the
// ceremony can say that the policy was not read.
func TestAnOpenPGPCardRequestIsAcceptedWithThePolicyNotRead(t *testing.T) {
	m := cardMaker(t, false)
	for name, change := range map[string]func(c *handoff.Config){
		"the default policy": nil,
		"a firmware that no card has": func(c *handoff.Config) {
			c.Policy.MinFirmware = "99.0.0"
		},
		"a PIN policy that the card could not meet": func(c *handoff.Config) {
			c.Policy.PINPolicies = []handoff.PINPolicy{handoff.PINAlways}
		},
		"both": func(c *handoff.Config) {
			c.Policy.MinFirmware = "99.0.0"
			c.Policy.PINPolicies = []handoff.PINPolicy{handoff.PINAlways}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
			f.proof["evidence"] = json.RawMessage(m.OpenPGPEvidence(t, f.sub.pub()))
			chk := cardPGPChecker(t, f, m.Bundle(t), change)
			v, err := chk.Check(t.Context(), f.request())
			wantAccepted(t, v, err)
			if v.Evidence.Details[attest.DetailPolicyRead] != "false" {
				t.Errorf("details %v", v.Evidence.Details)
			}
			if v.Evidence.Firmware != "" || v.Evidence.PINPolicy != "" {
				t.Errorf("evidence %+v", v.Evidence)
			}
		})
	}
	// The same policy refuses a piv key that does not meet it.
	chk := cardChecker(t, m.Bundle(t), func(c *handoff.Config) { c.Policy.MinFirmware = "99.0.0" })
	f := cardFixture(t, handoff.StorePIV, pivSlot(m, t, attesttest.Slot{}))
	v, err := chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
}

// A card key's chain is checked and its key is compared with the subkey of the request: another key is a
// key-mismatch, and a chain that is not the card's is proof-invalid.
func TestAnOpenPGPCardRequestIsCheckedLikeAnyOther(t *testing.T) {
	m := cardMaker(t, false)
	other := newP384(t)
	g := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	g.proof["evidence"] = json.RawMessage(m.OpenPGPEvidence(t, other.Public()))
	v, err := cardPGPChecker(t, g, m.Bundle(t), nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)

	g = newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	g.proof["evidence"] = json.RawMessage(m.PIVEvidence(t, g.sub.pub(), attesttest.Slot{}))
	v, err = cardPGPChecker(t, g, m.Bundle(t), nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)

	// The store of the proof is the one the checker dispatches on: a piv chain under the store piv, with the
	// openpgp-card verifier alone registered, stops at check 7 as undecided.
	ov, _ := openpgpcard.New(m.Bundle(t))
	only := newCheckerWith(t, func(c *handoff.Config) {
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreOpenPGPCard: ov}
	})
	f := cardFixture(t, handoff.StorePIV, pivSlot(m, t, attesttest.Slot{}))
	v, err = only.Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrNoVerifier, "ppppppnnn")
}

// A piv chain presented as openpgp-card evidence is refused at check 7. A maker with one intermediate for
// both applets makes a spec that the bundle refuses, so the piv key cannot pass as a card key.
func TestAPIVChainDoesNotPassAsACardChain(t *testing.T) {
	m := cardMaker(t, false)
	chk := cardChecker(t, m.Bundle(t), nil)
	g := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	g.proof["evidence"] = json.RawMessage(m.PIVEvidence(t, g.sub.pub(), attesttest.Slot{Policy: []byte{1, 1}}))
	v, err := cardPGPChecker(t, g, m.Bundle(t), nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
	// As a piv key the same evidence passes check 7 and is refused by the policy.
	f := cardFixture(t, handoff.StorePIV, pivSlot(m, t, attesttest.Slot{Policy: []byte{1, 1}}))
	v, err = chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)

	shared := cardMaker(t, true)
	if b, err := attest.NewBundle(shared.Spec()); b != nil || !errors.Is(err, attest.ErrBundle) {
		t.Errorf("a shared intermediate: bundle %v, error %v", b, err)
	}
}

// A slot certificate that has expired is refused at check 7 with fixed words in the verdict: the detail
// holds no text of the certificate.
func TestAVerdictCarriesTheFixedWordsOfTheRefusal(t *testing.T) {
	m := cardMaker(t, false)
	chk := cardChecker(t, m.Bundle(t), nil)
	f := cardFixture(t, handoff.StorePIV, pivSlot(m, t, attesttest.Slot{
		Tweak: func(c *x509.Certificate) { c.NotAfter = testNow.Add(-time.Hour) },
	}))
	v, err := chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
	if v.Detail == "" {
		t.Error("a refusal with no detail")
	}
	for _, w := range []string{"YubiKey", "Example", "acme", "2026"} {
		if strings.Contains(v.Detail, w) {
			t.Errorf("the detail %q holds %q", v.Detail, w)
		}
	}
}
