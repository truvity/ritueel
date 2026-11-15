package handoff_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// A key on an OpenPGP card is not taken for an X.509 intermediate: the attestation of such a card shows no PIN
// or touch rule. Check 6 refuses a request of type x509-intermediate whose store is openpgp-card with the code
// store-not-allowed, also when the policy lists that store, and before any evidence is read. A request of type
// openpgp-subkey with the same store is judged by the policy list alone. The refusal has fixed words.

const cardRefusalWords = "the store openpgp-card is not allowed for an x509-intermediate: its attestation shows no PIN or touch rule"

// listing is a change of the policy that lists exactly these stores.
func listing(stores ...handoff.Store) func(c *handoff.Config) {
	return func(c *handoff.Config) { c.Policy.Stores = slices.Clone(stores) }
}

// wantCardRefusal checks the refusal of an X.509 request with the store openpgp-card: check 6, the fixed words,
// and the five checks before it passed.
func wantCardRefusal(t testing.TB, v handoff.Verdict, err error) {
	t.Helper()
	wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
	if got := statuses(v); got != "pppppfnnn" {
		t.Errorf("statuses %s, want pppppfnnn", got)
	}
	if v.Detail != cardRefusalWords {
		t.Errorf("detail %q, want %q", v.Detail, cardRefusalWords)
	}
	if v.Accepted() || v.Complete() || !v.Refused() {
		t.Errorf("accepted %v, complete %v, refused %v", v.Accepted(), v.Complete(), v.Refused())
	}
}

// Case 1 and 2: the refusal does not depend on what the policy lists, and it never reads evidence.
func TestAnX509RequestWithTheStoreOpenPGPCardIsRefusedAtCheckSixWhateverThePolicyLists(t *testing.T) {
	for name, change := range map[string]func(c *handoff.Config){
		"a policy that lists every store":           nil,
		"a policy that lists only the card":         listing(handoff.StoreOpenPGPCard),
		"a policy that lists the card and piv":      listing(handoff.StorePIV, handoff.StoreOpenPGPCard),
		"a policy that does not list the card":      listing(handoff.StorePIV, handoff.StoreKMS, handoff.StoreSoftware),
		"a policy that lists software only":         listing(handoff.StoreSoftware),
		"a policy with a minimum firmware of 0.0.1": func(c *handoff.Config) { c.Policy.MinFirmware = "0.0.1" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
			sv := returning(f.goodEvidence(handoff.StoreOpenPGPCard))
			v, err := checkerWithCfg(t, handoff.StoreOpenPGPCard, sv, change).Check(t.Context(), f.request())
			wantCardRefusal(t, v, err)
			if sv.calls.Load() != 0 {
				t.Errorf("a verifier was called %d times for a store that check 6 refused", sv.calls.Load())
			}
			// With no verifier at all the request is refused as well, and it is not an undecided call.
			v, err = newCheckerWith(t, change).Check(t.Context(), f.request())
			wantCardRefusal(t, v, err)
		})
	}
}

// Case 3: a verifier that would refuse, fail, panic or give another key is not heard.
func TestAnX509RequestWithTheStoreOpenPGPCardNeverReachesTheVerifier(t *testing.T) {
	f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
	wrong := f.goodEvidence(handoff.StoreOpenPGPCard)
	wrong.Key = &newP384(t).PublicKey
	boom := &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		panic("the verifier was called")
	}}
	for name, sv := range map[string]*stub{
		"a verifier that gives the key of the request": returning(f.goodEvidence(handoff.StoreOpenPGPCard)),
		"a verifier that gives another key":            returning(wrong),
		"a verifier that gives nothing":                returning(nil),
		"a verifier that refuses":                      failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "the chain is broken"}),
		"a verifier that cannot decide":                failing(errCannotDecide),
		"a verifier that panics":                       boom,
	} {
		t.Run(name, func(t *testing.T) {
			v, err := checkerWith(t, handoff.StoreOpenPGPCard, sv).Check(t.Context(), f.request())
			wantCardRefusal(t, v, err)
			if sv.calls.Load() != 0 {
				t.Errorf("the verifier was called %d times", sv.calls.Load())
			}
		})
	}
}

// The same with the verifiers of the bundle: a chain that is good for the key of an X.509 request, made by the
// maker of the tests, is still refused at check 6. The verifier of a card is registered and is not called.
func TestAnX509RequestWithAGoodCardChainIsStillRefusedAtCheckSix(t *testing.T) {
	m := cardMaker(t, false)
	chk := cardChecker(t, m.Bundle(t), nil)
	f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
	f.proof["evidence"] = json.RawMessage(m.OpenPGPEvidence(t, f.publicKey()))
	v, err := chk.Check(t.Context(), f.request())
	wantCardRefusal(t, v, err)
	// The same chain, as the evidence of a subkey request for the same store, is accepted by the same checker.
	g := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	g.proof["evidence"] = json.RawMessage(m.OpenPGPEvidence(t, g.sub.pub()))
	g.mustAccept(cardPGPChecker(t, g, m.Bundle(t), nil))
	// An X.509 request of the store piv with a good chain is accepted by the checker that refused the card.
	p := cardFixture(t, handoff.StorePIV, pivSlot(m, t, attesttest.Slot{}))
	acceptFixture(t, chk, p)
}

func acceptFixture(t testing.TB, chk *handoff.Checker, f *fixture) {
	t.Helper()
	v, err := chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
}

// Case 4 and 5: a request of type openpgp-subkey with the store is judged by the policy list and the evidence.
func TestAnOpenPGPSubkeyRequestWithTheStoreOpenPGPCardIsJudgedByThePolicyList(t *testing.T) {
	// Listed: check 6 passes, the verifier is called once, and the request is accepted.
	f := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	sv := returning(f.goodEvidence(handoff.StoreOpenPGPCard))
	v, err := f.checker(withVerifier(handoff.StoreOpenPGPCard, sv)).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if sv.calls.Load() != 1 {
		t.Errorf("the verifier was called %d times", sv.calls.Load())
	}
	// Listed, with no verifier: check 6 passed and check 7 could not run.
	v, err = f.checker(nil).Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrNoVerifier, "ppppppnnn")
	// Listed, a verifier that refuses: the refusal is the verifier's, at check 7.
	v, err = f.checker(withVerifier(handoff.StoreOpenPGPCard, failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "the chain is broken"}))).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)

	// Not listed: store-not-allowed at check 6 with the words of the policy, not the words for X.509, and the
	// verifier is not called.
	sv = returning(f.goodEvidence(handoff.StoreOpenPGPCard))
	v, err = f.checker(func(c *handoff.Config) {
		c.Policy.Stores = []handoff.Store{handoff.StorePIV, handoff.StoreKMS, handoff.StoreSoftware}
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreOpenPGPCard: sv}
	}).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
	if v.Detail != "the policy does not allow the store openpgp-card" {
		t.Errorf("detail %q", v.Detail)
	}
	if strings.Contains(v.Detail, "x509") || sv.calls.Load() != 0 {
		t.Errorf("detail %q, calls %d", v.Detail, sv.calls.Load())
	}
}

// Case 6: the other stores of an X.509 request are judged by the policy list as before.
func TestTheOtherStoresOfAnX509RequestAreJudgedByThePolicyListAsBefore(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreKMS, handoff.StoreSoftware} {
		t.Run(string(store), func(t *testing.T) {
			f := newStoreCase(t, store)
			sv := returning(f.good())
			acceptCase(t, f, sv, nil)
			// Not listed: the words of the policy.
			v, err := f.checker(sv, func(c *handoff.Config) {
				c.Policy.Stores = slices.DeleteFunc(slices.Clone(c.Policy.Stores), func(s handoff.Store) bool { return s == store })
			}).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
			if want := "the policy does not allow the store " + string(store); v.Detail != want {
				t.Errorf("detail %q, want %q", v.Detail, want)
			}
		})
	}
}

func acceptCase(t testing.TB, f *storeCase, sv handoff.EvidenceVerifier, change func(c *handoff.Config)) {
	t.Helper()
	v, err := f.checker(sv, change).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
}

// Case 7: the checks before check 6 judge first, whatever the store; the checks after it never run.
func TestAnX509RequestWithTheStoreOpenPGPCardGetsTheEarlierCodeOfAnEarlierFault(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T) *handoff.Request
		code handoff.Code
		n    int
	}{
		{"version 2", func(t *testing.T) *handoff.Request {
			f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
			f.proof["handoff"] = 2
			return f.request()
		}, handoff.CodeVersionUnsupported, 1},
		{"an unknown member", func(t *testing.T) *handoff.Request {
			f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
			f.proof["unknown"] = 1
			return f.request()
		}, handoff.CodeMalformed, 2},
		{"no evidence", func(t *testing.T) *handoff.Request {
			f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
			delete(f.proof, "evidence")
			return f.request()
		}, handoff.CodeMalformed, 2},
		{"a wrong digest", func(t *testing.T) *handoff.Request {
			f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
			f.proof["request_sha256"] = digestHex(nil)
			return f.request()
		}, handoff.CodeRequestMismatch, 3},
		{"a key on P-256", func(t *testing.T) *handoff.Request {
			return newFixture(t, handoff.StoreOpenPGPCard, csrSpec{key: otherKeys(t)["P-256"], sigAlg: x509.ECDSAWithSHA256}).request()
		}, handoff.CodeAlgorithmUnsupported, 4},
		{"a signature of another kind", func(t *testing.T) *handoff.Request {
			return newFixture(t, handoff.StoreOpenPGPCard, csrSpec{sigAlg: x509.ECDSAWithSHA256}).request()
		}, handoff.CodePossessionInvalid, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
			sv := returning(f.goodEvidence(handoff.StoreOpenPGPCard))
			v, err := checkerWith(t, handoff.StoreOpenPGPCard, sv).Check(t.Context(), tc.make(t))
			wantRefusal(t, v, err, tc.code, tc.n)
			if strings.Contains(v.Detail, "openpgp-card") {
				t.Errorf("the detail of check %d speaks of the store: %q", tc.n, v.Detail)
			}
			if sv.calls.Load() != 0 {
				t.Error("a verifier was called")
			}
		})
	}
	// A fault that check 9 would find does not change the refusal: check 6 comes first, and check 9 does not run.
	for name, spec := range map[string]csrSpec{
		"a name outside the delegation": {exts: goodExtensions(uriName("example.net"))},
		"a subject of 65 characters":    {subject: &pkixName65},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreOpenPGPCard, spec)
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantCardRefusal(t, v, err)
		})
	}
}

// The refusal does not need a delegation: it is the refusal of the store, and check 9 is not reached.
func TestTheRefusalOfTheCardStoreIsTheSameWithNoDelegation(t *testing.T) {
	f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
	chk := newCheckerWith(t, func(c *handoff.Config) { c.Delegation = nil })
	v, err := chk.Check(t.Context(), f.request())
	wantCardRefusal(t, v, err)
}

// Case 8: the nine results of the refusal, and what a verdict of the refusal does not hold.
func TestTheVerdictOfTheCardRefusalHoldsNoKeyNoEvidenceAndPlainWords(t *testing.T) {
	f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
	v := mustCheck(t, newChecker(t), f.request())
	if got := statuses(v); got != "pppppfnnn" {
		t.Fatalf("statuses %s", got)
	}
	if v.Code != handoff.CodeStoreNotAllowed || v.Key != nil || v.Evidence != nil || v.Subkey != nil {
		t.Errorf("code %q, key %v, evidence %v, subkey %v", v.Code, v.Key, v.Evidence, v.Subkey)
	}
	if !plain(v.Detail) || strings.ContainsAny(v.Detail, "\"\\") {
		t.Errorf("the words are not plain: %q", v.Detail)
	}
	for i, c := range v.Checks {
		if len(c.NotRun) != 0 {
			t.Errorf("check %d lists rules that did not run: %v", i+1, c.NotRun)
		}
	}
	// The same request again gives the same verdict: the refusal holds no state.
	again := mustCheck(t, newChecker(t), f.request())
	if statuses(again) != statuses(v) || again.Detail != v.Detail || again.Code != v.Code {
		t.Errorf("a second call differs: %+v", again)
	}
}

// The refusal belongs to the type. The store of an openpgp-subkey request is not read as the store of an X.509
// request, and a proof file that names one type is never judged as the other.
func TestTheCardRuleReadsTheTypeOfTheProofAndNotTheFilesOfTheRequest(t *testing.T) {
	// A proof of type openpgp-subkey that comes with a csr.pem and no subkey file is malformed at check 2: it is
	// not an X.509 request, so the card rule is not what answers.
	f := newFixture(t, handoff.StoreOpenPGPCard, csrSpec{})
	f.proof["type"] = "openpgp-subkey"
	f.proof["primaries"] = []string{strings.Repeat("a", 40)}
	f.proof["capabilities"] = []string{"sign"}
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	// The other way: a proof of type x509-intermediate with the file of a subkey and no csr.pem.
	g := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	req := g.request()
	req.Files[handoff.FileProof] = mustJSON(t, map[string]any{
		"handoff": 1, "type": "x509-intermediate", "store": "openpgp-card",
		"request_sha256": digestHex(req.Files[handoff.FileSubkey]), "evidence": evidenceFor(handoff.StoreOpenPGPCard),
	})
	v, err = newChecker(t).Check(t.Context(), req)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}
