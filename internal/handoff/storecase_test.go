package handoff_test

import (
	"crypto/ecdsa"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// A store case is one good request that the page lets use the store, with the checker that serves it. The
// store openpgp-card is not a store of an X.509 intermediate (check 6 refuses it, see cardstore_test.go), so
// its case is a request of type openpgp-subkey; every other store is held by a request of type
// x509-intermediate. A test that is about the key, the evidence or the proof of a store, and not about the
// type, runs over store cases, so that the card store is still tested at the checks it reaches.
type storeCase struct {
	store   handoff.Store
	typ     handoff.Type
	proof   map[string]any
	key     *ecdsa.PublicKey
	request func() *handoff.Request
	good    func() *handoff.Evidence
	checker func(v handoff.EvidenceVerifier, change func(c *handoff.Config)) *handoff.Checker
}

// newStoreCase makes the case of a store.
func newStoreCase(t testing.TB, store handoff.Store) *storeCase {
	t.Helper()
	if store == handoff.StoreOpenPGPCard {
		f := newPGPFixture(t, 2, store)
		return &storeCase{
			store: store, typ: handoff.TypeOpenPGP, proof: f.proof, key: f.sub.pub(),
			request: f.request,
			good:    func() *handoff.Evidence { return f.goodEvidence(store) },
			checker: func(v handoff.EvidenceVerifier, change func(c *handoff.Config)) *handoff.Checker {
				return f.checker(func(c *handoff.Config) {
					if v != nil {
						c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{store: v}
					}
					if change != nil {
						change(c)
					}
				})
			},
		}
	}
	f := newFixture(t, store, csrSpec{})
	return &storeCase{
		store: store, typ: handoff.TypeX509, proof: f.proof, key: f.publicKey(),
		request: f.request,
		good:    func() *handoff.Evidence { return f.goodEvidence(store) },
		checker: func(v handoff.EvidenceVerifier, change func(c *handoff.Config)) *handoff.Checker {
			return newCheckerWith(t, func(c *handoff.Config) {
				if v != nil {
					c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{store: v}
				}
				if change != nil {
					change(c)
				}
			})
		},
	}
}
