package handoff_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// A key that names a curve and holds no point, or only one of the two coordinates, is data that a verifier
// or a configuration can hand over. It is never the key of a request, and it never stops a call with a panic:
// a verifier's key is `key-mismatch` at check 8, and a root key is a fault of the configuration.

// lookalike is a curve that is not one of the curves of the standard library, whatever it wraps.
type lookalike struct{ elliptic.Curve }

func pointlessKeys() map[string]*ecdsa.PublicKey {
	p256 := elliptic.P256()
	one := big.NewInt(1)
	g := elliptic.P384().Params()
	return map[string]*ecdsa.PublicKey{
		"P-384 with only X":            {Curve: elliptic.P384(), X: one},                                 //nolint:staticcheck // a key with no point is the case under test
		"P-384 with only Y":            {Curve: elliptic.P384(), Y: one},                                 //nolint:staticcheck // as above
		"P-384 with only the real X":   {Curve: elliptic.P384(), X: new(big.Int).Set(g.Gx)},              //nolint:staticcheck // as above
		"P-384 with only the real Y":   {Curve: elliptic.P384(), Y: new(big.Int).Set(g.Gy)},              //nolint:staticcheck // as above
		"P-256 with no point":          {Curve: p256},                                                    //nolint:staticcheck // as above
		"P-256 with only X":            {Curve: p256, X: one},                                            //nolint:staticcheck // as above
		"P-256 with only Y":            {Curve: p256, Y: one},                                            //nolint:staticcheck // as above
		"a curve of another type":      {Curve: lookalike{elliptic.P384()}, X: g.Gx, Y: g.Gy},            //nolint:staticcheck // as above
		"a curve of another type only": {Curve: lookalike{elliptic.P384()}},                              //nolint:staticcheck // as above
		"a zero X and a zero Y":        {Curve: elliptic.P384(), X: new(big.Int), Y: new(big.Int)},       //nolint:staticcheck // as above
		"a huge X and a huge Y":        {Curve: elliptic.P384(), X: new(big.Int).Lsh(one, 4000), Y: one}, //nolint:staticcheck // as above
	}
}

func TestAKeyOfAVerifierWithOnlyOneCoordinateIsKeyMismatchForEveryStore(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS} {
		f := newFixture(t, store, csrSpec{})
		for name, key := range pointlessKeys() {
			t.Run(string(store)+"/"+name, func(t *testing.T) {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("Check panicked on a key that a verifier returned: %v", r)
					}
				}()
				ev := f.goodEvidence(store)
				ev.Key = key
				sv := returning(ev)
				v, err := checkerWith(t, store, sv).Check(t.Context(), f.request())
				wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
				if v.Detail == "" || !plain(v.Detail) {
					t.Errorf("the detail is empty or not plain text: %q", v.Detail)
				}
				if sv.calls.Load() != 1 {
					t.Errorf("the verifier was called %d times", sv.calls.Load())
				}
			})
		}
	}
}

func TestAKeyOfAVerifierWithNoPointIsKeyMismatchBesideAKMSPublicKeyInTheProof(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	f.proof["evidence"] = kmsEvidence(f.publicKey())
	for name, key := range pointlessKeys() {
		t.Run(name, func(t *testing.T) {
			ev := f.goodEvidence(handoff.StoreKMS)
			ev.Key = key
			v, err := checkerWith(t, handoff.StoreKMS, returning(ev)).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
		})
	}
}

func TestACheckerServesTheNextCallAfterAVerifierGaveAKeyWithNoPoint(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	bad := f.goodEvidence(handoff.StorePIV)
	bad.Key = &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1)} //nolint:staticcheck // a key with no point is the case under test
	good := f.goodEvidence(handoff.StorePIV)
	var n int
	sv := &stub{fn: func(_ context.Context, _ *handoff.Request, _ *handoff.Proof, _ time.Time) (*handoff.Evidence, error) {
		n++
		if n%2 == 1 {
			return bad, nil
		}
		return good, nil
	}}
	chk := checkerWith(t, handoff.StorePIV, sv)
	for i := range 4 {
		v, err := chk.Check(t.Context(), f.request())
		if i%2 == 0 {
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
		} else {
			wantAccepted(t, v, err)
		}
	}
}

func TestARootWithOnlyOneCoordinateIsAConfigurationFault(t *testing.T) {
	good := newRoot(t, "Example Test Root")
	for name, key := range pointlessKeys() {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("New panicked on a root key that is not a point: %v", r)
				}
			}()
			for _, roots := range [][]handoff.RootRef{
				{{Subject: good.subject, Key: key}},
				{good.ref(), {Subject: []byte("other"), Key: key}},
				{{Subject: good.subject, Key: key}, good.ref()},
			} {
				cfg := defaultConfig(t)
				cfg.Roots = roots
				wantConfigError(t, cfg)
			}
		})
	}
}

func TestAConfigurationFaultOfARootKeyNamesTheRoot(t *testing.T) {
	good := newRoot(t, "Example Test Root")
	cfg := defaultConfig(t)
	cfg.Roots = []handoff.RootRef{good.ref(), {Subject: good.subject, Key: &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1)}}} //nolint:staticcheck // a key with no point is the case under test
	_, err := handoff.New(cfg)
	if err == nil || !strings.Contains(err.Error(), "root 1") {
		t.Errorf("the error does not name the root: %v", err)
	}
}
