package attest_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// The page, "Key match (check 8)": the attested key is the key of the slot certificate. KeyOf returns it
// as ECDSA on P-384, and any other key is a refusal of the evidence (the page leaves the code open; proof-invalid is the one built).
func TestKeyOfReturnsTheP384KeyOfTheCertificate(t *testing.T) {
	m := newMaker(t)
	key := attesttest.P384(t)
	leaf, _ := m.PIVChain(t, key.Public(), attesttest.Slot{})
	cert := mustCert(t, leaf)
	got, err := attest.KeyOf(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(key.Public()) {
		t.Error("the attested key is not the key of the certificate")
	}
	if got.Curve != elliptic.P384() {
		t.Errorf("curve %v", got.Curve.Params().Name)
	}
}

// The key is a copy: a change to the coordinates of what was returned reaches neither the certificate nor
// the next call.
func TestKeyOfReturnsACopy(t *testing.T) {
	m := newMaker(t)
	key := attesttest.P384(t)
	leaf, _ := m.PIVChain(t, key.Public(), attesttest.Slot{})
	cert := mustCert(t, leaf)
	first, err := attest.KeyOf(cert)
	if err != nil {
		t.Fatal(err)
	}
	orig := cert.PublicKey.(*ecdsa.PublicKey)
	if first == orig || first.X == orig.X || first.Y == orig.Y { //nolint:staticcheck // the coordinates are the only way to see a shared big number
		t.Fatal("the returned key shares a pointer with the certificate")
	}
	first.X.SetInt64(1) //nolint:staticcheck // the coordinates are the only way to change a key in place
	first.Y.SetInt64(2) //nolint:staticcheck // the coordinates are the only way to change a key in place
	second, err := attest.KeyOf(cert)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Equal(key.Public()) {
		t.Error("a change to a returned key reached the certificate")
	}
	if !orig.Equal(key.Public()) {
		t.Error("the certificate's key changed")
	}
	if second == first {
		t.Error("two calls returned the same key")
	}
}

// Every key but ECDSA on P-384 is a refusal with proof-invalid and fixed words. The page says nothing about
// the code for an attested key of another kind; the one built is proof-invalid, and this test names it.
func TestKeyOfRefusesEveryOtherKey(t *testing.T) {
	m := newMaker(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, pub := range map[string]any{
		"P-256":   p256.Public(),
		"P-521":   p521.Public(),
		"P-224":   p224.Public(),
		"RSA":     rsaKey.Public(),
		"Ed25519": edPub,
	} {
		t.Run(name, func(t *testing.T) {
			leaf, _ := m.PIVChain(t, pub, attesttest.Slot{})
			cert := mustCert(t, leaf)
			k, err := attest.KeyOf(cert)
			if k != nil {
				t.Error("a key beside a refusal")
			}
			wantRefusal(t, err, handoff.CodeProofInvalid)
		})
	}
}

// KeyOf on a certificate built by hand never panics: no key, a key of another type, a P-384 key with no
// coordinates or with a point that is not on the curve.
func TestKeyOfOnACertificateThatIsNotWhole(t *testing.T) {
	var nilKey *ecdsa.PublicKey
	for name, c := range map[string]*x509.Certificate{
		"no key":                        {},
		"a nil key of the ECDSA type":   {PublicKey: nilKey},
		"a key with no curve":           {PublicKey: &ecdsa.PublicKey{}},
		"a P-384 key with no point":     {PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384()}},
		"a P-384 key off the curve":     {PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(1)}}, //nolint:staticcheck // the coordinates are the only way to make a point that is not on the curve
		"a P-384 key with a nil Y":      {PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1)}},                   //nolint:staticcheck // the coordinates are the only way to make a key that is not whole
		"a key that is a string":        {PublicKey: "text"},
		"an ECDSA value, not a pointer": {PublicKey: ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(1)}}, //nolint:staticcheck // the coordinates are the only way to make a key that is not whole
	} {
		t.Run(name, func(t *testing.T) {
			k, err := attest.KeyOf(c)
			if k != nil {
				t.Error("a key beside a refusal")
			}
			wantRefusal(t, err, handoff.CodeProofInvalid)
		})
	}
	// No certificate at all is a fault of the caller.
	if k, err := attest.KeyOf(nil); k != nil {
		t.Error("a key for no certificate")
	} else {
		wantPlainError(t, err)
	}
}

// Many goroutines call one bundle on the same evidence and get the same answer; the bundle is immutable.
// The test joins them with a WaitGroup and decides nothing by timing.
func TestOneBundleServesManyCallsAtOnce(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	good := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	bad := m.PIVEvidence(t, p384(t), attesttest.Slot{UnpinnedIssuer: true})
	const n = 32
	var wg sync.WaitGroup
	errs := make([]error, 2*n)
	for i := range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs[i] = verify(t, b, attest.AppletPIV, good, clock)
		}()
		go func() {
			defer wg.Done()
			errs[n+i] = verify(t, b, attest.AppletPIV, bad, clock)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Errorf("goroutine %d, good evidence: %v", i, errs[i])
		}
		wantRefusal(t, errs[n+i], handoff.CodeProofInvalid)
	}
}
