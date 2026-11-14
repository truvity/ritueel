package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"math/big"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// A caller's key belongs to the caller. SecretKey and ParseSecretKey make copies of the scalar and
// clear what they made; they never clear the scalar that crypto/ecdsa keeps for the key, a buffer
// that Bytes handed out before, or the number of the caller's key (record 0002, rule 3).

func TestEverySecretKeyCallLeavesTheScalarOfTheCallersKeyAndTheBytesItHeldAsTheyWere(t *testing.T) {
	f := newSecretFixture(t)
	other := genKey(t)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	huge := privateWith(f.signer.key.PublicKey, new(big.Int).Lsh(big.NewInt(1), 500))
	cases := []struct {
		name string
		cert []byte
		priv *ecdsa.PrivateKey
		ok   bool
	}{
		{"a good call", f.cert, f.signer.key, true},
		{"a good call again", f.cert, f.signer.key, true},
		{"the certificate of another key", mustCert(t, other), f.signer.key, false},
		{"a nil certificate", nil, f.signer.key, false},
		{"junk for a certificate", bytes.Repeat([]byte{0xA5}, 100), f.signer.key, false},
		{"a certificate with a trailing byte", append(bytes.Clone(f.cert), 0), f.signer.key, false},
		{"the secret key where a certificate is meant", f.secret, f.signer.key, false},
	}
	for _, c := range cases {
		held, err := c.priv.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Clone(held)
		wantD := new(big.Int).SetBytes(want)
		//nolint:staticcheck // the test looks at the deprecated number on purpose
		dBefore := new(big.Int).Set(c.priv.D)
		out, err := openpgp.SecretKey(c.cert, c.priv)
		if (err == nil) != c.ok {
			t.Errorf("%s: error %v", c.name, err)
		}
		if !bytes.Equal(held, want) {
			t.Errorf("%s: the bytes that Bytes handed out before are changed", c.name)
		}
		again, err := c.priv.Bytes()
		if err != nil || !bytes.Equal(again, want) {
			t.Errorf("%s: the scalar of the key is changed (%v)", c.name, err)
		}
		//nolint:staticcheck // the deprecated number
		if c.priv.D.Cmp(dBefore) != 0 || c.priv.D.Cmp(wantD) != 0 {
			t.Errorf("%s: the number of the caller's key is changed", c.name)
		}
		clear(out)
	}
	// Keys that the package refuses before it reads the scalar keep their number too.
	for name, k := range map[string]*ecdsa.PrivateKey{"P-256": p256, "a number of 500 bits": huge, "another key": other} {
		//nolint:staticcheck // the deprecated number
		before := new(big.Int).Set(k.D)
		if out, err := openpgp.SecretKey(f.cert, k); err == nil || out != nil {
			t.Errorf("%s: %v", name, err)
		}
		//nolint:staticcheck // the deprecated number
		if k.D.Cmp(before) != 0 {
			t.Errorf("%s: the number of the caller's key is changed", name)
		}
	}
	// The key still signs after all of it.
	digest := sha512.Sum384([]byte("after"))
	sig, err := ecdsa.SignASN1(rand.Reader, f.signer.key, digest[:])
	if err != nil || !ecdsa.VerifyASN1(&f.signer.key.PublicKey, digest[:], sig) {
		t.Errorf("the key does not sign after the calls: %v", err)
	}
}

// One goroutine signs with the key while others write its secret key packet. Every signature
// verifies and every packet is the same bytes. The test waits on a WaitGroup and not on time; the
// race detector, run over the package, sees any unsynchronised clear of the shared scalar.
func TestSigningWithAKeyWhileItsSecretKeyIsWrittenGivesValidSignaturesAndTheSameBytes(t *testing.T) {
	f := newSecretFixture(t)
	const rounds = 12
	var wg sync.WaitGroup
	errs := make(chan string, 4*rounds)
	wg.Add(1)
	go func() {
		defer wg.Done()
		digest := sha512.Sum384([]byte("concurrent"))
		for i := 0; i < 8*rounds; i++ {
			sig, err := ecdsa.SignASN1(rand.Reader, f.signer.key, digest[:])
			if err != nil || !ecdsa.VerifyASN1(&f.signer.key.PublicKey, digest[:], sig) {
				errs <- "a signature made while the secret key was written does not verify"
				return
			}
		}
	}()
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				out, err := openpgp.SecretKey(f.cert, f.signer.key)
				if err != nil || !bytes.Equal(out, f.secret) {
					errs <- "the secret key written while another goroutine signs is not the same bytes"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// Two reads of the same bytes give two keys that share nothing: the number of one can be cleared
// and the other is still the key.
func TestTwoReadsOfOneSecretKeyGiveKeysThatShareNoMemory(t *testing.T) {
	f := newSecretFixture(t)
	a, _, _, err := openpgp.ParseSecretKey(f.secret)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _, err := openpgp.ParseSecretKey(f.secret)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // the deprecated number
	clear(a.D.Bits())
	//nolint:staticcheck // the deprecated number
	if b.D.Cmp(f.signer.key.D) != 0 {
		t.Error("clearing the number of one key changed the other")
	}
	// The key from the first read is not the caller's key either.
	//nolint:staticcheck // the deprecated number
	if f.signer.key.D.Sign() == 0 {
		t.Error("the caller's key was cleared")
	}
	digest := sha512.Sum384([]byte("two"))
	sig, err := ecdsa.SignASN1(rand.Reader, b, digest[:])
	if err != nil || !ecdsa.VerifyASN1(&f.signer.key.PublicKey, digest[:], sig) {
		t.Errorf("the second key does not sign: %v", err)
	}
}

// The input of ParseSecretKey is read, never changed.
func TestParseSecretKeyLeavesItsInputAsItWasOnSuccessAndOnEveryRefusal(t *testing.T) {
	f := newSecretFixture(t)
	inputs := map[string][]byte{
		"a good secret key":  f.secret,
		"a cut":              f.secret[:len(f.secret)-1],
		"a trailing byte":    append(bytes.Clone(f.secret), 1),
		"the certificate":    f.cert,
		"a changed checksum": secretRebuild(t, f.secret, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }),
		"a changed scalar":   secretRebuild(t, f.secret, func(b []byte) []byte { b[len(b)-3] ^= 1; return b }),
	}
	for name, in := range inputs {
		before := bytes.Clone(in)
		_, _, _, _ = openpgp.ParseSecretKey(in)
		if !bytes.Equal(in, before) {
			t.Errorf("%s: the input was changed", name)
		}
	}
}

// The scalar of the page is a multiprecision integer: the 48 bytes of the key with the leading
// zero bytes taken off, whatever the key is. The test builds keys whose scalars have a zero in
// front, and checks the integer in the packet against one made by hand.
func TestTheScalarInThePacketIsTheIntegerOfTheKeyWithNoLeadingZeroByteForAnyLeadingZeros(t *testing.T) {
	order := elliptic.P384().Params().N
	for zeros := 0; zeros <= 6; zeros++ {
		d := new(big.Int).Rsh(new(big.Int).Sub(order, big.NewInt(12345)), uint(8*zeros))
		if d.Sign() == 0 {
			t.Fatal("zero")
		}
		pub := scalarPublic(t, d)
		k := privateWith(*pub, d)
		cert := mustCert(t, k)
		out, err := openpgp.SecretKey(cert, k)
		if err != nil {
			t.Fatalf("%d bits: %v", d.BitLen(), err)
		}
		if !bytes.Contains(out, mpi(d)) {
			t.Errorf("%d bits: the packet does not hold the integer of the scalar", d.BitLen())
		}
		if bytes.Contains(out, append([]byte{byte(d.BitLen() >> 8), byte(d.BitLen()), 0}, d.Bytes()...)) {
			t.Errorf("%d bits: the integer has a leading zero byte", d.BitLen())
		}
		k2, _, cert2, err := openpgp.ParseSecretKey(out)
		if err != nil {
			t.Fatalf("%d bits: read back: %v", d.BitLen(), err)
		}
		//nolint:staticcheck // the deprecated number
		if k2.D.Cmp(d) != 0 || !bytes.Equal(cert2, cert) {
			t.Errorf("%d bits: not the same key", d.BitLen())
		}
	}
}

// scalarPublic is the public key of a scalar, made with crypto/ecdsa so that the point is right.
func scalarPublic(t testing.TB, d *big.Int) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), d.FillBytes(make([]byte, 48)))
	if err != nil {
		t.Fatal(err)
	}
	return &k.PublicKey
}
