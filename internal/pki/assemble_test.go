package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"math/big"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

func TestAssemble(t *testing.T) {
	key := newKey(t)
	tbs := mustRootTBS(t, key)
	sig := signatureOf(t, key, tbs)
	der, err := pki.Assemble(tbs, sig, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// The certificate is the body, the algorithm and the signature, in a sequence.
	want := tlv(0x30, tbs, algECDSAWithSHA384DER, tlv(0x03, []byte{0x00}, sig))
	if !bytes.Equal(der, want) {
		t.Errorf("the certificate is not SEQUENCE { body, ecdsa-with-SHA384, BIT STRING { 0, signature } }:\n got %x\nwant %x", der, want)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.RawTBSCertificate, tbs) || !bytes.Equal(cert.Signature, sig) || cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Error("the certificate does not hold the parts it was made of")
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
	// The result is a copy: a change to the inputs does not reach it.
	snapshot := append([]byte(nil), der...)
	tbs[len(tbs)-1] ^= 0xff
	sig[0] ^= 0xff
	if !bytes.Equal(der, snapshot) {
		t.Error("the certificate shares memory with its inputs")
	}
}

// A signature that is not for this body, by this key, is refused: Assemble verifies it with the issuer key
// and does not depend on Sign having been used.
func TestAssembleChecksTheSignatureAgainstTheBodyAndTheKey(t *testing.T) {
	f := newGuardFixture(t)
	rootPub, otherKey := &f.root.key.PublicKey, newKey(t)
	rootSig := signatureOf(t, f.root.key, f.root.tbs)
	interSig := signatureOf(t, f.root.key, f.inter.tbs)
	secondRootBody := rootBodyWithSerial(t, f.root.key, 3)
	rows := []struct {
		name   string
		tbs    []byte
		sig    []byte
		issuer *ecdsa.PublicKey
	}{
		{"the signature of another body (a root's of an intermediate's)", f.inter.tbs, rootSig, rootPub},
		{"the signature of another body (an intermediate's of a root's)", f.root.tbs, interSig, rootPub},
		{"the signature of another root body with another serial", secondRootBody, rootSig, rootPub},
		{"a signature by another key, for a root body", f.root.tbs, rawSign(t, otherKey, f.root.tbs), rootPub},
		{"a signature by another key, for an intermediate body", f.inter.tbs, rawSign(t, otherKey, f.inter.tbs), rootPub},
		{"a good signature, and the key of another issuer, for a root body", f.root.tbs, rootSig, &otherKey.PublicKey},
		{"a good signature, and the key of another issuer, for an intermediate body", f.inter.tbs, interSig, &otherKey.PublicKey},
		{"a good signature, and the key of the intermediate itself, for its body", f.inter.tbs, interSig, &f.inter.csr.Key.PublicKey},
		{"a signature of the body made with another key that the issuer key is named by (right signature, wrong key)", f.inter.tbs, rawSign(t, f.inter.csr.Key, f.inter.tbs), &f.inter.csr.Key.PublicKey},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			der, err := pki.Assemble(r.tbs, r.sig, r.issuer)
			refused(t, err, pki.ErrSignature)
			if der != nil {
				t.Error("a certificate came with the error")
			}
		})
	}
	t.Run("a typed nil key", func(t *testing.T) {
		der, err := pki.Assemble(f.root.tbs, rootSig, (*ecdsa.PublicKey)(nil))
		refused(t, err, pki.ErrParams)
		if der != nil {
			t.Error("a certificate came with the error")
		}
	})
	for name, key := range badKeys(t) {
		t.Run("the issuer key is "+name, func(t *testing.T) {
			_, err := pki.Assemble(f.root.tbs, rootSig, key)
			refused(t, err, pki.ErrParams)
		})
	}
	t.Run("the honest ones", func(t *testing.T) {
		for _, c := range []struct {
			tbs, sig []byte
		}{{f.root.tbs, rootSig}, {f.inter.tbs, interSig}} {
			if _, err := pki.Assemble(c.tbs, c.sig, rootPub); err != nil {
				t.Error(err)
			}
		}
	})
}

// A body that no builder returns is not assembled, whatever signature it has: a key may have signed it, but
// this package does not put a certificate together from it.
func TestAssembleRefusesABodyThatNoBuilderReturns(t *testing.T) {
	f := newGuardFixture(t)
	key := f.root.key
	edit := func(base []byte, find, repl []byte) []byte {
		i := bytes.Index(base, find)
		if i < 0 {
			t.Fatalf("%x is not in the body", find)
		}
		out := append([]byte(nil), base...)
		copy(out[i:], repl)
		return out
	}
	version := []byte{0xa0, 0x03, 0x02, 0x01, 0x02}
	alg := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}
	bodies := []struct {
		name string
		tbs  []byte
	}{
		{"no body", nil},
		{"an empty body", []byte{}},
		{"a body cut by one byte", f.root.tbs[:len(f.root.tbs)-1]},
		{"a body cut to its first 10 bytes", f.root.tbs[:10]},
		{"a body with a byte after it", append(append([]byte{}, f.root.tbs...), 0x00)},
		{"two bodies", append(append([]byte{}, f.root.tbs...), f.root.tbs...)},
		{"a set instead of a sequence", append([]byte{0x31}, f.root.tbs[1:]...)},
		{"a primitive sequence tag", append([]byte{0x10}, f.root.tbs[1:]...)},
		{"version 1", edit(f.root.tbs, version, []byte{0xa0, 0x03, 0x02, 0x01, 0x00})},
		{"version 2", edit(f.root.tbs, version, []byte{0xa0, 0x03, 0x02, 0x01, 0x01})},
		{"the algorithm ecdsa-with-SHA256", edit(f.root.tbs, alg, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02})},
		{"the algorithm ecdsa-with-SHA512", edit(f.root.tbs, alg, []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04})},
		{"a bare sequence", tlv(0x30, []byte("garbage"))},
		{"a sequence of three integers", tlv(0x30, tlv(0x02, []byte{1}), tlv(0x02, []byte{2}), tlv(0x02, []byte{3}))},
		{"the version, a serial and an algorithm, and nothing more", tlv(0x30, version, tlv(0x02, []byte{1}), algECDSAWithSHA384DER)},
		{"a root body with a changed letter in the subject only", func() []byte {
			b := append([]byte(nil), f.root.tbs...)
			b[bytes.LastIndex(b, []byte("Example"))] = 'F'
			return b
		}()},
		{"a root body with a changed letter in the issuer only", func() []byte {
			b := append([]byte(nil), f.root.tbs...)
			b[bytes.Index(b, []byte("Example"))] = 'F'
			return b
		}()},
		{"an intermediate body with another extension order", func() []byte {
			// The key usage written before the basic constraints.
			b := append([]byte(nil), f.inter.tbs...)
			bc := []byte{0x30, 0x12, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}
			ku := []byte{0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06}
			i := bytes.Index(b, bc)
			if i < 0 || !bytes.Equal(b[i+len(bc):i+len(bc)+len(ku)], ku) {
				t.Fatal("the fixture's extensions are not where the test expects them")
			}
			copy(b[i:], ku)
			copy(b[i+len(ku):], bc)
			return b
		}()},
	}
	for _, c := range bodies {
		t.Run(c.name, func(t *testing.T) {
			// A signature that verifies over these very bytes: the refusal is the body's.
			sig := rawSign(t, key, c.tbs)
			der, err := pki.Assemble(c.tbs, sig, &key.PublicKey)
			refused(t, err, pki.ErrSignature)
			if der != nil {
				t.Errorf("a certificate %x came with the error", der)
			}
		})
	}
}

// A body with the letter changed in both names is another valid root name, so it is another body that a
// builder returns, and it is assembled with a signature that verifies over it.
func TestAssembleAcceptsAnotherBodyThatABuilderCouldReturn(t *testing.T) {
	key := newKey(t)
	tbs := mustRootTBS(t, key)
	b := append([]byte(nil), tbs...)
	for i := 0; ; {
		j := bytes.Index(b[i:], []byte("Example"))
		if j < 0 {
			break
		}
		b[i+j] = 'F'
		i += j + 1
	}
	if _, err := pki.Assemble(b, rawSign(t, key, b), &key.PublicKey); err != nil {
		t.Error(err)
	}
}

func TestAssembleRefusesASignatureOfAWrongForm(t *testing.T) {
	key := newKey(t)
	tbs := mustRootTBS(t, key)
	sig := signatureOf(t, key, tbs)
	n := elliptic.P384().Params().N
	ones := bytes.Repeat([]byte{0x01}, 48)
	derSig := func(r, s []byte) []byte { return tlv(0x30, tlv(0x02, r), tlv(0x02, s)) }
	be := func(x *big.Int) []byte { return append([]byte{0}, x.Bytes()...) }
	rows := []struct {
		name string
		sig  []byte
	}{
		{"no signature", nil},
		{"an empty signature", []byte{}},
		{"a signature cut by one byte", sig[:len(sig)-1]},
		{"a signature with a byte after it", append(append([]byte{}, sig...), 0x00)},
		{"the raw r and s", bytes.Repeat([]byte{0x07}, 96)},
		{"r is zero", derSig([]byte{0}, ones)},
		{"s is zero", derSig(ones, []byte{0})},
		{"r is the order", derSig(be(n), ones)},
		{"s is the order", derSig(ones, be(n))},
		{"r is much larger than the order", derSig(append([]byte{0}, bytes.Repeat([]byte{0xff}, 60)...), ones)},
		{"r is negative", derSig([]byte{0xff}, ones)},
		{"r with a useless leading zero", derSig(append([]byte{0}, ones...), ones)},
		{"r that is empty", derSig(nil, ones)},
		{"one integer", tlv(0x30, tlv(0x02, ones))},
		{"three integers", tlv(0x30, tlv(0x02, ones), tlv(0x02, ones), tlv(0x02, ones))},
		{"a bit string", tlv(0x03, []byte{0}, ones)},
		{"a set", tlv(0x31, tlv(0x02, ones), tlv(0x02, ones))},
		{"an empty sequence", []byte{0x30, 0x00}},
		{"a sequence of octet strings", tlv(0x30, tlv(0x04, ones), tlv(0x04, ones))},
		{"a sequence of indefinite length", []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00}},
		{"a well-formed value that is not a signature of the body", derSig([]byte{1}, []byte{1})},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			der, err := pki.Assemble(tbs, c.sig, &key.PublicKey)
			refused(t, err, pki.ErrSignature)
			if der != nil {
				t.Error("a certificate came with the error")
			}
		})
	}
	t.Run("the signature of the key, as it is, is accepted", func(t *testing.T) {
		if _, err := pki.Assemble(tbs, sig, &key.PublicKey); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a high s is accepted", func(t *testing.T) {
		if _, err := pki.Assemble(tbs, highS(t, sig), &key.PublicKey); err != nil {
			t.Fatal(err)
		}
	})
}

// The sentence that Assemble does not check the signature is gone: a made-up signature is refused.
func TestAssembleDoesCheckTheSignatureAgainstTheKey(t *testing.T) {
	key := newKey(t)
	tbs := mustRootTBS(t, key)
	wrong := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	_, err := pki.Assemble(tbs, wrong, &key.PublicKey)
	refused(t, err, pki.ErrSignature)
}
