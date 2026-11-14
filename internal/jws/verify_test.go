package jws_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"ritueel.id/ritueel/internal/jws"
)

// orderP384 is the order of the group of P-384, from the standard.
var orderP384 = elliptic.P384().Params().N

// rs writes r and s as one 96-byte signature.
func rs(r, s *big.Int) []byte {
	out := make([]byte, 96)
	r.FillBytes(out[:48])
	s.FillBytes(out[48:])
	return out
}

func TestVerifyES384Good(t *testing.T) {
	k := newKey(t)
	input := []byte("protected.payload")
	sig := k.rawSign(t, input)
	if err := jws.VerifyES384(&k.priv.PublicKey, input, sig); err != nil {
		t.Fatal(err)
	}
	t.Run("it is SHA-384, not another hash", func(t *testing.T) {
		for name, sum := range map[string][]byte{
			"SHA-256": func() []byte { s := sha256.Sum256(input); return s[:] }(),
			"SHA-512": func() []byte { s := sha512.Sum512(input); return s[:] }(),
		} {
			r, s, err := ecdsa.Sign(rand.Reader, k.priv, sum)
			if err != nil {
				t.Fatal(err)
			}
			if err := jws.VerifyES384(&k.priv.PublicKey, input, rs(r, s)); !errors.Is(err, jws.ErrSignature) {
				t.Errorf("a signature over the %s of the input verified: %v", name, err)
			}
		}
	})
	t.Run("the signature of an empty input", func(t *testing.T) {
		s := k.rawSign(t, nil)
		if err := jws.VerifyES384(&k.priv.PublicKey, nil, s); err != nil {
			t.Fatal(err)
		}
		if err := jws.VerifyES384(&k.priv.PublicKey, []byte{0}, s); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("the other key does not verify it", func(t *testing.T) {
		if err := jws.VerifyES384(&newKey(t).priv.PublicKey, input, sig); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("got %v", err)
		}
	})
}

func TestVerifyES384EveryChangeOfTheInputOrSignatureIsRefused(t *testing.T) {
	k := newKey(t)
	input := []byte("eyJhbGciOiJFUzM4NCJ9.e30")
	sig := k.rawSign(t, input)
	for i := range input {
		for _, mask := range []byte{0x01, 0x20, 0x80} {
			m := bytes.Clone(input)
			m[i] ^= mask
			if err := jws.VerifyES384(&k.priv.PublicKey, m, sig); !errors.Is(err, jws.ErrSignature) {
				t.Fatalf("input byte %d xor %#x verified or gave %v", i, mask, err)
			}
		}
	}
	for n := range len(input) {
		if err := jws.VerifyES384(&k.priv.PublicKey, input[:n], sig); !errors.Is(err, jws.ErrSignature) {
			t.Fatalf("input cut to %d verified or gave %v", n, err)
		}
	}
	if err := jws.VerifyES384(&k.priv.PublicKey, append(bytes.Clone(input), 0), sig); !errors.Is(err, jws.ErrSignature) {
		t.Errorf("input with a byte added verified")
	}
	for i := range sig {
		for _, mask := range []byte{0x01, 0x80} {
			m := bytes.Clone(sig)
			m[i] ^= mask
			if err := jws.VerifyES384(&k.priv.PublicKey, input, m); !errors.Is(err, jws.ErrSignature) {
				t.Fatalf("signature byte %d xor %#x verified or gave %v", i, mask, err)
			}
		}
	}
	for n := range len(sig) {
		if err := jws.VerifyES384(&k.priv.PublicKey, input, sig[:n]); !errors.Is(err, jws.ErrSignature) {
			t.Fatalf("signature cut to %d bytes verified or gave %v", n, err)
		}
	}
}

func TestVerifyES384SignatureForms(t *testing.T) {
	k := newKey(t)
	input := []byte("protected.payload")
	sig := k.rawSign(t, input)
	r := new(big.Int).SetBytes(sig[:48])
	s := new(big.Int).SetBytes(sig[48:])
	one := big.NewInt(1)
	pub := &k.priv.PublicKey
	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"95 bytes", sig[:95]},
		{"97 bytes", append(bytes.Clone(sig), 0)},
		{"the ASN.1 form", asn1Sig(t, k, input)},
		{"the ASN.1 form of 103 bytes", der103()},
		{"r and s swapped", rs(s, r)},
		{"r zero", rs(new(big.Int), s)},
		{"s zero", rs(r, new(big.Int))},
		{"r and s zero", make([]byte, 96)},
		{"r the order of the group", rs(orderP384, s)},
		{"s the order of the group", rs(r, orderP384)},
		{"r the order plus one", rs(new(big.Int).Add(orderP384, one), s)},
		{"s the order plus one", rs(r, new(big.Int).Add(orderP384, one))},
		{"r the order minus one", rs(new(big.Int).Sub(orderP384, one), s)},
		{"r and s 2^384 minus one", bytes.Repeat([]byte{0xff}, 96)},
		{"r one and s one", rs(one, one)},
		{"r the order of the group less than s", rs(orderP384, orderP384)},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := jws.VerifyES384(pub, input, c.sig)
			if !errors.Is(err, jws.ErrSignature) {
				t.Fatalf("got %v, want ErrSignature", err)
			}
			mustBeASCII(t, "the error text", err.Error())
		})
	}
	t.Run("a signature that is r and s as numbers but not as 48 bytes each is refused", func(t *testing.T) {
		// The same two numbers, written in another number of bytes: 97 bytes with a zero before s,
		// and 95 bytes with the leading zero byte of s left out. Both split at byte 48 into a
		// valid r and a valid s, so only the length says no.
		padded := append(append(bytes.Clone(sig[:48]), 0), sig[48:]...)
		if err := jws.VerifyES384(pub, input, padded); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("97 bytes: got %v", err)
		}
		for range 100000 {
			short := k.rawSign(t, input)
			if short[48] != 0 {
				continue
			}
			if err := jws.VerifyES384(pub, input, short); err != nil {
				t.Fatalf("the full form is refused: %v", err)
			}
			if err := jws.VerifyES384(pub, input, append(bytes.Clone(short[:48]), short[49:]...)); !errors.Is(err, jws.ErrSignature) {
				t.Errorf("95 bytes: got %v", err)
			}
			return
		}
		t.Fatal("no signature with a zero first byte of s in 100000 tries")
	})
	t.Run("the signature with s replaced by the order less s verifies, as ECDSA allows", func(t *testing.T) {
		// A second valid signature for the same input exists for every signature. Nothing in the
		// format uses a signature as an identifier, so it is not a fault; the test says so.
		high := rs(r, new(big.Int).Sub(orderP384, s))
		if err := jws.VerifyES384(pub, input, high); err != nil {
			t.Errorf("the high-s form is refused: %v", err)
		}
	})
}

// asn1Sig is the DER form that a library of ECDSA writes.
func asn1Sig(t *testing.T, k *key, input []byte) []byte {
	t.Helper()
	sum := sha512.Sum384(input)
	der, err := ecdsa.SignASN1(rand.Reader, k.priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(der) == 96 {
		t.Fatal("the DER form is 96 bytes; run again")
	}
	return der
}

func TestVerifyES384RefusesKeysThatAreNotP384(t *testing.T) {
	input := []byte("protected.payload")
	good := newKey(t)
	sig := good.rawSign(t, input)
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P224(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			k := newKeyOn(t, curve)
			// A signature of the right form over the input, made by that key.
			for _, s := range [][]byte{sig, make([]byte, 96), bytes.Repeat([]byte{0x7f}, 96)} {
				if err := jws.VerifyES384(&k.priv.PublicKey, input, s); !errors.Is(err, jws.ErrSignature) {
					t.Errorf("got %v, want ErrSignature", err)
				}
			}
		})
	}
	t.Run("nil key", func(t *testing.T) {
		if err := jws.VerifyES384(nil, input, sig); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a key with no curve", func(t *testing.T) {
		if err := jws.VerifyES384(&ecdsa.PublicKey{}, input, sig); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a key on P-384 with no point", func(t *testing.T) {
		if err := jws.VerifyES384(&ecdsa.PublicKey{Curve: elliptic.P384()}, input, sig); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("got %v", err)
		}
	})
	t.Run("a key on P-384 with only one coordinate", func(t *testing.T) {
		pub := &ecdsa.PublicKey{Curve: elliptic.P384()}
		pub.X = big.NewInt(1) //nolint:staticcheck // the test builds a key that has no point
		if err := jws.VerifyES384(pub, input, sig); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("only X: got %v", err)
		}
		pub = &ecdsa.PublicKey{Curve: elliptic.P384()}
		pub.Y = big.NewInt(1) //nolint:staticcheck // the test builds a key that has no point
		if err := jws.VerifyES384(pub, input, sig); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("only Y: got %v", err)
		}
	})
	for name, xy := range map[string][2]*big.Int{
		"a point that is not on the curve":   {big.NewInt(1), big.NewInt(1)},
		"the point at the origin":            {new(big.Int), new(big.Int)},
		"a point with negative coordinates":  {big.NewInt(-1), big.NewInt(-1)},
		"a point with coordinates above p":   {new(big.Int).Lsh(big.NewInt(1), 400), new(big.Int).Lsh(big.NewInt(1), 400)},
		"a good point with the y of another": {good.priv.PublicKey.X, big.NewInt(2)}, //nolint:staticcheck // reads the coordinate of a made key
	} {
		t.Run(name, func(t *testing.T) {
			pub := &ecdsa.PublicKey{Curve: elliptic.P384()}
			pub.X, pub.Y = xy[0], xy[1] //nolint:staticcheck // the test builds a key that is not a point of the curve
			if err := jws.VerifyES384(pub, input, sig); !errors.Is(err, jws.ErrSignature) {
				t.Errorf("got %v", err)
			}
		})
	}
}

func TestSignatureVerifyRefusesCertificatesThatAreNotP384Keys(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"sequence":7}`)
	p := goodHeader(k, typList).text()
	sig := k.rawSign(t, []byte(p+"."+b64u(payload)))
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"no certificate", nil},
		{"a certificate with no key", &x509.Certificate{}},
		{"an Ed25519 key", &x509.Certificate{PublicKey: ed}},
		{"an RSA key", &x509.Certificate{PublicKey: &rk.PublicKey}},
		{"an ECDSA key as a value and not a pointer", &x509.Certificate{PublicKey: k.priv.PublicKey}},
		{"a P-256 key", newKeyOn(t, elliptic.P256()).cert},
		{"a P-384 key with no point", &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384()}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := jws.Signature{Protected: p, Sig: sig, Cert: c.cert}
			if err := s.Verify(payload); !errors.Is(err, jws.ErrSignature) {
				t.Errorf("got %v, want ErrSignature", err)
			}
		})
	}
	t.Run("the right key verifies", func(t *testing.T) {
		s := jws.Signature{Protected: p, Sig: sig, Cert: k.cert}
		if err := s.Verify(payload); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the protected text, the payload and the signature are each covered", func(t *testing.T) {
		for name, s := range map[string]jws.Signature{
			"protected": {Protected: p + "A", Sig: sig, Cert: k.cert},
			"signature": {Protected: p, Sig: append(bytes.Clone(sig[:95]), sig[95]^1), Cert: k.cert},
		} {
			if err := s.Verify(payload); !errors.Is(err, jws.ErrSignature) {
				t.Errorf("%s: got %v", name, err)
			}
		}
		s := jws.Signature{Protected: p, Sig: sig, Cert: k.cert}
		for _, other := range [][]byte{nil, payload[:len(payload)-1], append(bytes.Clone(payload), '\n'), []byte(`{"sequence":8}`)} {
			if err := s.Verify(other); !errors.Is(err, jws.ErrSignature) {
				t.Errorf("payload %q: got %v", other, err)
			}
		}
	})
}

func TestSigningInput(t *testing.T) {
	for _, c := range []struct {
		protected string
		payload   []byte
		want      string
	}{
		{"abc", []byte("x"), "abc.eA"},
		{"abc", nil, "abc."},
		{"", []byte("x"), ".eA"},
		{"abc", []byte("xy"), "abc.eHk"},
		{"abc", []byte("xyz"), "abc.eHl6"},
		{"abc", []byte{0xfb, 0xff, 0xbf}, "abc.-_-_"},
		{"abc", []byte{0xfb, 0xff}, "abc.-_8"},
		{"abc", []byte("{\"a\":1}\n"), "abc.eyJhIjoxfQo"},
	} {
		if got := string(jws.SigningInput(c.protected, c.payload)); got != c.want {
			t.Errorf("SigningInput(%q, %q) = %q, want %q", c.protected, c.payload, got, c.want)
		}
	}
	t.Run("every byte value", func(t *testing.T) {
		all := make([]byte, 256)
		for i := range all {
			all[i] = byte(i)
		}
		got := string(jws.SigningInput("p", all))
		if got[:2] != "p." || len(got) != 2+342 || bytes.ContainsAny([]byte(got), "=+/\n") {
			t.Errorf("not Base64url without padding: %q", got)
		}
	})
	t.Run("the protected text is not changed or decoded", func(t *testing.T) {
		const odd = "a b\n=+/c"
		if got := string(jws.SigningInput(odd, []byte("x"))); got != odd+".eA" {
			t.Errorf("got %q", got)
		}
	})
}

func TestPin(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P256()} {
		k := newKeyOn(t, curve)
		der, err := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(der)
		want := hex.EncodeToString(sum[:])
		got := jws.Pin(k.cert)
		if got != want {
			t.Errorf("Pin = %s, want %s", got, want)
		}
		if len(got) != 64 || got != k.pin {
			t.Errorf("Pin is not 64 lower-case hexadecimal digits: %s", got)
		}
	}
	a, b := newKey(t), newKey(t)
	if jws.Pin(a.cert) == jws.Pin(b.cert) {
		t.Errorf("two keys have one pin")
	}
	t.Run("a certificate re-issued over the same key keeps its pin", func(t *testing.T) {
		again := reissue(t, a)
		if again.Raw == nil || bytes.Equal(again.Raw, a.cert.Raw) {
			t.Fatal("the certificate was not issued again")
		}
		if jws.Pin(again) != jws.Pin(a.cert) {
			t.Errorf("the pin changed with the certificate")
		}
	})
}

// reissue makes another certificate over the key of k.
func reissue(t *testing.T, k *key) *x509.Certificate {
	t.Helper()
	tmpl := *k.cert
	tmpl.SerialNumber = big.NewInt(2)
	tmpl.Raw, tmpl.RawTBSCertificate, tmpl.RawSubjectPublicKeyInfo = nil, nil, nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &k.priv.PublicKey, k.priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
