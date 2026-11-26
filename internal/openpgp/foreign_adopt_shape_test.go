package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"

	gecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The shape of the lone secret key packet, held by a reader of the tests and by go-crypto, and the
// signatures of the key that is read back from it, checked with the standard library.

// alPublicOf is the public key that the public part of a packet says, made from the pieces as the
// tests read them.
func alPublicOf(t testing.TB, p alPacket) crypto.PublicKey {
	t.Helper()
	switch p.alg() {
	case 1:
		return &rsa.PublicKey{N: new(big.Int).SetBytes(p.Pub[0][2:]), E: int(new(big.Int).SetBytes(p.Pub[1][2:]).Int64())}
	case 19:
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), p.Pub[1][2:])
		if err != nil {
			t.Fatalf("the point of the packet is not a point of P-384: %v", err)
		}
		return pub
	case 22:
		return ed25519.PublicKey(bytes.Clone(p.Pub[1][3:]))
	}
	t.Fatalf("the algorithm %d", p.alg())
	return nil
}

// alSignAndVerify signs with a signer in the way of its algorithm and verifies each signature with the
// standard library against the public key that the tests read from the packet.
func alSignAndVerify(t testing.TB, s crypto.Signer, pub crypto.PublicKey) {
	t.Helper()
	msg := []byte("a message to be signed")
	switch k := pub.(type) {
	case *rsa.PublicKey:
		for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA512} {
			var d []byte
			if h == crypto.SHA256 {
				s := sha256.Sum256(msg)
				d = s[:]
			} else {
				s := sha512.Sum512(msg)
				d = s[:]
			}
			sig, err := s.Sign(rand.Reader, d, h)
			if err != nil || rsa.VerifyPKCS1v15(k, h, d, sig) != nil {
				t.Errorf("an RSA signature with %v does not verify: %v", h, err)
			}
		}
	case ed25519.PublicKey:
		sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil || !ed25519.Verify(k, msg, sig) {
			t.Errorf("an Ed25519 signature does not verify: %v", err)
		}
	case *ecdsa.PublicKey:
		d := sha512.Sum384(msg)
		sig, err := s.Sign(rand.Reader, d[:], crypto.SHA384)
		if err != nil || !ecdsa.VerifyASN1(k, d[:], sig) {
			t.Errorf("an ECDSA signature does not verify: %v", err)
		}
	default:
		t.Errorf("the public key is %T", pub)
	}
}

func TestTheLonePacketIsTheOneThatTheStandardDescribes(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, protected := range []bool{false, true} {
			k, pkt, p := alLone(t, b, protected)
			// the header, the version, the time and the algorithm
			if len(pkt) > openpgp.MaxAdoptedPacketBytes {
				t.Errorf("the packet is %d bytes, over MaxAdoptedPacketBytes", len(pkt))
			}
			if p.Head[0] != 4 || binary.BigEndian.Uint32(p.Head[1:5]) != uint32(fkEpoch.Unix()) || p.alg() != b.want.ID {
				t.Errorf("the fixed octets are % x, want version 4, the creation time and algorithm %d", p.Head, b.want.ID)
			}
			if p.Usage != 0 {
				t.Errorf("the usage is %d", p.Usage)
			}
			// the public part: the body of the first packet of the certificate, and the one that go-crypto
			// writes for the key
			first := fkSplit(t, k.Certificate())[0]
			if first.Tag != 6 || !bytes.Equal(p.pubBody(), first.Body) || !bytes.Equal(p.pubBody(), b.pubBody(t)) {
				t.Errorf("the public part is not the body of the first packet of the certificate")
			}
			if got := alFingerprint(p.pubBody()); got != k.Primary.Fingerprint {
				t.Errorf("the fingerprint of the public part is %s, the key says %s", got, k.Primary.Fingerprint)
			}
			// the secret numbers are those of the template, in the order of the standard
			own := b.secrets(t).Primary
			vals := p.values()
			if len(vals) != len(own) {
				t.Fatalf("the packet holds %d numbers, the key %d", len(vals), len(own))
			}
			for i := range own {
				if !bytes.Equal(vals[i], bytes.TrimLeft(own[i], "\x00")) {
					t.Errorf("the secret number %d is not the number of the key", i)
				}
			}
			switch b.name {
			case "rsa4096":
				if got := new(big.Int).SetBytes(p.Pub[0][2:]).BitLen(); got != 4096 {
					t.Errorf("the modulus has %d bits", got)
				}
				if !bytes.Equal(p.Pub[1][2:], []byte{1, 0, 1}) {
					t.Errorf("the exponent is % x", p.Pub[1][2:])
				}
				if len(p.Sec) != 4 {
					t.Errorf("RSA has %d secret numbers", len(p.Sec))
				}
			case "p384":
				if !bytes.Equal(p.Pub[0], []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}) || len(p.Pub[1]) != 2+97 || p.Pub[1][2] != 4 {
					t.Errorf("the curve and the point of P-384 are not as the standard writes them")
				}
			case "ed25519":
				if !bytes.Equal(p.Pub[0], []byte{9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}) || len(p.Pub[1]) != 2+33 || p.Pub[1][2] != 0x40 {
					t.Errorf("the curve and the point of Ed25519 are not as the standard writes them")
				}
			}
			// the key that is read back signs, and the standard library verifies with the public key
			secret, pub, err := openpgp.OpenSecretPacket(pkt)
			if err != nil {
				t.Fatalf("OpenSecretPacket: %v", err)
			}
			want := alPublicOf(t, p)
			alSignAndVerify(t, secret.Signer(), want)
			if !publicEqual(secret.Signer().Public(), want) {
				t.Errorf("the public key of the signer is not the public key of the packet")
			}
			if pub.Fingerprint != k.Primary.Fingerprint || !bytes.Equal(pub.PublicBody, p.pubBody()) {
				t.Errorf("the facts that the packet says do not match the key")
			}
			secret.Wipe()
		}
	})
}

// publicEqual compares two public keys of the three kinds.
func publicEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}

func TestTheLonePacketDoesNotDependOnHowTheExportWasProtected(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, plain, _ := alLone(t, b, false)
		k, protected, _ := alLone(t, b, true)
		if !bytes.Equal(plain, protected) {
			t.Errorf("a protected export and an unprotected one of the same key give different packets")
		}
		again, err := k.SecretPacket([]byte(fkPass))
		if err != nil || !bytes.Equal(again, protected) {
			t.Errorf("the packet is not the same on a second call: %v", err)
		}
		// the caller may clear its copy: the next packet is not changed by it
		clear(again)
		third, err := k.SecretPacket([]byte(fkPass))
		if err != nil || !bytes.Equal(third, protected) {
			t.Errorf("clearing a packet changed what the key writes next: %v", err)
		}
	})
}

func TestGoCryptoReadsTheLonePacketAsTheSameKey(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		for _, protected := range []bool{false, true} {
			k, pkt, p := alLone(t, b, protected)
			read, err := gpacket.Read(bytes.NewReader(pkt))
			if err != nil {
				t.Fatalf("go-crypto does not read the packet: %v", err)
			}
			sk, ok := read.(*gpacket.PrivateKey)
			if !ok || sk.Encrypted || sk.IsSubkey || sk.Version != 4 {
				t.Fatalf("go-crypto reads the packet as %T", read)
			}
			if got := alHex(sk.Fingerprint); got != k.Primary.Fingerprint {
				t.Errorf("go-crypto computes the fingerprint %s, want %s", got, k.Primary.Fingerprint)
			}
			if !sk.CreationTime.Equal(fkEpoch) {
				t.Errorf("go-crypto reads the creation time %v", sk.CreationTime)
			}
			vals := p.values()
			trim := func(v []byte) []byte { return bytes.TrimLeft(v, "\x00") }
			switch priv := sk.PrivateKey.(type) {
			case *rsa.PrivateKey:
				if !bytes.Equal(priv.D.Bytes(), vals[0]) {
					t.Errorf("go-crypto reads another exponent d")
				}
				// go-crypto keeps the primes as q, p
				if len(priv.Primes) != 2 || !bytes.Equal(priv.Primes[1].Bytes(), vals[1]) || !bytes.Equal(priv.Primes[0].Bytes(), vals[2]) {
					t.Errorf("go-crypto reads other primes")
				}
				// and the key that go-crypto read signs for the public key that this package opens
				secret, _, err := openpgp.OpenSecretPacket(pkt)
				if err != nil {
					t.Fatal(err)
				}
				d := sha256.Sum256([]byte("a message"))
				sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, d[:])
				if err != nil || rsa.VerifyPKCS1v15(secret.Signer().Public().(*rsa.PublicKey), crypto.SHA256, d[:], sig) != nil {
					t.Errorf("a signature of the go-crypto key does not verify with ours: %v", err)
				}
				secret.Wipe()
			case *gecdsa.PrivateKey:
				if !bytes.Equal(trim(priv.D.Bytes()), vals[0]) {
					t.Errorf("go-crypto reads another scalar")
				}
			case *eddsa.PrivateKey:
				if !bytes.Equal(trim(priv.MarshalByteSecret()), vals[0]) {
					t.Errorf("go-crypto reads another seed")
				}
			default:
				t.Errorf("go-crypto reads a private key of type %T", sk.PrivateKey)
			}
		}
	})
}

func alHex(b []byte) string { return strings.ToLower(fkHex(b)) }

// A reader that is looked at by a reader: the checker of the tests must tell a leak from none, in
// every form that a leak takes, or a refusal table that uses it would pass for nothing.
func TestTheLeakCheckerSeesEveryFormOfANumber(t *testing.T) {
	v := fkRandom(t, 48)
	v[0] |= 0x80
	forms := map[string]string{
		"raw":         string(v),
		"a window":    string(v[10:20]),
		"hex":         strings.ToLower(fkHex(v)),
		"hex upper":   strings.ToUpper(fkHex(v)),
		"a hex part":  strings.ToLower(fkHex(v))[20:44],
		"spaced":      alSpaced(v[5:13]),
		"decimal":     new(big.Int).SetBytes(v).String(),
		"base64":      base64.StdEncoding.EncodeToString(v),
		"base64 at 1": base64.RawURLEncoding.EncodeToString(v[1:]),
		"base64 at 2": base64.URLEncoding.EncodeToString(v[2:]),
		"reversed":    alReverse(string(v)),
	}
	for name, text := range forms {
		if _, bad := alLeaks("an error: "+text+" and more", v); !bad {
			t.Errorf("the checker does not see %s", name)
		}
	}
	if _, bad := alLeaks("the key is not the key of the file (checksum 4096 bits)", v); bad {
		t.Errorf("the checker sees a leak in a text that has none")
	}
	if _, bad := alLeaks("anything", nil, []byte{0, 0}); bad {
		t.Errorf("an empty number is a leak")
	}
}

func alSpaced(v []byte) string {
	var sb strings.Builder
	for i, c := range v {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(strings.ToLower(fkHex([]byte{c})))
	}
	return sb.String()
}

func alReverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func TestPrimaryPublicBodyIsACopyAndHoldsItsLimits(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		cert := k.Certificate()
		body, err := openpgp.PrimaryPublicBody(cert)
		if err != nil {
			t.Fatal(err)
		}
		want := bytes.Clone(body)
		clear(body)
		if again, _ := openpgp.PrimaryPublicBody(cert); !bytes.Equal(again, want) {
			t.Errorf("the body that was returned is not a copy: clearing it changed the certificate")
		}
		// either form of the header, and what follows the first packet is not read
		old := append(oldPacket(6, want), []byte("not packets at all")...)
		if got, err := openpgp.PrimaryPublicBody(old); err != nil || !bytes.Equal(got, want) {
			t.Errorf("the old form of the header: %v", err)
		}
		// a packet that claims more than the limit is a limit, not a form
		huge := []byte{0xC6, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF}
		if _, err := openpgp.PrimaryPublicBody(huge); !errors.Is(err, openpgp.ErrForeignLimit) {
			t.Errorf("a packet of 2 GiB: %v, want ErrForeignLimit", err)
		}
		over := wrap(6, make([]byte, openpgp.MaxForeignPacketBytes+1))
		if _, err := openpgp.PrimaryPublicBody(over); !errors.Is(err, openpgp.ErrForeignLimit) {
			t.Errorf("a packet one byte over the limit: %v, want ErrForeignLimit", err)
		}
		// the public part of another algorithm is not read, and a packet with bytes after the key is not one
		for name, c := range map[string][]byte{
			"a byte after the key": wrap(6, append(bytes.Clone(want), 0)),
			"the version changed":  wrap(6, append([]byte{3}, want[1:]...)),
			"a secret key packet":  wrap(5, want),
			"an empty packet":      wrap(6, nil),
			"nothing":              nil,
		} {
			got, err := openpgp.PrimaryPublicBody(c)
			if err == nil || got != nil || !errors.Is(err, openpgp.ErrForeignKey) {
				t.Errorf("%s: %v %v, want a refusal and nothing", name, got, err)
			}
		}
	})
}

// oldPacket writes a packet in the old format with a two-octet length.
func oldPacket(tag byte, body []byte) []byte {
	return append([]byte{0x80 | tag<<2 | 1, byte(len(body) >> 8), byte(len(body))}, body...)
}
