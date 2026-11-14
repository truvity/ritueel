package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// builder is one of the four functions that sign, with the parameters of a good call.
type builder struct {
	name string
	call func(t testing.TB, s *privateSigner) ([]byte, error)
}

var builders = []builder{
	{"NewPrimary", func(_ testing.TB, s *privateSigner) ([]byte, error) {
		return openpgp.NewPrimary(rand.Reader, s.params())
	}},
	{"ExtendPrimary", func(_ testing.TB, s *privateSigner) ([]byte, error) {
		return openpgp.ExtendPrimary(rand.Reader, s.params())
	}},
	{"RevocationSignature", func(_ testing.TB, s *privateSigner) ([]byte, error) {
		return openpgp.RevocationSignature(rand.Reader, s.params(), openpgp.Compromised)
	}},
	{"BindSubkey", func(t testing.TB, s *privateSigner) ([]byte, error) {
		m := newSubkey(t, &s.key.PublicKey, created, subAt)
		return openpgp.BindSubkey(rand.Reader, openpgp.BindParams{
			Primary: s.params(), Subkey: m.Packet, BackSig: m.BackSig, Capability: "authenticate", ExpiresAt: ceremony.AddDate(1, 0, 0),
		})
	}},
}

// A result is verified before it is returned (record 0010, rule 20): a signer that answers with
// something that is not a good signature by its own key gets no packet out of any builder.
func TestASignerThatReturnsABadSignatureGetsNoBytesFromAnyBuilder(t *testing.T) {
	other := genKey(t)
	good := func(s *privateSigner, d []byte) []byte {
		t.Helper()
		sig, err := ecdsa.SignASN1(rand.Reader, s.key, d)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	bad := []struct {
		name string
		sign func(s *privateSigner, d []byte) ([]byte, error)
	}{
		{"an error", func(*privateSigner, []byte) ([]byte, error) { return nil, errors.New("the card is not there") }},
		{"nothing and no error", func(*privateSigner, []byte) ([]byte, error) { return nil, nil }},
		{"an empty answer", func(*privateSigner, []byte) ([]byte, error) { return []byte{}, nil }},
		{"bytes that are not a signature", func(*privateSigner, []byte) ([]byte, error) { return []byte("not a signature"), nil }},
		{"a signature by another key", func(_ *privateSigner, d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, other, d) }},
		{"a signature over another digest", func(s *privateSigner, d []byte) ([]byte, error) {
			return ecdsa.SignASN1(rand.Reader, s.key, bytes.Repeat([]byte{1}, len(d)))
		}},
		{"a signature over the digest with one bit changed", func(s *privateSigner, d []byte) ([]byte, error) {
			e := bytes.Clone(d)
			e[0] ^= 1
			return ecdsa.SignASN1(rand.Reader, s.key, e)
		}},
		{"a good signature with one byte after it", func(s *privateSigner, d []byte) ([]byte, error) { return append(good(s, d), 0), nil }},
		{"a good signature cut short", func(s *privateSigner, d []byte) ([]byte, error) { g := good(s, d); return g[:len(g)-1], nil }},
		{"a good signature with its last byte changed", func(s *privateSigner, d []byte) ([]byte, error) {
			g := good(s, d)
			g[len(g)-1] ^= 1
			return g, nil
		}},
		{"the two numbers side by side and not in DER", func(*privateSigner, []byte) ([]byte, error) {
			return bytes.Repeat([]byte{7}, 96), nil
		}},
		{"a signature of zeros", func(*privateSigner, []byte) ([]byte, error) {
			return []byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}, nil
		}},
		{"a signature of ones", func(*privateSigner, []byte) ([]byte, error) {
			return []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, nil
		}},
	}
	for _, b := range builders {
		for _, c := range bad {
			t.Run(b.name+" with a signer that returns "+c.name, func(t *testing.T) {
				s := newSigner(t)
				s.sign = func(d []byte) ([]byte, error) { return c.sign(s, d) }
				assertRefused(t, b.name, func() ([]byte, error) { return b.call(t, s) }, openpgp.ErrSignature)
				if s.calls != 1 {
					t.Errorf("the signer was asked %d times, want once", s.calls)
				}
			})
		}
	}
}

// A signer that fails says so in the error. The reason is not lost.
func TestTheErrorOfASignerThatFailsIsNamedInTheError(t *testing.T) {
	s := newSigner(t)
	s.sign = func([]byte) ([]byte, error) { return nil, errors.New("touch timed out") }
	_, err := openpgp.NewPrimary(nil, s.params())
	if !errors.Is(err, openpgp.ErrSignature) {
		t.Fatalf("error %v, want ErrSignature", err)
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("touch timed out")) {
		t.Errorf("the error %q does not carry the reason of the signer", got)
	}
}

// The signer is asked once for each signature the builder makes, and never for a request that is
// refused first.
func TestEachBuilderAsksTheSignerOnceWithTheSHA384Hash(t *testing.T) {
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			s := newSigner(t)
			out, err := b.call(t, s)
			if err != nil || len(out) == 0 {
				t.Fatalf("%s: %v", b.name, err)
			}
			if s.calls != 1 {
				t.Fatalf("the signer was asked %d times, want once", s.calls)
			}
			if h := s.hashes[0].HashFunc(); h != crypto.SHA384 {
				t.Errorf("the hash named to the signer is %v, want SHA-384", h)
			}
			if len(s.digests[0]) != 48 {
				t.Errorf("the signer was given %d bytes, want 48", len(s.digests[0]))
			}
		})
	}
}

func TestTheBindingSignerIsGivenTheDigestOfThePrimaryTheSubkeyAndTheFields(t *testing.T) {
	s, b, m := bindFixture(t)
	sig := parseSig(t, splitPackets(t, bind(t, b))[1].Body)
	h := sha512.New384()
	h.Write(hashPrefix(&s.key.PublicKey, created))
	h.Write(hashPrefix(&m.Key.PublicKey, subAt))
	h.Write(sig.Fields)
	h.Write(append([]byte{4, 0xFF}, u32(uint32(len(sig.Fields)))...))
	if !bytes.Equal(s.digests[0], h.Sum(nil)) {
		t.Error("the digest the signer was given is not that of the primary, the subkey, the fields and the trailer")
	}
}

// A signature the signer made for something else, kept and returned later, does not pass: it is a
// valid signature but not over this data.
func TestASignerThatReplaysAnEarlierSignatureGetsNoBytes(t *testing.T) {
	s := newSigner(t)
	if _, err := openpgp.NewPrimary(nil, s.params()); err != nil {
		t.Fatal(err)
	}
	earlier, err := ecdsa.SignASN1(rand.Reader, s.key, s.digests[0])
	if err != nil {
		t.Fatal(err)
	}
	s.sign = func([]byte) ([]byte, error) { return earlier, nil }
	p := s.params()
	p.CeremonyTime = ceremony.Add(time.Hour)
	p.ExpiresAt = p.CeremonyTime.AddDate(3, 0, 0)
	assertRefused(t, "NewPrimary", func() ([]byte, error) { return openpgp.NewPrimary(nil, p) }, openpgp.ErrSignature)
}

// What the caller hands over is copied at once: a signer or a caller that changes the request while
// the signer works changes neither what was checked nor what is returned.
func TestTheRequestIsCopiedSoThatChangesDuringSigningChangeNothing(t *testing.T) {
	s, b, m := bindFixture(t)
	origSub := bytes.Clone(b.Subkey)
	origBack := bytes.Clone(b.BackSig)
	s.sign = func(d []byte) ([]byte, error) {
		sig, err := ecdsa.SignASN1(rand.Reader, s.key, d)
		for i := range b.Subkey {
			b.Subkey[i] ^= 0xFF
		}
		for i := range b.BackSig {
			b.BackSig[i] ^= 0xFF
		}
		return sig, err
	}
	out, err := openpgp.BindSubkey(nil, b)
	if err != nil {
		t.Fatalf("BindSubkey: %v", err)
	}
	ps := splitPackets(t, out)
	if !bytes.Equal(ps[0].Raw, origSub) {
		t.Error("the subkey packet returned is not the one that was checked")
	}
	if got := find(t, parseSig(t, ps[1].Body).Unhashed, 32).Data; !bytes.Equal(got, splitPackets(t, origBack)[0].Body) {
		t.Error("the embedded signature is not the back-signature that was checked")
	}
	if !verifySig(t, &s.key.PublicKey, ps[1].Body, hashPrefix(&s.key.PublicKey, created), hashPrefix(&m.Key.PublicKey, subAt)) {
		t.Error("the binding does not verify")
	}
}

// The bytes returned belong to the caller: changing them changes nothing of a second call.
func TestTheBytesReturnedAreNotSharedWithTheRequest(t *testing.T) {
	_, b, _ := bindFixture(t)
	before := bytes.Clone(b.Subkey)
	out := bind(t, b)
	clear(out)
	if !bytes.Equal(b.Subkey, before) {
		t.Error("the request's subkey bytes were changed through the answer")
	}
}

// The key object of the signer is copied: a signer that changes its public key object after it
// signed does not make the builder verify against the changed key.
func TestAPublicKeyObjectThatChangesAfterSigningDoesNotSpoilTheResult(t *testing.T) {
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			s := newSigner(t)
			orig := *s.key
			s.sign = func(d []byte) ([]byte, error) {
				sig, err := ecdsa.SignASN1(rand.Reader, &orig, d)
				// the public key object that Public() handed out is damaged once the signature is made
				s.key.Curve = elliptic.P256()
				return sig, err
			}
			out, err := b.call(t, s)
			if err != nil || len(out) == 0 {
				t.Fatalf("%s: %v", b.name, err)
			}
		})
	}
}

// The reader of randomness that the caller gives is the one the signer is given; with none, the
// system source is used.
func TestEachBuilderGivesTheSignerTheReaderOfTheCaller(t *testing.T) {
	mine := bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			s := newSigner(t)
			s.sign = nil
			var got io.Reader
			orig := builderWithReader[b.name]
			if _, err := orig(t, s, mine); err != nil {
				t.Fatal(err)
			}
			got = s.rands[0]
			if got != io.Reader(mine) {
				t.Errorf("the signer was given %T, want the reader of the caller", got)
			}
			s2 := newSigner(t)
			if _, err := orig(t, s2, nil); err != nil {
				t.Fatal(err)
			}
			if s2.rands[0] == nil {
				t.Error("with no reader the signer was given none, want the system source")
			}
		})
	}
}

var builderWithReader = map[string]func(t testing.TB, s *privateSigner, rnd io.Reader) ([]byte, error){
	"NewPrimary": func(_ testing.TB, s *privateSigner, rnd io.Reader) ([]byte, error) {
		return openpgp.NewPrimary(rnd, s.params())
	},
	"ExtendPrimary": func(_ testing.TB, s *privateSigner, rnd io.Reader) ([]byte, error) {
		return openpgp.ExtendPrimary(rnd, s.params())
	},
	"RevocationSignature": func(_ testing.TB, s *privateSigner, rnd io.Reader) ([]byte, error) {
		return openpgp.RevocationSignature(rnd, s.params(), openpgp.Retired)
	},
	"BindSubkey": func(t testing.TB, s *privateSigner, rnd io.Reader) ([]byte, error) {
		m := newSubkey(t, &s.key.PublicKey, created, subAt)
		return openpgp.BindSubkey(rnd, openpgp.BindParams{Primary: s.params(), Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: ceremony.AddDate(1, 0, 0)})
	},
}
