package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// A signer that misbehaves: its own crypto.Signer around a real key. Whatever it answers, the step that
// signs checks the answer with the public key of the primary before it uses a byte of it, so a builder
// returns a refusal and no signature bytes, or a signature that verifies.

type qaSignFunc = func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error)

type qaMisbehaviour struct {
	name string
	sign qaSignFunc
	// refused is true when the answer is wrong for sure: the builder must refuse it. A false is an answer
	// that is a valid signature by another encoding, which may be taken, and then verifies.
	refused bool
}

func qaDER(r, s *big.Int) []byte {
	out, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		panic(err)
	}
	return out
}

// qaMisbehaviours lists the answers that a signer of the template's key and algorithm may give wrongly.
func qaMisbehaviours(t testing.TB, b *fkBase, std, other crypto.Signer) []qaMisbehaviour {
	t.Helper()
	real := func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) { return std.Sign(r, d, o) }
	mutate := func(f func(sig []byte) []byte) qaSignFunc {
		return func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
			s, err := real(r, d, o)
			if err != nil {
				return nil, err
			}
			return f(bytes.Clone(s)), nil
		}
	}
	list := []qaMisbehaviour{
		{"no answer", func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }, true},
		{"an empty answer", func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return []byte{}, nil }, true},
		{"seventy bytes of one value", func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return bytes.Repeat([]byte{0x55}, 70), nil }, true},
		{"random bytes", func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
			b := make([]byte, 64)
			_, _ = rand.Read(b)
			return b, nil
		}, true},
		{"a valid signature of another key", func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) { return other.Sign(r, d, o) }, true},
		{"a valid signature over another digest", func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
			d2 := bytes.Clone(d)
			d2[0] ^= 0x80
			return std.Sign(r, d2, o)
		}, true},
		{"a valid signature with the first byte changed", mutate(func(s []byte) []byte { s[0] ^= 1; return s }), true},
		{"a valid signature with a middle bit changed", mutate(func(s []byte) []byte { s[len(s)/2] ^= 0x10; return s }), true},
		{"a valid signature with the last bit changed", mutate(func(s []byte) []byte { s[len(s)-1] ^= 1; return s }), true},
		{"a signature of one byte less", mutate(func(s []byte) []byte { return s[:len(s)-1] }), true},
		{"a signature of one byte more", mutate(func(s []byte) []byte { return append(s, 0) }), true},
		{"a signature with a zero byte in front", mutate(func(s []byte) []byte { return append([]byte{0}, s...) }), true},
		{"a signature with the first byte left out", mutate(func(s []byte) []byte { return s[1:] }), true},
		{"a signature of half its length", mutate(func(s []byte) []byte { return s[:len(s)/2] }), true},
	}
	switch k := std.Public().(type) {
	case ed25519.PublicKey:
		list = append(list,
			qaMisbehaviour{"63 bytes", mutate(func(s []byte) []byte { return s[:63] }), true},
			qaMisbehaviour{"65 bytes", mutate(func(s []byte) []byte { return append(s, 0) }), true},
			qaMisbehaviour{"64 zero bytes", func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) { return make([]byte, 64), nil }, true},
			qaMisbehaviour{"the signature of the digest of the digest (Ed25519ph)", func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				return std.Sign(r, d, &ed25519.Options{Hash: crypto.SHA512})
			}, true},
			// S plus the group order is the same point and a different number: RFC 8032 refuses it
			qaMisbehaviour{"S plus the group order", mutate(func(s []byte) []byte {
				l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
				v := new(big.Int).SetBytes(qaReverse(s[32:]))
				v.Add(v, l)
				out := append(bytes.Clone(s[:32]), qaReverse(qaPad(v.Bytes(), 32))...)
				if len(out) != 64 {
					return s
				}
				return out
			}), true},
		)
	case *rsa.PublicKey:
		size := (k.N.BitLen() + 7) / 8
		list = append(list,
			qaMisbehaviour{"the signature plus the modulus", mutate(func(s []byte) []byte {
				v := new(big.Int).SetBytes(s)
				v.Add(v, k.N)
				return v.FillBytes(make([]byte, size+1))
			}), true},
			qaMisbehaviour{"the signature of a SHA-256 digest", func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				return std.Sign(r, d[:32], crypto.SHA256)
			}, true},
			qaMisbehaviour{"the digest padded as a raw value (no DigestInfo)", func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				// a PKCS#1 v1.5 block with no DigestInfo: the hash of the options is zero
				return std.Sign(r, d, crypto.Hash(0))
			}, true},
			qaMisbehaviour{"a PSS signature", func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				return std.Sign(r, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA384})
			}, true},
		)
	case *ecdsa.PublicKey:
		n := k.Curve.Params().N
		parts := func(r io.Reader, d []byte, o crypto.SignerOpts) (*big.Int, *big.Int) {
			der, err := std.Sign(r, d, o)
			if err != nil {
				panic(err)
			}
			var rs struct{ R, S *big.Int }
			if _, err := asn1.Unmarshal(der, &rs); err != nil {
				panic(err)
			}
			return rs.R, rs.S
		}
		with := func(f func(r, s *big.Int) []byte) qaSignFunc {
			return func(rd io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				r, s := parts(rd, d, o)
				return f(r, s), nil
			}
		}
		list = append(list,
			qaMisbehaviour{"DER with a zero byte after it", mutate(func(s []byte) []byte { return append(s, 0) }), true},
			qaMisbehaviour{"DER with a second value after it", with(func(r, s *big.Int) []byte { return append(qaDER(r, s), qaDER(r, s)...) }), true},
			qaMisbehaviour{"a negative r", with(func(r, s *big.Int) []byte { return qaDER(new(big.Int).Neg(r), s) }), true},
			qaMisbehaviour{"a negative s", with(func(r, s *big.Int) []byte { return qaDER(r, new(big.Int).Neg(s)) }), true},
			qaMisbehaviour{"r of zero", with(func(r, s *big.Int) []byte { return qaDER(new(big.Int), s) }), true},
			qaMisbehaviour{"s of zero", with(func(r, s *big.Int) []byte { return qaDER(r, new(big.Int)) }), true},
			qaMisbehaviour{"r and s of zero", with(func(r, s *big.Int) []byte { return qaDER(new(big.Int), new(big.Int)) }), true},
			qaMisbehaviour{"r of the group order", with(func(r, s *big.Int) []byte { return qaDER(n, s) }), true},
			qaMisbehaviour{"s of the group order", with(func(r, s *big.Int) []byte { return qaDER(r, n) }), true},
			qaMisbehaviour{"r plus the group order", with(func(r, s *big.Int) []byte { return qaDER(new(big.Int).Add(r, n), s) }), true},
			qaMisbehaviour{"s plus the group order", with(func(r, s *big.Int) []byte { return qaDER(r, new(big.Int).Add(s, n)) }), true},
			qaMisbehaviour{"r and s as 48 raw bytes each", with(func(r, s *big.Int) []byte {
				return append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...)
			}), true},
			qaMisbehaviour{"a signature of a shorter digest", func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
				return std.Sign(r, d[:32], o)
			}, true},
			// the other half of the same signature is a valid signature: it may be taken, and it verifies
			qaMisbehaviour{"the other s (n minus s)", with(func(r, s *big.Int) []byte { return qaDER(r, new(big.Int).Sub(n, s)) }), false},
		)
	}
	return list
}

func qaReverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

// qaCall calls f and tells whether it panicked.
func qaCall(f func() ([]byte, error)) (out []byte, panicked any, err error) {
	defer func() { panicked = recover() }()
	out, err = f()
	return
}

func TestQASignerThatMisbehavesGetsNoSignature(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		std, other := fkStdSigner(t, b), fkOtherSigner(t, b)
		at := fkEpoch.Add(time.Hour)
		msg := []byte("a message")
		for _, c := range qaMisbehaviours(t, b, std, other) {
			a, err := openpgp.NewAdoptedIssuer(k, fkSigner{pub: std.Public, sign: c.sign})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			for what, make := range map[string]func() ([]byte, error){
				"a direct-key signature": func() ([]byte, error) { return openpgp.DirectKeySignatureFor(rand.Reader, a, at) },
				"a detached signature":   func() ([]byte, error) { return openpgp.DetachedSignatureFor(rand.Reader, a, at, msg) },
			} {
				sig, panicked, err := qaCall(make)
				if panicked != nil {
					t.Errorf("%s, %s: the builder panicked: %v", c.name, what, panicked)
					continue
				}
				switch {
				case err != nil:
					if len(sig) != 0 {
						t.Errorf("%s, %s: %d bytes of signature with the error %v", c.name, what, len(sig), err)
					}
					if !errors.Is(err, openpgp.ErrSignature) {
						t.Errorf("%s, %s: %v is not an ErrSignature", c.name, what, err)
					}
					fkCheckText(t, c.name, err, b)
				case c.refused:
					t.Errorf("%s, %s: a signature of %d bytes came back, want a refusal", c.name, what, len(sig))
				default:
					// accepted: then it must be a signature
					typ, data := byte(0x00), [][]byte{msg}
					m := qaMade{b: b, pub: std.Public(), pubBody: fkSplit(t, k.Certificate())[0].Body, fp: b.ent.PrimaryKey.Fingerprint}
					if what == "a direct-key signature" {
						typ, data = 0x1F, [][]byte{m.keyData()}
					}
					m.check(t, sig, typ, at, data...)
				}
			}
		}
	})
}

// The signer says no: the cause that it gave stays in the error, with the kind, and no signature comes back.
func TestQASignerThatFailsKeepsItsCause(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		std := fkStdSigner(t, b)
		cause := fmt.Errorf("the module is locked: %w", openpgp.ErrSecretWiped)
		a, err := openpgp.NewAdoptedIssuer(k, fkSigner{pub: std.Public, sign: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
			return []byte("not a signature"), cause
		}})
		if err != nil {
			t.Fatal(err)
		}
		at := fkEpoch.Add(time.Hour)
		for what, make := range map[string]func() ([]byte, error){
			"direct-key": func() ([]byte, error) { return openpgp.DirectKeySignatureFor(rand.Reader, a, at) },
			"detached":   func() ([]byte, error) { return openpgp.DetachedSignatureFor(rand.Reader, a, at, nil) },
		} {
			sig, err := make()
			if len(sig) != 0 || !errors.Is(err, openpgp.ErrSignature) || !errors.Is(err, openpgp.ErrSecretWiped) || !errors.Is(err, cause) {
				t.Errorf("%s: %d bytes, %v", what, len(sig), err)
			}
			fkCheckText(t, what, err, b)
		}
	})
}

// A signer that panics when it is asked to sign: a signature error and no bytes (the first form of the
// step let the panic through, and the test said so while that was so).
func TestQASignerThatPanicsIsRefused(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		std := fkStdSigner(t, b)
		a, err := openpgp.NewAdoptedIssuer(k, fkSigner{pub: std.Public, sign: func(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
			panic("the signer is broken")
		}})
		if err != nil {
			t.Fatal(err)
		}
		sig, panicked, err := qaCall(func() ([]byte, error) { return openpgp.DirectKeySignatureFor(rand.Reader, a, fkEpoch.Add(time.Hour)) })
		if panicked != nil {
			t.Fatalf("the builder panicked: %v", panicked)
		}
		if len(sig) != 0 || !errors.Is(err, openpgp.ErrSignature) {
			t.Errorf("%d bytes, %v", len(sig), err)
		}
	})
}

// A signer whose Public answers another key: the key is asked when the issuer is made, and whatever it
// answers later changes nothing, since every answer of Sign is checked with the key of the primary packet.
func TestQASignerWhosePublicKeyChanges(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		k := fkRead(t, b.plain)
		std, other := fkStdSigner(t, b), fkOtherSigner(t, b)
		at := fkEpoch.Add(time.Hour)

		// the right key first, another key after: the issuer is made, and a signature by the signer that
		// the other key stands for is refused; the right key still signs
		calls := 0
		flip := fkSigner{
			pub: func() crypto.PublicKey {
				calls++
				if calls == 1 {
					return std.Public()
				}
				return other.Public()
			},
			sign: std.Sign,
		}
		a, err := openpgp.NewAdoptedIssuer(k, flip)
		if err != nil {
			t.Fatalf("the right key at the first call: %v", err)
		}
		if _, err := openpgp.DirectKeySignatureFor(rand.Reader, a, at); err != nil {
			t.Errorf("a signer whose key was right when it was asked signs: %v", err)
		}
		// another key at the first call: refused, whatever the second call says
		calls = 0
		wrongFirst := fkSigner{
			pub: func() crypto.PublicKey {
				calls++
				if calls == 1 {
					return other.Public()
				}
				return std.Public()
			},
			sign: std.Sign,
		}
		if a, err := openpgp.NewAdoptedIssuer(k, wrongFirst); err == nil || a != nil || !errors.Is(err, openpgp.ErrParams) {
			t.Errorf("another key at the first call: %v", err)
		}
		// the right key, with the other key's signatures: each is refused
		a, err = openpgp.NewAdoptedIssuer(k, fkSigner{pub: std.Public, sign: other.Sign})
		if err != nil {
			t.Fatal(err)
		}
		if sig, err := openpgp.DirectKeySignatureFor(rand.Reader, a, at); err == nil || len(sig) != 0 {
			t.Errorf("a signature of another key: %v", err)
		}
	})
}

// The signer is given a copy of the digest: what it does to it afterwards changes nothing that is written.
func TestQASignerThatScribblesOnTheDigest(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		m := qaNew(t, b)
		std := fkStdSigner(t, b)
		k := fkRead(t, b.plain)
		a, err := openpgp.NewAdoptedIssuer(k, fkSigner{pub: std.Public, sign: func(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
			s, err := std.Sign(r, bytes.Clone(d), o)
			clear(d)
			return s, err
		}})
		if err != nil {
			t.Fatal(err)
		}
		at := fkEpoch.Add(time.Hour)
		msg := []byte("m")
		sig, err := openpgp.DetachedSignatureFor(rand.Reader, a, at, msg)
		if err != nil {
			t.Fatal(err)
		}
		m.check(t, sig, 0x00, at, msg)
	})
}

// The builders of the P-384 key that existed before the signing step took three algorithms are read by
// the parser of the tests. Their own tests pass unchanged; here the structure of what they write is held
// byte by byte: the types, the order and the content of the subpackets, the algorithm, the hash and the
// two numbers.
func TestQAP384BuildersKeepTheirStructure(t *testing.T) {
	s := newSigner(t)
	pub := &s.key.PublicKey
	fp := fingerprint(pub, created)
	issuer := append([]byte{4}, fp...)
	check := func(what string, sigPkt []byte, typ byte, at time.Time, wantTypes []byte, data ...[]byte) qaSig {
		t.Helper()
		g := qaParse(t, sigPkt)
		if g.Version != 4 || g.Type != typ || g.Algo != 19 || g.Hash != 9 {
			t.Errorf("%s: version %d type %#x algorithm %d hash %d", what, g.Version, g.Type, g.Algo, g.Hash)
		}
		var got []byte
		for _, p := range g.Hashed {
			got = append(got, p.Typ)
		}
		if !bytes.Equal(got, wantTypes) {
			t.Errorf("%s: the hashed subpackets are %v, want %v", what, got, wantTypes)
		}
		if g.Hashed[0].Typ != 2 || int64(be32(g.Hashed[0].Data)) != at.Unix() {
			t.Errorf("%s: the creation time is %v, want %d", what, g.Hashed[0].Data, at.Unix())
		}
		last := g.Hashed[len(g.Hashed)-1]
		if last.Typ != 33 || !bytes.Equal(last.Data, issuer) {
			t.Errorf("%s: the issuer fingerprint is not the last of the hashed area", what)
		}
		for _, p := range g.Hashed {
			// only the key expiration is critical
			if p.Critical != (p.Typ == 9) {
				t.Errorf("%s: subpacket %d has the critical bit %v", what, p.Typ, p.Critical)
			}
		}
		if len(g.Unhashed) < 1 || g.Unhashed[0].Typ != 16 || !bytes.Equal(g.Unhashed[0].Data, fp[12:]) {
			t.Errorf("%s: the unhashed area does not start with the issuer key ID", what)
		}
		d := g.digest(data...)
		if !bytes.Equal(g.Check, d[:2]) {
			t.Errorf("%s: the check bytes", what)
		}
		if len(g.Values) != 2 {
			t.Fatalf("%s: %d numbers", what, len(g.Values))
		}
		if !ecdsa.Verify(pub, d, new(big.Int).SetBytes(g.Values[0]), new(big.Int).SetBytes(g.Values[1])) {
			t.Errorf("%s: the signature does not verify with the standard library", what)
		}
		return g
	}
	keyData := func(body []byte) []byte { return append([]byte{0x99, byte(len(body) >> 8), byte(len(body))}, body...) }
	primaryBody := keyBody(pub, created)

	// NewPrimary: a public key packet, the user ID, one certification
	p := s.params()
	cert, err := openpgp.NewPrimary(rand.Reader, p)
	if err != nil {
		t.Fatal(err)
	}
	ps := splitPackets(t, cert)
	if string(tags(ps)) != string([]byte{6, 13, 2}) || !bytes.Equal(ps[0].Body, primaryBody) || string(ps[1].Body) != p.UserID {
		t.Fatalf("the certificate is not a primary, its user ID and one signature")
	}
	uid := []byte(p.UserID)
	uidData := append([]byte{0xB4, 0, 0, byte(len(uid) >> 8), byte(len(uid))}, uid...)
	g := check("NewPrimary", ps[2].Raw, 0x13, ceremony, []byte{2, 27, 9, 33}, keyData(primaryBody), uidData)
	if g.Hashed[1].Typ != 27 || !bytes.Equal(g.Hashed[1].Data, []byte{0x01}) {
		t.Errorf("NewPrimary: the key flags are %v", g.Hashed[1].Data)
	}
	if want := uint32(p.ExpiresAt.Unix() - created.Unix()); be32(g.Hashed[2].Data) != want {
		t.Errorf("NewPrimary: the key expiration is %d, want %d", be32(g.Hashed[2].Data), want)
	}
	if len(g.Unhashed) != 1 {
		t.Errorf("NewPrimary: the unhashed area has %d subpackets", len(g.Unhashed))
	}
	// the primary packet itself: version 4, ECDSA, the OID of P-384, the point
	if b := ps[0].Body; b[0] != 4 || be32(b[1:5]) != uint32(created.Unix()) || b[5] != 19 || !bytes.Equal(b[6:12], []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}) {
		t.Errorf("NewPrimary: the primary key packet is % x", b[:14])
	}

	// ExtendPrimary: the same signature, later
	later := p
	later.CeremonyTime = ceremony.Add(24 * time.Hour)
	ext, err := openpgp.ExtendPrimary(rand.Reader, later)
	if err != nil {
		t.Fatal(err)
	}
	check("ExtendPrimary", ext, 0x13, later.CeremonyTime, []byte{2, 27, 9, 33}, keyData(primaryBody), uidData)

	// RevocationSignature: each of the four reasons
	for _, r := range []openpgp.Reason{openpgp.Compromised, openpgp.Superseded, openpgp.Retired, openpgp.NoReason} {
		rev, err := openpgp.RevocationSignature(rand.Reader, p, r)
		if err != nil {
			t.Fatal(err)
		}
		g := check("RevocationSignature "+r.Text, rev, 0x20, ceremony, []byte{2, 29, 33}, keyData(primaryBody))
		if !bytes.Equal(g.Hashed[1].Data, append([]byte{r.Code}, r.Text...)) {
			t.Errorf("RevocationSignature %s: the reason is %v", r.Text, g.Hashed[1].Data)
		}
		if len(g.Unhashed) != 1 {
			t.Errorf("RevocationSignature %s: the unhashed area has %d subpackets", r.Text, len(g.Unhashed))
		}
	}

	// BindSubkey: the subkey packet as it came, then one binding with the back-signature embedded
	m := newSubkey(t, pub, created, subAt)
	bp := openpgp.BindParams{Primary: s.params(), Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: ceremony.AddDate(1, 1, 0)}
	out, err := openpgp.BindSubkey(rand.Reader, bp)
	if err != nil {
		t.Fatal(err)
	}
	ps = splitPackets(t, out)
	if string(tags(ps)) != string([]byte{14, 2}) || !bytes.Equal(ps[0].Raw, m.Packet) {
		t.Fatalf("the binding is not the subkey packet and one signature")
	}
	g = check("BindSubkey", ps[1].Raw, 0x18, ceremony, []byte{2, 27, 9, 33}, keyData(primaryBody), keyData(m.body()))
	if !bytes.Equal(g.Hashed[1].Data, []byte{0x02}) {
		t.Errorf("BindSubkey: the key flags are %v", g.Hashed[1].Data)
	}
	if len(g.Unhashed) != 2 || g.Unhashed[1].Typ != 32 || !bytes.Equal(g.Unhashed[1].Data, m.BackBody) {
		t.Errorf("BindSubkey: the unhashed area is not the issuer key ID and the back-signature: %d subpackets", len(g.Unhashed))
	}
}

func be32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
