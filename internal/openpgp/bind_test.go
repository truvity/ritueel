package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

var subAt = ceremony.Add(-2 * time.Hour)

// bindFixture is a primary with a signer, a subkey with its back-signature over that primary, and
// the parameters of the binding.
func bindFixture(t testing.TB) (*privateSigner, openpgp.BindParams, subkeyMaterial) {
	t.Helper()
	s := newSigner(t)
	m := newSubkey(t, &s.key.PublicKey, created, subAt)
	return s, openpgp.BindParams{
		Primary:    s.params(),
		Subkey:     m.Packet,
		BackSig:    m.BackSig,
		Capability: "sign",
		ExpiresAt:  ceremony.AddDate(1, 1, 0),
	}, m
}

func bind(t testing.TB, b openpgp.BindParams) []byte {
	t.Helper()
	out, err := openpgp.BindSubkey(rand.Reader, b)
	if err != nil {
		t.Fatalf("BindSubkey: %v", err)
	}
	return out
}

func TestTheAnswerIsTheSubkeyPacketAsRequestedThenTheBindingSignature(t *testing.T) {
	s, b, m := bindFixture(t)
	ps := splitPackets(t, bind(t, b))
	if got := tags(ps); !bytes.Equal(got, []byte{tagSubkey, tagSignature}) {
		t.Fatalf("packet tags % d, want 14 2", got)
	}
	if !bytes.Equal(ps[0].Raw, m.Packet) {
		t.Error("the subkey packet is not the one of the request, byte for byte")
	}
	if s.calls != 1 {
		t.Errorf("the signer was asked %d times, want once", s.calls)
	}
}

// The vectors write the key packet with a five-byte length. The answer returns what it was given.
func TestTheSubkeyPacketIsReturnedUnchangedWhateverTheFormOfItsLength(t *testing.T) {
	s, b, m := bindFixture(t)
	for _, form := range []struct {
		name string
		pkt  []byte
	}{
		{"the shortest length", wrap(tagSubkey, m.body())},
		{"a five-byte length", wrapLong(tagSubkey, m.body())},
	} {
		t.Run(form.name, func(t *testing.T) {
			b.Subkey = form.pkt
			out := bind(t, b)
			if !bytes.HasPrefix(out, form.pkt) {
				t.Error("the answer does not start with the subkey packet as it was sent")
			}
			ps := splitPackets(t, out)
			if !verifySig(t, &s.key.PublicKey, ps[1].Body, hashPrefix(&s.key.PublicKey, created), hashPrefix(&m.Key.PublicKey, subAt)) {
				t.Error("the binding does not verify")
			}
		})
	}
}

func TestTheBindingHasTheSubpacketsOfThePageForEachCapability(t *testing.T) {
	for _, c := range []struct {
		capability string
		flag       byte
	}{{"sign", 0x02}, {"authenticate", 0x20}} {
		t.Run(c.capability, func(t *testing.T) {
			s, b, m := bindFixture(t)
			b.Capability = c.capability
			ps := splitPackets(t, bind(t, b))
			sig := parseSig(t, ps[1].Body)
			if sig.Version != 4 || sig.Type != 0x18 || sig.Algo != 19 || sig.Hash != 9 {
				t.Errorf("version %d type %#x algorithm %d hash %d, want 4, 0x18, 19, 9", sig.Version, sig.Type, sig.Algo, sig.Hash)
			}
			if got := types(sig.Hashed); !bytes.Equal(got, []byte{2, 27, 9, 33}) {
				t.Errorf("hashed types % d, want 2 27 9 33", got)
			}
			if got := types(sig.Unhashed); !bytes.Equal(got, []byte{16, 32}) {
				t.Errorf("unhashed types % d, want 16 32", got)
			}
			if got := critical(sig.Hashed); !bytes.Equal(got, []byte{9}) {
				t.Errorf("critical hashed subpackets % d, want only 9", got)
			}
			if got := critical(sig.Unhashed); len(got) != 0 {
				t.Errorf("critical unhashed subpackets % d, want none", got)
			}
			if got := find(t, sig.Hashed, 27).Data; !bytes.Equal(got, []byte{c.flag}) {
				t.Errorf("key flags % x, want exactly %02x", got, c.flag)
			}
			if got := find(t, sig.Hashed, 2).Data; !bytes.Equal(got, u32(uint32(ceremony.Unix()))) {
				t.Errorf("creation time % x, want the ceremony time", got)
			}
			// The subkey ends at ExpiresAt: the lifetime counts from the creation of the subkey.
			life := binary.BigEndian.Uint32(find(t, sig.Hashed, 9).Data)
			if end := subAt.Add(time.Duration(life) * time.Second); !end.Equal(b.ExpiresAt) {
				t.Errorf("the subkey ends at %v, want %v", end, b.ExpiresAt)
			}
			fp := fingerprint(&s.key.PublicKey, created)
			if got := find(t, sig.Hashed, 33).Data; !bytes.Equal(got, append([]byte{4}, fp...)) {
				t.Errorf("issuer fingerprint % x, want that of the primary", got)
			}
			if got := find(t, sig.Unhashed, 16).Data; !bytes.Equal(got, fp[12:]) {
				t.Errorf("issuer key ID % x, want that of the primary", got)
			}
			if got := find(t, sig.Unhashed, 32).Data; !bytes.Equal(got, m.BackBody) {
				t.Error("the embedded signature is not the request's back-signature, byte for byte")
			}
		})
	}
}

func TestTheBindingSignsThePrimaryKeyThenTheSubkey(t *testing.T) {
	s, b, m := bindFixture(t)
	body := splitPackets(t, bind(t, b))[1].Body
	pp, sp := hashPrefix(&s.key.PublicKey, created), hashPrefix(&m.Key.PublicKey, subAt)
	if !verifySig(t, &s.key.PublicKey, body, pp, sp) {
		t.Error("the binding does not verify over the primary and then the subkey")
	}
	if verifySig(t, &s.key.PublicKey, body, sp, pp) {
		t.Error("the binding verifies over the subkey and then the primary")
	}
	if verifySig(t, &s.key.PublicKey, body, pp) {
		t.Error("the binding verifies over the primary alone")
	}
	other := newSubkey(t, &s.key.PublicKey, created, subAt)
	if verifySig(t, &s.key.PublicKey, body, pp, hashPrefix(&other.Key.PublicKey, subAt)) {
		t.Error("the binding verifies over another subkey")
	}
}

func TestAnotherReaderTakesTheBindingAsTheBindingOfTheSubkey(t *testing.T) {
	s, b, m := bindFixture(t)
	_, _, cert, _ := certOf(t, s)
	out := bind(t, b)
	rd := gopacket.NewReader(bytes.NewReader(out))
	var sub *gopacket.PublicKey
	var sig *gopacket.Signature
	for {
		p, err := rd.Next()
		if err != nil {
			break
		}
		switch x := p.(type) {
		case *gopacket.PublicKey:
			sub = x
		case *gopacket.Signature:
			sig = x
		}
	}
	if sub == nil || sig == nil {
		t.Fatalf("read %v and %v from the answer", sub, sig)
	}
	primary := readPublicKey(t, cert)
	if err := primary.VerifyKeySignature(sub, sig); err != nil {
		t.Errorf("the binding does not verify as a subkey binding: %v", err)
	}
	if sig.EmbeddedSignature == nil || sig.EmbeddedSignature.SigType != 0x19 {
		t.Errorf("the embedded signature is %v, want a primary key binding", sig.EmbeddedSignature)
	}
	if !bytes.Equal(sub.Fingerprint, fingerprint(&m.Key.PublicKey, subAt)) {
		t.Error("the subkey in the answer is not the requested one")
	}
}

// The same layout as the answer of the vectors (a binding made by primary A for a software subkey).
func TestTheBindingHasTheLayoutOfTheVectorAnswer(t *testing.T) {
	vps := splitPackets(t, vector(t, "responses", "pgp-software-valid.bound.pgp"))
	vs := parseSig(t, vps[1].Body)
	_, b, _ := bindFixture(t)
	ps := splitPackets(t, bind(t, b))
	if !bytes.Equal(tags(ps), tags(vps)) {
		t.Fatalf("tags % d, the vector has % d", tags(ps), tags(vps))
	}
	sig := parseSig(t, ps[1].Body)
	for _, c := range []struct {
		name      string
		got, want []byte
	}{
		{"hashed types", types(sig.Hashed), types(vs.Hashed)},
		{"hashed critical", critical(sig.Hashed), critical(vs.Hashed)},
		{"unhashed types", types(sig.Unhashed), types(vs.Unhashed)},
		{"unhashed critical", critical(sig.Unhashed), critical(vs.Unhashed)},
		{"the first fields", []byte{sig.Version, sig.Type, sig.Algo, sig.Hash}, []byte{vs.Version, vs.Type, vs.Algo, vs.Hash}},
		{"the length of the embedded signature", []byte{byte(len(find(t, sig.Unhashed, 32).Data) / 16)}, []byte{byte(len(find(t, vs.Unhashed, 32).Data) / 16)}},
	} {
		if !bytes.Equal(c.got, c.want) {
			t.Errorf("%s: % x, the vector has % x", c.name, c.got, c.want)
		}
	}
	if len(sig.HashedRaw) != len(vs.HashedRaw) {
		t.Errorf("hashed area of %d bytes, the vector has %d", len(sig.HashedRaw), len(vs.HashedRaw))
	}
}

func TestACapabilityOtherThanSignOrAuthenticateIsRefused(t *testing.T) {
	for _, c := range []string{"", "encrypt", "certify", "Sign", "sign ", "authenticate ", "sign,authenticate", "sign authenticate", "signing"} {
		t.Run(fmt.Sprintf("%q", c), func(t *testing.T) {
			s, b, _ := bindFixture(t)
			b.Capability = c
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrParams)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

func TestAParameterOfTheBindingThatIsRefusedGivesNoBytes(t *testing.T) {
	cases := map[string]func(b *openpgp.BindParams){
		"a subkey end equal to the ceremony":          func(b *openpgp.BindParams) { b.ExpiresAt = b.Primary.CeremonyTime },
		"a subkey end before the ceremony":            func(b *openpgp.BindParams) { b.ExpiresAt = b.Primary.CeremonyTime.Add(-time.Hour) },
		"a subkey end with a fraction of a second":    func(b *openpgp.BindParams) { b.ExpiresAt = b.ExpiresAt.Add(time.Millisecond) },
		"a subkey end after the year 2106":            func(b *openpgp.BindParams) { b.ExpiresAt = time.Unix(1<<32, 0) },
		"no subkey end":                               func(b *openpgp.BindParams) { b.ExpiresAt = time.Time{} },
		"a ceremony before the primary was created":   func(b *openpgp.BindParams) { b.Primary.CeremonyTime = created.Add(-time.Second) },
		"a ceremony with a fraction of a second":      func(b *openpgp.BindParams) { b.Primary.CeremonyTime = ceremony.Add(time.Millisecond) },
		"a primary creation with a fraction of a sec": func(b *openpgp.BindParams) { b.Primary.CreationTime = created.Add(time.Millisecond) },
		"no key for the primary":                      func(b *openpgp.BindParams) { b.Primary.Key = nil },
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			s, b, _ := bindFixture(t)
			mod(&b)
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrParams)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

func TestAPrimaryThatIsNotEcdsaOnP384CannotBindAKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, b, _ := bindFixture(t)
	b.Primary.Key = p256
	assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrParams)
}

// A primary whose key holds no point is a parameter that is refused, not a panic.
func TestAPrimaryWhoseKeyHoldsNoPointCannotBindAKey(t *testing.T) {
	for name, pub := range map[string]*ecdsa.PublicKey{
		"no point":              {Curve: elliptic.P384()},
		"only the abscissa":     abscissaOnly(t),
		"only the ordinate":     ordinateOnly(t),
		"no curve":              {},
		"a point off the curve": offCurve(t),
	} {
		t.Run(name, func(t *testing.T) {
			_, b, _ := bindFixture(t)
			b.Primary.Key = fixedPublic{pub}
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrParams)
		})
	}
}

func TestTheBindingDoesNotNeedTheUserIDOrTheExpiryOfThePrimary(t *testing.T) {
	_, b, _ := bindFixture(t)
	b.Primary.UserID = ""
	b.Primary.ExpiresAt = time.Time{}
	if out := bind(t, b); len(out) == 0 {
		t.Error("nothing came back")
	}
}

// A subkey created at the ceremony instant is fine ("at or before"); one second later is not.
func TestASubkeyCreatedAtTheCeremonyIsBoundAndOneCreatedAfterItIsRefused(t *testing.T) {
	s := newSigner(t)
	for _, c := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"at the ceremony", ceremony, true},
		{"one second before the ceremony", ceremony.Add(-time.Second), true},
		{"one second after the ceremony", ceremony.Add(time.Second), false},
		{"a day after the ceremony", ceremony.Add(24 * time.Hour), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := newSubkey(t, &s.key.PublicKey, created, c.at)
			b := openpgp.BindParams{Primary: s.params(), Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: ceremony.AddDate(1, 0, 0)}
			out, err := openpgp.BindSubkey(nil, b)
			if c.ok && err != nil {
				t.Fatalf("BindSubkey: %v", err)
			}
			if !c.ok {
				assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrRequest)
			} else if len(out) == 0 {
				t.Error("nothing came back")
			}
		})
	}
}

// A subkey that is itself the primary key, written as a subkey packet, is not bound to itself.
func TestTheSubkeyThatIsThePrimaryItselfIsRefused(t *testing.T) {
	s := newSigner(t)
	pkt := wrap(tagSubkey, keyBody(&s.key.PublicKey, created))
	b := openpgp.BindParams{
		Primary: s.params(), Subkey: pkt, Capability: "sign", ExpiresAt: ceremony.AddDate(1, 0, 0),
		BackSig: backSig(t, s.key, created, &s.key.PublicKey, created, nil),
	}
	assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrRequest)
	if s.calls != 0 {
		t.Errorf("the signer was asked %d times", s.calls)
	}
}

// The primary's own public point is not a subkey of it, whatever the creation time of the packet:
// the points are compared, and not the fingerprints, which change with the creation time. The
// back-signature is made with the primary's own key, and is a good one, so that only the point is
// wrong. A subkey of another point, with the same creation times, is bound.
func TestASubkeyWithThePrimarysOwnPointIsRefusedWhateverItsCreationTime(t *testing.T) {
	for _, c := range []struct {
		name string
		at   time.Time
	}{
		{"the creation time of the primary", created},
		{"one second after the primary", created.Add(time.Second)},
		{"one hour after the primary", created.Add(time.Hour)},
		{"the creation time of the usual subkey", subAt},
		{"the ceremony", ceremony},
		{"one second before the primary", created.Add(-time.Second)},
		{"a year before the primary", created.AddDate(-1, 0, 0)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSigner(t)
			b := openpgp.BindParams{
				Primary: s.params(), Subkey: wrap(tagSubkey, keyBody(&s.key.PublicKey, c.at)),
				BackSig:    backSig(t, s.key, c.at, &s.key.PublicKey, created, nil),
				Capability: "sign", ExpiresAt: ceremony.AddDate(1, 0, 0),
			}
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(rand.Reader, b) }, openpgp.ErrRequest)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
			// The control: the same creation time and the same back-signature by the subkey of
			// another key is bound.
			if c.at.Before(created) {
				return
			}
			m := newSubkey(t, &s.key.PublicKey, created, c.at)
			b.Subkey, b.BackSig = m.Packet, m.BackSig
			if out, err := openpgp.BindSubkey(rand.Reader, b); err != nil || len(out) == 0 {
				t.Errorf("a subkey of another point at the same time is refused: %v", err)
			}
		})
	}
}

// A key with a curve and no point (or one coordinate, or a point off the curve) is a fault of the
// parameters in every function of the package that takes a key, whatever else is wrong with the
// call: nothing comes back, the signer is not asked and nothing panics.
func TestAKeyWithACurveAndNoPointIsAFaultOfTheParametersInEveryExportedFunction(t *testing.T) {
	keys := map[string]*ecdsa.PublicKey{
		"a curve and no point":  {Curve: elliptic.P384()},
		"only the abscissa":     abscissaOnly(t),
		"only the ordinate":     ordinateOnly(t),
		"a point off the curve": offCurve(t),
	}
	for name, pub := range keys {
		t.Run(name, func(t *testing.T) {
			s := &namedSigner{privateSigner: newSigner(t), pub: pub}
			p := s.params()
			p.Key = s
			if _, err := openpgp.Fingerprint(pub, created); !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("Fingerprint: %v, want a fault of the parameters", err)
			}
			assertRefused(t, "NewPrimary", func() ([]byte, error) { return openpgp.NewPrimary(rand.Reader, p) }, openpgp.ErrParams)
			assertRefused(t, "ExtendPrimary", func() ([]byte, error) { return openpgp.ExtendPrimary(rand.Reader, p) }, openpgp.ErrParams)
			for _, r := range []openpgp.Reason{openpgp.Compromised, openpgp.Superseded, openpgp.Retired, openpgp.NoReason} {
				assertRefused(t, "RevocationSignature", func() ([]byte, error) { return openpgp.RevocationSignature(rand.Reader, p, r) }, openpgp.ErrParams)
			}
			_, b, _ := bindFixture(t)
			b.Primary = p
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(rand.Reader, b) }, openpgp.ErrParams)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

// A request that is refused: the error says so, nothing comes back and the signer is not asked.
func TestARequestThatIsRefusedGivesNoBytesAndNoRequestToTheSigner(t *testing.T) {
	cases := []struct {
		name string
		mod  func(t *testing.T, s *privateSigner, b *openpgp.BindParams, m subkeyMaterial)
	}{
		{"no subkey packet", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) { b.Subkey = nil }},
		{"an empty subkey packet", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) { b.Subkey = []byte{} }},
		{"a subkey that is not a packet", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.Subkey = []byte("garbage")
		}},
		{"a subkey packet cut short", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.Subkey = b.Subkey[:len(b.Subkey)-1]
		}},
		{"a subkey packet with a byte after it", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.Subkey = append(append([]byte{}, b.Subkey...), 0)
		}},
		{"a subkey packet followed by the back-signature", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.Subkey = append(append([]byte{}, b.Subkey...), b.BackSig...)
		}},
		{"a primary key packet in place of the subkey", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.Subkey = wrap(tagPublicKey, m.body())
		}},
		{"a subkey of version 5", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			body[0] = 5
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey of version 3", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			body[0] = 3
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey with the algorithm Ed25519", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			body[5] = 22
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey with the algorithm RSA", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			body[5] = 1
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey on the curve P-256", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			copy(body[6:], []byte{8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}) // the OID of P-256, one byte longer
			b.Subkey = wrap(tagSubkey, body[:len(body)-1])
		}},
		{"a subkey with a point that is not on the curve", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			body[len(body)-1] ^= 0x01
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey with a compressed point", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()[:6+6]
			body = append(body, 0x01, 0x80, 0x03) // 385 bits, then 0x03 and the X coordinate
			body = append(body, 0x03)
			body = append(body, m.Key.X.FillBytes(make([]byte, 48))...)
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey whose MPI says 776 bits for a point of 771", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			body[12], body[13] = 0x03, 0x08
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey whose MPI says 770 bits for a point of 771", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			body := m.body()
			body[12], body[13] = 0x03, 0x02
			b.Subkey = wrap(tagSubkey, body)
		}},
		{"a subkey packet with a partial length", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.Subkey = append([]byte{0xC0 | tagSubkey, 0xE1}, m.body()...)
		}},
		{"no back-signature", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) { b.BackSig = nil }},
		{"a back-signature that is not a packet", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = []byte("garbage")
		}},
		{"a back-signature cut short", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = b.BackSig[:len(b.BackSig)-1]
		}},
		{"a back-signature with a byte after it", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = append(append([]byte{}, b.BackSig...), 0)
		}},
		{"two back-signatures", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = append(append([]byte{}, b.BackSig...), b.BackSig...)
		}},
		{"a back-signature with one bit of the signature changed", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = append([]byte{}, b.BackSig...)
			b.BackSig[len(b.BackSig)-1] ^= 0x01
		}},
		{"a back-signature with one bit of the hashed area changed", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = append([]byte{}, b.BackSig...)
			ps := splitPackets(t, b.BackSig)
			b.BackSig[ps[0].HeaderLen+8+2] ^= 0x01 // a byte of the creation time
		}},
		{"a back-signature of type 0x18", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Type = 0x18 })
		}},
		{"a back-signature of type 0x13", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Type = 0x13 })
		}},
		{"a back-signature made over another primary", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, &genKey(t).PublicKey, created, nil)
		}},
		{"a back-signature made over the same primary key with another creation time", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, created.Add(time.Second), nil)
		}},
		{"a back-signature made over another subkey", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				sp.Data = [][]byte{hashPrefix(m.Primary, m.PrimaryAt), hashPrefix(&genKey(t).PublicKey, m.Created)}
			})
		}},
		{"a back-signature made over the primary alone", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Data = sp.Data[:1] })
		}},
		{"a back-signature made over the subkey and then the primary", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Data[0], sp.Data[1] = sp.Data[1], sp.Data[0] })
		}},
		{"a back-signature made by another key", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Key = genKey(t) })
		}},
		{"a back-signature without the issuer key ID", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Unhashed = nil })
		}},
		{"a back-signature with the issuer key ID in the hashed area", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				sp.Hashed = append(sp.Hashed, sp.Unhashed...)
				sp.Unhashed = nil
			})
		}},
		{"a back-signature without the issuer fingerprint", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Hashed = sp.Hashed[:1] })
		}},
		{"a back-signature with the issuer fingerprint in the unhashed area", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				sp.Unhashed = append(sp.Unhashed, sp.Hashed[1])
			})
		}},
		{"a back-signature that names another subkey by its fingerprint", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				sp.Hashed[1].Data = append([]byte{4}, fingerprint(&genKey(t).PublicKey, m.Created)...)
			})
		}},
		{"a back-signature that names another subkey by its key ID", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				sp.Unhashed[0].Data = bytes.Repeat([]byte{7}, 8)
			})
		}},
		{"a back-signature that names the primary as its issuer", func(t *testing.T, s *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				fp := fingerprint(&s.key.PublicKey, created)
				sp.Hashed[1].Data = append([]byte{4}, fp...)
				sp.Unhashed[0].Data = fp[12:]
			})
		}},
		{"a back-signature with two issuer fingerprints", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[1]) })
		}},
		{"a back-signature with two issuer key IDs", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sp.Unhashed[0]) })
		}},
		{"a back-signature made with SHA-256", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Hash = 8 })
		}},
		{"a back-signature made with SHA-512", func(t *testing.T, _ *privateSigner, b *openpgp.BindParams, m subkeyMaterial) {
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.Hash = 10 })
		}},
		{"a back-signature that is an old-format packet of another kind", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = append([]byte{0x88, 0x01}, 0x00)
		}},
		{"a back-signature that is a user ID packet", func(_ *testing.T, _ *privateSigner, b *openpgp.BindParams, _ subkeyMaterial) {
			b.BackSig = wrap(tagUserID, []byte("Example Test"))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, b, m := bindFixture(t)
			c.mod(t, s, &b, m)
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrRequest)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times for a request that is refused", s.calls)
			}
		})
	}
}

// What the standard says of a back-signature the profile accepts, written again with the tests' own
// code: the page's check 5 of the hand-off contract.
func pageAcceptsBackSig(t testing.TB, primary *ecdsa.PublicKey, primaryAt time.Time, subkey, back []byte) bool {
	t.Helper()
	sps := splitPackets(t, subkey)
	if len(sps) != 1 || sps[0].Tag != tagSubkey || sps[0].Body[0] != 4 || sps[0].Body[5] != 19 {
		return false
	}
	body := sps[0].Body
	sub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), body[len(body)-97:])
	if err != nil {
		return false
	}
	subAt := time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0).UTC()
	bps := splitPackets(t, back)
	if len(bps) != 1 || bps[0].Tag != tagSignature {
		return false
	}
	sig := parseSig(t, bps[0].Body)
	if sig.Type != 0x19 || sig.Algo != 19 || sig.Hash != 9 {
		return false
	}
	fp := fingerprint(sub, subAt)
	var haveFP, haveID bool
	for _, s := range sig.Hashed {
		if s.Type == 33 && bytes.Equal(s.Data, append([]byte{4}, fp...)) {
			haveFP = true
		}
	}
	for _, s := range sig.Unhashed {
		if s.Type == 16 && bytes.Equal(s.Data, fp[12:]) {
			haveID = true
		}
	}
	return haveFP && haveID && verifySig(t, sub, bps[0].Body, hashPrefix(primary, primaryAt), hashPrefix(sub, subAt))
}

// The vector requests, each with the back-signatures it carries, against the primaries A and B: a
// back-signature reaches the signer exactly when the tests' own check of the page accepts it, and
// a refused one is an ErrRequest with the signer never asked.
func TestTheBackSignaturesOfTheVectorRequestsAreAcceptedExactlyWhenThePageAcceptsThem(t *testing.T) {
	pubA, _ := vectorPrimary(t, "a")
	pubB, _ := vectorPrimary(t, "b")
	primaries := map[string]*ecdsa.PublicKey{"A": pubA, "B": pubB}
	// The request files that hold a P-384 subkey.
	names := []string{
		"pgp-software-valid", "pgp-piv-valid", "pgp-kms-valid", "pgp-openpgp-card-valid", "pgp-openpgp-card-authenticate",
		"pgp-backsig-missing", "pgp-backsig-missing-one", "pgp-backsig-no-key-id", "pgp-backsig-tampered",
		"pgp-backsig-wrong-primary", "pgp-backsig-wrong-type", "pgp-primaries-incomplete", "pgp-ed25519",
	}
	accepted, refused := 0, 0
	for _, name := range names {
		raw := vector(t, "requests", name+".subkey.pgp")
		ps := splitPackets(t, raw)
		subkey := ps[0].Raw
		for i, bp := range ps[1:] {
			for label, pub := range primaries {
				t.Run(fmt.Sprintf("%s, back-signature %d, primary %s", name, i+1, label), func(t *testing.T) {
					want := pageAcceptsBackSig(t, pub, created, subkey, bp.Raw)
					signer := &privateSigner{key: genKey(t)}
					// The signer names the vector primary but holds another private key, so a request that
					// passes every check stops at the signature, with ErrSignature.
					fake := &namedSigner{privateSigner: signer, pub: pub}
					b := openpgp.BindParams{
						Primary:    openpgp.PrimaryParams{Key: fake, CreationTime: created, CeremonyTime: ceremony, ExpiresAt: ceremony.AddDate(3, 0, 0)},
						Subkey:     subkey,
						BackSig:    bp.Raw,
						Capability: "sign",
						ExpiresAt:  time.Date(2027, 12, 15, 12, 0, 0, 0, time.UTC),
					}
					out, err := openpgp.BindSubkey(nil, b)
					if out != nil {
						t.Errorf("%d bytes came back with the error %v", len(out), err)
					}
					if want {
						accepted++
						if !errors.Is(err, openpgp.ErrSignature) || signer.calls != 1 {
							t.Errorf("the page accepts this back-signature: error %v, signer asked %d times, want ErrSignature after one request", err, signer.calls)
						}
					} else {
						refused++
						if !errors.Is(err, openpgp.ErrRequest) || signer.calls != 0 {
							t.Errorf("the page refuses this back-signature: error %v, signer asked %d times, want ErrRequest and none", err, signer.calls)
						}
					}
				})
			}
		}
	}
	if accepted < 10 || refused < 10 {
		t.Errorf("the vectors gave %d accepted and %d refused back-signatures; a check that finds nothing to check fails", accepted, refused)
	}
}

// Every valid vector request has a back-signature for each of A and B, and no other pairing is
// accepted: the back-signature of A does not serve B.
func TestEachValidVectorRequestHasABackSignatureForTheFirstPrimaryAndOneForTheSecond(t *testing.T) {
	pubA, _ := vectorPrimary(t, "a")
	pubB, _ := vectorPrimary(t, "b")
	for _, name := range []string{"pgp-software-valid", "pgp-piv-valid", "pgp-kms-valid", "pgp-openpgp-card-valid", "pgp-openpgp-card-authenticate"} {
		ps := splitPackets(t, vector(t, "requests", name+".subkey.pgp"))
		if len(ps) != 3 {
			t.Fatalf("%s holds %d packets, want a subkey and two back-signatures", name, len(ps))
		}
		got := [2][2]bool{}
		for i, bp := range ps[1:] {
			for j, pub := range []*ecdsa.PublicKey{pubA, pubB} {
				got[i][j] = pageAcceptsBackSig(t, pub, created, ps[0].Raw, bp.Raw)
			}
		}
		if want := [2][2]bool{{true, false}, {false, true}}; got != want {
			t.Errorf("%s: back-signature by primary %v, want %v", name, got, want)
		}
	}
}

type namedSigner struct {
	*privateSigner
	pub *ecdsa.PublicKey
}

func (n *namedSigner) Public() crypto.PublicKey { return n.pub }

// A back-signature that carries other unhashed subpackets is refused, whatever their length: the
// page gives the unhashed area one subpacket, the issuer key ID, and the binding embeds the
// back-signature as it came, so it cannot be cut down.
func TestABackSignatureWithOtherUnhashedSubpacketsIsRefusedWhateverTheirLength(t *testing.T) {
	for _, n := range []int{0, 20, 100, 300, 9000} {
		t.Run(fmt.Sprintf("%d extra bytes", n), func(t *testing.T) {
			s, b, m := bindFixture(t)
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
				sp.Unhashed = append(sp.Unhashed, sub{Type: 101, Data: bytes.Repeat([]byte{0x5A}, n)})
			})
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(rand.Reader, b) }, openpgp.ErrRequest)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

// A back-signature far too long to be embedded in the unhashed area of a binding is a request that
// cannot be answered, and so a refusal of the request, not of a parameter.
func TestABackSignatureTooLongToEmbedIsRefusedAsARequest(t *testing.T) {
	s, b, m := bindFixture(t)
	b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) {
		sp.Hashed = append(sp.Hashed, sub{Type: 101, Data: bytes.Repeat([]byte{1}, 30000)})
		sp.Unhashed = append(sp.Unhashed, sub{Type: 101, Data: bytes.Repeat([]byte{2}, 30000)})
		sp.Unhashed = append(sp.Unhashed, sub{Type: 102, Data: bytes.Repeat([]byte{3}, 30000)})
	})
	assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrRequest)
	if s.calls != 0 {
		t.Errorf("the signer was asked %d times", s.calls)
	}
}

// One request may be answered by several goroutines at once, and the builders leave their input as
// it was: the race detector sees any write to the shared bytes.
func TestTheBuildersLeaveTheirInputAsItWasAndMayRunTogether(t *testing.T) {
	k := genKey(t)
	pp := openpgp.PrimaryParams{Key: k, CreationTime: created, CeremonyTime: ceremony, ExpiresAt: ceremony.AddDate(3, 0, 0), UserID: "Example Test Release Root A <a@example.org>"}
	m := newSubkey(t, &k.PublicKey, created, subAt)
	b := openpgp.BindParams{Primary: pp, Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: ceremony.AddDate(1, 0, 0)}
	subBefore, backBefore := bytes.Clone(b.Subkey), bytes.Clone(b.BackSig)
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := openpgp.BindSubkey(rand.Reader, b); err != nil {
				errs <- err
			}
			if _, err := openpgp.NewPrimary(rand.Reader, pp); err != nil {
				errs <- err
			}
			if _, err := openpgp.RevocationSignature(rand.Reader, pp, openpgp.Superseded); err != nil {
				errs <- err
			}
			if _, err := openpgp.ExtendPrimary(rand.Reader, pp); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if !bytes.Equal(b.Subkey, subBefore) || !bytes.Equal(b.BackSig, backBefore) {
		t.Error("a builder changed the bytes of the request")
	}
}

// A request cut short anywhere is a refusal: no panic, no bytes and no request to the signer. The
// packet header is rewritten for each cut, so that the body itself is what ends early.
func TestARequestCutShortAnywhereIsRefusedWithoutAPanic(t *testing.T) {
	s, b, m := bindFixture(t)
	subBody := splitPackets(t, b.Subkey)[0].Body
	backBody := splitPackets(t, b.BackSig)[0].Body
	for n := 0; n < len(subBody); n++ {
		p := b
		p.Subkey = wrap(tagSubkey, subBody[:n])
		assertRefused(t, fmt.Sprintf("a subkey of %d bytes", n), func() ([]byte, error) { return openpgp.BindSubkey(nil, p) }, openpgp.ErrRequest)
	}
	for n := 0; n < len(backBody); n++ {
		p := b
		p.BackSig = wrap(tagSignature, bytes.Clone(backBody[:n]))
		assertRefused(t, fmt.Sprintf("a back-signature of %d bytes", n), func() ([]byte, error) { return openpgp.BindSubkey(nil, p) }, openpgp.ErrRequest)
	}
	if s.calls != 0 {
		t.Errorf("the signer was asked %d times", s.calls)
	}
	_ = m
}

// RFC 9580, section 4.2: the first bit of a packet header is always set. A packet without it is not a
// packet, and the answer must not hand it back as one.
func TestAPacketWhoseHeaderLacksTheLeadingBitIsRefused(t *testing.T) {
	s, b, m := bindFixture(t)
	for name, hdr := range map[string][]byte{
		"a new-format header without the bit":  {0x40 | tagSubkey, byte(len(m.body()))},
		"an old-format header without the bit": {tagSubkey << 2, byte(len(m.body()))},
	} {
		t.Run(name, func(t *testing.T) {
			p := b
			p.Subkey = append(bytes.Clone(hdr), m.body()...)
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, p) }, openpgp.ErrRequest)
		})
	}
	back := splitPackets(t, b.BackSig)[0]
	p := b
	p.BackSig = bytes.Clone(b.BackSig)
	p.BackSig[0] &^= 0x80
	assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, p) }, openpgp.ErrRequest)
	_ = back
	if s.calls != 0 {
		t.Errorf("the signer was asked %d times", s.calls)
	}
}

// Only version 4 signatures are made and read.
func TestABackSignatureOfAnotherVersionIsRefused(t *testing.T) {
	for _, v := range []byte{0, 2, 3, 5, 6} {
		s, b, _ := bindFixture(t)
		ps := splitPackets(t, b.BackSig)
		body := bytes.Clone(ps[0].Body)
		body[0] = v
		b.BackSig = wrap(tagSignature, body)
		assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(nil, b) }, openpgp.ErrRequest)
		if s.calls != 0 {
			t.Errorf("version %d: the signer was asked %d times", v, s.calls)
		}
	}
}

// The back-signature of the page has a body of about 150 bytes, so the subpacket that embeds it
// always has the one-octet length form. The numbers of a signature vary by a byte now and then; with
// every subpacket in the five-octet form the body grows by twelve bytes. Every such back-signature is
// embedded unchanged, and the binding verifies.
func TestTheEmbeddingOfTheBackSignatureOfThePageHasTheOneOctetLengthForm(t *testing.T) {
	seen := map[int]bool{}
	for i := range 60 {
		s, b, m := bindFixture(t)
		long := i%2 == 1
		b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, func(sp *sigSpec) { sp.LongLengths = long })
		back := splitPackets(t, b.BackSig)[0].Body
		if len(back) >= 191 {
			t.Fatalf("a back-signature of %d bytes: the page's shape has outgrown the one-octet form", len(back))
		}
		seen[len(back)] = true
		ps := splitPackets(t, bind(t, b))
		un := parseSig(t, ps[1].Body).UnhashedRaw
		// The issuer key ID: 1 length octet, the type and 8 bytes; then the embedded signature, with
		// a one-octet length and the type 32.
		if got := int(un[10]); got != len(back)+1 || un[11] != 32 || !bytes.Equal(un[12:], back) {
			t.Fatalf("the embedding subpacket has length octet %d for a back-signature of %d bytes", un[10], len(back))
		}
		if !verifySig(t, &s.key.PublicKey, ps[1].Body, hashPrefix(&s.key.PublicKey, created), hashPrefix(&m.Key.PublicKey, subAt)) {
			t.Fatalf("the binding for a back-signature of %d bytes does not verify", len(back))
		}
	}
	if len(seen) < 2 {
		t.Errorf("the back-signatures had %d different sizes; the test needs both the short and the long numbers", len(seen))
	}
}

// The faults of a request are found in the order of the code: the subkey is read before its expiry
// is looked at. A subkey that was created after the ceremony is a fault of the request, also when
// the expiry that the caller gave is not after the creation of the subkey, which would be a fault of
// the parameters if it were looked at first.
func TestASubkeyCreatedAfterTheCeremonyIsAFaultOfTheRequestWhateverTheExpiryIs(t *testing.T) {
	s := newSigner(t)
	late := ceremony.Add(2 * time.Hour)
	m := newSubkey(t, &s.key.PublicKey, created, late)
	for _, expires := range []time.Time{ceremony.Add(time.Hour), ceremony.Add(time.Second), late, late.Add(time.Hour)} {
		b := openpgp.BindParams{Primary: s.params(), Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: expires}
		assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(rand.Reader, b) }, openpgp.ErrRequest)
		if _, err := openpgp.BindSubkey(rand.Reader, b); errors.Is(err, openpgp.ErrParams) {
			t.Errorf("expiry %v: %v is a fault of the parameters", expires, err)
		}
	}
	if s.calls != 0 {
		t.Errorf("the signer was asked %d times", s.calls)
	}
	// A subkey created at the ceremony, with the same expiry, is not refused for its creation time.
	ok := newSubkey(t, &s.key.PublicKey, created, ceremony)
	b := openpgp.BindParams{Primary: s.params(), Subkey: ok.Packet, BackSig: ok.BackSig, Capability: "sign", ExpiresAt: ceremony.Add(time.Hour)}
	if _, err := openpgp.BindSubkey(rand.Reader, b); err != nil {
		t.Errorf("a subkey created at the ceremony: %v", err)
	}
}
