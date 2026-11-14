package openpgp_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The root signs the binding with the back-signature of the request inside it, and a relying party
// reads the finished binding with a strict reader. So a back-signature that such a reader refuses
// is refused by the builder, as a fault of the request, before the signer is asked: bytes after the
// two numbers of the signature, a creation time that is not between the creation of the subkey and
// the ceremony, any signature expiration, and a two-byte hash tag that is not the start of the
// digest (docs/reference/hand-off-contract.md, "The request" and check 5: the back-signature must be
// valid).

func u32at(at time.Time) []byte { return u32(uint32(at.Unix())) }

// creationAt makes a tweak that sets the creation time of the back-signature.
func creationAt(at time.Time) func(*sigSpec) {
	return func(sp *sigSpec) { sp.Hashed[0].Data = u32at(at) }
}

// addHashed and addUnhashed make tweaks that add a subpacket.
func addHashed(s sub) func(*sigSpec) { return func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, s) } }
func addUnhashed(s sub) func(*sigSpec) {
	return func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, s) }
}

// tweakCase is a back-signature made with one change to the usual spec.
type tweakCase struct {
	name  string
	tweak func(*sigSpec)
}

// strictRefusals is the list of back-signatures that a strict reader refuses. One list serves the
// tests of BindSubkey and the tests of VerifyBackSignature, so that the two cannot drift apart.
func strictRefusals() []tweakCase {
	far := time.Unix(1<<32-1, 0).UTC()
	return []tweakCase{
		// Bytes after the two numbers of the signature.
		{"one byte after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0xAA} }},
		{"three bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0xAA, 0xBB, 0xCC} }},
		{"a zero byte after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0x00} }},
		{"a third number after the two numbers", func(sp *sigSpec) { sp.Trailing = mpi(big.NewInt(0x1234567890)) }},
		{"a hundred bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = bytes.Repeat([]byte{0x5A}, 100) }},
		// A creation time after the ceremony.
		{"a creation time one second after the ceremony", creationAt(ceremony.Add(time.Second))},
		{"a creation time a day after the ceremony", creationAt(ceremony.Add(24 * time.Hour))},
		{"a creation time in 2100", creationAt(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))},
		{"the last creation time that a four-byte field holds", creationAt(far)},
		// A creation time that is not there, or not once, or not of four bytes.
		{"no creation time", func(sp *sigSpec) { sp.Hashed = sp.Hashed[1:] }},
		{"a creation time in the unhashed area only", func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[0])
			sp.Hashed = sp.Hashed[1:]
		}},
		{"a creation time of three bytes", func(sp *sigSpec) { sp.Hashed[0].Data = sp.Hashed[0].Data[:3] }},
		{"a creation time of five bytes", func(sp *sigSpec) { sp.Hashed[0].Data = append(sp.Hashed[0].Data, 0) }},
		// A creation time before the subkey existed: both tools refuse the binding then.
		{"a creation time one second before the subkey", creationAt(subAt.Add(-time.Second))},
		{"a creation time a day before the subkey", creationAt(subAt.Add(-24 * time.Hour))},
		{"a creation time before the primary", creationAt(created.Add(-time.Second))},
		// Any signature expiration, in either area, whatever its value.
		{"a hashed expiration of one second", addHashed(sub{Type: 3, Data: u32(1)})},
		{"a hashed expiration of one day", addHashed(sub{Type: 3, Data: u32(86400)})},
		{"a hashed expiration of a hundred years", addHashed(sub{Type: 3, Data: u32(100 * 365 * 86400)})},
		{"a hashed expiration of zero", addHashed(sub{Type: 3, Data: u32(0)})},
		{"a hashed expiration of the largest value", addHashed(sub{Type: 3, Data: u32(1<<32 - 1)})},
		{"a hashed expiration marked critical", addHashed(sub{Type: 3, Critical: true, Data: u32(1000000000)})},
		{"a hashed expiration of one byte", addHashed(sub{Type: 3, Data: []byte{1}})},
		{"an unhashed expiration of one second", addUnhashed(sub{Type: 3, Data: u32(1)})},
		{"an unhashed expiration of a hundred years", addUnhashed(sub{Type: 3, Data: u32(100 * 365 * 86400)})},
		{"an unhashed expiration of zero", addUnhashed(sub{Type: 3, Data: u32(0)})},
		{"a hashed and an unhashed expiration", func(sp *sigSpec) {
			addHashed(sub{Type: 3, Data: u32(1000000000)})(sp)
			addUnhashed(sub{Type: 3, Data: u32(1000000000)})(sp)
		}},
		{"two hashed expirations", func(sp *sigSpec) {
			addHashed(sub{Type: 3, Data: u32(1000000000)})(sp)
			addHashed(sub{Type: 3, Data: u32(2000000000)})(sp)
		}},
		{"an expiration before the other subpackets", func(sp *sigSpec) {
			sp.Hashed = append([]sub{{Type: 3, Data: u32(1000000000)}}, sp.Hashed...)
		}},
		// A hash tag that is not the start of the digest.
		{"a hash tag with the first byte changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{0x01, 0} }},
		{"a hash tag with the second byte changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{0, 0x80} }},
		{"a hash tag with both bytes changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{0xFF, 0xFF} }},
		{"a hash tag with one bit changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{0, 0x01} }},
	}
}

func TestABackSignatureThatAStrictReaderRefusesIsRefusedAsARequestAndTheSignerIsNeverAsked(t *testing.T) {
	for _, c := range strictRefusals() {
		t.Run(c.name, func(t *testing.T) {
			s, b, m := bindFixture(t)
			if out := bind(t, b); len(out) == 0 {
				t.Fatal("the control does not start from an acceptance")
			}
			s.calls = 0
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, c.tweak)
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(rand.Reader, b) }, openpgp.ErrRequest)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times for a back-signature that a strict reader refuses", s.calls)
			}
		})
	}
}

// A refusal for a stated reason must come from that reason: the same back-signature with only the
// one thing put right is accepted.
// faultsPutRight is the list of back-signatures that a strict reader accepts: the faults of the
// list above, each put right.
func faultsPutRight() []tweakCase {
	return []tweakCase{
		{"no bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = nil }},
		{"a creation time at the ceremony", creationAt(ceremony)},
		{"a creation time one second before the ceremony", creationAt(ceremony.Add(-time.Second))},
		{"a creation time at the creation of the subkey", creationAt(subAt)},
		{"a creation time one second after the creation of the subkey", creationAt(subAt.Add(time.Second))},
		{"a creation time between the two", creationAt(subAt.Add(time.Hour))},
		{"a hash tag that is the start of the digest", func(sp *sigSpec) { sp.TagXOR = [2]byte{} }},
		{"the same subpackets with five-octet lengths", func(sp *sigSpec) { sp.LongLengths = true }},
		{"the packet with an old-format header", func(sp *sigSpec) { sp.OldHeader = true }},
	}
}

func TestTheSameBackSignaturesWithTheFaultPutRightAreAccepted(t *testing.T) {
	for _, c := range faultsPutRight() {
		t.Run(c.name, func(t *testing.T) {
			s, b, m := bindFixture(t)
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, c.tweak)
			out, err := openpgp.BindSubkey(rand.Reader, b)
			if err != nil {
				t.Fatalf("BindSubkey: %v", err)
			}
			if s.calls != 1 {
				t.Errorf("the signer was asked %d times, want once", s.calls)
			}
			ps := splitPackets(t, out)
			if got := find(t, parseSig(t, ps[1].Body).Unhashed, 32).Data; !bytes.Equal(got, splitPackets(t, b.BackSig)[0].Body) {
				t.Error("the back-signature is not embedded unchanged")
			}
		})
	}
}

// The limits are exact to the second: the ceremony second is allowed, the next one is not; the
// creation second of the subkey is allowed, the one before it is not.
func TestTheCreationTimeOfTheBackSignatureIsHeldToTheSecond(t *testing.T) {
	for _, c := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"the creation of the subkey less one second", subAt.Add(-time.Second), false},
		{"the creation of the subkey", subAt, true},
		{"the ceremony less one second", ceremony.Add(-time.Second), true},
		{"the ceremony", ceremony, true},
		{"the ceremony and one second", ceremony.Add(time.Second), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, b, m := bindFixture(t)
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, creationAt(c.at))
			if c.ok {
				if _, err := openpgp.BindSubkey(rand.Reader, b); err != nil {
					t.Fatalf("BindSubkey: %v", err)
				}
				return
			}
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(rand.Reader, b) }, openpgp.ErrRequest)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}

// The ceremony of the primary decides the upper limit, not the time of the test: a ceremony far
// from the present, in the past and in the future, holds the same limits.
func TestTheCeremonyDecidesTheLimitOfTheBackSignatureWhateverThePresentTimeIs(t *testing.T) {
	for _, c := range []struct {
		name     string
		ceremony time.Time
	}{
		{"a ceremony in 1990", time.Date(1990, 6, 1, 12, 0, 0, 0, time.UTC)},
		{"a ceremony in 2090", time.Date(2090, 6, 1, 12, 0, 0, 0, time.UTC)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSigner(t)
			pcreated := c.ceremony.Add(-72 * time.Hour)
			subCreated := c.ceremony.Add(-2 * time.Hour)
			p := s.params()
			p.CreationTime, p.CeremonyTime, p.ExpiresAt = pcreated, c.ceremony, c.ceremony.AddDate(3, 0, 0)
			mk := func(at time.Time) openpgp.BindParams {
				m := newSubkeyWith(t, &s.key.PublicKey, pcreated, subCreated, creationAt(at))
				return openpgp.BindParams{Primary: p, Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: c.ceremony.AddDate(1, 0, 0)}
			}
			if out, err := openpgp.BindSubkey(rand.Reader, mk(c.ceremony)); err != nil || len(out) == 0 {
				t.Fatalf("a back-signature made at the ceremony: %v", err)
			}
			assertRefused(t, "BindSubkey", func() ([]byte, error) {
				return openpgp.BindSubkey(rand.Reader, mk(c.ceremony.Add(time.Second)))
			}, openpgp.ErrRequest)
			assertRefused(t, "BindSubkey", func() ([]byte, error) {
				return openpgp.BindSubkey(rand.Reader, mk(subCreated.Add(-time.Second)))
			}, openpgp.ErrRequest)
		})
	}
}

// The builders take their times from the parameters and never from the clock: with every time of a
// world in the far past or the far future, all four builders work, and what they write verifies.
func TestTheBuildersDoNotReadTheClock(t *testing.T) {
	for _, c := range []struct {
		name  string
		start time.Time
	}{
		{"1980", time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"2090", time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"2104", time.Date(2104, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSigner(t)
			pcreated := c.start
			cer := c.start.Add(72 * time.Hour)
			subAt := c.start.Add(48 * time.Hour)
			p := s.params()
			p.CreationTime, p.CeremonyTime, p.ExpiresAt = pcreated, cer, cer.AddDate(1, 0, 0)
			cert, err := openpgp.NewPrimary(rand.Reader, p)
			if err != nil {
				t.Fatalf("NewPrimary: %v", err)
			}
			if _, err := openpgp.ExtendPrimary(rand.Reader, p); err != nil {
				t.Errorf("ExtendPrimary: %v", err)
			}
			if _, err := openpgp.RevocationSignature(rand.Reader, p, openpgp.Superseded); err != nil {
				t.Errorf("RevocationSignature: %v", err)
			}
			m := newSubkey(t, &s.key.PublicKey, pcreated, subAt)
			out, err := openpgp.BindSubkey(rand.Reader, openpgp.BindParams{Primary: p, Subkey: m.Packet, BackSig: m.BackSig, Capability: "sign", ExpiresAt: cer.AddDate(0, 6, 0)})
			if err != nil {
				t.Fatalf("BindSubkey: %v", err)
			}
			ps := splitPackets(t, out)
			if !verifySig(t, &s.key.PublicKey, ps[1].Body, hashPrefix(&s.key.PublicKey, pcreated), hashPrefix(&m.Key.PublicKey, subAt)) {
				t.Error("the binding does not verify")
			}
			if cs := splitPackets(t, cert); len(cs) != 3 {
				t.Errorf("the certificate holds %d packets", len(cs))
			}
		})
	}
}

// The shape of the page (docs/reference/hand-off-contract.md, "The request"): "Its hashed area has
// the signature creation time and the issuer fingerprint of the subkey. Its unhashed area has the
// issuer key ID of the subkey." The root signs the binding with the back-signature inside it, and
// gpgv or sqv refuse the binding for a subpacket that go-crypto passes over, so a back-signature
// with one subpacket more, one less or in the other area, or with a critical bit on any subpacket,
// is refused as a fault of the request, before the signer is asked.

// backSigShape is a back-signature of one shape. A shape of kind refuse must not get a binding; any
// other shape must get one that both tools accept.
type backSigShape struct {
	name  string
	tweak func(*sigSpec)
	kind  shapeKind
}

type shapeKind int

const (
	accept shapeKind = iota
	refuse
)

// numbers makes a tweak that writes the two numbers of the signature with the given encoders.
func numbers(first, second func(*big.Int) []byte) func(*sigSpec) {
	return func(sp *sigSpec) {
		sp.Numbers = func(r, s *big.Int) []byte { return append(first(r), second(s)...) }
	}
}

// leadingZero writes a number with a zero byte in front. With counted set the bit length counts that
// byte, and then it is as long as the bytes; otherwise it is the true bit length.
func leadingZero(counted bool) func(*big.Int) []byte {
	return func(v *big.Int) []byte {
		b := append([]byte{0}, v.Bytes()...)
		bits := v.BitLen()
		if counted {
			bits = 8 * len(b)
		}
		return append([]byte{byte(bits >> 8), byte(bits)}, b...)
	}
}

// backTimes are the two moments that the shapes of a back-signature are measured from.
type backTimes struct{ subAt, ceremony time.Time }

// extra is one subpacket that a back-signature may carry beyond the page. The subpacket may depend on
// the spec, for the two issuers.
type extra struct {
	name string
	make func(sp *sigSpec) sub
}

func fixed(name string, typ byte, data ...byte) extra {
	return extra{name, func(*sigSpec) sub { return sub{Type: typ, Data: data} }}
}

// subpacketsBeyondThePage are subpackets that go-crypto lets through in a back-signature and that
// the page does not give: each of them is refused in either area, with the critical bit and
// without it.
func subpacketsBeyondThePage(c backTimes) []extra {
	notation := func(flags byte) []byte {
		return append([]byte{flags, 0, 0, 0, 0, 3, 0, 1}, []byte("abc1")...)
	}
	otherFp := append([]byte{4}, bytes.Repeat([]byte{0x11}, 20)...)
	return []extra{
		fixed("a notation, human-readable", 20, notation(0x80)...),
		fixed("a notation, not human-readable", 20, notation(0)...),
		fixed("an unknown subpacket, type 100", 100, 1, 2, 3),
		fixed("an unknown subpacket, type 99", 99, 1, 2),
		fixed("an unknown subpacket of no data, type 101", 101),
		fixed("a key expiration of one year", 9, 0x01, 0xE1, 0x33, 0x80),
		fixed("a key expiration of one byte", 9, 1),
		fixed("a key expiration of eight bytes", 9, 1, 2, 3, 4, 5, 6, 7, 8),
		fixed("key flags of a signing key", 27, 0x02),
		fixed("key flags of a certifying key", 27, 0x01),
		fixed("preferred hash algorithms", 21, 9, 8, 10),
		fixed("preferred symmetric algorithms", 11, 9, 8),
		fixed("preferred compression algorithms", 22, 0),
		fixed("preferred AEAD ciphersuites", 39, 9, 2),
		fixed("key server preferences", 23, 0x80),
		fixed("a signer's user ID", 28, []byte("Example Test")...),
		fixed("a signature expiration of one second", 3, 0, 0, 0, 1),
		fixed("a signature expiration of a hundred years", 3, 0xBB, 0x03, 0x84, 0x00),
		fixed("an exportable certification flag, set", 4, 1),
		fixed("an exportable certification flag, not set", 4, 0),
		fixed("a revocable flag", 7, 1),
		fixed("a trust signature", 5, 1, 60),
		fixed("a regular expression", 6, []byte("x\x00")...),
		fixed("a revocation key", 12, 0x80, 19, 1, 2, 3),
		fixed("a policy URI", 26, []byte("https://example.org/policy")...),
		fixed("a primary user ID flag", 25, 1),
		fixed("a reason for revocation", 29, 0, 'x'),
		fixed("features", 30, 1),
		fixed("an intended recipient", 35, append([]byte{4}, bytes.Repeat([]byte{0x22}, 20)...)...),
		fixed("a second creation time, the same", 2, u32at(c.subAt)...),
		fixed("a second creation time, after the ceremony", 2, u32at(c.ceremony.Add(time.Hour))...),
		fixed("a second creation time, before the subkey", 2, u32at(c.subAt.Add(-time.Hour))...),
		fixed("an embedded signature of junk", 32, 4, 0x19, 19, 9, 0, 0, 0, 0, 0, 0),
		{"a second issuer fingerprint, the same", func(sp *sigSpec) sub { return sp.Hashed[1] }},
		fixed("a second issuer fingerprint, of another key", 33, otherFp...),
		{"a second issuer key ID, the same", func(sp *sigSpec) sub { return sp.Unhashed[0] }},
		fixed("a second issuer key ID, of another key", 16, bytes.Repeat([]byte{0x33}, 8)...),
		fixed("an issuer key ID of seven bytes", 16, bytes.Repeat([]byte{0x33}, 7)...),
		fixed("an issuer fingerprint of 20 bytes", 33, bytes.Repeat([]byte{0x44}, 20)...),
		fixed("a long subpacket (300 bytes)", 100, bytes.Repeat([]byte{7}, 300)...),
		fixed("a long subpacket (9000 bytes)", 100, bytes.Repeat([]byte{7}, 9000)...),
		fixed("a very long subpacket (12000 bytes)", 100, bytes.Repeat([]byte{7}, 12000)...),
		fixed("a very long subpacket (17000 bytes)", 100, bytes.Repeat([]byte{7}, 17000)...),
	}
}

// backSigShapes is a set of back-signatures: the shapes that the page allows, which both tools must
// accept inside the finished binding, and the shapes that it does not, which get no binding.
func backSigShapes(c backTimes) []backSigShape {
	var out []backSigShape
	add := func(name string, kind shapeKind, tweak func(*sigSpec)) {
		out = append(out, backSigShape{name: name, tweak: tweak, kind: kind})
	}
	// What the page allows. The order of the two hashed subpackets, the form of the lengths and the
	// form of the packet header are not part of the shape; the creation time may be anywhere between
	// the creation of the subkey and the ceremony.
	add("the plain back-signature", accept, nil)
	add("the issuer fingerprint before the creation time", accept, func(sp *sigSpec) { sp.Hashed[0], sp.Hashed[1] = sp.Hashed[1], sp.Hashed[0] })
	add("every subpacket with a five-octet length", accept, func(sp *sigSpec) { sp.LongLengths = true })
	add("an old-format packet header", accept, func(sp *sigSpec) { sp.OldHeader = true })
	add("an old-format header and five-octet lengths", accept, func(sp *sigSpec) { sp.OldHeader, sp.LongLengths = true, true })
	add("a creation time one hour after the creation of the subkey", accept, creationAt(c.subAt.Add(time.Hour)))
	add("a creation time at the ceremony", accept, creationAt(c.ceremony))
	add("a creation time one second before the ceremony", accept, creationAt(c.ceremony.Add(-time.Second)))
	add("two numbers of the usual form", accept, numbers(mpi, mpi))
	add("the second number replaced by its complement", accept, func(sp *sigSpec) {
		n := elliptic.P384().Params().N
		sp.Numbers = func(r, s *big.Int) []byte { return append(mpi(r), mpi(new(big.Int).Sub(n, s))...) }
	})

	// A subpacket more, in either area, critical or not.
	for _, x := range subpacketsBeyondThePage(c) {
		for _, area := range []string{"hashed", "unhashed"} {
			for _, crit := range []bool{false, true} {
				name := x.name + ", in the " + area + " area"
				if crit {
					name += ", marked critical"
				}
				add(name, refuse, func(sp *sigSpec) {
					s := x.make(sp)
					s.Critical = crit
					if area == "hashed" {
						sp.Hashed = append(sp.Hashed, s)
					} else {
						sp.Unhashed = append(sp.Unhashed, s)
					}
				})
			}
		}
	}
	// A subpacket of the page with the critical bit, or in the other area, or not there.
	add("the creation time with the critical bit", refuse, func(sp *sigSpec) { sp.Hashed[0].Critical = true })
	add("the issuer fingerprint with the critical bit", refuse, func(sp *sigSpec) { sp.Hashed[1].Critical = true })
	add("the issuer key ID with the critical bit", refuse, func(sp *sigSpec) { sp.Unhashed[0].Critical = true })
	add("the issuer key ID in the hashed area, not in the unhashed area", refuse, func(sp *sigSpec) {
		sp.Hashed = append(sp.Hashed, sp.Unhashed[0])
		sp.Unhashed = nil
	})
	add("the issuer fingerprint in the unhashed area, not in the hashed area", refuse, func(sp *sigSpec) {
		sp.Unhashed = append(sp.Unhashed, sp.Hashed[1])
		sp.Hashed = sp.Hashed[:1]
	})
	add("the two issuers each in the other area", refuse, func(sp *sigSpec) {
		sp.Hashed, sp.Unhashed = []sub{sp.Hashed[0], sp.Unhashed[0]}, []sub{sp.Hashed[1]}
	})
	add("no issuer key ID", refuse, func(sp *sigSpec) { sp.Unhashed = nil })
	add("no issuer fingerprint", refuse, func(sp *sigSpec) { sp.Hashed = sp.Hashed[:1] })
	add("no creation time", refuse, func(sp *sigSpec) { sp.Hashed = sp.Hashed[1:] })
	add("a creation time in the unhashed area, not in the hashed area", refuse, func(sp *sigSpec) {
		sp.Unhashed = append(sp.Unhashed, sp.Hashed[0])
		sp.Hashed = sp.Hashed[1:]
	})
	add("no subpackets at all", refuse, func(sp *sigSpec) { sp.Hashed, sp.Unhashed = nil, nil })
	// The creation time and the two numbers.
	add("a creation time after the ceremony", refuse, creationAt(c.ceremony.Add(time.Second)))
	add("a creation time before the subkey", refuse, creationAt(c.subAt.Add(-time.Second)))
	add("a first number with a leading zero byte and its true bit length", refuse, numbers(leadingZero(false), mpi))
	add("a first number with a leading zero byte that the bit length counts", refuse, numbers(leadingZero(true), mpi))
	add("a second number with a leading zero byte and its true bit length", refuse, numbers(mpi, leadingZero(false)))
	add("a second number with a leading zero byte that the bit length counts", refuse, numbers(mpi, leadingZero(true)))
	add("a second number of no bits", refuse, numbers(mpi, func(*big.Int) []byte { return []byte{0, 0} }))
	add("a first number of no bits", refuse, numbers(func(*big.Int) []byte { return []byte{0, 0} }, mpi))
	add("one byte after the two numbers", refuse, func(sp *sigSpec) { sp.Trailing = []byte{0xAA} })
	add("a wrong hash tag", refuse, func(sp *sigSpec) { sp.TagXOR = [2]byte{0x01, 0x01} })
	return out
}

// Every shape of the list: the shapes of the page get a binding with the back-signature embedded
// unchanged, and the signer is asked once; every other shape is refused as a fault of the request,
// and the signer is never asked.
func TestAcceptedShapesOfTheBackSignatureAreEmbeddedUnchangedAndAllOthersAreRefused(t *testing.T) {
	shapes := backSigShapes(backTimes{subAt: subAt, ceremony: ceremony})
	if len(shapes) < 200 {
		t.Fatalf("%d shapes, want at least 200", len(shapes))
	}
	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			s, b, m := bindFixture(t)
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, sh.tweak)
			out, err := openpgp.BindSubkey(rand.Reader, b)
			if sh.kind == refuse {
				assertRefused(t, "BindSubkey", func() ([]byte, error) { return out, err }, openpgp.ErrRequest)
				if s.calls != 0 {
					t.Errorf("the signer was asked %d times", s.calls)
				}
				return
			}
			if err != nil {
				t.Fatalf("BindSubkey: %v", err)
			}
			if s.calls != 1 {
				t.Errorf("the signer was asked %d times, want once", s.calls)
			}
			ps := splitPackets(t, out)
			if got := find(t, parseSig(t, ps[1].Body).Unhashed, 32).Data; !bytes.Equal(got, splitPackets(t, b.BackSig)[0].Body) {
				t.Error("the back-signature is not embedded unchanged")
			}
		})
	}
}

// subpacketTypeFaults is the list of back-signatures with a subpacket of any type from 0 to 127 more
// than the page gives, in either area, critical or not, of one byte or of eight; and each of the
// three subpackets of the page made into any other type.
func subpacketTypeFaults() []tweakCase {
	var out []tweakCase
	add := func(name string, tweak func(*sigSpec)) { out = append(out, tweakCase{name, tweak}) }
	for typ := 0; typ < 128; typ++ {
		for _, crit := range []bool{false, true} {
			for _, n := range []int{1, 8} {
				x := sub{Type: byte(typ), Critical: crit, Data: bytes.Repeat([]byte{1}, n)}
				name := fmt.Sprintf("type %d, critical %v, %d bytes", typ, crit, n)
				add("hashed, "+name, func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, x) })
				add("unhashed, "+name, func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, x) })
			}
		}
		if typ == 2 {
			continue
		}
		add(fmt.Sprintf("the creation time as type %d", typ), func(sp *sigSpec) { sp.Hashed[0].Type = byte(typ) })
	}
	for typ := 0; typ < 128; typ++ {
		if typ == 33 {
			continue
		}
		add(fmt.Sprintf("the issuer fingerprint as type %d", typ), func(sp *sigSpec) { sp.Hashed[1].Type = byte(typ) })
	}
	for typ := 0; typ < 128; typ++ {
		if typ == 16 {
			continue
		}
		add(fmt.Sprintf("the issuer key ID as type %d", typ), func(sp *sigSpec) { sp.Unhashed[0].Type = byte(typ) })
	}
	return out
}

// A subpacket of any type from 0 to 127 more than the page gives, in either area, critical or not,
// of one byte or of eight: every one is refused, and the signer is never asked. The same for each
// of the three subpackets of the page made into any other type.
func TestAnySubpacketTypeBeyondThePageIsRefusedWhateverItsAreaBitAndLength(t *testing.T) {
	s, b, m := bindFixture(t)
	if out := bind(t, b); len(out) == 0 {
		t.Fatal("the control does not start from an acceptance")
	}
	s.calls = 0
	for _, c := range subpacketTypeFaults() {
		p := b
		p.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, c.tweak)
		out, err := openpgp.BindSubkey(rand.Reader, p)
		if !errors.Is(err, openpgp.ErrRequest) || out != nil {
			t.Errorf("%s: %d bytes and error %v, want a refusal of the request", c.name, len(out), err)
		}
	}
	if s.calls != 0 {
		t.Errorf("the signer was asked %d times", s.calls)
	}
}

// Each of the subpackets of the page, with a length that is not its own, is refused. The two issuers
// are held to their exact values and the creation time to four bytes.
// pageLengthFaults is the list of back-signatures whose subpackets of the page have a length or a
// value that is not their own.
func pageLengthFaults() []tweakCase {
	return []tweakCase{
		{"a creation time of no bytes", func(sp *sigSpec) { sp.Hashed[0].Data = nil }},
		{"a creation time of three bytes", func(sp *sigSpec) { sp.Hashed[0].Data = sp.Hashed[0].Data[:3] }},
		{"a creation time of five bytes", func(sp *sigSpec) { sp.Hashed[0].Data = append(sp.Hashed[0].Data, 0) }},
		{"a creation time of eight bytes", func(sp *sigSpec) { sp.Hashed[0].Data = append(sp.Hashed[0].Data, make([]byte, 4)...) }},
		{"an issuer fingerprint of no bytes", func(sp *sigSpec) { sp.Hashed[1].Data = nil }},
		{"an issuer fingerprint of 20 bytes", func(sp *sigSpec) { sp.Hashed[1].Data = sp.Hashed[1].Data[:20] }},
		{"an issuer fingerprint of 22 bytes", func(sp *sigSpec) { sp.Hashed[1].Data = append(sp.Hashed[1].Data, 0) }},
		{"an issuer fingerprint of 21 bytes with the version of another key format", func(sp *sigSpec) {
			sp.Hashed[1].Data = append([]byte{5}, sp.Hashed[1].Data[1:]...)
		}},
		{"an issuer key ID of no bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = nil }},
		{"an issuer key ID of seven bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = sp.Unhashed[0].Data[:7] }},
		{"an issuer key ID of nine bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = append(sp.Unhashed[0].Data, 0) }},
		{"an issuer key ID that is not the end of the fingerprint", func(sp *sigSpec) {
			sp.Unhashed[0].Data = bytes.Clone(sp.Unhashed[0].Data)
			sp.Unhashed[0].Data[7] ^= 1
		}},
		{"an issuer fingerprint that is not the one of the subkey", func(sp *sigSpec) {
			sp.Hashed[1].Data = bytes.Clone(sp.Hashed[1].Data)
			sp.Hashed[1].Data[20] ^= 1
		}},
	}
}

func TestTheSubpacketsOfThePageWithAnotherLengthAreRefused(t *testing.T) {
	for _, c := range pageLengthFaults() {
		t.Run(c.name, func(t *testing.T) {
			s, b, m := bindFixture(t)
			b.BackSig = backSig(t, m.Key, m.Created, m.Primary, m.PrimaryAt, c.tweak)
			assertRefused(t, "BindSubkey", func() ([]byte, error) { return openpgp.BindSubkey(rand.Reader, b) }, openpgp.ErrRequest)
			if s.calls != 0 {
				t.Errorf("the signer was asked %d times", s.calls)
			}
		})
	}
}
