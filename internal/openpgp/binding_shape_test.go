package openpgp_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The faults of a binding. A fault of the signature, of its form or of its issuer is an ErrBinding.
// A fault of the subpackets is an ErrBindingShape, which is returned only after the signature
// verified: the tests that need a signature that verifies write it again with a primary of their
// own (the kit), so that the signature is good and only the shape is wrong.

// An unhashed area at the edge of what gpgv reads.
const (
	maxUnhashedArea = 10000
	idSubpacketLen  = 10 // the issuer key ID subpacket: a length byte, the type and 8 bytes
	embeddedHeader  = 3  // the embedded signature subpacket's length (two bytes) and its type
)

// embeddedFor is a body for the embedded signature that makes the whole unhashed area n bytes, with
// the shortest length form for each subpacket.
func embeddedFor(n int) []byte {
	header := embeddedHeader
	if n-idSubpacketLen-header+1 >= 16320 {
		header = 6 // the five-byte form of the length, and the type
	}
	return bytes.Repeat([]byte{0xAB}, n-idSubpacketLen-header)
}

func TestASubpacketOfAnotherTypeIsAShapeFaultInEitherAreaCriticalOrNot(t *testing.T) {
	k := newBindKit(t)
	n := 0
	for typ := byte(0); typ < 128; typ++ {
		for _, critical := range []bool{false, true} {
			for _, area := range []string{"hashed", "unhashed"} {
				used := typ == 2 || typ == 9 || typ == 27 || typ == 33 // the four of the hashed area
				if area == "unhashed" {
					used = typ == 16 || typ == 32
				}
				if used {
					continue
				}
				what := fmt.Sprintf("a subpacket of type %d, critical %v, in the %s area", typ, critical, area)
				pkt := k.build(t, func(sp *sigSpec) {
					extra := sub{Type: typ, Critical: critical, Data: []byte{0, 1, 2, 3}}
					if area == "hashed" {
						sp.Hashed = append(sp.Hashed, extra)
					} else {
						sp.Unhashed = append(sp.Unhashed, extra)
					}
				})
				k.assertFault(t, what, pkt, openpgp.ErrBindingShape)
				n++
			}
		}
	}
	if n < 400 {
		t.Fatalf("only %d cases were run", n)
	}
}

func TestAnotherKindOfSubpacketInTheOtherAreaIsAShapeFault(t *testing.T) {
	k := newBindKit(t)
	for name, tweak := range map[string]func(*sigSpec){
		"the issuer key ID in the hashed area as well":      func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Unhashed[0]) },
		"the embedded signature in the hashed area as well": func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Unhashed[1]) },
		"the issuer fingerprint in the unhashed area as well": func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[3])
		},
		"the issuer fingerprint of another key in the unhashed area, the right one in the hashed": func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sub{Type: 33, Data: append([]byte{4}, newBindKit(t).fp...)})
		},
		"the creation time in the unhashed area as well": func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sp.Hashed[0]) },
		"the key flags in the unhashed area as well":     func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sp.Hashed[1]) },
		"the key expiration in the unhashed area as well": func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[2])
		},
		"the key expiration in the unhashed area instead of the hashed": func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[2])
			sp.Hashed = append(sp.Hashed[:2:2], sp.Hashed[3])
		},
		"the key flags in the unhashed area instead of the hashed": func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[1])
			sp.Hashed = append(sp.Hashed[:1:1], sp.Hashed[2:]...)
		},
	} {
		k.assertFault(t, name, k.build(t, tweak), openpgp.ErrBindingShape)
	}
}

func TestTheHashedAreaHoldsTheFourSubpacketsOfThePageEachOnceWithTheirValues(t *testing.T) {
	k := newBindKit(t)
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		// Missing, one at a time.
		{"no creation time", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed[:0:0], sp.Hashed[1:]...) }},
		{"no key flags", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed[:1:1], sp.Hashed[2:]...) }},
		{"no key expiration", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed[:2:2], sp.Hashed[3]) }},
		// Replaced by a second copy of another, so that there are still four and one is twice.
		{"two creation times and no key flags", func(sp *sigSpec) { sp.Hashed[1] = sp.Hashed[0] }},
		{"two creation times and no key expiration", func(sp *sigSpec) { sp.Hashed[2] = sp.Hashed[0] }},
		{"two key flags and no creation time", func(sp *sigSpec) { sp.Hashed[0] = sp.Hashed[1] }},
		{"two key flags and no key expiration", func(sp *sigSpec) { sp.Hashed[2] = sp.Hashed[1] }},
		{"two key expirations and no creation time", func(sp *sigSpec) { sp.Hashed[0] = sp.Hashed[2] }},
		{"two key expirations and no key flags", func(sp *sigSpec) { sp.Hashed[1] = sp.Hashed[2] }},
		{"a second creation time", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[0]) }},
		{"a second key flags", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[1]) }},
		{"a second key expiration", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[2]) }},
		// The critical bit: only the key expiration has it.
		{"a critical creation time", func(sp *sigSpec) { sp.Hashed[0].Critical = true }},
		{"critical key flags", func(sp *sigSpec) { sp.Hashed[1].Critical = true }},
		{"a key expiration that is not critical", func(sp *sigSpec) { sp.Hashed[2].Critical = false }},
		{"a critical issuer fingerprint", func(sp *sigSpec) { sp.Hashed[3].Critical = true }},
		{"every subpacket critical", func(sp *sigSpec) {
			for i := range sp.Hashed {
				sp.Hashed[i].Critical = true
			}
			for i := range sp.Unhashed {
				sp.Unhashed[i].Critical = true
			}
		}},
		{"no subpacket critical", func(sp *sigSpec) {
			for i := range sp.Hashed {
				sp.Hashed[i].Critical = false
			}
		}},
		// The lengths.
		{"a creation time of 3 bytes", func(sp *sigSpec) { sp.Hashed[0].Data = sp.Hashed[0].Data[:3] }},
		{"a creation time of 5 bytes", func(sp *sigSpec) { sp.Hashed[0].Data = append(sp.Hashed[0].Data, 0) }},
		{"a creation time of 0 bytes", func(sp *sigSpec) { sp.Hashed[0].Data = nil }},
		{"key flags of 0 bytes", func(sp *sigSpec) { sp.Hashed[1].Data = nil }},
		{"key flags of two bytes", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x02, 0x00} }},
		{"key flags of two bytes, the second not zero", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x02, 0x01} }},
		{"key flags of 0x20 and a second byte", func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x20, 0x00} }},
		{"a key expiration of 3 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = sp.Hashed[2].Data[1:] }},
		{"a key expiration of 5 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = append(sp.Hashed[2].Data, 0) }},
		{"a key expiration of 0 bytes", func(sp *sigSpec) { sp.Hashed[2].Data = nil }},
		{"a key expiration of zero seconds", func(sp *sigSpec) { sp.Hashed[2].Data = u32(0) }},
		{"a key expiration of zero and not critical", func(sp *sigSpec) { sp.Hashed[2].Data, sp.Hashed[2].Critical = u32(0), false }},
	} {
		k.assertFault(t, c.name, k.build(t, c.tweak), openpgp.ErrBindingShape)
	}
}

// The key flags are exactly 0x02 or 0x20, "and nothing else": of the 256 values of the byte, two.
func TestOnlyTheKeyFlagsOfTheTwoCapabilitiesAreAccepted(t *testing.T) {
	k := newBindKit(t)
	accepted := 0
	for flags := range 256 {
		pkt := k.build(t, func(sp *sigSpec) { sp.Hashed[1].Data = []byte{byte(flags)} })
		what := fmt.Sprintf("the key flags %#02x", flags)
		switch flags {
		case 0x02, 0x20:
			b := k.assertAccepted(t, what, pkt)
			want := map[int]string{0x02: "sign", 0x20: "authenticate"}[flags]
			if b != nil && b.Capability() != want {
				t.Errorf("%s: Capability = %q, want %q", what, b.Capability(), want)
			}
			accepted++
		default:
			k.assertFault(t, what, pkt, openpgp.ErrBindingShape)
		}
	}
	if accepted != 2 {
		t.Errorf("%d key flags were accepted, want 2", accepted)
	}
}

func TestTheUnhashedAreaHoldsTheIssuerKeyIDAndOneEmbeddedSignatureAndNothingElse(t *testing.T) {
	k := newBindKit(t)
	other := newBindKit(t)
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"nothing", func(sp *sigSpec) { sp.Unhashed = nil }},
		{"no issuer key ID", func(sp *sigSpec) { sp.Unhashed = sp.Unhashed[1:] }},
		{"no embedded signature", func(sp *sigSpec) { sp.Unhashed = sp.Unhashed[:1] }},
		{"an empty embedded signature", func(sp *sigSpec) { sp.Unhashed[1].Data = nil }},
		{"two embedded signatures and no key ID", func(sp *sigSpec) { sp.Unhashed[0] = sp.Unhashed[1] }},
		{"two issuer key IDs and no embedded signature", func(sp *sigSpec) { sp.Unhashed[1] = sp.Unhashed[0] }},
		{"a second embedded signature", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sp.Unhashed[1]) }},
		{"a second embedded signature, another one", func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sub{Type: 32, Data: other.sub.BackBody})
		}},
		{"a second issuer key ID", func(sp *sigSpec) { sp.Unhashed = append(sp.Unhashed, sp.Unhashed[0]) }},
		{"the issuer key ID of another key", func(sp *sigSpec) { sp.Unhashed[0].Data = other.fp[12:] }},
		{"the issuer key ID with one byte changed", func(sp *sigSpec) { sp.Unhashed[0].Data[7] ^= 1 }},
		{"the issuer key ID with the first byte changed", func(sp *sigSpec) { sp.Unhashed[0].Data[0] ^= 1 }},
		{"the issuer key ID of the subkey", func(sp *sigSpec) { sp.Unhashed[0].Data = fingerprint(&k.sub.Key.PublicKey, subAt)[12:] }},
		{"the first 8 bytes of the primary's fingerprint as the key ID", func(sp *sigSpec) { sp.Unhashed[0].Data = k.fp[:8] }},
		{"an issuer key ID of 7 bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = k.fp[13:] }},
		{"an issuer key ID of 9 bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = k.fp[11:] }},
		{"an issuer key ID of 20 bytes", func(sp *sigSpec) { sp.Unhashed[0].Data = k.fp }},
		{"an empty issuer key ID", func(sp *sigSpec) { sp.Unhashed[0].Data = nil }},
		{"a critical issuer key ID", func(sp *sigSpec) { sp.Unhashed[0].Critical = true }},
		{"a critical embedded signature", func(sp *sigSpec) { sp.Unhashed[1].Critical = true }},
		{"the issuer fingerprint instead of the key ID", func(sp *sigSpec) { sp.Unhashed[0] = sub{Type: 33, Data: append([]byte{4}, k.fp...)} }},
	} {
		k.assertFault(t, c.name, k.build(t, c.tweak), openpgp.ErrBindingShape)
	}
}

// The embedded signature is not read, only its presence: "the request's back-signature for this
// primary, unchanged", which the caller compares with its own (Embeds). A body of any bytes is a
// body here.
func TestTheEmbeddedSignatureIsKeptAsItIsAndNotRead(t *testing.T) {
	k := newBindKit(t)
	for name, body := range map[string][]byte{
		"one byte": {0x01},
		"the back-signature of another primary's request": newBindKit(t).sub.BackBody,
		"a version 3 signature body":                      append([]byte{3}, make([]byte, 20)...),
		"zeros":                                           make([]byte, 200),
	} {
		b := k.assertAccepted(t, name, k.build(t, withEmbedded(body)))
		if b == nil {
			continue
		}
		if b.Embeds(k.sub.BackSig) && !bytes.Equal(body, k.sub.BackBody) {
			t.Errorf("%s: Embeds is true for a back-signature that is not the embedded one", name)
		}
		if !b.Embeds(wrap(tagSignature, body)) {
			t.Errorf("%s: Embeds is false for the embedded body, whole", name)
		}
	}
}

// "at most 10,000 bytes in all in the area, the limit gpgv reads": the unhashed area is not longer
// than that.
func TestTheUnhashedAreaIsAtMost10000BytesAndNoLonger(t *testing.T) {
	k := newBindKit(t)
	for _, c := range []struct {
		area int
		ok   bool
	}{{600, true}, {9999, true}, {maxUnhashedArea, true}, {maxUnhashedArea + 1, false}, {maxUnhashedArea + 2, false}, {20000, false}, {60000, false}} {
		what := fmt.Sprintf("an unhashed area of %d bytes", c.area)
		pkt := k.build(t, withEmbedded(embeddedFor(c.area)))
		if l := layoutOf(bodyOf(t, pkt)).unhashedLen; l != c.area {
			t.Fatalf("%s: the test wrote %d bytes", what, l)
		}
		if c.ok {
			k.assertAccepted(t, what, pkt)
		} else {
			k.assertFault(t, what, pkt, openpgp.ErrBindingShape)
		}
	}
}

// Both areas may hold up to 32 subpackets and no more (the bound on the walk of an area). A hashed
// area of 32 subpackets is read as far as its content: it is a shape fault, after the signature
// verified. One of 33 is refused as a form that is not read at all.
func TestAnAreaOf32SubpacketsIsReadAndOneOf33IsRefusedBeforeItsSignatureIsLooked(t *testing.T) {
	k := newBindKit(t)
	pad := func(sp *sigSpec, hashed bool, total int) {
		for {
			area := &sp.Unhashed
			if hashed {
				area = &sp.Hashed
			}
			if len(*area) >= total {
				return
			}
			*area = append(*area, sub{Type: 100, Data: []byte{1}})
		}
	}
	for _, hashed := range []bool{true, false} {
		area := map[bool]string{true: "hashed", false: "unhashed"}[hashed]
		for _, c := range []struct {
			n    int
			kind error
		}{
			{32, openpgp.ErrBindingShape},
			{33, openpgp.ErrBinding},
			{34, openpgp.ErrBinding},
			{200, openpgp.ErrBinding},
		} {
			pkt := k.build(t, func(sp *sigSpec) { pad(sp, hashed, c.n) })
			k.assertFault(t, fmt.Sprintf("%d subpackets in the %s area", c.n, area), pkt, c.kind)
			// 33 subpackets are refused whatever the signature: one that does not verify is the same fault.
			if errors.Is(c.kind, openpgp.ErrBinding) {
				bad := k.build(t, func(sp *sigSpec) { pad(sp, hashed, c.n); sp.Key = genKey(t) })
				k.assertFault(t, fmt.Sprintf("%d subpackets in the %s area, another signer", c.n, area), bad, openpgp.ErrBinding)
			}
		}
	}
	// The subpackets that the page names, with 28 others of one more type, are 32 and are read.
}

// A fault of the signature, of the form of the packet or of its issuer is an ErrBinding, never an
// ErrBindingShape, and it is found whatever the subpackets are.
func TestAFaultOfTheSignatureTheFormOrTheIssuerIsABindingFault(t *testing.T) {
	k := newBindKit(t)
	good := k.build(t, nil)
	for typ := range 256 {
		if typ == 0x18 {
			continue
		}
		k.assertFault(t, fmt.Sprintf("the signature type %#02x", typ), k.build(t, func(sp *sigSpec) { sp.Type = byte(typ) }), openpgp.ErrBinding)
	}
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"SHA-256", func(sp *sigSpec) { sp.Hash = 8 }},
		{"SHA-512", func(sp *sigSpec) { sp.Hash = 10 }},
		{"a hash tag that is not the start of the digest (the signature is good)", func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 0} }},
		{"a hash tag with the second byte changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{0, 0x80} }},
		{"a hash tag with both bytes changed", func(sp *sigSpec) { sp.TagXOR = [2]byte{0xFF, 0xFF} }},
		{"a byte after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{0} }},
		{"three bytes after the two numbers", func(sp *sigSpec) { sp.Trailing = []byte{1, 2, 3} }},
		{"a second signature value after the two", func(sp *sigSpec) { sp.Trailing = mpi(big.NewInt(1)) }},
		{"a first number with a bit length one too long", func(sp *sigSpec) { sp.Numbers = badBits(1, 0) }},
		{"a first number with a bit length one too short", func(sp *sigSpec) { sp.Numbers = badBits(-1, 0) }},
		{"a second number with a bit length one too long", func(sp *sigSpec) { sp.Numbers = badBits(0, 1) }},
		{"a second number with a bit length one too short", func(sp *sigSpec) { sp.Numbers = badBits(0, -1) }},
		{"a number with a leading zero byte", func(sp *sigSpec) {
			sp.Numbers = func(r, s *big.Int) []byte {
				rb := append([]byte{0}, r.Bytes()...)
				return append(append([]byte{byte(r.BitLen() >> 8), byte(r.BitLen())}, rb...), mpi(s)...)
			}
		}},
		{"the first number of zero bits", func(sp *sigSpec) { sp.Numbers = func(_, s *big.Int) []byte { return append([]byte{0, 0}, mpi(s)...) } }},
		{"the second number missing", func(sp *sigSpec) { sp.Numbers = func(r, _ *big.Int) []byte { return mpi(r) } }},
		{"both numbers missing", func(sp *sigSpec) { sp.Numbers = func(_, _ *big.Int) []byte { return nil } }},
		{"the numbers swapped", func(sp *sigSpec) { sp.Numbers = func(r, s *big.Int) []byte { return append(mpi(s), mpi(r)...) } }},
		{"a first number of 1", func(sp *sigSpec) {
			sp.Numbers = func(_, s *big.Int) []byte { return append(mpi(big.NewInt(1)), mpi(s)...) }
		}},
		{"both numbers of 1", func(sp *sigSpec) {
			sp.Numbers = func(_, _ *big.Int) []byte { return append(mpi(big.NewInt(1)), mpi(big.NewInt(1))...) }
		}},
		{"a second number as big as the curve order", func(sp *sigSpec) {
			sp.Numbers = func(r, _ *big.Int) []byte {
				n := new(big.Int).Lsh(big.NewInt(1), 384)
				return append(mpi(r), mpi(n)...)
			}
		}},
	} {
		k.assertFault(t, c.name, k.build(t, c.tweak), openpgp.ErrBinding)
	}
	// A signature that names another algorithm or another hash than the page's, and that was made over
	// the SHA-384 digest of those same fields: it verifies under the digest that the reader computes,
	// and a program that reads what it says computes another one. Control: the page's own values.
	if _, err := k.verify(k.buildClaiming(t, 19, 9)); err != nil {
		t.Fatalf("the control of the claims: %v", err)
	}
	for algo := range 256 {
		for _, hash := range []byte{9, 8, 10} {
			if algo == 19 && hash == 9 {
				continue
			}
			k.assertFault(t, fmt.Sprintf("a signature that names algorithm %d and hash %d, made over a SHA-384 digest", algo, hash),
				k.buildClaiming(t, byte(algo), hash), openpgp.ErrBinding)
		}
	}
	for hash := range 256 {
		if hash != 9 {
			k.assertFault(t, fmt.Sprintf("a signature that names hash %d, made over a SHA-384 digest", hash), k.buildClaiming(t, 19, byte(hash)), openpgp.ErrBinding)
		}
	}
	// Fields that the signature covers are changed after it was made: version, algorithm, hash.
	for _, c := range []struct {
		name string
		at   int
		val  byte
	}{
		{"version 3", 0, 3}, {"version 5", 0, 5}, {"version 6", 0, 6}, {"version 0", 0, 0}, {"version 0x84", 0, 0x84},
		{"type 0x19", 1, 0x19}, {"type 0x13", 1, 0x13}, {"type 0x1F", 1, 0x1F},
		{"algorithm 1 (RSA)", 2, 1}, {"algorithm 18 (ECDH)", 2, 18}, {"algorithm 22 (EdDSA)", 2, 22}, {"algorithm 0", 2, 0},
		{"hash 8", 3, 8}, {"hash 10", 3, 10}, {"hash 2 (SHA-1)", 3, 2}, {"hash 0", 3, 0},
	} {
		body := bodyOf(t, good)
		body[c.at] = c.val
		k.assertFault(t, c.name, withBody(body), openpgp.ErrBinding)
	}
	// The lengths of the two areas, which run past the packet or cut a subpacket.
	body := bodyOf(t, good)
	l := layoutOf(body)
	setHashed := func(n int) []byte {
		b := bytes.Clone(body)
		binary.BigEndian.PutUint16(b[4:], uint16(n))
		return withBody(b)
	}
	setUnhashed := func(n int) []byte {
		b := bytes.Clone(body)
		binary.BigEndian.PutUint16(b[6+l.hashedLen:], uint16(n))
		return withBody(b)
	}
	for _, n := range []int{0, 1, l.hashedLen - 1, l.hashedLen + 1, l.hashedLen + 2, l.hashedLen + 100, len(body), 0xFFFF} {
		if n == l.hashedLen {
			continue
		}
		k.assertFault(t, fmt.Sprintf("a hashed area of %d bytes in place of %d", n, l.hashedLen), setHashed(n), openpgp.ErrBinding)
	}
	for _, n := range []int{0, 1, l.unhashedLen - 1, l.unhashedLen + 1, l.unhashedLen + 2, l.unhashedLen + 100, len(body), 0xFFFF} {
		if n == l.unhashedLen {
			continue
		}
		k.assertFault(t, fmt.Sprintf("an unhashed area of %d bytes in place of %d", n, l.unhashedLen), setUnhashed(n), openpgp.ErrBinding)
	}
}

// badBits writes the two numbers of the signature with a wrong bit length: the bytes are the
// signature's, the length that comes before them is changed by dr and ds.
func badBits(dr, ds int) func(r, s *big.Int) []byte {
	return func(r, s *big.Int) []byte {
		enc := func(v *big.Int, d int) []byte {
			bits := v.BitLen() + d
			return append([]byte{byte(bits >> 8), byte(bits)}, v.Bytes()...)
		}
		return append(enc(r, dr), enc(s, ds)...)
	}
}

func TestAFaultOfTheIssuerFingerprintIsABindingFault(t *testing.T) {
	k := newBindKit(t)
	other := newBindKit(t)
	fp := append([]byte{4}, k.fp...)
	flip := func(i int) func(*sigSpec) {
		return func(sp *sigSpec) { sp.Hashed[3].Data[i] ^= 0x01 }
	}
	cases := []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"the issuer fingerprint of another key", func(sp *sigSpec) { sp.Hashed[3].Data = append([]byte{4}, other.fp...) }},
		{"the fingerprint of the subkey", func(sp *sigSpec) { sp.Hashed[3].Data = append([]byte{4}, fingerprint(&k.sub.Key.PublicKey, subAt)...) }},
		{"no issuer fingerprint", func(sp *sigSpec) { sp.Hashed = sp.Hashed[:3] }},
		{"two issuer fingerprints, both the primary's", func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sp.Hashed[3]) }},
		{"two issuer fingerprints, the second another key's", func(sp *sigSpec) {
			sp.Hashed = append(sp.Hashed, sub{Type: 33, Data: append([]byte{4}, other.fp...)})
		}},
		{"two issuer fingerprints, the first another key's", func(sp *sigSpec) {
			sp.Hashed = append([]sub{{Type: 33, Data: append([]byte{4}, other.fp...)}}, sp.Hashed...)
		}},
		{"version 5 in place of the version byte", func(sp *sigSpec) { sp.Hashed[3].Data[0] = 5 }},
		{"version 3 in place of the version byte", func(sp *sigSpec) { sp.Hashed[3].Data[0] = 3 }},
		{"version 0 in place of the version byte", func(sp *sigSpec) { sp.Hashed[3].Data[0] = 0 }},
		{"a version 5 fingerprint of 33 bytes", func(sp *sigSpec) { sp.Hashed[3].Data = append([]byte{5}, make([]byte, 32)...) }},
		{"no version byte", func(sp *sigSpec) { sp.Hashed[3].Data = fp[1:] }},
		{"20 bytes", func(sp *sigSpec) { sp.Hashed[3].Data = fp[:20] }},
		{"22 bytes", func(sp *sigSpec) { sp.Hashed[3].Data = append(bytes.Clone(fp), 0) }},
		{"an empty fingerprint", func(sp *sigSpec) { sp.Hashed[3].Data = nil }},
		{"the fingerprint in the unhashed area, not in the hashed", func(sp *sigSpec) {
			sp.Unhashed = append(sp.Unhashed, sp.Hashed[3])
			sp.Hashed = sp.Hashed[:3]
		}},
	}
	for i := 0; i < len(fp); i++ {
		cases = append(cases, struct {
			name  string
			tweak func(*sigSpec)
		}{fmt.Sprintf("byte %d of the fingerprint with one bit changed", i), flip(i)})
	}
	for _, c := range cases {
		// The signature is by the right primary and verifies, so the fault is the issuer's alone,
		// and the faults of the shape that some of the rows also have are not what is found first.
		k.assertFault(t, c.name, k.build(t, c.tweak), openpgp.ErrBinding)
	}
}

// The order of the checks: a fault of the signature is found before a fault of the subpackets, so
// that ErrBindingShape says "the primary is right".
func TestAShapeFaultIsOnlyReportedForASignatureThatVerified(t *testing.T) {
	k := newBindKit(t)
	other := newBindKit(t)
	shapes := map[string]func(*sigSpec){
		"an extra subpacket":       func(sp *sigSpec) { sp.Hashed = append(sp.Hashed, sub{Type: 100, Data: []byte{1}}) },
		"key flags of 0x03":        func(sp *sigSpec) { sp.Hashed[1].Data = []byte{0x03} },
		"no embedded signature":    func(sp *sigSpec) { sp.Unhashed = sp.Unhashed[:1] },
		"a key expiration of zero": func(sp *sigSpec) { sp.Hashed[2].Data = u32(0) },
		"another key ID":           func(sp *sigSpec) { sp.Unhashed[0].Data = other.fp[12:] },
	}
	for name, shape := range shapes {
		k.assertFault(t, name+", signature good", k.build(t, shape), openpgp.ErrBindingShape)
		k.assertFault(t, name+", signed by another key", k.build(t, func(sp *sigSpec) { shape(sp); sp.Key = other.key }), openpgp.ErrBinding)
		k.assertFault(t, name+", issuer of another key", k.build(t, func(sp *sigSpec) {
			shape(sp)
			sp.Hashed[3].Data = append([]byte{4}, other.fp...)
		}), openpgp.ErrBinding)
		k.assertFault(t, name+", hash tag wrong", k.build(t, func(sp *sigSpec) { shape(sp); sp.TagXOR = [2]byte{0, 1} }), openpgp.ErrBinding)
		k.assertFault(t, name+", a byte after the numbers", k.build(t, func(sp *sigSpec) { shape(sp); sp.Trailing = []byte{0} }), openpgp.ErrBinding)
		k.assertFault(t, name+", type 0x19", k.build(t, func(sp *sigSpec) { shape(sp); sp.Type = 0x19 }), openpgp.ErrBinding)
		// One bit of the number s: the same shape fault now has a signature that does not verify.
		pkt := k.build(t, shape)
		pkt[len(pkt)-1] ^= 1
		k.assertFault(t, name+", s damaged", pkt, openpgp.ErrBinding)
		pkt = k.build(t, shape)
		pkt[layoutOf(bodyOf(t, pkt)).rs+len(pkt)-len(bodyOf(t, pkt))+3] ^= 0x10
		k.assertFault(t, name+", r damaged", pkt, openpgp.ErrBinding)
	}
}

// Every bit of the binding, one at a time. A bit of the signed fields, of the hash tag or of the two
// numbers is a binding fault. The unhashed area is not covered by the signature, so a bit there is
// found by its meaning: a bit of the issuer key ID, of a type or of a critical bit is a shape fault,
// and a bit that changes a length is a form fault or a shape fault. The one thing that the reader
// does not see is a bit inside the embedded signature, which the caller compares with Embeds: those
// bindings are read, and none of them embeds the request's back-signature any more.
func TestEveryBitOfABindingIsFoundByTheReaderOrBytheComparisonOfTheEmbeddedSignature(t *testing.T) {
	k := newBindKit(t)
	pkt := k.build(t, nil)
	body := bodyOf(t, pkt)
	l := layoutOf(body)
	headerLen := len(pkt) - len(body)
	// The embedded signature subpacket is the second of the unhashed area: its data starts after the
	// key ID subpacket (10 bytes), a two-byte length and the type.
	embLen := len(k.sub.BackBody)
	embAt := bytes.Index(body[l.unhashedAt:], k.sub.BackBody) + l.unhashedAt
	if embAt < l.unhashedAt+idSubpacketLen || embAt+embLen != l.tagAt {
		t.Fatal("the test does not find the embedded signature at the end of the unhashed area")
	}
	accepted := 0
	for bit := 0; bit < 8*len(pkt); bit++ {
		changed := bytes.Clone(pkt)
		changed[bit/8] ^= 1 << (bit % 8)
		at := bit/8 - headerLen // the byte of the body, negative for the header
		what := fmt.Sprintf("bit %d (byte %d of the body)", bit, at)
		b, err := k.verifySafely(t, what, changed)
		switch {
		case err == nil && at >= embAt && at < embAt+embLen:
			accepted++
			if b == nil || b.Embeds(k.sub.BackSig) {
				t.Errorf("%s: a changed embedded signature is still the request's back-signature", what)
			}
		case err == nil:
			t.Errorf("%s: a changed binding was accepted", what)
		case at < 0:
			assertFaultResult(t, what, b, err, openpgp.ErrBinding) // the header of the packet
		case at < l.unhashedAt-2: // the fields, which the signature covers
			assertFaultResult(t, what, b, err, openpgp.ErrBinding)
		case at >= l.tagAt: // the hash tag and the two numbers
			assertFaultResult(t, what, b, err, openpgp.ErrBinding)
		default: // the length of the unhashed area and the area itself
			if b != nil || (!isKind(err, openpgp.ErrBinding) && !isKind(err, openpgp.ErrBindingShape)) {
				t.Errorf("%s: VerifyBinding = %v, %v; want a binding fault or a shape fault", what, b, err)
			}
		}
	}
	if accepted != 8*embLen {
		t.Errorf("%d single-bit changes inside the embedded signature were accepted, want all %d", accepted, 8*embLen)
	}
}

func isKind(err, kind error) bool { return err != nil && errors.Is(err, kind) }

// Every prefix of a binding, whole or cut in its body, is refused, and so is every binding with
// bytes after it.
func TestACutBindingOrOneWithBytesAfterItIsRefused(t *testing.T) {
	k := newBindKit(t)
	pkt := k.build(t, nil)
	body := bodyOf(t, pkt)
	for n := 0; n < len(pkt); n++ {
		k.assertFault(t, fmt.Sprintf("the first %d bytes of the packet", n), pkt[:n], openpgp.ErrBinding)
	}
	for n := 0; n < len(body); n++ {
		k.assertFault(t, fmt.Sprintf("a packet whose body is cut after %d bytes", n), withBody(body[:n]), openpgp.ErrBinding)
	}
	for _, extra := range [][]byte{{0}, {0xC2}, {1, 2, 3, 4}, pkt, make([]byte, 100)} {
		k.assertFault(t, fmt.Sprintf("%d bytes after the packet", len(extra)), append(bytes.Clone(pkt), extra...), openpgp.ErrBinding)
	}
	for _, extra := range [][]byte{{0}, {1, 2, 3, 4}, make([]byte, 100)} {
		k.assertFault(t, fmt.Sprintf("%d bytes after the two numbers, inside the packet", len(extra)), withBody(append(bytes.Clone(body), extra...)), openpgp.ErrBinding)
	}
}

func TestAnotherPacketIsNotABinding(t *testing.T) {
	k := newBindKit(t)
	pkt := k.build(t, nil)
	body := bodyOf(t, pkt)
	for tag := byte(0); tag < 64; tag++ {
		if tag == tagSignature {
			continue
		}
		k.assertFault(t, fmt.Sprintf("the body of the binding in a packet of tag %d", tag), wrap(tag, body), openpgp.ErrBinding)
	}
	both := append(bytes.Clone(k.sub.Packet), pkt...)
	k.assertFault(t, "the whole bound file", both, openpgp.ErrBinding)
	k.assertFault(t, "two bindings", append(bytes.Clone(pkt), pkt...), openpgp.ErrBinding)
	k.assertFault(t, "the body without a header", body, openpgp.ErrBinding)
	k.assertFault(t, "a partial length", append([]byte{0xC2, 0xE0}, body...), openpgp.ErrBinding)
	for _, first := range []byte{0xE0, 0xE1, 0xF0, 0xFE} {
		partial := append(append([]byte{0xC2, first}, u32(uint32(len(body)))...), body...)
		k.assertFault(t, fmt.Sprintf("a partial length of %d followed by a five-byte length", first), partial, openpgp.ErrBinding)
	}
	k.assertFault(t, "an indeterminate length", append([]byte{0x80 | tagSignature<<2 | 3}, body...), openpgp.ErrBinding)
	k.assertFault(t, "a header with the top bit not set", append([]byte{0x42, byte(len(body))}, body...), openpgp.ErrBinding)
	big := make([]byte, maxBoundFile+1)
	copy(big, pkt)
	k.assertFault(t, "a packet of 256 KiB and one byte of zeros", big, openpgp.ErrBinding)
}

// A subpacket with a length that is zero or that runs past its area is a form fault, in either area.
func TestASubpacketWhoseLengthIsZeroOrRunsPastItsAreaIsAFormFault(t *testing.T) {
	k := newBindKit(t)
	base := k.spec()
	hashed := encodeSubs(base.Hashed)
	unhashed := encodeSubs(base.Unhashed)
	fields := func(h []byte) []byte {
		f := []byte{4, 0x18, 19, 9, byte(len(h) >> 8), byte(len(h))}
		return append(f, h...)
	}
	// The signature does not verify for these, which is the point: a form fault is found first,
	// and it is the same fault.
	build := func(h, u []byte) []byte {
		body := fields(h)
		body = append(body, byte(len(u)>>8), byte(len(u)))
		body = append(body, u...)
		body = append(body, 0xAA, 0xBB)
		body = append(body, mpi(big.NewInt(12345))...)
		body = append(body, mpi(big.NewInt(54321))...)
		return withBody(body)
	}
	for name, c := range map[string][2][]byte{
		"a zero length in the hashed area":                      {append([]byte{0}, hashed...), unhashed},
		"a zero length at the end of the hashed area":           {append(bytes.Clone(hashed), 0), unhashed},
		"a length past the end in the hashed area":              {append(bytes.Clone(hashed), 5, 2, 1), unhashed},
		"the last subpacket of the hashed area cut by a byte":   {hashed[:len(hashed)-1], unhashed},
		"a zero length in the unhashed area":                    {hashed, append([]byte{0}, unhashed...)},
		"a zero length at the end of the unhashed area":         {hashed, append(bytes.Clone(unhashed), 0)},
		"a length past the end in the unhashed area":            {hashed, append(bytes.Clone(unhashed), 5, 2, 1)},
		"the last subpacket of the unhashed area cut by a byte": {hashed, unhashed[:len(unhashed)-1]},
		"a two-byte length with its second byte missing":        {append(bytes.Clone(hashed), 200), unhashed},
		"a five-byte length with its last byte missing":         {hashed, append(bytes.Clone(unhashed), 0xFF, 0, 0, 0)},
		"a five-byte length of zero":                            {hashed, append(bytes.Clone(unhashed), 0xFF, 0, 0, 0, 0)},
		"a five-byte length of 2^32 - 1":                        {hashed, append(bytes.Clone(unhashed), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2)},
	} {
		k.assertFault(t, name, build(c[0], c[1]), openpgp.ErrBinding)
	}
}
