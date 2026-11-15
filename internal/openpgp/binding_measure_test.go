package openpgp_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// The two limits of a binding that the reader holds as the writer does: the unhashed area is
// measured by the bytes it is written in (the limit gpgv reads), and the end of the subkey is a time
// that a time field holds (the year 2106). The unhashed area is not covered by the signature, so any
// hand can write its two subpackets in any length form of the standard, and in either order.

// writeUnhashed is the packet of pkt with its unhashed area written anew: the issuer key ID and the
// embedded signature, each with the five-byte length form or with the shortest one, in the order
// asked. The signature does not cover the area, so it still verifies.
func writeUnhashed(t testing.TB, pkt []byte, idLong, embLong, embFirst bool, embedded []byte) []byte {
	t.Helper()
	body := bodyOf(t, pkt)
	l := layoutOf(body)
	id := sub{Type: 16, Data: bytes.Clone(body[l.unhashedAt+2 : l.unhashedAt+10])}
	// The key ID is the first subpacket of the page's binding: one byte of length, one of type.
	if body[l.unhashedAt] != 9 || body[l.unhashedAt+1] != 16 {
		t.Fatalf("the first unhashed subpacket is % x, want the issuer key ID", body[l.unhashedAt:l.unhashedAt+2])
	}
	enc := func(s sub, long bool) []byte {
		if long {
			return encodeSubLong(s)
		}
		return encodeSub(s)
	}
	idB, embB := enc(id, idLong), enc(sub{Type: 32, Data: embedded}, embLong)
	area := append(bytes.Clone(idB), embB...)
	if embFirst {
		area = append(bytes.Clone(embB), idB...)
	}
	out := bytes.Clone(body[:l.unhashedAt-2])
	out = append(out, byte(len(area)>>8), byte(len(area)))
	out = append(out, area...)
	out = append(out, body[l.tagAt:]...)
	return withBody(out)
}

// A mix of length forms and an order of the two subpackets: the area is as long as it is written.
func TestTheUnhashedAreaOfAnyMixOfLengthFormsAndOrderIsMeasuredAsWritten(t *testing.T) {
	k := newBindKit(t)
	base := k.build(t, nil)
	for _, idLong := range []bool{false, true} {
		for _, embLong := range []bool{false, true} {
			for _, embFirst := range []bool{false, true} {
				for _, area := range []int{600, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10009, 12000} {
					// The key ID: length, type and 8 bytes. The embedded signature: the length in two bytes
					// (the shortest form up to 16319 bytes) or in five, and the type.
					idLen, embHead := 10, 3
					if idLong {
						idLen = 14
					}
					if embLong {
						embHead = 6
					}
					n := area - idLen - embHead
					if n < 1 {
						continue
					}
					body := bytes.Repeat([]byte{0xCD}, n)
					what := fmt.Sprintf("an unhashed area of %d bytes (key ID long %v, embedded long %v, embedded first %v)", area, idLong, embLong, embFirst)
					pkt := writeUnhashed(t, base, idLong, embLong, embFirst, body)
					if got := layoutOf(bodyOf(t, pkt)).unhashedLen; got != area {
						t.Fatalf("%s: the test wrote %d bytes", what, got)
					}
					if area <= 10000 {
						b := k.assertAccepted(t, what, pkt)
						if b != nil && !b.Embeds(wrap(tagSignature, body)) {
							t.Errorf("%s: the embedded signature is not the one written", what)
						}
					} else {
						k.assertFault(t, what, pkt, openpgp.ErrBindingShape)
					}
				}
			}
		}
	}
}

// An area that is 10000 bytes or less in its shortest form and more as it is written is refused: the
// old measure took the shortest form.
func TestAnAreaOfTenThousandBytesInTheShortestFormAndMoreAsWrittenIsRefused(t *testing.T) {
	k := newBindKit(t)
	base := k.build(t, nil)
	body := bytes.Repeat([]byte{0xCD}, 10000-10-3) // 10000 bytes with the shortest forms
	short := writeUnhashed(t, base, false, false, false, body)
	if got := layoutOf(bodyOf(t, short)).unhashedLen; got != 10000 {
		t.Fatalf("the test wrote %d bytes, want 10000", got)
	}
	k.assertAccepted(t, "10000 bytes in the shortest forms", short)
	for _, c := range []struct {
		name                string
		idLong, embLong     bool
		wantArea            int
		embFirst, wantAllow bool
	}{
		{"the key ID in the five-byte form", true, false, 10004, false, false},
		{"the key ID in the five-byte form, the embedded signature first", true, false, 10004, true, false},
		{"both in the five-byte form", true, true, 10007, false, false},
		{"the embedded signature in the five-byte form", false, true, 10003, false, false},
		{"the embedded signature in the five-byte form, first", false, true, 10003, true, false},
		{"the two in the shortest forms, the embedded signature first", false, false, 10000, true, true},
	} {
		pkt := writeUnhashed(t, base, c.idLong, c.embLong, c.embFirst, body)
		if got := layoutOf(bodyOf(t, pkt)).unhashedLen; got != c.wantArea {
			t.Fatalf("%s: the test wrote %d bytes, want %d", c.name, got, c.wantArea)
		}
		if c.wantAllow {
			k.assertAccepted(t, c.name, pkt)
		} else {
			k.assertFault(t, c.name, pkt, openpgp.ErrBindingShape)
		}
	}
}

// The limit is judged after the signature: an area that is too long under a signature that does not
// verify, or by another signer, is an ErrBinding. The length of the area never makes a fault of the
// shape out of a fault of the signature.
func TestAnAreaThatIsTooLongUnderABadSignatureIsABindingFault(t *testing.T) {
	k := newBindKit(t)
	for _, c := range []struct {
		name  string
		tweak func(*sigSpec)
	}{
		{"another signer", func(sp *sigSpec) { sp.Key = genKey(t) }},
		{"a changed hash tag", func(sp *sigSpec) { sp.TagXOR = [2]byte{1, 0} }},
		{"a byte after the numbers", func(sp *sigSpec) { sp.Trailing = []byte{0} }},
	} {
		pkt := k.build(t, func(sp *sigSpec) {
			c.tweak(sp)
			sp.LongLengths = true
			sp.Unhashed[1].Data = bytes.Repeat([]byte{0xAB}, 10100)
		})
		k.assertFault(t, "a long area, "+c.name, pkt, openpgp.ErrBinding)
	}
}

// subkeyCreatedAt is a kit whose subkey was created at the given second. The embedded signature is
// not read by VerifyBinding, so the one of the kit stands in.
func subkeyCreatedAt(t testing.TB, k bindKit, at time.Time) (*openpgp.Subkey, sigSpec) {
	t.Helper()
	sk, err := openpgp.ReadSubkey(wrap(tagSubkey, keyBody(&k.sub.Key.PublicKey, at)))
	if err != nil {
		t.Fatalf("ReadSubkey at %v: %v", at, err)
	}
	sp := k.spec()
	sp.Data = [][]byte{hashPrefix(&k.key.PublicKey, created), hashPrefix(&k.sub.Key.PublicKey, at)}
	return sk, sp
}

// The end is the creation time of the subkey plus the key expiration time, and at most the last
// second of a time field, whenever the subkey was made.
func TestTheEndOfTheSubkeyIsAtMostTheLastSecondOfATimeFieldWhateverItsCreationTime(t *testing.T) {
	k := newBindKit(t)
	for _, made := range []int64{1, 86400, 1 << 30, 1 << 31, 1<<31 + 12345, 1767225600, 4102444800, lastSecond - 86400, lastSecond - 1} {
		at := time.Unix(made, 0).UTC()
		sk, spec := subkeyCreatedAt(t, k, at)
		maxLife := uint64(lastSecond - made)
		for _, c := range []struct {
			name string
			life uint64
			ok   bool
		}{
			{"one second", 1, true},
			{"one second before the last second", maxLife - 1, maxLife > 1},
			{"the last second", maxLife, true},
			{"one second after it", maxLife + 1, false},
			{"a sum that wraps a 32-bit time to a second", 1<<32 - uint64(made) + 5, false},
			{"the longest key expiration", 0xFFFFFFFF, maxLife >= 0xFFFFFFFF},
		} {
			if c.life < 1 || c.life > 0xFFFFFFFF {
				continue
			}
			what := fmt.Sprintf("a subkey made at %d with a key expiration of %d seconds (%s)", made, c.life, c.name)
			sp := spec
			sp.Hashed = append([]sub(nil), spec.Hashed...)
			sp.Hashed[2].Data = u32(uint32(c.life))
			pkt := sp.build(t)
			b, err := openpgp.VerifyBinding(pkt, k.primary, sk)
			if c.ok {
				if err != nil || b == nil {
					t.Errorf("%s: %v", what, err)
					continue
				}
				if want := made + int64(c.life); b.Ends().Unix() != want || b.Ends().Location() != time.UTC {
					t.Errorf("%s: Ends = %v, want %d in UTC", what, b.Ends(), want)
				}
				if b.Ends().Unix() > lastSecond || b.Ends().Year() > 2106 {
					t.Errorf("%s: Ends = %v is after the last second of a time field", what, b.Ends())
				}
				continue
			}
			assertFaultResult(t, what, b, err, openpgp.ErrBindingShape)
			if errors.Is(err, openpgp.ErrBinding) {
				t.Errorf("%s: a fault of the shape is not a fault of the binding: %v", what, err)
			}
		}
	}
}

// The last second itself: the end is the 7th of February 2106 at 06:28:15 UTC, in UTC.
func TestTheLastSecondOfATimeFieldIsAnEndThatIsRead(t *testing.T) {
	k := newBindKit(t)
	b := k.assertAccepted(t, "an end at the last second", k.build(t, func(sp *sigSpec) { sp.Hashed[2].Data = u32(uint32(lastSecond - subAt.Unix())) }))
	if b == nil {
		return
	}
	if want := time.Date(2106, 2, 7, 6, 28, 15, 0, time.UTC); !b.Ends().Equal(want) || b.Ends().Location() != time.UTC {
		t.Errorf("Ends = %v, want %v", b.Ends(), want)
	}
}

// The end is judged after the signature too: a key expiration past the limit under another signer or
// a changed hash tag is an ErrBinding, and one past the limit under a good signature is a shape fault.
func TestAnEndPastTheLimitIsAShapeFaultOnlyUnderAGoodSignature(t *testing.T) {
	k := newBindKit(t)
	past := func(sp *sigSpec) { sp.Hashed[2].Data = u32(0xFFFFFFFF) }
	k.assertFault(t, "an end past the limit, good signature", k.build(t, past), openpgp.ErrBindingShape)
	k.assertFault(t, "an end past the limit, another signer", k.build(t, func(sp *sigSpec) { past(sp); sp.Key = genKey(t) }), openpgp.ErrBinding)
	k.assertFault(t, "an end past the limit, changed hash tag", k.build(t, func(sp *sigSpec) { past(sp); sp.TagXOR = [2]byte{0, 1} }), openpgp.ErrBinding)
}
