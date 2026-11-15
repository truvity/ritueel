package openpgp_test

import (
	"bytes"
	"fmt"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// Places where the reader holds the limits of the builder and of the tools: the unhashed area is
// measured as it is written, and the end of a subkey is a time that a time field holds.

// The same limit in the longer forms of the length that the standard allows. A binding with a
// five-byte length on the subpackets of its unhashed area is as long as it is written, and gpgv
// reads it by that length. The unhashed area is not covered by the signature, so any hand can write
// it in this form.
func TestTheUnhashedAreaIsMeasuredAsItIsWrittenAndNotAsItWouldBeInTheShortestForm(t *testing.T) {
	k := newBindKit(t)
	for _, c := range []struct {
		area int // the bytes of the unhashed area as written, with five-byte lengths
		ok   bool
	}{{10000, true}, {10001, false}, {10002, false}, {10003, false}, {10010, false}, {12000, false}} {
		what := fmt.Sprintf("an unhashed area of %d bytes written with five-byte lengths", c.area)
		// Two subpackets with five-byte lengths: 6 + 8 bytes for the key ID, 6 + n for the embedded body.
		body := bytes.Repeat([]byte{0xAB}, c.area-14-6)
		pkt := k.build(t, func(sp *sigSpec) {
			sp.LongLengths = true
			sp.Unhashed[1].Data = body
		})
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

// A subkey ends at its creation time plus the key expiration time. BindSubkey refuses an end after
// the last second that a time field holds (the year 2106), and gpgv reads such a sum as a wrapped
// time and refuses the subkey (see TestGpgvReadsAnEndThatPassesTheTimeFieldAsAWrappedTime). The
// reader refuses an end that no writer makes.
func TestAnEndAfterTheLastSecondOfATimeFieldIsRefused(t *testing.T) {
	k := newBindKit(t)
	last := uint32(lastSecond - subAt.Unix()) // the longest life that ends within a time field
	for _, c := range []struct {
		name string
		life uint32
		ok   bool
	}{
		{"an end one second before the last second", last - 1, true},
		{"an end at the last second", last, true},
		{"an end one second after it", last + 1, false},
		{"an end a day after it", last + 86400, false},
		{"the longest key expiration", 0xFFFFFFFF, false},
		{"a key expiration of 0xC0000000", 0xC0000000, false},
	} {
		pkt := k.build(t, func(sp *sigSpec) { sp.Hashed[2].Data = u32(c.life) })
		if c.ok {
			k.assertAccepted(t, c.name, pkt)
		} else {
			k.assertFault(t, c.name, pkt, openpgp.ErrBindingShape)
		}
	}
}
