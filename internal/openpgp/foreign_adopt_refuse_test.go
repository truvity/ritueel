package openpgp_test

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The refusals of OpenSecretPacket that a damaged frame, a damaged field or a damaged checksum
// cause. Each case damages a good packet in one place, and the answer is the named error, no key,
// and a text that holds no run of a secret.

// alLen writes a packet length in the shortest form of RFC 9580, section 4.2.1.
func alLen(n int) []byte {
	switch {
	case n < 192:
		return []byte{byte(n)}
	case n < 8384:
		return []byte{byte((n-192)>>8) + 192, byte(n - 192)}
	}
	return []byte{0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// alHeaderLen is the length of the header of a good packet.
func alHeaderLen(pkt []byte) int {
	if pkt[1] < 192 {
		return 2
	}
	return 3
}

// alAccepted says that a packet reads, and clears the key.
func alAccepted(t testing.TB, what string, in []byte) bool {
	t.Helper()
	secret, _, err := openpgp.OpenSecretPacket(in)
	if err != nil {
		t.Errorf("%s: the packet is refused: %v", what, err)
		return false
	}
	secret.Wipe()
	return true
}

func TestOpenSecretPacketRefusesEveryTag(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, _ := alLone(t, b, false)
		body := pkt[alHeaderLen(pkt):]
		for tag := byte(0); tag < 64; tag++ {
			in := wrap(tag, body)
			what := fmt.Sprintf("tag %d", tag)
			switch tag {
			case 5:
				if !bytes.Equal(in, pkt) {
					t.Fatalf("the packet is not the good packet again")
				}
				alAccepted(t, what, in)
			case 6:
				alRefuses(t, what, b, in, nil, openpgp.ErrForeignNoSecret)
			case 7, 14:
				alRefuses(t, what, b, in, nil, openpgp.ErrForeignForm)
			default:
				alRefuses(t, what, b, in, nil, openpgp.ErrForeignPacket)
			}
		}
	})
}

func TestOpenSecretPacketRefusesEveryHeaderThatIsNotTheShortestOfTheNewFormat(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, _ := alLone(t, b, false)
		hl := alHeaderLen(pkt)
		body := pkt[hl:]
		n := len(body)
		form := openpgp.ErrForeignForm
		// the five-octet length of the new format, which is not the shortest below 8384
		five := append([]byte{0xC5, 0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, body...)
		alRefuses(t, "the five-octet length", b, five, nil, form)
		// the old format, each length type, and the indeterminate one; a header with no tag bit
		old := []struct {
			name string
			in   []byte
			want error
		}{
			{"old, length type 2", append([]byte{0x80 | 5<<2 | 2, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, body...), form},
			{"old, length type 1", append([]byte{0x80 | 5<<2 | 1, byte(n >> 8), byte(n)}, body...), form},
			{"old, indeterminate", append([]byte{0x80 | 5<<2 | 3}, body...), form},
			{"a header with no tag bit", append([]byte{0x40 | 5, byte(n)}, body...), form},
			{"old, a public key packet", append([]byte{0x80 | 6<<2 | 1, byte(n >> 8), byte(n)}, body...), openpgp.ErrForeignNoSecret},
			{"old, a subkey packet", append([]byte{0x80 | 7<<2 | 1, byte(n >> 8), byte(n)}, body...), form},
			{"old, a user ID packet", append([]byte{0x80 | 13<<2 | 1, byte(n >> 8), byte(n)}, body...), openpgp.ErrForeignPacket},
		}
		if n < 256 {
			old = append(old, struct {
				name string
				in   []byte
				want error
			}{"old, length type 0", append([]byte{0x80 | 5<<2, byte(n)}, body...), form})
		}
		for _, c := range old {
			alRefuses(t, c.name, b, c.in, nil, c.want)
		}
		// a partial length, the first octet of every value of the form
		for l := 224; l <= 254; l++ {
			alRefuses(t, fmt.Sprintf("partial length %d", l), b, append([]byte{0xC5, byte(l)}, body...), nil, form)
		}
		// a length that is one too long or one too short, in the shortest form
		alRefuses(t, "the length one too long", b, append(append([]byte{0xC5}, alLen(n+1)...), body...), nil, form)
		alRefuses(t, "the length one too short", b, append(append([]byte{0xC5}, alLen(n-1)...), body...), nil, form)
		alRefuses(t, "the length 0", b, append([]byte{0xC5, 0}, body...), nil, form)
		// the bytes of the length field, each changed
		for i := 1; i < hl; i++ {
			for _, d := range []byte{1, 0xFF} {
				in := bytes.Clone(pkt)
				in[i] += d
				alRefuses(t, fmt.Sprintf("length octet %d plus %d", i, d), b, in, nil, form)
			}
		}
	})
}

func TestOpenSecretPacketRefusesAPacketThatIsNotWhole(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, _ := alLone(t, b, false)
		form := openpgp.ErrForeignForm
		alRefuses(t, "nil", b, nil, nil, form)
		alRefuses(t, "empty", b, []byte{}, nil, form)
		// every prefix
		for k := 1; k < len(pkt); k++ {
			alRefuses(t, fmt.Sprintf("the first %d bytes", k), b, pkt[:k], nil, form)
		}
		// trailing bytes of any kind, and more packets
		for _, tail := range [][]byte{{0}, {0xFF}, {0xC5}, {'\n'}, {0, 0}, bytes.Repeat([]byte{0xC5, 0}, 3), pkt, wrap(6, pkt[alHeaderLen(pkt):]), wrap(2, []byte{4, 0, 0, 0}), wrap(13, []byte("a name"))} {
			in := append(bytes.Clone(pkt), tail...)
			kind := form
			if len(in) > openpgp.MaxAdoptedPacketBytes {
				kind = openpgp.ErrForeignLimit // two RSA-4096 packets are over the bound
			}
			alRefuses(t, fmt.Sprintf("%d trailing bytes", len(tail)), b, in, nil, kind)
		}
		// something before it
		alRefuses(t, "a byte in front", b, append([]byte{0}, pkt...), nil, form)
		alRefuses(t, "a marker packet in front", b, append(wrap(10, []byte("PGP")), pkt...), nil, form)
		alRefuses(t, "a packet that is not a packet", b, bytes.Repeat([]byte{0x01}, 200), nil, form)
		alRefuses(t, "text", b, []byte("this is not a key"), nil, form)
	})
}

func TestOpenSecretPacketHoldsItsSizeBoundExactly(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, _ := alLone(t, b, false)
		body := pkt[alHeaderLen(pkt):]
		max := openpgp.MaxAdoptedPacketBytes
		// a packet of exactly the bound is read by the packet reader as one packet, and refused for what it
		// holds, not for its size
		exact := wrap(5, append(bytes.Clone(body), make([]byte, max-3-len(body))...))
		if len(exact) != max {
			t.Fatalf("the test packet is %d bytes, want %d", len(exact), max)
		}
		err := alRefusal(t, "exactly the bound", b, exact, nil, openpgp.ErrForeignForm)
		if errors.Is(err, openpgp.ErrForeignLimit) {
			t.Errorf("a packet of exactly %d bytes is refused for its size: %v", max, err)
		}
		// one byte more is refused for its size, before anything is read
		over := wrap(5, append(bytes.Clone(body), make([]byte, max-2-len(body))...))
		if len(over) != max+1 {
			t.Fatalf("the test packet is %d bytes, want %d", len(over), max+1)
		}
		alRefuses(t, "one byte over the bound", b, over, nil, openpgp.ErrForeignLimit)
		// the good packet with one byte after it is not over the bound: it is more than one packet
		alRefuses(t, "the good packet and a byte", b, append(bytes.Clone(pkt), 0), nil, openpgp.ErrForeignForm)
		alRefuses(t, "far over the bound", b, make([]byte, 1<<20), nil, openpgp.ErrForeignLimit)
		// the good packet is under the bound, and so is the largest key that the reader takes
		if len(pkt) > max {
			t.Errorf("the good packet is %d bytes", len(pkt))
		}
	})
}

func TestOpenSecretPacketRefusesEveryVersionButFour(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, _ := alLone(t, b, false)
		hl := alHeaderLen(pkt)
		for v := 0; v < 256; v++ {
			if v == 4 {
				continue
			}
			in := bytes.Clone(pkt)
			in[hl] = byte(v)
			alRefuses(t, fmt.Sprintf("version %d", v), b, in, nil, openpgp.ErrForeignVersion)
		}
	})
}

func TestOpenSecretPacketRefusesEveryUsageButZero(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, p := alLone(t, b, false)
		at := alHeaderLen(pkt) + len(p.pubBody())
		for u := 1; u < 256; u++ {
			in := bytes.Clone(pkt)
			in[at] = byte(u)
			alRefuses(t, fmt.Sprintf("usage %d", u), b, in, nil, openpgp.ErrForeignProtection)
		}
		// usage 254 with a protected region that is a real one: the form of an export, not of a lone packet
		region := fkProtectRegion(t, bytes.Join(p.Sec, nil), fkPass, 9, crypto.SHA256, 8, 0x60)
		alRefuses(t, "a protected region", b, wrap(5, append(p.pubBody(), region...)), nil, openpgp.ErrForeignProtection)
	})
}

func TestOpenSecretPacketRefusesAChecksumThatIsNotTheSum(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, p := alLone(t, b, false)
		want := openpgp.ErrForeignSecret
		for _, i := range []int{len(pkt) - 2, len(pkt) - 1} {
			for bit := 0; bit < 8; bit++ {
				in := bytes.Clone(pkt)
				in[i] ^= 1 << bit
				alRefuses(t, fmt.Sprintf("checksum byte %d bit %d", len(pkt)-i, bit), b, in, nil, want)
			}
		}
		right := int(p.Sum)
		for name, sum := range map[string]int{"zero": 0, "all ones": 0xFFFF, "one more": right + 1, "one less": right - 1, "the bytes swapped": right&0xFF<<8 | right>>8} {
			if sum == right {
				continue
			}
			in := wrap(5, p.body(0, sum&0xFFFF))
			alRefuses(t, "the checksum "+name, b, in, nil, want)
		}
		// the sum is not that of the whole region: the same bytes with the checksum of the numbers of
		// another place
		var other uint16
		for _, c := range p.pubBody() {
			other += uint16(c)
		}
		if int(other) != right {
			alRefuses(t, "the sum of the public part", b, wrap(5, p.body(0, int(other))), nil, want)
		}
	})
}

func TestOpenSecretPacketRefusesEverySecretByteThatIsChanged(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, p := alLone(t, b, false)
		start := len(pkt) - 2 - len(bytes.Join(p.Sec, nil))
		for i := start; i < len(pkt)-2; i++ {
			in := bytes.Clone(pkt)
			in[i] ^= 1
			err := alRefusal(t, fmt.Sprintf("secret byte %d", i-start), b, in, nil)
			// a byte of a number is a checksum that does not hold; a byte of a bit count is a number that is
			// not in its form, and the checksum is judged after the form
			if err != nil && !errors.Is(err, openpgp.ErrForeignSecret) && !errors.Is(err, openpgp.ErrForeignForm) {
				t.Errorf("secret byte %d: %v is neither a secret nor a form that is refused", i-start, err)
			}
		}
	})
}

func TestOpenSecretPacketRefusesEveryNumberWhoseLengthIsOff(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, _, p := alLone(t, b, false)
		type spot struct {
			name  string
			piece func(q alPacket) []byte
		}
		var spots []spot
		switch p.alg() {
		case 1:
			spots = []spot{{"n", func(q alPacket) []byte { return q.Pub[0] }}, {"e", func(q alPacket) []byte { return q.Pub[1] }}}
			for i := range p.Sec {
				spots = append(spots, spot{fmt.Sprintf("secret number %d", i), func(q alPacket) []byte { return q.Sec[i] }})
			}
		default:
			spots = []spot{{"the point", func(q alPacket) []byte { return q.Pub[1] }}, {"the secret", func(q alPacket) []byte { return q.Sec[0] }}}
		}
		for _, s := range spots {
			for _, d := range []int{1, -1, 8, -8, 16, -16} {
				q := p.clone()
				piece := s.piece(q)
				count := int(piece[0])<<8 | int(piece[1])
				count += d
				if count <= 0 || count > 0xFFFF {
					continue
				}
				piece[0], piece[1] = byte(count>>8), byte(count)
				// the checksum is made again, so that only the form of the number can refuse it
				alRefuses(t, fmt.Sprintf("%s with its length %+d bits", s.name, d), b, q.packet(), nil)
			}
		}
		// a number with a leading zero byte, its length field right for the bytes
		for i := range p.Sec {
			q := p.clone()
			v := append([]byte{0}, p.values()[i]...)
			bitsLen := (len(v)-1)*8 + 8
			q.Sec[i] = append([]byte{byte(bitsLen >> 8), byte(bitsLen)}, v...)
			alRefuses(t, fmt.Sprintf("secret number %d with a leading zero byte", i), b, q.packet(), nil)
		}
	})
}

func TestOpenSecretPacketRefusesAPublicPartThatIsChangedInAnyByte(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		_, pkt, p := alLone(t, b, false)
		hl := alHeaderLen(pkt)
		pub := len(p.pubBody())
		step := 1
		if b.name == "rsa4096" {
			step = 13
		}
		for i := 0; i < pub; i += step {
			if i >= 1 && i <= 4 {
				continue // the creation time is part of the key and not judged: another time is another key
			}
			in := bytes.Clone(pkt)
			in[hl+i] ^= 1
			alRefuses(t, fmt.Sprintf("public byte %d", i), b, in, nil)
		}
		// the first and the last bytes of each piece, whatever the step
		if b.name == "rsa4096" {
			for _, i := range []int{6, 7, 8, pub - 1, pub - 2, pub - 3, pub - 4} {
				in := bytes.Clone(pkt)
				in[hl+i] ^= 1
				alRefuses(t, fmt.Sprintf("public byte %d", i), b, in, nil)
			}
		}
		// the creation time is the one thing that may change: the key is another key, with another fingerprint
		in := bytes.Clone(pkt)
		in[hl+4] ^= 1
		secret, pub2, err := openpgp.OpenSecretPacket(in)
		if err != nil {
			t.Fatalf("another creation time: %v", err)
		}
		secret.Wipe()
		if pub2.Fingerprint == alFingerprint(p.pubBody()) || pub2.Fingerprint != alFingerprint(in[hl:hl+pub]) {
			t.Errorf("the fingerprint does not follow the creation time")
		}
	})
}
