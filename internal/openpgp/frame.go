package openpgp

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// Packet tags (RFC 9580, section 5) and signature types (section 5.2.1) that the builders use.
const (
	tagSignature = 2
	tagPublicKey = 6
	tagUserID    = 13
	tagSubkey    = 14

	sigPositiveCertification = 0x13
	sigSubkeyBinding         = 0x18
	sigPrimaryKeyBinding     = 0x19
	sigKeyRevocation         = 0x20

	algoECDSA  = 19 // ECDSA (RFC 9580, section 9.1)
	hashSHA384 = 9  // SHA-384 (section 9.5)
)

// Signature subpacket types (RFC 9580, section 5.2.3).
const (
	spCreationTime      = 2
	spSigExpiration     = 3
	spKeyExpiration     = 9
	spIssuerKeyID       = 16
	spKeyFlags          = 27
	spRevocationReason  = 29
	spEmbeddedSignature = 32
	spIssuerFingerprint = 33
)

// Key flags (RFC 9580, section 5.2.3.29).
const (
	flagCertify      = 0x01
	flagSign         = 0x02
	flagAuthenticate = 0x20
)

// errFrame is the cause of every error of the packet framing below.
var errFrame = errors.New("malformed packet")

// header writes the new-format header of a packet (RFC 9580, section 4.2) with the shortest length.
func header(tag byte, n int) []byte {
	h := []byte{0xC0 | tag}
	switch {
	case n < 192:
		h = append(h, byte(n))
	case n < 8384:
		n -= 192
		h = append(h, byte(n>>8)+192, byte(n))
	default:
		h = append(h, 0xFF, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return h
}

// wrap is header plus body.
func wrap(tag byte, body []byte) []byte {
	out := header(tag, len(body))
	return append(out, body...)
}

// splitPacket reads the first packet of b. It returns the tag, the body and the rest. It reads
// the old format and the new format, and refuses a partial or an indeterminate length: a packet
// of the profile has a fixed length.
func splitPacket(b []byte) (tag byte, body, rest []byte, err error) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return 0, nil, nil, errFrame
	}
	var start, n int
	if b[0]&0x40 != 0 {
		tag = b[0] & 0x3F
		switch l := int(b[1]); {
		case l < 192:
			start, n = 2, l
		case l < 224:
			if len(b) < 3 {
				return 0, nil, nil, errFrame
			}
			start, n = 3, (l-192)<<8+int(b[2])+192
		case l == 255:
			if len(b) < 6 {
				return 0, nil, nil, errFrame
			}
			start, n = 6, int(binary.BigEndian.Uint32(b[2:6]))
		default:
			return 0, nil, nil, errFrame
		}
	} else {
		tag = (b[0] >> 2) & 0x0F
		switch b[0] & 3 {
		case 0:
			start, n = 2, int(b[1])
		case 1:
			if len(b) < 3 {
				return 0, nil, nil, errFrame
			}
			start, n = 3, int(binary.BigEndian.Uint16(b[1:3]))
		case 2:
			if len(b) < 5 {
				return 0, nil, nil, errFrame
			}
			start, n = 5, int(binary.BigEndian.Uint32(b[1:5]))
		default:
			return 0, nil, nil, errFrame
		}
	}
	if n < 0 || start+n > len(b) || start+n < start {
		return 0, nil, nil, errFrame
	}
	return tag, b[start : start+n], b[start+n:], nil
}

// subpacket is one signature subpacket: its type, its critical bit and its contents.
type subpacket struct {
	typ      byte
	critical bool
	data     []byte
}

// encode writes a subpacket with its length (RFC 9580, section 5.2.3.7).
func (s subpacket) encode() []byte {
	n := len(s.data) + 1
	var out []byte
	switch {
	case n < 192:
		out = append(out, byte(n))
	case n < 16320:
		out = append(out, byte((n-192)>>8)+192, byte(n-192))
	default:
		out = append(out, 0xFF, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	t := s.typ
	if s.critical {
		t |= 0x80
	}
	out = append(out, t)
	return append(out, s.data...)
}

// encodeArea writes the subpackets one after the other, in the order given.
func encodeArea(subs []subpacket) []byte {
	var out []byte
	for _, s := range subs {
		out = append(out, s.encode()...)
	}
	return out
}

// parseArea reads a subpacket area. It refuses a length that leaves the area.
func parseArea(b []byte) ([]subpacket, error) {
	var out []subpacket
	for len(b) > 0 {
		var n, hl int
		switch l := int(b[0]); {
		case l < 192:
			n, hl = l, 1
		case l < 255:
			if len(b) < 2 {
				return nil, errFrame
			}
			n, hl = (l-192)<<8+int(b[1])+192, 2
		default:
			if len(b) < 5 {
				return nil, errFrame
			}
			n, hl = int(binary.BigEndian.Uint32(b[1:5])), 5
		}
		if n < 1 || hl+n > len(b) {
			return nil, errFrame
		}
		out = append(out, subpacket{typ: b[hl] & 0x7F, critical: b[hl]&0x80 != 0, data: b[hl+1 : hl+n]})
		b = b[hl+n:]
	}
	return out, nil
}

// sigAreas splits the body of a version 4 signature into its fixed fields, its hashed area and
// its unhashed area. The rest holds the hash tag and the signature values. The fields are the bytes
// from the version to the end of the hashed area, which a signature hashes before its trailer.
type sigAreas struct {
	sigType  byte
	algo     byte
	hash     byte
	fields   []byte
	hashed   []subpacket
	unhashed []subpacket
	rest     []byte
}

func splitSig(body []byte) (sigAreas, error) {
	var a sigAreas
	if len(body) < 6 || body[0] != 4 {
		return a, errFrame
	}
	a.sigType, a.algo, a.hash = body[1], body[2], body[3]
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	if len(body) < 6+hl+2 {
		return a, errFrame
	}
	a.fields = body[:6+hl]
	var err error
	if a.hashed, err = parseArea(body[6 : 6+hl]); err != nil {
		return a, err
	}
	ul := int(binary.BigEndian.Uint16(body[6+hl : 8+hl]))
	if len(body) < 8+hl+ul {
		return a, errFrame
	}
	if a.unhashed, err = parseArea(body[8+hl : 8+hl+ul]); err != nil {
		return a, err
	}
	a.rest = body[8+hl+ul:]
	return a, nil
}

// count is the number of subpackets of a type.
func count(subs []subpacket, typ byte) int {
	n := 0
	for _, s := range subs {
		if s.typ == typ {
			n++
		}
	}
	return n
}

// find returns the data of the one subpacket of a type, and false when there is none or several.
func find(subs []subpacket, typ byte) ([]byte, bool) {
	var out []byte
	for _, s := range subs {
		if s.typ == typ {
			out = s.data
		}
	}
	return out, count(subs, typ) == 1
}

// readMPI reads one multiprecision integer in the form that [mpi] writes: a bit length of at least
// 1, then the bytes of the number with no leading zero. It returns the bytes and what follows.
func readMPI(b []byte) (value, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errFrame
	}
	bits := int(binary.BigEndian.Uint16(b))
	n := (bits + 7) / 8
	if bits == 0 || len(b) < 2+n || bits != (n-1)*8+bitLen(b[2]) {
		return nil, nil, errFrame
	}
	return b[2 : 2+n], b[2+n:], nil
}

// bitLen is the number of bits of a byte without its leading zeros.
func bitLen(c byte) int {
	n := 0
	for ; c != 0; c >>= 1 {
		n++
	}
	return n
}

// mpi writes a multiprecision integer (RFC 9580, section 3.2): the bit length, then the bytes
// without leading zeros.
func mpi(v *big.Int) []byte {
	b := v.Bytes()
	bits := v.BitLen()
	return append([]byte{byte(bits >> 8), byte(bits)}, b...)
}

func u32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
