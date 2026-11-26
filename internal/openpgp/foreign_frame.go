package openpgp

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// This file is the framing of the reader of a foreign key: the armour block of a private key and
// the packets of a transferable key (RFC 9580, sections 4 and 6). Everything here works on bytes
// that the caller has already held to [MaxForeignKeyBytes].

const (
	// foreignArmourType is the one armour type that the reader takes.
	foreignArmourType = "PGP PRIVATE KEY BLOCK"
	// armourDashes frames a head line and an end line of an armour block.
	armourDashes = "-----"
	// maxArmourLine is the longest line of the base64 text of a block (RFC 9580, section 6.2).
	maxArmourLine = 76
	// maxArmourHeaders is the most header lines that a block may carry.
	maxArmourHeaders = 32
	// maxArmourHeaderLine is the longest header line that a block may carry.
	maxArmourHeaderLine = 256
)

// Packet tags of a transferable key that the foreign reader meets (RFC 9580, section 5).
const (
	tagSecretSubkey  = 7
	tagMarker        = 10
	tagTrust         = 12
	tagUserAttribute = 17
)

// tagName names the tag of a packet that is refused, so that an error says "a compressed data packet
// (tag 8)" and a reader of the text does not need the standard open. A tag that has no name here has
// the number only.
func tagName(tag byte) string {
	names := map[byte]string{
		0:  "a reserved packet",
		2:  "a signature packet",
		13: "a user ID packet",
		17: "a user attribute packet",
		1:  "a public-key encrypted session key packet",
		3:  "a symmetric-key encrypted session key packet",
		4:  "a one-pass signature packet",
		8:  "a compressed data packet",
		9:  "a symmetrically encrypted data packet",
		11: "a literal data packet",
		18: "a symmetrically encrypted and integrity protected data packet",
		19: "a modification detection code packet",
		20: "an AEAD encrypted data packet",
		21: "a padding packet",
	}
	if n, ok := names[tag]; ok {
		return fmt.Sprintf("%s (tag %d)", n, tag)
	}
	return fmt.Sprintf("a packet of tag %d", tag)
}

// armourKindName names an armour type that is not a private key block, from a fixed list: the text
// of the head line is the file's, so it is never copied into an error.
func armourKindName(head []byte) string {
	t := bytes.TrimSuffix(bytes.TrimPrefix(head, []byte(armourLine+" ")), []byte(armourDashes))
	switch {
	case string(t) == "PGP PUBLIC KEY BLOCK":
		return "a public key block, which holds no secret"
	case string(t) == "PGP MESSAGE" || bytes.HasPrefix(t, []byte("PGP MESSAGE,")):
		return "a message, not a key"
	case string(t) == "PGP SIGNATURE":
		return "a signature, not a key"
	case string(t) == "PGP SIGNED MESSAGE":
		return "a signed message, not a key"
	}
	return "another armour type"
}

// readForeignArmour reads exactly one armour block of type PGP PRIVATE KEY BLOCK and returns the
// bytes it holds, in a buffer of its own that the caller clears. The head line starts the file (a
// file is taken for armour only when it starts with the head line); the headers are at most
// maxArmourHeaders lines of "Key: Value"; one blank line follows them; the base64 lines are at most
// 76 characters, each a whole number of four-character groups, with padding only on the last; an
// optional CRC-24 line "=" and four characters is checked when present (RFC 9580 makes it optional);
// the end line closes the block; and nothing but white space follows. Lines end with LF or CRLF, and
// white space at the end of a line is ignored. The size was checked by the caller. Every fault is an
// [ErrForeignArmour]. No partly decoded byte is left in a buffer that the caller cannot clear.
func readForeignArmour(file []byte) (out []byte, err error) {
	out = make([]byte, 0, len(file)/4*3+3)
	defer func() {
		if err != nil {
			clear(out[:cap(out)])
			out = nil
		}
	}()
	next := newLineReader(file)
	head, _ := next()
	begin := []byte(armourDashes + "BEGIN " + foreignArmourType + armourDashes)
	if !bytes.Equal(head, begin) {
		return out, fail(ErrForeignArmour, "the armour is %s: only one block of type %s is read", armourKindName(head), foreignArmourType)
	}
	line, ok := next()
	for headers := 0; ok && len(line) > 0; headers++ {
		if headers == maxArmourHeaders {
			return out, fail(ErrForeignArmour, "the armour has more than %d header lines", maxArmourHeaders)
		}
		if len(line) > maxArmourHeaderLine || !bytes.Contains(line, []byte(": ")) {
			return out, fail(ErrForeignArmour, "a header line of the armour is longer than %d bytes or is not of the form Key: Value, or the blank line after the head line is missing", maxArmourHeaderLine)
		}
		line, ok = next()
	}
	if !ok {
		return out, fail(ErrForeignArmour, "the armour ends before its blank line")
	}
	out, err = readArmourBody(out, next)
	return out, err
}

// readArmourBody reads the base64 lines, the optional CRC-24 line and the end line of a block that
// readForeignArmour has read the head of, appends the bytes to out and returns them.
func readArmourBody(out []byte, next func() ([]byte, bool)) ([]byte, error) {
	enc := base64.StdEncoding.Strict()
	var crc []byte
	padded := false
	for {
		line, ok := next()
		if !ok {
			return out, fail(ErrForeignArmour, "the armour has no end line")
		}
		if bytes.HasPrefix(line, []byte(armourDashes)) {
			return finishArmour(out, crc, line, next)
		}
		if len(line) > 0 && line[0] == '=' {
			if crc != nil || len(line) != 5 {
				return out, fail(ErrForeignArmour, "the CRC-24 line of the armour is not one line of four characters")
			}
			sum, err := enc.DecodeString(string(line[1:]))
			if err != nil || len(sum) != 3 {
				return out, fail(ErrForeignArmour, "the CRC-24 line of the armour is not base64")
			}
			crc = sum
			continue
		}
		if crc != nil || padded {
			return out, fail(ErrForeignArmour, "the armour has base64 text after its padding or its CRC-24 line")
		}
		if len(line) == 0 || len(line) > maxArmourLine || len(line)%4 != 0 {
			return out, fail(ErrForeignArmour, "a line of the armour is empty, longer than %d characters, or not a whole number of groups of four", maxArmourLine)
		}
		n, err := enc.Decode(out[len(out):cap(out)], line)
		if err != nil {
			return out, fail(ErrForeignArmour, "the base64 text of the armour is not base64")
		}
		out = out[:len(out)+n]
		padded = line[len(line)-1] == '='
	}
}

// finishArmour checks the end line, the CRC-24 line and what follows the block.
func finishArmour(out, crc, end []byte, next func() ([]byte, bool)) ([]byte, error) {
	if string(end) != armourDashes+"END "+foreignArmourType+armourDashes {
		return out, fail(ErrForeignArmour, "the end line of the armour is not the end line of a block of type %s", foreignArmourType)
	}
	for {
		line, ok := next()
		if !ok {
			break
		}
		if len(line) > 0 {
			if bytes.HasPrefix(line, []byte(armourLine)) {
				return out, fail(ErrForeignArmour, "the file holds a second armour block")
			}
			return out, fail(ErrForeignArmour, "the file holds text after the end line of the armour")
		}
	}
	if len(out) == 0 {
		return out, fail(ErrForeignArmour, "the armour holds no bytes")
	}
	if crc != nil && uint32(crc[0])<<16|uint32(crc[1])<<8|uint32(crc[2]) != crc24Of(out) {
		return out, fail(ErrForeignArmour, "the CRC-24 line of the armour is wrong")
	}
	return out, nil
}

// newLineReader returns the lines of b one by one, with the line end and the white space at the end
// of the line cut off, and false after the last one. A last line with no line end is a line.
func newLineReader(b []byte) func() ([]byte, bool) {
	return func() ([]byte, bool) {
		if len(b) == 0 {
			return nil, false
		}
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		return bytes.TrimRight(line, " \t\r"), true
	}
}

// splitForeignPacket reads the first packet of b, old or new header form. It returns the tag, the
// whole packet with its header, its body and the rest. A partial body length (a new-format length
// octet from 224 to 254, RFC 9580 section 4.2.1.4) and an indeterminate length (an old-format
// length type 3) are not read: a key packet and a signature are never written with them, and the
// refusal names which one it met. A body longer than [MaxForeignPacketBytes] is an [ErrForeignLimit];
// every other fault is an [ErrForeignForm]. n is the number of the packet, for the text only.
func splitForeignPacket(b []byte, n int) (tag byte, raw, body, rest []byte, err error) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d does not start with a packet header", n)
	}
	var start int
	var size uint64
	if b[0]&0x40 != 0 {
		tag = b[0] & 0x3F
		switch l := int(b[1]); {
		case l < 192:
			start, size = 2, uint64(l)
		case l < 224:
			if len(b) < 3 {
				return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d is cut short in its length", n)
			}
			start, size = 3, uint64((l-192)<<8+int(b[2])+192)
		case l < 255:
			return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d (tag %d) has a partial body length, which is not read", n, tag)
		default:
			if len(b) < 6 {
				return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d is cut short in its length", n)
			}
			start, size = 6, uint64(binary.BigEndian.Uint32(b[2:6]))
		}
	} else {
		tag = (b[0] >> 2) & 0x0F
		switch b[0] & 3 {
		case 0:
			start, size = 2, uint64(b[1])
		case 1:
			if len(b) < 3 {
				return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d is cut short in its length", n)
			}
			start, size = 3, uint64(binary.BigEndian.Uint16(b[1:3]))
		case 2:
			if len(b) < 5 {
				return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d is cut short in its length", n)
			}
			start, size = 5, uint64(binary.BigEndian.Uint32(b[1:5]))
		default:
			return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d (tag %d) has an indeterminate length, which is not read", n, tag)
		}
	}
	if size > MaxForeignPacketBytes {
		return 0, nil, nil, nil, fail(ErrForeignLimit, "packet %d is longer than MaxForeignPacketBytes (%d bytes)", n, MaxForeignPacketBytes)
	}
	if uint64(len(b)-start) < size {
		return 0, nil, nil, nil, fail(ErrForeignForm, "packet %d is cut short: its length runs past the end of the file", n)
	}
	end := start + int(size)
	return tag, b[:end], b[start:end], b[end:], nil
}
