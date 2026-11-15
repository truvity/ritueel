package openpgp

import (
	"bytes"
	"encoding/base64"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

const (
	// MaxSignatureFileBytes is the most bytes of the file of one revocation signature, binary or
	// armoured: 8 KiB. It is checked before anything is read.
	MaxSignatureFileBytes = 8 << 10

	// maxSignaturePacket is the most bytes of the one signature packet of such a file, with its
	// header: 1 KiB, the limit of the software store.
	maxSignaturePacket = 1 << 10

	sigArmourType  = "PGP SIGNATURE"
	sigArmourBegin = "-----BEGIN PGP SIGNATURE-----"
	sigArmourEnd   = "-----END PGP SIGNATURE-----"
	// sigArmourComment is the one header that a block may carry: the mark that the software store
	// of a test root writes.
	sigArmourComment = "TEST ONLY"
	// ageBinaryPrefix is how a binary age file starts.
	ageBinaryPrefix = "age-encryption.org/"
)

// ReadSignatureFile returns the one signature packet that a stored file holds. The file is either
// the binary packet or exactly one armour block "-----BEGIN PGP SIGNATURE-----" with no header line
// or with the one header line "Comment: TEST ONLY" (RFC 9580, section 6.2), whose CRC-24 line is
// present and checked, in the form that go-crypto writes (lines of 64 characters, LF line ends),
// with no byte before the first line and none after the last one but one final line end. A file is
// taken for an armoured one only when it starts with the armour head line; any other file is the
// binary packet, whatever bytes it holds inside, and a file with bytes before an armour block is
// refused as a binary packet that is not one. The size is checked before anything is read. It
// reads no armour of another kind (a public key block, a message), no second block and no encrypted
// file: an age file is refused with a text that says it is not read here. The packet that it returns is exactly one whole signature packet of at most
// 1 KiB, with the shortest header that its length allows (a new-format header), and no byte after
// it. It judges the container and the framing only: the packet is not read as a signature, and that
// is for [ReadRevocation].
//
// Every fault is an [ErrSignatureFile]. The text of an error names a fault and holds no byte of the
// file. Nothing is returned with an error.
func ReadSignatureFile(file []byte) (packet []byte, err error) {
	if len(file) == 0 {
		return nil, fail(ErrSignatureFile, "the file is empty")
	}
	if len(file) > MaxSignatureFileBytes {
		return nil, fail(ErrSignatureFile, "the file is longer than %d bytes", MaxSignatureFileBytes)
	}
	var pkt []byte
	switch {
	case bytes.HasPrefix(file, []byte(armourLine)):
		pkt, err = readSignatureArmour(file)
		if err != nil {
			return nil, err
		}
	case bytes.HasPrefix(file, []byte(ageBinaryPrefix)):
		return nil, fail(ErrSignatureFile, "the file is an age file, which is not read here: it holds a signature that is not open")
	default:
		pkt = file
	}
	if err := checkSignaturePacket(pkt); err != nil {
		return nil, err
	}
	return bytes.Clone(pkt), nil
}

// checkSignaturePacket holds pkt to be exactly one whole signature packet of at most 1 KiB, with
// the shortest new-format header, and no byte after it.
func checkSignaturePacket(pkt []byte) error {
	if len(pkt) > maxSignaturePacket {
		return fail(ErrSignatureFile, "the packet is longer than %d bytes", maxSignaturePacket)
	}
	tag, body, rest, err := splitPacket(pkt)
	if err != nil {
		return fail(ErrSignatureFile, "the file is not a whole packet, or its length is a form that is not read")
	}
	if tag != tagSignature {
		return fail(ErrSignatureFile, "the packet is not a Signature packet (tag %d)", tag)
	}
	if len(rest) != 0 {
		return fail(ErrSignatureFile, "there are bytes after the first packet")
	}
	if !bytes.Equal(pkt, wrap(tagSignature, body)) {
		return fail(ErrSignatureFile, "the header of the packet is not the shortest one of the new format")
	}
	return nil
}

// readSignatureArmour reads one armour block of a signature and returns the bytes it holds. The
// block is read with go-crypto, whose reader does not check the CRC-24 and skips what stands before
// a block, so the checks that it leaves are made here: the type, the headers, the CRC-24 line, and
// at last the whole text against the text that go-crypto writes for those bytes.
func readSignatureArmour(file []byte) ([]byte, error) {
	first, _, _ := bytes.Cut(file, []byte("\n"))
	if string(first) != sigArmourBegin {
		if bytes.HasPrefix(first, []byte("-----BEGIN AGE")) {
			return nil, fail(ErrSignatureFile, "the armour is an age file, which is not read here")
		}
		return nil, fail(ErrSignatureFile, "the armour is not a block of type %s", sigArmourType)
	}
	if bytes.Count(file, []byte(armourLine)) != 1 {
		return nil, fail(ErrSignatureFile, "the file has a second armour block")
	}
	blk, err := armor.Decode(bytes.NewReader(file))
	if err != nil || blk == nil || blk.Type != sigArmourType {
		return nil, fail(ErrSignatureFile, "the file is not one armour block of type %s", sigArmourType)
	}
	header, err := armourHeader(blk.Header)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(blk.Body, maxSignaturePacket+1))
	if err != nil {
		return nil, fail(ErrSignatureFile, "the armour body does not read")
	}
	if len(body) > maxSignaturePacket {
		return nil, fail(ErrSignatureFile, "the packet is longer than %d bytes", maxSignaturePacket)
	}
	if got, ok := armourCRC(file); ok && got != crc24Of(body) {
		return nil, fail(ErrSignatureFile, "the CRC-24 line of the armour is wrong")
	}
	again, err := writeSignatureArmour(header, body)
	if err != nil || (!bytes.Equal(file, again) && !bytes.Equal(file, append(again, '\n'))) {
		return nil, fail(ErrSignatureFile, "the file is not exactly one armour block with its CRC-24 line and nothing else")
	}
	return body, nil
}

// armourHeader holds the headers that go-crypto read to none or to the one comment of a test root,
// and returns them in the form that [writeSignatureArmour] takes.
func armourHeader(h map[string]string) (map[string]string, error) {
	switch {
	case len(h) == 0:
		return nil, nil
	case len(h) == 1 && h["Comment"] == sigArmourComment:
		return map[string]string{"Comment": sigArmourComment}, nil
	}
	return nil, fail(ErrSignatureFile, "the armour has a header line other than Comment: %s", sigArmourComment)
}

// writeSignatureArmour is the text that go-crypto writes for body: no byte after the end line.
func writeSignatureArmour(header map[string]string, body []byte) ([]byte, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, sigArmourType, header)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(body); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// armourCRC finds the CRC-24 line of an armour block, the line before the end line, and returns its
// value. It reports false for a block that has no such line, which the comparison with the written
// text then refuses.
func armourCRC(file []byte) (uint32, bool) {
	end := bytes.LastIndex(file, []byte(sigArmourEnd))
	if end < 1 || file[end-1] != '\n' {
		return 0, false
	}
	line := file[:end-1]
	if i := bytes.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	if len(line) != 5 || line[0] != '=' {
		return 0, false
	}
	raw, err := base64.StdEncoding.DecodeString(string(line[1:]))
	if err != nil || len(raw) != 3 {
		return 0, false
	}
	return uint32(raw[0])<<16 | uint32(raw[1])<<8 | uint32(raw[2]), true
}

// crc24Of is the OpenPGP checksum of RFC 9580, section 6.1.
func crc24Of(data []byte) uint32 {
	const (
		crcInit = 0xB704CE
		crcPoly = 0x1864CFB
	)
	crc := uint32(crcInit)
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= crcPoly
			}
		}
	}
	return crc & 0xFFFFFF
}
