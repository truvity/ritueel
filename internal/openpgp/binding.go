package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"time"
)

// This file reads an answer: the file `<stem>.bound.pgp` that [BindSubkey] writes
// (docs/reference/hand-off-contract.md, "OpenPGP subkey", "What comes back"). It is the reader that
// the requester's checks use, in the same package as the writer, so that a binding that BindSubkey
// returns is a binding that [VerifyBinding] accepts, and no other.

const (
	// maxBoundFile is the longest bound file, and the longest signature packet, that is read: the
	// 256 KiB of a file of the contract.
	maxBoundFile = 256 * 1024
	// maxBindingSubpackets is the most subpackets that either area of a binding may hold. The page's
	// set is four in the hashed area and two in the unhashed area, so this is far above any binding
	// of the page, and it is the bound that stops a walk over an area that a hostile file fills with
	// empty subpackets. It is checked by [scanArea] before the shared reader parseArea, which has no
	// count limit, is called.
	maxBindingSubpackets = 32
	// criticalSubpacket is the one subpacket of a binding that carries the critical bit.
	criticalSubpacket = spKeyExpiration
)

// SplitBoundFile splits `<stem>.bound.pgp` into its two packets, each whole with its header, as
// copies. The file is exactly two packets: the first has tag 14 (Public-Subkey), the second tag 2
// (Signature). A file with fewer or more packets, a packet that is not whole, a partial or an
// indeterminate length, a byte after the second packet, or a packet of another tag is an
// [ErrBoundFile]. So is a file longer than 256 KiB. Both old-format and new-format headers are read.
// Nothing is returned with an error.
func SplitBoundFile(file []byte) (subkey, binding []byte, err error) {
	if len(file) > maxBoundFile {
		return nil, nil, fail(ErrBoundFile, "the file is longer than %d bytes", maxBoundFile)
	}
	tag, _, rest, err := splitPacket(file)
	if err != nil {
		return nil, nil, fail(ErrBoundFile, "the file is not whole packets")
	}
	if tag != tagSubkey {
		return nil, nil, fail(ErrBoundFile, "the first packet is not a Public-Subkey packet (tag %d)", tag)
	}
	first := file[:len(file)-len(rest)]
	if len(rest) == 0 {
		return nil, nil, fail(ErrBoundFile, "the file has no second packet")
	}
	tag, _, after, err := splitPacket(rest)
	if err != nil {
		return nil, nil, fail(ErrBoundFile, "the second packet is not whole")
	}
	if tag != tagSignature {
		return nil, nil, fail(ErrBoundFile, "the second packet is not a Signature packet (tag %d)", tag)
	}
	if len(after) != 0 {
		return nil, nil, fail(ErrBoundFile, "there are bytes after the second packet")
	}
	return bytes.Clone(first), bytes.Clone(rest), nil
}

// BindingIssuer reads, from one signature packet, the issuer fingerprint of its hashed area: 40
// lower-case hexadecimal digits. It verifies nothing and is for finding which primary to verify
// with. A packet that is not one version 4 signature packet, whose areas hold more than 32
// subpackets or are cut, or whose hashed area holds no issuer fingerprint of version 4, or holds
// two, is an [ErrBinding]. Nothing is returned with an error.
func BindingIssuer(binding []byte) (fingerprint string, err error) {
	_, a, err := readBindingPacket(binding)
	if err != nil {
		return "", err
	}
	fp, ok := find(a.hashed, spIssuerFingerprint)
	if !ok || len(fp) != 21 || fp[0] != 4 {
		return "", fail(ErrBinding, "the hashed area has not one issuer fingerprint of version 4")
	}
	return hex.EncodeToString(fp[1:]), nil
}

// Binding is a subkey binding that [VerifyBinding] accepted. Its embedded signature was not read:
// VerifyBinding accepts any embedded body that is not empty, so a caller takes a binding as good
// only after [Binding.Embeds] holds for the back-signature that it sent. The zero value holds
// nothing and its accessors return the zero values.
type Binding struct {
	created    time.Time
	ends       time.Time
	issuer     string
	capability string
	embedded   []byte
}

// Created is the signature creation time of the binding: the ceremony time. It is the zero time for
// a nil or zero value.
func (b *Binding) Created() time.Time {
	if b == nil {
		return time.Time{}
	}
	return b.created
}

// IssuerFingerprint is the fingerprint of the primary that made the binding: 40 lower-case
// hexadecimal digits. It is empty for a nil or zero value.
func (b *Binding) IssuerFingerprint() string {
	if b == nil {
		return ""
	}
	return b.issuer
}

// Capability is "sign" for the key flags 0x02 and "authenticate" for 0x20. It is empty for a nil or
// zero value.
func (b *Binding) Capability() string {
	if b == nil {
		return ""
	}
	return b.capability
}

// Ends is the instant the subkey ends: its creation time plus the key expiration time of the
// binding, in UTC. It is the zero time for a nil or zero value.
func (b *Binding) Ends() time.Time {
	if b == nil {
		return time.Time{}
	}
	return b.ends
}

// Embeds tells whether the embedded signature of the binding (subpacket 32) is the body of backSig,
// one whole signature packet, byte for byte. [VerifyBinding] does not read the embedded signature
// and lets any body that is not empty pass, so this comparison is the only check of it: a caller
// compares it with the back-signature that it sent before it takes the binding as good. It is false
// for anything else: a nil or empty input, a packet that is not whole, a packet of another tag,
// bytes after the packet, and a nil or zero Binding.
func (b *Binding) Embeds(backSig []byte) bool {
	if b == nil || len(b.embedded) == 0 {
		return false
	}
	tag, body, rest, err := splitPacket(backSig)
	if err != nil || tag != tagSignature || len(rest) != 0 {
		return false
	}
	return bytes.Equal(body, b.embedded)
}

// VerifyBinding checks one signature packet as the binding of sub by primary. It does not read the
// embedded signature: any embedded body that is not empty passes it. A caller must compare it with
// [Binding.Embeds] against the back-signature that it sent before it takes a binding as good. The
// checks run in this order, the cheapest first, and the first that fails gives the error:
//
//  1. The packet is one version 4 signature of type 0x18 with algorithm 19 (ECDSA) and hash 9
//     (SHA-384); its two subpacket areas read to their ends with at most 32 subpackets in each,
//     counted before the shared reader is called; and after the two bytes of the hash tag it holds
//     two numbers and no byte after them.
//  2. Its hashed area holds one issuer fingerprint of version 4, and it is the primary's.
//  3. The two bytes of the hash tag are the start of the digest of the primary key, the subkey, the
//     fields of the signature and its trailer, and the signature verifies with the key of the
//     primary over that digest. This is the one signature verification of the call. It is the
//     check that go-crypto makes for [BindSubkey] without its look at the embedded signature, so
//     that a binding with a shape fault is still known to be the primary's.
//  4. The subpackets are the set of the page (the contract, "What comes back"; the two issuer
//     subpackets are also record 0009, rule 8).
//
// A fault of 1 to 3 is an [ErrBinding]. A fault of 4 is an [ErrBindingShape], which is returned only
// after the signature verified, so a caller may read it as "the issuer is right and the profile is
// not". The hashed area holds exactly these, each once and no other, in any order: the signature
// creation time (4 bytes), the key flags (one byte, 0x02 or 0x20), the key expiration time (4 bytes,
// not zero, the only subpacket marked critical) and the issuer fingerprint (21 bytes). The unhashed
// area holds exactly the issuer key ID (8 bytes, the last 8 bytes of the primary's fingerprint) and
// one embedded signature (subpacket 32, not empty), and is at most 10000 bytes, which is what gpgv
// reads, measured as written in the packet and not as a new encoding of its subpackets (every length
// form of the standard is read). The end of the subkey, its creation time plus the key expiration
// time, is at most 4294967295 seconds: a larger sum is an [ErrBindingShape]. The embedded signature
// is the requester's own back-signature and is compared by [Binding.Embeds], not here.
//
// A nil or zero primary or subkey is an [ErrParams], never a refusal of the answer. Nothing is
// returned with an error.
func VerifyBinding(binding []byte, primary *PrimaryKey, sub *Subkey) (*Binding, error) {
	if primary == nil || primary.k == nil {
		return nil, fail(ErrParams, "there is no primary")
	}
	if sub == nil || sub.k == nil {
		return nil, fail(ErrParams, "there is no subkey")
	}
	body, a, err := readBindingPacket(binding)
	if err != nil {
		return nil, err
	}
	if a.sigType != sigSubkeyBinding || a.algo != algoECDSA || a.hash != hashSHA384 {
		return nil, fail(ErrBinding, "the signature is not a type 0x18 signature with ECDSA and SHA-384")
	}
	tag, r, s, err := readSigValues(a.rest)
	if err != nil {
		return nil, err
	}
	fp, ok := find(a.hashed, spIssuerFingerprint)
	if !ok || !bytes.Equal(fp, append([]byte{4}, primary.k.fp...)) {
		return nil, fail(ErrBinding, "the hashed area has no one issuer fingerprint of the primary")
	}
	if err := verifyBindingSignature(a, tag, r, s, primary.k, sub.k); err != nil {
		return nil, err
	}
	return checkBindingShape(body, a, primary.k, sub.k)
}

// readBindingPacket reads one signature packet: whole, version 4, with the two subpacket areas
// counted by [scanArea] before the shared reader reads them. It returns the body and the areas.
func readBindingPacket(pkt []byte) ([]byte, sigAreas, error) {
	var a sigAreas
	if len(pkt) > maxBoundFile {
		return nil, a, fail(ErrBinding, "the signature is longer than %d bytes", maxBoundFile)
	}
	tag, body, rest, err := splitPacket(pkt)
	if err != nil || tag != tagSignature || len(rest) != 0 {
		return nil, a, fail(ErrBinding, "the bytes are not one signature packet")
	}
	if err := scanSigAreas(body); err != nil {
		return nil, a, err
	}
	a, err = splitSig(body)
	if err != nil {
		return nil, a, fail(ErrBinding, "the signature is not a version 4 signature that reads to its end")
	}
	return body, a, nil
}

// scanSigAreas walks the lengths of the two subpacket areas of a signature body and counts the
// subpackets of each, so that the shared reader, which has no limit, is called only for areas of
// at most maxBindingSubpackets. It checks no more than that: the form of the body is read by splitSig.
func scanSigAreas(body []byte) error {
	if len(body) < 6 || body[0] != 4 {
		return fail(ErrBinding, "the signature is not a version 4 signature")
	}
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	if len(body) < 6+hl+2 {
		return fail(ErrBinding, "the hashed area runs past the packet")
	}
	if _, err := scanArea(body[6:6+hl], maxBindingSubpackets); err != nil {
		return fail(ErrBinding, "the hashed area: %v", err)
	}
	ul := int(binary.BigEndian.Uint16(body[6+hl : 8+hl]))
	if len(body) < 8+hl+ul {
		return fail(ErrBinding, "the unhashed area runs past the packet")
	}
	if _, err := scanArea(body[8+hl:8+hl+ul], maxBindingSubpackets); err != nil {
		return fail(ErrBinding, "the unhashed area: %v", err)
	}
	return nil
}

// scanArea counts the subpackets of an area by their lengths, as parseArea reads them (RFC 9580,
// section 5.2.3.7), and stops with an error at the first one past limit: it never walks further, so
// the cost is bounded by limit and not by the size of the area. It returns the number counted so far,
// which is limit+1 when it stopped at the limit. A length that is zero or leaves the area is an error.
func scanArea(b []byte, limit int) (int, error) {
	n := 0
	for len(b) > 0 {
		if n >= limit {
			return n + 1, errAreaTooMany
		}
		var size, hl int
		switch l := int(b[0]); {
		case l < 192:
			size, hl = l, 1
		case l < 255:
			if len(b) < 2 {
				return n, errFrame
			}
			size, hl = (l-192)<<8+int(b[1])+192, 2
		default:
			if len(b) < 5 {
				return n, errFrame
			}
			size, hl = int(binary.BigEndian.Uint32(b[1:5])), 5
		}
		if size < 1 || hl+size > len(b) {
			return n, errFrame
		}
		n++
		b = b[hl+size:]
	}
	return n, nil
}

// errAreaTooMany is the cause of a subpacket area that holds more subpackets than the limit.
var errAreaTooMany = errors.New("more subpackets than the limit")

// readSigValues reads what follows the unhashed area: the two bytes of the hash tag and the two
// numbers of an ECDSA signature, with no byte after them.
func readSigValues(rest []byte) (tag, r, s []byte, err error) {
	if len(rest) < 2 {
		return nil, nil, nil, fail(ErrBinding, "the signature has no hash tag")
	}
	r, tail, err := readMPI(rest[2:])
	if err != nil {
		return nil, nil, nil, fail(ErrBinding, "the signature has no first number")
	}
	s, tail, err = readMPI(tail)
	if err != nil {
		return nil, nil, nil, fail(ErrBinding, "the signature has no second number")
	}
	if len(tail) != 0 {
		return nil, nil, nil, fail(ErrBinding, "the signature has bytes after its two numbers")
	}
	return rest[:2], r, s, nil
}

// verifyBindingSignature is check 3: the hash tag and the signature of the primary over the primary
// key, the subkey, the fields of the signature and its trailer (RFC 9580, section 5.2.4).
func verifyBindingSignature(a sigAreas, tag, r, s []byte, primary, sub *key) error {
	trailer := []byte{4, 0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(a.fields)))
	h := sha512.New384()
	h.Write(hashPrefix(primary.body))
	h.Write(hashPrefix(sub.body))
	h.Write(a.fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	if !bytes.Equal(tag, digest[:2]) {
		return fail(ErrBinding, "the hash tag of the signature is not the start of its digest")
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)})
	if err != nil || !ecdsa.VerifyASN1(primary.ec, digest, der) {
		return fail(ErrBinding, "the signature does not verify with the key of the primary")
	}
	return nil
}

// checkBindingShape is check 4: the subpackets are the set of the page, each once. It returns the
// binding that it read. It is called only after the signature verified. The body is the signature
// body that a was read from: the length of the unhashed area is the one written in it.
func checkBindingShape(body []byte, a sigAreas, primary, sub *key) (*Binding, error) {
	if len(a.hashed) != 4 {
		return nil, fail(ErrBindingShape, "the hashed area has not exactly four subpackets")
	}
	if len(a.unhashed) != 2 {
		return nil, fail(ErrBindingShape, "the unhashed area has not exactly two subpackets")
	}
	for _, sp := range a.hashed {
		if sp.critical != (sp.typ == criticalSubpacket) {
			return nil, fail(ErrBindingShape, "the subpacket of type %d has the wrong critical bit", sp.typ)
		}
	}
	for _, sp := range a.unhashed {
		if sp.critical {
			return nil, fail(ErrBindingShape, "a subpacket of the unhashed area is marked critical (type %d)", sp.typ)
		}
	}
	created, ok := find(a.hashed, spCreationTime)
	if !ok || len(created) != 4 {
		return nil, fail(ErrBindingShape, "the hashed area has not one creation time of 4 bytes")
	}
	flags, ok := find(a.hashed, spKeyFlags)
	if !ok || len(flags) != 1 {
		return nil, fail(ErrBindingShape, "the hashed area has not one key flags subpacket of one byte")
	}
	var capability string
	switch flags[0] {
	case flagSign:
		capability = "sign"
	case flagAuthenticate:
		capability = "authenticate"
	default:
		return nil, fail(ErrBindingShape, "the key flags are neither 0x02 nor 0x20")
	}
	life, ok := find(a.hashed, spKeyExpiration)
	if !ok || len(life) != 4 || binary.BigEndian.Uint32(life) == 0 {
		return nil, fail(ErrBindingShape, "the hashed area has not one key expiration time of 4 bytes that is not zero")
	}
	if _, ok := find(a.hashed, spIssuerFingerprint); !ok {
		return nil, fail(ErrBindingShape, "the hashed area has not one issuer fingerprint")
	}
	id, ok := find(a.unhashed, spIssuerKeyID)
	if !ok || !bytes.Equal(id, primary.keyID) {
		return nil, fail(ErrBindingShape, "the unhashed area has not the issuer key ID of the primary")
	}
	emb, ok := find(a.unhashed, spEmbeddedSignature)
	if !ok || len(emb) == 0 {
		return nil, fail(ErrBindingShape, "the unhashed area has not one embedded signature")
	}
	// The area is measured as written, by the length read from the packet, and not by a new encoding
	// of its subpackets: a length form longer than the shortest one is as long as it is written, and
	// gpgv reads the area by that length. scanSigAreas checked that the body holds both lengths.
	if hl := len(a.fields) - 6; int(binary.BigEndian.Uint16(body[6+hl:8+hl])) > maxUnhashedArea {
		return nil, fail(ErrBindingShape, "the unhashed area is longer than %d bytes, which gpgv does not read", maxUnhashedArea)
	}
	// The end is a time that a time field holds: the creation time of the subkey plus the key
	// expiration time is at most 4294967295 seconds, as BindSubkey writes it. gpgv reads a larger sum
	// as a wrapped time, so the binding is refused and Ends never returns a time after the year 2106.
	end := sub.created.Unix() + int64(binary.BigEndian.Uint32(life))
	if end > math.MaxUint32 {
		return nil, fail(ErrBindingShape, "the subkey ends after the last second of a time field (the year 2106)")
	}
	return &Binding{
		created:    time.Unix(int64(binary.BigEndian.Uint32(created)), 0).UTC(),
		ends:       time.Unix(end, 0).UTC(),
		issuer:     hex.EncodeToString(primary.fp),
		capability: capability,
		embedded:   bytes.Clone(emb),
	}, nil
}
