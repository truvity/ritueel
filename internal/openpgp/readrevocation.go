package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// This file reads a revocation signature: the packet that [RevocationSignature] writes and that the
// software store of a test root keeps next to the key (docs/reference/revocation-material.md, "What
// is made"; record 0007, rules 21 and 23). It is the reader that the check of stored material
// uses, in the same package as the writer, so that a signature that RevocationSignature returns is
// one that [ReadRevocation] accepts, and no other.

// maxRevocationBody is the most bytes of the body of a revocation signature that are read: the same
// bound as a self-certification. The exact shape is about 150 bytes (proposed).
const maxRevocationBody = maxCertificationBody

// Revocation is what [ReadRevocation] read: the reason (code and word), the signature creation time,
// the issuer and the SHA-256 of the packet, which is the digest that the bundle keeps. The zero
// value holds nothing.
type Revocation struct {
	Reason  Reason
	Created time.Time
	Issuer  string // 40 lower-case hexadecimal digits
	SHA256  string // 64 lower-case hexadecimal digits, over the binary packet as given
}

// readRevocationPacket reads the frame of one revocation signature packet: whole, no byte after
// it, a body of at most maxRevocationBody bytes (judged before any byte is copied or compared), the
// shortest new-format header, version 4, and both subpacket areas counted (at most 32 subpackets in
// each) before the shared reader, which has no limit, reads them. It returns the body and its
// areas. Every fault is an [ErrRevocation].
func readRevocationPacket(pkt []byte) ([]byte, sigAreas, error) {
	var a sigAreas
	tag, body, rest, err := splitPacket(pkt)
	if err != nil || tag != tagSignature || len(rest) != 0 {
		return nil, a, fail(ErrRevocation, "the bytes are not one signature packet")
	}
	if len(body) > maxRevocationBody {
		return nil, a, fail(ErrRevocation, "the signature is longer than %d bytes", maxRevocationBody)
	}
	if !bytes.Equal(pkt, wrap(tagSignature, body)) {
		return nil, a, fail(ErrRevocation, "the header of the packet is not the shortest one of the new format")
	}
	if err := scanAreasOf(ErrRevocation, body); err != nil {
		return nil, a, err
	}
	a, err = splitSig(body)
	if err != nil {
		return nil, sigAreas{}, fail(ErrRevocation, "the signature is not a version 4 signature that reads to its end")
	}
	return body, a, nil
}

// issuerOf is the fingerprint of the one issuer fingerprint subpacket of the hashed area: version 4,
// 20 bytes.
func issuerOf(a sigAreas) ([]byte, error) {
	fp, ok := find(a.hashed, spIssuerFingerprint)
	if !ok || len(fp) != 21 || fp[0] != 4 {
		return nil, fail(ErrRevocation, "the hashed area has not one issuer fingerprint of version 4")
	}
	return fp[1:], nil
}

// RevocationIssuer returns the fingerprint that a revocation signature names in its Issuer
// Fingerprint subpacket (hashed area): 40 lower-case hexadecimal digits, so that a caller picks the
// primary before it verifies. It reads the frame of the packet as [ReadRevocation] does (one whole
// signature packet of version 4, the shortest header, a body of at most 512 bytes, at most 32
// subpackets in each area) and verifies nothing: it does not look at the reason or the algorithms,
// which are for ReadRevocation. It names the issuer of a key revocation only: a signature of
// another type than 0x20 is an [ErrRevocation], as ReadRevocation gives for it. A packet with no
// issuer fingerprint of version 4, or with two, is an ErrRevocation. Nothing is returned with an
// error.
func RevocationIssuer(packet []byte) (fingerprint string, err error) {
	defer func() {
		if r := recover(); r != nil {
			fingerprint, err = "", fail(ErrRevocation, "the signature could not be read")
		}
	}()
	_, a, err := readRevocationPacket(packet)
	if err != nil {
		return "", err
	}
	if a.sigType != sigKeyRevocation {
		return "", fail(ErrRevocation, "the signature is not a type 0x20 signature")
	}
	fp, err := issuerOf(a)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(fp), nil
}

// ReadRevocation reads exactly what [RevocationSignature] writes and verifies it with primary. The
// checks run in this order, the cheapest first, and the first that fails gives the error:
//
//  1. The packet is one whole signature packet with the shortest new-format header and no byte
//     after it, a body of at most 512 bytes, version 4, with at most 32 subpackets in each area,
//     counted before the shared reader or go-crypto reads them.
//  2. It is of type 0x20 (key revocation), with ECDSA (19) and SHA-384 (9); after the two bytes of
//     the hash tag it holds two numbers and no byte after them.
//  3. Its hashed area holds one issuer fingerprint of version 4, and it is the primary's.
//  4. Its hashed area holds one reason for revocation subpacket, with the code and the word of one of
//     the four reasons ([Compromised], [Superseded], [Retired], [NoReason]). No such subpacket, or a
//     code and a word that are not one of the four, is an [ErrRevocationReason]; two of them are an
//     ErrRevocation.
//  5. The hashed area holds exactly the signature creation time (4 bytes), the reason and the issuer
//     fingerprint, each once; the unhashed area holds exactly the issuer key ID (the last 8 bytes of
//     the fingerprint). No subpacket is marked critical.
//  6. The signature creation time is not before the creation time of the primary.
//  7. The two bytes of the hash tag are the start of the digest of the key packet of the primary, the
//     fields of the signature and its trailer, which go-crypto does not compare, and the signature
//     verifies with the key of the primary over that digest.
//  8. go-crypto reads the packet as a key revocation with the same reason and creation time, and
//     verifies it with the key of the primary over the key packet alone (RFC 9580, section 5.2.4).
//
// It reads no clock: the expiry of the primary is not compared with the time of the check. A nil or
// zero primary is an [ErrRevocation], as is a packet that names another primary. The text of an
// error holds no byte of the packet. It returns no Revocation with an error.
func ReadRevocation(packet []byte, primary *PrimaryKey) (rev *Revocation, err error) {
	defer func() {
		if r := recover(); r != nil {
			rev, err = nil, fail(ErrRevocation, "the signature could not be read")
		}
	}()
	if primary == nil || primary.k == nil {
		return nil, fail(ErrRevocation, "there is no primary")
	}
	_, a, err := readRevocationPacket(packet)
	if err != nil {
		return nil, err
	}
	if a.sigType != sigKeyRevocation || a.algo != algoECDSA || a.hash != hashSHA384 {
		return nil, fail(ErrRevocation, "the signature is not a type 0x20 signature with ECDSA and SHA-384")
	}
	tag, r, s, err := readValuesOf(ErrRevocation, a.rest)
	if err != nil {
		return nil, err
	}
	issuer, err := issuerOf(a)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(issuer, primary.k.fp) {
		return nil, fail(ErrRevocation, "the issuer fingerprint is not the fingerprint of the primary")
	}
	reason, err := revocationReason(a)
	if err != nil {
		return nil, err
	}
	created, err := checkRevocationShape(a, primary.k)
	if err != nil {
		return nil, err
	}
	if created.Before(primary.k.created) {
		return nil, fail(ErrRevocation, "the signature is dated before the creation of the primary")
	}
	if err := verifyRevocationSignature(a, tag, r, s, primary.k); err != nil {
		return nil, err
	}
	if err := readRevocationAgain(packet, reason, created, primary.k); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(packet)
	return &Revocation{
		Reason:  reason,
		Created: created,
		Issuer:  hex.EncodeToString(primary.k.fp),
		SHA256:  hex.EncodeToString(sum[:]),
	}, nil
}

// revocationReason is check 4: the one reason subpacket of the hashed area, as one of the four.
func revocationReason(a sigAreas) (Reason, error) {
	switch n := count(a.hashed, spRevocationReason); {
	case n == 0:
		return Reason{}, fail(ErrRevocationReason, "the hashed area has no reason for revocation")
	case n > 1:
		return Reason{}, fail(ErrRevocation, "the hashed area has more than one reason for revocation")
	}
	data, _ := find(a.hashed, spRevocationReason)
	if len(data) == 0 {
		return Reason{}, fail(ErrRevocationReason, "the reason for revocation has no code")
	}
	for _, r := range []Reason{Compromised, Superseded, Retired, NoReason} {
		if data[0] == r.Code && string(data[1:]) == r.Text {
			return r, nil
		}
	}
	return Reason{}, fail(ErrRevocationReason, "the code and the word of the reason for revocation are not one of the four of the profile")
}

// checkRevocationShape is check 5, and returns the signature creation time.
func checkRevocationShape(a sigAreas, k *key) (time.Time, error) {
	if len(a.hashed) != 3 {
		return time.Time{}, fail(ErrRevocation, "the hashed area has not exactly three subpackets")
	}
	if len(a.unhashed) != 1 {
		return time.Time{}, fail(ErrRevocation, "the unhashed area has not exactly one subpacket")
	}
	for _, sp := range a.hashed {
		if sp.critical {
			return time.Time{}, fail(ErrRevocation, "the subpacket of type %d is marked critical", sp.typ)
		}
	}
	if a.unhashed[0].critical {
		return time.Time{}, fail(ErrRevocation, "the subpacket of the unhashed area is marked critical")
	}
	created, ok := find(a.hashed, spCreationTime)
	if !ok || len(created) != 4 {
		return time.Time{}, fail(ErrRevocation, "the hashed area has not one creation time of 4 bytes")
	}
	id, ok := find(a.unhashed, spIssuerKeyID)
	if !ok || !bytes.Equal(id, k.keyID) {
		return time.Time{}, fail(ErrRevocation, "the unhashed area has not exactly the issuer key ID of the primary")
	}
	return time.Unix(int64(binary.BigEndian.Uint32(created)), 0).UTC(), nil
}

// verifyRevocationSignature is check 7: the hash tag and the signature of the primary over its key
// packet, the fields of the signature and its trailer.
func verifyRevocationSignature(a sigAreas, tag, r, s []byte, k *key) error {
	trailer := []byte{4, 0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(a.fields)))
	h := sha512.New384()
	h.Write(hashPrefix(k.body))
	h.Write(a.fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	if !bytes.Equal(tag, digest[:2]) {
		return fail(ErrRevocation, "the hash tag of the signature is not the start of its digest")
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)})
	if err != nil || !ecdsa.VerifyASN1(k.ec, digest, der) {
		return fail(ErrRevocation, "the signature does not verify with the key of the primary")
	}
	return nil
}

// readRevocationAgain is check 8: go-crypto must read the packet as the fields read here say, and
// verify it.
func readRevocationAgain(pkt []byte, reason Reason, created time.Time, k *key) error {
	p, err := packet.Read(bytes.NewReader(pkt))
	if err != nil {
		return fail(ErrRevocation, "the signature is not read by a second reader")
	}
	sig, ok := p.(*packet.Signature)
	if !ok || sig.SigType != sigKeyRevocation || !sig.CreationTime.Equal(created) ||
		sig.RevocationReason == nil || byte(*sig.RevocationReason) != reason.Code || sig.RevocationReasonText != reason.Text {
		return fail(ErrRevocation, "a second reader does not read the signature as it is here")
	}
	if err := k.pk.VerifyRevocationSignature(sig); err != nil {
		return fail(ErrRevocation, "the signature does not verify with the key of the primary over its key packet")
	}
	return nil
}
