package openpgp

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// PrimaryParams names a root key's OpenPGP primary and the moment of one ceremony.
type PrimaryParams struct {
	// Key signs. Its public key must be ECDSA on P-384. A card or a cloud key plugs in here: it is
	// given the SHA-384 digest of what is signed (crypto.SHA384) and returns an ASN.1 signature.
	Key crypto.Signer
	// CreationTime is the OpenPGP creation time of the primary. It fixes the fingerprint
	// (docs/reference/bundle.md, "root.json": openpgp_created). Whole seconds.
	CreationTime time.Time
	// CeremonyTime is the time every signature carries. Whole seconds, not before CreationTime.
	CeremonyTime time.Time
	// ExpiresAt is the instant the key expires, after CeremonyTime. The caller passes the ceremony
	// time plus 36 calendar months. The key expiration time is written in seconds after
	// CreationTime, as the standard says, so that the key ends at this instant.
	ExpiresAt time.Time
	// UserID is the user ID, see [UserID]. One that has not the shape of [UserID], or holds a part
	// that breaks its rules, is refused.
	UserID string
}

// newPrimarySigner checks what every builder needs of the parameters (the key, the creation time
// and the ceremony time) and makes the signer.
func newPrimarySigner(rnd io.Reader, p PrimaryParams) (*signer, error) {
	g, err := newSigner(rnd, p.Key, p.CreationTime)
	if err != nil {
		return nil, err
	}
	if err := checkTime("the ceremony time", p.CeremonyTime); err != nil {
		return nil, err
	}
	if p.CeremonyTime.Before(p.CreationTime) {
		return nil, fail(ErrParams, "the ceremony time is before the creation time of the key")
	}
	return g, nil
}

// lifetime is the number of seconds from start to end, which must be a positive number that fits
// a key expiration time, and end must be after the ceremony.
func lifetime(what string, start, end, ceremony time.Time) (uint32, error) {
	if err := checkTime(what, end); err != nil {
		return 0, err
	}
	if !end.After(ceremony) {
		return 0, fail(ErrParams, "%s is not after the ceremony time", what)
	}
	d := end.Unix() - start.Unix()
	if d <= 0 || d > math.MaxUint32 {
		return 0, fail(ErrParams, "%s is not between 1 second and 136 years after the key was created", what)
	}
	return uint32(d), nil
}

// NewPrimary returns the public certificate of the primary: the primary key packet, the user ID
// packet and the self-signature. The self-signature is a positive certification (type 0x13) with
// SHA-384; its hashed area holds the signature creation time (the ceremony time), the key flags
// 0x01 (certify only), the key expiration time marked critical, and the issuer fingerprint; its
// unhashed area holds the issuer key ID. The certificate has no subkey.
//
// docs/reference/bundle.md, "The OpenPGP primary"; record 0009, rules 1, 2, 4 and 8. The signature
// is verified before the bytes are returned; nothing is returned with an error.
func NewPrimary(rnd io.Reader, p PrimaryParams) (cert []byte, err error) {
	g, sig, err := selfSign(rnd, p)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = append(out, g.packet...)
	out = append(out, wrap(tagUserID, []byte(p.UserID))...)
	return append(out, sig...), nil
}

// ExtendPrimary returns a new self-signature of the same shape as the one of [NewPrimary], at
// p.CeremonyTime: "each use extends it" (docs/reference/bundle.md, "The OpenPGP primary"). It is
// one signature packet, to be added to the certificate. The newest signature gives the expiry.
func ExtendPrimary(rnd io.Reader, p PrimaryParams) (selfSig []byte, err error) {
	_, sig, err := selfSign(rnd, p)
	return sig, err
}

// selfSign makes the self-signature packet of p and reads it back.
func selfSign(rnd io.Reader, p PrimaryParams) (*signer, []byte, error) {
	if err := checkUserID(p.UserID); err != nil {
		return nil, nil, err
	}
	g, err := newPrimarySigner(rnd, p)
	if err != nil {
		return nil, nil, err
	}
	life, err := lifetime("the expiry of the key", g.created, p.ExpiresAt, p.CeremonyTime)
	if err != nil {
		return nil, nil, err
	}
	uid := []byte(p.UserID)
	body, err := g.sign(sigSpec{
		sigType: sigPositiveCertification,
		hashed: []subpacket{
			{typ: spCreationTime, data: u32(unixU32(p.CeremonyTime))},
			{typ: spKeyFlags, data: []byte{flagCertify}},
			{typ: spKeyExpiration, critical: true, data: u32(life)},
			g.issuerFingerprint(),
		},
		unhashed: []subpacket{g.issuerKeyID()},
		data: [][]byte{
			hashPrefix(g.body),
			{0xB4, byte(len(uid) >> 24), byte(len(uid) >> 16), byte(len(uid) >> 8), byte(len(uid))},
			uid,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	pkt := wrap(tagSignature, body)
	cert, err := checkCertification(pkt, g.key, p.UserID, g.created)
	if err != nil {
		return nil, nil, fail(ErrSignature, "the self-signature does not read back as it was built: %v", err)
	}
	if !cert.created.Equal(p.CeremonyTime) || cert.life != life {
		return nil, nil, fail(ErrSignature, "the self-signature does not read back as it was built")
	}
	return g, bytes.Clone(pkt), nil
}

// maxCertificationBody is the most bytes of the body of one self-certification that is read. The
// exact shape is about 160 bytes; the bound is checked before any subpacket is counted and before
// go-crypto reads the packet (proposed).
const maxCertificationBody = 512

// certification is what [checkCertification] read from one self-certification.
type certification struct {
	created time.Time // the signature creation time
	life    uint32    // the key expiration time, in seconds after the creation of the key
}

// certError is a fault of one self-certification. Its text is fixed words and numbers: it holds no
// byte of the packet. The builder and the reader of the keyring file each wrap it in their own kind.
type certError string

func (e certError) Error() string { return string(e) }

// checkCertification is the one check of a self-certification of a primary, for the builder
// ([selfSign]) and for [ReadKeyring], so that a certification that the builder returns is one that
// the reader accepts, and no other (docs/reference/bundle.md, "The OpenPGP primary", row
// Self-signature; record 0009, rule 8). pkt is one whole signature packet. The checks run in this
// order, the cheapest first, and the first that fails gives the error:
//
//  1. The packet is whole, is tag 2, and its body is at most maxCertificationBody bytes.
//  2. Both subpacket areas read to their ends with at most maxBindingSubpackets subpackets in each,
//     counted by [scanArea] before the shared reader, which has no count limit, or go-crypto reads
//     them; the signature is version 4, type 0x13 (positive certification), ECDSA, SHA-384, and
//     after the hash tag it holds two numbers and no byte after them.
//  3. The hashed area holds exactly the signature creation time (4 bytes), the key flags (one byte,
//     0x01), the key expiration time (4 bytes, not zero, the only subpacket marked critical) and the
//     issuer fingerprint (the fingerprint of k, version 4), each once and in any order. The unhashed
//     area holds exactly the issuer key ID (the last 8 bytes of that fingerprint), not critical.
//  4. The creation time is not before notBefore.
//  5. The two bytes of the hash tag are the start of the digest that the signature covers, which
//     go-crypto does not compare.
//  6. go-crypto reads the packet, agrees on the creation time and the key expiration time, and the
//     signature verifies with k over userID.
//
// It reads no clock: the expiry is not compared with the time of the check.
func checkCertification(pkt []byte, k *key, userID string, notBefore time.Time) (cert certification, err error) {
	defer func() {
		if r := recover(); r != nil {
			cert, err = certification{}, certError("the certification could not be read")
		}
	}()
	tag, body, rest, err := splitPacket(pkt)
	if err != nil || tag != tagSignature || len(rest) != 0 {
		return cert, certError("the bytes are not one signature packet")
	}
	if len(body) > maxCertificationBody {
		return cert, certError(fmt.Sprintf("the certification is longer than %d bytes", maxCertificationBody))
	}
	a, err := readCertificationFields(body)
	if err != nil {
		return cert, err
	}
	cert, err = checkCertificationShape(a, k)
	if err != nil {
		return certification{}, err
	}
	if cert.created.Before(notBefore) {
		return certification{}, certError("the certification is dated before the key or before the certification that precedes it")
	}
	if err := checkCertificationHashTag(a, k, userID); err != nil {
		return certification{}, err
	}
	if err := verifyCertification(pkt, cert, k, userID); err != nil {
		return certification{}, err
	}
	return cert, nil
}

// readCertificationFields counts the subpackets of both areas, reads them, checks the fixed fields
// and the two numbers of the signature, and returns the areas.
func readCertificationFields(body []byte) (sigAreas, error) {
	var a sigAreas
	if len(body) < 6 || body[0] != 4 {
		return a, certError("the certification is not a version 4 signature")
	}
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	if len(body) < 6+hl+2 {
		return a, certError("the hashed area runs past the packet")
	}
	if _, err := scanArea(body[6:6+hl], maxBindingSubpackets); err != nil {
		return a, certError("the hashed area is not a list of at most 32 whole subpackets")
	}
	ul := int(binary.BigEndian.Uint16(body[6+hl : 8+hl]))
	if len(body) < 8+hl+ul {
		return a, certError("the unhashed area runs past the packet")
	}
	if _, err := scanArea(body[8+hl:8+hl+ul], maxBindingSubpackets); err != nil {
		return a, certError("the unhashed area is not a list of at most 32 whole subpackets")
	}
	a, err := splitSig(body)
	if err != nil {
		return sigAreas{}, certError("the certification does not read to its end")
	}
	if a.sigType != sigPositiveCertification || a.algo != algoECDSA || a.hash != hashSHA384 {
		return sigAreas{}, certError("the certification is not a type 0x13 signature with ECDSA and SHA-384")
	}
	if len(a.rest) < 2 {
		return sigAreas{}, certError("the certification has no hash tag")
	}
	_, tail, err := readMPI(a.rest[2:])
	if err == nil {
		_, tail, err = readMPI(tail)
	}
	if err != nil || len(tail) != 0 {
		return sigAreas{}, certError("the certification does not hold exactly two numbers after its hash tag")
	}
	return a, nil
}

// checkCertificationShape holds the subpackets to the set of the page and returns the creation time
// and the key expiration time that they hold.
func checkCertificationShape(a sigAreas, k *key) (certification, error) {
	if len(a.hashed) != 4 {
		return certification{}, certError("the hashed area has not exactly four subpackets")
	}
	if len(a.unhashed) != 1 {
		return certification{}, certError("the unhashed area has not exactly one subpacket")
	}
	for _, sp := range a.hashed {
		if sp.critical != (sp.typ == spKeyExpiration) {
			return certification{}, certError(fmt.Sprintf("the subpacket of type %d has the wrong critical bit", sp.typ))
		}
	}
	if a.unhashed[0].critical {
		return certification{}, certError("the subpacket of the unhashed area is marked critical")
	}
	created, ok := find(a.hashed, spCreationTime)
	if !ok || len(created) != 4 {
		return certification{}, certError("the hashed area has not one creation time of 4 bytes")
	}
	flags, ok := find(a.hashed, spKeyFlags)
	if !ok || len(flags) != 1 || flags[0] != flagCertify {
		return certification{}, certError("the hashed area has not one key flags subpacket that is 0x01 (certify only)")
	}
	life, ok := find(a.hashed, spKeyExpiration)
	if !ok || len(life) != 4 || binary.BigEndian.Uint32(life) == 0 {
		return certification{}, certError("the hashed area has not one key expiration time of 4 bytes that is not zero")
	}
	fp, ok := find(a.hashed, spIssuerFingerprint)
	if !ok || !bytes.Equal(fp, append([]byte{4}, k.fp...)) {
		return certification{}, certError("the hashed area has not one issuer fingerprint that is the fingerprint of the key")
	}
	id, ok := find(a.unhashed, spIssuerKeyID)
	if !ok || !bytes.Equal(id, k.keyID) {
		return certification{}, certError("the unhashed area has not exactly the issuer key ID of the key")
	}
	return certification{
		created: time.Unix(int64(binary.BigEndian.Uint32(created)), 0).UTC(),
		life:    binary.BigEndian.Uint32(life),
	}, nil
}

// checkCertificationHashTag holds the two bytes after the unhashed area to the start of the digest
// that the signature covers, which go-crypto does not compare (RFC 9580, section 5.2.4): so that no
// byte of the packet can change and leave the certification accepted.
func checkCertificationHashTag(a sigAreas, k *key, userID string) error {
	n := len(userID)
	trailer := []byte{4, 0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(a.fields)))
	h := sha512.New384()
	h.Write(hashPrefix(k.body))
	h.Write([]byte{0xB4, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	h.Write([]byte(userID))
	h.Write(a.fields)
	h.Write(trailer)
	if !bytes.Equal(a.rest[:2], h.Sum(nil)[:2]) {
		return certError("the hash tag of the certification is not the start of its digest")
	}
	return nil
}

// verifyCertification reads the packet with go-crypto, which must agree with the fields read here,
// and verifies the signature with the key over the user ID.
func verifyCertification(pkt []byte, cert certification, k *key, userID string) error {
	p, err := packet.Read(bytes.NewReader(pkt))
	if err != nil {
		return certError("the certification is not read by a second reader")
	}
	sig, ok := p.(*packet.Signature)
	if !ok || !sig.CreationTime.Equal(cert.created) || sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs != cert.life {
		return certError("a second reader does not read the certification as it is here")
	}
	if err := k.pk.VerifyUserIdSignature(userID, k.pk, sig); err != nil {
		return certError("the certification does not verify with the key over the user ID")
	}
	return nil
}
