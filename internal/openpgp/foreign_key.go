package openpgp

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Public-key algorithm numbers (RFC 9580, section 9.1) that the foreign reader names. algoECDSA is
// in frame.go.
const (
	algoRSA        = 1
	algoRSAEncrypt = 2
	algoRSASign    = 3
	algoElGamal    = 16
	algoDSA        = 17
	algoECDH       = 18
	algoEdDSA      = 22 // EdDSA legacy, with an OID for its curve
	algoX25519     = 25
	algoX448       = 26
	algoEd25519    = 27
	algoEd448      = 28
)

// rsaPrimaryBits is the one modulus size of an RSA primary that the reader takes.
const rsaPrimaryBits = 4096

// ed25519OID is the object identifier of the curve Ed25519 in EdDSA legacy keys (RFC 9580, section
// 9.2), with its length octet.
var ed25519OID = []byte{9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}

// curveInfo is what the reader knows of a curve: its name, the length of its public point in the
// form that OpenPGP writes (RFC 9580, section 5.5.5.6 and 9.2) and the octet that the point starts
// with (0x04 for the uncompressed form of a Weierstrass curve, 0x40 for the native form).
type curveInfo struct {
	name  string
	point int
	lead  byte
}

// curves lists the curves of the object identifiers that OpenPGP keys carry, by the identifier
// without its length octet.
var curves = map[string]curveInfo{
	"\x2A\x86\x48\xCE\x3D\x03\x01\x07":         {"P-256", 65, 0x04},
	"\x2B\x81\x04\x00\x22":                     {"P-384", 97, 0x04},
	"\x2B\x81\x04\x00\x23":                     {"P-521", 133, 0x04},
	"\x2B\x24\x03\x03\x02\x08\x01\x01\x07":     {"brainpoolP256r1", 65, 0x04},
	"\x2B\x24\x03\x03\x02\x08\x01\x01\x0B":     {"brainpoolP384r1", 97, 0x04},
	"\x2B\x24\x03\x03\x02\x08\x01\x01\x0D":     {"brainpoolP512r1", 129, 0x04},
	"\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01":     {"Ed25519", 33, 0x40},
	"\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01": {"Curve25519", 33, 0x40},
	"\x2B\x81\x04\x00\x0A":                     {"secp256k1", 65, 0x04},
}

// The bounds of the public numbers of a key packet whose secret follows in the same packet. A cut
// that is made by the length fields of the packet is only as safe as these are tight (see
// [parseForeignPublic]).
const (
	// maxRSAModulusBits and maxElGamalBits bound a modulus or a prime.
	maxRSAModulusBits = 16384
	maxElGamalBits    = 16384
	// maxRSAExponentBytes bounds the public exponent of RSA: 3 bytes, as go-crypto reads at most, and
	// every exponent in use is 17 bits or less. The exponent is the one number that stands last in its
	// packet, so the bound is the most bytes that a wrong length can take from what follows.
	maxRSAExponentBytes = 3
	// maxDSAQBytes bounds the subprime of DSA (at most 512 bits).
	maxDSAQBytes = 64
)

// ForeignAlgorithm names the algorithm of a key and, when the key has one, its size or its curve.
type ForeignAlgorithm struct {
	// ID is the algorithm number of RFC 9580, section 9.1: 1 RSA, 16 ElGamal, 17 DSA, 18 ECDH, 19
	// ECDSA, 22 EdDSA legacy.
	ID uint8
	// Bits is the size of the modulus (RSA) or of the prime (ElGamal, DSA), and 0 for the others.
	Bits int
	// Curve is the name of the curve of ECDSA, EdDSA and ECDH keys ("P-384", "Ed25519",
	// "Curve25519", ...), or "unknown curve" when the object identifier is not one of a fixed list, so
	// that no byte of the file is shown. It is empty for the others.
	Curve string
}

// String is the algorithm as a person reads it: "RSA 4096", "ECDSA P-384", "EdDSA Ed25519", "ECDH
// Curve25519", "DSA 2048", "X25519", or "algorithm 99" for a number that is not named.
func (a ForeignAlgorithm) String() string {
	switch a.ID {
	case algoRSA, algoRSAEncrypt, algoRSASign:
		return fmt.Sprintf("RSA %d", a.Bits)
	case algoElGamal:
		return fmt.Sprintf("ElGamal %d", a.Bits)
	case algoDSA:
		return fmt.Sprintf("DSA %d", a.Bits)
	case algoECDH:
		return "ECDH " + a.Curve
	case algoECDSA:
		return "ECDSA " + a.Curve
	case algoEdDSA:
		return "EdDSA " + a.Curve
	case algoX25519:
		return "X25519"
	case algoX448:
		return "X448"
	case algoEd25519:
		return "Ed25519 (native)"
	case algoEd448:
		return "Ed448 (native)"
	}
	return fmt.Sprintf("algorithm %d", a.ID)
}

// fkPublic is the public part of a version 4 key packet, read.
type fkPublic struct {
	created time.Time
	alg     ForeignAlgorithm
	length  int    // the length of the public part, in bytes: the whole body of a public key packet
	rsaN    []byte // RSA modulus, big-endian, no leading zero
	rsaE    []byte // RSA public exponent
	point   []byte // the point of an ECDSA key (97 bytes, uncompressed), or of an EdDSA key (33 bytes, 0x40 then the key)
	oid     []byte // the object identifier of the curve of an ECC key, with its length octet
}

// versionFault is the refusal of a key that is not version 4, each version with its own reason.
func versionFault(what string, version byte) error {
	switch version {
	case 2, 3:
		return fail(ErrForeignVersion, "%s is a version %d key (RSA only, and its fingerprint is an MD5 hash): only version 4 is read", what, version)
	case 5:
		return fail(ErrForeignVersion, "%s is a version 5 key (a draft form that was never standardised): only version 4 is read", what)
	case 6:
		return fail(ErrForeignVersion, "%s is a version 6 key (RFC 9580): only version 4 is read", what)
	}
	return fail(ErrForeignVersion, "%s has a key version that is not known (%d): only version 4 is read", what, version)
}

// parseForeignPublic reads the public part of the body of a key packet (RFC 9580, section 5.5.2):
// version 4, the creation time, the algorithm and the algorithm's numbers, each number in the strict
// form of readMPI. what names the packet in an error ("the primary key", "a subkey"). With whole
// set, the body is a public key packet and the part must be all of it; otherwise it is a secret
// key packet, the part is what stands before the secret, and every length that the packet gives is
// held to a tight bound for its algorithm: the cut that these lengths make is the line between the
// public certificate and the secret, so a length that could move it into the secret is refused. The
// bounds are: RSA with a modulus of at most 16384 bits and an odd exponent of at most 3 bytes; DSA
// with a prime of 1024, 2048 or 3072 bits, a subprime of at most 64 bytes, and g and y no longer
// than the prime; ElGamal with a prime of 512 to 16384 bits, and g and y no longer than the prime;
// ECDSA, EdDSA and ECDH on a curve of the list [curves] that suits the algorithm, with the point at
// the length and the first octet of the curve; ECDH with the KDF field of RFC 9580 section 5.5.5.6
// (SHA-256, SHA-384 or SHA-512 and AES); and the native keys at their fixed sizes. An algorithm that
// is not one of the list is taken only for a public packet (whole): its length is the body's, and
// its numbers are not read. A curve or an algorithm that is refused is an [ErrForeignAlgorithm],
// any other fault an [ErrForeignForm].
func parseForeignPublic(what string, body []byte, whole bool) (fkPublic, error) {
	var p fkPublic
	if len(body) < 6 {
		return p, fail(ErrForeignForm, "%s is cut short before its algorithm", what)
	}
	if body[0] != 4 {
		return p, versionFault(what, body[0])
	}
	p.created = time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0).UTC()
	p.alg.ID = body[5]
	strict := !whole
	rest := body[6:]
	var err error
	switch p.alg.ID {
	case algoRSA, algoRSAEncrypt, algoRSASign:
		rest, err = parseRSAPublic(&p, rest, strict)
	case algoElGamal:
		rest, err = parseElGamalPublic(&p, rest, strict)
	case algoDSA:
		rest, err = parseDSAPublic(&p, rest, strict)
	case algoECDSA, algoEdDSA:
		rest, err = parseECCPublic(&p, rest, false, strict)
	case algoECDH:
		rest, err = parseECCPublic(&p, rest, true, strict)
	case algoX25519, algoEd25519:
		rest, err = fixedKey(rest, 32)
	case algoX448:
		rest, err = fixedKey(rest, 56)
	case algoEd448:
		rest, err = fixedKey(rest, 57)
	default:
		if !whole {
			return p, fail(ErrForeignAlgorithm, "%s has an algorithm (%d) whose public part this reader cannot delimit", what, p.alg.ID)
		}
		p.length = len(body)
		return p, nil
	}
	var refused errKeyAlgo
	if errors.As(err, &refused) {
		return p, fail(ErrForeignAlgorithm, "%s: %v", what, refused)
	}
	if err != nil {
		return p, fail(ErrForeignForm, "the public part of %s is not well formed (%v)", what, err)
	}
	p.length = len(body) - len(rest)
	if whole && len(rest) != 0 {
		return p, fail(ErrForeignForm, "%s has bytes after its public part", what)
	}
	return p, nil
}

// errKeyPart is the cause of a public part that does not read, and errKeyAlgo the cause of one that
// reads and names a curve or a size that the reader does not take.
type (
	errKeyPart string
	errKeyAlgo string
)

func (e errKeyPart) Error() string { return string(e) }
func (e errKeyAlgo) Error() string { return string(e) }

// mpiBits is the bit length of a number that readMPI returned.
func mpiBits(v []byte) int { return (len(v)-1)*8 + bitLen(v[0]) }

// parseRSAPublic reads the modulus and the exponent of an RSA key. With strict, the modulus is at most
// maxRSAModulusBits long and the exponent is odd, at least 3 and at most maxRSAExponentBytes long: this
// is the check that stops an exponent whose length field claims bytes of the secret that follows it.
func parseRSAPublic(p *fkPublic, b []byte, strict bool) ([]byte, error) {
	n, rest, err := readMPI(b)
	if err != nil {
		return nil, errKeyPart("the modulus is not in the form of RFC 9580 section 3.2")
	}
	e, rest, err := readMPI(rest)
	if err != nil {
		return nil, errKeyPart("the exponent is not in the form of RFC 9580 section 3.2")
	}
	if strict && (mpiBits(n) > maxRSAModulusBits || len(e) > maxRSAExponentBytes || e[len(e)-1]&1 == 0 || (len(e) == 1 && e[0] < 3)) {
		return nil, errKeyPart("the modulus or the exponent of an RSA key is outside the bounds of this reader")
	}
	p.alg.Bits = mpiBits(n)
	p.rsaN, p.rsaE = bytes.Clone(n), bytes.Clone(e)
	return rest, nil
}

// parseElGamalPublic reads p, g and y of an ElGamal key.
func parseElGamalPublic(p *fkPublic, b []byte, strict bool) ([]byte, error) {
	var v [3][]byte
	rest := b
	for i := range v {
		var err error
		if v[i], rest, err = readMPI(rest); err != nil {
			return nil, errKeyPart("a number is not in the form of RFC 9580 section 3.2")
		}
	}
	if strict && (mpiBits(v[0]) < 512 || mpiBits(v[0]) > maxElGamalBits || len(v[1]) > len(v[0]) || len(v[2]) > len(v[0])) {
		return nil, errKeyPart("a number of an ElGamal key is outside the bounds of this reader")
	}
	p.alg.Bits = mpiBits(v[0])
	return rest, nil
}

// parseDSAPublic reads p, q, g and y of a DSA key.
func parseDSAPublic(p *fkPublic, b []byte, strict bool) ([]byte, error) {
	var v [4][]byte
	rest := b
	for i := range v {
		var err error
		if v[i], rest, err = readMPI(rest); err != nil {
			return nil, errKeyPart("a number is not in the form of RFC 9580 section 3.2")
		}
	}
	bits := mpiBits(v[0])
	if strict && ((bits != 1024 && bits != 2048 && bits != 3072) || len(v[1]) > maxDSAQBytes || len(v[2]) > len(v[0]) || len(v[3]) > len(v[0])) {
		return nil, errKeyPart("a number of a DSA key is outside the bounds of this reader")
	}
	p.alg.Bits = bits
	return rest, nil
}

// eccCurveFits tells whether an algorithm takes a curve: EdDSA legacy only Ed25519, ECDSA no curve of
// the native form, ECDH no Ed25519.
func eccCurveFits(alg byte, name string) bool {
	switch alg {
	case algoEdDSA:
		return name == "Ed25519"
	case algoECDSA:
		return name != "Ed25519" && name != "Curve25519"
	}
	return name != "Ed25519"
}

// parseECCPublic reads the object identifier and the point of an ECDSA, EdDSA or ECDH key, and the
// KDF parameters of an ECDH key (RFC 9580, section 5.5.5.6). With strict, the curve must be one of
// [curves] and suit the algorithm, the point must have the length and the first octet of the curve, and
// the KDF field must be 3, 1, a hash of SHA-256, SHA-384 or SHA-512 and a cipher of AES.
func parseECCPublic(p *fkPublic, b []byte, kdf, strict bool) ([]byte, error) {
	if len(b) < 1 || b[0] == 0 || b[0] == 0xFF || len(b) < 1+int(b[0]) {
		return nil, errKeyPart("the curve identifier is cut short")
	}
	oid := b[:1+int(b[0])]
	point, rest, err := readMPI(b[len(oid):])
	if err != nil {
		return nil, errKeyPart("the point is not in the form of RFC 9580 section 3.2")
	}
	info, known := curves[string(oid[1:])]
	if strict {
		switch {
		case !known:
			return nil, errKeyAlgo("the curve is not one that this reader knows")
		case !eccCurveFits(p.alg.ID, info.name):
			return nil, errKeyAlgo("the curve " + info.name + " does not go with the algorithm")
		case len(point) != info.point || point[0] != info.lead:
			return nil, errKeyPart("the point does not have the length or the form of its curve")
		}
	}
	p.oid, p.point = bytes.Clone(oid), bytes.Clone(point)
	p.alg.Curve = info.name
	if !known {
		p.alg.Curve = "unknown curve"
	}
	if kdf {
		if len(rest) < 4 || rest[0] != 3 || rest[1] != 1 {
			return nil, errKeyPart("the KDF parameters are not the three octets of RFC 9580 section 5.5.5.6")
		}
		if strict && ((rest[2] != 8 && rest[2] != 9 && rest[2] != 10) || (rest[3] != 7 && rest[3] != 8 && rest[3] != 9)) {
			return nil, errKeyPart("the KDF parameters name a hash or a cipher that this reader does not take")
		}
		rest = rest[4:]
	}
	return rest, nil
}

// fixedKey reads a native key of a fixed size (RFC 9580, section 5.5.5).
func fixedKey(b []byte, size int) ([]byte, error) {
	if len(b) < size {
		return nil, errKeyPart("the key is cut short")
	}
	return b[size:], nil
}

// agreePublic is the second parser of a public key packet: go-crypto reads the packet pkt (the public
// part of a key, with a header of tag 6 or 14) as a version 4 public key or subkey, with the
// fingerprint fp that this package computed, and writes it again to exactly the body pubBody. A
// packet that go-crypto cannot read is an [ErrForeignAlgorithm]; one that it reads as something
// else is an [ErrForeignForm].
func agreePublic(pkt, pubBody, fp []byte, subkey bool) (*packet.PublicKey, error) {
	var pk *packet.PublicKey
	err := safely(func() error {
		var err error
		pk, err = goCryptoPublic(pkt)
		return err
	})
	if err != nil {
		return nil, fail(ErrForeignAlgorithm, "go-crypto cannot read the public part of the key packet")
	}
	var again bytes.Buffer
	if safely(func() error { return pk.Serialize(&again) }) != nil {
		return nil, fail(ErrForeignForm, "go-crypto cannot write the public part of the key packet again")
	}
	_, _, body, rest, err := splitForeignPacket(again.Bytes(), 1)
	if err != nil || len(rest) != 0 || pk.IsSubkey != subkey || !bytes.Equal(pk.Fingerprint, fp) || !bytes.Equal(body, pubBody) {
		return nil, fail(ErrForeignForm, "go-crypto does not read the public part of the key packet as it is read here")
	}
	return pk, nil
}

// foreignFingerprint is the version 4 fingerprint of the public part of a key packet: SHA-1 over
// 0x99, the two-octet length and the body (RFC 9580, section 5.5.4.1). The body of a packet is at most
// [MaxForeignPacketBytes], and a fingerprint is defined only for a body that fits two octets: a
// longer one gets none, and is an error.
func foreignFingerprint(pub []byte) ([]byte, error) {
	if len(pub) > 0xFFFF {
		return nil, fail(ErrForeignForm, "a key packet is longer than 65535 bytes, which a version 4 fingerprint cannot cover")
	}
	sum := sha1.Sum(hashPrefix(pub)) // SHA-1 is what the standard defines here, not a choice
	return sum[:], nil
}

// fingerprintHex is a fingerprint as 40 lower-case hexadecimal digits, and its key ID is the last 16.
func fingerprintHex(fp []byte) (full, id string) {
	full = hex.EncodeToString(fp)
	return full, full[24:]
}
