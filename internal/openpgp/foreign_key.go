package openpgp

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
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

// curveNames names the curves of the object identifiers that OpenPGP keys carry (RFC 9580, section
// 9.2), by the identifier without its length octet.
var curveNames = map[string]string{
	"\x2A\x86\x48\xCE\x3D\x03\x01\x07":         "P-256",
	"\x2B\x81\x04\x00\x22":                     "P-384",
	"\x2B\x81\x04\x00\x23":                     "P-521",
	"\x2B\x24\x03\x03\x02\x08\x01\x01\x07":     "brainpoolP256r1",
	"\x2B\x24\x03\x03\x02\x08\x01\x01\x0B":     "brainpoolP384r1",
	"\x2B\x24\x03\x03\x02\x08\x01\x01\x0D":     "brainpoolP512r1",
	"\x2B\x06\x01\x04\x01\xDA\x47\x0F\x01":     "Ed25519",
	"\x2B\x06\x01\x04\x01\x97\x55\x01\x05\x01": "Curve25519",
	"\x2B\x81\x04\x00\x0A":                     "secp256k1",
}

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
// key packet and the part is what stands before the secret. An algorithm that is not one of the
// list is taken only for a public packet (whole): its length is the body's, and its numbers are not
// read. Any other fault is an [ErrForeignForm].
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
	rest := body[6:]
	var err error
	switch p.alg.ID {
	case algoRSA, algoRSAEncrypt, algoRSASign:
		rest, err = parseRSAPublic(&p, rest)
	case algoElGamal:
		rest, p.alg.Bits, err = readMPIs(rest, 3)
	case algoDSA:
		rest, p.alg.Bits, err = readMPIs(rest, 4)
	case algoECDSA, algoEdDSA:
		rest, err = parseECCPublic(&p, rest, false)
	case algoECDH:
		rest, err = parseECCPublic(&p, rest, true)
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
	if err != nil {
		return p, fail(ErrForeignForm, "the public part of %s is not well formed (%v)", what, err)
	}
	p.length = len(body) - len(rest)
	if whole && len(rest) != 0 {
		return p, fail(ErrForeignForm, "%s has bytes after its public part", what)
	}
	return p, nil
}

// errKeyPart is the cause of a public part that does not read.
type errKeyPart string

func (e errKeyPart) Error() string { return string(e) }

// readMPIs reads count numbers in the strict form and returns what follows and the bit length of
// the first.
func readMPIs(b []byte, count int) (rest []byte, bits int, err error) {
	rest = b
	for i := 0; i < count; i++ {
		var v []byte
		v, rest, err = readMPI(rest)
		if err != nil {
			return nil, 0, errKeyPart("a number is not in the form of RFC 9580 section 3.2")
		}
		if i == 0 {
			bits = (len(v)-1)*8 + bitLen(v[0])
		}
	}
	return rest, bits, nil
}

// parseRSAPublic reads the modulus and the exponent of an RSA key.
func parseRSAPublic(p *fkPublic, b []byte) ([]byte, error) {
	n, rest, err := readMPI(b)
	if err != nil {
		return nil, errKeyPart("the modulus is not in the form of RFC 9580 section 3.2")
	}
	e, rest, err := readMPI(rest)
	if err != nil {
		return nil, errKeyPart("the exponent is not in the form of RFC 9580 section 3.2")
	}
	p.alg.Bits = (len(n)-1)*8 + bitLen(n[0])
	p.rsaN, p.rsaE = bytes.Clone(n), bytes.Clone(e)
	return rest, nil
}

// parseECCPublic reads the object identifier and the point of an ECDSA, EdDSA or ECDH key, and the
// KDF parameters of an ECDH key (RFC 9580, section 5.5.5.6).
func parseECCPublic(p *fkPublic, b []byte, kdf bool) ([]byte, error) {
	if len(b) < 1 || b[0] == 0 || b[0] == 0xFF || len(b) < 1+int(b[0]) {
		return nil, errKeyPart("the curve identifier is cut short")
	}
	oid := b[:1+int(b[0])]
	point, rest, err := readMPI(b[len(oid):])
	if err != nil {
		return nil, errKeyPart("the point is not in the form of RFC 9580 section 3.2")
	}
	p.oid, p.point = bytes.Clone(oid), bytes.Clone(point)
	p.alg.Curve = curveNames[string(oid[1:])]
	if p.alg.Curve == "" {
		p.alg.Curve = "unknown curve"
	}
	if kdf {
		if len(rest) < 4 || rest[0] != 3 || rest[1] != 1 {
			return nil, errKeyPart("the KDF parameters are not the three octets of RFC 9580 section 5.5.5.6")
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
