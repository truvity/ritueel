package pki

import (
	"encoding/asn1"
	"errors"
	"math/big"
	"time"
)

// The DER writer. A certificate is built by hand from these few functions, so that every byte of
// it is written here and no reflection decides an encoding (a string type, an optional member, a
// time format).

const (
	tagBoolean         = 0x01
	tagInteger         = 0x02
	tagBitString       = 0x03
	tagOctetString     = 0x04
	tagOID             = 0x06
	tagUTF8String      = 0x0c
	tagUTCTime         = 0x17
	tagGeneralizedTime = 0x18
	tagSequence        = 0x30
	tagSet             = 0x31
	tagVersion         = 0xa0 // [0] EXPLICIT
	tagExtensions      = 0xa3 // [3] EXPLICIT
	tagAKIKeyID        = 0x80 // [0] IMPLICIT OCTET STRING
)

var (
	oidCommonName       = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// algECDSAWithSHA384 is the AlgorithmIdentifier of ecdsa-with-SHA384 (RFC 5758, section 3.2): the
// OID 1.2.840.10045.4.3.3 and no parameters.
var algECDSAWithSHA384 = []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}

// maxContent is the longest content that tlv writes: a definite length of at most three octets
// (0x83 and three octets), so 2^24 - 1 = 16,777,215 octets. A longer element is an error, never a
// wrong length.
const maxContent = 1<<24 - 1

// maxBodyLen is the longest TBSCertificate that this package writes, signs or assembles: 16,777,096
// octets. It is the one limit on the size of a body, and tbs checks it for every body that a
// builder writes (so no body is returned that [Assemble] cannot always wrap) and readBody for every
// body that [Assemble] is given. A certificate is one sequence of the body, the
// algorithm (12 octets) and the signature as a BIT STRING (at most 107 octets: 3 octets of header
// and unused bits, and a DER ECDSA value of P-384 of at most 104), and the content of one sequence
// is at most maxContent. A request is held to [MaxRequestSize] long before this, so only a caller's
// own bytes (the issuer name, or a body given to [Assemble]) can reach the limit.
const maxBodyLen = maxContent - 12 - 107

// errBodyTooLong is the error of tbs for a body longer than maxBodyLen. The caller wraps it with the
// kind of error that fits what it was building.
var errBodyTooLong = errors.New("the body is longer than 16777096 octets, the most that a certificate can hold")

// errTooLong is the error of tlv for content that it cannot write. The caller wraps it with the
// kind of error that fits what it was building.
var errTooLong = errors.New("an element is longer than 16777215 octets")

// tlv is one DER element with a definite length. It returns errTooLong for content longer than
// maxContent.
func tlv(tag byte, parts ...[]byte) ([]byte, error) {
	n := 0
	for _, p := range parts {
		n += len(p)
		if n > maxContent {
			return nil, errTooLong
		}
	}
	out := make([]byte, 0, n+5)
	out = append(out, tag)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	for _, p := range parts {
		out = append(out, p...)
	}
	return out, nil
}

func seq(parts ...[]byte) ([]byte, error) { return tlv(tagSequence, parts...) }

// short is tlv for content that is known to be short: a few hundred octets at most, built from
// constants, a serial, a time or a key identifier. Content that long that fails is a fault of this
// package and not of an input, so it panics.
func short(tag byte, parts ...[]byte) []byte {
	out, err := tlv(tag, parts...)
	if err != nil {
		panic("pki: content that is known to be short is too long")
	}
	return out
}

func shortSeq(parts ...[]byte) []byte { return short(tagSequence, parts...) }

// oid is an OBJECT IDENTIFIER. The ones used here are fixed and valid; the encoder of the
// standard library writes the arcs.
func oid(o asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(o)
	if err != nil {
		panic("pki: invalid built-in object identifier " + o.String())
	}
	return der
}

// integer is a positive INTEGER: the shortest two's complement, with a leading zero octet when
// the first octet has its high bit set.
func integer(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return short(tagInteger, b)
}

// timeValue is UTCTime from 1950 to 2049 and GeneralizedTime otherwise (RFC 5280, section
// 4.1.2.5), in UTC with a Z and whole seconds.
func timeValue(t time.Time) []byte {
	t = t.UTC()
	if y := t.Year(); y >= 1950 && y < 2050 {
		return short(tagUTCTime, []byte(t.Format("060102150405Z")))
	}
	return short(tagGeneralizedTime, []byte(t.Format("20060102150405Z")))
}

// commonName is a Name of one RDN of one attribute, the common name, as a UTF8String (RFC 5280,
// section 4.1.2.4: a CA of today writes UTF8String).
func commonName(cn string) []byte {
	return shortSeq(short(tagSet, shortSeq(oid(oidCommonName), short(tagUTF8String, []byte(cn)))))
}

// extension is one Extension. A critical one writes BOOLEAN TRUE; one that is not critical
// leaves the member out, which is DER for the default FALSE. It returns errTooLong for a value that
// is too long to write.
func extension(id asn1.ObjectIdentifier, critical bool, value []byte) ([]byte, error) {
	parts := [][]byte{oid(id)}
	if critical {
		parts = append(parts, short(tagBoolean, []byte{0xff}))
	}
	octets, err := tlv(tagOctetString, value)
	if err != nil {
		return nil, err
	}
	return seq(append(parts, octets)...)
}

// The key usage bits of RFC 5280, section 4.2.1.3, numbered from the most significant bit.
const (
	usageDigitalSignature = 0
	usageKeyCertSign      = 5
	usageCRLSign          = 6
)

// keyUsageValue is the value of a key usage extension: a BIT STRING in the named-bit form of DER
// (the trailing zero bits are left out, and the first octet says how many bits of the last one
// are unused). The bits all lie in the first octet. It returns the empty slice when no bit is set.
func keyUsageValue(bits ...int) []byte {
	var b byte
	for _, bit := range bits {
		b |= 0x80 >> uint(bit)
	}
	if b == 0 {
		return nil
	}
	unused := 0
	for b&(1<<uint(unused)) == 0 {
		unused++
	}
	return short(tagBitString, []byte{byte(unused), b})
}

// basicConstraintsCA0 is the value of the basic constraints of an intermediate: cA true, path
// length 0 (RFC 5280, section 4.2.1.9).
var basicConstraintsCA0 = []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}

// basicConstraintsCA is the value of the basic constraints of a root: cA true, no path length.
var basicConstraintsCA = []byte{0x30, 0x03, 0x01, 0x01, 0xff}

// subjectKeyIDValue is the value of a subject key identifier: an OCTET STRING.
func subjectKeyIDValue(id []byte) []byte { return short(tagOctetString, id) }

// authorityKeyIDValue is the value of an authority key identifier that holds only the
// keyIdentifier: SEQUENCE { [0] OCTET STRING }.
func authorityKeyIDValue(id []byte) []byte { return shortSeq(short(tagAKIKeyID, id)) }

// tbs assembles a TBSCertificate of version 3 (RFC 5280, section 4.1). It returns errTooLong when
// the parts are too long to write, and errBodyTooLong for a body longer than maxBodyLen.
func tbs(serial *big.Int, issuer []byte, notBefore, notAfter time.Time, subject, spki []byte, exts [][]byte) ([]byte, error) {
	list, err := seq(exts...)
	if err != nil {
		return nil, err
	}
	extensions, err := tlv(tagExtensions, list)
	if err != nil {
		return nil, err
	}
	body, err := seq(
		short(tagVersion, integer(big.NewInt(2))),
		integer(serial),
		algECDSAWithSHA384,
		issuer,
		shortSeq(timeValue(notBefore), timeValue(notAfter)),
		subject,
		spki,
		extensions,
	)
	if err != nil {
		return nil, err
	}
	if len(body) > maxBodyLen {
		return nil, errBodyTooLong
	}
	return body, nil
}
