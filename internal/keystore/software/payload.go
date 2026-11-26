package software

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"ritueel.id/ritueel/internal/openpgp"
)

// The payloads are what a key file holds before the mode wraps it: the PEM of the X.509 key, the
// binary transferable secret key, one signature packet, the text of a JWS. The wrapping of a test
// root is in plain.go. Each parser accepts exactly the shape of the page and nothing else, and
// every refusal is an [ErrKeyFile].

const (
	pemType = "PRIVATE KEY"
	// scalarLen is the length of a P-384 scalar.
	scalarLen = 48
	// pointLen is the length of the uncompressed point of P-384.
	pointLen = 97
)

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP384        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// pkcs8 is a PrivateKeyInfo (RFC 5958) of an EC key: version 0, the algorithm id-ecPublicKey with
// the named curve, and the octet string that holds the ECPrivateKey. It has no attribute and no
// public key of its own, and the parser refuses a structure that has them.
type pkcs8 struct {
	Version int
	Algo    struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}
	Key []byte
}

// ecPrivate is an ECPrivateKey (RFC 5915). The curve is named in the algorithm of the wrapper, so
// the element is absent, or the same curve; the public key is absent, or it is the point of the
// scalar.
type ecPrivate struct {
	Version int
	Key     []byte
	Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	Public  asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ecElements is the number of elements that an ECPrivateKey with the parts that ec has must hold.
func ecElements(ec ecPrivate) int {
	n := 2
	if len(ec.Curve) != 0 {
		n++
	}
	if len(ec.Public.Bytes) != 0 || ec.Public.BitLength != 0 {
		n++
	}
	return n
}

// sequenceLen is the number of elements of the DER SEQUENCE at the start of der, or -1 when it is
// not one. encoding/asn1 reads a structure and ignores an element after the last one it knows, so
// the count is taken apart to refuse an attribute or a field that the page does not have.
func sequenceLen(der []byte) int {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return -1
	}
	n := 0
	for rest := seq.Bytes; len(rest) > 0; n++ {
		var elem asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &elem); err != nil {
			return -1
		}
	}
	return n
}

// encodeX509 writes the PKCS#8 PrivateKeyInfo of the key, PEM-armoured as PRIVATE KEY (RFC 7468).
func encodeX509(priv *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, refuse(ErrParams, "the key cannot be written as PKCS#8")
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

// parseX509 reads the PEM that [encodeX509] writes: one block labelled PRIVATE KEY, no header
// line, LF line ends, lines of 64 characters, and nothing else (the text is compared with the
// block written again). The DER is a PKCS#8 PrivateKeyInfo of an ECDSA key on P-384 with no
// trailing byte, and its public point, when it carries one, is the point of the scalar.
func parseX509(text []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(text)
	if blk == nil {
		return nil, refuse(ErrKeyFile, "no PEM block of the key")
	}
	defer clear(blk.Bytes)
	if blk.Type != pemType || len(blk.Headers) != 0 {
		return nil, refuse(ErrKeyFile, "the PEM block is not one block labelled PRIVATE KEY with no header line")
	}
	again := pem.EncodeToMemory(blk)
	same := bytes.Equal(again, text)
	clear(again)
	if !same {
		return nil, refuse(ErrKeyFile, "the PEM text is not exactly one block of the page and nothing else")
	}
	return parsePKCS8(blk.Bytes)
}

// parsePKCS8 reads a PKCS#8 PrivateKeyInfo of a P-384 key as the page says.
func parsePKCS8(der []byte) (*ecdsa.PrivateKey, error) {
	var info pkcs8
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil || len(rest) != 0 || sequenceLen(der) != 3 {
		return nil, refuse(ErrKeyFile, "the DER is not one PKCS#8 PrivateKeyInfo of an EC key")
	}
	defer clear(info.Key)
	if info.Version != 0 || !info.Algo.Algorithm.Equal(oidECPublicKey) || !info.Algo.Parameters.Equal(oidP384) {
		return nil, refuse(ErrKeyFile, "the key is not an ECDSA key on P-384")
	}
	var ec ecPrivate
	rest, err = asn1.Unmarshal(info.Key, &ec)
	if err != nil || len(rest) != 0 || sequenceLen(info.Key) != ecElements(ec) {
		return nil, refuse(ErrKeyFile, "the ECPrivateKey is not one structure with no trailing byte")
	}
	defer clear(ec.Key)
	if ec.Version != 1 || len(ec.Key) != scalarLen || (len(ec.Curve) != 0 && !ec.Curve.Equal(oidP384)) {
		return nil, refuse(ErrKeyFile, "the ECPrivateKey is not a P-384 scalar of 48 bytes")
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), ec.Key)
	if err != nil {
		return nil, refuse(ErrKeyFile, "the scalar is zero or not below the order of the group")
	}
	if len(ec.Public.Bytes) != 0 || ec.Public.BitLength != 0 {
		point, err := priv.PublicKey.Bytes()
		if err != nil || ec.Public.BitLength != 8*pointLen || !bytes.Equal(ec.Public.Bytes, point) {
			wipe(priv)
			return nil, refuse(ErrKeyFile, "the public point does not match the scalar")
		}
	}
	return priv, nil
}

// parseOpenPGP reads the transferable secret key of the page (see openpgp.ParseSecretKey). A payload
// that is the other form of an OpenPGP key file, the lone secret key packet of an adopted key, is
// refused with a text that says so.
func parseOpenPGP(secret []byte) (*ecdsa.PrivateKey, time.Time, []byte, error) {
	priv, created, cert, err := openpgp.ParseSecretKey(secret)
	if err != nil {
		if isAdoptedForm(secret) {
			return nil, time.Time{}, nil, refuse(ErrKeyFile, "the file holds an adopted key (a lone secret key packet), not a key that ritueel made (a transferable secret key with a user ID)")
		}
		return nil, time.Time{}, nil, fmt.Errorf("%w: the secret key packets are refused: %w", ErrKeyFile, err)
	}
	return priv, created, cert, nil
}

// checkRevocation checks one signature packet that is a version 4 key revocation signature
// (type 0x20) of at most 1 KiB, and nothing after it.
func checkRevocation(sig []byte) error {
	if len(sig) == 0 || len(sig) > maxRevocationSize {
		return refuse(ErrKeyFile, "the revocation signature is empty or longer than 1 KiB")
	}
	r := bytes.NewReader(sig)
	p, err := packet.Read(r)
	if err != nil {
		return refuse(ErrKeyFile, "the revocation signature does not parse as an OpenPGP packet")
	}
	s, ok := p.(*packet.Signature)
	if !ok || r.Len() != 0 || s.Version != 4 || s.SigType != packet.SigTypeKeyRevocation {
		return refuse(ErrKeyFile, "the revocation is not exactly one version 4 signature packet of type 0x20")
	}
	return nil
}

// checkRemoval checks the compact JWS of a removal authorisation: three non-empty parts of Base64url
// text without padding, two dots, at most 4 KiB. Its content is checked by the code that makes
// and uses it, not here.
func checkRemoval(jws []byte) error {
	if len(jws) == 0 || len(jws) > maxRemovalSize {
		return refuse(ErrKeyFile, "the removal authorisation is empty or longer than 4 KiB")
	}
	// The strict decoder of the standard library skips a carriage return and a line feed, so a
	// byte outside the alphabet is refused before it decodes anything.
	for _, b := range jws {
		if !removalByte(b) {
			return refuse(ErrKeyFile, "the removal authorisation holds a byte that is not Base64url text or a dot")
		}
	}
	parts := bytes.Split(jws, []byte{'.'})
	if len(parts) != 3 {
		return refuse(ErrKeyFile, "the removal authorisation is not three parts and two dots")
	}
	for _, part := range parts {
		if len(part) == 0 {
			return refuse(ErrKeyFile, "a part of the removal authorisation is empty")
		}
		if _, err := base64.RawURLEncoding.Strict().DecodeString(string(part)); err != nil {
			return refuse(ErrKeyFile, "a part of the removal authorisation is not Base64url text")
		}
	}
	return nil
}

// removalByte reports whether b is a letter, a digit, a hyphen, an underscore or a dot: the
// alphabet of Base64url without padding (RFC 4648, section 5) and the separator of a compact JWS.
func removalByte(b byte) bool {
	return 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '_' || b == '.'
}
