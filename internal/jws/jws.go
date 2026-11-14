// Package jws reads and checks the two forms of JSON Web Signature (RFC 7515) that a root list
// needs, and nothing more: the detached general serialisation of root-list.jws and the compact
// serialisation of a removal authorisation (docs/reference/root-list.md, "The signature" and "The
// removal authorisation"). The algorithm is ES384 only (RFC 7518, section 3.4): ECDSA on P-384 with
// SHA-384, the signature the 96 bytes of r and s, each 48 bytes, and never an ASN.1 sequence.
//
// How a wrong reading is made impossible, in the order a hostile file would try it:
//
//   - The signature covers the text of the protected header exactly as it was read and the
//     Base64url of the payload bytes exactly as they were read; nothing is parsed and written
//     again before it is checked ([SigningInput]). A header is decoded only to be read, and the
//     text that was decoded is the text that is hashed.
//   - Every Base64 text must be the one spelling that the encoder writes: the alphabet of the
//     form, no padding for Base64url, padding for the standard form, zero padding bits, no
//     line break. The standard decoder of Go skips line breaks and accepts padding bits that are
//     not zero, so each text is decoded and written again, and must come back the same.
//   - The only headers are the four of the page: alg, kid, typ and x5c, each once. The reader
//     fills a closed set of members and refuses every other (crit, b64, jwk, jku, x5u, x5t,
//     zip, cty, a second kid, a member in another letter case), so no header can change how the
//     signature is computed or where its key comes from.
//   - alg is the text ES384 and nothing else ("none", HS384, RS384, ES256 are refused as text, so
//     the algorithm never comes from the file's say-so). typ is the text the caller asks for, so
//     a signature over another kind of document is not read as this one (RFC 8725, section 3.11).
//   - x5c is a list of exactly one certificate. It is parsed only to read its public key; its
//     validity period, issuer, constraints and chain are not looked at, and it is never trusted
//     as a certificate. The kid must equal the SHA-256 of that key's SubjectPublicKeyInfo, so a
//     kid cannot name one key and carry another.
//   - A signature that is not 96 bytes, or whose r or s is zero or not below the order of the
//     curve, or whose key is not on P-384, does not verify.
//
// Every error of the readers wraps [ErrMalformed]; every error of a check of a signature wraps
// [ErrSignature]. A text from the file that an error shows is shown by package jsonset (printable
// ASCII only).
package jws

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
)

// AlgES384 is the one algorithm: ECDSA on P-384 with SHA-384.
const AlgES384 = "ES384"

// SignatureSize is the size of an ES384 signature: r and s, 48 bytes each.
const SignatureSize = 96

// MaxBytes is the most bytes that a reader of this package takes: 256 KiB, the limit of the JSON
// files of ritueel.
const MaxBytes = strictjson.DefaultMaxBytes

// ErrMalformed is wrapped by every error of the readers.
var ErrMalformed = errors.New("malformed JWS")

// ErrSignature is wrapped by every error of a signature that does not verify.
var ErrSignature = errors.New("the signature does not verify")

// Header is the protected header of a signature, with the four members that the page allows.
type Header struct {
	// Alg is the algorithm, always AlgES384 once read.
	Alg string
	// Kid is the SHA-256 of the SubjectPublicKeyInfo of the key in X5C, lower-case hexadecimal.
	Kid string
	// Typ is the type of the signed document, the one the caller asked for.
	Typ string
	// X5C is the list of certificates as Base64 of the DER; always one entry once read.
	X5C []string
}

// Signature is one signature of a general JWS.
type Signature struct {
	// Protected is the Base64url text of the protected header exactly as it was read; it is what
	// the signature covers, and it is never written again.
	Protected string
	// Header is the protected header, read from Protected.
	Header Header
	// Sig is the signature: r and s, 96 bytes.
	Sig []byte
	// Cert is the certificate of X5C. It is parsed to read its public key and for nothing else.
	Cert *x509.Certificate
}

// General is a general JWS with a detached payload.
type General struct {
	// Signatures are the signatures in the order of the file; there is at least one and no two
	// have the same Kid.
	Signatures []Signature
}

// Compact is a compact JWS with the payload attached.
type Compact struct {
	// Protected is the Base64url text of the protected header exactly as it was read.
	Protected string
	// Header is the protected header, read from Protected.
	Header Header
	// Payload is the decoded payload.
	Payload []byte
	// PayloadText is the Base64url text of the payload exactly as it was read.
	PayloadText string
	// Sig is the signature: r and s, 96 bytes.
	Sig []byte
	// Cert is the certificate of the header's X5C, parsed to read its key.
	Cert *x509.Certificate
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// headerJSON is what the protected header is read into. A pointer tells a member that is absent
// from one that is empty.
type headerJSON struct {
	Alg *string  `json:"alg"`
	Kid *string  `json:"kid"`
	Typ *string  `json:"typ"`
	X5C []string `json:"x5c"`
}

type signatureJSON struct {
	Protected *string `json:"protected"`
	Signature *string `json:"signature"`
}

type generalJSON struct {
	Signatures []signatureJSON `json:"signatures"`
}

// ParseGeneral reads the detached general JWS of root-list.jws: one JSON object, under the rules
// of package strictjson, whose only member is signatures, a list of one or more objects that
// each have exactly the members protected and signature, both Base64url without padding. There is
// no payload member and no unprotected header. Each protected header has exactly alg (ES384),
// kid, typ (the text typ) and x5c (one certificate, whose key has the SHA-256 kid), and no two
// signatures have one kid. The file is not required to be in canonical form: the signature covers
// the text of each protected header, and the object around it is read, not signed. Every error
// wraps ErrMalformed.
func ParseGeneral(data []byte, typ string) (*General, error) {
	var g generalJSON
	if err := strictjson.Unmarshal(data, &g, strictjson.Options{MaxBytes: MaxBytes}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if len(g.Signatures) == 0 {
		return nil, malformed("signatures is missing or empty")
	}
	out := &General{Signatures: make([]Signature, 0, len(g.Signatures))}
	seen := make(map[string]bool, len(g.Signatures))
	for i, s := range g.Signatures {
		if s.Protected == nil || s.Signature == nil {
			return nil, malformed("signature %d must have the members protected and signature", i)
		}
		hdr, cert, err := readProtected(*s.Protected, typ)
		if err != nil {
			return nil, fmt.Errorf("signature %d: %w", i, err)
		}
		sig, err := decodeBase64URL(*s.Signature)
		if err != nil {
			return nil, malformed("signature %d: the signature is not Base64url without padding", i)
		}
		if len(sig) != SignatureSize {
			return nil, malformed("signature %d: the signature is %d bytes, ES384 needs %d (r and s, not ASN.1)", i, len(sig), SignatureSize)
		}
		if seen[hdr.Kid] {
			return nil, malformed("signature %d: the kid appears twice", i)
		}
		seen[hdr.Kid] = true
		out.Signatures = append(out.Signatures, Signature{Protected: *s.Protected, Header: hdr, Sig: sig, Cert: cert})
	}
	return out, nil
}

// ParseCompact reads a compact JWS, header.payload.signature: ASCII, three non-empty parts of
// Base64url without padding separated by two dots, no white space and no trailing newline, with
// the protected header as for ParseGeneral and the type typ. Every error wraps ErrMalformed.
func ParseCompact(s, typ string) (*Compact, error) {
	if len(s) > MaxBytes {
		return nil, malformed("longer than %d bytes", MaxBytes)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, malformed("not three parts separated by two dots")
	}
	hdr, cert, err := readProtected(parts[0], typ)
	if err != nil {
		return nil, err
	}
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, malformed("the payload is not Base64url without padding")
	}
	sig, err := decodeBase64URL(parts[2])
	if err != nil {
		return nil, malformed("the signature is not Base64url without padding")
	}
	if len(sig) != SignatureSize {
		return nil, malformed("the signature is %d bytes, ES384 needs %d (r and s, not ASN.1)", len(sig), SignatureSize)
	}
	return &Compact{Protected: parts[0], Header: hdr, Payload: payload, PayloadText: parts[1], Sig: sig, Cert: cert}, nil
}

// decodeBase64URL decodes the one spelling of Base64url without padding that an encoder writes. The
// decoder of Go skips a carriage return and a line feed and accepts padding bits that are not
// zero, so the text is written again and must come back the same.
func decodeBase64URL(text string) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != text {
		return nil, ErrMalformed
	}
	return b, nil
}

// decodeBase64 decodes the one spelling of standard Base64 with padding that an encoder writes.
func decodeBase64(text string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(b) != text {
		return nil, ErrMalformed
	}
	return b, nil
}

// readProtected reads the text of a protected header: Base64url of one JSON object with exactly
// the four members, then the certificate of x5c.
func readProtected(text, typ string) (Header, *x509.Certificate, error) {
	raw, err := decodeBase64URL(text)
	if err != nil || len(raw) == 0 {
		return Header{}, nil, malformed("the protected header is not Base64url without padding")
	}
	var h headerJSON
	if err := strictjson.Unmarshal(raw, &h, strictjson.Options{MaxBytes: MaxBytes}); err != nil {
		return Header{}, nil, fmt.Errorf("%w: the protected header: %w", ErrMalformed, err)
	}
	if h.Alg == nil || h.Kid == nil || h.Typ == nil || h.X5C == nil {
		return Header{}, nil, malformed("the protected header must have exactly the members alg, kid, typ and x5c")
	}
	if *h.Alg != AlgES384 {
		return Header{}, nil, malformed("alg is %s, the only algorithm is %s", jsonset.Quote(*h.Alg), AlgES384)
	}
	if *h.Typ != typ {
		return Header{}, nil, malformed("typ is %s, it must be %s", jsonset.Quote(*h.Typ), jsonset.Quote(typ))
	}
	if len(h.X5C) != 1 {
		return Header{}, nil, malformed("x5c holds %d certificates, it must hold exactly one", len(h.X5C))
	}
	der, err := decodeBase64(h.X5C[0])
	if err != nil {
		return Header{}, nil, malformed("the certificate of x5c is not standard Base64 with padding")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Header{}, nil, malformed("the certificate of x5c cannot be read")
	}
	if want := Pin(cert); *h.Kid != want {
		return Header{}, nil, malformed("kid %s is not the SHA-256 of the key in x5c", jsonset.Quote(*h.Kid))
	}
	return Header{Alg: *h.Alg, Kid: *h.Kid, Typ: *h.Typ, X5C: h.X5C}, cert, nil
}

// Pin is the SHA-256 of the DER SubjectPublicKeyInfo of the certificate's key, in lower-case
// hexadecimal: the pin of the root list, and the kid of a signature.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// SigningInput is protected || "." || BASE64URL(payload): the bytes that a signature covers
// (RFC 7515, section 5.1 with the payload detached, appendix F). protected is the text of the
// header as it was read.
func SigningInput(protected string, payload []byte) []byte {
	enc := base64.RawURLEncoding
	out := make([]byte, 0, len(protected)+1+enc.EncodedLen(len(payload)))
	out = append(out, protected...)
	out = append(out, '.')
	return enc.AppendEncode(out, payload)
}

// VerifyES384 checks an ES384 signature: sig is r and s as two integers of 48 bytes each, input is
// the signing input, and the hash is SHA-384. The key must be on P-384, and r and s must each be
// at least 1 and below the order of the curve. The error wraps ErrSignature.
func VerifyES384(pub *ecdsa.PublicKey, input, sig []byte) error {
	if pub == nil || pub.Curve != elliptic.P384() || hasNoPoint(pub) {
		return fmt.Errorf("%w: the key is not an ECDSA key on P-384", ErrSignature)
	}
	// Bytes fails for a point that is not on the curve, which Verify must not be asked about.
	if _, err := pub.Bytes(); err != nil {
		return fmt.Errorf("%w: the key is not a point on P-384", ErrSignature)
	}
	if len(sig) != SignatureSize {
		return fmt.Errorf("%w: the signature is %d bytes, ES384 needs %d", ErrSignature, len(sig), SignatureSize)
	}
	r := new(big.Int).SetBytes(sig[:SignatureSize/2])
	s := new(big.Int).SetBytes(sig[SignatureSize/2:])
	sum := sha512.Sum384(input)
	if !ecdsa.Verify(pub, sum[:], r, s) {
		return ErrSignature
	}
	return nil
}

// hasNoPoint reports whether a key lacks its coordinates, which makes the functions of the
// package ecdsa panic. The fields are read for that and for nothing else.
func hasNoPoint(pub *ecdsa.PublicKey) bool {
	return pub.X == nil || pub.Y == nil //nolint:staticcheck // read only to refuse a key with no point
}

// Verify checks the signature over the detached payload, with the key of its certificate. The
// payload is the bytes that were signed, as they were read. The error wraps ErrSignature.
func (s *Signature) Verify(payload []byte) error {
	return verifyWithCert(s.Cert, SigningInput(s.Protected, payload), s.Sig)
}

// Verify checks the signature of a compact JWS with the key of its certificate. The signing input
// is the first two parts of the text as they were read.
func (c *Compact) Verify() error {
	return verifyWithCert(c.Cert, []byte(c.Protected+"."+c.PayloadText), c.Sig)
}

func verifyWithCert(cert *x509.Certificate, input, sig []byte) error {
	if cert == nil {
		return fmt.Errorf("%w: there is no certificate", ErrSignature)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: the key is not an ECDSA key", ErrSignature)
	}
	return VerifyES384(pub, input, sig)
}
