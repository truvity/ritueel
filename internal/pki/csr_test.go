package pki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // a request signed with SHA-1 is a hostile shape that the package must refuse
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// testCSR is a certificate request that a test builds from parts, as bytes. The package reads a request
// from its bytes and trusts nothing else, so a test that wants a hostile request writes the bytes: the
// subject, the key, the attributes, the extensions, the algorithm, the version and the signature are
// each a field, and DER signs whatever the fields say with the key. A test edits a field and calls DER
// again, so the request is always one that its key signed, whatever is wrong with its parts. Keys are
// made in memory.
type testCSR struct {
	// Key signs the request and is the key in it unless RawSubjectPublicKeyInfo is set.
	Key *ecdsa.PrivateKey
	// RawSubject is the DER of the subject name.
	RawSubject []byte
	// Extensions are the extensions that the one attribute asks for.
	Extensions []pkix.Extension
	// RawSubjectPublicKeyInfo, when set, replaces the SubjectPublicKeyInfo that the key encodes to.
	RawSubjectPublicKeyInfo []byte
	// PublicKey is the public key of the request, for a test that reads it (set for fixtures).
	PublicKey crypto.PublicKey

	// Version is the DER of the version, "02 01 00" when nil.
	Version []byte
	// Algorithm is the DER of the signature algorithm, ecdsa-with-SHA384 when nil.
	Algorithm []byte
	// Digest is the hash that the signature is over, SHA-384 when 0.
	Digest crypto.Hash
	// Attributes, when not nil, are the DER of the attributes (each one a whole Attribute) in place of
	// the one extensionRequest that Extensions make.
	Attributes [][]byte
	// ExtensionsDER, when not nil, is the DER of the Extensions value (the sequence) in place of the one
	// that Extensions make.
	ExtensionsDER []byte
	// InfoTrailer is put after the attributes in the request info, OuterTrailer after the signature
	// inside the request, AfterRequest after the request.
	InfoTrailer, OuterTrailer, AfterRequest []byte
	// SignatureEdit, when set, changes the DER of the signature before it is put in the bit string, and
	// UnusedBits is the first octet of the bit string.
	SignatureEdit func([]byte) []byte
	UnusedBits    byte
	// InfoTag and AttributesTag are the tags of the request info (0x30 when 0) and of the attributes (0xa0 when 0);
	// both are under the signature. SignatureElement, when set, rewrites the whole element that holds the
	// signature, which is not under it.
	InfoTag, AttributesTag byte
	SignatureElement       func([]byte) []byte
	// Fixed, when set, is the whole request, and every other field is only for reading.
	Fixed []byte
}

var algECDSAWithSHA384DER = []byte{0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03}

// ExtensionsValue is the DER of the extensions, as the one attribute holds them.
func extensionsValue(exts []pkix.Extension) []byte {
	var list [][]byte
	for _, e := range exts {
		parts := [][]byte{mustOIDOf(e.Id)}
		if e.Critical {
			parts = append(parts, []byte{0x01, 0x01, 0xff})
		}
		parts = append(parts, tlv(0x04, e.Value))
		list = append(list, tlv(0x30, parts...))
	}
	return tlv(0x30, list...)
}

func mustOIDOf(id asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(id)
	if err != nil {
		panic(err)
	}
	return der
}

// extensionRequestAttribute is the one attribute of a request: the extensionRequest with one value.
func extensionRequestAttribute(value []byte) []byte {
	return tlv(0x30, mustOIDOf(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}), tlv(0x31, value))
}

// SPKI is the SubjectPublicKeyInfo that the request has.
func (c *testCSR) SPKI() []byte {
	if c.RawSubjectPublicKeyInfo != nil {
		return c.RawSubjectPublicKeyInfo
	}
	der, err := x509.MarshalPKIXPublicKey(&c.Key.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
}

// DER writes the request and signs it.
func (c *testCSR) DER() []byte {
	if c.Fixed != nil {
		return slices.Clone(c.Fixed)
	}
	spki := c.RawSubjectPublicKeyInfo
	if spki == nil {
		var err error
		if spki, err = x509.MarshalPKIXPublicKey(&c.Key.PublicKey); err != nil {
			panic(err)
		}
	}
	version := c.Version
	if version == nil {
		version = []byte{0x02, 0x01, 0x00}
	}
	var attrs []byte
	if c.Attributes != nil {
		for _, a := range c.Attributes {
			attrs = append(attrs, a...)
		}
	} else {
		value := c.ExtensionsDER
		if value == nil {
			value = extensionsValue(c.Extensions)
		}
		attrs = extensionRequestAttribute(value)
	}
	infoTag, attrsTag := byte(0x30), byte(0xa0)
	if c.InfoTag != 0 {
		infoTag = c.InfoTag
	}
	if c.AttributesTag != 0 {
		attrsTag = c.AttributesTag
	}
	info := tlv(infoTag, version, c.RawSubject, spki, tlv(attrsTag, attrs), c.InfoTrailer)
	alg := c.Algorithm
	if alg == nil {
		alg = algECDSAWithSHA384DER
	}
	var digest []byte
	switch c.Digest {
	case crypto.SHA1:
		d := sha1.Sum(info) //nolint:gosec // see the import
		digest = d[:]
	case crypto.SHA256:
		d := sha256.Sum256(info)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(info)
		digest = d[:]
	default:
		d := sha512.Sum384(info)
		digest = d[:]
	}
	sig, err := ecdsa.SignASN1(rand.Reader, c.Key, digest)
	if err != nil {
		panic(err)
	}
	if c.SignatureEdit != nil {
		sig = c.SignatureEdit(sig)
	}
	bits := tlv(0x03, append([]byte{c.UnusedBits}, sig...))
	if c.SignatureElement != nil {
		bits = c.SignatureElement(bits)
	}
	return append(tlv(0x30, info, alg, bits, c.OuterTrailer), c.AfterRequest...)
}

// csrOptions says what a made request holds.
type csrOptions struct {
	// key is the key of the request: a P-384 key makes a request that the package reads, another key
	// a request that it refuses (made with the standard library, signed as that key signs).
	key        crypto.Signer
	subject    pkix.Name
	rawSubject []byte
	exts       []pkix.Extension
}

// goodSubject is the subject of a request that has no other: an organisation and a common name, in DER.
func goodSubject() []byte {
	return nameOf(rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 10}), str(0x13, "acme"))), rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 3}), str(0x13, "acme example ca"))))
}

// makeCSR builds a request. A P-384 key (or none, for a new one) gives a request made by hand from the
// parts; a key of another kind gives a request that the standard library writes.
func makeCSR(t testing.TB, o csrOptions) *testCSR {
	t.Helper()
	if o.key == nil {
		o.key = newKey(t)
	}
	raw := o.rawSubject
	if raw == nil && (o.subject.CommonName != "" || o.subject.Organization != nil || o.subject.Country != nil || o.subject.ExtraNames != nil) {
		rdns := o.subject.ToRDNSequence()
		der, err := asn1.Marshal(rdns)
		if err != nil {
			t.Fatal(err)
		}
		raw = der
	}
	if raw == nil {
		raw = goodSubject()
	}
	if k, ok := o.key.(*ecdsa.PrivateKey); ok && k.Curve.Params().BitSize == 384 {
		return &testCSR{Key: k, RawSubject: raw, Extensions: o.exts, PublicKey: &k.PublicKey}
	}
	tmpl := &x509.CertificateRequest{RawSubject: raw, ExtraExtensions: o.exts}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, o.key)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}
	return &testCSR{Fixed: der, RawSubject: parsed.RawSubject, Extensions: parsed.Extensions, PublicKey: parsed.PublicKey, RawSubjectPublicKeyInfo: parsed.RawSubjectPublicKeyInfo}
}

// withExtensions is a request with the extensions it is given and a fresh P-384 key. The contract's
// request has an extended key usage, so one is added, not critical, with serverAuth and clientAuth, unless
// the extensions given have one of their own (a test of a request without one, or with a bad one, says so
// by using withExactExtensions or by giving its own).
func withExtensions(t testing.TB, exts ...pkix.Extension) *testCSR {
	t.Helper()
	for _, e := range exts {
		if e.Id.Equal(oidExtKeyUsage) {
			return makeCSR(t, csrOptions{exts: exts})
		}
	}
	return makeCSR(t, csrOptions{exts: append(slices.Clone(exts), extExtKeyUsage(false, oidServerAuth, oidClientAuth))})
}

// withExactExtensions is a request with exactly the extensions it is given: none added.
func withExactExtensions(t testing.TB, exts ...pkix.Extension) *testCSR {
	t.Helper()
	return makeCSR(t, csrOptions{exts: exts})
}

// copyCSR returns a copy with its own slices, to be edited by a test. A request that was fixed bytes
// stays fixed bytes.
func copyCSR(c *testCSR) *testCSR {
	d := *c
	d.Extensions = append([]pkix.Extension(nil), c.Extensions...)
	d.RawSubject = slices.Clone(c.RawSubject)
	d.RawSubjectPublicKeyInfo = slices.Clone(c.RawSubjectPublicKeyInfo)
	d.Fixed = slices.Clone(c.Fixed)
	return &d
}

var _ = pki.MaxRequestSize

// p256Key and p521Key are keys of other curves, in memory.
func p256Key(t testing.TB) *ecdsa.PrivateKey { return curveKey(t, elliptic.P256()) }
func p521Key(t testing.TB) *ecdsa.PrivateKey { return curveKey(t, elliptic.P521()) }

func curveKey(t testing.TB, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
