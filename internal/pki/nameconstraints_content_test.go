package pki_test

import (
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The reading of the builder judges the tag and the form of a base, and the standard library judges a
// few contents (an IP range, an IA5String, a DNS name). The content of the other forms is the ASN.1 of
// GeneralName (RFC 5280, 4.2.1.6), and a value whose content is not that is not a GeneralName. These
// rows are such values, in the right tag and the right form. Once the builder issued them; now it issues
// name constraints for the four forms of e-mail, DNS, URI and IP address only, so all are refused.
//
// A row must be refused by the builder (ErrRequest, no body). A row that is issued fails the test, and the
// message says what OpenSSL does with the certificate.
func TestNameConstraintsOfTheRightFormWithContentThatIsNotThatTypeAreRefused(t *testing.T) {
	root := buildRoot(t, nil)
	at := ceremony.Add(24 * time.Hour)
	oid := []byte{0x06, 0x03, 0x2b, 0x06, 0x01}
	str := tlv(0x0c, []byte("x"))
	rows := []struct {
		name           string
		base           []byte
		opensslRefuses bool // seen with OpenSSL 3.6.4 in the strict mode
	}{
		{"otherName with no content", tlv(0xa0), true},
		{"otherName that holds an integer", tlv(0xa0, tlv(0x02, []byte{5})), true},
		{"otherName with a type-id and no value", tlv(0xa0, oid), true},
		{"otherName whose value is not explicit", tlv(0xa0, oid, str), true},
		{"directoryName with no content", tlv(0xa4), true},
		{"directoryName that holds an integer", tlv(0xa4, tlv(0x02, []byte{5})), true},
		{"directoryName that holds two names", tlv(0xa4, tlv(0x30), tlv(0x30)), true},
		{"directoryName with an RDN that is not a set", tlv(0xa4, tlv(0x30, tlv(0x02, []byte{1}))), true},
		{"ediPartyName with no content", tlv(0xa5), true},
		{"ediPartyName with no partyName", tlv(0xa5, tlv(0xa0, str)), true},
		{"ediPartyName whose partyName is not a string", tlv(0xa5, tlv(0xa1, tlv(0x02, []byte{1}))), true},
		{"ediPartyName whose partyName is implicit", tlv(0xa5, tlv(0x81, []byte("x"))), true},
		{"ediPartyName with the parts in the wrong order", tlv(0xa5, tlv(0xa1, str), tlv(0xa0, str)), true},
		{"registeredID with no content", tlv(0x88), true},
		{"registeredID that is cut in a subidentifier", tlv(0x88, []byte{0x2b, 0x80}), true},
		{"registeredID with a subidentifier that is not minimal", tlv(0x88, []byte{0x2b, 0x80, 0x01}), true},
		// Not a GeneralName either, and no verifier tried here reads these forms, so they pass both.
		{"x400Address with no content", tlv(0xa3), false},
		{"x400Address that holds an integer", tlv(0xa3, tlv(0x02, []byte{1})), false},
		{"directoryName with an RDN that has no attribute", tlv(0xa4, tlv(0x30, tlv(0x31))), false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := ncRequest(t, ncValue([][]byte{ncSub(r.base)}, nil))
			tbs, err := intermediateTBS(t, root.interParams(csr))
			if err != nil {
				refused(t, err, pki.ErrRequest)
				return
			}
			der, err := pki.Assemble(tbs, signatureOf(t, root.key, tbs), &root.key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if oerr := verifier.OpenSSLVerify(t, root.cert, der, at); oerr != nil {
				t.Errorf("a body was issued whose base %x is not a GeneralName, and OpenSSL refuses the certificate: %v", r.base, oerr)
			} else {
				t.Errorf("a body was issued whose base %x is not a GeneralName (OpenSSL reads it all the same; refused by it before: %v)", r.base, r.opensslRefuses)
			}
		})
	}
}

// A name whose attributes are not what the Name syntax says is not a name. A value that is not a string (a
// common name is a DirectoryString), a VisibleString (which DirectoryString does not hold), and an attribute
// with an element after its value are read by the standard library, and OpenSSL cannot parse the certificate
// at all. The builder once issued them; it reads a name by RFC 5280 (4.1.2.4) now, and refuses all of them.
func TestNamesThatOpenSSLCannotReadAreRefused(t *testing.T) {
	root := buildRoot(t, nil)
	at := ceremony.Add(24 * time.Hour)
	cn := []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	name := func(attr ...[]byte) []byte { return tlv(0x30, tlv(0x31, tlv(0x30, attr...))) }
	rows := map[string][]byte{
		"a common name that is a visible string":   name(cn, tlv(0x1a, []byte("abc"))),
		"a common name that is an integer":         name(cn, tlv(0x02, []byte{1})),
		"a common name that is an octet string":    name(cn, tlv(0x04, []byte("x"))),
		"a common name that is a null":             name(cn, tlv(0x05)),
		"an attribute with a null after its value": name(cn, tlv(0x0c, []byte("x")), tlv(0x05)),
		"an attribute with a byte after its value": name(cn, tlv(0x0c, []byte("x")), []byte{0x00}),
	}
	good := withExtensions(t, goodExtensions()...)
	for label, raw := range rows {
		check := func(t *testing.T, tbs []byte, err error, params, request bool) {
			t.Helper()
			if err != nil {
				want := pki.ErrParams
				if request {
					want = pki.ErrRequest
				}
				if !errors.Is(kindOf(t, err), want) || !printable(err.Error()) || tbs != nil {
					t.Errorf("refused in the wrong way: %v (body %x)", err, tbs)
				}
				return
			}
			der, aerr := pki.Assemble(tbs, signatureOf(t, root.key, tbs), &root.key.PublicKey)
			if aerr != nil {
				t.Fatal(aerr)
			}
			oerr := verifier.OpenSSLVerify(t, root.cert, der, at)
			t.Errorf("a body was issued with the name %x; OpenSSL: %v", raw, oerr)
		}
		t.Run("the subject is "+label, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = raw
			tbs, err := intermediateTBS(t, root.interParams(csr))
			check(t, tbs, err, false, true)
		})
		t.Run("the issuer is "+label, func(t *testing.T) {
			p := root.interParams(good)
			p.IssuerSubject = raw
			tbs, err := intermediateTBS(t, p)
			if err == nil {
				// The issuer is not the root, so OpenSSL cannot chain it: it is enough that the body is not issued.
				t.Errorf("a body was issued with the issuer %x", raw)
				return
			}
			check(t, tbs, err, true, false)
		})
	}
}

// Every body the builders return, for valid and for damaged parameters, is verified by OpenSSL in the
// strict mode as well as by the standard library. It once failed on bodies whose name constraints or names
// OpenSSL cannot read (the rows above found these by hand; the damaged inputs found more).
func TestEveryBodyTheBuildersReturnIsVerifiedByOpenSSL(t *testing.T) {
	runBuildersProperty(t, true)
}

// The types that RFC 5280, Appendix A.1, gives to three attributes are not DirectoryStrings: countryName is a
// PrintableString of 2 characters, serialNumber and dnQualifier are a PrintableString. And a PrintableString has
// a character set (letters, digits, space and '()+,-./:=?), which has no asterisk and no ampersand. The builder
// issues all of these, and neither the standard library nor OpenSSL objects; the table asks for a refusal.
func TestAttributeValuesThatBreakTheTypeOfTheirAttributeAreRefused(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	serial := mustOID(asn1.ObjectIdentifier{2, 5, 4, 5})
	dnq := mustOID(asn1.ObjectIdentifier{2, 5, 4, 46})
	rows := []namedRow{
		{"a country as UTF8String", nameOf(rdn(atv(oidAttrC, str(tUTF8, "NL"))))},
		{"a country of one character", nameOf(rdn(atv(oidAttrC, str(tPrintable, "N"))))},
		{"a country of three characters", nameOf(rdn(atv(oidAttrC, str(tPrintable, "NLD"))))},
		{"a serial number as UTF8String", nameOf(rdn(atv(serial, str(tUTF8, "123"))))},
		{"a dnQualifier as UTF8String", nameOf(rdn(atv(dnq, str(tUTF8, "abc"))))},
		{"a PrintableString with an asterisk", nameOf(rdn(atv(oidAttrCN, str(tPrintable, "a*b"))))},
		{"a PrintableString with an ampersand", nameOf(rdn(atv(oidAttrCN, str(tPrintable, "a&b"))))},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = r.raw
			tbs, err := intermediateTBS(t, root.interParams(csr))
			if err != nil {
				refused(t, err, pki.ErrRequest)
				return
			}
			der, aerr := pki.Assemble(tbs, signatureOf(t, root.key, tbs), &root.key.PublicKey)
			if aerr != nil {
				t.Fatal(aerr)
			}
			t.Errorf("a body was issued with the subject %x (OpenSSL: %v)", r.raw, verifier.OpenSSLVerify(t, root.cert, der, ceremony.Add(24*time.Hour)))
		})
	}
}
