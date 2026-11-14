package pki_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The table of what a conforming name is, written from RFC 5280 (sections 4.1.2.4, 4.1.2.6 and Appendix
// A.1) and X.690, and not from the code under test.
//
//	Name ::= CHOICE { rdnSequence RDNSequence }              4.1.2.4, Appendix A.1
//	RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
//	RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
//	AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY DEFINED BY type }
//
//   - one DER SEQUENCE and nothing after it (the certificate is DER: 4.1);
//   - not empty: "The issuer field MUST contain a non-empty distinguished name"; "If the subject is a CA
//     ... the subject field MUST be populated with a non-empty distinguished name" (4.1.2.6);
//   - each relative name is a SET (31) of at least one attribute: SIZE (1..MAX);
//   - the elements of a SET OF are in ascending order of their encodings in DER (X.690, 11.6). The RFC
//     asks for it only through DER; it says nothing in its own words;
//   - an attribute is a SEQUENCE of exactly two elements, an OID and a value;
//   - the value of an attribute of type DirectoryString (the common name, the organisation, ...) is a
//     string that is not empty (SIZE (1..MAX)), and "CAs conforming to this profile MUST use either the
//     PrintableString or UTF8String encoding", with a legacy exception (TeletexString, BMPString,
//     UniversalString) for a CA that already issued with them: the RFC allows these to such a CA and asks
//     nothing of a new one;
//   - domainComponent is an IA5String, and so is the e-mail address of PKCS #9 (Appendix A.1: "DomainComponent
//     ::= IA5String", "EmailAddress ::= IA5String (SIZE (1..ub-emailaddress-length))"): the RFC asks for
//     IA5String there, and for no other attribute;
//   - countryName, serialNumber and dnQualifier are a PrintableString (Appendix A.1): the RFC asks for
//     PrintableString, and the country for 2 characters;
//   - a type that the RFC does not define has ANY as its value: the RFC says nothing of it.
//
// What the code does beyond or short of this: it asks for a string of PrintableString or
// UTF8String for every type but the two IA5String ones (so it is stricter for the legacy exception and for
// unknown types, and looser for the country, the serial number and the dnQualifier, which it lets be UTF8String).

var (
	oidAttrCN      = mustOID(asn1.ObjectIdentifier{2, 5, 4, 3})
	oidAttrO       = mustOID(asn1.ObjectIdentifier{2, 5, 4, 10})
	oidAttrC       = mustOID(asn1.ObjectIdentifier{2, 5, 4, 6})
	oidAttrDC      = mustOID(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25})
	oidAttrEmail   = mustOID(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1})
	oidAttrUnknown = mustOID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 5})
)

func mustOID(o asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(o)
	if err != nil {
		panic(err)
	}
	return der
}

// atv is an attribute: its OID, then the value as DER.
func atv(oid, value []byte, more ...[]byte) []byte {
	return tlv(0x30, append([][]byte{oid, value}, more...)...)
}

func str(tag byte, s string) []byte { return tlv(tag, []byte(s)) }

const (
	tPrintable = 0x13
	tUTF8      = 0x0c
	tIA5       = 0x16
)

// rdn is a relative name: a SET of the attributes, in DER order (ascending encodings).
func rdn(attrs ...[]byte) []byte {
	sorted := append([][]byte(nil), attrs...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	return tlv(0x31, sorted...)
}

// rdnAsGiven is a relative name with the attributes in the order given, which may not be DER.
func rdnAsGiven(attrs ...[]byte) []byte { return tlv(0x31, attrs...) }

func nameOf(rdns ...[]byte) []byte { return tlv(0x30, rdns...) }

// namedRow is a name and what it is.
type namedRow struct {
	name string
	raw  []byte
}

func issuedNames() []namedRow {
	cn := func(tag byte, s string) []byte { return atv(oidAttrCN, str(tag, s)) }
	return []namedRow{
		{"a common name, PrintableString", nameOf(rdn(cn(tPrintable, "acme example ca")))},
		{"a common name, UTF8String", nameOf(rdn(cn(tUTF8, "acme example ca")))},
		{"a common name with punctuation, UTF8String", nameOf(rdn(cn(tUTF8, "Example, Issuing CA (1) #2")))},
		{"a name attribute of 300 characters", nameOf(rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 41}), str(tUTF8, strings.Repeat("x", 300)))))},
		{"an organisation and a common name, two relative names", nameOf(rdn(atv(oidAttrO, str(tPrintable, "acme"))), rdn(cn(tPrintable, "ca")))},
		{"one relative name of two attributes, in DER order", nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme")), cn(tUTF8, "ca")))},
		{"one relative name of three attributes, in DER order", nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme")), cn(tUTF8, "ca"), atv(oidAttrC, str(tPrintable, "NL"))))},
		{"two organisational units in two relative names", nameOf(rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 11}), str(tUTF8, "a"))), rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 11}), str(tUTF8, "b"))), rdn(cn(tUTF8, "ca")))},
		{"a domain component as IA5String", nameOf(rdn(atv(oidAttrDC, str(tIA5, "example"))), rdn(cn(tUTF8, "ca")))},
		{"two domain components and a common name", nameOf(rdn(atv(oidAttrDC, str(tIA5, "org"))), rdn(atv(oidAttrDC, str(tIA5, "example"))), rdn(cn(tUTF8, "ca")))},
		{"an e-mail address as IA5String", nameOf(rdn(cn(tUTF8, "ca")), rdn(atv(oidAttrEmail, str(tIA5, "ca@example.org"))))},
		{"a country as PrintableString", nameOf(rdn(atv(oidAttrC, str(tPrintable, "NL"))), rdn(cn(tUTF8, "ca")))},
		{"a multi-valued relative name with a domain component and a common name", nameOf(rdn(atv(oidAttrDC, str(tIA5, "example")), cn(tUTF8, "ca")))},
	}
}

// Every name that is issued is copied byte for byte, and the certificate is verified by both verifiers.
func TestIntermediateIssuesTheNamesOfTheTable(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	for _, r := range issuedNames() {
		t.Run("the subject is "+r.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = r.raw
			got := root.issue(t, csr, nil)
			if !bytes.Equal(got.parsed.RawSubject, r.raw) {
				t.Errorf("subject = %x, want %x", got.parsed.RawSubject, r.raw)
			}
			verifyEverywhere(t, root, got, true)
		})
		t.Run("the issuer is "+r.name, func(t *testing.T) {
			got := root.issue(t, good, func(p *pki.IntermediateParams) { p.IssuerSubject = r.raw })
			if !bytes.Equal(got.parsed.RawIssuer, r.raw) {
				t.Errorf("issuer = %x, want %x", got.parsed.RawIssuer, r.raw)
			}
			// The issuer is not the root, so no chain can be built to it: the body is read by both
			// verifiers as a certificate instead.
			if err := verifyReads(t, got); err != nil {
				t.Error(err)
			}
		})
	}
}

// Refusals of a name, by the table: ErrRequest for the subject, ErrParams for the issuer, no body, printable
// ASCII, and the text says which name it is and that it is not the standard library's second check.
func TestIntermediateRefusesTheNamesThatAreNotOfTheTable(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	cnOID := oidAttrCN
	cn := func(v []byte) []byte { return atv(cnOID, v) }
	one := func(v []byte) []byte { return nameOf(rdn(cn(v))) }
	okName := nameOf(rdn(cn(str(tUTF8, "ca"))))
	var rows []namedRow
	add := func(name string, raw []byte) { rows = append(rows, namedRow{name, raw}) }

	// The name.
	add("nothing", nil)
	add("an empty sequence", []byte{0x30, 0x00})
	add("a set instead of a sequence", append([]byte{0x31}, okName[1:]...))
	add("an octet string", append([]byte{0x04}, okName[1:]...))
	add("a primitive sequence tag", append([]byte{0x10}, okName[1:]...))
	add("the sequence tag number in the context class", append([]byte{0xb0}, okName[1:]...))
	add("the sequence tag number in the application class", append([]byte{0x70}, okName[1:]...))
	add("bytes after the name", append(append([]byte{}, okName...), 0x00))
	add("two names", append(append([]byte{}, okName...), okName...))
	add("a name cut short", okName[:len(okName)-1])
	add("an indefinite length", append(append([]byte{0x30, 0x80}, okName[2:]...), 0x00, 0x00))

	// The relative names.
	add("a relative name that is an integer", nameOf(tlv(0x02, []byte{1})))
	add("a relative name that is a sequence", nameOf(tlv(0x30, cn(str(tUTF8, "a")))))
	add("a relative name that is the attribute itself", nameOf(cn(str(tUTF8, "a"))))
	add("a relative name that is a primitive set", nameOf(tlv(0x11, cn(str(tUTF8, "a")))))
	add("an empty relative name", nameOf(tlv(0x31)))
	add("a good relative name and then an empty one", nameOf(rdn(cn(str(tUTF8, "a"))), tlv(0x31)))
	add("a relative name of the wrong class", nameOf(tlv(0xb1, cn(str(tUTF8, "a")))))
	add("two attributes in the wrong order", nameOf(rdnAsGiven(atv(oidAttrO, str(tUTF8, "acme")), cn(str(tUTF8, "ca")))))
	add("three attributes, the last two swapped", nameOf(rdnAsGiven(cn(str(tUTF8, "a")), atv(oidAttrO, str(tUTF8, "acme")), atv(oidAttrC, str(tPrintable, "NL")))))
	add("two attributes in the wrong order in the second relative name", nameOf(rdn(cn(str(tUTF8, "a"))), rdnAsGiven(atv(oidAttrO, str(tUTF8, "acme")), cn(str(tUTF8, "ca")))))

	// The attributes.
	add("an attribute that is a set", nameOf(tlv(0x31, tlv(0x31, oidAttrCN, str(tUTF8, "a")))))
	add("an attribute that is a primitive sequence", nameOf(tlv(0x31, tlv(0x10, oidAttrCN, str(tUTF8, "a")))))
	add("an attribute that is an integer", nameOf(tlv(0x31, tlv(0x02, []byte{1}))))
	add("an attribute of the wrong class", nameOf(tlv(0x31, tlv(0xb0, oidAttrCN, str(tUTF8, "a")))))
	add("an attribute that is empty", nameOf(tlv(0x31, tlv(0x30))))
	add("an attribute that starts with an integer", nameOf(rdn(atv(tlv(0x02, []byte{1}), str(tUTF8, "a")))))
	add("an attribute that starts with a string", nameOf(rdn(atv(str(tUTF8, "cn"), str(tUTF8, "a")))))
	add("an attribute of an empty object identifier", nameOf(rdn(atv(tlv(0x06), str(tUTF8, "a")))))
	add("an attribute with only its type", nameOf(tlv(0x31, tlv(0x30, oidAttrCN))))
	add("an attribute with a null after its value", nameOf(rdn(atv(oidAttrCN, str(tUTF8, "x"), tlv(0x05)))))
	add("an attribute with a byte after its value", nameOf(rdn(atv(oidAttrCN, str(tUTF8, "x"), []byte{0x00}))))
	add("an attribute with a second string after its value", nameOf(rdn(atv(oidAttrCN, str(tUTF8, "x"), str(tUTF8, "y")))))

	// The values.
	add("a value that is an integer", one(tlv(0x02, []byte{1})))
	add("a value that is an octet string", one(tlv(0x04, []byte("x"))))
	add("a value that is a null", one(tlv(0x05)))
	add("a value that is a boolean", one(tlv(0x01, []byte{0xff})))
	add("a value that is an object identifier", one(tlv(0x06, []byte{0x2a})))
	add("a value that is a VisibleString", one(str(0x1a, "abc")))
	add("a value that is a NumericString", one(str(0x12, "123")))
	add("a value that is a T61String", one(str(0x14, "abc")))
	add("a value that is a BMPString", one(tlv(0x1e, []byte{0, 'a'})))
	add("a value that is a UniversalString", one(tlv(0x1c, []byte{0, 0, 0, 'a'})))
	add("a value that is a UTCTime", one(str(0x17, "261115120000Z")))
	add("a value that is a sequence", one(tlv(0x30, str(tUTF8, "x"))))
	add("a value that is a constructed UTF8String", one(tlv(0x2c, str(tUTF8, "x"))))
	add("a value that is a constructed PrintableString", one(tlv(0x33, str(tPrintable, "x"))))
	add("a value of the context class", one(tlv(0x80, []byte("x"))))
	add("a value of the application class", one(tlv(0x4c, []byte("x"))))
	add("a value of the private class", one(tlv(0xcc, []byte("x"))))
	add("an empty UTF8String", one(tlv(tUTF8)))
	add("an empty PrintableString", one(tlv(tPrintable)))
	add("a common name that is an IA5String", one(str(tIA5, "ca")))
	add("an organisation that is an IA5String", nameOf(rdn(atv(oidAttrO, str(tIA5, "acme")))))
	add("an unknown type with an IA5String", nameOf(rdn(atv(oidAttrUnknown, str(tIA5, "x")))))
	add("an unknown type with a BMPString", nameOf(rdn(atv(oidAttrUnknown, tlv(0x1e, []byte{0, 'a'})))))
	add("an unknown type with an integer", nameOf(rdn(atv(oidAttrUnknown, tlv(0x02, []byte{1})))))
	add("a domain component as PrintableString", nameOf(rdn(atv(oidAttrDC, str(tPrintable, "example")))))
	add("a domain component as UTF8String", nameOf(rdn(atv(oidAttrDC, str(tUTF8, "example")))))
	add("a domain component that is empty", nameOf(rdn(atv(oidAttrDC, tlv(tIA5)))))
	add("a domain component that is an integer", nameOf(rdn(atv(oidAttrDC, tlv(0x02, []byte{1})))))
	add("an e-mail address as PrintableString", nameOf(rdn(atv(oidAttrEmail, str(tPrintable, "ca@example.org")))))
	add("an e-mail address as UTF8String", nameOf(rdn(atv(oidAttrEmail, str(tUTF8, "ca@example.org")))))
	add("an e-mail address that is empty", nameOf(rdn(atv(oidAttrEmail, tlv(tIA5)))))
	add("a common name that is a visible string in a good name", nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme"))), rdn(cn(str(0x1a, "ca")))))

	if len(rows) < 60 {
		t.Fatalf("only %d rows", len(rows))
	}
	// say is the words of the text that the row must have: which rule refused it.
	say := func(name string) string {
		for _, k := range []struct{ in, say string }{
			{"bytes after the name", "bytes after the name"},
			{"two names", "bytes after the name"},
			{"an empty relative name", "empty relative name"},
			{"wrong order", "DER order"},
			{"swapped", "DER order"},
			{"relative name that is", "not a DER set"},
			{"relative name of the wrong class", "not a DER set"},
			{"attribute that is empty", "object identifier"},
			{"attribute that is", "not a sequence"},
			{"attribute of the wrong class", "not a sequence"},
			{"attribute that starts with", "object identifier"},
			{"empty object identifier", "object identifier"},
			{"only its type", "no value"},
			{"after its value", "element after its value"},
			{"value that is a constructed", "not a string"},
			{"value that is a sequence", "not a string"},
			{"value of the context class", "not a string"},
			{"value of the application class", "not a string"},
			{"value of the private class", "not a string"},
			{"an empty UTF8String", "empty string"},
			{"an empty PrintableString", "empty string"},
			{"domain component that is empty", "empty string"},
			{"e-mail address that is empty", "empty string"},
			{"domain component as", "IA5String"},
			{"e-mail address as", "IA5String"},
			{"domain component that is an integer", "IA5String"},
			{"value that is a null", "empty string"},
			{"a value that is", "PrintableString or a UTF8String"},
			{"that is an IA5String", "PrintableString or a UTF8String"},
			{"with an IA5String", "PrintableString or a UTF8String"},
			{"with a BMPString", "PrintableString or a UTF8String"},
			{"with an integer", "PrintableString or a UTF8String"},
			{"visible string in a good name", "PrintableString or a UTF8String"},
		} {
			if strings.Contains(name, k.in) {
				return k.say
			}
		}
		return ""
	}
	for _, r := range rows {
		t.Run("the subject is "+r.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = r.raw
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
			if err != nil && strings.Contains(err.Error(), "standard library") {
				t.Errorf("the refusal is the second check's, not the reading of the name: %q", err.Error())
			}
			// A name with bytes after it is not read as a name: it is an element too many in the request.
			want, who := say(r.name), "subject"
			if want == "bytes after the name" {
				want, who = "request info", "request"
			}
			if err != nil && !strings.Contains(err.Error(), want) {
				t.Errorf("the text does not say which rule refused it (%q): %q", want, err.Error())
			}
			if err != nil && !strings.Contains(err.Error(), who) && !strings.Contains(err.Error(), "request info") {
				t.Errorf("the text does not say that it is the %s: %q", who, err.Error())
			}
		})
		t.Run("the issuer is "+r.name, func(t *testing.T) {
			p := root.interParams(good)
			p.IssuerSubject = r.raw
			tbs, err := intermediateTBS(t, p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
			if err != nil && strings.Contains(err.Error(), "standard library") {
				t.Errorf("the refusal is the second check's, not the reading of the name: %q", err.Error())
			}
			if err != nil && !strings.Contains(err.Error(), say(r.name)) {
				t.Errorf("the text does not say which rule refused it (%q): %q", say(r.name), err.Error())
			}
			if err != nil && !strings.Contains(err.Error(), "issuer") {
				t.Errorf("the text does not say that it is the issuer: %q", err.Error())
			}
		})
	}
}

// The standard library's own request: a request that Go writes with a domain component has it as a
// PrintableString, which RFC 5280 does not allow for a domain component (Appendix A.1: IA5String), so it is
// refused; a request with a common name and an organisation is accepted. The test states the fact so that
// it is on record, so that a later change of this rule is a choice.
func TestARequestMadeByTheStandardLibraryWithADomainComponentIsRefused(t *testing.T) {
	root := buildRoot(t, nil)
	withDC := makeCSR(t, csrOptions{
		subject: pkix.Name{
			CommonName: "acme example ca",
			ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, Value: "example"}},
		},
		exts: goodExtensions(),
	})
	if i := bytes.Index(withDC.RawSubject, oidAttrDC); i < 0 || withDC.RawSubject[i+len(oidAttrDC)] != tPrintable {
		t.Fatalf("the standard library did not write the domain component as a PrintableString: %x", withDC.RawSubject)
	}
	tbs, err := intermediateTBS(t, root.interParams(withDC))
	refused(t, err, pki.ErrRequest)
	if tbs != nil {
		t.Error("a body came with the error")
	}
	if err != nil && !strings.Contains(err.Error(), "IA5String") {
		t.Errorf("the text does not say why: %q", err.Error())
	}

	plain := makeCSR(t, csrOptions{
		subject: pkix.Name{CommonName: "acme example ca", Organization: []string{"acme"}, Country: []string{"NL"}},
		exts:    goodExtensions(),
	})
	got := root.issue(t, plain, nil)
	verifyEverywhere(t, root, got, true)
}

// verifyReads has the standard library and OpenSSL read a certificate whose issuer is not the root, so that
// no chain can be built: both must read the certificate.
func verifyReads(t *testing.T, got *issued) error {
	t.Helper()
	if _, err := x509.ParseCertificate(got.cert); err != nil {
		return fmt.Errorf("the standard library cannot read it: %w", err)
	}
	bin := verifier.Require(t, "openssl")
	file := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(file, pemOf(got.cert), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "x509", "-in", file, "-noout", "-text").CombinedOutput()
	if err != nil {
		return fmt.Errorf("OpenSSL cannot read it: %w: %s", err, jsonset.Escape(string(out)))
	}
	return nil
}
