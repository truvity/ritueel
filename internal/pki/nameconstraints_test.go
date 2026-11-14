package pki_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The table of what a conforming name constraints value is, written from RFC 5280 and not from the
// code under test.
//
//	NameConstraints ::= SEQUENCE {                                    (4.2.1.10, Appendix A.2)
//	    permittedSubtrees [0] GeneralSubtrees OPTIONAL,
//	    excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
//	GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
//	GeneralSubtree  ::= SEQUENCE { base GeneralName,
//	                               minimum [0] BaseDistance DEFAULT 0, maximum [1] BaseDistance OPTIONAL }
//
//   - one DER SEQUENCE, and nothing after it: the module is DER, and a value is one element;
//   - the fields are [0] then [1], each at most once, in that order (the order of a SEQUENCE's members);
//   - at least one of them: "MUST NOT issue certificates where name constraints is an empty sequence";
//   - each is IMPLICIT, so it is the constructed tag a0 or a1 (context class, constructed), and holds
//     one or more GeneralSubtree: SIZE (1..MAX);
//   - a GeneralSubtree is a SEQUENCE (30) that holds exactly one base, because "the minimum MUST be zero,
//     and maximum MUST be absent" and a minimum of zero is the DEFAULT, which DER leaves out;
//   - the base is a GeneralName (4.2.1.6), a CHOICE of nine tags. The module is IMPLICIT TAGS, so a tag
//     replaces the tag of the type it is put on:
//
//     tag  name                      type                  form          bytes
//     [0]  otherName                 AnotherName SEQUENCE  constructed   a0
//     [1]  rfc822Name                IA5String             primitive     81
//     [2]  dNSName                   IA5String             primitive     82
//     [3]  x400Address               ORAddress SEQUENCE    constructed   a3
//     [4]  directoryName             Name, a CHOICE        constructed   a4   (a tagged CHOICE is always
//     explicit: X.680 31.2.7, the rule that overrides IMPLICIT TAGS; the tag wraps the SEQUENCE of Name)
//     [5]  ediPartyName              EDIPartyName SEQUENCE constructed   a5
//     [6]  uniformResourceIdentifier IA5String             primitive     86
//     [7]  iPAddress                 OCTET STRING          primitive     87  (8 or 32 octets: 4.2.1.10)
//     [8]  registeredID              OBJECT IDENTIFIER     primitive     88
//
// The content of each form is what its type says (an IA5String is 7-bit, an OID is a DER OID, a Name is
// a SEQUENCE of RDNs, an AnotherName is { OID, [0] EXPLICIT ANY }, an EDIPartyName has a partyName [1]
// that holds a DirectoryString, and an ORAddress is a SEQUENCE that holds the standard attributes).

// gnForm is one of the nine forms of a GeneralName, with a conforming base, as DER.
type gnForm struct {
	tag    byte
	name   string
	prim   bool   // the form: primitive or constructed
	source string // where the RFC or the module makes it so
	base   []byte
}

func gnForms() []gnForm {
	name := tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, tlv(0x0c, []byte("x")))))
	return []gnForm{
		{0, "otherName", false, "4.2.1.6: AnotherName is a SEQUENCE, IMPLICIT TAGS", tlv(0xa0, []byte{0x06, 0x03, 0x2b, 0x06, 0x01}, tlv(0xa0, tlv(0x0c, []byte("x"))))},
		{1, "rfc822Name", true, "4.2.1.6: IA5String is primitive", tlv(0x81, []byte("example.org"))},
		{2, "dNSName", true, "4.2.1.6: IA5String is primitive", tlv(0x82, []byte("example.org"))},
		{3, "x400Address", false, "4.2.1.6: ORAddress is a SEQUENCE, IMPLICIT TAGS", tlv(0xa3, tlv(0x30))},
		{4, "directoryName", false, "4.2.1.6: Name is a CHOICE, so the tag is explicit (X.680 31.2.7)", tlv(0xa4, name)},
		{5, "ediPartyName", false, "4.2.1.6: EDIPartyName is a SEQUENCE, IMPLICIT TAGS", tlv(0xa5, tlv(0xa1, tlv(0x0c, []byte("x"))))},
		{6, "uniformResourceIdentifier", true, "4.2.1.6: IA5String is primitive", tlv(0x86, []byte("example.org"))},
		{7, "iPAddress", true, "4.2.1.6: OCTET STRING is primitive; 4.2.1.10: 8 or 32 octets", tlv(0x87, []byte{10, 0, 0, 0, 255, 0, 0, 0})},
		{8, "registeredID", true, "4.2.1.6: OBJECT IDENTIFIER is primitive", tlv(0x88, []byte{0x2b, 0x06, 0x01})},
	}
}

// verifyEverywhere checks an issued intermediate with the standard library and with OpenSSL in the
// strict mode (through the helper), at the first second of its validity.
//
// The standard library processes the name constraints of four forms (e-mail, DNS, URI, IP address). For
// any other form in a critical extension it refuses to verify a chain, as RFC 5280 allows ("MUST either
// process the constraint or reject the certificate"): that is the verifier's rule, not a fault of the
// certificate, so for such a value goHandles is false and only that refusal is accepted. The signature
// is checked either way.
func verifyEverywhere(t *testing.T, root *testRoot, got *issued, goHandles bool) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(root.parsed)
	at := got.parsed.NotBefore
	if err := got.parsed.CheckSignatureFrom(root.parsed); err != nil {
		t.Errorf("the standard library does not verify the signature: %v", err)
	}
	_, err := got.parsed.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	var unhandled x509.UnhandledCriticalExtension
	switch {
	case err == nil:
	case !goHandles && errors.As(err, &unhandled):
	default:
		t.Errorf("the standard library refuses it: %v", err)
	}
	if err := verifier.OpenSSLVerify(t, root.cert, got.cert, at); err != nil {
		t.Errorf("OpenSSL (strict) refuses it: %v\nname constraints: %x", err, extensionOf(got.parsed, oidNameConstraints).Value)
	}
}

func ncRequest(t *testing.T, value []byte) *testCSR {
	t.Helper()
	return withExtensions(t, extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign), pkix.Extension{Id: oidNameConstraints, Critical: true, Value: value})
}

// What the builder's own reading refuses, by the table: every row is ErrRequest, with no body, in
// printable ASCII, and says that it is the RFC that refuses it (not the standard library's second check).
func TestIntermediateRefusesWhatTheRFCDoesNotAllow(t *testing.T) {
	root := buildRoot(t, nil)
	good := ncSub(dns("example.org"))
	goodValue := ncValue([][]byte{good}, nil)
	type row struct {
		name  string
		value []byte
	}
	var rows []row
	add := func(name string, value []byte) { rows = append(rows, row{name, value}) }

	// The value.
	add("an empty sequence", []byte{0x30, 0x00})
	add("an octet string", append([]byte{0x04}, goodValue[1:]...))
	add("a set", append([]byte{0x31}, goodValue[1:]...))
	add("a context-specific constructed value", append([]byte{0xb0}, goodValue[1:]...))
	add("a primitive sequence tag", append([]byte{0x10}, goodValue[1:]...))
	add("nothing", nil)
	add("a value cut short", goodValue[:len(goodValue)-1])
	add("bytes after the value", append(append([]byte{}, goodValue...), 0x00))
	add("a second value after the first", append(append([]byte{}, goodValue...), goodValue...))
	add("an indefinite length", append(append([]byte{0x30, 0x80}, goodValue[2:]...), 0x00, 0x00))
	add("a length in the long form where the short one suffices", append([]byte{0x30, 0x81, goodValue[1]}, goodValue[2:]...))
	add("an integer where the sequence should be", []byte{0x30, 0x03, 0x02, 0x01, 0x05})

	// The fields.
	add("a field [2]", tlv(0x30, tlv(0xa2, good)))
	add("a field [2] after a good one", tlv(0x30, tlv(0xa0, good), tlv(0xa2, good)))
	add("a field [3]", tlv(0x30, tlv(0xa3, good)))
	add("a field of a high tag number", tlv(0x30, []byte{0xbf, 0x20, 0x02, 0x30, 0x00}))
	add("the excluded list before the permitted one", tlv(0x30, tlv(0xa1, good), tlv(0xa0, good)))
	add("the permitted list twice", tlv(0x30, tlv(0xa0, good), tlv(0xa0, good)))
	add("the excluded list twice", tlv(0x30, tlv(0xa1, good), tlv(0xa1, good)))
	add("both lists and the permitted one again", tlv(0x30, tlv(0xa0, good), tlv(0xa1, good), tlv(0xa0, good)))
	add("the permitted list primitive", tlv(0x30, tlv(0x80, good)))
	add("the excluded list primitive", tlv(0x30, tlv(0x81, good)))
	add("a universal field", tlv(0x30, tlv(0x30, good)))
	add("an application field", tlv(0x30, tlv(0x60, good)))
	add("a private field", tlv(0x30, tlv(0xe0, good)))

	// The lists.
	add("an empty permitted list", tlv(0x30, tlv(0xa0)))
	add("an empty excluded list", tlv(0x30, tlv(0xa1)))
	add("a good permitted list and an empty excluded one", tlv(0x30, tlv(0xa0, good), tlv(0xa1)))
	add("an empty permitted list and a good excluded one", tlv(0x30, tlv(0xa0), tlv(0xa1, good)))
	add("a list of a primitive that is not a subtree", tlv(0x30, tlv(0xa0, tlv(0x04, []byte("x")))))

	// The subtrees.
	add("a subtree that is the base itself, not in a sequence", tlv(0x30, tlv(0xa0, dns("example.org"))))
	add("a subtree that is a set", tlv(0x30, tlv(0xa0, tlv(0x31, dns("example.org")))))
	add("a subtree that is a primitive sequence", tlv(0x30, tlv(0xa0, tlv(0x10, dns("example.org")))))
	add("a subtree of the sequence tag number in the context class", tlv(0x30, tlv(0xa0, tlv(0xb0, dns("example.org")))))
	add("a subtree of the sequence tag number in the application class", tlv(0x30, tlv(0xa0, tlv(0x70, dns("example.org")))))
	add("an empty subtree", tlv(0x30, tlv(0xa0, tlv(0x30))))
	add("a good subtree and then an empty one", tlv(0x30, tlv(0xa0, good, tlv(0x30))))
	add("an empty subtree in the excluded list", tlv(0x30, tlv(0xa1, tlv(0x30))))
	add("a good subtree and then a bad one", tlv(0x30, tlv(0xa0, good, ncSub(tlv(0x89, []byte("x"))))))
	add("a bad subtree in the excluded list", tlv(0x30, tlv(0xa0, good), tlv(0xa1, ncSub(tlv(0x89, []byte("x"))))))
	add("two bases in one subtree", ncValue([][]byte{ncSub(dns("example.org"), dns("example.com"))}, nil))
	add("two bases of different forms", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x86, []byte("example.org")))}, nil))
	add("a minimum of 1", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x80, []byte{1}))}, nil))
	add("a minimum of 0, which DER leaves out", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x80, []byte{0}))}, nil))
	add("a maximum of 5", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x81, []byte{5}))}, nil))
	add("a maximum of 0", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x81, []byte{0}))}, nil))
	add("a minimum and a maximum", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x80, []byte{1}), tlv(0x81, []byte{5}))}, nil))
	add("a minimum of the wrong tag", ncValue([][]byte{ncSub(dns("example.org"), tlv(0x02, []byte{1}))}, nil))
	add("a minimum and a maximum in the excluded list", ncValue(nil, [][]byte{ncSub(dns("example.org"), tlv(0x80, []byte{1}), tlv(0x81, []byte{5}))}))
	add("bytes in a subtree after the base", ncValue([][]byte{ncSub(dns("example.org"), []byte{0x00})}, nil))

	// The tag of the base: the nine are 0 to 8; others are not names.
	forms := gnForms()
	for _, f := range forms {
		flipped := f.base[0] ^ 0x20 // the other form
		add(fmt.Sprintf("%s in the other form", f.name), ncValue([][]byte{ncSub(append([]byte{flipped}, f.base[1:]...))}, nil))
	}
	add("a base of the tag 9", ncValue([][]byte{ncSub(tlv(0x89, []byte("x")))}, nil))
	add("a base of the tag 9, constructed", ncValue([][]byte{ncSub(tlv(0xa9, tlv(0x0c, []byte("x"))))}, nil))
	add("a base of the tag 10", ncValue([][]byte{ncSub(tlv(0x8a, []byte("x")))}, nil))
	add("a base of the tag 30", ncValue([][]byte{ncSub(tlv(0x9e, []byte("x")))}, nil))
	add("a base of the tag 31, in the long form, primitive", ncValue([][]byte{ncSub([]byte{0x9f, 0x1f, 0x01, 'x'})}, nil))
	add("a base of the tag 31, in the long form, constructed", ncValue([][]byte{ncSub([]byte{0xbf, 0x1f, 0x03, 0x0c, 0x01, 'x'})}, nil))
	add("a base of a high tag number", ncValue([][]byte{ncSub([]byte{0x9f, 0x20, 0x01, 'x'})}, nil))
	add("a universal base (a UTF8String)", ncValue([][]byte{ncSub(tlv(0x0c, []byte("x")))}, nil))
	add("a universal base (an IA5String)", ncValue([][]byte{ncSub(tlv(0x16, []byte("example.org")))}, nil))
	add("a universal base (an OID)", ncValue([][]byte{ncSub(tlv(0x06, []byte{0x2b, 6, 1}))}, nil))
	add("an application base", ncValue([][]byte{ncSub(tlv(0x42, []byte("x")))}, nil))
	add("a private base", ncValue([][]byte{ncSub(tlv(0xc2, []byte("example.org")))}, nil))

	if len(rows) < 60 {
		t.Fatalf("only %d rows", len(rows))
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tbs, err := intermediateTBS(t, root.interParams(ncRequest(t, r.value)))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
			if err != nil && (!strings.Contains(err.Error(), "RFC 5280") || strings.Contains(err.Error(), "standard library")) {
				t.Errorf("the refusal is not the reading by the RFC: %q", err.Error())
			}
			// The same value in a request that has every other extension too.
			exts := []pkix.Extension{extBasicConstraints(), extKeyUsage(kuDigitalSignature, kuKeyCertSign, kuCRLSign), {Id: oidNameConstraints, Critical: true, Value: r.value}, ekuExt(false, oidInts(oidServerAuth))}
			tbs, err = intermediateTBS(t, root.interParams(withExtensions(t, exts...)))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
}

// Extended key usage: every form that the builder issues is read by both verifiers. Under the contract these are the four forms that a
// request may have (serverAuth, clientAuth, both in either order, not critical); the rows of the earlier test that issued any
// purpose, other purposes, a purpose twice, a critical flag and thousands of purposes are refused now and are in
// TestExtendedKeyUsageFormsAreRefused (eku_test.go), which replaces them.
func TestExtendedKeyUsageFormsAreVerified(t *testing.T) {
	root := buildRoot(t, nil)
	cases := []struct {
		name string
		eku  func() []pkix.Extension
	}{
		{"serverAuth", func() []pkix.Extension { return []pkix.Extension{ekuExt(false, oidInts(oidServerAuth))} }},
		{"clientAuth", func() []pkix.Extension { return []pkix.Extension{ekuExt(false, oidInts(oidClientAuth))} }},
		{"serverAuth and clientAuth", func() []pkix.Extension {
			return []pkix.Extension{ekuExt(false, oidInts(oidServerAuth), oidInts(oidClientAuth))}
		}},
		{"clientAuth and serverAuth", func() []pkix.Extension {
			return []pkix.Extension{ekuExt(false, oidInts(oidClientAuth), oidInts(oidServerAuth))}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			exts := slices.Concat(goodExtensions()[:3], c.eku())
			csr := withExtensions(t, exts...)
			got := root.issue(t, csr, nil)
			e := extensionOf(got.parsed, oidExtKeyUsage)
			if e == nil || !bytes.Equal(e.Value, c.eku()[0].Value) || e.Critical != c.eku()[0].Critical {
				t.Fatal("the extended key usage is not copied")
			}
			verifyEverywhere(t, root, got, true)
		})
	}
}

func oidInts(o asn1.ObjectIdentifier) []int { return []int(o) }

func ekuExt(critical bool, oids ...[]int) pkix.Extension {
	list := make([]asn1.ObjectIdentifier, len(oids))
	for i, o := range oids {
		list[i] = asn1.ObjectIdentifier(o)
	}
	return extExtKeyUsage(critical, list...)
}
