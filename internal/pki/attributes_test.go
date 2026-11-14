package pki_test

import (
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The attribute types of RFC 5280, Appendix A.1, written out from the module (lines "id-at-..." and the
// X520 types), with their object identifiers, string types and sizes. The upper bounds are the module's
// "Upper Bounds" block, which it says "MUST be regarded as mandatory": ub-name 32768, ub-common-name 64,
// ub-locality-name 128, ub-state-name 128, ub-organization-name 64, ub-organizational-unit-name 64,
// ub-title 64, ub-serial-number 64, ub-pseudonym 128, ub-emailaddress-length 255.
//
//	type                 OID                           string types                      size
//	name                 2.5.4.41                      DirectoryString                   1..32768
//	surname              2.5.4.4                       DirectoryString                   1..32768
//	givenName            2.5.4.42                      DirectoryString                   1..32768
//	initials             2.5.4.43                      DirectoryString                   1..32768
//	generationQualifier  2.5.4.44                      DirectoryString                   1..32768
//	commonName           2.5.4.3                       DirectoryString                   1..64
//	localityName         2.5.4.7                       DirectoryString                   1..128
//	stateOrProvinceName  2.5.4.8                       DirectoryString                   1..128
//	organizationName     2.5.4.10                      DirectoryString                   1..64
//	organizationalUnit   2.5.4.11                      DirectoryString                   1..64
//	title                2.5.4.12                      DirectoryString                   1..64
//	pseudonym            2.5.4.65                      DirectoryString                   1..128
//	dnQualifier          2.5.4.46                      PrintableString                   (no size)
//	countryName          2.5.4.6                       PrintableString                   2
//	serialNumber         2.5.4.5                       PrintableString                   1..64
//	domainComponent      0.9.2342.19200300.100.1.25    IA5String                         (no size)
//	emailAddress         1.2.840.113549.1.9.1          IA5String                         1..255
//
// A DirectoryString is a PrintableString or a UTF8String for this CA (4.1.2.4). A size counts characters.
// The module gives no lower bound to dnQualifier and domainComponent, so by its letter an empty value is
// allowed; the builder refuses an empty one, which is stricter than the module.

type attrRow struct {
	name   string
	oid    []byte
	max    int
	tags   []byte // the string types allowed
	minLen int
}

func attrRows() []attrRow {
	oid := func(a ...int) []byte { return mustOID(asn1.ObjectIdentifier(a)) }
	ds := []byte{tPrintable, tUTF8}
	return []attrRow{
		{"name", oid(2, 5, 4, 41), 32768, ds, 1},
		{"surname", oid(2, 5, 4, 4), 32768, ds, 1},
		{"givenName", oid(2, 5, 4, 42), 32768, ds, 1},
		{"initials", oid(2, 5, 4, 43), 32768, ds, 1},
		{"generationQualifier", oid(2, 5, 4, 44), 32768, ds, 1},
		{"commonName", oid(2, 5, 4, 3), 64, ds, 1},
		{"localityName", oid(2, 5, 4, 7), 128, ds, 1},
		{"stateOrProvinceName", oid(2, 5, 4, 8), 128, ds, 1},
		{"organizationName", oid(2, 5, 4, 10), 64, ds, 1},
		{"organizationalUnitName", oid(2, 5, 4, 11), 64, ds, 1},
		{"title", oid(2, 5, 4, 12), 64, ds, 1},
		{"pseudonym", oid(2, 5, 4, 65), 128, ds, 1},
		{"serialNumber", oid(2, 5, 4, 5), 64, []byte{tPrintable}, 1},
		{"countryName", oid(2, 5, 4, 6), 2, []byte{tPrintable}, 2},
		{"emailAddress", oid(1, 2, 840, 113549, 1, 9, 1), 255, []byte{tIA5}, 1},
	}
}

func oneAttr(oid []byte, tag byte, value []byte) []byte {
	return nameOf(rdn(atv(oid, tlv(tag, value))))
}

// At each bound: a value of exactly the upper size is issued and verified by both verifiers, one more
// character is refused; and below the lower size is refused.
func TestAttributeSizesAtTheirBounds(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	issueName := func(t *testing.T, raw []byte) {
		t.Helper()
		csr := copyCSR(good)
		csr.RawSubject = raw
		verifyEverywhere(t, root, root.issue(t, csr, nil), true)
	}
	refuseName := func(t *testing.T, raw []byte, say string) {
		t.Helper()
		csr := copyCSR(good)
		csr.RawSubject = raw
		tbs, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
		if tbs != nil {
			t.Error("a body came with the error")
		}
		if err != nil && (!strings.Contains(err.Error(), say) || strings.Contains(err.Error(), "standard library")) {
			t.Errorf("the text is not the reading's (%q): %q", say, err.Error())
		}
		p := root.interParams(good)
		p.IssuerSubject = raw
		_, err = intermediateTBS(t, p)
		refused(t, err, pki.ErrParams)
		if err != nil && !strings.Contains(err.Error(), say) {
			t.Errorf("the text for the issuer is not the reading's (%q): %q", say, err.Error())
		}
	}
	for _, a := range attrRows() {
		for _, tag := range a.tags {
			label := fmt.Sprintf("%s as %s", a.name, map[byte]string{tPrintable: "PrintableString", tUTF8: "UTF8String", tIA5: "IA5String"}[tag])
			fill := strings.Repeat("a", a.max)
			t.Run(label+" of "+fmt.Sprint(a.max), func(t *testing.T) { issueName(t, oneAttr(a.oid, tag, []byte(fill))) })
			t.Run(label+" of "+fmt.Sprint(a.max+1), func(t *testing.T) {
				refuseName(t, oneAttr(a.oid, tag, []byte(fill+"a")), "SIZE constraint")
			})
			if a.minLen > 1 { // the country: one character is too few as well as three too many
				t.Run(label+" of 1", func(t *testing.T) { refuseName(t, oneAttr(a.oid, tag, []byte("a")), "SIZE constraint") })
			} else { // the lower bound: one character is issued
				t.Run(label+" of 1", func(t *testing.T) { issueName(t, oneAttr(a.oid, tag, []byte("a"))) })
			}
			t.Run(label+" that is empty", func(t *testing.T) { refuseName(t, oneAttr(a.oid, tag, nil), "empty string") })
		}
	}
	t.Run("a country of exactly 2 characters, issued", func(t *testing.T) {
		issueName(t, nameOf(rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 6}), str(tPrintable, "NL"))), rdn(atv(oidAttrCN, str(tUTF8, "ca")))))
	})
	t.Run("a country of 3 characters", func(t *testing.T) {
		refuseName(t, oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 6}), tPrintable, []byte("NLD")), "SIZE constraint")
	})
	t.Run("three UTF8Strings that fill the name bound, the subject then longer than 65536 octets", func(t *testing.T) {
		fill := []byte(strings.Repeat("a", 32768))
		raw := nameOf(rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 41}), tlv(tUTF8, fill))), rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 4}), tlv(tUTF8, fill))), rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 42}), tlv(tUTF8, fill))))
		if len(raw) <= 65536 {
			t.Fatalf("the subject has %d octets", len(raw))
		}
		issueName(t, raw)
	})
}

// Sizes are in characters, and with the text of a subject printable ASCII a character is an octet: 64 characters are issued,
// 65 are refused by the size. A value of non-ASCII characters of 2, 3 or 4 octets is refused by the text rule, at 64
// characters as at 65 (the earlier test, which counted such characters, is replaced by this one: with the text rule of the contract no
// value has a character of more than one octet).
func TestAttributeSizesAreCountedInOctetsNowThatTheTextIsASCII(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	cn := mustOID(asn1.ObjectIdentifier{2, 5, 4, 3})
	t.Run("64 characters are issued", func(t *testing.T) {
		csr := copyCSR(good)
		csr.RawSubject = oneAttr(cn, tUTF8, []byte(strings.Repeat("a", 64)))
		verifyEverywhere(t, root, root.issue(t, csr, nil), true)
	})
	t.Run("65 characters are refused by the size", func(t *testing.T) {
		csr := copyCSR(good)
		csr.RawSubject = oneAttr(cn, tUTF8, []byte(strings.Repeat("a", 65)))
		_, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
		if err != nil && !strings.Contains(err.Error(), "SIZE constraint") {
			t.Errorf("not the size rule: %q", err.Error())
		}
		if got := pki.CheckOf(err); got != pki.CheckPolicy {
			t.Errorf("check %q, want policy", got)
		}
	})
	for _, c := range []struct {
		name string
		char string
	}{{"two-octet characters", "\u00e9"}, {"three-octet characters", "\u20ac"}, {"four-octet characters", "\U0001F600"}} {
		for _, n := range []int{1, 64, 65} {
			t.Run(fmt.Sprintf("%d %s are refused by the text", n, c.name), func(t *testing.T) {
				csr := copyCSR(good)
				csr.RawSubject = oneAttr(cn, tUTF8, []byte(strings.Repeat(c.char, n)))
				_, err := intermediateTBS(t, root.interParams(csr))
				refused(t, err, pki.ErrRequest)
				if got := pki.CheckOf(err); got != pki.CheckPolicy {
					t.Errorf("check %q, want policy", got)
				}
				if err != nil && !strings.Contains(err.Error(), "printable ASCII") && !strings.Contains(err.Error(), "SIZE constraint") {
					t.Errorf("neither the text rule nor the size rule: %q", err.Error())
				}
			})
		}
	}
}

// Attribute types without a bound: a type that the module does not define, the distinguished name
// qualifier and the domain component. Long values are issued, verified by both verifiers.
func TestAttributesWithoutABound(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	dnq := mustOID(asn1.ObjectIdentifier{2, 5, 4, 46})
	for _, r := range []namedRow{
		{"an undefined type of 5000 characters, UTF8String", oneAttr(oidAttrUnknown, tUTF8, []byte(strings.Repeat("x", 5000)))},
		{"an undefined type of 5000 characters, PrintableString", oneAttr(oidAttrUnknown, tPrintable, []byte(strings.Repeat("x", 5000)))},
		{"a distinguished name qualifier of 1000 characters", oneAttr(dnq, tPrintable, []byte(strings.Repeat("x", 1000)))},
		{"a domain component of 400 characters", oneAttr(oidAttrDC, tIA5, []byte(strings.Repeat("x", 400)))},
		{"an undefined type of 1 character", oneAttr(oidAttrUnknown, tUTF8, []byte("x"))},
		{"a distinguished name qualifier of 1 character", oneAttr(dnq, tPrintable, []byte("x"))},
		{"a domain component of 1 character", oneAttr(oidAttrDC, tIA5, []byte("x"))},
		{"a street (2.5.4.9) of 200 characters", oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 9}), tUTF8, []byte(strings.Repeat("x", 200)))},
	} {
		t.Run(r.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = r.raw
			verifyEverywhere(t, root, root.issue(t, csr, nil), true)
		})
	}
}

// Empty values of the types that have no upper bound are refused too: the lower bound is 1 for an undefined
// type, and the builder holds it for the distinguished name qualifier and the domain component, where the
// module gives none (stricter than the module).
func TestEmptyValuesOfTypesWithoutABoundAreRefused(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	dnq := mustOID(asn1.ObjectIdentifier{2, 5, 4, 46})
	for _, r := range []namedRow{
		{"an undefined type, UTF8String", oneAttr(oidAttrUnknown, tUTF8, nil)},
		{"an undefined type, PrintableString", oneAttr(oidAttrUnknown, tPrintable, nil)},
		{"a distinguished name qualifier", oneAttr(dnq, tPrintable, nil)},
		{"a domain component", oneAttr(oidAttrDC, tIA5, nil)},
	} {
		t.Run(r.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = r.raw
			_, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if err != nil && !strings.Contains(err.Error(), "empty string") {
				t.Errorf("not the empty string rule: %q", err.Error())
			}
		})
	}
}

// The character set of a PrintableString: every character of the set is accepted (in a name attribute, with
// both verifiers) and a sample outside it is refused.
func TestPrintableStringCharacterSet(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	const set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
	nameAttr := mustOID(asn1.ObjectIdentifier{2, 5, 4, 41})
	t.Run("all 74 characters of the set", func(t *testing.T) {
		if len(set) != 74 {
			t.Fatalf("the set has %d characters", len(set))
		}
		csr := copyCSR(good)
		csr.RawSubject = oneAttr(nameAttr, tPrintable, []byte(set))
		verifyEverywhere(t, root, root.issue(t, csr, nil), true)
	})
	for i := 0; i < len(set); i++ {
		ch := set[i : i+1]
		t.Run(fmt.Sprintf("the character %q is accepted", ch), func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = oneAttr(oidAttrCN, tPrintable, []byte("a"+ch+"b"))
			if _, err := intermediateTBS(t, root.interParams(csr)); err != nil {
				t.Fatal(err)
			}
		})
	}
	outside := "!\"#$%&*;<>@[\\]^_`{|}~" + "\x00\x01\t\n\r\x1f\x7f" + "\x80\xc3\xa9\xff"
	for i := 0; i < len(outside); i++ {
		ch := outside[i : i+1]
		t.Run(fmt.Sprintf("the byte %q is refused", ch), func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = oneAttr(oidAttrCN, tPrintable, []byte("a"+ch+"b"))
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Error("a body came with the error")
			}
			if err != nil && (!strings.Contains(err.Error(), "character set") || strings.Contains(err.Error(), "standard library")) {
				t.Errorf("not the reading's character set rule: %q", err.Error())
			}
			p := root.interParams(good)
			p.IssuerSubject = oneAttr(oidAttrCN, tPrintable, []byte("a"+ch+"b"))
			_, err = intermediateTBS(t, p)
			refused(t, err, pki.ErrParams)
		})
	}
	t.Run("a non-ASCII letter in a PrintableString, as a letter", func(t *testing.T) {
		csr := copyCSR(good)
		csr.RawSubject = oneAttr(oidAttrCN, tPrintable, []byte("café"))
		_, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
	})
}

// IA5String is 7-bit: any ASCII character is accepted, a byte of 0x80 or above is refused.
func TestIA5StringIsSevenBit(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	t.Run("ASCII punctuation in a domain component and an e-mail address", func(t *testing.T) {
		csr := copyCSR(good)
		csr.RawSubject = nameOf(rdn(atv(oidAttrDC, str(tIA5, "a*b&c@d_e!"))), rdn(atv(oidAttrEmail, str(tIA5, "a b@c_d.org"))), rdn(atv(oidAttrCN, str(tUTF8, "ca"))))
		verifyEverywhere(t, root, root.issue(t, csr, nil), true)
	})
	// The control characters are ASCII, and an IA5String may hold them, but the text of a subject may not, and the issuer is
	// held to the same text rule (a root's name is "<name> Root <label>", ASCII with single spaces). Before the text rule held the issuer it was
	// read for its structure only and these were accepted there.
	t.Run("DEL and the control characters in the issuer, in a domain component, are refused by the text rule", func(t *testing.T) {
		p := root.interParams(good)
		p.IssuerSubject = nameOf(rdn(atv(oidAttrDC, str(tIA5, "a\x01\x1f\x7f"))), rdn(atv(oidAttrCN, str(tUTF8, "ca"))))
		_, err := intermediateTBS(t, p)
		refusedSaying(t, err, pki.ErrParams, "printable ASCII")
		if got := pki.CheckOf(err); got != pki.CheckNone {
			t.Errorf("the issuer is the caller's: check %q, want none", got)
		}
	})
	for _, b := range []string{"\x80", "\xc3\xa9", "\xff", "\x7f\x80"} {
		for _, o := range []struct {
			name string
			oid  []byte
		}{{"a domain component", oidAttrDC}, {"an e-mail address", oidAttrEmail}} {
			t.Run(fmt.Sprintf("%s with the bytes %x", o.name, b), func(t *testing.T) {
				csr := copyCSR(good)
				csr.RawSubject = oneAttr(o.oid, tIA5, []byte("a"+b+"b"))
				tbs, err := intermediateTBS(t, root.interParams(csr))
				refused(t, err, pki.ErrRequest)
				if tbs != nil {
					t.Error("a body came with the error")
				}
				if err != nil && (!strings.Contains(err.Error(), "ASCII") || strings.Contains(err.Error(), "standard library")) {
					t.Errorf("not the reading's ASCII rule: %q", err.Error())
				}
				p := root.interParams(good)
				p.IssuerSubject = oneAttr(o.oid, tIA5, []byte("a"+b+"b"))
				_, err = intermediateTBS(t, p)
				refused(t, err, pki.ErrParams)
			})
		}
	}
}

// The types: the three attributes that the module gives a PrintableString take nothing else, a
// DirectoryString attribute takes a PrintableString or a UTF8String and no IA5String, and the two IA5String
// attributes take nothing else.
func TestAttributeStringTypes(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	serial := mustOID(asn1.ObjectIdentifier{2, 5, 4, 5})
	dnq := mustOID(asn1.ObjectIdentifier{2, 5, 4, 46})
	country := mustOID(asn1.ObjectIdentifier{2, 5, 4, 6})
	ok := []namedRow{
		{"a country as PrintableString", oneAttr(country, tPrintable, []byte("NL"))},
		{"a serial number as PrintableString", oneAttr(serial, tPrintable, []byte("123 456"))},
		{"a distinguished name qualifier as PrintableString", oneAttr(dnq, tPrintable, []byte("abc"))},
		{"a title as UTF8String", oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 12}), tUTF8, []byte("Dr E"))},
		{"a name as UTF8String", oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 41}), tUTF8, []byte("Example EUR"))},
		{"a locality as PrintableString", oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 7}), tPrintable, []byte("Amsterdam"))},
		{"an organisation as UTF8String", oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 10}), tUTF8, []byte("Acme E"))},
		{"an e-mail address as IA5String of 255 characters", oneAttr(oidAttrEmail, tIA5, []byte(strings.Repeat("a", 243)+"@example.org"))},
		{"a domain component as IA5String", oneAttr(oidAttrDC, tIA5, []byte("example"))},
	}
	for _, r := range ok {
		t.Run(r.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = r.raw
			verifyEverywhere(t, root, root.issue(t, csr, nil), true)
		})
	}
	bad := []struct {
		namedRow
		say string
	}{
		{namedRow{"a country as UTF8String", oneAttr(country, tUTF8, []byte("NL"))}, "not a PrintableString"},
		{namedRow{"a serial number as UTF8String", oneAttr(serial, tUTF8, []byte("123"))}, "not a PrintableString"},
		{namedRow{"a distinguished name qualifier as UTF8String", oneAttr(dnq, tUTF8, []byte("abc"))}, "not a PrintableString"},
		{namedRow{"a country as IA5String", oneAttr(country, tIA5, []byte("NL"))}, "not a PrintableString"},
		{namedRow{"a serial number as IA5String", oneAttr(serial, tIA5, []byte("1"))}, "not a PrintableString"},
		{namedRow{"a common name as IA5String", oneAttr(oidAttrCN, tIA5, []byte("ca"))}, "PrintableString or a UTF8String"},
		{namedRow{"a locality as IA5String", oneAttr(mustOID(asn1.ObjectIdentifier{2, 5, 4, 7}), tIA5, []byte("x"))}, "PrintableString or a UTF8String"},
		{namedRow{"an e-mail address as UTF8String", oneAttr(oidAttrEmail, tUTF8, []byte("a@b"))}, "not an IA5String"},
		{namedRow{"an e-mail address as PrintableString", oneAttr(oidAttrEmail, tPrintable, []byte("a.b"))}, "not an IA5String"},
		{namedRow{"a domain component as UTF8String", oneAttr(oidAttrDC, tUTF8, []byte("example"))}, "not an IA5String"},
	}
	for _, r := range bad {
		t.Run(r.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = r.raw
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Error("a body came with the error")
			}
			if err != nil && !strings.Contains(err.Error(), r.say) {
				t.Errorf("the text is not %q: %q", r.say, err.Error())
			}
		})
	}
}
