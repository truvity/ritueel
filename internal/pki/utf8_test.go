package pki_test

import (
	"encoding/asn1"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// A UTF8String that is not UTF-8 is refused by the one reading of a name, in the kind of its source: an issuer (a parameter)
// ErrParams, a subject (a request) ErrRequest, and SameName ErrParams. The attribute types are those that may hold a
// UTF8String (every DirectoryString type of Appendix A.1, and a type that the module does not define).

var badUTF8 = []struct {
	name string
	b    []byte
}{
	{"a lone continuation octet 0x80", []byte{0x80}},
	{"a lone continuation octet 0xbf", []byte{0xbf}},
	{"a truncated two-octet sequence", []byte{0xc2}},
	{"a truncated three-octet sequence", []byte{0xe2, 0x82}},
	{"a truncated four-octet sequence", []byte{0xf0, 0x9f, 0x98}},
	{"a truncated sequence before a letter", []byte{0xe2, 0x82, 'a'}},
	{"an overlong NUL", []byte{0xc0, 0x80}},
	{"an overlong slash", []byte{0xc0, 0xaf}},
	{"the overlong 0xc1 0xbf", []byte{0xc1, 0xbf}},
	{"an overlong of three octets", []byte{0xe0, 0x80, 0x80}},
	{"an overlong of four octets", []byte{0xf0, 0x80, 0x80, 0x80}},
	{"a surrogate, the first", []byte{0xed, 0xa0, 0x80}},
	{"a surrogate, the last", []byte{0xed, 0xbf, 0xbf}},
	{"a code point above U+10FFFF", []byte{0xf4, 0x90, 0x80, 0x80}},
	{"a code point far above U+10FFFF", []byte{0xf7, 0xbf, 0xbf, 0xbf}},
	{"the octet 0xc0", []byte{0xc0}},
	{"the octet 0xc1", []byte{0xc1}},
	{"the octet 0xf5", []byte{0xf5}},
	{"the octet 0xf8", []byte{0xf8}},
	{"the octet 0xfe", []byte{0xfe}},
	{"the octet 0xff", []byte{0xff}},
	{"a continuation octet after a letter", []byte{'a', 0x80}},
	{"a bad octet between good text", []byte("acme \xff ca")},
	{"a bad octet at the end of good text", []byte("acme ca\xc0")},
}

var directoryStringTypes = []struct {
	name string
	oid  []int
}{
	{"name", []int{2, 5, 4, 41}}, {"surname", []int{2, 5, 4, 4}}, {"givenName", []int{2, 5, 4, 42}}, {"initials", []int{2, 5, 4, 43}},
	{"generationQualifier", []int{2, 5, 4, 44}}, {"commonName", []int{2, 5, 4, 3}}, {"localityName", []int{2, 5, 4, 7}},
	{"stateOrProvinceName", []int{2, 5, 4, 8}}, {"organizationName", []int{2, 5, 4, 10}}, {"organizationalUnitName", []int{2, 5, 4, 11}},
	{"title", []int{2, 5, 4, 12}}, {"pseudonym", []int{2, 5, 4, 65}}, {"a type that the module does not define", []int{1, 3, 6, 1, 4, 1, 99999, 7}},
}

func oneAttributeName(oid []int, tag byte, text []byte) []byte {
	return nameOf(rdn(atv(mustOID(oidOfInts(oid)), tlv(tag, text))))
}

func TestInvalidUTF8IsRefusedInTheKindOfItsSource(t *testing.T) {
	root := buildRoot(t, nil)
	good := goodSubject()
	n := 0
	for _, ty := range directoryStringTypes {
		for _, bad := range badUTF8 {
			n++
			t.Run(ty.name+": "+bad.name, func(t *testing.T) {
				name := oneAttributeName(ty.oid, tUTF8, bad.b)
				// As the issuer: a parameter.
				p := root.interParams(withExtensions(t, goodExtensions()...))
				p.IssuerSubject = name
				tbs, err := intermediateTBS(t, p)
				refusedSaying(t, err, pki.ErrParams, "the issuer has a value that is not valid UTF-8")
				if tbs != nil {
					t.Error("a body came with the error")
				}
				// As the subject of a request.
				csr := withExtensions(t, goodExtensions()...)
				csr.RawSubject = name
				der := csr.DER()
				req, err := pki.ParseRequest(der)
				refusedSaying(t, err, pki.ErrRequest, "the subject of the request has a value that is not valid UTF-8")
				if got := pki.CheckOf(err); got != pki.CheckPolicy {
					t.Errorf("check %q, want policy", got)
				}
				assertRefusedForContent(t, req, der)
				if _, err := intermediateTBS(t, root.interParams(csr)); err == nil {
					t.Error("a body for a subject that is not UTF-8")
				}
				// In SameName, as the first name and as the second.
				for _, pair := range [][2][]byte{{name, good}, {good, name}, {name, name}} {
					same, err := pki.SameName(pair[0], pair[1])
					refusedSaying(t, err, pki.ErrParams, "not valid UTF-8")
					if same {
						t.Error("a comparison was made")
					}
				}
			})
		}
	}
	t.Logf("%d rows, each as an issuer, as a subject and in SameName", n)
}

// The same octets in a type that is not a UTF8String are refused as what they are: a PrintableString and an IA5String hold
// no octet above 0x7f, and a type that holds only those does not hold a UTF8String at all.
func TestTheOctetsOfInvalidUTF8InOtherStringTypes(t *testing.T) {
	root := buildRoot(t, nil)
	rows := []struct {
		name string
		oid  []int
		tag  byte
		b    []byte
		ok   bool
	}{
		{"a PrintableString with 0xff", []int{2, 5, 4, 3}, tPrintable, []byte{0xff}, false},
		{"a PrintableString with 0x80", []int{2, 5, 4, 3}, tPrintable, []byte("a\x80"), false},
		{"an IA5String with 0xc3 0xa9", []int{0, 9, 2342, 19200300, 100, 1, 25}, tIA5, []byte("caf\xc3\xa9"), false},
		{"an IA5String with 0xff", []int{1, 2, 840, 113549, 1, 9, 1}, tIA5, []byte{0xff}, false},
		{"a UTF8String for a country", []int{2, 5, 4, 6}, tUTF8, []byte("NL"), false},
		{"a UTF8String that is valid, for a type of PrintableString", []int{2, 5, 4, 5}, tUTF8, []byte("1"), false},
		{"an IA5String that is plain ASCII", []int{0, 9, 2342, 19200300, 100, 1, 25}, tIA5, []byte("example"), true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			name := oneAttributeName(r.oid, r.tag, r.b)
			p := root.interParams(withExtensions(t, goodExtensions()...))
			p.IssuerSubject = name
			_, err := intermediateTBS(t, p)
			if r.ok {
				if err != nil {
					t.Fatalf("refused as an issuer: %v", err)
				}
				return
			}
			refused(t, err, pki.ErrParams)
			csr := withExtensions(t, goodExtensions()...)
			csr.RawSubject = name
			_, err = pki.ParseRequest(csr.DER())
			refused(t, err, pki.ErrRequest)
		})
	}
}

// Valid UTF-8 that is printable ASCII is accepted in an issuer and in a subject, and every other valid UTF-8 is refused in both:
// the issuer is held to the text rule of the subject (the name of a root is ASCII with single spaces, which the rule accepts),
// as a parameter of the caller (ErrParams), and the subject as a request (ErrRequest, check policy). This replaces the test of
// the earlier rule, which accepted an issuer with a control character and any valid UTF-8 of the issuer. SameName compares
// names and holds no text rule, so valid UTF-8 of any text is still compared.
func TestValidUTF8IsRefusedOutsideASCIIInAnIssuerAndASubjectAlike(t *testing.T) {
	root := buildRoot(t, nil)
	valid := []struct {
		name, text string
		ok         bool
	}{
		{"ASCII", "acme root", true},
		{"ASCII with punctuation", "acme, root (1)", true},
		{"a two-octet letter", "caf\u00e9", false},
		{"a three-octet letter", "\u4e2d\u6587", false},
		{"a four-octet letter", "\U00020000", false},
		{"the last code point", "a\U0010FFFF", false},
		{"U+FFFD", "a\ufffd", false},
		{"U+D7FF, before the surrogates", "a\ud7ff", false},
		{"U+E000, after the surrogates", "a\ue000", false},
		{"a noncharacter", "a\ufffe", false},
		{"U+0080, the first C1 character", "a\u0080", false},
		{"a NUL", "a\x00b", false}, {"a control character", "a\x01b", false}, {"a tab", "a\tb", false}, {"DEL", "a\x7fb", false}, {"U+0085", "a\u0085b", false},
		{"a leading space", " acme", false}, {"two spaces", "acme  root", false}, {"U+202E", "a\u202eb", false},
	}
	for _, v := range valid {
		t.Run(v.name, func(t *testing.T) {
			p := root.interParams(withExtensions(t, goodExtensions()...))
			p.IssuerSubject = oneAttributeName([]int{2, 5, 4, 3}, tUTF8, []byte(v.text))
			_, err := intermediateTBS(t, p)
			csr := withExtensions(t, goodExtensions()...)
			csr.RawSubject = oneAttributeName([]int{2, 5, 4, 3}, tUTF8, []byte(v.text))
			der := csr.DER()
			req, err2 := pki.ParseRequest(der)
			if v.ok {
				if err != nil || err2 != nil {
					t.Errorf("refused: as an issuer %v, as a subject %v", err, err2)
				}
			} else {
				refused(t, err, pki.ErrParams)
				refused(t, err2, pki.ErrRequest)
				if got := pki.CheckOf(err2); got != pki.CheckPolicy {
					t.Errorf("check %q, want policy", got)
				}
				assertRefusedForContent(t, req, der)
				for _, e := range []error{err, err2} {
					if e != nil && strings.Contains(e.Error(), "not valid UTF-8") {
						t.Errorf("valid UTF-8 is called invalid: %v", e)
					}
				}
			}
			if same, err := pki.SameName(p.IssuerSubject, p.IssuerSubject); err != nil || !same {
				t.Errorf("SameName: %v, %v", same, err)
			}
		})
	}
}

func oidOfInts(a []int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(a) }
