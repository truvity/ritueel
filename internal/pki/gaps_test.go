package pki_test

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

// Tests that the mutation round found missing: each row is a refusal that has to come from the rule of its own
// part, so the text of the error is held to say so (a refusal that only comes later from the standard library's
// second check is not the rule).

func refusedSaying(t *testing.T, err error, kind error, words string) {
	t.Helper()
	refused(t, err, kind)
	if err != nil && !strings.Contains(err.Error(), words) {
		t.Errorf("the text does not say %q: %q", words, err.Error())
	}
	if err != nil && strings.Contains(err.Error(), "standard library") {
		t.Errorf("the refusal is the second check of the standard library: %q", err.Error())
	}
}

func TestNameConstraintsWithStrayBytesAndExcludedListsThatAreNotTheContract(t *testing.T) {
	root := buildRoot(t, nil)
	good := ncSub(dns("example.org"))
	v4, v6 := ipSub(8), ipSub(32)
	rows := []struct {
		name  string
		value []byte
		words string
	}{
		{"a stray octet after the permitted list, inside the sequence", tlv(0x30, tlv(0xa0, good), []byte{0x00}), "not DER"},
		{"a stray octet after both lists", tlv(0x30, tlv(0xa0, good), tlv(0xa1, v4, v6), []byte{0x00}), "not DER"},
		{"a stray octet inside the permitted list", tlv(0x30, tlv(0xa0, good, []byte{0x00})), "not a DER sequence"},
		{"a stray octet inside the excluded list", tlv(0x30, tlv(0xa0, good), tlv(0xa1, v4, v6, []byte{0x00})), "not a DER sequence"},
		{"the excluded lists alone, both address spaces", ncValue(nil, [][]byte{v4, v6}), "no permitted subtree"},
		{"the excluded list alone, one address space", ncValue(nil, [][]byte{v4}), "no permitted subtree"},
		{"an excluded address space and a DNS name", ncValue([][]byte{good}, [][]byte{v4, ncSub(dns("example.com"))}), "excluded subtrees"},
		{"a DNS name and an excluded address space", ncValue([][]byte{good}, [][]byte{ncSub(dns("example.com")), v6}), "excluded subtrees"},
		{"the IPv4 space twice", ncValue([][]byte{good}, [][]byte{v4, v4}), "excluded subtrees"},
		{"the IPv6 space twice", ncValue([][]byte{good}, [][]byte{v6, v6}), "excluded subtrees"},
		{"the IPv4 space and a smaller IPv6 range", ncValue([][]byte{good}, [][]byte{v4, ncSub(tlv(0x87, append([]byte{0x20, 0x01}, make([]byte, 30)...)))}), "excluded subtrees"},
		{"the IPv4 space with a mask of one bit and the IPv6 space", ncValue([][]byte{good}, [][]byte{ncSub(tlv(0x87, []byte{0, 0, 0, 0, 128, 0, 0, 0})), v6}), "excluded subtrees"},
		{"three excluded subtrees", ncValue([][]byte{good}, [][]byte{v4, v6, v4}), "excluded subtrees"},
		{"one excluded IPv6 space", ncValue([][]byte{good}, [][]byte{v6}), "excluded subtrees"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tbs, err := intermediateTBS(t, root.interParams(ncRequest(t, r.value)))
			refusedSaying(t, err, pki.ErrRequest, r.words)
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
}

func TestNamesWithStrayBytesAndNamesOfDifferentLengths(t *testing.T) {
	root := buildRoot(t, nil)
	cn := atv(oidAttrCN, str(tUTF8, "ca"))
	good := withExtensions(t, goodExtensions()...)
	badNames := []struct {
		name string
		raw  []byte
	}{
		{"a stray octet after the last relative name", tlv(0x30, rdn(cn), []byte{0x00})},
		{"a stray octet after the last attribute of a relative name", tlv(0x30, tlv(0x31, cn, []byte{0x00}))},
		{"a stray octet between two relative names", tlv(0x30, rdn(cn), []byte{0x00}, rdn(atv(oidAttrO, str(tUTF8, "x"))))},
	}
	for _, n := range badNames {
		t.Run("the subject has "+n.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = n.raw
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refusedSaying(t, err, pki.ErrRequest, "subject of the request")
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
		t.Run("the issuer has "+n.name, func(t *testing.T) {
			p := root.interParams(good)
			p.IssuerSubject = n.raw
			tbs, err := intermediateTBS(t, p)
			refusedSaying(t, err, pki.ErrParams, "the issuer")
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
	// A value that is not UTF-8 in a UTF8String is refused by the rule of the text.
	for name, text := range map[string]string{"a lone continuation octet": "a\x80b", "a truncated sequence": "a\xe2\x82", "an overlong encoding": "a\xc0\x80b", "a surrogate": "a\xed\xa0\x80b", "a code point above U+10FFFF": "a\xf4\x90\x80\x80b"} {
		t.Run("a subject with "+name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = nameOf(rdn(atv(oidAttrCN, tlv(tUTF8, []byte(text)))))
			_, err := intermediateTBS(t, root.interParams(csr))
			refusedSaying(t, err, pki.ErrRequest, "UTF-8")
		})
	}
	// Names of other lengths than the issuer's, with the same beginning, are other names; a name made only of white
	// space is a name with nothing in it, and must not be read past its end.
	o := func(s string) []byte { return rdn(atv(oidAttrO, str(tUTF8, s))) }
	c := func(s string) []byte { return rdn(atv(oidAttrCN, str(tUTF8, s))) }
	loc := func(s string) []byte { return rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 7}), str(tUTF8, s))) }
	pairs := []struct {
		name            string
		issuer, subject []byte
	}{
		{"a subject that is the issuer without its last relative name", nameOf(o("acme"), c("root")), nameOf(o("acme"))},
		{"a subject that is the issuer and one more relative name", nameOf(o("acme")), nameOf(o("acme"), c("ca"))},
		{"a subject that is the first relative names of a longer issuer", nameOf(o("a"), loc("b"), c("root")), nameOf(o("a"), loc("b"))},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = p.subject
			params := root.interParams(csr)
			params.IssuerSubject = p.issuer
			tbs, err := intermediateTBS(t, params)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got := parseBodyOf(t, tbs); string(got.RawIssuer) != string(p.issuer) || string(got.RawSubject) != string(p.subject) {
				t.Error("the names are not copied")
			}
		})
	}
	// An issuer that holds white space, a tab or a byte of 0x80 and above is refused now by the text rule of the issuer (it was
	// a pair that passed under the earlier rule, to show that the name compare did not read past the end of a name of white space; the
	// name compare itself is tested in SameName's tests).
	badIssuers := []struct {
		name   string
		issuer []byte
		words  string
	}{
		{"an issuer of one space", nameOf(c(" ")), "a space at its start or its end"},
		{"an issuer of spaces", nameOf(c("     ")), "a space at its start or its end"},
		{"an issuer of white space of every kind", nameOf(c(" \t\n\v\f\r ")), "outside printable ASCII"},
		{"an issuer of one tab", nameOf(c("\t")), "outside printable ASCII"},
		{"an issuer with a space between two letters and spaces at both ends", nameOf(c("  a  b  ")), "a space at its start or its end"},
		{"an issuer with a byte of 0x80 and above", nameOf(c("a\u0080b")), "outside printable ASCII"},
	}
	for _, p := range badIssuers {
		t.Run(p.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = nameOf(c("ca"))
			params := root.interParams(csr)
			params.IssuerSubject = p.issuer
			tbs, err := intermediateTBS(t, params)
			refusedSaying(t, err, pki.ErrParams, p.words)
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
}

func TestTheKeyOfTheRequestIsNotTheKeyOfTheIssuer(t *testing.T) {
	root := buildRoot(t, nil)
	csr := withExtensions(t, goodExtensions()...)
	csr.Key = root.key
	csr.RawSubjectPublicKeyInfo = nil
	tbs, err := intermediateTBS(t, root.interParams(csr))
	refusedSaying(t, err, pki.ErrRequest, "the key of the request is the key of the issuer")
	if tbs != nil {
		t.Error("a body came with the error")
	}
}

func TestTheMessagesOfTheExtensionRules(t *testing.T) {
	root := buildRoot(t, nil)
	bc, ku := extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign)
	kuBits := ku.Value
	eku := extExtKeyUsage(false, oidServerAuth)
	rows := []struct {
		name  string
		exts  []pkix.Extension
		words string
	}{
		{"no key usage", []pkix.Extension{bc}, "no key usage"},
		{"no basic constraints", []pkix.Extension{ku}, "no basic constraints"},
		{"a key usage with a stray octet", []pkix.Extension{bc, {Id: oidKeyUsage, Critical: true, Value: append(append([]byte{}, kuBits...), 0)}}, "key usage is not one DER bit string"},
		{"a key usage that is not a bit string", []pkix.Extension{bc, {Id: oidKeyUsage, Critical: true, Value: []byte{0x04, 0x01, 0x06}}}, "key usage is not one DER bit string"},
		{"an extended key usage with a stray octet", []pkix.Extension{bc, ku, {Id: oidExtKeyUsage, Value: append(append([]byte{}, eku.Value...), 0)}}, "extended key usage is not a non-empty list"},
		{"an empty extended key usage", []pkix.Extension{bc, ku, {Id: oidExtKeyUsage, Value: []byte{0x30, 0x00}}}, "extended key usage is not a non-empty list"},
		{"an extended key usage that is not a sequence", []pkix.Extension{bc, ku, {Id: oidExtKeyUsage, Value: []byte{0x31, 0x00}}}, "extended key usage is not a non-empty list"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tbs, err := intermediateTBS(t, root.interParams(withExtensions(t, r.exts...)))
			refusedSaying(t, err, pki.ErrRequest, r.words)
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
}

// The messages of the rules for the name and the time of a root: each rule is told from the one after it by what it says.
func TestTheRulesForARootNameAndTimeSayWhichRuleRefusedIt(t *testing.T) {
	key := newKey(t)
	rows := []struct {
		name  string
		edit  func(p *pki.RootParams)
		words string
	}{
		{"a name of 65 characters", func(p *pki.RootParams) { p.Name = strings.Repeat("a", 65) }, "has 65 characters, not 1 to 45"},
		{"a name of 46 characters", func(p *pki.RootParams) { p.Name = strings.Repeat("a", 46) }, "has 46 characters, not 1 to 45"},
		{"an empty name", func(p *pki.RootParams) { p.Name = "" }, "has 0 characters, not 1 to 45"},
		{"a name with a space at its start", func(p *pki.RootParams) { p.Name = " abc" }, "a space at its start or its end"},
		{"a name with a space at its end", func(p *pki.RootParams) { p.Name = "abc " }, "a space at its start or its end"},
		{"a name of one space", func(p *pki.RootParams) { p.Name = " " }, "a space at its start or its end"},
		{"a name with two spaces in a row", func(p *pki.RootParams) { p.Name = "ab  cd" }, "two spaces in a row"},
		{"a name that starts with a character that is not allowed", func(p *pki.RootParams) { p.Name = "*abc" }, "at position 0"},
		{"a name with a character that is not allowed in the middle", func(p *pki.RootParams) { p.Name = "ab*cd" }, "at position 2"},
		{"a name that ends with a character that is not allowed", func(p *pki.RootParams) { p.Name = "abc*" }, "at position 3"},
		{"a name of characters of the edges of the ranges", func(p *pki.RootParams) { p.Name = "/:@[`{" }, "at position 0"},
		{"a time in the year 0", func(p *pki.RootParams) { p.CeremonyTime = utc(0, 12, 31, 23, 59, 59) }, "before the year 1"},
		{"a time in the year 10000", func(p *pki.RootParams) { p.CeremonyTime = utc(10000, 1, 1, 0, 0, 0) }, "after the year 9999"},
		{"a time with a fraction of a second", func(p *pki.RootParams) { p.CeremonyTime = p.CeremonyTime.Add(time.Nanosecond) }, "fraction of a second"},
		{"the zero time", func(p *pki.RootParams) { p.CeremonyTime = time.Time{} }, "zero time"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			p := rootParams(&key.PublicKey)
			r.edit(&p)
			tbs, err := pki.RootTBS(p)
			refusedSaying(t, err, pki.ErrParams, r.words)
			if tbs != nil {
				t.Error("a body came with the error")
			}
		})
	}
	t.Run("names of every allowed character are accepted", func(t *testing.T) {
		for _, name := range []string{"aZ09-", "a b-c", "z", "A", "0", "9", "-", strings.Repeat("n", 45)} {
			p := rootParams(&key.PublicKey)
			p.Name = name
			if _, err := pki.RootTBS(p); err != nil {
				t.Errorf("%q: %v", name, err)
			}
		}
	})
	t.Run("a serial of zero says that it is not positive", func(t *testing.T) {
		refusedSaying(t, pki.CheckSerial(new(big.Int)), pki.ErrParams, "not positive")
		refusedSaying(t, pki.CheckSerial(big.NewInt(-1)), pki.ErrParams, "not positive")
	})
}
