package pki_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"os/exec"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// opensslNameHash is the hash that OpenSSL gives to the subject of a certificate: it is made from the canonical
// form of the name (the text as UTF-8, white space trimmed and folded, ASCII letters in lower case), so two names that
// OpenSSL calls the same have the same hash. It is the ground for the table below, and it does not come from the code.
func opensslNameHash(t *testing.T, name []byte) string {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), RawSubject: name, NotBefore: ceremony, NotAfter: ceremony.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("a certificate of the name %x: %v", name, err)
	}
	bin := verifier.Require(t, "openssl")
	cmd := exec.Command(bin, "x509", "-inform", "DER", "-noout", "-subject_hash")
	cmd.Stdin = strings.NewReader(string(der))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509: %v: %q", err, out)
	}
	return strings.TrimSpace(string(out))
}

// textAdmissible says whether every string of a name holds the text rule of the contract, read here with the standard library from the
// DER of the name: the octets are U+0020 to U+007E (the strings of these tests are ASCII or the rows that are not), no space at
// either end and no two in a row.
func textAdmissible(t *testing.T, name []byte) bool {
	t.Helper()
	var rdns asn1.RawValue
	if rest, err := asn1.Unmarshal(name, &rdns); err != nil || len(rest) != 0 {
		t.Fatalf("not a name: %v", err)
	}
	ok := true
	for rest := rdns.Bytes; len(rest) > 0; {
		var set asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &set); err != nil {
			t.Fatal(err)
		}
		for in := set.Bytes; len(in) > 0; {
			var atvv asn1.RawValue
			if in, err = asn1.Unmarshal(in, &atvv); err != nil {
				t.Fatal(err)
			}
			var oid asn1.ObjectIdentifier
			val, err := asn1.UnmarshalWithParams(atvv.Bytes, &oid, "")
			if err != nil {
				t.Fatal(err)
			}
			var str asn1.RawValue
			if _, err := asn1.Unmarshal(val, &str); err != nil {
				t.Fatal(err)
			}
			text := str.Bytes
			for _, c := range text {
				if c < 0x20 || c > 0x7e {
					ok = false
				}
			}
			if len(text) > 0 && (text[0] == ' ' || text[len(text)-1] == ' ') || strings.Contains(string(text), "  ") {
				ok = false
			}
		}
	}
	return ok
}

func cnName(tag byte, s string) []byte { return nameOf(rdn(atv(oidAttrCN, str(tag, s)))) }

// sameRow is a pair of names and whether OpenSSL calls them the same.
type sameRow struct {
	name           string
	issuer, subj   []byte
	same           bool
	subjectIsClean bool // the subject passes the text rules, so the answer is about the issuer alone
}

// sameNameRows is the table of pairs: each is checked against OpenSSL's own hash, and then against the code.
func sameNameRows() []sameRow {
	ou := mustOID(asn1.ObjectIdentifier{2, 5, 4, 11})
	nbsp, eacute, ecomb := " ", "é", "é"
	return []sameRow{
		{"the same bytes", cnName(tUTF8, "acme root"), cnName(tUTF8, "acme root"), true, true},
		{"a capital letter", cnName(tUTF8, "Acme Root"), cnName(tUTF8, "acme root"), true, true},
		{"all capitals", cnName(tUTF8, "ACME ROOT"), cnName(tUTF8, "acme root"), true, true},
		{"a PrintableString and a UTF8String", cnName(tPrintable, "acme root"), cnName(tUTF8, "acme root"), true, true},
		{"an IA5String and a UTF8String", nameOf(rdn(atv(oidAttrDC, str(tIA5, "acme")))), nameOf(rdn(atv(oidAttrDC, str(tIA5, "ACME")))), true, true},
		{"a space at the start of the issuer", cnName(tUTF8, " acme root"), cnName(tUTF8, "acme root"), true, true},
		{"a space at the end of the issuer", cnName(tUTF8, "acme root "), cnName(tUTF8, "acme root"), true, true},
		{"three spaces at both ends of the issuer", cnName(tUTF8, "   acme root   "), cnName(tUTF8, "acme root"), true, true},
		{"two spaces inside the issuer", cnName(tUTF8, "acme  root"), cnName(tUTF8, "acme root"), true, true},
		{"seven spaces inside the issuer", cnName(tUTF8, "acme       root"), cnName(tUTF8, "acme root"), true, true},
		{"a tab inside the issuer", cnName(tUTF8, "acme\troot"), cnName(tUTF8, "acme root"), true, true},
		{"a line feed inside the issuer", cnName(tUTF8, "acme\nroot"), cnName(tUTF8, "acme root"), true, true},
		{"a vertical tab inside the issuer", cnName(tUTF8, "acme\vroot"), cnName(tUTF8, "acme root"), true, true},
		{"a form feed inside the issuer", cnName(tUTF8, "acme\froot"), cnName(tUTF8, "acme root"), true, true},
		{"a carriage return inside the issuer", cnName(tUTF8, "acme\rroot"), cnName(tUTF8, "acme root"), true, true},
		{"a mix of white space inside the issuer", cnName(tUTF8, "acme \t\r\n root"), cnName(tUTF8, "acme root"), true, true},
		{"white space at both ends of the issuer", cnName(tUTF8, "\t acme root \n"), cnName(tUTF8, "acme root"), true, true},
		{"a no-break space instead of a space", cnName(tUTF8, "acme"+nbsp+"root"), cnName(tUTF8, "acme root"), false, true},
		{"a no-break space at the end", cnName(tUTF8, "acme root"+nbsp), cnName(tUTF8, "acme root"), false, true},
		{"a capital letter outside ASCII", cnName(tUTF8, "acme É"), cnName(tUTF8, "acme "+eacute), false, true},
		{"a composed and a decomposed letter", cnName(tUTF8, "acme "+eacute), cnName(tUTF8, "acme "+ecomb), false, true},
		{"one letter more", cnName(tUTF8, "acme roots"), cnName(tUTF8, "acme root"), false, true},
		{"one letter changed", cnName(tUTF8, "acme roof"), cnName(tUTF8, "acme root"), false, true},
		{"a hyphen instead of a space", cnName(tUTF8, "acme-root"), cnName(tUTF8, "acme root"), false, true},
		{"no space", cnName(tUTF8, "acmeroot"), cnName(tUTF8, "acme root"), false, true},
		{"another attribute type with the same text", nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme root")))), cnName(tUTF8, "acme root"), false, true},
		{"the same attributes in two relative names, in another order",
			nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme"))), rdn(atv(oidAttrCN, str(tUTF8, "root")))),
			nameOf(rdn(atv(oidAttrCN, str(tUTF8, "root"))), rdn(atv(oidAttrO, str(tUTF8, "acme")))), false, true},
		{"the same two attributes, one relative name or two",
			nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme")), atv(oidAttrCN, str(tUTF8, "root")))),
			nameOf(rdn(atv(oidAttrO, str(tUTF8, "acme"))), rdn(atv(oidAttrCN, str(tUTF8, "root")))), false, true},
		{"one attribute more in the subject", cnName(tUTF8, "acme root"), nameOf(rdn(atv(ou, str(tUTF8, "x"))), rdn(atv(oidAttrCN, str(tUTF8, "acme root")))), false, true},
		{"the same units with other case, in a multi-valued relative name",
			nameOf(rdn(atv(ou, str(tUTF8, "A")), atv(oidAttrCN, str(tUTF8, "Root")))),
			nameOf(rdn(atv(ou, str(tUTF8, "a")), atv(oidAttrCN, str(tUTF8, "root")))), true, true},
		{"a longer name that is the same in every relative name",
			nameOf(rdn(atv(oidAttrDC, str(tIA5, "ORG"))), rdn(atv(oidAttrDC, str(tIA5, "Example"))), rdn(atv(oidAttrCN, str(tPrintable, " Root  CA ")))),
			nameOf(rdn(atv(oidAttrDC, str(tIA5, "org"))), rdn(atv(oidAttrDC, str(tIA5, "example"))), rdn(atv(oidAttrCN, str(tUTF8, "root ca")))), true, true},
	}
}

// The subject of a request is not the issuer. Two names are the same when OpenSSL says so (it would chain the
// certificate to itself); the table is checked against OpenSSL's own name hash first, and then against the builder.
func TestTheSubjectIsNotTheNameOfTheIssuerAsOpenSSLCompares(t *testing.T) {
	root := buildRoot(t, nil)
	rows := sameNameRows()
	if len(rows) < 30 {
		t.Fatalf("only %d rows", len(rows))
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			// The table first, against OpenSSL's own hash.
			if got := opensslNameHash(t, r.issuer) == opensslNameHash(t, r.subj); got != r.same {
				t.Fatalf("OpenSSL calls the two names the same: %v; the table says %v", got, r.same)
			}
			// Then the builder.
			good := withExtensions(t, goodExtensions()...)
			csr := copyCSR(good)
			csr.RawSubject = r.subj
			p := root.interParams(csr)
			p.IssuerSubject = r.issuer
			tbs, err := intermediateTBS(t, p)
			// Under the text rule of the contract the text of an issuer and of a subject is printable ASCII with single spaces, so a name that differs from
			// another only by white space, a no-break space or a letter outside ASCII is refused for its text before the two are
			// compared (the issuer first, as a parameter; then the subject, as a request). The folding of white space itself
			// is tested on SameName (names_test.go), which holds no text rule.
			switch {
			case !textAdmissible(t, r.issuer):
				refusedSaying(t, err, pki.ErrParams, "the issuer has a value with")
				if tbs != nil {
					t.Error("a body came with the error")
				}
				return
			case !textAdmissible(t, r.subj):
				refusedSaying(t, err, pki.ErrRequest, "the subject of the request has a value with")
				if got := pki.CheckOf(err); got != pki.CheckPolicy {
					t.Errorf("check %q, want policy", got)
				}
				if tbs != nil {
					t.Error("a body came with the error")
				}
				return
			}
			if r.same {
				refused(t, err, pki.ErrRequest)
				if tbs != nil {
					t.Error("a body came with the error")
				}
				if err != nil && !strings.Contains(err.Error(), "name of the issuer") {
					t.Errorf("the text does not name the rule: %q", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("different names are refused: %v", err)
			}
			// The names are copied, and both verifiers read the body.
			cert := parseBodyOf(t, tbs)
			if string(cert.RawIssuer) != string(r.issuer) || string(cert.RawSubject) != string(r.subj) {
				t.Error("the names in the body are not the names asked for")
			}
		})
	}
	// The same rows with the roles of the two names swapped: the subject is the odd one. Where the text rules refuse
	// the subject first, the refusal is that one, and still ErrRequest.
	t.Run("a subject that is the root's own name with another capital", func(t *testing.T) {
		csr := copyCSR(withExtensions(t, goodExtensions()...))
		csr.RawSubject = cnName(tUTF8, strings.ToUpper(root.parsed.Subject.CommonName))
		_, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
	})
	t.Run("the very name of the root, byte for byte", func(t *testing.T) {
		csr := copyCSR(withExtensions(t, goodExtensions()...))
		csr.RawSubject = root.parsed.RawSubject
		_, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
	})
}
