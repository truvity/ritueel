package pki_test

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// The order of the checks holds inside a subject too (the contract: "a fault of form anywhere in the subject is malformed, also when a
// fault of content stands earlier in it"), and the algorithm element of the request is a fault of form when it is not well formed and
// check 5 when it is another algorithm. The faults of a subject here are the ones that the other tables of the suite use, one by one.

// A fault of content in a subject: the relative names that hold it, and the words that the refusal says.
type subjectFault struct {
	name  string
	rdns  [][]byte
	words string
}

func contentFaults() []subjectFault {
	cn := func(v []byte) [][]byte { return [][]byte{rdn(atv(oidAttrCN, v))} }
	return []subjectFault{
		{"a PrintableString with an at sign", cn(str(tPrintable, "a@b")), "character set"},
		{"a UTF8String with a letter outside ASCII", cn(str(tUTF8, "café")), "outside printable ASCII"},
		{"a space at the start", cn(str(tUTF8, " a")), "a space at its start or its end"},
		{"a space at the end", cn(str(tUTF8, "a ")), "a space at its start or its end"},
		{"two spaces in a row", cn(str(tUTF8, "a  b")), "two spaces in a row"},
		{"a common name that is an IA5String", cn(str(tIA5, "ca")), "PrintableString or a UTF8String"},
		{"a value that is an integer", cn(tlv(0x02, []byte{1})), "not a PrintableString or a UTF8String"},
		{"a value that is a BMPString", cn(tlv(0x1e, []byte{0, 'a'})), "not a PrintableString or a UTF8String"},
		{"an empty value", cn(str(tUTF8, "")), "empty string"},
		{"a value that is not UTF-8", cn(tlv(tUTF8, []byte{0xff})), "not valid UTF-8"},
		{"a common name of 65 characters", cn(str(tUTF8, strings.Repeat("a", 65))), "SIZE constraint"},
		{"a country of three characters", [][]byte{rdn(atv(oidAttrC, str(tPrintable, "NLD")))}, "SIZE constraint"},
		{"a country that is a UTF8String", [][]byte{rdn(atv(oidAttrC, str(tUTF8, "NL")))}, "not a PrintableString"},
		{"a domain component that is a PrintableString", [][]byte{rdn(atv(oidAttrDC, str(tPrintable, "example")))}, "IA5String"},
		{"a common name twice", [][]byte{rdn(atv(oidAttrCN, str(tUTF8, "a"))), rdn(atv(oidAttrCN, str(tUTF8, "b")))}, "more than once"},
		{"an organisational unit twice in one relative name", [][]byte{rdn(atv(oidAttrOU, str(tUTF8, "a")), atv(oidAttrOU, str(tUTF8, "b")))}, "in one relative name"},
	}
}

var oidAttrOU = mustOID(asn1.ObjectIdentifier{2, 5, 4, 11})

// A fault of form in a subject (check 2): the relative names that hold it.
func formFaults() []subjectFault {
	cnOID := oidAttrCN
	ok := str(tUTF8, "ca")
	return []subjectFault{
		{"a relative name that is a sequence", [][]byte{tlv(0x30, atv(cnOID, ok))}, "not a DER set"},
		{"an empty relative name", [][]byte{tlv(0x31)}, "empty relative name"},
		{"an attribute that is not a sequence", [][]byte{tlv(0x31, tlv(0x04, []byte{1}))}, "not a sequence"},
		{"an attribute that does not start with an identifier", [][]byte{tlv(0x31, tlv(0x30, tlv(0x04, []byte{1}), ok))}, "object identifier"},
		{"an attribute with no value", [][]byte{tlv(0x31, tlv(0x30, cnOID))}, "no value that is DER"},
		{"an element after a value", [][]byte{tlv(0x31, tlv(0x30, cnOID, ok, tlv(0x05)))}, "after its value"},
		{"a constructed value", [][]byte{rdn(atv(cnOID, tlv(0x30)))}, "not a string"},
		{"a value of the context class", [][]byte{rdn(atv(cnOID, tlv(0x80, []byte("a"))))}, "not a string"},
		{"the attributes of a relative name out of DER order", [][]byte{rdnAsGiven(atv(oidAttrC, str(tPrintable, "NL")), atv(oidAttrCN, ok))}, "DER order"},
	}
}

// subjectOf is the subject of the given relative names.
func subjectOf(parts ...[][]byte) []byte {
	var all [][]byte
	for _, p := range parts {
		all = append(all, p...)
	}
	return nameOf(all...)
}

func allContentFaults() []subjectFault { return contentFaults() }

// The faults that stand beside the subject's: none, a key that is not P-384 (check 4), a signature that does not verify and an algorithm
// that is not ecdsa-with-SHA384 (check 5). A fault of form in the subject is told before each of them; a fault of content only after.
type besideFault struct {
	name        string
	build       func(t *testing.T, subject []byte) *testCSR
	formWins    pki.Check // what a request with a fault of form in its subject says
	contentOnly pki.Check // what a request with a fault of content only in its subject says
}

func besideFaults() []besideFault {
	return []besideFault{
		{"nothing beside", func(t *testing.T, s []byte) *testCSR {
			return makeCSR(t, csrOptions{rawSubject: s, exts: goodExtensions()})
		}, pki.CheckMalformed, pki.CheckPolicy},
		{"a P-256 key", func(t *testing.T, s []byte) *testCSR {
			// The standard library cannot write a request with a subject that it does not read, so the request is made by hand: the key of
			// P-256 in a request that a P-384 key signed (the key is judged before the signature).
			c := makeCSR(t, csrOptions{rawSubject: s, exts: goodExtensions()})
			c.RawSubjectPublicKeyInfo = p256Fuzz()
			return c
		}, pki.CheckMalformed, pki.CheckAlgorithm},
		{"a signature that does not verify", func(t *testing.T, s []byte) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: s, exts: goodExtensions()})
			c.SignatureEdit = func(b []byte) []byte { b[len(b)-1] ^= 1; return b }
			return c
		}, pki.CheckMalformed, pki.CheckPossession},
		{"a signature with SHA-256", func(t *testing.T, s []byte) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: s, exts: goodExtensions()})
			c.Algorithm, c.Digest = algDER(0x02), crypto.SHA256
			return c
		}, pki.CheckMalformed, pki.CheckPossession},
		{"an algorithm element that is not well formed", func(t *testing.T, s []byte) *testCSR {
			c := makeCSR(t, csrOptions{rawSubject: s, exts: goodExtensions()})
			c.Algorithm = []byte{0x04, 0x01, 0x00}
			return c
		}, pki.CheckMalformed, pki.CheckMalformed},
		{"an extension that is not in the profile", func(t *testing.T, s []byte) *testCSR {
			return makeCSR(t, csrOptions{rawSubject: s, exts: append(goodExtensions()[:3:3], extExtKeyUsage(false, oidServerAuth), extExtKeyUsage(false, oidClientAuth))})
		}, pki.CheckMalformed, pki.CheckPolicy},
	}
}

// For every fault of content and every fault of form of a subject, in both orders: the subject is malformed, with a good key, a key that
// is not P-384, a bad signature, another algorithm and an extension fault beside it. A fault of content alone says the check of what
// stands beside it, or policy; two faults of content name the first, in the order of the subject. Each fault is also tried by itself
// first, so that a row cannot pass for another reason.
func TestAFaultOfFormLaterInASubjectWinsOverAFaultOfContentEarlier(t *testing.T) {
	content, form := allContentFaults(), formFaults()
	root := buildRoot(t, nil)
	pairs := 0
	for _, side := range besideFaults() {
		for _, c := range content {
			t.Run(side.name+": "+c.name+" alone", func(t *testing.T) {
				csr := side.build(t, subjectOf(c.rdns))
				_, err := pki.ParseRequest(csr.DER())
				refused(t, err, pki.ErrRequest)
				if got := pki.CheckOf(err); got != side.contentOnly {
					t.Errorf("check %q, want %q: %v", got, side.contentOnly, err)
				}
				if side.contentOnly == pki.CheckPolicy && !contains(err.Error(), c.words) {
					t.Errorf("the text does not say %q: %v", c.words, err)
				}
			})
		}
		for _, f := range form {
			t.Run(side.name+": "+f.name+" alone", func(t *testing.T) {
				csr := side.build(t, subjectOf(f.rdns))
				_, err := pki.ParseRequest(csr.DER())
				refused(t, err, pki.ErrRequest)
				if got := pki.CheckOf(err); got != side.formWins {
					t.Errorf("check %q, want %q: %v", got, side.formWins, err)
				}
				if !contains(err.Error(), f.words) && side.name != "an algorithm element that is not well formed" {
					t.Errorf("the text does not say %q: %v", f.words, err)
				}
			})
		}
		for _, c := range content {
			for _, f := range form {
				for _, order := range []string{"content first", "form first"} {
					pairs++
					subject := subjectOf(c.rdns, f.rdns)
					if order == "form first" {
						subject = subjectOf(f.rdns, c.rdns)
					}
					csr := side.build(t, subject)
					der := csr.DER()
					_, err := pki.ParseRequest(der)
					if got := pki.CheckOf(err); err == nil || got != pki.CheckMalformed {
						t.Errorf("%s, %s, %s, %s: check %q, want malformed: %v", side.name, c.name, f.name, order, got, err)
						continue
					}
					// RequestKey stops at check 5, so a fault of form in the subject is its answer too, unless a P-256 key or a signature
					// comes first in the contract's order (2 is first: it is malformed for every one of them).
					if _, kerr := pki.RequestKey(der); pki.CheckOf(kerr) != pki.CheckMalformed {
						t.Errorf("%s, %s, %s, %s: RequestKey says %q, want malformed: %v", side.name, c.name, f.name, order, pki.CheckOf(kerr), kerr)
					}
				}
			}
		}
	}
	// The same reading by IntermediateTBS, for the first row of each beside-fault (the readers are one function).
	for _, c := range content[:2] {
		csr := besideFaults()[0].build(t, subjectOf(c.rdns, form[0].rdns))
		p := root.interParams(csr)
		_, err := pki.IntermediateTBS(p)
		if pki.CheckOf(err) != pki.CheckMalformed {
			t.Errorf("IntermediateTBS: check %q for %s then %s", pki.CheckOf(err), c.name, form[0].name)
		}
	}
	t.Logf("%d pairs of a fault of content and a fault of form, in both orders, with %d things beside them", pairs, len(besideFaults()))
	if pairs < 1000 {
		t.Errorf("only %d pairs", pairs)
	}
}

// Two faults of content name the first one of the subject, whichever it is, and a fault of content that stands later is not told.
func TestTwoFaultsOfContentInASubjectNameTheFirst(t *testing.T) {
	content := allContentFaults()
	n := 0
	for _, a := range content {
		for _, b := range content {
			if a.name == b.name {
				continue
			}
			n++
			csr := makeCSR(t, csrOptions{rawSubject: subjectOf(a.rdns, b.rdns), exts: goodExtensions()})
			_, err := pki.ParseRequest(csr.DER())
			refused(t, err, pki.ErrRequest)
			if pki.CheckOf(err) != pki.CheckPolicy {
				t.Errorf("%s then %s: check %q", a.name, b.name, pki.CheckOf(err))
			}
		}
	}
	if n < 200 {
		t.Errorf("only %d pairs", n)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// --- the algorithm element ----------------------------------------------------------------------------

// The algorithm element of a request is judged with the form of the request, before the key: an element that is not an AlgorithmIdentifier
// (a sequence of an identifier and its parameters, with nothing after it) is malformed, with a P-256 key as with a P-384 key, and with a
// signature that does not verify; an AlgorithmIdentifier that is not ecdsa-with-SHA384 is check 5 (and check 4 comes first when the key
// is not P-384).
func TestTheAlgorithmElementIsAFaultOfFormOrAnotherAlgorithm(t *testing.T) {
	sha384 := algECDSAWithSHA384DER
	oidOf := func(arcs ...int) []byte { return mustOID(asn1.ObjectIdentifier(arcs)) }
	rows := []struct {
		name  string
		alg   []byte
		want  pki.Check
		words string
	}{
		// Not well formed: a fault of form (check 2).
		{"an octet string", []byte{0x04, 0x01, 0x00}, pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"an integer", []byte{0x02, 0x01, 0x00}, pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"a null", []byte{0x05, 0x00}, pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"an identifier alone, not in a sequence", oidOf(1, 2, 840, 10045, 4, 3, 3), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"an empty sequence", []byte{0x30, 0x00}, pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"a set", append([]byte{0x31, byte(len(sha384) - 2)}, sha384[2:]...), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"a sequence of an integer", tlv(0x30, tlv(0x02, []byte{1})), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"a sequence of a string", tlv(0x30, tlv(0x0c, []byte("ecdsa"))), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"ecdsa-with-SHA384 and a byte after it inside the element", tlv(0x30, sha384[2:], []byte{0x00}), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"a sequence that is primitive", append([]byte{0x10, byte(len(sha384) - 2)}, sha384[2:]...), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"a sequence of the context class", append([]byte{0xb0, byte(len(sha384) - 2)}, sha384[2:]...), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"an identifier with a leading zero arc octet", tlv(0x30, []byte{0x06, 0x03, 0x80, 0x01, 0x01}), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		// An identifier, parameters and one more element: three elements, not an AlgorithmIdentifier (a fault of form, not another algorithm).
		{"ecdsa-with-SHA384, null parameters and a null", tlv(0x30, sha384[2:], tlv(0x05), tlv(0x05)), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"ecdsa-with-SHA384, null parameters and two more elements", tlv(0x30, sha384[2:], tlv(0x05), tlv(0x05), tlv(0x05)), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"ecdsa-with-SHA256, null parameters and a null", tlv(0x30, algDER(0x02)[2:], tlv(0x05), tlv(0x05)), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		{"an identifier that nobody knows, and two elements", tlv(0x30, oidOf(1, 3, 6, 1, 4, 1, 99999, 9), tlv(0x05), tlv(0x05)), pki.CheckMalformed, "not an AlgorithmIdentifier"},
		// Well formed, and another algorithm: check 5.
		{"ecdsa-with-SHA256", algDER(0x02), pki.CheckPossession, "ecdsa-with-SHA384"},
		{"ecdsa-with-SHA512", algDER(0x04), pki.CheckPossession, "ecdsa-with-SHA384"},
		{"ecdsa-with-SHA1", tlv(0x30, oidOf(1, 2, 840, 10045, 4, 1)), pki.CheckPossession, "ecdsa-with-SHA384"},
		{"ecdsa-with-SHA384 with null parameters", tlv(0x30, sha384[2:], tlv(0x05)), pki.CheckPossession, "ecdsa-with-SHA384"},
		{"sha256WithRSAEncryption", tlv(0x30, oidOf(1, 2, 840, 113549, 1, 1, 11), tlv(0x05)), pki.CheckPossession, "ecdsa-with-SHA384"},
		{"Ed25519", tlv(0x30, oidOf(1, 3, 101, 112)), pki.CheckPossession, "ecdsa-with-SHA384"},
		{"an identifier that nobody knows", tlv(0x30, oidOf(1, 3, 6, 1, 4, 1, 99999, 9)), pki.CheckPossession, "ecdsa-with-SHA384"},
		// One element as parameters is well formed (the parameters of an AlgorithmIdentifier are any one element). An identifier and an
		// integer are an AlgorithmIdentifier that is not the algorithm that the contract names: RFC 5758 wants no parameters for this
		// algorithm, and a request that has some is not signed with ecdsa-with-SHA384 in the form that the contract names, so it is
		// check 5, as for null parameters, and not a fault of form.
		{"ecdsa-with-SHA384 and an integer as its parameters", tlv(0x30, sha384[2:], tlv(0x02, []byte{1})), pki.CheckPossession, "ecdsa-with-SHA384"},
		{"an identifier with parameters of a string", tlv(0x30, sha384[2:], tlv(0x0c, []byte("x"))), pki.CheckPossession, "ecdsa-with-SHA384"},
	}
	for _, r := range rows {
		for _, side := range []struct {
			name string
			mod  func(t *testing.T, c *testCSR)
			want func(pki.Check) pki.Check
		}{
			{"a P-384 key", func(*testing.T, *testCSR) {}, func(c pki.Check) pki.Check { return c }},
			// A key that is not P-384: a malformed algorithm element is told first (form), another algorithm after the key (check 4).
			{"a P-256 key", func(t *testing.T, c *testCSR) { c.RawSubjectPublicKeyInfo = p256Fuzz() }, func(c pki.Check) pki.Check {
				if c == pki.CheckMalformed {
					return c
				}
				return pki.CheckAlgorithm
			}},
			{"a signature that does not verify", func(t *testing.T, c *testCSR) { c.SignatureEdit = func(b []byte) []byte { b[len(b)-1] ^= 1; return b } }, func(c pki.Check) pki.Check { return c }},
			{"a content fault", func(t *testing.T, c *testCSR) { c.RawSubject = cnName(tUTF8, "café") }, func(c pki.Check) pki.Check { return c }},
		} {
			t.Run(r.name+", "+side.name, func(t *testing.T) {
				csr := goodRequest(t)
				csr = copyCSR(csr)
				csr.Algorithm = r.alg
				csr.Digest = 0
				side.mod(t, csr)
				der := csr.DER()
				req, err := pki.ParseRequest(der)
				refused(t, err, pki.ErrRequest)
				want := side.want(r.want)
				if got := pki.CheckOf(err); got != want {
					t.Fatalf("ParseRequest: check %q, want %q: %v", got, want, err)
				}
				if side.name == "a P-384 key" || want == pki.CheckMalformed {
					if !contains(err.Error(), r.words) {
						t.Errorf("the text does not say %q: %v", r.words, err)
					}
				}
				if req != nil {
					t.Error("a request came with the error")
				}
				// RequestKey reads the same three checks.
				key, kerr := pki.RequestKey(der)
				if key != nil || kerr == nil || pki.CheckOf(kerr) != want {
					t.Errorf("RequestKey: %v, %v (%q), want %q", key, kerr, pki.CheckOf(kerr), want)
				}
				file := pemBlockOf("CERTIFICATE REQUEST", der)
				if fk, ferr := pki.RequestKeyFile(file); fk != nil || ferr == nil || pki.CheckOf(ferr) != pki.CheckOf(kerr) {
					t.Errorf("RequestKeyFile: %v, %v", fk, ferr)
				}
			})
		}
	}
	// ecdsa-with-SHA384 itself is the one algorithm that is read on.
	if _, err := pki.ParseRequest(goodRequest(t).DER()); err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprint(len(rows), " algorithm elements, each with four things beside"))
}
