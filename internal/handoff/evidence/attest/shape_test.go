package attest_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// goodPieces are the two certificates of a good chain, in DER.
func goodPieces(t testing.TB) (leaf, token []byte) {
	t.Helper()
	return newMaker(t).PIVChain(t, p384(t), attesttest.Slot{})
}

func list(items ...string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = `"` + s + `"`
	}
	return `{"attestation":[` + strings.Join(q, ",") + `]}`
}

// The page: "The proof file", piv and openpgp-card. The evidence is exactly {"attestation": [...]}, a list of
// two to handoff.MaxAttestation certificates, each in standard Base64 with padding in its one spelling.
// Any other shape is malformed, and none is a panic.
func TestTheEvidenceMustBeExactlyTheListOfCertificates(t *testing.T) {
	leaf, token := goodPieces(t)
	l, k := b64(leaf), b64(token)
	// A string whose Base64 text has the bits that the last character leaves over set: "AB==" decodes to one
	// byte, and so does "AA==", so only one of the two is canonical.
	nonCanonical := "AB=="
	cases := []struct {
		name     string
		evidence string
	}{
		{"not JSON", "not json"},
		{"an array", "[" + l + "]"},
		{"an array of the two", `["` + l + `","` + k + `"]`},
		{"a string", `"` + l + `"`},
		{"an unknown member beside attestation", `{"attestation":["` + l + `","` + k + `"],"extra":1}`},
		{"attestation as a string", `{"attestation":"` + l + `"}`},
		{"attestation as an object", `{"attestation":{"a":"` + l + `"}}`},
		{"attestation repeated", `{"attestation":["` + l + `","` + k + `"],"attestation":["` + l + `","` + k + `"]}`},
		{"another member name", `{"attest":["` + l + `","` + k + `"]}`},
		{"an upper-case member name", `{"Attestation":["` + l + `","` + k + `"]}`},
		{"no member", `{}`},
		{"attestation null", `{"attestation":null}`},
		{"an entry null", `{"attestation":["` + l + `",null]}`},
		{"two entries null", `{"attestation":[null,null]}`},
		{"entries that are numbers", `{"attestation":[1,2]}`},
		{"entries that are lists", `{"attestation":[["a"],["b"]]}`},
		{"an empty list", `{"attestation":[]}`},
		{"one entry", list(l)},
		{"nine entries", list(l, k, l, l, l, l, l, l, l)},
		{"many entries", list(strings.Split(strings.Repeat("AA==,", 5000), ",")[:5000]...)},
		{"missing padding", list("AQ", k)},
		{"missing padding on the second", list(l, "AQ")},
		{"a line break inside", list(l[:20]+`\n`+l[20:], k)},
		{"a carriage return", list(l[:20]+`\r\n`+l[20:], k)},
		{"URL-safe letters", list(strings.NewReplacer("+", "-", "/", "_").Replace(l+"+/"), k)},
		{"a space inside", list(l[:20]+" "+l[20:], k)},
		{"a space after", list(l+" ", k)},
		{"a letter that is not Base64", list(l[:20]+"*"+l[21:], k)},
		{"non-canonical trailing bits", list(nonCanonical, k)},
		{"an empty string", list("", k)},
		{"an empty second string", list(l, "")},
		{"only padding", list("====", k)},
		{"the second entry is bad Base64", list(l, "!!!!")},
		{"the third entry is bad Base64", list(l, k, "!!!!")},
		{"the third entry is empty", list(l, k, "")},
		{"the third entry is not canonical", list(l, k, nonCanonical)},
		{"a top-level number", `5`},
		{"a top-level null", `null`},
		{"empty", ``},
		{"white space only", "   \n"},
		{"a byte order mark", "\xef\xbb\xbf" + list(l, k)},
		{"bytes that are not UTF-8 in a member name", "{\"attest\xff\":[\"" + l + "\",\"" + k + "\"]}"},
		{"bytes that are not UTF-8 in an entry", "{\"attestation\":[\"" + l + "\",\"\xff\xfe\"]}"},
		{"a NUL in an entry", "{\"attestation\":[\"" + l + "\",\"\\u0000\"]}"},
		{"a comment", `{"attestation":["` + l + `","` + k + `"]} // x`},
		{"a second value after the object", list(l, k) + list(l, k)},
		{"a trailing comma", `{"attestation":["` + l + `","` + k + `",]}`},
		{"single quotes", `{'attestation':['` + l + `','` + k + `']}`},
		{"a deep nesting", strings.Repeat("[", 100000) + strings.Repeat("]", 100000)},
		{"a deep nesting in the member", `{"attestation":` + strings.Repeat("[", 50000) + strings.Repeat("]", 50000) + `}`},
		{"a very long string", `{"attestation":["` + strings.Repeat("A", handoff.MaxFileSize) + `","` + k + `"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			att, err := attest.ParseAttestation([]byte(c.evidence))
			if att != nil {
				t.Fatal("a result beside a refusal")
			}
			wantRefusal(t, err, handoff.CodeMalformed)
		})
	}
}

// An empty or missing evidence is malformed too.
func TestAMissingEvidenceIsMalformed(t *testing.T) {
	for _, ev := range [][]byte{nil, {}} {
		att, err := attest.ParseAttestation(ev)
		if att != nil {
			t.Fatal("a result beside a refusal")
		}
		wantRefusal(t, err, handoff.CodeMalformed)
	}
}

// The page: a file is at most 256 KiB (handoff.MaxFileSize). One byte over is refused, and a good evidence
// at the limit is read.
func TestTheEvidenceIsBoundedByTheSizeOfAFile(t *testing.T) {
	leaf, token := goodPieces(t)
	good := []byte(list(b64(leaf), b64(token)))

	atLimit := append(bytes.Clone(good), bytes.Repeat([]byte(" "), handoff.MaxFileSize-len(good))...)
	if len(atLimit) != handoff.MaxFileSize {
		t.Fatalf("test setup: %d bytes", len(atLimit))
	}
	if att, err := attest.ParseAttestation(atLimit); err != nil || att == nil {
		t.Errorf("an evidence of exactly %d bytes: %v", handoff.MaxFileSize, err)
	}

	over := append(bytes.Clone(atLimit), ' ')
	att, err := attest.ParseAttestation(over)
	if att != nil {
		t.Error("a result beside a refusal")
	}
	wantRefusal(t, err, handoff.CodeMalformed)

	huge := bytes.Repeat([]byte("["), 4*handoff.MaxFileSize)
	if att, err := attest.ParseAttestation(huge); att != nil {
		t.Error("a result beside a refusal")
	} else {
		wantRefusal(t, err, handoff.CodeMalformed)
	}
}

// The page: two to eight entries. Two and eight are read; the entries from the third are checked for their
// spelling and are not read as certificates.
func TestTwoToEightEntriesAreRead(t *testing.T) {
	leaf, token := goodPieces(t)
	l, k := b64(leaf), b64(token)
	for n := 2; n <= handoff.MaxAttestation; n++ {
		items := []string{l, k}
		for len(items) < n {
			items = append(items, "AAAA") // not a certificate, and never read as one
		}
		att, err := attest.ParseAttestation([]byte(list(items...)))
		if err != nil || att == nil {
			t.Errorf("%d entries: %v", n, err)
		}
	}
	items := []string{l, k}
	for len(items) < handoff.MaxAttestation+1 {
		items = append(items, "AAAA")
	}
	if att, err := attest.ParseAttestation([]byte(list(items...))); att != nil {
		t.Errorf("%d entries are read", len(items))
	} else {
		wantRefusal(t, err, handoff.CodeMalformed)
	}
}

// The first two entries are the key's certificate and the token's, in the standard Base64 that the shape
// check accepts; a good evidence is read into exactly those two.
func TestAGoodEvidenceIsReadIntoTheTwoCertificates(t *testing.T) {
	leaf, token := goodPieces(t)
	att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, leaf, token))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(att.Leaf.Raw, leaf) || !bytes.Equal(att.Token.Raw, token) {
		t.Error("the certificates are not the first and the second entry, in this order")
	}
	if att.Leaf.IsCA || !att.Token.IsCA {
		t.Error("the roles are mixed")
	}
}

// The page: "Both certificates parse." A certificate that is cut, has a byte after it, or is too large is
// refused with proof-invalid.
func TestBothCertificatesMustParse(t *testing.T) {
	leaf, token := goodPieces(t)
	cases := []struct {
		name        string
		first, next []byte
	}{
		{"a byte after the first", append(bytes.Clone(leaf), 0), token},
		{"a byte after the second", leaf, append(bytes.Clone(token), 0)},
		{"two certificates in one entry", append(bytes.Clone(leaf), token...), token},
		{"the first cut short", leaf[:len(leaf)-1], token},
		{"the first cut to a header", leaf[:4], token},
		{"the second cut short", leaf, token[:len(token)-1]},
		{"the first is one byte", []byte{0x30}, token},
		{"the first is a sequence of nothing", []byte{0x30, 0x00}, token},
		{"the second is a sequence of nothing", leaf, []byte{0x30, 0x00}},
		{"the first is text", []byte("not a certificate"), token},
		{"the second is text", leaf, []byte("not a certificate")},
		{"the first has a bad length", append([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, leaf[4:]...), token},
		{"the first is all 0xff", bytes.Repeat([]byte{0xff}, 64), token},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, c.first, c.next))
			if att != nil {
				t.Fatal("a result beside a refusal")
			}
			wantRefusal(t, err, handoff.CodeProofInvalid)
		})
	}
}

// A byte flipped inside a certificate either gives a certificate that does not parse (refused here) or one
// that parses and fails later; it is never a panic. Flipping every byte of the leaf is cheap.
func TestAFlippedByteIsNeverAPanic(t *testing.T) {
	leaf, token := goodPieces(t)
	for i := range leaf {
		bad := bytes.Clone(leaf)
		bad[i] ^= 0xff
		att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, bad, token))
		if err != nil {
			wantRefusal(t, err, handoff.CodeProofInvalid)
			if att != nil {
				t.Fatalf("byte %d: a result beside a refusal", i)
			}
		}
	}
}

// padded makes a key's certificate of exactly size bytes of DER, and the token's certificate that signed it.
// The template carries an extension of an unknown number whose value is padding. The maker's RSA token key
// signs it, so that the signature has a fixed size and one more try finds the length.
func padded(t *testing.T, m *attesttest.Maker, size int) (leaf, token []byte) {
	t.Helper()
	key := p384(t)
	pad := size - 800
	for range 6 {
		leaf, token = m.PIVChain(t, key, attesttest.Slot{Tweak: func(tmpl *x509.Certificate) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
				Id: []int{1, 3, 6, 1, 4, 1, 99999, 1}, Value: bytes.Repeat([]byte{0x5a}, pad),
			})
		}})
		if len(leaf) == size {
			return leaf, token
		}
		pad += size - len(leaf)
	}
	t.Fatalf("could not make a certificate of %d bytes", size)
	return nil, nil
}

// The size of one certificate is limited to attest.MaxCertificateSize (a limit of this package; the page gives no size).
func TestACertificateOfTheLimitIsReadAndOneByteMoreIsRefused(t *testing.T) {
	m := attesttest.NewMaker(t, attesttest.MakerOptions{Now: clock}) // an RSA token key
	for _, c := range []struct {
		size int
		ok   bool
	}{
		{attest.MaxCertificateSize - 1, true},
		{attest.MaxCertificateSize, true},
		{attest.MaxCertificateSize + 1, false},
	} {
		leaf, token := padded(t, m, c.size)
		att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, leaf, token))
		if c.ok {
			if err != nil || att == nil {
				t.Errorf("a certificate of %d bytes: %v", c.size, err)
			}
			continue
		}
		if att != nil {
			t.Errorf("a certificate of %d bytes is read", c.size)
		}
		wantRefusal(t, err, handoff.CodeProofInvalid)
	}
	// The token's certificate has the same limit.
	leaf, token := goodPieces(t)
	tokBig := append(bytes.Clone(token), bytes.Repeat([]byte{0}, attest.MaxCertificateSize)...)
	if att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, leaf, tokBig)); att != nil {
		t.Error("a token certificate over the limit is read")
	} else {
		wantRefusal(t, err, handoff.CodeProofInvalid)
	}
}

// The page has no rule for these (proposed): the key's certificate is not a CA certificate and is not the token's. The
// two are in this order.
func TestTheKeysCertificateIsNotACAAndNotTheTokens(t *testing.T) {
	m := newMaker(t)
	leaf, token := m.PIVChain(t, p384(t), attesttest.Slot{})
	asCA, _ := m.PIVChain(t, p384(t), attesttest.Slot{Tweak: func(tmpl *x509.Certificate) {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.MaxPathLen, tmpl.MaxPathLenZero = true, true, 0, true
	}})
	cases := []struct {
		name        string
		first, next []byte
	}{
		{"the first is a CA", asCA, token},
		{"the first is the token's certificate", token, token},
		{"the same certificate twice", leaf, leaf},
		{"the token first and the leaf second", token, leaf},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, c.first, c.next))
			if att != nil {
				t.Fatal("a result beside a refusal")
			}
			d := wantRefusal(t, err, handoff.CodeProofInvalid)
			if bytes.Equal(c.first, c.next) && !strings.Contains(d, "same certificate") {
				t.Errorf("the detail %q does not say that the two are the same certificate", d)
			}
		})
	}
	// Basic constraints present with cA false are a leaf's, and are accepted.
	notCA, _ := m.PIVChain(t, p384(t), attesttest.Slot{Tweak: func(tmpl *x509.Certificate) {
		tmpl.BasicConstraintsValid, tmpl.IsCA = true, false
	}})
	if _, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, notCA, token)); err != nil {
		t.Errorf("a leaf with cA false: %v", err)
	}
}

// The page: "the token's certificate is a CA with path length 0". Anything else is refused: not a CA, cA
// false, a path length of 1, no path length.
func TestTheTokensCertificateIsACAWithPathLengthZero(t *testing.T) {
	m := newMaker(t)
	cases := []struct {
		name  string
		tweak func(*x509.Certificate)
		ok    bool
	}{
		{"a CA with path length 0", func(*x509.Certificate) {}, true},
		{"no basic constraints", func(c *x509.Certificate) { c.BasicConstraintsValid, c.IsCA = false, false }, false},
		{"basic constraints with cA false", func(c *x509.Certificate) { c.IsCA, c.MaxPathLen, c.MaxPathLenZero = false, -1, false }, false},
		{"path length 1", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 1, false }, false},
		{"path length 2", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 2, false }, false},
		{"no path length", func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = -1, false }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			leaf, token := m.PIVChain(t, p384(t), attesttest.Slot{TokenTweak: c.tweak, Check: attesttest.CheckSignature})
			att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, leaf, token))
			if c.ok {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if att != nil {
				t.Fatal("a result beside a refusal")
			}
			wantRefusal(t, err, handoff.CodeProofInvalid)
		})
	}
}

// A token's certificate whose basic constraints hold a path length of 0 and no cA flag (so cA is false by
// default) is not a CA, whatever the path length says.
func TestATokenWithAPathLengthAndNoCAFlagIsRefused(t *testing.T) {
	m := newMaker(t)
	// SEQUENCE { INTEGER 0 }: the DER of basic constraints with the default cA (false) and a path length of 0.
	raw := pkix.Extension{Id: []int{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}
	leaf, token := m.PIVChain(t, p384(t), attesttest.Slot{
		TokenTweak: func(c *x509.Certificate) {
			c.BasicConstraintsValid, c.IsCA, c.MaxPathLen, c.MaxPathLenZero = false, false, -1, false
			c.ExtraExtensions = append(c.ExtraExtensions, raw)
		},
		Check: attesttest.CheckSignature,
	})
	parsed := mustCert(t, token)
	if parsed.IsCA || !parsed.BasicConstraintsValid || !parsed.MaxPathLenZero {
		t.Fatalf("test setup: CA %v, valid %v, zero %v", parsed.IsCA, parsed.BasicConstraintsValid, parsed.MaxPathLenZero)
	}
	att, err := attest.ParseAttestation(attesttest.EvidenceJSON(t, leaf, token))
	if att != nil {
		t.Fatal("a result beside a refusal")
	}
	wantRefusal(t, err, handoff.CodeProofInvalid)
}

// Both readers of the roles, ParseAttestation and Verify, hold the same rules: an Attestation that a caller
// builds by hand is checked again.
func TestAHandBuiltAttestationIsCheckedAgain(t *testing.T) {
	m := newMaker(t)
	b := m.Bundle(t)
	good := pivChain(t, m, attesttest.Slot{})
	if err := b.Verify(attest.AppletPIV, good, clock); err != nil {
		t.Fatalf("a good chain: %v", err)
	}
	twice := &attest.Attestation{Leaf: good.Leaf, Token: good.Leaf}
	asCA := pivChain(t, m, attesttest.Slot{Tweak: func(c *x509.Certificate) {
		c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.MaxPathLenZero = true, true, 0, true
	}})
	badToken := pivChain(t, m, attesttest.Slot{
		TokenTweak: func(c *x509.Certificate) { c.MaxPathLen, c.MaxPathLenZero = 1, false },
	})
	swapped := &attest.Attestation{Leaf: good.Token, Token: good.Leaf}
	for name, att := range map[string]*attest.Attestation{
		"the same certificate twice":     twice,
		"a key's certificate that is CA": asCA,
		"a token with path length 1":     badToken,
		"the two swapped":                swapped,
	} {
		t.Run(name, func(t *testing.T) {
			wantRefusal(t, b.Verify(attest.AppletPIV, att, clock), handoff.CodeProofInvalid)
		})
	}
	// An Attestation that is not whole is a fault of the caller, not a verdict.
	for name, att := range map[string]*attest.Attestation{
		"nil":       nil,
		"no leaf":   {Token: good.Token},
		"no token":  {Leaf: good.Leaf},
		"empty":     {},
		"both nils": {Leaf: nil, Token: nil},
	} {
		t.Run("fault: "+name, func(t *testing.T) {
			wantPlainError(t, b.Verify(attest.AppletPIV, att, clock))
		})
	}
}

// ParseAttestation reads canonical Base64 only: the encoder's output for the bytes is the only spelling.
func TestOnlyTheCanonicalSpellingOfBase64IsRead(t *testing.T) {
	leaf, token := goodPieces(t)
	// RawStdEncoding (no padding), URL encoding and a wrapped encoding of the same bytes.
	for name, enc := range map[string]string{
		"raw":     base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3, 4}),
		"url":     base64.URLEncoding.EncodeToString(append([]byte{0xfb, 0xff}, leaf...)),
		"wrapped": wrap(b64(leaf), 64),
	} {
		t.Run(name, func(t *testing.T) {
			ev := fmt.Sprintf(`{"attestation":[%q,%q]}`, enc, b64(token))
			if att, err := attest.ParseAttestation([]byte(ev)); att != nil {
				t.Fatal("read")
			} else {
				wantRefusal(t, err, handoff.CodeMalformed)
			}
		})
	}
}

func wrap(s string, n int) string {
	var out []string
	for len(s) > n {
		out, s = append(out, s[:n]), s[n:]
	}
	return strings.Join(append(out, s), "\n")
}
