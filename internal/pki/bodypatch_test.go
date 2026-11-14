package pki_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

// Bodies that no builder returns, made from one that a builder returned by changing one part and writing the
// sequence again, so that every length is right and the body is still well formed DER of a certificate body. What
// refuses them is the rule of the part, and the rows say which. Every one is refused by Sign before the key is used
// and by Assemble, with the signature of the key that the body names.

// parts splits a TBSCertificate into its elements: [0] version, serial, algorithm, issuer, validity, subject,
// key, [3] extensions.
func parts(t *testing.T, body []byte) [][]byte {
	t.Helper()
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(body, &outer); err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for rest := outer.Bytes; len(rest) > 0; {
		var e asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e.FullBytes)
	}
	if len(out) != 8 {
		t.Fatalf("a body of %d elements", len(out))
	}
	return out
}

const (
	pSerial = 1
	pIssuer = 3
	pTimes  = 4
	pSubj   = 5
)

func rewrite(t *testing.T, body []byte, edit func(p [][]byte)) []byte {
	t.Helper()
	p := parts(t, body)
	edit(p)
	return tlv(0x30, p...)
}

func timeDER(t time.Time) []byte {
	t = t.UTC()
	if y := t.Year(); y >= 1950 && y < 2050 {
		return tlv(0x17, []byte(t.Format("060102150405Z")))
	}
	return tlv(0x18, []byte(t.Format("20060102150405Z")))
}

func serialDER(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return tlv(0x02, b)
}

// validityOf reads the two dates of a body.
func validityOf(t *testing.T, body []byte) (time.Time, time.Time) {
	t.Helper()
	c := parseBodyOf(t, body)
	return c.NotBefore, c.NotAfter
}

func TestSignAndAssembleRefuseABodyWithAPartThatNoBuilderWrites(t *testing.T) {
	f := newGuardFixture(t)
	rootBody, interBody := f.root.tbs, f.inter.tbs
	issuerCN := f.root.parsed.Subject.CommonName
	nb, na := validityOf(t, interBody)
	rnb, _ := validityOf(t, rootBody)
	bit := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
	type row struct {
		name   string
		body   []byte
		signer *opaqueSigner // nil: the root's
		pub    bool          // the key given to Assemble is the signer's (the intermediate's own)
	}
	own := &opaqueSigner{key: f.inter.csr.Key}
	rows := []row{
		// The serial of the profile: positive, 64 to 159 bits.
		{name: "a root with a serial of 63 bits", body: rewrite(t, rootBody, func(p [][]byte) { p[pSerial] = serialDER(new(big.Int).Sub(bit(63), big.NewInt(1))) })},
		{name: "a root with a serial of 8 octets", body: rewrite(t, rootBody, func(p [][]byte) { p[pSerial] = serialDER(big.NewInt(1 << 62)) })},
		{name: "a root with a serial of zero", body: rewrite(t, rootBody, func(p [][]byte) { p[pSerial] = serialDER(big.NewInt(0)) })},
		{name: "a root with a negative serial", body: rewrite(t, rootBody, func(p [][]byte) { p[pSerial] = tlv(0x02, []byte{0xff, 0x01, 2, 3, 4, 5, 6, 7, 8, 9}) })},
		{name: "a root with a serial of 160 bits", body: rewrite(t, rootBody, func(p [][]byte) { p[pSerial] = serialDER(bit(160)) })},
		{name: "an intermediate with a serial of 63 bits", body: rewrite(t, interBody, func(p [][]byte) { p[pSerial] = serialDER(new(big.Int).Sub(bit(63), big.NewInt(1))) })},
		{name: "an intermediate with a serial of zero", body: rewrite(t, interBody, func(p [][]byte) { p[pSerial] = serialDER(big.NewInt(0)) })},
		{name: "an intermediate with a serial of 160 bits", body: rewrite(t, interBody, func(p [][]byte) { p[pSerial] = serialDER(bit(160)) })},

		// The key of the body is ECDSA on P-384, and nothing else.
		{name: "a root with a P-256 key", body: rewrite(t, rootBody, func(p [][]byte) { p[6] = otherSPKI(t, "p256") })},
		{name: "a root with a P-521 key", body: rewrite(t, rootBody, func(p [][]byte) { p[6] = otherSPKI(t, "p521") })},
		{name: "a root with an Ed25519 key", body: rewrite(t, rootBody, func(p [][]byte) { p[6] = otherSPKI(t, "ed25519") })},
		{name: "an intermediate with a P-256 key", body: rewrite(t, interBody, func(p [][]byte) { p[6] = otherSPKI(t, "p256") })},
		{name: "an intermediate with an Ed25519 key", body: rewrite(t, interBody, func(p [][]byte) { p[6] = otherSPKI(t, "ed25519") })},

		// A date outside what the profile allows, that the standard library still reads.
		{name: "a root that starts at the zero time", body: rewrite(t, rootBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(time.Time{}), timeDER(utc(2000, 1, 1, 0, 0, 0))) })},
		{name: "a root that starts in the year 0", body: rewrite(t, rootBody, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(0, 12, 31, 23, 59, 59)), timeDER(utc(2000, 1, 1, 0, 0, 0)))
		})},
		{name: "an intermediate that starts at the zero time", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(time.Time{}), timeDER(utc(2000, 1, 1, 0, 0, 0))) })},
		{name: "an intermediate that starts in the year 0", body: rewrite(t, interBody, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(0, 12, 31, 23, 59, 59)), timeDER(utc(2000, 1, 1, 0, 0, 0)))
		})},

		// A root name that RootCommonName does not make.
		{name: "a root whose name has no Root and no label", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tUTF8, "Example"); p[pIssuer], p[pSubj] = n, n })},
		{name: "a root whose name has another word than Root", body: rewrite(t, rootBody, func(p [][]byte) {
			n := cnName(tUTF8, strings.Replace(issuerCN, " Root ", " Rxxt ", 1))
			p[pIssuer], p[pSubj] = n, n
		})},
		{name: "a root whose name ends in a label of two letters", body: rewrite(t, rootBody, func(p [][]byte) {
			n := cnName(tUTF8, strings.Replace(issuerCN, " K ", " KK ", 1))
			p[pIssuer], p[pSubj] = n, n
		})},
		{name: "a root whose name is a PrintableString", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tPrintable, issuerCN); p[pIssuer], p[pSubj] = n, n })},
		{name: "a root whose name is two attributes", body: rewrite(t, rootBody, func(p [][]byte) {
			n := nameOf(rdn(atv(oidAttrCN, str(tUTF8, issuerCN))), rdn(atv(oidAttrO, str(tUTF8, "x"))))
			p[pIssuer], p[pSubj] = n, n
		})},
		{name: "a root whose name has the mark of a test root and no Root", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tUTF8, "Example (TEST ONLY)"); p[pIssuer], p[pSubj] = n, n })},

		// A root whose validity is not 36 months.
		{name: "a root of 35 months", body: rewrite(t, rootBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(rnb), timeDER(monthsAfter(rnb, 35))) })},
		{name: "a root of 37 months", body: rewrite(t, rootBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(rnb), timeDER(monthsAfter(rnb, 37))) })},
		{name: "a root of 36 months and a second", body: rewrite(t, rootBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(rnb), timeDER(monthsAfter(rnb, 36).Add(time.Second))) })},

		// An intermediate whose end is not a whole number of months from its start, or not after it.
		{name: "an intermediate that ends where it starts", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(nb)) })},
		{name: "an intermediate that ends a second before it starts", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(nb.Add(-time.Second))) })},
		{name: "an intermediate that ends a month before it starts", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(monthsAfter(nb, -1))) })},
		{name: "an intermediate that ends a second after it starts", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(nb.Add(time.Second))) })},
		{name: "an intermediate that ends a day after a whole number of months", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(na.Add(24*time.Hour))) })},
		{name: "an intermediate that ends a second before a whole number of months", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(na.Add(-time.Second))) })},
		{name: "an intermediate of one month", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(monthsAfter(nb, 1))) })},
		{name: "an intermediate of 12 months", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(monthsAfter(nb, 12))) })},
		{name: "an intermediate of 14 months", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(monthsAfter(nb, 14))) })},
		{name: "an intermediate of 36 months", body: rewrite(t, interBody, func(p [][]byte) { p[pTimes] = tlv(0x30, timeDER(nb), timeDER(monthsAfter(nb, 36))) })},
		{name: "an intermediate of 119987 months", body: rewrite(t, interBody, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(1, 1, 1, 0, 0, 1)), timeDER(utc(9999, 12, 1, 0, 0, 1)))
		})},
		{name: "an intermediate that starts on the 31st and ends on the 27th of February", body: rewrite(t, interBody, func(p [][]byte) {
			s := time.Date(2027, 1, 31, 10, 0, 0, 0, time.UTC)
			p[pTimes] = tlv(0x30, timeDER(s), timeDER(time.Date(2027, 2, 27, 10, 0, 0, 0, time.UTC)))
		})},
		{name: "an intermediate that starts on the 31st and ends on the 1st of March", body: rewrite(t, interBody, func(p [][]byte) {
			s := time.Date(2027, 1, 31, 10, 0, 0, 0, time.UTC)
			p[pTimes] = tlv(0x30, timeDER(s), timeDER(time.Date(2027, 3, 1, 10, 0, 0, 0, time.UTC)))
		})},

		// The subject of an intermediate is held to the text rules, as a request is.
		{name: "an intermediate whose subject has a control character", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, "acme\x01ca") })},
		{name: "an intermediate whose subject has a mark that changes the direction of text", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, "acme\u202eca") })},
		{name: "an intermediate whose subject starts with a space", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, " acme ca") })},
		{name: "an intermediate whose subject ends with a space", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, "acme ca ") })},
		{name: "an intermediate whose subject has two spaces", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, "acme  ca") })},
		{name: "an intermediate whose subject has two common names", body: rewrite(t, interBody, func(p [][]byte) {
			p[pSubj] = nameOf(rdn(atv(oidAttrCN, str(tUTF8, "a"))), rdn(atv(oidAttrCN, str(tUTF8, "b"))))
		})},
		{name: "an intermediate whose subject is the empty name", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = nameOf() })},
		{name: "an intermediate whose subject has an attribute of 70 characters in a common name", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, strings.Repeat("a", 70)) })},
		{name: "an intermediate whose subject is the name of its issuer with other capitals", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, strings.ToUpper(issuerCN)) })},
		{name: "an intermediate whose subject is the name of its issuer in a PrintableString", body: rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tPrintable, issuerCN) })},
		{name: "an intermediate whose issuer is not a name", body: rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = tlv(0x04, []byte("x")) })},

		// The issuer of an intermediate is held to the text rule of a subject (the name of a root is ASCII with single spaces), as
		// IntermediateTBS holds it: a body that has another issuer is read by the same rule.
		{name: "an intermediate whose issuer has a control character", body: rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = cnName(tUTF8, "Example\x01 Root K") })},
		{name: "an intermediate whose issuer has a no-break space", body: rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = cnName(tUTF8, "Example\u00a0Root K") })},
		{name: "an intermediate whose issuer has a Cyrillic letter that looks like a Latin one", body: rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = cnName(tUTF8, "Ex\u0430mple Root K") })},
		{name: "an intermediate whose issuer has two spaces", body: rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = cnName(tUTF8, "Example  Root K") })},
		{name: "an intermediate whose issuer starts with a space", body: rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = cnName(tUTF8, " Example Root K") })},
		{name: "an intermediate whose issuer ends with a space", body: rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = cnName(tUTF8, "Example Root K ") })},

		// The name of a root is 1 to 45 characters of single-spaced ASCII: the body reader asks RootCommonName.
		{name: "a root whose name has 46 characters", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tUTF8, strings.Repeat("n", 46)+" Root K"); p[pIssuer], p[pSubj] = n, n })},
		{name: "a root whose name has two spaces in a row", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tUTF8, "Example  Test Root K (TEST ONLY)"); p[pIssuer], p[pSubj] = n, n })},
		{name: "a root whose name starts with a space", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tUTF8, " Example Root K"); p[pIssuer], p[pSubj] = n, n })},
		{name: "a root whose name ends with a space", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tUTF8, "Example  Root K"); p[pIssuer], p[pSubj] = n, n })},
		{name: "a root whose name has a Cyrillic letter", body: rewrite(t, rootBody, func(p [][]byte) { n := cnName(tUTF8, "Ex\u0430mple Root K"); p[pIssuer], p[pSubj] = n, n })},

		// The key identifiers of an intermediate.
		{name: "an intermediate that names its own key as its issuer", body: ownKeyBody(t, interBody, f.inter), signer: own, pub: true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := r.signer
			if s == nil {
				s = f.signer
			}
			f.refused(t, s, r.body)
			key := &f.root.key.PublicKey
			sigKey := f.root.key
			if r.pub {
				key, sigKey = &s.key.PublicKey, s.key
			}
			der, err := pki.Assemble(r.body, rawSign(t, sigKey, r.body), key)
			refused(t, err, pki.ErrSignature)
			onePrefix(t, err)
			if der != nil {
				t.Error("Assemble made a certificate from the body")
			}
		})
	}
	// The rows next to them that are another body that a builder could return: they are signed.
	accepted := []struct {
		name string
		body []byte
	}{
		{"a root with a serial of exactly 64 bits", rewrite(t, rootBody, func(p [][]byte) { p[pSerial] = serialDER(bit(63)) })},
		{"a root with a serial of exactly 159 bits", rewrite(t, rootBody, func(p [][]byte) { p[pSerial] = serialDER(new(big.Int).Sub(bit(159), big.NewInt(1))) })},
		{"an intermediate with a serial of exactly 64 bits", rewrite(t, interBody, func(p [][]byte) { p[pSerial] = serialDER(bit(63)) })},
		{"an intermediate with a serial of exactly 159 bits", rewrite(t, interBody, func(p [][]byte) { p[pSerial] = serialDER(new(big.Int).Sub(bit(159), big.NewInt(1))) })},
		{"an intermediate of 13 months that starts on the 31st of January and ends at the end of February", rewrite(t, interBody, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(2026, 1, 31, 10, 0, 0)), timeDER(utc(2027, 2, 28, 10, 0, 0)))
		})},
		{"the same in the year before a leap year", rewrite(t, interBody, func(p [][]byte) {
			p[pTimes] = tlv(0x30, timeDER(utc(2027, 1, 31, 10, 0, 0)), timeDER(utc(2028, 2, 29, 10, 0, 0)))
		})},
		{"an intermediate whose issuer is another name", rewrite(t, interBody, func(p [][]byte) { p[pIssuer] = cnName(tUTF8, "another root") })},
		{"an intermediate whose subject is a name of another case than its own", rewrite(t, interBody, func(p [][]byte) { p[pSubj] = cnName(tUTF8, "ACME CA") })},
	}
	for _, r := range accepted {
		t.Run("accepted: "+r.name, func(t *testing.T) {
			// The form is one that a builder writes for some input, so Assemble takes it; and no parameters of this fixture
			// give it, so neither signing function signs it.
			if _, err := pki.Assemble(r.body, rawSign(t, f.root.key, r.body), &f.root.key.PublicKey); err != nil {
				t.Fatalf("Assemble refused: %v", err)
			}
			f.refused(t, f.signer, r.body)
		})
	}
	_ = bytes.Equal
}

// ownKeyBody is an intermediate body that names the key of its own subject as the key of its issuer: the authority key
// identifier is the subject key identifier. The body is the one that the builder would write for such a request, except
// that the builder refuses it, so the bytes are the honest body's with the 20 octets of the authority key identifier
// replaced by those of the subject key identifier.
func ownKeyBody(t *testing.T, body []byte, inter *issued) []byte {
	t.Helper()
	ski, aki := inter.parsed.SubjectKeyId, inter.parsed.AuthorityKeyId
	if len(ski) != 20 || len(aki) != 20 || bytes.Equal(ski, aki) {
		t.Fatalf("key identifiers %x %x", ski, aki)
	}
	if bytes.Count(body, aki) != 1 {
		t.Fatalf("the authority key identifier is %d times in the body", bytes.Count(body, aki))
	}
	return bytes.Replace(body, aki, ski, 1)
}

func monthsAfter(base time.Time, n int) time.Time {
	out, err := pki.AddMonths(base, n)
	if err != nil {
		panic(err)
	}
	return out
}

// otherSPKI is the SubjectPublicKeyInfo of a key that is not on P-384.
func otherSPKI(t *testing.T, kind string) []byte {
	t.Helper()
	var pub any
	switch kind {
	case "p256":
		pub = &p256Key(t).PublicKey
	case "p521":
		pub = &p521Key(t).PublicKey
	default:
		k, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = k
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
