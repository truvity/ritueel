package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The invariant of both builders: a body that is returned is one that the standard library reads as
// a certificate, so Assemble accepts it with a real signature. These tests look at it from both
// sides: what the builders refuse that no earlier rule of the profile looks at, and that nothing
// they return fails to assemble.

// ncSub is one subtree of name constraints: a sequence of a general name, as DER.
func ncSub(parts ...[]byte) []byte { return tlv(0x30, parts...) }

// ncValue is name constraints with the given permitted and excluded subtrees, as DER.
func ncValue(permitted, excluded [][]byte) []byte {
	var parts [][]byte
	if permitted != nil {
		parts = append(parts, tlv(0xa0, permitted...))
	}
	if excluded != nil {
		parts = append(parts, tlv(0xa1, excluded...))
	}
	return tlv(0x30, parts...)
}

func dns(name string) []byte { return tlv(0x82, []byte(name)) }

// Nothing else of an intermediate request got through the earlier rules and then failed the
// invariant: a subject, an issuer name and an extended key usage that passed the rules before it
// have always been read by the standard library. The rows are the forms that came closest, and they are all issued. (The
// odd forms of the earlier rows, a string type the parser does not interpret, an empty value, an odd OID, are refused now by the
// rules of the contract for the extended key usage, the string types and the text; the rows that held them are replaced by the purposes that a request may name.)
func TestIntermediateSubjectIssuerAndPurposesTheLibraryReads(t *testing.T) {
	root := buildRoot(t, nil)
	name := func(value []byte) []byte {
		return tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, value)))
	}
	values := map[string][]byte{}
	good := withExtensions(t, goodExtensions()...)
	for label, v := range values {
		t.Run("a subject with "+label, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = name(v)
			got := root.issue(t, csr, nil)
			if !bytes.Equal(got.parsed.RawSubject, csr.RawSubject) {
				t.Error("the subject is not copied")
			}
			verifyEverywhere(t, root, got, true)
		})
		t.Run("an issuer with "+label, func(t *testing.T) {
			got := root.issue(t, good, func(p *pki.IntermediateParams) { p.IssuerSubject = name(v) })
			if !bytes.Equal(got.parsed.RawIssuer, name(v)) {
				t.Error("the issuer is not copied")
			}
		})
	}
	for label, oids := range map[string][]asn1.ObjectIdentifier{
		"serverAuth":                {oidServerAuth},
		"clientAuth":                {oidClientAuth},
		"serverAuth and clientAuth": {oidServerAuth, oidClientAuth},
		"clientAuth and serverAuth": {oidClientAuth, oidServerAuth},
	} {
		t.Run("purposes: "+label, func(t *testing.T) {
			verifyEverywhere(t, root, root.issue(t, withExtensions(t, append(goodExtensions()[:3:3], extExtKeyUsage(false, oids...))...), nil), true)
		})
	}
	t.Run("a subject of more than 65536 octets: three attributes at their bound of 32768 characters", func(t *testing.T) {
		csr := copyCSR(good)
		fill := tlv(0x0c, bytes.Repeat([]byte("a"), 32768))
		csr.RawSubject = nameOf(rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 41}), fill)), rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 4}), fill)), rdn(atv(mustOID(asn1.ObjectIdentifier{2, 5, 4, 42}), fill)))
		verifyEverywhere(t, root, root.issue(t, csr, nil), true)
	})
}

// A root has fixed extensions and a name from a fixed alphabet, so the check of the invariant, which
// comes last, has nothing to refuse that an earlier rule does not: no set of parameters was found that
// passes them and fails it (see TestBuildersNeverReturnABodyThatDoesNotAssemble, which tries many). These
// are the regression rows: the parameters nearest to the edges of what a parser reads.
func TestRootBodiesAtTheEdgesAssemble(t *testing.T) {
	maxSerial := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
	cases := []struct {
		name string
		mod  func(*pki.RootParams)
	}{
		{"the longest serial", func(p *pki.RootParams) { p.Serial = maxSerial }},
		{"the shortest serial", func(p *pki.RootParams) { p.Serial = new(big.Int).Lsh(big.NewInt(1), 63) }},
		{"the longest name of a real root", func(p *pki.RootParams) { p.Test = false; p.Name = strings.Repeat("n", 45) }},
		{"the longest name of a test root", func(p *pki.RootParams) { p.Name = strings.Repeat("n", 45) }},
		{"the first second of the year 1 after the zero time", func(p *pki.RootParams) { p.CeremonyTime = utc(1, 1, 1, 0, 0, 1) }},
		{"the last second of 1949", func(p *pki.RootParams) { p.CeremonyTime = utc(1949, 12, 31, 23, 59, 59) }},
		{"the first second of 1950", func(p *pki.RootParams) { p.CeremonyTime = utc(1950, 1, 1, 0, 0, 0) }},
		{"the last second of 2049", func(p *pki.RootParams) { p.CeremonyTime = utc(2049, 12, 31, 23, 59, 59) }},
		{"the first second of 2050", func(p *pki.RootParams) { p.CeremonyTime = utc(2050, 1, 1, 0, 0, 0) }},
		{"an end one second before the last second of 9999", func(p *pki.RootParams) { p.CeremonyTime = utc(9996, 12, 31, 23, 59, 58) }},
		{"a leap day that ends on 28 February", func(p *pki.RootParams) { p.CeremonyTime = utc(2096, 2, 29, 0, 0, 0) }},
		{"a time given in another zone", func(p *pki.RootParams) {
			p.CeremonyTime = time.Date(2026, 11, 15, 17, 0, 0, 0, time.FixedZone("UTC+5", 5*3600))
		}},
		{"the last label", func(p *pki.RootParams) { p.Label = "Z" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := buildRoot(t, c.mod) // builds, signs, assembles and parses
			if err := r.parsed.CheckSignatureFrom(r.parsed); err != nil {
				t.Errorf("the self-signature does not verify: %v", err)
			}
		})
	}
}

// The lower edge of the dates, exactly: the last second of the year 0 is refused, the first second
// of the year 1 that is not the zero time is issued and assembles, and the end of the validity may
// not go past the year 9999.
func TestTheEdgesOfTheDates(t *testing.T) {
	root := buildRoot(t, nil)
	csr := withExtensions(t, goodExtensions()...)
	plus5 := time.FixedZone("UTC+5", 5*3600)
	minus5 := time.FixedZone("UTC-5", -5*3600)
	cases := []struct {
		name   string
		at     time.Time
		accept bool
	}{
		{"the last second of the year 0", utc(0, 12, 31, 23, 59, 59), false},
		{"the zero time, which is the first second of the year 1", utc(1, 1, 1, 0, 0, 0), false},
		{"the second after the zero time", utc(1, 1, 1, 0, 0, 1), true},
		{"the last second of the year 0 given in a zone ahead of UTC", time.Date(1, 1, 1, 4, 59, 59, 0, plus5), false},
		{"the first accepted second given in a zone ahead of UTC", time.Date(1, 1, 1, 5, 0, 1, 0, plus5), true},
		{"a time in the year 0 in a zone behind UTC that is the year 1 in UTC", time.Date(0, 12, 31, 23, 0, 0, 0, minus5), true},
		{"the last second of the year 1 minus a day", utc(0, 12, 30, 23, 59, 59), false},
		{"the last second of 9996 (the end is 9999-12-31 23:59:59Z, which means no expiry)", utc(9996, 12, 31, 23, 59, 59), false},
		{"one second before it", utc(9996, 12, 31, 23, 59, 58), true},
		{"the first second of 9996", utc(9996, 1, 1, 0, 0, 0), true},
		{"the first second of 9997 (the end is in 10000)", utc(9997, 1, 1, 0, 0, 0), false},
		{"the last second of 9997 (the end is in 10000)", utc(9997, 12, 31, 23, 59, 59), false},
		{"the first second of 10000", utc(10000, 1, 1, 0, 0, 0), false},
	}
	for _, c := range cases {
		t.Run("a root: "+c.name, func(t *testing.T) {
			key := newKey(t)
			p := rootParams(&key.PublicKey)
			p.CeremonyTime = c.at
			tbs, err := pki.RootTBS(p)
			if !c.accept {
				refused(t, err, pki.ErrParams)
				if tbs != nil {
					t.Errorf("a body came with the error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			der, err := pki.Assemble(tbs, signatureOf(t, key, tbs), &key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil || !cert.NotBefore.Equal(c.at) {
				t.Errorf("NotBefore = %v, %v; want %v", cert.NotBefore, err, c.at)
			}
		})
		t.Run("an intermediate: "+c.name, func(t *testing.T) {
			p := root.interParams(csr)
			p.CeremonyTime = c.at
			tbs, err := intermediateTBS(t, p)
			if !interAccepts(c.at) {
				refused(t, err, pki.ErrParams)
				if tbs != nil {
					t.Errorf("a body came with the error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pki.SignIntermediate(nil, root.key, p, tbs); err != nil {
				t.Fatal(err)
			}
			if _, err := pki.Assemble(tbs, signatureOf(t, root.key, tbs), &root.key.PublicKey); err != nil {
				t.Fatal(err)
			}
		})
	}
	// The end of the validity of an intermediate: the last start whose end is a date, and the next one.
	for _, c := range []struct {
		name   string
		at     time.Time
		accept bool
	}{
		{"an end in December 9999", utc(9998, 11, 15, 12, 0, 0), true},
		{"an end in January 10000", utc(9998, 12, 15, 12, 0, 0), false},
	} {
		t.Run("an intermediate with "+c.name, func(t *testing.T) {
			p := root.interParams(csr)
			p.CeremonyTime = c.at
			tbs, err := intermediateTBS(t, p)
			if !c.accept {
				refused(t, err, pki.ErrParams)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pki.Assemble(tbs, signatureOf(t, root.key, tbs), &root.key.PublicKey); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// --- the property test ----------------------------------------------------------------------------

type gen struct{ r *rand.Rand }

func (g gen) intn(n int) int { return g.r.IntN(n) }

func (g gen) word(max int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	n := 1 + g.intn(max)
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[g.intn(len(letters))]
	}
	return string(b)
}

func (g gen) host() string {
	parts := make([]string, 1+g.intn(4))
	for i := range parts {
		parts[i] = g.word(12)
	}
	// RFC 1123, 2.1: the highest-level label is alphabetic. The other labels may be digits only.
	if last := parts[len(parts)-1]; strings.Trim(last, "0123456789") == "" {
		parts[len(parts)-1] = "a" + last
	}
	return strings.Join(parts, ".")
}

// permittedName is the base of a permitted subtree that is issued: a DNS name, a URI host, or a URI
// domain (a period and a name).
func (g gen) permittedName() []byte {
	switch g.intn(3) {
	case 0:
		return dns(g.host())
	case 1:
		return tlv(0x86, []byte(g.host()))
	default:
		return tlv(0x86, []byte("."+g.host()))
	}
}

func (g gen) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.intn(256))
	}
	return b
}

func (g gen) subtrees() [][]byte {
	out := make([][]byte, 1+g.intn(3))
	for i := range out {
		out[i] = ncSub(g.permittedName())
	}
	return out
}

// nameConstraints makes name constraints that are issued: one to three permitted subtrees, and the
// excluded subtrees none, or the two ranges of the contract in either order.
func (g gen) nameConstraints() []byte {
	v4, v6 := ncSubRaw(allV4()), ncSubRaw(allV6())
	var excluded [][]byte
	switch g.intn(3) {
	case 1:
		excluded = [][]byte{v4, v6}
	case 2:
		excluded = [][]byte{v6, v4}
	}
	return ncValue(g.subtrees(), excluded)
}

func allV4() []byte { return tlv(0x87, make([]byte, 8)) }
func allV6() []byte { return tlv(0x87, make([]byte, 32)) }

func ncSubRaw(base []byte) []byte { return ncSub(base) }

// oids makes the purposes of an extended key usage that is issued: serverAuth, clientAuth, or both in either order.
func (g gen) oids() []asn1.ObjectIdentifier {
	return [][]asn1.ObjectIdentifier{{oidServerAuth}, {oidClientAuth}, {oidServerAuth, oidClientAuth}, {oidClientAuth, oidServerAuth}}[g.intn(4)]
}

// subject makes a name that is issued: relative names of attributes in DER order, whose values are
// PrintableString or UTF8String, or IA5String for a domain component and an e-mail address; an
// attribute type once, but the organisational unit and the domain component, which may repeat.
func (g gen) subject() []byte {
	str := func() []byte {
		s := []byte(g.word(30))
		if g.intn(2) == 0 {
			return tlv(tPrintable, s)
		}
		// A character of printable ASCII that is not a letter: the punctuation (the rule is the range U+0020 to U+007E).
		issued := []rune("!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\"")
		return tlv(tUTF8, append(s, []byte("-"+string(issued[g.intn(len(issued))]))...))
	}
	ou := mustOID(asn1.ObjectIdentifier{2, 5, 4, 11})
	var rdns [][]byte
	for n := g.intn(3); n > 0; n-- {
		if g.intn(2) == 0 {
			rdns = append(rdns, rdn(atv(oidAttrDC, tlv(tIA5, []byte(g.word(10))))))
		} else {
			rdns = append(rdns, rdn(atv(ou, str())))
		}
	}
	last := [][]byte{atv(oidAttrCN, str())}
	if g.intn(3) == 0 { // a relative name of several attributes
		last = append(last, atv(oidAttrO, str()), atv(oidAttrDC, tlv(tIA5, []byte(g.word(6)))))
	}
	rdns = append(rdns, rdn(last...))
	if g.intn(3) == 0 {
		rdns = append(rdns, rdn(atv(oidAttrEmail, tlv(tIA5, []byte(g.word(8)+"@"+g.host())))))
	}
	return nameOf(rdns...)
}

func (g gen) usage() pkix.Extension {
	bits := []int{kuKeyCertSign}
	if g.intn(2) == 0 {
		bits = append(bits, kuCRLSign)
	}
	if g.intn(2) == 0 {
		bits = append([]int{kuDigitalSignature}, bits...)
	}
	return extKeyUsage(bits...)
}

func (g gen) when() time.Time {
	year := 1 + g.intn(7000)
	return time.Date(year, time.Month(1+g.intn(12)), 1+g.intn(31), g.intn(24), g.intn(60), g.intn(60), 0, time.UTC)
}

// windowTime is a ceremony time inside the validity of the test root, so that OpenSSL can verify at it.
func (g gen) windowTime() time.Time {
	return ceremony.Add(time.Duration(g.intn(2*365*24*3600)) * time.Second)
}

func (g gen) serial() *big.Int {
	bits := 64 + g.intn(96) // 64 to 159
	n := new(big.Int).Rsh(new(big.Int).SetBytes(g.bytes(21)), uint(21*8-bits))
	return n.SetBit(n, bits-1, 1)
}

// mutate changes a few bytes of a value: flips, drops, inserts or cuts.
func (g gen) mutate(b []byte) []byte {
	out := append([]byte(nil), b...)
	for n := 1 + g.intn(3); n > 0 && len(out) > 0; n-- {
		i := g.intn(len(out))
		switch g.intn(5) {
		case 0:
			out[i] ^= byte(1 << g.intn(8))
		case 1:
			out[i] = byte(g.intn(256))
		case 2:
			out = append(out[:i], out[i+1:]...)
		case 3:
			out = append(out[:i], append([]byte{byte(g.intn(256))}, out[i:]...)...)
		default:
			out = out[:i]
		}
	}
	return out
}

// Every valid set of parameters is issued and assembles; and whatever the builders return for a
// damaged one is a body that Assemble accepts with a real signature.
func TestBuildersNeverReturnABodyThatDoesNotAssemble(t *testing.T) {
	runBuildersProperty(t, false)
}

// runBuildersProperty is the property test. With openssl set, every body that is returned is also
// verified by OpenSSL in the strict mode (and by the standard library's chain verification).
func runBuildersProperty(t *testing.T, openssl bool) {
	g := gen{rand.New(rand.NewPCG(20261113, 5))}
	rootKey := newKey(t)
	rootCert := func() *x509.Certificate {
		p := rootParams(&rootKey.PublicKey)
		tbs, err := pki.RootTBS(p)
		if err != nil {
			t.Fatal(err)
		}
		der, err := pki.Assemble(tbs, signatureOf(t, rootKey, tbs), &rootKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}()
	keys := []*ecdsa.PrivateKey{newKey(t), newKey(t), newKey(t), newKey(t)}

	// assembles checks a returned body: it signs, assembles, parses, and verifies under the key.
	opensslChecked, opensslRefused := 0, 0
	piece := "" // the damaged part of the request being checked, for the count of refusals
	refusedBy := map[string]int{}
	assembles := func(t *testing.T, tbs []byte, sign func() ([]byte, error), signer *ecdsa.PrivateKey, issuer *x509.Certificate, withOpenSSL bool) {
		t.Helper()
		sig, err := sign()
		if err != nil {
			t.Fatalf("signing the body that the builder returned: %v", err)
		}
		der, err := pki.Assemble(tbs, sig, &signer.PublicKey)
		if err != nil {
			t.Fatalf("a body that was returned does not assemble: %v\nbody %x", err, tbs)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("a certificate that was assembled does not parse: %v", err)
		}
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			t.Fatalf("the signature does not verify: %v", err)
		}
		if !withOpenSSL {
			return
		}
		// The standard library verifies the chain, unless it declines a name form it does not process;
		// OpenSSL in the strict mode verifies it at the first second of its validity.
		pool := x509.NewCertPool()
		pool.AddCert(issuer)
		_, err = cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: cert.NotBefore, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		var unhandled x509.UnhandledCriticalExtension
		if err != nil && !errors.As(err, &unhandled) {
			t.Fatalf("the standard library refuses the chain: %v\nbody %x", err, tbs)
		}
		if err := verifier.OpenSSLVerify(t, issuer.Raw, der, cert.NotBefore); err != nil {
			opensslRefused++
			refusedBy[piece]++
			if opensslRefused <= 3 { // the first few, in full
				t.Errorf("OpenSSL (strict) refuses a body that was returned: %v\nbody %x", err, tbs)
			}
			return
		}
		opensslChecked++
	}

	t.Run("valid roots", func(t *testing.T) {
		built := 0
		for i := 0; i < 150; i++ {
			key := newKey(t)
			p := pki.RootParams{Label: string(rune('A' + g.intn(26))), Test: g.intn(2) == 0, CeremonyTime: g.when(), Key: &key.PublicKey, Serial: g.serial()}
			// A name of 1 to 45 characters (the same limit for a root and a test root) of ASCII letters, digits and hyphens, with
			// single spaces inside.
			const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
			name := make([]byte, 1+g.intn(pki.MaxNameLength))
			for j := range name {
				name[j] = alphabet[g.intn(len(alphabet))]
				if j > 0 && j < len(name)-1 && name[j-1] != ' ' && g.intn(6) == 0 {
					name[j] = ' '
				}
			}
			p.Name = string(name)
			tbs, err := pki.RootTBS(p)
			if err != nil {
				t.Fatalf("a valid root is refused: %v\nparameters: %+v", err, p)
			}
			sig := signatureOf(t, key, tbs)
			der, err := pki.Assemble(tbs, sig, &key.PublicKey)
			if err != nil {
				t.Fatalf("a body that was returned does not assemble: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil || cert.CheckSignatureFrom(cert) != nil {
				t.Fatalf("the root does not parse or verify: %v", err)
			}
			if !cert.NotBefore.Equal(p.CeremonyTime) || cert.SerialNumber.Cmp(p.Serial) != 0 {
				t.Fatalf("the dates or the serial read back differ")
			}
			if openssl && cert.NotBefore.Unix() > 0 { // -attime takes no time before 1970
				if err := verifier.OpenSSLVerify(t, der, der, cert.NotBefore); err != nil {
					t.Fatalf("OpenSSL (strict) refuses a root that was returned: %v\nbody %x", err, tbs)
				}
				opensslChecked++
			}
			built++
		}
		if built != 150 {
			t.Fatalf("%d roots built", built)
		}
		t.Logf("%d valid roots built; OpenSSL has verified %d, refused %d", built, opensslChecked, opensslRefused)
	})

	t.Run("damaged roots", func(t *testing.T) {
		returned, refusals := 0, 0
		for i := 0; i < 400; i++ {
			key := newKey(t)
			name := g.mutate([]byte(g.word(30) + " " + g.word(10)))
			label := string(g.mutate([]byte{byte('A' + g.intn(26))}))
			at := g.when().Add(time.Duration(g.intn(3)-1) * time.Duration(g.intn(2)) * time.Nanosecond)
			serial := g.serial()
			if g.intn(4) == 0 {
				serial = new(big.Int).Rsh(serial, uint(g.intn(120)))
			}
			p := pki.RootParams{Name: string(name), Label: label, Test: g.intn(2) == 0, CeremonyTime: at, Key: &key.PublicKey, Serial: serial}
			tbs, err := pki.RootTBS(p)
			if err != nil {
				refused(t, err, pki.ErrParams)
				refusals++
				continue
			}
			returned++
			self := mustParseSelf(t, key, tbs)
			assembles(t, tbs, func() ([]byte, error) { return pki.SignRoot(nil, key, p, tbs) }, key, self, false)
			if openssl && self.NotBefore.Unix() > 0 {
				if err := verifier.OpenSSLVerify(t, self.Raw, self.Raw, self.NotBefore); err != nil {
					t.Fatalf("OpenSSL (strict) refuses a root that was returned: %v\nbody %x", err, tbs)
				}
				opensslChecked++
			}
		}
		if returned == 0 || refusals == 0 {
			t.Fatalf("returned %d, refused %d: the property was not tried on both", returned, refusals)
		}
	})

	t.Run("valid intermediates", func(t *testing.T) {
		withNC, withEKU, viewChecked := 0, 0, 0
		for i := 0; i < 400; i++ {
			inWindow := i%2 == 0 // half of them are verified by both verifiers, half have any year
			ikey := keys[g.intn(len(keys))]
			exts := []pkix.Extension{extBasicConstraints(), g.usage()}
			exts = append(exts, pkix.Extension{Id: oidNameConstraints, Critical: true, Value: g.nameConstraints()}) // required
			withNC++
			exts = append(exts, extExtKeyUsage(false, g.oids()...)) // required, not critical
			withEKU++
			g.r.Shuffle(len(exts), func(a, b int) { exts[a], exts[b] = exts[b], exts[a] })
			csr := makeCSR(t, csrOptions{key: ikey, rawSubject: g.subject(), exts: exts})
			p := pki.IntermediateParams{
				CSR: csr.DER(), IssuerSubject: rootCert.RawSubject, IssuerKey: &rootKey.PublicKey,
				Roots:        []pki.RootRef{{Subject: rootCert.RawSubject, Key: &rootKey.PublicKey}},
				CeremonyTime: g.when(), Serial: g.serial(),
			}
			if inWindow {
				p.CeremonyTime = g.windowTime()
			}
			for !interAccepts(p.CeremonyTime) { // a start whose end is not a date is not one that is issued
				p.CeremonyTime = g.windowTime()
			}
			tbs, err := intermediateTBS(t, p)
			if err != nil {
				t.Fatalf("a valid request is refused: %v\nrequest extensions %v", err, extensionNamesOf(exts))
			}
			assembles(t, tbs, func() ([]byte, error) { return pki.SignIntermediate(nil, rootKey, p, tbs) }, rootKey, rootCert, openssl && inWindow)
			// The request that is checked is the request that is issued: what the view of the request shows is
			// what the body holds.
			view, err := pki.ParseRequest(p.CSR)
			if err != nil {
				t.Fatalf("a request that is issued cannot be read: %v", err)
			}
			body := parseBodyOf(t, tbs)
			if !bytes.Equal(body.RawSubject, view.Subject()) || !view.PublicKey().Equal(body.PublicKey) {
				t.Fatalf("the subject or the key issued is not that of the request %x", p.CSR)
			}
			for _, e := range view.Extensions() {
				if e.Id.Equal(oidBasicConstraints) || e.Id.Equal(oidKeyUsage) {
					continue // the profile writes these itself, from the request's wish
				}
				if got := extensionOf(body, e.Id); got == nil || got.Critical != e.Critical || !bytes.Equal(got.Value, e.Value) {
					t.Fatalf("the extension %s issued is not the one of the request %x", e.Id, p.CSR)
				}
			}
			viewChecked++
		}
		t.Logf("valid intermediates: 400 issued, %d with name constraints, %d with an extended key usage, %d read back against the view of their request; OpenSSL has verified %d, refused %d", withNC, withEKU, viewChecked, opensslChecked, opensslRefused)
		if withNC != 400 || withEKU != 400 || viewChecked != 400 {
			t.Fatalf("the generator did not reach the forms: %d with name constraints, %d with an extended key usage, %d checked", withNC, withEKU, viewChecked)
		}
		if openssl && opensslChecked < 300 {
			t.Fatalf("OpenSSL looked at only %d valid bodies", opensslChecked)
		}
	})

	t.Run("damaged intermediates", func(t *testing.T) {
		returned, refusals, byInvariant, badIssuers, badSubjects := 0, 0, 0, 0, 0
		reached := map[string]int{} // which damaged part met the second reading of the body (none may)
		for i := 0; i < 6000; i++ {
			ikey := keys[g.intn(len(keys))]
			nc, eku, subject, issuer := g.nameConstraints(), extExtKeyUsage(false, g.oids()...).Value, g.subject(), rootCert.RawSubject
			// Damage one of them.
			piece = []string{"name constraints", "extended key usage", "subject", "issuer", "the text of the subject", "the text of the issuer", "the text of the issuer", "the text of the issuer"}[g.intn(8)]
			badUTF8 := ""
			switch piece {
			case "the text of the issuer":
				issuer, badUTF8 = g.issuerWithBadText()
				badIssuers++
			case "the text of the subject":
				subject, badUTF8 = g.issuerWithBadText()
				badSubjects++
			case "name constraints":
				nc = g.mutate(nc)
			case "extended key usage":
				eku = g.mutate(eku)
			case "subject":
				subject = g.mutate(subject)
			default:
				issuer = g.mutate(issuer)
			}
			exts := []pkix.Extension{extBasicConstraints(), g.usage(), {Id: oidNameConstraints, Critical: true, Value: nc}, {Id: oidExtKeyUsage, Critical: false, Value: eku}}
			csr := makeCSR(t, csrOptions{key: ikey, exts: exts})
			csr.RawSubject = subject
			p := pki.IntermediateParams{
				CSR: csr.DER(), IssuerSubject: issuer, IssuerKey: &rootKey.PublicKey,
				Roots:        []pki.RootRef{{Subject: issuer, Key: &rootKey.PublicKey}},
				CeremonyTime: g.windowTime(), Serial: g.serial(),
			}
			tbs, err := intermediateTBS(t, p)
			if badUTF8 != "" {
				// Text that is not UTF-8 is refused by the reading of the name, in the kind of its source, with its own words.
				want := pki.ErrParams
				if piece == "the text of the subject" {
					want = pki.ErrRequest
				}
				refused(t, err, want)
				if err != nil && !strings.Contains(err.Error(), "not valid UTF-8") {
					t.Fatalf("%s: the text does not say that the value is not UTF-8: %v", badUTF8, err)
				}
			}
			if err != nil {
				if k := kindOf(t, err); !errors.Is(k, pki.ErrParams) && !errors.Is(k, pki.ErrRequest) {
					t.Fatalf("an error of no kind that IntermediateTBS returns: %v", err)
				}
				if !printable(err.Error()) {
					t.Fatalf("the text is not printable ASCII: %q", err.Error())
				}
				refusals++
				if strings.Contains(err.Error(), "standard library") || strings.Contains(err.Error(), "a fault of this package") {
					byInvariant++
					reached[piece]++
				}
				continue
			}
			returned++
			// A damaged issuer is not the root any more, so no chain can be built to it: it is only assembled.
			assembles(t, tbs, func() ([]byte, error) { return pki.SignIntermediate(nil, rootKey, p, tbs) }, rootKey, rootCert, openssl && piece != "issuer")
		}
		// The rules for the extended key usage and the text refuse more of the damaged pieces than the earlier rules did (a changed extended key usage
		// that named another purpose was issued before; a damaged subject that held another letter was issued), so fewer are
		// returned: about 120 of 6000, where there were 200 and more.
		if returned < 80 || refusals < 5000 {
			t.Fatalf("returned %d, refused %d: the property was not tried on both", returned, refusals)
		}
		if byInvariant != 0 {
			t.Fatalf("%d damaged inputs reached the second reading of the body (%v), which only a fault of the package can reach", byInvariant, reached)
		}
		if badIssuers < 1400 || badSubjects < 450 {
			t.Fatalf("only %d issuers and %d subjects of invalid UTF-8 were tried", badIssuers, badSubjects)
		}
		t.Logf("returned %d, refused %d, none of them by the second reading of the body (%d damaged issuers and %d damaged subjects of invalid UTF-8, all refused by the reading of the name); OpenSSL verified %d bodies in all and refused %d (by the damaged part: %v)", returned, refusals, badIssuers, badSubjects, opensslChecked, opensslRefused, refusedBy)
		if openssl && opensslChecked+opensslRefused < 350 { // 384 now: the stricter rules return fewer damaged bodies
			t.Fatalf("OpenSSL looked at only %d bodies", opensslChecked+opensslRefused)
		}
		if opensslRefused > 0 {
			t.Errorf("OpenSSL (strict) refused %d of the %d bodies it was given", opensslRefused, opensslChecked+opensslRefused)
		}
	})
}

func extensionNamesOf(exts []pkix.Extension) []string {
	var out []string
	for _, e := range exts {
		out = append(out, fmt.Sprintf("%s critical=%v len=%d", e.Id, e.Critical, len(e.Value)))
	}
	return out
}

// mustParseSelf assembles a root body with the key and parses it, to give assembles its issuer.
func mustParseSelf(t *testing.T, key *ecdsa.PrivateKey, tbs []byte) *x509.Certificate {
	t.Helper()
	der, err := pki.Assemble(tbs, signatureOf(t, key, tbs), &key.PublicKey)
	if err != nil {
		t.Fatalf("a body that was returned does not assemble: %v\nbody %x", err, tbs)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// interAccepts says whether the validity of an intermediate that starts at the time is one that a certificate holds: the
// end is 13 calendar months later, so a start from December 9998 on has an end in the year 10000, and the start is not the
// zero time. It is worked out from the calendar here and not from the package.
func interAccepts(at time.Time) bool {
	u := at.UTC()
	if u.IsZero() || u.Nanosecond() != 0 || u.Year() < 1 {
		return false
	}
	endYear := u.Year() + (int(u.Month())+12)/12
	return endYear <= 9999
}

// issuerWithBadText is a name of one common name whose UTF8String is not UTF-8, of every kind in turn: a lone continuation
// octet, a truncated sequence, an overlong form (two, three and four octets), a surrogate, a code point above U+10FFFF, and the
// octets that never occur in UTF-8 (0xc0, 0xc1, 0xf5 to 0xff), alone and between good text.
func (g gen) issuerWithBadText() ([]byte, string) {
	kinds := []struct {
		name string
		b    []byte
	}{
		{"a lone continuation octet", []byte{0x80 + byte(g.intn(0x40))}},
		{"a truncated two-octet sequence", []byte{0xc2}},
		{"a truncated three-octet sequence", []byte{0xe2, 0x82}},
		{"a truncated four-octet sequence", []byte{0xf0, 0x9f, 0x98}},
		{"an overlong NUL", []byte{0xc0, 0x80}},
		{"an overlong slash", []byte{0xc0, 0xaf}},
		{"an overlong of three octets", []byte{0xe0, 0x80, 0x80}},
		{"an overlong of four octets", []byte{0xf0, 0x80, 0x80, 0x80}},
		{"a surrogate", []byte{0xed, 0xa0 + byte(g.intn(0x20)), 0x80}},
		{"a code point above U+10FFFF", []byte{0xf4, 0x90, 0x80, 0x80}},
		{"a code point far above U+10FFFF", []byte{0xf7, 0xbf, 0xbf, 0xbf}},
		{"the octet 0xc0", []byte{0xc0}},
		{"the octet 0xc1", []byte{0xc1}},
		{"an octet from 0xf5 to 0xff", []byte{0xf5 + byte(g.intn(11))}},
		{"a continuation octet after an ASCII letter", []byte{'a', 0x80}},
	}
	k := kinds[g.intn(len(kinds))]
	text := append(append([]byte(g.word(8)), k.b...), []byte(g.word(5))...)
	if g.intn(3) == 0 {
		text = k.b
	}
	return nameOf(rdn(atv(oidAttrCN, tlv(tUTF8, text)))), k.name
}
