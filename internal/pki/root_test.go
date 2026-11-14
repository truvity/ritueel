package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

func TestConstants(t *testing.T) {
	if pki.RootValidityMonths != 36 {
		t.Errorf("RootValidityMonths = %d, want 36 (bundle.md, the root certificate)", pki.RootValidityMonths)
	}
	if pki.MaxNameLength != 45 {
		t.Errorf("MaxNameLength = %d, want 45 (45 + \" Root A\" + \" (TEST ONLY)\" = 64, the RFC 5280 limit of a common name)", pki.MaxNameLength)
	}
	// The one number is the other number minus the longest ending that a root name gets: no root name, test or not, can
	// make a common name of more than MaxCommonNameLength.
	if got := pki.MaxNameLength + len(" Root A") + len(" (TEST ONLY)"); got != pki.MaxCommonNameLength {
		t.Errorf("the longest name makes a common name of %d characters, MaxCommonNameLength is %d", got, pki.MaxCommonNameLength)
	}
	if pki.MaxCommonNameLength != 64 {
		t.Errorf("MaxCommonNameLength = %d, want 64 (RFC 5280, ub-common-name)", pki.MaxCommonNameLength)
	}
}

func TestRootCommonName(t *testing.T) {
	long := func(n int) string { return strings.Repeat("n", n) }
	cases := []struct {
		name   string
		in     string
		label  string
		test   bool
		want   string
		reason string // "" for an accepted name
	}{
		{name: "an ordinary name", in: "Example Test", label: "A", want: "Example Test Root A"},
		{name: "a test root", in: "Example Test", label: "A", test: true, want: "Example Test Root A (TEST ONLY)"},
		{name: "one character", in: "a", label: "Z", want: "a Root Z"},
		{name: "digits and a hyphen and a space", in: "Example-Org 2", label: "B", want: "Example-Org 2 Root B"},
		{name: "every kind of character at the ends of their ranges", in: "azAZ09 -", label: "M", want: "azAZ09 - Root M"},
		{name: "a single space inside is allowed", in: "a b", label: "A", want: "a b Root A"},
		{name: "45 characters make a 52-character common name", in: long(45), label: "A", want: long(45) + " Root A"},
		{name: "45 characters make a 64-character common name for a test root", in: long(45), label: "A", test: true, want: long(45) + " Root A (TEST ONLY)"},
		{name: "a name of 45 characters that ends in a space", in: strings.Repeat("ab-c ", 9), label: "A", reason: "space"},
		{name: "a name of 45 characters that ends in a letter", in: strings.Repeat("ab-c ", 8) + "ab-cd", label: "A", want: strings.Repeat("ab-c ", 8) + "ab-cd Root A"},

		{name: "a space at the start", in: " a", label: "A", reason: "space"},
		{name: "a space at the end", in: "a ", label: "A", reason: "space"},
		{name: "a single space", in: " ", label: "A", reason: "space"},
		{name: "a double space", in: "a  b", label: "A", reason: "space"},
		{name: "a triple space", in: "a   b", label: "A", reason: "space"},
		{name: "a double space at the start", in: "  a", label: "A", reason: "space"},
		{name: "a double space at the end", in: "a  ", label: "A", reason: "space"},
		{name: "a hyphen next to a space is allowed", in: "a - b", label: "A", want: "a - b Root A"},
		{name: "46 characters", in: long(46), label: "A", reason: "length"},
		{name: "46 characters for a test root", in: long(46), label: "A", test: true, reason: "length"},
		{name: "57 characters, the old limit of a real root", in: long(57), label: "A", reason: "length"},
		{name: "64 characters", in: long(64), label: "A", reason: "length"},
		{name: "65 characters", in: long(65), label: "A", reason: "length"},
		{name: "a very long name", in: long(5000), label: "A", reason: "length"},
		{name: "empty", in: "", label: "A", reason: "length"},
		{name: "an underscore", in: "a_b", label: "A", reason: "character"},
		{name: "a dot", in: "a.b", label: "A", reason: "character"},
		{name: "a slash", in: "a/b", label: "A", reason: "character"},
		{name: "a comma", in: "a,b", label: "A", reason: "character"},
		{name: "an equals sign", in: "a=b", label: "A", reason: "character"},
		{name: "a plus", in: "a+b", label: "A", reason: "character"},
		{name: "a quote", in: "a\"b", label: "A", reason: "character"},
		{name: "a backslash", in: "a\\b", label: "A", reason: "character"},
		{name: "a bracket", in: "a<b>", label: "A", reason: "character"},
		{name: "a newline", in: "a\nb", label: "A", reason: "character"},
		{name: "a trailing newline", in: "ab\n", label: "A", reason: "character"},
		{name: "a carriage return", in: "a\rb", label: "A", reason: "character"},
		{name: "a tab", in: "a\tb", label: "A", reason: "character"},
		{name: "a NUL", in: "a\x00b", label: "A", reason: "character"},
		{name: "the escape character", in: "a\x1bb", label: "A", reason: "character"},
		{name: "DEL", in: "a\x7fb", label: "A", reason: "character"},
		{name: "the character before the digits", in: "a/", label: "A", reason: "character"},
		{name: "the character after the digits", in: "a:", label: "A", reason: "character"},
		{name: "the character before the upper-case letters", in: "a@", label: "A", reason: "character"},
		{name: "the character after the upper-case letters", in: "a[", label: "A", reason: "character"},
		{name: "the character before the lower-case letters", in: "a`", label: "A", reason: "character"},
		{name: "the character after the lower-case letters", in: "a{", label: "A", reason: "character"},
		{name: "a Latin letter with an accent", in: "caf" + string(rune(0xe9)), label: "A", reason: "character"},
		{name: "a Cyrillic letter that looks like a Latin one", in: "Ex" + string(rune(0x0430)) + "mple", label: "A", reason: "character"},
		{name: "a Greek letter that looks like a Latin one", in: "Alph" + string(rune(0x03b1)), label: "A", reason: "character"},
		{name: "a full-width letter", in: string(rune(0xff21)), label: "A", reason: "character"},
		{name: "the Kelvin sign", in: string(rune(0x212a)), label: "A", reason: "character"},
		{name: "a zero-width space", in: "a" + string(rune(0x200b)) + "b", label: "A", reason: "character"},
		{name: "a right-to-left override", in: "a" + string(rune(0x202e)) + "b", label: "A", reason: "character"},
		{name: "a no-break space", in: "a" + string(rune(0xa0)) + "b", label: "A", reason: "character"},
		{name: "an emoji", in: "a" + string(rune(0x1f600)), label: "A", reason: "character"},
		{name: "a byte that is not UTF-8", in: "a" + string([]byte{0xff}) + "b", label: "A", reason: "character"},
		{name: "a truncated UTF-8 sequence", in: "a" + string([]byte{0xc3}), label: "A", reason: "character"},

		{name: "the label A", in: "n", label: "A", want: "n Root A"},
		{name: "the label Z", in: "n", label: "Z", want: "n Root Z"},
		{name: "a lower-case label", in: "n", label: "a", reason: "label"},
		{name: "the character before A", in: "n", label: "@", reason: "label"},
		{name: "the character after Z", in: "n", label: "[", reason: "label"},
		{name: "a digit label", in: "n", label: "1", reason: "label"},
		{name: "an empty label", in: "n", label: "", reason: "label"},
		{name: "a two-letter label", in: "n", label: "AB", reason: "label"},
		{name: "a label with a space", in: "n", label: "A ", reason: "label"},
		{name: "a label with a newline", in: "n", label: "A\n", reason: "label"},
		{name: "a label that is a non-ASCII letter", in: "n", label: string(rune(0xc9)), reason: "label"},
		{name: "a label that is one byte that is not UTF-8", in: "n", label: string([]byte{0xc3}), reason: "label"},
		{name: "a label that is a Cyrillic A", in: "n", label: string(rune(0x0410)), reason: "label"},
		{name: "a label that is a NUL", in: "n", label: "\x00", reason: "label"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := pki.RootCommonName(c.in, c.label, c.test)
			if c.reason == "" {
				if err != nil {
					t.Fatalf("RootCommonName refuses it: %v", err)
				}
				if got != c.want {
					t.Errorf("RootCommonName = %q, want %q", got, c.want)
				}
				if len(got) > pki.MaxCommonNameLength {
					t.Errorf("the common name has %d characters", len(got))
				}
				return
			}
			// Each rule says its own words, so a refusal for one rule is not taken for another.
			words := map[string]string{"length": "not 1 to 45", "character": "a character other than an ASCII letter, a digit, a space or a hyphen", "space": "space", "label": "the label is not one upper-case ASCII letter"}[c.reason]
			refusedSaying(t, err, pki.ErrParams, words)
			if got != "" {
				t.Errorf("the name %q came with the error", got)
			}
		})
	}
}

type rootCase struct {
	name   string
	serial string
	params func(t testing.TB) pki.RootParams
}

// rootCases are the cases of expected.txt, written as parameters: the times and the serials are
// those of reproduce.sh.
func rootCases() []rootCase {
	base := func(mod func(*pki.RootParams)) func(t testing.TB) pki.RootParams {
		return func(t testing.TB) pki.RootParams {
			p := pki.RootParams{Name: "Example Test", Label: "K", Test: true, CeremonyTime: ceremony, Key: fixturePublicKey(t, "root.pub.pem")}
			mod(&p)
			return p
		}
	}
	return []rootCase{
		{"root-test", "4b1c9e0d77a2f35b8c6e1d0a93f4b27c5e8a1d36", base(func(p *pki.RootParams) {})},
		{"root-real", "8000000000000001", base(func(p *pki.RootParams) {
			p.Name, p.Label, p.Test, p.CeremonyTime = "Example-Org 2", "Z", false, utc(2024, 2, 29, 8, 30, 0)
		})},
		{"root-2049", "7fffffffffffffffffffffffffffffffffffffff", base(func(p *pki.RootParams) { p.CeremonyTime = utc(2049, 12, 31, 23, 59, 59) })},
		{"root-2050", "ffffffffffffffff", base(func(p *pki.RootParams) { p.CeremonyTime = utc(2050, 1, 1, 0, 0, 0) })},
		{"root-1950", "0123456789abcdef01", base(func(p *pki.RootParams) { p.CeremonyTime = utc(1950, 1, 1, 0, 0, 0) })},
		{"root-1949", "0123456789abcdef02", base(func(p *pki.RootParams) { p.CeremonyTime = utc(1949, 12, 31, 23, 59, 59) })},
		{"root-longest", "0fedcba9876543210f", base(func(p *pki.RootParams) { p.Name = "Abcdefghij Abcdefghij Abcdefghij Abcdefghij a" })},
	}
}

func TestRootTBSKnownAnswers(t *testing.T) {
	want := loadAnswers(t)
	cases := rootCases()
	if len(cases) == 0 {
		t.Fatal("no case")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := c.params(t)
			p.Serial = hexBig(t, c.serial)
			tbs, err := pki.RootTBS(p)
			if err != nil {
				t.Fatal(err)
			}
			if got, w := hex.EncodeToString(tbs), want.text(t, c.name+".tbs"); got != w {
				t.Errorf("the body differs from the one OpenSSL made:\n got %s\nwant %s", got, w)
			}
			if got, w := pki.TBSSHA256(tbs), want.text(t, c.name+".tbs.sha256"); got != w {
				t.Errorf("TBSSHA256 = %s, want %s", got, w)
			}
			if got, w := hex.EncodeToString(pki.TBSDigest(tbs)), want.text(t, c.name+".tbs.sha384"); got != w {
				t.Errorf("TBSDigest = %s, want %s", got, w)
			}
			// The same parameters, again, and the same instant in another zone.
			again, err := pki.RootTBS(p)
			if err != nil || !bytes.Equal(again, tbs) {
				t.Errorf("a second call gives %x, %v", again, err)
			}
			p.CeremonyTime = p.CeremonyTime.In(time.FixedZone("UTC+5", 5*3600))
			zoned, err := pki.RootTBS(p)
			if err != nil || !bytes.Equal(zoned, tbs) {
				t.Errorf("the same instant in another zone gives %x, %v", zoned, err)
			}
		})
	}
}

// The answers file is read for every name the tests use, and nothing in it is left unused.
func TestAnswersAreAllUsed(t *testing.T) {
	want := loadAnswers(t)
	// The pins of the two requests that the builder refuses are read by TestKeyPinAndIdentifierKnownAnswers.
	used := map[string]bool{"issuer": true, "root.pin": true, "root.keyid": true, "csr-no-eku.pin": true, "csr-eku-critical.pin": true}
	for _, c := range rootCases() {
		for _, s := range []string{"", ".sha256", ".sha384"} {
			used[c.name+".tbs"+s] = true
		}
	}
	for _, c := range interCases() {
		for _, s := range []string{"", ".sha256", ".sha384"} {
			used[c.name+".tbs"+s] = true
		}
		for _, s := range []string{".pin", ".keyid"} {
			used[c.csr+s] = true
		}
	}
	for name := range want {
		if !used[name] {
			t.Errorf("expected.txt has %s, which no test reads", name)
		}
	}
	for name := range used {
		if _, ok := want[name]; !ok {
			t.Errorf("a test reads %s, which expected.txt does not have", name)
		}
	}
}

// The fixture certificates are whole certificates made by OpenSSL, signed with the root key of
// root.pub.pem: Assemble puts the same signature to the same body and gets the same bytes.
func TestAssembleKnownAnswers(t *testing.T) {
	want := loadAnswers(t)
	cases := []struct{ name, cert string }{{"root-test", "root-test.cert.pem"}, {"inter-nc", "inter-nc.cert.pem"}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbs := want.bytes(t, c.name+".tbs")
			sig := mustHex(t, strings.TrimSpace(string(readFixture(t, c.name+".sig.hex"))))
			der := pemBlock(t, readFixture(t, c.cert), "CERTIFICATE")
			got, err := pki.Assemble(tbs, sig, fixturePublicKey(t, "root.pub.pem"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, der) {
				t.Errorf("Assemble differs from the certificate OpenSSL's generator made:\n got %x\nwant %x", got, der)
			}
			// The fixture is itself sound: the body inside it is the expected one, and the root key
			// that made the signature is the key of root.pub.pem.
			parsed := fixtureCert(t, c.cert)
			if !bytes.Equal(parsed.RawTBSCertificate, tbs) {
				t.Error("the body in the fixture certificate is not the expected body")
			}
			rootKey := fixturePublicKey(t, "root.pub.pem")
			if !ecdsa.VerifyASN1(rootKey, pki.TBSDigest(tbs), sig) {
				t.Error("the signature of the fixture does not verify with root.pub.pem")
			}
		})
	}
}

func TestRootTBSRefusals(t *testing.T) {
	key := newKey(t).PublicKey
	base := func() pki.RootParams { return rootParams(&key) }
	pow := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
	cases := []struct {
		name string
		mod  func(*pki.RootParams)
	}{
		{"an empty name", func(p *pki.RootParams) { p.Name = "" }},
		{"a name with an underscore", func(p *pki.RootParams) { p.Name = "a_b" }},
		{"a name with a newline", func(p *pki.RootParams) { p.Name = "a\nb" }},
		{"a name with a look-alike letter", func(p *pki.RootParams) { p.Name = "Ex" + string(rune(0x0430)) + "mple" }},
		{"a name of 65 characters", func(p *pki.RootParams) { p.Name = strings.Repeat("n", 65) }},
		{"a common name of 65 characters", func(p *pki.RootParams) { p.Name = strings.Repeat("n", 46) }},
		{"a lower-case label", func(p *pki.RootParams) { p.Label = "a" }},
		{"a two-letter label", func(p *pki.RootParams) { p.Label = "AB" }},
		{"an empty label", func(p *pki.RootParams) { p.Label = "" }},
		{"the zero time", func(p *pki.RootParams) { p.CeremonyTime = time.Time{} }},
		{"the zero time in another zone", func(p *pki.RootParams) { p.CeremonyTime = time.Time{}.In(time.FixedZone("UTC+5", 5*3600)) }},
		{"a nanosecond", func(p *pki.RootParams) { p.CeremonyTime = ceremony.Add(time.Nanosecond) }},
		{"a millisecond", func(p *pki.RootParams) { p.CeremonyTime = ceremony.Add(time.Millisecond) }},
		{"all but a nanosecond of a second", func(p *pki.RootParams) { p.CeremonyTime = ceremony.Add(999999999 * time.Nanosecond) }},
		{"a fraction in another zone", func(p *pki.RootParams) {
			p.CeremonyTime = ceremony.Add(time.Microsecond).In(time.FixedZone("UTC-3", -3*3600))
		}},
		{"a ceremony after the year 9999", func(p *pki.RootParams) { p.CeremonyTime = utc(10000, 1, 1, 0, 0, 0) }},
		{"a ceremony in 9999, which has no end", func(p *pki.RootParams) { p.CeremonyTime = utc(9999, 6, 1, 0, 0, 0) }},
		{"an end in the year 10000", func(p *pki.RootParams) { p.CeremonyTime = utc(9997, 1, 1, 0, 0, 0) }},
		{"a time that is in 9999 only in another zone", func(p *pki.RootParams) {
			p.CeremonyTime = time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("UTC-5", -5*3600))
		}},
		{"no key", func(p *pki.RootParams) { p.Key = nil }},
		{"a nil ECDSA pointer", func(p *pki.RootParams) { p.Key = (*ecdsa.PublicKey)(nil) }},
		{"a key by value", func(p *pki.RootParams) { p.Key = key }},
		{"no serial", func(p *pki.RootParams) { p.Serial = nil }},
		{"serial zero", func(p *pki.RootParams) { p.Serial = big.NewInt(0) }},
		{"a negative serial", func(p *pki.RootParams) { p.Serial = big.NewInt(-5) }},
		{"a serial of 63 bits", func(p *pki.RootParams) { p.Serial = new(big.Int).Sub(pow(63), big.NewInt(1)) }},
		{"a serial of 160 bits", func(p *pki.RootParams) { p.Serial = pow(159) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := base()
			c.mod(&p)
			tbs, err := pki.RootTBS(p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
	for name, bad := range badKeys(t) {
		t.Run("the key is "+name, func(t *testing.T) {
			p := base()
			p.Key = bad
			tbs, err := pki.RootTBS(p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
}

// The edges of the validity: the end that is still a date, and the one that is not.
func TestRootTBSEndOfTime(t *testing.T) {
	key := newKey(t).PublicKey
	for _, c := range []struct {
		name   string
		from   time.Time
		accept bool
	}{
		{"an end on 31 December 9999 at 23:59:58", utc(9996, 12, 31, 23, 59, 58), true},
		{"an end on 31 December 9999 at 23:59:59, which means no expiry", utc(9996, 12, 31, 23, 59, 59), false},
		{"an end on 1 January 10000", utc(9997, 1, 1, 0, 0, 0), false},
		{"the first second of the year 1", utc(1, 1, 1, 0, 0, 1), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := rootParams(&key)
			p.CeremonyTime = c.from
			if !c.accept {
				tbs, err := pki.RootTBS(p)
				refused(t, err, pki.ErrParams)
				if tbs != nil {
					t.Errorf("a body %x came with the error", tbs)
				}
				return
			}
			// The body is a date that a parser reads back as the same instant, whatever the year.
			cert := buildRootAt(t, p)
			if !cert.NotBefore.Equal(c.from) {
				t.Errorf("NotBefore = %v, want %v", cert.NotBefore, c.from)
			}
			if got, want := cert.NotAfter.Year(), c.from.Year()+3; got != want {
				t.Errorf("NotAfter year = %d, want %d", got, want)
			}
		})
	}
}

// buildRootAt builds, signs and assembles a root from p with a new key, and returns it parsed.
func buildRootAt(t testing.TB, p pki.RootParams) *x509.Certificate {
	t.Helper()
	key := newKey(t)
	p.Key = &key.PublicKey
	tbs, err := pki.RootTBS(p)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := pki.SignRoot(nil, key, p, tbs)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.Assemble(tbs, sig, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A root built with a software key, parsed with Go, row by row against bundle.md.
func TestRootCertificateRows(t *testing.T) {
	for _, c := range []struct {
		name   string
		mod    func(*pki.RootParams)
		cn     string
		starts time.Time
		ends   time.Time
	}{
		{"a test root", nil, "Example Test Root K (TEST ONLY)", ceremony, utc(2029, 11, 15, 12, 0, 0)},
		{"a real root", func(p *pki.RootParams) { p.Test = false; p.Name = "Example-Org 2"; p.Label = "Z" }, "Example-Org 2 Root Z", ceremony, utc(2029, 11, 15, 12, 0, 0)},
		{"a ceremony on 29 February", func(p *pki.RootParams) { p.CeremonyTime = utc(2028, 2, 29, 1, 2, 3) }, "Example Test Root K (TEST ONLY)", utc(2028, 2, 29, 1, 2, 3), utc(2031, 2, 28, 1, 2, 3)},
		{"a ceremony in 2049", func(p *pki.RootParams) { p.CeremonyTime = utc(2049, 7, 4, 5, 6, 7) }, "Example Test Root K (TEST ONLY)", utc(2049, 7, 4, 5, 6, 7), utc(2052, 7, 4, 5, 6, 7)},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := buildRoot(t, c.mod)
			cert := r.parsed
			if cert.Version != 3 {
				t.Errorf("version = %d, want 3", cert.Version)
			}
			if cert.SerialNumber.Cmp(aSerial) != 0 {
				t.Errorf("serial = %x, want %x", cert.SerialNumber, aSerial)
			}
			if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
				t.Errorf("signature algorithm = %v, want ecdsa-with-SHA384", cert.SignatureAlgorithm)
			}
			if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				t.Error("the issuer is not the subject, byte for byte")
			}
			if cert.Subject.CommonName != c.cn || len(cert.Subject.Names) != 1 {
				t.Errorf("subject = %v, want the one attribute CN=%s", cert.Subject, c.cn)
			}
			if !cert.NotBefore.Equal(c.starts) || !cert.NotAfter.Equal(c.ends) {
				t.Errorf("validity = %v to %v, want %v to %v", cert.NotBefore, cert.NotAfter, c.starts, c.ends)
			}
			// The public key is the root's own key, and the certificate is self-signed.
			pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok || !pub.Equal(&r.key.PublicKey) || pub.Curve != elliptic.P384() {
				t.Errorf("the public key is not the key of the root")
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				t.Errorf("the self-signature does not verify: %v", err)
			}
			// Exactly three extensions, in the order of the vectors, with these flags.
			wantIDs := []string{"2.5.29.19", "2.5.29.14", "2.5.29.15"}
			if got := extensionIDs(cert); strings.Join(got, ",") != strings.Join(wantIDs, ",") {
				t.Errorf("extensions = %v, want %v", got, wantIDs)
			}
			wantCritical := []bool{true, false, true}
			for i, e := range cert.Extensions {
				if i < len(wantCritical) && e.Critical != wantCritical[i] {
					t.Errorf("extension %s critical = %v, want %v", e.Id, e.Critical, wantCritical[i])
				}
			}
			if bc := extensionOf(cert, oidBasicConstraints); bc == nil || !bytes.Equal(bc.Value, []byte{0x30, 0x03, 0x01, 0x01, 0xff}) {
				t.Errorf("basic constraints = %v, want cA true and no path length", bc)
			}
			if !cert.IsCA || cert.MaxPathLen != -1 || cert.MaxPathLenZero {
				t.Errorf("IsCA = %v, MaxPathLen = %d, MaxPathLenZero = %v; want a CA with no path length", cert.IsCA, cert.MaxPathLen, cert.MaxPathLenZero)
			}
			if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
				t.Errorf("key usage = %b, want keyCertSign and cRLSign only", cert.KeyUsage)
			}
			// The key identifier is worked out here again from the point, not by KeyIdentifier.
			point := elliptic.Marshal(elliptic.P384(), r.key.X, r.key.Y) //nolint:staticcheck // the uncompressed point, as RFC 7093 hashes it
			sum := sha256.Sum256(point)
			if !bytes.Equal(cert.SubjectKeyId, sum[:20]) {
				t.Errorf("subject key identifier = %x, want %x", cert.SubjectKeyId, sum[:20])
			}
			if id, err := pki.KeyIdentifier(pub); err != nil || !bytes.Equal(id, cert.SubjectKeyId) {
				t.Errorf("KeyIdentifier = %x, %v; the certificate has %x", id, err, cert.SubjectKeyId)
			}
			if len(cert.AuthorityKeyId) != 0 || extensionOf(cert, oidAuthorityKeyID) != nil {
				t.Error("an authority key identifier is present")
			}
			if extensionOf(cert, oidNameConstraints) != nil || len(cert.PermittedDNSDomains) != 0 {
				t.Error("name constraints are present")
			}
			// The digests are those of the body.
			if got, want := pki.TBSSHA256(r.tbs), sha256.Sum256(cert.RawTBSCertificate); got != hex.EncodeToString(want[:]) {
				t.Errorf("TBSSHA256 = %s, want %x", got, want)
			}
			if got, want := pki.TBSDigest(r.tbs), sha512.Sum384(cert.RawTBSCertificate); !bytes.Equal(got, want[:]) {
				t.Errorf("TBSDigest = %x, want %x", got, want)
			}
			// Go accepts it as the only root at the ceremony time and a day.
			pool := x509.NewCertPool()
			pool.AddCert(cert)
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: c.starts.Add(24 * time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Errorf("x509 Verify: %v", err)
			}
			// The same parameters again give the same bytes.
			again, err := pki.RootTBS(r.params)
			if err != nil || !bytes.Equal(again, r.tbs) {
				t.Errorf("the same parameters give %x, %v", again, err)
			}
		})
	}
}

// The structure of the root of the hand-off vectors, read through the manifest: the same extension
// identifiers in the same order with the same flags, the same signature algorithm, and the same
// number of months of validity.
func TestRootStructureAgainstVector(t *testing.T) {
	vec := vectorRootCertificate(t)
	r := buildRoot(t, nil)
	if got, want := strings.Join(extensionIDs(r.parsed), ","), strings.Join(extensionIDs(vec), ","); got != want {
		t.Errorf("extensions = %s, the vector has %s", got, want)
	}
	for i, e := range vec.Extensions {
		if i < len(r.parsed.Extensions) && r.parsed.Extensions[i].Critical != e.Critical {
			t.Errorf("extension %s critical = %v, the vector has %v", e.Id, r.parsed.Extensions[i].Critical, e.Critical)
		}
		if i < len(r.parsed.Extensions) && e.Id.Equal(oidBasicConstraints) && !bytes.Equal(r.parsed.Extensions[i].Value, e.Value) {
			t.Errorf("basic constraints = %x, the vector has %x", r.parsed.Extensions[i].Value, e.Value)
		}
		if i < len(r.parsed.Extensions) && e.Id.Equal(oidKeyUsage) && !bytes.Equal(r.parsed.Extensions[i].Value, e.Value) {
			t.Errorf("key usage = %x, the vector has %x", r.parsed.Extensions[i].Value, e.Value)
		}
	}
	if r.parsed.SignatureAlgorithm != vec.SignatureAlgorithm || r.parsed.Version != vec.Version {
		t.Errorf("algorithm %v version %d, the vector has %v and %d", r.parsed.SignatureAlgorithm, r.parsed.Version, vec.SignatureAlgorithm, vec.Version)
	}
	if got, want := monthsBetween(r.parsed.NotBefore, r.parsed.NotAfter), monthsBetween(vec.NotBefore, vec.NotAfter); got != want {
		t.Errorf("validity = %d months, the vector has %d", got, want)
	}
	if !bytes.Equal(r.parsed.RawIssuer, r.parsed.RawSubject) || !bytes.Equal(vec.RawIssuer, vec.RawSubject) {
		t.Error("issuer and subject are not the same bytes")
	}
	// The vector's name is one common name, as UTF8String: the same shape as ours.
	if len(vec.Subject.Names) != len(r.parsed.Subject.Names) || vec.RawSubject[0] != r.parsed.RawSubject[0] {
		t.Errorf("the name has another shape: %d attributes, the vector has %d", len(r.parsed.Subject.Names), len(vec.Subject.Names))
	}
	if !strings.HasSuffix(vec.Subject.CommonName, " (TEST ONLY)") || !strings.HasSuffix(r.parsed.Subject.CommonName, " (TEST ONLY)") {
		t.Errorf("a test root's name ends %q, the vector's %q", r.parsed.Subject.CommonName, vec.Subject.CommonName)
	}
}

func monthsBetween(a, b time.Time) int {
	return (b.Year()-a.Year())*12 + int(b.Month()) - int(a.Month())
}

// vectorRootCertificate is the first X.509 root of the root list of the hand-off set, found through
// its manifest.
func vectorRootCertificate(t testing.TB) *x509.Certificate {
	t.Helper()
	var m struct {
		Pinned struct {
			RootList struct {
				X509 []string `json:"x509"`
			} `json:"root_list"`
		} `json:"pinned"`
	}
	if err := json.Unmarshal(testrepo.Read(t, "testdata", "hand-off", "v1", "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Pinned.RootList.X509) == 0 {
		t.Fatal("the hand-off manifest names no root")
	}
	cert, err := x509.ParseCertificate(pemBlock(t, testrepo.Read(t, "testdata", "hand-off", "v1", m.Pinned.RootList.X509[0]), "CERTIFICATE"))
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
