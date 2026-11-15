//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"regexp"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/pki"
)

// The root certificate of a first apply is judged by CheckRootCertificate against the profile of
// docs/reference/bundle.md, "The root certificate", with code that did not write it. The
// certificates here are written by hand (rootcert_helpers_test.go), one member at a time.

var hexRun = regexp.MustCompile(`[0-9a-f]{40,}`)

func TestAGoodCertificateIsAccepted(t *testing.T) {
	c := mkGoodCert()
	if err := ceremony.CheckRootCertificate(c.DER, c.Want); err != nil {
		t.Fatalf("a certificate of the profile is refused: %v", err)
	}
}

func TestTheBodyWrittenByHandIsTheBodyOfPki(t *testing.T) {
	// The page and the code that builds the profile agree byte for byte, for a fixed key and serial.
	c := mkGoodCert()
	body, err := pki.RootTBS(pki.RootParams{Name: "Example", Label: "A", Test: true, CeremonyTime: pfClock, Key: &c.Key.PublicKey, Serial: mkSerial(1)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, c.TBS) {
		t.Fatalf("the body written by hand and the body of internal/pki differ:\nhand %x\npki  %x", c.TBS, body)
	}
}

func TestACertificateIsGoodForEveryLabelAndNameThePageAllows(t *testing.T) {
	for _, tc := range []struct{ name, label string }{
		{"Example", "A"}, {"Example", "B"}, {"Example", "Z"}, {"a", "C"}, {"Example Test 2-x", "D"},
		{strings.Repeat("N", 45), "A"},
	} {
		c := mkCertSpec{Name: tc.name, Label: tc.label}.build()
		if err := ceremony.CheckRootCertificate(c.DER, c.Want); err != nil {
			t.Errorf("name %q label %s: %v", tc.name, tc.label, err)
		}
	}
}

// refused is one certificate that breaks one row of the profile, and the member that the error names.
type refused struct {
	name   string
	spec   mkCertSpec
	member string
	// reason, when it is not empty, is a text that the reason of the error holds.
	reason string
	// change edits the facts that the check is given, after the certificate is built.
	change func(w *ceremony.RootCertWant, c mkCert)
}

func controls() []refused {
	other := mkKeyP384()
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	p256SPKI, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		panic(err)
	}
	k := mkKeyP384()
	basic := func(critical bool, body []byte) []byte { return mkExt(mkOIDBasic, critical, body) }
	ski := func(key *ecdsa.PrivateKey) []byte { return mkExt(mkOIDSKI, false, mkOctet(mkSKI(&key.PublicKey))) }
	usage := func(critical bool, bits []byte) []byte { return mkExt(mkOIDUsage, critical, bits) }
	std := func(key *ecdsa.PrivateKey) [][]byte {
		return [][]byte{basic(true, mkSeq(mkBool(true))), ski(key), usage(true, []byte{0x03, 0x02, 0x01, 0x06})}
	}
	with := func(i int, e []byte) [][]byte { x := std(k); x[i] = e; return x }
	nb := pfClock
	return []refused{
		{name: "the common name without TEST ONLY", spec: mkCertSpec{Production: true}, member: "subject"},
		{name: "the common name with the mark in lower case", spec: mkCertSpec{CN: "Example Root A (test only)"}, member: "subject"},
		{name: "the mark without the space", spec: mkCertSpec{CN: "Example Root A(TEST ONLY)"}, member: "subject"},
		{name: "another label in the name", spec: mkCertSpec{CN: "Example Root B (TEST ONLY)"}, member: "subject"},
		{name: "another name", spec: mkCertSpec{CN: "Other Root A (TEST ONLY)"}, member: "subject"},
		{name: "a trailing space in the name", spec: mkCertSpec{CN: "Example Root A (TEST ONLY) "}, member: "subject"},
		{name: "an empty name in the facts", spec: mkCertSpec{}, member: "subject", change: func(w *ceremony.RootCertWant, _ mkCert) { w.Name = "" }},
		{name: "a name in another script", spec: mkCertSpec{CN: "Ex\u00e9 Root A (TEST ONLY)"}, member: "subject"},
		{name: "issuer not equal to subject", spec: mkCertSpec{IssuerCN: "Example Root B (TEST ONLY)"}, member: "issuer"},
		{name: "not a CA", spec: mkCertSpec{Exts: with(0, basic(true, mkSeq()))}, member: "basic constraints"},
		{name: "cA written false", spec: mkCertSpec{Exts: with(0, basic(true, mkSeq(mkBool(false))))}, member: "basic constraints"},
		{name: "cA not critical", spec: mkCertSpec{Exts: with(0, basic(false, mkSeq(mkBool(true))))}, member: "basic constraints"},
		{name: "a path length of zero", spec: mkCertSpec{Exts: with(0, basic(true, mkSeq(mkBool(true), mkInt(big.NewInt(0)))))}, member: "basic constraints"},
		{name: "a path length of one", spec: mkCertSpec{Exts: with(0, basic(true, mkSeq(mkBool(true), mkInt(big.NewInt(1)))))}, member: "basic constraints"},
		{name: "key usage without cRLSign", spec: mkCertSpec{Key: k, Exts: with(2, usage(true, []byte{0x03, 0x02, 0x02, 0x04}))}, member: "key usage"},
		{name: "key usage without keyCertSign", spec: mkCertSpec{Key: k, Exts: with(2, usage(true, []byte{0x03, 0x02, 0x01, 0x02}))}, member: "key usage"},
		{name: "key usage with digitalSignature", spec: mkCertSpec{Key: k, Exts: with(2, usage(true, []byte{0x03, 0x02, 0x01, 0x86}))}, member: "key usage"},
		{name: "key usage written with a trailing zero byte (not the shortest form)", spec: mkCertSpec{Key: k, Exts: with(2, usage(true, []byte{0x03, 0x03, 0x00, 0x06, 0x00}))}, member: "key usage"},
		{name: "key usage not critical", spec: mkCertSpec{Key: k, Exts: with(2, usage(false, []byte{0x03, 0x02, 0x01, 0x06}))}, member: "key usage"},
		{name: "subject key identifier critical (the standard library refuses it)", spec: mkCertSpec{Key: k, Exts: with(1, mkExt(mkOIDSKI, true, mkOctet(mkSKI(&k.PublicKey))))}, member: "certificate"},
		{name: "subject key identifier of another key", spec: mkCertSpec{Key: k, Exts: with(1, ski(other))}, member: "subject key identifier"},
		{name: "subject key identifier of 19 bytes", spec: mkCertSpec{Key: k, Exts: with(1, mkExt(mkOIDSKI, false, mkOctet(mkSKI(&k.PublicKey)[:19])))}, member: "subject key identifier"},
		{name: "an extra extension", spec: mkCertSpec{Key: k, Exts: append(std(k), mkExt(mkOIDEKU, false, mkSeq()))}, member: "extensions"},
		{name: "an authority key identifier", spec: mkCertSpec{Key: k, Exts: append(std(k), mkExt(mkOIDAKI, false, mkSeq(mkDER(0x80, mkSKI(&k.PublicKey)))))}, member: "extensions", reason: "authority key identifier"},
		{name: "name constraints", spec: mkCertSpec{Key: k, Exts: append(std(k), mkExt(mkOIDNC, true, mkSeq(mkDER(0xa0, mkSeq(mkSeq(mkDER(0x82, []byte("example.org"))))))))}, member: "extensions", reason: "name constraints"},
		{name: "an explicit FALSE for critical, which DER leaves out", spec: mkCertSpec{Key: k, Exts: with(1, mkSeq(mkOID(mkOIDSKI), mkBool(false), mkOctet(mkOctet(mkSKI(&k.PublicKey)))))}, member: "tbsCertificate"},
		{name: "extensions in another order (usage first)", spec: mkCertSpec{Key: k, Exts: [][]byte{std(k)[2], std(k)[0], std(k)[1]}}, member: "extensions"},
		{name: "extensions in another order (ski first)", spec: mkCertSpec{Key: k, Exts: [][]byte{std(k)[1], std(k)[0], std(k)[2]}}, member: "extensions"},
		{name: "two extensions only", spec: mkCertSpec{Key: k, Exts: std(k)[:2]}, member: "extensions"},
		{name: "no extensions", spec: mkCertSpec{NoExts: true}, member: "extensions"},
		{name: "a validity of 35 months", spec: mkCertSpec{NotAfter: mkAddMonths(nb, 35)}, member: "notAfter", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotAfter = mkAddMonths(nb, 35) }},
		{name: "a validity of 37 months", spec: mkCertSpec{NotAfter: mkAddMonths(nb, 37)}, member: "notAfter", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotAfter = mkAddMonths(nb, 37) }},
		{name: "a validity of 36 months less a second", spec: mkCertSpec{NotAfter: mkAddMonths(nb, 36).Add(-time.Second)}, member: "notAfter", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotAfter = mkAddMonths(nb, 36).Add(-time.Second) }},
		{name: "a validity of 1095 days", spec: mkCertSpec{NotAfter: nb.AddDate(0, 0, 1095)}, member: "notAfter", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotAfter = nb.AddDate(0, 0, 1095) }},
		{name: "notBefore one second late", spec: mkCertSpec{NotBefore: nb.Add(time.Second)}, member: "notBefore", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotBefore = nb }},
		{name: "notBefore one second early", spec: mkCertSpec{NotBefore: nb.Add(-time.Second)}, member: "notBefore", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotBefore = nb }},
		{name: "a good certificate with a plan that names another end", spec: mkCertSpec{}, member: "notAfter", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotAfter = w.NotAfter.Add(time.Second) }},
		{name: "a good certificate with a plan that names another start", spec: mkCertSpec{}, member: "notBefore", change: func(w *ceremony.RootCertWant, c mkCert) { w.NotBefore = w.NotBefore.Add(-time.Hour) }},
		{name: "notBefore as GeneralizedTime in 2026", spec: mkCertSpec{NotBeforeGT: true}, member: "notBefore"},
		{name: "notAfter as GeneralizedTime in 2029", spec: mkCertSpec{NotAfterGT: true}, member: "notAfter"},
		{name: "another serial", spec: mkCertSpec{Serial: mkSerial(9)}, member: "serial", change: func(w *ceremony.RootCertWant, c mkCert) { w.Serial = mkSerial(1).Text(16) }},
		{name: "the serial of the plan in upper case", spec: mkCertSpec{}, member: "", change: func(w *ceremony.RootCertWant, c mkCert) { w.Serial = strings.ToUpper(w.Serial) }},
		{name: "a plan serial that is not a number", spec: mkCertSpec{}, member: "serial", change: func(w *ceremony.RootCertWant, c mkCert) { w.Serial = "zz" }},
		{name: "a plan serial that is empty", spec: mkCertSpec{}, member: "serial", change: func(w *ceremony.RootCertWant, c mkCert) { w.Serial = "" }},
		{name: "a plan serial of zero", spec: mkCertSpec{Serial: big.NewInt(0)}, member: "serial", change: func(w *ceremony.RootCertWant, c mkCert) { w.Serial = "0" }},
		{name: "a plan serial that is negative", spec: mkCertSpec{}, member: "serial", change: func(w *ceremony.RootCertWant, c mkCert) { w.Serial = "-1" + w.Serial }},
		{name: "a P-256 key", spec: mkCertSpec{SPKI: p256SPKI}, member: "public key"},
		{name: "a key that is not the born key", spec: mkCertSpec{}, member: "public key", change: func(w *ceremony.RootCertWant, c mkCert) { w.Pin = mkPin(&other.PublicKey) }},
		{name: "a pin that is not a pin", spec: mkCertSpec{}, member: "public key", change: func(w *ceremony.RootCertWant, c mkCert) { w.Pin = "abc" }},
		{name: "a pin in upper case", spec: mkCertSpec{}, member: "public key", change: func(w *ceremony.RootCertWant, c mkCert) { w.Pin = strings.ToUpper(w.Pin) }},
		{name: "a signature by another key", spec: mkCertSpec{SignKey: other}, member: "signature"},
		{name: "a trailing byte after the DER", spec: mkCertSpec{Trailing: []byte{0}}, member: "certificate"},
		{name: "a trailing newline after the DER", spec: mkCertSpec{Trailing: []byte{'\n'}}, member: "certificate"},
		{name: "version 1", spec: mkCertSpec{Version: -1}, member: "version"},
		{name: "version 2", spec: mkCertSpec{Version: 1}, member: "version"},
		{name: "unique identifiers", spec: mkCertSpec{UniqueIDs: true}, member: "unique identifiers"},
		{name: "the SHA-256 algorithm", spec: mkCertSpec{SigAlg: mkOIDSHA256}, member: "signature algorithm"},
		{name: "two algorithms that differ (the standard library refuses it)", spec: mkCertSpec{OuterAlg: mkOIDSHA256}, member: "certificate"},
		{name: "a parameter on the algorithm (the standard library refuses it)", spec: mkCertSpec{SigParams: true}, member: "certificate"},
	}
}

func TestEveryBreakOfTheProfileIsRefusedWithTheMemberNamed(t *testing.T) {
	for _, tc := range controls() {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.spec.build()
			w := c.Want
			if tc.change != nil {
				tc.change(&w, c)
			}
			err := ceremony.CheckRootCertificate(c.DER, w)
			if tc.member == "" {
				// The serial of the plan in upper case is the same number: accepted.
				if err != nil {
					t.Fatalf("a serial in upper case is the same number, and is refused: %v", err)
				}
				return
			}
			mkWantArtifactError(t, err, "root certificate A", tc.member)
			if ae, _ := mkAs[*ceremony.ArtifactError](err); tc.reason != "" && !strings.Contains(ae.Reason, tc.reason) {
				t.Errorf("the reason %q does not say %q", ae.Reason, tc.reason)
			}
			if hexRun.MatchString(err.Error()) {
				t.Errorf("the error shows a digest or a key: %v", err)
			}
		})
	}
}

func TestAnUnparseableOrOversizeCertificateIsRefused(t *testing.T) {
	c := mkGoodCert()
	for name, der := range map[string][]byte{
		"nil":               nil,
		"empty":             {},
		"one byte":          {0x30},
		"a truncated body":  c.DER[:len(c.DER)-1],
		"a short body":      c.DER[:len(c.DER)/2],
		"text":              []byte("-----BEGIN CERTIFICATE-----"),
		"all zero":          make([]byte, 600),
		"over the limit":    append(append([]byte{}, c.DER...), make([]byte, 16<<10)...),
		"a PEM block":       []byte("-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"),
		"an indefinite len": {0x30, 0x80, 0x00, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			err := ceremony.CheckRootCertificate(der, c.Want)
			mkWantArtifactError(t, err, "root certificate A", "certificate")
			if name == "over the limit" {
				if ae, _ := mkAs[*ceremony.ArtifactError](err); !strings.Contains(ae.Reason, "longer than") {
					t.Errorf("the reason %q does not say that the certificate is too long", ae.Reason)
				}
			}
		})
	}
}

func TestAnErrorOfTheCheckIsPrintableAsciiAndNamesNoKey(t *testing.T) {
	c := mkCertSpec{CN: "Ex\u00e9\x1b[31m Root A (TEST ONLY)"}.build()
	err := ceremony.CheckRootCertificate(c.DER, c.Want)
	if err == nil {
		t.Fatal("a name in another script is accepted")
	}
	if !pfPrintable(err.Error()) {
		t.Errorf("the text %+q is not printable ASCII", err.Error())
	}
	var ae *ceremony.ArtifactError
	if !errorsAs(err, &ae) || ae.Artifact == "" || ae.Reason == "" {
		t.Errorf("the error is %T: %v", err, err)
	}
}

func TestACertificateIsCheckedForTheLabelOfItsKeyAndNoOther(t *testing.T) {
	a := mkCertSpec{Label: "A"}.build()
	b := mkCertSpec{Label: "B"}.build()
	// The certificate of A is not the certificate of B, and B is not A.
	wb := b.Want
	if err := ceremony.CheckRootCertificate(a.DER, wb); err == nil {
		t.Error("the certificate of A is accepted for B")
	}
	wa := a.Want
	wa.Pin = b.Want.Pin
	if err := ceremony.CheckRootCertificate(a.DER, wa); err == nil {
		t.Error("the certificate of A is accepted with the pin of B")
	}
}

func TestTheMonthsOfTheValidityFollowThePage(t *testing.T) {
	// "36 calendar months later (same day and time of the month, or the last day of the month if it
	// has none)", for the days of the month where the rule shows.
	for _, tc := range []struct {
		from time.Time
		to   time.Time
	}{
		{time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC), time.Date(2029, 11, 20, 10, 0, 0, 0, time.UTC)},
		{time.Date(2028, 2, 29, 23, 59, 59, 0, time.UTC), time.Date(2031, 2, 28, 23, 59, 59, 0, time.UTC)},
		{time.Date(2025, 2, 28, 0, 0, 0, 0, time.UTC), time.Date(2028, 2, 28, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 5, 31, 12, 30, 15, 0, time.UTC), time.Date(2029, 5, 31, 12, 30, 15, 0, time.UTC)},
		{time.Date(2024, 2, 29, 1, 2, 3, 0, time.UTC), time.Date(2027, 2, 28, 1, 2, 3, 0, time.UTC)},
		{time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC), time.Date(2029, 12, 31, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC)},
	} {
		c := mkCertSpec{NotBefore: tc.from, NotAfter: tc.to}.build()
		if err := ceremony.CheckRootCertificate(c.DER, c.Want); err != nil {
			t.Errorf("%s to %s: %v", tc.from, tc.to, err)
		}
		// One day either way is refused.
		for _, d := range []int{-1, 1} {
			bad := mkCertSpec{NotBefore: tc.from, NotAfter: tc.to.AddDate(0, 0, d)}.build()
			if err := ceremony.CheckRootCertificate(bad.DER, bad.Want); err == nil {
				t.Errorf("%s to %s%+d days is accepted", tc.from, tc.to, d)
			}
		}
	}
}

func TestAValidityThatLeavesTheYearsOfUTCTimeUsesGeneralizedTime(t *testing.T) {
	// RFC 5280, 4.1.2.5: UTCTime to the year 2049, GeneralizedTime from 2050. A notAfter in 2051
	// written as GeneralizedTime is right, and a UTCTime there is not.
	nb := time.Date(2048, 6, 1, 0, 0, 0, 0, time.UTC)
	na := mkAddMonths(nb, 36)
	good := mkCertSpec{NotBefore: nb, NotAfter: na, NotAfterGT: true}.build()
	if err := ceremony.CheckRootCertificate(good.DER, good.Want); err != nil {
		t.Fatalf("a notAfter of 2051 in GeneralizedTime is refused: %v", err)
	}
	bad := mkCertSpec{NotBefore: nb, NotAfter: na}.build()
	mkWantArtifactError(t, ceremony.CheckRootCertificate(bad.DER, bad.Want), "root certificate A", "notAfter")
	// A year before 2050 in GeneralizedTime is not right either, and that is the case 2026 above.
}

func TestACertificateKeyCanBeAnyP384KeyAndTheSerialAnyPositiveNumber(t *testing.T) {
	for _, s := range []*big.Int{big.NewInt(1), mkSerial(3), new(big.Int).Lsh(big.NewInt(1), 159)} {
		c := mkCertSpec{Serial: s}.build()
		if err := ceremony.CheckRootCertificate(c.DER, c.Want); err != nil {
			t.Errorf("serial %x: %v", s, err)
		}
	}
}
