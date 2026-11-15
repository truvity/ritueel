//go:build linux || darwin

package ceremony_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/trustset"
)

// Edges of the profile that the table of breaks does not reach.

func TestASubjectThatHoldsMoreThanOneCommonNameIsRefused(t *testing.T) {
	cn := "Example Root A (TEST ONLY)"
	oidCN := []byte{0x06, 0x03, 0x55, 0x04, 0x03}
	oidO := []byte{0x06, 0x03, 0x55, 0x04, 0x0a}
	utf := func(s string) []byte { return mkDER(0x0c, []byte(s)) }
	names := map[string][]byte{
		"two attributes in one set":   mkSeq(mkSet(mkSeq(oidCN, utf(cn)), mkSeq(oidO, utf("Example")))),
		"two sets of one attribute":   mkSeq(mkSet(mkSeq(oidCN, utf(cn))), mkSet(mkSeq(oidO, utf("Example")))),
		"an organisation, no CN":      mkSeq(mkSet(mkSeq(oidO, utf(cn)))),
		"the name twice":              mkSeq(mkSet(mkSeq(oidCN, utf(cn))), mkSet(mkSeq(oidCN, utf(cn)))),
		"an empty name":               mkSeq(),
		"a common name that is empty": mkSeq(mkSet(mkSeq(oidCN, utf("")))),
	}
	for name, subject := range names {
		t.Run(name, func(t *testing.T) {
			c := mkGoodCert()
			der := mkCertWithName(c, subject)
			mkWantArtifactError(t, ceremony.CheckRootCertificate(der, c.Want), "root certificate A", "subject")
		})
	}
}

// mkCertWithName writes the certificate of a good one again with the given name as issuer and
// subject, signed by the key.
func mkCertWithName(c mkCert, name []byte) []byte {
	spki, err := x509.MarshalPKIXPublicKey(&c.Key.PublicKey)
	if err != nil {
		panic(err)
	}
	exts := [][]byte{
		mkExt(mkOIDBasic, true, mkSeq(mkBool(true))),
		mkExt(mkOIDSKI, false, mkOctet(mkSKI(&c.Key.PublicKey))),
		mkExt(mkOIDUsage, true, []byte{0x03, 0x02, 0x01, 0x06}),
	}
	tbs := mkSeq(
		mkDER(0xa0, mkInt(bigInt(2))), mkInt(mkSerial(1)), mkSeq(mkOID(mkOIDSHA384)), name,
		mkSeq(mkUTC(c.Want.NotBefore), mkUTC(c.Want.NotAfter)), name, spki, mkDER(0xa3, mkSeq(exts...)),
	)
	return mkSign(tbs, c.Key)
}

func TestTheTimeTypeFollowsTheYearOfEachTime(t *testing.T) {
	// RFC 5280, 4.1.2.5: UTCTime up to the year 2049, GeneralizedTime from 2050, for each of the
	// two times of a validity.
	for _, tc := range []struct {
		name       string
		nb         time.Time
		nbGT, naGT bool
		ok         bool
		member     string
	}{
		{"both in UTCTime, the last second of 2049 to 2052", time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), false, true, true, ""},
		{"notBefore on the last second of 2049 as GeneralizedTime", time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), true, true, false, "notBefore"},
		{"notBefore on the first second of 2050 as UTCTime", time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), false, true, false, "notBefore"},
		{"notBefore on the first second of 2050 as GeneralizedTime", time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), true, true, true, ""},
		{"notAfter in 2049 as UTCTime", time.Date(2046, 6, 1, 0, 0, 0, 0, time.UTC), false, false, true, ""},
		{"notAfter in 2049 as GeneralizedTime", time.Date(2046, 6, 1, 0, 0, 0, 0, time.UTC), false, true, false, "notAfter"},
		{"notAfter on the first second of 2050 as UTCTime", time.Date(2047, 1, 1, 0, 0, 0, 0, time.UTC), false, false, false, "notAfter"},
		{"notBefore in 1949 as GeneralizedTime", time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC), true, false, true, ""},
		{"notBefore in 1949 as UTCTime", time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC), false, false, false, "notBefore"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := mkCertSpec{NotBefore: tc.nb, NotBeforeGT: tc.nbGT, NotAfterGT: tc.naGT}.build()
			err := ceremony.CheckRootCertificate(c.DER, c.Want)
			if tc.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			mkWantArtifactError(t, err, "root certificate A", tc.member)
		})
	}
}

func TestAP256KeyWhosePinIsTheWantedPinIsStillRefused(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	c := mkCertSpec{SPKI: spki}.build()
	w := c.Want
	w.Pin = mkPin(&p256.PublicKey)
	mkWantArtifactError(t, ceremony.CheckRootCertificate(c.DER, w), "root certificate A", "public key")
}

func TestAListThatNamesAnOpenPGPFingerprintIsNotTheListOfAnX509OnlyRoot(t *testing.T) {
	keys := mkRootKeys("A", "B")
	var roots []trustset.Root
	certs := map[string][]byte{}
	for i, k := range keys {
		r := trustset.Root{Label: k.Label, X509SPKISHA256: k.Pin}
		r.OpenPGPFingerprint = strings.Repeat(string(rune('a'+i)), 40)
		roots = append(roots, r)
		certs[k.Label] = k.Cert.DER
	}
	d, err := trustset.NewDraft(trustset.Input{Sequence: 1, SignedAt: pfClock, Roots: roots, Certificates: certs})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(keys[0].Cert.DER)
	if err != nil {
		t.Fatal(err)
	}
	sg, err := trustset.NewKeySigner("A", cert, keys[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	set, err := d.Sign([]trustset.Signer{sg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ceremony.CheckRootList(set, mkWantFor(keys, "A"))
	mkWantArtifactError(t, err, "root list", "roots")
}

func TestATimeThatIsNotInTheFormOfRFC5280IsRefused(t *testing.T) {
	// RFC 5280, 4.1.2.5.1: a UTCTime is in Greenwich Mean Time, written with a Z, and with seconds
	// even when they are zero (YYMMDDHHMMSSZ). The page says that both times are UTC. The standard
	// library reads the other spellings of the same instant, so a check that reads the times only
	// as instants does not see them; the certificate is not the one that the profile describes.
	for name, raw := range map[string][]byte{
		"without seconds":     mkDER(0x17, []byte("2611201000Z")),
		"with an offset":      mkDER(0x17, []byte("261120"+"110000+0100")),
		"with a minus offset": mkDER(0x17, []byte("261120"+"090000-0100")),
	} {
		t.Run("notBefore "+name, func(t *testing.T) {
			c := mkCertSpec{NotBeforeDER: raw}.build()
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatal("a certificate with a time that is not in the form of RFC 5280 is accepted")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"without seconds": mkDER(0x17, []byte("2911201000Z")),
		"with an offset":  mkDER(0x17, []byte("291120"+"110000+0100")),
	} {
		t.Run("notAfter "+name, func(t *testing.T) {
			c := mkCertSpec{}.buildWithNotAfterDER(raw)
			if err := ceremony.CheckRootCertificate(c.DER, c.Want); err == nil {
				t.Fatal("a certificate with a time that is not in the form of RFC 5280 is accepted")
			}
		})
	}
}
