package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/openpgp"
)

// A trust set made in memory: each root key has a self-signed X.509 root certificate (P-384) and an OpenPGP primary
// that openpgp.NewPrimary writes. The keys are made when a test runs. The test trust set of the vectors has two
// primaries; a test that needs another size, a creation time after the clock or a user ID of the real kind (no test
// mark) makes its set here. The requests of the vectors are not signed by these roots, so a run that reaches the
// checks refuses or does not accept them; the tests use these sets for what the command does before any check.

type memRoot struct {
	label string
	cert  []byte // the OpenPGP certificate
	fp    string
	der   []byte // the X.509 root certificate
	pin   string
}

// memCreated is a creation time well before the clock of the vectors.
var memCreated = time.Date(2026, time.March, 1, 9, 30, 0, 0, time.UTC)

func newMemRoot(t testing.TB, label string, created time.Time, test bool) memRoot {
	t.Helper()
	pgpKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := openpgp.UserID("Example Test", label, "release@example.org", test)
	if err != nil {
		t.Fatal(err)
	}
	ceremony := created.Add(time.Hour)
	cert, err := openpgp.NewPrimary(rand.Reader, openpgp.PrimaryParams{
		Key: pgpKey, CreationTime: created, CeremonyTime: ceremony, ExpiresAt: ceremony.AddDate(3, 0, 0), UserID: uid,
	})
	if err != nil {
		t.Fatal(err)
	}
	fp, err := openpgp.Fingerprint(&pgpKey.PublicKey, created)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Test Root " + label + " (TEST ONLY)"},
		NotBefore: clock.Add(-time.Hour), NotAfter: clock.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &xKey.PublicKey, xKey)
	if err != nil {
		t.Fatal(err)
	}
	cx, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return memRoot{label: label, cert: cert, fp: fp, der: der, pin: jws.Pin(cx)}
}

// memTrustOf is the files of the trust set of sequence 7 for the roots in the order given: the list, the CA bundle
// and the keyring file of all of them.
func memTrustOf(roots []memRoot) crqTree {
	at := "trust/" + crqTrustSet + "/"
	var list strings.Builder
	list.WriteString(`{"expires_at":"2027-12-15T12:00:00Z","last_record_sha256":"` + strings.Repeat("ab", 32) + `","roots":[`)
	pemData := []byte("# trust-sequence: 7\n")
	var keyring []byte
	for i, r := range roots {
		if i > 0 {
			list.WriteString(",")
		}
		list.WriteString(`{"label":"` + r.label + `","openpgp_fingerprint":"` + r.fp + `","x509_spki_sha256":"` + r.pin + `"}`)
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der})...)
		keyring = append(keyring, r.cert...)
	}
	list.WriteString(`],"sequence":` + strconv.Itoa(7) + `,"signed_at":"2026-11-15T12:00:00Z","version":1}`)
	return crqTree{at + "root-list.json": []byte(list.String()), at + "ca-bundle.pem": pemData, at + crqKeyringFile: keyring}
}

func memRoots(t testing.TB, n int) []memRoot {
	t.Helper()
	out := make([]memRoot, n)
	for i := range out {
		out[i] = newMemRoot(t, string(rune('A'+i)), memCreated, true)
	}
	return out
}
