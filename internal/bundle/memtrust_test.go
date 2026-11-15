package bundle_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/openpgp"
)

// Trust sets made in memory: each root key has an X.509 root certificate (self-signed, P-384) and an OpenPGP primary
// (a certificate that openpgp.NewPrimary writes). The keys are made when a test runs and thrown away with it. The
// test sets of the vectors have two primaries; a test that needs a set of another size, a creation time after the
// clock or a user ID of the real kind (no test mark) makes it here.

// memPrimary is one root key of an in-memory trust set.
type memPrimary struct {
	label   string
	created time.Time
	cert    []byte // the OpenPGP certificate: key packet, user ID, one certification
	fp      string // the fingerprint of the primary
	der     []byte // the X.509 root certificate
	pin     string // the pin of its key in the root list
}

// memTime is a creation time well before the clock of the vectors.
var memTime = time.Date(2026, time.March, 1, 9, 30, 0, 0, time.UTC)

// newMemPrimary makes the root key of a label. created is the creation time of its primary; test says whether its
// user ID carries the mark of a test root.
func newMemPrimary(t testing.TB, label string, created time.Time, test bool) memPrimary {
	t.Helper()
	pgpKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := openpgp.UserID("Example Test", label, "release@example.org", test)
	if err != nil {
		t.Fatalf("UserID: %v", err)
	}
	ceremony := created.Add(time.Hour)
	cert, err := openpgp.NewPrimary(rand.Reader, openpgp.PrimaryParams{
		Key: pgpKey, CreationTime: created, CeremonyTime: ceremony, ExpiresAt: ceremony.AddDate(3, 0, 0), UserID: uid,
	})
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	fp, err := openpgp.Fingerprint(&pgpKey.PublicKey, created)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example Test Root " + label + " (TEST ONLY)"},
		NotBefore: vectorNow.Add(-time.Hour), NotAfter: vectorNow.Add(24 * time.Hour),
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
	return memPrimary{label: label, created: created, cert: cert, fp: fp, der: der, pin: jws.Pin(cx)}
}

// memPrimaries makes primaries with the labels A, B, C and so on, all created at memTime, with test user IDs.
func memPrimaries(t testing.TB, n int) []memPrimary {
	t.Helper()
	out := make([]memPrimary, n)
	for i := range out {
		out[i] = newMemPrimary(t, string(rune('A'+i)), memTime, true)
	}
	return out
}

// memList is the text of a root list of sequence n that holds the roots in the order given, each with its
// fingerprint unless noPrint says that its label has none.
func memList(n int, roots []memPrimary, noPrint map[string]bool) []byte {
	var b strings.Builder
	b.WriteString(`{"expires_at":"2027-12-15T12:00:00Z","last_record_sha256":"` + strings.Repeat("ab", 32) + `","roots":[`)
	for i, r := range roots {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"label":"` + r.label + `",`)
		if !noPrint[r.label] {
			b.WriteString(`"openpgp_fingerprint":"` + r.fp + `",`)
		}
		b.WriteString(`"x509_spki_sha256":"` + r.pin + `"}`)
	}
	b.WriteString(`],"sequence":` + strconv.Itoa(n) + `,"signed_at":"2026-11-15T12:00:00Z","version":1}`)
	return []byte(b.String())
}

// memBundlePEM is the CA bundle of a list of sequence n: the first line and the certificates in the order given.
func memBundlePEM(n int, roots []memPrimary) []byte {
	out := []byte(header(n))
	for _, r := range roots {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der})...)
	}
	return out
}

// memKeyring is the keyring file of the roots, in the order given: their certificates joined.
func memKeyring(roots []memPrimary) []byte {
	var out []byte
	for _, r := range roots {
		out = append(out, r.cert...)
	}
	return out
}

// memSet is the files of a trust set of sequence n for the roots in the order given, with the keyring file of all of
// them.
func memSet(n int, roots []memPrimary) tree {
	return tree{"root-list.json": memList(n, roots, nil), "ca-bundle.pem": memBundlePEM(n, roots), keyringName: memKeyring(roots)}
}

// ringRefs are the primaries of a keyring file as a second reader gives them: go-crypto reads the file, and the
// fingerprint, the key and the creation time of each primary are taken from its key packet. The reader of the
// program (package openpgp) is not used.
func ringRefs(t testing.TB, file []byte) []handoff.PrimaryRef {
	t.Helper()
	ring, err := pgp.ReadKeyRing(strings.NewReader(string(file)))
	if err != nil || len(ring) == 0 {
		t.Fatalf("go-crypto cannot read the keyring file: %v", err)
	}
	var out []handoff.PrimaryRef
	for _, e := range ring {
		pub, ok := e.PrimaryKey.PublicKey.(*pgpecdsa.PublicKey)
		if !ok {
			t.Fatalf("go-crypto reads a key of type %T", e.PrimaryKey.PublicKey)
		}
		pt := make([]byte, 97)
		pt[0] = 4
		pub.X.FillBytes(pt[1:49])
		pub.Y.FillBytes(pt[49:])
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pt)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, handoff.PrimaryRef{Fingerprint: hex.EncodeToString(e.PrimaryKey.Fingerprint), Key: key, Created: e.PrimaryKey.CreationTime.UTC()})
	}
	return out
}
