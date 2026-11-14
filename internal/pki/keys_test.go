package pki_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"path"
	"regexp"
	"testing"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The pins and the identifiers that OpenSSL computes (expected.txt), not the code under test.
func TestKeyPinAndIdentifierKnownAnswers(t *testing.T) {
	want := loadAnswers(t)
	cases := []struct {
		name string
		key  *ecdsa.PublicKey
		pin  string
		kid  string
	}{
		{"the root key", fixturePublicKey(t, "root.pub.pem"), "root.pin", "root.keyid"},
		{"the key of csr-nc", fixtureCSR(t, "csr-nc.csr.pem").PublicKey.(*ecdsa.PublicKey), "csr-nc.pin", "csr-nc.keyid"},
		{"the key of csr-eku", fixtureCSR(t, "csr-eku.csr.pem").PublicKey.(*ecdsa.PublicKey), "csr-eku.pin", "csr-eku.keyid"},
		{"the key of csr-no-eku", fixtureCSR(t, "csr-no-eku.csr.pem").PublicKey.(*ecdsa.PublicKey), "csr-no-eku.pin", ""},
		{"the key of csr-eku-critical", fixtureCSR(t, "csr-eku-critical.csr.pem").PublicKey.(*ecdsa.PublicKey), "csr-eku-critical.pin", ""},
		{"the key of csr-eku-reversed", fixtureCSR(t, "csr-eku-reversed.csr.pem").PublicKey.(*ecdsa.PublicKey), "csr-eku-reversed.pin", "csr-eku-reversed.keyid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pin, err := pki.SPKISHA256(c.key)
			if err != nil {
				t.Fatal(err)
			}
			if pin != want.text(t, c.pin) {
				t.Errorf("SPKISHA256 = %s, want %s", pin, want.text(t, c.pin))
			}
			if !lowerHex64.MatchString(pin) {
				t.Errorf("the pin %q is not 64 lower-case hexadecimal digits", pin)
			}
			kid, err := pki.KeyIdentifier(c.key)
			if err != nil {
				t.Fatal(err)
			}
			if c.kid == "" {
				return // a request that no certificate is made from has a pin only
			}
			if hex.EncodeToString(kid) != want.text(t, c.kid) {
				t.Errorf("KeyIdentifier = %x, want %s", kid, want.text(t, c.kid))
			}
			if len(kid) != 20 {
				t.Errorf("the identifier has %d octets, want 20", len(kid))
			}
		})
	}
}

// For every root of the root-list vectors, the pin is the pin of the manifest and the identifier
// is the certificate's own subject key identifier: both read at run time, no value is held here.
func TestKeyPinAndIdentifierAgainstRootList(t *testing.T) {
	var manifest struct {
		Roots []struct {
			Label       string `json:"label"`
			Certificate string `json:"certificate"`
			Pin         string `json:"x509_spki_sha256"`
		} `json:"roots"`
	}
	if err := json.Unmarshal(testrepo.Read(t, "testdata", "root-list", "v1", "manifest.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Roots) < 2 {
		t.Fatalf("the manifest lists %d roots, want at least 2", len(manifest.Roots))
	}
	for _, r := range manifest.Roots {
		t.Run(r.Label, func(t *testing.T) {
			cert := fixtureRootListCert(t, r.Certificate)
			pin, err := pki.SPKISHA256(cert.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if r.Pin == "" || pin != r.Pin {
				t.Errorf("SPKISHA256 = %s, the manifest says %q", pin, r.Pin)
			}
			kid, err := pki.KeyIdentifier(cert.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if len(cert.SubjectKeyId) == 0 || !bytes.Equal(kid, cert.SubjectKeyId) {
				t.Errorf("KeyIdentifier = %x, the certificate says %x", kid, cert.SubjectKeyId)
			}
		})
	}
}

func fixtureRootListCert(t testing.TB, rel string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(pemBlock(t, testrepo.Read(t, "testdata", "root-list", "v1", path.Clean(rel)), "CERTIFICATE"))
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return cert
}

func TestKeyPinAndIdentifierBehaviour(t *testing.T) {
	a, b := newKey(t), newKey(t)
	pinA, _ := pki.SPKISHA256(&a.PublicKey)
	pinA2, _ := pki.SPKISHA256(&a.PublicKey)
	pinB, _ := pki.SPKISHA256(&b.PublicKey)
	if pinA != pinA2 || pinA == pinB {
		t.Errorf("the pin is not a function of the key: %s %s %s", pinA, pinA2, pinB)
	}
	idA, _ := pki.KeyIdentifier(&a.PublicKey)
	idB, _ := pki.KeyIdentifier(&b.PublicKey)
	if bytes.Equal(idA, idB) {
		t.Error("two keys have the same identifier")
	}
	// The result is the caller's: a change to it does not reach the next call.
	idA[0] ^= 0xff
	idAgain, _ := pki.KeyIdentifier(&a.PublicKey)
	if bytes.Equal(idA, idAgain) {
		t.Error("KeyIdentifier returned a slice that is shared with the next call")
	}
	// The pin and the identifier are of the same key in any form it is given: the value read back
	// from its own encoding.
	der, err := x509.MarshalPKIXPublicKey(&a.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	back, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	if pin, err := pki.SPKISHA256(back); err != nil || pin != pinA {
		t.Errorf("pin of the parsed key = %q, %v; want %s", pin, err, pinA)
	}
}

// badKeys are the keys that are not ECDSA on P-384.
func badKeys(t testing.TB) map[string]any {
	t.Helper()
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ecdhKey, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	goodKey := newKey(t).PublicKey
	good := goodKey
	x, y := coordinates(&goodKey)
	off := rawKey(elliptic.P384(), x, new(big.Int).Add(y, big.NewInt(1)))
	zero := rawKey(elliptic.P384(), big.NewInt(0), big.NewInt(0))
	negative := rawKey(elliptic.P384(), new(big.Int).Neg(x), y)
	noCurve := rawKey(nil, x, y)
	return map[string]any{
		"nil":                              nil,
		"a nil ECDSA pointer":              (*ecdsa.PublicKey)(nil),
		"an ECDSA key by value":            good,
		"an ECDSA key with no coordinates": rawKey(elliptic.P384(), nil, nil),
		"an ECDSA key with no X":           rawKey(elliptic.P384(), nil, y),
		"an ECDSA key with no Y":           rawKey(elliptic.P384(), x, nil),
		"an ECDSA key with no curve":       noCurve,
		"a point off the curve":            off,
		"the point (0, 0)":                 zero,
		"a negative coordinate":            negative,
		"P-224":                            &p224.PublicKey,
		"P-256":                            &p256.PublicKey,
		"P-521":                            &p521.PublicKey,
		"RSA":                              &rsaKey.PublicKey,
		"Ed25519":                          edPub,
		"an ECDH P-384 key":                ecdhKey.PublicKey(),
		"a string":                         "not a key",
		"bytes":                            []byte{4, 1, 2, 3},
	}
}

func TestKeyPinAndIdentifierRefuseWhatIsNotP384(t *testing.T) {
	for name, key := range badKeys(t) {
		t.Run(name, func(t *testing.T) {
			pin, err := pki.SPKISHA256(key)
			refused(t, err, pki.ErrParams)
			if pin != "" {
				t.Errorf("a pin %q came with the error", pin)
			}
			kid, err := pki.KeyIdentifier(key)
			refused(t, err, pki.ErrParams)
			if kid != nil {
				t.Errorf("an identifier %x came with the error", kid)
			}
		})
	}
}
