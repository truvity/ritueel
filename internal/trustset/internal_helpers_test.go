package trustset

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jws"
)

// ikey is a root key made in memory for the tests of the unexported functions: a P-384 key, a
// self-signed CA certificate, the pin and a Signer.
type ikey struct {
	label  string
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	pin    string
	signer Signer
}

var iserial int64

// newIKey makes a key. padding is the size of an extra extension, for a certificate that is large.
func newIKey(t testing.TB, label string, padding int) ikey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iserial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(5000 + iserial),
		Subject:               pkix.Name{CommonName: "Example Test Root " + label + " (TEST ONLY)"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if padding > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 99999, 1}, Value: bytes.Repeat([]byte{'a'}, padding)}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewKeySigner(label, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	return ikey{label: label, cert: cert, key: key, pin: jws.Pin(cert), signer: s}
}

// kindOf checks that err wraps want and not the other kind, and returns it.
func kindOf(t testing.TB, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("%q does not wrap %v", err, want)
	}
	other := ErrSign
	if errors.Is(want, ErrSign) {
		other = ErrParams
	}
	if errors.Is(err, other) {
		t.Fatalf("%q wraps %v as well", err, other)
	}
}

// order is the order of the curve P-384.
func order() *big.Int { return elliptic.P384().Params().N }
