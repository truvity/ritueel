package trustset_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/keystore/software"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/trustset"
)

// ceremony is the time at which the test certificates are made.
var ceremony = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// testRoot is one root key made in memory: a P-384 software key, its self-signed root certificate,
// the pin, and a real OpenPGP primary of its own (a second P-384 key, the certificate that
// openpgp.NewPrimary made and the fingerprint of its key packet). The primary carries the test mark
// of the root, so a test root and a real root are never mixed by accident.
type testRoot struct {
	Label string
	Pin   string
	Print string
	Cert  *x509.Certificate
	DER   []byte
	Key   *software.Key
	Test  bool
	// PGP is the public certificate of the OpenPGP primary (key, user ID, one certification).
	PGP []byte
	// PGPKey is the key of the OpenPGP primary, for a test that adds a certification.
	PGPKey *software.Key
}

// primaryCreated is the creation time of the OpenPGP primaries of the test roots; the ceremony is
// after it.
var primaryCreated = time.Date(2025, time.December, 1, 0, 0, 0, 0, time.UTC)

// primaryParams are the parameters of the primary of a test root at a ceremony time.
func (r *testRoot) primaryParams(t testing.TB, at time.Time) openpgp.PrimaryParams {
	t.Helper()
	uid, err := openpgp.UserID("Example Test", r.Label, "root@example.org", r.Test)
	if err != nil {
		t.Fatalf("UserID: %v", err)
	}
	return openpgp.PrimaryParams{Key: r.PGPKey, CreationTime: primaryCreated, CeremonyTime: at, ExpiresAt: at.AddDate(3, 0, 0), UserID: uid}
}

// makePrimary gives the root a new OpenPGP primary.
func (r *testRoot) makePrimary(t testing.TB) {
	t.Helper()
	key, err := software.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r.PGPKey = key
	r.PGP, err = openpgp.NewPrimary(rand.Reader, r.primaryParams(t, ceremony))
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the public key is a %T", key.Public())
	}
	r.Print, err = openpgp.Fingerprint(pub, primaryCreated)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
}

var (
	rootsMu sync.Mutex
	roots   = map[string]*testRoot{}
)

// newRoot returns the root key of a label. A test root has the mark " (TEST ONLY)" in its common
// name, a real one has not. A key is made once for each label and kind and is shared by the
// tests, which never close it.
func newRoot(t testing.TB, label string, test bool) *testRoot {
	t.Helper()
	name := label
	if test {
		name += "-test"
	}
	rootsMu.Lock()
	defer rootsMu.Unlock()
	if r, ok := roots[name]; ok {
		return r
	}
	key, err := software.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	r := &testRoot{Label: label, Key: key, Test: test}
	r.DER = rootCertificate(t, key, label, test)
	r.Cert, err = x509.ParseCertificate(r.DER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	r.Pin = jws.Pin(r.Cert)
	r.makePrimary(t)
	roots[name] = r
	return r
}

// rootCertificate makes the root certificate of the profile (package pki) for a key.
func rootCertificate(t testing.TB, key *software.Key, label string, test bool) []byte {
	t.Helper()
	serial, err := pki.NewSerial(nil)
	if err != nil {
		t.Fatalf("NewSerial: %v", err)
	}
	p := pki.RootParams{Name: "Example Test", Label: label, Test: test, CeremonyTime: ceremony, Key: key.Public(), Serial: serial}
	tbs, err := pki.RootTBS(p)
	if err != nil {
		t.Fatalf("RootTBS: %v", err)
	}
	sig, err := pki.SignRoot(nil, key, p, tbs)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	der, err := pki.Assemble(tbs, sig, key.Public())
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	return der
}

// entry is the entry of roots for this key.
func (r *testRoot) entry(withPrint bool) trustset.Root {
	e := trustset.Root{Label: r.Label, X509SPKISHA256: r.Pin}
	if withPrint {
		e.OpenPGPFingerprint = r.Print
	}
	return e
}

// certificatesOfRoots returns the OpenPGPCertificates of an input for the given entries: the
// certificate of the made root whose fingerprint an entry has, by the label of the entry. An entry
// with no fingerprint, or with a fingerprint that no made root has, gives none. The result is nil
// when no entry gives one.
func certificatesOfRoots(entries []trustset.Root) map[string][]byte {
	rootsMu.Lock()
	defer rootsMu.Unlock()
	var out map[string][]byte
	for _, e := range entries {
		if e.OpenPGPFingerprint == "" {
			continue
		}
		for _, r := range roots {
			if r.Print == e.OpenPGPFingerprint {
				if out == nil {
					out = map[string][]byte{}
				}
				out[e.Label] = slices.Clone(r.PGP)
			}
		}
	}
	return out
}

// signer makes the Signer of the key.
func (r *testRoot) signer(t testing.TB) trustset.Signer {
	t.Helper()
	s, err := trustset.NewKeySigner(r.Label, r.Cert, r.Key)
	if err != nil {
		t.Fatalf("NewKeySigner(%s): %v", r.Label, err)
	}
	return s
}

// removal makes the removal authorisation of the key.
func (r *testRoot) removal(t testing.TB) string {
	t.Helper()
	text, err := trustset.NewRemoval(r.signer(t))
	if err != nil {
		t.Fatalf("NewRemoval(%s): %v", r.Label, err)
	}
	return text
}

// hexOf is the SHA-256 of a text in lower-case hexadecimal: a made-up pin or digest.
func hexOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fakeRoot is an entry of roots with made-up pins, for the tests of the list, which needs no key.
func fakeRoot(label string, withPrint bool) trustset.Root {
	r := trustset.Root{Label: label, X509SPKISHA256: hexOf("pin " + label)}
	if withPrint {
		r.OpenPGPFingerprint = hexOf("fingerprint " + label)[:40]
	}
	return r
}

// fakeSpec is a list of the second sequence with two roots that have a fingerprint.
func fakeSpec() trustset.ListSpec {
	return trustset.ListSpec{
		Sequence:         2,
		SignedAt:         time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC),
		Roots:            []trustset.Root{fakeRoot("A", true), fakeRoot("B", true)},
		LastRecordSHA256: hexOf("last record"),
	}
}

// printable reports whether s is printable ASCII only: 0x20 to 0x7e.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// wantKind checks that err wraps want and no other kind of the package, has a text of printable
// ASCII that is short (a hostile input is not echoed), and is not nil.
func wantKind(t testing.TB, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("error %q does not wrap %v", err, want)
	}
	for _, other := range []error{trustset.ErrParams, trustset.ErrSign} {
		if !errors.Is(want, other) && errors.Is(err, other) {
			t.Fatalf("error %q wraps %v as well as %v", err, other, want)
		}
	}
	if !printable(err.Error()) {
		t.Fatalf("the text of the error is not printable ASCII: %+q", err.Error())
	}
	if len(err.Error()) > 400 {
		t.Fatalf("the text of the error is %d bytes long: %.100q", len(err.Error()), err.Error())
	}
}

// wantParams is wantKind for ErrParams.
func wantParams(t testing.TB, err error) {
	t.Helper()
	wantKind(t, err, trustset.ErrParams)
}

// wantSign is wantKind for ErrSign.
func wantSign(t testing.TB, err error) {
	t.Helper()
	wantKind(t, err, trustset.ErrSign)
}

// scriptedSigner is a Signer whose answers the test gives. A field left nil forwards to inner.
type scriptedSigner struct {
	inner trustset.Signer
	label func() string
	cert  func() *x509.Certificate
	sign  func(input []byte) ([]byte, error)

	mu     sync.Mutex
	calls  int
	inputs [][]byte
}

func (s *scriptedSigner) Label() string {
	if s.label != nil {
		return s.label()
	}
	return s.inner.Label()
}

func (s *scriptedSigner) Certificate() *x509.Certificate {
	if s.cert != nil {
		return s.cert()
	}
	return s.inner.Certificate()
}

func (s *scriptedSigner) SignES384(input []byte) ([]byte, error) {
	s.mu.Lock()
	s.calls++
	s.inputs = append(s.inputs, append([]byte(nil), input...))
	s.mu.Unlock()
	if s.sign != nil {
		return s.sign(input)
	}
	return s.inner.SignES384(input)
}

func (s *scriptedSigner) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// counting wraps a Signer and counts the calls of SignES384.
func counting(s trustset.Signer) *scriptedSigner { return &scriptedSigner{inner: s} }
