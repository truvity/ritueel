package trustset_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/keystore/software"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/trustset"
)

// fakeKey is a crypto.Signer whose public key and signature the test gives.
type fakeKey struct {
	pub  crypto.PublicKey
	sign func(digest []byte, opts crypto.SignerOpts) ([]byte, error)

	digests [][]byte
	opts    []crypto.SignerOpts
}

func (f *fakeKey) Public() crypto.PublicKey { return f.pub }

func (f *fakeKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	f.digests = append(f.digests, bytes.Clone(digest))
	f.opts = append(f.opts, opts)
	return f.sign(digest, opts)
}

// panicPublic is a crypto.Signer whose Public panics, as a nil pointer in an interface does.
type panicPublic struct{}

func (panicPublic) Public() crypto.PublicKey { panic("no key") }
func (panicPublic) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	panic("no key")
}

// fakeSigner makes a Signer of a root through a key that answers as the test says.
func fakeSigner(t testing.TB, r *testRoot, sign func(digest []byte, opts crypto.SignerOpts) ([]byte, error)) (trustset.Signer, *fakeKey) {
	t.Helper()
	k := &fakeKey{pub: r.Key.Public(), sign: sign}
	s, err := trustset.NewKeySigner(r.Label, r.Cert, k)
	if err != nil {
		t.Fatalf("NewKeySigner: %v", err)
	}
	return s, k
}

func order() *big.Int { return elliptic.P384().Params().N }

func pair(r, s *big.Int) []byte {
	out, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		panic(err)
	}
	return out
}

func TestKeySignerSignsForTheReader(t *testing.T) {
	r := newRoot(t, "A", true)
	s := r.signer(t)
	if s.Label() != "A" {
		t.Errorf("Label() = %q", s.Label())
	}
	if c := s.Certificate(); c == nil || !bytes.Equal(c.Raw, r.DER) || jws.Pin(c) != r.Pin {
		t.Errorf("Certificate() is not the certificate of the key")
	}
	pub, ok := r.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("the certificate holds no ECDSA key")
	}
	for i := 0; i < 200; i++ {
		input := []byte("message " + strconv.Itoa(i) + " of a signing input")
		sig, err := s.SignES384(input)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if len(sig) != jws.SignatureSize {
			t.Fatalf("message %d: %d bytes, want 96", i, len(sig))
		}
		if err := jws.VerifyES384(pub, input, sig); err != nil {
			t.Fatalf("message %d: the signature does not verify: %v", i, err)
		}
		// Another message does not verify with it.
		if err := jws.VerifyES384(pub, append(input, '!'), sig); err == nil {
			t.Fatalf("message %d: the signature verifies for another input", i)
		}
	}
}

// The key is asked to sign the SHA-384 digest of the input, with crypto.SHA384.
func TestKeySignerAsksForTheSHA384DigestOfTheInput(t *testing.T) {
	r := newRoot(t, "B", true)
	s, k := fakeSigner(t, r, func(digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		return r.Key.Sign(rand.Reader, digest, opts)
	})
	input := []byte("protected.payload")
	sig, err := s.SignES384(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.digests) != 1 {
		t.Fatalf("the key was asked %d times", len(k.digests))
	}
	want := sha512.Sum384(input)
	if !bytes.Equal(k.digests[0], want[:]) {
		t.Errorf("the digest is not the SHA-384 of the input")
	}
	if k.opts[0] == nil || k.opts[0].HashFunc() != crypto.SHA384 {
		t.Errorf("the options are %v, want crypto.SHA384", k.opts[0])
	}
	if err := jws.VerifyES384(r.Cert.PublicKey.(*ecdsa.PublicKey), input, sig); err != nil {
		t.Errorf("the signature does not verify: %v", err)
	}
}

// The ASN.1 value of a key is read with the rules of DER, and r and s come out as 48 bytes each.
func TestKeySignerReadsOnlyTheShortestAsn1(t *testing.T) {
	r := newRoot(t, "C", true)
	n := order()
	one := big.NewInt(1)
	nMinus1 := new(big.Int).Sub(n, one)
	high := new(big.Int).Add(new(big.Int).Lsh(one, 383), big.NewInt(5)) // 48 bytes, high bit set
	forty := new(big.Int).Lsh(one, 319)                                 // 40 bytes
	pad := func(v *big.Int) []byte { return v.FillBytes(make([]byte, 48)) }

	legal := []struct {
		name string
		der  []byte
		r, s *big.Int
	}{
		{"r of 40 bytes and s of 1 byte", pair(forty, one), forty, one},
		{"r and s are 1", pair(one, one), one, one},
		{"r and s are the order minus 1", pair(nMinus1, nMinus1), nMinus1, nMinus1},
		{"r with its high bit set", pair(high, nMinus1), high, nMinus1},
		{"s with its high bit set", pair(one, high), one, high},
	}
	for _, c := range legal {
		s, _ := fakeSigner(t, r, func([]byte, crypto.SignerOpts) ([]byte, error) { return c.der, nil })
		got, err := s.SignES384([]byte("x"))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		want := append(pad(c.r), pad(c.s)...)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: got %x, want %x", c.name, got, want)
		}
	}

	four9 := new(big.Int).Lsh(one, 384) // 49 bytes
	illegal := []struct {
		name string
		der  []byte
	}{
		{"nothing", nil},
		{"an empty value", []byte{}},
		{"one byte", []byte{0x30}},
		{"r = 0", pair(big.NewInt(0), one)},
		{"s = 0", pair(one, big.NewInt(0))},
		{"r and s = 0", pair(big.NewInt(0), big.NewInt(0))},
		{"r equal to the order", pair(n, one)},
		{"s equal to the order", pair(one, n)},
		{"r above the order", pair(new(big.Int).Add(n, one), one)},
		{"s above the order", pair(one, new(big.Int).Add(n, big.NewInt(7)))},
		{"r of 49 bytes", pair(four9, one)},
		{"a negative r", pair(big.NewInt(-5), one)},
		{"a negative s", pair(one, big.NewInt(-1))},
		{"bytes after the sequence", append(pair(one, one), 0)},
		{"a second sequence after the first", append(pair(one, one), pair(one, one)...)},
		{"a sequence of three integers", []byte{0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03}},
		{"a sequence of one integer", []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		{"an empty sequence", []byte{0x30, 0x00}},
		{"a long-form length where a short one fits", []byte{0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}},
		{"an indefinite length", []byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00, 0x00}},
		{"an integer that is not the shortest (a zero byte first)", []byte{0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01}},
		{"an integer with two zero bytes first", []byte{0x30, 0x08, 0x02, 0x03, 0x00, 0x00, 0x01, 0x02, 0x01, 0x01}},
		{"an integer with a redundant 0xff first", []byte{0x30, 0x07, 0x02, 0x02, 0xff, 0x80, 0x02, 0x01, 0x01}},
		{"a set instead of a sequence", []byte{0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}},
		{"an integer instead of a sequence", []byte{0x02, 0x01, 0x01}},
		{"an octet string for r", []byte{0x30, 0x06, 0x04, 0x01, 0x01, 0x02, 0x01, 0x01}},
		{"a null for s", []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x05, 0x00}},
		{"a length longer than the data", []byte{0x30, 0x10, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}},
		{"96 bytes of r and s, not ASN.1", bytes.Repeat([]byte{1}, 96)},
		{"an ASN.1 value of zeros", make([]byte, 100)},
	}
	for _, c := range illegal {
		s, _ := fakeSigner(t, r, func([]byte, crypto.SignerOpts) ([]byte, error) { return c.der, nil })
		got, err := s.SignES384([]byte("x"))
		if err == nil {
			t.Errorf("%s: accepted, %x", c.name, got)
			continue
		}
		if got != nil {
			t.Errorf("%s: a signature comes with the error", c.name)
		}
		wantSign(t, err)
	}
}

func TestKeySignerKeyErrors(t *testing.T) {
	r := newRoot(t, "D", true)
	cause := errors.New("the card was removed\x1b[31m \xff \u00e9")
	s, _ := fakeSigner(t, r, func([]byte, crypto.SignerOpts) ([]byte, error) { return nil, cause })
	got, err := s.SignES384([]byte("x"))
	if err == nil || got != nil {
		t.Fatalf("got %x, %v", got, err)
	}
	wantSign(t, err)
	// The error of the key is shown, escaped, and is not in the chain.
	if errors.Is(err, cause) {
		t.Errorf("the error of the key is in the chain")
	}
	if !strings.Contains(err.Error(), "the card was removed") {
		t.Errorf("the text %q does not show the error of the key", err)
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Errorf("the text %q holds a raw control character", err)
	}
	// A key whose error wraps the other kind of the package gives ErrSign and no other kind.
	s, _ = fakeSigner(t, r, func([]byte, crypto.SignerOpts) ([]byte, error) {
		return nil, fmt.Errorf("%w: pretend", trustset.ErrParams)
	})
	_, err = s.SignES384([]byte("x"))
	wantSign(t, err)
}

func TestNewKeySignerRefusals(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	ok := func(*testRoot) crypto.Signer { return nil }
	_ = ok
	closed, err := software.Generate()
	if err != nil {
		t.Fatal(err)
	}
	closedCert := rootCertificate(t, closed, "A", true)
	closedParsed, err := x509.ParseCertificate(closedCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256 := makeCert(t, certOptions{curve: elliptic.P256()})
	rsaCert := makeCert(t, certOptions{rsaKey: true})
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	huge := *a.Cert
	huge.Raw = make([]byte, trustset.MaxBytes+1)
	garbage := *a.Cert
	garbage.Raw = []byte("not a certificate")
	noRaw := *a.Cert
	noRaw.Raw = nil
	//nolint:staticcheck // a point that is not on the curve can only be built from its coordinates
	offCurve := &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(2)}
	var nilPtr *software.Key
	var nilEC *ecdsa.PublicKey
	sign := func([]byte, crypto.SignerOpts) ([]byte, error) { return nil, errors.New("must not be called") }

	// The refusal is for the reason of the case, so that a check that is gone is not hidden by
	// another that refuses the same input.
	reasons := map[string]string{
		"a nil key":                               "there is no key",
		"a typed nil key":                         "not an ECDSA key",
		"a nil certificate":                       "there is no certificate",
		"a certificate of another key":            "holds another key",
		"a closed key":                            "not an ECDSA key",
		"a key that is not ECDSA":                 "not an ECDSA key",
		"a P-256 key and certificate":             "the certificate: the key is not an ECDSA key",
		"an RSA certificate":                      "the certificate: the key is not an ECDSA key",
		"a key whose public key is nil":           "not an ECDSA key",
		"a key whose public key is a nil pointer": "not an ECDSA key",
		"a key whose point is not on the curve":   "not a point on P-384",
		"a key whose Public panics":               "the key has no public key",
		"a certificate of more than the limit":    "no DER or is longer than",
		"a certificate that is not DER":           "not one DER certificate",
		"a certificate with no DER":               "no DER or is longer than",
		"an empty certificate":                    "no DER or is longer than",
		"the label a":                             "label is not one upper-case letter",
		"the label AB":                            "label is not one upper-case letter",
		"an empty label":                          "label is not one upper-case letter",
		"the label 1":                             "label is not one upper-case letter",
		"the label of a newline":                  "label is not one upper-case letter",
		"a label outside ASCII":                   "label is not one upper-case letter",
	}
	for _, c := range []struct {
		name  string
		label string
		cert  *x509.Certificate
		key   crypto.Signer
	}{
		{"a nil key", "A", a.Cert, nil},
		{"a typed nil key", "A", a.Cert, nilPtr},
		{"a nil certificate", "A", nil, a.Key},
		{"a certificate of another key", "A", a.Cert, b.Key},
		{"a closed key", "A", closedParsed, closed},
		{"a key that is not ECDSA", "A", a.Cert, edPriv},
		{"a P-256 key and certificate", "A", p256.cert, p256Key},
		{"an RSA certificate", "A", rsaCert.cert, a.Key},
		{"a key whose public key is nil", "A", a.Cert, &fakeKey{sign: sign}},
		{"a key whose public key is a nil pointer", "A", a.Cert, &fakeKey{pub: nilEC, sign: sign}},
		{"a key whose point is not on the curve", "A", a.Cert, &fakeKey{pub: offCurve, sign: sign}},
		{"a key whose Public panics", "A", a.Cert, panicPublic{}},
		{"a certificate of more than the limit", "A", &huge, a.Key},
		{"a certificate that is not DER", "A", &garbage, a.Key},
		{"a certificate with no DER", "A", &noRaw, a.Key},
		{"an empty certificate", "A", &x509.Certificate{}, a.Key},
		{"the label a", "a", a.Cert, a.Key},
		{"the label AB", "AB", a.Cert, a.Key},
		{"an empty label", "", a.Cert, a.Key},
		{"the label 1", "1", a.Cert, a.Key},
		{"the label of a newline", "A\n", a.Cert, a.Key},
		{"a label outside ASCII", "\u00c4", a.Cert, a.Key},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := trustset.NewKeySigner(c.label, c.cert, c.key)
			if err == nil {
				t.Fatalf("accepted: %v", s)
			}
			if s != nil {
				t.Errorf("a signer comes with the error")
			}
			wantParams(t, err)
			why, ok := reasons[c.name]
			if !ok {
				t.Fatalf("no reason is given for the case %q", c.name)
			}
			if !strings.Contains(err.Error(), why) {
				t.Errorf("the refusal %q does not say %q", err, why)
			}
		})
	}
}

// The key and the pin come from the DER of the certificate, not from the fields of the struct that
// the caller filled: a struct whose PublicKey says one key and whose DER holds another is judged by
// the DER.
func TestNewKeySignerReadsTheDER(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	liar := *a.Cert
	liar.PublicKey = b.Cert.PublicKey
	if _, err := trustset.NewKeySigner("A", &liar, b.Key); err == nil {
		t.Errorf("a certificate whose DER holds the key of A was taken for the key of B")
	}
	truth := *b.Cert
	truth.PublicKey = a.Cert.PublicKey
	s, err := trustset.NewKeySigner("B", &truth, b.Key)
	if err != nil {
		t.Fatalf("a certificate whose DER holds the key of B, with a wrong PublicKey field: %v", err)
	}
	if jws.Pin(s.Certificate()) != b.Pin {
		t.Errorf("the signer's pin is not the pin of the DER")
	}
}

// The signer's certificate is its own: bytes that the caller changes later in the DER it gave do
// not change the certificate that the signer hands out. (A parsed certificate keeps the byte array it
// was parsed from, so a signer that does not copy the DER shares memory with its caller.)
func TestNewKeySignerKeepsItsOwnCopyOfTheDER(t *testing.T) {
	a := newRoot(t, "A", true)
	der := bytes.Clone(a.DER) // a copy, so that the shared root is not touched
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s, err := trustset.NewKeySigner("A", cert, a.Key)
	if err != nil {
		t.Fatal(err)
	}
	for i := range der {
		der[i] = 0
	}
	got := s.Certificate()
	if got == nil || !bytes.Equal(got.Raw, a.DER) {
		t.Fatalf("the DER of the signer's certificate changed with the caller's bytes")
	}
	if _, err := trustset.NewRemoval(s); err != nil {
		t.Errorf("the signer no longer makes an authorisation: %v", err)
	}
}

// A signer prints its label and nothing else, whatever verb is used.
func TestKeySignerPrintsOnlyItsLabel(t *testing.T) {
	r := newRoot(t, "Q", true)
	s := r.signer(t)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
		got := fmt.Sprintf(verb, s)
		if got != "trustset.Signer(Q)" {
			t.Errorf("%s prints %q", verb, got)
		}
	}
	if got := fmt.Sprint(s, []trustset.Signer{s}); got != "trustset.Signer(Q) [trustset.Signer(Q)]" {
		t.Errorf("Sprint prints %q", got)
	}
}

// The signer gives out no key: its methods are the three of the interface and the printing one.
func TestKeySignerHasNoMethodThatGivesTheKey(t *testing.T) {
	s := newRoot(t, "A", true).signer(t)
	var names []string
	typ := reflect.TypeOf(s)
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	sort.Strings(names)
	want := []string{"Certificate", "Format", "Label", "SignES384"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("the methods are %v, want %v", names, want)
	}
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).IsExported() {
			t.Errorf("the signer has the exported field %s", typ.Field(i).Name)
		}
	}
}

func TestKeySignerInParallel(t *testing.T) {
	r := newRoot(t, "E", true)
	s := r.signer(t)
	pub := r.Cert.PublicKey.(*ecdsa.PublicKey)
	const workers = 16
	start := make(chan struct{})
	done := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func() {
			<-start
			input := []byte("worker " + strconv.Itoa(i))
			sig, err := s.SignES384(input)
			if err == nil {
				err = jws.VerifyES384(pub, input, sig)
			}
			done <- err
		}()
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

// Whatever the caller does to the certificate it gave, in place or by replacing fields, the signer
// is the same: its certificate has the DER, the key and the pin it had, and it is a different
// object than the caller's, whose bytes it does not share.
func TestNewKeySignerIsNotAffectedByTheCallersCertificate(t *testing.T) {
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	der := bytes.Clone(a.DER)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s, err := trustset.NewKeySigner("A", cert, a.Key)
	if err != nil {
		t.Fatal(err)
	}
	own := s.Certificate()
	if own == cert {
		t.Fatalf("the signer hands out the caller's certificate")
	}
	if len(own.Raw) > 0 && &own.Raw[0] == &cert.Raw[0] {
		t.Fatalf("the signer shares the bytes of the caller's certificate")
	}
	// Replace every field the caller can, and change one byte at the end.
	*cert = *b.Cert
	cert.Raw = nil
	der[len(der)-1] ^= 0xff
	if got := s.Certificate(); !bytes.Equal(got.Raw, a.DER) || jws.Pin(got) != a.Pin {
		t.Errorf("the certificate of the signer changed with the caller's certificate")
	}
	text, err := trustset.NewRemoval(s)
	if err != nil {
		t.Fatalf("NewRemoval: %v", err)
	}
	if err := rootlist.CheckRemoval(rootlist.Removal{Label: "A", X509SPKISHA256: a.Pin, Authorisation: text}, nil, []string{a.Pin}); err != nil {
		t.Errorf("the text is not the authorisation of A: %v", err)
	}
}

// A label of the signer that is the same letter as the certificate's name but another letter than
// the one given is the caller's choice: the label is the one given to NewKeySigner, and it is
// exactly one of A to Z, in every position of the alphabet.
func TestNewKeySignerLabelsAreTheLettersAToZOnly(t *testing.T) {
	a := newRoot(t, "A", true)
	for c := 0; c < 256; c++ {
		label := string([]byte{byte(c)})
		s, err := trustset.NewKeySigner(label, a.Cert, a.Key)
		if c >= 'A' && c <= 'Z' {
			if err != nil || s.Label() != label {
				t.Errorf("label %q refused: %v", label, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("label %+q accepted", label)
		} else {
			wantParams(t, err)
		}
	}
	for _, label := range []string{"", "AA", "A ", " A", "A\x00", "\u0391", "\uff21", "A\u0301"} {
		if _, err := trustset.NewKeySigner(label, a.Cert, a.Key); err == nil {
			t.Errorf("label %+q accepted", label)
		} else {
			wantParams(t, err)
		}
	}
}
