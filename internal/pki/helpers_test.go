package pki_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// The known answers of testdata/x509-builders were made with OpenSSL, not with this code; the
// README of that folder says how. Nothing here holds a value of another folder of testdata/.
const fixtureSet = "x509-builders"

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	return testrepo.Read(t, "testdata", fixtureSet, name)
}

// answers is expected.txt: one "name value" pair per line.
type answers map[string]string

func loadAnswers(t testing.TB) answers {
	t.Helper()
	a := answers{}
	for _, line := range strings.Split(string(readFixture(t, "expected.txt")), "\n") {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, " ")
		if !ok || value == "" {
			t.Fatalf("expected.txt: bad line %q", line)
		}
		if _, dup := a[name]; dup {
			t.Fatalf("expected.txt: %s twice", name)
		}
		a[name] = value
	}
	if len(a) == 0 {
		t.Fatal("expected.txt holds no answer")
	}
	return a
}

func (a answers) text(t testing.TB, name string) string {
	t.Helper()
	v, ok := a[name]
	if !ok {
		t.Fatalf("expected.txt has no %s", name)
	}
	return v
}

func (a answers) bytes(t testing.TB, name string) []byte {
	t.Helper()
	return mustHex(t, a.text(t, name))
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func pemBlock(t testing.TB, data []byte, typ string) []byte {
	t.Helper()
	block, rest := pem.Decode(data)
	if block == nil || block.Type != typ || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatalf("not one PEM block of type %s", typ)
	}
	return block.Bytes
}

func fixturePublicKey(t testing.TB, name string) *ecdsa.PublicKey {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(pemBlock(t, readFixture(t, name), "PUBLIC KEY"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P384() {
		t.Fatalf("%s is not an ECDSA P-384 key", name)
	}
	return k
}

func fixtureCSR(t testing.TB, name string) *testCSR {
	t.Helper()
	der := pemBlock(t, readFixture(t, name), "CERTIFICATE REQUEST")
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return &testCSR{Fixed: der, RawSubject: csr.RawSubject, Extensions: csr.Extensions, PublicKey: csr.PublicKey, RawSubjectPublicKeyInfo: csr.RawSubjectPublicKeyInfo}
}

func fixtureCert(t testing.TB, name string) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(pemBlock(t, readFixture(t, name), "CERTIFICATE"))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return cert
}

func hexBig(t testing.TB, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		t.Fatalf("bad serial %q", s)
	}
	return n
}

func utc(year int, month time.Month, day, hour, min, sec int) time.Time {
	return time.Date(year, month, day, hour, min, sec, 0, time.UTC)
}

// newKey makes a P-384 key in memory; it is thrown away with the test.
func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// aSerial is a serial of 159 bits that the tests use when the serial is not the point.
var aSerial = new(big.Int).SetBytes(mustHexStatic("4b1c9e0d77a2f35b8c6e1d0a93f4b27c5e8a1d36"))

func mustHexStatic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var ceremony = utc(2026, time.November, 15, 12, 0, 0)

// kinds are the four kinds of error of the package: every error wraps exactly one. The fourth, ErrPEM, is the
// kind of a PEM file that is not in the form of the page, and only ReadPEMFile returns it.
var kinds = []error{pki.ErrParams, pki.ErrRequest, pki.ErrSignature, pki.ErrPEM}

// printable reports whether s holds printable ASCII only: bytes 0x20 to 0x7e.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// onePrefix checks that the text of an error of the package says its kind once: a refusal that is made again in the
// kind of the call keeps the words of the refusal and not its prefix.
func onePrefix(t testing.TB, err error) {
	t.Helper()
	if n := strings.Count(err.Error(), "pki: "); n != 1 {
		t.Errorf("the text has the prefix of the package %d times, want once: %q", n, err.Error())
	}
}

// kindOf returns the one kind of the package that err wraps. Every error of the package wraps exactly one of the four
// kinds, so an error that wraps none or more than one is a fault, and the test that met it fails.
// refusalLog is what zz_refusals_test.go reads at the end of the package: every error of kind ErrRequest or ErrParams that a test looked at,
// with its text and its check.
var refusalLog = struct {
	sync.Mutex
	seen map[string]pki.Check
}{seen: map[string]pki.Check{}}

// noteRefusal is called by kindOf for every error that a test looks at. The errors of kind ErrParams are kept too, because the
// readers of a name are shared by a request (ErrRequest, with a check) and an issuer (ErrParams, with none), and two of their
// refusals can only be met through the issuer.
func noteRefusal(err error) {
	if !errors.Is(err, pki.ErrRequest) && !errors.Is(err, pki.ErrParams) {
		return
	}
	refusalLog.Lock()
	defer refusalLog.Unlock()
	refusalLog.seen[err.Error()] = pki.CheckOf(err)
}

func kindOf(t testing.TB, err error) error {
	t.Helper()
	noteRefusal(err) // what zz_refusals_test.go reads at the end of the package
	var found []error
	for _, k := range kinds {
		if errors.Is(err, k) {
			found = append(found, k)
		}
	}
	if len(found) != 1 {
		t.Errorf("the error wraps %d kinds of the package, want exactly one: %v; error: %q", len(found), found, err.Error())
		return nil
	}
	return found[0]
}

// refused checks that err is a refusal of the given kind: it wraps that kind and no other, and
// its text is printable ASCII.
func refused(t testing.TB, err error, kind error) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v", kind)
	}
	_ = kindOf(t, err)
	for _, k := range kinds {
		if got, want := errors.Is(err, k), errors.Is(kind, k); got != want {
			t.Errorf("errors.Is(err, %v) = %v, want %v; error: %q", k, got, want, err.Error())
		}
	}
	if !printable(err.Error()) {
		t.Errorf("the text of the error is not printable ASCII: %q", err.Error())
	}
}

// --- keys that are not Go keys -------------------------------------------------------------------

// opaqueSigner is a bare crypto.Signer, as a card or a cloud key would be: the scalar is private
// to it, and it records what it is asked to sign.
type opaqueSigner struct {
	key    *ecdsa.PrivateKey
	calls  int
	digest []byte
	opts   crypto.SignerOpts
	rnd    io.Reader
	// tweak, when set, changes the answer: it gets the digest, the key and the signature that a
	// right signer would give, and returns what this signer returns.
	tweak func(digest []byte, key *ecdsa.PrivateKey, sig []byte) ([]byte, error)
	// pub, when set, is what Public returns instead of the key's own.
	pub crypto.PublicKey
}

func newOpaque(t testing.TB) *opaqueSigner { return &opaqueSigner{key: newKey(t)} }

func (s *opaqueSigner) Public() crypto.PublicKey {
	if s.pub != nil {
		return s.pub
	}
	return &s.key.PublicKey
}

func (s *opaqueSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	s.digest = append([]byte(nil), digest...)
	s.opts = opts
	s.rnd = rnd
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest)
	if err != nil {
		return nil, err
	}
	if s.tweak != nil {
		return s.tweak(digest, s.key, sig)
	}
	return sig, nil
}

// --- DER pieces written out for the tests -----------------------------------------------------

func tlv(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	n := len(body)
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidSAN              = asn1.ObjectIdentifier{2, 5, 29, 17}

	oidServerAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

// The key usage bits, numbered from the most significant bit as RFC 5280 does.
const (
	kuDigitalSignature = 0
	kuKeyCertSign      = 5
	kuCRLSign          = 6
)

// bitString is the DER of a named-bit BIT STRING with the given bits set: trailing zero bits left
// out, as DER says.
func bitString(bits ...int) []byte {
	max := 0
	for _, b := range bits {
		if b > max {
			max = b
		}
	}
	buf := make([]byte, max/8+1)
	for _, b := range bits {
		buf[b/8] |= 0x80 >> uint(b%8)
	}
	length := max + 1
	out, err := asn1.Marshal(asn1.BitString{Bytes: buf, BitLength: length})
	if err != nil {
		panic(err)
	}
	return out
}

func extBasicConstraints() pkix.Extension {
	return pkix.Extension{Id: oidBasicConstraints, Critical: true, Value: []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}}
}

func extKeyUsage(bits ...int) pkix.Extension {
	return pkix.Extension{Id: oidKeyUsage, Critical: true, Value: bitString(bits...)}
}

// nameConstraintsValue is permitted { host } as a DNS name (tag 2), a URI (tag 6) or another tag.
func nameConstraintsValue(tag byte, host string) []byte {
	base := tlv(0x80|tag, []byte(host))
	return tlv(0x30, tlv(0xa0, tlv(0x30, base)))
}

func extNameConstraints(host string) pkix.Extension {
	return pkix.Extension{Id: oidNameConstraints, Critical: true, Value: nameConstraintsValue(2, host)}
}

func extExtKeyUsage(critical bool, oids ...asn1.ObjectIdentifier) pkix.Extension {
	value, err := asn1.Marshal(oids)
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: oidExtKeyUsage, Critical: critical, Value: value}
}

// goodExtensions is what an ordinary request asks for: basic constraints, key usage with
// keyCertSign and cRLSign, name constraints, and the extended key usage that the contract's request
// has, not critical, with serverAuth and clientAuth.
func goodExtensions() []pkix.Extension {
	return []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign, kuCRLSign), extNameConstraints("example.org"), extExtKeyUsage(false, oidServerAuth, oidClientAuth)}
}

// A root key for the tests that build a root or an issuer.
type testRoot struct {
	key    *ecdsa.PrivateKey
	params pki.RootParams
	tbs    []byte
	cert   []byte
	parsed *x509.Certificate
}

func rootParams(key crypto.PublicKey) pki.RootParams {
	return pki.RootParams{Name: "Example Test", Label: "K", Test: true, CeremonyTime: ceremony, Key: key, Serial: aSerial}
}

// buildRoot builds, signs and assembles a root, with a software key made in memory.
func buildRoot(t testing.TB, mod func(*pki.RootParams)) *testRoot {
	t.Helper()
	key := newKey(t)
	p := rootParams(&key.PublicKey)
	if mod != nil {
		mod(&p)
	}
	tbs, err := pki.RootTBS(p)
	if err != nil {
		t.Fatalf("RootTBS: %v", err)
	}
	sig, err := pki.SignRoot(nil, key, p, tbs)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	cert, err := pki.Assemble(tbs, sig, &key.PublicKey)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &testRoot{key: key, params: p, tbs: tbs, cert: cert, parsed: parsed}
}

// issued is an intermediate built, signed and assembled under a test root.
type issued struct {
	csr    *testCSR
	params pki.IntermediateParams
	tbs    []byte
	cert   []byte
	parsed *x509.Certificate
}

func (r *testRoot) interParams(csr *testCSR) pki.IntermediateParams {
	return pki.IntermediateParams{
		CSR:           csr.DER(),
		IssuerSubject: r.parsed.RawSubject,
		IssuerKey:     &r.key.PublicKey,
		Roots:         []pki.RootRef{r.ref()},
		CeremonyTime:  ceremony,
		Serial:        aSerial,
	}
}

// ref is the root as the bundle holds it: its subject and its key.
func (r *testRoot) ref() pki.RootRef {
	return pki.RootRef{Subject: r.parsed.RawSubject, Key: &r.key.PublicKey}
}

// withIssuerInRoots makes the list of roots hold the issuer of the parameters, as a caller that changes the issuer of the parameters
// after they were made has to do: the roots are required to hold the issuer (ErrParams otherwise). A bundle holds a name once and
// a key once, so a root that has the key of the issuer, or its name, is the old issuer and is replaced by the new entry; the
// other roots stay.
func withIssuerInRoots(p pki.IntermediateParams) pki.IntermediateParams {
	for _, r := range p.Roots {
		if string(r.Subject) == string(p.IssuerSubject) && r.Key == p.IssuerKey {
			return p
		}
	}
	roots := make([]pki.RootRef, 0, len(p.Roots)+1)
	for _, r := range p.Roots {
		if same, err := pki.SameName(r.Subject, p.IssuerSubject); (err == nil && same) || r.Key == p.IssuerKey {
			continue
		}
		roots = append(roots, r)
	}
	roots = append(roots, pki.RootRef{Subject: p.IssuerSubject, Key: p.IssuerKey})
	p.Roots = roots
	return p
}

// issue builds the intermediate of the request under the root.
func (r *testRoot) issue(t testing.TB, csr *testCSR, mod func(*pki.IntermediateParams)) *issued {
	t.Helper()
	p := r.interParams(csr)
	if mod != nil {
		mod(&p)
	}
	p = withIssuerInRoots(p)
	tbs, err := intermediateTBS(t, p)
	if err != nil {
		t.Fatalf("IntermediateTBS: %v", err)
	}
	sig, err := pki.SignIntermediate(nil, r.key, p, tbs)
	if err != nil {
		t.Fatalf("SignIntermediate: %v", err)
	}
	cert, err := pki.Assemble(tbs, sig, &r.key.PublicKey)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	parsed, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return &issued{csr: csr, params: p, tbs: tbs, cert: cert, parsed: parsed}
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// extensionOf returns the extension of a certificate with the object identifier, or nil.
func extensionOf(c *x509.Certificate, id asn1.ObjectIdentifier) *pkix.Extension {
	for i := range c.Extensions {
		if c.Extensions[i].Id.Equal(id) {
			return &c.Extensions[i]
		}
	}
	return nil
}

func extensionIDs(c *x509.Certificate) []string {
	var ids []string
	for _, e := range c.Extensions {
		ids = append(ids, e.Id.String())
	}
	return ids
}

// rawKey makes a public key from its parts, whatever they are: a point that is not on the curve, a key
// with no coordinates, a key with no curve. Go deprecates the fields for good reasons, and the
// point of these keys is that they are not good.
//
//nolint:staticcheck // the deprecated fields are the only way to make a key that is not valid
func rawKey(curve elliptic.Curve, x, y *big.Int) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

// coordinates are the parts of a key that is valid.
//
//nolint:staticcheck // reading the deprecated fields of a good key, to make a bad one from them
func coordinates(k *ecdsa.PublicKey) (x, y *big.Int) { return k.X, k.Y }

// failReader fails at once with err.
type failReader struct{ err error }

func (f failReader) Read([]byte) (int, error) { return 0, f.err }

// rawSign signs the SHA-384 of tbs with key, with no check of anything: the signature of a key that the body
// does not name, or of a body that no builder returned, as a hostile or broken signer would make it.
func rawSign(t testing.TB, key *ecdsa.PrivateKey, tbs []byte) []byte {
	t.Helper()
	sig, err := ecdsa.SignASN1(rand.Reader, key, pki.TBSDigest(tbs))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// handAssemble puts a body and a signature into a certificate by hand, with no check of anything, so that a
// test can have another tool read a certificate that [pki.Assemble] would refuse.
func handAssemble(body, sig []byte) ([]byte, error) {
	return tlv(0x30, body, algECDSAWithSHA384DER, tlv(0x03, append([]byte{0}, sig...))), nil
}

// signatureOf is the signature that a key makes over the digest of a body, with no check of the body: the signature
// that an honest signer would return. A test that wants the package's own signing uses SignRoot or SignIntermediate.
func signatureOf(t testing.TB, key *ecdsa.PrivateKey, tbs []byte) []byte {
	t.Helper()
	return rawSign(t, key, tbs)
}

// mustRootTBS is the body of a root for key.
func mustRootTBS(t testing.TB, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tbs, err := pki.RootTBS(rootParams(&key.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return tbs
}

// randReader is crypto/rand.

// rootBodyWithSerial is the body of a root for key with the serial 2^64 + n.
func rootBodyWithSerial(t testing.TB, key *ecdsa.PrivateKey, n int64) []byte {
	t.Helper()
	p := rootParams(&key.PublicKey)
	p.Serial = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(n))
	tbs, err := pki.RootTBS(p)
	if err != nil {
		t.Fatal(err)
	}
	return tbs
}

// highS returns the signature with s replaced by n - s: the other form that ECDSA allows.
func highS(t testing.TB, sig []byte) []byte {
	t.Helper()
	var v struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &v); err != nil {
		t.Fatal(err)
	}
	v.S = new(big.Int).Sub(elliptic.P384().Params().N, v.S)
	out, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// intermediateTBS is pki.IntermediateTBS with the property that a request is read once and whole: every refusal for the
// content of a request that IntermediateTBS gives is given by ParseRequest too, in the same words, and a request that is
// issued is one that ParseRequest reads, whose view is what the body holds. IntermediateTBS adds only the two rules that
// need the issuer (the key of the request is the issuer's key, the subject is the issuer's name by SameName), and
// the parameters. Every test that builds a body goes through it, so the property holds for every row.
func intermediateTBS(t testing.TB, p pki.IntermediateParams) ([]byte, error) {
	t.Helper()
	p = withIssuerInRoots(p)
	tbs, err := pki.IntermediateTBS(p)
	if err != nil && (strings.Contains(err.Error(), "standard library") || strings.Contains(err.Error(), "a fault of this package")) {
		// The second reading of a finished body is reached only by a fault of the package: the readings before it
		// (the issuer, the request, the parameters) accept nothing that it refuses.
		t.Errorf("IntermediateTBS was refused by the reading of the finished body, which only a fault of the package can reach: %v", err)
	}
	if len(p.CSR) == 0 {
		return tbs, err
	}
	req, rerr := pki.ParseRequest(p.CSR)
	switch {
	case err == nil:
		if rerr != nil {
			t.Errorf("IntermediateTBS issued a request that ParseRequest refuses: %v", rerr)
			return tbs, err
		}
		viewIsTheBody(t, req, tbs)
	case errors.Is(err, pki.ErrRequest):
		if rerr != nil {
			if rerr.Error() != err.Error() {
				t.Errorf("IntermediateTBS and ParseRequest refuse the request in other words:\n IntermediateTBS: %v\n ParseRequest:    %v", err, rerr)
			}
			if !errors.Is(kindOf(t, rerr), kindOf(t, err)) {
				t.Errorf("the kinds differ: %v and %v", rerr, err)
			}
			break
		}
		// ParseRequest read it: the refusal is one of the two rules that need the issuer.
		if m := err.Error(); !strings.Contains(m, "the key of the request is the key of the issuer") && !strings.Contains(m, "is the name of the issuer") &&
			!strings.Contains(m, "the key of the request is the key of a root of the bundle") && !strings.Contains(m, "is the name of a root of the bundle") {
			t.Errorf("IntermediateTBS refuses a request that ParseRequest reads, and not by a rule of the issuer: %v", err)
		}
	default:
		// A parameter: the request itself may be good or not; if ParseRequest refuses it, the order of the checks is the builder's.
	}
	return tbs, err
}

// viewIsTheBody checks that what ParseRequest shows of a request is what the body that was issued from it holds: the
// subject (as DER and as relative names of type and value, read here by the standard library), the key, the extensions
// but the two key identifiers (identifier, flag, value, in order), and the name constraints decoded.
func viewIsTheBody(t testing.TB, req *pki.Request, tbs []byte) {
	t.Helper()
	cert := parseBodyOf(t, tbs)
	if !bytes.Equal(cert.RawSubject, req.Subject()) {
		t.Errorf("the subject of the body is not the subject of the view")
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(req.PublicKey()) {
		t.Errorf("the key of the body is not the key of the view")
	}
	var want []pkix.Extension
	for _, e := range cert.Extensions {
		if !e.Id.Equal(oidSubjectKeyID) && !e.Id.Equal(oidAuthorityKeyID) {
			want = append(want, e)
		}
	}
	// The body writes the extensions in the order of the profile, whatever order the request had them in, so they are matched by
	// identifier; each stands once.
	got := req.Extensions()
	if len(got) != len(want) {
		t.Errorf("the view has %d extensions, the body %d besides the key identifiers", len(got), len(want))
	}
	for _, g := range got {
		var found *pkix.Extension
		for i := range want {
			if want[i].Id.Equal(g.Id) {
				found = &want[i]
			}
		}
		if found == nil || found.Critical != g.Critical || !bytes.Equal(found.Value, g.Value) {
			t.Errorf("extension %v of the view is not the extension of the body", g.Id)
		}
	}
	// The relative names: the standard library reads the attributes of the name in order, flattened.
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(cert.RawSubject, &rdns); err != nil || len(rest) != 0 {
		t.Fatalf("the subject of the body does not parse: %v", err)
	}
	view := req.SubjectName()
	if len(view) != len(rdns) {
		t.Errorf("the view has %d relative names, the body %d", len(view), len(rdns))
	} else {
		for i, set := range rdns {
			if len(view[i]) != len(set) {
				t.Errorf("relative name %d: %d attributes in the view, %d in the body", i, len(view[i]), len(set))
				continue
			}
			for j, a := range set {
				if !view[i][j].Type.Equal(a.Type) || view[i][j].Value != fmt.Sprint(a.Value) {
					t.Errorf("attribute %d.%d of the view is %v=%q, the body has %v=%v", i, j, view[i][j].Type, view[i][j].Value, a.Type, a.Value)
				}
			}
		}
	}
	nc := req.NameConstraints()
	if !slices.Equal(nc.PermittedDNS, cert.PermittedDNSDomains) || !slices.Equal(nc.PermittedURI, cert.PermittedURIDomains) {
		t.Errorf("the name constraints of the view (%v, %v) are not those of the body (%v, %v)", nc.PermittedDNS, nc.PermittedURI, cert.PermittedDNSDomains, cert.PermittedURIDomains)
	}
	if nc.ExcludesAllIP != (len(cert.ExcludedIPRanges) == 2) || len(cert.ExcludedDNSDomains) != 0 || len(cert.PermittedIPRanges) != 0 {
		t.Errorf("the excluded ranges of the view (%v) are not those of the body (%v)", nc.ExcludesAllIP, cert.ExcludedIPRanges)
	}
}

// wraps says whether err wraps the kind, without the rule of refused that it wraps no other: for an error of a signer, which the package
// holds as a cause, and which may be an error of any kind itself.
func wraps(err, kind error) bool { return errors.Is(err, kind) }
