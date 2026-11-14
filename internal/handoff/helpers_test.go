package handoff_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// The clock of the tests is the clock of the vectors.
var testNow = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

const testStem = "example-request"

// The keys of the tests are made in memory.
func newP384(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// asn1 pieces, written by hand so that a test can make a value that the standard library would not.

// tlv writes one DER element with the identifier octet tag.
func tlv(tag byte, content ...[]byte) []byte {
	var body []byte
	for _, c := range content {
		body = append(body, c...)
	}
	out := []byte{tag}
	n := len(body)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// generalName is the base of a name constraint subtree.
type generalName struct {
	tag     byte
	content []byte
}

func dnsName(s string) generalName { return generalName{0x82, []byte(s)} }
func uriName(s string) generalName { return generalName{0x86, []byte(s)} }

// ipRange is an iPAddress base: address and mask.
func ipRange(addr, mask []byte) generalName {
	return generalName{0x87, append(slices.Clone(addr), mask...)}
}

func emailName(s string) generalName { return generalName{0x81, []byte(s)} }

func subtrees(tag byte, names []generalName) []byte {
	var each [][]byte
	for _, n := range names {
		each = append(each, tlv(0x30, tlv(n.tag, n.content)))
	}
	return tlv(tag, each...)
}

var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidEKU              = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidServerAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func extBasic(critical bool, pathLen int) pkix.Extension {
	return pkix.Extension{Id: oidBasicConstraints, Critical: critical,
		Value: tlv(0x30, []byte{0x01, 0x01, 0xff}, mustMarshal(pathLen))}
}

func extKeyUsage(critical bool, usage byte) pkix.Extension {
	// One byte of bits; the unused bits are the trailing zero bits.
	unused := byte(0)
	for b := usage; b != 0 && b&1 == 0; b >>= 1 {
		unused++
	}
	return pkix.Extension{Id: oidKeyUsage, Critical: critical, Value: tlv(0x03, []byte{unused, usage})}
}

// keyCertSign is bit 5 of the key usage: 0x04 in the first octet.
const keyCertSign = 0x04

func extEKU(critical bool, oids ...asn1.ObjectIdentifier) pkix.Extension {
	var each [][]byte
	for _, o := range oids {
		each = append(each, mustMarshal(o))
	}
	return pkix.Extension{Id: oidEKU, Critical: critical, Value: tlv(0x30, each...)}
}

func extNameConstraints(critical bool, permitted, excluded []generalName) pkix.Extension {
	var parts [][]byte
	if permitted != nil {
		parts = append(parts, subtrees(0xa0, permitted))
	}
	if excluded != nil {
		parts = append(parts, subtrees(0xa1, excluded))
	}
	return pkix.Extension{Id: oidNameConstraints, Critical: critical, Value: tlv(0x30, parts...)}
}

// allIPs are the two excluded ranges that the page allows.
func allIPs() []generalName {
	return []generalName{ipRange(make([]byte, 4), make([]byte, 4)), ipRange(make([]byte, 16), make([]byte, 16))}
}

// The extensions of a request that the page accepts, with the permitted names given.
func goodExtensions(permitted ...generalName) []pkix.Extension {
	return []pkix.Extension{
		extBasic(true, 0),
		extKeyUsage(true, keyCertSign),
		extNameConstraints(true, permitted, allIPs()),
		extEKU(false, oidServerAuth, oidClientAuth),
	}
}

// replaceExt swaps the extension of one id for another, or adds it.
func replaceExt(exts []pkix.Extension, e pkix.Extension) []pkix.Extension {
	out := slices.Clone(exts)
	for i := range out {
		if out[i].Id.Equal(e.Id) {
			out[i] = e
			return out
		}
	}
	return append(out, e)
}

func dropExt(exts []pkix.Extension, id asn1.ObjectIdentifier) []pkix.Extension {
	return slices.DeleteFunc(slices.Clone(exts), func(e pkix.Extension) bool { return e.Id.Equal(id) })
}

// csrSpec says how to build a request. A zero field takes the value that makes a good request.
type csrSpec struct {
	key     crypto.Signer
	sigAlg  x509.SignatureAlgorithm
	subject *pkix.Name
	exts    []pkix.Extension
	noExts  bool
}

func defaultSubject() pkix.Name {
	return pkix.Name{CommonName: "Example Test Intermediate", Organization: []string{"acme"}}
}

// makeCSR builds a certificate request in memory and returns its DER and the key that signed it.
func makeCSR(t testing.TB, s csrSpec) (der []byte, signer crypto.Signer) {
	t.Helper()
	signer = s.key
	if signer == nil {
		signer = newP384(t)
	}
	subj := defaultSubject()
	if s.subject != nil {
		subj = *s.subject
	}
	tmpl := &x509.CertificateRequest{Subject: subj, SignatureAlgorithm: s.sigAlg}
	switch {
	case s.noExts:
	case s.exts != nil:
		tmpl.ExtraExtensions = s.exts
	default:
		tmpl.ExtraExtensions = goodExtensions(uriName("example.org"))
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, signer)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	return der, signer
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func digestHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// evidenceFor is the evidence member that the page gives a store.
func evidenceFor(store handoff.Store) map[string]any {
	switch store {
	case handoff.StorePIV, handoff.StoreOpenPGPCard:
		return map[string]any{"attestation": []string{b64("slot certificate"), b64("card certificate")}}
	case handoff.StoreKMS:
		return map[string]any{
			"key_arn":    "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555",
			"public_key": b64("public key"),
		}
	}
	return nil
}

// A fixture is one good request of type x509-intermediate, with the key that made it.
type fixture struct {
	t      testing.TB
	signer crypto.Signer
	der    []byte
	csr    []byte
	proof  map[string]any
}

// newFixture builds a good request for the store with the extensions of the spec.
func newFixture(t testing.TB, store handoff.Store, spec csrSpec) *fixture {
	t.Helper()
	der, signer := makeCSR(t, spec)
	f := &fixture{t: t, signer: signer, der: der, csr: pemOf(der)}
	f.proof = map[string]any{
		"handoff":        1,
		"type":           "x509-intermediate",
		"request_sha256": digestHex(der),
		"store":          string(store),
	}
	if ev := evidenceFor(store); ev != nil {
		f.proof["evidence"] = ev
	}
	if store == handoff.StoreKMS {
		// The public key of a KMS proof is the key of the request, as an honest requester writes it.
		f.proof["evidence"] = kmsEvidence(f.publicKey())
	}
	return f
}

// kmsEvidence is the evidence of a KMS key whose proof names the public key.
func kmsEvidence(pub *ecdsa.PublicKey) map[string]any {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"key_arn":    "arn:aws:kms:eu-west-1:123456789012:key/11111111-2222-3333-4444-555555555555",
		"public_key": base64.StdEncoding.EncodeToString(der),
	}
}

// request renders the proof to JSON and returns the request.
func (f *fixture) request() *handoff.Request {
	f.t.Helper()
	return &handoff.Request{Stem: testStem, Files: map[string][]byte{
		handoff.FileProof: mustJSON(f.t, f.proof),
		handoff.FileCSR:   slices.Clone(f.csr),
	}}
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// publicKey is the key of the request.
func (f *fixture) publicKey() *ecdsa.PublicKey {
	f.t.Helper()
	k, ok := f.signer.Public().(*ecdsa.PublicKey)
	if !ok {
		f.t.Fatal("the fixture's key is not ECDSA")
	}
	return k
}

// A root of the bundle for the tests.
type testRoot struct {
	key     *ecdsa.PrivateKey
	subject []byte
}

func newRoot(t testing.TB, cn string) testRoot {
	t.Helper()
	name := pkix.Name{CommonName: cn, Organization: []string{"acme"}}
	return testRoot{key: newP384(t), subject: mustMarshal(name.ToRDNSequence())}
}

func (r testRoot) ref() handoff.RootRef {
	return handoff.RootRef{Subject: slices.Clone(r.subject), Key: &r.key.PublicKey}
}

// defaultPolicy is the reference policy of the vectors, with software allowed.
func defaultPolicy() handoff.Policy {
	return handoff.Policy{
		Stores:         []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS, handoff.StoreSoftware},
		MinFirmware:    "5.7.0",
		PINPolicies:    []handoff.PINPolicy{handoff.PINOnce, handoff.PINAlways},
		ValidityMonths: 13,
	}
}

func defaultDelegation() *handoff.Delegation {
	return &handoff.Delegation{
		Name:              "example-intermediate",
		Type:              handoff.TypeX509,
		Root:              "example-root",
		PermittedURIHosts: []string{"example.org"},
		PermittedDNSNames: []string{"example.org"},
	}
}

// defaultConfig is a whole configuration: a policy, a delegation, a root and a clock, and no verifier.
func defaultConfig(t testing.TB) handoff.Config {
	t.Helper()
	root := newRoot(t, "Example Test Root")
	return handoff.Config{
		Policy:     defaultPolicy(),
		Delegation: defaultDelegation(),
		Roots:      []handoff.RootRef{root.ref()},
		Now:        func() time.Time { return testNow },
	}
}

// mustNew makes the checker of a configuration that the test says is whole.
func mustNew(t testing.TB, cfg handoff.Config) *handoff.Checker {
	t.Helper()
	c, err := handoff.New(cfg)
	if err != nil {
		t.Fatalf("New refused a whole configuration: %v", err)
	}
	return c
}

// newCheckerWith is a checker made from the default configuration after the change.
func newCheckerWith(t testing.TB, change func(c *handoff.Config)) *handoff.Checker {
	t.Helper()
	cfg := defaultConfig(t)
	if change != nil {
		change(&cfg)
	}
	return mustNew(t, cfg)
}

// newChecker is a checker that has everything: a policy, a delegation, a root, a clock, and no verifier.
func newChecker(t testing.TB) *handoff.Checker {
	t.Helper()
	return newCheckerWith(t, nil)
}

// wantConfigError says that New refuses the configuration with ErrConfig and returns no checker.
func wantConfigError(t testing.TB, cfg handoff.Config) {
	t.Helper()
	c, err := handoff.New(cfg)
	if !errors.Is(err, handoff.ErrConfig) {
		t.Fatalf("New returned the error %v, want ErrConfig", err)
	}
	if c != nil {
		t.Fatal("New returned a checker beside an error")
	}
}

// stub is an evidence verifier that a test controls. It counts its calls.
type stub struct {
	fn    func(ctx context.Context, r *handoff.Request, p *handoff.Proof, now time.Time) (*handoff.Evidence, error)
	calls atomic.Int32
}

func (s *stub) Verify(ctx context.Context, r *handoff.Request, p *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
	s.calls.Add(1)
	return s.fn(ctx, r, p, now)
}

// returning is a verifier that gives the evidence.
func returning(ev *handoff.Evidence) *stub {
	return &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		return ev, nil
	}}
}

// failing is a verifier that gives the error.
func failing(err error) *stub {
	return &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		return nil, err
	}}
}

// goodEvidence is what a verifier would read from a good card: the key of the request, a recent
// firmware and a PIN policy that is allowed.
func (f *fixture) goodEvidence(store handoff.Store) *handoff.Evidence {
	ev := &handoff.Evidence{Key: f.publicKey()}
	switch store {
	case handoff.StorePIV:
		ev.Firmware, ev.PINPolicy, ev.TouchPolicy = "5.8.0", handoff.PINOnce, "always"
	case handoff.StoreKMS:
		ev.SignPrincipals = []handoff.Principal{{ARN: "arn:aws:iam::123456789012:role/example-holder", Kind: handoff.PrincipalRole}}
	}
	return ev
}

// check runs the checker on the request and fails the test on an error that the test did not expect.
func mustCheck(t testing.TB, c *handoff.Checker, r *handoff.Request) handoff.Verdict {
	t.Helper()
	v, err := c.Check(t.Context(), r)
	if err != nil {
		t.Fatalf("Check returned the error %v, and the verdict %+v", err, v)
	}
	return v
}

// statuses writes the nine results as one string such as "ppppfnnnn", for the shape tests.
func statuses(v handoff.Verdict) string {
	out := make([]byte, 0, len(v.Checks))
	for _, c := range v.Checks {
		switch c.Status {
		case handoff.StatusPassed:
			out = append(out, 'p')
		case handoff.StatusFailed:
			out = append(out, 'f')
		case handoff.StatusNotRun:
			out = append(out, 'n')
		default:
			out = append(out, '?')
		}
	}
	return string(out)
}

// wantRefusal checks the code of a refusal and the nine results around the failed check n.
func wantRefusal(t testing.TB, v handoff.Verdict, err error, code handoff.Code, n int) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if v.Code != code {
		t.Fatalf("code %q (%s), want %q at check %d; statuses %s", v.Code, v.Detail, code, n, statuses(v))
	}
	if !v.Refused() {
		t.Fatal("a refusal that Refused() does not report")
	}
	if v.Accepted() {
		t.Fatal("a refusal that Accepted() reports as an acceptance")
	}
	if v.Key != nil || v.Evidence != nil {
		t.Fatalf("a refused verdict holds a key or evidence: %+v %+v", v.Key, v.Evidence)
	}
	// A refusal by check 9 is the one refusal that leaves no check unrun: every check ran, and the last
	// one refused. Any earlier refusal leaves the later checks unrun.
	if v.Complete() != (n == 9) {
		t.Fatalf("Complete() is %v for a refusal at check %d", v.Complete(), n)
	}
	want := make([]byte, 9)
	for i := range want {
		switch {
		case i+1 < n:
			want[i] = 'p'
		case i+1 == n:
			want[i] = 'f'
		default:
			want[i] = 'n'
		}
	}
	if got := statuses(v); got != string(want) {
		t.Fatalf("statuses %s, want %s", got, want)
	}
}

// wantAccepted checks that the verdict is an acceptance: no error, nothing refused, every check ran and
// passed, and Accepted() says so.
func wantAccepted(t testing.TB, v handoff.Verdict, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if v.Refused() || !v.Complete() || statuses(v) != "ppppppppp" {
		t.Fatalf("not accepted: code %q (%s), statuses %s", v.Code, v.Detail, statuses(v))
	}
	if !v.Accepted() {
		t.Fatalf("every check passed and Accepted() is false: %s", statuses(v))
	}
	if v.Key == nil || v.Evidence == nil {
		t.Fatalf("an accepted verdict holds no key or no evidence: %+v %+v", v.Key, v.Evidence)
	}
}

// wantUnreadableVersion checks the refusal of a proof file whose version cannot be read: the page gives
// `malformed` to check 2 and `version-unsupported` to check 1, so the check that fails is check 2 and check 1
// did not run.
func wantUnreadableVersion(t testing.TB, v handoff.Verdict, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if v.Code != handoff.CodeMalformed || !v.Refused() || v.Accepted() || v.Complete() {
		t.Fatalf("code %q (%s), refused %v, accepted %v, complete %v", v.Code, v.Detail, v.Refused(), v.Accepted(), v.Complete())
	}
	if got := statuses(v); got != "nfnnnnnnn" {
		t.Fatalf("statuses %s, want nfnnnnnnn: check 2 failed and check 1 did not run", got)
	}
	if v.Detail == "" || v.Key != nil || v.Evidence != nil {
		t.Fatalf("detail %q, key %v, evidence %v", v.Detail, v.Key, v.Evidence)
	}
}

// wantUndecided checks that the call could not decide: an error, no refusal, a verdict that is not
// complete and not accepted, the statuses the test names, and no key or evidence.
func wantUndecided(t testing.TB, v handoff.Verdict, err, want error, wantStatuses string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error %v, want %v", err, want)
	}
	if v.Refused() || v.Complete() || v.Accepted() {
		t.Fatalf("refused %v, complete %v, accepted %v beside the error %v", v.Refused(), v.Complete(), v.Accepted(), err)
	}
	if wantStatuses != "" && statuses(v) != wantStatuses {
		t.Fatalf("statuses %s, want %s", statuses(v), wantStatuses)
	}
	if v.Key != nil || v.Evidence != nil {
		t.Fatalf("a verdict beside an error holds a key or evidence: %+v %+v", v.Key, v.Evidence)
	}
}

// otherKeys are the keys of the algorithms that are not P-384.
func otherKeys(t testing.TB) map[string]crypto.Signer {
	t.Helper()
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]crypto.Signer{"P-256": p256, "P-521": p521, "RSA-2048": r, "Ed25519": ed}
}

// jsonOf is mustJSON for a builder that has no test at hand.
func jsonOf(v any) ([]byte, error) { return json.Marshal(v) }

// pkixName65 is a subject whose common name is one character over the limit of 64.
var pkixName65 = pkix.Name{CommonName: strings.Repeat("a", 65)}
