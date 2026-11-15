package answer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // see the use
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/rootlist"
)

// This file writes answers in memory, for the cases that the vectors do not show. The roots, the requests and
// the certificates are made here with the standard library and with the builders of package pki; the
// certificate writer signs the body itself with crypto/ecdsa, so that a case can have a fault that no builder
// writes (the test says so where it does). A control is built first and each refusal is the control with one
// change.

// testNow is the clock of the vectors, so that the in-memory answers and the vectors share one time.
var testNow = vectorNow

func newP384(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

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
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, body...)
}

// The extensions of a request of the profile.
var (
	oidBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidNameConstraints  = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidEKU              = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidSKI              = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAKI              = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidCertPolicies     = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidAIA              = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidServerAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidClientAuth       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
)

func extBasic(critical bool, pathLen int) pkix.Extension {
	return pkix.Extension{Id: oidBasicConstraints, Critical: critical, Value: tlv(0x30, []byte{0x01, 0x01, 0xff}, mustMarshal(pathLen))}
}

func extKeyUsage(critical bool, usage byte) pkix.Extension {
	unused := byte(0)
	for b := usage; b != 0 && b&1 == 0; b >>= 1 {
		unused++
	}
	return pkix.Extension{Id: oidKeyUsage, Critical: critical, Value: tlv(0x03, []byte{unused, usage})}
}

const keyCertSign = 0x04

func extEKU(critical bool, oids ...asn1.ObjectIdentifier) pkix.Extension {
	var each [][]byte
	for _, o := range oids {
		each = append(each, mustMarshal(o))
	}
	return pkix.Extension{Id: oidEKU, Critical: critical, Value: tlv(0x30, each...)}
}

// extNameConstraints is the extension with a permitted URI host and the two excluded IP ranges that the page allows.
func extNameConstraints(critical bool, permittedURI string) pkix.Extension {
	subtree := func(base []byte) []byte { return tlv(0x30, base) }
	permitted := tlv(0xa0, subtree(tlv(0x86, []byte(permittedURI))))
	excluded := tlv(0xa1,
		subtree(tlv(0x87, make([]byte, 8))),
		subtree(tlv(0x87, make([]byte, 32))))
	return pkix.Extension{Id: oidNameConstraints, Critical: critical, Value: tlv(0x30, permitted, excluded)}
}

func goodExtensions() []pkix.Extension {
	return []pkix.Extension{
		extBasic(true, 0),
		extKeyUsage(true, keyCertSign),
		extNameConstraints(true, "example.org"),
		extEKU(false, oidServerAuth, oidClientAuth),
	}
}

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

// memCSR is a request of type x509-intermediate that the test made: the file, the DER, the key.
type memCSR struct {
	key  *ecdsa.PrivateKey
	der  []byte
	file []byte
	req  *pki.Request
}

// newCSR makes a good request, with the extensions given (the good ones when nil).
func newCSR(t testing.TB, key *ecdsa.PrivateKey, exts []pkix.Extension) *memCSR {
	t.Helper()
	if key == nil {
		key = newP384(t)
	}
	if exts == nil {
		exts = goodExtensions()
	}
	tmpl := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "Example Test Intermediate", Organization: []string{"acme"}},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}
	file := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	req, err := pki.ParseRequestFile(file)
	if err != nil {
		t.Fatalf("the request is not read by the builder's reader: %v", err)
	}
	return &memCSR{key: key, der: der, file: file, req: req}
}

func (c *memCSR) asked(t testing.TB) *answer.Asked {
	t.Helper()
	a, err := answer.AskedX509(c.file)
	if err != nil {
		t.Fatalf("AskedX509: %v", err)
	}
	return a
}

// memRoot is a root of the bundle: its key, its certificate and, for the OpenPGP cases, its primary.
type memRoot struct {
	label   string
	key     *ecdsa.PrivateKey
	der     []byte
	cert    *x509.Certificate
	pin     string
	primary *pgpKey
}

func newRoot(t testing.TB, label string) memRoot {
	t.Helper()
	return newRootAt(t, label, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
}

// newRootAt makes a root whose certificate starts at the given time and lasts 36 months.
func newRootAt(t testing.TB, label string, ceremony time.Time) memRoot {
	t.Helper()
	key := newP384(t)
	serial, err := pki.NewSerial(nil)
	if err != nil {
		t.Fatal(err)
	}
	p := pki.RootParams{Name: "Example Test", Label: label, Test: true, CeremonyTime: ceremony, Key: &key.PublicKey, Serial: serial}
	tbs, err := pki.RootTBS(p)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := pki.SignRoot(nil, key, p, tbs)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.Assemble(tbs, sig, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return memRoot{label: label, key: key, der: der, cert: cert, pin: jws.Pin(cert), primary: newPGPKey(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))}
}

// memKit is the trust of the in-memory answers: three roots (A and B on the list, Z not), the held list of a
// sequence and its CA bundle.
type memKit struct {
	t        testing.TB
	a, b, z  memRoot
	sequence int64
	expires  string // the expires_at of the held list; empty takes 2027-12-15T12:00:00Z
	listJSON []byte
	held     *rootlist.Held
	bundle   []byte
}

func newKit(t testing.TB) *memKit {
	t.Helper()
	k := &memKit{t: t, a: newRoot(t, "A"), b: newRoot(t, "B"), z: newRoot(t, "Z"), sequence: 7}
	k.writeList([]memRoot{k.a, k.b})
	return k
}

// writeList makes the held list and the bundle of the roots, in that order.
func (k *memKit) writeList(roots []memRoot) {
	k.t.Helper()
	type rootJSON struct {
		Label string `json:"label"`
		X509  string `json:"x509_spki_sha256"`
		PGP   string `json:"openpgp_fingerprint,omitempty"`
	}
	var rs []rootJSON
	expires := k.expires
	if expires == "" {
		expires = "2027-12-15T12:00:00Z"
	}
	bundle := []byte(fmt.Sprintf("# trust-sequence: %d\n", k.sequence))
	for _, r := range roots {
		rs = append(rs, rootJSON{Label: r.label, X509: r.pin, PGP: r.primary.fingerprint()})
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.der})...)
	}
	list, err := json.Marshal(map[string]any{
		"version": 1, "sequence": k.sequence,
		"signed_at": "2026-11-15T12:00:00Z", "expires_at": expires,
		"roots": rs,
	})
	if err != nil {
		k.t.Fatal(err)
	}
	held, err := rootlist.ParseHeld(list)
	if err != nil {
		k.t.Fatal(err)
	}
	k.listJSON, k.held, k.bundle = list, held, bundle
}

// config is a configuration for the full contract, with the trust of the kit, the primaries of A and B, the
// range of 12 to 14 months and the clock of the vectors. change edits it before it is returned.
func (k *memKit) config(change func(*answer.Config)) answer.Config {
	k.t.Helper()
	cfg := answer.Config{
		Held: k.held, CABundle: slices.Clone(k.bundle),
		Primaries: []handoff.PrimaryRef{k.a.primary.ref(), k.b.primary.ref()},
		Now:       func() time.Time { return testNow },
	}
	cfg.Validity.MinMonths, cfg.Validity.MaxMonths = 12, 14
	if change != nil {
		change(&cfg)
	}
	return cfg
}

func (k *memKit) checker(change func(*answer.Config)) *answer.Checker {
	k.t.Helper()
	return mustChecker(k.t, k.config(change))
}

// certSpec says how to write an issued certificate. A zero field takes the value of the profile.
type certSpec struct {
	issuer       *memRoot // the root that signs and is named as the issuer; A
	signWith     *ecdsa.PrivateKey
	issuerName   []byte // the raw issuer name when it is not the subject of the issuer
	version      int    // the version number as written (2 is version 3); 0 means 2, and -1 writes none (version 1)
	serialLen    int    // the length of the serial in bytes; 0 means 20
	notBefore    time.Time
	months       int // the length of the validity in calendar months; 0 means 13
	notAfter     time.Time
	exts         []pkix.Extension // the whole list of extensions, in order; nil takes the profile's
	noExts       bool
	extraExts    []pkix.Extension // added after the profile's six
	sigAlg       asn1.ObjectIdentifier
	digest       crypto.Hash
	subjectDER   []byte
	spki         []byte
	flipSigByte  bool
	sigAlgInside asn1.ObjectIdentifier // the algorithm of the signature field inside the body, when it differs
	algNull      bool                  // write the algorithm identifiers with NULL parameters, in the body and outside it
}

var (
	oidECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
)

func algID(oid asn1.ObjectIdentifier) []byte { return tlv(0x30, mustMarshal(oid)) }

func algIDNull(oid asn1.ObjectIdentifier) []byte {
	return tlv(0x30, mustMarshal(oid), []byte{0x05, 0x00})
}

func utcTime(t time.Time) []byte {
	t = t.UTC()
	if t.Year() >= 2050 {
		return tlv(0x18, []byte(t.Format("20060102150405Z")))
	}
	return tlv(0x17, []byte(t.Format("060102150405Z")))
}

// profileExts is the list of extensions that the profile gives for the request, in the order of the builder.
func profileExts(c *memCSR, issuerPub *ecdsa.PublicKey) []pkix.Extension {
	byID := map[string]pkix.Extension{}
	for _, e := range c.req.Extensions() {
		byID[e.Id.String()] = e
	}
	subjectID, err := pki.KeyIdentifier(&c.key.PublicKey)
	if err != nil {
		panic(err)
	}
	issuerID, err := pki.KeyIdentifier(issuerPub)
	if err != nil {
		panic(err)
	}
	return []pkix.Extension{
		byID[oidBasicConstraints.String()],
		byID[oidKeyUsage.String()],
		byID[oidNameConstraints.String()],
		byID[oidEKU.String()],
		{Id: oidSKI, Value: tlv(0x04, subjectID)},
		{Id: oidAKI, Value: tlv(0x30, tlv(0x80, issuerID))},
	}
}

func extDER(e pkix.Extension) []byte {
	parts := [][]byte{mustMarshal(e.Id)}
	if e.Critical {
		parts = append(parts, []byte{0x01, 0x01, 0xff})
	}
	parts = append(parts, tlv(0x04, e.Value))
	return tlv(0x30, parts...)
}

// issue writes a certificate for the request, signed by the issuer, and returns its DER. The control
// (a zero spec) is checked against the builder of package pki by TestTheTestWriterWritesTheBodyOfTheBuilder.
func (k *memKit) issue(c *memCSR, s certSpec) []byte {
	k.t.Helper()
	issuer := s.issuer
	if issuer == nil {
		issuer = &k.a
	}
	signer := s.signWith
	if signer == nil {
		signer = issuer.key
	}
	nb := s.notBefore
	if nb.IsZero() {
		nb = testNow
	}
	na := s.notAfter
	if na.IsZero() {
		months := s.months
		if months == 0 {
			months = 13
		}
		var err error
		if na, err = pki.AddMonths(nb, months); err != nil {
			k.t.Fatal(err)
		}
	}
	serialLen := s.serialLen
	if serialLen == 0 {
		serialLen = 20
	}
	serial := make([]byte, serialLen)
	if _, err := rand.Read(serial); err != nil {
		k.t.Fatal(err)
	}
	serial[0] = serial[0]&0x7f | 0x40 // positive and not a short number
	serialN := new(big.Int).SetBytes(serial)

	issuerName := s.issuerName
	if issuerName == nil {
		issuerName = issuer.cert.RawSubject
	}
	subject := s.subjectDER
	if subject == nil {
		subject = c.req.Subject()
	}
	spki := s.spki
	if spki == nil {
		var err error
		if spki, err = x509.MarshalPKIXPublicKey(c.req.PublicKey()); err != nil {
			k.t.Fatal(err)
		}
	}
	exts := s.exts
	if exts == nil && !s.noExts {
		exts = append(profileExts(c, &issuer.key.PublicKey), s.extraExts...)
	}
	alg := s.sigAlg
	if alg == nil {
		alg = oidECDSASHA384
	}
	hash := s.digest
	if hash == 0 {
		hash = crypto.SHA384
	}
	inside := s.sigAlgInside
	if inside == nil {
		inside = alg
	}

	var parts [][]byte
	switch {
	case s.version == 0:
		parts = append(parts, tlv(0xa0, []byte{0x02, 0x01, 0x02}))
	case s.version > 0:
		parts = append(parts, tlv(0xa0, []byte{0x02, 0x01, byte(s.version)}))
	}
	id := algID
	if s.algNull {
		id = algIDNull
	}
	parts = append(parts, mustMarshal(serialN), id(inside), issuerName,
		tlv(0x30, utcTime(nb), utcTime(na)), subject, spki)
	if len(exts) > 0 {
		var each [][]byte
		for _, e := range exts {
			each = append(each, extDER(e))
		}
		parts = append(parts, tlv(0xa3, tlv(0x30, each...)))
	}
	tbs := tlv(0x30, parts...)

	var digest []byte
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256(tbs)
		digest = d[:]
	case crypto.SHA1:
		d := sha1.Sum(tbs) //nolint:gosec // a certificate signed with SHA-1, which the requester refuses
		digest = d[:]
	default:
		d := sha512.Sum384(tbs)
		digest = d[:]
	}
	sig, err := ecdsa.SignASN1(rand.Reader, signer, digest)
	if err != nil {
		k.t.Fatal(err)
	}
	if s.flipSigByte {
		sig[len(sig)-1] ^= 0x01
	}
	return tlv(0x30, tbs, id(alg), tlv(0x03, append([]byte{0}, sig...)))
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// x509Case is one in-memory answer to a request of type x509-intermediate.
type x509Case struct {
	t         testing.TB
	kit       *memKit
	csr       *memCSR
	spec      certSpec
	stem      string
	pemFile   []byte // the certificate file as written; nil writes it from the certificate
	der       []byte // the certificate; nil writes it from the spec
	edits     []func(m map[string]any)
	rawJSON   []byte // the result file as written; nil writes it from the members
	sequence  int64  // trust_sequence; 0 takes the kit's
	issuerPin string // the issuer member; empty takes the pin of the issuing root
}

func (k *memKit) newX509(c *memCSR) *x509Case {
	k.t.Helper()
	if c == nil {
		c = newCSR(k.t, nil, nil)
	}
	return &x509Case{t: k.t, kit: k, csr: c, stem: "example-answer"}
}

func (x *x509Case) with(change func(m map[string]any)) *x509Case {
	x.edits = append(x.edits, change)
	return x
}

func (x *x509Case) certDER() []byte {
	if x.der == nil {
		x.der = x.kit.issue(x.csr, x.spec)
	}
	return x.der
}

func formatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// files writes the answer's files.
func (x *x509Case) files() map[string][]byte {
	x.t.Helper()
	der := x.certDER()
	file := x.pemFile
	if file == nil {
		file = certPEM(der)
	}
	if x.rawJSON != nil {
		return map[string][]byte{answer.FileResult: slices.Clone(x.rawJSON), answer.FileCert: file}
	}
	// A certificate that the standard library does not read is a case of its own: its dates are the default's.
	from, until := testNow, testNow.AddDate(1, 1, 0)
	if cert, err := x509.ParseCertificate(der); err == nil {
		from, until = cert.NotBefore, cert.NotAfter
	}
	issuer := x.spec.issuer
	if issuer == nil {
		issuer = &x.kit.a
	}
	pin := x.issuerPin
	if pin == "" {
		pin = issuer.pin
	}
	seq := x.sequence
	if seq == 0 {
		seq = x.kit.sequence
	}
	m := map[string]any{
		"handoff": 1, "type": "x509-intermediate",
		"request_sha256": sha256Hex(x.csr.der),
		"outcome":        "issued",
		"artifacts":      []map[string]any{{"name": x.stem + ".cert.pem", "sha256": sha256Hex(file)}},
		"valid_from":     formatTime(from), "valid_until": formatTime(until),
		"issuer": pin, "trust_sequence": seq,
	}
	for _, e := range x.edits {
		e(m)
	}
	out, err := json.Marshal(m)
	if err != nil {
		x.t.Fatal(err)
	}
	return map[string][]byte{answer.FileResult: out, answer.FileCert: file}
}

func (x *x509Case) answer() *answer.Answer {
	x.t.Helper()
	return &answer.Answer{Stem: x.stem, Files: x.files()}
}

// check runs the checker of the kit on the case.
func (x *x509Case) check(chk *answer.Checker) (answer.Verdict, error) {
	x.t.Helper()
	return chk.Check(x.csr.asked(x.t), x.answer())
}

// want asserts the verdict: the code ("" for an acceptance), the statuses and no error.
func want(t testing.TB, v answer.Verdict, err error, code answer.Code, statusString string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Check returned %v", err)
	}
	if v.Code != code {
		t.Fatalf("code %q (detail %q), want %q; statuses %s", v.Code, v.Detail, code, statuses(v))
	}
	if got := statuses(v); got != statusString {
		t.Fatalf("statuses %s, want %s (code %q, detail %q)", got, statusString, v.Code, v.Detail)
	}
	// The words of a refusal are printable ASCII: no byte of the answer is in them.
	for i := 0; i < len(v.Detail); i++ {
		if v.Detail[i] < 0x20 || v.Detail[i] > 0x7e {
			t.Fatalf("the detail %q holds a byte that is not printable ASCII", v.Detail)
		}
	}
	// A check that ran says no reason; a check that did not run says why.
	for _, c := range v.Checks {
		if (c.Status == handoff.StatusNotRun) != (c.Reason != "") {
			t.Fatalf("check %d is %s and its reason is %q", c.N, c.Status, c.Reason)
		}
	}
	if code == "" {
		if !v.Accepted() || v.Info == nil {
			t.Fatalf("not accepted: %+v", v)
		}
	} else if v.Accepted() || v.Info != nil {
		t.Fatalf("a refusal is accepted or holds Info: %+v", v)
	}
}

func parseCert(der []byte) (*x509.Certificate, error) { return x509.ParseCertificate(der) }
