package rootlist_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
)

// Every key of these tests is made in memory and written nowhere. The names are the example names
// of the repository: the root keys are A, B and C (C is added by a list), and Z is on no list.

const (
	typList    = "root-list+json"
	typRemoval = "root-removal+json"
)

// The times of the lists the tests write, and the clock that sits between them.
const (
	signedAt  = "2026-11-15T12:00:00Z"
	expiresAt = "2027-12-15T12:00:00Z"
	clockText = "2026-12-01T12:00:00Z"
)

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

var now = mustTime(clockText)

// key is a signing key with the label it has on a list and its self-signed certificate.
type key struct {
	label string
	priv  *ecdsa.PrivateKey
	cert  *x509.Certificate
	pin   string
}

func newKeyOn(t testing.TB, label string, curve elliptic.Curve) *key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("make key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Test Root " + label},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("make certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("read certificate: %v", err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return &key{label: label, priv: priv, cert: cert, pin: hex.EncodeToString(sum[:])}
}

func newKey(t testing.TB, label string) *key { return newKeyOn(t, label, elliptic.P384()) }

// fp is the OpenPGP fingerprint that the tests give a key: 40 lower-case hexadecimal digits.
func (k *key) fp() string { return k.pin[:40] }

func (k *key) x5c() string { return base64.StdEncoding.EncodeToString(k.cert.Raw) }

// certPEM is the certificate as one PEM block, as a CA bundle holds it.
func (k *key) certPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.cert.Raw}))
}

func (k *key) rawSign(t testing.TB, input []byte) []byte {
	t.Helper()
	sum := sha512.Sum384(input)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// A key on a larger curve has an r or s that does not fit: the low 48 bytes are written.
	out := make([]byte, 96)
	copy(out[:48], lowBytes(r.Bytes(), 48))
	copy(out[48:], lowBytes(s.Bytes(), 48))
	return out
}

// lowBytes returns n bytes: b with zeros before it, or its last n bytes.
func lowBytes(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	return append(make([]byte, n-len(b)), b...)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// world is the four keys that most tests use. They are made once.
type world struct{ a, b, c, z *key }

var (
	worldOnce sync.Once
	theWorld  *world
)

func newWorld(t testing.TB) *world {
	t.Helper()
	worldOnce.Do(func() {
		theWorld = &world{a: newKey(t, "A"), b: newKey(t, "B"), c: newKey(t, "C"), z: newKey(t, "Z")}
	})
	return theWorld
}

// header is a protected header as text, member by member, so that a test can write one that no
// honest writer would. A member is written only when it is not empty.
type header struct {
	alg, kid, typ string // JSON text of the value, with its quotes
	x5c           string // JSON text of the value, with its brackets
	extra         string // more members, each starting with a comma
	drop          string // a member to leave out
}

func goodHeader(k *key, typ string) header {
	return header{alg: `"ES384"`, kid: `"` + k.pin + `"`, typ: `"` + typ + `"`, x5c: `["` + k.x5c() + `"]`}
}

func (h header) json() string {
	var parts []string
	add := func(name, val string) {
		if h.drop != name && val != "" {
			parts = append(parts, `"`+name+`":`+val)
		}
	}
	add("alg", h.alg)
	add("kid", h.kid)
	add("typ", h.typ)
	add("x5c", h.x5c)
	return "{" + strings.Join(parts, ",") + h.extra + "}"
}

func (h header) text() string { return b64u([]byte(h.json())) }

func sigOver(t testing.TB, k *key, protected string, payload []byte) string {
	t.Helper()
	return b64u(k.rawSign(t, []byte(protected+"."+b64u(payload))))
}

func entry(protected, signature string) string {
	return `{"protected":"` + protected + `","signature":"` + signature + `"}`
}

func jwsFile(entries ...string) []byte {
	return []byte(`{"signatures":[` + strings.Join(entries, ",") + `]}`)
}

func goodEntry(t testing.TB, k *key, typ string, payload []byte) string {
	t.Helper()
	p := goodHeader(k, typ).text()
	return entry(p, sigOver(t, k, p, payload))
}

// sign writes the root-list.jws that the signers sign over payload, in the order given.
func sign(t testing.TB, payload []byte, signers ...*key) []byte {
	t.Helper()
	entries := make([]string, len(signers))
	for i, k := range signers {
		entries[i] = goodEntry(t, k, typList, payload)
	}
	return jwsFile(entries...)
}

// authorisation is the removal authorisation of k: a compact JWS over the pin, as the page says.
func authorisation(t testing.TB, k *key) string {
	t.Helper()
	return authWith(t, k, goodHeader(k, typRemoval), removalPayload(k.pin))
}

func removalPayload(pin string) []byte {
	return []byte(`{"version":1,"x509_spki_sha256":"` + pin + `"}`)
}

// authWith signs payload with signer under the header h, and writes the compact JWS.
func authWith(t testing.TB, signer *key, h header, payload []byte) string {
	t.Helper()
	p := h.text()
	return p + "." + b64u(payload) + "." + sigOver(t, signer, p, payload)
}

// rootSpec is an entry of roots as the tests write it.
type rootSpec struct {
	label, pin, fp string
	noFP           bool
}

func rootOf(k *key) rootSpec { return rootSpec{label: k.label, pin: k.pin, fp: k.fp()} }

// removalSpec is an entry of removals.
type removalSpec struct{ label, pin, auth string }

func removalOf(t testing.TB, k *key) removalSpec {
	return removalSpec{label: k.label, pin: k.pin, auth: authorisation(t, k)}
}

// spec is a list as the tests write it, in the canonical form: members in the order of RFC 8785,
// no white space. A text member holds JSON text, so that a test can write a value that is wrong.
type spec struct {
	version, sequence, signedAt, expiresAt string
	last                                   string // the digest, with no quotes; "" is the default
	noLast                                 bool
	roots                                  []rootSpec
	removals                               []removalSpec
	hasRemovals                            bool
}

const defaultLast = "4392706aef367339fb0b77f4adf5ca2377c2ffc8dcd869ba6caf1800b69109cc"

func listOf(seq int, keys ...*key) spec {
	s := spec{sequence: strconv.Itoa(seq)}
	for _, k := range keys {
		s.roots = append(s.roots, rootOf(k))
	}
	return s
}

// at signs the list at the given time (RFC 3339, UTC) and gives it the expiry that the page asks of
// it: 13 calendar months later. Both are set from the one time, so that a list is of the shape that
// check 5 accepts, whatever its day.
func (s spec) at(signed string) spec {
	s.signedAt = `"` + signed + `"`
	s.expiresAt = `"` + rootlist.ExpiresFor(mustTime(signed)).Format(rootlist.TimeLayout) + `"`
	return s
}

// longAgo is a signing time whose expiry, 13 months later, is before the clock of most tests.
const longAgo = "2025-10-15T12:00:00Z"

func (s spec) withRemovals(r ...removalSpec) spec {
	s.removals, s.hasRemovals = r, true
	return s
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func (s spec) json() []byte {
	var b strings.Builder
	b.WriteString(`{"expires_at":` + or(s.expiresAt, `"`+expiresAt+`"`))
	if !s.noLast {
		b.WriteString(`,"last_record_sha256":"` + or(s.last, defaultLast) + `"`)
	}
	if s.hasRemovals {
		b.WriteString(`,"removals":[`)
		for i, r := range s.removals {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{"authorisation":"` + r.auth + `","label":"` + r.label + `","x509_spki_sha256":"` + r.pin + `"}`)
		}
		b.WriteString(`]`)
	}
	b.WriteString(`,"roots":[`)
	for i, r := range s.roots {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"label":"` + r.label + `"`)
		if !r.noFP {
			b.WriteString(`,"openpgp_fingerprint":"` + r.fp + `"`)
		}
		b.WriteString(`,"x509_spki_sha256":"` + r.pin + `"}`)
	}
	b.WriteString(`],"sequence":` + or(s.sequence, "7"))
	b.WriteString(`,"signed_at":` + or(s.signedAt, `"`+signedAt+`"`))
	b.WriteString(`,"version":` + or(s.version, "1") + `}`)
	return []byte(b.String())
}

// signed is a list written and signed by signers.
func signed(t testing.TB, s spec, signers ...*key) rootlist.Signed {
	t.Helper()
	data := s.json()
	return rootlist.Signed{JSON: data, JWS: sign(t, data, signers...)}
}

// replace changes the first old in data to repl and fails the test when old is not there, so that a
// test cannot pass because its edit found nothing to edit.
func replace(t testing.TB, data []byte, old, repl string) []byte {
	t.Helper()
	if old == repl {
		t.Fatalf("the edit of %q changes nothing", old)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("the text %q is not in %q", old, data)
	}
	return []byte(strings.Replace(string(data), old, repl, 1))
}

// heldOf reads a list the host holds.
func heldOf(t testing.TB, s spec) rootlist.Trust {
	t.Helper()
	h, err := rootlist.ParseHeld(s.json())
	if err != nil {
		t.Fatalf("the held list: %v", err)
	}
	return rootlist.HeldTrust(h)
}

func pinsOf(t testing.TB, pins ...string) rootlist.Trust {
	t.Helper()
	tr, err := rootlist.PinTrust(pins)
	if err != nil {
		t.Fatalf("the pins: %v", err)
	}
	return tr
}

// printable reports whether s holds bytes 0x20 to 0x7e only.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func mustBeASCII(t testing.TB, what, s string) {
	t.Helper()
	if !printable(s) {
		t.Errorf("%s is not printable ASCII: %q", what, s)
	}
}

// accepts fails the test unless the verdict accepts, and checks what an acceptance must look like.
func accepts(t testing.TB, v rootlist.Verdict) {
	t.Helper()
	if !v.Accepted {
		t.Fatalf("refused with %s at check %d: %s", v.Reason, v.Check, v.Detail)
	}
	if v.Reason != "" || v.Check != 0 || v.Detail != "" || v.List == nil {
		t.Errorf("an acceptance must have no reason, check or detail, and the list: %+v", v)
	}
	if v.Again {
		t.Errorf("a list that is new is not the held list again: %+v", v)
	}
}

// acceptsAgain fails the test unless the verdict accepts the held list received again.
func acceptsAgain(t testing.TB, v rootlist.Verdict) {
	t.Helper()
	if !v.Accepted {
		t.Fatalf("refused with %s at check %d: %s", v.Reason, v.Check, v.Detail)
	}
	if v.Reason != "" || v.Check != 0 || v.Detail != "" || v.List == nil || !v.Again {
		t.Errorf("the held list again is accepted with no reason, check or detail, the list, and Again: %+v", v)
	}
}

// refuses fails the test unless the verdict refuses with that reason at that check, and checks what
// a refusal must look like.
func refuses(t testing.TB, v rootlist.Verdict, reason rootlist.Reason, check int) {
	t.Helper()
	if v.Accepted {
		t.Fatalf("accepted; want %s at check %d", reason, check)
	}
	if v.Reason != reason || v.Check != check {
		t.Fatalf("refused with %q at check %d (%s); want %q at check %d", v.Reason, v.Check, v.Detail, reason, check)
	}
	if v.List != nil || v.Again {
		t.Errorf("a refusal carries a list or says Again: %+v", v)
	}
	if v.Detail == "" {
		t.Errorf("a refusal has no detail")
	}
	mustBeASCII(t, "Detail", v.Detail)
}

// base is the case that most tests start from: the host holds the list of sequence 7 with A and B,
// and a list of sequence 8 with the same root keys, signed by A, arrives.
type base struct {
	w    *world
	held spec
	cand spec
}

func newBase(t testing.TB) *base {
	w := newWorld(t)
	return &base{w: w, held: listOf(7, w.a, w.b), cand: listOf(8, w.a, w.b)}
}

func (b *base) trust(t testing.TB) rootlist.Trust { return heldOf(t, b.held) }

// ok verifies a candidate written from the spec and signed by signers against the held list.
func (b *base) verify(t testing.TB, s spec, signers ...*key) rootlist.Verdict {
	t.Helper()
	return rootlist.Verify(signed(t, s, signers...), b.trust(t), now)
}

const payloadSep = "-"

func stdB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func hexOf(b []byte) string { return hex.EncodeToString(b) }

// padded adds the padding that Base64url does without.
func padded(s string) string {
	for len(s)%4 != 0 {
		s += "="
	}
	return s + "="
}

func bytesOf(v byte, n int) []byte { return bytes.Repeat([]byte{v}, n) }

// der103 is an ASN.1 sequence of two integers with the 48-byte r and the 49-byte s (a leading zero
// keeps it positive): the form that a library of ECDSA writes, 103 bytes.
func der103() []byte {
	r := bytes.Repeat([]byte{0x01}, 48)
	s := append([]byte{0x00}, bytes.Repeat([]byte{0x81}, 48)...)
	out := []byte{0x30, 0x65, 0x02, 0x30}
	out = append(out, r...)
	out = append(out, 0x02, 0x31)
	out = append(out, s...)
	return out
}

// jwsPinOf is the pin of a certificate, from its public key (the test's own computation).
func jwsPinOf(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
