package jws_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The tests of this package make every key in memory and write none of them anywhere.

// typList and typRemoval are the two types of signed documents of the page.
const (
	typList    = "root-list+json"
	typRemoval = "root-removal+json"
)

// key is a signing key with its self-signed certificate. The certificate only carries the public
// key, as the page says of x5c.
type key struct {
	priv *ecdsa.PrivateKey
	cert *x509.Certificate
	pin  string
}

func newKeyOn(t testing.TB, curve elliptic.Curve) *key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("make key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Test Root"},
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
	return &key{priv: priv, cert: cert, pin: hex.EncodeToString(sum[:])}
}

func newKey(t testing.TB) *key { return newKeyOn(t, elliptic.P384()) }

// x5c is the one entry of the header: the certificate as standard Base64 with padding.
func (k *key) x5c() string { return base64.StdEncoding.EncodeToString(k.cert.Raw) }

// rawSign signs input with ES384 and returns r and s as 48 bytes each.
func (k *key) rawSign(t testing.TB, input []byte) []byte {
	t.Helper()
	sum := sha512.Sum384(input)
	r, s, err := ecdsa.Sign(rand.Reader, k.priv, sum[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out := make([]byte, 96)
	r.FillBytes(out[:48])
	s.FillBytes(out[48:])
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// header describes a protected header as text, member by member, so that a test can write a header
// that no honest writer would. A member is written only when it is not empty; raw members are
// written as they are.
type header struct {
	alg, kid, typ string // JSON text of the value, with its quotes
	x5c           string // JSON text of the value, with its brackets
	extra         string // more members, each starting with a comma
	drop          string // a member to leave out: alg, kid, typ or x5c
}

// goodHeader is the header of the page for k and typ.
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

// text is the Base64url of the header's JSON: the protected text.
func (h header) text() string { return b64u([]byte(h.json())) }

// sigOver returns the signature of k over protected || "." || BASE64URL(payload), as text.
func sigOver(t testing.TB, k *key, protected string, payload []byte) string {
	t.Helper()
	return b64u(k.rawSign(t, []byte(protected+"."+b64u(payload))))
}

// entry is one object of "signatures".
func entry(protected, signature string) string {
	return `{"protected":"` + protected + `","signature":"` + signature + `"}`
}

// file is a root-list.jws with the given entries.
func file(entries ...string) []byte {
	return []byte(`{"signatures":[` + strings.Join(entries, ",") + `]}`)
}

// goodEntry is the entry that k signs over payload with typ.
func goodEntry(t testing.TB, k *key, typ string, payload []byte) string {
	t.Helper()
	p := goodHeader(k, typ).text()
	return entry(p, sigOver(t, k, p, payload))
}

// compact is a compact JWS from its three texts.
func compact(protected, payload, signature string) string {
	return protected + "." + payload + "." + signature
}

// goodCompact is the compact JWS of k over payload with typ.
func goodCompact(t testing.TB, k *key, typ string, payload []byte) string {
	t.Helper()
	p := goodHeader(k, typ).text()
	return compact(p, b64u(payload), sigOver(t, k, p, payload))
}

// printable reports whether s is printable ASCII only: bytes 0x20 to 0x7e.
func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// mustBeASCII fails the test when s holds anything but printable ASCII.
func mustBeASCII(t testing.TB, what, s string) {
	t.Helper()
	if !printable(s) {
		t.Errorf("%s is not printable ASCII: %q", what, s)
	}
}

// fixture is a key with a signed entry, for the tests that break one part of a good file. The key
// is made again until the certificate and the signature hold a character that only one alphabet of
// Base64 has, so that a swap of the alphabets changes their text. (The protected text never holds
// one: the header is ASCII, and an ASCII text writes only the first 62 characters of either alphabet.)
type fixture struct {
	k, other  *key
	payload   []byte
	protected string // the good protected text
	sig       string // the good signature text
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	for range 200 {
		k := newKey(t)
		h := goodHeader(k, typList).text()
		payload := []byte(`{"sequence":7}`)
		sig := sigOver(t, k, h, payload)
		if strings.ContainsAny(sig, "-_") && strings.ContainsAny(k.x5c(), "+/") {
			return &fixture{k: k, other: newKey(t), payload: payload, protected: h, sig: sig}
		}
	}
	t.Fatal("no key whose texts hold both alphabets in 200 tries")
	return nil
}

func (f *fixture) entry() string { return entry(f.protected, f.sig) }

// swapAlphabet writes Base64url as standard Base64 and the reverse, on the characters that differ.
func swapAlphabet(s string) string {
	return strings.NewReplacer("-", "+", "_", "/", "+", "-", "/", "_").Replace(s)
}

// variant is a text with the reason it is not the one spelling of a Base64 text.
type variant struct{ name, text string }

// b64Variants returns the spellings of canonical that a strict reader refuses. canonical is the
// one spelling of Base64url without padding, or, when std is set, of standard Base64 with padding.
// A text is JSON string content, so a line break is the escape that a JSON reader turns into one:
// the decoder of Go skips it, and only a check of the text itself can refuse it.
func b64Variants(canonical string, std bool) []variant {
	mid := len(canonical) / 2
	out := []variant{
		{"line feed in the middle", canonical[:mid] + `\n` + canonical[mid:]},
		{"carriage return and line feed in the middle", canonical[:mid] + `\r\n` + canonical[mid:]},
		{"carriage return in the middle", canonical[:mid] + `\r` + canonical[mid:]},
		{"line feed at the end", canonical + `\n`},
		{"line feed at the start", `\n` + canonical},
		{"space in the middle", canonical[:mid] + " " + canonical[mid:]},
		{"tab in the middle", canonical[:mid] + `\t` + canonical[mid:]},
		{"a character outside both alphabets", canonical[:mid] + "*" + canonical[mid+1:]},
		{"empty", ""},
	}
	if swapped := swapAlphabet(canonical); swapped != canonical {
		out = append(out, variant{"the other alphabet", swapped})
	}
	if std {
		if trimmed := strings.TrimRight(canonical, "="); trimmed != canonical {
			out = append(out, variant{"padding removed", trimmed})
		}
		out = append(out, variant{"extra padding", canonical + "="})
	} else {
		out = append(out, variant{"padding added", canonical + strings.Repeat("=", 1+(4-len(canonical)%4)%4)})
		out = append(out, variant{"one padding character", canonical + "="})
	}
	if v, ok := nonZeroPaddingBits(canonical); ok {
		out = append(out, variant{"padding bits that are not zero", v})
	}
	short := canonical
	for len(short)%4 != 1 && len(short) > 0 {
		short = short[:len(short)-1]
	}
	if len(short) > 0 && !std {
		out = append(out, variant{"a length that no byte string has", short})
	}
	return out
}

const alphabetURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// nonZeroPaddingBits changes the last character of a text that has padding bits to the next one,
// which sets a bit that the decoded bytes do not hold. It reports false when the text has none.
func nonZeroPaddingBits(s string) (string, bool) {
	t := strings.TrimRight(s, "=")
	if len(t) == 0 {
		return "", false
	}
	std := strings.ContainsAny(s, "=") // padded text is standard Base64
	idx := strings.IndexByte(alphabetURL, t[len(t)-1])
	if std {
		idx = strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", t[len(t)-1])
	}
	var mask int
	switch len(t) % 4 {
	case 2:
		mask = 0x0f
	case 3:
		mask = 0x03
	default:
		return "", false
	}
	if idx < 0 || idx&mask != 0 || idx+1 > 63 {
		return "", false
	}
	alphabet := alphabetURL
	if std {
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	}
	return t[:len(t)-1] + string(alphabet[idx+1]) + s[len(t):], true
}

func stdB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// marshalPKIX is the DER SubjectPublicKeyInfo of the key.
func marshalPKIX(t testing.TB, k *key) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// certPin is the SHA-256 of the whole certificate, which is not the pin.
func certPin(k *key) string {
	sum := sha256.Sum256(k.cert.Raw)
	return hex.EncodeToString(sum[:])
}

// flipHex returns another hexadecimal digit than c.
func flipHex(c byte) string {
	if c == '0' {
		return "1"
	}
	return "0"
}

// hex4 is the four hexadecimal digits of a byte, for a \u escape.
func hex4(c byte) string { return "00" + hex.EncodeToString([]byte{c}) }

// upperFirstLetter writes the first letter a to f of a hexadecimal text in upper case.
func upperFirstLetter(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'f' {
			return s[:i] + strings.ToUpper(s[i:i+1]) + s[i+1:]
		}
	}
	return s + "A"
}
