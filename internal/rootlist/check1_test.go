package rootlist_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

func TestCheck1TheJWSMustBeOfTheForm(t *testing.T) {
	b := newBase(t)
	w := b.w
	payload := b.cand.json()
	trust := b.trust(t)
	goodSig := func() string { return sigOver(t, w.a, goodHeader(w.a, typList).text(), payload) }
	one := func(edit func(*header)) []byte {
		h := goodHeader(w.a, typList)
		edit(&h)
		p := h.text()
		return jwsFile(entry(p, sigOver(t, w.a, p, payload)))
	}
	protected := goodHeader(w.a, typList).text()
	sig := w.a.rawSign(t, []byte(protected+"."+b64u(payload)))
	asn1sig, err := ecdsa.SignASN1(rand.Reader, w.a.priv, func() []byte { s := sha512.Sum384([]byte("x")); return s[:] }())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		jws  []byte
	}{
		{"alg none", one(func(h *header) { h.alg = `"none"` })},
		{"alg ES256", one(func(h *header) { h.alg = `"ES256"` })},
		{"alg es384", one(func(h *header) { h.alg = `"es384"` })},
		{"alg ES384 with a Cyrillic E", one(func(h *header) { h.alg = "\"\u0415S384\"" })},
		{"alg missing", one(func(h *header) { h.drop = "alg" })},
		{"typ missing", one(func(h *header) { h.drop = "typ" })},
		{"typ of the removal authorisation", one(func(h *header) { h.typ = `"` + typRemoval + `"` })},
		{"typ in upper case", one(func(h *header) { h.typ = `"ROOT-LIST+JSON"` })},
		{"typ with a trailing space", one(func(h *header) { h.typ = `"root-list+json "` })},
		{"typ of the SSH CA key list", one(func(h *header) { h.typ = `"ssh-ca-key-list+json"` })},
		{"crit", one(func(h *header) { h.extra = `,"crit":["b64"]` })},
		{"b64", one(func(h *header) { h.extra = `,"b64":false` })},
		{"jwk", one(func(h *header) { h.extra = `,"jwk":{"kty":"EC","crv":"P-384"}` })},
		{"jku", one(func(h *header) { h.extra = `,"jku":"https://example.org/keys"` })},
		{"x5u", one(func(h *header) { h.extra = `,"x5u":"https://example.org/cert"` })},
		{"zip", one(func(h *header) { h.extra = `,"zip":"DEF"` })},
		{"cty", one(func(h *header) { h.extra = `,"cty":"json"` })},
		{"a second kid", one(func(h *header) { h.extra = `,"kid":"` + w.b.pin + `"` })},
		{"a second typ", one(func(h *header) { h.extra = `,"typ":"root-list+json"` })},
		{"a second alg", one(func(h *header) { h.extra = `,"alg":"ES384"` })},
		{"Alg in another case", one(func(h *header) { h.extra = `,"Alg":"ES384"` })},
		{"two certificates", one(func(h *header) { h.x5c = `["` + w.a.x5c() + `","` + w.b.x5c() + `"]` })},
		{"the same certificate twice", one(func(h *header) { h.x5c = `["` + w.a.x5c() + `","` + w.a.x5c() + `"]` })},
		{"no certificate", one(func(h *header) { h.x5c = `[]` })},
		{"x5c missing", one(func(h *header) { h.drop = "x5c" })},
		{"x5c a string", one(func(h *header) { h.x5c = `"` + w.a.x5c() + `"` })},
		{"the certificate of another key under A's kid", one(func(h *header) { h.x5c = `["` + w.b.x5c() + `"]` })},
		{"the kid of another key", one(func(h *header) { h.kid = `"` + w.b.pin + `"` })},
		{"the kid in upper case", one(func(h *header) { h.kid = `"` + strings.ToUpper(w.a.pin) + `"` })},
		{"the kid with a space", one(func(h *header) { h.kid = `"` + w.a.pin + ` "` })},
		{"a line feed in the x5c text", one(func(h *header) { c := w.a.x5c(); h.x5c = `["` + c[:20] + `\n` + c[20:] + `"]` })},
		{"x5c without padding", one(func(h *header) { h.x5c = `["` + strings.TrimRight(w.a.x5c(), "=") + `X"]` })},
		{"a line feed in the protected text", jwsFile(entry(protected[:20]+`\n`+protected[20:], b64u(sig)))},
		{"a carriage return and line feed in the protected text", jwsFile(entry(protected[:20]+`\r\n`+protected[20:], b64u(sig)))},
		{"padding on the protected text", jwsFile(entry(protected+"=", b64u(sig)))},
		{"a line feed in the signature", jwsFile(entry(protected, b64u(sig)[:20]+`\n`+b64u(sig)[20:]))},
		{"padding on the signature", jwsFile(entry(protected, b64u(sig)+"="))},
		{"standard Base64 in the signature", jwsFile(entry(protected, strings.NewReplacer("-", "+", "_", "/").Replace(strings.Repeat("-_", 64))))},
		{"a signature of 95 bytes", jwsFile(entry(protected, b64u(sig[:95])))},
		{"a signature of 97 bytes", jwsFile(entry(protected, b64u(append(bytes.Clone(sig), 0))))},
		{"a signature in the ASN.1 form", jwsFile(entry(protected, b64u(asn1sig)))},
		{"an empty signature", jwsFile(entry(protected, ""))},
		{"the same kid twice", jwsFile(entry(protected, goodSig()), entry(protected, goodSig()))},
		{"a payload member", []byte(`{"payload":"` + b64u(payload) + `","signatures":[` + entry(protected, goodSig()) + `]}`)},
		{"an unprotected header", []byte(`{"signatures":[{"header":{"kid":"x"},"protected":"` + protected + `","signature":"` + goodSig() + `"}]}`)},
		{"the flattened form", []byte(entry(protected, goodSig()))},
		{"no signatures", []byte(`{"signatures":[]}`)},
		{"an empty file", nil},
		{"a file of one byte", []byte("{")},
		{"a removal authorisation as a list signature", jwsFile(goodEntry(t, w.a, typRemoval, payload))},
		{"a list signature over a removal payload", jwsFile(goodEntry(t, w.a, typRemoval, removalPayload(w.a.pin)))},
		{"the compact form of a removal authorisation", []byte(authorisation(t, w.a))},
		{"a good signature and a second with the wrong type", jwsFile(goodEntry(t, w.a, typList, payload), goodEntry(t, w.b, typRemoval, payload))},
		{"a good signature and a second with the kid of the first", jwsFile(goodEntry(t, w.a, typList, payload), entry(goodHeader(w.a, typList).text(), goodSig()))},
		{"a trusted signer and an unknown one with a broken form", jwsFile(goodEntry(t, w.a, typList, payload), one2(t, w.z, payload))},
		{"every byte of a good file but the last", jwsFile(goodEntry(t, w.a, typList, payload))[:len(jwsFile(goodEntry(t, w.a, typList, payload)))-1]},
		{"a good file with a byte after it", append(jwsFile(goodEntry(t, w.a, typList, payload)), 'x')},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := rootlist.Verify(rootlist.Signed{JSON: payload, JWS: c.jws}, trust, now)
			refuses(t, v, rootlist.Malformed, 1)
		})
	}
	t.Run("the witness: the same payload with a good file is accepted", func(t *testing.T) {
		accepts(t, rootlist.Verify(rootlist.Signed{JSON: payload, JWS: sign(t, payload, w.a)}, trust, now))
	})
	t.Run("a P-256 key is read, and refused later", func(t *testing.T) {
		p := newKeyOn(t, "P", elliptic.P256())
		held := listOf(7, p)
		cand := listOf(8, p)
		v := rootlist.Verify(signed(t, cand, p), heldOf(t, held), now)
		refuses(t, v, rootlist.SignatureInvalid, 3)
	})
}

// one2 is an entry with a header that has an extra member, signed by k: a broken form.
func one2(t *testing.T, k *key, payload []byte) string {
	t.Helper()
	h := goodHeader(k, typList)
	h.extra = `,"crit":["b64"]`
	p := h.text()
	return entry(p, sigOver(t, k, p, payload))
}
