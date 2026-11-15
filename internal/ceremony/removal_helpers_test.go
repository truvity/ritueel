//go:build linux || darwin

package ceremony_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// A removal authorisation written by hand, as the page of the root list gives it: a compact JWS
// "<header>.<payload>.<signature>", Base64url without padding, the payload
// {"version":1,"x509_spki_sha256":"<pin>"}, and a header with alg ES384, kid the pin, typ
// root-removal+json and x5c the one certificate of the key.

// mkRemovalSpec describes one. The zero value of a field means "as the page says".
type mkRemovalSpec struct {
	Key     *ecdsa.PrivateKey // the key of the certificate; made if nil
	Cert    []byte            // the certificate in x5c; one is made for the key if nil
	SignKey *ecdsa.PrivateKey // signs, when it is not the key
	Pin     string            // the pin in kid and payload; that of Key if empty
	KidOnly string            // another kid, when not empty
	Typ     string            // root-removal+json when empty
	Alg     string            // ES384 when empty
	Payload string            // the payload text, when not empty
	X5C     []string          // replaces x5c, when not nil
	Extra   map[string]any    // more members of the header
}

// mkRemoval is the result: the text, and the certificate and pin that belong to it.
type mkRemoval struct {
	Text string
	Cert []byte
	Pin  string
	Key  *ecdsa.PrivateKey
}

func (s mkRemovalSpec) build() mkRemoval {
	key := s.Key
	if key == nil {
		key = mkKeyP384()
	}
	cert := s.Cert
	if cert == nil {
		cert = mkCertSpec{Key: key}.build().DER
	}
	pin := s.Pin
	if pin == "" {
		pin = mkPin(&key.PublicKey)
	}
	kid := pin
	if s.KidOnly != "" {
		kid = s.KidOnly
	}
	typ, alg := s.Typ, s.Alg
	if typ == "" {
		typ = "root-removal+json"
	}
	if alg == "" {
		alg = "ES384"
	}
	x5c := s.X5C
	if x5c == nil {
		x5c = []string{base64.StdEncoding.EncodeToString(cert)}
	}
	// The canonical form of RFC 8785 sorts the members by name: alg, kid, typ, x5c.
	hdr := map[string]any{"alg": alg, "kid": kid, "typ": typ, "x5c": x5c}
	for k, v := range s.Extra {
		hdr[k] = v
	}
	hb, err := json.Marshal(hdr) // json.Marshal sorts map keys and writes no space
	if err != nil {
		panic(err)
	}
	protected := base64.RawURLEncoding.EncodeToString(hb)
	payload := s.Payload
	if payload == "" {
		payload = `{"version":1,"x509_spki_sha256":"` + pin + `"}`
	}
	input := protected + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	signer := s.SignKey
	if signer == nil {
		signer = key
	}
	digest := sha512.Sum384([]byte(input))
	r, ss, err := ecdsa.Sign(rand.Reader, signer, digest[:])
	if err != nil {
		panic(err)
	}
	sig := append(r.FillBytes(make([]byte, 48)), ss.FillBytes(make([]byte, 48))...)
	text := input + "." + base64.RawURLEncoding.EncodeToString(sig)
	return mkRemoval{Text: text, Cert: cert, Pin: pin, Key: key}
}

// mkRemovalParts splits a text into its three parts.
func mkRemovalParts(text string) (h, p, s string) {
	parts := strings.Split(text, ".")
	return parts[0], parts[1], parts[2]
}
