package attest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/strictjson"
)

// Attestation is the first two certificates of the evidence of a proof: the certificate of the key (for
// piv the slot certificate) and the certificate of the token that signed it. Entries from the third are
// not read: only the roots and intermediates that the certifier pinned lead a chain to its end (record 0003,
// rule 18).
type Attestation struct {
	// Leaf is the key's certificate.
	Leaf *x509.Certificate
	// Token is the token's own certificate.
	Token *x509.Certificate
}

// wireEvidence is the evidence of piv and openpgp-card as the strict reader fills it.
type wireEvidence struct {
	Attestation []string `json:"attestation"`
}

// refuse makes the refusal of the evidence with fixed words.
func refuse(detail string) error {
	return &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: detail}
}

// malformed makes the refusal of a shape that is not the page's, with fixed words.
func malformed(detail string) error {
	return &handoff.CodeError{Code: handoff.CodeMalformed, Detail: detail}
}

// ParseAttestation reads {"attestation": [...]} (the evidence member of a proof of the stores piv and
// openpgp-card) with the strict JSON reader: exactly that one member, a list of 2 to
// [handoff.MaxAttestation] strings, each standard Base64 with padding in its one canonical spelling, and
// at most [handoff.MaxFileSize] bytes. It then parses the first two entries as one DER certificate each,
// at most [MaxCertificateSize] bytes with nothing after the DER. The key's certificate is not a CA and is
// not the token's certificate, and the token's certificate is a CA with a path length of exactly 0. The
// entries from the third are checked for their spelling and are not read.
//
// A refusal is a *[handoff.CodeError]: malformed for the shape of the evidence, proof-invalid for a
// certificate that is too large, does not parse, is the same as the other, or is not what a key's
// certificate or a token's certificate may be. The result is nil beside an error.
func ParseAttestation(evidence []byte) (*Attestation, error) {
	if len(evidence) == 0 || len(evidence) > handoff.MaxFileSize {
		return nil, malformed("the evidence is empty or longer than the limit of a file")
	}
	var w wireEvidence
	if err := strictjson.Unmarshal(evidence, &w, strictjson.Options{MaxBytes: handoff.MaxFileSize}); err != nil {
		return nil, malformed("the evidence is not an object with the one member attestation")
	}
	if len(w.Attestation) < 2 {
		return nil, malformed("the attestation is not a list of two or more certificates")
	}
	if len(w.Attestation) > handoff.MaxAttestation {
		return nil, malformed("the attestation holds too many certificates")
	}
	ders := make([][]byte, len(w.Attestation))
	for i, s := range w.Attestation {
		der, ok := canonicalBase64(s)
		if !ok {
			return nil, malformed("an attested certificate is not Base64 of a DER value")
		}
		ders[i] = der
	}
	leaf, err := parseCertificate(ders[0])
	if err != nil {
		return nil, err
	}
	token, err := parseCertificate(ders[1])
	if err != nil {
		return nil, err
	}
	a := &Attestation{Leaf: leaf, Token: token}
	if err := checkRoles(a); err != nil {
		return nil, err
	}
	return a, nil
}

// canonicalBase64 decodes standard Base64 with padding in its one canonical spelling, of at least one
// byte: no line break, no missing padding, no bit left over.
func canonicalBase64(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(b) == 0 || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// parseCertificate reads one DER certificate of at most MaxCertificateSize bytes with nothing after it.
func parseCertificate(der []byte) (*x509.Certificate, error) {
	if len(der) > MaxCertificateSize {
		return nil, refuse("a certificate of the attestation is larger than the limit")
	}
	c, err := x509.ParseCertificate(der)
	if err != nil || len(c.Raw) != len(der) {
		return nil, refuse("a certificate of the attestation does not parse as one DER certificate")
	}
	return c, nil
}

// checkRoles is the part of the page's list order that a certificate alone shows: the two are two
// certificates, the first is not a CA, and the second is a CA with path length 0. Nil members are a fault
// of the caller.
func checkRoles(a *Attestation) error {
	if a == nil || a.Leaf == nil || a.Token == nil {
		return errors.New("attest: the attestation is not whole")
	}
	if bytes.Equal(a.Leaf.Raw, a.Token.Raw) {
		return refuse("the key's certificate and the token's certificate are the same certificate")
	}
	if a.Leaf.BasicConstraintsValid && a.Leaf.IsCA {
		return refuse("the key's certificate is a CA certificate")
	}
	t := a.Token
	if !t.BasicConstraintsValid || !t.IsCA || t.MaxPathLen != 0 || !t.MaxPathLenZero {
		return refuse("the token's certificate is not a CA certificate with path length 0")
	}
	return nil
}

// Attest is the common first half of both verifiers. It checks what is the caller's to get right (a
// bundle made by NewBundle, a context that is not nil and not done, a proof of the store that belongs to
// the applet, a clock that was set), then reads the evidence of the proof ([ParseAttestation]) and verifies
// its chain ([Bundle.Verify]). It returns the attestation only when the chain verified: no value of a
// certificate whose chain failed is ever handed on. A fault of the caller is a plain error, and a refusal
// of the evidence is a *[handoff.CodeError].
func (b *Bundle) Attest(ctx context.Context, a Applet, p *handoff.Proof, now time.Time) (*Attestation, error) {
	if !b.usable() {
		return nil, errors.New("attest: the bundle was not made by NewBundle")
	}
	if ctx == nil {
		return nil, errors.New("attest: no context")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("attest: the check was stopped: %w", err)
	}
	if p == nil {
		return nil, errors.New("attest: no proof")
	}
	var want handoff.Store
	switch a {
	case AppletPIV:
		want = handoff.StorePIV
	case AppletOpenPGP:
		want = handoff.StoreOpenPGPCard
	default:
		return nil, errors.New("attest: the applet is not known")
	}
	if p.Store != want {
		return nil, errors.New("attest: the proof is for another key store than this verifier's")
	}
	if now.IsZero() {
		return nil, errors.New("attest: the clock was not set")
	}
	att, err := ParseAttestation(p.Evidence)
	if err != nil {
		return nil, err
	}
	if err := b.Verify(a, att, now); err != nil {
		return nil, err
	}
	return att, nil
}

// Verify is the chain rule of the page for one applet at time now (taken as UTC). The key's certificate
// must be signed by the token's certificate, and the chain from it through the token's certificate, then
// the pinned intermediates of this applet and no others, must end in a pinned root, with every
// certificate valid at now, the pinned ones included (a certificate is valid at its notBefore and at its
// notAfter, as the standard library has it). At least one chain that is built has the token's certificate
// as its second element and a pinned intermediate of this applet as its third, so it has at least four
// certificates. A token's certificate that a pinned root signed directly is refused: the roots are shared
// by both applets, so such a chain does not tell which applet it belongs to. The page says the chain runs
// "through the token's certificate and the maker's intermediates" for piv and "through the maker's
// OpenPGP intermediates" for openpgp-card. The pools are made again at each call, a root that came with
// the evidence is never put in one, and a certificate of the evidence from the third entry on is not read.
//
// A refusal is a *[handoff.CodeError] with proof-invalid and fixed words. A zero now, a nil Attestation
// (or one with a nil member), an unknown applet and a bundle that was not made by [NewBundle] are errors
// that are not a refusal.
func (b *Bundle) Verify(a Applet, att *Attestation, now time.Time) error {
	if !b.usable() {
		return errors.New("attest: the bundle was not made by NewBundle")
	}
	if now.IsZero() {
		return errors.New("attest: the clock was not set")
	}
	var group []*x509.Certificate
	switch a {
	case AppletPIV:
		group = b.piv
	case AppletOpenPGP:
		group = b.opgp
	default:
		return errors.New("attest: the applet is not known")
	}
	if err := checkRoles(att); err != nil {
		return err
	}
	if len(att.Leaf.UnhandledCriticalExtensions) > 0 {
		return refuse("the key's certificate has a critical extension that is not known")
	}
	if err := att.Leaf.CheckSignatureFrom(att.Token); err != nil {
		return refuse("the key's certificate is not signed by the token's certificate")
	}

	roots := x509.NewCertPool()
	for _, c := range b.roots {
		roots.AddCert(c)
	}
	inter := x509.NewCertPool()
	inter.AddCert(att.Token)
	for _, c := range group {
		inter.AddCert(c)
	}
	chains, err := att.Leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now.UTC(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return chainRefusal(err)
	}
	viaToken := false
	for _, chain := range chains {
		if len(chain) >= 2 && bytes.Equal(chain[1].Raw, att.Token.Raw) {
			viaToken = true
			// The pool of intermediates holds the token's certificate and this applet's group only, so
			// every certificate between the token's and the root is a pinned intermediate of this applet.
			if len(chain) >= 4 {
				return nil
			}
		}
	}
	if viaToken {
		return refuse("the chain does not pass through a pinned intermediate of the applet")
	}
	return refuse("the chain does not pass through the token's certificate")
}

// chainRefusal turns the error of the chain builder into a refusal with fixed words. The texts of the
// standard library hold subject names and times, and none of them is copied.
func chainRefusal(err error) error {
	var invalid x509.CertificateInvalidError
	var unknown x509.UnknownAuthorityError
	var critical x509.UnhandledCriticalExtension
	var insecure x509.InsecureAlgorithmError
	switch {
	case errors.As(err, &unknown):
		return refuse("the chain does not lead to a pinned root")
	case errors.As(err, &invalid):
		if invalid.Reason == x509.Expired {
			return refuse("a certificate of the chain is not valid at the time of the ceremony")
		}
		return refuse("the chain does not verify")
	case errors.As(err, &critical):
		return refuse("a certificate of the chain has a critical extension that is not known")
	case errors.As(err, &insecure):
		return refuse("a certificate of the chain is signed with an algorithm that is not accepted")
	}
	return refuse("the chain does not verify")
}

// KeyOf returns the attested key of a key's certificate: ECDSA on P-384, as a copy that shares nothing
// with the certificate. Any other key (another curve, RSA, Ed25519, no key that the standard library
// knows) is a *[handoff.CodeError] with proof-invalid. A nil certificate is a plain error.
func KeyOf(leaf *x509.Certificate) (*ecdsa.PublicKey, error) {
	if leaf == nil {
		return nil, errors.New("attest: no certificate")
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub == nil || pub.Curve != elliptic.P384() {
		return nil, refuse("the attested key is not an ECDSA key on P-384")
	}
	k, ok := copyP384(pub)
	if !ok {
		return nil, refuse("the attested key is not an ECDSA key on P-384")
	}
	return k, nil
}

// copyP384 returns a copy of a P-384 key made from its uncompressed point. It reports false for a key that
// has no point to write: a key built by hand with no X or no Y makes Bytes panic, and that is the answer
// "no key".
func copyP384(pub *ecdsa.PublicKey) (k *ecdsa.PublicKey, ok bool) {
	defer func() {
		if recover() != nil {
			k, ok = nil, false
		}
	}()
	b, err := pub.Bytes()
	if err != nil {
		return nil, false
	}
	c, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), b)
	if err != nil {
		return nil, false
	}
	return c, true
}
