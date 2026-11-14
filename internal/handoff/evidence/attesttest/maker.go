package attesttest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff/evidence/attest"
)

// The roles that [MakerOptions.Tweak] is called with, one for each certificate the maker makes when it is
// made. With [MakerOptions.SharedIntermediate] there is no separate openpgp intermediate.
const (
	// RoleRoot is the maker's root.
	RoleRoot = "root"
	// RolePIVIntermediate is the intermediate of the PIV applet (the only one when it is shared).
	RolePIVIntermediate = "piv-intermediate"
	// RoleOpenPGPIntermediate is the intermediate of the OpenPGP applet.
	RoleOpenPGPIntermediate = "openpgp-intermediate"
	// RoleStrayIntermediate is an intermediate under the root that no Spec holds.
	RoleStrayIntermediate = "stray-intermediate"
	// RolePIVToken is the token's certificate for the PIV applet.
	RolePIVToken = "piv-token"
	// RoleOpenPGPToken is the token's certificate for the OpenPGP applet.
	RoleOpenPGPToken = "openpgp-token"
)

// The names of the four extensions of a slot certificate, for [Slot.Omit] and [Slot.Critical].
const (
	// ExtFirmware is the extension .3.
	ExtFirmware = "firmware"
	// ExtSerial is the extension .7.
	ExtSerial = "serial"
	// ExtPolicy is the extension .8.
	ExtPolicy = "policy"
	// ExtForm is the extension .9.
	ExtForm = "form"
)

// The extension arc of the maker's attestation.
var extensionOIDs = map[string]asn1.ObjectIdentifier{
	ExtFirmware: {1, 3, 6, 1, 4, 1, 41482, 3, 3},
	ExtSerial:   {1, 3, 6, 1, 4, 1, 41482, 3, 7},
	ExtPolicy:   {1, 3, 6, 1, 4, 1, 41482, 3, 8},
	ExtForm:     {1, 3, 6, 1, 4, 1, 41482, 3, 9},
}

// extensionOrder is the order in which the four extensions are written.
var extensionOrder = []string{ExtFirmware, ExtSerial, ExtPolicy, ExtForm}

// CheckMode is how far the builder reads back a certificate that it made.
type CheckMode int

const (
	// CheckFull parses the certificate and checks it with CheckSignatureFrom against its parent. It is the
	// zero value.
	CheckFull CheckMode = iota
	// CheckSignature parses the certificate and checks only its signature against the signer's
	// certificate, for a certificate that a rule must refuse for what the parent is or for the algorithm
	// it is signed with (a token that is not a CA, a SHA-1 signature).
	CheckSignature
	// CheckNone reads nothing back, for a certificate that is meant not to parse.
	CheckNone
)

// MakerOptions are the options of [NewMaker].
type MakerOptions struct {
	// TokenECDSA is false (the zero value) for a token key of RSA 2048, as the vectors have, and true for
	// P-384, which is faster.
	TokenECDSA bool
	// Now is the time that every validity is built around: the root is valid ten years either side of it,
	// each intermediate five, each token's certificate two and each slot or key certificate one. The zero
	// value is 2026-11-15T12:00:00Z, the clock of the vectors. The windows are nested, so that the clock
	// of a call is inside all of them. To test the edge of one certificate's window, move that window
	// (Tweak for the hierarchy, [Slot.TokenTweak] and [Slot.Tweak] for the evidence) and call at Now.
	Now time.Time
	// SharedIntermediate makes one intermediate serve both applets, and puts it in both groups of the
	// spec. [attest.NewBundle] refuses such a spec, so [Maker.Bundle] stops the test; it is for the test
	// of that refusal.
	SharedIntermediate bool
	// Tweak, when it is not nil, is called with the role and the template of each certificate of the
	// hierarchy before it is signed. It may change the template, for example to add an extension.
	Tweak func(role string, tmpl *x509.Certificate)
}

// authority is a certificate of the hierarchy with the key that signs for it.
type authority struct {
	cert *x509.Certificate
	der  []byte
	key  crypto.Signer
}

// Maker is a made-up maker: a P-384 root, one intermediate for the PIV applet and one for the OpenPGP
// applet (path length 1; one for both when shared), one intermediate that no bundle holds, and a token key
// with a token's certificate for each applet (path length 0). All keys are made in memory. A Maker is
// immutable after [NewMaker] and may be used by several goroutines at once.
type Maker struct {
	now      time.Time
	root     *authority
	pivInt   *authority
	opgpInt  *authority
	stray    *authority
	tokenKey crypto.Signer
	pivTok   *authority
	opgpTok  *authority
	shared   bool
}

var rsaToken = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
})

// P384 makes a P-384 key in memory, for the key that a slot certificate attests.
func P384(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("attesttest: P-384 key: %v", err)
	}
	return k
}

// serial returns a random positive serial number.
func serial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("attesttest: serial number: %v", err)
	}
	return n.Add(n, big.NewInt(1))
}

// issue signs the template with signer, under the names of parent, and reads the result back as mode says
// (a builder that signs verifies its own output). check is the certificate whose key made the
// signature, which is the parent unless the parent only lends its name. It returns the DER and, unless the
// mode reads nothing back, the parsed certificate.
func issue(t testing.TB, tmpl *x509.Certificate, pub crypto.PublicKey, parent *x509.Certificate, signer crypto.Signer, check *x509.Certificate, mode CheckMode) ([]byte, *x509.Certificate) {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("attesttest: creating %q: %v", tmpl.Subject.CommonName, err)
	}
	if mode == CheckNone {
		return der, nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("attesttest: %q does not parse: %v", tmpl.Subject.CommonName, err)
	}
	switch mode {
	case CheckFull:
		if err := c.CheckSignatureFrom(check); err != nil {
			t.Fatalf("attesttest: %q does not verify against its parent: %v", tmpl.Subject.CommonName, err)
		}
	case CheckSignature:
		if err := check.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			t.Fatalf("attesttest: the signature of %q does not verify: %v", tmpl.Subject.CommonName, err)
		}
	}
	return der, c
}

// caTemplate is the template of a CA certificate with the path length (-1 for none; 0 is a zero length).
func caTemplate(t testing.TB, cn string, from, to time.Time, pathLen int, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{Organization: []string{"acme"}, CommonName: cn},
		NotBefore:             from,
		NotAfter:              to,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		KeyUsage:              usage,
	}
	return tmpl
}

// NewMaker makes a maker: its root, its intermediates, its token key and the token's certificate of each
// applet. It fails the test on an error.
func NewMaker(t testing.TB, o MakerOptions) *Maker {
	t.Helper()
	now := o.Now
	if now.IsZero() {
		now = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	}
	now = now.UTC().Truncate(time.Second)
	m := &Maker{now: now, shared: o.SharedIntermediate}
	tweak := func(role string, tmpl *x509.Certificate) {
		if o.Tweak != nil {
			o.Tweak(role, tmpl)
		}
	}
	window := func(years int) (time.Time, time.Time) { return now.AddDate(-years, 0, 0), now.AddDate(years, 0, 0) }

	// The root signs itself.
	from, to := window(10)
	rk := P384(t)
	rt := caTemplate(t, "Example Test Maker Root (TEST ONLY)", from, to, -1, x509.KeyUsageCertSign|x509.KeyUsageCRLSign)
	tweak(RoleRoot, rt)
	rootDER, _ := issue(t, rt, rk.Public(), rt, rk, rt, CheckNone)
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("attesttest: the root does not parse: %v", err)
	}
	if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("attesttest: the root does not verify against itself: %v", err)
	}
	m.root = &authority{cert: rootCert, der: rootDER, key: rk}

	intermediate := func(role, cn string) *authority {
		from, to := window(5)
		k := P384(t)
		tmpl := caTemplate(t, cn, from, to, 1, x509.KeyUsageCertSign|x509.KeyUsageCRLSign)
		tweak(role, tmpl)
		der, c := issue(t, tmpl, k.Public(), m.root.cert, m.root.key, m.root.cert, CheckFull)
		return &authority{cert: c, der: der, key: k}
	}
	m.pivInt = intermediate(RolePIVIntermediate, "Example Test PIV Attestation Intermediate")
	m.opgpInt = m.pivInt
	if !o.SharedIntermediate {
		m.opgpInt = intermediate(RoleOpenPGPIntermediate, "Example Test OPGP Attestation Intermediate")
	}
	m.stray = intermediate(RoleStrayIntermediate, "Example Other Attestation Intermediate")

	// The token has one key for both applets and one certificate for each.
	if o.TokenECDSA {
		m.tokenKey = P384(t)
	} else {
		k, err := rsaToken()
		if err != nil {
			t.Fatalf("attesttest: token key: %v", err)
		}
		m.tokenKey = k
	}
	m.pivTok = m.token(t, RolePIVToken, "Example Test PIV Attestation", m.pivInt, tweak)
	m.opgpTok = m.token(t, RoleOpenPGPToken, "Example Test OPGP Attestation", m.opgpInt, tweak)
	return m
}

// token makes the token's certificate: a CA with path length 0, issued by parent. tweak may change the
// template.
func (m *Maker) token(t testing.TB, role, cn string, parent *authority, tweak func(string, *x509.Certificate)) *authority {
	t.Helper()
	tmpl := caTemplate(t, cn, m.now.AddDate(-2, 0, 0), m.now.AddDate(2, 0, 0), 0, 0)
	tmpl.Subject.Organization = []string{"Example Test"}
	tweak(role, tmpl)
	der, c := issue(t, tmpl, m.tokenKey.Public(), parent.cert, parent.key, parent.cert, CheckFull)
	return &authority{cert: c, der: der, key: m.tokenKey}
}

// Now returns the time that the validities of the maker are built around.
func (m *Maker) Now() time.Time { return m.now }

// Spec returns a bundle spec that holds the root and the intermediates of the maker: the PIV
// intermediate in the PIV group and the OpenPGP intermediate in the OpenPGP group (the shared one in both).
// The version is "example-maker". It is a new copy at each call, for a test that adds, drops or moves a
// certificate before it calls [attest.NewBundle].
func (m *Maker) Spec() attest.BundleSpec {
	return attest.BundleSpec{
		Version:              "example-maker",
		Roots:                [][]byte{append([]byte(nil), m.root.der...)},
		PIVIntermediates:     [][]byte{append([]byte(nil), m.pivInt.der...)},
		OpenPGPIntermediates: [][]byte{append([]byte(nil), m.opgpInt.der...)},
	}
}

// Bundle returns the bundle of [Maker.Spec].
func (m *Maker) Bundle(t testing.TB) *attest.Bundle {
	t.Helper()
	b, err := attest.NewBundle(m.Spec())
	if err != nil {
		t.Fatalf("attesttest: the maker's bundle is refused: %v", err)
	}
	return b
}

// Root returns the maker's root certificate.
func (m *Maker) Root() *x509.Certificate { return m.root.cert }

// PIVIntermediate returns the intermediate of the PIV applet.
func (m *Maker) PIVIntermediate() *x509.Certificate { return m.pivInt.cert }

// OpenPGPIntermediate returns the intermediate of the OpenPGP applet (the PIV one when it is shared).
func (m *Maker) OpenPGPIntermediate() *x509.Certificate { return m.opgpInt.cert }

// StrayIntermediate returns an intermediate under the root that no [Maker.Spec] holds.
func (m *Maker) StrayIntermediate() *x509.Certificate { return m.stray.cert }

// Token returns the token's certificate that a PIV chain uses.
func (m *Maker) Token(t testing.TB) *x509.Certificate {
	t.Helper()
	return m.pivTok.cert
}

// OpenPGPToken returns the token's certificate that an OpenPGP-card chain uses.
func (m *Maker) OpenPGPToken(t testing.TB) *x509.Certificate {
	t.Helper()
	return m.opgpTok.cert
}

// Slot describes one slot certificate (or, for the OpenPGP applet, one key certificate). Every field has a
// default of the vectors: the slot 9c, firmware 5.8.0, the serial number 12345678, PIN policy once, touch
// policy never, form factor 2, the validity of a year either side of the maker's Now, signed by the
// token's certificate of the applet that the call names, whose certificate is issued by the applet's
// pinned intermediate. A field can be changed, an extension left out, or its value written as raw bytes,
// to make a bad one.
type Slot struct {
	// Subject is the common name, "YubiKey PIV Attestation 9c" by default for a slot certificate and
	// "YubiKey OPGP Attestation SIG" for an OpenPGP-card key. A subject of another form is made with Tweak.
	Subject string
	// Firmware, Serial, Policy and Form are the raw values of the extensions .3, .7, .8 and .9: nil is the
	// default (05 08 00; 02 04 00 bc 61 4e; 02 01; 02), and a slice that is not nil, an empty one too, is
	// written as it is.
	Firmware, Serial, Policy, Form []byte
	// Omit leaves out the extensions named ExtFirmware, ExtSerial, ExtPolicy and ExtForm.
	Omit map[string]bool
	// Critical marks the named extensions critical.
	Critical map[string]bool
	// PIVExtensions makes an OpenPGP-card key certificate carry the four extensions of a slot certificate.
	// A slot certificate always carries them, unless they are omitted.
	PIVExtensions bool
	// Tweak, when it is not nil, is called with the template of the certificate after the fields above were
	// written into it and before it is signed: it may add an extension, set RawSubject, change the validity
	// or the SignatureAlgorithm.
	Tweak func(tmpl *x509.Certificate)
	// Check is how far the builder reads the certificate back; the zero value is CheckFull.
	Check CheckMode

	// TokenTweak, when it is not nil, makes the evidence a token's certificate of its own, issued by the
	// applet's intermediate, and calls it with its template before it is signed: for a token that is not a
	// CA, that has a path length of 1 or none, or a validity of its own.
	TokenTweak func(tmpl *x509.Certificate)
	// UnpinnedIssuer has the token's certificate issued by the intermediate under the root that no
	// [Maker.Spec] holds.
	UnpinnedIssuer bool
	// OtherSigner has the key's certificate signed by another key whose certificate has the token's name,
	// so that the signature does not verify against the token's certificate.
	OtherSigner bool
	// IssuerName gives the key's certificate this common name for its issuer, and signs it with the token's
	// key, so that the signature verifies and the names do not match.
	IssuerName string
}

// defaultValue is the raw value of an extension of the vectors.
func defaultValue(name string) []byte {
	switch name {
	case ExtFirmware:
		return []byte{5, 8, 0}
	case ExtSerial:
		return []byte{0x02, 0x04, 0x00, 0xbc, 0x61, 0x4e}
	case ExtPolicy:
		return []byte{2, 1}
	default:
		return []byte{2}
	}
}

// extensions writes the extensions of a slot as the fields say.
func (s Slot) extensions(withDefaults bool) []pkix.Extension {
	raw := map[string][]byte{ExtFirmware: s.Firmware, ExtSerial: s.Serial, ExtPolicy: s.Policy, ExtForm: s.Form}
	var out []pkix.Extension
	for _, name := range extensionOrder {
		if s.Omit[name] {
			continue
		}
		v := raw[name]
		if v == nil {
			if !withDefaults {
				continue
			}
			v = defaultValue(name)
		}
		out = append(out, pkix.Extension{Id: extensionOIDs[name], Critical: s.Critical[name], Value: append([]byte{}, v...)})
	}
	return out
}

// chain makes the key's certificate and the token's certificate of one applet, in DER.
func (m *Maker) chain(t testing.TB, applet attest.Applet, key crypto.PublicKey, s Slot) (leaf, token []byte) {
	t.Helper()
	if key == nil {
		t.Fatal("attesttest: no key to attest")
	}
	tok, parent := m.pivTok, m.pivInt
	subject, withDefaults := "YubiKey PIV Attestation 9c", true
	if applet == attest.AppletOpenPGP {
		tok, parent = m.opgpTok, m.opgpInt
		subject, withDefaults = "YubiKey OPGP Attestation SIG", s.PIVExtensions
	}
	if s.UnpinnedIssuer {
		parent = m.stray
	}
	if s.UnpinnedIssuer || s.TokenTweak != nil {
		cn := tok.cert.Subject.CommonName
		tok = m.token(t, "evidence-token", cn, parent, func(_ string, tmpl *x509.Certificate) {
			if s.TokenTweak != nil {
				s.TokenTweak(tmpl)
			}
		})
	}
	if s.Subject != "" {
		subject = s.Subject
	}
	tmpl := &x509.Certificate{
		SerialNumber:    serial(t),
		Subject:         pkix.Name{CommonName: subject},
		NotBefore:       m.now.AddDate(-1, 0, 0),
		NotAfter:        m.now.AddDate(1, 0, 0),
		ExtraExtensions: s.extensions(withDefaults),
	}
	if s.Tweak != nil {
		s.Tweak(tmpl)
	}

	// The certificate whose names and key the signature is made under, and the certificate that the
	// signature is read back against.
	signerParent, signer, checkAgainst := tok.cert, tok.key, tok.cert
	switch {
	case s.OtherSigner:
		other := P384(t)
		tt := caTemplate(t, tok.cert.Subject.CommonName, m.now.AddDate(-2, 0, 0), m.now.AddDate(2, 0, 0), 0, 0)
		tt.RawSubject = tok.cert.RawSubject
		_, fake := issue(t, tt, other.Public(), parent.cert, parent.key, parent.cert, CheckFull)
		signerParent, signer, checkAgainst = fake, other, fake
	case s.IssuerName != "":
		fake := &x509.Certificate{Subject: pkix.Name{CommonName: s.IssuerName}}
		signerParent, signer = fake, tok.key
	}
	der, _ := issue(t, tmpl, key, signerParent, signer, checkAgainst, s.Check)
	return der, tok.der
}

// PIVChain returns the DER of the slot certificate and of the token's certificate for key.
func (m *Maker) PIVChain(t testing.TB, key crypto.PublicKey, s Slot) (leaf, token []byte) {
	t.Helper()
	return m.chain(t, attest.AppletPIV, key, s)
}

// OpenPGPChain returns the DER of the key's certificate and of the token's certificate for key, for the
// OpenPGP applet. The key's certificate has no extension unless s.PIVExtensions is set or a raw value is
// given.
func (m *Maker) OpenPGPChain(t testing.TB, key crypto.PublicKey, s Slot) (leaf, token []byte) {
	t.Helper()
	return m.chain(t, attest.AppletOpenPGP, key, s)
}

// EvidenceJSON writes the evidence member {"attestation": [...]} of a proof from DER certificates, each in
// the canonical standard Base64.
func EvidenceJSON(t testing.TB, ders ...[]byte) []byte {
	t.Helper()
	list := make([]string, len(ders))
	for i, d := range ders {
		list[i] = base64.StdEncoding.EncodeToString(d)
	}
	b, err := json.Marshal(map[string][]string{"attestation": list})
	if err != nil {
		t.Fatalf("attesttest: evidence: %v", err)
	}
	return b
}

// PIVEvidence returns the evidence member of a piv proof, as JSON: the slot certificate for key as s
// says, and the token's certificate. Every certificate is read back and checked as s.Check says.
func (m *Maker) PIVEvidence(t testing.TB, key crypto.PublicKey, s Slot) []byte {
	t.Helper()
	leaf, token := m.PIVChain(t, key, s)
	return EvidenceJSON(t, leaf, token)
}

// OpenPGPEvidence returns the evidence member of an openpgp-card proof, as JSON: a key certificate with
// the subject "YubiKey OPGP Attestation SIG" and no extension, and the token's certificate of the OpenPGP
// applet.
func (m *Maker) OpenPGPEvidence(t testing.TB, key crypto.PublicKey) []byte {
	t.Helper()
	return m.OpenPGPEvidenceWith(t, key, Slot{})
}

// OpenPGPEvidenceWith is [Maker.OpenPGPEvidence] for a key certificate that s describes.
func (m *Maker) OpenPGPEvidenceWith(t testing.TB, key crypto.PublicKey, s Slot) []byte {
	t.Helper()
	leaf, token := m.OpenPGPChain(t, key, s)
	return EvidenceJSON(t, leaf, token)
}
