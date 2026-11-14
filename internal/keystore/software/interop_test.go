package software

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The key is the signer of the other packages, and what it signs is read by tools that did not
// build it.

// The root certificate that the key signs is accepted by OpenSSL, also when the key is one that was
// opened from its file.
func TestARootCertificateSignedByTheKeyAndByTheKeyFromItsFileIsAcceptedByOpenSSL(t *testing.T) {
	verifier.Require(t, "openssl")
	s, _, _ := openStore(t)
	saved := mustGenerate(t)
	if err := s.SaveX509("A", saved); err != nil {
		t.Fatal(err)
	}
	opened, err := s.OpenX509(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	for name, k := range map[string]*Key{"a key in memory": saved, "a key from its file": opened} {
		serial, err := pki.NewSerial(nil)
		if err != nil {
			t.Fatal(err)
		}
		p := pki.RootParams{Name: "Example Test", Label: "A", Test: true, CeremonyTime: testCeremony, Key: k.Public(), Serial: serial}
		tbs, err := pki.RootTBS(p)
		if err != nil {
			t.Fatalf("%s: RootTBS: %v", name, err)
		}
		sig, err := pki.SignRoot(nil, k, p, tbs)
		if err != nil {
			t.Fatalf("%s: SignRoot: %v", name, err)
		}
		der, err := pki.Assemble(tbs, sig, k.Public())
		if err != nil {
			t.Fatalf("%s: Assemble: %v", name, err)
		}
		if err := verifier.OpenSSLVerify(t, der, der, testCeremony); err != nil {
			t.Errorf("%s: OpenSSL: %v", name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%s: the standard library does not verify the self-signature: %v", name, err)
		}
		if !k.Public().(*ecdsa.PublicKey).Equal(cert.PublicKey) {
			t.Errorf("%s: the certificate holds another key", name)
		}
	}
}

// sqv, which did not build the certificate, accepts a signature of a subkey that a primary
// bound, where the primary's own signatures were made by the key from its file.
func TestSqvAcceptsAMessageSignedByASubkeyThatThePrimaryFromItsFileBound(t *testing.T) {
	verifier.Require(t, "sqv")
	s, _, _ := openStore(t)
	saved := mustGenerate(t)
	cert := certFor(t, saved)
	if err := s.SaveOpenPGP("A", saved, cert); err != nil {
		t.Fatal(err)
	}
	opened, err := s.OpenOpenPGP(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Key.Close() }()

	pp := openpgp.PrimaryParams{
		Key: opened.Key, CreationTime: opened.Created, CeremonyTime: testCeremony,
		ExpiresAt: testCeremony.AddDate(3, 0, 0), UserID: mustUserID(t),
	}
	primaryPub := opened.Key.Public().(*ecdsa.PublicKey)
	subAt := testCreated.Add(24 * time.Hour)
	sk := keyP384(t)
	subPkt := pgpWrap(14, pgpKeyBody(&sk.PublicKey, subAt))
	fp := pgpFingerprint(&sk.PublicKey, subAt)
	back := pgpSig(t, 0x19,
		append(pgpSubpacket(2, pgpU32(uint32(subAt.Unix()))), pgpSubpacket(33, append([]byte{4}, fp...))...),
		pgpSubpacket(16, fp[12:]),
		[][]byte{pgpHashPrefix(primaryPub, opened.Created), pgpHashPrefix(&sk.PublicKey, subAt)}, sk)
	bound, err := openpgp.BindSubkey(rand.Reader, openpgp.BindParams{
		Primary: pp, Subkey: subPkt, BackSig: back, Capability: "sign", ExpiresAt: testCeremony.AddDate(1, 0, 0),
	})
	if err != nil {
		t.Fatalf("BindSubkey with the key from the file: %v", err)
	}
	msg := []byte("the release of example.org version 1.2.3\n")
	at := testCeremony.Add(2 * time.Hour)
	sign := func(m []byte) []byte {
		return pgpSig(t, 0x00,
			append(pgpSubpacket(2, pgpU32(uint32(at.Add(-time.Hour).Unix()))), pgpSubpacket(33, append([]byte{4}, fp...))...),
			pgpSubpacket(16, fp[12:]), [][]byte{m}, sk)
	}
	sig := sign(msg)
	primaryFP, err := openpgp.Fingerprint(primaryPub, opened.Created)
	if err != nil {
		t.Fatal(err)
	}
	ring := append(bytes.Clone(opened.Cert), bound...)
	if err := verifier.SQVVerify(t, ring, sig, msg, primaryFP, at); err != nil {
		t.Errorf("sqv: %v", err)
	}
	// The controls: the same world, one thing taken away or changed, is refused.
	if err := verifier.SQVVerify(t, ring, sig, append(bytes.Clone(msg), '!'), primaryFP, at); err == nil {
		t.Error("sqv accepts a changed message")
	}
	if err := verifier.SQVVerify(t, opened.Cert, sig, msg, primaryFP, at); err == nil {
		t.Error("sqv accepts the signature with no binding of the subkey")
	}
	other := mustGenerate(t)
	otherPP := pp
	otherPP.Key = other
	otherCert, err := openpgp.NewPrimary(rand.Reader, otherPP)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.SQVVerify(t, append(bytes.Clone(otherCert), bound...), sig, msg, primaryFP, at); err == nil {
		t.Error("sqv accepts a binding made by another primary")
	}
}

// A revocation signature that was saved and read back is a revocation of the primary of the
// certificate, for a second reader (go-crypto) that did not write it.
func TestARevocationReadBackIsAKeyRevocationOfThePrimaryOfTheCertificate(t *testing.T) {
	s, _, _ := openStore(t)
	k := mustGenerate(t)
	cert := certFor(t, k)
	pkt, err := packet.Read(bytes.NewReader(cert))
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := pkt.(*packet.PublicKey)
	if !ok {
		t.Fatalf("the first packet is a %T", pkt)
	}
	for _, r := range allReasons {
		if err := s.SaveRevocation("A", r.Text, revocationFor(t, k, r)); err != nil {
			t.Fatal(err)
		}
		raw, err := s.ReadRevocation(bg(), "A", r.Text)
		if err != nil {
			t.Fatal(err)
		}
		sp, err := packet.Read(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		sig, ok := sp.(*packet.Signature)
		if !ok || sig.SigType != packet.SigTypeKeyRevocation || sig.Version != 4 {
			t.Fatalf("%s: %T", r.Text, sp)
		}
		if err := pub.VerifyRevocationSignature(sig); err != nil {
			t.Errorf("%s: the revocation does not verify for the primary: %v", r.Text, err)
		}
		if sig.RevocationReason == nil || byte(*sig.RevocationReason) != r.Code {
			t.Errorf("%s: the reason code is %v, want %d", r.Text, sig.RevocationReason, r.Code)
		}
	}
}
