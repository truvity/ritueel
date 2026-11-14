package attest_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// handCA is a certificate of a chain that a test builds by hand, with the key that signs for it.
type handCA struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

func handKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var handSerial int64 = 100

// handIssue makes a certificate for key under the name cn, signed by the parent (self-signed when parent is
// nil), valid one year either side of the clock.
func handIssue(t testing.TB, cn string, key *ecdsa.PrivateKey, parent *handCA, isCA bool, pathLen int, mutate func(*x509.Certificate)) *handCA {
	t.Helper()
	handSerial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(handSerial),
		Subject:               pkix.Name{Organization: []string{"acme"}, CommonName: cn},
		NotBefore:             clock.AddDate(-1, 0, 0),
		NotAfter:              clock.AddDate(1, 0, 0),
		BasicConstraintsValid: isCA,
		IsCA:                  isCA,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        isCA && pathLen == 0,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		tmpl.MaxPathLen = 0
	}
	if mutate != nil {
		mutate(tmpl)
	}
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &handCA{cert: c, der: der, key: key}
}

// The page: the chain goes "from the slot certificate through the token's certificate". A chain that exists
// without it is not the page's chain: here a pinned intermediate has the token's name and key, and the
// token's certificate in the evidence is issued by an issuer that is pinned nowhere. The leaf would verify
// through the pinned certificate, and the evidence is refused because the token's certificate is not what
// the chain passes through.
func TestTheChainMustPassThroughTheTokensCertificate(t *testing.T) {
	root := handIssue(t, "Example Test Root", handKey(t), nil, true, -1, nil)
	inter := handIssue(t, "Example Test Intermediate", handKey(t), root, true, 1, nil)
	tokenKey := handKey(t)
	pinned := handIssue(t, "Example Test Token", tokenKey, inter, true, 0, nil)
	stranger := handIssue(t, "Example Test Stranger", handKey(t), nil, true, 1, nil)
	token := handIssue(t, "Example Test Token", tokenKey, stranger, true, 0, nil)
	leaf := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), &handCA{cert: token.cert, key: tokenKey}, false, 0, nil)

	spec := func(piv ...[]byte) attest.BundleSpec {
		return attest.BundleSpec{Version: "hand", Roots: [][]byte{root.der}, PIVIntermediates: piv}
	}
	// The pinned set holds the intermediate and a certificate with the token's name and key.
	b, err := attest.NewBundle(spec(inter.der, pinned.der))
	if err != nil {
		t.Fatal(err)
	}
	// The same chain, with the token's certificate that the pinned set holds as the evidence's own, passes.
	if err := verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf.der, pinned.der), clock); err != nil {
		t.Fatalf("the chain through the pinned token certificate: %v", err)
	}
	// With the stranger's token certificate in the evidence, a chain exists through the pinned one, and the
	// evidence is refused.
	err = verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf.der, token.der), clock)
	if d := wantRefusal(t, err, handoff.CodeProofInvalid); !strings.Contains(d, "pass through the token") {
		t.Errorf("the detail %q does not say that the chain does not pass through the token's certificate", d)
	}
}

// A token's certificate that is itself pinned as a root, self-signed with path length 0, ends the chain at
// once: the chain is the key's certificate and the token's certificate, and the token's certificate is the
// second element. (A device whose own certificate is pinned needs no intermediate.)
func TestAPinnedTokenCertificateIsARootOfTheChain(t *testing.T) {
	tokenKey := handKey(t)
	token := handIssue(t, "Example Test Token", tokenKey, nil, true, 0, nil)
	leaf := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), token, false, 0, nil)
	b, err := attest.NewBundle(attest.BundleSpec{Version: "hand", Roots: [][]byte{token.der}})
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf.der, token.der), clock); err != nil {
		t.Errorf("a pinned token certificate: %v", err)
	}
	// Another device's certificate is not pinned, and the chain ends nowhere.
	other := handIssue(t, "Example Test Token", handKey(t), nil, true, 0, nil)
	leaf2 := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), other, false, 0, nil)
	wantRefusal(t, verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf2.der, other.der), clock), handoff.CodeProofInvalid)
}

// A certificate above the key's certificate that is signed with SHA-1, a pinned intermediate or the token's
// own, does not carry a chain. (The standard library reports it as a chain that leads nowhere, so the
// refusal has the words of an unpinned chain; the weak-algorithm sentence of the package is not reached.)
func TestASHA1CertificateInTheChainIsRefused(t *testing.T) {
	root := handIssue(t, "Example Test Root", handKey(t), nil, true, -1, nil)
	sha1 := func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA1 }
	for name, weak := range map[string]struct{ inter, token func(*x509.Certificate) }{
		"the pinned intermediate": {sha1, nil},
		"the token's certificate": {nil, sha1},
	} {
		t.Run(name, func(t *testing.T) {
			inter := handIssue(t, "Example Test Intermediate", handKey(t), root, true, 1, weak.inter)
			token := handIssue(t, "Example Test Token", handKey(t), inter, true, 0, weak.token)
			leaf := handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), token, false, 0, nil)
			b, err := attest.NewBundle(attest.BundleSpec{Version: "hand", Roots: [][]byte{root.der}, PIVIntermediates: [][]byte{inter.der}})
			if err != nil {
				t.Fatal(err)
			}
			wantRefusal(t, verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf.der, token.der), clock), handoff.CodeProofInvalid)
			// The same chain with SHA-256 everywhere verifies, so the refusal is for the algorithm.
			inter = handIssue(t, "Example Test Intermediate", handKey(t), root, true, 1, nil)
			token = handIssue(t, "Example Test Token", handKey(t), inter, true, 0, nil)
			leaf = handIssue(t, "YubiKey PIV Attestation 9c", handKey(t), token, false, 0, nil)
			b, err = attest.NewBundle(attest.BundleSpec{Version: "hand", Roots: [][]byte{root.der}, PIVIntermediates: [][]byte{inter.der}})
			if err != nil {
				t.Fatal(err)
			}
			if err := verify(t, b, attest.AppletPIV, attesttest.EvidenceJSON(t, leaf.der, token.der), clock); err != nil {
				t.Errorf("the chain with SHA-256: %v", err)
			}
		})
	}
}
