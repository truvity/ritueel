package pki_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// A body at the limit of what the DER writer can write. The issuer is the caller's own bytes, so it is the one
// input that can be as large as 16 MiB; the request is held to MaxRequestSize before. The largest TBSCertificate that
// Assemble can put into a certificate is 16,777,096 octets (the certificate holds the body, the algorithm of 12 octets
// and the signature as a BIT STRING of at most 107 octets in one sequence, whose content is at most 2^24-1 octets).
const maxBody = 1<<24 - 1 - 12 - 107

// issuerOfSize is a name whose single attribute has n characters of an attribute type that RFC 5280 gives no bound.
func issuerOfSize(n int) []byte {
	return nameOf(rdn(atv(oidAttrUnknown, tlv(tUTF8, bytes.Repeat([]byte("a"), n)))))
}

// bodyFor is a body of exactly the wanted size, found by growing the issuer.
func bodyFor(t *testing.T, root *testRoot, want int) (tbs []byte, n int, params pki.IntermediateParams) {
	t.Helper()
	good := withExtensions(t, goodExtensions()...)
	// The size is the issuer's plus a fixed part: measure it once with a large issuer, then adjust.
	n = want - 600
	for try := 0; try < 4; try++ {
		p := root.interParams(good)
		p.IssuerSubject = issuerOfSize(n)
		p = withIssuerInRoots(p) // the roots hold the issuer: the returned parameters are those of the body
		b, err := intermediateTBS(t, p)
		if err != nil {
			t.Fatalf("issuer of %d characters: %v", n, err)
		}
		if len(b) == want {
			return b, n, p
		}
		n += want - len(b)
	}
	t.Fatalf("could not make a body of %d octets", want)
	return nil, 0, pki.IntermediateParams{}
}

func TestABodyAtTheLimitOfTheWriter(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	start := time.Now()
	// The body of exactly the limit, and the size of the issuer that makes it.
	max, issuerSize, maxParams := bodyFor(t, root, maxBody)

	t.Run("the body of exactly the limit is built, signed, assembled and verified by both verifiers", func(t *testing.T) {
		sig, err := pki.SignIntermediate(nil, root.key, maxParams, max)
		if err != nil {
			t.Fatal(err)
		}
		der, err := pki.Assemble(max, sig, &root.key.PublicKey)
		if err != nil {
			t.Fatalf("Assemble of a body of %d octets: %v", len(max), err)
		}
		if len(der) > 1<<24-1+5 {
			t.Errorf("the certificate is %d octets", len(der))
		}
		// Go reads the certificate and verifies the signature with the key of the root (the issuer name is not the
		// root's, so no chain can be built to it).
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cert.RawTBSCertificate, max) || !bytes.Equal(cert.Signature, sig) {
			t.Error("the certificate does not hold the body and the signature")
		}
		if err := cert.CheckSignatureFrom(root.parsed); err != nil {
			t.Errorf("Go does not verify the signature: %v", err)
		}
		// OpenSSL reads the certificate, and verifies the same signature over the same body with the key of the root.
		bin := verifier.Require(t, "openssl")
		dir := t.TempDir()
		write := func(name string, data []byte) string {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}
		certFile := write("cert.der", der)
		// (openssl x509 refuses a certificate of more than about 1 MiB, 1,048,724 octets read and 1,049,123 not, a limit of
		// its loader, so the generic reader asn1parse is the one that reads this one.)
		if out, err := exec.Command(bin, "asn1parse", "-inform", "DER", "-in", certFile, "-noout").CombinedOutput(); err != nil {
			t.Errorf("OpenSSL cannot read the certificate: %v: %.200s", err, out)
		}
		pub, err := x509.MarshalPKIXPublicKey(&root.key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(bin, "dgst", "-sha384", "-verify", write("pub.pem", pemBlockOf("PUBLIC KEY", pub)), "-signature", write("sig.der", sig), write("tbs.der", max)).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "Verified OK") {
			t.Errorf("OpenSSL does not verify the signature: %v: %.200s", err, out)
		}
	})

	t.Run("a body longer by any number of octets is never returned by a builder", func(t *testing.T) {
		for _, extra := range []int{1, 2, 3, 107, 108, 300} {
			p := root.interParams(good)
			p.IssuerSubject = issuerOfSize(issuerSize + extra)
			tbs, err := intermediateTBS(t, p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body of %d octets came with the error", len(tbs))
			}
			if err != nil && !strings.Contains(err.Error(), "issuer is too long") {
				t.Errorf("the text does not say that the issuer is too long: %q", err.Error())
			}
		}
		// One octet less is still returned: the limit is exact on both sides.
		p := root.interParams(good)
		p.IssuerSubject = issuerOfSize(issuerSize - 1)
		if tbs, err := intermediateTBS(t, p); err != nil || len(tbs) != maxBody-1 {
			t.Errorf("a body of %d octets: %v", len(tbs), err)
		}
		p.IssuerSubject = issuerOfSize(1<<24 - 100)
		tbs, err := intermediateTBS(t, p)
		refused(t, err, pki.ErrParams)
		if tbs != nil {
			t.Error("a body came with the error")
		}
	})

	t.Run("Sign and Assemble refuse a hand-built body over the limit with their own kind, and the signer is not called", func(t *testing.T) {
		over := func(n int) []byte { return append(append([]byte(nil), max...), make([]byte, n-len(max))...) }
		rows := []struct {
			name string
			body []byte
		}{
			{"the honest body and one octet", over(maxBody + 1)},
			{"the honest body and two octets", over(maxBody + 2)},
			{"the honest body and 108 octets", over(maxBody + 108)},
			{"zeros of one octet more than the limit", make([]byte, maxBody+1)},
			{"zeros of 2^24-1 octets", make([]byte, 1<<24-1)},
			{"zeros of 2^24 octets", make([]byte, 1<<24)},
			{"zeros of 20 MiB", make([]byte, 20<<20)},
		}
		for _, r := range rows {
			t.Run(r.name, func(t *testing.T) {
				s := &opaqueSigner{key: root.key}
				sig, err := pki.SignIntermediate(nil, s, maxParams, r.body)
				refused(t, err, pki.ErrParams)
				if sig != nil || s.calls != 0 {
					t.Errorf("a signature came, or the signer was called %d times", s.calls)
				}
				der, err := pki.Assemble(r.body, rawSign(t, root.key, max), &root.key.PublicKey)
				refused(t, err, pki.ErrSignature)
				if der != nil {
					t.Error("a certificate came with the error")
				}
				if err != nil && !strings.Contains(err.Error(), "longer than 16777096 octets") {
					t.Errorf("the text does not say the limit: %q", err.Error())
				}
			})
		}
		// And the body of exactly the limit is not refused by the length.
		s := &opaqueSigner{key: root.key}
		if _, err := pki.SignIntermediate(nil, s, maxParams, max); err != nil || s.calls != 1 {
			t.Errorf("the body of the limit: %v, %d calls", err, s.calls)
		}
	})

	t.Logf("the body of %d octets, an issuer of %d characters; the whole test took %v", len(max), issuerSize, time.Since(start).Round(time.Millisecond))
}

func pemBlockOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
