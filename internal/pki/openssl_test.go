package pki_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// These tests check the certificates with a tool that did not build them. A control must fail for
// the reason it names: the text of OpenSSL's refusal holds that reason.
const (
	reasonSignature = "certificate signature failure"
	reasonIssuer    = "unable to get local issuer certificate"
	reasonSelf      = "self-signed certificate"
	reasonExpired   = "certificate has expired"
	reasonNotYet    = "certificate is not yet valid"
	reasonSubtree   = "permitted subtree violation"
)

func requireRefusal(t testing.TB, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("OpenSSL accepts it, want a refusal: %s", reason)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("OpenSSL refuses it, but not for %q: %v", reason, err)
	}
	if !printable(err.Error()) {
		t.Errorf("the text of the refusal is not printable ASCII: %q", err.Error())
	}
}

func TestOpenSSLAcceptsARoot(t *testing.T) {
	for _, c := range []struct {
		name string
		at   time.Time
		mod  func(*pki.RootParams)
	}{
		{"a test root", ceremony, nil},
		{"a real root", ceremony, func(p *pki.RootParams) { p.Test = false; p.Name = "Example-Org 2"; p.Label = "Z" }},
		{"the longest common name", ceremony, func(p *pki.RootParams) { p.Name = strings.Repeat("n", 45) }},
		{"a ceremony on 29 February", utc(2028, 2, 29, 8, 30, 0), nil},
		{"a ceremony on the last second of 2049", utc(2049, 12, 31, 23, 59, 59), nil},
		{"a ceremony in 2050", utc(2050, 1, 1, 0, 0, 0), nil},
		{"a ceremony in 1999", utc(1999, 12, 31, 23, 59, 59), nil},
		{"a serial of 64 bits", ceremony, func(p *pki.RootParams) { p.Serial = new(big.Int).Lsh(big.NewInt(1), 63) }},
		{"a serial of 159 bits", ceremony, func(p *pki.RootParams) {
			p.Serial = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := buildRoot(t, func(p *pki.RootParams) {
				p.CeremonyTime = c.at
				if c.mod != nil {
					c.mod(p)
				}
			})
			start, end := r.parsed.NotBefore, r.parsed.NotAfter
			if err := verifier.OpenSSLVerify(t, r.cert, r.cert, start.Add(24*time.Hour)); err != nil {
				t.Errorf("a day after the start: %v", err)
			}
			// The edges of the validity are exact: the first second is in and the second before it is
			// out; the second before the end is in and the second after the end is out. (OpenSSL
			// counts the end second itself as past, so it is not asserted.)
			if err := verifier.OpenSSLVerify(t, r.cert, r.cert, start); err != nil {
				t.Errorf("at the first second: %v", err)
			}
			if err := verifier.OpenSSLVerify(t, r.cert, r.cert, end.Add(-time.Second)); err != nil {
				t.Errorf("a second before the end: %v", err)
			}
			requireRefusal(t, verifier.OpenSSLVerify(t, r.cert, r.cert, start.Add(-time.Second)), reasonNotYet)
			requireRefusal(t, verifier.OpenSSLVerify(t, r.cert, r.cert, end.Add(time.Second)), reasonExpired)
			// The reading of OpenSSL, row by row.
			text := verifier.OpenSSLText(t, r.cert)
			for _, row := range []string{
				"Version: 3 (0x2)",
				"Signature Algorithm: ecdsa-with-SHA384",
				"Issuer: CN=" + r.parsed.Subject.CommonName + "\n",
				"Subject: CN=" + r.parsed.Subject.CommonName + "\n",
				"Public-Key: (384 bit)",
				"ASN1 OID: secp384r1",
				"X509v3 Basic Constraints: critical\n                CA:TRUE\n",
				"X509v3 Key Usage: critical\n                Certificate Sign, CRL Sign\n",
				"X509v3 Subject Key Identifier: \n                " + colonHex(r.parsed.SubjectKeyId) + "\n",
				"Not Before: " + opensslTime(start),
				"Not After : " + opensslTime(end),
			} {
				if !strings.Contains(text, row) {
					t.Errorf("the text of the certificate has no %q:\n%s", row, text)
				}
			}
			for _, absent := range []string{"Authority Key Identifier", "Name Constraints", "pathlen", "Extended Key Usage"} {
				if strings.Contains(text, absent) {
					t.Errorf("the text of the certificate has %q:\n%s", absent, text)
				}
			}
			if got, want := opensslExtensionNames(text), []string{"Basic Constraints", "Subject Key Identifier", "Key Usage"}; strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("extensions in the text = %v, want %v", got, want)
			}
		})
	}
}

var opensslExtension = regexp.MustCompile(`(?m)^ {12}X509v3 ([A-Za-z ]+):`)

// opensslExtensionNames are the extensions that "openssl x509 -text" lists, in its order.
func opensslExtensionNames(text string) []string {
	var names []string
	for _, m := range opensslExtension.FindAllStringSubmatch(text, -1) {
		names = append(names, m[1])
	}
	return names
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}

// opensslTime is the way OpenSSL prints a time: "Nov 15 12:00:00 2026 GMT".
func opensslTime(t time.Time) string {
	return t.UTC().Format("Jan _2 15:04:05 2006") + " GMT"
}

// strictVerify is "openssl verify" as OpenSSLVerify runs it, and two more checks: the self-signature
// of a root is verified (OpenSSL does not do that for a trusted root unless it is asked to), and the
// profile of RFC 5280 is enforced strictly. The text of a refusal is printable ASCII.
func strictVerify(t testing.TB, root, cert []byte, at time.Time) error {
	t.Helper()
	bin := verifier.Require(t, "openssl")
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		if !bytes.HasPrefix(data, []byte("-----")) {
			data = pemOf(data)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	rootFile, certFile := write("root.pem", root), write("cert.pem", cert)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "verify", "-attime", fmt.Sprint(at.Unix()), "-no-CApath", "-no-CAstore",
		"-check_ss_sig", "-x509_strict", "-CAfile", rootFile, certFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("openssl verify: %w: %s", err, jsonset.Escape(string(out)))
	}
	if !strings.HasSuffix(strings.TrimSpace(string(out)), ": OK") {
		return fmt.Errorf("openssl verify did not print OK: %s", jsonset.Escape(string(out)))
	}
	return nil
}

// Controls for the root: each is a certificate that is not what it should be, and OpenSSL refuses it
// for the reason that is named.
func TestOpenSSLRefusesATamperedRoot(t *testing.T) {
	r := buildRoot(t, nil)
	cn := []byte(r.parsed.Subject.CommonName)
	first, last := bytes.Index(r.tbs, cn), bytes.LastIndex(r.tbs, cn)
	if first < 0 || first == last {
		t.Fatalf("the name is not twice in the body: %d %d", first, last)
	}
	sig := signatureOf(t, r.key, r.tbs)
	tampered := func(at int) []byte {
		body := append([]byte(nil), r.tbs...)
		body[at] ^= 0x02 // 'E' to 'G': a letter stays a letter
		der, err := handAssemble(body, sig)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		return der
	}
	at := ceremony.Add(24 * time.Hour)
	if err := verifier.OpenSSLVerify(t, r.cert, r.cert, at); err != nil {
		t.Fatalf("the control itself is refused: %v", err)
	}
	if err := strictVerify(t, r.cert, r.cert, at); err != nil {
		t.Fatalf("the control itself is refused when strict: %v", err)
	}
	// A root that is changed after it was signed: its own signature no longer verifies. It is trusted
	// as itself, so only the check of the self-signature can refuse it.
	for name, at := range map[string]int{
		"the serial":                 bytes.Index(r.tbs, aSerial.Bytes()) + 3,
		"the validity":               bytes.Index(r.tbs, []byte("261115120000Z")) + 5,
		"the key identifier":         bytes.Index(r.tbs, r.parsed.SubjectKeyId) + 3,
		"the issuer and the subject": -1,
	} {
		t.Run("a changed "+name+", checked as its own root", func(t *testing.T) {
			var der []byte
			if at < 0 {
				// Both names, so that it stays self-signed: only its signature is wrong.
				body := append([]byte(nil), r.tbs...)
				body[first] ^= 0x02
				body[last] ^= 0x02
				var err error
				if der, err = handAssemble(body, sig); err != nil {
					t.Fatal(err)
				}
			} else {
				der = tampered(at)
			}
			requireRefusal(t, strictVerify(t, der, der, ceremony.Add(24*time.Hour)), reasonSignature)
		})
	}
	t.Run("a signature of another key, checked as its own root", func(t *testing.T) {
		forged, err := handAssemble(r.tbs, rawSign(t, newKey(t), r.tbs))
		if err != nil {
			t.Fatal(err)
		}
		requireRefusal(t, strictVerify(t, forged, forged, at), reasonSignature)
	})
	cases := []struct {
		name   string
		cert   []byte
		reason string
	}{
		{"the subject changed by a letter", tampered(last), reasonSignature},
		{"the issuer changed by a letter", tampered(first), reasonIssuer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireRefusal(t, verifier.OpenSSLVerify(t, r.cert, c.cert, at), c.reason)
			requireRefusal(t, strictVerify(t, r.cert, c.cert, at), c.reason)
		})
	}
	t.Run("another root, of another name", func(t *testing.T) {
		other := buildRoot(t, func(p *pki.RootParams) { p.Name = "Another Test"; p.Label = "Q" })
		requireRefusal(t, verifier.OpenSSLVerify(t, other.cert, r.cert, at), reasonSelf)
	})
	t.Run("another root of the same name and another key", func(t *testing.T) {
		other := buildRoot(t, nil)
		requireRefusal(t, verifier.OpenSSLVerify(t, other.cert, r.cert, at), reasonSelf)
	})
	t.Run("a time after the end", func(t *testing.T) {
		requireRefusal(t, verifier.OpenSSLVerify(t, r.cert, r.cert, r.parsed.NotAfter.Add(time.Hour)), reasonExpired)
	})
	t.Run("a time before the start", func(t *testing.T) {
		requireRefusal(t, verifier.OpenSSLVerify(t, r.cert, r.cert, r.parsed.NotBefore.Add(-time.Hour)), reasonNotYet)
	})
}

// The intermediate: accepted by OpenSSL under its root at the right times, text read row by row,
// and controls that fail for the reason they name.
func TestOpenSSLAcceptsAnIntermediate(t *testing.T) {
	names4 := []string{"Basic Constraints", "Key Usage", "Name Constraints", "Extended Key Usage", "Subject Key Identifier", "Authority Key Identifier"}
	for _, c := range []struct {
		name   string
		at     time.Time
		months int
		exts   func() []pkix.Extension
		names  []string
		rows   []string
		absent []string
	}{
		{"the ordinary request", ceremony, 13, goodExtensions, names4, []string{
			"X509v3 Basic Constraints: critical\n                CA:TRUE, pathlen:0\n",
			"X509v3 Key Usage: critical\n                Certificate Sign, CRL Sign\n",
			"X509v3 Name Constraints: critical\n                Permitted:\n                  DNS:example.org\n",
			"X509v3 Extended Key Usage: \n                TLS Web Server Authentication, TLS Web Client Authentication\n",
		}, nil},
		{"an end on 29 February", utc(2027, 1, 31, 10, 20, 30), 13, goodExtensions, names4, nil, nil},
		{"an end in 2050", utc(2049, 12, 31, 23, 59, 59), 1, goodExtensions, names4, nil, nil},
		{"digitalSignature too and an extended key usage that is not critical", ceremony, 13, func() []pkix.Extension {
			return []pkix.Extension{extBasicConstraints(), extKeyUsage(kuDigitalSignature, kuKeyCertSign, kuCRLSign), extNameConstraints("example.org"), extExtKeyUsage(false, oidServerAuth, oidClientAuth)}
		}, []string{"Basic Constraints", "Key Usage", "Name Constraints", "Extended Key Usage", "Subject Key Identifier", "Authority Key Identifier"}, []string{
			"Digital Signature, Certificate Sign, CRL Sign",
			"X509v3 Extended Key Usage: \n                TLS Web Server Authentication, TLS Web Client Authentication\n",
		}, nil},
		{"an extended key usage of clientAuth then serverAuth", ceremony, 13, func() []pkix.Extension {
			return []pkix.Extension{extBasicConstraints(), extKeyUsage(kuKeyCertSign), extNameConstraints("example.org"), extExtKeyUsage(false, oidClientAuth, oidServerAuth)}
		}, []string{"Basic Constraints", "Key Usage", "Name Constraints", "Extended Key Usage", "Subject Key Identifier", "Authority Key Identifier"}, []string{"X509v3 Extended Key Usage: \n                TLS Web Client Authentication, TLS Web Server Authentication\n"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := buildRoot(t, func(p *pki.RootParams) { p.CeremonyTime = c.at })
			csr := withExtensions(t, c.exts()...)
			inter := root.issue(t, csr, func(p *pki.IntermediateParams) { p.CeremonyTime = c.at })
			if err := strictVerify(t, root.cert, inter.cert, c.at.Add(24*time.Hour)); err != nil {
				t.Errorf("strict: %v", err)
			}
			start, end := inter.parsed.NotBefore, inter.parsed.NotAfter
			if err := verifier.OpenSSLVerify(t, root.cert, inter.cert, start.Add(24*time.Hour)); err != nil {
				t.Errorf("a day after the start: %v", err)
			}
			if err := verifier.OpenSSLVerify(t, root.cert, inter.cert, start); err != nil {
				t.Errorf("at the first second: %v", err)
			}
			if err := verifier.OpenSSLVerify(t, root.cert, inter.cert, end.Add(-time.Second)); err != nil {
				t.Errorf("a second before the end: %v", err)
			}
			requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, inter.cert, start.Add(-time.Second)), reasonNotYet)
			requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, inter.cert, end.Add(time.Second)), reasonExpired)

			text := verifier.OpenSSLText(t, inter.cert)
			rows := append([]string{
				"Version: 3 (0x2)",
				"Signature Algorithm: ecdsa-with-SHA384",
				"Issuer: CN=" + root.parsed.Subject.CommonName + "\n",
				"Subject: O=acme, CN=acme example ca\n",
				"Public-Key: (384 bit)",
				"X509v3 Subject Key Identifier: \n                " + colonHex(inter.parsed.SubjectKeyId) + "\n",
				"X509v3 Authority Key Identifier: \n                " + colonHex(root.parsed.SubjectKeyId) + "\n",
				"Not Before: " + opensslTime(start),
				"Not After : " + opensslTime(end),
			}, c.rows...)
			for _, row := range rows {
				if !strings.Contains(text, row) {
					t.Errorf("the text of the certificate has no %q:\n%s", row, text)
				}
			}
			if got := opensslExtensionNames(text); strings.Join(got, ",") != strings.Join(c.names, ",") {
				t.Errorf("extensions in the text = %v, want %v", got, c.names)
			}
			for _, absent := range c.absent {
				if strings.Contains(text, absent) {
					t.Errorf("the text of the certificate has %q:\n%s", absent, text)
				}
			}
		})
	}
}

func TestOpenSSLRefusesATamperedIntermediate(t *testing.T) {
	root := buildRoot(t, nil)
	csr := withExtensions(t, goodExtensions()...)
	inter := root.issue(t, csr, nil)
	at := ceremony.Add(24 * time.Hour)
	if err := verifier.OpenSSLVerify(t, root.cert, inter.cert, at); err != nil {
		t.Fatalf("the control itself is refused: %v", err)
	}
	sig := signatureOf(t, root.key, inter.tbs)
	flip := func(at int) []byte {
		body := append([]byte(nil), inter.tbs...)
		body[at] ^= 0x02
		der, err := handAssemble(body, sig)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		return der
	}
	subjectAt := bytes.Index(inter.tbs, []byte("acme example ca"))
	issuerAt := bytes.Index(inter.tbs, []byte(root.parsed.Subject.CommonName))
	cases := []struct {
		name   string
		cert   []byte
		reason string
	}{
		{"a letter of the subject changed", flip(subjectAt), reasonSignature},
		{"a letter of the issuer changed", flip(issuerAt), reasonIssuer},
		{"the serial changed", flip(bytes.Index(inter.tbs, aSerial.Bytes()) + 3), reasonSignature},
		{"the end of the validity changed", flip(bytes.Index(inter.tbs, []byte("271215120000Z")) + 5), reasonSignature},
		{"the name constraints changed", flip(bytes.Index(inter.tbs, []byte("example.org"))), reasonSignature},
		{"the authority key identifier changed", flip(bytes.Index(inter.tbs, root.parsed.SubjectKeyId) + 2), reasonIssuer},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, c.cert, at), c.reason)
		})
	}
	t.Run("an unrelated root of another name", func(t *testing.T) {
		other := buildRoot(t, func(p *pki.RootParams) { p.Name = "Another Test"; p.Label = "Q" })
		requireRefusal(t, verifier.OpenSSLVerify(t, other.cert, inter.cert, at), reasonIssuer)
	})
	t.Run("an unrelated root of the same name", func(t *testing.T) {
		other := buildRoot(t, nil)
		// The name matches and the key identifier does not: OpenSSL does not take it for the issuer.
		requireRefusal(t, verifier.OpenSSLVerify(t, other.cert, inter.cert, at), reasonIssuer)
	})
	t.Run("a signature by another key under the right issuer name", func(t *testing.T) {
		forged := root.issue(t, csr, nil)
		badSig := rawSign(t, newKey(t), forged.tbs)
		der, err := handAssemble(forged.tbs, badSig)
		if err != nil {
			t.Fatal(err)
		}
		requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, der, at), reasonSignature)
	})
	t.Run("an issuer name of another root, signed by the right key", func(t *testing.T) {
		other := buildRoot(t, func(p *pki.RootParams) { p.Name = "Another Test"; p.Label = "Q" })
		forged := root.issue(t, csr, func(p *pki.IntermediateParams) { p.IssuerSubject = other.parsed.RawSubject })
		requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, forged.cert, at), reasonIssuer)
	})
	t.Run("a time after the end", func(t *testing.T) {
		requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, inter.cert, inter.parsed.NotAfter.Add(time.Hour)), reasonExpired)
	})
	t.Run("a time before the start", func(t *testing.T) {
		requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, inter.cert, inter.parsed.NotBefore.Add(-time.Hour)), reasonNotYet)
	})
	t.Run("the root has ended and the intermediate has not", func(t *testing.T) {
		// A root of a ceremony long before: its end is before the intermediate's end.
		old := buildRoot(t, func(p *pki.RootParams) { p.CeremonyTime = utc(2020, 1, 1, 0, 0, 0) })
		late := old.issue(t, withExtensions(t, goodExtensions()...), func(p *pki.IntermediateParams) {
			p.CeremonyTime = utc(2022, 12, 1, 0, 0, 0)
		})
		// 2023-01-01 is inside both; 2023-06-01 is after the root's end (2023-01-01 00:00:00 is its last second).
		if err := verifier.OpenSSLVerify(t, old.cert, late.cert, utc(2022, 12, 15, 0, 0, 0)); err != nil {
			t.Fatalf("inside both: %v", err)
		}
		requireRefusal(t, verifier.OpenSSLVerify(t, old.cert, late.cert, utc(2023, 6, 1, 0, 0, 0)), reasonExpired)
	})
}

// The name constraints and the extended key usage are in effect for a certificate below the
// intermediate, under OpenSSL and under Go: the copied bytes are what a relying party reads.
func TestIntermediateConstraintsHoldBelow(t *testing.T) {
	root := buildRoot(t, nil)
	ikey := newKey(t)
	csr := makeCSR(t, csrOptions{key: ikey, exts: goodExtensions()})
	inter := root.issue(t, csr, nil)
	chain := append(pemOf(root.cert), pemOf(inter.cert)...)
	at := ceremony.Add(24 * time.Hour)
	leaf := func(t *testing.T, name string, eku ...x509.ExtKeyUsage) []byte {
		t.Helper()
		lkey := newKey(t)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(77),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     []string{name},
			NotBefore:    ceremony.Add(time.Hour),
			NotAfter:     ceremony.Add(48 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  eku,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, inter.parsed, &lkey.PublicKey, ikey)
		if err != nil {
			t.Fatalf("leaf: %v", err)
		}
		return der
	}
	pool := func(c ...*x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		for _, x := range c {
			p.AddCert(x)
		}
		return p
	}
	t.Run("a name inside the subtree", func(t *testing.T) {
		l := leaf(t, "www.example.org", x509.ExtKeyUsageServerAuth)
		if err := verifier.OpenSSLVerify(t, chain, l, at); err != nil {
			t.Errorf("OpenSSL: %v", err)
		}
		cert, _ := x509.ParseCertificate(l)
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool(root.parsed), Intermediates: pool(inter.parsed), DNSName: "www.example.org", CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("Go: %v", err)
		}
	})
	t.Run("a name outside the subtree", func(t *testing.T) {
		l := leaf(t, "www.example.com", x509.ExtKeyUsageServerAuth)
		requireRefusal(t, verifier.OpenSSLVerify(t, chain, l, at), reasonSubtree)
		cert, _ := x509.ParseCertificate(l)
		_, err := cert.Verify(x509.VerifyOptions{Roots: pool(root.parsed), Intermediates: pool(inter.parsed), DNSName: "www.example.com", CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		var invalid x509.CertificateInvalidError
		if err == nil || !asCertInvalid(err, &invalid) || invalid.Reason != x509.CANotAuthorizedForThisName {
			t.Errorf("Go: %v, want CANotAuthorizedForThisName", err)
		}
	})
	t.Run("the chain without the intermediate is refused", func(t *testing.T) {
		l := leaf(t, "www.example.org", x509.ExtKeyUsageServerAuth)
		requireRefusal(t, verifier.OpenSSLVerify(t, root.cert, l, at), reasonIssuer)
	})

	// The extended key usage, as requested, bounds the purposes below it (Go checks the chain).
	t.Run("an extended key usage bounds the leaf", func(t *testing.T) {
		ekey := newKey(t)
		ecsr := makeCSR(t, csrOptions{key: ekey, exts: append(goodExtensions()[:3:3], extExtKeyUsage(false, oidClientAuth))})
		einter := root.issue(t, ecsr, nil)
		lkey := newKey(t)
		mk := func(eku x509.ExtKeyUsage) *x509.Certificate {
			der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
				SerialNumber: big.NewInt(78), Subject: pkix.Name{CommonName: "www.example.org"}, DNSNames: []string{"www.example.org"},
				NotBefore: ceremony.Add(time.Hour), NotAfter: ceremony.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
			}, einter.parsed, &lkey.PublicKey, ekey)
			if err != nil {
				t.Fatal(err)
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
		opts := func(eku x509.ExtKeyUsage) x509.VerifyOptions {
			return x509.VerifyOptions{Roots: pool(root.parsed), Intermediates: pool(einter.parsed), CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{eku}}
		}
		if _, err := mk(x509.ExtKeyUsageClientAuth).Verify(opts(x509.ExtKeyUsageClientAuth)); err != nil {
			t.Errorf("a client leaf under a client-only intermediate: %v", err)
		}
		_, err := mk(x509.ExtKeyUsageServerAuth).Verify(opts(x509.ExtKeyUsageServerAuth))
		var invalid x509.CertificateInvalidError
		if err == nil || !asCertInvalid(err, &invalid) || invalid.Reason != x509.IncompatibleUsage {
			t.Errorf("a server leaf under a client-only intermediate: %v, want IncompatibleUsage", err)
		}
	})
}

func asCertInvalid(err error, target *x509.CertificateInvalidError) bool {
	if e, ok := err.(x509.CertificateInvalidError); ok { //nolint:errorlint // Go returns the value itself from Verify
		*target = e
		return true
	}
	return false
}

// A key that holds only the crypto.Signer methods builds and verifies the same certificate under
// OpenSSL as the software key does.
func TestOpenSSLAcceptsACertificateOfABareSigner(t *testing.T) {
	rootSigner := newOpaque(t)
	p := rootParams(&rootSigner.key.PublicKey)
	tbs, err := pki.RootTBS(p)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := pki.SignRoot(nil, rootSigner, p, tbs)
	if err != nil {
		t.Fatal(err)
	}
	rootDER, err := pki.Assemble(tbs, sig, rootSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	csr := withExtensions(t, goodExtensions()...)
	ip := pki.IntermediateParams{
		CSR: csr.DER(), IssuerSubject: rootCert.RawSubject, IssuerKey: rootSigner.Public(), Roots: []pki.RootRef{{Subject: rootCert.RawSubject, Key: rootSigner.Public()}}, CeremonyTime: ceremony, Serial: aSerial,
	}
	itbs, err := intermediateTBS(t, ip)
	if err != nil {
		t.Fatal(err)
	}
	isig, err := pki.SignIntermediate(nil, rootSigner, ip, itbs)
	if err != nil {
		t.Fatal(err)
	}
	interDER, err := pki.Assemble(itbs, isig, rootSigner.Public())
	if err != nil {
		t.Fatal(err)
	}
	at := ceremony.Add(24 * time.Hour)
	if err := verifier.OpenSSLVerify(t, rootDER, rootDER, at); err != nil {
		t.Errorf("root: %v", err)
	}
	if err := verifier.OpenSSLVerify(t, rootDER, interDER, at); err != nil {
		t.Errorf("intermediate: %v", err)
	}
	if rootSigner.calls != 2 {
		t.Errorf("the bare signer was called %d times, want 2", rootSigner.calls)
	}
}
