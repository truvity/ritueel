package rootlist_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
)

// Each certificate of a CA bundle must also verify with its own key (a
// root certificate signs itself) and be a CA certificate, so that its text is what the root key
// signed. The names, the dates and the other extensions are not judged. All keys are made in
// memory.

// certOf makes a certificate for the key k, from the template, signed by signer (k itself when it
// is nil), and returns it as a PEM block.
func certOf(t testing.TB, k *key, tmpl *x509.Certificate, signer *key) (der []byte, block string) {
	t.Helper()
	parent, signKey := tmpl, k
	if signer != nil {
		signKey = signer
		parent = &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Example Test Other Root"}, IsCA: true, BasicConstraintsValid: true}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &k.priv.PublicKey, signKey.priv)
	if err != nil {
		t.Fatalf("make certificate: %v", err)
	}
	return der, pemOf(der)
}

func caTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Test Root"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

func TestVerifyCABundleJudgesTheCertificateItself(t *testing.T) {
	w := newWorld(t)
	l := listFor(t, 7, w.a, w.b)
	first := "# trust-sequence: 7\n"
	goodA, goodB := w.a.certPEM(), w.b.certPEM()
	if v := rootlist.VerifyCABundle([]byte(first+goodA+goodB), l); !v.Accepted {
		t.Fatalf("the witness: %+v", v)
	}
	mod := func(f func(*x509.Certificate)) string {
		tmpl := caTemplate()
		f(tmpl)
		_, b := certOf(t, w.a, tmpl, nil)
		return b
	}
	flipped := func(der []byte, at int) string {
		d := bytes.Clone(der)
		d[at] ^= 0x01
		return pemOf(d)
	}
	der, _ := certOf(t, w.a, caTemplate(), nil)
	subject := bytes.Index(der, []byte("Example Test Root"))
	if subject < 0 {
		t.Fatal("the subject is not in the certificate")
	}
	for _, c := range []struct{ name, block string }{
		{"the right key, signed by another key", func() string { _, b := certOf(t, w.a, caTemplate(), w.z); return b }()},
		{"the right key, signed by the other root key of the list", func() string { _, b := certOf(t, w.a, caTemplate(), w.b); return b }()},
		{"the right key and the CA flag false", mod(func(c *x509.Certificate) { c.IsCA = false })},
		{"the right key and no basic constraints", mod(func(c *x509.Certificate) { c.BasicConstraintsValid = false; c.IsCA = false })},
		{"the last byte of the signature changed", flipped(der, len(der)-1)},
		{"a byte of the signature value in the middle changed", flipped(der, len(der)-20)},
		{"a letter of the subject changed after it was signed", flipped(der, subject)},
		{"the serial number changed after it was signed", flipped(der, bytes.Index(der, []byte{0x02, 0x01, 0x01})+2)},
	} {
		t.Run(c.name, func(t *testing.T) {
			// In each place of a bundle of two: the first, and the second.
			mismatch(t, rootlist.VerifyCABundle([]byte(first+c.block+goodB), l))
		})
	}
	t.Run("the same, for the second block", func(t *testing.T) {
		_, bad := certOf(t, w.b, caTemplate(), w.z)
		mismatch(t, rootlist.VerifyCABundle([]byte(first+goodA+bad), l))
	})
}

func TestVerifyCABundleDoesNotJudgeTheRest(t *testing.T) {
	w := newWorld(t)
	l := listFor(t, 7, w.a, w.b)
	first := "# trust-sequence: 7\n"
	for name, f := range map[string]func(*x509.Certificate){
		"another name": func(c *x509.Certificate) {
			c.Subject = pkix.Name{CommonName: "Other Root", Organization: []string{"Example Org"}}
		},
		"no name": func(c *x509.Certificate) { c.Subject = pkix.Name{} },
		"dates in the past": func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1991, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"dates far away": func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"another serial": func(c *x509.Certificate) { c.SerialNumber = big.NewInt(987654321) },
		"name constraints": func(c *x509.Certificate) {
			c.PermittedDNSDomains = []string{"example.org"}
			c.PermittedDNSDomainsCritical = true
		},
		"another key usage":        func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign },
		"an extended key usage":    func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} },
		"a path length":            func(c *x509.Certificate) { c.MaxPathLen = 2 },
		"a signature with SHA-256": func(c *x509.Certificate) { c.SignatureAlgorithm = x509.ECDSAWithSHA256 },
		"a subject key id":         func(c *x509.Certificate) { c.SubjectKeyId = []byte{1, 2, 3, 4} },
		"every one of them together": func(c *x509.Certificate) {
			c.Subject = pkix.Name{CommonName: "x"}
			c.SerialNumber = big.NewInt(5)
			c.MaxPathLen = 1
			c.NotAfter = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		},
	} {
		t.Run(name, func(t *testing.T) {
			tmpl := caTemplate()
			f(tmpl)
			_, a := certOf(t, w.a, tmpl, nil)
			v := rootlist.VerifyCABundle([]byte(first+a+w.b.certPEM()), l)
			if !v.Accepted || v.List != l {
				t.Fatalf("a self-signed CA certificate with the right key is refused for its %s: %+v", name, v)
			}
		})
	}
}

func TestVerifyCABundleOfSeveralJudgesEachBlock(t *testing.T) {
	w := newWorld(t)
	keys := []*key{w.a, w.b, w.c, w.z}
	l := listFor(t, 9, keys...)
	good := func(i int) string { return keys[i].certPEM() }
	bads := map[string]func(k *key) string{
		"signed by another key": func(k *key) string { _, b := certOf(t, k, caTemplate(), pickOther(keys, k)); return b },
		"no CA flag":            func(k *key) string { tm := caTemplate(); tm.IsCA = false; _, b := certOf(t, k, tm, nil); return b },
		"no basic constraints": func(k *key) string {
			tm := caTemplate()
			tm.BasicConstraintsValid, tm.IsCA = false, false
			_, b := certOf(t, k, tm, nil)
			return b
		},
	}
	all := func(replace map[int]string) string {
		var b strings.Builder
		b.WriteString("# trust-sequence: 9\n")
		for i := range keys {
			if r, ok := replace[i]; ok {
				b.WriteString(r)
			} else {
				b.WriteString(good(i))
			}
		}
		return b.String()
	}
	if v := rootlist.VerifyCABundle([]byte(all(nil)), l); !v.Accepted {
		t.Fatalf("the witness: %+v", v)
	}
	for kind, mk := range bads {
		for i := range keys {
			t.Run(kind+" in block "+string(rune('1'+i)), func(t *testing.T) {
				v := rootlist.VerifyCABundle([]byte(all(map[int]string{i: mk(keys[i])})), l)
				mismatch(t, v)
				if !strings.Contains(v.Detail, "block "+string(rune('1'+i))) {
					t.Errorf("the detail does not name the block: %q", v.Detail)
				}
			})
		}
	}
	t.Run("two bad blocks are refused at the first", func(t *testing.T) {
		v := rootlist.VerifyCABundle([]byte(all(map[int]string{1: bads["no CA flag"](keys[1]), 3: bads["no CA flag"](keys[3])})), l)
		mismatch(t, v)
		if !strings.Contains(v.Detail, "block 2") {
			t.Errorf("the detail: %q", v.Detail)
		}
	})
}

func pickOther(keys []*key, k *key) *key {
	for _, o := range keys {
		if o != k {
			return o
		}
	}
	return nil
}

func TestVerifyCABundleKeepsEveryOldRule(t *testing.T) {
	// A good certificate does not make a bad bundle good: the first line, the order and the form of
	// the blocks are asked as before.
	w := newWorld(t)
	l := listFor(t, 7, w.a, w.b)
	a, b := w.a.certPEM(), w.b.certPEM()
	mismatch(t, rootlist.VerifyCABundle([]byte("# trust-sequence: 8\n"+a+b), l))
	mismatch(t, rootlist.VerifyCABundle([]byte("# trust-sequence: 7\n"+b+a), l))
	mismatch(t, rootlist.VerifyCABundle([]byte("# trust-sequence: 7\n"+a), l))
}

// The third rule of a certificate of the CA bundle: it names itself as its issuer. The issuer name
// and the subject name, as the bytes of their encoding, are equal. No name is judged otherwise, and
// no clock is read.

// issuedBy makes a certificate for the key k from the template that k's own key signs, with the
// issuer name that the parent has; with the parent's name the same as the subject's it is a root
// certificate.
func issuedBy(t testing.TB, k *key, tmpl *x509.Certificate, issuer pkix.Name) string {
	t.Helper()
	parent := *tmpl
	parent.Subject = issuer
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &parent, &k.priv.PublicKey, k.priv)
	if err != nil {
		t.Fatalf("make certificate: %v", err)
	}
	return pemOf(der)
}

func TestVerifyCABundleNeedsTheIssuerToBeTheSubject(t *testing.T) {
	w := newWorld(t)
	keys := []*key{w.a, w.b, w.c}
	l := listFor(t, 6, keys...)
	subject := pkix.Name{CommonName: "Example Test Root"}
	bundleWith := func(block int, pem string) string {
		var b strings.Builder
		b.WriteString("# trust-sequence: 6\n")
		for i, k := range keys {
			if i == block {
				b.WriteString(pem)
			} else {
				b.WriteString(k.certPEM())
			}
		}
		return b.String()
	}
	t.Run("the witness: the issuer is the subject", func(t *testing.T) {
		for i, k := range keys {
			tmpl := caTemplate()
			tmpl.Subject = subject
			v := rootlist.VerifyCABundle([]byte(bundleWith(i, issuedBy(t, k, tmpl, subject))), l)
			if !v.Accepted {
				t.Fatalf("block %d: %+v", i+1, v)
			}
		}
	})
	for name, issuer := range map[string]pkix.Name{
		"another name":                           {CommonName: "Other Root"},
		"an empty issuer":                        {},
		"the same name in other letter case":     {CommonName: "EXAMPLE TEST ROOT"},
		"the same name with a space more":        {CommonName: "Example Test Root "},
		"the same name and another organisation": {CommonName: "Example Test Root", Organization: []string{"Example Org"}},
		"a longer name that starts the same":     {CommonName: "Example Test Root A"},
	} {
		for i := range keys {
			t.Run(name+", in block "+string(rune('1'+i)), func(t *testing.T) {
				tmpl := caTemplate()
				tmpl.Subject = subject
				v := rootlist.VerifyCABundle([]byte(bundleWith(i, issuedBy(t, keys[i], tmpl, issuer))), l)
				mismatch(t, v)
				if !strings.Contains(v.Detail, "block "+string(rune('1'+i))) || !strings.Contains(v.Detail, "issuer") {
					t.Errorf("the detail does not name the block and the issuer: %q", v.Detail)
				}
			})
		}
	}
	t.Run("the CA flag is asked before the issuer", func(t *testing.T) {
		tmpl := caTemplate()
		tmpl.IsCA = false
		v := rootlist.VerifyCABundle([]byte(bundleWith(1, issuedBy(t, w.b, tmpl, pkix.Name{CommonName: "Other Root"}))), l)
		mismatch(t, v)
		if !strings.Contains(v.Detail, "CA certificate") || strings.Contains(v.Detail, "issuer") {
			t.Errorf("the detail: %q", v.Detail)
		}
	})
	t.Run("a certificate that is not self-signed and has another issuer says the issuer", func(t *testing.T) {
		_, b := certOf(t, w.a, caTemplate(), w.z)
		v := rootlist.VerifyCABundle([]byte(bundleWith(0, b)), l)
		mismatch(t, v)
		if !strings.Contains(v.Detail, "block 1") {
			t.Errorf("the detail: %q", v.Detail)
		}
	})
	t.Run("names, dates, the serial and key usage are still not judged", func(t *testing.T) {
		tmpl := caTemplate()
		tmpl.Subject = pkix.Name{CommonName: "Another Root", Organization: []string{"Example Org"}}
		tmpl.NotBefore, tmpl.NotAfter = time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
		tmpl.SerialNumber = big.NewInt(424242)
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		v := rootlist.VerifyCABundle([]byte(bundleWith(2, issuedBy(t, w.c, tmpl, tmpl.Subject))), l)
		if !v.Accepted {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("the first refusal of two blocks says the first block", func(t *testing.T) {
		tmpl := caTemplate()
		bad := issuedBy(t, w.a, tmpl, pkix.Name{CommonName: "x"})
		bad2 := issuedBy(t, w.c, tmpl, pkix.Name{CommonName: "y"})
		v := rootlist.VerifyCABundle([]byte("# trust-sequence: 6\n"+bad+w.b.certPEM()+bad2), l)
		mismatch(t, v)
		if !strings.Contains(v.Detail, "block 1") {
			t.Errorf("the detail: %q", v.Detail)
		}
	})
}
