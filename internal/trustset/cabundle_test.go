package trustset_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/trustset"
	"ritueel.id/ritueel/internal/verifier"
)

// certOptions says how a hand-made root certificate departs from the profile. The zero value is a
// good one: a CA certificate of a P-384 key, its own issuer, signed by its own key.
type certOptions struct {
	cn       string
	emptyCN  bool
	noCA     bool
	noBC     bool
	issuerCN string            // another name for the issuer
	signedBy *ecdsa.PrivateKey // a key other than its own signs it
	curve    elliptic.Curve    // default P-384
	rsaKey   bool
	padding  int // bytes of an extra extension, to make the certificate large
}

type madeCert struct {
	der  []byte
	cert *x509.Certificate
	pin  string
	key  *ecdsa.PrivateKey
}

var serialSeq int64

func makeCert(t testing.TB, o certOptions) madeCert {
	t.Helper()
	curve := o.curve
	if curve == nil {
		curve = elliptic.P384()
	}
	var priv crypto.Signer
	var pub crypto.PublicKey
	var ec *ecdsa.PrivateKey
	if o.rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = k, &k.PublicKey
	} else {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub, ec = k, &k.PublicKey, k
	}
	cn := o.cn
	if cn == "" && !o.emptyCN {
		cn = "Example Test Root X (TEST ONLY)"
	}
	serialSeq++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1000 + serialSeq),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             ceremony,
		NotAfter:              ceremony.AddDate(3, 0, 0),
		BasicConstraintsValid: !o.noBC,
		IsCA:                  !o.noCA,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	if o.padding > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 99999, 1}, Value: bytes.Repeat([]byte{'a'}, o.padding)}}
	}
	parent := tmpl
	if o.issuerCN != "" {
		parent = &x509.Certificate{Subject: pkix.Name{CommonName: o.issuerCN}}
	}
	signer := priv
	if o.signedBy != nil {
		signer = o.signedBy
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return madeCert{der: der, cert: cert, pin: jws.Pin(cert), key: ec}
}

func (m madeCert) root(label string) trustset.Root {
	return trustset.Root{Label: label, X509SPKISHA256: m.pin, OpenPGPFingerprint: hexOf("fingerprint of " + m.pin)[:40]}
}

// profileRoots makes the roots A to the n-th letter, test roots or real ones, as the profile does.
func profileRoots(t testing.TB, n int, test bool) ([]trustset.Root, [][]byte) {
	t.Helper()
	var roots []trustset.Root
	var certs [][]byte
	for i := 0; i < n; i++ {
		r := newRoot(t, string(rune('A'+i)), test)
		roots = append(roots, r.entry(true))
		certs = append(certs, r.DER)
	}
	return roots, certs
}

// verifyAs asks the reader of the page about a bundle for the roots at a sequence.
func verifyAs(bundle []byte, sequence int64, roots []trustset.Root) rootlist.Verdict {
	l := &rootlist.List{Version: rootlist.Version, Sequence: sequence}
	for _, r := range roots {
		l.Roots = append(l.Roots, rootlist.Root(r))
	}
	return rootlist.VerifyCABundle(bundle, l)
}

func TestMarshalCABundleAccepted(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int
		test bool
		seq  int64
	}{
		{"one test root", 1, true, 1},
		{"two test roots", 2, true, 7},
		{"three real roots", 3, false, 42},
		{"26 test roots", 26, true, 123456},
		{"the highest sequence", 2, true, strictjson.MaxSafeInt},
	} {
		t.Run(c.name, func(t *testing.T) {
			roots, certs := profileRoots(t, c.n, c.test)
			out, err := trustset.MarshalCABundle(c.seq, roots, certs)
			if err != nil {
				t.Fatal(err)
			}
			want := "# trust-sequence: " + strconv.FormatInt(c.seq, 10) + "\n"
			for _, der := range certs {
				want += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			}
			if string(out) != want {
				t.Fatalf("got  %q\nwant %q", out, want)
			}
			if bytes.Contains(out, []byte("\r")) {
				t.Errorf("the bundle has a carriage return")
			}
			if !bytes.HasSuffix(out, []byte("-----END CERTIFICATE-----\n")) {
				t.Errorf("the bundle does not end with the line feed that closes its last block")
			}
			if v := verifyAs(out, c.seq, roots); !v.Accepted {
				t.Errorf("rootlist.VerifyCABundle: %s %s", v.Reason, v.Detail)
			}
			// The reader of the page refuses the bundle for another sequence.
			if v := verifyAs(out, c.seq-1, roots); v.Accepted && c.seq > 1 {
				t.Errorf("the bundle was accepted for the sequence %d", c.seq-1)
			}
		})
	}
}

// The first line names the sequence in plain decimal, and each block is the one spelling that
// pem.EncodeToMemory writes (64 characters to a line), whose bytes are those the caller gave.
func TestMarshalCABundleFirstLineAndBlocks(t *testing.T) {
	roots, certs := profileRoots(t, 2, true)
	out, err := trustset.MarshalCABundle(10, roots, certs)
	if err != nil {
		t.Fatal(err)
	}
	line, rest, _ := strings.Cut(string(out), "\n")
	if line != "# trust-sequence: 10" {
		t.Errorf("first line %q", line)
	}
	for i := 0; i < 2; i++ {
		block, remaining := pem.Decode([]byte(rest))
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			t.Fatalf("block %d is not a plain certificate block", i)
		}
		if !bytes.Equal(block.Bytes, certs[i]) {
			t.Errorf("block %d does not hold the DER the caller gave", i)
		}
		for _, l := range strings.Split(strings.TrimSuffix(rest[:len(rest)-len(remaining)], "\n"), "\n") {
			if len(l) > 64 {
				t.Errorf("block %d: a line of %d characters", i, len(l))
			}
		}
		rest = string(remaining)
	}
	if rest != "" {
		t.Errorf("text after the last block: %q", rest)
	}
}

func TestMarshalCABundleIsDeterministic(t *testing.T) {
	roots, certs := profileRoots(t, 3, true)
	a, err := trustset.MarshalCABundle(5, roots, certs)
	if err != nil {
		t.Fatal(err)
	}
	b, err := trustset.MarshalCABundle(5, roots, certs)
	if err != nil || !bytes.Equal(a, b) {
		t.Errorf("two calls give other bytes (%v)", err)
	}
	// The result does not share memory with the input.
	a[0] ^= 0xff
	certsBefore := bytes.Clone(certs[0])
	c, err := trustset.MarshalCABundle(5, roots, certs)
	if err != nil || !bytes.Equal(b, c) || !bytes.Equal(certs[0], certsBefore) {
		t.Errorf("a change of a result changed a later result (%v)", err)
	}
}

func TestMarshalCABundleRefusals(t *testing.T) {
	roots, certs := profileRoots(t, 2, true)
	good := func() ([]trustset.Root, [][]byte) {
		return append([]trustset.Root(nil), roots...), [][]byte{bytes.Clone(certs[0]), bytes.Clone(certs[1])}
	}
	flip := func(der []byte, at int) []byte {
		out := bytes.Clone(der)
		out[at] ^= 0x01
		return out
	}
	// A certificate whose key point is not on the curve: the last byte of the Y coordinate of the
	// public key, cut out of the DER by hand.
	offCurve := func(r *testRoot) []byte {
		spki := r.Cert.RawSubjectPublicKeyInfo
		at := bytes.Index(r.DER, spki)
		if at < 0 {
			t.Fatal("the SubjectPublicKeyInfo is not in the certificate")
		}
		return flip(r.DER, at+len(spki)-1)
	}
	a, b := newRoot(t, "A", true), newRoot(t, "B", true)
	mid := len(a.DER) / 2

	rsaCert := makeCert(t, certOptions{cn: "Example Test Root A (TEST ONLY)", rsaKey: true})
	p256 := makeCert(t, certOptions{cn: "Example Test Root A (TEST ONLY)", curve: elliptic.P256()})
	notCA := makeCert(t, certOptions{noCA: true})
	noBC := makeCert(t, certOptions{noBC: true})
	otherIssuer := makeCert(t, certOptions{issuerCN: "Example Test Another Name (TEST ONLY)"})
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedByOther := makeCert(t, certOptions{signedBy: other})

	reasons := map[string]string{
		"no certificate for two roots":                 "certificates for 2 roots",
		"one certificate for two roots":                "certificates for 2 roots",
		"three certificates for two roots":             "certificates for 2 roots",
		"roots in the wrong order":                     "label order",
		"certificates in the wrong order":              "does not hold the key of its pin",
		"a nil certificate":                            "empty or longer than",
		"an empty certificate":                         "empty or longer than",
		"a certificate that is not DER":                "not one DER certificate",
		"DER with a byte after it":                     "not one DER certificate",
		"a certificate of more than the limit":         "empty or longer than",
		"an RSA certificate":                           "P-384",
		"a P-256 certificate":                          "P-384",
		"a key point not on the curve":                 "",
		"a certificate of another key":                 "does not hold the key of its pin",
		"a pin that is not the key of the certificate": "does not hold the key of its pin",
		"not a CA certificate":                         "of root B is not a CA certificate",
		"no basic constraints":                         "of root B is not a CA certificate",
		"an issuer that is another name":               "of root B does not name itself as its issuer",
		"signed by another key":                        "of root B does not verify with its own key",
		"a changed byte of the signature":              "of root B does not verify with its own key",
		"a changed byte of the body":                   "of root B does not verify with its own key",
	}
	for _, c := range []struct {
		name string
		mut  func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte)
	}{
		{"no roots and no certificates", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) { return nil, nil }},
		{"no certificate for two roots", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) { return r, nil }},
		{"one certificate for two roots", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) { return r, d[:1] }},
		{"three certificates for two roots", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, append(d, newRoot(t, "C", true).DER)
		}},
		{"the same certificate twice", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], d[0]}
		}},
		{"certificates in the wrong order", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[1], d[0]}
		}},
		{"roots in the wrong order", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return []trustset.Root{r[1], r[0]}, [][]byte{d[1], d[0]}
		}},
		{"27 roots", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			var rs []trustset.Root
			var ds [][]byte
			for i := 0; i < 27; i++ {
				rs = append(rs, fakeRoot(string(rune('A'+i%26)), true))
				ds = append(ds, d[0])
			}
			return rs, ds
		}},
		{"a nil certificate", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) { return r, [][]byte{d[0], nil} }},
		{"an empty certificate", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], {}}
		}},
		{"a certificate that is not DER", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], []byte("not a certificate")}
		}},
		{"a certificate in PEM", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d[1]})}
		}},
		{"DER with a byte after it", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], append(bytes.Clone(d[1]), 0)}
		}},
		{"DER cut short", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], d[1][:len(d[1])-1]}
		}},
		{"a certificate of more than the limit", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], make([]byte, trustset.MaxBytes+1)}
		}},
		{"a certificate at the limit that is not a certificate", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], make([]byte, trustset.MaxBytes)}
		}},
		{"an RSA certificate", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return []trustset.Root{r[0], rsaCert.root("B")}, [][]byte{d[0], rsaCert.der}
		}},
		{"a P-256 certificate", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return []trustset.Root{r[0], p256.root("B")}, [][]byte{d[0], p256.der}
		}},
		{"a key point not on the curve", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], offCurve(b)}
		}},
		{"a certificate of another key", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], newRoot(t, "C", true).DER}
		}},
		{"a pin that is not the key of the certificate", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			r[1].X509SPKISHA256 = hexOf("another pin")
			return r, d
		}},
		{"not a CA certificate", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return []trustset.Root{r[0], notCA.root("B")}, [][]byte{d[0], notCA.der}
		}},
		{"no basic constraints", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return []trustset.Root{r[0], noBC.root("B")}, [][]byte{d[0], noBC.der}
		}},
		{"an issuer that is another name", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return []trustset.Root{r[0], otherIssuer.root("B")}, [][]byte{d[0], otherIssuer.der}
		}},
		{"signed by another key", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return []trustset.Root{r[0], signedByOther.root("B")}, [][]byte{d[0], signedByOther.der}
		}},
		{"a changed byte of the signature", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{d[0], flip(d[1], len(d[1])-1)}
		}},
		{"a changed byte of the body", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			// A byte of the common name, in the issuer and in the subject alike, so that the two
			// still agree and only the signature can refuse it.
			changed := bytes.ReplaceAll(d[1], []byte("Root B"), []byte("Root C"))
			if bytes.Equal(changed, d[1]) {
				t.Fatal("the common name is not in the certificate")
			}
			return r, [][]byte{d[0], changed}
		}},
		{"a changed byte in the middle", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			return r, [][]byte{flip(d[0], mid), d[1]}
		}},
		{"a label that is not a letter", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			r[0].Label = "a"
			return r, d
		}},
		{"a label twice", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			r[1].Label = "A"
			return r, d
		}},
		{"a pin twice", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			r[1].X509SPKISHA256 = r[0].X509SPKISHA256
			return r, d
		}},
		{"a pin in upper case", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			r[0].X509SPKISHA256 = strings.ToUpper(r[0].X509SPKISHA256)
			return r, d
		}},
		{"a fingerprint of the wrong form", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			r[0].OpenPGPFingerprint = "abc"
			return r, d
		}},
		{"a fingerprint on one root only", func(r []trustset.Root, d [][]byte) ([]trustset.Root, [][]byte) {
			r[1].OpenPGPFingerprint = ""
			return r, d
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r, d := good()
			r, d = c.mut(r, d)
			out, err := trustset.MarshalCABundle(7, r, d)
			if err == nil {
				t.Fatalf("accepted: %.200q", out)
			}
			if out != nil {
				t.Errorf("%d bytes come with the error", len(out))
			}
			wantParams(t, err)
			// The refusal is for the reason of the case, so that a check that is gone is not
			// hidden by another that happens to refuse the same input.
			if why, ok := reasons[c.name]; ok && !strings.Contains(err.Error(), why) {
				t.Errorf("the refusal %q does not say %q", err, why)
			}
		})
	}
}

func TestMarshalCABundleSequenceRefusals(t *testing.T) {
	roots, certs := profileRoots(t, 1, true)
	for _, seq := range []int64{0, -1, strictjson.MaxSafeInt + 1, 1 << 62} {
		out, err := trustset.MarshalCABundle(seq, roots, certs)
		if err == nil || out != nil {
			t.Errorf("sequence %d: %q, %v", seq, out, err)
			continue
		}
		wantParams(t, err)
	}
}

// A list never mixes test roots and real roots: the mark is the common name's end, " (TEST ONLY)".
func TestMarshalCABundleNeverMixesTestAndRealRoots(t *testing.T) {
	testA, realB := newRoot(t, "A", true), newRoot(t, "B", false)
	for _, c := range []struct {
		name  string
		roots []*testRoot
	}{
		{"a test root and a real one", []*testRoot{testA, realB}},
		{"a real root and a test one", []*testRoot{newRoot(t, "A", false), newRoot(t, "B", true)}},
		{"two test roots and a real one", []*testRoot{newRoot(t, "A", true), newRoot(t, "B", true), newRoot(t, "C", false)}},
		{"a real root between two test ones", []*testRoot{newRoot(t, "A", true), newRoot(t, "B", false), newRoot(t, "C", true)}},
	} {
		var roots []trustset.Root
		var certs [][]byte
		for _, r := range c.roots {
			roots = append(roots, r.entry(true))
			certs = append(certs, r.DER)
		}
		out, err := trustset.MarshalCABundle(3, roots, certs)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if out != nil {
			t.Errorf("%s: bytes come with the error", c.name)
		}
		wantParams(t, err)
	}
}

// Only a common name that ends with the mark is a test root. A mark in the middle, in lower case or
// without its space is not the mark: such a certificate is real, and a mix with a test root is
// refused while all of them together are accepted.
func TestMarshalCABundleReadsOnlyTheEndOfTheCommonName(t *testing.T) {
	for _, cn := range []string{
		"Example Test (TEST ONLY) Root B",
		"Example Test Root B (test only)",
		"Example Test Root B(TEST ONLY)",
		"Example Test Root B (TEST ONLY) ",
		"Example Test Root B",
		"",
	} {
		real := makeCert(t, certOptions{cn: cn, emptyCN: cn == ""})
		wasTest := strings.HasSuffix(cn, " (TEST ONLY)")
		if wasTest {
			t.Fatalf("%q is the mark", cn)
		}
		// Alone, and with another real root, it is a bundle of real roots.
		other := makeCert(t, certOptions{cn: "Example Test Root A"})
		out, err := trustset.MarshalCABundle(2, []trustset.Root{other.root("A"), real.root("B")}, [][]byte{other.der, real.der})
		if err != nil {
			t.Errorf("%q: %v", cn, err)
			continue
		}
		if v := verifyAs(out, 2, []trustset.Root{other.root("A"), real.root("B")}); !v.Accepted {
			t.Errorf("%q: the reader refuses it: %s", cn, v.Detail)
		}
		// With a test root, it is a mix.
		marked := makeCert(t, certOptions{cn: "Example Test Root A (TEST ONLY)"})
		if _, err := trustset.MarshalCABundle(2, []trustset.Root{marked.root("A"), real.root("B")}, [][]byte{marked.der, real.der}); err == nil {
			t.Errorf("%q with a test root: a mix was accepted", cn)
		}
	}
	// Two certificates with the mark at its end are test roots, whatever else the names hold.
	x := makeCert(t, certOptions{cn: "Example (TEST ONLY) Root A (TEST ONLY)"})
	y := makeCert(t, certOptions{cn: "Another Name Root B (TEST ONLY)"})
	if _, err := trustset.MarshalCABundle(2, []trustset.Root{x.root("A"), y.root("B")}, [][]byte{x.der, y.der}); err != nil {
		t.Errorf("two test roots: %v", err)
	}
}

// A certificate with the profile of the page that is large: 26 of them pass the limit of the
// bundle, though each is under the limit of one certificate.
func TestMarshalCABundleOverTheLimit(t *testing.T) {
	var roots []trustset.Root
	var certs [][]byte
	for i := 0; i < trustset.MaxRoots; i++ {
		m := makeCert(t, certOptions{padding: 8000, cn: "Example Test Root X (TEST ONLY)"})
		roots = append(roots, m.root(string(rune('A'+i))))
		certs = append(certs, m.der)
	}
	out, err := trustset.MarshalCABundle(1, roots, certs)
	if err == nil {
		t.Fatalf("a bundle of %d bytes was written", len(out))
	}
	if out != nil {
		t.Errorf("bytes come with the error")
	}
	wantParams(t, err)
	if !strings.Contains(err.Error(), "ca-bundle.pem is longer than") {
		t.Errorf("the refusal %q does not say that the bundle is too long", err)
	}
	// Fewer of the same certificates are written.
	out, err = trustset.MarshalCABundle(1, roots[:10], certs[:10])
	if err != nil {
		t.Fatalf("a bundle of 10: %v", err)
	}
	if len(out) > trustset.MaxBytes {
		t.Errorf("%d bytes", len(out))
	}
}

// OpenSSL, which did not write the bundle, reads it as a list of trust anchors: each root
// certificate verifies against the bundle, and a certificate of a key that is not in it does not.
func TestMarshalCABundleOpenSSLReadsIt(t *testing.T) {
	roots, certs := profileRoots(t, 2, true)
	bundle, err := trustset.MarshalCABundle(4, roots, certs)
	if err != nil {
		t.Fatal(err)
	}
	at := ceremony.Add(24 * time.Hour)
	for i, der := range certs {
		if err := verifier.OpenSSLVerify(t, bundle, der, at); err != nil {
			t.Errorf("root %s against the bundle: %v", roots[i].Label, err)
		}
	}
	stranger := newRoot(t, "C", true)
	if err := verifier.OpenSSLVerify(t, bundle, stranger.DER, at); err == nil {
		t.Errorf("a root that is not in the bundle verified against it")
	}
}

func TestMarshalCABundleInParallel(t *testing.T) {
	roots, certs := profileRoots(t, 3, true)
	want, err := trustset.MarshalCABundle(9, roots, certs)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	got := make([][]byte, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got[i], errs[i] = trustset.MarshalCABundle(9, roots, certs)
		}()
	}
	close(start)
	wg.Wait()
	for i := range got {
		if errs[i] != nil || !bytes.Equal(got[i], want) {
			t.Errorf("worker %d: %v", i, errs[i])
		}
	}
}
