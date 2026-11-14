package attest_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// selfSigned makes a self-signed CA certificate for a fresh P-384 key, with padding bytes in an extension
// of an unknown number, and returns its DER.
func selfSigned(t testing.TB, pad int, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{Organization: []string{"acme"}, CommonName: "Example Test Self Signed"},
		NotBefore:             clock.AddDate(-1, 0, 0),
		NotAfter:              clock.AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            -1,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	if pad > 0 {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: []int{1, 3, 6, 1, 4, 1, 99999, 1}, Value: bytes.Repeat([]byte{1}, pad)}}
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// selfSignedOfSize makes a self-signed CA of exactly size bytes. The ECDSA signature varies in length by a
// byte or two, so the padding is tried again until it lands.
func selfSignedOfSize(t testing.TB, size int) []byte {
	t.Helper()
	pad := size - 400
	for range 300 {
		der := selfSigned(t, pad, nil)
		switch {
		case len(der) == size:
			return der
		case len(der) < size:
			pad += size - len(der)
		default:
			pad -= len(der) - size
		}
	}
	t.Fatalf("no certificate of %d bytes after 300 tries", size)
	return nil
}

func goodSpec(t testing.TB) (attest.BundleSpec, *attesttest.Maker) {
	t.Helper()
	m := newMaker(t)
	return m.Spec(), m
}

func wantBundleError(t testing.TB, s attest.BundleSpec) {
	t.Helper()
	b, err := attest.NewBundle(s)
	if b != nil {
		t.Error("a bundle beside an error")
	}
	if !errors.Is(err, attest.ErrBundle) {
		t.Fatalf("error %v does not wrap ErrBundle", err)
	}
}

// The page of cards.md, "The attestation bundle": what it trusts is the pinned root; an intermediate is a
// helper that must chain to it. A spec has at least one root, every root is a self-signed CA that verifies
// its own signature, and every intermediate is a CA.
func TestABundleNeedsARootThatIsASelfSignedCA(t *testing.T) {
	s, m := goodSpec(t)
	if _, err := attest.NewBundle(s); err != nil {
		t.Fatalf("the good spec: %v", err)
	}
	leaf, _ := m.PIVChain(t, p384(t), attesttest.Slot{})
	tampered := bytes.Clone(s.Roots[0])
	tampered[len(tampered)-1] ^= 0x01 // the last byte of the signature
	notSelfSigned := s.PIVIntermediates[0]
	notCA := selfSigned(t, 0, func(c *x509.Certificate) { c.IsCA, c.BasicConstraintsValid, c.MaxPathLen = false, true, 0 })
	noBasic := selfSigned(t, 0, func(c *x509.Certificate) {
		c.IsCA, c.BasicConstraintsValid, c.MaxPathLen, c.KeyUsage = false, false, 0, 0
	})

	// A certificate that is signed by its own key under another issuer name is not self-signed.
	otherName := func() []byte {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Example Test Subject"},
			NotBefore: clock.AddDate(-1, 0, 0), NotAfter: clock.AddDate(1, 0, 0), BasicConstraintsValid: true, IsCA: true, MaxPathLen: -1,
			KeyUsage: x509.KeyUsageCertSign,
		}
		issuer := &x509.Certificate{Subject: pkix.Name{CommonName: "Example Test Issuer"}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil || c.CheckSignatureFrom(c) != nil || bytes.Equal(c.RawIssuer, c.RawSubject) {
			t.Fatalf("test setup: %v", err)
		}
		return der
	}()
	cases := map[string]func(*attest.BundleSpec){
		"a root whose issuer name is not its subject": func(s *attest.BundleSpec) { s.Roots = [][]byte{otherName} },
		"no root":                              func(s *attest.BundleSpec) { s.Roots = nil },
		"an empty list of roots":               func(s *attest.BundleSpec) { s.Roots = [][]byte{} },
		"a root that is an intermediate":       func(s *attest.BundleSpec) { s.Roots = [][]byte{notSelfSigned} },
		"a root that is a leaf":                func(s *attest.BundleSpec) { s.Roots = [][]byte{leaf} },
		"a root with a bad self-signature":     func(s *attest.BundleSpec) { s.Roots = [][]byte{tampered} },
		"a good root and a bad one":            func(s *attest.BundleSpec) { s.Roots = append(s.Roots, tampered) },
		"a root that is not a CA":              func(s *attest.BundleSpec) { s.Roots = [][]byte{notCA} },
		"a root with no basic constraints":     func(s *attest.BundleSpec) { s.Roots = [][]byte{noBasic} },
		"an intermediate that is a leaf":       func(s *attest.BundleSpec) { s.PIVIntermediates = [][]byte{leaf} },
		"an openpgp intermediate that is leaf": func(s *attest.BundleSpec) { s.OpenPGPIntermediates = [][]byte{leaf} },
		"a good intermediate and a leaf":       func(s *attest.BundleSpec) { s.PIVIntermediates = append(s.PIVIntermediates, leaf) },
		"an intermediate that is not a CA":     func(s *attest.BundleSpec) { s.PIVIntermediates = [][]byte{notCA} },
		"an intermediate with no constraints":  func(s *attest.BundleSpec) { s.OpenPGPIntermediates = [][]byte{noBasic} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			sp, _ := goodSpec(t)
			change(&sp)
			wantBundleError(t, sp)
		})
	}
	// An intermediate that is a self-signed CA is a CA, and is accepted as an intermediate (it only helps).
	sp := s
	sp.PIVIntermediates = append(slices.Clone(s.PIVIntermediates), selfSigned(t, 0, nil))
	if _, err := attest.NewBundle(sp); err != nil {
		t.Errorf("a CA as an intermediate: %v", err)
	}
	// No intermediate at all is a spec: a chain that needs none (a token issued by the root).
	sp = s
	sp.PIVIntermediates, sp.OpenPGPIntermediates = nil, nil
	if _, err := attest.NewBundle(sp); err != nil {
		t.Errorf("no intermediates: %v", err)
	}
}

// Each group has at most 64 certificates, and each certificate is at most 16 KiB with no byte after it.
func TestABundleIsBounded(t *testing.T) {
	root := selfSigned(t, 0, nil)
	many := func(n int) [][]byte {
		g := make([][]byte, n)
		for i := range g {
			g[i] = root
		}
		return g
	}
	for _, g := range []struct {
		name string
		set  func(*attest.BundleSpec, [][]byte)
	}{
		{"roots", func(s *attest.BundleSpec, v [][]byte) { s.Roots = v }},
		{"piv intermediates", func(s *attest.BundleSpec, v [][]byte) { s.PIVIntermediates = v }},
		{"openpgp intermediates", func(s *attest.BundleSpec, v [][]byte) { s.OpenPGPIntermediates = v }},
	} {
		t.Run(g.name, func(t *testing.T) {
			s := attest.BundleSpec{Version: "v1", Roots: many(1)}
			g.set(&s, many(attest.MaxPinned))
			if _, err := attest.NewBundle(s); err != nil {
				t.Errorf("%d certificates: %v", attest.MaxPinned, err)
			}
			g.set(&s, many(attest.MaxPinned+1))
			wantBundleError(t, s)
		})
	}

	// A certificate at the limit is accepted, one byte over is not.
	atLimit := selfSignedOfSize(t, attest.MaxCertificateSize)
	if _, err := attest.NewBundle(attest.BundleSpec{Version: "v1", Roots: [][]byte{atLimit}}); err != nil {
		t.Errorf("a root of %d bytes: %v", attest.MaxCertificateSize, err)
	}
	over := selfSignedOfSize(t, attest.MaxCertificateSize+1)
	wantBundleError(t, attest.BundleSpec{Version: "v1", Roots: [][]byte{over}})
	wantBundleError(t, attest.BundleSpec{Version: "v1", Roots: [][]byte{root}, PIVIntermediates: [][]byte{over}})
	wantBundleError(t, attest.BundleSpec{Version: "v1", Roots: [][]byte{root}, OpenPGPIntermediates: [][]byte{over}})
	if _, err := attest.NewBundle(attest.BundleSpec{Version: "v1", Roots: [][]byte{root}, PIVIntermediates: [][]byte{atLimit}}); err != nil {
		t.Errorf("an intermediate of the limit: %v", err)
	}
}

// A certificate that is empty, cut, with a byte after its DER, or no DER at all is refused.
func TestABundleReadsOneWholeDERCertificateForEachEntry(t *testing.T) {
	root := selfSigned(t, 0, nil)
	bad := map[string][]byte{
		"empty":            {},
		"nil":              nil,
		"a byte after":     append(bytes.Clone(root), 0),
		"two certificates": append(bytes.Clone(root), root...),
		"cut":              root[:len(root)-1],
		"text":             []byte("not a certificate"),
		"PEM, not DER":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root}),
	}
	for name, der := range bad {
		t.Run(name, func(t *testing.T) {
			wantBundleError(t, attest.BundleSpec{Version: "v1", Roots: [][]byte{der}})
			wantBundleError(t, attest.BundleSpec{Version: "v1", Roots: [][]byte{root}, PIVIntermediates: [][]byte{der}})
			wantBundleError(t, attest.BundleSpec{Version: "v1", Roots: [][]byte{root}, OpenPGPIntermediates: [][]byte{der}})
		})
	}
}

// The version is 1 to 32 printable ASCII characters.
func TestTheVersionOfABundleIsOneToThirtyTwoPrintableCharacters(t *testing.T) {
	root := selfSigned(t, 0, nil)
	good := []string{"a", "2026-11-15", strings.Repeat("v", 32), "with space", "~", " ", "v1.0+build~7"}
	bad := []string{"", strings.Repeat("v", 33), "café", "tab\there", "line\nbreak", "\x1f", "\x7f", "\x00", "\xff", "snow☃", strings.Repeat("v", 31) + "é"}
	for _, v := range good {
		b, err := attest.NewBundle(attest.BundleSpec{Version: v, Roots: [][]byte{root}})
		if err != nil {
			t.Errorf("version %q: %v", v, err)
			continue
		}
		if b.Version() != v {
			t.Errorf("Version() %q, want %q", b.Version(), v)
		}
	}
	for _, v := range bad {
		wantBundleError(t, attest.BundleSpec{Version: v, Roots: [][]byte{root}})
	}
}

// The bundle keeps its own copy: a change that the caller makes to its slices afterwards changes nothing.
func TestABundleKeepsItsOwnCopy(t *testing.T) {
	s, m := goodSpec(t)
	b, err := attest.NewBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	digest := b.SHA256()
	ev := m.PIVEvidence(t, p384(t), attesttest.Slot{})
	for _, g := range [][][]byte{s.Roots, s.PIVIntermediates, s.OpenPGPIntermediates} {
		for _, der := range g {
			clear(der)
		}
	}
	s.Roots, s.PIVIntermediates, s.OpenPGPIntermediates, s.Version = nil, nil, nil, "changed"
	if err := verify(t, b, attest.AppletPIV, ev, clock); err != nil {
		t.Errorf("the chain after the caller changed its slices: %v", err)
	}
	if b.SHA256() != digest || b.Version() == "changed" {
		t.Error("the version or the digest followed the caller's change")
	}
}

// digestOf is the definition of Bundle.SHA256 written again from its comment: SHA-256 over the three
// groups, roots first, then the piv intermediates, then the openpgp ones; a group is four bytes of its count
// and then its certificates sorted by their DER bytes, each as four bytes of its length and its DER.
func digestOf(groups ...[][]byte) string {
	h := sha256.New()
	u32 := func(n int) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		h.Write(b[:])
	}
	for _, g := range groups {
		g = slices.Clone(g)
		slices.SortFunc(g, bytes.Compare)
		u32(len(g))
		for _, der := range g {
			u32(len(der))
			h.Write(der)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

var lowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestTheDigestOfABundle(t *testing.T) {
	s, m := goodSpec(t)
	b, err := attest.NewBundle(s)
	if err != nil {
		t.Fatal(err)
	}
	if !lowerHex64.MatchString(b.SHA256()) {
		t.Fatalf("digest %q is not 64 lower-case hexadecimal digits", b.SHA256())
	}
	if want := digestOf(s.Roots, s.PIVIntermediates, s.OpenPGPIntermediates); b.SHA256() != want {
		t.Errorf("digest %s, want %s", b.SHA256(), want)
	}
	// The same spec, the same digest; the version is not in it.
	s2 := m.Spec()
	s2.Version = "another-version"
	b2, _ := attest.NewBundle(s2)
	if b2.SHA256() != b.SHA256() {
		t.Error("the version changed the digest")
	}

	// The order of a group does not change the digest.
	o := newMaker(t)
	two := attest.BundleSpec{Version: "v", Roots: [][]byte{s.Roots[0], o.Spec().Roots[0]}, PIVIntermediates: s.PIVIntermediates, OpenPGPIntermediates: s.OpenPGPIntermediates}
	swapped := two
	swapped.Roots = [][]byte{two.Roots[1], two.Roots[0]}
	bTwo, err1 := attest.NewBundle(two)
	bSwapped, err2 := attest.NewBundle(swapped)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if bTwo.SHA256() != bSwapped.SHA256() {
		t.Error("the order of the roots changed the digest")
	}
	if bTwo.SHA256() == b.SHA256() {
		t.Error("a second root did not change the digest")
	}

	// Any certificate changes it: another root, another intermediate in either group, none of them.
	variants := map[string]attest.BundleSpec{
		"another root":                      {Version: "v", Roots: o.Spec().Roots, PIVIntermediates: s.PIVIntermediates, OpenPGPIntermediates: s.OpenPGPIntermediates},
		"another piv intermediate":          {Version: "v", Roots: s.Roots, PIVIntermediates: o.Spec().PIVIntermediates, OpenPGPIntermediates: s.OpenPGPIntermediates},
		"another openpgp intermediate":      {Version: "v", Roots: s.Roots, PIVIntermediates: s.PIVIntermediates, OpenPGPIntermediates: o.Spec().OpenPGPIntermediates},
		"no piv intermediate":               {Version: "v", Roots: s.Roots, OpenPGPIntermediates: s.OpenPGPIntermediates},
		"no openpgp intermediate":           {Version: "v", Roots: s.Roots, PIVIntermediates: s.PIVIntermediates},
		"the groups swapped":                {Version: "v", Roots: s.Roots, PIVIntermediates: s.OpenPGPIntermediates, OpenPGPIntermediates: s.PIVIntermediates},
		"the intermediate in both groups":   {Version: "v", Roots: s.Roots, PIVIntermediates: s.PIVIntermediates, OpenPGPIntermediates: s.PIVIntermediates},
		"no intermediate at all":            {Version: "v", Roots: s.Roots, PIVIntermediates: nil, OpenPGPIntermediates: nil},
		"an intermediate repeated in a row": {Version: "v", Roots: s.Roots, PIVIntermediates: append(slices.Clone(s.PIVIntermediates), s.PIVIntermediates...), OpenPGPIntermediates: s.OpenPGPIntermediates},
	}
	seen := map[string]string{b.SHA256(): "the good spec"}
	for name, v := range variants {
		bv, err := attest.NewBundle(v)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if prev, dup := seen[bv.SHA256()]; dup {
			t.Errorf("%s has the digest of %s", name, prev)
		}
		seen[bv.SHA256()] = name
	}

	// A certificate that moves from the last place of a group to the first place of the next one, with the
	// same certificates in the same order, is another bundle: the digest holds the count of each group.
	i1 := s.PIVIntermediates[0]
	i2 := o.Spec().PIVIntermediates[0]
	i3 := m.Spec().OpenPGPIntermediates[0]
	left, errL := attest.NewBundle(attest.BundleSpec{Version: "v", Roots: s.Roots, PIVIntermediates: [][]byte{i1, i2}, OpenPGPIntermediates: [][]byte{i3}})
	right, errR := attest.NewBundle(attest.BundleSpec{Version: "v", Roots: s.Roots, PIVIntermediates: [][]byte{i1}, OpenPGPIntermediates: [][]byte{i2, i3}})
	if errL != nil || errR != nil {
		t.Fatal(errL, errR)
	}
	if left.SHA256() == right.SHA256() {
		t.Error("moving a certificate from the piv group to the openpgp group left the digest as it was")
	}
}

// A nil Bundle and the zero Bundle answer with no version and no digest.
func TestANilOrZeroBundleHasNoVersionAndNoDigest(t *testing.T) {
	var nilB *attest.Bundle
	for _, b := range []*attest.Bundle{nilB, {}} {
		if b.Version() != "" || b.SHA256() != "" {
			t.Errorf("version %q, digest %q", b.Version(), b.SHA256())
		}
	}
}

func pemOf(label string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
}

func TestCertificatesFromPEM(t *testing.T) {
	a, b := []byte{0x30, 0x01, 0x01}, []byte{0x30, 0x02, 0x02, 0x02}
	one := pemOf("CERTIFICATE", a)
	two := append(bytes.Clone(one), pemOf("CERTIFICATE", b)...)

	got, err := attest.CertificatesFromPEM(one)
	if err != nil || len(got) != 1 || !bytes.Equal(got[0], a) {
		t.Fatalf("one block: %v %x", err, got)
	}
	got, err = attest.CertificatesFromPEM(two)
	if err != nil || len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Fatalf("two blocks: %v %x", err, got)
	}
	for name, text := range map[string][]byte{
		"white space between blocks":        append(append(bytes.Clone(one), " \r\n\t\n"...), pemOf("CERTIFICATE", b)...),
		"white space before and after":      append(append([]byte(" \n\t"), one...), "  \n\n"...),
		"windows line breaks":               bytes.ReplaceAll(two, []byte("\n"), []byte("\r\n")),
		"a block with a trailing space too": append(bytes.Clone(one), ' '),
	} {
		if got, err := attest.CertificatesFromPEM(text); err != nil || len(got) == 0 {
			t.Errorf("%s: %v", name, err)
		}
	}

	bad := map[string][]byte{
		"empty":                       {},
		"only white space":            []byte(" \n\n"),
		"text only":                   []byte("hello"),
		"text before a block":         append([]byte("note\n"), one...),
		"text between blocks":         append(append(bytes.Clone(one), "note\n"...), pemOf("CERTIFICATE", b)...),
		"text after a block":          append(bytes.Clone(one), "note\n"...),
		"a private key block":         pemOf("PRIVATE KEY", a),
		"an EC private key block":     pemOf("EC PRIVATE KEY", a),
		"a request block":             pemOf("CERTIFICATE REQUEST", a),
		"a public key block":          pemOf("PUBLIC KEY", a),
		"a trusted certificate":       pemOf("TRUSTED CERTIFICATE", a),
		"a good block then a key":     append(bytes.Clone(one), pemOf("PRIVATE KEY", a)...),
		"a key then a good block":     append(pemOf("PRIVATE KEY", a), one...),
		"a block with a header":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: a}),
		"a block that does not close": []byte("-----BEGIN CERTIFICATE-----\nMAEB\n"),
		"a begin line only":           []byte("-----BEGIN CERTIFICATE-----"),
		"bad Base64 in a block":       []byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"),
		"an end line only":            []byte("-----END CERTIFICATE-----\n"),
		"non UTF-8 bytes":             {0xff, 0xfe, 0x00},
		"NUL bytes":                   bytes.Repeat([]byte{0}, 100),
	}
	for name, text := range bad {
		t.Run(name, func(t *testing.T) {
			if got, err := attest.CertificatesFromPEM(text); err == nil {
				t.Errorf("read %d blocks", len(got))
			} else if got != nil {
				t.Error("a result beside an error")
			}
		})
	}
}

func TestCertificatesFromPEMIsBounded(t *testing.T) {
	block := pemOf("CERTIFICATE", []byte{0x30, 0x01, 0x01})
	sixtyFour := bytes.Repeat(block, attest.MaxPinned)
	if got, err := attest.CertificatesFromPEM(sixtyFour); err != nil || len(got) != attest.MaxPinned {
		t.Errorf("%d blocks: %v %d", attest.MaxPinned, err, len(got))
	}
	if got, err := attest.CertificatesFromPEM(bytes.Repeat(block, attest.MaxPinned+1)); err == nil {
		t.Errorf("%d blocks were read", len(got))
	}
	// 1 MiB of text is read, one byte more is not (white space does not count against the blocks).
	atLimit := append(bytes.Clone(block), bytes.Repeat([]byte(" "), 1<<20-len(block))...)
	if got, err := attest.CertificatesFromPEM(atLimit); err != nil || len(got) != 1 {
		t.Errorf("a text of 1 MiB: %v", err)
	}
	if _, err := attest.CertificatesFromPEM(append(atLimit, ' ')); err == nil {
		t.Error("a text of 1 MiB and a byte was read")
	}
	if _, err := attest.CertificatesFromPEM(bytes.Repeat([]byte("A"), 4<<20)); err == nil {
		t.Error("4 MiB of text was read")
	}
}

// The vectors' own PEM files hold one certificate each and pin a bundle.
func TestTheVectorBundleHoldsTheTestRootAndBothIntermediates(t *testing.T) {
	b := attesttest.VectorBundle(t)
	if b.Version() != "example-test" {
		t.Errorf("version %q", b.Version())
	}
	if !lowerHex64.MatchString(b.SHA256()) {
		t.Errorf("digest %q", b.SHA256())
	}
}
