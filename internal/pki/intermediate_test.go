package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// rfc7093 is the key identifier of RFC 7093, method 1, worked out here from the point: the first 20
// octets of the SHA-256 of the uncompressed point.
func rfc7093(k *ecdsa.PublicKey) []byte {
	point := elliptic.Marshal(elliptic.P384(), k.X, k.Y) //nolint:staticcheck // the uncompressed point, as RFC 7093 hashes it
	sum := sha256.Sum256(point)
	return sum[:20]
}

type interCase struct {
	name   string
	csr    string
	serial string
	at     time.Time
}

// interCases are the cases of expected.txt, written as parameters; the times and the serials are
// those of reproduce.sh.
func interCases() []interCase {
	return []interCase{
		{"inter-nc", "csr-nc", "73a1553666c0f868e34f116d4af6a1acb8c6b6", ceremony},
		{"inter-eku", "csr-eku", "8000000000000000", utc(2027, 1, 31, 10, 20, 30)},
		{"inter-eku-reversed", "csr-eku-reversed", "7fffffffffffffffffffffffffffffffffffffff", utc(2049, 12, 31, 23, 59, 59)},
	}
}

func fixtureInterParams(t testing.TB, c interCase) pki.IntermediateParams {
	t.Helper()
	return pki.IntermediateParams{
		CSR:           fixtureCSR(t, c.csr+".csr.pem").DER(),
		IssuerSubject: loadAnswers(t).bytes(t, "issuer"),
		IssuerKey:     fixturePublicKey(t, "root.pub.pem"),
		Roots:         []pki.RootRef{{Subject: loadAnswers(t).bytes(t, "issuer"), Key: fixturePublicKey(t, "root.pub.pem")}},
		CeremonyTime:  c.at,
		Serial:        hexBig(t, c.serial),
	}
}

func TestIntermediateTBSKnownAnswers(t *testing.T) {
	want := loadAnswers(t)
	for _, c := range interCases() {
		t.Run(c.name, func(t *testing.T) {
			p := fixtureInterParams(t, c)
			tbs, err := intermediateTBS(t, p)
			if err != nil {
				t.Fatal(err)
			}
			if got, w := hex.EncodeToString(tbs), want.text(t, c.name+".tbs"); got != w {
				t.Errorf("the body differs from the one OpenSSL made:\n got %s\nwant %s", got, w)
			}
			if got, w := pki.TBSSHA256(tbs), want.text(t, c.name+".tbs.sha256"); got != w {
				t.Errorf("TBSSHA256 = %s, want %s", got, w)
			}
			if got, w := hex.EncodeToString(pki.TBSDigest(tbs)), want.text(t, c.name+".tbs.sha384"); got != w {
				t.Errorf("TBSDigest = %s, want %s", got, w)
			}
			again, err := intermediateTBS(t, p)
			if err != nil || !bytes.Equal(again, tbs) {
				t.Errorf("a second call gives %x, %v", again, err)
			}
			p.CeremonyTime = p.CeremonyTime.In(time.FixedZone("UTC-7", -7*3600))
			zoned, err := intermediateTBS(t, p)
			if err != nil || !bytes.Equal(zoned, tbs) {
				t.Errorf("the same instant in another zone gives %x, %v", zoned, err)
			}
		})
	}
}

// A request that carries the extensions of csr-nc, parsed with Go, gives the rows of
// hand-off-contract.md, "What is issued".
func TestIntermediateRows(t *testing.T) {
	root := buildRoot(t, nil)
	key := newKey(t)
	subject := pkix.Name{Organization: []string{"acme"}, CommonName: "acme example ca"}
	csr := makeCSR(t, csrOptions{key: key, subject: subject, exts: goodExtensions()})
	got := root.issue(t, csr, nil)
	cert := got.parsed

	if cert.Version != 3 || cert.SerialNumber.Cmp(aSerial) != 0 || cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("version %d, serial %x, algorithm %v", cert.Version, cert.SerialNumber, cert.SignatureAlgorithm)
	}
	if !bytes.Equal(cert.RawIssuer, root.parsed.RawSubject) {
		t.Error("the issuer is not the subject of the root, byte for byte")
	}
	if !bytes.Equal(cert.RawSubject, csr.RawSubject) {
		t.Error("the subject is not the subject of the request, byte for byte")
	}
	if !bytes.Equal(cert.RawSubjectPublicKeyInfo, csr.SPKI()) {
		t.Error("the public key is not the key of the request, byte for byte")
	}
	if !cert.NotBefore.Equal(ceremony) || !cert.NotAfter.Equal(utc(2027, 12, 15, 12, 0, 0)) {
		t.Errorf("validity = %v to %v, want 13 calendar months from the ceremony", cert.NotBefore, cert.NotAfter)
	}
	wantIDs := []string{"2.5.29.19", "2.5.29.15", "2.5.29.30", "2.5.29.37", "2.5.29.14", "2.5.29.35"}
	if ids := extensionIDs(cert); strings.Join(ids, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("extensions = %v, want %v", ids, wantIDs)
	}
	wantCritical := []bool{true, true, true, false, false, false}
	for i, e := range cert.Extensions {
		if i < len(wantCritical) && e.Critical != wantCritical[i] {
			t.Errorf("extension %s critical = %v, want %v", e.Id, e.Critical, wantCritical[i])
		}
	}
	if !cert.IsCA || cert.MaxPathLen != 0 || !cert.MaxPathLenZero {
		t.Errorf("IsCA = %v, MaxPathLen = %d, MaxPathLenZero = %v; want cA true and path length 0", cert.IsCA, cert.MaxPathLen, cert.MaxPathLenZero)
	}
	if bc := extensionOf(cert, oidBasicConstraints); bc == nil || !bytes.Equal(bc.Value, []byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00}) {
		t.Errorf("basic constraints value = %v", bc)
	}
	if ku := extensionOf(cert, oidKeyUsage); ku == nil || !bytes.Equal(ku.Value, csr.Extensions[1].Value) || !bytes.Equal(ku.Value, []byte{0x03, 0x02, 0x01, 0x06}) {
		t.Errorf("key usage value = %v, want the request's", ku)
	}
	if cert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %b", cert.KeyUsage)
	}
	if nc := extensionOf(cert, oidNameConstraints); nc == nil || !bytes.Equal(nc.Value, csr.Extensions[2].Value) {
		t.Errorf("name constraints value = %v, want the request's, byte for byte", nc)
	}
	if got, want := cert.SubjectKeyId, rfc7093(&key.PublicKey); !bytes.Equal(got, want) {
		t.Errorf("subject key identifier = %x, want %x", got, want)
	}
	if got, want := cert.AuthorityKeyId, rfc7093(&root.key.PublicKey); !bytes.Equal(got, want) {
		t.Errorf("authority key identifier = %x, want %x", got, want)
	}
	// The extended key usage is the request's, byte for byte (the purposes and their order), and not critical.
	if eku := extensionOf(cert, oidExtKeyUsage); eku == nil || eku.Critical || !bytes.Equal(eku.Value, csr.Extensions[3].Value) {
		t.Errorf("extended key usage = %+v, want the request's value, not critical", eku)
	}
	if !slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
		t.Errorf("the purposes read by the standard library are %v", cert.ExtKeyUsage)
	}
	if err := cert.CheckSignatureFrom(root.parsed); err != nil {
		t.Errorf("the root's signature does not verify: %v", err)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		t.Error("the public key of the certificate is not the key of the request")
	}
	if got, want := pki.TBSSHA256(got.tbs), sha256.Sum256(cert.RawTBSCertificate); got != hex.EncodeToString(want[:]) {
		t.Errorf("TBSSHA256 = %s", got)
	}
}

// Subjects are copied as they are, in the string types and with the printable ASCII characters that the contract allows (a look-alike
// letter of another script is refused: see chars_test.go; the row that had one is replaced by the punctuation of ASCII).
func TestIntermediateSubjectIsCopied(t *testing.T) {
	root := buildRoot(t, nil)
	printable := tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, tlv(0x13, []byte("acme ca")))))
	// One relative name (a SET) of two attributes, in DER order: the shorter encoding of the common
	// name comes before the longer one of the organisation. (The row was once in the other order, which is
	// not DER, and it was called "two RDNs".)
	cnAttr := tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, tlv(0x0c, []byte("ca")))
	oAttr := tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x0a}, tlv(0x0c, []byte("acme")))
	multi := tlv(0x30, tlv(0x31, cnAttr, oAttr))
	twoRDNs := tlv(0x30, tlv(0x31, oAttr), tlv(0x31, cnAttr))
	punctuation := tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, tlv(0x0c, []byte("a,b+c=\"d\"\\e<f>;#!~")))))
	// The attribute "name" (2.5.4.41) has the upper bound 32768; a common name has 64.
	long := tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x29}, tlv(0x0c, bytes.Repeat([]byte("x"), 300)))))
	for name, raw := range map[string][]byte{"PrintableString": printable, "one relative name of two attributes, in DER order": multi, "two relative names": twoRDNs, "punctuation of ASCII": punctuation, "a name attribute of 300 characters": long} {
		t.Run(name, func(t *testing.T) {
			csr := makeCSR(t, csrOptions{rawSubject: raw, exts: goodExtensions()})
			if !bytes.Equal(csr.RawSubject, raw) {
				t.Fatal("the test request does not hold the subject")
			}
			got := root.issue(t, csr, nil)
			if !bytes.Equal(got.parsed.RawSubject, raw) {
				t.Errorf("subject = %x, want %x", got.parsed.RawSubject, raw)
			}
		})
	}
}

// The issuer is copied as it is, in whatever string type it has.
func TestIntermediateIssuerIsCopied(t *testing.T) {
	root := buildRoot(t, nil)
	for name, raw := range map[string][]byte{
		"PrintableString": tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, tlv(0x13, []byte("Example Root"))))),
		"two RDNs":        tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x0a}, tlv(0x0c, []byte("acme")))), tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, tlv(0x0c, []byte("Root"))))),
	} {
		t.Run(name, func(t *testing.T) {
			tbs, err := intermediateTBS(t, func() pki.IntermediateParams {
				p := root.interParams(withExtensions(t, goodExtensions()...))
				p.IssuerSubject = raw
				return p
			}())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(tbs, raw) {
				t.Error("the issuer name is not in the body as given")
			}
		})
	}
}

// What the extended key usage of a request becomes: the value as given, not critical, in the place after the name constraints, the
// purposes in the order of the request. Which requests are refused for it is TestExtendedKeyUsageFormsAreRefused.
func TestIntermediateExtendedKeyUsageIsCopied(t *testing.T) {
	root := buildRoot(t, nil)
	cases := []struct {
		name string
		eku  pkix.Extension
		want []x509.ExtKeyUsage
	}{
		{"serverAuth", extExtKeyUsage(false, oidServerAuth), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"clientAuth", extExtKeyUsage(false, oidClientAuth), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"serverAuth then clientAuth", extExtKeyUsage(false, oidServerAuth, oidClientAuth), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}},
		{"clientAuth then serverAuth", extExtKeyUsage(false, oidClientAuth, oidServerAuth), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csr := withExtensions(t, append(goodExtensions()[:3:3], c.eku)...)
			got := root.issue(t, csr, nil).parsed
			e := extensionOf(got, oidExtKeyUsage)
			if e == nil {
				t.Fatal("the extended key usage was not copied")
			}
			if !bytes.Equal(e.Value, c.eku.Value) {
				t.Errorf("value = %x, want %x", e.Value, c.eku.Value)
			}
			if e.Critical {
				t.Error("the extended key usage of the certificate is critical")
			}
			if !slices.Equal(got.ExtKeyUsage, c.want) {
				t.Errorf("purposes = %v, want %v, in the order of the request", got.ExtKeyUsage, c.want)
			}
			wantIDs := []string{"2.5.29.19", "2.5.29.15", "2.5.29.30", "2.5.29.37", "2.5.29.14", "2.5.29.35"}
			if ids := extensionIDs(got); strings.Join(ids, ",") != strings.Join(wantIDs, ",") {
				t.Errorf("extensions = %v, want %v", ids, wantIDs)
			}
			wantCritical := []bool{true, true, true, false, false, false}
			for i, x := range got.Extensions {
				if x.Critical != wantCritical[i] {
					t.Errorf("extension %s critical = %v, want %v", x.Id, x.Critical, wantCritical[i])
				}
			}
		})
	}
}

// The key usage is copied exactly, for every combination the profile accepts.
func TestIntermediateKeyUsageIsCopied(t *testing.T) {
	root := buildRoot(t, nil)
	cases := []struct {
		name string
		bits []int
		want x509.KeyUsage
	}{
		{"keyCertSign alone", []int{kuKeyCertSign}, x509.KeyUsageCertSign},
		{"keyCertSign and cRLSign", []int{kuKeyCertSign, kuCRLSign}, x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
		{"digitalSignature and keyCertSign", []int{kuDigitalSignature, kuKeyCertSign}, x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign},
		{"all three", []int{kuDigitalSignature, kuKeyCertSign, kuCRLSign}, x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ext := extKeyUsage(c.bits...)
			csr := withExtensions(t, extBasicConstraints(), ext, extNameConstraints("example.org"))
			got := root.issue(t, csr, nil).parsed
			ku := extensionOf(got, oidKeyUsage)
			if ku == nil || !bytes.Equal(ku.Value, ext.Value) || !ku.Critical {
				t.Errorf("key usage extension = %+v, want the request's value, critical", ku)
			}
			if got.KeyUsage != c.want {
				t.Errorf("key usage = %b, want %b", got.KeyUsage, c.want)
			}
			// Basic constraints, key usage, name constraints, extended key usage, and the two key identifiers.
			if len(got.Extensions) != 6 {
				t.Errorf("%d extensions, want 6: %v", len(got.Extensions), extensionIDs(got))
			}
		})
	}
}

// --- what is refused --------------------------------------------------------------------------

func TestIntermediateTBSRefusesTheRequest(t *testing.T) {
	root := buildRoot(t, nil)
	good := goodExtensions()
	bc, ku, nc := good[0], good[1], good[2]
	withBC := func(v []byte, critical bool) pkix.Extension {
		return pkix.Extension{Id: oidBasicConstraints, Critical: critical, Value: v}
	}
	withKU := func(v []byte, critical bool) pkix.Extension {
		return pkix.Extension{Id: oidKeyUsage, Critical: critical, Value: v}
	}
	withNC := func(v []byte, critical bool) pkix.Extension {
		return pkix.Extension{Id: oidNameConstraints, Critical: critical, Value: v}
	}
	withEKU := func(v []byte, critical bool) pkix.Extension {
		return pkix.Extension{Id: oidExtKeyUsage, Critical: critical, Value: v}
	}
	other := func(id asn1.ObjectIdentifier, critical bool, value []byte) pkix.Extension {
		return pkix.Extension{Id: id, Critical: critical, Value: value}
	}
	san := other(oidSAN, false, tlv(0x30, tlv(0x82, []byte("www.example.org"))))
	cases := []struct {
		name string
		exts []pkix.Extension
	}{
		// An extension outside the four.
		{"a subject alternative name", append(append([]pkix.Extension{}, good...), san)},
		{"a critical subject alternative name", append(append([]pkix.Extension{}, good...), other(oidSAN, true, san.Value))},
		{"a subject key identifier", append(append([]pkix.Extension{}, good...), other(oidSubjectKeyID, false, tlv(0x04, bytes.Repeat([]byte{1}, 20))))},
		{"an authority key identifier", append(append([]pkix.Extension{}, good...), other(oidAuthorityKeyID, false, tlv(0x30, tlv(0x80, bytes.Repeat([]byte{1}, 20)))))},
		{"certificate policies", append(append([]pkix.Extension{}, good...), other(asn1.ObjectIdentifier{2, 5, 29, 32}, false, tlv(0x30, tlv(0x30, []byte{0x06, 0x01, 0x2a}))))},
		{"a CRL distribution point", append(append([]pkix.Extension{}, good...), other(asn1.ObjectIdentifier{2, 5, 29, 31}, false, tlv(0x30, tlv(0x30))))},
		{"an extension of no known kind, not critical", append(append([]pkix.Extension{}, good...), other(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, false, tlv(0x05)))},
		{"an extension of no known kind, critical", append(append([]pkix.Extension{}, good...), other(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, true, tlv(0x05)))},
		{"authority information access", append(append([]pkix.Extension{}, good...), other(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}, false, tlv(0x30)))},
		{"inhibit any policy", append(append([]pkix.Extension{}, good...), other(asn1.ObjectIdentifier{2, 5, 29, 54}, true, tlv(0x02, []byte{0})))},
		{"policy constraints", append(append([]pkix.Extension{}, good...), other(asn1.ObjectIdentifier{2, 5, 29, 36}, true, tlv(0x30)))},

		// Missing.
		{"no basic constraints", []pkix.Extension{ku, nc}},
		{"no key usage", []pkix.Extension{bc, nc}},
		{"no extensions at all", nil},

		// Basic constraints.
		{"basic constraints that are not critical", []pkix.Extension{withBC(bc.Value, false), ku, nc}},
		{"a path length of 1", []pkix.Extension{withBC([]byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x01}, true), ku, nc}},
		{"a path length of 2", []pkix.Extension{withBC([]byte{0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x02}, true), ku, nc}},
		{"no path length", []pkix.Extension{withBC([]byte{0x30, 0x03, 0x01, 0x01, 0xff}, true), ku, nc}},
		{"cA false", []pkix.Extension{withBC([]byte{0x30, 0x00}, true), ku, nc}},
		{"cA false, path length 0", []pkix.Extension{withBC([]byte{0x30, 0x03, 0x02, 0x01, 0x00}, true), ku, nc}},
		{"cA written as an explicit false", []pkix.Extension{withBC([]byte{0x30, 0x06, 0x01, 0x01, 0x00, 0x02, 0x01, 0x00}, true), ku, nc}},
		{"basic constraints with bytes after the sequence", []pkix.Extension{withBC(append(append([]byte{}, bc.Value...), 0), true), ku, nc}},
		{"basic constraints that are not a sequence", []pkix.Extension{withBC([]byte{0x04, 0x00}, true), ku, nc}},
		{"empty basic constraints", []pkix.Extension{withBC(nil, true), ku, nc}},

		// Key usage.
		{"a key usage that is not critical", []pkix.Extension{bc, withKU(ku.Value, false), nc}},
		{"digitalSignature alone", []pkix.Extension{bc, extKeyUsage(kuDigitalSignature), nc}},
		{"cRLSign alone", []pkix.Extension{bc, extKeyUsage(kuCRLSign), nc}},
		{"digitalSignature and cRLSign without keyCertSign", []pkix.Extension{bc, extKeyUsage(kuDigitalSignature, kuCRLSign), nc}},
		{"no bit at all", []pkix.Extension{bc, withKU([]byte{0x03, 0x01, 0x00}, true), nc}},
		{"contentCommitment with keyCertSign", []pkix.Extension{bc, extKeyUsage(1, kuKeyCertSign), nc}},
		{"keyEncipherment with keyCertSign", []pkix.Extension{bc, extKeyUsage(2, kuKeyCertSign), nc}},
		{"dataEncipherment with keyCertSign", []pkix.Extension{bc, extKeyUsage(3, kuKeyCertSign), nc}},
		{"keyAgreement with keyCertSign", []pkix.Extension{bc, extKeyUsage(4, kuKeyCertSign), nc}},
		{"encipherOnly with keyCertSign", []pkix.Extension{bc, extKeyUsage(kuKeyCertSign, 7), nc}},
		{"decipherOnly with keyCertSign", []pkix.Extension{bc, extKeyUsage(kuKeyCertSign, 8), nc}},
		{"keyCertSign, cRLSign and keyEncipherment", []pkix.Extension{bc, extKeyUsage(2, kuKeyCertSign, kuCRLSign), nc}},
		{"a key usage that keeps its zero bits", []pkix.Extension{bc, withKU([]byte{0x03, 0x02, 0x00, 0x06}, true), nc}},
		{"a key usage that keeps a zero octet", []pkix.Extension{bc, withKU([]byte{0x03, 0x03, 0x01, 0x06, 0x00}, true), nc}},
		{"a key usage with bytes after it", []pkix.Extension{bc, withKU(append(append([]byte{}, ku.Value...), 0), true), nc}},
		{"a key usage that is an octet string", []pkix.Extension{bc, withKU([]byte{0x04, 0x01, 0x06}, true), nc}},
		{"empty key usage", []pkix.Extension{bc, withKU(nil, true), nc}},

		// Name constraints.
		{"name constraints that are not critical", []pkix.Extension{bc, ku, withNC(nc.Value, false)}},
		{"name constraints that are an octet string", []pkix.Extension{bc, ku, withNC([]byte{0x04, 0x01, 0x00}, true)}},
		{"name constraints that are a set", []pkix.Extension{bc, ku, withNC([]byte{0x31, 0x03, 0x02, 0x01, 0x05}, true)}},
		{"empty name constraints", []pkix.Extension{bc, ku, withNC([]byte{0x30, 0x00}, true)}},
		{"name constraints with bytes after the sequence", []pkix.Extension{bc, ku, withNC(append(append([]byte{}, nc.Value...), 0x00), true)}},
		{"name constraints with a second sequence", []pkix.Extension{bc, ku, withNC(append(append([]byte{}, nc.Value...), nc.Value...), true)}},
		{"name constraints of indefinite length", []pkix.Extension{bc, ku, withNC([]byte{0x30, 0x80, 0x00, 0x00}, true)}},
		{"name constraints of the sequence tag number in the context class", []pkix.Extension{bc, ku, withNC([]byte{0xb0, 0x03, 0x02, 0x01, 0x05}, true)}},
		{"name constraints of the sequence tag number, primitive", []pkix.Extension{bc, ku, withNC([]byte{0x10, 0x03, 0x02, 0x01, 0x05}, true)}},
		{"name constraints that are context-specific", []pkix.Extension{bc, ku, withNC([]byte{0xa0, 0x03, 0x02, 0x01, 0x05}, true)}},
		{"name constraints cut short", []pkix.Extension{bc, ku, withNC(nc.Value[:len(nc.Value)-1], true)}},
		{"empty-valued name constraints", []pkix.Extension{bc, ku, withNC(nil, true)}},

		// Extended key usage (the shape only: which purposes is the policy's).
		{"an empty list of purposes", append(append([]pkix.Extension{}, good[:3]...), withEKU([]byte{0x30, 0x00}, false))},
		{"a list of integers", append(append([]pkix.Extension{}, good[:3]...), withEKU([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, false))},
		{"purposes that are an octet string", append(append([]pkix.Extension{}, good[:3]...), withEKU([]byte{0x04, 0x00}, false))},
		{"purposes with bytes after the list", append(append([]pkix.Extension{}, good[:3]...), withEKU(append(append([]byte{}, extExtKeyUsage(false, oidServerAuth).Value...), 0), false))},
		{"purposes cut short", append(append([]pkix.Extension{}, good[:3]...), withEKU(extExtKeyUsage(false, oidServerAuth).Value[:5], true))},
		{"purposes of indefinite length", append(append([]pkix.Extension{}, good[:3]...), withEKU([]byte{0x30, 0x80, 0x00, 0x00}, false))},
		{"a purpose with a trailing octet inside the list", append(append([]pkix.Extension{}, good[:3]...), withEKU([]byte{0x30, 0x0b, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x00, 0x00, 0x00}, false))},
		{"empty-valued purposes", append(append([]pkix.Extension{}, good[:3]...), withEKU(nil, false))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			csr := withExtensions(t, c.exts...)
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
}

// An extension that appears twice cannot be in a request that Go parses, so the request that
// carries it is made by hand from a parsed one.
func TestIntermediateTBSRefusesAnExtensionTwice(t *testing.T) {
	root := buildRoot(t, nil)
	base := withExtensions(t, goodExtensions()...)
	for i, e := range base.Extensions {
		for _, critical := range []bool{e.Critical, !e.Critical} {
			t.Run(fmt.Sprintf("%s critical %v", e.Id, critical), func(t *testing.T) {
				csr := copyCSR(base)
				dup := e
				dup.Critical = critical
				csr.Extensions = append(csr.Extensions, dup)
				tbs, err := intermediateTBS(t, root.interParams(csr))
				refused(t, err, pki.ErrRequest)
				if tbs != nil {
					t.Errorf("a body %x came with the error", tbs)
				}
				_ = i
			})
		}
	}
	if len(base.Extensions) != 4 {
		t.Fatalf("the base request has %d extensions, want 4 (basic constraints, key usage, name constraints, extended key usage)", len(base.Extensions))
	}
}

func TestIntermediateTBSRefusesTheKeyAndTheSignatureOfTheRequest(t *testing.T) {
	root := buildRoot(t, nil)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name string
		csr  *testCSR
	}{
		{"a P-256 key", makeCSR(t, csrOptions{key: p256, exts: goodExtensions()})},
		{"a P-521 key", makeCSR(t, csrOptions{key: p521, exts: goodExtensions()})},
		{"an RSA key", makeCSR(t, csrOptions{key: rsaKey, exts: goodExtensions()})},
		{"an Ed25519 key", makeCSR(t, csrOptions{key: edKey, exts: goodExtensions()})},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbs, err := intermediateTBS(t, root.interParams(c.csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
			if got := pki.CheckOf(err); got != pki.CheckAlgorithm {
				t.Errorf("check %q, want algorithm-unsupported", got)
			}
		})
	}

	good := withExtensions(t, goodExtensions()...)
	spkiOf := func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	goodSPKI := spkiOf(good.Key)
	for _, c := range []struct {
		name  string
		spki  []byte
		check pki.Check
	}{
		{"a request with no key", []byte{0x30, 0x00}, pki.CheckMalformed},
		{"a key that is not in the canonical form", append(append([]byte(nil), goodSPKI[:len(goodSPKI)-1]...), goodSPKI[len(goodSPKI)-1]^0x01), pki.CheckAlgorithm},
		{"a key with a byte more", append(append([]byte(nil), goodSPKI...), 0), pki.CheckMalformed},
		{"a key cut short", goodSPKI[:len(goodSPKI)-1], pki.CheckMalformed},
		{"a key that is a bare bit string", tlv(0x03, []byte{0, 4}), pki.CheckMalformed},
	} {
		t.Run(c.name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubjectPublicKeyInfo = c.spki
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body came with the error")
			}
			if got := pki.CheckOf(err); got != c.check {
				t.Errorf("check %q, want %q", got, c.check)
			}
		})
	}
	t.Run("a key that is another key than the one that signed", func(t *testing.T) {
		csr := copyCSR(good)
		csr.RawSubjectPublicKeyInfo = spkiOf(newKey(t))
		_, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
		if got := pki.CheckOf(err); got != pki.CheckPossession {
			t.Errorf("check %q, want possession-invalid", got)
		}
	})

	// A request whose signature does not verify with its own key.
	key := newKey(t)
	der := makeCSR(t, csrOptions{key: key, exts: goodExtensions()}).DER()
	tamper := func(t *testing.T, edit func(der []byte)) *testCSR {
		t.Helper()
		d := append([]byte(nil), der...)
		edit(d)
		return &testCSR{Fixed: d}
	}
	sigTests := map[string]func(d []byte){
		"the last byte of the signature": func(d []byte) { d[len(d)-1] ^= 0x01 },
		"a byte inside the signature":    func(d []byte) { d[len(d)-10] ^= 0x01 },
		"a letter of the subject":        func(d []byte) { d[bytes.Index(d, []byte("acme example ca"))] ^= 0x02 },
		"a byte of the name constraints": func(d []byte) { d[bytes.Index(d, []byte("example.org"))] ^= 0x01 },
	}
	for name, edit := range sigTests {
		t.Run("a request with "+name+" changed", func(t *testing.T) {
			csr := tamper(t, edit)
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
	t.Run("the request itself is fine", func(t *testing.T) {
		csr := tamper(t, func([]byte) {})
		if _, err := intermediateTBS(t, root.interParams(csr)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestIntermediateTBSRefusesTheSubject(t *testing.T) {
	root := buildRoot(t, nil)
	t.Run("an empty subject in a made request", func(t *testing.T) {
		csr := makeCSR(t, csrOptions{rawSubject: []byte{0x30, 0x00}, exts: goodExtensions()})
		_, err := intermediateTBS(t, root.interParams(csr))
		refused(t, err, pki.ErrRequest)
	})
	good := withExtensions(t, goodExtensions()...)
	bad := map[string][]byte{
		"no bytes":                      nil,
		"an empty sequence":             {0x30, 0x00},
		"an empty relative name":        {0x30, 0x02, 0x31, 0x00},
		"one empty relative name among": tlv(0x30, tlv(0x31, tlv(0x30, []byte{0x06, 0x03, 0x55, 0x04, 0x03}, tlv(0x0c, []byte("a")))), tlv(0x31)),
		"bytes that are not a name":     {0x01, 0x02, 0x03},
		"bytes after the name":          append(append([]byte{}, good.RawSubject...), 0x00),
		"a name cut short":              good.RawSubject[:len(good.RawSubject)-1],
		"a set":                         append([]byte{0x31}, good.RawSubject[1:]...),
		"a sequence of integers":        {0x30, 0x03, 0x02, 0x01, 0x05},
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			csr := copyCSR(good)
			csr.RawSubject = raw
			tbs, err := intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
}

func TestIntermediateTBSRefusesTheParameters(t *testing.T) {
	root := buildRoot(t, nil)
	csr := withExtensions(t, goodExtensions()...)
	pow := func(n uint) *big.Int { return new(big.Int).Lsh(big.NewInt(1), n) }
	cases := []struct {
		name string
		mod  func(*pki.IntermediateParams)
	}{
		{"no request", func(p *pki.IntermediateParams) { p.CSR = nil }},
		{"the zero time", func(p *pki.IntermediateParams) { p.CeremonyTime = time.Time{} }},
		{"the zero time in another zone", func(p *pki.IntermediateParams) { p.CeremonyTime = time.Time{}.In(time.FixedZone("UTC+5", 5*3600)) }},
		{"a nanosecond", func(p *pki.IntermediateParams) { p.CeremonyTime = ceremony.Add(time.Nanosecond) }},
		{"a millisecond", func(p *pki.IntermediateParams) { p.CeremonyTime = ceremony.Add(time.Millisecond) }},
		{"the year 10000", func(p *pki.IntermediateParams) { p.CeremonyTime = utc(10000, 1, 1, 0, 0, 0) }},
		{"an end in the year 10000", func(p *pki.IntermediateParams) { p.CeremonyTime = utc(9999, 12, 31, 23, 59, 59) }},
		{"no serial", func(p *pki.IntermediateParams) { p.Serial = nil }},
		{"serial zero", func(p *pki.IntermediateParams) { p.Serial = big.NewInt(0) }},
		{"a negative serial", func(p *pki.IntermediateParams) { p.Serial = big.NewInt(-1) }},
		{"a serial of 63 bits", func(p *pki.IntermediateParams) { p.Serial = new(big.Int).Sub(pow(63), big.NewInt(1)) }},
		{"a serial of 160 bits", func(p *pki.IntermediateParams) { p.Serial = pow(159) }},
		{"no issuer name", func(p *pki.IntermediateParams) { p.IssuerSubject = nil }},
		{"an empty issuer name", func(p *pki.IntermediateParams) { p.IssuerSubject = []byte{} }},
		{"an issuer name that is an empty sequence", func(p *pki.IntermediateParams) { p.IssuerSubject = []byte{0x30, 0x00} }},
		{"an issuer name with an empty relative name", func(p *pki.IntermediateParams) { p.IssuerSubject = []byte{0x30, 0x02, 0x31, 0x00} }},
		{"an issuer name that is junk", func(p *pki.IntermediateParams) { p.IssuerSubject = []byte("not a name") }},
		{"an issuer name with a byte after it", func(p *pki.IntermediateParams) {
			p.IssuerSubject = append(append([]byte{}, root.parsed.RawSubject...), 0)
		}},
		{"an issuer name cut short", func(p *pki.IntermediateParams) {
			p.IssuerSubject = root.parsed.RawSubject[:len(root.parsed.RawSubject)-1]
		}},
		{"an issuer name that is a set", func(p *pki.IntermediateParams) {
			p.IssuerSubject = append([]byte{0x31}, root.parsed.RawSubject[1:]...)
		}},
		{"no issuer key", func(p *pki.IntermediateParams) { p.IssuerKey = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := root.interParams(csr)
			c.mod(&p)
			tbs, err := intermediateTBS(t, p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
	for name, bad := range badKeys(t) {
		t.Run("the issuer key is "+name, func(t *testing.T) {
			p := root.interParams(csr)
			p.IssuerKey = bad
			tbs, err := intermediateTBS(t, p)
			refused(t, err, pki.ErrParams)
			if tbs != nil {
				t.Errorf("a body %x came with the error", tbs)
			}
		})
	}
}

// The validity of an intermediate is the constant 13: it ends exactly 13 calendar months after its start, whatever the
// start, with the last day of the month where the month has no such day.
func TestIntermediateValidityIsThirteenMonths(t *testing.T) {
	if pki.IntermediateValidityMonths != 13 {
		t.Fatalf("IntermediateValidityMonths = %d, want 13 (hand-off contract, the profile of an intermediate)", pki.IntermediateValidityMonths)
	}
	root := buildRoot(t, nil)
	csr := withExtensions(t, goodExtensions()...)
	cases := []struct {
		name string
		from time.Time
		end  time.Time
	}{
		{"an ordinary start", ceremony, utc(2027, 12, 15, 12, 0, 0)},
		{"the 31st of January, to the end of February", utc(2026, 1, 31, 10, 20, 30), utc(2027, 2, 28, 10, 20, 30)},
		{"the 31st of January before a leap year", utc(2027, 1, 31, 10, 20, 30), utc(2028, 2, 29, 10, 20, 30)},
		{"the 29th of February", utc(2028, 2, 29, 0, 0, 1), utc(2029, 3, 29, 0, 0, 1)},
		{"the last day of the year", utc(2026, 12, 31, 23, 59, 59), utc(2028, 1, 31, 23, 59, 59)},
		{"the first second of the year 1", utc(1, 1, 1, 0, 0, 1), utc(2, 2, 1, 0, 0, 1)},
		{"the 31st of July, to the 31st of August", utc(2026, 7, 31, 8, 0, 0), utc(2027, 8, 31, 8, 0, 0)},
		{"the 30th of November", utc(2026, 11, 30, 8, 0, 0), utc(2027, 12, 30, 8, 0, 0)},
		{"1949, a start before the UTCTime years", utc(1949, 12, 31, 23, 59, 59), utc(1951, 1, 31, 23, 59, 59)},
		{"2049, the last UTCTime start", utc(2049, 12, 31, 23, 59, 59), utc(2051, 1, 31, 23, 59, 59)},
		{"a start in 9998, the end in 9999", utc(9998, 11, 15, 0, 0, 0), utc(9999, 12, 15, 0, 0, 0)},
	}
	// Every month end of two years, one of them a leap year: the end is the same day of the month 13 months later, or the
	// last day of that month.
	for year := 2027; year <= 2028; year++ {
		for month := time.January; month <= time.December; month++ {
			last := time.Date(year, month+1, 0, 6, 7, 8, 0, time.UTC)
			target := time.Date(year+1, month+1, 1, 6, 7, 8, 0, time.UTC) // the first of the month 13 months later
			dim := time.Date(target.Year(), target.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
			want := time.Date(target.Year(), target.Month(), min(last.Day(), dim), 6, 7, 8, 0, time.UTC)
			cases = append(cases, struct {
				name string
				from time.Time
				end  time.Time
			}{"the last day of " + last.Format("2006-01"), last, want})
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := root.interParams(csr)
			p.CeremonyTime = c.from
			tbs, err := intermediateTBS(t, p)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := pki.SignIntermediate(nil, root.key, p, tbs)
			if err != nil {
				t.Fatal(err)
			}
			der, err := pki.Assemble(tbs, sig, &root.key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if !cert.NotBefore.Equal(c.from) || !cert.NotAfter.Equal(c.end) {
				t.Errorf("validity = %v to %v, want %v to %v", cert.NotBefore, cert.NotAfter, c.from, c.end)
			}
			if got, err := pki.AddMonths(c.from, 13); err != nil || !got.Equal(cert.NotAfter) {
				t.Errorf("AddMonths(13) = %v, %v: not the end of the body", got, err)
			}
		})
	}
}

// The request and the root of the hand-off vectors, read through the manifest: the intermediate is
// built with test root A as issuer and has the structure of the vector's own answer.
func TestIntermediateAgainstHandOffVector(t *testing.T) {
	var m struct {
		Pinned struct {
			RootList struct {
				X509 []string `json:"x509"`
			} `json:"root_list"`
		} `json:"pinned"`
		Requests []struct {
			ID    string   `json:"id"`
			Files []string `json:"files"`
		} `json:"requests"`
		Responses []struct {
			ID      string   `json:"id"`
			Request string   `json:"request"`
			Files   []string `json:"files"`
			Expect  string   `json:"expect"`
		} `json:"responses"`
	}
	if err := json.Unmarshal(testrepo.Read(t, "testdata", "hand-off", "v1", "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, resp := range m.Responses {
		if resp.Expect != "install" || !strings.HasPrefix(resp.ID, "x509-") || strings.Contains(resp.ID, "floor") || len(resp.Files) == 0 || !strings.HasSuffix(resp.Files[0], ".cert.pem") {
			continue
		}
		// The request that this answer answers.
		var csrFile string
		for _, r := range m.Requests {
			if r.ID == resp.Request {
				for _, f := range r.Files {
					if strings.HasSuffix(f, ".csr.pem") {
						csrFile = f
					}
				}
			}
		}
		if csrFile == "" {
			continue
		}
		rootCert, err := x509.ParseCertificate(pemBlock(t, testrepo.Read(t, "testdata", "hand-off", "v1", m.Pinned.RootList.X509[0]), "CERTIFICATE"))
		if err != nil {
			t.Fatal(err)
		}
		vecCert, err := x509.ParseCertificate(pemBlock(t, testrepo.Read(t, "testdata", "hand-off", "v1", resp.Files[0]), "CERTIFICATE"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(vecCert.RawIssuer, rootCert.RawSubject) {
			continue // the answer of this case is by another root: it is not a case of this test
		}
		t.Run(resp.ID, func(t *testing.T) {
			csr := pemBlock(t, testrepo.Read(t, "testdata", "hand-off", "v1", csrFile), "CERTIFICATE REQUEST")
			serial := hexBig(t, "73a1553666c0f868e34f116d4af6a1acb8c6b6")
			if months := monthsBetween(vecCert.NotBefore, vecCert.NotAfter); months != pki.IntermediateValidityMonths {
				t.Fatalf("the vector's answer lasts %d months, the constant is %d", months, pki.IntermediateValidityMonths)
			}
			tbs, err := intermediateTBS(t, pki.IntermediateParams{
				CSR: csr, IssuerSubject: rootCert.RawSubject, IssuerKey: rootCert.PublicKey,
				CeremonyTime: vecCert.NotBefore, Serial: serial,
			})
			if err != nil {
				t.Fatal(err)
			}
			// Wrap the body with the signature of the answer to read it back with Go's parser: the
			// signature is not ours, so only the body is looked at.
			bodyCert := parseBodyOf(t, tbs)
			if got, want := strings.Join(extensionIDs(bodyCert), ","), strings.Join(extensionIDs(vecCert), ","); got != want {
				t.Errorf("extensions = %s, the vector has %s", got, want)
			}
			for _, e := range vecCert.Extensions {
				mine := extensionOf(bodyCert, e.Id)
				if mine == nil {
					continue
				}
				if mine.Critical != e.Critical {
					t.Errorf("extension %s critical = %v, the vector has %v", e.Id, mine.Critical, e.Critical)
				}
				if !bytes.Equal(mine.Value, e.Value) {
					t.Errorf("extension %s value = %x, the vector has %x", e.Id, mine.Value, e.Value)
				}
			}
			if !bytes.Equal(bodyCert.RawIssuer, vecCert.RawIssuer) || !bytes.Equal(bodyCert.RawSubject, vecCert.RawSubject) || !bytes.Equal(bodyCert.RawSubjectPublicKeyInfo, vecCert.RawSubjectPublicKeyInfo) {
				t.Error("the issuer, the subject or the key differ from the vector's")
			}
			if !bodyCert.NotBefore.Equal(vecCert.NotBefore) || !bodyCert.NotAfter.Equal(vecCert.NotAfter) {
				t.Errorf("validity %v to %v, the vector has %v to %v", bodyCert.NotBefore, bodyCert.NotAfter, vecCert.NotBefore, vecCert.NotAfter)
			}
			if !bytes.Equal(bodyCert.AuthorityKeyId, vecCert.AuthorityKeyId) || !bytes.Equal(bodyCert.SubjectKeyId, vecCert.SubjectKeyId) {
				t.Error("the key identifiers differ from the vector's")
			}
			if bodyCert.SignatureAlgorithm != vecCert.SignatureAlgorithm || bodyCert.Version != vecCert.Version {
				t.Errorf("algorithm %v version %d, the vector has %v and %d", bodyCert.SignatureAlgorithm, bodyCert.Version, vecCert.SignatureAlgorithm, vecCert.Version)
			}
			checked++
		})
	}
	if checked == 0 {
		t.Fatal("no answer of the hand-off vectors was compared")
	}
}

// parseBodyOf puts a signature that is not valid but is well formed to a body and parses it with Go,
// to read the fields of the body.
func parseBodyOf(t testing.TB, tbs []byte) *x509.Certificate {
	t.Helper()
	sig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	der, _ := handAssemble(tbs, sig)
	var err error
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
