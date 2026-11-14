package pki_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// Fuzz targets for the readers of a request. A fuzzer cannot forge an ECDSA signature, so a target that mutates the whole request
// stops at the signature almost every time; the targets that sign (FuzzRequestSubject, FuzzRequestExtensions) take the parts of
// a request from the fuzzer and sign them with a fixed key, so that every input reaches the reading of the content.
//
// The properties, for every input:
//   - no panic, and an error is an ErrRequest with a check (CheckOf is not none) and a text that is printable ASCII;
//   - a request that is accepted is read back: its DER is the input, its subject is printable ASCII with single spaces, its
//     extended key usage is one of the four forms and not critical, and the standard library reads the same request with the same
//     subject and the same extension identifiers;
//   - a partial request comes with a refusal by the policy check and with no other;
//   - ParseRequestFile of the armoured request, and IntermediateTBS under a fixed root, say the same check;
//   - a body that IntermediateTBS returns is read by the standard library, has the subject of the request and the profile's
//     extensions.
//
// The corpus is made of the requests of the hand-off vectors and the cases of the tests; `go test` runs them as ordinary tests.

var fuzzKey = sync.OnceValue(func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
})

// fuzzRootOnce is one root for every input, made with the testing value of the first input.
var (
	fuzzRootOnce sync.Once
	fuzzRootVal  *testRoot
)

func fuzzRoot(t *testing.T) *testRoot {
	fuzzRootOnce.Do(func() { fuzzRootVal = buildRoot(t, nil) })
	return fuzzRootVal
}

// fuzzRootB is a second root of the bundle.
var (
	fuzzRootBOnce sync.Once
	fuzzRootBVal  *testRoot
)

func fuzzRootB(t *testing.T) *testRoot {
	fuzzRootBOnce.Do(func() { fuzzRootBVal = buildRoot(t, func(p *pki.RootParams) { p.Name = "Second Test"; p.Label = "B" }) })
	return fuzzRootBVal
}

func armorOf(der []byte) []byte { return pemBlockOf("CERTIFICATE REQUEST", der) }

// checkRequestProperties holds the properties above for the bytes of a request.
func checkRequestProperties(t *testing.T, der []byte) {
	t.Helper()
	req, err := pki.ParseRequest(der)
	file, errFile := pki.ParseRequestFile(armorOf(der))
	if len(armorOf(der)) > pki.MaxRequestSize && errFile == nil {
		t.Fatal("a file over the limit is read")
	}
	if len(armorOf(der)) <= pki.MaxRequestSize && pki.CheckOf(err) != pki.CheckOf(errFile) {
		t.Fatalf("ParseRequest says %q and ParseRequestFile %q (%v, %v)", pki.CheckOf(err), pki.CheckOf(errFile), err, errFile)
	}
	checkRequestKey(t, der, req, err)
	root := fuzzRoot(t)
	p := pki.IntermediateParams{CSR: der, IssuerSubject: root.parsed.RawSubject, IssuerKey: &root.key.PublicKey, Roots: []pki.RootRef{root.ref(), fuzzRootB(t).ref()}, CeremonyTime: ceremony, Serial: aSerial}
	tbs, errTBS := pki.IntermediateTBS(p)
	if err != nil {
		_ = kindOf(t, err)
		if pki.CheckOf(err) == pki.CheckNone {
			t.Fatalf("a refusal with no check: %v", err)
		}
		if !printable(err.Error()) {
			t.Fatalf("the text is not printable ASCII: %q", err.Error())
		}
		if req != nil || file != nil {
			t.Fatalf("a request came with the check %q", pki.CheckOf(err))
		}
		if len(der) == 0 {
			return // no request at all is a parameter (ErrParams, no check), not a request that is refused
		}
		if errTBS == nil || tbs != nil {
			t.Fatalf("IntermediateTBS accepts what ParseRequest refuses: %v", errTBS)
		}
		_ = kindOf(t, errTBS)
		if pki.CheckOf(errTBS) != pki.CheckOf(err) {
			t.Fatalf("IntermediateTBS says %q and ParseRequest %q", pki.CheckOf(errTBS), pki.CheckOf(err))
		}
		return
	}
	if req == nil || !bytes.Equal(req.DER(), der) || file == nil {
		t.Fatal("a request that is accepted does not read back")
	}
	for _, set := range req.SubjectName() {
		for _, a := range set {
			if f := textOf(a.Value); f != "" {
				t.Fatalf("an accepted subject has a value %q: %s", a.Value, f)
			}
		}
	}
	var eku []byte
	for _, e := range req.Extensions() {
		if e.Id.Equal(oidExtKeyUsage) {
			eku = e.Value
			if e.Critical {
				t.Fatal("an accepted request has a critical extended key usage")
			}
		}
	}
	var oids []asn1.ObjectIdentifier
	if rest, e := asn1.Unmarshal(eku, &oids); e != nil || len(rest) != 0 || len(oids) == 0 || len(oids) > 2 {
		t.Fatalf("an accepted request has the extended key usage %x", eku)
	}
	for i, o := range oids {
		if !o.Equal(oidServerAuth) && !o.Equal(oidClientAuth) || (i == 1 && o.Equal(oids[0])) {
			t.Fatalf("an accepted request has the purposes %v", oids)
		}
	}
	// The standard library reads the same request.
	sc, e := x509.ParseCertificateRequest(der)
	if e != nil {
		t.Fatalf("the standard library refuses a request that is accepted: %v", e)
	}
	if sc.CheckSignature() != nil || !bytes.Equal(sc.RawSubject, req.Subject()) {
		t.Fatal("the standard library reads another subject or a bad signature")
	}
	var ids, want []string
	for _, e := range sc.Extensions {
		ids = append(ids, e.Id.String())
	}
	for _, e := range req.Extensions() {
		want = append(want, e.Id.String())
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("the extensions of the standard library %v, of the view %v", ids, want)
	}
	// The body: if the issuer rules do not refuse it, it is read and has the profile.
	if errTBS != nil {
		_ = kindOf(t, errTBS)
		return
	}
	cert := parseBodyOf(t, tbs)
	if !bytes.Equal(cert.RawSubject, req.Subject()) || !bytes.Equal(cert.RawIssuer, root.parsed.RawSubject) {
		t.Fatal("the names of the body are not the names asked for")
	}
	if got, w := strings.Join(extensionIDs(cert), ","), "2.5.29.19,2.5.29.15,2.5.29.30,2.5.29.37,2.5.29.14,2.5.29.35"; got != w {
		t.Fatalf("the extensions of the body are %s", got)
	}
	if e := extensionOf(cert, oidExtKeyUsage); e == nil || e.Critical || !bytes.Equal(e.Value, eku) {
		t.Fatal("the extended key usage of the body is not the request's")
	}
	sig := signatureOf(t, root.key, tbs)
	if _, e := pki.Assemble(tbs, sig, &root.key.PublicKey); e != nil {
		t.Fatalf("a body that was returned does not assemble: %v", e)
	}
}

// checkRequestKey holds the properties of RequestKey and RequestKeyFile against what ParseRequest said of the same bytes: never a key
// with an error and never an error without a key; for a refusal of check 2, 4 or 5 the same check and the same words and no key; for a
// refusal of content (policy) the key of the request and no error; for a request that is accepted, its key.
func checkRequestKey(t *testing.T, der []byte, req *pki.Request, err error) {
	t.Helper()
	key, kerr := pki.RequestKey(der)
	if (key != nil) == (kerr != nil) {
		t.Fatalf("RequestKey: a key %v with the error %v", key, kerr)
	}
	switch c := pki.CheckOf(err); c {
	case pki.CheckNone:
		if kerr != nil || !key.Equal(req.PublicKey()) {
			t.Fatalf("RequestKey of a request that is accepted: %v, %v", key, kerr)
		}
	case pki.CheckPolicy:
		if kerr != nil {
			t.Fatalf("RequestKey refuses a request that passes checks 2, 4 and 5: %v", kerr)
		}
		if sc, e := x509.ParseCertificateRequest(der); e == nil {
			if pub, ok := sc.PublicKey.(*ecdsa.PublicKey); ok && !pub.Equal(key) {
				t.Fatal("RequestKey gives a key that is not the key of the request")
			}
		}
	default:
		if c == pki.CheckNone || key != nil || pki.CheckOf(kerr) != c || kerr.Error() != err.Error() {
			t.Fatalf("RequestKey says %v (%q) and ParseRequest %v (%q)", kerr, pki.CheckOf(kerr), err, c)
		}
	}
	if len(armorOf(der)) <= pki.MaxRequestSize {
		fileKey, ferr := pki.RequestKeyFile(armorOf(der))
		if (fileKey == nil) != (key == nil) || pki.CheckOf(ferr) != pki.CheckOf(kerr) || (key != nil && !fileKey.Equal(key)) {
			t.Fatalf("RequestKeyFile says %v, %v and RequestKey %v, %v", fileKey, ferr, key, kerr)
		}
	}
}

// textOf is the text rule of a subject, written here again: printable ASCII, no space at the ends, none twice in a row.
func textOf(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return "outside printable ASCII"
		}
	}
	if strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") || strings.Contains(s, "  ") {
		return "a space"
	}
	return ""
}

// fuzzSeeds adds the requests of the hand-off vectors and the shapes of the tests.
func fuzzSeeds(f *testing.F, add func(der []byte)) {
	f.Helper()
	var m struct {
		Requests []struct {
			Type  string   `json:"type"`
			Files []string `json:"files"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(testrepo.Read(f, "testdata", "hand-off", "v1", "manifest.json"), &m); err != nil {
		f.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range m.Requests {
		if r.Type != "x509-intermediate" || seen[r.Files[0]] {
			continue
		}
		seen[r.Files[0]] = true
		// A file that is not one block gives the block that it holds (the first), whatever stands around it.
		if block, _ := pem.Decode(testrepo.Read(f, "testdata", "hand-off", "v1", r.Files[0])); block != nil {
			add(block.Bytes)
		}
	}
}

func FuzzParseRequest(f *testing.F) {
	fuzzSeeds(f, func(der []byte) { f.Add(der) })
	good := withExtensions(f, goodExtensions()...)
	f.Add(good.DER())
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, der []byte) {
		if len(der) > 1<<20 {
			t.Skip()
		}
		checkRequestProperties(t, der)
	})
}

func FuzzParseRequestFile(f *testing.F) {
	fuzzSeeds(f, func(der []byte) { f.Add(armorOf(der)) })
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"))
	fuzzSeeds(f, func(der []byte) {
		f.Add([]byte(wrapFile(der, 76, "\r\n", "")))
		f.Add([]byte(wrapFile(der, 1, "\n", "\n")))
		f.Add([]byte(wrapFile(der, 64, "\n", "\n\n")))
	})
	f.Fuzz(func(t *testing.T, file []byte) {
		if len(file) > 1<<20 {
			t.Skip()
		}
		req, err := pki.ParseRequestFile(file)
		fileKey, ferr := pki.RequestKeyFile(file)
		if (fileKey != nil) == (ferr != nil) {
			t.Fatalf("RequestKeyFile: a key %v with the error %v", fileKey, ferr)
		}
		// The rule of the file (requestfile_rule_test.go) says which files are blocks of the contract: any other is refused as malformed, and
		// for a block the result is that of ParseRequest of the DER inside.
		if der, ok := fileRule(file); !ok {
			if err == nil || pki.CheckOf(err) != pki.CheckMalformed || fileKey != nil || ferr == nil || ferr.Error() != err.Error() {
				t.Fatalf("a file that is not a block of the rule: ParseRequestFile %v, RequestKeyFile %v, %v", err, fileKey, ferr)
			}
		} else if _, derr := pki.ParseRequest(der); (derr == nil) != (err == nil) || (err != nil && err.Error() != derr.Error()) {
			t.Fatalf("a block of the rule: ParseRequestFile says %v and ParseRequest of the DER says %v", err, derr)
		}
		if err != nil {
			_ = kindOf(t, err)
			if pki.CheckOf(err) == pki.CheckNone {
				t.Fatalf("a refusal with no check: %v", err)
			}
			if req != nil {
				t.Fatalf("a request came with the check %q", pki.CheckOf(err))
			}
			if c := pki.CheckOf(err); c != pki.CheckPolicy && (fileKey != nil || pki.CheckOf(ferr) != c || ferr.Error() != err.Error()) {
				t.Fatalf("RequestKeyFile says %v and ParseRequestFile %v", ferr, err)
			}
			if c := pki.CheckOf(err); c == pki.CheckPolicy && ferr != nil {
				t.Fatalf("RequestKeyFile refuses a file that passes checks 2, 4 and 5: %v", ferr)
			}
			return
		}
		checkRequestProperties(t, req.DER())
		if !bytes.HasPrefix(file, []byte("-----BEGIN CERTIFICATE REQUEST-----")) {
			t.Fatal("a file that does not start with the label is read")
		}
	})
}

// FuzzRequestSubject signs a request with the subject that the fuzzer gives, and the good extensions.
func FuzzRequestSubject(f *testing.F) {
	f.Add(goodSubject())
	f.Add(cnName(tUTF8, "acme example ca"))
	f.Add(cnName(tPrintable, "acme example ca"))
	f.Add(cnName(tUTF8, "acme  example"))
	f.Add(cnName(tUTF8, "café"))
	f.Add(nameOf(rdn(atv(oidAttrDC, str(tIA5, "example"))), rdn(atv(oidAttrCN, str(tUTF8, "ca")))))
	f.Add(nameOf(rdn(atv(oidAttrDC, str(tPrintable, "example"))), rdn(atv(oidAttrCN, str(tUTF8, "ca")))))
	f.Add(nameOf(rdn(atv(oidAttrC, str(tPrintable, "NL")), atv(oidAttrCN, str(tUTF8, "ca")))))
	f.Fuzz(func(t *testing.T, subject []byte) {
		csr := &testCSR{Key: fuzzKey(), RawSubject: subject, Extensions: goodExtensions()}
		checkRequestProperties(t, csr.DER())
	})
}

// FuzzRequestExtensions signs a request with the key usage, the name constraints and the extended key usage that the fuzzer gives
// (and the flags of the three), beside the basic constraints of the profile.
func FuzzRequestExtensions(f *testing.F) {
	good := goodExtensions()
	f.Add(good[1].Value, good[2].Value, good[3].Value, byte(0b011))
	f.Add(good[1].Value, good[2].Value, extExtKeyUsage(false, oidClientAuth).Value, byte(0b011))
	f.Add(good[1].Value, good[2].Value, extExtKeyUsage(false, oidServerAuth, oidClientAuth, oidServerAuth).Value, byte(0b011))
	f.Add(good[1].Value, good[2].Value, extExtKeyUsage(false, oidAnyExtendedKeyUsage).Value, byte(0b011))
	f.Add(good[1].Value, good[2].Value, good[3].Value, byte(0b111))
	f.Add(good[1].Value, ncValue([][]byte{ncSub(dns("example.org"))}, [][]byte{ipSub(8), ipSub(32)}), good[3].Value, byte(0b011))
	f.Add(good[1].Value, ncValue([][]byte{ncSub(tlv(0x86, []byte(".example.org")))}, nil), good[3].Value, byte(0b011))
	f.Fuzz(func(t *testing.T, ku, nc, eku []byte, flags byte) {
		exts := []pkix.Extension{
			extBasicConstraints(),
			{Id: oidKeyUsage, Critical: flags&1 != 0, Value: ku},
			{Id: oidNameConstraints, Critical: flags&2 != 0, Value: nc},
			{Id: oidExtKeyUsage, Critical: flags&4 != 0, Value: eku},
		}
		csr := &testCSR{Key: fuzzKey(), RawSubject: goodSubject(), Extensions: exts}
		checkRequestProperties(t, csr.DER())
	})
}

// FuzzRequestKey signs a request whose algorithm element, version, key and signature the fuzzer chooses, beside a subject of its own, so
// that every input is a request of one or more faults of check 2, 4, 5 and 9, and holds that RequestKey and ParseRequest never disagree
// about the first three (checkRequestProperties holds it with checkRequestKey).
func FuzzRequestKey(f *testing.F) {
	f.Add(goodSubject(), []byte(nil), byte(0), byte(0))
	f.Add(goodSubject(), []byte{0x04, 0x01, 0x00}, byte(0), byte(0))
	f.Add(goodSubject(), algDER(0x02), byte(1), byte(0))
	f.Add(goodSubject(), []byte(nil), byte(7), byte(0))
	f.Add(goodSubject(), []byte(nil), byte(0), byte(1))
	f.Add(goodSubject(), []byte(nil), byte(0), byte(2))
	f.Add(cnName(tUTF8, "café"), []byte(nil), byte(0), byte(0))
	f.Add(cnName(tUTF8, "caf\u00e9"), []byte(nil), byte(0), byte(4))
	f.Add(nameOf(rdn(atv(oidAttrCN, tlv(0x30)))), []byte(nil), byte(0), byte(0))
	f.Fuzz(func(t *testing.T, subject, alg []byte, version, flags byte) {
		csr := &testCSR{Key: fuzzKey(), RawSubject: subject, Extensions: goodExtensions()}
		if len(alg) > 0 {
			csr.Algorithm = alg
			if flags&8 != 0 {
				csr.Digest = crypto.SHA256
			}
		}
		if version != 0 {
			csr.Version = []byte{0x02, 0x01, version}
		}
		if flags&1 != 0 {
			csr.SignatureEdit = func(s []byte) []byte { s[len(s)-1] ^= 1; return s }
		}
		if flags&2 != 0 {
			other := p256Fuzz()
			csr.Key, csr.RawSubjectPublicKeyInfo = fuzzKey(), nil
			csr.RawSubjectPublicKeyInfo = other
		}
		if flags&4 != 0 {
			csr.Extensions = goodExtensions()[:3]
		}
		checkRequestProperties(t, csr.DER())
	})
}

var p256Fuzz = sync.OnceValue(func() []byte {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		panic(err)
	}
	return der
})
