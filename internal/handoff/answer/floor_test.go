package answer_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // key identifiers of the foreign CA, as the vectors have them
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/jws"
)

// caSpec says how to make a CA certificate that an operator installed. A zero field is a CA of the floor: a
// self-signed P-384 certificate with basic constraints and the key usage keyCertSign, valid now.
type caSpec struct {
	cn        string
	key       *ecdsa.PrivateKey
	rsaKey    *rsa.PrivateKey
	notBefore time.Time
	notAfter  time.Time
	noBC      bool
	notCA     bool
	usage     x509.KeyUsage
	noUsage   bool
}

// foreignCA is an installed CA: the certificate, its file, and the key.
type foreignCA struct {
	root   memRoot // the key and the certificate, for an ECDSA CA
	rsaKey *rsa.PrivateKey
	file   []byte
}

func newForeignCA(t testing.TB, s caSpec) foreignCA {
	t.Helper()
	if s.cn == "" {
		s.cn = "Example Foreign Root (TEST ONLY)"
	}
	if s.notBefore.IsZero() {
		s.notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if s.notAfter.IsZero() {
		s.notAfter = s.notBefore.AddDate(10, 0, 0)
	}
	var signer crypto.Signer
	var pub crypto.PublicKey
	switch {
	case s.rsaKey != nil:
		signer, pub = s.rsaKey, &s.rsaKey.PublicKey
	default:
		if s.key == nil {
			s.key = newP384(t)
		}
		signer, pub = s.key, &s.key.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1234567),
		Subject:               pkix.Name{CommonName: s.cn},
		NotBefore:             s.notBefore,
		NotAfter:              s.notAfter,
		BasicConstraintsValid: !s.noBC,
		IsCA:                  !s.notCA,
	}
	if !s.noUsage {
		tmpl.KeyUsage = x509.KeyUsageCertSign
		if s.usage != 0 {
			tmpl.KeyUsage = s.usage
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return foreignCA{root: memRoot{label: "F", key: s.key, der: der, cert: cert, pin: jws.Pin(cert)}, rsaKey: s.rsaKey, file: certPEM(der)}
}

func floorConfig(t testing.TB, change func(*answer.Config), cas ...foreignCA) answer.Config {
	t.Helper()
	var files [][]byte
	for _, c := range cas {
		files = append(files, bytes.Clone(c.file))
	}
	cfg := answer.Config{FloorAnchors: files, Now: func() time.Time { return testNow }}
	cfg.Validity.MinMonths, cfg.Validity.MaxMonths = 12, 14
	if change != nil {
		change(&cfg)
	}
	return cfg
}

// floorCert writes a certificate of a foreign CA for the request: the four extensions as asked and, as such a CA
// does, key identifiers by SHA-1 and nothing critical besides. The CA is an ECDSA key.
func floorCert(t testing.TB, k *memKit, csr *memCSR, ca foreignCA, s certSpec) []byte {
	t.Helper()
	s.issuer = &ca.root
	if s.exts == nil && !s.noExts {
		subjectPoint, err := csr.req.PublicKey().Bytes()
		if err != nil {
			t.Fatal(err)
		}
		issuerPoint, err := ca.root.key.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		skid := sha1.Sum(subjectPoint) //nolint:gosec // as the foreign CA does
		akid := sha1.Sum(issuerPoint)  //nolint:gosec // as the foreign CA does
		var exts []pkix.Extension
		for _, id := range []string{oidBasicConstraints.String(), oidKeyUsage.String(), oidNameConstraints.String(), oidEKU.String()} {
			for _, e := range csr.req.Extensions() {
				if e.Id.String() == id {
					exts = append(exts, e)
				}
			}
		}
		exts = append(exts, pkix.Extension{Id: oidSKI, Value: tlv(0x04, skid[:])}, pkix.Extension{Id: oidAKI, Value: tlv(0x30, tlv(0x80, akid[:]))})
		s.exts = slices.Concat(exts, s.extraExts)
	}
	return k.issue(csr, s)
}

type floorCase struct {
	t   testing.TB
	csr *memCSR
	der []byte
	ans *answer.Answer
}

func newFloorCase(t testing.TB, k *memKit, ca foreignCA, s certSpec) *floorCase {
	t.Helper()
	csr := newCSR(t, nil, nil)
	der := floorCert(t, k, csr, ca, s)
	return &floorCase{t: t, csr: csr, der: der, ans: &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileCert: certPEM(der)}}}
}

func (f *floorCase) check(chk *answer.Checker) (answer.Verdict, error) {
	f.t.Helper()
	a, err := answer.AskedX509(f.csr.file)
	if err != nil {
		f.t.Fatal(err)
	}
	return chk.Check(a, f.ans)
}

func floorWant(t testing.TB, v answer.Verdict, err error, code answer.Code, st string) {
	t.Helper()
	want(t, v, err, code, st)
	if !v.Floor() {
		t.Error("the verdict of a floor checker is not a floor verdict")
	}
}

const (
	floorOK = "npnppppnn"
	fl4     = "npnfnnnnn"
	fl5     = "npnpfnnnn"
	fl6     = "npnppfnnn"
	fl7     = "npnpppfnn"
	fl2     = "nfnnnnnnn"
)

func TestTheFloorAcceptsACertificateOfAnInstalledCAAndNamesTheFourChecksItDidNotRun(t *testing.T) {
	k := newKit(t)
	ca := newForeignCA(t, caSpec{})
	chk := mustChecker(t, floorConfig(t, nil, ca))
	f := newFloorCase(t, k, ca, certSpec{})
	v, err := f.check(chk)
	floorWant(t, v, err, "", floorOK)
	if v.Info.Issuer != ca.root.pin || v.Info.TrustSequence != 0 || v.Info.Type != handoff.TypeX509 || v.Info.Stem != "example-answer" {
		t.Errorf("Info %+v", *v.Info)
	}
	if len(v.Warnings) != 0 || v.RequestRefused() || v.AnswerRefused() {
		t.Errorf("warnings %v", v.Warnings)
	}
	if len(v.Checks) != 9 {
		t.Fatalf("%d slots", len(v.Checks))
	}
	for _, i := range []int{0, 2, 7, 8} {
		if v.Checks[i].Status != handoff.StatusNotRun || v.Checks[i].Reason == "" {
			t.Errorf("slot %d: %s %q; it cannot run and says why", i+1, v.Checks[i].Status, v.Checks[i].Reason)
		}
	}
	// A verdict of the floor with one of the fixed slots made passed is not accepted.
	w := v
	w.Checks = append([]answer.CheckResult(nil), v.Checks...)
	w.Checks[0].Status = handoff.StatusPassed
	if w.Accepted() {
		t.Error("a floor verdict with a slot that cannot run reported as passed is accepted")
	}
	w.Checks[0].Status = handoff.StatusNotRun
	w.Checks[3].Status = handoff.StatusNotRun
	if w.Accepted() {
		t.Error("a floor verdict with a slot that ran and was not run is accepted")
	}
}

func TestTheFloorTakesAP256CAAndAnRSA2048CA(t *testing.T) {
	k := newKit(t)
	t.Run("a P-256 CA", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := newForeignCA(t, caSpec{key: key})
		f := newFloorCase(t, k, ca, certSpec{})
		v, err := f.check(mustChecker(t, floorConfig(t, nil, ca)))
		floorWant(t, v, err, "", floorOK)
	})
	t.Run("an RSA CA", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		ca := newForeignCA(t, caSpec{rsaKey: rk})
		csr := newCSR(t, nil, nil)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(99), NotBefore: testNow, NotAfter: testNow.AddDate(1, 1, 0),
			RawSubject: csr.req.Subject(), ExtraExtensions: csr.req.Extensions(), SignatureAlgorithm: x509.SHA256WithRSA,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.root.cert, csr.req.PublicKey(), rk)
		if err != nil {
			t.Fatal(err)
		}
		chk := mustChecker(t, floorConfig(t, nil, ca))
		a, err := answer.AskedX509(csr.file)
		if err != nil {
			t.Fatal(err)
		}
		v, err := chk.Check(a, &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileCert: certPEM(der)}})
		floorWant(t, v, err, "", floorOK)
	})
}

func TestTheFloorRefusesWhereTheTableSays(t *testing.T) {
	k := newKit(t)
	ca := newForeignCA(t, caSpec{})
	chk := mustChecker(t, floorConfig(t, nil, ca))
	csr := newCSR(t, nil, nil)
	asCert := func(extras ...pkix.Extension) certSpec { return certSpec{extraExts: extras} }
	_ = csr
	for _, c := range []struct {
		name string
		spec certSpec
		code answer.Code
		st   string
	}{
		{"a certificate with a critical extension of its own", asCert(pkix.Extension{Id: oidCertPolicies, Critical: true, Value: tlv(0x30)}), answer.CodeProfile, fl6},
		{"a certificate with an authority information access that is not critical", asCert(pkix.Extension{Id: oidAIA, Value: tlv(0x30)}), "", floorOK},
		{"a certificate with a certificate policies extension that is not critical", asCert(pkix.Extension{Id: oidCertPolicies, Value: tlv(0x30)}), "", floorOK},
		{"a serial of 21 bytes", certSpec{serialLen: 21}, "", floorOK},
		{"a validity of 12 months", certSpec{months: 12}, "", floorOK},
		{"a validity of 14 months", certSpec{months: 14}, "", floorOK},
		{"a validity of 11 months", certSpec{months: 11}, answer.CodeValidity, fl7},
		{"a validity of 15 months", certSpec{months: 15}, answer.CodeValidity, fl7},
		{"a validity of two years", certSpec{months: 24}, answer.CodeValidity, fl7},
		{"a certificate that ended a second ago", certSpec{notBefore: time.Date(2025, 10, 15, 11, 59, 59, 0, time.UTC)}, answer.CodeValidity, fl7},
		{"a certificate that ends now", certSpec{notBefore: time.Date(2025, 10, 15, 12, 0, 0, 0, time.UTC)}, "", floorOK},
		{"a certificate that starts in a second", certSpec{notBefore: testNow.Add(time.Second)}, answer.CodeValidity, fl7},
		{"a certificate of version 2", certSpec{version: 1}, answer.CodeProfile, fl6},
		{"a signature of SHA-256", certSpec{sigAlg: oidECDSASHA256, digest: crypto.SHA256}, "", floorOK},
		{"a signature of SHA-1", certSpec{sigAlg: oidECDSASHA1, digest: crypto.SHA1}, answer.CodeIssuer, fl4},
		{"a signature with a flipped bit", certSpec{flipSigByte: true}, answer.CodeIssuer, fl4},
		{"another issuer name", certSpec{issuerName: nameDER("Example Other Root")}, answer.CodeIssuer, fl4},
		{"an issuer name in capitals", certSpec{issuerName: nameDER("EXAMPLE FOREIGN ROOT (TEST ONLY)")}, answer.CodeIssuer, fl4},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFloorCase(t, k, ca, c.spec)
			v, err := f.check(chk)
			floorWant(t, v, err, c.code, c.st)
		})
	}
	t.Run("the four extensions of the request, each dropped, changed or with the other criticality", func(t *testing.T) {
		ids := []struct {
			id   string
			mod  func(e pkix.Extension) pkix.Extension
			name string
		}{
			{oidBasicConstraints.String(), func(e pkix.Extension) pkix.Extension { return extBasic(true, 1) }, "path length 1"},
			{oidKeyUsage.String(), func(e pkix.Extension) pkix.Extension { return extKeyUsage(true, keyCertSign|0x02) }, "key usage with cRLSign"},
			{oidNameConstraints.String(), func(e pkix.Extension) pkix.Extension { return extNameConstraints(true, "example.com") }, "another permitted name"},
			{oidEKU.String(), func(e pkix.Extension) pkix.Extension { return extEKU(false, oidClientAuth) }, "another purpose"},
			{oidEKU.String(), func(e pkix.Extension) pkix.Extension { e.Critical = true; return e }, "a critical extended key usage"},
			{oidBasicConstraints.String(), func(e pkix.Extension) pkix.Extension { e.Critical = false; return e }, "basic constraints not critical"},
		}
		for _, c := range ids {
			for _, drop := range []bool{false, true} {
				name := c.name
				if drop {
					name = "no " + c.name
				}
				csr := newCSR(t, nil, nil)
				var exts []pkix.Extension
				for _, e := range csr.req.Extensions() {
					switch {
					case e.Id.String() == c.id && drop:
					case e.Id.String() == c.id:
						exts = append(exts, c.mod(e))
					default:
						exts = append(exts, e)
					}
				}
				der := k.issue(csr, certSpec{issuer: &ca.root, exts: exts})
				a, err := answer.AskedX509(csr.file)
				if err != nil {
					t.Fatal(err)
				}
				v, err := chk.Check(a, &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileCert: certPEM(der)}})
				if err != nil || v.Code != answer.CodeProfile || statuses(v) != fl6 {
					t.Errorf("%s: %v, code %q, statuses %s", name, err, v.Code, statuses(v))
				}
			}
		}
	})
	t.Run("a certificate of another request: the key", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		other := newCSR(t, nil, nil)
		f.der = floorCert(t, k, other, ca, certSpec{})
		f.ans.Files[answer.FileCert] = certPEM(f.der)
		v, err := f.check(chk)
		floorWant(t, v, err, answer.CodeKeyMismatch, fl5)
	})
	t.Run("a wrong issuer together with a wrong key is the issuer", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		stranger := newForeignCA(t, caSpec{cn: "Example Stranger Root"})
		other := newCSR(t, nil, nil)
		f.ans.Files[answer.FileCert] = certPEM(floorCert(t, k, other, stranger, certSpec{}))
		v, err := f.check(chk)
		floorWant(t, v, err, answer.CodeIssuer, fl4)
	})
}

func TestTheInstalledCertificateMustBeACAThatIsValidAndWhoseKeyVerifies(t *testing.T) {
	k := newKit(t)
	for _, c := range []struct {
		name string
		ca   caSpec
	}{
		{"a certificate that is not a CA", caSpec{notCA: true}},
		{"a certificate with no basic constraints", caSpec{noBC: true}},
		{"a CA without keyCertSign", caSpec{usage: x509.KeyUsageDigitalSignature}},
		{"a CA that has ended", caSpec{notBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), notAfter: time.Date(2026, 11, 15, 11, 59, 59, 0, time.UTC)}},
		{"a CA that is not yet valid", caSpec{notBefore: testNow.Add(time.Second), notAfter: testNow.AddDate(10, 0, 0)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ca := newForeignCA(t, c.ca)
			chk := mustChecker(t, floorConfig(t, nil, ca))
			f := newFloorCase(t, k, ca, certSpec{})
			v, err := f.check(chk)
			floorWant(t, v, err, answer.CodeIssuer, fl4)
		})
	}
	t.Run("a CA with no key usage at all is a CA", func(t *testing.T) {
		ca := newForeignCA(t, caSpec{noUsage: true})
		v, err := newFloorCase(t, k, ca, certSpec{}).check(mustChecker(t, floorConfig(t, nil, ca)))
		floorWant(t, v, err, "", floorOK)
	})
	t.Run("a CA that ends this second is valid", func(t *testing.T) {
		ca := newForeignCA(t, caSpec{notBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), notAfter: testNow})
		v, err := newFloorCase(t, k, ca, certSpec{}).check(mustChecker(t, floorConfig(t, nil, ca)))
		floorWant(t, v, err, "", floorOK)
	})
	t.Run("two installed certificates of one name: the one whose key verifies is used", func(t *testing.T) {
		good := newForeignCA(t, caSpec{})
		twin := newForeignCA(t, caSpec{}) // the same name, another key
		for _, order := range [][]foreignCA{{good, twin}, {twin, good}} {
			f := newFloorCase(t, k, good, certSpec{})
			v, err := f.check(mustChecker(t, floorConfig(t, nil, order...)))
			floorWant(t, v, err, "", floorOK)
			if v.Info.Issuer != good.root.pin {
				t.Errorf("issuer %s, want the pin of the key that signed", v.Info.Issuer)
			}
		}
	})
	t.Run("two installed certificates of one key: one is the same pin", func(t *testing.T) {
		key := newP384(t)
		a := newForeignCA(t, caSpec{key: key, notAfter: testNow.AddDate(5, 0, 0)})
		b := newForeignCA(t, caSpec{key: key, notAfter: testNow.AddDate(6, 0, 0)})
		f := newFloorCase(t, k, a, certSpec{})
		v, err := f.check(mustChecker(t, floorConfig(t, nil, b, a)))
		floorWant(t, v, err, "", floorOK)
		if v.Info.Issuer != a.root.pin {
			t.Errorf("issuer %s", v.Info.Issuer)
		}
	})
	t.Run("an installed certificate of another name with the key that signed is not a candidate", func(t *testing.T) {
		signer := newP384(t)
		real := newForeignCA(t, caSpec{key: signer})
		renamed := newForeignCA(t, caSpec{key: signer, cn: "Example Renamed Root"})
		f := newFloorCase(t, k, real, certSpec{})
		v, err := f.check(mustChecker(t, floorConfig(t, nil, renamed)))
		floorWant(t, v, err, answer.CodeIssuer, fl4)
	})
	t.Run("a chain of two: the issuing CA is not installed though its issuer is", func(t *testing.T) {
		root := newForeignCA(t, caSpec{cn: "Example Foreign Root"})
		// The sub-CA is issued by the root, is a CA and is not installed.
		subKey := newP384(t)
		subTmpl := &x509.Certificate{
			SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "Example Foreign Sub CA"},
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		}
		subDER, err := x509.CreateCertificate(rand.Reader, subTmpl, root.root.cert, &subKey.PublicKey, root.root.key)
		if err != nil {
			t.Fatal(err)
		}
		subCert, err := x509.ParseCertificate(subDER)
		if err != nil {
			t.Fatal(err)
		}
		sub := foreignCA{root: memRoot{label: "S", key: subKey, der: subDER, cert: subCert, pin: jws.Pin(subCert)}, file: certPEM(subDER)}
		f := newFloorCase(t, k, sub, certSpec{})
		chk := mustChecker(t, floorConfig(t, nil, root))
		v, err := f.check(chk)
		floorWant(t, v, err, answer.CodeIssuer, fl4)
		// Installing the issuing CA is what makes it pass.
		v, err = f.check(mustChecker(t, floorConfig(t, nil, root, sub)))
		floorWant(t, v, err, "", floorOK)
	})
}

// A refusal on the floor leaves the four slots that cannot run with their own reasons, and the slots after the
// failed one with the reason that a check before them did not pass.
func TestARefusalOnTheFloorKeepsTheReasonsOfTheSlotsThatCannotRun(t *testing.T) {
	k := newKit(t)
	ca := newForeignCA(t, caSpec{})
	chk := mustChecker(t, floorConfig(t, nil, ca))
	f := newFloorCase(t, k, ca, certSpec{months: 24})
	v, err := f.check(chk)
	floorWant(t, v, err, answer.CodeValidity, fl7)
	for i, wantReason := range []string{
		"the floor has no result file", "", "the floor has no result file", "", "", "", "",
		"the floor does not ask a foreign CA for the form of ritueel's certificates", "the floor has no result file",
	} {
		if v.Checks[i].Reason != wantReason {
			t.Errorf("slot %d: reason %q, want %q", i+1, v.Checks[i].Reason, wantReason)
		}
	}
	f = newFloorCase(t, k, ca, certSpec{flipSigByte: true})
	v, err = f.check(chk)
	floorWant(t, v, err, answer.CodeIssuer, fl4)
	for _, i := range []int{4, 5, 6} { // slots 5, 6 and 7 did not run because slot 4 failed
		if v.Checks[i].Reason != "a check before it did not pass" {
			t.Errorf("slot %d: reason %q", i+1, v.Checks[i].Reason)
		}
	}
	for _, i := range []int{0, 2, 7, 8} {
		if v.Checks[i].Reason == "a check before it did not pass" || v.Checks[i].Reason == "" {
			t.Errorf("slot %d: reason %q", i+1, v.Checks[i].Reason)
		}
	}
}

func TestTheFloorFilesAndTheErrorsOfAFloorChecker(t *testing.T) {
	k := newKit(t)
	ca := newForeignCA(t, caSpec{})
	chk := mustChecker(t, floorConfig(t, nil, ca))
	t.Run("a result file is an error of the caller and no verdict", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		f.ans.Files[answer.FileResult] = []byte("{}")
		v, err := f.check(chk)
		if !errors.Is(err, answer.ErrFloorHasResult) {
			t.Fatalf("error %v", err)
		}
		if v.Accepted() || v.AnswerRefused() || len(v.Checks) != 0 || v.Info != nil {
			t.Errorf("a verdict comes with the error: %+v", v)
		}
	})
	t.Run("an empty result file counts as a result file", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		f.ans.Files[answer.FileResult] = nil
		if _, err := f.check(chk); !errors.Is(err, answer.ErrFloorHasResult) {
			t.Fatalf("error %v", err)
		}
	})
	t.Run("an OpenPGP request is not judged", func(t *testing.T) {
		c := k.newPGP("sign")
		v, err := chk.Check(c.req.asked(), &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileBound: c.bound}})
		if !errors.Is(err, answer.ErrUnsupported) || v.Accepted() || len(v.Checks) != 0 {
			t.Fatalf("error %v accepted %v", err, v.Accepted())
		}
	})
	t.Run("an SSH request is not judged: the floor is X.509 only", func(t *testing.T) {
		m := readVectorManifest(t)
		c := vectorCase(t, "ssh-piv-valid")
		_ = m
		v, err := chk.Check(vectorAsked(t, c), vectorAnswer(t, c))
		if !errors.Is(err, answer.ErrUnsupported) || v.Accepted() {
			t.Fatalf("error %v accepted %v", err, v.Accepted())
		}
	})
	t.Run("a full checker given a floor answer: no result file", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		v, err := f.check(k.checker(nil))
		want(t, v, err, answer.CodeMalformed, malformedNoVer)
		if v.Floor() {
			t.Error("a full checker gives a floor verdict")
		}
	})
	t.Run("no certificate file", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		clear(f.ans.Files)
		v, err := f.check(chk)
		floorWant(t, v, err, answer.CodeMalformed, fl2)
	})
	t.Run("a bound file beside the certificate", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		f.ans.Files[answer.FileBound] = []byte{1}
		v, err := f.check(chk)
		floorWant(t, v, err, answer.CodeMalformed, fl2)
	})
	t.Run("the certificate file is held to the strict form", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		good := string(f.ans.Files[answer.FileCert])
		for name, file := range map[string][]byte{
			"two blocks":      []byte(good + good),
			"text before":     []byte("note\n" + good),
			"a request label": []byte(strings.ReplaceAll(good, "CERTIFICATE", "CERTIFICATE REQUEST")),
			"not PEM":         []byte("x"),
			"empty":           {},
			"too large":       make([]byte, answer.MaxFileSize+1),
		} {
			f.ans.Files[answer.FileCert] = file
			v, err := f.check(chk)
			if err != nil || v.Code != answer.CodeMalformed || statuses(v) != fl2 {
				t.Errorf("%s: %v %q %s", name, err, v.Code, statuses(v))
			}
		}
	})
	t.Run("the clock of the floor is the checker's", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{})
		later := mustChecker(t, floorConfig(t, func(c *answer.Config) { c.Now = func() time.Time { return testNow.AddDate(2, 0, 0) } }, ca))
		v, err := f.check(later)
		floorWant(t, v, err, answer.CodeValidity, fl7)
	})
	t.Run("a floor request through a request with a proof", func(t *testing.T) {
		// The requester that has the files of a request and uses the floor passes the CSR file alone.
		csr := newCSR(t, nil, nil)
		if _, err := answer.AskedX509(csr.file); err != nil {
			t.Fatal(err)
		}
	})
}

// The name of the issuer only picks the installed certificates to try; the signature decides. A certificate whose
// issuer name is the subject of an installed certificate and whose signature is by another key is refused with the
// code issuer, and it is not accepted for the name alone.
func TestTheSignatureDecidesOnTheFloorAndNotTheNameOfTheIssuer(t *testing.T) {
	k := newKit(t)
	ca := newForeignCA(t, caSpec{})
	rogue := newForeignCA(t, caSpec{}) // the same name, another key
	if !bytes.Equal(ca.root.cert.RawSubject, rogue.root.cert.RawSubject) || ca.root.cert.Equal(rogue.root.cert) {
		t.Fatal("the two certificates are meant to share a name and to be two certificates")
	}
	chk := mustChecker(t, floorConfig(t, nil, ca))
	t.Run("a certificate of a CA that has the name of an installed one but is not installed", func(t *testing.T) {
		f := newFloorCase(t, k, rogue, certSpec{})
		v, err := f.check(chk)
		floorWant(t, v, err, answer.CodeIssuer, fl4)
		if v.Accepted() || v.Info != nil {
			t.Error("accepted for the name alone")
		}
	})
	t.Run("a certificate that names the installed CA in every field but is signed by another key", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{signWith: rogue.root.key})
		v, err := f.check(chk)
		floorWant(t, v, err, answer.CodeIssuer, fl4)
	})
	t.Run("the control: the same certificate signed by the installed key is accepted", func(t *testing.T) {
		f := newFloorCase(t, k, ca, certSpec{signWith: ca.root.key})
		v, err := f.check(chk)
		floorWant(t, v, err, "", floorOK)
		if v.Info.Issuer != ca.root.pin {
			t.Errorf("issuer %s, want %s", v.Info.Issuer, ca.root.pin)
		}
	})
	t.Run("two installed CAs of one name: the one whose key verifies is the issuer, whatever the order", func(t *testing.T) {
		for _, order := range [][]foreignCA{{ca, rogue}, {rogue, ca}} {
			chk := mustChecker(t, floorConfig(t, nil, order...))
			v, err := newFloorCase(t, k, ca, certSpec{}).check(chk)
			floorWant(t, v, err, "", floorOK)
			if v.Info.Issuer != ca.root.pin {
				t.Errorf("issuer %s, want %s", v.Info.Issuer, ca.root.pin)
			}
			v, err = newFloorCase(t, k, rogue, certSpec{}).check(chk)
			floorWant(t, v, err, "", floorOK)
			if v.Info.Issuer != rogue.root.pin {
				t.Errorf("issuer %s, want %s", v.Info.Issuer, rogue.root.pin)
			}
		}
	})
	t.Run("two installed CAs of one name and a certificate of a third key", func(t *testing.T) {
		third := newForeignCA(t, caSpec{})
		chk := mustChecker(t, floorConfig(t, nil, ca, rogue))
		v, err := newFloorCase(t, k, third, certSpec{}).check(chk)
		floorWant(t, v, err, answer.CodeIssuer, fl4)
	})
}

// What the docs of Verdict.Accepted and Verdict.Floor say: a floor verdict is accepted with four checks that were
// not run; a checker is a floor checker or a full one for its whole life; the same files can be accepted by the
// one and refused by the other; and a caller that needs the full contract makes a full checker.
func TestAFloorVerdictIsAcceptedWithFourChecksNotRunAndOnlyAFullCheckerHoldsTheFullContract(t *testing.T) {
	k := newKit(t)
	ca := newForeignCA(t, caSpec{})
	floor := mustChecker(t, floorConfig(t, nil, ca))
	f := newFloorCase(t, k, ca, certSpec{})

	v, err := f.check(floor)
	floorWant(t, v, err, "", floorOK)
	if !v.Accepted() || !v.Floor() {
		t.Fatalf("accepted %v, floor %v", v.Accepted(), v.Floor())
	}
	var notRun []int
	for _, c := range v.Checks {
		if c.Status == handoff.StatusNotRun {
			notRun = append(notRun, c.N)
		}
	}
	if !slices.Equal(notRun, []int{1, 3, 8, 9}) {
		t.Errorf("the checks not run are %v, the page says 1, 3, 8 and 9", notRun)
	}

	// The same files at a full checker: a full checker needs the result file, and the verdict is not a floor one.
	full := k.checker(nil)
	v, err = f.check(full)
	want(t, v, err, answer.CodeMalformed, malformedNoVer)
	if v.Accepted() || v.Floor() {
		t.Errorf("accepted %v, floor %v for a full checker", v.Accepted(), v.Floor())
	}

	// The checker keeps its kind: many calls, and a floor answer, still give floor verdicts, never a full one.
	for range 3 {
		v, err = f.check(floor)
		floorWant(t, v, err, "", floorOK)
		v, err = f.check(full)
		want(t, v, err, answer.CodeMalformed, malformedNoVer)
	}

	// A full checker's accepted verdict has no check that was not run, and it is not a floor verdict.
	x := k.newX509(nil)
	v, err = x.check(full)
	want(t, v, err, "", "ppppppppp")
	if !v.Accepted() || v.Floor() {
		t.Errorf("accepted %v, floor %v", v.Accepted(), v.Floor())
	}
	for _, c := range v.Checks {
		if c.Status == handoff.StatusNotRun {
			t.Errorf("check %d was not run in a full verdict", c.N)
		}
	}

	// A caller cannot make one checker of both kinds.
	both := floorConfig(t, nil, ca)
	both.Held, both.CABundle = k.config(nil).Held, k.config(nil).CABundle
	if _, err := answer.New(both); !errors.Is(err, answer.ErrConfig) {
		t.Errorf("New with the floor and a held list: %v", err)
	}
}
