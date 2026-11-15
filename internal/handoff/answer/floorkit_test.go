package answer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"  //nolint:gosec // a certificate signed with MD5, which the floor refuses
	"crypto/rand" //nolint:gosec // keys of the tests
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // a certificate signed with SHA-1, which the floor refuses
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/jws"
	"ritueel.id/ritueel/internal/pki"
)

// This file makes installed CA certificates of any key and answers of any signature algorithm, in memory, for
// the tests of the list of keys and signature algorithms of the floor. The certificates are written by hand
// (the body, then the signature over it) so that a case can have a key or an algorithm that the standard library
// does not write: a P-224 key, an unknown key, a SHA-1 or MD5 signature, an RSA-PSS with other parameters. Each
// control (a certificate of the list) is accepted by the floor and by the standard library alike, which shows
// that the writer writes certificates and that the refusals are the list's.

// The words of the refusals that the tests expect. The page fixes the rule, not the text; the text is the one
// of the package, fixed.
const (
	wordsKey = "the key of the installed CA certificate is not ECDSA on P-256, P-384 or P-521, Ed25519, or RSA of 2048 bits or more"
	wordsSig = "the signature algorithm of the certificate is not ECDSA or RSA with SHA-256, SHA-384 or SHA-512, or Ed25519"
	// wordsNone is what a refusal of slot 4 says when no installed certificate stands behind the name, or the
	// signature does not verify: the words of the floor before the list was added.
	wordsNone     = "the certificate does not verify to a CA certificate that the operator installed"
	wordsNotValid = "the installed CA certificate that issued it is not valid now"
)

var (
	oidMGF1    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidPSS     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidX25519  = asn1.ObjectIdentifier{1, 3, 101, 110}
	// oidDSASHA1 and oidDSASHA256 are DSA signatures, and oidNobody an identifier that no library knows.
	oidDSASHA1   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidDSASHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidNobody    = asn1.ObjectIdentifier{1, 2, 3, 4}
	oidMLDSA44   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidHashes    = map[crypto.Hash]asn1.ObjectIdentifier{
		crypto.SHA1:   {1, 3, 14, 3, 2, 26},
		crypto.SHA224: {2, 16, 840, 1, 101, 3, 4, 2, 4},
		crypto.SHA256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
		crypto.SHA384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
		crypto.SHA512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
	}
)

// listSig is one signature algorithm: its identifier as written, the hash it digests with, and how it signs.
type listSig struct {
	name string
	der  []byte      // the AlgorithmIdentifier, with its parameters
	hash crypto.Hash // 0 for Ed25519
	pss  bool
	// listed is what the page says: this algorithm is in the sentence, with a key of its kind.
	listed bool
	// kind is the kind of key that signs with it: "ecdsa", "rsa", "ed25519", or "" when no key can (then the
	// signature bytes are the ones of a key of the CA's kind, and the algorithm is only a label).
	kind string
}

func ecdsaSig(name string, hash crypto.Hash, oid asn1.ObjectIdentifier, listed bool) listSig {
	return listSig{name: name, der: algID(oid), hash: hash, listed: listed, kind: "ecdsa"}
}

func rsaSig(name string, hash crypto.Hash, oid asn1.ObjectIdentifier, listed bool) listSig {
	return listSig{name: name, der: algIDNull(oid), hash: hash, listed: listed, kind: "rsa"}
}

// pssSig is RSASSA-PSS with the parameters that the standard library reads: the hash, MGF1 with the same hash
// and a salt as long as the hash. salt is the length written, so that a case can write another.
func pssSig(name string, hash crypto.Hash, salt int, listed bool) listSig {
	h := tlv(0x30, mustMarshal(oidHashes[hash]), []byte{0x05, 0x00})
	params := tlv(0x30,
		tlv(0xa0, h),
		tlv(0xa1, tlv(0x30, mustMarshal(oidMGF1), h)),
		tlv(0xa2, mustMarshal(salt)))
	return listSig{name: name, der: tlv(0x30, mustMarshal(oidPSS), params), hash: hash, pss: true, listed: listed, kind: "rsa"}
}

var (
	sigECDSASHA1   = ecdsaSig("ecdsa-with-SHA1", crypto.SHA1, oidECDSASHA1, false)
	sigECDSASHA256 = ecdsaSig("ecdsa-with-SHA256", crypto.SHA256, oidECDSASHA256, true)
	sigECDSASHA384 = ecdsaSig("ecdsa-with-SHA384", crypto.SHA384, oidECDSASHA384, true)
	sigECDSASHA512 = ecdsaSig("ecdsa-with-SHA512", crypto.SHA512, asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, true)

	sigMD2RSA    = rsaSig("md2WithRSA", crypto.MD5, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}, false)
	sigMD5RSA    = rsaSig("md5WithRSA", crypto.MD5, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}, false)
	sigSHA1RSA   = rsaSig("sha1WithRSA", crypto.SHA1, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}, false)
	sigSHA256RSA = rsaSig("sha256WithRSA", crypto.SHA256, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, true)
	sigSHA384RSA = rsaSig("sha384WithRSA", crypto.SHA384, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}, true)
	sigSHA512RSA = rsaSig("sha512WithRSA", crypto.SHA512, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}, true)

	sigPSS256 = pssSig("RSASSA-PSS with SHA-256", crypto.SHA256, 32, true)
	sigPSS384 = pssSig("RSASSA-PSS with SHA-384", crypto.SHA384, 48, true)
	sigPSS512 = pssSig("RSASSA-PSS with SHA-512", crypto.SHA512, 64, true)

	sigEd25519 = listSig{name: "Ed25519", der: algID(oidEd25519), listed: true, kind: "ed25519"}
)

// A signature that the key of the CA can make, in the algorithm of the list or not.
var (
	// sigsECDSA is every ECDSA algorithm, SHA-1 included.
	sigsECDSA = []listSig{sigECDSASHA1, sigECDSASHA256, sigECDSASHA384, sigECDSASHA512}
	// sigsRSA is every RSA algorithm, MD5 and SHA-1 included.
	sigsRSA = []listSig{sigMD5RSA, sigSHA1RSA, sigSHA256RSA, sigSHA384RSA, sigSHA512RSA, sigPSS256, sigPSS384, sigPSS512}
)

// listKeys makes each key once for the whole run of the tests: an RSA key takes a moment.
var (
	listKeyMu sync.Mutex
	listKeyOf = map[string]crypto.Signer{}
)

func listKey(t testing.TB, name string) crypto.Signer {
	t.Helper()
	listKeyMu.Lock()
	defer listKeyMu.Unlock()
	if k, ok := listKeyOf[name]; ok {
		return k
	}
	var k crypto.Signer
	var err error
	switch name {
	case "P-224":
		k, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P-256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P-384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P-521":
		k, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "Ed25519":
		_, k, err = ed25519.GenerateKey(rand.Reader)
	case "RSA-1024":
		k, err = rsa.GenerateKey(rand.Reader, 1024)
	case "RSA-2047":
		k, err = rsa.GenerateKey(rand.Reader, 2047)
	case "RSA-2048":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case "RSA-3072":
		k, err = rsa.GenerateKey(rand.Reader, 3072)
	case "RSA-4096":
		k, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		t.Fatalf("no key %q", name)
	}
	if err != nil {
		t.Fatalf("key %s: %v", name, err)
	}
	listKeyOf[name] = k
	return k
}

// nativeSig is the algorithm a CA of the key signs its own certificate with.
func nativeSig(pub crypto.PublicKey) listSig {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P384():
			return sigECDSASHA384
		case elliptic.P521():
			return sigECDSASHA512
		}
		return sigECDSASHA256
	case *rsa.PublicKey:
		return sigSHA256RSA
	}
	return sigEd25519
}

// certIn is the body of a certificate and how it is signed.
type certIn struct {
	subject, issuer     []byte
	spki                []byte
	exts                []pkix.Extension
	notBefore, notAfter time.Time
	alg                 listSig
	signer              crypto.Signer
	// algInside is written in the body instead of alg when it is not nil (a body and a certificate that disagree).
	algInside []byte
}

// signBody signs the body with the key by the algorithm.
func signBody(t testing.TB, signer crypto.Signer, a listSig, tbs []byte) []byte {
	t.Helper()
	_, edSigner := signer.(ed25519.PrivateKey)
	switch {
	case a.kind == "ed25519" && !edSigner:
		// An Ed25519 label on a signature of another key: bytes of the length of an Ed25519 signature.
		sig := make([]byte, 64)
		if _, err := rand.Read(sig); err != nil {
			t.Fatal(err)
		}
		return sig
	case edSigner:
		sig, err := signer.Sign(rand.Reader, tbs, crypto.Hash(0))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	var digest []byte
	switch a.hash {
	case crypto.MD5:
		d := md5.Sum(tbs) //nolint:gosec // see the import
		digest = d[:]
	case crypto.SHA1:
		d := sha1.Sum(tbs) //nolint:gosec // see the import
		digest = d[:]
	case crypto.SHA224:
		d := sha256.Sum224(tbs)
		digest = d[:]
	case crypto.SHA256:
		d := sha256.Sum256(tbs)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(tbs)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(tbs)
		digest = d[:]
	default:
		t.Fatalf("hash %v", a.hash)
	}
	var opts crypto.SignerOpts = a.hash
	if a.pss {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: a.hash}
	}
	sig, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// buildCert writes a version 3 certificate and signs it.
func buildCert(t testing.TB, in certIn) []byte {
	t.Helper()
	serial := make([]byte, 20)
	if _, err := rand.Read(serial); err != nil {
		t.Fatal(err)
	}
	serial[0] = serial[0]&0x7f | 0x40
	inside := in.alg.der
	if in.algInside != nil {
		inside = in.algInside
	}
	parts := [][]byte{
		tlv(0xa0, []byte{0x02, 0x01, 0x02}),
		mustMarshal(new(big.Int).SetBytes(serial)),
		inside,
		in.issuer,
		tlv(0x30, utcTime(in.notBefore), utcTime(in.notAfter)),
		in.subject,
		in.spki,
	}
	if len(in.exts) > 0 {
		var each [][]byte
		for _, e := range in.exts {
			each = append(each, extDER(e))
		}
		parts = append(parts, tlv(0xa3, tlv(0x30, each...)))
	}
	tbs := tlv(0x30, parts...)
	sig := signBody(t, in.signer, in.alg, tbs)
	return tlv(0x30, tbs, in.alg.der, tlv(0x03, append([]byte{0}, sig...)))
}

// listCA is an installed CA certificate, made in memory, and the key that signs for it.
type listCA struct {
	name    string
	signer  crypto.Signer // nil for a certificate whose key cannot sign (an unknown key)
	subject []byte
	der     []byte
	file    []byte
	cert    *x509.Certificate
}

// caOpts changes the CA that newListCA makes.
type caOpts struct {
	cn                  string
	notBefore, notAfter time.Time
	// sig is the algorithm of the self-signature of the certificate; the zero value takes the native one.
	sig listSig
	// spki replaces the key of the certificate with a key that the standard library may not know; the
	// certificate is then signed with the key named by name.
	spki []byte
}

// newListCA makes a self-signed CA certificate (a CA of the profile of the floor: basic constraints and the key
// usage keyCertSign) for the key.
func newListCA(t testing.TB, keyName string, o caOpts) *listCA {
	t.Helper()
	if o.cn == "" {
		o.cn = "Example Foreign Root (TEST ONLY)"
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if o.notAfter.IsZero() {
		o.notAfter = o.notBefore.AddDate(10, 0, 0)
	}
	signer := listKey(t, keyName)
	spki := o.spki
	if spki == nil {
		var err error
		if spki, err = x509.MarshalPKIXPublicKey(signer.Public()); err != nil {
			t.Fatal(err)
		}
	}
	if o.sig.der == nil {
		o.sig = nativeSig(signer.Public())
	}
	name := nameDER(o.cn)
	der := buildCert(t, certIn{
		subject: name, issuer: name, spki: spki,
		exts:      []pkix.Extension{{Id: oidBasicConstraints, Critical: true, Value: tlv(0x30, []byte{0x01, 0x01, 0xff})}, extKeyUsage(true, keyCertSign)},
		notBefore: o.notBefore, notAfter: o.notAfter, alg: o.sig, signer: signer,
	})
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the CA %s does not parse: %v", keyName, err)
	}
	return &listCA{name: keyName, signer: signer, subject: name, der: der, file: certPEM(der), cert: cert}
}

// pin is the pin of the key of the CA, as the verdict names the issuer.
func (c *listCA) pin() string { return jws.Pin(c.cert) }

// answerCert writes the certificate for the request that the CA signs with the algorithm: the subject and the
// public key of the request, its four extensions as asked, 13 months from the clock.
func (c *listCA) answerCert(t testing.TB, csr *memCSR, sig listSig) []byte {
	t.Helper()
	return c.answerCertWith(t, csr, certIn{alg: sig})
}

// answerCertWith is answerCert with the fields of in that the case sets; the others take the values of the
// profile.
func (c *listCA) answerCertWith(t testing.TB, csr *memCSR, in certIn) []byte {
	t.Helper()
	if in.signer == nil {
		in.signer = c.signer
	}
	if in.subject == nil {
		in.subject = csr.req.Subject()
	}
	if in.issuer == nil {
		in.issuer = c.subject
	}
	if in.spki == nil {
		var err error
		if in.spki, err = x509.MarshalPKIXPublicKey(csr.req.PublicKey()); err != nil {
			t.Fatal(err)
		}
	}
	if in.exts == nil {
		in.exts = csr.req.Extensions()
	}
	if in.notBefore.IsZero() {
		in.notBefore = testNow
	}
	if in.notAfter.IsZero() {
		var err error
		if in.notAfter, err = pki.AddMonths(in.notBefore, 13); err != nil {
			t.Fatal(err)
		}
	}
	return buildCert(t, in)
}

// listChecker is a floor checker whose installed certificates are the CAs, in that order.
func listChecker(t testing.TB, cas ...*listCA) *answer.Checker {
	t.Helper()
	var files [][]byte
	for _, c := range cas {
		files = append(files, append([]byte(nil), c.file...))
	}
	cfg := answer.Config{FloorAnchors: files, Now: func() time.Time { return testNow }}
	cfg.Validity.MinMonths, cfg.Validity.MaxMonths = 12, 14
	return mustChecker(t, cfg)
}

// checkCert judges the certificate as the answer to the request.
func checkCert(t testing.TB, chk *answer.Checker, csr *memCSR, der []byte) (answer.Verdict, error) {
	t.Helper()
	a, err := answer.AskedX509(csr.file)
	if err != nil {
		t.Fatal(err)
	}
	return chk.Check(a, &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileCert: certPEM(der)}})
}

// wantRefusedByList is the verdict of a refusal of slot 4 with the words.
func wantRefusedByList(t testing.TB, v answer.Verdict, err error, words string) {
	t.Helper()
	floorWant(t, v, err, answer.CodeIssuer, fl4)
	if v.Detail != words {
		t.Fatalf("detail %q, want %q", v.Detail, words)
	}
	if v.Info != nil || v.Accepted() {
		t.Fatalf("a refusal holds Info or is accepted")
	}
}

// pkixExt is the extension of a certificate, under a name that the hostile tests share.
type pkixExt = pkix.Extension

// floorCfg is the configuration of a floor checker whose installed certificates are the files, as they are.
func floorCfg(files ...[]byte) answer.Config {
	var pems [][]byte
	for _, f := range files {
		pems = append(pems, certPEM(f))
	}
	cfg := answer.Config{FloorAnchors: pems, Now: func() time.Time { return testNow }}
	cfg.Validity.MinMonths, cfg.Validity.MaxMonths = 12, 14
	return cfg
}

// pemDER is the DER of the one certificate block of a PEM file.
func pemDER(t testing.TB, file []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(file)
	if blk == nil {
		t.Fatal("no PEM block")
	}
	return blk.Bytes
}
