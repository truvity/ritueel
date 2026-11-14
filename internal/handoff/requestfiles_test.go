package handoff_test

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// withCSR is the fixture's request with the request file replaced.
func withCSR(f *fixture, file []byte) *handoff.Request {
	r := f.request()
	r.Files[handoff.FileCSR] = file
	return r
}

func TestACertificateRequestFileThatIsNotOfTheFormOfThePageIsMalformed(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	body := strings.TrimSuffix(strings.TrimPrefix(string(f.csr), "-----BEGIN CERTIFICATE REQUEST-----\n"), "-----END CERTIFICATE REQUEST-----\n")
	second := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for name, file := range map[string][]byte{
		"empty":                     {},
		"text":                      []byte("hello"),
		"the wrong label":           pem.EncodeToMemory(&pem.Block{Type: "NEW CERTIFICATE REQUEST", Bytes: f.der}),
		"a certificate label":       pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.der}),
		"a lower-case label":        []byte("-----BEGIN certificate request-----\n" + body + "-----END certificate request-----\n"),
		"two blocks":                append(bytes.Clone(f.csr), second.csr...),
		"the same block twice":      append(bytes.Clone(f.csr), f.csr...),
		"text after the block":      append(bytes.Clone(f.csr), []byte("trailing\n")...),
		"text before the block":     append([]byte("leading\n"), f.csr...),
		"a header in the block":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: f.der}),
		"DER that is not a request": pemOf([]byte{0x30, 0x03, 0x02, 0x01, 0x01}),
		"DER of nothing":            pemOf([]byte{}),
		"the DER cut off":           pemOf(f.der[:len(f.der)-1]),
		"the DER with a byte after": pemOf(append(bytes.Clone(f.der), 0)),
		"the DER, bare":             f.der,
		"a block with no end":       []byte("-----BEGIN CERTIFICATE REQUEST-----\n" + body),
		"a blank line in the block": []byte("-----BEGIN CERTIFICATE REQUEST-----\n\n" + body + "-----END CERTIFICATE REQUEST-----\n"),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := newChecker(t).Check(t.Context(), withCSR(f, file))
			wantRefusal(t, v, err, handoff.CodeMalformed, 2)
		})
	}
}

func TestACertificateRequestFileAtTheLimitIsReadAndOneByteMoreIsMalformed(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	over := bytes.Repeat([]byte("A"), handoff.MaxFileSize+1)
	v, err := newChecker(t).Check(t.Context(), withCSR(f, over))
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	// Over the limit, and a good request at its start: the size is refused before the file is read.
	v, err = newChecker(t).Check(t.Context(), withCSR(f, append(bytes.Clone(f.csr), make([]byte, handoff.MaxFileSize)...)))
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	// Exactly the limit is not refused for its size: whatever refuses it, the detail does not say so.
	atLimit := append(bytes.Clone(f.csr), bytes.Repeat([]byte("\n"), handoff.MaxFileSize-len(f.csr))...)
	v, err = newChecker(t).Check(t.Context(), withCSR(f, atLimit))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(v.Detail, "longer than") {
		t.Errorf("a file of exactly the limit is refused for its size: %s", v.Detail)
	}
}

func TestAMissingFileOfARequestIsMalformedAtCheckTwo(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	r := f.request()
	delete(r.Files, handoff.FileCSR)
	v, err := newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
	// An x509 request with the file of another type in its place has no request.
	r.Files[handoff.FileSubkey] = f.der
	v, err = newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

func TestARequestFileInOtherLineEndingsIsTheSameRequest(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	crlf := bytes.ReplaceAll(f.csr, []byte("\n"), []byte("\r\n"))
	v, err := newChecker(t).Check(t.Context(), withCSR(f, crlf))
	wantAccepted(t, v, err)
	noEnd := bytes.TrimSuffix(f.csr, []byte("\n"))
	v, err = newChecker(t).Check(t.Context(), withCSR(f, noEnd))
	wantAccepted(t, v, err)
}

func TestTheDigestIsOfTheDERAndNotOfTheFile(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for name, digest := range map[string]string{
		"of the PEM text":          digestHex(f.csr),
		"of the DER, one byte off": digestHex(f.der[1:]),
		"of the Base64 body":       digestHex([]byte(strings.Join(strings.Split(strings.TrimSpace(string(f.csr)), "\n")[1:], ""))),
		"of nothing":               digestHex(nil),
		"all zeros":                strings.Repeat("0", 64),
	} {
		t.Run(name, func(t *testing.T) {
			f.proof["request_sha256"] = digest
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)
		})
	}
	f.proof["request_sha256"] = digestHex(f.der)
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
}

func TestAProofForAnotherRequestIsAMismatch(t *testing.T) {
	a := newFixture(t, handoff.StoreSoftware, csrSpec{})
	b := newFixture(t, handoff.StoreSoftware, csrSpec{})
	r := a.request()
	r.Files[handoff.FileCSR] = b.csr // a swapped pair of files
	v, err := newChecker(t).Check(t.Context(), r)
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)
}

func TestAKeyThatIsNotP384IsAlgorithmUnsupported(t *testing.T) {
	for name, key := range otherKeys(t) {
		t.Run(name, func(t *testing.T) {
			// The request is signed in the way that fits its key, so the key is what is wrong.
			f := newFixture(t, handoff.StoreSoftware, csrSpec{key: key})
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeAlgorithmUnsupported, 4)
		})
	}
}

func TestAKeyThatIsNotP384WithAnotherSignatureIsStillTheKeyThatIsRefused(t *testing.T) {
	keys := otherKeys(t)
	for name, alg := range map[string]x509.SignatureAlgorithm{"P-256": x509.ECDSAWithSHA384, "P-521": x509.ECDSAWithSHA256} {
		f := newFixture(t, handoff.StoreSoftware, csrSpec{key: keys[name], sigAlg: alg})
		v, err := newChecker(t).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodeAlgorithmUnsupported, 4)
	}
}

func TestARequestNotSignedWithSHA384IsPossessionInvalid(t *testing.T) {
	for name, alg := range map[string]x509.SignatureAlgorithm{
		"ecdsa-with-SHA256": x509.ECDSAWithSHA256,
		"ecdsa-with-SHA512": x509.ECDSAWithSHA512,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreSoftware, csrSpec{sigAlg: alg})
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
		})
	}
}

func TestARequestWithATamperedSignatureIsPossessionInvalid(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	// The last bytes of the DER are the end of the signature value; one change keeps the DER well formed.
	for _, back := range []int{1, 2, 10, 30} {
		t.Run(fmt.Sprintf("byte %d from the end", back), func(t *testing.T) {
			der := bytes.Clone(f.der)
			der[len(der)-back] ^= 0x01
			g := &fixture{t: t, signer: f.signer, der: der, csr: pemOf(der), proof: map[string]any{}}
			for k, v := range f.proof {
				g.proof[k] = v
			}
			g.proof["request_sha256"] = digestHex(der)
			v, err := newChecker(t).Check(t.Context(), g.request())
			wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
		})
	}
}

func TestARequestSignedByAnotherKeyIsPossessionInvalid(t *testing.T) {
	// The request of b, with the point of the key of a written in place of the point of b: the DER is as
	// well formed as before and the key is a key, but the signature is not the signature of that key.
	a, b := newP384(t), newP384(t)
	f := newFixture(t, handoff.StoreSoftware, csrSpec{key: b})
	from := elliptic.Marshal(elliptic.P384(), b.PublicKey.X, b.PublicKey.Y) //nolint:staticcheck // the point is written on purpose, to find it in the DER
	to := elliptic.Marshal(elliptic.P384(), a.PublicKey.X, a.PublicKey.Y)   //nolint:staticcheck // as above
	if bytes.Count(f.der, from) != 1 {
		t.Fatal("test setup: the point is not in the DER once")
	}
	der := bytes.Replace(f.der, from, to, 1)
	f.csr, f.der = pemOf(der), der
	f.proof["request_sha256"] = digestHex(der)
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
}

func TestAPointThatIsNotOnTheCurveIsNeverAccepted(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	pt := elliptic.Marshal(elliptic.P384(), f.publicKey().X, f.publicKey().Y) //nolint:staticcheck // the point is written on purpose, to find it in the DER
	at := bytes.Index(f.der, pt)
	if at < 0 {
		t.Fatal("test setup: the point is not in the DER")
	}
	der := bytes.Clone(f.der)
	der[at+len(pt)-1] ^= 0x01
	f.csr, f.der = pemOf(der), der
	f.proof["request_sha256"] = digestHex(der)
	v, err := newChecker(t).Check(t.Context(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	// The page names the canonical form as malformed and a key that is not P-384 as unsupported; it does
	// not say which of them a point off the curve is. It is refused, before the store is looked at.
	if v.Code != handoff.CodeMalformed && v.Code != handoff.CodeAlgorithmUnsupported {
		t.Fatalf("code %q (%s)", v.Code, v.Detail)
	}
	if v.Complete() || v.Checks[5].Status != handoff.StatusNotRun {
		t.Fatalf("statuses %s", statuses(v))
	}
}
