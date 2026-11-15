package answer_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/handoff/answer"
)

// Fuzz targets of the readers of untrusted bytes that the list of the floor stands behind: the certificate of an
// answer, and an installed CA certificate. Run in the ordinary way they run the seeds. None starts a program.

// pageAllowsKey and pageAllowsSignature are the sentence of the page "The floor", written again here, by the
// types of the standard library and not by the code under test: an ECDSA key on P-256, P-384 or P-521, an
// Ed25519 key, or an RSA key of 2048 bits or more; signed with SHA-256, SHA-384 or SHA-512 (ECDSA, PKCS #1
// version 1.5 or PSS), or with Ed25519.
func pageAllowsKey(pub any) bool {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return true
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	}
	return false
}

func pageAllowsSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.PureEd25519:
		return true
	}
	return false
}

// FuzzFloorAnswerCertificate gives the floor a checker with five installed certificates of one name (three on the
// list and two that are not) and an answer that the fuzzer changes. An answer that is accepted is signed with an
// algorithm of the page by an installed certificate whose key is on the page, and the signature verifies.
func FuzzFloorAnswerCertificate(f *testing.F) {
	var cas []*listCA
	for _, k := range []string{"P-384", "RSA-2048", "Ed25519", "RSA-1024", "P-224"} {
		cas = append(cas, newListCA(f, k, caOpts{}))
	}
	chk := listChecker(f, cas...)
	csr := newCSR(f, nil, nil)
	asked, err := answer.AskedX509(csr.file)
	if err != nil {
		f.Fatal(err)
	}
	for _, ca := range cas {
		for _, sig := range []listSig{sigECDSASHA384, sigECDSASHA1, sigSHA256RSA, sigPSS256, sigSHA1RSA, sigEd25519} {
			f.Add(ca.answerCert(f, csr, sig))
		}
	}
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, der []byte) {
		keep := bytes.Clone(der)
		v, err := chk.Check(asked, &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileCert: certPEM(der)}})
		if !bytes.Equal(der, keep) {
			t.Fatal("the bytes of the answer were changed")
		}
		if err != nil {
			t.Fatalf("an error for a floor answer: %v", err)
		}
		verdictLaws(t, v, err, true)
		if v.Code == answer.CodeIssuer && v.Detail != wordsKey && v.Detail != wordsSig && v.Detail != wordsNone && v.Detail != wordsNotValid {
			t.Fatalf("a refusal of slot 4 with words that are not fixed: %q", v.Detail)
		}
		if !v.Accepted() {
			return
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("an answer that does not parse is accepted: %v", err)
		}
		if !pageAllowsSignature(cert.SignatureAlgorithm) {
			t.Fatalf("accepted with the signature algorithm %v, which the page does not list", cert.SignatureAlgorithm)
		}
		var issuer *listCA
		for _, ca := range cas {
			if ca.pin() == v.Info.Issuer {
				issuer = ca
			}
		}
		if issuer == nil {
			t.Fatalf("accepted under an issuer %s that is not installed", v.Info.Issuer)
		}
		if !pageAllowsKey(issuer.cert.PublicKey) {
			t.Fatalf("accepted under a key of %s, which the page does not list", issuer.name)
		}
		if err := cert.CheckSignatureFrom(issuer.cert); err != nil {
			t.Fatalf("accepted though the signature does not verify: %v", err)
		}
	})
}

// FuzzFloorInstalledCertificate gives New the file of an installed certificate that the fuzzer changes. New
// refuses it with ErrConfig or takes it; when it takes it, an answer of the seeds is judged and never accepted
// unless the page lists the key of the installed certificate and the signature algorithm of the answer.
func FuzzFloorInstalledCertificate(f *testing.F) {
	var cas []*listCA
	for _, k := range []string{"P-384", "RSA-2048", "Ed25519", "RSA-1024", "RSA-2047", "P-224"} {
		cas = append(cas, newListCA(f, k, caOpts{}))
	}
	csr := newCSR(f, nil, nil)
	asked, err := answer.AskedX509(csr.file)
	if err != nil {
		f.Fatal(err)
	}
	type seedAnswer struct {
		der []byte
		ca  *listCA
	}
	var answers []seedAnswer
	for _, ca := range cas {
		sig := nativeSig(ca.cert.PublicKey)
		answers = append(answers, seedAnswer{ca.answerCert(f, csr, sig), ca}, seedAnswer{ca.answerCert(f, csr, sigSHA1RSA), ca})
		f.Add(ca.der)
	}
	f.Add([]byte(nil))
	f.Fuzz(func(t *testing.T, der []byte) {
		cfg := floorCfg(der)
		chk, err := answer.New(cfg)
		if err != nil {
			if !errors.Is(err, answer.ErrConfig) {
				t.Fatalf("New: %v, want the kind ErrConfig", err)
			}
			return
		}
		installed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("New took a file that does not parse: %v", err)
		}
		for _, a := range answers {
			v, err := chk.Check(asked, &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileCert: certPEM(a.der)}})
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			verdictLaws(t, v, err, true)
			if !v.Accepted() {
				continue
			}
			cert, err := x509.ParseCertificate(a.der)
			if err != nil {
				t.Fatal(err)
			}
			if !pageAllowsKey(installed.PublicKey) || !pageAllowsSignature(cert.SignatureAlgorithm) {
				t.Fatalf("accepted with the key %T and the algorithm %v, which the page does not list", installed.PublicKey, cert.SignatureAlgorithm)
			}
			if err := cert.CheckSignatureFrom(installed); err != nil {
				t.Fatalf("accepted though the signature does not verify: %v", err)
			}
		}
	})
}

// The floor vectors are all on the list, and their verdicts are what the manifest says: the list took nothing
// away from the answers of the vectors.
func TestTheFloorVectorsAreOnTheListAndKeepTheirVerdicts(t *testing.T) {
	m := readVectorManifest(t)
	chk := mustChecker(t, vectorFloorConfig(t, m))
	var anchors []*x509.Certificate
	for _, file := range vectorFloorAnchors(t, m) {
		c, err := parseCert(pemDER(t, file))
		if err != nil {
			t.Fatal(err)
		}
		if !pageAllowsKey(c.PublicKey) {
			t.Errorf("an anchor of the vectors has a key that the page does not list: %T", c.PublicKey)
		}
		anchors = append(anchors, c)
	}
	if len(anchors) == 0 {
		t.Fatal("no anchor")
	}
	n := 0
	for _, c := range m.Responses {
		if !c.Floor {
			continue
		}
		n++
		t.Run(c.ID, func(t *testing.T) {
			ans := vectorAnswer(t, c)
			cert, err := parseCert(pemDER(t, ans.Files[answer.FileCert]))
			if err != nil {
				t.Fatal(err)
			}
			if !pageAllowsSignature(cert.SignatureAlgorithm) {
				t.Errorf("the signature algorithm of the vector is %v, which the page does not list", cert.SignatureAlgorithm)
			}
			v, err := chk.Check(vectorAsked(t, c), ans)
			if err != nil {
				t.Fatal(err)
			}
			if c.Expect == "install" {
				if !v.Accepted() {
					t.Fatalf("code %q detail %q", v.Code, v.Detail)
				}
				return
			}
			if string(v.Code) != c.Reason {
				t.Fatalf("code %q, the manifest says %s", v.Code, c.Reason)
			}
			if v.Detail == wordsKey || v.Detail == wordsSig {
				t.Errorf("a vector is refused by the list: %q", v.Detail)
			}
		})
	}
	if n != 5 {
		t.Errorf("%d floor vectors, the manifest has 5", n)
	}
}
