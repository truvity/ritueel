package answer_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"ritueel.id/ritueel/internal/handoff/answer"
)

// Hostile certificates for the list of the floor: an installed certificate or an answer whose key or signature
// algorithm is as odd as a file can make it. None crashes the checker, none is accepted by the list, and each
// is refused with a code and fixed words, or, where the standard library does not read the certificate at all,
// as a file that is not a certificate (New: ErrConfig; an answer: malformed).

// nest wraps a value in n sequences.
func nest(n int, inner []byte) []byte {
	for range n {
		inner = tlv(0x30, inner)
	}
	return inner
}

// bigRSA is the key of an RSA certificate with a modulus of the given bits: an odd number, not a product of
// primes. It is a key that no one can sign with.
func bigRSA(bits int, e int) []byte {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	n.Or(n, big.NewInt(1))
	body := tlv(0x30, mustMarshal(n), mustMarshal(e))
	return tlv(0x30, algIDNull(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}), tlv(0x03, append([]byte{0}, body...)))
}

func TestHostileInstalledCertificatesAreRefusedOrNeverAcceptAnAnswer(t *testing.T) {
	signer := listKey(t, "P-384")
	good := newListCA(t, "P-384", caOpts{})
	csr := newCSR(t, nil, nil)
	der := good.answerCert(t, csr, sigECDSASHA384)
	for _, c := range []struct {
		name string
		spki []byte
	}{
		{"an RSA key of 16384 bits", bigRSA(16384, 65537)},
		{"an RSA key of 20000 bits", bigRSA(20000, 65537)},
		{"an RSA key of 3 bits", bigRSA(3, 65537)},
		{"an RSA key with the exponent 1", bigRSA(2048, 1)},
		{"an RSA key with the exponent 2", bigRSA(2048, 2)},
		{"an RSA key with a huge exponent", bigRSA(2048, 1<<31-1)},
		{"an RSA key whose parameters are not NULL", func() []byte {
			b := bigRSA(2048, 65537)
			return bytes.Replace(b, []byte{0x05, 0x00}, []byte{0x04, 0x00}, 1)
		}()},
		{"an unknown key with deeply nested parameters", tlv(0x30, tlv(0x30, mustMarshal(asn1.ObjectIdentifier{1, 2, 3, 4}), nest(200, []byte{0x05, 0x00})), tlv(0x03, []byte{0, 1, 2, 3}))},
		{"an ML-DSA-44 key of random bytes", tlv(0x30, algID(oidMLDSA44), tlv(0x03, append([]byte{0}, randomBytes(1312)...)))},
		{"an ML-DSA-44 identifier with a key of one byte", tlv(0x30, algID(oidMLDSA44), tlv(0x03, []byte{0, 1}))},
		{"an unknown key with an empty bit string", tlv(0x30, algID(asn1.ObjectIdentifier{1, 2, 3, 4}), tlv(0x03, []byte{0}))},
		{"an Ed25519 identifier with a key of one byte", tlv(0x30, algID(oidEd25519), tlv(0x03, []byte{0, 1}))},
		{"an Ed25519 identifier with parameters", tlv(0x30, tlv(0x30, mustMarshal(oidEd25519), []byte{0x05, 0x00}), tlv(0x03, append([]byte{0}, make([]byte, 32)...)))},
		{"an ECDSA key with a curve that nobody names", tlv(0x30, tlv(0x30, mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}), mustMarshal(asn1.ObjectIdentifier{1, 2, 3, 4})), tlv(0x03, append([]byte{0}, make([]byte, 65)...)))},
		{"an ECDSA key with its parameters left out", tlv(0x30, algID(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}), tlv(0x03, append([]byte{0}, make([]byte, 65)...)))},
		{"an ECDSA key whose point is zero", tlv(0x30, tlv(0x30, mustMarshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}), mustMarshal(asn1.ObjectIdentifier{1, 3, 132, 0, 34})), tlv(0x03, append([]byte{0, 4}, make([]byte, 96)...)))},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The certificate is signed by a good key; its own key is the odd one.
			hostile := buildCert(t, certIn{
				subject: good.subject, issuer: good.subject, spki: c.spki,
				exts:      []pkixExt{{Id: oidBasicConstraints, Critical: true, Value: tlv(0x30, []byte{0x01, 0x01, 0xff})}, extKeyUsage(true, keyCertSign)},
				notBefore: good.cert.NotBefore, notAfter: good.cert.NotAfter, alg: sigECDSASHA384, signer: signer,
			})
			chk, err := answer.New(floorCfg(hostile))
			if err != nil {
				if !errors.Is(err, answer.ErrConfig) {
					t.Fatalf("New: %v, want the kind ErrConfig", err)
				}
				return
			}
			// It is installed: an answer that it did not sign is refused, whichever way, and never accepted.
			v, err := checkCert(t, chk, csr, der)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if v.Accepted() || v.Info != nil || v.Code != answer.CodeIssuer || statuses(v) != fl4 {
				t.Fatalf("code %q statuses %s accepted %v", v.Code, statuses(v), v.Accepted())
			}
			if v.Detail != wordsKey && v.Detail != wordsNone {
				t.Errorf("detail %q is not one of the fixed words", v.Detail)
			}
		})
	}
}

func TestHostileAnswerSignaturesAreRefusedByTheListOrAsMalformed(t *testing.T) {
	ca := newListCA(t, "RSA-2048", caOpts{})
	chk := listChecker(t, ca)
	pssWithHash := func(h []byte) listSig {
		params := tlv(0x30, tlv(0xa0, h), tlv(0xa2, mustMarshal(32)))
		return listSig{name: "pss", der: tlv(0x30, mustMarshal(oidPSS), params), hash: crypto.SHA256, pss: true}
	}
	for _, c := range []struct {
		name string
		sig  listSig
	}{
		{"parameters nested 300 deep", listSig{name: "deep", der: tlv(0x30, mustMarshal(oidPSS), nest(300, []byte{0x05, 0x00})), hash: crypto.SHA256, pss: true}},
		{"a PSS with no MGF", pssWithHash(tlv(0x30, mustMarshal(oidHashes[crypto.SHA256]), []byte{0x05, 0x00}))},
		{"a PSS with no parameters at all", listSig{name: "bare", der: tlv(0x30, mustMarshal(oidPSS)), hash: crypto.SHA256, pss: true}},
		{"a PSS with a NULL in the place of the parameters", listSig{name: "null", der: algIDNull(oidPSS), hash: crypto.SHA256, pss: true}},
		{"an identifier with an arc of 2^60", listSig{name: "arc", der: tlv(0x30, []byte{0x06, 0x0a, 0x2a, 0x86, 0xf8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}), hash: crypto.SHA256}},
		{"an identifier of 500 arcs", listSig{name: "long", der: tlv(0x30, mustMarshal(longOID(500))), hash: crypto.SHA256}},
		{"an empty identifier", listSig{name: "empty", der: tlv(0x30), hash: crypto.SHA256}},
	} {
		t.Run(c.name, func(t *testing.T) {
			csr := newCSR(t, nil, nil)
			v, err := checkCert(t, chk, csr, ca.answerCert(t, csr, c.sig))
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if v.Accepted() || v.Info != nil || v.Code == "" {
				t.Fatalf("accepted %v code %q", v.Accepted(), v.Code)
			}
			switch {
			case v.Code == answer.CodeMalformed && statuses(v) == fl2:
			case v.Code == answer.CodeIssuer && statuses(v) == fl4 && (v.Detail == wordsSig || v.Detail == wordsNone):
			default:
				t.Errorf("code %q statuses %s detail %q", v.Code, statuses(v), v.Detail)
			}
		})
	}
	t.Run("a signature of a megabyte", func(t *testing.T) {
		csr := newCSR(t, nil, nil)
		der := ca.answerCert(t, csr, sigSHA256RSA)
		big := append(bytes.Clone(der), make([]byte, answer.MaxFileSize)...)
		v, err := checkCert(t, chk, csr, big)
		floorWant(t, v, err, answer.CodeMalformed, fl2)
	})
	t.Run("a body that names SHA-1 in the certificate and SHA-256 outside it", func(t *testing.T) {
		csr := newCSR(t, nil, nil)
		der := ca.answerCertWith(t, csr, certIn{alg: sigSHA256RSA, algInside: sigSHA1RSA.der})
		v, err := checkCert(t, chk, csr, der)
		floorWant(t, v, err, answer.CodeMalformed, fl2)
	})
	t.Run("a body that names SHA-256 in the certificate and SHA-1 outside it", func(t *testing.T) {
		csr := newCSR(t, nil, nil)
		der := ca.answerCertWith(t, csr, certIn{alg: sigSHA1RSA, algInside: sigSHA256RSA.der})
		v, err := checkCert(t, chk, csr, der)
		floorWant(t, v, err, answer.CodeMalformed, fl2)
	})
}

// A modulus the standard library refuses to verify with is not a key of the list that is accepted: the library's
// own floor on the modulus (1024 bits) is below the page's (2048), so the page's rule is the one that holds.
func TestTheLibraryFloorOnAnRSAKeyIsBelowThePageAndThePageHolds(t *testing.T) {
	ca := newListCA(t, "RSA-1024", caOpts{})
	pub := ca.cert.PublicKey.(*rsa.PublicKey)
	if pub.N.BitLen() != 1024 {
		t.Fatalf("%d bits", pub.N.BitLen())
	}
	csr := newCSR(t, nil, nil)
	der := ca.answerCert(t, csr, sigSHA256RSA)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if cert.CheckSignatureFrom(ca.cert) != nil {
		t.Skip("this library does not verify with a key of 1024 bits; the page's rule is not what refuses it")
	}
	v, err := checkCert(t, listChecker(t, ca), csr, der)
	wantRefusedByList(t, v, err, wordsKey)
}

func longOID(n int) asn1.ObjectIdentifier {
	oid := asn1.ObjectIdentifier{1, 2}
	for i := 0; i < n; i++ {
		oid = append(oid, i+3)
	}
	return oid
}

// randomBytes are n bytes that no one chose.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
