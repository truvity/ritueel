package answer_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
)

// The sentence of the page "The floor" of docs/reference/hand-off-contract.md that these tests hold the floor to:
//
//	The requester accepts a CA certificate with an ECDSA key on P-256, P-384 or P-521, an Ed25519 key, or an RSA
//	key of 2048 bits or more, signed with SHA-256, SHA-384 or SHA-512, or with Ed25519. It refuses any other key
//	or signature, a SHA-1 or MD5 signature included.
//
// A test names the rows of the sentence: each key of the sentence with each signature of the sentence, each
// edge of the size of an RSA key, each key and each signature outside the sentence.

// listedKeys are the keys of the sentence, with the signatures that each of them can make.
func listedKeys() []struct {
	name string
	sigs []listSig
} {
	pick := func(all []listSig) []listSig {
		var out []listSig
		for _, s := range all {
			if s.listed {
				out = append(out, s)
			}
		}
		return out
	}
	return []struct {
		name string
		sigs []listSig
	}{
		{"P-256", pick(sigsECDSA)},
		{"P-384", pick(sigsECDSA)},
		{"P-521", pick(sigsECDSA)},
		{"Ed25519", []listSig{sigEd25519}},
		{"RSA-2048", pick(sigsRSA)},
		{"RSA-3072", pick(sigsRSA)},
		{"RSA-4096", pick(sigsRSA)},
	}
}

// Every key of the sentence with every signature of the sentence is accepted, and the standard library agrees
// that each certificate is what it says it is.
func TestTheFloorAcceptsEachKeyAndEachSignatureOfTheList(t *testing.T) {
	n := 0
	for _, k := range listedKeys() {
		ca := newListCA(t, k.name, caOpts{})
		chk := listChecker(t, ca)
		for _, sig := range k.sigs {
			t.Run(k.name+" signed with "+sig.name, func(t *testing.T) {
				csr := newCSR(t, nil, nil)
				der := ca.answerCert(t, csr, sig)
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if err := cert.CheckSignatureFrom(ca.cert); err != nil {
					t.Fatalf("the writer made a certificate that the standard library does not verify: %v", err)
				}
				v, err := checkCert(t, chk, csr, der)
				floorWant(t, v, err, "", floorOK)
				if v.Info.Issuer != ca.pin() {
					t.Errorf("issuer %s, want the pin of the key of %s", v.Info.Issuer, k.name)
				}
				n++
			})
		}
	}
	// 3 ECDSA keys with 3 hashes, Ed25519 once, 3 RSA keys with 3 PKCS #1 and 3 PSS signatures.
	if want := 3*3 + 1 + 3*6; n != want {
		t.Errorf("%d rows of the list were run, want %d", n, want)
	}
}

// The key rows that the sentence refuses. Each is an installed certificate that New accepts, signed itself with
// the algorithm of its key, and an answer that it signed validly with a signature algorithm of the list: the
// refusal is the key's alone.
func TestTheFloorRefusesAKeyOutsideTheListAndSaysSo(t *testing.T) {
	for _, c := range []struct {
		key  string
		sigs []listSig
		bits int // the bits of the modulus, for an RSA key
	}{
		{"RSA-1024", []listSig{sigSHA256RSA, sigSHA384RSA, sigSHA512RSA, sigPSS256}, 1024},
		{"RSA-2047", []listSig{sigSHA256RSA, sigSHA384RSA, sigSHA512RSA, sigPSS256}, 2047},
		{"P-224", []listSig{sigECDSASHA256, sigECDSASHA384, sigECDSASHA512}, 0},
	} {
		ca := newListCA(t, c.key, caOpts{})
		if c.bits != 0 {
			if got := ca.cert.PublicKey.(*rsa.PublicKey).N.BitLen(); got != c.bits {
				t.Fatalf("the modulus of %s has %d bits, the case is about %d", c.key, got, c.bits)
			}
		}
		chk := listChecker(t, ca) // New accepts it
		for _, sig := range c.sigs {
			t.Run(c.key+" signed with "+sig.name, func(t *testing.T) {
				csr := newCSR(t, nil, nil)
				der := ca.answerCert(t, csr, sig)
				// The signature is good: the standard library verifies it. Only the list refuses.
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if err := cert.CheckSignatureFrom(ca.cert); err != nil {
					t.Fatalf("the writer made a certificate that the standard library does not verify: %v", err)
				}
				v, err := checkCert(t, chk, csr, der)
				wantRefusedByList(t, v, err, wordsKey)
			})
		}
	}
	t.Run("a key that the standard library does not know", func(t *testing.T) {
		// An X25519 key in the place of the key of the CA. The certificate parses; its public key is nil.
		spki := tlv(0x30, algID(oidX25519), tlv(0x03, append([]byte{0}, make([]byte, 32)...)))
		ca := newListCA(t, "Ed25519", caOpts{spki: spki})
		if ca.cert.PublicKey != nil {
			t.Fatalf("the library reads this key as %T", ca.cert.PublicKey)
		}
		chk := listChecker(t, ca)
		csr := newCSR(t, nil, nil)
		v, err := checkCert(t, chk, csr, ca.answerCert(t, csr, sigEd25519))
		wantRefusedByList(t, v, err, wordsKey)
	})
}

// The edge of the size of an RSA key: 2047 bits refused, 2048 accepted. The same answer, the same algorithm.
func TestTheFloorHoldsAnRSAKeyToTwoThousandAndFortyEightBits(t *testing.T) {
	for _, c := range []struct {
		key  string
		bits int
		code answer.Code
	}{
		{"RSA-1024", 1024, answer.CodeIssuer},
		{"RSA-2047", 2047, answer.CodeIssuer},
		{"RSA-2048", 2048, ""},
		{"RSA-3072", 3072, ""},
	} {
		t.Run(c.key, func(t *testing.T) {
			ca := newListCA(t, c.key, caOpts{})
			if got := ca.cert.PublicKey.(*rsa.PublicKey).N.BitLen(); got != c.bits {
				t.Fatalf("%d bits", got)
			}
			csr := newCSR(t, nil, nil)
			v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sigSHA256RSA))
			if c.code == "" {
				floorWant(t, v, err, "", floorOK)
				return
			}
			wantRefusedByList(t, v, err, wordsKey)
		})
	}
}

// The curves: P-256, P-384 and P-521 are in the sentence and P-224 is not.
func TestTheFloorHoldsAnECDSAKeyToThreeCurves(t *testing.T) {
	for _, c := range []struct {
		key     string
		curve   string
		allowed bool
	}{
		{"P-224", "P-224", false},
		{"P-256", "P-256", true},
		{"P-384", "P-384", true},
		{"P-521", "P-521", true},
	} {
		t.Run(c.key, func(t *testing.T) {
			ca := newListCA(t, c.key, caOpts{})
			if got := ca.cert.PublicKey.(*ecdsa.PublicKey).Curve.Params().Name; got != c.curve {
				t.Fatalf("the curve of the key is %s", got)
			}
			csr := newCSR(t, nil, nil)
			v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sigECDSASHA256))
			if c.allowed {
				floorWant(t, v, err, "", floorOK)
				return
			}
			wantRefusedByList(t, v, err, wordsKey)
		})
	}
}

// The signature rows that the sentence refuses, under each key that it accepts: SHA-1 and MD5 first, and then the
// algorithms that no row names. The certificate is signed by the key, with the hash that the label says where a
// key can, so that the refusal is the algorithm's alone.
func TestTheFloorRefusesASignatureOutsideTheListAndSaysSo(t *testing.T) {
	unlisted := []listSig{
		sigECDSASHA1, sigSHA1RSA, sigMD5RSA, sigMD2RSA,
		pssSig("RSASSA-PSS with SHA-1", crypto.SHA1, 20, false),
		pssSig("RSASSA-PSS with SHA-256 and a salt of 16", crypto.SHA256, 16, false),
		{name: "ecdsa-with-SHA224", der: algID(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}), hash: crypto.SHA224},
		{name: "sha224WithRSA", der: algIDNull(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}), hash: crypto.SHA224},
		pssSig("RSASSA-PSS with SHA-224", crypto.SHA224, 28, false),
		{name: "ML-DSA-44", der: algID(oidMLDSA44), hash: crypto.SHA256},
		{name: "dsa-with-SHA1", der: algID(oidDSASHA1), hash: crypto.SHA256},
		{name: "dsa-with-SHA256", der: algID(oidDSASHA256), hash: crypto.SHA256},
		{name: "an identifier that nobody knows", der: algID(oidNobody), hash: crypto.SHA256},
	}
	for _, k := range listedKeys() {
		ca := newListCA(t, k.name, caOpts{})
		chk := listChecker(t, ca)
		for _, sig := range unlisted {
			t.Run(k.name+" and "+sig.name, func(t *testing.T) {
				csr := newCSR(t, nil, nil)
				der := ca.answerCert(t, csr, sig)
				v, err := checkCert(t, chk, csr, der)
				wantRefusedByList(t, v, err, wordsSig)
			})
		}
	}
}

// Where the library can still make a certificate with SHA-1, it is the library's certificate that is refused:
// not only the writer of these tests.
func TestTheFloorRefusesASHA1CertificateThatTheLibraryWrites(t *testing.T) {
	for _, c := range []struct {
		key string
		alg x509.SignatureAlgorithm
	}{
		{"P-384", x509.ECDSAWithSHA1},
		{"RSA-2048", x509.SHA1WithRSA},
	} {
		t.Run(c.key+" "+c.alg.String(), func(t *testing.T) {
			ca := newListCA(t, c.key, caOpts{})
			csr := newCSR(t, nil, nil)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1), NotBefore: testNow, NotAfter: testNow.AddDate(1, 1, 0),
				RawSubject: csr.req.Subject(), ExtraExtensions: csr.req.Extensions(), SignatureAlgorithm: c.alg,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.req.PublicKey(), ca.signer)
			if err != nil {
				t.Skipf("this library no longer writes %s: %v", c.alg, err)
			}
			v, err := checkCert(t, listChecker(t, ca), csr, der)
			wantRefusedByList(t, v, err, wordsSig)
		})
	}
}

// A certificate that the library writes with each algorithm of the sentence is accepted too, so that the list is
// not tuned to the writer of these tests.
func TestTheFloorAcceptsWhatTheLibraryWritesWithTheAlgorithmsOfTheList(t *testing.T) {
	for _, c := range []struct {
		key string
		alg x509.SignatureAlgorithm
	}{
		{"P-256", x509.ECDSAWithSHA256}, {"P-384", x509.ECDSAWithSHA384}, {"P-521", x509.ECDSAWithSHA512},
		{"Ed25519", x509.PureEd25519},
		{"RSA-2048", x509.SHA256WithRSA}, {"RSA-3072", x509.SHA384WithRSA}, {"RSA-4096", x509.SHA512WithRSA},
		{"RSA-2048", x509.SHA256WithRSAPSS}, {"RSA-3072", x509.SHA384WithRSAPSS}, {"RSA-4096", x509.SHA512WithRSAPSS},
	} {
		t.Run(c.key+" "+c.alg.String(), func(t *testing.T) {
			ca := newListCA(t, c.key, caOpts{})
			csr := newCSR(t, nil, nil)
			tmpl := &x509.Certificate{
				SerialNumber: big.NewInt(1), NotBefore: testNow, NotAfter: testNow.AddDate(1, 1, 0),
				RawSubject: csr.req.Subject(), ExtraExtensions: csr.req.Extensions(), SignatureAlgorithm: c.alg,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.req.PublicKey(), ca.signer)
			if err != nil {
				t.Fatal(err)
			}
			v, err := checkCert(t, listChecker(t, ca), csr, der)
			floorWant(t, v, err, "", floorOK)
		})
	}
}

// A signature algorithm of the sentence under a key of another kind does not verify. The list lets it through
// (the algorithm is on it) and the signature decides, with the words of a signature that does not verify.
func TestAListedAlgorithmUnderAKeyOfAnotherKindIsRefusedByTheSignature(t *testing.T) {
	for _, c := range []struct {
		key string
		sig listSig
	}{
		{"P-384", sigEd25519},
		{"P-384", sigSHA256RSA},
		{"P-384", sigPSS256},
		{"RSA-2048", sigECDSASHA256},
		{"RSA-2048", sigEd25519},
		{"Ed25519", sigECDSASHA256},
		{"Ed25519", sigSHA256RSA},
		{"Ed25519", sigPSS256},
	} {
		t.Run(c.key+" with "+c.sig.name, func(t *testing.T) {
			ca := newListCA(t, c.key, caOpts{})
			csr := newCSR(t, nil, nil)
			v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, c.sig))
			wantRefusedByList(t, v, err, wordsNone)
		})
	}
}

// A certificate that is on the list in every part and carries a signature that does not verify is refused with
// the words of the signature, not the words of the list.
func TestAListedCertificateWithABrokenSignatureIsNotAListFault(t *testing.T) {
	for _, k := range listedKeys() {
		ca := newListCA(t, k.name, caOpts{})
		csr := newCSR(t, nil, nil)
		der := ca.answerCert(t, csr, k.sigs[0])
		der[len(der)-1] ^= 0x01
		v, err := checkCert(t, listChecker(t, ca), csr, der)
		wantRefusedByList(t, v, err, wordsNone)
	}
}

// The key rule stands before the signature rule: a certificate that breaks both is refused with the key words.
func TestTheKeyWordsStandOverTheSignatureWords(t *testing.T) {
	for _, c := range []struct {
		key string
		sig listSig
	}{
		{"RSA-1024", sigSHA1RSA},
		{"RSA-2047", sigMD5RSA},
		{"P-224", sigECDSASHA1},
	} {
		t.Run(c.key+" with "+c.sig.name, func(t *testing.T) {
			ca := newListCA(t, c.key, caOpts{})
			csr := newCSR(t, nil, nil)
			v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, c.sig))
			wantRefusedByList(t, v, err, wordsKey)
		})
	}
}

// The rest of the walk after a refusal of the list is the walk of any refusal of slot 4: slots 5 to 7 are not run,
// with the reason that a check before them did not pass, and the four slots that cannot run say why.
func TestARefusalOfTheListLeavesTheSlotsAsAnyRefusalOfTheIssuer(t *testing.T) {
	ca := newListCA(t, "RSA-1024", caOpts{})
	csr := newCSR(t, nil, nil)
	v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sigSHA256RSA))
	wantRefusedByList(t, v, err, wordsKey)
	if len(v.Checks) != 9 {
		t.Fatalf("%d slots", len(v.Checks))
	}
	for _, i := range []int{4, 5, 6} {
		if v.Checks[i].Status != handoff.StatusNotRun || v.Checks[i].Reason != "a check before it did not pass" {
			t.Errorf("slot %d: %s %q", i+1, v.Checks[i].Status, v.Checks[i].Reason)
		}
	}
	for _, i := range []int{0, 2, 7, 8} {
		if v.Checks[i].Status != handoff.StatusNotRun || v.Checks[i].Reason == "" || v.Checks[i].Reason == "a check before it did not pass" {
			t.Errorf("slot %d: %s %q, a slot that cannot run says why", i+1, v.Checks[i].Status, v.Checks[i].Reason)
		}
	}
	if !v.AnswerRefused() || v.RequestRefused() || len(v.CertifierReasons) != 0 {
		t.Errorf("a fault of the answer is not marked so: %+v", v)
	}
}

// The words of a refusal of the list are the fixed words: no byte of the answer, of the name of the installed
// certificate or of its key stands in them.
func TestTheWordsOfTheListHoldNoByteOfTheCertificates(t *testing.T) {
	ca := newListCA(t, "RSA-1024", caOpts{cn: "Example Distinct Root Name 7731"})
	csr := newCSR(t, nil, nil)
	v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sigSHA256RSA))
	wantRefusedByList(t, v, err, wordsKey)
	if strings.Contains(v.Detail, "7731") || strings.Contains(v.Detail, "Example") || strings.Contains(v.Detail, "1024") {
		t.Errorf("the detail %q names the certificate", v.Detail)
	}
	ca = newListCA(t, "P-384", caOpts{cn: "Example Distinct Root Name 7732"})
	v, err = checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sigECDSASHA1))
	wantRefusedByList(t, v, err, wordsSig)
	if strings.Contains(v.Detail, "7732") || strings.Contains(v.Detail, "SHA1") || strings.Contains(v.Detail, "1.2.840") {
		t.Errorf("the detail %q names the certificate", v.Detail)
	}
}

// New does not refuse an installed certificate outside the list, as it does not refuse one that is not a CA. Many
// of them, with the others, are one checker, and an answer of a CA of the list is accepted beside them.
func TestNewAcceptsInstalledCertificatesOutsideTheList(t *testing.T) {
	good := newListCA(t, "P-384", caOpts{cn: "Example Good Root"})
	var cas []*listCA
	for i, k := range []string{"RSA-1024", "RSA-2047", "P-224"} {
		cas = append(cas, newListCA(t, k, caOpts{cn: "Example Outside Root " + string(rune('A'+i))}))
	}
	cas = append(cas, good)
	chk := listChecker(t, cas...)
	csr := newCSR(t, nil, nil)
	v, err := checkCert(t, chk, csr, good.answerCert(t, csr, sigECDSASHA384))
	floorWant(t, v, err, "", floorOK)
	if v.Info.Issuer != good.pin() {
		t.Errorf("issuer %s", v.Info.Issuer)
	}
	// An answer that names an outside certificate is refused with the key words, though the checker holds others.
	for i, out := range cas[:3] {
		sig := sigSHA256RSA
		if out.name == "P-224" {
			sig = sigECDSASHA256
		}
		v, err = checkCert(t, chk, csr, out.answerCert(t, csr, sig))
		wantRefusedByList(t, v, err, wordsKey)
		_ = i
	}
}

// An installed certificate outside the list is not a candidate for an answer that does not name it: that answer is
// refused as an answer with no installed issuer, with the words of that refusal and not of the list.
func TestAnAnswerThatDoesNotNameTheCertificateOutsideTheListIsNotJudgedByIt(t *testing.T) {
	outside := newListCA(t, "RSA-1024", caOpts{cn: "Example Outside Root"})
	stranger := newListCA(t, "P-384", caOpts{cn: "Example Stranger Root"})
	csr := newCSR(t, nil, nil)
	v, err := checkCert(t, listChecker(t, outside), csr, stranger.answerCert(t, csr, sigECDSASHA384))
	wantRefusedByList(t, v, err, wordsNone)
	// The same, with a stranger whose signature is by a SHA-1 algorithm: the list is applied to a candidate, and
	// there is none.
	v, err = checkCert(t, listChecker(t, outside), csr, stranger.answerCert(t, csr, sigECDSASHA1))
	wantRefusedByList(t, v, err, wordsNone)
}

// Two installed certificates of one name. The one that is outside the list does not stop the good one, whatever
// the order, and the answer is judged by the one that is on the list.
func TestTwoInstalledCertificatesOfOneNameOneOfThemOutsideTheList(t *testing.T) {
	for _, out := range []string{"RSA-1024", "RSA-2047", "P-224"} {
		bad := newListCA(t, out, caOpts{})
		good := newListCA(t, "P-384", caOpts{})
		if !slices.Equal(bad.subject, good.subject) {
			t.Fatal("the two certificates are meant to share a name")
		}
		for _, order := range [][]*listCA{{bad, good}, {good, bad}} {
			t.Run(out+" first="+order[0].name, func(t *testing.T) {
				chk := listChecker(t, order...)
				csr := newCSR(t, nil, nil)
				v, err := checkCert(t, chk, csr, good.answerCert(t, csr, sigECDSASHA384))
				floorWant(t, v, err, "", floorOK)
				if v.Info.Issuer != good.pin() {
					t.Errorf("issuer %s, want the pin of the one on the list", v.Info.Issuer)
				}
				// An answer that the outside certificate signed is refused with the key words.
				sig := sigSHA256RSA
				if out == "P-224" {
					sig = sigECDSASHA256
				}
				v, err = checkCert(t, chk, csr, bad.answerCert(t, csr, sig))
				wantRefusedByList(t, v, err, wordsKey)
			})
		}
	}
}

// Two installed certificates of one name, one not valid now and one with a key outside the list: the key words
// stand, whatever the order. (The page does not say which fault stands when two candidates fail for different
// reasons; the fault of the furthest step is built.)
func TestTheKeyWordsStandOverTheWordsOfACertificateThatIsNotValidNow(t *testing.T) {
	ended := caOpts{notBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), notAfter: time.Date(2026, 11, 15, 11, 59, 59, 0, time.UTC)}
	old := newListCA(t, "P-384", ended)
	bad := newListCA(t, "RSA-1024", caOpts{})
	csr := newCSR(t, nil, nil)
	for _, order := range [][]*listCA{{old, bad}, {bad, old}} {
		chk := listChecker(t, order...)
		v, err := checkCert(t, chk, csr, bad.answerCert(t, csr, sigSHA256RSA))
		wantRefusedByList(t, v, err, wordsKey)
		// The answer of the one that ended is the one that is not valid now, and the key words do not hide it.
		v, err = checkCert(t, chk, csr, old.answerCert(t, csr, sigECDSASHA384))
		wantRefusedByList(t, v, err, wordsKey)
	}
	// Alone, the one that ended says that it is not valid now.
	v, err := checkCert(t, listChecker(t, old), csr, old.answerCert(t, csr, sigECDSASHA384))
	wantRefusedByList(t, v, err, wordsNotValid)
}

// An installed certificate outside the list that has ended says that it is not valid now: the date is the first
// thing that is asked of a candidate (the page is silent on which fault comes first; the earlier words stand).
func TestAnInstalledCertificateOutsideTheListThatHasEndedSaysItIsNotValid(t *testing.T) {
	ended := caOpts{notBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), notAfter: time.Date(2026, 11, 15, 11, 59, 59, 0, time.UTC)}
	ca := newListCA(t, "RSA-1024", ended)
	csr := newCSR(t, nil, nil)
	v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sigSHA256RSA))
	wantRefusedByList(t, v, err, wordsNotValid)
}

// The signature fault and the key fault of two candidates of one name: the certificate that the answer needs is
// refused for its algorithm by the one with a key on the list, and the other for its key. The signature words,
// the furthest step, stand, whatever the order.
func TestTwoCandidatesOfOneNameTheFurthestFaultStands(t *testing.T) {
	bad := newListCA(t, "RSA-1024", caOpts{})
	other := newListCA(t, "P-384", caOpts{})
	csr := newCSR(t, nil, nil)
	for _, order := range [][]*listCA{{bad, other}, {other, bad}} {
		chk := listChecker(t, order...)
		v, err := checkCert(t, chk, csr, other.answerCert(t, csr, sigECDSASHA1))
		wantRefusedByList(t, v, err, wordsSig)
	}
}

// The list is applied to the CA that the answer names, and to no other installed certificate: a good answer is
// accepted though another installed certificate, of another name, has a key that the list refuses.
func TestTheListHoldsTheIssuingCertificateAndNotOthersThatAreInstalled(t *testing.T) {
	weakRoot := newListCA(t, "RSA-1024", caOpts{cn: "Example Weak Root"})
	good := newListCA(t, "P-384", caOpts{cn: "Example Good Root"})
	csr := newCSR(t, nil, nil)
	v, err := checkCert(t, listChecker(t, weakRoot, good), csr, good.answerCert(t, csr, sigECDSASHA384))
	floorWant(t, v, err, "", floorOK)
}

// The floor has not widened what it checks after slot 4: the certificates that pass the list are held to the
// key of the request, the profile and the validity as before. One row each for a CA of each kind.
func TestTheListDoesNotLetAnAnswerPastTheLaterSlots(t *testing.T) {
	for _, k := range listedKeys() {
		ca := newListCA(t, k.name, caOpts{})
		chk := listChecker(t, ca)
		sig := k.sigs[0]
		t.Run(k.name+" key of another request", func(t *testing.T) {
			csr, other := newCSR(t, nil, nil), newCSR(t, nil, nil)
			v, err := checkCert(t, chk, csr, ca.answerCert(t, other, sig))
			floorWant(t, v, err, answer.CodeKeyMismatch, fl5)
		})
		t.Run(k.name+" no extensions", func(t *testing.T) {
			csr := newCSR(t, nil, nil)
			stripped := ca.answerCertWith(t, csr, certIn{alg: sig, exts: []pkix.Extension{}})
			v, err := checkCert(t, chk, csr, stripped)
			floorWant(t, v, err, answer.CodeProfile, fl6)
		})
		t.Run(k.name+" two years", func(t *testing.T) {
			csr := newCSR(t, nil, nil)
			der := ca.answerCertWith(t, csr, certIn{alg: sig, notAfter: testNow.AddDate(2, 0, 0)})
			v, err := checkCert(t, chk, csr, der)
			floorWant(t, v, err, answer.CodeValidity, fl7)
		})
	}
}

// The full contract is not touched: it keeps ECDSA on P-384 with SHA-384 only. The same certificate that the
// floor takes (a P-384 CA, a signature of SHA-256) is refused by a checker of the full contract, and a full
// answer with ecdsa-with-SHA384 is still accepted.
func TestTheFullContractKeepsP384AndSHA384WhereTheFloorTakesMore(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	t.Run("a signature of SHA-256 under the root of the full contract", func(t *testing.T) {
		x := k.newX509(nil)
		x.spec.sigAlg, x.spec.digest = oidECDSASHA256, crypto.SHA256
		v, err := x.check(chk)
		want(t, v, err, answer.CodeIssuer, st4)
		if !strings.Contains(v.Detail, "ecdsa-with-SHA384") {
			t.Errorf("detail %q", v.Detail)
		}
		if v.Floor() {
			t.Error("a full verdict is a floor verdict")
		}
	})
	t.Run("a signature of SHA-384", func(t *testing.T) {
		v, err := k.newX509(nil).check(chk)
		want(t, v, err, "", "ppppppppp")
	})
	t.Run("a floor checker takes the SHA-256 signature that the full contract refuses", func(t *testing.T) {
		ca := newListCA(t, "P-384", caOpts{})
		csr := newCSR(t, nil, nil)
		v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sigECDSASHA256))
		floorWant(t, v, err, "", floorOK)
	})
	t.Run("a root of the full contract with a key that the floor takes is not a root of the full contract", func(t *testing.T) {
		// The CA bundle of a held list holds P-384 roots that the ceremony made. A bundle with an RSA root, or a
		// P-256 root, is not the bundle of a list that package rootlist verifies; the full checker never holds one
		// (the list pins the key of the bundle), so the keys of the floor do not reach it.
		ca := newListCA(t, "P-256", caOpts{})
		cfg := k.config(func(c *answer.Config) { c.CABundle = append(c.CABundle, ca.file...) })
		if _, err := answer.New(cfg); !errors.Is(err, answer.ErrConfig) {
			t.Fatalf("New with a bundle that holds a P-256 certificate beside the roots: %v", err)
		}
		cfg = k.config(func(c *answer.Config) { c.FloorAnchors = [][]byte{ca.file} })
		if _, err := answer.New(cfg); !errors.Is(err, answer.ErrConfig) {
			t.Fatalf("New with a held list and floor anchors: %v", err)
		}
	})
}

// A checker is read by many callers at once. The list holds no state: a floor checker with certificates inside and
// outside the list gives the same verdicts to many goroutines, which are started behind one closed channel.
func TestAFloorCheckerWithTheListGivesTheSameVerdictsToManyCallers(t *testing.T) {
	good := newListCA(t, "RSA-2048", caOpts{cn: "Example Good Root"})
	bad := newListCA(t, "RSA-1024", caOpts{cn: "Example Weak Root"})
	chk := listChecker(t, good, bad)
	csr := newCSR(t, nil, nil)
	goodDER := good.answerCert(t, csr, sigPSS256)
	badDER := bad.answerCert(t, csr, sigSHA256RSA)
	sha1DER := good.answerCert(t, csr, sigSHA1RSA)
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for _, c := range []struct {
				der   []byte
				words string
				ok    bool
			}{{goodDER, "", true}, {badDER, wordsKey, false}, {sha1DER, wordsSig, false}} {
				a, err := answer.AskedX509(csr.file)
				if err != nil {
					errs <- err.Error()
					return
				}
				v, err := chk.Check(a, &answer.Answer{Stem: "example-answer", Files: map[string][]byte{answer.FileCert: certPEM(c.der)}})
				if err != nil || v.Accepted() != c.ok || v.Detail != c.words {
					errs <- "a verdict differs: " + v.Detail
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// The signature that the list holds is the one on the answer. The signature on the installed certificate itself
// (a root signs itself; the operator trusts the file, not its signature) is not read by the floor. The sentence of
// the page can be read either way ("a CA certificate ... signed with SHA-256, SHA-384 or SHA-512"); the floor is
// built as the list of the change says, and this test pins that, so that a change of that reading is a change of
// a test.
func TestTheOwnSignatureOfAnInstalledCertificateIsNotHeldToTheList(t *testing.T) {
	for _, c := range []struct {
		key string
		sig listSig
	}{
		{"P-384", sigECDSASHA1},
		{"RSA-2048", sigSHA1RSA},
		{"RSA-2048", sigMD5RSA},
		{"P-256", sigECDSASHA1},
	} {
		t.Run(c.key+" signed itself with "+c.sig.name, func(t *testing.T) {
			ca := newListCA(t, c.key, caOpts{sig: c.sig})
			if ca.cert.SignatureAlgorithm != x509.ECDSAWithSHA1 && ca.cert.SignatureAlgorithm != x509.SHA1WithRSA && ca.cert.SignatureAlgorithm != x509.MD5WithRSA {
				t.Fatalf("the installed certificate is signed with %v", ca.cert.SignatureAlgorithm)
			}
			csr := newCSR(t, nil, nil)
			sig := sigECDSASHA256
			if c.key == "RSA-2048" {
				sig = sigSHA256RSA
			}
			v, err := checkCert(t, listChecker(t, ca), csr, ca.answerCert(t, csr, sig))
			floorWant(t, v, err, "", floorOK)
		})
	}
}
