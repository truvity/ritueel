package answer_test

import (
	"bytes"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/pki"
)

// The control of every X.509 case: an answer that is accepted with nine checks passed.
func TestTheControlAnswersAreAccepted(t *testing.T) {
	k := newKit(t)
	chk := k.checker(nil)
	t.Run("x509", func(t *testing.T) {
		v, err := k.newX509(nil).check(chk)
		want(t, v, err, "", "ppppppppp")
		if v.Info.Issuer != k.a.pin || v.Info.TrustSequence != 7 || v.Info.Stem != "example-answer" {
			t.Errorf("Info %+v", *v.Info)
		}
		if !v.Info.ValidFrom.Equal(testNow) || !v.Info.ValidUntil.Equal(time.Date(2027, 12, 15, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("valid %v to %v", v.Info.ValidFrom, v.Info.ValidUntil)
		}
	})
	t.Run("openpgp sign", func(t *testing.T) {
		v, err := k.newPGP("sign").check(chk)
		want(t, v, err, "", "pppppppp")
	})
	t.Run("openpgp authenticate", func(t *testing.T) {
		v, err := k.newPGP("authenticate").check(chk)
		want(t, v, err, "", "pppppppp")
	})
	t.Run("by the other primary", func(t *testing.T) {
		c := k.newPGP("sign")
		c.bound, c.by = c.req.bind(1), k.b.primary
		v, err := c.check(chk)
		want(t, v, err, "", "pppppppp")
		if v.Info.Issuer != k.b.primary.fingerprint() {
			t.Errorf("issuer %s", v.Info.Issuer)
		}
	})
}

// The certificate writer of the tests writes the body of the builder of package pki, byte for byte, when the
// serial and the time are the same, so that a control is not a certificate that only this test accepts.
func TestTheTestWriterWritesTheBodyOfTheBuilder(t *testing.T) {
	k := newKit(t)
	csr := newCSR(t, nil, nil)
	der := k.issue(csr, certSpec{})
	mine, err := parseCert(der)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := pki.NewSerial(nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = serial
	params := pki.IntermediateParams{
		CSR: csr.der, IssuerSubject: k.a.cert.RawSubject, IssuerKey: &k.a.key.PublicKey,
		Roots:        []pki.RootRef{{Subject: k.a.cert.RawSubject, Key: &k.a.key.PublicKey}, {Subject: k.b.cert.RawSubject, Key: &k.b.key.PublicKey}},
		CeremonyTime: testNow, Serial: mine.SerialNumber,
	}
	tbs, err := pki.IntermediateTBS(params)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tbs, mine.RawTBSCertificate) {
		t.Fatalf("the test writer's body differs from the builder's:\n%x\n%x", mine.RawTBSCertificate, tbs)
	}
	whole, err := pki.Assemble(mine.RawTBSCertificate, mine.Signature, &k.a.key.PublicKey)
	if err != nil || !bytes.Equal(whole, der) {
		t.Fatalf("the builder does not assemble the test writer's certificate: %v", err)
	}
	// The builder itself, with a signer, makes a certificate that the checker accepts.
	sig, err := pki.SignIntermediate(nil, k.a.key, params, tbs)
	if err != nil {
		t.Fatal(err)
	}
	built, err := pki.Assemble(tbs, sig, &k.a.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	x := k.newX509(csr)
	x.der = built
	v, err := x.check(k.checker(nil))
	want(t, v, err, "", "ppppppppp")
	_ = answer.MaxFileSize
}
