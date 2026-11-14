package attest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
)

// clock is the time of the vectors, and the time that a maker builds its validities around by default.
var clock = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

// newMaker is a made-up maker with a P-384 token key, which is faster than the RSA key of the vectors.
func newMaker(t testing.TB) *attesttest.Maker {
	t.Helper()
	return attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock})
}

// pivChain returns the parsed slot certificate and token certificate of a good chain for a fresh key.
func pivChain(t testing.TB, m *attesttest.Maker, s attesttest.Slot) *attest.Attestation {
	t.Helper()
	leaf, token := m.PIVChain(t, attesttest.P384(t).Public(), s)
	return &attest.Attestation{Leaf: mustCert(t, leaf), Token: mustCert(t, token)}
}

// mustCert parses a certificate that the test made.
func mustCert(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("the test's own certificate does not parse: %v", err)
	}
	return c
}

// codeErr returns the refusal in err, and fails the test when err is not one.
func codeErr(t testing.TB, err error) *handoff.CodeError {
	t.Helper()
	var ce *handoff.CodeError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *handoff.CodeError", err)
	}
	return ce
}

// wantRefusal checks that err is a refusal with the code and returns its detail. The detail holds no word
// of the made-up subjects, no year and no text of a Go error.
func wantRefusal(t testing.TB, err error, code handoff.Code) string {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want a refusal %s", code)
	}
	ce := codeErr(t, err)
	if ce.Code != code {
		t.Fatalf("code %q (%s), want %q", ce.Code, ce.Detail, code)
	}
	noLeak(t, ce.Detail)
	return ce.Detail
}

// leakWords are text that a certificate of the made-up maker holds and that a refusal must never copy.
var leakWords = []string{
	"Example", "acme", "YubiKey", "Maker", "Intermediate", "Attestation ", "TEST ONLY", "x509:", "2026", "2025",
	"certificate signed by", "unknown authority", "expired or is not yet valid", "CN=", "O=",
}

func noLeak(t testing.TB, detail string) {
	t.Helper()
	if detail == "" {
		t.Error("a refusal with no detail")
	}
	for _, w := range leakWords {
		if strings.Contains(detail, w) {
			t.Errorf("the detail %q holds %q, which comes from a certificate or from Go", detail, w)
		}
	}
}

// wantPlainError checks that err is an error and is not a verdict on the evidence.
func wantPlainError(t testing.TB, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("no error, want a fault of the caller")
	}
	var ce *handoff.CodeError
	if errors.As(err, &ce) {
		t.Fatalf("a fault of the caller is a refusal: %v", err)
	}
}

// b64 is the canonical Base64 of the pieces that a test makes.
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// done is a context that is already cancelled.
func done() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// proofOf is a proof of the store with the evidence.
func proofOf(store handoff.Store, evidence []byte) *handoff.Proof {
	return &handoff.Proof{Handoff: 1, Type: handoff.TypeX509, Store: store, Evidence: evidence}
}

// p384 is a P-384 public key for a slot certificate to attest.
func p384(t testing.TB) *ecdsa.PublicKey {
	t.Helper()
	k, ok := attesttest.P384(t).Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	return k
}
