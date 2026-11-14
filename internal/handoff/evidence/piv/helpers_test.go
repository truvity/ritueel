package piv_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/handoff/evidence/piv"
)

// clock is the time of the vectors.
var clock = time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

func newMaker(t testing.TB) *attesttest.Maker {
	t.Helper()
	return attesttest.NewMaker(t, attesttest.MakerOptions{TokenECDSA: true, Now: clock})
}

func newVerifier(t testing.TB, b *attest.Bundle) *piv.Verifier {
	t.Helper()
	v, err := piv.New(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func p384(t testing.TB) *ecdsa.PublicKey {
	t.Helper()
	k, ok := attesttest.P384(t).Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("not an ECDSA key")
	}
	return k
}

func proofOf(store handoff.Store, evidence []byte) *handoff.Proof {
	return &handoff.Proof{Handoff: 1, Type: handoff.TypeX509, Store: store, Evidence: evidence}
}

// verifyPIV calls the verifier on the evidence of a piv proof at the clock.
func verifyPIV(t testing.TB, v *piv.Verifier, evidence []byte) (*handoff.Evidence, error) {
	t.Helper()
	return v.Verify(t.Context(), nil, proofOf(handoff.StorePIV, evidence), clock)
}

// wantRefusal checks that err is a refusal with the code, returns its detail, and checks that no evidence
// came back beside it.
func wantRefusal(t testing.TB, ev *handoff.Evidence, err error, code handoff.Code) string {
	t.Helper()
	if ev != nil {
		t.Errorf("evidence beside an error: %+v", ev)
	}
	var ce *handoff.CodeError
	if !errors.As(err, &ce) {
		t.Fatalf("error %v is not a *handoff.CodeError", err)
	}
	if ce.Code != code {
		t.Fatalf("code %q (%s), want %q", ce.Code, ce.Detail, code)
	}
	if ce.Detail == "" {
		t.Error("a refusal with no detail")
	}
	for _, w := range []string{"Example", "acme", "YubiKey", "Maker", "Intermediate", "TEST ONLY", "x509:", "2026", "CN=", "9c", "12345678"} {
		if strings.Contains(ce.Detail, w) {
			t.Errorf("the detail %q holds %q, which comes from a certificate or from Go", ce.Detail, w)
		}
	}
	return ce.Detail
}

func wantPlainError(t testing.TB, ev *handoff.Evidence, err error) {
	t.Helper()
	if ev != nil {
		t.Errorf("evidence beside an error: %+v", ev)
	}
	if err == nil {
		t.Fatal("no error, want a fault of the caller")
	}
	var ce *handoff.CodeError
	if errors.As(err, &ce) {
		t.Fatalf("a fault of the caller is a refusal: %v", err)
	}
}

func done() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// vectorTime is the clock of the vectors, read as the manifest writes it.
func vectorTime(t testing.TB) time.Time {
	t.Helper()
	c, err := time.Parse(time.RFC3339, vectorClock)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
