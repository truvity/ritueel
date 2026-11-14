package piv_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attest"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// vectorClock is the clock of the vectors (testdata/hand-off/v1/manifest.json).
const vectorClock = "2026-11-15T12:00:00Z"

// pivStems are the stems of the vector cases whose proof is of the store piv.
func pivStems(t testing.TB) []string {
	t.Helper()
	var out []string
	for _, stem := range attesttest.VectorEvidenceStems(t) {
		if attesttest.VectorProof(t, stem).Store == handoff.StorePIV {
			out = append(out, stem)
		}
	}
	return out
}

// The vectors: the evidence of every piv case is read by the verifier with no checker and no request, at
// the clock of the vectors. The cases that are about an untrusted chain are refused with proof-invalid and
// give no evidence; every other gives the key, the firmware and the policies that the case's name says.
// The test fails when it finds no case, or when the split is not the one of the set.
func TestTheEvidenceOfEveryPIVVectorCase(t *testing.T) {
	v := newVerifier(t, attesttest.VectorBundle(t))
	stems := pivStems(t)
	if len(stems) != 32 {
		t.Fatalf("%d piv cases in the vectors, want 32 (10 X.509, 13 OpenPGP, 9 SSH)", len(stems))
	}
	clock := vectorTime(t)
	refused, given := 0, 0
	for _, stem := range stems {
		t.Run(stem, func(t *testing.T) {
			p := attesttest.VectorProof(t, stem)
			ev, err := v.Verify(t.Context(), nil, p, clock)
			if strings.Contains(stem, "untrusted-chain") {
				refused++
				wantRefusal(t, ev, err, handoff.CodeProofInvalid)
				return
			}
			given++
			if err != nil {
				t.Fatal(err)
			}
			if ev.Key == nil || ev.Key.Curve.Params().Name != "P-384" {
				t.Fatalf("key %v", ev.Key)
			}
			wantFirmware, wantPIN := "5.8.0", handoff.PINOnce
			if stem == "x509-piv-old-firmware" {
				wantFirmware = "5.4.3"
			}
			if strings.Contains(stem, "pin-never") {
				wantPIN = handoff.PINNever
			}
			if ev.Firmware != wantFirmware || ev.PINPolicy != wantPIN || ev.TouchPolicy != "never" {
				t.Errorf("firmware %q PIN %q touch %q, want %q %q never", ev.Firmware, ev.PINPolicy, ev.TouchPolicy, wantFirmware, wantPIN)
			}
			for k, want := range map[string]string{
				attest.DetailSlot: "9c", attest.DetailSerial: "12345678", attest.DetailFormFactor: "2", attest.DetailPolicyRead: "true",
			} {
				if ev.Details[k] != want {
					t.Errorf("detail %s %q, want %q", k, ev.Details[k], want)
				}
			}
			if ev.Details[attest.DetailBundleVersion] != "example-test" {
				t.Errorf("bundle version %q", ev.Details[attest.DetailBundleVersion])
			}
			// The key of an X.509 case is compared with the key of its request: equal for every case but the one
			// that is about a key that is not the request's.
			if !strings.HasPrefix(stem, "x509-") {
				return
			}
			csr, err := pki.RequestKeyFile(testrepo.Read(t, "testdata/hand-off/v1", "requests", stem+"."+handoff.FileCSR))
			if err != nil {
				t.Fatal(err)
			}
			if same := ev.Key.Equal(csr); same == (stem == "x509-piv-key-mismatch") {
				t.Errorf("the attested key equals the request's key: %v", same)
			}
		})
	}
	if refused != 2 || given != 30 {
		t.Errorf("%d refused and %d with evidence, want 2 and 30", refused, given)
	}
}

// Evidence that is for another store is not read: the openpgp-card vectors offered to the piv verifier are
// refused or are a fault of the caller (the store is the verifier's own).
func TestAnOpenPGPCardProofIsNotAPIVProof(t *testing.T) {
	v := newVerifier(t, attesttest.VectorBundle(t))
	for _, stem := range attesttest.VectorEvidenceStems(t) {
		p := attesttest.VectorProof(t, stem)
		if p.Store != handoff.StoreOpenPGPCard {
			continue
		}
		ev, err := v.Verify(t.Context(), nil, p, vectorTime(t))
		wantPlainError(t, ev, err)
		// The same evidence under the piv store: its OpenPGP chain does not pass the piv intermediate.
		p.Store = handoff.StorePIV
		ev, err = v.Verify(t.Context(), nil, p, vectorTime(t))
		wantRefusal(t, ev, err, handoff.CodeProofInvalid)
	}
}

// The evidence that the first vector gives, written once for a reader of the test log: a way to see what the
// verifier returned by hand.
func TestVectorEvidenceIsLogged(t *testing.T) {
	v := newVerifier(t, attesttest.VectorBundle(t))
	ev, err := v.Verify(t.Context(), nil, attesttest.VectorProof(t, "x509-piv-valid"), vectorTime(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("firmware %s, PIN %s, touch %s, details %v", ev.Firmware, ev.PINPolicy, ev.TouchPolicy, ev.Details)
}
