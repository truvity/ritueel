package handoff_test

import (
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/evidence/attesttest"
	"ritueel.id/ritueel/internal/handoff/evidence/openpgpcard"
	"ritueel.id/ritueel/internal/handoff/evidence/piv"
)

// The evidence verifiers of the two card stores, built on the pinned attestation roots and intermediates
// of the manifest, decide the X.509 cases whose key is in a PIV slot. They are registered for every case,
// as the verifiers of any other store are.
func init() {
	vectorVerifiers = append(vectorVerifiers, cardVerifiers)
}

func cardVerifiers(t testing.TB, m vectorManifest, _ vectorCase, _ handoff.Config) map[handoff.Store]handoff.EvidenceVerifier {
	t.Helper()
	if len(m.Pinned.AttestationRoots) == 0 || len(m.Pinned.AttestationIntermediates) == 0 {
		t.Fatalf("the manifest pins %d attestation roots and %d intermediates: a check that finds nothing to check fails",
			len(m.Pinned.AttestationRoots), len(m.Pinned.AttestationIntermediates))
	}
	b := attesttest.VectorBundle(t)
	pv, err := piv.New(b)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := openpgpcard.New(b)
	if err != nil {
		t.Fatal(err)
	}
	return map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: pv, handoff.StoreOpenPGPCard: ov}
}

// The seven X.509 cases of a PIV key are decided by the code with the real verifier: each ends as the
// manifest says, with a checker made from the verifiers of the registered set.
func TestTheSevenX509CasesOfAPIVKeyAreDecidedByTheVerifier(t *testing.T) {
	m := readManifest(t)
	roots := rootsOfManifest(t, m)
	ids := []string{
		"x509-piv-valid", "x509-piv-key-mismatch", "x509-piv-pin-never", "x509-piv-old-firmware",
		"x509-piv-untrusted-chain", "x509-no-name-constraints", "x509-name-constraint-outside",
	}
	byID := map[string]vectorCase{}
	for _, c := range m.Cases {
		byID[c.ID] = c
	}
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			t.Fatalf("the manifest holds no case %s", id)
		}
		if _, isPending := pending[id]; isPending {
			t.Errorf("%s is still in the pending map", id)
		}
		t.Run(id, func(t *testing.T) {
			v, err := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), loadCase(t, c))
			if !matches(c, v, err) {
				t.Errorf("the manifest says %s %s, and the verdict is code %q (%s), error %v", c.Expect, c.Reason, v.Code, v.Detail, err)
			}
		})
	}
	// The reasons are the ones the page gives, and not another code that happens to refuse.
	want := map[string]handoff.Code{
		"x509-piv-key-mismatch":        handoff.CodeKeyMismatch,
		"x509-piv-pin-never":           handoff.CodePolicy,
		"x509-piv-old-firmware":        handoff.CodePolicy,
		"x509-piv-untrusted-chain":     handoff.CodeProofInvalid,
		"x509-no-name-constraints":     handoff.CodePolicy,
		"x509-name-constraint-outside": handoff.CodePolicy,
	}
	for id, code := range want {
		c := byID[id]
		v, err := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), loadCase(t, c))
		if err != nil || v.Code != code {
			t.Errorf("%s: code %q, error %v, want %q", id, v.Code, err, code)
		}
	}
	// The untrusted chain stops at check 7: checks 1 to 6 passed, 7 failed, 8 and 9 did not run.
	c := byID["x509-piv-untrusted-chain"]
	v, _ := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), loadCase(t, c))
	if got := statuses(v); got != "ppppppfnn" {
		t.Errorf("statuses %s, want ppppppfnn", got)
	}
}
