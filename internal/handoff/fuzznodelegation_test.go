package handoff_test

import (
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// FuzzCheckWithNoDelegation runs the checker that has no delegation on the request files of the vectors and
// their mutations. Whatever the bytes, the verdict keeps the laws of every verdict, and a request is never
// accepted: with no delegation the two rules that need one are not run, and a verdict that holds a check that did
// not run is no acceptance. When check 9 is not run, it names the two rules and no check before it failed.
func FuzzCheckWithNoDelegation(f *testing.F) {
	for _, s := range seedRequests(f) {
		f.Add(s[0], s[1], s[2], s[3])
	}
	m := readManifest(f)
	cfg := configOfCase(f, m, vectorCase{ID: "fuzz", Type: "x509-intermediate", Config: "development"}, rootsOfManifest(f, m), testNow)
	cfg.Delegation = nil
	v := fuzzVerifier{}
	cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: v, handoff.StoreKMS: v, handoff.StoreOpenPGPCard: v}
	chk := mustNew(f, cfg)
	f.Fuzz(func(t *testing.T, proof, csr, subkey, ssh []byte) {
		r := requestOf(proof, csr, subkey, ssh)
		verdict, err := chk.Check(t.Context(), r)
		checkVerdictLaws(t, r, verdict, err)
		if verdict.Accepted() {
			t.Fatalf("a request is accepted with no delegation: %s", statuses(verdict))
		}
		if last := verdict.Checks[8]; last.Status == handoff.StatusNotRun && len(last.NotRun) != 0 {
			if statuses(verdict) != "pppppppp"+"n" || last.NotRun[0] != "delegation-type" || last.NotRun[1] != "name-constraints" || len(last.NotRun) != 2 {
				t.Fatalf("check 9 names %v as not run, with the statuses %s", last.NotRun, statuses(verdict))
			}
			if err != nil || verdict.Refused() || verdict.Complete() {
				t.Fatalf("a verdict with rules not run: error %v, refused %v, complete %v", err, verdict.Refused(), verdict.Complete())
			}
		}
	})
}
