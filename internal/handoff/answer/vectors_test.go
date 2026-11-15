package answer_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
)

// The response cases of the vector set are decided by the requester's checks. The test has the three laws of
// the request side: a pending case that is decided fails the test (so the map shrinks), a case that is not
// pending and is not decided as the manifest says fails it, and every case is run.

const laterSSHList = "the checks of an SSH CA key answer: the SSH CA key list has no reader (issue 55)"

// pendingSSH holds the answers that wait for the reader of the signed SSH CA key list.
var pendingSSH = map[string]string{
	"ssh-piv-valid":               laterSSHList,
	"ssh-kms-valid":               laterSSHList,
	"ssh-software-valid":          laterSSHList,
	"ssh-response-other-root":     laterSSHList,
	"ssh-response-key-not-listed": laterSSHList,
	"ssh-response-wrong-use":      laterSSHList,
	"ssh-response-old-list":       laterSSHList,
}

// codeCheck is the number of the check that gives a code, as the tables of the contract list them: the full
// X.509 table, the OpenPGP table and, with the same numbers as the full one, the floor.
func codeCheck(c vectorResponse) int {
	if c.Type == string(handoff.TypeOpenPGP) {
		return map[string]int{"key-mismatch": 4, "issuer": 5, "profile": 6, "validity": 7}[c.Reason]
	}
	return map[string]int{"issuer": 4, "key-mismatch": 5, "profile": 6, "validity": 7}[c.Reason]
}

// wantStatuses is the string of results that the page gives a case: all passed for an acceptance, and for a
// refusal passed before the check of its code, failed at it and not run after it. On the floor the slots 1, 3,
// 8 and 9 are never run.
func wantStatuses(c vectorResponse) string {
	total := 9
	if c.Type == string(handoff.TypeOpenPGP) {
		total = 8
	}
	out := make([]byte, total)
	for i := 1; i <= total; i++ {
		switch {
		case c.Floor && (i == 1 || i == 3 || i == 8 || i == 9):
			out[i-1] = 'n'
		case c.Expect == "install":
			out[i-1] = 'p'
		case i < codeCheck(c):
			out[i-1] = 'p'
		case i == codeCheck(c):
			out[i-1] = 'f'
		default:
			out[i-1] = 'n'
		}
	}
	return string(out)
}

func TestTheVectorSetHoldsThirtyEightResponsesAndThirtyOneAreDecided(t *testing.T) {
	m := readVectorManifest(t)
	clock, err := time.Parse("2006-01-02T15:04:05Z", m.Clock)
	if err != nil || !clock.Equal(vectorNow) {
		t.Fatalf("the clock of the manifest is %q, the test's is %v", m.Clock, vectorNow)
	}
	if m.Pinned.TrustSequence != 7 {
		t.Fatalf("the manifest pins trust sequence %d", m.Pinned.TrustSequence)
	}
	held, _ := vectorHeld(t)
	if held.List.Sequence != m.Pinned.TrustSequence {
		t.Fatalf("the held list is sequence %d, the manifest pins %d", held.List.Sequence, m.Pinned.TrustSequence)
	}
	pending, decided := 0, 0
	byType := map[string]int{}
	ids := map[string]bool{}
	for _, c := range m.Responses {
		byType[c.Type]++
		ids[c.ID] = true
		if _, ok := pendingSSH[c.ID]; ok {
			pending++
		} else {
			decided++
		}
	}
	if len(m.Responses) != 38 || decided != 31 || pending != 7 {
		t.Errorf("responses %d, decided %d, pending %d; want 38, 31 and 7", len(m.Responses), decided, pending)
	}
	if byType["x509-intermediate"] != 20 || byType["openpgp-subkey"] != 11 || byType["ssh-ca-key"] != 7 {
		t.Errorf("by type %v; want 20 X.509, 11 OpenPGP and 7 SSH", byType)
	}
	for id := range pendingSSH {
		if !ids[id] {
			t.Errorf("the pending map names %s, which the manifest does not hold", id)
		}
	}
}

// The pinned trust of the vectors is the two roots A and B and their primaries, as the page says.
func TestThePinnedTrustOfTheVectorsIsRootsAAndB(t *testing.T) {
	m := readVectorManifest(t)
	held, _ := vectorHeld(t)
	if got := held.List.Pins(); !slices.Equal(got, []string{
		"f4a1d27aa6079ab8a786f3c9bf96b179361a55ef84e88c7ec5e17335570b5114",
		"5924152b774f652e5eaa0bb2a8eeef527364d1c23ce5d82c48f46e02eaff5d4c",
	}) {
		t.Errorf("the held list has the pins %v", got)
	}
	prim := vectorPrimaries(t, m)
	wantFP := []string{"6df387de63525c9dc0ec1174bd138d2c4889b79b", "c4288657012230588b51fa66e0831b9c6e084f39"}
	for i, p := range prim {
		if p.Fingerprint != wantFP[i] {
			t.Errorf("primary %d has the fingerprint %s, want %s", i, p.Fingerprint, wantFP[i])
		}
		if !p.Created.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("primary %d was created %v", i, p.Created)
		}
		if held.List.Roots[i].OpenPGPFingerprint != p.Fingerprint {
			t.Errorf("root %d of the list names %s, the primary file gives %s", i, held.List.Roots[i].OpenPGPFingerprint, p.Fingerprint)
		}
	}
}

func TestEveryResponseVectorIsDecidedAsTheManifestSaysOrIsPending(t *testing.T) {
	m := readVectorManifest(t)
	full := mustChecker(t, vectorConfig(t, m))
	floor := mustChecker(t, vectorFloorConfig(t, m))
	ran := 0
	for _, c := range m.Responses {
		t.Run(c.ID, func(t *testing.T) {
			ran++
			a, ans := vectorAsked(t, c), vectorAnswer(t, c)
			chk := full
			if c.Floor {
				chk = floor
			}
			v, err := chk.Check(a, ans)
			if reason, pending := pendingSSH[c.ID]; pending {
				if !errors.Is(err, answer.ErrTypeNotBuilt) {
					t.Fatalf("the case is pending (%s) and Check returned %v with the verdict %q: it is decided now, so take it out of the map", reason, err, v.Code)
				}
				if v.Accepted() || v.AnswerRefused() {
					t.Fatal("an error comes with a verdict that is accepted or refused")
				}
				return
			}
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			switch c.Expect {
			case "install":
				if !v.Accepted() || v.Code != "" || v.Info == nil {
					t.Fatalf("the manifest says install; code %q, detail %q, statuses %s", v.Code, v.Detail, statuses(v))
				}
			case "refuse":
				if v.Accepted() || !v.AnswerRefused() || string(v.Code) != c.Reason {
					t.Fatalf("the manifest says refuse with %s; accepted %v, code %q, detail %q", c.Reason, v.Accepted(), v.Code, v.Detail)
				}
				if v.Info != nil {
					t.Error("a refused verdict holds Info")
				}
			default:
				t.Fatalf("the manifest says %q", c.Expect)
			}
			if got, want := statuses(v), wantStatuses(c); got != want {
				t.Errorf("statuses %s, the page gives %s (detail %q)", got, want, v.Detail)
			}
			if v.Floor() != c.Floor {
				t.Errorf("Floor() = %v for a case with floor = %v", v.Floor(), c.Floor)
			}
		})
	}
	if ran != len(m.Responses) || ran != 38 {
		t.Errorf("ran %d cases of %d", ran, len(m.Responses))
	}
}

func TestTheInstalledVectorsGiveTheInfoThatTheirFilesSay(t *testing.T) {
	m := readVectorManifest(t)
	full := mustChecker(t, vectorConfig(t, m))
	seen := 0
	for _, c := range m.Responses {
		if c.Expect != "install" || c.Floor || c.Type == "ssh-ca-key" {
			continue
		}
		seen++
		v, err := full.Check(vectorAsked(t, c), vectorAnswer(t, c))
		if err != nil || !v.Accepted() {
			t.Fatalf("%s: %v, accepted %v", c.ID, err, v.Accepted())
		}
		in := v.Info
		if in.Type != handoff.Type(c.Type) || in.Stem != c.ID || in.TrustSequence != 7 {
			t.Errorf("%s: Info %+v", c.ID, *in)
		}
		if !in.ValidFrom.Equal(vectorNow) || !in.ValidUntil.Equal(time.Date(2027, 12, 15, 12, 0, 0, 0, time.UTC)) {
			t.Errorf("%s: valid %v to %v", c.ID, in.ValidFrom, in.ValidUntil)
		}
		wantIssuer := "f4a1d27aa6079ab8a786f3c9bf96b179361a55ef84e88c7ec5e17335570b5114"
		switch {
		case c.Type == "openpgp-subkey" && c.ID == "pgp-response-other-primary":
			wantIssuer = "c4288657012230588b51fa66e0831b9c6e084f39"
		case c.Type == "openpgp-subkey":
			wantIssuer = "6df387de63525c9dc0ec1174bd138d2c4889b79b"
		case c.ID == "x509-response-other-root":
			wantIssuer = "5924152b774f652e5eaa0bb2a8eeef527364d1c23ce5d82c48f46e02eaff5d4c"
		}
		if in.Issuer != wantIssuer {
			t.Errorf("%s: issuer %s, want %s", c.ID, in.Issuer, wantIssuer)
		}
		if len(v.Warnings) != 0 {
			t.Errorf("%s: warnings %v with a list that has not expired", c.ID, v.Warnings)
		}
	}
	if seen != 12 {
		t.Errorf("%d accepted full-contract cases, want 12 (6 X.509 and 6 OpenPGP)", seen)
	}
}

func TestTheFloorVectorGivesNoTrustSequenceAndTheFourFixedReasons(t *testing.T) {
	m := readVectorManifest(t)
	c := vectorCase(t, "x509-floor-valid")
	v, err := mustChecker(t, vectorFloorConfig(t, m)).Check(vectorAsked(t, c), vectorAnswer(t, c))
	if err != nil || !v.Accepted() || !v.Floor() {
		t.Fatalf("%v, accepted %v, floor %v", err, v.Accepted(), v.Floor())
	}
	if v.Info.TrustSequence != 0 || len(v.Warnings) != 0 {
		t.Errorf("trust sequence %d, warnings %v on the floor", v.Info.TrustSequence, v.Warnings)
	}
	if got := statuses(v); got != "npnppppnn" {
		t.Fatalf("statuses %s", got)
	}
	want := map[int]string{
		1: "the floor has no result file",
		3: "the floor has no result file",
		8: "the floor does not ask a foreign CA for the form of ritueel's certificates",
		9: "the floor has no result file",
	}
	for _, ck := range v.Checks {
		if w, fixed := want[ck.N]; fixed {
			if ck.Reason != w || ck.Status != handoff.StatusNotRun {
				t.Errorf("slot %d: %s %q, want not-run %q", ck.N, ck.Status, ck.Reason, w)
			}
		} else if ck.Reason != "" || ck.Status != handoff.StatusPassed {
			t.Errorf("slot %d: %s %q", ck.N, ck.Status, ck.Reason)
		}
	}
}
