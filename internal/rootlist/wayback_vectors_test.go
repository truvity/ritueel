package rootlist_test

import (
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// wayBackClock is the clock of a case of the way back unless the case gives another: after the lists
// are signed (2026-11-15) and before any of them expires.
const wayBackClock = "2026-12-01T12:00:00Z"

// wayBackCases are the cases of the way back that the vector set must hold, by id, with what each
// has: the held list ("" for initial pins), the candidate, the clock ("" for wayBackClock), the
// lowest sequence of a host with pins (0 for none), and the answer. They are the list of the page
// (docs/reference/root-list.md, "Test vectors") written out here, so that a case that is dropped from
// the manifest, or one whose answer is changed, fails a test. TestManifestCases runs every case of
// the manifest against the code; this table holds the manifest to the page.
var wayBackCases = []struct {
	id, held, candidate, clock string
	minSequence                int64
	accept                     bool
	reason                     rootlist.Reason
	wayback                    bool
}{
	{id: "way-back-from-the-highest-sequence", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a", accept: true, wayback: true},
	{id: "way-back-at-the-sequence-of-the-thief", held: "seq8-ab-by-a", candidate: "seq8-b-without-a", accept: true, wayback: true},
	{id: "way-back-with-a-signature-missing", held: "seqmax-abc-by-a", candidate: "seq8-bc-without-a-by-b", reason: rootlist.InsufficientSigners},
	{id: "way-back-with-another-keys-authorisation", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a-wrong-removal", reason: rootlist.RemovalInvalid},
	{id: "no-entry-is-not-the-way-back", held: "seqmax-ab-by-a", candidate: "seq8-ab-without-a", reason: rootlist.Rollback},
	{id: "lower-sequence-removes-nothing", held: "seqmax-ab-by-a", candidate: "seq7-a", reason: rootlist.Rollback},
	{id: "way-back-after-its-expiry", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a", clock: "2028-01-02T12:00:00Z", reason: rootlist.Expired},
	{id: "way-back-signed-after-the-clock", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a", clock: "2026-11-30T12:00:00Z", reason: rootlist.Malformed},
	{id: "old-list-as-published", held: "h4-bcz", candidate: "h2-abc", reason: rootlist.Rollback},
	{id: "old-list-with-the-signature-of-a-later-key", held: "h4-bcz", candidate: "h2-abc-with-z", reason: rootlist.Rollback},
	{id: "old-list-that-removes-a-later-key", held: "h3-bc", candidate: "h2-b-without-a", reason: rootlist.Rollback},
	{id: "pins-keep-their-lowest-sequence", candidate: "h3-bc", minSequence: 4, reason: rootlist.Rollback},
	{id: "pins-keep-their-lowest-sequence-for-a-named-removal", candidate: "seq8-b-without-a", minSequence: 9, reason: rootlist.Rollback},
	{id: "one-key-and-one-authorisation-by-design", held: "seq5-ab", candidate: "seq1-az-without-b", accept: true, wayback: true},
	{id: "the-same-takeover-at-the-next-sequence", held: "seq5-ab", candidate: "seq6-az-without-b", accept: true},
	{id: "retire-with-the-authorisation", held: "seqmax-abc-by-a", candidate: "seq8-ac-without-b-named", accept: true, wayback: true},
	{id: "two-removed-one-named", held: "seqmax-abc-by-a", candidate: "seq8-c-without-ab-a-named", reason: rootlist.Rollback},
	{id: "two-removed-both-named", held: "seqmax-abc-by-a", candidate: "seq8-c-without-ab-named", accept: true, wayback: true},
	{id: "extra-entry-for-a-key-not-held", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a-and-c-named", reason: rootlist.RemovalInvalid},
	{id: "entry-for-a-key-that-stays", held: "seqmax-abc-by-a", candidate: "seq8-bc-with-b-named", reason: rootlist.RemovalInvalid},
	{id: "removal-list-signed-only-by-a-new-key", held: "seqmax-ab-by-a", candidate: "seq8-z-without-ab", reason: rootlist.UnknownSigner},
	{id: "way-back-over-an-expired-held-list", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a", clock: "2027-12-20T12:00:00Z", accept: true, wayback: true},
	{id: "way-back-chain-lowers-the-sequence-step-1", held: "h3-bc", candidate: "seq1-b-without-c", accept: true, wayback: true},
	{id: "way-back-chain-lowers-the-sequence-step-2", held: "seq1-b-without-c", candidate: "h2-abc", accept: true},
	{id: "way-back-with-a-new-label", held: "seqmax-abc-by-a", candidate: "seq8-bc-new-label-without-a", accept: true, wayback: true},
	{id: "way-back-entry-with-another-label", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a-entry-labelled-d", accept: true, wayback: true},
	{id: "way-back-list-changed-after-signing", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a-changed-after-signing", reason: rootlist.SignatureInvalid},
	{id: "way-back-with-a-new-label-the-kept-key-not-signing", held: "seqmax-abc-by-a", candidate: "seq8-bc-new-label-without-a-by-c", reason: rootlist.InsufficientSigners},
	{id: "revoke-signed-by-the-key-with-its-entry", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a-signed-by-a-and-named", accept: true, wayback: true},
	{id: "way-back-that-also-adds-a-key", held: "seqmax-ab-by-a", candidate: "seq8-bc-without-a-adds-c", accept: true, wayback: true},
	{id: "old-revoke-list-after-its-key-came-back", held: "seq5-ac", candidate: "seq3-bc-revoke-a", accept: true, wayback: true},
	{id: "lower-sequence-with-a-new-label-removes-nothing", held: "seqmax-ab-by-a", candidate: "seq8-ab-new-label", reason: rootlist.Rollback},
	{id: "way-back-with-a-new-fingerprint", held: "seqmax-abc-by-a", candidate: "seq8-bc-new-fingerprint-without-a", accept: true, wayback: true},
	{id: "way-back-removing-every-held-key", held: "seqmax-ab-by-a", candidate: "seq8-z-without-ab-by-a-and-z", accept: true, wayback: true},
	{id: "way-back-with-a-second-signer-on-no-list", held: "seqmax-ab-by-a", candidate: "seq8-b-without-a-signed-by-b-and-z", reason: rootlist.UnknownSigner},
}

func TestTheVectorSetHoldsEveryWayBackCaseOfThePage(t *testing.T) {
	m := loadManifest(t)
	byID := map[string]manifestCase{}
	for _, c := range m.Cases {
		byID[c.ID] = c
	}
	for _, want := range wayBackCases {
		t.Run(want.id, func(t *testing.T) {
			c, ok := byID[want.id]
			if !ok {
				t.Fatalf("the case is not in the manifest")
			}
			if (c.Held == nil) != (want.held == "") || (c.Held != nil && *c.Held != want.held) {
				t.Errorf("the held list is %v, the page says %q", c.Held, want.held)
			}
			if c.Candidate == nil || *c.Candidate != want.candidate {
				t.Errorf("the candidate is %v, the page says %q", c.Candidate, want.candidate)
			}
			wantClock := want.clock
			if wantClock == "" {
				wantClock = wayBackClock
			}
			if c.Clock != wantClock {
				t.Errorf("the clock is %q, the page says %q", c.Clock, wantClock)
			}
			if (c.MinSequence == nil) != (want.minSequence == 0) || (c.MinSequence != nil && *c.MinSequence != want.minSequence) {
				t.Errorf("the lowest sequence is %v, the page says %d", c.MinSequence, want.minSequence)
			}
			if want.accept {
				if c.Expect != "accept" || c.Reason != "" {
					t.Errorf("the case expects %q %q, the page says accept", c.Expect, c.Reason)
				}
			} else if c.Expect != "refuse" || c.Reason != string(want.reason) {
				t.Errorf("the case expects %q %q, the page says refuse %q", c.Expect, c.Reason, want.reason)
			}
			if c.Wayback != want.wayback {
				t.Errorf("wayback is %v, the page says %v", c.Wayback, want.wayback)
			}
		})
	}
	// The case that is signed after its clock says so, and no other case of the way back has a flaw.
	for _, c := range m.Cases {
		if c.Flaw != "" && c.ID != "way-back-signed-after-the-clock" {
			t.Errorf("the case %s has the flaw %q", c.ID, c.Flaw)
		}
	}
	if c := byID["way-back-signed-after-the-clock"]; c.Flaw != "signed_at-after-clock" {
		t.Errorf("way-back-signed-after-the-clock has the flaw %q", c.Flaw)
	}
}

func TestTheWayBackCasesOfTheVectorSetAreNotMoreThanThePageNames(t *testing.T) {
	// A case with wayback is one the page names: a case added to the manifest with wayback and
	// not on the page is a case that the page does not describe. No case of main changes: none of
	// them is a way back.
	m := loadManifest(t)
	named := map[string]bool{}
	for _, c := range wayBackCases {
		named[c.id] = true
	}
	for _, c := range m.Cases {
		if c.Wayback && !named[c.ID] {
			t.Errorf("the case %s has wayback and is not a way-back case of the page", c.ID)
		}
	}
}
