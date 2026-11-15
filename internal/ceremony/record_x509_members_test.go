package ceremony_test

import (
	"encoding/json"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
)

// The record of a ceremony of an X.509 key only has the members that it had before keys of two kinds
// were built, and no list of revocations unless the caller gives one: the page says the member is
// there for "a ceremony that made revocation material".
func TestTheRecordOfAnX509OnlyCeremonyHasTheMembersOfBeforeAndNoRevocations(t *testing.T) {
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("")
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(fl.out, &doc); err != nil {
		t.Fatal(err)
	}
	var got []string
	for k := range doc {
		got = append(got, k)
	}
	slices.Sort(got)
	want := []string{
		"applied", "arguments", "artifacts", "attempt_sha256", "births_sha256", "ceremony", "command", "confirmation",
		"finished_at", "left_out", "limit_shown", "outcome", "plan_sha256", "ran_on", "root", "root_reason",
		"signatures", "signatures_sha256", "started_at", "transcript_sha256", "trust_sequence", "version", "wanted",
	}
	if !slices.Equal(got, want) {
		t.Errorf("the members of the record are\n%v\nwant\n%v", got, want)
	}
	if rep := b.check(); !rep.Clean() {
		t.Errorf("findings %+v", rep.Findings)
	}
}

// The same ceremony with a removal entry for its key: the member is there, as the page says.
func TestTheRecordOfAnX509OnlyCeremonyTakesTheRemovalEntryAndNothingElse(t *testing.T) {
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.in = func(in *ceremony.RecordIn) {
		in.Revocations = []files.RevocationEntry{{Label: "A", Reason: "root-removal", SHA256: rep('c')}}
	}
	fl.must("artifacts")
	// The flow's root.json is a stub without the digest: the list is judged against root.json, so a
	// root.json that holds no removal_sha256 refuses it.
	if err := fl.run(""); err == nil {
		t.Fatal("a removal entry was taken over a root.json that holds no digest")
	}
}
