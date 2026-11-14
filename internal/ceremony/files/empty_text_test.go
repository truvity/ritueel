package files_test

import (
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// An empty text is not "absent". A Go string cannot tell the two apart and the members are written
// with omitempty, so without a check "prev_record_sha256":"" would read as no predecessor: a file
// that ritueel never writes, and that a reader must not take for the first record.

func TestEmptyTextForAnOptionalMemberOfARecordIsRefused(t *testing.T) {
	cases := []struct {
		member string
		edit   func(map[string]any)
		doc    func() map[string]any
	}{
		{"prev_record_sha256", set("prev_record_sha256", ""), applyDoc},
		{"plan_sha256", set("plan_sha256", ""), applyDoc},
		{"started_at", set("started_at", ""), applyDoc},
		{"finished_at", set("finished_at", ""), applyDoc},
		{"root_reason", set("root_reason", ""), applyDoc},
		{"ran_on", set("ran_on", ""), applyDoc},
		{"confirmation.at", set("confirmation", map[string]any{"by": "typed", "at": ""}), applyDoc},
		{"advisory_review.at", set("advisory_review", map[string]any{"at": "", "note": "x"}), applyDoc},
		// In a closing record the members that it must not have are refused as they were, and an
		// empty one is refused at least as hard.
		{"plan_sha256", set("plan_sha256", ""), closeDoc},
		{"root_reason", set("root_reason", ""), closeDoc},
		{"prev_record_sha256", set("prev_record_sha256", ""), closeDoc},
	}
	for _, c := range cases {
		t.Run(c.member, func(t *testing.T) {
			r, err := files.ReadRecord(encode(t, c.doc(), c.edit))
			if err == nil {
				t.Fatalf("accepted: %+v", r)
			}
			var fe *files.FormatError
			if !errors.As(err, &fe) || fe.Member != c.member || !printableASCII(err.Error()) {
				t.Errorf("err = %v, want a *FormatError for %s", err, c.member)
			}
		})
	}
}

func TestEmptyTextForAnOptionalMemberOfAPlanOrAnAttemptIsRefused(t *testing.T) {
	for _, member := range []string{"made_at", "ceremony_time", "last_record_sha256", "root_reason"} {
		t.Run("plan "+member, func(t *testing.T) {
			_, err := files.ReadPlan(encode(t, planDoc(), set(member, "")))
			var fe *files.FormatError
			if !errors.As(err, &fe) || fe.Member != member {
				t.Errorf("err = %v, want a *FormatError for %s", err, member)
			}
		})
	}
	for _, member := range []string{"root", "started_at"} {
		t.Run("attempt "+member, func(t *testing.T) {
			_, err := files.ReadAttempt(encode(t, attemptDoc(), set(member, "")))
			var fe *files.FormatError
			if !errors.As(err, &fe) || fe.Member != member {
				t.Errorf("err = %v, want a *FormatError for %s", err, member)
			}
		})
	}
}

// A member that is left out reads as it did; one that has a value is read.
func TestOptionalMembersLeftOutOrGivenAValueAreRead(t *testing.T) {
	if _, err := files.ReadRecord(encode(t, applyDoc(), without("prev_record_sha256"))); err != nil {
		t.Errorf("no predecessor: %v", err)
	}
	m := applyDoc()
	m["ran_on"] = "workstation"
	m["root_reason"] = "the card was lost"
	m["started_at"] = "2026-11-14T10:00:00Z"
	if _, err := files.ReadRecord(encode(t, m, nil)); err != nil {
		t.Errorf("members with a value: %v", err)
	}
	if _, err := files.ReadPlan(encode(t, planDoc(), without("last_record_sha256"))); err != nil {
		t.Errorf("a plan with no end: %v", err)
	}
	if _, err := files.ReadAttempt(encode(t, attemptDoc(), without("root", "started_at"))); err != nil {
		t.Errorf("an attempt with the three members: %v", err)
	}
}

// A member that is required and empty stays a fault of that member (not the empty-text fault), as
// before.
func TestRequiredMembersThatAreEmptyAreStillRequired(t *testing.T) {
	_, err := files.ReadRecord(encode(t, applyDoc(), set("transcript_sha256", "")))
	wantMember(t, err, "transcript_sha256")
	_, err = files.ReadAttempt(encode(t, attemptDoc(), set("plan_sha256", "")))
	wantMember(t, err, "plan_sha256")
}
