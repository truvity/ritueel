//go:build linux || darwin

package history

import (
	"bytes"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// The ceremony member of a record is the name of the folder that holds it. A record that is found
// in another folder is record-invalid, and stays on the chain: it is read, and only its place is
// wrong.

// Before: a renamed folder was clean, with the end line of the untouched history.
func TestRecordInAFolderOfAnotherNameIsInvalid(t *testing.T) {
	b, r := threeRecords(t)
	if err := renameDir(b, "history/"+r[1].folder, "history/x2"); err != nil {
		t.Fatal(err)
	}
	rep := b.run()
	// The transcript, the plan and the copies of the second record are listed under its own
	// folder name, so they are gone from there: the files are findings too.
	has(t, rep, RecordInvalid, "history/x2/record.json")
	if rep.Clean() {
		t.Error("clean")
	}
	// The record is read, so it is on the chain: nothing else is wrong with the chain.
	lacks(t, rep, ChainBroken)
	lacks(t, rep, RecordOffChain)
	lacks(t, rep, Fork)
	if eight, count, ok := rep.End(); !ok || count != 3 || eight != r[2].digest[:8] {
		t.Errorf("End() = %q, %d, %v: the end line of an untouched history", eight, count, ok)
	}
}

func TestRecordThatNamesAnotherCeremonyThanItsFolderIsInvalidAndOnTheChain(t *testing.T) {
	for _, other := range []string{"20269999T000000Z-apply", "x"} {
		t.Run(other, func(t *testing.T) {
			b := newBundle(t)
			b.apply(noSet)
			r := b.apply(noSet, func(r *rec) { r.record.Ceremony = other })
			b.apply(noSet)
			rep := b.run()
			wantFindings(t, rep, []wf{{RecordInvalid, recordPath(r)}})
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}

// What a closing record names as its ceremony is its own folder, and closes.ceremony is another
// thing: the ceremony it closes.
func TestClosingRecordNamesItsOwnFolderAndClosesAnother(t *testing.T) {
	b := newBundle(t)
	b.apply()
	stopped := b.unfinished()
	closing := b.closing(stopped, func(r *rec) {
		for p, data := range stopped.artifacts {
			r.artifacts[p] = data
		}
		r.refresh()
	})
	wantFindings(t, b.run(), nil)
	if closing.record.Ceremony == closing.record.Closes.Ceremony {
		t.Fatal("the closing record closes its own ceremony")
	}
	// Its own ceremony member must be its own folder.
	b2 := newBundle(t)
	b2.apply()
	stopped2 := b2.unfinished()
	c2 := b2.closing(stopped2, func(r *rec) {
		for p, data := range stopped2.artifacts {
			r.artifacts[p] = data
		}
		r.refresh()
		r.record.Ceremony = stopped2.folder
	})
	rep := b2.run()
	has(t, rep, RecordInvalid, recordPath(c2))
}

// The ceremony member of the attempt and of the plan of an open ceremony is its folder, each
// alone: a plan or an attempt that names another ceremony is not the one of this folder.
func TestOpenCeremonyWhoseAttemptOrPlanNamesAnotherCeremonyIsNotLinked(t *testing.T) {
	t.Run("the attempt", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		u := b.unfinished(func(r *rec) { r.attempt.Ceremony = "other" })
		wantFindings(t, b.run(), []wf{{TrustSetUnlisted, setPath(u)}})
	})
	t.Run("the plan", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		u := b.unfinished(func(r *rec) {
			r.plan.Ceremony = "other"
			r.rawPlan = must(r.plan.Canonical())
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		})
		wantFindings(t, b.run(), []wf{{TrustSetUnlisted, setPath(u)}})
	})
}

// The required members. Kept: plan_sha256 and a non-empty wanted for apply, closes.ceremony and
// closes.attempt_sha256 for close. Not required: the time inside confirmation and advisory_review.
func TestRecordMissingAMemberThatCheckHistoryReadsIsInvalid(t *testing.T) {
	drop := map[string]struct {
		build func(b *bundle) *rec
		from  string
	}{
		"plan_sha256 of apply":           {func(b *bundle) *rec { return b.apply(noSet) }, `"plan_sha256":"`},
		"closes.ceremony of close":       {func(b *bundle) *rec { return b.closing(b.unfinished(), noSet) }, `"ceremony":"`},
		"closes.attempt_sha256 of close": {func(b *bundle) *rec { return b.closing(b.unfinished(), noSet) }, `"attempt_sha256":"`},
	}
	for name, c := range drop {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			r := c.build(b)
			rewrite(b, r, func(rec []byte) []byte {
				if c.from == `"plan_sha256":"` {
					return dropMember(t, rec, c.from)
				}
				// A member of closes: cut inside the closes object.
				i := bytes.Index(rec, []byte(`"closes":{`)) + len(`"closes":{`)
				return append(append([]byte{}, rec[:i]...), dropMember(t, rec[i:], c.from)...)
			})
			has(t, b.run(), RecordInvalid, recordPath(r))
		})
	}
	t.Run("wanted that is empty", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply(noSet, func(r *rec) { r.record.Wanted = nil })
		has(t, b.run(), RecordInvalid, recordPath(r))
	})
}

func TestTimeInsideConfirmationAndAdvisoryReviewIsNotRequired(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		r.record.Confirmation = &files.Confirmation{By: "typed"}
		r.record.AdvisoryReview = &files.Advisory{Note: "read them"}
	})
	wantFindings(t, b.run(), nil)
}
