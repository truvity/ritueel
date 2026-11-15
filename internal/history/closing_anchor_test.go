//go:build linux || darwin

package history

import (
	"errors"
	"io/fs"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// A closing record that lists the files of the trust set that a stopped ceremony left: the ceremony
// that wrote the list is the closed one, so the anchor of the list is the end that the plan of that
// ceremony names, and not the record before the closing record. The plan is found through the
// attempt that the closing record names. When it cannot be found, the anchor is not accepted.

func listsLeftover(stopped *rec, root []byte) func(*rec) {
	return func(r *rec) {
		for p, data := range stopped.artifacts {
			r.artifacts[p] = data
		}
		if root != nil {
			r.artifacts["trust/"+stopped.set+"/root-list.json"] = root
		}
		r.refresh()
	}
}

func rootListPath(r *rec) string { return "trust/" + r.set + "/root-list.json" }

// A ceremony stops, another one runs, and then close lists the leftover set. That is the honest
// sequence, and before the rule it was refused: the list names the end at the plan, and the closing
// record's predecessor is the end now.
func TestHonestClosingOfAStoppedCeremonyAfterAnotherCeremonyRanIsClean(t *testing.T) {
	for _, between := range []int{0, 1, 3} {
		t.Run(string(rune('0'+between))+" ceremonies in between", func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			stopped := b.unfinished()
			for i := 0; i < between; i++ {
				b.apply(noSet)
			}
			closing := b.closing(stopped, listsLeftover(stopped, nil))
			rep := b.run()
			wantFindings(t, rep, nil)
			if rep.Records != 2+between {
				t.Errorf("Records = %d, want %d", rep.Records, 2+between)
			}
			if between > 0 && closing.record.PrevRecordSHA256 == stopped.plan.LastRecordSHA256 {
				t.Fatal("the closing record follows the end of the plan: nothing ran in between")
			}
		})
	}
}

func TestFirstCeremonyThatStoppedAndWasClosedIsCleanWithAListThatHasNoAnchor(t *testing.T) {
	b := newBundle(t)
	stopped := b.unfinished()
	b.closing(stopped, listsLeftover(stopped, nil))
	wantFindings(t, b.run(), nil)
}

func TestClosingRecordThatListsALeftoverSetWithAnotherAnchorIsAnchorUnknown(t *testing.T) {
	// Each case: the list of the leftover set that the closing record lists.
	cases := map[string]func(b *bundle, stopped *rec, between *rec) []byte{
		"the predecessor of the closing record": func(b *bundle, stopped, between *rec) []byte { return rootListBytes(stopped.set, between.digest) },
		"a digest of no record":                 func(_ *bundle, stopped, _ *rec) []byte { return rootListBytes(stopped.set, digestB) },
		"no anchor, where the plan names one":   func(_ *bundle, stopped, _ *rec) []byte { return rootListBytes(stopped.set, "") },
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply()
			stopped := b.unfinished()
			between := b.apply(noSet)
			b.closing(stopped, listsLeftover(stopped, list(b, stopped, between)))
			rep := b.run()
			has(t, rep, AnchorUnknown, rootListPath(stopped))
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
	t.Run("an anchor, where the closed ceremony's plan names none", func(t *testing.T) {
		b := newBundle(t)
		stopped := b.unfinished() // the first ceremony: its plan names no end
		b.closing(stopped, listsLeftover(stopped, rootListBytes(stopped.set, digestA)))
		rep := b.run()
		has(t, rep, AnchorUnknown, rootListPath(stopped))
	})
}

// When the plan of the closed ceremony cannot be found or read, the anchor is not accepted: there is
// nothing to compare it with.
func TestClosingRecordThatListsALeftoverSetWhosePlanCannotBeFoundIsAnchorUnknown(t *testing.T) {
	build := func(t *testing.T, mut func(r *rec)) (*bundle, *rec) {
		b := newBundle(t)
		b.apply()
		var opts []func(*rec)
		if mut != nil {
			opts = append(opts, mut)
		}
		stopped := b.unfinished(opts...)
		b.apply(noSet)
		b.closing(stopped, listsLeftover(stopped, nil))
		return b, stopped
	}
	t.Run("the plan is removed", func(t *testing.T) {
		b, s := build(t, nil)
		b.remove(ceremonyPath(s, "plan.json"))
		has(t, b.run(), AnchorUnknown, rootListPath(s))
	})
	t.Run("the plan is another file", func(t *testing.T) {
		b, s := build(t, nil)
		b.put(ceremonyPath(s, "plan.json"), []byte("{}"))
		has(t, b.run(), AnchorUnknown, rootListPath(s))
	})
	t.Run("the plan cannot be read as a plan", func(t *testing.T) {
		b, s := build(t, func(r *rec) {
			r.rawPlan = []byte("not json")
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		})
		has(t, b.run(), AnchorUnknown, rootListPath(s))
	})
	t.Run("the plan is of another ceremony", func(t *testing.T) {
		b, s := build(t, func(r *rec) {
			r.plan.Ceremony = "other"
			r.rawPlan = must(r.plan.Canonical())
			r.attempt.PlanSHA256 = files.Digest(r.rawPlan)
		})
		has(t, b.run(), AnchorUnknown, rootListPath(s))
	})
	t.Run("the attempt names another plan", func(t *testing.T) {
		b, s := build(t, func(r *rec) { r.attempt.PlanSHA256 = digestA })
		has(t, b.run(), AnchorUnknown, rootListPath(s))
	})
	t.Run("the attempt is not the one the closing record names", func(t *testing.T) {
		b, s := build(t, nil)
		other := s.attempt
		other.Root = "another-root"
		b.put(ceremonyPath(s, "attempt.json"), must(other.Canonical()))
		rep := b.run()
		has(t, rep, AnchorUnknown, rootListPath(s))
		has(t, rep, FileDigest, ceremonyPath(s, "attempt.json"))
	})
	t.Run("the attempt is removed", func(t *testing.T) {
		b, s := build(t, nil)
		b.remove(ceremonyPath(s, "attempt.json"))
		rep := b.run()
		has(t, rep, AnchorUnknown, rootListPath(s))
		has(t, rep, FileMissing, ceremonyPath(s, "attempt.json"))
	})
	t.Run("the attempt cannot be read", func(t *testing.T) {
		b, s := build(t, func(r *rec) { r.rawAttempt = []byte("not json") })
		has(t, b.run(), AnchorUnknown, rootListPath(s))
	})
	t.Run("the attempt is of another ceremony", func(t *testing.T) {
		b, s := build(t, func(r *rec) { r.attempt.Ceremony = "other" })
		has(t, b.run(), AnchorUnknown, rootListPath(s))
	})
}

// A set listed by a closing record and by an ordinary record: the two do not say the same about the
// ceremony that wrote it.
func TestSetListedByAClosingRecordAndByAnOrdinaryRecordIsAnchorUnknown(t *testing.T) {
	b := newBundle(t)
	b.apply()
	stopped := b.unfinished()
	b.closing(stopped, listsLeftover(stopped, nil))
	b.apply(func(r *rec) {
		p := "trust/" + stopped.set + "/keys.txt"
		r.artifacts[p] = stopped.artifacts[p]
		r.refresh()
	})
	has(t, b.run(), AnchorUnknown, rootListPath(stopped))
}

// A ceremony that a closing record closes cannot be an open attempt, even when its plan names the
// end: the closing record is the end then, and a plan made before it cannot name it.
func TestClosedCeremonyIsNotLinkedAsAnOpenAttempt(t *testing.T) {
	b := newBundle(t)
	b.apply()
	stopped := b.unfinished()
	b.closing(stopped) // lists nothing
	rep := b.run()
	wantFindings(t, rep, []wf{{TrustSetUnlisted, setPath(stopped)}})
	lacks(t, rep, UnfinishedCeremony)
}

// A plan of the closed ceremony that cannot be read from the disk stops the check: it is not a plan
// that is not there.
func TestPlanOfAClosedCeremonyThatCannotBeReadStopsTheCheck(t *testing.T) {
	b := newBundle(t)
	b.apply()
	stopped := b.unfinished()
	b.apply(noSet)
	b.closing(stopped, listsLeftover(stopped, nil))
	m := loadMem(t, b.dir)
	m.get(ceremonyPath(stopped, "plan.json")).readErr = fs.ErrPermission
	rep, err := runMem(t, m)
	if !errors.Is(err, fs.ErrPermission) || rep != nil {
		t.Errorf("Check = %v, %v; want a refused permission", rep, err)
	}
}

// A closed ceremony's plan is read once, however many of its sets a closing record lists.
func TestPlanOfAClosedCeremonyIsReadOnceForSeveralSets(t *testing.T) {
	b := newBundle(t)
	b.apply()
	stopped := b.unfinished()
	b.closing(stopped, func(r *rec) {
		listsLeftover(stopped, nil)(r)
		// A second set that the closing record lists, with the same anchor as the first.
		for p, data := range stopped.artifacts {
			r.artifacts["trust/"+stopped.set+"-copy/"+p[len("trust/"+stopped.set+"/"):]] = data
		}
		r.refresh()
	})
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	if n := log.reads[ceremonyPath(stopped, "plan.json")]; n != 1 {
		t.Errorf("the plan of the closed ceremony was read %d times, want once", n)
	}
}

// The first ceremony stopped, its plan names no end because the history was empty; another ceremony
// ran, and then close lists the leftover set. The honest list has no anchor. A list that anchors a
// record of the chain cannot be honest: no record came before the ceremony that wrote it. Before, it
// was accepted (clean, with the closing record's own end).
func TestLeftoverSetOfAFirstCeremonyThatStoppedAnchorsNothing(t *testing.T) {
	build := func(t *testing.T, anchor func(stopped, between *rec) []byte) (*bundle, *rec) {
		b := newBundle(t)
		stopped := b.unfinished() // the first: its plan names no end
		between := b.apply(noSet)
		b.closing(stopped, listsLeftover(stopped, anchor(stopped, between)))
		return b, stopped
	}
	t.Run("honest: no anchor", func(t *testing.T) {
		b, _ := build(t, func(_, _ *rec) []byte { return nil })
		wantFindings(t, b.run(), nil)
	})
	t.Run("an anchor on a record of the chain", func(t *testing.T) {
		b, stopped := build(t, func(stopped, between *rec) []byte { return rootListBytes(stopped.set, between.digest) })
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, rootListPath(stopped)}})
	})
	t.Run("an anchor on no record", func(t *testing.T) {
		b, stopped := build(t, func(stopped, _ *rec) []byte { return rootListBytes(stopped.set, digestA) })
		has(t, b.run(), AnchorUnknown, rootListPath(stopped))
	})
}
