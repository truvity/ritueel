//go:build linux || darwin

package history

import (
	"fmt"
	"runtime"
	"testing"
)

// A root list with no anchor in a trust set that nothing explains (no record lists it, no open
// ceremony of this history wrote it): the set is unlisted already. A list without an anchor is right
// in the first list only, so it is a second finding, except in the set with the lowest trust number,
// which can be the first (its record was removed, or its ceremony did not finish), and for which the
// first finding says it all. The rule makes two results agree (a planted set has both findings, the first set after its
// folder was removed has one); it is held here, in one place.

func TestUnexplainedSetWithTheLowestNumberAndNoAnchorHasOneFinding(t *testing.T) {
	t.Run("the folder of the first record removed", func(t *testing.T) {
		b, r := threeRecords(t)
		b.remove("history/" + r[0].folder)
		rep := b.run()
		has(t, rep, TrustSetUnlisted, setPath(r[0]))
		lacks(t, rep, UnfinishedCeremony)
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown && f.Path == "trust/"+r[0].set+"/root-list.json" {
				t.Errorf("a second finding for the first set: %s", f.Line())
			}
		}
	})
	t.Run("the only set of a history of no record", func(t *testing.T) {
		b := newBundle(t)
		b.apply(func(r *rec) { r.noRecord = true })
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, "trust/1-3fa9c1d3"}})
	})
}

func TestUnexplainedSetThatIsNotTheLowestAndHasNoAnchorHasTwoFindings(t *testing.T) {
	t.Run("a planted set after three", func(t *testing.T) {
		b, _ := threeRecords(t)
		b.put("trust/4-3fa9c1d6/root-list.json", rootListBytes(""))
		rep := b.run()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/4-3fa9c1d6"}, {AnchorUnknown, "trust/4-3fa9c1d6/root-list.json"}})
	})
	t.Run("a set with no number among sets with numbers", func(t *testing.T) {
		b, _ := threeRecords(t)
		b.put("trust/x-3fa9c1d6/root-list.json", rootListBytes(""))
		rep := b.run()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/x-3fa9c1d6"}, {AnchorUnknown, "trust/x-3fa9c1d6/root-list.json"}})
	})
	t.Run("the second of two unexplained sets", func(t *testing.T) {
		b := newBundle(t)
		b.put("trust/1-aaaaaaaa/root-list.json", rootListBytes(""))
		b.put("trust/2-aaaaaaaa/root-list.json", rootListBytes(""))
		rep := b.run()
		wantFindings(t, rep, []wf{
			{TrustSetUnlisted, "trust/1-aaaaaaaa"},
			{TrustSetUnlisted, "trust/2-aaaaaaaa"},
			{AnchorUnknown, "trust/2-aaaaaaaa/root-list.json"},
		})
	})
}

func TestUnexplainedSetWithTheLowestNumberAndAnAnchorIsJudgedByTheAnchor(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet)
	b.put("trust/1-aaaaaaaa/root-list.json", rootListBytes(digestA)) // a digest that is no record
	rep := b.run()
	wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/1-aaaaaaaa"}, {AnchorUnknown, "trust/1-aaaaaaaa/root-list.json"}})
}

// The lowest trust number is worked out once, so the work of a run grows about linearly with the
// number of sets that nothing explains (it grew with the square: 16,000 such sets took 21 seconds).
// The test does not measure seconds, which a busy machine spoils. It counts the allocations of the
// run: every judgement of a set that looks for the lowest number again allocates in proportion to
// the number of sets (the number of a set above 99 is written to a text to be compared), so a rule
// that looks again makes the count grow with the square, and a rule that looks once makes it grow
// with the number of sets. Four times the sets must cost under eight times the allocations.
func TestWorkGrowsAboutLinearlyWithTheNumberOfUnexplainedSets(t *testing.T) {
	allocsOf := func(n int) uint64 {
		m := newMem()
		m.file("ritueel.yaml", "name: x\n")
		m.put("history", newMem())
		for i := 0; i < n; i++ {
			m.file(fmt.Sprintf("trust/%d-aaaaaaaa/root-list.json", i+200), `{"version":1}`)
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		rep, err := runMem(t, m)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Findings) == 0 {
			t.Fatal("no finding: the sets were not judged")
		}
		return after.Mallocs - before.Mallocs
	}
	small, large := allocsOf(1000), allocsOf(4000)
	t.Logf("1,000 sets: %d allocations, 4,000 sets: %d", small, large)
	if large > 8*small {
		t.Errorf("4,000 sets cost %d allocations, more than 8 times the %d of 1,000", large, small)
	}
}
