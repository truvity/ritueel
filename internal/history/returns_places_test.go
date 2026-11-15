//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The place of a set in the chain, for the shapes of history that a bundle may have: a ceremony that
// stopped and was closed later, a fork, records that name the same record, and many sets that no
// record can place.

// A closing record lists the files that a stopped ceremony left. The closing record is a record of
// the chain like any other, so the set it lists stands at the place of the closing record: after the
// record before it, which is the end when the closing record was written. The plan of the closed
// ceremony does not move the set (record 0006, rule 8: the chain is the order; a plan is a file that
// the writer of the closing record can make).
func TestRootReturnsALeftoverSetStandsWhereTheClosingRecordStands(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet("1-aaaaaaaa", keyList(1, kA)))
	stopped := b.unfinished(withSet("2-aaaaaaaa", keyList(2, kK)))
	b.apply(withSet("3-aaaaaaaa", keyList(3)))
	b.closing(stopped, listsLeftover(stopped, nil))
	b.apply(withSet("5-aaaaaaaa", keyList(5, kK)))
	rep := b.run()
	// The leftover set follows the third ceremony's record, and the fifth ceremony follows the
	// closing record: K is on the list before the fifth's, so K stays.
	wantReturnsAt(t, rep)
	noNotSure(t, rep)
	for _, f := range rep.Findings {
		if f.Code == AnchorUnknown {
			t.Errorf("an anchor that the plan names is not an anchor-unknown: %s", f.Line())
		}
	}
}

// The same bundle where the key of the leftover set left after the stopped ceremony began: the set
// stands after the third ceremony's set, which lacks K, so K returns at it (record 0006, rule 54).
func TestRootReturnsALateClosingThatListsAKeyThatLeftInBetweenIsAReturn(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet("1-aaaaaaaa", keyList(1, kA, kK)))
	stopped := b.unfinished(withSet("2-aaaaaaaa", keyList(2, kA, kK)))
	b.apply(withSet("3-aaaaaaaa", keyList(3, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	rep := b.run()
	wantReturnsAt(t, rep, "2-aaaaaaaa K")
	noNotSure(t, rep)
	f := returnsOf(rep)[0]
	for _, w := range []string{wPin(pc) + wRule, "; " + wHeldPin("1-aaaaaaaa"), "; " + wBefore("3-aaaaaaaa")} {
		if !strings.Contains(f.Detail, w) {
			t.Errorf("the detail %q lacks %q", f.Detail, w)
		}
	}
}

// Two records that name one record are a fork (another finding). The sets of the two ceremonies follow
// the same record and so share a place: the chain does not order the lists inside a fork, and their
// names and sequences are the writer's, so every order of them is judged.
func TestRootReturnsTheSetsOfAForkShareAPlace(t *testing.T) {
	build := func(t *testing.T, second, third cset) *Report {
		b := chainBundle(t, true, cset{"1-aaaaaaaa", keyList(1, kA)})
		first := b.recs[0].digest
		b.apply(prev(first), withSet(second.name, second.list))
		b.apply(prev(first), withSet(third.name, third.list))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		checkReport(t, rep)
		has(t, rep, Fork, "history/"+b.recs[0].folder)
		return rep
	}
	t.Run("statements that agree: every order is judged", func(t *testing.T) {
		// The chain does not order the sets of a fork, and the writer of the newest record
		// chooses the names and the sequences: by them 2 comes before 3 and A would be on the list
		// before 3, but the other order is as true, and then A comes back at 2.
		rep := build(t, cset{"2-aaaaaaaa", keyList(2, kB)}, cset{"3-aaaaaaaa", keyList(3, kA)})
		wantReturnsAt(t, rep, "3-aaaaaaaa A")
		allNotSure(t, rep)
	})
	t.Run("statements that agree, in the other direction", func(t *testing.T) {
		rep := build(t, cset{"3-aaaaaaaa", keyList(3, kB)}, cset{"2-aaaaaaaa", keyList(2, kA)})
		wantReturnsAt(t, rep, "2-aaaaaaaa A")
		allNotSure(t, rep)
	})
	t.Run("statements that tie: any order", func(t *testing.T) {
		rep := build(t, cset{"2-aaaaaaaa", keyList(0, kB)}, cset{"3-aaaaaaaa", keyList(0, kA)})
		wantReturnsAt(t, rep, "3-aaaaaaaa A")
		allNotSure(t, rep)
	})
}

// A chain of many ceremonies after one record is a place of many sets: the work stays bounded.
func TestRootReturnsManySetsOfAForkAreBounded(t *testing.T) {
	const forks = 2000
	b := chainBundle(t, true, cset{"1-aaaaaaaa", keyList(1, kK)})
	first := b.recs[0].digest
	for i := 0; i < forks; i++ {
		l := keyList(0)
		if i%2 == 0 {
			l = keyList(0, kK)
		}
		b.apply(prev(first), withSet(fmt.Sprintf("2-%08x", i), l))
	}
	start := time.Now()
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("took %v", d)
	}
	checkReport(t, rep)
	// The sets of one place tie (no sequence, one number): every list that holds K and has another
	// list in its place that lacks it may follow that list.
	if got := len(returnsOf(rep)); got != forks/2 {
		t.Errorf("%d findings, want %d", got, forks/2)
	}
	for _, f := range returnsOf(rep) {
		if !strings.Contains(f.Detail, notSure) {
			t.Fatalf("the detail does not say that the order is not sure: %q", f.Detail)
		}
	}
}

// Many sets whose place cannot be told: one pass, whatever the number.
func TestRootReturnsManyListsWhosePlaceCannotBeToldAreBounded(t *testing.T) {
	const sets = 10000 // 260,000 entries: the run keeps 262,144
	m := chainMem(t, cset{"1-aaaaaaaa", keyList(1, kA)})
	var es []ent
	for j := 0; j < 26; j++ {
		es = append(es, ent{string(rune('A' + j)), pinOf(500 + j), ""})
	}
	for i := 0; i < sets; i++ {
		addList(m, fmt.Sprintf("%d-%08x", i+2, i), claims(keyList(0, es...), digestB))
	}
	start := time.Now()
	rep, err := runMem(t, m)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("took %v", d)
	}
	checkReport(t, rep)
	// Each list holds the same 26 keys as every other, so every entry is a return against the
	// others, but the run keeps 1,000 findings and counts the rest.
	if got := len(returnsOf(rep)); got != MaxFindingsPerCode || rep.Omitted == 0 {
		t.Errorf("%d findings kept, %d not shown", got, rep.Omitted)
	}
}

// A read that fails while the plan of a closed ceremony is read (for the anchor of its set) is an
// error of the check, never a finding and never a clean report.
func TestRootReturnsAReadThatFailsWhilePlacingASetIsAnErrorOfTheCheck(t *testing.T) {
	b := chainBundle(t, true)
	b.apply(withSet(setN(1), keyList(1, kA)))
	stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
	b.apply(withSet(setN(3), keyList(3, kB)))
	b.closing(stopped, listsLeftover(stopped, nil))
	boom := errors.New("the disk failed")
	b.mem.get(ceremonyPath(stopped, "plan.json")).readErr = boom
	rep, err := runMem(t, b.mem)
	if !errors.Is(err, boom) || rep != nil {
		t.Errorf("Check = %v, %v; want the read error and no report", rep, err)
	}
}
