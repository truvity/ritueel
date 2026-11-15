//go:build linux || darwin

package history

import (
	"strings"
	"testing"
)

// The sets that one record lists together stand at one place of the chain. They are judged one
// after the other in the order that the package gives sets at one place (the sequence of their
// lists, a list with none after all that have one, then the number in the folder name, then the
// name), by the rule of every other set: the number in the folder name is the sequence of its list
// and is higher than the number of the judged set directly before it. The last set of a place is
// the set before for the next place (record 0006, rules 14 and 21).

const (
	g1 = "1-aaaaaaaa"
	g2 = "2-bbbbbbbb"
	g3 = "3-cccccccc"
)

// afterOne is a chain with the set 1-aaaaaaaa, to which the test adds more.
func afterOne(t testing.TB) *bundle {
	t.Helper()
	return chainBundle(t, false, cset{g1, keyList(1, kA)})
}

// notHigher is the part of a detail that says a number is not higher than the number of the set
// before it, and names that set.
func notHigher(n, before int, set string) string {
	return "the number in its name, " + itoa(n) + ", is not higher than " + itoa(before) + ", the number of the set before it in the chain, trust/" + set
}

// One record lists 2-b and 2-c, each with the sequence 2: the second of them in the order of the
// place (the same sequence, the same number, then the name) is not higher than the first.
func TestTrustSequenceOneRecordListsTwoSetsWithOneNumber(t *testing.T) {
	b := afterOne(t)
	b.apply(withSets(
		cset{"2-cccccccc", keyList(2, kA)},
		cset{"2-bbbbbbbb", keyList(2, kA)}))
	rep := b.run()
	wantExactly(t, rep, wf{TrustSequence, "trust/2-cccccccc"})
	wantReasons(t, rep, []Code{TrustSequence}, nil)
	d := detail(rep, TrustSequence, "trust/2-cccccccc")
	for _, w := range []string{notHigher(2, 2, "2-bbbbbbbb"), seqWords} {
		if !strings.Contains(d, w) {
			t.Errorf("the detail %q lacks %q", d, w)
		}
	}
	if strings.Contains(d, "is not the sequence of its root list") {
		t.Errorf("the detail %q says the sequence differs, and it does not", d)
	}
	if in := b.inspect(); in.State != nil || in.OrderErr != nil {
		t.Errorf("State %v and OrderErr %v for a report with a failing finding", in.State, in.OrderErr)
	}
}

// The three sets stand in the sets of the table by the order of the place, not by their order in
// the record or in the folder: the findings do not depend on how the record spells them.
func TestTrustSequenceTheOrderOfAPlaceIsTheSequenceThenTheNumber(t *testing.T) {
	cases := []struct {
		name string
		last int // the folder number of the set before the place, with the sequence of the number
		sets []cset
		bad  map[string]string // the set with the finding and a word of its detail
	}{
		{
			// 5, then the place: 1-c (sequence 1) comes before 6-b (sequence 6), then 7-d.
			name: "5, then 6 and 1 in one record, then 7",
			last: 5,
			sets: []cset{{"6-bbbbbbbb", keyList(6, kA)}, {"1-cccccccc", keyList(1, kA)}},
			bad:  map[string]string{"1-cccccccc": notHigher(1, 5, "5-aaaaaaaa")},
		},
		{
			name: "the same sets, spelled in the other order",
			last: 5,
			sets: []cset{{"1-cccccccc", keyList(1, kA)}, {"6-bbbbbbbb", keyList(6, kA)}},
			bad:  map[string]string{"1-cccccccc": notHigher(1, 5, "5-aaaaaaaa")},
		},
		{
			name: "2 and 3 after 1: growing numbers, no finding",
			last: 1,
			sets: []cset{{"2-bbbbbbbb", keyList(2, kA)}, {"3-cccccccc", keyList(3, kA)}},
		},
		{
			name: "2 and 3 spelled the other way: growing numbers, no finding",
			last: 1,
			sets: []cset{{"3-cccccccc", keyList(3, kA)}, {"2-bbbbbbbb", keyList(2, kA)}},
		},
		{
			name: "2 and 4 after 1: a skip is no finding",
			last: 1,
			sets: []cset{{"2-bbbbbbbb", keyList(2, kA)}, {"4-cccccccc", keyList(4, kA)}},
		},
		{
			// no sequence in either list: the folder number orders them, so 2 comes before 3
			name: "two lists with no sequence are ordered by the folder number",
			last: 1,
			sets: []cset{{"3-bbbbbbbb", rootsJSON(0, kA)}, {"2-cccccccc", rootsJSON(0, kA)}},
		},
		{
			// 3-b has no sequence, 2-c has one: the one with a sequence is first, so 2 then 3
			name: "a list with no sequence comes after a list with one",
			last: 1,
			sets: []cset{{"3-bbbbbbbb", rootsJSON(0, kA)}, {"2-cccccccc", keyList(2, kA)}},
		},
		{
			// 2-b has no sequence, 3-c has the sequence 3: 3-c is first, then 2-b is not higher than 3
			name: "a list with no sequence is judged last, whatever its number",
			last: 1,
			sets: []cset{{"2-bbbbbbbb", rootsJSON(0, kA)}, {"3-cccccccc", keyList(3, kA)}},
			bad:  map[string]string{"2-bbbbbbbb": notHigher(2, 3, "3-cccccccc")},
		},
		{
			// 2-b has the sequence 3 and 3-c has the sequence 2: by sequence 3-c comes first
			// (folder 3 is not its sequence 2, but 3 is higher than 1), then 2-b (folder 2 is not its
			// sequence 3, and 2 is not higher than 3). By folder number 2-b would come first and have
			// one reason only.
			name: "the sequence orders before the folder number",
			last: 1,
			sets: []cset{{"2-bbbbbbbb", keyList(3, kA)}, {"3-cccccccc", keyList(2, kA)}},
			bad: map[string]string{
				"3-cccccccc": "the number in its name, 3, is not the sequence of its root list, 2",
				"2-bbbbbbbb": notHigher(2, 3, "3-cccccccc"),
			},
		},
		{
			// 10-b and 9-c have no sequence: by number 9 comes before 10, by name 10-b would be
			// first and 9-c would not be higher than 10
			name: "numbers of more than one digit are ordered as numbers, not as names",
			last: 8,
			sets: []cset{{"10-bbbbbbbb", rootsJSON(0, kA)}, {"9-cccccccc", rootsJSON(0, kA)}},
		},
		{
			name: "the same sequence is ordered by the folder number",
			last: 1,
			sets: []cset{{"3-bbbbbbbb", keyList(2, kA)}, {"2-cccccccc", keyList(2, kA)}},
			bad: map[string]string{
				"3-bbbbbbbb": "the number in its name, 3, is not the sequence of its root list, 2",
			},
		},
		{
			name: "the same sequence and the same number are ordered by the name",
			last: 1,
			sets: []cset{{"2-dddddddd", keyList(2, kA)}, {"2-bbbbbbbb", keyList(2, kA)}, {"2-cccccccc", keyList(2, kA)}},
			bad: map[string]string{
				"2-cccccccc": notHigher(2, 2, "2-bbbbbbbb"),
				"2-dddddddd": notHigher(2, 2, "2-cccccccc"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first := itoa(c.last) + "-aaaaaaaa"
			b := chainBundle(t, false, cset{first, keyList(int64(c.last), kA)})
			b.apply(withSets(c.sets...))
			b.apply(withSet("99-zzzzzzzz", keyList(99, kA)))
			rep := b.run()
			var want []wf
			for set := range c.bad {
				want = append(want, wf{TrustSequence, "trust/" + set})
			}
			wantExactly(t, rep, want...)
			for set, w := range c.bad {
				if d := detail(rep, TrustSequence, "trust/"+set); !strings.Contains(d, w) {
					t.Errorf("the detail of %s, %q, lacks %q", set, d, w)
				}
			}
			if rep.Clean() != (len(c.bad) == 0) {
				t.Errorf("Clean() = %v with %d findings", rep.Clean(), len(c.bad))
			}
		})
	}
}

// 6-b and 1-c in one record after 5-a, then 7-d: by the order of the place the sets of the record
// are 1-c and 6-b. Only 1-c has the finding: 6-b is higher than the number before it, which is 1,
// and 7-d is higher than the last set of the place.
func TestTrustSequenceASetThatComesBeforeThePlaceInTheNumbersIsFoundOnce(t *testing.T) {
	b := chainBundle(t, false, cset{"5-aaaaaaaa", keyList(5, kA)})
	b.apply(withSets(cset{"6-bbbbbbbb", keyList(6, kA)}, cset{"1-cccccccc", keyList(1, kA)}))
	b.apply(withSet("7-dddddddd", keyList(7, kA)))
	rep := b.run()
	wantExactly(t, rep, wf{TrustSequence, "trust/1-cccccccc"})
	if d := detail(rep, TrustSequence, "trust/1-cccccccc"); !strings.Contains(d, notHigher(1, 5, "5-aaaaaaaa")) {
		t.Errorf("the detail %q does not compare 1-c with 5-a", d)
	}
}

// One record lists 2-b and 3-c after 1-a: the numbers grow, so there is no finding, the report is
// clean, and the State is refused because the order of the sets of one record is not given
// (an OrderErr, not a finding).
func TestTrustSequenceOneRecordListsTwoSetsWithGrowingNumbers(t *testing.T) {
	b := afterOne(t)
	b.apply(withSets(cset{g2, keyList(2, kA)}, cset{g3, keyList(3, kA)}))
	rep := b.run()
	wantExactly(t, rep)
	if !rep.Clean() {
		t.Error("a report that is not clean for numbers that grow")
	}
	wantOrderErr(t, b.inspect())
}

// The last set of a place is the set before for the next place.
func TestTrustSequenceTheLastSetOfAPlaceIsTheSetBeforeForTheNextPlace(t *testing.T) {
	build := func(t *testing.T, next int) *bundle {
		b := afterOne(t)
		b.apply(withSets(cset{g2, keyList(2, kA)}, cset{"4-cccccccc", keyList(4, kA)}))
		name := itoa(next) + "-dddddddd"
		b.apply(withSet(name, keyList(int64(next), kA)))
		return b
	}
	t.Run("3 after 2 and 4 is not higher than 4", func(t *testing.T) {
		b := build(t, 3)
		rep := b.run()
		wantExactly(t, rep, wf{TrustSequence, "trust/3-dddddddd"})
		if d := detail(rep, TrustSequence, "trust/3-dddddddd"); !strings.Contains(d, notHigher(3, 4, "4-cccccccc")) {
			t.Errorf("the detail %q does not compare 3-d with 4-c", d)
		}
	})
	t.Run("4 after 2 and 4 is not higher than 4", func(t *testing.T) {
		wantExactly(t, build(t, 4).run(), wf{TrustSequence, "trust/4-dddddddd"})
	})
	t.Run("5 after 2 and 4 is higher", func(t *testing.T) {
		wantExactly(t, build(t, 5).run())
	})
	t.Run("a place that has a finding gives its last set as the set before all the same", func(t *testing.T) {
		// 1-a, then 2-b and 2-c (finding for 2-c), then 3-d: 3 is higher than 2, no finding.
		b := afterOne(t)
		b.apply(withSets(cset{g2, keyList(2, kA)}, cset{"2-cccccccc", keyList(2, kA)}))
		b.apply(withSet("3-dddddddd", keyList(3, kA)))
		wantExactly(t, b.run(), wf{TrustSequence, "trust/2-cccccccc"})
	})
	t.Run("a set before the place is compared with the last set of the place before it", func(t *testing.T) {
		// 1-a, 5-b and 6-c in one record, then 2-d and 7-e in the next: 2 is not higher than 6.
		b := afterOne(t)
		b.apply(withSets(cset{"5-bbbbbbbb", keyList(5, kA)}, cset{"6-cccccccc", keyList(6, kA)}))
		b.apply(withSets(cset{"2-dddddddd", keyList(2, kA)}, cset{"7-eeeeeeee", keyList(7, kA)}))
		rep := b.run()
		wantExactly(t, rep, wf{TrustSequence, "trust/2-dddddddd"})
		if d := detail(rep, TrustSequence, "trust/2-dddddddd"); !strings.Contains(d, notHigher(2, 6, "6-cccccccc")) {
			t.Errorf("the detail %q does not compare 2-d with 6-c", d)
		}
	})
}

// A set of a group that has no trust number or no sequence is held as any other set, and the sets
// of the group around it are still compared with each other.
func TestTrustSequenceASetWithNoNumberInAGroup(t *testing.T) {
	t.Run("a name with no trust number gets its own finding and is no set before", func(t *testing.T) {
		b := afterOne(t)
		b.apply(withSets(cset{"02-bbbbbbbb", rootsJSON(0, kA)}, cset{g2, keyList(2, kA)}))
		rep := b.run()
		wantExactly(t, rep, wf{TrustSequence, "trust/02-bbbbbbbb"})
		if d := detail(rep, TrustSequence, "trust/02-bbbbbbbb"); !strings.Contains(d, "its name has no trust number") {
			t.Errorf("the detail %q lacks the words about the name", d)
		}
	})
	t.Run("the set with no number comes after the numbered sets of its place", func(t *testing.T) {
		// both have no sequence: 2-b is judged first, then the name with no number; the next place
		// is compared with 2-b.
		b := afterOne(t)
		b.apply(withSets(cset{"02-aaaaaaaa", rootsJSON(0, kA)}, cset{g2, rootsJSON(0, kA)}))
		b.apply(withSet("2-dddddddd", keyList(2, kA)))
		rep := b.run()
		wantExactly(t, rep, wf{TrustSequence, "trust/02-aaaaaaaa"}, wf{TrustSequence, "trust/2-dddddddd"})
	})
}

// A fork, and a closing record, still leave their sets out, though a record of them lists two sets
// that have one number.
func TestTrustSequenceStillLeavesOutAForkAndAClosingRecordWithTwoSets(t *testing.T) {
	t.Run("a fork whose records list two sets with one number each", func(t *testing.T) {
		b := afterOne(t)
		a := b.recs[0]
		b.apply(withSets(cset{g2, keyList(2, kA)}, cset{"2-cccccccc", keyList(2, kA)}))
		b.apply(prev(a.digest), withSets(cset{"2-dddddddd", keyList(2, kA)}, cset{"2-eeeeeeee", keyList(2, kA)}))
		rep := b.run()
		has(t, rep, Fork, folderPath(a))
		lacks(t, rep, TrustSequence)
	})
	t.Run("a closing record that lists two sets with one number", func(t *testing.T) {
		b := afterOne(t)
		stopped := b.unfinished(withSet("2-bbbbbbbb", keyList(2, kA)))
		b.closing(stopped, listsLeftover(stopped, nil), listsNewSet("2-cccccccc", keyList(2, kA)))
		rep := b.run()
		lacks(t, rep, TrustSequence)
	})
}

// A set that stands at one place and a set at another place are judged by the order of the chain,
// so a fall between two records that list two sets each is found where the chain puts it.
func TestTrustSequenceTwoPlacesOfTwoSets(t *testing.T) {
	b := afterOne(t)
	b.apply(withSets(cset{g2, keyList(2, kA)}, cset{g3, keyList(3, kA)}))
	b.apply(withSets(cset{"4-dddddddd", keyList(4, kA)}, cset{"5-eeeeeeee", keyList(5, kA)}))
	wantExactly(t, b.run())
	b2 := afterOne(t)
	b2.apply(withSets(cset{"4-bbbbbbbb", keyList(4, kA)}, cset{"5-cccccccc", keyList(5, kA)}))
	b2.apply(withSets(cset{"2-dddddddd", keyList(2, kA)}, cset{"3-eeeeeeee", keyList(3, kA)}))
	// 2 is not higher than 5; 3 is higher than 2 and has no finding
	wantExactly(t, b2.run(), wf{TrustSequence, "trust/2-dddddddd"})
}

// The cases that the finding leaves out on purpose are clean (exit code 0): a set that a closing
// record lists with a repeated or lowered number, an unfinished set with a repeated number, and a
// closed leftover followed by an ordinary set with the number of the leftover.
func TestTrustSequenceCasesLeftOutOnPurposeAreClean(t *testing.T) {
	clean := func(t *testing.T, b *bundle, warnings ...Code) {
		t.Helper()
		rep := b.run()
		lacks(t, rep, TrustSequence)
		wantReasons(t, rep, nil, warnings)
		if !rep.Clean() {
			t.Errorf("a report that is not clean: %v", findingsOf(rep))
		}
	}
	t.Run("a closing record lists a leftover with a repeated number", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kA)})
		stopped := b.unfinished(withSet("2-bbbbbbbb", keyList(2, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		clean(t, b)
	})
	t.Run("a closing record lists a leftover with a lowered number", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(5), keyList(5, kA)})
		stopped := b.unfinished(withSet("2-bbbbbbbb", keyList(2, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		clean(t, b)
	})
	t.Run("a closing record lists a leftover whose number is not its sequence", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		stopped := b.unfinished(withSet(setN(2), keyList(1, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		clean(t, b)
	})
	t.Run("an unfinished set with a repeated number", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kA)})
		u := b.unfinished(withSet("2-bbbbbbbb", keyList(2, kA)), func(r *rec) {
			r.plan.TrustSequence = ptr(int64(2))
			r.refresh()
		})
		rep := b.run()
		wantExactly(t, rep, wf{UnfinishedCeremony, "trust/" + u.set})
		wantReasons(t, rep, nil, []Code{UnfinishedCeremony})
		if !rep.Clean() {
			t.Error("a notice makes the report fail")
		}
	})
	t.Run("a closed leftover and then an ordinary set with the same number", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		stopped := b.unfinished(withSet("2-bbbbbbbb", keyList(2, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		b.apply(withSet("2-cccccccc", keyList(2, kA)))
		clean(t, b)
	})
	t.Run("a closed leftover with a number above the ordinary set after it", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		stopped := b.unfinished(withSet("9-bbbbbbbb", keyList(9, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		b.apply(withSet("2-cccccccc", keyList(2, kA)))
		clean(t, b)
	})
}

// A set that a record lists whose predecessor is not a record of the chain has no place: it is left
// out, though records of the chain are there, and its number is not compared with the sets that
// have one.
func TestTrustSequenceLeavesOutASetWhoseRecordIsOffTheChain(t *testing.T) {
	b := afterOne(t)
	b.apply(withSet("2-bbbbbbbb", keyList(2, kA)))
	b.apply(prev(digestA), withSet("1-zzzzzzzz", keyList(1, kA)))
	rep := b.run()
	has(t, rep, ChainBroken, folderPath(b.recs[2]))
	lacks(t, rep, TrustSequence)
}
