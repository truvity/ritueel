//go:build linux || darwin

package history

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The order of the root lists (record 0006, rules 8, 14 and 54). The hash chain of the ceremony
// records cannot be reordered without another finding, so it is the order of the lists:
//
//   - a set that a record lists follows the record before the ceremony that wrote it, whatever its
//     folder number and the sequence of its list say;
//   - a set that no record lists follows the record that the last_record_sha256 of its list names,
//     and a list that names none follows no record;
//   - sets that follow the same record are ordered by the sequence of the list, then by the number
//     of the folder; where those tie, are missing or disagree, every reading is judged and the
//     detail says that the order is not sure;
//   - a set whose place cannot be told is judged as a list after one that cannot be read.

// keyList is a root list with the entries and the member sequence seq (none when seq is 0).
func keyList(seq int64, ents ...ent) []byte { return rootsJSON(seq, ents...) }

// seqList is a root list whose member sequence is written as the text seq.
func seqList(seq string, ents ...ent) []byte {
	var es []string
	for _, e := range ents {
		es = append(es, rawEntry(e.label, e.pin, e.fp))
	}
	return []byte(`{"roots":[` + strings.Join(es, ",") + `],"sequence":` + seq + `,"version":1}`)
}

var (
	kA = ent{"A", pa, ""}
	kB = ent{"B", pb, ""}
	kK = ent{"K", pc, ""}
)

// noNotSure fails when a finding says that the order is not sure.
func noNotSure(t *testing.T, rep *Report) {
	t.Helper()
	for _, f := range returnsOf(rep) {
		if strings.Contains(f.Detail, "not sure") {
			t.Errorf("the order is sure, and the detail says it is not: %q", f.Detail)
		}
	}
}

// allNotSure fails when a finding does not say that the order is not sure.
func allNotSure(t *testing.T, rep *Report) {
	t.Helper()
	for _, f := range returnsOf(rep) {
		if !strings.Contains(f.Detail, notSure) {
			t.Errorf("the order is not sure, and the detail does not say it: %q", f.Detail)
		}
	}
}

// The writer of the newest ceremony chooses the name of its trust set and the sequence of its
// list. Whatever it chooses, the three ceremonies below (A and B, then B, then A and B) have one
// order, the order of the chain, and the list of the third brings A back.
func TestRootReturnsTheNamesAndSequencesOfTheSetsCannotHideAReturn(t *testing.T) {
	type pick struct {
		name string
		seq  string // "" is no member sequence
	}
	cases := []struct {
		name string
		sets [3]pick
	}{
		{"names and sequences that agree with the chain", [3]pick{{"1-aaaaaaaa", "1"}, {"2-bbbbbbbb", "2"}, {"3-cccccccc", "3"}}},
		{"no sequence at all", [3]pick{{"1-aaaaaaaa", ""}, {"2-bbbbbbbb", ""}, {"3-cccccccc", ""}}},
		{"the newest set has the number 0 and no sequence", [3]pick{{"1-aaaaaaaa", "1"}, {"2-bbbbbbbb", "2"}, {"0-cccccccc", ""}}},
		{"the newest set has the number 0 and the sequence 0", [3]pick{{"1-aaaaaaaa", "1"}, {"2-bbbbbbbb", "2"}, {"0-cccccccc", "0"}}},
		{"the newest set has the number 0 and the sequence -1", [3]pick{{"1-aaaaaaaa", "1"}, {"2-bbbbbbbb", "2"}, {"0-cccccccc", "-1"}}},
		{"the newest set is named 1-zzzzzzzz and has the sequence 1", [3]pick{{"1-aaaaaaaa", "1"}, {"2-bbbbbbbb", "2"}, {"1-zzzzzzzz", "1"}}},
		{"the newest set has the number of the oldest and its sequence", [3]pick{{"1-aaaaaaaa", "1"}, {"2-bbbbbbbb", "2"}, {"1-aaaaaaab", "1"}}},
		{"the numbers are turned and the sequences with them", [3]pick{{"3-aaaaaaaa", "3"}, {"1-bbbbbbbb", "1"}, {"2-cccccccc", "2"}}},
		{"both statements lie: numbers 1, 3, 2 and sequences 3, 2, 1", [3]pick{{"1-aaaaaaaa", "3"}, {"3-bbbbbbbb", "2"}, {"2-cccccccc", "1"}}},
		{"the numbers fall", [3]pick{{"9-aaaaaaaa", ""}, {"8-bbbbbbbb", ""}, {"7-cccccccc", ""}}},
		{"the sequences fall", [3]pick{{"1-aaaaaaaa", "30"}, {"2-bbbbbbbb", "20"}, {"3-cccccccc", "10"}}},
		{"the same number in all three", [3]pick{{"5-aaaaaaaa", "1"}, {"5-bbbbbbbb", "2"}, {"5-cccccccc", "3"}}},
		{"no number in any name", [3]pick{{"x-aaaaaaaa", "1"}, {"y-bbbbbbbb", "2"}, {"z-cccccccc", "3"}}},
		{"the same sequence in all three", [3]pick{{"1-aaaaaaaa", "7"}, {"2-bbbbbbbb", "7"}, {"3-cccccccc", "7"}}},
		{"sequences beyond what a number holds", [3]pick{{"1-aaaaaaaa", "9007199254740991"}, {"2-bbbbbbbb", "-9007199254740991"}, {"3-cccccccc", "0"}}},
		{"a number of fifteen digits for the oldest", [3]pick{{"999999999999999-aaaaaaaa", "1"}, {"2-bbbbbbbb", "2"}, {"3-cccccccc", "3"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lists := [3][]ent{{kA, kB}, {kB}, {kA, kB}}
			var cs []cset
			for i, p := range c.sets {
				l := rootsJSON(0, lists[i]...)
				if p.seq != "" {
					l = seqList(p.seq, lists[i]...)
				}
				cs = append(cs, cset{p.name, l})
			}
			rep := runChain(t, cs...)
			wantReturnsAt(t, rep, c.sets[2].name+" A")
			noNotSure(t, rep)
			// The finding names the list before it by its place in the chain.
			f := returnsOf(rep)[0]
			if want := "; " + wBefore(c.sets[1].name); !strings.Contains(f.Detail, want) {
				t.Errorf("the detail %q lacks %q", f.Detail, want)
			}
			if want := "; " + wHeldPin(c.sets[0].name) + "; "; !strings.Contains(f.Detail, want) {
				t.Errorf("the detail %q lacks %q", f.Detail, want)
			}
		})
	}
}

// The same bundle where the true order hides a return from the order of the sequences and from the
// order of the numbers alike: the chain finds it.
func TestRootReturnsAReturnThatNeitherTheNumbersNorTheSequencesShow(t *testing.T) {
	// Chain order: 1-aaaaaaaa {A}, 3-cccccccc {B}, 2-bbbbbbbb {A, B}. By number the lists run
	// 1, 2, 3, by sequence 3, 2, 1: in neither does a key return. In the chain A returns.
	rep := runChain(t,
		cset{"1-aaaaaaaa", keyList(3, kA)},
		cset{"3-cccccccc", keyList(1, kB)},
		cset{"2-bbbbbbbb", keyList(2, kA, kB)},
	)
	wantReturnsAt(t, rep, "2-bbbbbbbb A")
	noNotSure(t, rep)
}

// A bundle that follows the rules: keys that stay, keys that move in the list, labels that change.
// Whatever the sequences say, one set for each place is one order and no finding.
func TestRootReturnsAnHonestBundleHasNoFindingAndOneOrder(t *testing.T) {
	t.Run("keys that stay, move and change their label", func(t *testing.T) {
		rep := runLists(t,
			keyList(1, ent{"A", pa, f1}, ent{"B", pb, ""}),
			keyList(2, ent{"B", pb, ""}, ent{"A", pa, f1}),
			keyList(3, ent{"C", pb, ""}, ent{"D", pa, f1}, ent{"E", pc, ""}),
			keyList(4, ent{"C", pb, ""}, ent{"D", pa, f1}, ent{"E", pc, ""}),
			keyList(5, ent{"E", pc, ""}),
		)
		wantReturnsAt(t, rep)
	})
	t.Run("sequences that do not follow the chain are no tie when each set has a place of its own", func(t *testing.T) {
		rep := runLists(t, keyList(50, kA), keyList(1, kA), keyList(9, kA), keyList(0, kA))
		wantReturnsAt(t, rep)
		noNotSure(t, rep)
	})
	t.Run("one return is one finding and the order is sure", func(t *testing.T) {
		rep := runLists(t, keyList(1, kA, kB), keyList(2, kB), keyList(3, kA, kB), keyList(4, kA, kB))
		wantReturnsAt(t, rep, setN(3)+" A")
		noNotSure(t, rep)
	})
	t.Run("a list that cannot be read has a place, and the order stays sure", func(t *testing.T) {
		rep := runLists(t, keyList(1, kA), []byte(`{`), keyList(3, kA))
		got := returnsOf(rep)
		if len(got) != 1 || got[0].Path != listPathOf(setN(3)) || strings.Contains(got[0].Detail, "not sure") ||
			!strings.Contains(got[0].Detail, "cannot be read") {
			t.Errorf("findings %v", lines(got))
		}
	})
	t.Run("a sequence of 0 is a sequence", func(t *testing.T) {
		rep := runChain(t,
			cset{setN(1), seqList("0", kA)}, cset{setN(2), seqList("1", kB)}, cset{setN(3), seqList("2", kA)})
		wantReturnsAt(t, rep, setN(3)+" A")
		noNotSure(t, rep)
	})
}

// A bundle in memory whose chain is built from the first sets, and then more sets that no record
// lists, each with the record that its list claims to follow.
type unlisted struct {
	name  string
	list  []byte
	claim int // 0: names no record; k > 0: names the record of ceremony k; -1: names no record of the chain
}

func runWithUnlisted(t *testing.T, chain []cset, extra ...unlisted) *Report {
	t.Helper()
	b := chainBundle(t, true, chain...)
	for _, u := range extra {
		list := u.list
		switch {
		case u.claim > 0:
			list = claims(list, b.digests()[u.claim-1])
		case u.claim < 0:
			list = claims(list, digestB)
		}
		addList(b.mem, u.name, list)
	}
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	checkReport(t, rep)
	return rep
}

// A set that no record lists has the place its own list claims: the record that its
// last_record_sha256 names, and no record when it names none. Every such set is also
// trust-set-unlisted, so the bundle fails with or without root-returns.
func TestRootReturnsASetThatNoRecordListsFollowsTheRecordItNames(t *testing.T) {
	chain := func() []cset {
		return []cset{{setN(1), keyList(1, kA)}, {setN(2), keyList(2, kB)}, {setN(3), keyList(3, kB)}}
	}
	t.Run("a set that names the end follows every ceremony", func(t *testing.T) {
		// A was on the first list, the list before this one holds B only: A returns.
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(9, kA), 3})
		wantReturnsAt(t, rep, "9-aaaaaaaa A")
		noNotSure(t, rep)
		has(t, rep, TrustSetUnlisted, "trust/9-aaaaaaaa")
		if rep.Clean() {
			t.Error("clean")
		}
	})
	t.Run("a set that names the end and holds only keys that stay is no return", func(t *testing.T) {
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(9, kB), 3})
		wantReturnsAt(t, rep)
	})
	t.Run("a set that names the end, whatever its number and sequence", func(t *testing.T) {
		for name, l := range map[string][]byte{
			"number 0, no sequence": keyList(0, kA),
			"sequence -1":           seqList("-1", kA),
			"sequence 0":            seqList("0", kA),
		} {
			set := "0-aaaaaaaa"
			rep := runWithUnlisted(t, chain(), unlisted{set, l, 3})
			if got := returnsOf(rep); len(got) != 1 || got[0].Path != listPathOf(set) {
				t.Errorf("%s: findings %v", name, lines(got))
			}
			noNotSure(t, rep)
		}
	})
	t.Run("a set that names an earlier record has the place of that record's successor", func(t *testing.T) {
		// It names the record of ceremony 2, so it follows it, as the third ceremony does: they
		// share a place. The third ceremony's list has a sequence and the set has none, so the
		// set is last in both readings (a list with no sequence comes last): A, which only the
		// first list held, returns at it, and no two sets tie.
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(0, kA), 2})
		wantReturnsAt(t, rep, "9-aaaaaaaa A")
		noNotSure(t, rep)
	})
	t.Run("a set that names an earlier record, that holds only keys that stay", func(t *testing.T) {
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(0, kB), 2})
		wantReturnsAt(t, rep)
	})
	t.Run("a set that names an earlier record and states its place after the ceremony's set", func(t *testing.T) {
		// Its number and sequence put it after the third ceremony's set (sequence 3, number 3):
		// one order, and A returns at it.
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(9, kA), 2})
		wantReturnsAt(t, rep, "9-aaaaaaaa A")
		noNotSure(t, rep)
	})
	t.Run("a set that names no record follows none and ties with the first ceremony", func(t *testing.T) {
		// The first ceremony's list and the set have no sequence, so they tie: the set holds B,
		// and may come before the first list (which lacks B), so B returns at the second list.
		rep := runWithUnlisted(t, []cset{{setN(1), keyList(0, kA)}, {setN(2), keyList(2, kB)}, {setN(3), keyList(3, kB)}},
			unlisted{"9-aaaaaaaa", keyList(0, kB), 0})
		wantReturnsAt(t, rep, setN(2)+" B")
		allNotSure(t, rep)
	})
	t.Run("a set that names no record, honest statements of the order", func(t *testing.T) {
		// Its sequence and number put it before the first ceremony's set (sequence 1, number 1).
		rep := runWithUnlisted(t, chain(), unlisted{"0-aaaaaaaa", seqList("0", kA), 0})
		wantReturnsAt(t, rep)
	})
	t.Run("a set that names a digest that is no record on the chain has no place", func(t *testing.T) {
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(9, kA), -1})
		// Its place cannot be told: A was held by the first list, so it is a return.
		wantReturnsAt(t, rep, "9-aaaaaaaa A")
		for _, f := range returnsOf(rep) {
			if !strings.Contains(f.Detail, "the place of this trust set in the chain cannot be told") {
				t.Errorf("the detail %q", f.Detail)
			}
		}
	})
	t.Run("a set whose place cannot be told, with a key no other list held", func(t *testing.T) {
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(9, kK), -1})
		wantReturnsAt(t, rep)
	})
	t.Run("a set whose place cannot be told does not change the lists that have a place", func(t *testing.T) {
		rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", keyList(9, kK), -1})
		wantReturnsAt(t, rep)
		rep = runWithUnlisted(t, []cset{{setN(1), keyList(1, kA)}, {setN(2), keyList(2, kB)}, {setN(3), keyList(3, kA)}},
			unlisted{"9-aaaaaaaa", keyList(9, kK), -1})
		wantReturnsAt(t, rep, setN(3)+" A")
	})
	t.Run("a set whose list cannot be read has no key, with any claim", func(t *testing.T) {
		for _, claim := range []int{0, 1, 3, -1} {
			rep := runWithUnlisted(t, chain(), unlisted{"9-aaaaaaaa", []byte(`{`), claim})
			wantReturnsAt(t, rep)
			has(t, rep, AnchorUnknown, listPathOf("9-aaaaaaaa"))
		}
	})
}

// A set whose place cannot be told, because the records that name it cannot place it, is judged as
// a list after one that cannot be read: an entry of it is a return when any other list that could
// be read held the key, by pin or by fingerprint. Such a list is already anchor-unknown or
// chain-broken, so the bundle fails with or without this finding.
func TestRootReturnsAListedSetWhosePlaceCannotBeToldIsJudgedAgainstEveryOtherList(t *testing.T) {
	floating := func(t *testing.T, rep *Report, set string, labels ...string) {
		t.Helper()
		var want []string
		for _, l := range labels {
			want = append(want, set+" "+l)
		}
		var got []Finding
		for _, f := range returnsOf(rep) {
			if f.Path == listPathOf(set) {
				got = append(got, f)
				if !strings.Contains(f.Detail, "the place of this trust set in the chain cannot be told") {
					t.Errorf("the detail %q does not say that the place cannot be told", f.Detail)
				}
				if strings.Contains(f.Detail, "not sure") {
					t.Errorf("the detail %q says the order is not sure", f.Detail)
				}
			}
		}
		if len(got) != len(want) {
			t.Errorf("findings at %s: %v, want %v", set, lines(got), want)
		}
	}
	t.Run("two records list one set after different records", func(t *testing.T) {
		b := chainBundle(t, true,
			cset{setN(1), keyList(1, kA, kB)},
			cset{setN(2), keyList(2, kB)},
			cset{setN(3), keyList(3, kK)},
		)
		// A fourth ceremony lists the set of the second again: the records that list it differ in
		// the record before them. The set stands at the place of each, so its place can be told, and
		// at the second one the list before it is the third set: A and B come back there.
		b.apply(withSet(setN(2), keyList(2, kA, kB)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		checkReport(t, rep)
		has(t, rep, AnchorUnknown, listPathOf(setN(2)))
		wantReturnsAt(t, rep, setN(2)+" A", setN(2)+" B")
		for _, f := range returnsOf(rep) {
			if strings.Contains(f.Detail, "cannot be told") {
				t.Errorf("the set has places, and the detail says it has not: %q", f.Detail)
			}
		}
	})
	t.Run("a record that is off the chain lists the set", func(t *testing.T) {
		b := chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kB)})
		b.apply(prev(digestB), withSet(setN(3), keyList(3, kA)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		checkReport(t, rep)
		has(t, rep, ChainBroken, "history/"+b.recs[2].folder)
		floating(t, rep, setN(3), "A")
	})
	t.Run("a closing record lists a set whose closed plan cannot be read", func(t *testing.T) {
		// The plan is not read for the place: the set stands where the closing record stands, after
		// the record of the third set, which does not hold the key A.
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
		b.apply(withSet(setN(3), keyList(3, kB)))
		b.closing(stopped, listsLeftover(stopped, nil))
		b.remove(ceremonyPath(stopped, "plan.json"))
		rep := b.run()
		has(t, rep, AnchorUnknown, listPathOf(setN(2)))
		wantReturnsAt(t, rep, setN(2)+" A")
		for _, f := range returnsOf(rep) {
			if strings.Contains(f.Detail, "cannot be told") {
				t.Errorf("the set has a place, and the detail says it has not: %q", f.Detail)
			}
		}
	})
	t.Run("an entry of it that no other list held is no return", func(t *testing.T) {
		b := chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kB)})
		b.apply(prev(digestB), withSet(setN(3), keyList(3, kK)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		wantReturnsAt(t, rep)
	})
	t.Run("a fingerprint held by another list under any pin is a return", func(t *testing.T) {
		b := chainBundle(t, true, cset{setN(1), keyList(1, ent{"A", pa, f1})}, cset{setN(2), keyList(2, kB)})
		b.apply(prev(digestB), withSet(setN(3), keyList(3, ent{"C", pc, f1})))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		floating(t, rep, setN(3), "C")
		for _, f := range returnsOf(rep) {
			if !strings.Contains(f.Detail, "its OpenPGP fingerprint "+f1[:16]) {
				t.Errorf("the detail %q", f.Detail)
			}
		}
	})
	t.Run("both reasons at once", func(t *testing.T) {
		b := chainBundle(t, true, cset{setN(1), keyList(1, ent{"A", pa, f1})}, cset{setN(2), keyList(2, kB)})
		b.apply(prev(digestB), withSet(setN(3), keyList(3, ent{"X", pa, f1})))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		got := atPath(returnsOf(rep), listPathOf(setN(3)))
		if len(got) != 1 || !strings.Contains(got[0].Detail, "its pin "+short16(pa)) || !strings.Contains(got[0].Detail, "its OpenPGP fingerprint "+f1[:16]) {
			t.Errorf("findings %v", lines(got))
		}
	})
}

// Sets that follow the same record are ordered by the sequence of the list and then by the number
// of the folder. Where the two give one order, that is the order.
func TestRootReturnsSetsOfOnePlaceThatAgreeHaveOneOrder(t *testing.T) {
	chain := []cset{{setN(1), keyList(1, kA)}}
	// Two sets follow the first record: the second ceremony's, and one that no record lists.
	t.Run("the numbers and the sequences agree", func(t *testing.T) {
		// 2-... (sequence 2) then 3-... (sequence 3): the order is sure, and A returns at the
		// second if the first lacks it.
		rep := runWithUnlisted(t, append(chain, cset{setN(2), keyList(2, kB)}),
			unlisted{"3-aaaaaaaa", keyList(3, kA), 1})
		wantReturnsAt(t, rep, "3-aaaaaaaa A")
		noNotSure(t, rep)
	})
	t.Run("the numbers and the sequences agree, in the other direction", func(t *testing.T) {
		// The unlisted set comes first (number 0 and sequence 0), then the ceremony's set holds
		// A which the first list held and the list before it, the unlisted set, does hold.
		rep := runWithUnlisted(t, append(chain, cset{setN(2), keyList(2, kA)}),
			unlisted{"0-aaaaaaaa", seqList("0", kA), 1})
		wantReturnsAt(t, rep)
		noNotSure(t, rep)
	})
}

// A return that one reading shows is a finding, and one that both readings show is one finding.
// Three sets follow the first record: the second ceremony's set P, and two sets that no record lists, Q and R.
// The key K is held by the first list and by Q only. Q returns when it is not first of its place.
func TestRootReturnsOneFindingForAnEntryWhicheverReadingShowsIt(t *testing.T) {
	base := []cset{{"1-aaaaaaaa", keyList(1, kK)}}
	t.Run("only the reading by number shows it", func(t *testing.T) {
		// By sequence: Q (1), P (2), R (3), so Q is first and holds the key of the list before.
		// By number: P (2), R (3), Q (9): Q follows R, which lacks the key.
		rep := runWithUnlisted(t, append(slicesClone(base), cset{"2-aaaaaaaa", keyList(2)}),
			unlisted{"3-aaaaaaaa", keyList(3), 1},
			unlisted{"9-aaaaaaaa", keyList(1, kK), 1},
		)
		wantReturnsAt(t, rep, "9-aaaaaaaa K")
	})
	t.Run("only the reading by sequence shows it", func(t *testing.T) {
		// By number: Q (1), P (2), R (3). By sequence: P (2), R (3), Q (9).
		rep := runWithUnlisted(t, append(slicesClone(base), cset{"2-aaaaaaaa", keyList(2)}),
			unlisted{"3-aaaaaaaa", keyList(3), 1},
			unlisted{"1-aaaaaaab", keyList(9, kK), 1},
		)
		wantReturnsAt(t, rep, "1-aaaaaaab K")
	})
	t.Run("both readings show it: one finding", func(t *testing.T) {
		// P and R swap places between the readings, and Q is last in both.
		rep := runWithUnlisted(t, append(slicesClone(base), cset{"3-aaaaaaaa", keyList(2)}),
			unlisted{"2-aaaaaaaa", keyList(3), 1},
			unlisted{"9-aaaaaaaa", keyList(9, kK), 1},
		)
		got := returnsOf(rep)
		if len(got) != 1 || got[0].Path != listPathOf("9-aaaaaaaa") {
			t.Errorf("findings: %v", lines(got))
		}
	})
	t.Run("the readings show a return of each of two keys", func(t *testing.T) {
		// Q holds K and is last by number; S holds L and is last by sequence.
		rep := runWithUnlisted(t, []cset{{"1-aaaaaaaa", keyList(1, kK, kA)}, {"2-aaaaaaaa", keyList(2)}},
			unlisted{"3-aaaaaaaa", keyList(3), 1},
			unlisted{"9-aaaaaaaa", keyList(1, kK), 1},
			unlisted{"1-aaaaaaab", keyList(9, kA), 1},
		)
		wantReturnsAt(t, rep, "9-aaaaaaaa K", "1-aaaaaaab A")
	})
}

// The package says that where the statements of the order disagree, each reading is judged and the
// detail of the finding says that the order of the sets is not sure (the sets of one place, the
// sequence of the one and the number of the other). Here no two sets share a value, so no set ties
// with another, and the two readings differ only in the order.
func TestRootReturnsTheDetailSaysTheOrderIsNotSureWhenTheStatementsDisagree(t *testing.T) {
	base := []cset{{"1-aaaaaaaa", keyList(1, kK)}, {"2-aaaaaaaa", keyList(2)}}
	t.Run("a return that only the reading by number shows", func(t *testing.T) {
		rep := runWithUnlisted(t, base, unlisted{"3-aaaaaaaa", keyList(3), 1}, unlisted{"9-aaaaaaaa", keyList(1, kK), 1})
		wantReturnsAt(t, rep, "9-aaaaaaaa K")
		allNotSure(t, rep)
	})
	t.Run("a return that only the reading by sequence shows", func(t *testing.T) {
		rep := runWithUnlisted(t, base, unlisted{"3-aaaaaaaa", keyList(3), 1}, unlisted{"1-aaaaaaab", keyList(9, kK), 1})
		wantReturnsAt(t, rep, "1-aaaaaaab K")
		allNotSure(t, rep)
	})
}

func slicesClone(in []cset) []cset { return append([]cset(nil), in...) }

// The tie rule: sets that tie may follow one another in any order, and the first of a group may
// follow any set of the group before.
func TestRootReturnsSetsThatTieMayFollowOneAnotherInAnyOrder(t *testing.T) {
	// Every case has the ceremonies given, and sets that no record lists, all of them named after
	// the first ceremony's record or (claim 0) after no record.
	cases := []struct {
		name  string
		chain []cset
		extra []unlisted
		want  []string
	}{
		{"three sets of one place, the middle one lacks a key that two hold",
			[]cset{{"1-aaaaaaaa", keyList(0, kK)}},
			[]unlisted{{"5-bbbbbbbb", keyList(0), 0}, {"5-cccccccc", keyList(0, kK), 0}},
			[]string{"1-aaaaaaaa K", "5-cccccccc K"}},
		{"a tie group in which every list holds the key",
			[]cset{{"1-aaaaaaaa", keyList(0, kK)}},
			[]unlisted{{"5-bbbbbbbb", keyList(0, kK), 0}},
			nil},
		{"a tie group in which only one list holds the key, and no later list does",
			[]cset{{"1-aaaaaaaa", keyList(0, kK)}, {"2-bbbbbbbb", keyList(0)}},
			[]unlisted{{"5-cccccccc", keyList(0), 0}},
			nil},
		{"a pair of tied sets where the later one adds a key the earlier lacked",
			[]cset{{"1-aaaaaaaa", keyList(0, kA)}},
			[]unlisted{{"5-bbbbbbbb", keyList(0, kA, kB), 0}},
			nil},
		{"the first list of a tie group follows any list of the group before",
			[]cset{{"1-aaaaaaaa", keyList(0, kA)}, {"2-bbbbbbbb", keyList(0, kA)}},
			[]unlisted{{"5-cccccccc", keyList(0, kB), 0}},
			[]string{"2-bbbbbbbb A"}},
		{"every list of the group before holds the key",
			[]cset{{"1-aaaaaaaa", keyList(0, kA)}, {"2-bbbbbbbb", keyList(0, kA)}},
			[]unlisted{{"5-cccccccc", keyList(0, kA), 0}},
			nil},
		{"a list that cannot be read, in a tie group, may come last in it",
			[]cset{{"1-aaaaaaaa", keyList(0, kK)}, {"2-bbbbbbbb", []byte(`{`)}, {"3-cccccccc", keyList(0, kK)}},
			[]unlisted{{"2-zzzzzzzz", keyList(0, kK), 1}},
			[]string{"2-zzzzzzzz K", "3-cccccccc K"}},
		{"a list that cannot be read between lists that hold the key, in a tie group",
			[]cset{{"1-aaaaaaaa", keyList(0, kK)}, {"2-bbbbbbbb", []byte(`{`)}},
			[]unlisted{{"2-yyyyyyyy", keyList(0, kK), 1}, {"2-zzzzzzzz", keyList(0, kK), 1}},
			[]string{"2-yyyyyyyy K", "2-zzzzzzzz K"}},
		{"an unlisted set whose list cannot be read holds no key and judges none",
			[]cset{{"1-aaaaaaaa", keyList(0, kK)}, {"2-bbbbbbbb", keyList(0, kK)}},
			[]unlisted{{"5-cccccccc", []byte(`{`), 0}},
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := runWithUnlisted(t, c.chain, c.extra...)
			wantReturnsAt(t, rep, c.want...)
			allNotSure(t, rep)
			for _, f := range returnsOf(rep) {
				notItself(t, f)
			}
		})
	}
	t.Run("a list that holds the key twice, in a tie group, is not named as its own earlier holder", func(t *testing.T) {
		rep := runWithUnlisted(t,
			[]cset{{"1-aaaaaaaa", keyList(0, kK, ent{"K2", pc, ""})}},
			unlisted{"5-bbbbbbbb", keyList(0), 0}, unlisted{"5-cccccccc", keyList(0, kK), 0})
		wantReturnsAt(t, rep, "1-aaaaaaaa K", "1-aaaaaaaa K2", "5-cccccccc K")
		for _, f := range returnsOf(rep) {
			notItself(t, f)
		}
	})
}

// The detail names at most two sets, in the order of their names, counts the rest, and cuts each
// name to 40 bytes.
func TestRootReturnsTheDetailNamesAtMostTwoSetsAndCountsTheRest(t *testing.T) {
	// n sets tie after no record (claim 0): the first ceremony's set and n-1 sets that no record lists.
	build := func(n int) *Report {
		// A later ceremony holds the key too, and follows the whole group.
		chain := []cset{{"1-aaaaaaaa", keyList(0, kK)}, {"2-zzzzzzzz", keyList(0, kK)}}
		var extra []unlisted
		for i := 1; i < n; i++ {
			l := keyList(0)
			if i%2 == 0 {
				l = keyList(0, kK)
			}
			extra = append(extra, unlisted{fmt.Sprintf("1-aaaaaaa%c", 'a'+i), l, 0})
		}
		return runWithUnlisted(t, chain, extra...)
	}
	t.Run("two sets are named", func(t *testing.T) {
		rep := build(2)
		if len(returnsOf(rep)) == 0 {
			t.Fatal("no finding")
		}
		for _, f := range returnsOf(rep) {
			if !strings.Contains(f.Detail, notSure+" (record 0006, rule 54); among trust/1-aaaaaaaa, trust/1-aaaaaaab;") {
				t.Errorf("the detail %q", f.Detail)
			}
		}
	})
	t.Run("three sets: one more", func(t *testing.T) {
		rep := build(3)
		got := returnsOf(rep)
		if len(got) == 0 {
			t.Fatal("no finding")
		}
		for _, f := range got {
			if want := notSure + " (record 0006, rule 54); among trust/1-aaaaaaaa, trust/1-aaaaaaab and 1 more;"; !strings.Contains(f.Detail, want) {
				t.Errorf("the detail %q lacks %q", f.Detail, want)
			}
		}
	})
	t.Run("seven sets: five more", func(t *testing.T) {
		rep := build(7)
		got := returnsOf(rep)
		if len(got) == 0 {
			t.Fatal("no finding")
		}
		for _, f := range got {
			if want := notSure + " (record 0006, rule 54); among trust/1-aaaaaaaa, trust/1-aaaaaaab and 5 more;"; !strings.Contains(f.Detail, want) {
				t.Errorf("the detail %q lacks %q", f.Detail, want)
			}
		}
	})
	t.Run("a name of 100 bytes is cut to 40 and three dots", func(t *testing.T) {
		long := "1-" + strings.Repeat("a", 98)
		rep := runWithUnlisted(t,
			[]cset{{"1-bbbbbbbb", keyList(0, kK)}, {"2-zzzzzzzz", keyList(0, kK)}},
			unlisted{long, keyList(0), 0}, unlisted{"1-cccccccc", keyList(0, kK), 0})
		got := returnsOf(rep)
		if len(got) == 0 {
			t.Fatal("no finding")
		}
		cut := "trust/" + long[:40] + "..."
		found := false
		for _, f := range got {
			found = found || strings.Contains(f.Detail, cut)
			if strings.Contains(f.Detail, long) {
				t.Errorf("the whole name is in %q", f.Detail)
			}
		}
		if !found {
			t.Errorf("no detail has %q: %v", cut, lines(got))
		}
	})
}

// The words of a finding when the order is not sure keep the form of the others: the code, the path
// of the list, the label, the pin or the fingerprint, and the record and rule.
func TestRootReturnsADetailWhenTheOrderIsNotSureHasTheFormOfTheOthers(t *testing.T) {
	rep := runWithUnlisted(t,
		[]cset{{"5-aaaaaaaa", keyList(0, kA)}},
		unlisted{"5-bbbbbbbb", keyList(0), 0}, unlisted{"5-cccccccc", keyList(0, kA), 0})
	got := returnsOf(rep)
	if len(got) != 2 {
		t.Fatalf("%d findings: %v", len(got), lines(got))
	}
	for _, f := range got {
		if !strings.HasPrefix(f.Line(), "root-returns trust/5-aaaaaaaa") && !strings.HasPrefix(f.Line(), "root-returns trust/5-cccccccc") {
			t.Errorf("the line is %q", f.Line())
		}
		for _, w := range []string{`root key "A" returns: ` + wPin(pa) + "; " + notSure + " (record 0006, rule 54); among trust/5-", "; among trust/5-"} {
			if !strings.Contains(f.Detail, w) {
				t.Errorf("the detail %q lacks %q", f.Detail, w)
			}
		}
		if len(f.Detail) > maxDetail+len("...") {
			t.Errorf("a detail of %d bytes", len(f.Detail))
		}
		if !printable(f.Line()) {
			t.Errorf("the line is not printable ASCII: %q", f.Line())
		}
	}
}

// A finding with both reasons and the shortest names a set may have says both, and the record and
// rule, inside the bound of a detail.
func TestRootReturnsADetailWithBothReasonsAndShortNamesKeepsThemAll(t *testing.T) {
	rep := runWithUnlisted(t,
		[]cset{{"5-a", keyList(0, ent{"A", pa, f1})}},
		unlisted{"5-b", keyList(0), 0}, unlisted{"5-c", keyList(0, ent{"A", pa, f1}), 0})
	got := returnsOf(rep)
	if len(got) != 2 {
		t.Fatalf("%d findings: %v", len(got), lines(got))
	}
	for _, f := range got {
		for _, w := range []string{"its pin " + short16(pa), "its OpenPGP fingerprint " + f1[:16], "(record 0006, rule 54)"} {
			if !strings.Contains(f.Detail, w) {
				t.Errorf("the detail %q lacks %q", f.Detail, w)
			}
		}
	}
}

// The names of the sets are cut to 40 bytes, so that the bound of a detail cuts the end of a name
// and not the key that returned: with names as long as a folder may be named, the pin is still
// there.
func TestRootReturnsACutDetailKeepsItsPin(t *testing.T) {
	long := func(c string) string { return "1-" + strings.Repeat(c, 200) }
	rep := runWithUnlisted(t,
		[]cset{{long("a"), keyList(0, kA)}},
		unlisted{long("b"), keyList(0), 0}, unlisted{long("c"), keyList(0, kA), 0},
		unlisted{long("d"), keyList(0, kA), 0})
	got := returnsOf(rep)
	if len(got) == 0 {
		t.Fatal("no finding")
	}
	for _, f := range got {
		if len(f.Detail) > maxDetail+len("...") {
			t.Errorf("a detail of %d bytes", len(f.Detail))
		}
		if w := "its pin " + short16(pa); !strings.Contains(f.Detail, w) {
			t.Errorf("the detail %q lacks %q", f.Detail, w)
		}
		if !printable(f.Line()) || strings.ContainsAny(f.Line(), "\r\n") {
			t.Errorf("the line is not one line of printable ASCII: %q", f.Line())
		}
	}
}

// The work for sets that tie stays bounded: two sorts and two passes, whatever the size of the
// group that ties.
func TestRootReturnsAGroupOfTiedSetsOfTheLargestSizeIsBounded(t *testing.T) {
	const sets = 10000
	build := func(entries func(i int) []ent) *mnode {
		lists := make(map[string][]byte, sets)
		for i := 0; i < sets; i++ {
			lists[fmt.Sprintf("5-%08x", i)] = keyList(0, entries(i)...)
		}
		return memBundle(lists)
	}
	var shared []ent
	for j := 0; j < 26; j++ {
		shared = append(shared, ent{string(rune('A' + j)), pinOf(9000 + j), ""})
	}
	cases := map[string]func(i int) []ent{
		"every list holds the same 26 keys": func(int) []ent { return shared },
		"every list holds 26 keys of its own": func(i int) []ent {
			var es []ent
			for j := 0; j < 26; j++ {
				es = append(es, ent{string(rune('A' + j)), pinOf(20000 + i*26 + j), ""})
			}
			return es
		},
		"half the lists hold the keys and half hold none": func(i int) []ent {
			if i%2 == 0 {
				return shared
			}
			return nil
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			rep, err := runMem(t, build(f))
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if d := time.Since(start); d > 60*time.Second {
				t.Errorf("took %v", d)
			}
			checkReport(t, rep)
		})
	}
	t.Run("many sets with no number", func(t *testing.T) {
		lists := map[string][]byte{}
		for i := 0; i < 20000; i++ {
			lists[fmt.Sprintf("x-%08x", i)] = keyList(int64(i%3), ent{"A", pinOf(i % 50), ""})
		}
		rep, err := runMem(t, memBundle(lists))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		checkReport(t, rep)
	})
	t.Run("65,000 lists of four entries in one place", func(t *testing.T) {
		const lists = 65000
		m := map[string][]byte{}
		for i := 0; i < lists; i++ {
			m[fmt.Sprintf("7-%08x", i)] = keyList(0,
				ent{"A", pinOf(i % 7), ""}, ent{"B", pinOf(100 + i%13), ""}, ent{"C", pinOf(200 + i%17), ""}, ent{"D", pinOf(300 + i), ""})
		}
		start := time.Now()
		rep, err := runMem(t, memBundle(m))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if d := time.Since(start); d > 60*time.Second {
			t.Errorf("took %v", d)
		}
		checkReport(t, rep)
	})
}
