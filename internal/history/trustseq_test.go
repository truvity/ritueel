//go:build linux || darwin

package history

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The finding trust-sequence (record 0006, rules 14 and 21) and the two ranges of a number: the
// trust sets that ordinary ceremony records list, taken in the order of the chain of records, hold
// in their folder name the sequence of their root list, and each number is higher than the number
// before it; a sequence below 1 is anchor-unknown; a folder number of 0 is no trust number.

const seqWords = "record 0006, rules 14 and 21"

// numbersChain builds a chain with one ceremony for each spec: the set is named "<num>-" and eight
// letters that differ from one ceremony to the next, and its list holds the sequence of the spec
// (no sequence member for a spec that says none). It returns the bundle and the names.
func numbersChain(t testing.TB, specs ...seqSet) (*bundle, []string) {
	t.Helper()
	b, names := chainOf(t, specs)
	return b, names
}

func trustSeqFindings(rep *Report) []Finding {
	var out []Finding
	for _, f := range rep.Findings {
		if f.Code == TrustSequence {
			out = append(out, f)
		}
	}
	return out
}

func countCode(rep *Report, c Code) int {
	n := 0
	for _, f := range rep.Findings {
		if f.Code == c {
			n++
		}
	}
	return n
}

// wantExactly fails unless the findings of the report are exactly want, in any order.
func wantExactly(t testing.TB, rep *Report, want ...wf) {
	t.Helper()
	got, w := sortWF(findingsOf(rep)), sortWF(want)
	if !slices.Equal(got, w) {
		t.Errorf("findings:\n got %v\nwant %v", got, w)
	}
	checkForm(t, rep)
}

// Three sets, 1, 2 and 2, written by three ceremonies in this order, each sequence equal to its
// folder number: one finding for the third, which is the failing exit meaning.
func TestTrustSequenceThreeSetsWithTheSecondNumberTwice(t *testing.T) {
	b, names := numbersChain(t, nums(1, 2, 2)...)
	rep := b.run()
	wantExactly(t, rep, wf{TrustSequence, "trust/" + names[2]})
	wantReasons(t, rep, []Code{TrustSequence}, nil)
	if rep.Clean() {
		t.Error("Clean() with a number that repeats")
	}
	if !TrustSequence.Fails() || TrustSequence.Notice() {
		t.Errorf("Fails() = %v, Notice() = %v: the finding ends the command with exit code 3", TrustSequence.Fails(), TrustSequence.Notice())
	}
	f := trustSeqFindings(rep)[0]
	for _, w := range []string{"2, is not higher than 2", "trust/" + names[1], seqWords} {
		if !strings.Contains(f.Detail, w) {
			t.Errorf("the detail %q lacks %q", f.Detail, w)
		}
	}
	if want := "trust-sequence trust/" + names[2] + ": "; !strings.HasPrefix(f.Line(), want) {
		t.Errorf("the line %q does not begin with %q", f.Line(), want)
	}
	if strings.Contains(f.Detail, "is not the sequence of its root list") {
		t.Errorf("the detail %q says the sequence differs, and it does not", f.Detail)
	}
	if in := b.inspect(); in.State != nil || in.OrderErr != nil {
		t.Errorf("State %v and OrderErr %v for a report with a failing finding", in.State, in.OrderErr)
	}
}

// The numbers of a chain, each sequence equal to its number: the sets that have a finding (by their
// place in the chain). A number is compared with the judged set directly before it, and a skip is
// not a finding.
func TestTrustSequenceTheNumbersOfAChain(t *testing.T) {
	cases := []struct {
		name string
		nums []int64
		bad  []int // places, from 0, of the sets that have the finding
	}{
		{"one set", []int64{1}, nil},
		{"one set with a high number", []int64{40}, nil},
		{"1, 2, 3", []int64{1, 2, 3}, nil},
		{"a skip: 1, 3", []int64{1, 3}, nil},
		{"skips: 1, 5, 9, 30", []int64{1, 5, 9, 30}, nil},
		{"a big skip: 1, 1000000", []int64{1, 1000000}, nil},
		{"a number that goes down: 1, 3, 2", []int64{1, 3, 2}, []int{2}},
		{"two numbers that are one: 1, 1", []int64{1, 1}, []int{1}},
		{"down at once: 2, 1", []int64{2, 1}, []int{1}},
		{"1, 2, 2, 3", []int64{1, 2, 2, 3}, []int{2}},
		{"1, 3, 2, 3: the number before is the set before, not the highest", []int64{1, 3, 2, 3}, []int{2}},
		{"5, 2, 3, 4: one fall, then growth", []int64{5, 2, 3, 4}, []int{1}},
		{"3, 2, 1: two falls", []int64{3, 2, 1}, []int{1, 2}},
		{"1, 2, 2, 2: three that repeat", []int64{1, 2, 2, 2}, []int{2, 3}},
		{"9, 8, 17: the last grows", []int64{9, 8, 17}, []int{1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, names := numbersChain(t, nums(c.nums...)...)
			rep := b.run()
			var want []wf
			for _, i := range c.bad {
				want = append(want, wf{TrustSequence, "trust/" + names[i]})
			}
			wantExactly(t, rep, want...)
			if rep.Clean() != (len(c.bad) == 0) {
				t.Errorf("Clean() = %v with %d findings", rep.Clean(), len(c.bad))
			}
			if len(c.bad) == 0 {
				wantState(t, b.inspect(), names...)
			} else if in := b.inspect(); in.State != nil || in.OrderErr != nil {
				t.Errorf("State %v, OrderErr %v for a failing report", in.State, in.OrderErr)
			}
			if got := modelTrustSeq(csetsOf(nums(c.nums...))); len(got) != len(c.bad) {
				t.Errorf("the model finds %d, the table says %d", len(got), len(c.bad))
			}
		})
	}
}

// A folder number that is not the sequence of its list: folder 2 with the sequence 3, folder 3
// with the sequence 2, a number that is both too low and not the sequence.
func TestTrustSequenceTheNumberIsTheSequenceOfItsList(t *testing.T) {
	const notSeq = "is not the sequence of its root list"
	const notHigher = "is not higher than"
	cases := []struct {
		name     string
		specs    []seqSet
		bad      []int
		reasons  []string
		excludes []string
	}{
		{"folder 2, sequence 3", []seqSet{{num: 1, seq: 1}, {num: 2, seq: 3}}, []int{1}, []string{notSeq, "2, is not the sequence of its root list, 3"}, []string{notHigher}},
		{"folder 3, sequence 2", []seqSet{{num: 1, seq: 1}, {num: 3, seq: 2}}, []int{1}, []string{notSeq, "3, is not the sequence of its root list, 2"}, []string{notHigher}},
		{"the first set has the sequence of another number", []seqSet{{num: 1, seq: 7}, {num: 2, seq: 2}}, []int{0}, []string{notSeq}, []string{notHigher}},
		{"both: the number repeats and is not the sequence", []seqSet{{num: 1, seq: 1}, {num: 1, seq: 2}}, []int{1}, []string{notSeq, notHigher}, nil},
		{"a number that falls and the sequence that follows it", []seqSet{{num: 5, seq: 5}, {num: 3, seq: 3}}, []int{1}, []string{notHigher}, []string{notSeq}},
		{"no sequence in two lists: only the order is held", []seqSet{{num: 1, none: true}, {num: 2, none: true}}, nil, nil, nil},
		{"no sequence and a number that repeats", []seqSet{{num: 1, none: true}, {num: 1, none: true}}, []int{1}, []string{notHigher}, []string{notSeq}},
		{"no sequence in the middle", []seqSet{{num: 1, seq: 1}, {num: 2, none: true}, {num: 3, seq: 3}}, nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, names := numbersChain(t, c.specs...)
			rep := b.run()
			var want []wf
			for _, i := range c.bad {
				want = append(want, wf{TrustSequence, "trust/" + names[i]})
			}
			// A list with no sequence is not compared with its name; it is anchor-unknown.
			for i, s := range c.specs {
				if s.none {
					want = append(want, wf{AnchorUnknown, listPathOf(names[i])})
				}
			}
			wantExactly(t, rep, want...)
			for _, f := range trustSeqFindings(rep) {
				for _, w := range append(c.reasons, seqWords) {
					if !strings.Contains(f.Detail, w) {
						t.Errorf("the detail %q lacks %q", f.Detail, w)
					}
				}
				for _, w := range c.excludes {
					if strings.Contains(f.Detail, w) {
						t.Errorf("the detail %q holds %q", f.Detail, w)
					}
				}
			}
			if c.name == "both: the number repeats and is not the sequence" && !strings.Contains(trustSeqFindings(rep)[0].Detail, "; ") {
				t.Errorf("two reasons in one detail are not joined: %q", trustSeqFindings(rep)[0].Detail)
			}
		})
	}
}

// The order is the chain of records and never the numbers and never the names of the ceremony
// folders: a chain whose folder names run against it, and whose numbers grow, is clean; the same
// chain with numbers that fall is found where the chain puts the fall.
func TestTrustSequenceTheOrderIsTheChainNotTheFolderNames(t *testing.T) {
	build := func(t *testing.T, numbers ...int64) (*bundle, []string) {
		b := newBundle(t)
		var names []string
		for i, n := range numbers {
			name := fmt.Sprintf("%d-%s", n, strings.Repeat(string(rune('a'+i)), 8))
			names = append(names, name)
			// the first ceremony of the chain has the last folder name
			folder := fmt.Sprintf("2026%04dT100000Z-apply", 9000-i)
			b.apply(folderName(folder), withSet(name, keyList(n, kA)))
		}
		return b, names
	}
	b, names := build(t, 1, 2, 3, 4)
	rep := b.run()
	wantExactly(t, rep)
	wantState(t, b.inspect(), names...)
	b, names = build(t, 1, 3, 2, 4)
	wantExactly(t, b.run(), wf{TrustSequence, "trust/" + names[2]})
}

// A listing in any order gives the same findings.
func TestTrustSequenceDoesNotDependOnTheOrderOfAListing(t *testing.T) {
	b, _ := numbersChain(t, nums(1, 3, 2, 2, 5, 4)...)
	b.mem = loadMem(t, b.dir)
	b.dir = ""
	plain, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	rev, err := runFS(t, listsReversed{memFS{b.mem}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := trustSeqFindings(rev), trustSeqFindings(plain); !slices.Equal(got, want) || len(want) != 3 {
		t.Errorf("a reversed listing gives\n %v\nand the plain one\n %v (three expected)", got, want)
	}
}

// The sets of a fork are left out, whatever their numbers say; the set before the fork is judged.
func TestTrustSequenceLeavesOutTheSetsOfAFork(t *testing.T) {
	t.Run("two records name one record and list sets with one number", func(t *testing.T) {
		b := newBundle(t)
		a := b.apply()
		b.apply(setName("2-aaaaaaaa"))
		b.apply(setName("2-bbbbbbbb"), prev(a.digest))
		rep := b.run()
		wantExactly(t, rep, wf{Fork, folderPath(a)})
		lacks(t, rep, TrustSequence)
	})
	t.Run("numbers that fall in a fork", func(t *testing.T) {
		b := newBundle(t)
		a := b.apply(withSet("5-aaaaaaaa", keyList(5, kA)))
		b.apply(withSet("3-aaaaaaaa", keyList(3, kA)))
		b.apply(prev(a.digest), withSet("1-bbbbbbbb", keyList(1, kA)))
		rep := b.run()
		lacks(t, rep, TrustSequence)
		has(t, rep, Fork, folderPath(a))
	})
	t.Run("a fork whose other record lists no set", func(t *testing.T) {
		// The set of the one record that lists one stands alone at its place, and the fork is still
		// the reason to leave it out: its number is not judged, however wrong.
		b := newBundle(t)
		a := b.apply(withSet(setN(1), keyList(1, kA)))
		b.apply(withSet("9-aaaaaaaa", keyList(3, kA)))
		b.apply(noSet, prev(a.digest))
		rep := b.run()
		has(t, rep, Fork, folderPath(a))
		lacks(t, rep, TrustSequence)
	})
	t.Run("the set before the fork is judged", func(t *testing.T) {
		b := newBundle(t)
		a := b.apply(withSet("4-aaaaaaaa", keyList(9, kA))) // a number that is not its sequence
		b.apply(withSet("5-aaaaaaaa", keyList(5, kA)))
		b.apply(prev(a.digest), withSet("5-bbbbbbbb", keyList(5, kA)))
		rep := b.run()
		has(t, rep, TrustSequence, "trust/4-aaaaaaaa")
		if n := len(trustSeqFindings(rep)); n != 1 {
			t.Errorf("%d findings of trust-sequence, want 1: %v", n, findingsOf(rep))
		}
	})
}

// The sets that a closing record lists are left out, and they do not count as the set before: the
// set after them is compared with the set before them.
func TestTrustSequenceLeavesOutTheSetsOfAClosingRecord(t *testing.T) {
	t.Run("a leftover set with a number above the later ones", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		stopped := b.unfinished(withSet(setN(9), keyList(9, kA)))
		b.apply(withSet(setN(2), keyList(2, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		b.apply(withSet(setN(3), keyList(3, kA)))
		rep := b.run()
		wantExactly(t, rep)
		lacks(t, rep, TrustSequence)
	})
	t.Run("a leftover set with the number of another set", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet("3-aaaaaaaa", keyList(3, kA)))
		stopped := b.unfinished(withSet("3-bbbbbbbb", keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		wantExactly(t, b.run())
	})
	t.Run("a leftover set whose number is not its sequence", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		stopped := b.unfinished(withSet(setN(2), keyList(7, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		wantExactly(t, b.run())
	})
	t.Run("a set after the closing record is compared with the set before the stopped one", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(5), keyList(5, kA)))
		stopped := b.unfinished(withSet(setN(9), keyList(9, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		b.apply(withSet(setN(4), keyList(4, kA)))
		wantExactly(t, b.run(), wf{TrustSequence, "trust/" + setN(4)})
	})
}

// An unlisted set and an unfinished ceremony are not judged by this finding.
func TestTrustSequenceDoesNotJudgeUnlistedSetsOrUnfinishedCeremonies(t *testing.T) {
	t.Run("an unfinished ceremony with the number of a set", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		u := b.unfinished(withSet("1-bbbbbbbb", keyList(1, kA)), func(r *rec) {
			r.plan.TrustSequence = ptr(int64(1)) // the open attempt is for the number 1
			r.refresh()
		})
		rep := b.run()
		wantExactly(t, rep, wf{UnfinishedCeremony, "trust/" + u.set})
	})
	t.Run("an unfinished ceremony whose list holds another sequence", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		u := b.unfinished(withSet(setN(2), keyList(8, kA)))
		wantExactly(t, b.run(), wf{UnfinishedCeremony, "trust/" + u.set})
	})
	t.Run("an unlisted set with a number below the others", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(3), keyList(3, kA)))
		b.mkdir("trust/1-3fa9c1d2")
		wantExactly(t, b.run(), wf{TrustSetUnlisted, "trust/1-3fa9c1d2"})
	})
	t.Run("an unlisted set between two listed ones does not change what is before", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		b.mkdir("trust/7-3fa9c1d2")
		b.apply(withSet(setN(2), keyList(2, kA)))
		wantExactly(t, b.run(), wf{TrustSetUnlisted, "trust/7-3fa9c1d2"})
	})
}

// A set that two records list stands at two places, and a set whose record is not on the chain has
// none: they are left out. The sets that one record lists together are judged (see
// trustseq_group_test.go).
func TestTrustSequenceLeavesOutSetsThatHaveNoPlaceOfTheirOwn(t *testing.T) {
	t.Run("one record lists two sets with one number: the second of them is found", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		b.apply(withSets(cset{"2-aaaaaaaa", keyList(2, kA)}, cset{"2-bbbbbbbb", keyList(2, kA)}))
		wantExactly(t, b.run(), wf{TrustSequence, "trust/2-bbbbbbbb"})
	})
	t.Run("the set after a record that lists two is compared with the last of the two", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		b.apply(withSets(cset{"2-aaaaaaaa", keyList(2, kA)}, cset{"2-bbbbbbbb", keyList(2, kA)}))
		b.apply(withSet("2-cccccccc", keyList(2, kA)))
		// 2-b is not higher than 2-a, and 2-c is not higher than 2-b, the set before it
		wantExactly(t, b.run(), wf{TrustSequence, "trust/2-bbbbbbbb"}, wf{TrustSequence, "trust/2-cccccccc"})
	})
	t.Run("a set that two records list", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kA)})
		b.apply(withSet(setN(1), keyList(1, kA)))
		rep := b.run()
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
		lacks(t, rep, TrustSequence)
	})
	t.Run("a set that two records list with another record before each is left out", func(t *testing.T) {
		// The number of the set is not its sequence, and the set stands at two places: the finding
		// of the anchor says so, and trust-sequence does not judge a place that is not sure.
		b := chainBundle(t, false, cset{"1-aaaaaaaa", keyList(9, kA)}, cset{setN(2), keyList(2, kA)})
		b.apply(withSet("1-aaaaaaaa", keyList(9, kA)))
		rep := b.run()
		has(t, rep, AnchorUnknown, listPathOf("1-aaaaaaaa"))
		lacks(t, rep, TrustSequence)
	})
	t.Run("a bundle with records and none of them on the chain", func(t *testing.T) {
		b := newBundle(t)
		b.apply(prev(digestA), withSet("2-aaaaaaaa", keyList(2, kA)))
		b.apply(withSet("1-bbbbbbbb", keyList(1, kA)), prev(digestB))
		rep := b.run()
		lacks(t, rep, TrustSequence)
		has(t, rep, ChainBroken, folderPath(b.recs[0]))
	})
}

// A set that has no root list (a personal bundle's set) has a number in its name and no sequence.
func TestTrustSequenceASetWithNoRootListIsHeldToTheOrder(t *testing.T) {
	noList := func(r *rec) {
		delete(r.artifacts, "trust/"+r.set+"/root-list.json")
		r.refresh()
	}
	t.Run("in order", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		b.apply(noList)
		b.apply()
		wantExactly(t, b.run())
	})
	t.Run("a number that repeats", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(2), keyList(2, kA)))
		r := b.apply(setName("2-bbbbbbbb"), noList)
		wantExactly(t, b.run(), wf{TrustSequence, "trust/" + r.set})
	})
}

// A sequence below 1 is anchor-unknown with the case in the detail; the list is read all the same,
// so a key that it holds counts for the lists after it (it hides nothing).
func TestAnchorUnknownASequenceBelowOne(t *testing.T) {
	cases := []struct {
		seq   string
		words []string
	}{
		{"0", []string{"a sequence of 0", "at least 1", "its keys are still read"}},
		{"-1", []string{"a sequence of -1", "at least 1"}},
		{"-2", []string{"a sequence of -2"}},
		{"-9007199254740991", []string{"a sequence of -9007199254740991"}},
	}
	for _, c := range cases {
		t.Run(c.seq, func(t *testing.T) {
			b := chainBundle(t, false, cset{setN(1), seqList(c.seq, kA)})
			rep := b.run()
			// folder 1 is not the sequence of its list, too
			wantExactly(t, rep, wf{AnchorUnknown, listPathOf(setN(1))}, wf{TrustSequence, "trust/" + setN(1)})
			d := detail(rep, AnchorUnknown, listPathOf(setN(1)))
			for _, w := range c.words {
				if !strings.Contains(d, w) {
					t.Errorf("the detail %q lacks %q", d, w)
				}
			}
			wantReasons(t, rep, []Code{AnchorUnknown, TrustSequence}, nil)
		})
	}
	t.Run("a list with the sequence 1 is no finding", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), seqList("1", kA)})
		wantExactly(t, b.run())
	})
	t.Run("the sequence 0 of a list whose anchor is wrong gives two findings of the anchor", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		b.apply(withSet("0-aaaaaaaa", []byte(`{"last_record_sha256":"`+digestB+`","roots":[],"sequence":0,"version":1}`)))
		rep := b.run()
		var n int
		details := map[string]bool{}
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown && f.Path == listPathOf("0-aaaaaaaa") {
				n++
				details[f.Detail] = true
			}
		}
		if n != 2 || len(details) != 2 {
			t.Errorf("%d findings of anchor-unknown at the list, %d different details; want two of each: %v", n, len(details), findingsOf(rep))
		}
	})
	t.Run("the finding is refused by exit code 3 and has no State", func(t *testing.T) {
		b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("0", kA)})
		in := b.inspect()
		wantFailed(t, in, []wf{{AnchorUnknown, listPathOf("0-aaaaaaaa")}})
		if !AnchorUnknown.Fails() {
			t.Error("anchor-unknown does not fail")
		}
	})
}

// A sequence that no reader of root lists takes (outside the range that RFC 8785 can hold, which
// holds the lowest 64-bit number and one above the highest) is anchor-unknown: the list cannot be
// read, and the case is in the detail.
func TestAnchorUnknownASequenceTheListCannotHold(t *testing.T) {
	for _, seq := range []string{"-9223372036854775808", "-9007199254740992", "9007199254740992", "9223372036854775807", "9223372036854775808", "-9223372036854775809", "99999999999999999999999"} {
		t.Run(seq, func(t *testing.T) {
			b := chainBundle(t, false, cset{setN(1), seqList(seq, kA)})
			rep := b.run()
			wantExactly(t, rep, wf{AnchorUnknown, listPathOf(setN(1))})
			if d := detail(rep, AnchorUnknown, listPathOf(setN(1))); !strings.Contains(d, "the root list cannot be read: ") || strings.Contains(d, "its keys are still read") {
				t.Errorf("the detail %q does not say that the list cannot be read", d)
			}
		})
	}
	t.Run("the highest number a list can hold is a sequence", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), seqList("9007199254740991", kA)})
		wantExactly(t, b.run(), wf{TrustSequence, "trust/" + setN(1)}) // folder 1 is not that number
	})
	t.Run("the highest number as the folder number and the sequence", func(t *testing.T) {
		// a name has at most fifteen digits, so no folder name is that number
		name := "9007199254740991-aaaaaaaa"
		b := chainBundle(t, false, cset{name, seqList("9007199254740991", kA)})
		rep := b.run()
		wantExactly(t, rep, wf{TrustSequence, "trust/" + name})
	})
}

// The keys of a list with a sequence below 1 are read: a key that left the root list and comes
// back on such a list is found, and a key that such a list holds is held for the list after it.
func TestRootReturnsThroughAListWithASequenceBelowOne(t *testing.T) {
	for _, seq := range []string{"0", "-1", "-9007199254740991"} {
		t.Run("a return on a list with the sequence "+seq, func(t *testing.T) {
			b := chainBundle(t, false,
				cset{setN(1), keyList(1, kA, kB)},
				cset{setN(2), keyList(2, kB)},
				cset{setN(3), seqList(seq, kA, kB)})
			rep := b.run()
			// the finding of the return is at the LATER set, the one that brings the key back, and
			// nowhere else; the list with the low sequence is also anchor-unknown and not its number
			wantExactly(t, rep,
				wf{RootReturns, listPathOf(setN(3))},
				wf{AnchorUnknown, listPathOf(setN(3))},
				wf{TrustSequence, "trust/" + setN(3)})
			rs := returnsOf(rep)
			if len(rs) != 1 || rs[0].Path != listPathOf(setN(3)) || !strings.HasPrefix(rs[0].Detail, `root key "A"`) {
				t.Errorf("returns %v, want one, for the key A, at %s", rs, listPathOf(setN(3)))
			}
			wantReasons(t, rep, []Code{AnchorUnknown, RootReturns, TrustSequence}, nil)
		})
		t.Run("a list with the sequence "+seq+" in the middle hides no key", func(t *testing.T) {
			// list 2 holds A: the list before list 3 holds A, so A on list 3 is no return.
			b := chainBundle(t, false,
				cset{setN(1), keyList(1, kA)},
				cset{setN(2), seqList(seq, kA)},
				cset{setN(3), keyList(3, kA)})
			rep := b.run()
			// no return anywhere: the keys of list 2 are read, so list 3 brings nothing back
			wantExactly(t, rep, wf{AnchorUnknown, listPathOf(setN(2))}, wf{TrustSequence, "trust/" + setN(2)})
			lacks(t, rep, RootReturns)
		})
		t.Run("a list with the sequence "+seq+" that drops a key makes a return later", func(t *testing.T) {
			// list 2 drops A; A on list 3 is a return, whatever the sequence of list 2.
			b := chainBundle(t, false,
				cset{setN(1), keyList(1, kA, kB)},
				cset{setN(2), seqList(seq, kB)},
				cset{setN(3), keyList(3, kA, kB)})
			rep := b.run()
			wantExactly(t, rep,
				wf{AnchorUnknown, listPathOf(setN(2))},
				wf{TrustSequence, "trust/" + setN(2)},
				wf{RootReturns, listPathOf(setN(3))})
			if rs := returnsOf(rep); len(rs) != 1 || rs[0].Path != listPathOf(setN(3)) || !strings.HasPrefix(rs[0].Detail, `root key "A"`) {
				t.Errorf("returns %v, want one, for the key A, at %s", rs, listPathOf(setN(3)))
			}
		})
	}
}

// A folder number of 0 is no trust number.
func TestTrustNumberZeroIsNoTrustNumber(t *testing.T) {
	t.Run("an unlisted set 0-", func(t *testing.T) {
		b := newBundle(t)
		b.apply(noSet)
		b.mkdir("trust/0-3fa9c1d2")
		rep := b.run()
		wantExactly(t, rep, wf{TrustSetUnlisted, "trust/0-3fa9c1d2"})
		if d := detail(rep, TrustSetUnlisted, "trust/0-3fa9c1d2"); !strings.Contains(d, "its name has no trust number") {
			t.Errorf("the detail %q does not say that the name has no trust number", d)
		}
	})
	t.Run("an unlisted set 0- with an open attempt of that number", func(t *testing.T) {
		b := newBundle(t)
		u := b.unfinished(setName("0-3fa9c1d3"), func(r *rec) {
			r.plan.TrustSequence = ptr(int64(0))
			r.refresh()
		})
		has(t, b.run(), TrustSetUnlisted, setPath(u))
	})
	t.Run("an unlisted set 0- and an unlisted set 1- differ", func(t *testing.T) {
		b := newBundle(t)
		b.apply(noSet)
		b.mkdir("trust/1-3fa9c1d2")
		b.mkdir("trust/0-3fa9c1d2")
		rep := b.run()
		wantExactly(t, rep, wf{TrustSetUnlisted, "trust/1-3fa9c1d2"}, wf{TrustSetUnlisted, "trust/0-3fa9c1d2"})
		if d := detail(rep, TrustSetUnlisted, "trust/1-3fa9c1d2"); strings.Contains(d, "no trust number") {
			t.Errorf("the set 1- has a trust number, and the detail says %q", d)
		}
	})
	t.Run("a listed set 0- with the sequence 0 gives the finding of the sequence only", func(t *testing.T) {
		b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("0", kA)})
		wantExactly(t, b.run(), wf{AnchorUnknown, listPathOf("0-aaaaaaaa")})
	})
	t.Run("a listed set 0- with the sequence 1 gives trust-sequence", func(t *testing.T) {
		b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("1", kA)})
		rep := b.run()
		wantExactly(t, rep, wf{TrustSequence, "trust/0-aaaaaaaa"})
		if d := detail(rep, TrustSequence, "trust/0-aaaaaaaa"); !strings.Contains(d, "0, is not the sequence of its root list, 1") {
			t.Errorf("the detail is %q", d)
		}
	})
	t.Run("a listed set 0- that has no sequence is not judged by its name", func(t *testing.T) {
		// the folder number of a listed set is held to the sequence of its list, and a list with no
		// sequence has none to compare: it is anchor-unknown, and not trust-sequence
		b := chainBundle(t, false, cset{"0-aaaaaaaa", rootsJSON(0, kA)})
		wantExactly(t, b.run(), wf{AnchorUnknown, listPathOf("0-aaaaaaaa")})
	})
	t.Run("the set 0- is the number before in the order", func(t *testing.T) {
		b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("0", kA)}, cset{setN(1), keyList(1, kA)})
		wantExactly(t, b.run(), wf{AnchorUnknown, listPathOf("0-aaaaaaaa")})
	})
	t.Run("the lowest set is the lowest from 1", func(t *testing.T) {
		// A set whose list has no last_record_sha256 is the first one when it has the lowest trust
		// number of all: 0 is no trust number, so the set 0- does not make the set 1- a later one.
		b := newBundle(t)
		b.apply(noSet)
		b.mkdir("trust/0-3fa9c1d2")
		b.put("trust/0-3fa9c1d2/root-list.json", rootListBytes("0-3fa9c1d2", ""))
		b.put("trust/1-3fa9c1d2/root-list.json", rootListBytes("1-3fa9c1d2", ""))
		rep := b.run()
		has(t, rep, TrustSetUnlisted, "trust/0-3fa9c1d2")
		has(t, rep, TrustSetUnlisted, "trust/1-3fa9c1d2")
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown && f.Path == listPathOf("1-3fa9c1d2") {
				t.Errorf("the set 1- is the lowest set from 1 and has no anchor: %q", f.Line())
			}
		}
	})
}

// The spellings of a folder number: with a leading zero, a plus sign, at most fifteen digits, the
// highest 64-bit number and one above it. A name that is not "digits without a leading zero, at
// most fifteen, then a hyphen" has no trust number: unlisted it is trust-set-unlisted, listed it is
// trust-sequence.
func TestTrustNumberSpellings(t *testing.T) {
	type spell struct {
		prefix string
		number bool // a trust number: digits, no leading zero, at most fifteen, from 1 up
		ok     bool // a name that the rule for names allows
	}
	spellings := []spell{
		{"1", true, true}, {"2", true, true}, {"10", true, true}, {"123456789012345", true, true}, {"999999999999999", true, true},
		{"01", false, true}, {"007", false, true}, {"00", false, true}, {"0000000000001", false, true}, {"-1", false, true},
		{"", false, true}, {"1000000000000000", false, true}, {"1234567890123456", false, true},
		{"9223372036854775807", false, true}, {"9223372036854775808", false, true}, // the highest 64-bit number, and one above it
		{"18446744073709551615", false, true}, {"18446744073709551616", false, true}, {"99999999999999999999", false, true},
		{"1e3", false, true}, {"0x1", false, true}, {"1_0", false, true}, {"1.5", false, true},
		{"+1", false, false}, {"+0", false, false}, {" 1", false, false}, {"\u0967", false, false},
	}
	for _, sp := range spellings {
		name := sp.prefix + "-3fa9c1d2"
		t.Run("unlisted "+name, func(t *testing.T) {
			b := newBundle(t)
			b.apply(noSet)
			b.mkdir("trust/" + name)
			rep := b.run()
			if !sp.ok {
				if countCode(rep, UnexpectedName) == 0 || rep.Clean() {
					t.Errorf("a name the rule for names refuses: %v", findingsOf(rep))
				}
				lacks(t, rep, TrustSequence)
				return
			}
			wantExactly(t, rep, wf{TrustSetUnlisted, "trust/" + name})
			d := detail(rep, TrustSetUnlisted, "trust/"+name)
			if sp.number && strings.Contains(d, "no trust number") {
				t.Errorf("%s is a trust number, and the detail says %q", name, d)
			}
			if !sp.number && !strings.Contains(d, "its name has no trust number") {
				t.Errorf("%s is no trust number, and the detail says %q", name, d)
			}
		})
		t.Run("listed "+name, func(t *testing.T) {
			// The list holds a sequence (the number of the name when it has one), so that the
			// findings are those of the name.
			list := keyList(1, kA)
			if sp.number {
				n, err := strconv.ParseInt(sp.prefix, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				list = keyList(n, kA)
			}
			b := newBundle(t)
			b.apply(withSet(name, list))
			rep := b.run()
			if !sp.ok {
				if countCode(rep, UnexpectedName) == 0 || rep.Clean() {
					t.Errorf("a name the rule for names refuses: %v", findingsOf(rep))
				}
				lacks(t, rep, TrustSequence)
				return
			}
			if sp.number {
				wantExactly(t, rep)
				return
			}
			wantExactly(t, rep, wf{TrustSequence, "trust/" + name})
			if d := detail(rep, TrustSequence, "trust/"+name); !strings.Contains(d, "its name has no trust number") {
				t.Errorf("the detail is %q", d)
			}
		})
	}
	t.Run("a name with no trust number is not the number before", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{"01-aaaaaaaa", keyList(2, kA)}, cset{setN(2), keyList(2, kA)})
		wantExactly(t, b.run(), wf{TrustSequence, "trust/01-aaaaaaaa"})
	})
	t.Run("fifteen digits and the same sequence is clean", func(t *testing.T) {
		name := "999999999999999-aaaaaaaa"
		b := chainBundle(t, false, cset{name, keyList(999999999999999, kA)})
		wantExactly(t, b.run())
	})
}

// A sequence outside the range that the strict reader of JSON takes (more than 2^53-1 or less than
// minus that, the lowest 64-bit number among them) makes the list one that cannot be read: it is
// anchor-unknown with that reason, the bundle fails (exit code 3), and the keys of the list are NOT
// read. A sequence of 0 or -1 is still read, so its keys count. No lenient reader is added.
func TestRootReturnsKeysOfAListWithASequenceTheListCannotHold(t *testing.T) {
	lowest := "-9223372036854775808"
	t.Run("a return on a list with the lowest 64-bit sequence is not found: the list cannot be read", func(t *testing.T) {
		b := chainBundle(t, false,
			cset{setN(1), keyList(1, kA, kB)},
			cset{setN(2), keyList(2, kB)},
			cset{setN(3), seqList(lowest, kA, kB)})
		rep := b.run()
		wantExactly(t, rep, wf{AnchorUnknown, listPathOf(setN(3))})
		lacks(t, rep, RootReturns)
		wantReasons(t, rep, []Code{AnchorUnknown}, nil)
		if d := detail(rep, AnchorUnknown, listPathOf(setN(3))); !strings.Contains(d, "cannot be read") {
			t.Errorf("the detail %q does not say that the list cannot be read", d)
		}
		if !AnchorUnknown.Fails() {
			t.Error("anchor-unknown does not fail: the bundle would exit 0")
		}
		if in := b.inspect(); in.State != nil || in.OrderErr != nil {
			t.Errorf("State %v and OrderErr %v for a report with a failing finding", in.State, in.OrderErr)
		}
	})
	t.Run("the keys of a list with the lowest 64-bit sequence are not read: the list after it holds a key that is a return", func(t *testing.T) {
		// A is on list 1 and on list 2, and not on list 3: were the keys of list 2 read, list 3 would
		// hold nothing back. List 2 cannot be read, so list 3 has no known list before it.
		b := chainBundle(t, false,
			cset{setN(1), keyList(1, kA)},
			cset{setN(2), seqList(lowest, kA)},
			cset{setN(3), keyList(3, kA)})
		rep := b.run()
		wantExactly(t, rep, wf{AnchorUnknown, listPathOf(setN(2))}, wf{RootReturns, listPathOf(setN(3))})
		if d := detail(rep, RootReturns, listPathOf(setN(3))); !strings.Contains(d, "the list before this one cannot be read") {
			t.Errorf("the detail %q does not say that the list before cannot be read", d)
		}
	})
	t.Run("the same chain with the sequence 0 or -1: the keys are read and the list after it is no return", func(t *testing.T) {
		for _, seq := range []string{"0", "-1"} {
			b := chainBundle(t, false,
				cset{setN(1), keyList(1, kA)},
				cset{setN(2), seqList(seq, kA)},
				cset{setN(3), keyList(3, kA)})
			rep := b.run()
			wantExactly(t, rep, wf{AnchorUnknown, listPathOf(setN(2))}, wf{TrustSequence, "trust/" + setN(2)})
			lacks(t, rep, RootReturns)
			if d := detail(rep, AnchorUnknown, listPathOf(setN(2))); !strings.Contains(d, "its keys are still read") {
				t.Errorf("sequence %s: the detail %q lacks the words that the keys are read", seq, d)
			}
		}
	})
	t.Run("a return on a list with the sequence 0 or -1 is found at that list, and nowhere else", func(t *testing.T) {
		for _, seq := range []string{"0", "-1"} {
			b := chainBundle(t, false,
				cset{setN(1), keyList(1, kA, kB)},
				cset{setN(2), keyList(2, kB)},
				cset{setN(3), seqList(seq, kA, kB)})
			rep := b.run()
			wantExactly(t, rep,
				wf{AnchorUnknown, listPathOf(setN(3))},
				wf{RootReturns, listPathOf(setN(3))},
				wf{TrustSequence, "trust/" + setN(3)})
			if rs := returnsOf(rep); len(rs) != 1 || !strings.HasPrefix(rs[0].Detail, `root key "A"`) {
				t.Errorf("sequence %s: returns %v, want one, for the key A", seq, rs)
			}
		}
	})
	t.Run("the lowest 64-bit sequence on a list that drops a key gives the key nothing to come back to", func(t *testing.T) {
		// list 2 cannot be read; list 3 holds A and B, which list 1 held: both are returns by the rule
		// of a list whose predecessor is not known.
		b := chainBundle(t, false,
			cset{setN(1), keyList(1, kA, kB)},
			cset{setN(2), seqList(lowest, kB)},
			cset{setN(3), keyList(3, kA, kB)})
		rep := b.run()
		has(t, rep, AnchorUnknown, listPathOf(setN(2)))
		wantReturnsAt(t, rep, setN(3)+" A", setN(3)+" B")
	})
}
