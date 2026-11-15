//go:build linux || darwin

package history

import (
	"fmt"
	"strings"
	"testing"
)

// The rule of when Inspect gives a State, as far as the sequences go: a writer builds the next list
// on the newest set and gives it the next number, so the newest set (the last of the chain) must
// hold the highest sequence of all root lists. A bundle where it does not has no State and an
// OrderErr that wraps ErrOrder with one sentence. The pages do not yet say what the next ceremony
// builds on after a ceremony that stopped and a later one with a higher number, so the inspection
// refuses; a chain whose numbers grow is not touched, and the report is the report of Check.

const (
	notHighestWords = "does not hold the highest sequence of the root lists"
	unreadableWords = "the sequence of a root list of the chain cannot be read"
	nameNumberWords = "is not the sequence of its root list"
)

// wantReason fails the test unless the Inspection has no State and an OrderErr that wraps ErrOrder
// and ends with a reason that holds words. The reason is one printable line.
func wantReason(t testing.TB, in *Inspection, words ...string) {
	t.Helper()
	wantOrderErr(t, in)
	msg := in.OrderErr.Error()
	if !strings.HasPrefix(msg, ErrOrder.Error()+": ") {
		t.Errorf("OrderErr %q does not begin with the words of ErrOrder and a reason", msg)
	}
	for _, w := range words {
		if !strings.Contains(msg, w) {
			t.Errorf("OrderErr %q does not say %q", msg, w)
		}
	}
	if !printable(msg) {
		t.Errorf("OrderErr %q is not printable ASCII on one line", msg)
	}
}

// seqSet is one ceremony of a table: the number of the name and the sequence of the list. A
// sequence of none writes a list with no sequence member.
type seqSet struct {
	num  int
	seq  int64
	none bool
}

func nums(seqs ...int64) []seqSet {
	out := make([]seqSet, len(seqs))
	for i, s := range seqs {
		out[i] = seqSet{num: int(s), seq: s}
	}
	return out
}

// chainOf builds one apply ceremony for each entry. The names are "<num>-" and eight letters that
// differ from one ceremony to the next, so two sets may carry the same number.
func chainOf(t testing.TB, specs []seqSet) (*bundle, []string) {
	t.Helper()
	sets := make([]cset, len(specs))
	names := make([]string, len(specs))
	for i, s := range specs {
		names[i] = fmt.Sprintf("%d-%s", s.num, strings.Repeat(string(rune('a'+i)), 8))
		if s.none {
			sets[i] = cset{names[i], rootsJSON(0, kA)}
		} else {
			sets[i] = cset{names[i], keyList(s.seq, kA)}
		}
	}
	return chainBundle(t, false, sets...), names
}

// The sequences of a chain that grows give a State, and the newest is the last of the chain with
// the highest sequence. Gaps are fine. A number that repeats or runs against the order of the chain
// is the finding trust-sequence, so a report with it has no State (see the next test).
func TestInspectAChainWhoseLastListIsTheHighestGivesAState(t *testing.T) {
	cases := map[string][]int64{
		"one list":                    {1},
		"one list with a high number": {40},
		"1, 2, 3":                     {1, 2, 3},
		"1, 3":                        {1, 3},
		"gaps":                        {2, 5, 9, 30},
	}
	for name, seqs := range cases {
		t.Run(name, func(t *testing.T) {
			b, names := chainOf(t, nums(seqs...))
			in := b.inspect()
			st := wantState(t, in, names...)
			last := seqs[len(seqs)-1]
			if st.Newest.Name != names[len(names)-1] || st.Newest.Number != last {
				t.Errorf("Newest = %+v, want %s with number %d", *st.Newest, names[len(names)-1], last)
			}
			if string(st.Newest.ListJSON) != string(b.get(listPathOf(st.Newest.Name))) {
				t.Error("ListJSON is not the file of the newest set")
			}
		})
	}
}

// A number that repeats or runs against the order of the chain is the finding trust-sequence, at the
// set whose number is not higher than the number of the set before it, and the report fails: no
// State, and no OrderErr (the finding is the reason). Equal counts as not higher.
func TestInspectAChainWhoseNumbersRepeatOrRunBackHasNoState(t *testing.T) {
	cases := map[string][]int64{
		"two earlier lists with a tie":     {2, 2, 3},
		"earlier lists that run backwards": {7, 4, 9},
		"the first one is the highest":     {1, 9, 3, 10},
		"a low list in the middle":         {5, 1, 6},
		"3, 1":                             {3, 1},
		"1, 3, 2":                          {1, 3, 2},
		"2, 2":                             {2, 2},
		"1, 2, 2":                          {1, 2, 2},
		"the highest in the middle":        {1, 9, 4},
		"the highest first":                {9, 2, 4, 3},
		"an equal one early":               {5, 1, 5},
		"5, 1, 4, 6, 6":                    {5, 1, 4, 6, 6},
	}
	for name, seqs := range cases {
		t.Run(name, func(t *testing.T) {
			b, _ := chainOf(t, nums(seqs...))
			wantModel(t, b.inspect(), csetsOf(nums(seqs...)))
		})
	}
}

// A long chain that stops: 25 ceremonies and a last one that carries a lower number. The finding
// is at the last set only.
func TestInspectALongChainThatEndsOnALowerSequenceHasNoState(t *testing.T) {
	b := numbered(t, false, 25)
	b.apply(withSet("24-bbbbbbbb", keyList(24, kA)))
	wantFailed(t, b.inspect(), []wf{{TrustSequence, "trust/24-bbbbbbbb"}})
}

// A ceremony stops, a later ceremony writes a set with a higher number, and then close lists the
// leftover set: it stands last in the chain with a lower number than a set that hosts already
// hold. There is no State, and the sentence says so; the report is the report of Check, clean.
func TestInspectAStoppedCeremonyClosedAfterALaterOneHasNoState(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(1), keyList(1, kA)))
	stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
	b.apply(withSet(setN(3), keyList(3, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	in := b.inspect()
	if !in.Report.Clean() {
		t.Fatalf("the report is not clean: %v", findingsOf(in.Report))
	}
	wantReason(t, in, notHighestWords, "trust/"+setN(2))
	if in.State != nil {
		t.Errorf("a State with the lists %v", namesOfLists(in.State))
	}
}

// The same history with different numbers and places of the closing record.
func TestInspectAClosingRecordAndTheHighestSequence(t *testing.T) {
	t.Run("the leftover set is the highest and stands last", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		b.apply(withSet(setN(2), keyList(2, kA)))
		stopped := b.unfinished(withSet(setN(3), keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		st := wantState(t, b.inspect(), setN(1), setN(2), setN(3))
		if st.Newest.Name != setN(3) || st.Newest.Number != 3 {
			t.Errorf("Newest = %+v", *st.Newest)
		}
	})
	t.Run("two ceremonies after the stop and the closing record last", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
		b.apply(withSet(setN(3), keyList(3, kA)))
		b.apply(withSet(setN(4), keyList(4, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		wantReason(t, b.inspect(), notHighestWords, "trust/"+setN(2))
	})
	t.Run("a ceremony after the closing record with a higher number", func(t *testing.T) {
		// Closing record, then a new ceremony above every number: the chain ends on the highest.
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
		b.apply(withSet(setN(3), keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		b.apply(withSet(setN(4), keyList(4, kA)))
		st := wantState(t, b.inspect(), setN(1), setN(3), setN(2), setN(4))
		if st.Newest.Name != setN(4) {
			t.Errorf("Newest = %s", st.Newest.Name)
		}
	})
	t.Run("the leftover set has the number of a set that stands before it", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet("3-aaaaaaaa", keyList(3, kA)))
		stopped := b.unfinished(withSet("3-bbbbbbbb", keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		wantReason(t, b.inspect(), notHighestWords, "trust/3-bbbbbbbb")
	})
	t.Run("the stopped ceremony is not closed and a later one ran", func(t *testing.T) {
		// Until the closing record is written the leftover set is unlisted and the report fails
		// (trust-set-unlisted): the finding is the reason, and there is neither State nor OrderErr.
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		b.unfinished(withSet(setN(2), keyList(2, kA)))
		b.apply(withSet(setN(3), keyList(3, kA)))
		in := b.inspect()
		if in.Report.Clean() || in.State != nil || in.OrderErr != nil {
			t.Errorf("clean %v, State %v, OrderErr %v", in.Report.Clean(), in.State, in.OrderErr)
		}
		has(t, in.Report, TrustSetUnlisted, "trust/"+setN(2))
	})
}

// Two lists with one sequence at two places: the last of the chain does not hold a higher one.
// Equal sequences with equal numbers in the names do not make a State.
func TestInspectTwoListsWithOneSequenceAtTwoPlaces(t *testing.T) {
	t.Run("the last two", func(t *testing.T) {
		b, names := chainOf(t, nums(1, 2, 2))
		wantFailed(t, b.inspect(), []wf{{TrustSequence, "trust/" + names[2]}})
	})
	t.Run("the first and the last", func(t *testing.T) {
		b, names := chainOf(t, nums(4, 5, 4))
		wantFailed(t, b.inspect(), []wf{{TrustSequence, "trust/" + names[2]}})
	})
	t.Run("only the earlier two", func(t *testing.T) {
		b, names := chainOf(t, nums(2, 2, 3))
		wantFailed(t, b.inspect(), []wf{{TrustSequence, "trust/" + names[1]}})
	})
	t.Run("a name number below the sequence of the list", func(t *testing.T) {
		// 2-aaaaaaaa has the sequence 3 and 3-bbbbbbbb the sequence 3: the first is not the sequence
		// of its list; the second is higher than the number 2 before it and is its list's number.
		b, names := chainOf(t, []seqSet{{num: 2, seq: 3}, {num: 3, seq: 3}})
		wantFailed(t, b.inspect(), []wf{{TrustSequence, "trust/" + names[0]}})
	})
}

// A list of the chain with no sequence: there is no State, and the sentence says that a sequence
// cannot be read. A list in the middle or at the front; the last list with none is held to its
// name first, as before.
func TestInspectAListOfTheChainWithNoSequenceHasNoState(t *testing.T) {
	none := func(num int) seqSet { return seqSet{num: num, none: true} }
	seq := func(n int64) seqSet { return seqSet{num: int(n), seq: n} }
	t.Run("the first", func(t *testing.T) {
		b, _ := chainOf(t, []seqSet{none(1), seq(2)})
		in := b.inspect()
		wantReason(t, in, unreadableWords)
		if got := in.OrderErr.Error(); got != ErrOrder.Error()+": "+unreadableWords {
			t.Errorf("OrderErr = %q", got)
		}
	})
	t.Run("in the middle", func(t *testing.T) {
		b, _ := chainOf(t, []seqSet{seq(1), none(2), seq(3)})
		wantReason(t, b.inspect(), unreadableWords)
	})
	t.Run("two of three", func(t *testing.T) {
		b, _ := chainOf(t, []seqSet{none(1), none(2), seq(3)})
		wantReason(t, b.inspect(), unreadableWords)
	})
	t.Run("one before a lower last", func(t *testing.T) {
		// The lower last is the finding trust-sequence, and the report fails.
		b, names := chainOf(t, []seqSet{none(1), seq(5), seq(3)})
		wantFailed(t, b.inspect(), []wf{{TrustSequence, "trust/" + names[2]}})
	})
	t.Run("the last", func(t *testing.T) {
		b, names := chainOf(t, []seqSet{seq(1), none(2)})
		wantReason(t, b.inspect(), nameNumberWords, "trust/"+names[1])
	})
	t.Run("a list with no sequence is not the sequence 0", func(t *testing.T) {
		// A first list with the sequence 0 written out is a list that has a sequence, and a sequence
		// below 1 is anchor-unknown; the name 1 is not that sequence.
		b := chainBundle(t, false, cset{setN(1), seqList("0", kA)}, cset{setN(2), keyList(2, kA)})
		wantFailed(t, b.inspect(), []wf{{AnchorUnknown, listPathOf(setN(1))}, {TrustSequence, "trust/" + setN(1)}})
		b2 := chainBundle(t, false, cset{setN(1), rootsJSON(0, kA)}, cset{setN(2), keyList(2, kA)})
		wantReason(t, b2.inspect(), unreadableWords)
	})
	t.Run("a sequence written as text", func(t *testing.T) {
		// A list whose sequence is no integer cannot be read: the report fails, and there is no
		// State and no OrderErr (the finding is the reason).
		b := chainBundle(t, false, cset{setN(1), seqList(`"1"`, kA)}, cset{setN(2), keyList(2, kA)})
		in := b.inspect()
		if in.Report.Clean() || in.State != nil || in.OrderErr != nil {
			t.Errorf("clean %v, State %v, OrderErr %v", in.Report.Clean(), in.State, in.OrderErr)
		}
	})
}

// A last set whose number is not its sequence, is not higher than the one before, or has no sequence
// is the finding trust-sequence, and the report fails.
func TestInspectTheNameNumberRefusalComesBeforeTheHighestSequence(t *testing.T) {
	cases := map[string][]seqSet{
		"the last list is lower and its name says another number": {{num: 3, seq: 3}, {num: 9, seq: 1}},
		"the last list is equal and its name says another number": {{num: 3, seq: 3}, {num: 4, seq: 3}},
		"the last list has no sequence":                           {{num: 3, seq: 3}, {num: 2, none: true}},
	}
	for name, specs := range cases {
		t.Run(name, func(t *testing.T) {
			b, _ := chainOf(t, specs)
			wantModel(t, b.inspect(), csetsOf(specs))
		})
	}
}

// A long name of the last set is cut in the sentence and shown with the escape, so the reason
// stays one printable line of bounded length.
func TestInspectTheReasonOfTheHighestSequenceCutsALongName(t *testing.T) {
	long := "2-" + strings.Repeat("a", 90)
	b := chainBundle(t, false, cset{setN(5), keyList(5, kA)}, cset{long, keyList(2, kA)})
	in := b.inspect()
	if in.Report.Clean() {
		wantReason(t, in, notHighestWords)
		if len(in.OrderErr.Error()) > 400 {
			t.Errorf("the reason has %d bytes", len(in.OrderErr.Error()))
		}
		if strings.Contains(in.OrderErr.Error(), long) {
			t.Errorf("the reason carries the whole name: %q", in.OrderErr)
		}
		return
	}
	// A name that long is a finding of Check: then there is neither State nor OrderErr.
	if in.State != nil || in.OrderErr != nil {
		t.Errorf("State %v, OrderErr %v with a failing report", in.State, in.OrderErr)
	}
}

// Over the budget of bytes a State keeps, a chain that ends on a lower sequence is an OrderErr and
// not ErrTooMuch: there is no State to keep bytes for.
func TestInspectNotHighestComesBeforeTheBytesBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 64 MiB of root lists")
	}
	const each = 256 << 10
	n := MaxStateBytes / each
	b := chainBundle(t, true)
	for i := 2; i <= n+1; i++ {
		b.apply(func(r *rec) {
			delete(r.artifacts, "trust/"+r.set+"/root-list.json")
			delete(r.artifacts, "trust/"+r.set+"/keys.txt")
			r.set = setN(i)
			mk := func(pad int) []byte {
				return []byte(fmt.Sprintf(`{"pad":"%s","roots":[{"label":"A","x509_spki_sha256":%q}],"sequence":%d,"version":1}`, strings.Repeat("x", pad), pa, i))
			}
			list := anchored(mk(0), r.record.PrevRecordSHA256)
			list = anchored(mk(each-len(list)), r.record.PrevRecordSHA256)
			r.artifacts["trust/"+r.set+"/root-list.json"] = list
			r.artifacts["trust/"+r.set+"/keys.txt"] = []byte("keys")
			r.refresh()
		})
	}
	// With the budget spent the newest list is not kept; the last set has the lowest sequence. It is
	// a leftover set that a closing record lists: the sets of a closing record are not judged by
	// trust-sequence, so the report is clean.
	stopped := b.unfinished(withSet("1-bbbbbbbb", keyList(1, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	want, err := runMem(t, b.mem)
	if err != nil || !want.Clean() {
		t.Fatalf("Check = %v, %v; the bundle is meant to be clean", want, err)
	}
	in, err := inspectFS(t, memFS{b.mem})
	if err != nil || in == nil {
		t.Fatalf("Inspect = %v, %v; want an OrderErr and no error", in, err)
	}
	sameReport(t, in.Report, want)
	wantReason(t, in, notHighestWords)
}

// The sequence 0 written out is a sequence below 1: the root list page says a host takes only a
// sequence of at least 1, so the report has the finding anchor-unknown for it and fails, and there
// is no State. Two lists with it are also two lists with one number.
func TestInspectTheSequenceZeroIsAFindingOfTheAnchor(t *testing.T) {
	t.Run("two lists with the sequence 0", func(t *testing.T) {
		b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("0", kA)}, cset{"0-bbbbbbbb", seqList("0", kA)})
		wantFailed(t, b.inspect(), []wf{
			{AnchorUnknown, listPathOf("0-aaaaaaaa")}, {AnchorUnknown, listPathOf("0-bbbbbbbb")},
			{TrustSequence, "trust/0-bbbbbbbb"},
		})
	})
	t.Run("the sequence 0 and then 1", func(t *testing.T) {
		b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("0", kA)}, cset{setN(1), keyList(1, kA)})
		wantFailed(t, b.inspect(), []wf{{AnchorUnknown, listPathOf("0-aaaaaaaa")}})
	})
}

// A single list with no sequence and the name 0 keeps the sentence of the name: the number in the
// name is held to the sequence of the list before anything else.
func TestInspectOneListWithNoSequenceKeepsTheSentenceOfTheName(t *testing.T) {
	b := chainBundle(t, false, cset{"0-aaaaaaaa", rootsJSON(0, kA)})
	wantReason(t, b.inspect(), nameNumberWords, "trust/0-aaaaaaaa")
}
