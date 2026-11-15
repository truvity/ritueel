//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The order of the root lists in a State (record 0006, rule 54; the page "The hash chain"): the
// place of a set is the place of the record that lists it, or, for a set that no record lists, the
// place of the record that its last_record_sha256 names. Where one reading of the order does not
// exist there is no State, an OrderErr that wraps ErrOrder, and no guess.

// A closing record lists the leftover set of a stopped ceremony: the set stands where the closing
// record stands, after the ceremonies that ran in between.
func TestInspectALeftoverSetStandsWhereTheClosingRecordStands(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(1), keyList(1, kA)))
	stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
	b.apply(withSet(setN(3), keyList(3, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	b.apply(withSet(setN(5), keyList(5, kA)))
	in := b.inspect()
	// The ceremonies are 1, 3, the closing record, 5: the leftover set 2 stands at the closing
	// record, and the name or the sequence of it does not move it before the set 3.
	st := wantState(t, in, setN(1), setN(3), setN(2), setN(5))
	if st.Records != 4 || st.End != b.recs[len(b.recs)-1].digest {
		t.Errorf("Records %d, End %s", st.Records, st.End)
	}
	if len(st.Unfinished) != 0 {
		t.Errorf("Unfinished = %v: a closing record names it", st.Unfinished)
	}
	if st.Newest.Name != setN(5) {
		t.Errorf("Newest = %s", st.Newest.Name)
	}
}

// A closing record that lists the leftover set as the newest record: the leftover set is last.
func TestInspectAClosingRecordAtTheEnd(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(1), keyList(1, kA)))
	stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	st := wantState(t, b.inspect(), setN(1), setN(2))
	if st.Newest.Name != setN(2) || st.Newest.Number != 2 {
		t.Errorf("Newest = %+v", *st.Newest)
	}
}

// The newest list after a closing record is in the chain after it, whatever the earlier names say:
// here the set after the closing record has the highest sequence of all, so it is the newest.
func TestInspectTheSetAfterAClosingRecordStandsAfterIt(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(5), keyList(5, kA)))
	stopped := b.unfinished(withSet(setN(6), keyList(6, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	b.apply(withSet(setN(7), keyList(7, kA)))
	wantState(t, b.inspect(), setN(5), setN(6), setN(7))
}

// The same chain with the set after the closing record the lowest of all: the last of the chain
// does not hold the highest sequence, so there is no State.
func TestInspectTheSetAfterAClosingRecordWithTheLowestSequenceHasNoState(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(5), keyList(5, kA)))
	stopped := b.unfinished(withSet(setN(6), keyList(6, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	b.apply(withSet(setN(1), keyList(1, kA)))
	wantOrderErr(t, b.inspect())
}

// A set that no record lists stands where its list says it follows (the record named by
// last_record_sha256). Two stopped ceremonies that both follow the end stand at one place; their
// sequences and numbers agree, so they have one order: by sequence.
func TestInspectUnlistedSetsOfOnePlaceThatAgreeAreOrderedBySequence(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(1), keyList(1, kA)))
	late := b.unfinished(withSet(setN(3), keyList(3, kA)))
	early := b.unfinished(withSet(setN(2), keyList(2, kA)))
	in := b.inspect()
	st := wantState(t, in, setN(1), setN(2), setN(3))
	if st.Newest.Name != setN(3) {
		t.Errorf("Newest = %s", st.Newest.Name)
	}
	want := []string{late.folder, early.folder}
	slices.Sort(want)
	if !slices.Equal(st.Unfinished, want) {
		t.Errorf("Unfinished = %v, want %v", st.Unfinished, want)
	}
}

// Sets of one place that tie, that miss a statement or that disagree have no one order: there is no
// State, ErrOrder says so, and the report is the report of Check. Every case here is a clean report.
func TestInspectSetsOfOnePlaceThatDoNotAgreeHaveNoState(t *testing.T) {
	type pair struct{ a, b cset }
	cases := map[string]pair{
		"the same sequence, names that differ":   {cset{setN(2), keyList(2, kA)}, cset{setN(3), keyList(2, kA)}},
		"the same number in the names":           {cset{"2-aaaaaaaa", keyList(2, kA)}, cset{"2-bbbbbbbb", keyList(3, kA)}},
		"no sequence on one of them":             {cset{setN(2), keyList(2, kA)}, cset{setN(3), rootsJSON(0, kA)}},
		"no sequence on the lower one":           {cset{setN(2), rootsJSON(0, kA)}, cset{setN(3), keyList(3, kA)}},
		"no sequence on either":                  {cset{setN(2), rootsJSON(0, kA)}, cset{setN(3), rootsJSON(0, kA)}},
		"the sequences and the numbers disagree": {cset{setN(2), keyList(3, kA)}, cset{setN(3), keyList(2, kA)}},
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, name := range names {
		c := cases[name]
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply(withSet(setN(1), keyList(1, kA)))
			b.unfinished(withSet(c.a.name, c.a.list))
			b.unfinished(withSet(c.b.name, c.b.list))
			in := b.inspect()
			wantOrderErr(t, in)
			if !strings.Contains(in.OrderErr.Error(), "stand at one place") {
				t.Errorf("the reason does not say that sets stand at one place: %v", in.OrderErr)
			}
		})
	}
}

// One record that lists two trust sets stands at one place twice over: the chain does not order
// them, and the names and sequences are the writer's. No State, whatever the statements say.
func TestInspectOneRecordThatListsTwoSetsHasNoState(t *testing.T) {
	for _, agree := range []bool{true, false} {
		t.Run(fmt.Sprintf("the statements agree %v", agree), func(t *testing.T) {
			b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
			x, y := cset{setN(2), keyList(2, kA)}, cset{setN(3), keyList(3, kA)}
			if !agree {
				x, y = y, x
			}
			b.apply(withSets(x, y))
			wantOrderErr(t, b.inspect())
		})
	}
}

// A set that more than one record lists, each time after another record, stands at more than one
// place. The anchor of its list can name only one record, so the check finds anchor-unknown at the
// set: the report fails, and there is no State and no OrderErr: the finding is the reason.
func TestInspectASetAtMoreThanOnePlaceFailsTheReport(t *testing.T) {
	b := chainBundle(t, false,
		cset{setN(1), keyList(1, kA)},
		cset{setN(2), keyList(2, kA)})
	b.apply(withSet(setN(1), keyList(1, kA)))
	in := b.inspect()
	if in.Report.Clean() || in.State != nil || in.OrderErr != nil {
		t.Errorf("clean %v, State %v, OrderErr %v", in.Report.Clean(), in.State, in.OrderErr)
	}
}

// A closing record that lists a leftover set and a second set: one record at one place that lists
// two sets. The chain does not order them and their names and sequences are the writer's, so there
// is no State even when the statements agree or the sequences tie.
func TestInspectAClosingRecordThatListsTwoSetsHasNoState(t *testing.T) {
	for name, second := range map[string][]byte{
		"the statements agree": keyList(3, kA),
		"the sequences tie":    keyList(2, kA),
		"the second is older":  keyList(1, kA),
	} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply(withSet(setN(1), keyList(1, kA)))
			stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
			b.closing(stopped, listsLeftover(stopped, nil), listsNewSet(setN(3), anchored(second, stopped.record.PrevRecordSHA256)))
			wantOrderErr(t, b.inspect())
		})
	}
}

// A fork has two ends: the report fails, and there is no State and no OrderErr: the findings are
// the reason.
func TestInspectAForkHasNoStateAndNoOrderErr(t *testing.T) {
	b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
	first := b.recs[0].digest
	b.apply(prev(first), withSet(setN(2), keyList(2, kA)))
	b.apply(prev(first), withSet(setN(3), keyList(3, kA)))
	in := b.inspect()
	if in.State != nil || in.OrderErr != nil || in.Report.Clean() {
		t.Errorf("State %v, OrderErr %v, clean %v", in.State, in.OrderErr, in.Report.Clean())
	}
	has(t, in.Report, Fork, "history/"+b.recs[0].folder)
}

// A record off the chain, a root list that cannot be read, a wrong anchor: failing findings, and so
// no State and no OrderErr.
func TestInspectAFailingReportHasNoStateAndNoOrderErr(t *testing.T) {
	cases := map[string]func(t *testing.T) *bundle{
		"a root list that cannot be read": func(t *testing.T) *bundle {
			return chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), []byte(`{`)})
		},
		"a wrong anchor": func(t *testing.T) *bundle {
			b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
			b.apply(withSet(setN(2), []byte(`{"last_record_sha256":"`+digestB+`","roots":[],"sequence":2,"version":1}`)))
			return b
		},
		"a set that no record lists": func(t *testing.T) *bundle {
			b := numbered(t, true, 2)
			addList(b.mem, "9-aaaaaaaa", claims(keyList(9, kA), b.digests()[1]))
			return b
		},
		"a key that returns": func(t *testing.T) *bundle {
			return chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kB)}, cset{setN(3), keyList(3, kA)})
		},
		"a record that names a record that is not there": func(t *testing.T) *bundle {
			b := numbered(t, false, 2)
			b.apply(prev(digestA), withSet(setN(3), keyList(3, kA)))
			return b
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			in := build(t).inspect()
			if in.Report.Clean() {
				t.Fatal("the report is clean")
			}
			if in.State != nil || in.OrderErr != nil {
				t.Errorf("State %v, OrderErr %v", in.State, in.OrderErr)
			}
		})
	}
}

// The newest set must carry its own number as the sequence of its list: the number in the name is
// from the writer, and a State is only made when the list agrees with it. A name with no number,
// a list with no sequence, a sequence of another number: no State.
func TestInspectNewestMustAgreeWithItsName(t *testing.T) {
	cases := []struct {
		name string
		set  string
		list []byte
	}{
		{"the sequence is another number", "2-aaaaaaaa", keyList(9, kA)},
		{"the sequence is lower", "5-aaaaaaaa", keyList(4, kA)},
		{"the name has no number", "latest", keyList(2, kA)},
		{"the name has no number and the sequence is 0", "latest", seqList("0", kA)},
		{"the list has no sequence", "2-aaaaaaaa", rootsJSON(0, kA)},
		{"the sequence is 0 and the name 2", "2-aaaaaaaa", seqList("0", kA)},
		{"the sequence is negative", "2-aaaaaaaa", seqList("-2", kA)},
		{"the number has 16 digits", "1000000000000000-aaaaaaaa", keyList(1000000000000000, kA)},
		{"the number has a leading zero", "02-aaaaaaaa", keyList(2, kA)},
		{"the number is empty", "-aaaaaaaa", keyList(2, kA)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{c.set, c.list})
			wantOrderErr(t, b.inspect())
		})
	}
	t.Run("no sequence and the name 0", func(t *testing.T) {
		// A list with no sequence is not a list with the sequence 0.
		b := chainBundle(t, false, cset{"0-aaaaaaaa", rootsJSON(0, kA)})
		wantOrderErr(t, b.inspect())
	})
	t.Run("a sequence of 0 and the name 0", func(t *testing.T) {
		b := chainBundle(t, false, cset{"0-aaaaaaaa", seqList("0", kA)})
		st := wantState(t, b.inspect(), "0-aaaaaaaa")
		if st.Newest.Number != 0 {
			t.Errorf("Number = %d", st.Newest.Number)
		}
	})
	t.Run("the first set carries any sequence when it is not the newest", func(t *testing.T) {
		// Only the newest set is held to its name: the order comes from the chain.
		b := chainBundle(t, false, cset{setN(1), keyList(50, kA)}, cset{setN(60), keyList(60, kA)})
		wantState(t, b.inspect(), setN(1), setN(60))
		// With the newest below the first, the newest is held to the sequences of the chain too.
		low := chainBundle(t, false, cset{setN(1), keyList(50, kA)}, cset{setN(2), keyList(2, kA)})
		wantOrderErr(t, low.inspect())
	})
}

// The longest number a name may have (fifteen digits) and a sequence of the same value.
func TestInspectNumberIsAnInteger(t *testing.T) {
	n := int64(999999999999999)
	name := fmt.Sprintf("%d-aaaaaaaa", n)
	b := chainBundle(t, false, cset{name, keyList(n, kA)})
	st := wantState(t, b.inspect(), name)
	if st.Newest.Number != n {
		t.Errorf("Number = %d", st.Newest.Number)
	}
}

// ErrOrder is a value of its own: a caller finds it with errors.Is, and it is not any other error
// of the package.
func TestInspectErrOrderIsItsOwnError(t *testing.T) {
	if ErrOrder == nil || errors.Is(ErrOrder, ErrTooMuch) || errors.Is(ErrOrder, ErrNotBundle) {
		t.Error("ErrOrder is nil or another error")
	}
	b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(9, kA)})
	in := b.inspect()
	wantOrderErr(t, in)
	if errors.Is(in.OrderErr, ErrTooMuch) {
		t.Error("OrderErr is ErrTooMuch")
	}
	if in.OrderErr.Error() == ErrOrder.Error() {
		t.Error("the reason adds nothing to ErrOrder")
	}
}

// The words of a reason never carry a name as it is on the stick: a name is shown with the escape,
// and cut.
func TestInspectOrderReasonDoesNotCarryRawNames(t *testing.T) {
	b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{"2-" + strings.Repeat("a", 8), keyList(7, kA)})
	in := b.inspect()
	wantOrderErr(t, in)
	if msg := in.OrderErr.Error(); !printable(msg) || strings.ContainsAny(msg, "\r\n") {
		t.Errorf("the reason %q is not printable ASCII on one line", msg)
	}
}

// The differential test with FindReturns: Inspect gives the lists in the order in which
// root-returns reads them, so FindReturns over the lists before one finds no return in a clean
// bundle, for every list.
func TestInspectFindReturnsOverTheListsOfACleanBundleFindsNothing(t *testing.T) {
	cases := map[string][]cset{
		"keys that stay, move and change their label": {
			{setN(1), keyList(1, kA, kB)}, {setN(2), keyList(2, kB, kA)}, {setN(3), keyList(3, ent{"C", pb, ""}, ent{"D", pa, ""})},
		},
		"a key that leaves and never returns": {
			{setN(1), keyList(1, kA, kB)}, {setN(2), keyList(2, kB)}, {setN(3), keyList(3, kB)}, {setN(4), keyList(4, kB, kK)},
		},
		"fingerprints": {
			{setN(1), keyList(1, ent{"A", pa, f1})}, {setN(2), keyList(2, ent{"A", pa, f1}, ent{"B", pb, f2})}, {setN(3), keyList(3, ent{"B", pb, f2})},
		},
		"descending names": {
			{"9-aaaaaaaa", keyList(9, kA, kB)}, {"8-aaaaaaaa", keyList(8, kB)}, {"17-aaaaaaaa", keyList(17, kB)},
		},
		"lists with no keys": {
			{setN(1), keyList(1)}, {setN(2), keyList(2)}, {setN(3), keyList(3, kA)},
		},
	}
	for name, sets := range cases {
		t.Run(name, func(t *testing.T) {
			in := chainBundle(t, false, sets...).inspect()
			st := wantState(t, in, setNames(sets)...)
			for i := range st.Lists {
				rets, err := FindReturns(st.Lists[:i], st.Lists[i])
				if err != nil {
					t.Fatalf("FindReturns(%d): %v", i, err)
				}
				if len(rets) != 0 {
					t.Errorf("FindReturns over the lists before %s finds %+v in a clean bundle", st.Lists[i].Name, rets)
				}
			}
		})
	}
}

func setNames(sets []cset) []string {
	out := make([]string, len(sets))
	for i, s := range sets {
		out[i] = s.name
	}
	return out
}

// For a bundle that has the finding root-returns there is no State. The lists are written by hand
// in the order of the chain, and FindReturns over them finds the same returns that Check puts in
// its findings: the same list and the same entry. This is the six cases of the root list page.
func TestInspectFindReturnsAgreesWithTheFindingsOfCheck(t *testing.T) {
	rk := func(label, pin, fp string) RootKey { return RootKey{Label: label, Pin: pin, Fingerprint: fp} }
	type list struct {
		seq  int64
		ents []ent
		keys []RootKey
	}
	mk := func(seq int64, ents ...ent) list {
		l := list{seq: seq, ents: ents}
		for _, e := range ents {
			l.keys = append(l.keys, rk(e.label, e.pin, e.fp))
		}
		return l
	}
	cases := []struct {
		name  string
		lists []list
		want  []string // "list index (from 1) label"
	}{
		{"after a revoke", []list{mk(1, kA, kB), mk(2, kB), mk(3, kA, kB)}, []string{"3 A"}},
		{"under a new label", []list{mk(1, kA, kB), mk(2, kB), mk(3, ent{"C", pa, ""}, kB)}, []string{"3 C"}},
		{"after several lists", []list{mk(1, kA, kB), mk(2, kB), mk(3, kB), mk(4, kB), mk(5, kA, kB)}, []string{"5 A"}},
		{"the old fingerprint under a new pin", []list{
			mk(1, ent{"A", pa, f1}, kB), mk(2, kB), mk(3, ent{"C", pc, f1}, kB)}, []string{"3 C"}},
		{"a key that stays", []list{mk(1, kA), mk(2, kA), mk(3, kA)}, nil},
		{"two returns", []list{mk(1, kA, kB), mk(2, kK), mk(3, kA, kB)}, []string{"3 A", "3 B"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sets := make([]cset, len(c.lists))
			var byHand []RootList
			for i, l := range c.lists {
				sets[i] = cset{setN(i + 1), keyList(l.seq, l.ents...)}
				byHand = append(byHand, RootList{Name: setN(i + 1), Keys: l.keys})
			}
			in := chainBundle(t, false, sets...).inspect()
			var fromCheck []string
			for _, f := range returnsOf(in.Report) {
				label, _, _ := strings.Cut(strings.TrimPrefix(f.Detail, `root key "`), `"`)
				set := strings.TrimSuffix(strings.TrimPrefix(f.Path, "trust/"), "/root-list.json")
				fromCheck = append(fromCheck, set+" "+label)
			}
			var fromFind []string
			for i := range byHand {
				rets, err := FindReturns(byHand[:i], byHand[i])
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range rets {
					fromFind = append(fromFind, byHand[i].Name+" "+byHand[i].Keys[r.Entry].Label)
				}
			}
			slices.Sort(fromCheck)
			slices.Sort(fromFind)
			if !slices.Equal(fromCheck, fromFind) {
				t.Errorf("Check says %v, FindReturns over the chain says %v", fromCheck, fromFind)
			}
			var want []string
			for _, w := range c.want {
				var n int
				var label string
				if _, err := fmt.Sscanf(w, "%d %s", &n, &label); err != nil {
					t.Fatal(err)
				}
				want = append(want, setN(n)+" "+label)
			}
			slices.Sort(want)
			if !slices.Equal(fromFind, want) && (len(want) != 0 || len(fromFind) != 0) {
				t.Errorf("returns %v, want %v", fromFind, want)
			}
			if len(want) > 0 && (in.State != nil || in.Report.Clean()) {
				t.Errorf("a bundle with the finding root-returns has a State or a clean report")
			}
			if len(want) == 0 {
				st := wantState(t, in, setNames(sets)...)
				for i := range st.Lists {
					if r, _ := FindReturns(st.Lists[:i], st.Lists[i]); len(r) != 0 {
						t.Errorf("FindReturns over State.Lists finds %+v", r)
					}
				}
			}
		})
	}
}

// The lists of a State are what FindReturns takes: a writer can put its own list after them and ask.
func TestInspectListsFeedFindReturnsForTheNextList(t *testing.T) {
	b := chainBundle(t, false, cset{setN(1), keyList(1, kA, kB)}, cset{setN(2), keyList(2, kB)})
	st := wantState(t, b.inspect(), setN(1), setN(2))
	next := RootList{Name: "next", Keys: []RootKey{{Label: "A", Pin: pa}, {Label: "B", Pin: pb}}}
	rets, err := FindReturns(st.Lists, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(rets) != 1 || rets[0].Entry != 0 || !rets[0].ByPin || rets[0].PinHeldOn != setN(1) {
		t.Errorf("returns %+v, want A returning by its pin, held on %s", rets, setN(1))
	}
	if rets, _ := FindReturns(st.Lists, RootList{Name: "next", Keys: []RootKey{{Label: "B", Pin: pb}, {Label: "K", Pin: pc}}}); len(rets) != 0 {
		t.Errorf("returns %+v for a list that adds a new key", rets)
	}
}

// Each reason that a clean report has no State is a sentence that says what is wrong, and a reason
// about one set names it, shown the way findings show names: with the folder "trust/" in front.
func TestInspectEachReasonOfNoOrderSaysWhatIsWrong(t *testing.T) {
	check := func(name string, in *Inspection, want ...string) {
		t.Helper()
		wantOrderErr(t, in)
		msg := in.OrderErr.Error()
		for _, w := range want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: the reason %q lacks %q", name, msg, w)
			}
		}
	}
	{
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		b.unfinished(withSet(setN(2), keyList(2, kA)))
		b.unfinished(withSet(setN(3), keyList(2, kA)))
		check("a tie of two unlisted sets at one place", b.inspect(), "stand at one place")
	}
	{
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		b.apply(withSets(cset{setN(2), keyList(2, kA)}, cset{setN(3), keyList(3, kA)}))
		check("one record lists two sets", b.inspect(), "stand at one place")
	}
	{
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(9, kA)})
		check("the newest set has another sequence than its number", b.inspect(), "trust/"+setN(2), "not the sequence")
	}
	{
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{"latest", keyList(2, kA)})
		check("the newest set has no number", b.inspect(), "trust/latest", "not the sequence")
	}
	{
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), rootsJSON(0, kA)})
		check("the newest list has no sequence", b.inspect(), "trust/"+setN(2), "not the sequence")
	}
}

// listsReversed gives every folder listing in the opposite order, and every listing of a name a
// second time later in the run, so that nothing can depend on the order of the names in a listing.
type listsReversed struct{ fsx.FS }

func (l listsReversed) ReadDir() ([]fs.DirEntry, error) {
	ents, err := l.FS.ReadDir()
	slices.Reverse(ents)
	return ents, err
}

func (l listsReversed) OpenDir(name string) (fsx.FS, error) {
	d, err := l.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return listsReversed{d}, nil
}

// A folder listing in any order gives the same State: the order of the lists is the chain and the
// order of the open ceremonies is the order of their names, whatever order the file system lists
// them in.
func TestInspectDoesNotDependOnTheOrderOfAListing(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(1), keyList(1, kA)))
	b.apply(withSet(setN(2), keyList(2, kA)))
	b.unfinished(withSet(setN(4), keyList(4, kA)))
	b.unfinished(withSet(setN(3), keyList(3, kA)))
	b.unfinished(noSet)
	b.unfinished(noSet)
	b.mem = loadMem(t, b.dir)
	b.dir = ""
	plain, err := inspectFS(t, memFS{b.mem})
	if err != nil || plain.State == nil {
		t.Fatalf("Inspect: %v %v %v", plain, err, findingsOf(plain.Report))
	}
	if len(plain.State.Unfinished) != 4 {
		t.Fatalf("Unfinished = %v", plain.State.Unfinished)
	}
	rev, err := inspectFS(t, listsReversed{memFS{b.mem}})
	if err != nil || rev.State == nil {
		t.Fatalf("Inspect: %v %v", rev, err)
	}
	if !reflect.DeepEqual(plain, rev) {
		t.Errorf("a reversed listing gives another answer:\n plain %+v\n rev   %+v", *plain.State, *rev.State)
	}
	if !slices.IsSorted(rev.State.Unfinished) {
		t.Errorf("Unfinished %v is not in the order of the names", rev.State.Unfinished)
	}
}

// A set that two closing records list stands at two places of the chain (the second closing record
// closes the same ceremony again, and lists the same files). The report is clean, the order has no
// one reading, and there is no State.
func TestInspectASetThatTwoClosingRecordsListHasNoState(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(1), keyList(1, kA)))
	stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	b.closing(stopped, listsLeftover(stopped, nil))
	in := b.inspect()
	wantOrderErr(t, in)
	if !strings.Contains(in.OrderErr.Error(), "more than one place") {
		t.Errorf("the reason %q does not say that the set stands at more than one place", in.OrderErr)
	}
	if want := b.recs[len(b.recs)-1].digest; in.Report.Ends[0] != want {
		t.Errorf("the end of the report is %s, want %s", in.Report.Ends[0], want)
	}
}
