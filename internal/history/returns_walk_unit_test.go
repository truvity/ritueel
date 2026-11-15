//go:build linux || darwin

package history

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// Units of the walk, of the groups of sets that tie and of the words of a finding, for the cases
// that a whole bundle shows only behind the bound of a detail.

func TestMergeNamesKeepsTheOrderAndNamesEachSetOnce(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want []string
	}{
		{"both empty", nil, nil, nil},
		{"the first is empty", nil, []string{"a", "b"}, []string{"a", "b"}},
		{"the second is empty", []string{"a", "b"}, nil, []string{"a", "b"}},
		{"apart", []string{"a", "b"}, []string{"c", "d"}, []string{"a", "b", "c", "d"}},
		{"apart, the other way", []string{"c", "d"}, []string{"a", "b"}, []string{"a", "b", "c", "d"}},
		{"between", []string{"a", "c"}, []string{"b", "d"}, []string{"a", "b", "c", "d"}},
		{"a name in both", []string{"a", "b"}, []string{"b", "c"}, []string{"a", "b", "c"}},
		{"the same", []string{"a", "b"}, []string{"a", "b"}, []string{"a", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mergeNames(c.a, c.b); !slices.Equal(got, c.want) {
				t.Errorf("mergeNames(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
			}
		})
	}
}

// The sets of one group of lists that tie are in the order of their names, in either reading, so
// that the holders and the words of a finding do not depend on the order in which a sort left them.
func TestTieGroupsHoldTheSetsInTheOrderOfTheirNames(t *testing.T) {
	names := []string{"7-d", "7-a", "7-c", "7-b"}
	var lists []setList
	keys := map[string]setOrder{}
	for _, n := range names {
		lists = append(lists, setList{set: n})
		keys[n] = setOrder{numbered: true, number: 7, hasSeq: true, sequence: 3}
	}
	for _, byNumber := range []bool{false, true} {
		got := tieGroups(5, lists, keys, byNumber)
		if len(got) != 1 || got[0].place != 5 {
			t.Fatalf("byNumber=%v: %d groups: %v", byNumber, len(got), got)
		}
		var order []string
		for _, l := range got[0].lists {
			order = append(order, l.set)
		}
		if want := []string{"7-a", "7-b", "7-c", "7-d"}; !slices.Equal(order, want) {
			t.Errorf("byNumber=%v: the group is %q, want %q", byNumber, order, want)
		}
	}
}

// The walk names, as the holder of a key, a set other than the one judged, also when the set
// judged is the first of its group that holds the key.
func TestWalkNamesAnotherSetThanTheOneJudgedAsHolder(t *testing.T) {
	key := func(pin, fp byte) rootKey {
		k := rootKey{label: "A", hasPin: true, hasFP: true}
		k.pin[0], k.fp[0] = pin, fp
		return k
	}
	list := func(set string, keys ...rootKey) setList { return setList{set: set, read: &anchorOf{keys: keys}} }
	// One group of three lists that tie: the first two hold the key, the third does not. The first,
	// in the order of the names, is a return (the third may stand before it), and the other holder
	// is the second.
	g := group{place: 0, lists: []setList{list("1-a", key(1, 1)), list("2-a", key(1, 1)), list("3-a")}}
	ck := &checker{ctx: context.Background()}
	w := &retWalk{ck: ck, places: map[int][]string{}, doubts: map[[2]int][]string{}}
	type seenReturn struct {
		set string
		r   returned
	}
	var got []seenReturn
	err := w.run([]group{g}, func(l setList, at int, r returned, s shown) {
		got = append(got, seenReturn{l.set, r})
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d returns, want 2: %v", len(got), got)
	}
	for _, x := range got {
		want := map[string]string{"1-a": "2-a", "2-a": "1-a"}[x.set]
		if x.r.holder != want || x.r.fpHolder != want {
			t.Errorf("the key of %s was held on %q (fingerprint %q), want %q", x.set, x.r.holder, x.r.fpHolder, want)
		}
		if !x.r.pinCase || !x.r.fpCase {
			t.Errorf("%s: pin %v, fingerprint %v", x.set, x.r.pinCase, x.r.fpCase)
		}
	}
	// The same through a cancelled context: the walk stops with the error of the context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = &retWalk{ck: &checker{ctx: ctx}, places: map[int][]string{}, doubts: map[[2]int][]string{}}
	if err := w.run([]group{g}, func(setList, int, returned, shown) { t.Error("a visit after the context ended") }); err == nil {
		t.Error("the walk of a context that ended returned no error")
	}
}

// The words of a finding about the list before are for a finding whose order is sure and whose place
// is known; a finding with doubt names the sets of the place, and a floating one names no list.
func TestReturnDetailNamesTheListBeforeOnlyWhenTheOrderIsSure(t *testing.T) {
	k := rootKey{label: "A", hasPin: true}
	base := returned{k: k, pinCase: true, holder: "h", prevSet: "p", known: true}
	if d := returnDetail(base); !strings.HasSuffix(d, "; pin held on trust/h; list before trust/p") {
		t.Errorf("a sure order: %q", d)
	}
	unsure := base
	unsure.doubt = []string{"a", "b"}
	if d := returnDetail(unsure); strings.Contains(d, "; list before trust/") || !strings.HasSuffix(d, "; among trust/a, trust/b; pin held on trust/h") {
		t.Errorf("an order that is not sure: %q", d)
	}
	floating := base
	floating.floating = true
	if d := returnDetail(floating); strings.Contains(d, "; list before trust/") || !strings.Contains(d, "the place of this trust set in the chain cannot be told") {
		t.Errorf("a place that cannot be told: %q", d)
	}
	none := base
	none.prevSet = ""
	if d := returnDetail(none); strings.Contains(d, "; list before trust/") {
		t.Errorf("no list before: %q", d)
	}
}

// ctxAfter is a context that is alive for its first n calls of Err and ended after them, so that a
// test ends the context at a chosen step of the walk, with no waiting.
type ctxAfter struct {
	context.Context
	n *int
}

func (c ctxAfter) Err() error {
	if *c.n > 0 {
		*c.n--
		return nil
	}
	return context.Canceled
}

// A context that ends in the middle of the walk of the lists ends the check with its error, whichever
// walk it ends in: the one walk of a sure order, the first, the second and the third of an order that
// is not sure, and the pass over the lists whose place cannot be told. No finding is kept as if the
// run had been whole.
func TestRootReturnsAContextThatEndsInTheWalkEndsTheRun(t *testing.T) {
	key := func(pin byte) rootKey {
		k := rootKey{label: "K", hasPin: true}
		k.pin[0] = pin
		return k
	}
	list := func(set string, seq int64, keys ...rootKey) setList {
		return setList{set: set, read: &anchorOf{hasSequence: true, sequence: seq, keys: keys}}
	}
	// Three sets that no record lists and that name no record: all stand at place 0. By sequence
	// the order is 9-a, 2-a, 3-a and the key K stays; by number it is 2-a, 3-a, 9-a and K returns at
	// 9-a. Only the second reading shows it.
	unsureLists := []setList{list("2-a", 2, key(1)), list("3-a", 3), list("9-a", 1, key(1))}
	// By sequence the order is 5-a, 2-a, 3-a and K returns at 3-a; by number it is 2-a, 3-a, 5-a and
	// K does not return. Only the first reading shows it, so that the third walk runs.
	thirdLists := []setList{list("5-a", 1, key(1)), list("2-a", 2), list("3-a", 3, key(1))}
	cases := []struct {
		name  string
		lists []setList
		extra []setList // sets whose place cannot be told
		steps int       // calls of Err that stay alive before the context ends
	}{
		{"a sure order", []setList{list("1-a", 1, key(1)), list("2-a", 2), list("3-a", 3, key(1))}, nil, 0},
		{"a sure order, the second group", []setList{list("1-a", 1, key(1)), list("2-a", 2), list("3-a", 3, key(1))}, nil, 1},
		{"the first reading", unsureLists, nil, 0},
		{"the second reading", unsureLists, nil, 3},
		{"the third walk", thirdLists, nil, 6},
		{"the pass over the sets with no place", []setList{list("1-a", 1, key(1))}, []setList{{set: "9-z", read: &anchorOf{keys: []rootKey{key(1)}}}}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := c.steps
			ck := &checker{ctx: ctxAfter{context.Background(), &n}, col: newCollector(MaxFindingsPerCode), listed: map[string]*anchorWant{}, depth: map[string]int{}}
			for _, l := range c.lists {
				l.read.present = false // names no record: it follows none
				ck.rootLists = append(ck.rootLists, l)
			}
			for _, l := range c.extra {
				l.read.present, l.read.value = true, strings.Repeat("e", 64) // names a digest that is no record
				ck.rootLists = append(ck.rootLists, l)
			}
			if err := ck.rootReturns(); !errors.Is(err, context.Canceled) {
				t.Errorf("rootReturns = %v, want context.Canceled", err)
			}
		})
	}
	// With a context that never ends the same lists give their findings.
	for _, c := range []struct {
		lists []setList
		set   string
	}{{unsureLists, "9-a"}, {thirdLists, "3-a"}} {
		n := 1 << 20
		ck := &checker{ctx: ctxAfter{context.Background(), &n}, col: newCollector(MaxFindingsPerCode), listed: map[string]*anchorWant{}, depth: map[string]int{}}
		ck.rootLists = append(ck.rootLists, c.lists...)
		if err := ck.rootReturns(); err != nil {
			t.Fatal(err)
		}
		if got := ck.col.list; len(got) != 1 || got[0].Path != listPath(c.set) || !strings.Contains(got[0].Detail, "the order of the trust sets is not sure") {
			t.Errorf("findings %v, want one at %s that says the order is not sure", got, c.set)
		}
	}
}
