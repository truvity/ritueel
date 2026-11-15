//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"
)

// FindReturns is the rule of the finding root-returns for one list and the lists before it, in the
// order of the ceremonies that wrote them (record 0006, rule 54). A writer that is about to write a
// list asks it before it writes, so it must give what the check gives for the same lists in a
// bundle whose order is the order of the lists.

// rl is a RootList whose entries are written from ent values: the pin, the fingerprint and the label.
func rl(name string, ents ...ent) RootList {
	l := RootList{Name: name}
	for _, e := range ents {
		l.Keys = append(l.Keys, RootKey{Label: e.label, Pin: e.pin, Fingerprint: e.fp})
	}
	return l
}

func unreadable(name string) RootList { return RootList{Name: name, Unreadable: true} }

func TestFindReturnsCases(t *testing.T) {
	type want struct {
		entry       int
		byPin, byFP bool
		pinOn, fpOn string
		prevUnread  bool
	}
	cases := []struct {
		name    string
		earlier []RootList
		list    RootList
		want    []want
	}{
		{"no list before: nothing returns", nil, rl("n", ent{"A", pa, f1}, ent{"B", pb, ""}), nil},
		{"a key that stays", []RootList{rl("a", ent{"A", pa, ""})}, rl("n", ent{"A", pa, ""}), nil},
		{"a key that left and returns", []RootList{rl("a", ent{"A", pa, ""}), rl("b", ent{"B", pb, ""})}, rl("n", ent{"A", pa, ""}),
			[]want{{entry: 0, byPin: true, pinOn: "a"}}},
		{"a new label is the same key", []RootList{rl("a", ent{"A", pa, ""}), rl("b", ent{"B", pb, ""})}, rl("n", ent{"Z", pa, ""}),
			[]want{{entry: 0, byPin: true, pinOn: "a"}}},
		{"the first list that held the key is named, not the last", []RootList{rl("a", ent{"A", pa, ""}), rl("b", ent{"A", pa, ""}), rl("c", ent{"B", pb, ""})}, rl("n", ent{"A", pa, ""}),
			[]want{{entry: 0, byPin: true, pinOn: "a"}}},
		{"a fingerprint under another pin", []RootList{rl("a", ent{"A", pa, f1}), rl("b", ent{"B", pb, ""})}, rl("n", ent{"C", pc, f1}),
			[]want{{entry: 0, byFP: true, fpOn: "a"}}},
		{"a fingerprint with no pin", []RootList{rl("a", ent{"A", "", f1}), rl("b", ent{"B", pb, ""})}, rl("n", ent{"C", "", f1}),
			[]want{{entry: 0, byFP: true, fpOn: "a"}}},
		{"a change of the pin in one step", []RootList{rl("a", ent{"A", pa, f1})}, rl("n", ent{"A", pb, f1}),
			[]want{{entry: 0, byFP: true, fpOn: "a"}}},
		{"a fingerprint that stays under its pin", []RootList{rl("a", ent{"A", pa, f1})}, rl("n", ent{"A", pa, f1}), nil},
		{"both reasons", []RootList{rl("a", ent{"A", pa, f1}), rl("b", ent{"B", pb, ""})}, rl("n", ent{"X", pa, f1}),
			[]want{{entry: 0, byPin: true, byFP: true, pinOn: "a", fpOn: "a"}}},
		{"two entries, one returns", []RootList{rl("a", ent{"A", pa, ""}, ent{"B", pb, ""}), rl("b", ent{"B", pb, ""})}, rl("n", ent{"B", pb, ""}, ent{"A", pa, ""}),
			[]want{{entry: 1, byPin: true, pinOn: "a"}}},
		{"the same key twice is a finding for each entry", []RootList{rl("a", ent{"A", pa, ""}), rl("b", ent{"B", pb, ""})}, rl("n", ent{"A", pa, ""}, ent{"A2", pa, ""}),
			[]want{{entry: 0, byPin: true, pinOn: "a"}, {entry: 1, byPin: true, pinOn: "a"}}},
		{"digits in capitals, a prefix and colons are the same key", []RootList{rl("a", ent{"A", pa, ""}), rl("b", ent{"B", pb, ""})},
			rl("n", ent{"A", "0X" + strings.ToUpper(pa), ""}, ent{"C", "", pairs(f1, ":")}),
			[]want{{entry: 0, byPin: true, pinOn: "a"}}},
		{"a list before that cannot be read: the key is a return, and it says so",
			[]RootList{rl("a", ent{"A", pa, ""}), unreadable("b")}, rl("n", ent{"A", pa, ""}),
			[]want{{entry: 0, byPin: true, pinOn: "a", prevUnread: true}}},
		{"a list before that cannot be read, and no earlier list held the key",
			[]RootList{rl("a", ent{"B", pb, ""}), unreadable("b")}, rl("n", ent{"A", pa, ""}), nil},
		{"an earlier list that cannot be read holds no key",
			[]RootList{unreadable("a"), rl("b", ent{"B", pb, ""})}, rl("n", ent{"A", pa, ""}), nil},
		{"an earlier list with an entry that cannot be read is a list that cannot be read",
			[]RootList{rl("a", ent{"A", pa, ""}), {Name: "b", Keys: []RootKey{{Label: "B", Pin: pb}, {Label: "X", Pin: "zz"}}}}, rl("n", ent{"A", pa, ""}),
			[]want{{entry: 0, byPin: true, pinOn: "a", prevUnread: true}}},
		{"an earlier list with an entry that names nothing is a list that cannot be read",
			[]RootList{rl("a", ent{"A", pa, ""}), {Name: "b", Keys: []RootKey{{Label: "B"}}}}, rl("n", ent{"A", pa, ""}),
			[]want{{entry: 0, byPin: true, pinOn: "a", prevUnread: true}}},
		{"an unreadable list to judge gives none", []RootList{rl("a", ent{"A", pa, ""}), rl("b", ent{"B", pb, ""})}, unreadable("n"), nil},
		{"an empty list to judge", []RootList{rl("a", ent{"A", pa, ""})}, rl("n"), nil},
		{"empty lists before", []RootList{rl("a"), rl("b")}, rl("n", ent{"A", pa, ""}), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := FindReturns(c.earlier, c.list)
			if err != nil {
				t.Fatalf("FindReturns: %v", err)
			}
			var wantR []Return
			for _, w := range c.want {
				wantR = append(wantR, Return{Entry: w.entry, ByPin: w.byPin, ByFingerprint: w.byFP, PinHeldOn: w.pinOn, FingerprintHeldOn: w.fpOn, PreviousUnreadable: w.prevUnread})
			}
			if !slices.Equal(got, wantR) {
				t.Errorf("got %+v\nwant %+v", got, wantR)
			}
		})
	}
}

// A list with an entry whose pin or fingerprint cannot be read, or that names neither, cannot be
// judged: the error says so and names the list.
func TestFindReturnsRefusesAListWithAnEntryItCannotRead(t *testing.T) {
	earlier := []RootList{rl("a", ent{"A", pa, ""})}
	bad := map[string]RootKey{
		"a pin of 63 digits":           {Label: "A", Pin: pa[:63]},
		"a pin that is not hex":        {Label: "A", Pin: strings.Repeat("g", 64)},
		"a fingerprint of 39 digits":   {Label: "A", Pin: pa, Fingerprint: f1[:39]},
		"a fingerprint of 41 digits":   {Label: "A", Pin: pa, Fingerprint: f1 + "0"},
		"no pin and a bad fingerprint": {Label: "A", Fingerprint: "zz"},
		"neither pin nor fingerprint":  {Label: "A"},
		"a byte that is not UTF-8":     {Label: "A", Pin: pa[:10] + "\xff" + pa[11:]},
		"a NUL":                        {Label: "A", Pin: pa[:10] + "\x00" + pa[11:]},
		"white space only":             {Label: "A", Pin: " \t\n"},
	}
	for name, k := range bad {
		t.Run(name, func(t *testing.T) {
			got, err := FindReturns(earlier, RootList{Name: "the-list", Keys: []RootKey{{Label: "B", Pin: pb}, k}})
			if !errors.Is(err, ErrRootKey) || got != nil {
				t.Fatalf("FindReturns = %v, %v; want ErrRootKey", got, err)
			}
			if !strings.Contains(err.Error(), `"the-list"`) {
				t.Errorf("the error does not name the list: %v", err)
			}
		})
	}
	t.Run("a list that is marked unreadable is not read, so its entries are not refused", func(t *testing.T) {
		l := RootList{Name: "x", Unreadable: true, Keys: []RootKey{{Pin: "zz"}}}
		got, err := FindReturns(earlier, l)
		if err != nil || got != nil {
			t.Errorf("FindReturns = %v, %v", got, err)
		}
	})
	t.Run("a name with a quote is quoted", func(t *testing.T) {
		_, err := FindReturns(nil, RootList{Name: "a\"b\n", Keys: []RootKey{{}}})
		if !errors.Is(err, ErrRootKey) || strings.ContainsAny(err.Error(), "\n") {
			t.Errorf("error %q", err)
		}
	})
}

func TestFindReturnsDoesNotChangeWhatItIsGiven(t *testing.T) {
	earlier := []RootList{rl("a", ent{"A", pa, f1}), rl("b", ent{"B", pb, ""})}
	list := rl("n", ent{"A", " " + strings.ToUpper(pa) + "\n", f1}, ent{"C", pc, ""})
	before := fmt.Sprintf("%+v %+v", earlier, list)
	for i := 0; i < 3; i++ {
		if _, err := FindReturns(earlier, list); err != nil {
			t.Fatal(err)
		}
	}
	if after := fmt.Sprintf("%+v %+v", earlier, list); after != before {
		t.Errorf("the input changed:\n%s\n%s", before, after)
	}
}

// The work is linear in the entries: many lists before, each with 26 entries.
func TestFindReturnsIsLinearInTheEntries(t *testing.T) {
	const lists = 10000
	var earlier []RootList
	for i := 0; i < lists; i++ {
		var es []ent
		for j := 0; j < 26; j++ {
			es = append(es, ent{"A", pinOf(i*26 + j), fpOf(i*26 + j)})
		}
		earlier = append(earlier, rl(fmt.Sprint(i), es...))
	}
	var es []ent
	for j := 0; j < 26; j++ {
		es = append(es, ent{"A", pinOf(j), ""})
	}
	start := time.Now()
	got, err := FindReturns(earlier, rl("n", es...))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 26 {
		t.Errorf("%d returns, want 26", len(got))
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("took %v", d)
	}
}

// Hostile text in a key: never a panic, and a refusal when it is not a key.
func TestFindReturnsHostileText(t *testing.T) {
	huge := strings.Repeat("a", 4<<20)
	for _, k := range []RootKey{
		{Pin: huge}, {Fingerprint: huge}, {Label: huge, Pin: pa},
		{Pin: strings.Repeat("0x", 1000) + pa}, {Pin: strings.Repeat(" ", 1<<20)},
		{Pin: strings.Repeat("\xff", 64)}, {Fingerprint: strings.Repeat("\x00", 40)},
	} {
		_, _ = FindReturns([]RootList{rl("a", ent{"A", pa, ""})}, RootList{Name: "n", Keys: []RootKey{k}})
		_, _ = FindReturns([]RootList{{Name: "a", Keys: []RootKey{k}}}, rl("n", ent{"A", pa, ""}))
	}
}

// A list of the check and a list of FindReturns say the same: the lists of a bundle whose order is
// the order of the ceremonies, judged one after the other with FindReturns, give the findings of
// the check at the same entries and for the same reasons.
func TestFindReturnsGivesWhatTheCheckGives(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261117, 3))
	for iter := 0; iter < 1500; iter++ {
		n := 1 + rng.IntN(6)
		var lists []mList
		for i := 0; i < n; i++ {
			l := mList{num: i + 1, seq: i + 1}
			if rng.IntN(8) == 0 {
				l.damaged = 1 + rng.IntN(3)
			} else {
				for k, c := 0, rng.IntN(5); k < c; k++ {
					e := mEnt{label: fmt.Sprintf("L%dE%d", i, k), pin: 1 + rng.IntN(mPins), form: rng.IntN(4) * (rng.IntN(5) / 4)}
					if rng.IntN(2) == 0 {
						e.fp = 1 + rng.IntN(mFPs)
					}
					if e.fp != 0 && rng.IntN(4) == 0 {
						e.pin = 0
					}
					l.ents = append(l.ents, e)
				}
			}
			lists = append(lists, l)
		}
		b := mBundle{}
		for _, l := range lists {
			b.sets = append(b.sets, mSet{mList: l, claim: listedByCeremony})
		}
		rep, err := runMem(t, b.build(t))
		if err != nil {
			t.Fatal(err)
		}
		byPath := map[string][]Finding{}
		for _, f := range returnsOf(rep) {
			byPath[f.Path] = append(byPath[f.Path], f)
		}
		var earlier []RootList
		for i, l := range lists {
			cur := textList(b.name(i), l)
			got, err := FindReturns(earlier, cur)
			if err != nil {
				t.Fatalf("FindReturns: %v", err)
			}
			var gotS, wantS []string
			for _, r := range got {
				gotS = append(gotS, fmt.Sprintf("%s pin=%v fp=%v", l.ents[r.Entry].label, r.ByPin, r.ByFingerprint))
			}
			for _, f := range byPath[listPathOf(b.name(i))] {
				label := labelOfDetail(f.Detail)
				wantS = append(wantS, fmt.Sprintf("%s pin=%v fp=%v", label, strings.Contains(f.Detail, "its pin "), strings.Contains(f.Detail, "OpenPGP fingerprint")))
			}
			slices.Sort(gotS)
			slices.Sort(wantS)
			if !slices.Equal(gotS, wantS) && !cutDetail(byPath[listPathOf(b.name(i))]) {
				t.Fatalf("list %d of %v\n FindReturns: %v\n      check: %v", i+1, describe(b), gotS, wantS)
			}
			earlier = append(earlier, cur)
		}
	}
}

// labelOfDetail is the label that a finding of root-returns names.
func labelOfDetail(detail string) string {
	label, _, _ := strings.Cut(strings.TrimPrefix(detail, `root key "`), `"`)
	return label
}

// cutDetail says whether a detail was cut at its bound, so that a reason may be missing from it.
func cutDetail(fs []Finding) bool {
	for _, f := range fs {
		if strings.HasSuffix(f.Detail, "...") {
			return true
		}
	}
	return false
}

// textList is a RootList of the entries of a model list, with the text the file would have.
func textList(name string, l mList) RootList {
	r := RootList{Name: name}
	if !l.readable() {
		r.Unreadable = true
		return r
	}
	for _, e := range l.ents {
		k := RootKey{Label: e.label}
		if e.pin != 0 {
			k.Pin = writeForm(pinOf(e.pin), e.form)
		}
		if e.fp != 0 {
			k.Fingerprint = writeForm(fpOf(e.fp), e.form)
		}
		r.Keys = append(r.Keys, k)
	}
	return r
}

// The rule of view, the one place of the rule, against a brute force: every order of the lists
// inside the groups that tie. An entry is a return in the view when some order shows it as a
// return, and the view says so exactly then.
func TestViewAgreesWithEveryOrderOfTheGroups(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261118, 5))
	type lst struct {
		keys []rootKey
		ok   bool // the list can be read
	}
	mk := func() lst {
		if rng.IntN(7) == 0 {
			return lst{}
		}
		var keys []rootKey
		for k, c := 0, rng.IntN(4); k < c; k++ {
			var key rootKey
			if p := rng.IntN(5); p > 0 {
				key.hasPin = true
				key.pin[0] = byte(p)
			}
			if f := rng.IntN(4); f > 0 {
				key.hasFP = true
				key.fp[0] = byte(f)
			}
			if key.hasPin || key.hasFP {
				keys = append(keys, key)
			}
		}
		return lst{keys: keys, ok: true}
	}
	holdsPinL := func(l lst, k rootKey) bool {
		return l.ok && slices.ContainsFunc(l.keys, func(o rootKey) bool { return o.hasPin && k.hasPin && o.pin == k.pin })
	}
	holdsFPAnyL := func(l lst, k rootKey) bool {
		return l.ok && slices.ContainsFunc(l.keys, func(o rootKey) bool { return o.hasFP && k.hasFP && o.fp == k.fp })
	}
	holdsFPUnderL := func(l lst, k rootKey) bool {
		return l.ok && slices.ContainsFunc(l.keys, func(o rootKey) bool {
			return o.hasFP && k.hasFP && o.fp == k.fp && o.hasPin == k.hasPin && o.pin == k.pin
		})
	}
	for iter := 0; iter < 20000; iter++ {
		var groups [][]lst
		for g, ng := 0, 1+rng.IntN(4); g < ng; g++ {
			var grp []lst
			for i, c := 0, 1+rng.IntN(3); i < c; i++ {
				grp = append(grp, mk())
			}
			groups = append(groups, grp)
		}
		// The view of each group, as the check makes it.
		cum := &tally{}
		var prev *tally
		views := make([]view, len(groups))
		for gi, g := range groups {
			cur := &tally{size: len(g)}
			for _, l := range g {
				if l.ok {
					cur.addList(l.keys)
				}
			}
			views[gi] = view{cum: cum, prev: prev, cur: cur}
			next := &tally{}
			next.merge(cum)
			next.merge(cur)
			cum, prev = next, cur
		}
		// Brute force: every order of the sets inside each group.
		var orders [][][2]int // each order: the (group, index) pairs in sequence
		orders = append(orders, nil)
		for gi, g := range groups {
			idx := make([]int, len(g))
			for i := range idx {
				idx[i] = i
			}
			var next [][][2]int
			for _, p := range permutations(idx) {
				for _, o := range orders {
					oo := slices.Clone(o)
					for _, i := range p {
						oo = append(oo, [2]int{gi, i})
					}
					next = append(next, oo)
				}
			}
			orders = next
		}
		for gi, g := range groups {
			for li, l := range g {
				if !l.ok {
					continue
				}
				for _, k := range l.keys {
					var wantPin, wantFP bool
					for _, o := range orders {
						pos := slices.Index(o, [2]int{gi, li})
						var beforeHeldPin, beforeHeldFP bool
						for _, q := range o[:pos] {
							beforeHeldPin = beforeHeldPin || holdsPinL(groups[q[0]][q[1]], k)
							beforeHeldFP = beforeHeldFP || holdsFPAnyL(groups[q[0]][q[1]], k)
						}
						var lastPin, lastFP bool
						if pos > 0 {
							last := groups[o[pos-1][0]][o[pos-1][1]]
							lastPin, lastFP = holdsPinL(last, k), holdsFPUnderL(last, k)
						}
						wantPin = wantPin || (k.hasPin && beforeHeldPin && !lastPin)
						wantFP = wantFP || (k.hasFP && beforeHeldFP && !lastFP)
					}
					if got := views[gi].pinReturns(k); got != wantPin {
						t.Fatalf("pinReturns = %v, brute force %v\n groups %+v\n entry %+v at group %d list %d", got, wantPin, groups, k, gi, li)
					}
					if got := views[gi].fpReturns(k); got != wantFP {
						t.Fatalf("fpReturns = %v, brute force %v\n groups %+v\n entry %+v at group %d list %d", got, wantFP, groups, k, gi, li)
					}
				}
			}
		}
	}
}
