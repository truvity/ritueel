//go:build linux || darwin

package history

import (
	"strings"
	"testing"
)

// Units of the words of a finding and of the holders of a key, for what a whole bundle cannot reach.

// The names in the words of a finding are escaped, whatever they hold, and cut to 40 bytes with
// three dots when they are longer; 40 bytes are kept whole.
func TestReturnDetailEscapesAndCutsTheNamesOfSets(t *testing.T) {
	k := rootKey{label: "A", hasPin: true}
	r := returned{k: k, pinCase: true, holder: "h h\n", doubt: []string{"a b", "c" + bs + "d"}}
	d := returnDetail(r)
	if want := "among trust/a" + bs + "x20b, trust/c" + bs + bs + "d"; !strings.Contains(d, want) {
		t.Errorf("the detail %q lacks %q", d, want)
	}
	if want := "pin held on trust/h" + bs + "x20h" + bs + "u000a"; !strings.Contains(d, want) {
		t.Errorf("the detail %q does not escape the holder", d)
	}
	if !printable(d) || strings.ContainsAny(d, "\r\n") {
		t.Errorf("the detail is not one line of printable ASCII: %q", d)
	}
	name := func(n int) string { return strings.Repeat("x", n) }
	for _, c := range []struct {
		n    int
		want string
	}{{39, name(39)}, {40, name(40)}, {41, name(40) + "..."}, {200, name(40) + "..."}} {
		got := returnDetail(returned{k: k, pinCase: true, known: true, holder: name(c.n), doubt: []string{name(c.n)}})
		if want := "among trust/" + c.want + "; pin held on trust/" + c.want; !strings.HasSuffix(got, want) {
			t.Errorf("a name of %d bytes: %q does not end with %q", c.n, got, want)
		}
	}
	// A label is escaped too.
	d = returnDetail(returned{k: rootKey{label: "A\nB\"", hasPin: true}, pinCase: true, holder: "h", prevSet: "p", known: true})
	if !strings.HasPrefix(d, `root key "A`+bs+`u000aB`) || strings.ContainsAny(d, "\n") {
		t.Errorf("the label is not escaped: %q", d)
	}
	// The path of a list is escaped.
	if got := listPath("a b"); got != "trust/a"+bs+"x20b/root-list.json" {
		t.Errorf("listPath = %q", got)
	}
}

// The holders of a key: the first set that held it, or the second when the first is the set judged;
// the set itself when no other held it.
func TestHoldersNameAnotherSet(t *testing.T) {
	var h *holders
	if got := h.other("x"); got != "x" {
		t.Errorf("no holders: %q", got)
	}
	h = &holders{}
	h.add("a")
	h.add("a") // the same set twice is one holder
	if h.n != 1 || h.b != "" {
		t.Errorf("holders %+v", h)
	}
	if got := h.other("a"); got != "a" {
		t.Errorf("only the set itself held it: %q", got)
	}
	if got := h.other("z"); got != "a" {
		t.Errorf("other(z) = %q", got)
	}
	h.add("b")
	h.add("c") // no third is kept
	if h.a != "a" || h.b != "b" || h.n != 2 {
		t.Errorf("holders %+v", h)
	}
	if got := h.other("a"); got != "b" {
		t.Errorf("other(a) = %q", got)
	}
	if got := h.other("b"); got != "a" {
		t.Errorf("other(b) = %q", got)
	}
}

// FindReturns names a holder other than the list judged, even when an earlier list has the same name.
func TestFindReturnsNamesAHolderThatIsNotTheListJudged(t *testing.T) {
	earlier := []RootList{rl("n", ent{"A", pa, f1}), rl("m", ent{"A", pa, f1}), rl("x", ent{"B", pb, ""})}
	got, err := FindReturns(earlier, rl("n", ent{"A", pa, f1}))
	if err != nil || len(got) != 1 {
		t.Fatalf("FindReturns = %v, %v", got, err)
	}
	if got[0].PinHeldOn != "m" || got[0].FingerprintHeldOn != "m" {
		t.Errorf("held on %q and %q, want m and m", got[0].PinHeldOn, got[0].FingerprintHeldOn)
	}
	// When the only holder has the name of the list, the name is the answer: a finding never names nothing.
	got, err = FindReturns([]RootList{rl("n", ent{"A", pa, f1}), rl("x", ent{"B", pb, ""})}, rl("n", ent{"A", pa, f1}))
	if err != nil || len(got) != 1 || got[0].PinHeldOn != "n" || got[0].FingerprintHeldOn != "n" {
		t.Errorf("FindReturns = %+v, %v", got, err)
	}
}

// A trust set that a ceremony lists and that has no root list (a personal bundle's set has none, record
// 0006, rule 12) is not in the order: the lists around it are neighbours.
func TestRootReturnsAListedSetWithNoRootListIsNotInTheOrder(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet(setN(1), keyList(1, kA)))
	b.apply(func(r *rec) {
		delete(r.artifacts, "trust/"+r.set+"/root-list.json")
		delete(r.artifacts, "trust/"+r.set+"/keys.txt")
		r.set = setN(2)
		r.artifacts["trust/"+setN(2)+"/keys.txt"] = []byte("keys\n")
		r.refresh()
	})
	b.apply(withSet(setN(3), keyList(3, kA)))
	rep := b.run()
	wantReturnsAt(t, rep)
	for _, f := range rep.Findings {
		if f.Code == AnchorUnknown {
			t.Errorf("a set with no root list is not anchor-unknown: %s", f.Line())
		}
	}
}
