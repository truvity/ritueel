//go:build linux || darwin

package history

import (
	"fmt"
	"strings"
	"testing"
)

// The words of a finding of root-returns in two forms that this file holds exactly:
//
//   - when the order of the sets is not sure, the names of the sets whose order is not sure come
//     directly after the words that say so, before the citation of the rule and before the holders;
//   - when the only earlier holder of a key is the set itself, at an earlier place, the detail says
//     so in plain words and does not print the name of the set as if it were another set.
//
// The reason comes first in every form, a detail whose order is sure is as it was, and the bound of
// a detail cuts from the end.

const (
	wSameSet = "the same set at an earlier place"
)

// reasonCase is one reason of a finding, as the words say it.
type reasonCase struct {
	name    string
	pin, fp bool
	known   bool
}

func (c reasonCase) words() string {
	switch {
	case c.pin && c.fp && c.known:
		return wBoth(pa, f1)
	case c.pin && c.fp:
		return wBothUnread(pa, f1)
	case c.pin && c.known:
		return wPin(pa)
	case c.pin:
		return wPinUnread(pa)
	case c.known:
		return wFP(f1)
	}
	return wFPUnread(f1)
}

func (c reasonCase) key(label string) rootKey {
	k := rootKey{label: label}
	if c.pin {
		k.hasPin = true
		copy(k.pin[:], mustHex(pa))
	}
	if c.fp {
		k.hasFP = true
		copy(k.fp[:], mustHex(f1))
	}
	return k
}

func reasonCases() []reasonCase {
	var out []reasonCase
	for _, pin := range []bool{true, false} {
		for _, fp := range []bool{true, false} {
			if !pin && !fp {
				continue
			}
			for _, known := range []bool{true, false} {
				out = append(out, reasonCase{fmt.Sprintf("pin %v fp %v known %v", pin, fp, known), pin, fp, known})
			}
		}
	}
	return out
}

// holdersOf is the words that name the holders, in the order the detail gives them.
func holdersOf(c reasonCase, pinHolder, fpHolder string) string {
	var out string
	if c.pin {
		out += "; " + pinHolder
	}
	if c.fp {
		out += "; " + fpHolder
	}
	return out
}

func TestReturnDetailWhenTheOrderIsNotSureNamesTheSetsDirectlyAfterTheWords(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e", "f"}
	for _, c := range reasonCases() {
		for n := 1; n <= len(names); n++ {
			t.Run(fmt.Sprintf("%s, %d sets", c.name, n), func(t *testing.T) {
				r := returned{k: c.key("A"), pinCase: c.pin, fpCase: c.fp, holder: "h", fpHolder: "g", known: c.known, prevSet: "p", doubt: names[:n]}
				want := `root key "A" returns: ` + c.words() + "; " + wUnsure(names[:n]...) + holdersOf(c, wHeldPin("h"), wHeldFP("g"))
				if got := returnDetail(r); got != want {
					t.Errorf("the detail is\n%q\nwant\n%q", got, want)
				}
				// The words, in this order: the reason, the words that the order is not sure with
				// the names, the rule, the holders; no list before when the order is not sure.
				d := returnDetail(r)
				at := []int{
					strings.Index(d, c.words()),
					strings.Index(d, wNotSure),
					strings.Index(d, ", among trust/a"),
					strings.Index(d, wRule),
				}
				if c.pin {
					at = append(at, strings.Index(d, "; pin held on"))
				} else {
					at = append(at, strings.Index(d, "; fingerprint held on"))
				}
				for i := range at {
					if at[i] < 0 || (i > 0 && at[i] <= at[i-1]) {
						t.Errorf("the parts are not in the order reason, words, names, rule, holders: %v in %q", at, d)
						break
					}
				}
				if strings.Contains(d, "; list before trust/") {
					t.Errorf("a detail whose order is not sure names a list before: %q", d)
				}
				// The rule comes after the names and not before them.
				if i, j := strings.Index(d, " (record 0006, rule 54)"), strings.Index(d, "among trust/a"); j > i {
					t.Errorf("the citation comes before the names: %q", d)
				}
			})
		}
	}
}

// The words that say the order is not sure are directly followed by the names: no other words
// between them, whatever the reason.
func TestReturnDetailWhenTheOrderIsNotSureHasNoWordsBetweenTheWordsAndTheNames(t *testing.T) {
	for _, c := range reasonCases() {
		d := returnDetail(returned{k: c.key("A"), pinCase: c.pin, fpCase: c.fp, holder: "h", fpHolder: "g", known: c.known, doubt: []string{"x", "y"}})
		if want := wNotSure + ", among trust/x, trust/y (record 0006, rule 54)"; !strings.Contains(d, want) {
			t.Errorf("%s: the detail %q lacks %q", c.name, d, want)
		}
	}
}

// A detail whose order is sure is as it was, byte for byte, and so is a detail whose place cannot
// be told.
func TestReturnDetailWhenTheOrderIsSureIsAsItWas(t *testing.T) {
	for _, c := range reasonCases() {
		t.Run(c.name, func(t *testing.T) {
			sure := returned{k: c.key("A"), pinCase: c.pin, fpCase: c.fp, holder: "h", fpHolder: "g", known: c.known, prevSet: "p"}
			want := `root key "A" returns: ` + c.words() + wRule + holdersOf(c, wHeldPin("h"), wHeldFP("g")) + "; " + wBefore("p")
			if got := returnDetail(sure); got != want {
				t.Errorf("sure order:\n%q\nwant\n%q", got, want)
			}
			sure.prevSet = ""
			want = `root key "A" returns: ` + c.words() + wRule + holdersOf(c, wHeldPin("h"), wHeldFP("g"))
			if got := returnDetail(sure); got != want {
				t.Errorf("no list before:\n%q\nwant\n%q", got, want)
			}
		})
	}
	for _, c := range reasonCases() {
		if !c.known {
			continue
		}
		fl := returned{k: c.key("A"), pinCase: c.pin, fpCase: c.fp, holder: "h", fpHolder: "g", floating: true}
		var reason string
		switch {
		case c.pin && c.fp:
			reason = "its pin " + pa[:16] + "... and its OpenPGP fingerprint " + f1[:16] + "... were on another list"
		case c.pin:
			reason = "its pin " + pa[:16] + "... was on another list"
		default:
			reason = "its OpenPGP fingerprint " + f1[:16] + "... was on another list"
		}
		want := `root key "A" returns: ` + reason + "; the place of this trust set in the chain cannot be told" + wRule + holdersOf(c, wHeldPin("h"), wHeldFP("g"))
		if got := returnDetail(fl); got != want {
			t.Errorf("%s, a place that cannot be told:\n%q\nwant\n%q", c.name, got, want)
		}
	}
}

// The reason is whole for the longest label and the longest reason, in every form: the bound cuts
// what comes after it.
func TestReturnDetailTheReasonIsWholeForTheLongestLabelInEveryForm(t *testing.T) {
	labels := map[string]string{
		"16 controls":           strings.Repeat("\x01", 16),
		"16 backslashes":        strings.Repeat(`\`, 16),
		"four byte characters":  strings.Repeat(string(rune(0x1f600)), 4),
		"a letter":              "A",
		"16 bytes beyond ASCII": strings.Repeat(string(rune(0xe9)), 8),
	}
	long := strings.Repeat("n", 200)
	for ln, label := range labels {
		kept := cut(label, maxLabelShown)
		for _, c := range reasonCases() {
			for _, form := range []string{"sure", "not sure", "floating"} {
				t.Run(ln+" "+c.name+" "+form, func(t *testing.T) {
					r := returned{k: c.key(kept), pinCase: c.pin, fpCase: c.fp, holder: long, fpHolder: long, known: c.known, prevSet: long}
					reason := c.words()
					switch form {
					case "not sure":
						r.doubt = []string{long, long, long}
					case "floating":
						if !c.known {
							t.Skip("a floating place has no list before")
						}
						r.floating, r.known, r.prevSet = true, false, ""
						reason = floatingReason(c)
					}
					d := cut(returnDetail(r), maxDetail)
					if want := `root key "` + labelShown(kept) + `" returns: ` + reason; !strings.HasPrefix(d, want) {
						t.Errorf("the reason is not whole: %q does not start with %q", d, want)
					}
					if len(d) > maxDetail+len("...") || !printable(d) {
						t.Errorf("a detail of %d bytes, printable %v: %q", len(d), printable(d), d)
					}
					// Never the words that say the order is not sure, or the names, before the reason.
					if form == "not sure" {
						if i := strings.Index(d, wNotSure); i >= 0 && i < len(reason) {
							t.Errorf("the words about the order come before the end of the reason: %q", d)
						}
					}
				})
			}
		}
	}
}

func floatingReason(c reasonCase) string {
	switch {
	case c.pin && c.fp:
		return "its pin " + pa[:16] + "... and its OpenPGP fingerprint " + f1[:16] + "... were on another list; the place of this trust set in the chain cannot be told"
	case c.pin:
		return wPinFloating(pa)
	}
	return wFPFloating(f1)
}

// The bound holds: the longest label, the longest reason, six sets with names of 200 bytes, a pin
// and a fingerprint holder of 200 bytes: one line of printable ASCII of at most 243 bytes, a prefix
// of the detail that is not cut.
func TestReturnDetailTheBoundHoldsInTheFormWhereTheOrderIsNotSure(t *testing.T) {
	long := strings.Repeat("n", 200)
	c := reasonCase{pin: true, fp: true, known: false}
	r := returned{k: c.key(strings.Repeat("\x01", 16)), pinCase: true, fpCase: true, holder: long, fpHolder: long, doubt: []string{long, long, long, long, long, long}}
	full := returnDetail(r)
	d := cut(full, maxDetail)
	if len(d) > maxDetail+len("...") {
		t.Errorf("%d bytes", len(d))
	}
	if !strings.HasPrefix(full, strings.TrimSuffix(d, "...")) || !strings.HasSuffix(d, "...") {
		t.Errorf("the cut detail is not a cut of the whole one:\n%q\n%q", d, full)
	}
	if !printable(d) || strings.ContainsAny(d, "\r\n") {
		t.Errorf("not one line of printable ASCII: %q", d)
	}
	// The names are cut to 40 bytes each, in the form that names the sets before the holders.
	if want := "among trust/" + strings.Repeat("n", 40) + "..., trust/"; !strings.Contains(full, want) {
		t.Errorf("the names are not cut to 40 bytes: %q", full)
	}
}

// A set that more than one record lists is judged at its later place against its own earlier place:
// when that is the only earlier holder, the detail says so in plain words.
func TestReturnDetailWhenTheOnlyEarlierHolderIsTheSetItselfSaysSo(t *testing.T) {
	for _, c := range reasonCases() {
		t.Run(c.name, func(t *testing.T) {
			r := returned{k: c.key("A"), pinCase: c.pin, fpCase: c.fp, holder: "s", pinSelf: true, fpHolder: "s", fpSelf: true, known: c.known, prevSet: "p"}
			want := `root key "A" returns: ` + c.words() + wRule + holdersOf(c, "pin held on "+wSameSet, "fingerprint held on "+wSameSet) + "; " + wBefore("p")
			if got := returnDetail(r); got != want {
				t.Errorf("the detail is\n%q\nwant\n%q", got, want)
			}
			if strings.Contains(returnDetail(r), "trust/s") && !strings.Contains(returnDetail(r), "list before trust/s") {
				t.Errorf("the name of the set is printed as a holder: %q", returnDetail(r))
			}
		})
	}
	// Each reason has its own flag: the pin is held by the set itself and the fingerprint by another.
	k := reasonCase{pin: true, fp: true, known: true}
	r := returned{k: k.key("A"), pinCase: true, fpCase: true, holder: "s", pinSelf: true, fpHolder: "o", known: true}
	want := `root key "A" returns: ` + wBoth(pa, f1) + wRule + "; pin held on " + wSameSet + "; " + wHeldFP("o")
	if got := returnDetail(r); got != want {
		t.Errorf("pin by the set itself:\n%q\nwant\n%q", got, want)
	}
	r = returned{k: k.key("A"), pinCase: true, fpCase: true, holder: "o", fpHolder: "s", fpSelf: true, known: true}
	want = `root key "A" returns: ` + wBoth(pa, f1) + wRule + "; " + wHeldPin("o") + "; fingerprint held on " + wSameSet
	if got := returnDetail(r); got != want {
		t.Errorf("fingerprint by the set itself:\n%q\nwant\n%q", got, want)
	}
	// With the order not sure, the names of the sets come first and the same words follow.
	r = returned{k: k.key("A"), pinCase: true, fpCase: true, holder: "s", pinSelf: true, fpHolder: "s", fpSelf: true, doubt: []string{"x", "y"}}
	want = `root key "A" returns: ` + wBothUnread(pa, f1) + "; " + wUnsure("x", "y") + "; pin held on " + wSameSet + "; fingerprint held on " + wSameSet
	if got := returnDetail(r); got != want {
		t.Errorf("order not sure:\n%q\nwant\n%q", got, want)
	}
}

// The same on whole bundles: a set that two records list, the key leaves in between and returns at
// the later place. A name that is another set is printed.
func TestRootReturnsASetThatReturnsAgainstItselfSaysTheSameSet(t *testing.T) {
	t.Run("the key was held only by the set itself", func(t *testing.T) {
		b := chainBundle(t, true,
			cset{setN(1), seqList("1", kA, kB)},
			cset{setN(2), seqList("2", kB)},
		)
		b.apply(withSet(setN(1), seqList("1", kA, kB)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		wantReturnsAt(t, rep, setN(1)+" A")
		f := firstReturn(t, rep)
		want := `root key "A" returns: ` + wPin(pa) + wRule + "; pin held on " + wSameSet + "; " + wBefore(setN(2))
		if f.Detail != want {
			t.Errorf("the detail is\n%q\nwant\n%q", f.Detail, want)
		}
		if strings.Contains(f.Detail, "held on trust/") {
			t.Errorf("the set names itself: %q", f.Detail)
		}
	})
	t.Run("the fingerprint was held only by the set itself", func(t *testing.T) {
		kf := ent{"F", "", f1}
		b := chainBundle(t, true,
			cset{setN(1), seqList("1", kf, kB)},
			cset{setN(2), seqList("2", kB)},
		)
		b.apply(withSet(setN(1), seqList("1", kf, kB)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		wantReturnsAt(t, rep, setN(1)+" F")
		f := firstReturn(t, rep)
		if !strings.Contains(f.Detail, "; fingerprint held on "+wSameSet) || strings.Contains(f.Detail, "held on trust/") {
			t.Errorf("the detail is %q", f.Detail)
		}
	})
	t.Run("another set held the key too: it is named", func(t *testing.T) {
		// A is on set 1 and on set 2, then on neither, and set 1 stands again: A returns, and the
		// other holder is set 2.
		b := chainBundle(t, true,
			cset{setN(1), seqList("1", kA, kB)},
			cset{setN(2), seqList("2", kA, kB)},
			cset{setN(3), seqList("3", kB)},
		)
		b.apply(withSet(setN(1), seqList("1", kA, kB)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		wantReturnsAt(t, rep, setN(1)+" A")
		f := firstReturn(t, rep)
		if !strings.Contains(f.Detail, "; "+wHeldPin(setN(2))) || strings.Contains(f.Detail, wSameSet) {
			t.Errorf("the detail is %q", f.Detail)
		}
	})
	t.Run("a set that is judged once never says it", func(t *testing.T) {
		rep := runLists(t, keyList(0, kA, kB), keyList(0, kB), keyList(0, kA))
		wantReturnsAt(t, rep, setN(3)+" A")
		f := firstReturn(t, rep)
		if strings.Contains(f.Detail, wSameSet) || !strings.Contains(f.Detail, "; "+wHeldPin(setN(1))) {
			t.Errorf("the detail is %q", f.Detail)
		}
	})
}

// A set judged at two places where the key is held by the set itself and the order is not sure:
// the names of the sets come first and the same words follow.
func TestRootReturnsASetThatReturnsAgainstItselfWithAnOrderThatIsNotSure(t *testing.T) {
	// The last record lists two sets, so they stand at one place and every order of them is judged;
	// one of them is a set that an earlier record listed.
	b := chainBundle(t, true)
	b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
	b.apply(withSet("3-aaaaaaaa", seqList("3", kB)))
	b.apply(withSets(cset{"1-aaaaaaaa", seqList("1", kA, kB)}, cset{"4-aaaaaaaa", seqList("4", kB)}))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	wantReturnsAt(t, rep, "1-aaaaaaaa A")
	f := firstReturn(t, rep)
	want := `root key "A" returns: ` + wPin(pa) + "; " + wUnsure("1-aaaaaaaa", "4-aaaaaaaa") + "; pin held on " + wSameSet
	// The bound of a detail cuts the end: the words about the holder.
	if want = cut(want, maxDetail); f.Detail != want {
		t.Errorf("the detail is\n%q\nwant\n%q", f.Detail, want)
	}
}
