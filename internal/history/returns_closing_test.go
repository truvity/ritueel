//go:build linux || darwin

package history

import (
	"fmt"
	"strings"
	"testing"
)

// The finding root-returns for a set that a closing record lists. A closing record is a record of
// the chain like any other (record 0006, rule 8), so the set it lists stands at its place, and not
// at the end that the plan of the closed ceremony names: that plan is a file that the writer of the
// closing record can make, and no digest of the chain covers it.

// planNames makes the plan of the ceremony name the record with this digest as the end, as a plan
// does, and works out the plan, the attempt and the record again.
func planNames(digest string) func(*rec) {
	return func(r *rec) {
		r.plan.LastRecordSHA256 = digest
		r.refresh()
	}
}

// withSets makes the record list these sets, each with its root list as given (anchored to the
// record before, as every other root list of these bundles).
func withSets(sets ...cset) func(*rec) {
	return func(r *rec) {
		r.artifacts = map[string][]byte{}
		for _, s := range sets {
			r.artifacts["trust/"+s.name+"/root-list.json"] = anchored(s.list, r.record.PrevRecordSHA256)
			r.artifacts["trust/"+s.name+"/keys.txt"] = []byte("keys of " + s.name + "\n")
		}
		r.refresh()
	}
}

// listsNewSet makes a closing record list a set of its own, whatever the stopped ceremony left.
func listsNewSet(name string, list []byte) func(*rec) {
	return func(r *rec) {
		r.artifacts["trust/"+name+"/root-list.json"] = list
		r.artifacts["trust/"+name+"/keys.txt"] = []byte("keys of " + name + "\n")
		r.refresh()
	}
}

// The plan of the closed ceremony names an old end, the anchor of the list names the same old end,
// and the closing record is the newest record. The set stands at the closing record, after the
// record of the second ceremony, which lacks A: A returns. Were the set placed at the end that the
// plan names, it would stand next to the second ceremony, ordered before it by its own statements,
// and no finding would be made.
func TestRootReturnsAClosingRecordCannotPlaceItsSetByAPlan(t *testing.T) {
	build := func(t *testing.T) (*bundle, *rec, *rec) {
		b := newBundle(t)
		first := b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
		b.apply(withSet("2-bbbbbbbb", seqList("2", kB)))
		return b, first, nil
	}
	t.Run("a stopped ceremony whose plan names the first record", func(t *testing.T) {
		b, first, _ := build(t)
		stopped := b.unfinished(withSet("1-zzzzzzzz", anchored(seqList("1", kA, kB), first.digest)), planNames(first.digest))
		b.closing(stopped, listsLeftover(stopped, nil))
		rep := b.run()
		wantReturnsAt(t, rep, "1-zzzzzzzz A")
		noNotSure(t, rep)
		f := firstReturn(t, rep)
		for _, w := range []string{wPin(pa) + wRule, "; " + wHeldPin("1-aaaaaaaa"), "; " + wBefore("2-bbbbbbbb")} {
			if !strings.Contains(f.Detail, w) {
				t.Errorf("the detail %q lacks %q", f.Detail, w)
			}
		}
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown {
				t.Errorf("the anchor is the end that the plan names: %s", f.Line())
			}
		}
	})
	t.Run("the closing record closes the second ceremony itself", func(t *testing.T) {
		b, first, _ := build(t)
		second := b.recs[1]
		b.closing(second, listsNewSet("1-zzzzzzzz", anchored(seqList("1", kA, kB), first.digest)))
		rep := b.run()
		wantReturnsAt(t, rep, "1-zzzzzzzz A")
	})
	t.Run("the plan names no record and the set names none", func(t *testing.T) {
		b, _, _ := build(t)
		stopped := b.unfinished(withSet("0-zzzzzzzz", seqList("0", kA, kB)), planNames(""))
		b.closing(stopped, listsLeftover(stopped, nil))
		rep := b.run()
		wantReturnsAt(t, rep, "0-zzzzzzzz A")
	})
	t.Run("the plan names the newest record: the same place", func(t *testing.T) {
		// The honest closing: the plan end and the record before the closing record are one record,
		// and the set stands at one place by either word. A returns all the same: the set follows
		// the second ceremony, whose list lacks A.
		b, _, _ := build(t)
		stopped := b.unfinished(withSet("3-aaaaaaaa", seqList("3", kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		wantReturnsAt(t, b.run(), "3-aaaaaaaa A")
	})
}

// An honest closing: the stopped ceremony is closed before the next ceremony runs, and the list it
// left holds no key that left in between. Nothing is a return, and nothing is not sure.
func TestRootReturnsAnHonestClosingIsClean(t *testing.T) {
	t.Run("closed at once, then the chain goes on", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
		stopped := b.unfinished(withSet("2-aaaaaaaa", seqList("2", kA, kB)))
		b.closing(stopped, listsLeftover(stopped, nil))
		b.apply(withSet("4-aaaaaaaa", seqList("4", kA)))
		b.apply(withSet("5-aaaaaaaa", seqList("5", kA)))
		wantReturnsAt(t, b.run())
	})
	t.Run("a stopped ceremony that nothing closes yet", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
		b.unfinished(withSet("2-aaaaaaaa", seqList("2", kA, kB)))
		rep := b.run()
		wantReturnsAt(t, rep)
		noNotSure(t, rep)
	})
	t.Run("a late closing of a list that holds only keys of the list before it", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
		stopped := b.unfinished(withSet("2-aaaaaaaa", seqList("2", kA)))
		b.apply(withSet("3-aaaaaaaa", seqList("3", kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		wantReturnsAt(t, b.run())
	})
	t.Run("a closing record that lists nothing", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withSet("1-aaaaaaaa", seqList("1", kA)))
		stopped := b.unfinished(withSet("2-aaaaaaaa", seqList("2", kA)))
		b.closing(stopped)
		b.apply(withSet("4-aaaaaaaa", seqList("4", kA)))
		wantReturnsAt(t, b.run())
	})
}

// A late honest closing whose list holds a key that left since (record 0006, rule 54: no list may add
// a pin that an earlier list held). The set stands after the set of the ceremony that ran in
// between, and the key returns at it.
func TestRootReturnsALateClosingWithAKeyThatLeftIsAReturnAtTheClosedSet(t *testing.T) {
	for _, between := range []int{1, 2, 4} {
		t.Run(fmt.Sprintf("%d ceremonies in between", between), func(t *testing.T) {
			b := newBundle(t)
			b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
			stopped := b.unfinished(withSet("2-aaaaaaaa", seqList("2", kA, kB)))
			for i := 0; i < between; i++ {
				b.apply(withSet(fmt.Sprintf("%d-aaaaaaaa", 3+i), seqList(fmt.Sprint(3+i), kB)))
			}
			b.closing(stopped, listsLeftover(stopped, nil))
			rep := b.run()
			wantReturnsAt(t, rep, "2-aaaaaaaa A")
			noNotSure(t, rep)
			if got := firstReturn(t, rep).Detail; !strings.Contains(got, wBefore(fmt.Sprintf("%d-aaaaaaaa", 2+between))) {
				t.Errorf("the detail %q does not name the list before", got)
			}
		})
	}
}

// A closing record placed among the records that follow it: the set it lists is a list before the
// ceremonies that come after it, whatever the sets of those ceremonies are named.
func TestRootReturnsTheListAfterAClosingRecordHasTheClosedSetBeforeIt(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet("1-aaaaaaaa", seqList("1", kA)))
	stopped := b.unfinished(withSet("2-aaaaaaaa", seqList("2", kB)))
	b.closing(stopped, listsLeftover(stopped, nil))
	// The ceremony after the closing record brings A back: the list before it is the closed set,
	// which holds B only. The name of its set and its sequence say it is the oldest of all.
	b.apply(withSet("0-aaaaaaaa", seqList("0", kA)))
	rep := b.run()
	wantReturnsAt(t, rep, "0-aaaaaaaa A")
	noNotSure(t, rep)
	if got := firstReturn(t, rep).Detail; !strings.Contains(got, wBefore("2-aaaaaaaa")) {
		t.Errorf("the detail %q does not name the closed set as the list before", got)
	}
}

// One record that lists more than one set: the chain does not order the sets of one record, and the
// names and the sequences are written by the writer of that record. Every order is judged.
func TestRootReturnsOneRecordThatListsTwoSetsIsJudgedInEveryOrder(t *testing.T) {
	build := func(t *testing.T, x, y cset) *Report {
		b := chainBundle(t, true,
			cset{"1-aaaaaaaa", seqList("1", kA)},
			cset{"2-aaaaaaaa", seqList("2", kA)},
		)
		b.apply(withSets(x, y))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		checkReport(t, rep)
		return rep
	}
	// y holds A, x holds B. In the order x, y the list before y lacks A, and A returns at y; in the
	// order y, x the list before y holds A.
	t.Run("the statements put the set that lacks the key first", func(t *testing.T) {
		rep := build(t, cset{"3-aaaaaaaa", seqList("3", kB)}, cset{"4-aaaaaaaa", seqList("4", kA)})
		wantReturnsAt(t, rep, "4-aaaaaaaa A")
		allNotSure(t, rep)
	})
	t.Run("the statements put the set that holds the key first", func(t *testing.T) {
		rep := build(t, cset{"4-aaaaaaaa", seqList("4", kB)}, cset{"3-aaaaaaaa", seqList("3", kA)})
		wantReturnsAt(t, rep, "3-aaaaaaaa A")
		allNotSure(t, rep)
	})
	t.Run("the statements are missing", func(t *testing.T) {
		rep := build(t, cset{"3-aaaaaaaa", rootsJSON(0, kB)}, cset{"4-aaaaaaaa", rootsJSON(0, kA)})
		wantReturnsAt(t, rep, "4-aaaaaaaa A")
		allNotSure(t, rep)
	})
	t.Run("the detail names the sets of the place", func(t *testing.T) {
		rep := build(t, cset{"3-aaaaaaaa", seqList("3", kB)}, cset{"4-aaaaaaaa", seqList("4", kA)})
		f := firstReturn(t, rep)
		if want := "; " + wAmong("3-aaaaaaaa", "4-aaaaaaaa"); !strings.Contains(f.Detail, want) {
			t.Errorf("the detail %q lacks %q", f.Detail, want)
		}
	})
	t.Run("both keys stay: no finding in either order", func(t *testing.T) {
		rep := build(t, cset{"3-aaaaaaaa", seqList("3", kA)}, cset{"4-aaaaaaaa", seqList("4", kA)})
		wantReturnsAt(t, rep)
	})
	t.Run("three sets of one record", func(t *testing.T) {
		b := chainBundle(t, true, cset{"1-aaaaaaaa", seqList("1", kA)})
		b.apply(withSets(
			cset{"2-aaaaaaaa", seqList("2", kB)},
			cset{"3-aaaaaaaa", seqList("3", kK)},
			cset{"4-aaaaaaaa", seqList("4", kA)},
		))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		wantReturnsAt(t, rep, "4-aaaaaaaa A")
		for _, f := range returnsOf(rep) {
			if want := wAmong("2-aaaaaaaa", "3-aaaaaaaa", "4-aaaaaaaa"); !strings.Contains(f.Detail, want) {
				t.Errorf("the detail %q lacks %q", f.Detail, want)
			}
		}
	})
}

// A set that two records list stands at the place of each record and is judged at each one. A set
// that two records of a fork list stands at one place, and is judged once.
func TestRootReturnsASetThatMoreThanOneRecordListsIsJudgedAtEachPlace(t *testing.T) {
	t.Run("two places", func(t *testing.T) {
		b := chainBundle(t, true,
			cset{"1-aaaaaaaa", seqList("1", kA, kB)},
			cset{"2-aaaaaaaa", seqList("2", kB)},
		)
		// The third record lists the first set again, with its own bytes: after the second
		// set, which lacks A, the set stands again, and A returns there.
		b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		wantReturnsAt(t, rep, "1-aaaaaaaa A")
		noNotSure(t, rep)
		f := firstReturn(t, rep)
		if !strings.Contains(f.Detail, "; "+wBefore("2-aaaaaaaa")) {
			t.Errorf("the detail %q does not name the list before the second place", f.Detail)
		}
		if strings.Contains(f.Detail, "cannot be told") {
			t.Errorf("a set with places is not a set whose place cannot be told: %q", f.Detail)
		}
	})
	t.Run("two places, the key stays on the list before each", func(t *testing.T) {
		b := chainBundle(t, true,
			cset{"1-aaaaaaaa", seqList("1", kA)},
			cset{"2-aaaaaaaa", seqList("2", kA)},
		)
		b.apply(withSet("1-aaaaaaaa", seqList("1", kA)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		wantReturnsAt(t, rep)
	})
	t.Run("a fork lists one set from both sides: one place", func(t *testing.T) {
		b := chainBundle(t, true, cset{"1-aaaaaaaa", seqList("1", kA)})
		first := b.recs[0].digest
		b.apply(prev(first), withSet("2-aaaaaaaa", seqList("2", kB)))
		b.apply(prev(first), withSet("2-aaaaaaaa", seqList("2", kB)))
		// The chain goes on from the second record of the fork: A returns after the set of the fork.
		b.apply(withSet("3-aaaaaaaa", seqList("3", kA)))
		rep, err := runMem(t, b.mem)
		if err != nil {
			t.Fatal(err)
		}
		checkReport(t, rep)
		has(t, rep, Fork, "history/"+b.recs[0].folder)
		wantReturnsAt(t, rep, "3-aaaaaaaa A")
		noNotSure(t, rep)
	})
}

// A set whose list is judged against a list that cannot be read, in the new places.
func TestRootReturnsAClosedSetThatCannotBeReadHidesNothingAfterIt(t *testing.T) {
	b := newBundle(t)
	b.apply(withSet("1-aaaaaaaa", seqList("1", kA)))
	stopped := b.unfinished(withSet("2-aaaaaaaa", []byte(`{`)))
	b.closing(stopped, listsLeftover(stopped, nil))
	b.apply(withSet("4-aaaaaaaa", seqList("4", kA)))
	rep := b.run()
	has(t, rep, AnchorUnknown, listPathOf("2-aaaaaaaa"))
	wantReturnsAt(t, rep, "4-aaaaaaaa A")
	if got := firstReturn(t, rep).Detail; !strings.Contains(got, wPinUnread(pa)) {
		t.Errorf("the detail %q does not say the list before cannot be read", got)
	}
}

// The detail says the order is not sure when the two statements of the order disagree and no two
// sets tie, and does not say it when the two readings give the same finding.
func TestRootReturnsTheDetailSaysNotSureExactlyWhenTheReadingsDiffer(t *testing.T) {
	t.Run("the statements disagree and no set ties", func(t *testing.T) {
		// Place 1 holds the second ceremony's set and two sets that name the first record.
		// By sequence the order is 9, 2, 3 (K stays), by number 2, 3, 9 (K returns at 9).
		rep := runWithUnlisted(t,
			[]cset{{"1-aaaaaaaa", seqList("1", kK)}, {"2-aaaaaaaa", seqList("2")}},
			unlisted{"3-aaaaaaaa", seqList("3"), 1}, unlisted{"9-aaaaaaaa", seqList("1", kK), 1})
		wantReturnsAt(t, rep, "9-aaaaaaaa K")
		allNotSure(t, rep)
		f := firstReturn(t, rep)
		if want := "; " + wAmong("2-aaaaaaaa", "3-aaaaaaaa", "9-aaaaaaaa"); !strings.Contains(f.Detail, want) {
			t.Errorf("the detail %q lacks %q", f.Detail, want)
		}
		if !strings.Contains(f.Detail, wPin(pc)) {
			t.Errorf("the detail %q lacks the reason", f.Detail)
		}
	})
	t.Run("the readings agree: an unlisted set with no sequence comes last in both", func(t *testing.T) {
		rep := runWithUnlisted(t,
			[]cset{{"1-aaaaaaaa", seqList("1", kA)}, {"2-aaaaaaaa", seqList("2", kB)}},
			unlisted{"3-bbbbbbbb", rootsJSON(0, kA), 1})
		wantReturnsAt(t, rep, "3-bbbbbbbb A")
		noNotSure(t, rep)
		f := firstReturn(t, rep)
		if want := wPin(pa) + wRule + "; " + wHeldPin("1-aaaaaaaa") + "; " + wBefore("2-aaaaaaaa"); !strings.HasSuffix(f.Detail, want) {
			t.Errorf("the detail %q does not end with %q", f.Detail, want)
		}
	})
	t.Run("both readings show the entry, with another list before it in each", func(t *testing.T) {
		// Place 1: ceremony 2's set (sequence 2, number 2), 4-aaaaaaaa (sequence 1) and
		// 5-aaaaaaaa (sequence 3). By sequence 4, 2, 5: the list before 5 is the second set. By
		// number 2, 4, 5: the list before 5 is 4-aaaaaaaa. K returns at 5 in both.
		rep := runWithUnlisted(t,
			[]cset{{"1-aaaaaaaa", seqList("1", kK)}, {"2-aaaaaaaa", seqList("2", kB)}},
			unlisted{"4-aaaaaaaa", seqList("1", ent{"C", pd, ""}), 1}, unlisted{"5-aaaaaaaa", seqList("3", kK), 1})
		wantReturnsAt(t, rep, "5-aaaaaaaa K")
		allNotSure(t, rep)
	})
	t.Run("both readings show the entry with the same list before it", func(t *testing.T) {
		// The same place, with the sets in the same order by both statements: sure, one reading.
		rep := runWithUnlisted(t,
			[]cset{{"1-aaaaaaaa", seqList("1", kK)}, {"2-aaaaaaaa", seqList("2", kB)}},
			unlisted{"5-aaaaaaaa", seqList("3", kK), 1})
		wantReturnsAt(t, rep, "5-aaaaaaaa K")
		noNotSure(t, rep)
	})
}

// Every form of the detail, with the longest label and names of 200 letters, in every combination of
// the reasons, the doubt, the place that cannot be told and the list before that cannot be read:
// after the bound of a detail is applied, the label and the whole reason are there, in the words of
// the page, and the line is one line of printable ASCII.
func TestRootReturnsEveryFormOfTheDetailKeepsItsReasonWhole(t *testing.T) {
	long := strings.Repeat("n", 200)
	pin := pinOf(1)
	fp := fpOf(1)
	labels := map[string]string{
		"a letter":              "A",
		"16 controls":           strings.Repeat("\x01", 16),
		"4 four byte letters":   strings.Repeat(rn(0x1f600), 4),
		"16 backslashes":        strings.Repeat(`\`, 16),
		"16 bytes beyond ASCII": strings.Repeat(rn(0xe9), 8),
	}
	type reasonCase struct {
		name     string
		pin, fp  bool
		floating bool
		known    bool
		doubt    []string
		prevSet  string
	}
	var cases []reasonCase
	for _, pinCase := range []bool{true, false} {
		for _, fpCase := range []bool{true, false} {
			if !pinCase && !fpCase {
				continue
			}
			for _, floating := range []bool{false, true} {
				for _, known := range []bool{true, false} {
					for _, doubt := range [][]string{nil, {long}, {long, long}, {long, long, long, long, long, long}} {
						for _, prev := range []string{"", long} {
							if floating && (!known || len(doubt) > 0 || prev != "") {
								continue
							}
							cases = append(cases, reasonCase{
								name: fmt.Sprintf("pin=%v fp=%v floating=%v known=%v doubt=%d prev=%v", pinCase, fpCase, floating, known, len(doubt), prev != ""),
								pin:  pinCase, fp: fpCase, floating: floating, known: known, doubt: doubt, prevSet: prev,
							})
						}
					}
				}
			}
		}
	}
	for ln, label := range labels {
		// What the reader keeps of a label.
		kept := cut(label, maxLabelShown)
		for _, c := range cases {
			t.Run(ln+" "+c.name, func(t *testing.T) {
				k := rootKey{label: kept}
				if c.pin {
					k.hasPin = true
					copy(k.pin[:], mustHex(pin))
				}
				if c.fp {
					k.hasFP = true
					copy(k.fp[:], mustHex(fp))
				}
				r := returned{k: k, pinCase: c.pin, fpCase: c.fp, holder: long, fpHolder: long, doubt: c.doubt, floating: c.floating, known: c.known, prevSet: c.prevSet}
				if c.floating {
					r.known = false
				}
				d := cut(returnDetail(r), maxDetail)
				var reason string
				switch {
				case c.floating && c.pin && c.fp:
					reason = "its pin " + pin[:16] + "... and its OpenPGP fingerprint " + fp[:16] + "... were on another list; the place of this trust set in the chain cannot be told"
				case c.floating && c.pin:
					reason = wPinFloating(pin)
				case c.floating:
					reason = wFPFloating(fp)
				case c.pin && c.fp && c.known:
					reason = wBoth(pin, fp)
				case c.pin && c.fp:
					reason = wBothUnread(pin, fp)
				case c.pin && c.known:
					reason = wPin(pin)
				case c.pin:
					reason = wPinUnread(pin)
				case c.known:
					reason = wFP(fp)
				default:
					reason = wFPUnread(fp)
				}
				if want := `root key "` + labelShown(kept) + `" returns: ` + reason; !strings.HasPrefix(d, want) {
					t.Errorf("the detail %q does not start with %q", d, want)
				}
				if len(d) > maxDetail+len("...") {
					t.Errorf("a detail of %d bytes", len(d))
				}
				if !printable(d) || strings.ContainsAny(d, "\r\n") {
					t.Errorf("not one line of printable ASCII: %q", d)
				}
				// The words about the order, when they fit, follow the reason; they never come
				// before it.
				if i := strings.Index(d, wUnsure); i >= 0 && i < len(reason) {
					t.Errorf("the words about the order come before the reason: %q", d)
				}
				if c.floating && len(d) < maxDetail && !strings.Contains(d, "cannot be told") {
					t.Errorf("a place that cannot be told is not said: %q", d)
				}
			})
		}
	}
}

func mustHex(h string) []byte {
	b := make([]byte, len(h)/2)
	for i := range b {
		var v int
		_, err := fmt.Sscanf(h[2*i:2*i+2], "%02x", &v)
		if err != nil {
			panic(err)
		}
		b[i] = byte(v)
	}
	return b
}

// firstReturn is the first finding of root-returns; the test stops when there is none.
func firstReturn(t *testing.T, rep *Report) Finding {
	t.Helper()
	got := returnsOf(rep)
	if len(got) == 0 {
		t.Fatal("no finding of root-returns")
	}
	return got[0]
}
