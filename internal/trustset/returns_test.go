package trustset_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/trustset"
)

// A name of an earlier list that no error may show: a control character, an escape sequence and a
// backslash. The chain helper gives every earlier list such a name.
const hostileMarker = "31m"

func noEarlierName(t *testing.T, err error) {
	t.Helper()
	text := err.Error()
	for _, bad := range []string{"trust/", "\x1b", hostileMarker, "\\u0041", "padding"} {
		if strings.Contains(text, bad) {
			t.Errorf("the error shows a part of the name of an earlier list (%q): %v", bad, err)
		}
	}
}

// wantReturn checks an error of NewDraft that says a root key came back.
func wantReturn(t *testing.T, err error, labels []string, how string) {
	t.Helper()
	wantOnly(t, err, trustset.ErrReturns)
	text := err.Error()
	if !strings.Contains(text, trustset.CodeRootReturns+":") || trustset.CodeRootReturns != "root-returns" {
		t.Errorf("the text does not hold the code root-returns: %v", err)
	}
	for _, l := range labels {
		if !strings.Contains(text, "root key "+l+" comes back "+how) {
			t.Errorf("the text does not say that %s comes back %s: %v", l, how, err)
		}
	}
	if !strings.Contains(text, "never returns") {
		t.Errorf("the text does not say that a key that left never returns: %v", err)
	}
	noEarlierName(t, err)
}

// pinOnly is a chain whose entries have no fingerprint, so that only the pin can bring a key back.
func chainOf(t *testing.T, noPrint bool, steps ...next) *chain {
	t.Helper()
	c := newChain(t)
	for _, n := range steps {
		n.noPrint = noPrint
		c.add(n)
	}
	return c
}

// The planned cases of testdata/root-list/README.md: root-returns-*. Each is ErrReturns with the
// code root-returns, names the label and says pin or fingerprint, shows no name of an earlier list,
// and gives no draft (so nothing is written and no key is asked: Sign has no draft to be called on).
func TestRootReturns(t *testing.T) {
	t.Run("root-returns-after-a-revoke", func(t *testing.T) {
		c := chainOf(t, true,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}})
		d, err := c.draft(next{labels: []string{"A", "B"}, noPrint: true})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"A"}, "by its pin")
		if strings.Contains(err.Error(), "fingerprint") && strings.Contains(err.Error(), "by its pin and") {
			t.Errorf("the text says fingerprint for a key that has none: %v", err)
		}
	})
	t.Run("root-returns-after-a-retire", func(t *testing.T) {
		c := chainOf(t, true,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "A")}})
		d, err := c.draft(next{labels: []string{"A", "B"}, noPrint: true})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"A"}, "by its pin")
	})
	t.Run("root-returns-under-a-new-label", func(t *testing.T) {
		c := chainOf(t, true,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}})
		d, err := c.draft(next{labels: []string{"B", "C"}, noPrint: true, change: func(in *trustset.Input) {
			// A's pin under the label C: the key is the pin.
			for i := range in.Roots {
				if in.Roots[i].Label == "C" {
					in.Roots[i].X509SPKISHA256 = newRoot(t, "A", true).Pin
				}
			}
		}})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"C"}, "by its pin")
	})
	t.Run("root-returns-after-several-lists", func(t *testing.T) {
		c := chainOf(t, true,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}},
			next{labels: []string{"B"}},
			next{labels: []string{"B", "C"}},
			next{labels: []string{"B", "C"}})
		d, err := c.draft(next{labels: []string{"A", "B", "C"}, noPrint: true})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"A"}, "by its pin")
		// The same key, however many lists ago it left, after a retire too.
		other := chainOf(t, true,
			next{labels: []string{"A", "B", "C"}},
			next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}},
			next{labels: []string{"A", "B"}},
			next{labels: []string{"A", "B"}},
			next{labels: []string{"A", "B"}})
		_, err = other.draft(next{labels: []string{"A", "B", "C"}, noPrint: true})
		wantReturn(t, err, []string{"C"}, "by its pin")
	})
	t.Run("root-returns-after-an-emergency-revoke", func(t *testing.T) {
		// The set without A was written by revoke and no ceremony record lists it. To the builder it
		// is one more list of Earlier, and it asks about every list it is given.
		c := chainOf(t, true,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}},
			next{labels: []string{"B", "C"}})
		d, err := c.draft(next{labels: []string{"A", "B", "C"}, noPrint: true})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"A"}, "by its pin")
		// Leave that one list out of Earlier and the history looks clean: the builder is only as good
		// as the lists it is given, which is why it counts them.
		in := c.input(next{labels: []string{"A", "B", "C"}, noPrint: true})
		in.Earlier = append(in.Earlier[:1:1], in.Earlier[2:]...)
		refuses(t, in, "earlier lists")
	})
	t.Run("root-returns-with-the-old-fingerprint-under-a-new-pin", func(t *testing.T) {
		c := chainOf(t, false,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}})
		nk := newRootVariant(t, "C", "fresh")
		d, err := c.draft(next{labels: []string{"B", "C"}, change: func(in *trustset.Input) {
			for i := range in.Roots {
				if in.Roots[i].Label == "C" {
					in.Roots[i].X509SPKISHA256 = nk.Pin
					in.Roots[i].OpenPGPFingerprint = newRoot(t, "A", true).Print // the fingerprint of A
				}
			}
			in.Certificates["C"] = nk.DER
		}})
		if d != nil {
			t.Fatal("a draft came with the error")
		}
		wantReturn(t, err, []string{"C"}, "by its fingerprint")
		if strings.Contains(err.Error(), "by its pin") {
			t.Errorf("a new pin is no return by pin: %v", err)
		}
	})
	t.Run("both by pin and by fingerprint", func(t *testing.T) {
		c := chainOf(t, false,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "A")}})
		_, err := c.draft(next{labels: []string{"A", "B"}})
		wantReturn(t, err, []string{"A"}, "by its pin and by its fingerprint")
	})
	t.Run("two keys come back", func(t *testing.T) {
		c := chainOf(t, true,
			next{labels: []string{"A", "B", "C"}},
			next{labels: []string{"C"}, deps: []trustset.Departure{revoke(t, "A"), revoke(t, "B")}})
		_, err := c.draft(next{labels: []string{"A", "B", "C"}, noPrint: true})
		wantReturn(t, err, []string{"A", "B"}, "by its pin")
	})
	t.Run("the control: a new key is added", func(t *testing.T) {
		c := chainOf(t, false,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}})
		d, err := c.draft(next{labels: []string{"B", "C"}})
		if err != nil || d == nil {
			t.Fatalf("a new key with a new label is refused: %v", err)
		}
		if d.Kind() != trustset.KindAdd {
			t.Errorf("Kind = %v", d.Kind())
		}
	})
	t.Run("a key that never left is no return", func(t *testing.T) {
		c := chainOf(t, false,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"A", "B"}},
			next{labels: []string{"A", "B", "C"}},
			next{labels: []string{"A", "B", "C"}})
		for _, n := range []next{{labels: []string{"A", "B", "C"}}, {labels: []string{"A", "B", "C", "D"}}} {
			if _, err := c.draft(n); err != nil {
				t.Errorf("%v: %v", n.labels, err)
			}
		}
		// A key that was retired and is added back is a return; a key kept, retired never, is not.
		if _, err := c.draft(next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}}); err != nil {
			t.Errorf("a retire: %v", err)
		}
	})
	t.Run("a pin that left, retired and added again, by its pin only, with the label kept", func(t *testing.T) {
		c := chainOf(t, true,
			next{labels: []string{"A", "B", "C"}},
			next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}})
		_, err := c.draft(next{labels: []string{"A", "B", "C"}, noPrint: true})
		wantReturn(t, err, []string{"C"}, "by its pin")
	})
}

// Rule 54 of record 0006 and the order of the checks: the shape of the change comes first, the
// return after it.
func TestTheShapeOfTheChangeIsToldBeforeAReturn(t *testing.T) {
	c := chainOf(t, true,
		next{labels: []string{"A", "B"}},
		next{labels: []string{"B"}, deps: []trustset.Departure{revoke(t, "A")}})
	// Adds A back and removes B in one list: a change that is not one of the five.
	d, err := c.draft(next{labels: []string{"A"}, noPrint: true, deps: []trustset.Departure{retire(t, "B")}})
	if d != nil {
		t.Fatal("a draft came with the error")
	}
	wantOnly(t, err, trustset.ErrParams)
	if errors.Is(err, trustset.ErrReturns) {
		t.Error("told as a return")
	}
}

// A label is never reused: an added entry whose label an earlier list held under another pin is
// refused, and a new key with a new label is not.
func TestLabelsAreNeverReused(t *testing.T) {
	c := chainOf(t, true,
		next{labels: []string{"A", "B"}},
		next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "A")}})
	other := newRootVariant(t, "A", "second")
	reuse := func(in *trustset.Input) {
		for i := range in.Roots {
			if in.Roots[i].Label == "A" {
				in.Roots[i].X509SPKISHA256 = other.Pin
			}
		}
		in.Certificates["A"] = other.DER
	}
	refuses(t, c.input(next{labels: []string{"A", "B"}, noPrint: true, change: reuse}), "label A was held by another root key")
	// The control: the new key takes the next label and is accepted.
	if _, err := c.draft(next{labels: []string{"B", "C"}, noPrint: true}); err != nil {
		t.Errorf("a new key under a new label: %v", err)
	}
	// An earlier list further back held the label: the same refusal.
	longer := chainOf(t, true,
		next{labels: []string{"A", "B"}},
		next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "A")}},
		next{labels: []string{"B", "C"}},
		next{labels: []string{"B", "C"}})
	refuses(t, longer.input(next{labels: []string{"A", "B", "C"}, noPrint: true, change: reuse}), "label A was held by another root key")
}

// A history that reused a label once does not stop the key that holds the label now: a kept key
// is not asked, so its renewal and an add of another key still go.
func TestAPastReuseOfALabelDoesNotStopTheKeptKey(t *testing.T) {
	c := chainOf(t, true,
		next{labels: []string{"A", "B"}},
		next{labels: []string{"A", "B"}})
	mark := func(in *trustset.Input) {
		// The first earlier list held A under another pin, as a history that reused a label would.
		in.Earlier[0].Keys[0].Pin = hexOf("an old key")
	}
	if _, err := c.draft(next{labels: []string{"A", "B"}, noPrint: true, change: mark}); err != nil {
		t.Errorf("the renewal of the key that holds the label: %v", err)
	}
	if _, err := c.draft(next{labels: []string{"A", "B", "C"}, noPrint: true, change: mark}); err != nil {
		t.Errorf("an add of another key: %v", err)
	}
	if _, err := c.draft(next{labels: []string{"B"}, noPrint: true, deps: []trustset.Departure{retire(t, "A")}, change: mark}); err != nil {
		t.Errorf("a retire of the key that holds the label: %v", err)
	}
}

// The count and the end of the history.
func TestEarlierListsAreCounted(t *testing.T) {
	three := func() *chain {
		return chainOf(t, true,
			next{labels: []string{"A", "B"}},
			next{labels: []string{"A", "B"}},
			next{labels: []string{"A", "B"}})
	}
	renew := next{labels: []string{"A", "B"}, noPrint: true}
	build := func(change func(*trustset.Input)) trustset.Input {
		n := renew
		n.change = change
		return three().input(n)
	}
	// The control builds.
	if _, err := trustset.NewDraft(build(nil)); err != nil {
		t.Fatalf("the control: %v", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*trustset.Input)
		want   string
	}{
		{"Earlier empty at sequence 4", func(in *trustset.Input) { in.Earlier = nil }, "earlier lists"},
		{"Earlier one short", func(in *trustset.Input) { in.Earlier = in.Earlier[1:] }, "earlier lists"},
		{"Earlier one too many", func(in *trustset.Input) { in.Earlier = append(in.Earlier, in.Earlier[0]) }, "earlier lists"},
		{"Earlier one too many at the front", func(in *trustset.Input) { in.Earlier = append([]history.RootList{in.Earlier[0]}, in.Earlier...) }, "earlier lists"},
		{"the last Earlier holds other keys than Previous", func(in *trustset.Input) {
			in.Earlier[2] = historyList("x", rootsOf(t, true, "A", "C"))
		}, "does not hold the entries of the previous"},
		{"the last Earlier holds one key more than Previous", func(in *trustset.Input) {
			in.Earlier[2] = historyList("x", rootsOf(t, true, "A", "B", "C"))
		}, "does not hold the entries of the previous"},
		{"the last Earlier holds the pin of Previous under another label", func(in *trustset.Input) {
			in.Earlier[2].Keys[0].Label = "C"
		}, "does not hold the entries of the previous"},
		{"the last Earlier holds another fingerprint", func(in *trustset.Input) {
			in.Earlier[2].Keys[0].Fingerprint = hexOf("fp")[:40]
		}, "does not hold the entries of the previous"},
		{"Previous with sequence 2 for sequence 4", func(in *trustset.Input) {
			in.Previous = previousOf(t, 2, firstCeremony, rootsOf(t, true, "A", "B"))
		}, "needs it to be 3"},
		{"Previous with sequence 4 for sequence 4", func(in *trustset.Input) {
			in.Previous = previousOf(t, 4, firstCeremony, rootsOf(t, true, "A", "B"))
		}, "needs it to be 3"},
		{"Previous nil", func(in *trustset.Input) { in.Previous = nil }, "previous list"},
		{"Previous empty", func(in *trustset.Input) { in.Previous = []byte{} }, "cannot be read"},
		{"Previous garbage", func(in *trustset.Input) { in.Previous = []byte("not a list") }, "cannot be read"},
		{"Previous with version 2", func(in *trustset.Input) {
			in.Previous = []byte(strings.Replace(string(in.Previous), `"version":1`, `"version":2`, 1))
		}, "cannot be read"},
		{"Previous over the limit", func(in *trustset.Input) { in.Previous = []byte(strings.Repeat(" ", trustset.MaxBytes+1)) }, "longer than"},
		{"an Earlier list unreadable", func(in *trustset.Input) { in.Earlier[0].Unreadable = true }, "cannot be read"},
		{"the last Earlier unreadable", func(in *trustset.Input) { in.Earlier[2].Unreadable = true }, "cannot be read"},
		{"an Earlier list of 27 keys", func(in *trustset.Input) {
			in.Earlier[0].Keys = nil
			for i := 0; i < 27; i++ {
				in.Earlier[0].Keys = append(in.Earlier[0].Keys, history.RootKey{Label: "A", Pin: hexOf(string(rune('a' + i)))})
			}
		}, "from 1 to 26"},
		{"an Earlier list of no key", func(in *trustset.Input) { in.Earlier[0].Keys = nil }, "from 1 to 26"},
		{"anchor missing at sequence 4", func(in *trustset.Input) { in.LastRecordSHA256 = "" }, "last_record_sha256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := build(tc.change)
			d, err := trustset.NewDraft(in)
			if d != nil || err == nil {
				t.Fatal("a draft was made")
			}
			wantOnly(t, err, trustset.ErrParams)
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the text does not hold %q: %v", tc.want, err)
			}
			noEarlierName(t, err)
		})
	}
}

// A first list has no list before it.
func TestAFirstListHasNothingBeforeIt(t *testing.T) {
	one := func(change func(*trustset.Input)) trustset.Input {
		return newChain(t).input(next{labels: []string{"A", "B"}, change: change})
	}
	if _, err := trustset.NewDraft(one(nil)); err != nil {
		t.Fatal(err)
	}
	prev := previousOf(t, 1, firstCeremony, rootsOf(t, false, "A", "B"))
	refuses(t, one(func(in *trustset.Input) { in.Previous = prev }), "no list before it")
	refuses(t, one(func(in *trustset.Input) { in.Previous = []byte{} }), "no list before it")
	refuses(t, one(func(in *trustset.Input) {
		in.Earlier = []history.RootList{historyList("x", rootsOf(t, false, "A", "B"))}
	}), "no list before it")
	refuses(t, one(func(in *trustset.Input) { in.Departures = []trustset.Departure{retire(t, "A")} }), "no root key that leaves")
	refuses(t, one(func(in *trustset.Input) { in.LastRecordSHA256 = hexOf("x") }), "no last_record_sha256")
}

// Entries of an earlier list that are not in the form of the page are refused: a label A to Z,
// a pin of 64 lower-case digits and a fingerprint of 40 or none.
func TestEarlierEntriesAreInTheFormOfThePage(t *testing.T) {
	good := newChain(t)
	good.add(next{labels: []string{"A", "B"}})
	pin, print := newRoot(t, "A", true).Pin, newRoot(t, "A", true).Print
	for _, tc := range []struct {
		name string
		key  history.RootKey
	}{
		{"label in lower case", history.RootKey{Label: "a", Pin: pin, Fingerprint: print}},
		{"label of two letters", history.RootKey{Label: "AB", Pin: pin, Fingerprint: print}},
		{"label empty", history.RootKey{Label: "", Pin: pin, Fingerprint: print}},
		{"label a digit", history.RootKey{Label: "1", Pin: pin, Fingerprint: print}},
		{"pin in upper case", history.RootKey{Label: "A", Pin: strings.ToUpper(pin), Fingerprint: print}},
		{"pin of 63 digits", history.RootKey{Label: "A", Pin: pin[:63], Fingerprint: print}},
		{"pin of 65 digits", history.RootKey{Label: "A", Pin: pin + "0", Fingerprint: print}},
		{"pin empty", history.RootKey{Label: "A", Pin: "", Fingerprint: print}},
		{"pin with a prefix", history.RootKey{Label: "A", Pin: "0x" + pin[2:], Fingerprint: print}},
		{"pin with white space", history.RootKey{Label: "A", Pin: " " + pin[1:], Fingerprint: print}},
		{"fingerprint of 39 digits", history.RootKey{Label: "A", Pin: pin, Fingerprint: print[:39]}},
		{"fingerprint of 41 digits", history.RootKey{Label: "A", Pin: pin, Fingerprint: print + "0"}},
		{"fingerprint in upper case", history.RootKey{Label: "A", Pin: pin, Fingerprint: strings.ToUpper(print)}},
		{"fingerprint with colons", history.RootKey{Label: "A", Pin: pin, Fingerprint: print[:20] + ":" + print[21:]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := good.input(next{labels: []string{"A", "B"}})
			// The bad entry stands in a list that is not the last, so only its own form is judged.
			in.Sequence, in.Previous = 3, previousOf(t, 2, firstCeremony.Add(time.Hour), rootsOf(t, false, "A", "B"))
			in.Earlier = []history.RootList{{Name: "one", Keys: []history.RootKey{tc.key}}, historyList("two", rootsOf(t, false, "A", "B"))}
			in.LastRecordSHA256 = lastRecord(3)
			refuses(t, in, "not in the form of the page")
		})
	}
}

// The most earlier lists: 4096 are taken, 4097 are not.
func TestMostEarlierLists(t *testing.T) {
	entries := rootsOf(t, false, "A", "B")
	for _, tc := range []struct {
		earlier int
		ok      bool
	}{{trustset.MaxEarlier, true}, {trustset.MaxEarlier + 1, false}} {
		in := trustset.Input{
			Sequence:         int64(tc.earlier) + 1,
			SignedAt:         firstCeremony.Add(time.Hour),
			Roots:            entries,
			Certificates:     certsOf(t, "A", "B"),
			LastRecordSHA256: hexOf("end"),
			Previous:         previousOf(t, int64(tc.earlier), firstCeremony, entries),

			OpenPGPCertificates: certificatesOfRoots(entries),
		}
		for i := 0; i < tc.earlier; i++ {
			in.Earlier = append(in.Earlier, historyList("x", entries))
		}
		d, err := trustset.NewDraft(in)
		if tc.ok {
			if err != nil {
				t.Errorf("%d earlier lists: %v", tc.earlier, err)
			}
			continue
		}
		if d != nil {
			t.Errorf("%d earlier lists: a draft", tc.earlier)
		}
		wantOnly(t, err, trustset.ErrParams)
		if !strings.Contains(err.Error(), "at most 4096") {
			t.Errorf("the text does not give the limit: %v", err)
		}
	}
}

// Record 0006, rule 54: ritueel refuses to plan or write a list that adds a root key that left, with
// the reason code root-returns, and the key is the pin: a key that comes back under a new label is
// the same key. So the pin of a key that left, put under a label that another key held before, is
// told as root-returns. (The label rule of the list page would refuse it too, but the page names the
// code root-returns for any list that adds a key that left.)
func TestAReturningKeyUnderAnOldLabelOfAnotherKeyIsToldAsAReturn(t *testing.T) {
	c := chainOf(t, true,
		next{labels: []string{"A", "B", "C"}},
		next{labels: []string{"A", "B"}, deps: []trustset.Departure{retire(t, "C")}},
		next{labels: []string{"B"}, deps: []trustset.Departure{retire(t, "A")}})
	a := newRoot(t, "A", true)
	d, err := c.draft(next{labels: []string{"B", "C"}, noPrint: true, change: func(in *trustset.Input) {
		// The pin of A, which left, under the label C, which the key C held before it left.
		for i := range in.Roots {
			if in.Roots[i].Label == "C" {
				in.Roots[i].X509SPKISHA256 = a.Pin
			}
		}
		in.Certificates["C"] = a.DER
	}})
	if d != nil {
		t.Fatal("a draft came with the error")
	}
	wantReturn(t, err, []string{"C"}, "by its pin")
}
