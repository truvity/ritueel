package trustset

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/rootlist"
)

func hk(label, pin string) history.RootKey { return history.RootKey{Label: label, Pin: pin} }

func pinN(c byte) string { return strings.Repeat(string(c), 64) }

// A label is never reused: seen from the function that holds the rule.
func TestLabelsNeverReusedRule(t *testing.T) {
	pinA, pinA2, pinB, pinC := pinN('a'), pinN('b'), pinN('c'), pinN('d')
	earlier := []history.RootList{
		{Keys: []history.RootKey{hk("A", pinA), hk("B", pinB)}},
		{Keys: []history.RootKey{hk("B", pinB)}},
	}
	for _, tc := range []struct {
		name     string
		earlier  []history.RootList
		roots    []Root
		removals []Removal
		bad      bool
	}{
		{"no history", nil, []Root{{Label: "A", X509SPKISHA256: pinA}}, nil, false},
		{"a kept key", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}}, nil, false},
		{"a new key under a new label", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}, {Label: "C", X509SPKISHA256: pinC}}, nil, false},
		{"a new key under an old label of another pin", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}, {Label: "A", X509SPKISHA256: pinA2}}, nil, true},
		{"the old key under its own label is a return, not a reuse", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}, {Label: "A", X509SPKISHA256: pinA}}, nil, false},
		{"a new key under the label of a kept key is not asked here", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}}, nil, false},
		{"a removal whose label stands in roots under another pin", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}}, []Removal{{Label: "B", X509SPKISHA256: pinA2}}, true},
		{"a removal whose label is not in roots", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}}, []Removal{{Label: "A", X509SPKISHA256: pinA}}, false},
		{"a removal of the same pin and label as a root", earlier, []Root{{Label: "B", X509SPKISHA256: pinB}}, []Removal{{Label: "B", X509SPKISHA256: pinB}}, false},
	} {
		err := checkLabelsNeverReused(tc.earlier, tc.roots, tc.removals)
		if tc.bad {
			kindOf(t, err, ErrParams)
		} else if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// A label held by another pin in the first of several earlier lists, and not in the last: the
	// new key that takes it is added, and refused.
	long := []history.RootList{
		{Keys: []history.RootKey{hk("A", pinA), hk("B", pinB)}},
		{Keys: []history.RootKey{hk("B", pinB)}},
		{Keys: []history.RootKey{hk("B", pinB)}},
		{Keys: []history.RootKey{hk("B", pinB)}},
	}
	kindOf(t, checkLabelsNeverReused(long, []Root{{Label: "B", X509SPKISHA256: pinB}, {Label: "A", X509SPKISHA256: pinA2}}, nil), ErrParams)
	// A history of one list: that list is the previous one, and its keys are kept.
	if err := checkLabelsNeverReused(earlier[:1], []Root{{Label: "A", X509SPKISHA256: pinA}, {Label: "B", X509SPKISHA256: pinB}}, nil); err != nil {
		t.Error(err)
	}
}

func TestCheckEarlierLimits(t *testing.T) {
	one := history.RootList{Keys: []history.RootKey{hk("A", pinN('a'))}}
	mk := func(n int) []history.RootList {
		out := make([]history.RootList, n)
		for i := range out {
			out[i] = one
		}
		return out
	}
	for _, n := range []int{0, 1, 2, MaxEarlier - 1, MaxEarlier} {
		if err := checkEarlier(mk(n)); err != nil {
			t.Errorf("%d lists: %v", n, err)
		}
	}
	kindOf(t, checkEarlier(mk(MaxEarlier+1)), ErrParams)
	// 26 entries are allowed in a list, 27 and 0 are not.
	full := history.RootList{}
	for i := 0; i < MaxRoots; i++ {
		full.Keys = append(full.Keys, hk(string(rune('A'+i)), fmt.Sprintf("%064x", i+1)))
	}
	if err := checkEarlier([]history.RootList{full}); err != nil {
		t.Errorf("26 entries: %v", err)
	}
	over := history.RootList{Keys: append(append([]history.RootKey(nil), full.Keys...), hk("A", pinN('z')))}
	kindOf(t, checkEarlier([]history.RootList{over}), ErrParams)
	kindOf(t, checkEarlier([]history.RootList{{}}), ErrParams)
	kindOf(t, checkEarlier([]history.RootList{one, {Unreadable: true, Keys: one.Keys}}), ErrParams)
	// A fingerprint of 40 digits is allowed, and none.
	fp := history.RootList{Keys: []history.RootKey{{Label: "A", Pin: pinN('a'), Fingerprint: strings.Repeat("e", 40)}}}
	if err := checkEarlier([]history.RootList{fp}); err != nil {
		t.Error(err)
	}
}

func TestSameKeys(t *testing.T) {
	pinA, pinB := pinN('a'), pinN('b')
	keys := []history.RootKey{{Label: "A", Pin: pinA, Fingerprint: strings.Repeat("e", 40)}, hk("B", pinB)}
	roots := func() []rootlist.Root {
		return []rootlist.Root{{Label: "B", X509SPKISHA256: pinB}, {Label: "A", X509SPKISHA256: pinA, OpenPGPFingerprint: strings.Repeat("e", 40)}}
	}
	if !sameKeys(roots(), keys) {
		t.Error("the same entries in another order are not the same")
	}
	r := roots()
	r[1].OpenPGPFingerprint = ""
	if sameKeys(r, keys) {
		t.Error("another fingerprint is the same")
	}
	r = roots()
	r[0].Label = "C"
	if sameKeys(r, keys) {
		t.Error("another label is the same")
	}
	if sameKeys(roots()[:1], keys) || sameKeys(roots(), keys[:1]) || sameKeys(nil, keys) {
		t.Error("a list of another length is the same")
	}
	if !sameKeys(nil, nil) {
		t.Error("two empty lists differ")
	}
}

// A forged Draft or Set (a struct with some fields set) is not valid: every accessor gives nothing
// and Sign and Write refuse.
func TestForgedDraftAndSet(t *testing.T) {
	f := newIFixture(t)
	good := *f.second
	for name, mutate := range map[string]func(*Draft){
		"kind 0":       func(d *Draft) { d.kind = 0 },
		"kind 6":       func(d *Draft) { d.kind = 6 },
		"kind -1":      func(d *Draft) { d.kind = -1 },
		"no list":      func(d *Draft) { d.listJSON = nil },
		"no CA bundle": func(d *Draft) { d.caBundle = nil },
		"empty list":   func(d *Draft) { d.listJSON = []byte{} },
		"empty bundle": func(d *Draft) { d.caBundle = []byte{} },
	} {
		d := good
		mutate(&d)
		if d.Kind() != 0 || d.ListJSON() != nil || d.Sequence() != 0 {
			t.Errorf("%s: a forged draft gives something", name)
		}
		s := counting1(f.a.signer)
		set, err := d.Sign([]Signer{s}, nil)
		if set != nil {
			t.Errorf("%s: a set", name)
		}
		kindOf(t, err, ErrParams)
		if s.n != 0 {
			t.Errorf("%s: a key was asked", name)
		}
	}
	// Every kind from 1 to 5 is valid.
	for k := KindFirst; k <= KindRevoke; k++ {
		d := good
		d.kind = k
		if d.Kind() != k {
			t.Errorf("kind %v is not valid", k)
		}
	}
	gs := *f.secondS
	for name, mutate := range map[string]func(*Set){
		"sequence 0": func(s *Set) { s.sequence = 0 },
		"no list":    func(s *Set) { s.listJSON = nil },
		"no jws":     func(s *Set) { s.listJWS = nil },
		"no CA":      func(s *Set) { s.caBundle = nil },
	} {
		s := gs
		mutate(&s)
		if s.Sequence() != 0 || s.ListJSON() != nil || s.Files() != nil {
			t.Errorf("%s: a forged set gives something", name)
		}
		if err := s.Write(nil, "x"); !errors.Is(err, ErrParams) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if gs.Sequence() != 2 {
		t.Error("the good set is not valid")
	}
}

type counted struct {
	Signer
	n int
}

func counting1(s Signer) *counted { return &counted{Signer: s} }

func (c *counted) SignES384(in []byte) ([]byte, error) {
	c.n++
	return c.Signer.SignES384(in)
}
