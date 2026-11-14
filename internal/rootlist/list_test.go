package rootlist_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
)

func TestParseListReadsTheMembers(t *testing.T) {
	w := newWorld(t)
	s := listOf(8, w.a, w.b).withRemovals(removalOf(t, w.c))
	s.roots[1].noFP = true
	data := s.json()
	l, err := rootlist.ParseList(data)
	if err != nil {
		t.Fatal(err)
	}
	if l.Version != 1 || l.Sequence != 8 || !l.SignedAt.Equal(mustTime(signedAt)) || !l.ExpiresAt.Equal(mustTime(expiresAt)) || l.LastRecordSHA256 != defaultLast {
		t.Errorf("members read wrongly: %+v", l)
	}
	if l.SignedAt.Location() != time.UTC || l.ExpiresAt.Location() != time.UTC {
		t.Errorf("the times are not in UTC")
	}
	wantRoots := []rootlist.Root{{Label: "A", X509SPKISHA256: w.a.pin, OpenPGPFingerprint: w.a.fp()}, {Label: "B", X509SPKISHA256: w.b.pin}}
	if len(l.Roots) != 2 || l.Roots[0] != wantRoots[0] || l.Roots[1] != wantRoots[1] {
		t.Errorf("roots read wrongly: %+v", l.Roots)
	}
	if len(l.Removals) != 1 || l.Removals[0] != (rootlist.Removal{Label: "C", X509SPKISHA256: w.c.pin, Authorisation: s.removals[0].auth}) {
		t.Errorf("removals read wrongly: %+v", l.Removals)
	}
	if got := l.Pins(); len(got) != 2 || got[0] != w.a.pin || got[1] != w.b.pin {
		t.Errorf("Pins() = %v", got)
	}
	t.Run("the first list has no last_record_sha256", func(t *testing.T) {
		first := listOf(1, w.a)
		first.noLast = true
		l, err := rootlist.ParseList(first.json())
		if err != nil || l.LastRecordSHA256 != "" || l.Sequence != 1 {
			t.Errorf("%+v %v", l, err)
		}
	})
	t.Run("the order of roots is the order of the file", func(t *testing.T) {
		l, err := rootlist.ParseList(listOf(1, w.c, w.a, w.b).json())
		if err != nil {
			t.Fatal(err)
		}
		if got := l.Pins(); got[0] != w.c.pin || got[1] != w.a.pin || got[2] != w.b.pin {
			t.Errorf("Pins() = %v", got)
		}
	})
	t.Run("Pins returns a copy", func(t *testing.T) {
		l, _ := rootlist.ParseList(listOf(1, w.a).json())
		p := l.Pins()
		p[0] = "x"
		if l.Pins()[0] != w.a.pin {
			t.Errorf("a change of the result changed the list")
		}
	})
	t.Run("the largest sequence and the smallest", func(t *testing.T) {
		for seq, want := range map[string]int64{"1": 1, "9007199254740991": 9007199254740991} {
			s := listOf(1, w.a)
			s.sequence = seq
			l, err := rootlist.ParseList(s.json())
			if err != nil || l.Sequence != want {
				t.Errorf("sequence %s: %+v %v", seq, l, err)
			}
		}
	})
	t.Run("a list of 26 root keys, the most labels there are", func(t *testing.T) {
		var keys []*key
		for c := 'A'; c <= 'Z'; c++ {
			keys = append(keys, newKey(t, string(c)))
		}
		l, err := rootlist.ParseList(listOf(1, keys...).json())
		if err != nil || len(l.Roots) != 26 {
			t.Fatalf("%v", err)
		}
		// A 27th entry has no label left that is not used.
		extra := listOf(1, keys...)
		extra.roots = append(extra.roots, rootSpec{label: "A", pin: newKey(t, "A").pin})
		if _, err := rootlist.ParseList(extra.json()); err == nil {
			t.Errorf("a label was used twice")
		}
	})
}

func TestParseListErrors(t *testing.T) {
	w := newWorld(t)
	j := listOf(8, w.a, w.b).json()
	t.Run("another version wraps ErrUnsupportedVersion and no other error does", func(t *testing.T) {
		for _, v := range []string{"2", "0", "-1", "3", "9007199254740991"} {
			l, err := rootlist.ParseList(replace(t, j, `"version":1`, `"version":`+v))
			if l != nil || !errors.Is(err, rootlist.ErrUnsupportedVersion) {
				t.Errorf("version %s: %v", v, err)
			}
		}
		for _, v := range []string{`1.0`, `"1"`, `null`, `[1]`} {
			_, err := rootlist.ParseList(replace(t, j, `"version":1`, `"version":`+v))
			if err == nil || errors.Is(err, rootlist.ErrUnsupportedVersion) {
				t.Errorf("version %s: %v", v, err)
			}
		}
		_, err := rootlist.ParseList(replace(t, j, `,"version":1`, ``))
		if err == nil || errors.Is(err, rootlist.ErrUnsupportedVersion) {
			t.Errorf("no version: %v", err)
		}
	})
	t.Run("every error wraps the malformed error of the JSON rules", func(t *testing.T) {
		for _, bad := range [][]byte{nil, []byte("{"), []byte("[]"), replace(t, j, `"sequence":8`, `"sequence":0`), replace(t, j, `"label":"A"`, `"label":"a"`), replace(t, j, `"version":1`, `"version":2`)} {
			_, err := rootlist.ParseList(bad)
			if !errors.Is(err, strictjson.ErrMalformed) && !errors.Is(err, rootlist.ErrUnsupportedVersion) {
				t.Errorf("%q: %v", bad, err)
			}
		}
	})
}

func TestParseHeld(t *testing.T) {
	w := newWorld(t)
	data := listOf(7, w.a, w.b).json()
	h, err := rootlist.ParseHeld(data)
	if err != nil {
		t.Fatal(err)
	}
	if h.List == nil || h.List.Sequence != 7 || !bytes.Equal(h.JSON, data) {
		t.Fatalf("held read wrongly: %+v", h)
	}
	t.Run("the bytes are kept as they were when read", func(t *testing.T) {
		copyOf := bytes.Clone(data)
		data[0] = '['
		defer func() { data[0] = '{' }()
		if !bytes.Equal(h.JSON, copyOf) {
			t.Errorf("a change of the caller's bytes changed the held bytes")
		}
	})
	t.Run("a held list that is not a list is the host's own fault, and an error", func(t *testing.T) {
		for _, bad := range [][]byte{nil, []byte("{}"), []byte("not json"), replace(t, listOf(7, w.a).json(), `"version":1`, `"version":2`)} {
			if h, err := rootlist.ParseHeld(bad); err == nil || h != nil {
				t.Errorf("accepted %q", bad)
			}
		}
		_, err := rootlist.ParseHeld(replace(t, listOf(7, w.a).json(), `"version":1`, `"version":2`))
		if !errors.Is(err, rootlist.ErrUnsupportedVersion) {
			t.Errorf("version 2: %v", err)
		}
	})
	t.Run("a held list in a form that the page does not allow is not trusted", func(t *testing.T) {
		for _, bad := range []string{
			string(replace(t, listOf(7, w.a).json(), `"label":"A"`, `"label":"AA"`)),
			string(replace(t, listOf(7, w.a).json(), `"sequence":7`, `"sequence":7,"x":1`)),
		} {
			if _, err := rootlist.ParseHeld([]byte(bad)); err == nil {
				t.Errorf("accepted %q", bad)
			}
		}
	})
}

func TestPinTrust(t *testing.T) {
	w := newWorld(t)
	for name, pins := range map[string][]string{
		"none":                       nil,
		"an empty list":              {},
		"one empty pin":              {""},
		"a pin in upper case":        {strings.ToUpper(w.a.pin)},
		"one letter in upper case":   {upperFirstLetter(w.a.pin)},
		"a valid pin and a bad one":  {w.a.pin, w.b.pin[:63]},
		"a bad pin and a valid one":  {w.a.pin + "0", w.b.pin},
		"63 digits":                  {w.a.pin[:63]},
		"65 digits":                  {w.a.pin + "0"},
		"a pin with a g":             {"g" + w.a.pin[1:]},
		"a pin with spaces":          {" " + w.a.pin},
		"a pin with a line feed":     {w.a.pin + "\n"},
		"a pin with a Cyrillic a":    {"\u0430" + w.a.pin[1:]},
		"a pin that is not UTF-8":    {"\xff" + w.a.pin[1:]},
		"a pin with a control char":  {"\x01" + w.a.pin[1:]},
		"a pin with a 0x prefix":     {"0x" + w.a.pin[2:]},
		"a long text that is no pin": {strings.Repeat("\u0430", 300)},
	} {
		t.Run(name, func(t *testing.T) {
			tr, err := rootlist.PinTrust(pins)
			if err == nil {
				t.Fatal("accepted")
			}
			mustBeASCII(t, "the error text", err.Error())
			// The zero value that comes with the error trusts nothing.
			cand := signed(t, listOf(1, w.a), w.a)
			refuses(t, rootlist.Verify(cand, tr, now), rootlist.UnknownSigner, 2)
		})
	}
	t.Run("valid pins, repeated, count once", func(t *testing.T) {
		tr, err := rootlist.PinTrust([]string{w.a.pin, w.b.pin, w.a.pin, w.a.pin})
		if err != nil {
			t.Fatal(err)
		}
		accepts(t, rootlist.Verify(signed(t, listOf(1, w.a, w.b), w.a), tr, now))
	})
	t.Run("a pin given twice is one pin: the same root keys are still the same", func(t *testing.T) {
		// Two pins of B and one of A, against a list of A and B: the set of pins is the list's, so
		// one signature is enough. A host that counted B twice would ask for B's signature.
		tr, err := rootlist.PinTrust([]string{w.a.pin, w.b.pin, w.b.pin})
		if err != nil {
			t.Fatal(err)
		}
		accepts(t, rootlist.Verify(signed(t, listOf(1, w.a, w.b), w.a), tr, now))
	})
	t.Run("the pins are copied", func(t *testing.T) {
		pins := []string{w.a.pin}
		tr, err := rootlist.PinTrust(pins)
		if err != nil {
			t.Fatal(err)
		}
		pins[0] = w.b.pin
		accepts(t, rootlist.Verify(signed(t, listOf(1, w.a), w.a), tr, now))
		refuses(t, rootlist.Verify(signed(t, listOf(1, w.b), w.b), tr, now), rootlist.UnknownSigner, 2)
	})
	t.Run("the zero Trust trusts nothing", func(t *testing.T) {
		var zero rootlist.Trust
		refuses(t, rootlist.Verify(signed(t, listOf(1, w.a), w.a), zero, now), rootlist.UnknownSigner, 2)
		refuses(t, rootlist.Verify(rootlist.Signed{}, zero, now), rootlist.Malformed, 1)
	})
}

// verifiesWithoutPanic runs Verify and reports a panic as text, so that a test can say what it saw.
func verifiesWithoutPanic(cand rootlist.Signed, tr rootlist.Trust) (v rootlist.Verdict, panicked any) {
	defer func() { panicked = recover() }()
	return rootlist.Verify(cand, tr, now), nil
}

// TestAHeldValueWithNoListTrustsNothing: CheckHeld treats a Held with no list as nothing held, and
// Verify treats it the same way, as it treats HeldTrust(nil): the host holds nothing it can trust.
func TestAHeldValueWithNoListTrustsNothing(t *testing.T) {
	w := newWorld(t)
	cand := signed(t, listOf(1, w.a), w.a)
	for name, tr := range map[string]rootlist.Trust{
		"a Held with no list":  rootlist.HeldTrust(&rootlist.Held{}),
		"a Held with no roots": rootlist.HeldTrust(&rootlist.Held{List: &rootlist.List{Sequence: 1}}),
		"a nil Held":           rootlist.HeldTrust(nil),
	} {
		t.Run(name, func(t *testing.T) {
			v, p := verifiesWithoutPanic(cand, tr)
			if p != nil {
				t.Fatalf("Verify panics on a Held with no list: %v", p)
			}
			refuses(t, v, rootlist.UnknownSigner, 2)
		})
	}
}
