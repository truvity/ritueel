package rootlist_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
)

// The page says that a list is a set of root keys. Beside a label twice and a pin twice, a list
// that gives one openpgp_fingerprint to two entries is refused as malformed: a certifier cannot hold
// such a list to a keyring file. These tests write lists of plain text, so they need no key.

// plainRoots are n entries with the labels A, B, C and so on, each with a pin and a fingerprint of
// its own (the number of the entry in hexadecimal digits).
func plainRoots(n int) []rootSpec {
	out := make([]rootSpec, n)
	for i := range out {
		out[i] = rootSpec{label: string(rune('A' + i)), pin: fmt.Sprintf("%064x", i+1), fp: fmt.Sprintf("%040x", i+1)}
	}
	return out
}

// plainList is the list of sequence 1 with the entries.
func plainList(roots ...rootSpec) []byte {
	s := spec{sequence: "1"}
	s.roots = roots
	return s.json()
}

// refusedAsAFingerprintTwice fails the test unless ParseList refuses the data with the error of the
// fingerprint twice: a list fault of the second entry (at index second) that names the two labels.
func refusedAsAFingerprintTwice(t *testing.T, data []byte, first, second string, secondIndex int) {
	t.Helper()
	l, err := rootlist.ParseList(data)
	if l != nil || err == nil {
		t.Fatalf("ParseList = (%v, %v), want a refusal", l, err)
	}
	if !errors.Is(err, strictjson.ErrMalformed) || errors.Is(err, rootlist.ErrUnsupportedVersion) {
		t.Errorf("the error is not a malformed-JSON error: %v", err)
	}
	var e *jsonset.Error
	if !errors.As(err, &e) {
		t.Fatalf("the error is not a *jsonset.Error, the kind of the label and pin checks: %T", err)
	}
	want := fmt.Sprintf("malformed JSON: $.roots[%d].openpgp_fingerprint: the fingerprint appears twice: the entries with the labels %s and %s have the same one", secondIndex, first, second)
	if err.Error() != want {
		t.Errorf("the text is\n%q\nwant\n%q", err.Error(), want)
	}
	mustBeASCII(t, "the error text", err.Error())
	if h, herr := rootlist.ParseHeld(data); h != nil || herr == nil || herr.Error() != err.Error() {
		t.Errorf("ParseHeld = (%v, %v), want the same refusal", h, herr)
	}
}

func TestParseListRefusesOneFingerprintOnTwoEntries(t *testing.T) {
	for _, tc := range []struct {
		name         string
		n            int
		copy         map[int]int // entry i takes the fingerprint of entry j
		first, other string
		at           int // the place of the entry that repeats
	}{
		{"the first and the second of two", 2, map[int]int{1: 0}, "A", "B", 1},
		{"the first and the second of three", 3, map[int]int{1: 0}, "A", "B", 1},
		{"the first and the third of three", 3, map[int]int{2: 0}, "A", "C", 2},
		{"the second and the third of three", 3, map[int]int{2: 1}, "B", "C", 2},
		{"the first and the last of 26", 26, map[int]int{25: 0}, "A", "Z", 25},
		{"the second and the last of 26", 26, map[int]int{25: 1}, "B", "Z", 25},
		{"the last two of 26", 26, map[int]int{25: 24}, "Y", "Z", 25},
		{"the middle two of 26", 26, map[int]int{13: 12}, "M", "N", 13},
		{"one fingerprint on three entries names the first and the second", 3, map[int]int{1: 0, 2: 0}, "A", "B", 1},
		{"one fingerprint on 26 entries names the first and the second", 26, func() map[int]int {
			m := map[int]int{}
			for i := 1; i < 26; i++ {
				m[i] = 0
			}
			return m
		}(), "A", "B", 1},
		{"one fingerprint on three entries that are not next to each other", 5, map[int]int{2: 0, 4: 0}, "A", "C", 2},
		{"two repeats: the entry met first is named", 6, map[int]int{4: 1, 2: 0}, "A", "C", 2},
		{"two repeats, the later pair listed first", 6, map[int]int{5: 3, 3: 2}, "C", "D", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := plainRoots(tc.n)
			for i, j := range tc.copy {
				roots[i].fp = roots[j].fp
			}
			refusedAsAFingerprintTwice(t, plainList(roots...), tc.first, tc.other, tc.at)
		})
	}
}

// The two labels are named in the order of the list, whatever the letters are.
func TestTheDetailOfAFingerprintTwiceNamesTheLabelsInTheOrderOfTheList(t *testing.T) {
	roots := []rootSpec{
		{label: "Z", pin: fmt.Sprintf("%064x", 1), fp: fmt.Sprintf("%040x", 1)},
		{label: "M", pin: fmt.Sprintf("%064x", 2), fp: fmt.Sprintf("%040x", 2)},
		{label: "A", pin: fmt.Sprintf("%064x", 3), fp: fmt.Sprintf("%040x", 1)},
	}
	refusedAsAFingerprintTwice(t, plainList(roots...), "Z", "A", 2)
}

// Every pair of entries of a list of eight, one pair at a time, is found and named.
func TestEveryPairOfEntriesThatSharesAFingerprintIsFound(t *testing.T) {
	const n = 8
	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			roots := plainRoots(n)
			roots[j].fp = roots[i].fp
			t.Run(fmt.Sprintf("entries %d and %d", i, j), func(t *testing.T) {
				refusedAsAFingerprintTwice(t, plainList(roots...), roots[i].label, roots[j].label, j)
			})
		}
	}
}

func TestEntriesThatDoNotShareAFingerprintAreAccepted(t *testing.T) {
	t.Run("26 entries with a fingerprint of their own", func(t *testing.T) {
		l, err := rootlist.ParseList(plainList(plainRoots(26)...))
		if err != nil || len(l.Roots) != 26 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("two entries whose fingerprints differ in one digit, the first or the last", func(t *testing.T) {
		for _, other := range []string{"1" + strings.Repeat("0", 39), strings.Repeat("0", 39) + "1", strings.Repeat("0", 38) + "10"} {
			roots := plainRoots(2)
			roots[0].fp = strings.Repeat("0", 40)
			roots[1].fp = other
			if _, err := rootlist.ParseList(plainList(roots...)); err != nil {
				t.Errorf("%s: %v", other, err)
			}
		}
	})
	t.Run("the fingerprint of an entry is not its pin: a fingerprint that is the start of another entry's pin is no repeat", func(t *testing.T) {
		roots := plainRoots(2)
		roots[1].fp = roots[0].pin[:40]
		if _, err := rootlist.ParseList(plainList(roots...)); err != nil {
			t.Error(err)
		}
	})
	t.Run("a list with the fingerprints of two keys of the world", func(t *testing.T) {
		w := newWorld(t)
		if _, err := rootlist.ParseList(listOf(1, w.a, w.b, w.c).json()); err != nil {
			t.Error(err)
		}
	})
}

// An entry with no openpgp_fingerprint is compared with nothing.
func TestEntriesWithNoFingerprintAreNotCompared(t *testing.T) {
	none := func(roots []rootSpec, at ...int) []rootSpec {
		for _, i := range at {
			roots[i].noFP = true
		}
		return roots
	}
	for name, roots := range map[string][]rootSpec{
		"two entries with none":                        none(plainRoots(2), 0, 1),
		"one entry with one and one with none":         none(plainRoots(2), 1),
		"one entry with none and one with one":         none(plainRoots(2), 0),
		"26 entries with none":                         none(plainRoots(26), seq(26)...),
		"all but one of 26 with none":                  none(plainRoots(26), seq(25)...),
		"an entry with none first and last of 26":      none(plainRoots(26), 0, 25),
		"many with none, and the others all different": none(plainRoots(10), 1, 3, 5, 7),
		"an entry with none between two that differ":   none(plainRoots(3), 1),
	} {
		t.Run(name, func(t *testing.T) {
			l, err := rootlist.ParseList(plainList(roots...))
			if err != nil || len(l.Roots) != len(roots) {
				t.Fatalf("(%v, %v), want the list", l, err)
			}
			for i, r := range l.Roots {
				if roots[i].noFP != (r.OpenPGPFingerprint == "") {
					t.Errorf("entry %d: the fingerprint read is %q", i, r.OpenPGPFingerprint)
				}
			}
		})
	}
	t.Run("an entry with none between two entries that repeat is no break in the repeat", func(t *testing.T) {
		roots := plainRoots(3)
		roots[2].fp = roots[0].fp
		roots[1].noFP = true
		refusedAsAFingerprintTwice(t, plainList(roots...), "A", "C", 2)
	})
	t.Run("the entries with none before and after the repeat do not change it", func(t *testing.T) {
		roots := plainRoots(6)
		roots[0].noFP, roots[5].noFP = true, true
		roots[4].fp = roots[2].fp
		refusedAsAFingerprintTwice(t, plainList(roots...), "C", "E", 4)
	})
}

func seq(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// A fingerprint of a form that the page does not allow is refused for its form, before the repeat is
// looked at: the same text twice in a wrong form gives the error of the form, at the first entry.
func TestAFingerprintOfAWrongFormIsRefusedForItsFormNotForTheRepeat(t *testing.T) {
	for name, bad := range map[string]string{
		"upper case":        strings.Repeat("A", 40),
		"39 digits":         strings.Repeat("a", 39),
		"41 digits":         strings.Repeat("a", 41),
		"a g":               "g" + strings.Repeat("a", 39),
		"an empty text":     "",
		"digits with space": strings.Repeat("a", 39) + " ",
	} {
		t.Run(name, func(t *testing.T) {
			roots := plainRoots(2)
			roots[0].fp, roots[1].fp = bad, bad
			_, err := rootlist.ParseList(plainList(roots...))
			if err == nil || !strings.Contains(err.Error(), "$.roots[0].openpgp_fingerprint: must be 40 lower-case hexadecimal digits") {
				t.Errorf("error %v, want the form at the first entry", err)
			}
			// The same text in the second entry only: the form at the second entry.
			roots[0].fp = plainRoots(1)[0].fp
			_, err = rootlist.ParseList(plainList(roots...))
			if err == nil || !strings.Contains(err.Error(), "$.roots[1].openpgp_fingerprint: must be 40 lower-case hexadecimal digits") {
				t.Errorf("error %v, want the form at the second entry", err)
			}
		})
	}
	t.Run("a repeat of a good fingerprint, and a wrong one in the next entry: the repeat is found first", func(t *testing.T) {
		roots := plainRoots(3)
		roots[1].fp = roots[0].fp
		roots[2].fp = strings.Repeat("A", 40)
		refusedAsAFingerprintTwice(t, plainList(roots...), "A", "B", 1)
	})
	t.Run("a wrong one in the first entry and a repeat after it: the form is found first", func(t *testing.T) {
		roots := plainRoots(3)
		roots[0].fp = strings.Repeat("A", 40)
		roots[2].fp = roots[1].fp
		_, err := rootlist.ParseList(plainList(roots...))
		if err == nil || !strings.Contains(err.Error(), "$.roots[0].openpgp_fingerprint: must be 40") {
			t.Errorf("error %v, want the form at the first entry", err)
		}
	})
}

// For one entry the checks run in the order: the form, the label twice, the pin twice, the
// fingerprint twice. Across entries the earlier entry's fault is the one that is named.
func TestTheOrderOfTheChecksOfTheEntries(t *testing.T) {
	t.Run("a label twice and a fingerprint twice in one entry give the label", func(t *testing.T) {
		roots := plainRoots(2)
		roots[1].label = "A"
		roots[1].fp = roots[0].fp
		_, err := rootlist.ParseList(plainList(roots...))
		if err == nil || !strings.Contains(err.Error(), "$.roots[1].label: the label appears twice") {
			t.Errorf("error %v, want the label", err)
		}
	})
	t.Run("a pin twice and a fingerprint twice in one entry give the pin", func(t *testing.T) {
		roots := plainRoots(2)
		roots[1].pin = roots[0].pin
		roots[1].fp = roots[0].fp
		_, err := rootlist.ParseList(plainList(roots...))
		if err == nil || !strings.Contains(err.Error(), "$.roots[1].x509_spki_sha256: the pin appears twice") {
			t.Errorf("error %v, want the pin", err)
		}
	})
	t.Run("a label twice, a pin twice and a fingerprint twice in one entry give the label", func(t *testing.T) {
		roots := plainRoots(2)
		roots[1] = roots[0]
		_, err := rootlist.ParseList(plainList(roots...))
		if err == nil || !strings.Contains(err.Error(), "$.roots[1].label: the label appears twice") {
			t.Errorf("error %v, want the label", err)
		}
	})
	t.Run("a fingerprint twice in an earlier entry and a label twice in a later one give the fingerprint", func(t *testing.T) {
		roots := plainRoots(4)
		roots[1].fp = roots[0].fp
		roots[3].label = "C"
		refusedAsAFingerprintTwice(t, plainList(roots...), "A", "B", 1)
	})
	t.Run("a fingerprint twice in an earlier entry and a pin twice in a later one give the fingerprint", func(t *testing.T) {
		roots := plainRoots(4)
		roots[1].fp = roots[0].fp
		roots[3].pin = roots[2].pin
		refusedAsAFingerprintTwice(t, plainList(roots...), "A", "B", 1)
	})
	t.Run("a label twice in an earlier entry and a fingerprint twice in a later one give the label", func(t *testing.T) {
		roots := plainRoots(4)
		roots[1].label = "A"
		roots[3].fp = roots[2].fp
		_, err := rootlist.ParseList(plainList(roots...))
		if err == nil || !strings.Contains(err.Error(), "$.roots[1].label: the label appears twice") {
			t.Errorf("error %v, want the label", err)
		}
	})
	t.Run("a pin twice in an earlier entry and a fingerprint twice in a later one give the pin", func(t *testing.T) {
		roots := plainRoots(4)
		roots[1].pin = roots[0].pin
		roots[3].fp = roots[2].fp
		_, err := rootlist.ParseList(plainList(roots...))
		if err == nil || !strings.Contains(err.Error(), "$.roots[1].x509_spki_sha256: the pin appears twice") {
			t.Errorf("error %v, want the pin", err)
		}
	})
	t.Run("a pin of a wrong form in a later entry does not hide the repeat of an earlier one", func(t *testing.T) {
		roots := plainRoots(3)
		roots[1].fp = roots[0].fp
		roots[2].pin = "xyz"
		refusedAsAFingerprintTwice(t, plainList(roots...), "A", "B", 1)
	})
	t.Run("a label of a wrong form in the same entry as the repeat gives the label form", func(t *testing.T) {
		roots := plainRoots(2)
		roots[1].fp = roots[0].fp
		roots[1].label = "b"
		_, err := rootlist.ParseList(plainList(roots...))
		if err == nil || !strings.Contains(err.Error(), "$.roots[1].label: the member is required and is one upper-case letter") {
			t.Errorf("error %v, want the label form", err)
		}
	})
}

// The checks of the members that come before roots, and the members that come after it, keep their
// place: a list that has a fingerprint twice and another fault is refused with the fault that the
// page names first.
func TestAFingerprintTwiceBesideAnotherFaultOfTheList(t *testing.T) {
	w := newWorld(t)
	roots := plainRoots(2)
	roots[1].fp = roots[0].fp
	twice := spec{sequence: "5", roots: roots}
	j := twice.json()
	refusedAsAFingerprintTwice(t, j, "A", "B", 1)

	t.Run("the version comes before", func(t *testing.T) {
		data := replace(t, j, `"version":1`, `"version":2`)
		l, err := rootlist.ParseList(data)
		if l != nil || !errors.Is(err, rootlist.ErrUnsupportedVersion) {
			t.Errorf("(%v, %v), want the error of the version", l, err)
		}
	})
	t.Run("the sequence comes before", func(t *testing.T) {
		_, err := rootlist.ParseList(replace(t, j, `"sequence":5`, `"sequence":0`))
		if err == nil || !strings.Contains(err.Error(), "$.sequence: must be an integer of at least 1") {
			t.Errorf("error %v", err)
		}
		_, err = rootlist.ParseList(replace(t, j, `,"sequence":5`, ``))
		if err == nil || !strings.Contains(err.Error(), "$.sequence: the member is required") {
			t.Errorf("error %v", err)
		}
	})
	t.Run("the times come before", func(t *testing.T) {
		_, err := rootlist.ParseList(replace(t, j, `"signed_at":"`+signedAt+`"`, `"signed_at":"x"`))
		if err == nil || !strings.Contains(err.Error(), "$.signed_at") {
			t.Errorf("error %v", err)
		}
		_, err = rootlist.ParseList(replace(t, j, `"expires_at":"`+expiresAt+`"`, `"expires_at":"x"`))
		if err == nil || !strings.Contains(err.Error(), "$.expires_at") {
			t.Errorf("error %v", err)
		}
	})
	t.Run("a member that the page does not know comes before", func(t *testing.T) {
		_, err := rootlist.ParseList(replace(t, j, `"version":1`, `"version":1,"x":1`))
		if err == nil || strings.Contains(err.Error(), "fingerprint appears twice") {
			t.Errorf("error %v, want the unknown member", err)
		}
	})
	t.Run("last_record_sha256 and removals come after: the repeat is named", func(t *testing.T) {
		badLast := replace(t, j, `"last_record_sha256":"`+defaultLast+`"`, `"last_record_sha256":"zz"`)
		refusedAsAFingerprintTwice(t, badLast, "A", "B", 1)
		withRemoval := spec{sequence: "5", roots: roots}.withRemovals(removalSpec{label: "Q", pin: "xyz", auth: ""})
		refusedAsAFingerprintTwice(t, withRemoval.json(), "A", "B", 1)
	})
	t.Run("a repeat in roots and a fault in removals, with the roots after the removals in the file: the repeat", func(t *testing.T) {
		withRemoval := spec{sequence: "5", roots: roots}.withRemovals(removalOf(t, w.c), removalOf(t, w.c))
		refusedAsAFingerprintTwice(t, withRemoval.json(), "A", "B", 1)
	})
}

// A removal does not take part: it has no fingerprint, and an entry of roots that has the pin of a
// removed key is no repeat of a fingerprint.
func TestARemovalIsNotComparedWithTheFingerprintsOfRoots(t *testing.T) {
	w := newWorld(t)
	s := listOf(8, w.a, w.b).withRemovals(removalOf(t, w.c))
	if _, err := rootlist.ParseList(s.json()); err != nil {
		t.Fatal(err)
	}
}

// Through Verify the refusal is check 5 with the reason malformed, and the detail names the labels
// and the place. The checks before it keep their codes, and the checks after it are not reached.
func TestVerifyGivesMalformedAtCheck5ForAFingerprintTwice(t *testing.T) {
	b := newBase(t)
	w := b.w
	trust := b.trust(t)
	twice := func(seq int) spec {
		s := listOf(seq, w.a, w.b)
		s.roots[1].fp = s.roots[0].fp
		return s
	}
	t.Run("signed by a trusted root key", func(t *testing.T) {
		v := rootlist.Verify(signed(t, twice(8), w.a), trust, now)
		refuses(t, v, rootlist.Malformed, 5)
		for _, part := range []string{"openpgp_fingerprint", "appears twice", "labels A and B", "roots[1]"} {
			if !strings.Contains(v.Detail, part) {
				t.Errorf("the detail %q lacks %q", v.Detail, part)
			}
		}
	})
	t.Run("against the initial pins", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, twice(1), w.a), pinsOf(t, w.a.pin), now), rootlist.Malformed, 5)
	})
	t.Run("the code is the code of a label twice and of a pin twice", func(t *testing.T) {
		labelTwice := listOf(8, w.a, w.b)
		labelTwice.roots[1].label = "A"
		pinTwice := listOf(8, w.a, w.b)
		pinTwice.roots[1].pin = pinTwice.roots[0].pin
		for _, s := range []spec{twice(8), labelTwice, pinTwice} {
			refuses(t, rootlist.Verify(signed(t, s, w.a), trust, now), rootlist.Malformed, 5)
		}
	})
	t.Run("check 1 comes before: a signature file that is not of the form", func(t *testing.T) {
		cand := rootlist.Signed{JSON: twice(8).json(), JWS: []byte(`{}`)}
		refuses(t, rootlist.Verify(cand, trust, now), rootlist.Malformed, 1)
	})
	t.Run("check 2 comes before: a signer that the host does not know", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, twice(8), w.z), trust, now), rootlist.UnknownSigner, 2)
	})
	t.Run("check 3 comes before: a signature that does not verify", func(t *testing.T) {
		data := twice(8).json()
		cand := rootlist.Signed{JSON: append(append([]byte{}, data...), ' '), JWS: sign(t, data, w.a)}
		refuses(t, rootlist.Verify(cand, trust, now), rootlist.SignatureInvalid, 3)
	})
	t.Run("check 4 comes before: a list of version 2", func(t *testing.T) {
		data := replace(t, twice(8).json(), `"version":1`, `"version":2`)
		refuses(t, rootlist.Verify(signedBytes(t, data, w.a), trust, now), rootlist.VersionUnsupported, 4)
	})
	t.Run("check 5 comes before 6, 7 and 11: a lower, an equal sequence and a list that has expired", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, twice(6), w.a), trust, now), rootlist.Malformed, 5)
		refuses(t, rootlist.Verify(signed(t, twice(7), w.a), trust, now), rootlist.Malformed, 5)
		old := twice(8).at(longAgo)
		refuses(t, rootlist.Verify(signed(t, old, w.a), trust, now), rootlist.Malformed, 5)
	})
	t.Run("check 5 comes before 8 and 10: signers that are too few or unknown", func(t *testing.T) {
		refuses(t, rootlist.Verify(signed(t, twice(8), w.b), trust, now), rootlist.Malformed, 5)
		refuses(t, rootlist.Verify(signed(t, twice(8), w.a, w.z), trust, now), rootlist.Malformed, 5)
	})
	t.Run("the same list without the repeat is accepted", func(t *testing.T) {
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.a, w.b), w.a), trust, now))
	})
	t.Run("the list that the host holds again is read by the same reader", func(t *testing.T) {
		if _, err := rootlist.ParseHeld(twice(7).json()); err == nil {
			t.Error("a held list with a fingerprint twice was taken")
		}
	})
}

// The check reads the value of the fingerprint, not the way it is written: white space between the
// members and an escape for a digit do not hide the repeat.
func TestAFingerprintTwiceIsFoundWhateverTheFormOfTheText(t *testing.T) {
	roots := plainRoots(2)
	roots[1].fp = roots[0].fp
	canonical := plainList(roots...)
	t.Run("the canonical form", func(t *testing.T) {
		refusedAsAFingerprintTwice(t, canonical, "A", "B", 1)
	})
	t.Run("white space and line breaks between the members", func(t *testing.T) {
		pretty := []byte(strings.NewReplacer(`{"label"`, "{\n \"label\"", `,"roots"`, ",\n\"roots\"", `"roots":[`, "\"roots\": [\n").Replace(string(canonical)))
		if string(pretty) == string(canonical) {
			t.Fatal("the form was not changed")
		}
		refusedAsAFingerprintTwice(t, pretty, "A", "B", 1)
	})
	t.Run("an escape that spells a digit of the second fingerprint", func(t *testing.T) {
		a := roots[0].fp
		if !strings.HasSuffix(a, "1") {
			t.Fatal("the test expects the fingerprint of A to end in 1")
		}
		old := `"openpgp_fingerprint":"` + a + `","x509_spki_sha256":"` + roots[1].pin
		data := []byte(strings.Replace(string(canonical), old, `"openpgp_fingerprint":"`+a[:39]+`\u0031","x509_spki_sha256":"`+roots[1].pin, 1))
		if string(data) == string(canonical) {
			t.Fatal("the edit changed nothing")
		}
		refusedAsAFingerprintTwice(t, data, "A", "B", 1)
	})
}

// A list of many entries that all have one fingerprint (within the size limit of the page) is refused
// at the second entry.
func TestAHostileListOfManyEntriesWithOneFingerprintIsRefused(t *testing.T) {
	one := fmt.Sprintf("%040x", 1)
	var b strings.Builder
	b.WriteString(`{"expires_at":"` + expiresAt + `","roots":[`)
	for i := 0; i < 1500; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"label":"%c","openpgp_fingerprint":"%s","x509_spki_sha256":"%064x"}`, 'A'+i%26, one, i+1)
	}
	b.WriteString(`],"sequence":1,"signed_at":"` + signedAt + `","version":1}`)
	if b.Len() > rootlist.MaxBytes {
		t.Fatalf("the list is %d bytes, over the limit of the page", b.Len())
	}
	refusedAsAFingerprintTwice(t, []byte(b.String()), "A", "B", 1)
}
