//go:build linux || darwin

package history

import (
	"encoding/json"
	"strings"
	"testing"
)

// The entries of a root list are read in one form: the bytes that the hexadecimal digits stand
// for. Digits of either case, white space around, a 0x prefix, and the separators space, colon and
// hyphen are dropped. A pin or a fingerprint that is there and is not read in this form makes the
// whole list one that cannot be read (anchor-unknown), so that the entries of a list that no host
// takes hide no key from the lists after it. An entry that has neither member names no key.

// rawEntry is one entry of roots as JSON text. A member whose text is empty is left out; a text
// that starts with "raw:" is put in as it is, otherwise it is a JSON string.
func rawEntry(label, pin, fp string) string {
	quote := func(s string) string {
		if rest, ok := strings.CutPrefix(s, "raw:"); ok {
			return rest
		}
		b, _ := json.Marshal(s)
		return string(b)
	}
	var m []string
	if label != "" {
		m = append(m, `"label":`+quote(label))
	}
	if pin != "" {
		m = append(m, `"x509_spki_sha256":`+quote(pin))
	}
	if fp != "" {
		m = append(m, `"openpgp_fingerprint":`+quote(fp))
	}
	return "{" + strings.Join(m, ",") + "}"
}

func rawList(entries ...string) []byte {
	return []byte(`{"roots":[` + strings.Join(entries, ",") + `],"version":1}`)
}

// pairs writes a hexadecimal text in groups of two digits joined by sep.
func pairs(h, sep string) string {
	var out []string
	for i := 0; i < len(h); i += 2 {
		out = append(out, h[i:i+2])
	}
	return strings.Join(out, sep)
}

// formsThatRead are the ways of writing a text of hexadecimal digits that the check reads as the
// same bytes.
func formsThatRead() map[string]func(string) string {
	up := strings.ToUpper
	return map[string]func(string) string{
		"lower case":                 func(h string) string { return h },
		"upper case":                 up,
		"mixed case":                 func(h string) string { return up(h[:7]) + h[7:20] + up(h[20:23]) + h[23:] },
		"a 0x prefix":                func(h string) string { return "0x" + h },
		"a 0X prefix":                func(h string) string { return "0X" + h },
		"a 0x prefix and capitals":   func(h string) string { return "0x" + up(h) },
		"a space before":             func(h string) string { return " " + h },
		"a space after":              func(h string) string { return h + " " },
		"white space around":         func(h string) string { return " \t\r\n" + h + "\n\t " },
		"a line break after":         func(h string) string { return h + "\n" },
		"colons between the bytes":   func(h string) string { return pairs(h, ":") },
		"spaces between the bytes":   func(h string) string { return pairs(h, " ") },
		"hyphens between the bytes":  func(h string) string { return pairs(h, "-") },
		"a prefix and colons":        func(h string) string { return "0x" + pairs(h, ":") },
		"white space and colons":     func(h string) string { return "  " + pairs(h, ":") + "  " },
		"mixed separators":           func(h string) string { return h[:4] + ":" + h[4:8] + " " + h[8:12] + "-" + h[12:] },
		"separators at both ends":    func(h string) string { return "-:" + h + ":-" },
		"a prefix, a space, digits":  func(h string) string { return "0x " + h },
		"groups of four with spaces": func(h string) string { return h[:4] + " " + h[4:8] + " " + h[8:] },
	}
}

func TestRootReturnsEntriesAreReadInOneForm(t *testing.T) {
	for name, form := range formsThatRead() {
		t.Run("a pin with "+name+" that returns", func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", pa, "")), rawList(rawEntry("B", pb, "")), rawList(rawEntry("A", form(pa), "")))
			wantReturns(t, rep, ret{list: 3, label: "A", has: []string{"its pin " + short16(pa)}})
			noUnreadable(t, rep)
		})
		t.Run("a pin with "+name+" that left", func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", form(pa), "")), rawList(rawEntry("B", pb, "")), rawList(rawEntry("A", pa, "")))
			wantReturns(t, rep, ret{list: 3, label: "A", has: []string{"its pin " + short16(pa)}})
			noUnreadable(t, rep)
		})
		t.Run("a pin with "+name+" that stays", func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", pa, "")), rawList(rawEntry("A", form(pa), "")), rawList(rawEntry("A", pa, "")))
			wantReturns(t, rep)
			noUnreadable(t, rep)
		})
		t.Run("a fingerprint with "+name+" that returns under another pin", func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", pa, f1)), rawList(rawEntry("B", pb, "")), rawList(rawEntry("C", pc, form(f1))))
			wantReturns(t, rep, ret{list: 3, label: "C", has: []string{"OpenPGP fingerprint " + f1[:16]}, not: []string{"its pin"}})
			noUnreadable(t, rep)
		})
		t.Run("a fingerprint with "+name+" that left", func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", pa, form(f1))), rawList(rawEntry("B", pb, "")), rawList(rawEntry("C", pc, f1)))
			wantReturns(t, rep, ret{list: 3, label: "C", has: []string{"OpenPGP fingerprint " + f1[:16]}})
			noUnreadable(t, rep)
		})
		t.Run("a fingerprint with "+name+" that stays under its pin", func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", pa, f1)), rawList(rawEntry("A", pa, form(f1))), rawList(rawEntry("A", form(pa), f1)))
			wantReturns(t, rep)
			noUnreadable(t, rep)
		})
		t.Run("a fingerprint with no pin, with "+name+", that returns", func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", pa, f1)), rawList(rawEntry("B", pb, "")), rawList(rawEntry("C", "", form(f1))))
			wantReturns(t, rep, ret{list: 3, label: "C", has: []string{"OpenPGP fingerprint " + f1[:16]}})
			noUnreadable(t, rep)
		})
	}
}

// noUnreadable fails when a root list of the bundle is said to be unreadable.
func noUnreadable(t *testing.T, rep *Report) {
	t.Helper()
	for _, f := range rep.Findings {
		if f.Code == AnchorUnknown && strings.Contains(f.Detail, "cannot be read") {
			t.Errorf("a list cannot be read: %s", f.Line())
		}
	}
}

// formsThatDoNotRead are texts that stand for no pin (64 digits) or no fingerprint (40 digits).
func formsThatDoNotRead(h string, digits int) map[string]string {
	return map[string]string{
		"one digit too few":                h[:digits-1],
		"one digit too many":               h + "0",
		"two digits too few":               h[:digits-2],
		"two digits too many":              h + "00",
		"twice the digits":                 h + h,
		"half the digits":                  h[:digits/2],
		"one digit":                        "a",
		"an empty text":                    `raw:""`,
		"white space only":                 " \t\n",
		"a prefix only":                    "0x",
		"separators only":                  ":-: ",
		"not hexadecimal":                  strings.Repeat("g", digits),
		"a letter beyond f at the end":     h[:digits-1] + "g",
		"a wide digit":                     h[:digits-2] + string(rune(0x663)) + string(rune(0x664)),
		"a wide digit in the place of two": h[:digits-2] + string(rune(0xff11)),
		"two prefixes of other case":       "0x0y" + h[2:],
		"a prefix twice":                   "0xx" + h[1:],
		"an underscore between":            h[:10] + "_" + h[10:],
		"a dot between":                    h[:10] + "." + h[10:],
		"a comma between":                  h[:10] + "," + h[10:],
		"a slash between":                  h[:10] + "/" + h[10:],
		"a tab between":                    h[:10] + "\t" + h[10:],
		"a line break between":             h[:10] + "\n" + h[10:],
		"a no-break space around":          " " + h + " ",
		"a vertical tab around":            "\v" + h + "\v",
		"a form feed around":               "\f" + h + "\f",
		"a plus sign":                      "+" + h[1:],
		"a minus sign as a digit":          "-" + h[1:digits-1] + "-",
		"a quote":                          "\"" + h[1:],
		"a NUL":                            h[:10] + "\x00" + h[11:],
		"a byte that is not UTF-8":         h[:10] + "\xff" + h[10:],
		"the other kind of digits":         map[int]string{64: pa[:40], 40: pa}[digits],
	}
}

// An entry with a pin or a fingerprint that is there and cannot be read makes the list one that
// cannot be read. The finding anchor-unknown is for that list, the list itself is not judged, and
// the list after it has an unknown list before it: a key that an earlier list held is a return.
func TestRootReturnsAnEntryThatCannotBeReadMakesTheListOneThatCannotBeRead(t *testing.T) {
	check := func(t *testing.T, bad string) {
		t.Helper()
		rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0, ent{"B", pb, ""}), []byte(bad), rootsJSON(0, ent{"A", pa, ""}))
		has(t, rep, AnchorUnknown, listPathOf(setN(3)))
		d := detail(rep, AnchorUnknown, listPathOf(setN(3)))
		if !strings.Contains(d, "entry 1 of roots has a pin or an OpenPGP fingerprint that is not hexadecimal digits of the right length") {
			t.Errorf("the detail of anchor-unknown is %q", d)
		}
		got := returnsOf(rep)
		if len(got) != 1 || got[0].Path != listPathOf(setN(4)) {
			t.Fatalf("findings %v", lines(got))
		}
		for _, want := range []string{"the list before this one cannot be read" + wRule, wBefore(setN(3))} {
			if !strings.Contains(got[0].Detail, want) {
				t.Errorf("the detail %q lacks %q", got[0].Detail, want)
			}
		}
		n := 0
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown && f.Path == listPathOf(setN(3)) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%d findings of anchor-unknown for the list", n)
		}
	}
	for name, pin := range formsThatDoNotRead(pa, 64) {
		t.Run("a pin: "+name, func(t *testing.T) {
			check(t, string(rawList(rawEntry("C", pc, ""), rawEntry("D", pin, ""))))
		})
		t.Run("a pin: "+name+", with a fingerprint that reads", func(t *testing.T) {
			check(t, string(rawList(rawEntry("C", pc, ""), rawEntry("D", pin, f1))))
		})
	}
	for name, fp := range formsThatDoNotRead(f1, 40) {
		t.Run("a fingerprint: "+name, func(t *testing.T) {
			check(t, string(rawList(rawEntry("C", pc, ""), rawEntry("D", pc, fp))))
		})
		t.Run("a fingerprint: "+name+", and no pin", func(t *testing.T) {
			check(t, string(rawList(rawEntry("C", pc, ""), rawEntry("D", "", fp))))
		})
	}
	t.Run("a pin that does not read and a fingerprint that does not read", func(t *testing.T) {
		check(t, string(rawList(rawEntry("C", pc, ""), rawEntry("D", pa[:5], f1[:5]))))
	})
	t.Run("the bad entry is the first", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0), rawList(rawEntry("D", pa[:5], ""), rawEntry("C", pc, "")), rootsJSON(0, ent{"A", pa, ""}))
		d := detail(rep, AnchorUnknown, listPathOf(setN(3)))
		if !strings.Contains(d, "entry 0 of roots") {
			t.Errorf("the detail is %q", d)
		}
		wantReturnsAt(t, rep, setN(4)+" A")
	})
	t.Run("a bad entry far into the list names its place", func(t *testing.T) {
		var es []string
		for i := 0; i < 25; i++ {
			es = append(es, rawEntry("C", pinOf(700+i), ""))
		}
		es = append(es, rawEntry("D", "zz", ""))
		rep := runLists(t, rawList(es...))
		d := detail(rep, AnchorUnknown, listPathOf(setN(1)))
		if !strings.Contains(d, "entry 25 of roots") {
			t.Errorf("the detail is %q", d)
		}
	})
	t.Run("the bad list is the first, the last, or the only one", func(t *testing.T) {
		bad := rawList(rawEntry("D", "zz", ""))
		rep := runLists(t, bad, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0), rootsJSON(0, ent{"A", pa, ""}), bad)
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
		has(t, rep, AnchorUnknown, listPathOf(setN(5)))
		wantReturns(t, rep, ret{list: 4, label: "A"})
		rep = runLists(t, bad)
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
		wantReturns(t, rep)
	})
	t.Run("a key that never was before the bad list is no return after it", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), rawList(rawEntry("D", "zz", "")), rootsJSON(0, ent{"B", pb, ""}))
		wantReturns(t, rep)
	})
}

// The entries of a list that cannot be read are not kept: the entries before the bad one do not
// count against the limit of the run, and the keys of such a list are not held.
func TestRootReturnsTheKeysOfAListThatCannotBeReadAreNotHeld(t *testing.T) {
	rep := runLists(t,
		rawList(rawEntry("A", pa, ""), rawEntry("D", "zz", "")), // A is in a list that cannot be read
		rootsJSON(0, ent{"B", pb, ""}),
		rootsJSON(0, ent{"A", pa, ""}),
	)
	wantReturns(t, rep)
	has(t, rep, AnchorUnknown, listPathOf(setN(1)))
	r := &reader{entriesLeft: 5, entryLimit: 5}
	a, err := r.parseAnchor(rawList(rawEntry("A", pa, ""), rawEntry("B", pb, ""), rawEntry("D", "zz", "")))
	if err != nil || a.problem == "" || len(a.keys) != 0 {
		t.Errorf("anchor %+v, error %v", a, err)
	}
	if r.entriesLeft != 5 {
		t.Errorf("%d entries left, want 5: the entries of a list that cannot be read are not counted", r.entriesLeft)
	}
}

// An entry that has neither a pin nor a fingerprint names no key, and a list with such an entry
// is not a list that a host takes (the reader of root lists wants a pin): the list cannot be read,
// the finding anchor-unknown says so once, no entry of the list is judged or held, and the list
// after it has an unknown list before it. The entries of that list are not counted against the
// limit of the run.
func TestRootReturnsAnEntryWithNeitherPinNorFingerprintMakesTheListOneThatCannotBeRead(t *testing.T) {
	entries := map[string]string{
		"a label only":                    rawEntry("A", "", ""),
		"no member":                       `{}`,
		"members the check does not read": `{"label":"A","note":"x","future":{"a":[1,2]}}`,
		"an empty text for the pin":       `{"label":"A","x509_spki_sha256":""}`,
	}
	for name, e := range entries {
		t.Run(name, func(t *testing.T) {
			rep := runLists(t,
				rawList(rawEntry("A", pa, "")),
				rawList(rawEntry("B", pb, "")),
				rawList(rawEntry("C", pc, ""), e),
				rawList(rawEntry("A", pa, "")),
			)
			d := detail(rep, AnchorUnknown, listPathOf(setN(3)))
			if name != "an empty text for the pin" && !strings.Contains(d, "entry 1 of roots has neither a pin nor an OpenPGP fingerprint") {
				t.Errorf("the detail of anchor-unknown is %q", d)
			}
			if name == "an empty text for the pin" && !strings.Contains(d, "entry 1 of roots has a pin or an OpenPGP fingerprint that is not hexadecimal digits of the right length") {
				t.Errorf("the detail of anchor-unknown is %q", d)
			}
			// The key C of the unreadable list is held by none; A returns at the list after it.
			wantReturns(t, rep, ret{list: 4, label: "A", has: []string{"the list before this one cannot be read" + wRule, wBefore(setN(3))}})
		})
	}
	t.Run("the entry that names nothing is the first", func(t *testing.T) {
		rep := runLists(t, rawList(`{}`, rawEntry("A", pa, "")), rootsJSON(0), rootsJSON(0, ent{"A", pa, ""}))
		d := detail(rep, AnchorUnknown, listPathOf(setN(1)))
		if !strings.Contains(d, "entry 0 of roots has neither") {
			t.Errorf("the detail is %q", d)
		}
		// A is not held by the first list, which cannot be read: nothing returns.
		wantReturns(t, rep)
	})
	t.Run("an empty list is a list that can be read", func(t *testing.T) {
		rep := runLists(t, rawList(), rawList(), rawList(rawEntry("A", pa, "")))
		wantReturns(t, rep)
		noUnreadable(t, rep)
	})
	t.Run("not counted against the limit", func(t *testing.T) {
		r := &reader{entriesLeft: 1, entryLimit: 1}
		a, err := r.parseAnchor(rawList(rawEntry("B", pb, ""), `{}`))
		if err != nil || a.problem == "" || len(a.keys) != 0 || r.entriesLeft != 1 {
			t.Errorf("anchor %+v, error %v, %d left", a, err, r.entriesLeft)
		}
	})
	t.Run("a fingerprint with no pin is a key and counts against the limit", func(t *testing.T) {
		r := &reader{entriesLeft: 1, entryLimit: 1}
		if _, err := r.parseAnchor(rawList(rawEntry("A", "", f1))); err != nil || r.entriesLeft != 0 {
			t.Fatalf("error %v, %d left", err, r.entriesLeft)
		}
		a, err := r.parseAnchor(rawList(rawEntry("A", "", f2)))
		if err == nil || a != nil {
			t.Errorf("anchor %v, error %v; want ErrTooMuch", a, err)
		}
	})
}

// A pin or a fingerprint of the wrong JSON type, or null, is a list that cannot be read.
func TestRootReturnsAPinOrFingerprintOfAnotherJSONType(t *testing.T) {
	for _, member := range []string{`7`, `1.5`, `true`, `[]`, `{}`, `["` + pa + `"]`, `{"a":"` + pa + `"}`} {
		for _, field := range []string{"x509_spki_sha256", "openpgp_fingerprint"} {
			t.Run(field+" "+member, func(t *testing.T) {
				bad := []byte(`{"roots":[{"label":"A","` + field + `":` + member + `}],"version":1}`)
				rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0, ent{"B", pb, ""}), bad, rootsJSON(0, ent{"A", pa, ""}))
				has(t, rep, AnchorUnknown, listPathOf(setN(3)))
				wantReturns(t, rep, ret{list: 4, label: "A", has: []string{"cannot be read"}})
			})
		}
	}
	for _, e := range []string{
		`{"label":"A","x509_spki_sha256":null}`,
		`{"label":"A","openpgp_fingerprint":null}`,
		`{"label":"A","x509_spki_sha256":null,"openpgp_fingerprint":null}`,
		`{"label":"C","x509_spki_sha256":null,"openpgp_fingerprint":"` + f1 + `"}`,
	} {
		t.Run("null: "+e, func(t *testing.T) {
			rep := runLists(t, rawList(rawEntry("A", pa, "")), rawList(rawEntry("B", pb, "")), rawList(e), rawList(rawEntry("A", pa, "")))
			has(t, rep, AnchorUnknown, listPathOf(setN(3)))
			wantReturns(t, rep, ret{list: 4, label: "A", has: []string{"cannot be read"}})
		})
	}
}

// An entry with only a fingerprint is a key known by its fingerprint: the pin of such an entry is
// "none", a pin of its own (record 0006, rule 54: the fingerprint of an entry that left is on no
// later list under any pin).
func TestRootReturnsAFingerprintWithNoPinIsAKey(t *testing.T) {
	cases := []struct {
		name  string
		lists [][]ent
		want  []ret
	}{
		{"a fingerprint-only entry that leaves and returns",
			[][]ent{{{"A", "", f1}}, {{"B", pb, ""}}, {{"A", "", f1}}},
			[]ret{{list: 3, label: "A", has: []string{"OpenPGP fingerprint " + f1[:16] + "... was on an earlier list", wHeldFP(setN(1))}}}},
		{"a fingerprint-only entry that stays",
			[][]ent{{{"A", "", f1}}, {{"A", "", f1}}, {{"A", "", f1}}}, nil},
		{"a fingerprint-only entry, then a pin that takes the fingerprint",
			[][]ent{{{"A", "", f1}}, {{"A", pa, f1}}, {{"A", pa, f1}}},
			[]ret{{list: 2, label: "A", has: []string{"OpenPGP fingerprint"}}}},
		{"a pin with the fingerprint, then the fingerprint alone",
			[][]ent{{{"A", pa, f1}}, {{"A", "", f1}}, {{"A", "", f1}}},
			[]ret{{list: 2, label: "A", has: []string{"OpenPGP fingerprint"}}}},
		{"a fingerprint-only entry after a gap, under a pin that no list held",
			[][]ent{{{"A", "", f1}}, {{"B", pb, ""}}, {{"C", pc, f1}}},
			[]ret{{list: 3, label: "C", has: []string{"OpenPGP fingerprint"}}}},
		{"a fingerprint-only entry that is new is no return",
			[][]ent{{{"A", pa, f1}}, {{"A", pa, f1}, {"B", "", f2}}, {{"A", pa, f1}, {"B", "", f2}}}, nil},
		{"two fingerprint-only entries, one returns",
			[][]ent{{{"A", "", f1}, {"B", "", f2}}, {{"B", "", f2}}, {{"A", "", f1}, {"B", "", f2}}},
			[]ret{{list: 3, label: "A"}}},
		{"the same fingerprint with no pin and with a pin in one list",
			[][]ent{{{"A", "", f1}, {"B", pb, f1}}, {{"A", "", f1}, {"B", pb, f1}}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var lists [][]byte
			for _, l := range c.lists {
				lists = append(lists, rootsJSON(0, l...))
			}
			wantReturns(t, runLists(t, lists...), c.want...)
		})
	}
	t.Run("after a list that cannot be read, a fingerprint-only entry of an earlier list is a return", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", "", f1}), []byte(`{`), rootsJSON(0, ent{"A", "", f1}))
		wantReturns(t, rep, ret{list: 3, label: "A", has: []string{"OpenPGP fingerprint", "cannot be read"}})
	})
}
