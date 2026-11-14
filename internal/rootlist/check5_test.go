package rootlist_test

import (
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
	"ritueel.id/ritueel/internal/strictjson"
)

// edit is a change of the bytes of a list that is signed after the change, so that checks 1 to 4
// pass and check 5 reads the members.
type edit struct {
	name string
	f    func(t testing.TB, j []byte) []byte
}

func sub(name, old, repl string) edit {
	return edit{name, func(t testing.TB, j []byte) []byte { return replace(t, j, old, repl) }}
}

func whole(name, data string) edit {
	return edit{name, func(testing.TB, []byte) []byte { return []byte(data) }}
}

func TestCheck5TheListMustFollowTheRulesAndMembers(t *testing.T) {
	b := newBase(t)
	w := b.w
	j := b.cand.json()
	trust := b.trust(t)
	pinA, fpA, last := w.a.pin, w.a.fp(), defaultLast
	var edits []edit
	add := func(e ...edit) { edits = append(edits, e...) }

	// JSON rules.
	add(
		sub("a repeated sequence", `"sequence":8`, `"sequence":8,"sequence":8`),
		sub("a repeated signed_at", `"signed_at":"`+signedAt+`"`, `"signed_at":"`+signedAt+`","signed_at":"`+signedAt+`"`),
		sub("a repeated expires_at", `"expires_at":"`+expiresAt+`"`, `"expires_at":"`+expiresAt+`","expires_at":"`+expiresAt+`"`),
		sub("a repeated last_record_sha256", `"last_record_sha256":"`+last+`"`, `"last_record_sha256":"`+last+`","last_record_sha256":"`+last+`"`),
		sub("a repeated version", `"version":1`, `"version":1,"version":1`),
		sub("a repeated roots", `"roots":[`, `"roots":[{"label":"A","x509_spki_sha256":"`+pinA+`"}],"roots":[`),
		sub("a repeated label", `"label":"A"`, `"label":"A","label":"A"`),
		sub("a repeated pin", `"x509_spki_sha256":"`+pinA+`"`, `"x509_spki_sha256":"`+pinA+`","x509_spki_sha256":"`+pinA+`"`),
		sub("a repeated fingerprint", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":"`+fpA+`","openpgp_fingerprint":"`+fpA+`"`),
		edit{"a byte order mark", func(t testing.TB, j []byte) []byte { return append([]byte("\xef\xbb\xbf"), j...) }},
		sub("a float sequence", `"sequence":8`, `"sequence":8.0`),
		sub("a fractional sequence", `"sequence":8`, `"sequence":8.5`),
		sub("an exponent in the sequence", `"sequence":8`, `"sequence":8e0`),
		sub("an exponent in capitals", `"sequence":8`, `"sequence":8E0`),
		sub("a float in an unknown member", `"sequence":8`, `"sequence":8,"x":1.5`),
		sub("a null in an unknown member", `"sequence":8`, `"sequence":8,"x":null`),
		sub("a null sequence", `"sequence":8`, `"sequence":null`),
		sub("a string sequence", `"sequence":8`, `"sequence":"8"`),
		sub("a boolean sequence", `"sequence":8`, `"sequence":true`),
		sub("a list sequence", `"sequence":8`, `"sequence":[8]`),
		sub("an object sequence", `"sequence":8`, `"sequence":{"a":8}`),
		sub("a sequence out of the range of integers", `"sequence":8`, `"sequence":9007199254740992`),
		sub("a sequence far out of range", `"sequence":8`, `"sequence":99999999999999999999`),
		sub("a negative sequence", `"sequence":8`, `"sequence":-8`),
		sub("sequence zero", `"sequence":8`, `"sequence":0`),
		sub("sequence minus zero", `"sequence":8`, `"sequence":-0`),
		sub("a sequence with a leading zero", `"sequence":8`, `"sequence":08`),
		sub("a sequence with a plus sign", `"sequence":8`, `"sequence":+8`),
		sub("a trailing comma", `"version":1}`, `"version":1,}`),
		sub("a comment", `"version":1}`, `"version":1}/* x */`),
		sub("single quotes", `"version":1}`, `"version":1,'x':1}`),
		sub("a control character in a string", `"label":"A"`, "\"label\":\"\x01A\""),
		sub("a raw line feed in a string", `"label":"A"`, "\"label\":\"A\n\""),
		sub("an invalid escape", `"label":"A"`, `"label":"\x41"`),
		sub("a lone surrogate escape", `"label":"A"`, `"label":"\ud800"`),
		sub("a byte that is not UTF-8 in a value", `"label":"A"`, "\"label\":\"A\xff\""),
		sub("a byte that is not UTF-8 in a member name", `"label":"A"`, "\"lab\xffel\":\"A\""),
		whole("an empty file", ``),
		whole("white space only", " \n\t"),
		whole("an array", `[]`),
		whole("a string", `"x"`),
		whole("null", `null`),
		whole("a number", `1`),
		whole("an empty object", `{}`),
		whole("a half object", `{"version":1,`),
		whole("a not-JSON text", `not json`),
		edit{"a byte after the object", func(t testing.TB, j []byte) []byte { return append(j[:len(j):len(j)], 'x') }},
		edit{"a second object after the first", func(t testing.TB, j []byte) []byte { return append(append(j[:len(j):len(j)], '\n'), j...) }},
		edit{"a nesting bomb in an unknown member", func(t testing.TB, j []byte) []byte {
			return replace(t, j, `"sequence":8`, `"sequence":8,"x":`+strings.Repeat("[", 30000)+strings.Repeat("]", 30000))
		}},
	)
	// Members.
	for _, m := range []string{`"expires_at":"` + expiresAt + `",`, `,"signed_at":"` + signedAt + `"`, `"roots":[`, `,"sequence":8`} {
		switch m {
		case `"roots":[`:
			add(edit{"no roots member", func(t testing.TB, j []byte) []byte {
				s := string(j)
				i := strings.Index(s, `"roots":[`)
				k := strings.Index(s, `],"sequence"`)
				return []byte(s[:i] + s[k+2:])
			}})
		default:
			add(sub("no "+strings.Trim(strings.SplitN(m, ":", 2)[0], `,"`), m, ""))
		}
	}
	add(
		sub("an unknown member", `"version":1}`, `"version":1,"x":1}`),
		sub("an unknown member first", `{"expires_at"`, `{"x":1,"expires_at"`),
		sub("an unknown member in a root", `"label":"A"`, `"label":"A","x":1`),
		sub("a member of another letter case", `"sequence":8`, `"Sequence":8`),
		sub("a member in upper case", `"sequence":8`, `"SEQUENCE":8`),
		sub("a member with a Cyrillic letter", `"expires_at"`, "\"\u0435xpires_at\""),
		sub("a member with a trailing space", `"sequence"`, `"sequence "`),
		sub("a member with a NUL", `"sequence"`, `"sequence\u0000"`),
		sub("a member with a look-alike hyphen", `"signed_at"`, "\"signed\u2011at\""),
		sub("a member that the page has for another file", `"version":1}`, `"version":1,"signatures":[]}`),
		sub("the member of removals under the wrong name", `"version":1}`, `"version":1,"removal":[]}`),
	)
	// Times.
	for _, name := range []string{"signed_at", "expires_at"} {
		tm := signedAt
		if name == "expires_at" {
			tm = expiresAt
		}
		old := `"` + name + `":"` + tm + `"`
		for label, bad := range map[string]string{
			"an offset of zero":        strings.TrimSuffix(tm, "Z") + "+00:00",
			"an offset":                strings.TrimSuffix(tm, "Z") + "+01:00",
			"a negative offset":        strings.TrimSuffix(tm, "Z") + "-05:00",
			"z in lower case":          strings.TrimSuffix(tm, "Z") + "z",
			"fractions of a second":    strings.TrimSuffix(tm, "Z") + ".5Z",
			"fractions of zero":        strings.TrimSuffix(tm, "Z") + ".000Z",
			"no zone":                  strings.TrimSuffix(tm, "Z"),
			"a date only":              tm[:10],
			"a space for the T":        strings.Replace(tm, "T", " ", 1),
			"a lower-case t":           strings.Replace(tm, "T", "t", 1),
			"no seconds":               tm[:16] + "Z",
			"the hour 24":              strings.Replace(tm, "T12", "T24", 1),
			"the minute 60":            strings.Replace(tm, ":00:00Z", ":60:00Z", 1),
			"the second 60":            strings.Replace(tm, ":00Z", ":60Z", 1),
			"the month 13":             tm[:5] + "13" + tm[7:],
			"the month 00":             tm[:5] + "00" + tm[7:],
			"the day 00":               tm[:8] + "00" + tm[10:],
			"the 30th of February":     "2027-02-30T12:00:00Z",
			"the 29th of February":     "2027-02-29T12:00:00Z",
			"a year of five digits":    "1" + tm,
			"a year of two digits":     tm[2:],
			"a trailing space":         tm + " ",
			"a leading space":          " " + tm,
			"a trailing line feed":     tm + `\n`,
			"Arabic-Indic digits":      "\u0662\u0660\u0662\u0666" + tm[4:],
			"a full-width digit":       "\uff12" + tm[1:],
			"an empty text":            "",
			"a Unix time as text":      "1763208000",
			"a slash for the hyphens":  strings.ReplaceAll(tm, "-", "/"),
			"a time with the word UTC": strings.TrimSuffix(tm, "Z") + " UTC",
		} {
			add(sub(label+" in "+name, old, `"`+name+`":"`+bad+`"`))
		}
		add(
			sub("a number for "+name, old, `"`+name+`":1763208000`),
			sub("null for "+name, old, `"`+name+`":null`),
			sub("a list for "+name, old, `"`+name+`":["`+tm+`"]`),
		)
	}
	// Roots.
	pinOf := func(k *key) string { return `"x509_spki_sha256":"` + k.pin + `"` }
	add(
		sub("roots empty", `"roots":[`+string(rootsText(t, w.a, w.b))+`]`, `"roots":[]`),
		sub("roots null", `"roots":[`+string(rootsText(t, w.a, w.b))+`]`, `"roots":null`),
		sub("roots an object", `"roots":[`+string(rootsText(t, w.a, w.b))+`]`, `"roots":{}`),
		sub("roots a string", `"roots":[`+string(rootsText(t, w.a, w.b))+`]`, `"roots":"A"`),
		sub("a root that is null", `"roots":[`, `"roots":[null,`),
		sub("a root that is a number", `"roots":[`, `"roots":[1,`),
		sub("a root that is a string", `"roots":[`, `"roots":["A",`),
		sub("a root with no members", `"roots":[`, `"roots":[{},`),
		sub("a root with no label", `"label":"A",`, ``),
		sub("a root with no pin", `,`+pinOf(w.a), ``),
		sub("a pin in upper case", pinOf(w.a), `"x509_spki_sha256":"`+strings.ToUpper(pinA)+`"`),
		sub("one letter of a pin in upper case", pinOf(w.a), `"x509_spki_sha256":"`+upperFirstLetter(pinA)+`"`),
		sub("a pin of 63 digits", pinOf(w.a), `"x509_spki_sha256":"`+pinA[:63]+`"`),
		sub("a pin of 65 digits", pinOf(w.a), `"x509_spki_sha256":"`+pinA+`0"`),
		sub("a pin with a g", pinOf(w.a), `"x509_spki_sha256":"g`+pinA[1:]+`"`),
		sub("a pin with a Cyrillic letter", pinOf(w.a), "\"x509_spki_sha256\":\"\u0430"+pinA[1:]+"\""),
		sub("a pin with a 0x prefix", pinOf(w.a), `"x509_spki_sha256":"0x`+pinA[2:]+`"`),
		sub("a pin with colons", pinOf(w.a), `"x509_spki_sha256":"`+colons(pinA)+`"`),
		sub("a pin that is a number", pinOf(w.a), `"x509_spki_sha256":1`),
		sub("a pin that is null", pinOf(w.a), `"x509_spki_sha256":null`),
		sub("a pin that is empty", pinOf(w.a), `"x509_spki_sha256":""`),
		sub("a pin twice in roots", pinOf(w.b), pinOf(w.a)),
		sub("a label twice in roots", `"label":"B"`, `"label":"A"`),
		sub("a label of two letters", `"label":"A"`, `"label":"AB"`),
		sub("a label in lower case", `"label":"A"`, `"label":"a"`),
		sub("an empty label", `"label":"A"`, `"label":""`),
		sub("a digit for a label", `"label":"A"`, `"label":"1"`),
		sub("a symbol for a label", `"label":"A"`, `"label":"@"`),
		sub("a label with a space", `"label":"A"`, `"label":"A "`),
		sub("a label with a line feed", `"label":"A"`, `"label":"A\n"`),
		sub("a Cyrillic A for the label", `"label":"A"`, "\"label\":\"\u0410\""),
		sub("a full-width A for the label", `"label":"A"`, "\"label\":\"\uff21\""),
		sub("the Kelvin sign for the label K", `"label":"B"`, "\"label\":\"\u212a\""),
		sub("an A with a combining mark", `"label":"A"`, "\"label\":\"A\u0301\""),
		sub("a label that is a number", `"label":"A"`, `"label":65`),
		sub("a label that is null", `"label":"A"`, `"label":null`),
		sub("a label that is not UTF-8", `"label":"A"`, "\"label\":\"\xc1\""),
		sub("a fingerprint in upper case", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":"`+upperFirstLetter(fpA)+`"`),
		sub("a fingerprint of 39 digits", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":"`+fpA[:39]+`"`),
		sub("a fingerprint of 41 digits", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":"`+fpA+`0"`),
		sub("a fingerprint of 64 digits", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":"`+pinA+`"`),
		sub("a fingerprint with a g", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":"g`+fpA[1:]+`"`),
		sub("a fingerprint with spaces", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":"`+spaces(fpA)+`"`),
		sub("an empty fingerprint", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":""`),
		sub("a fingerprint that is null", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":null`),
		sub("a fingerprint that is a number", `"openpgp_fingerprint":"`+fpA+`"`, `"openpgp_fingerprint":1`),
		// last_record_sha256.
		sub("a digest in upper case", `"last_record_sha256":"`+last+`"`, `"last_record_sha256":"`+upperFirstLetter(last)+`"`),
		sub("a digest of 63 digits", `"last_record_sha256":"`+last+`"`, `"last_record_sha256":"`+last[:63]+`"`),
		sub("a digest of 65 digits", `"last_record_sha256":"`+last+`"`, `"last_record_sha256":"`+last+`0"`),
		sub("a digest that is null", `"last_record_sha256":"`+last+`"`, `"last_record_sha256":null`),
		sub("a digest that is empty", `"last_record_sha256":"`+last+`"`, `"last_record_sha256":""`),
		sub("a digest that is a number", `"last_record_sha256":"`+last+`"`, `"last_record_sha256":1`),
	)
	for _, e := range edits {
		t.Run(e.name, func(t *testing.T) {
			data := e.f(t, j)
			if string(data) == string(j) {
				t.Fatal("the edit changed nothing")
			}
			v := rootlist.Verify(signedBytes(t, data, w.a), trust, now)
			refuses(t, v, rootlist.Malformed, 5)
			// The readers of the list alone refuse it in the same way.
			l, err := rootlist.ParseList(data)
			if err == nil || l != nil {
				t.Fatalf("ParseList accepted it")
			}
			if !errors.Is(err, strictjson.ErrMalformed) || errors.Is(err, rootlist.ErrUnsupportedVersion) {
				t.Errorf("the error of ParseList is not a malformed-JSON error: %v", err)
			}
			mustBeASCII(t, "the error text", err.Error())
			if h, err := rootlist.ParseHeld(data); err == nil || h != nil {
				t.Errorf("ParseHeld accepted it")
			}
		})
	}
	if len(edits) < 100 {
		t.Errorf("the table has only %d edits", len(edits))
	}
}

// rootsText is the text of the entries of roots that the spec writes for the keys, without the
// brackets.
func rootsText(t testing.TB, keys ...*key) []byte {
	t.Helper()
	j := listOf(1, keys...).json()
	s := string(j)
	i := strings.Index(s, `"roots":[`) + len(`"roots":[`)
	k := strings.Index(s, `],"sequence"`)
	return []byte(s[i:k])
}

func colons(s string) string {
	var out []string
	for i := 0; i < len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return strings.Join(out, ":")
}

func spaces(s string) string {
	var out []string
	for i := 0; i < len(s); i += 4 {
		out = append(out, s[i:min(i+4, len(s))])
	}
	return strings.Join(out, " ")
}

func upperFirstLetter(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'f' {
			return s[:i] + strings.ToUpper(s[i:i+1]) + s[i+1:]
		}
	}
	return s + "A"
}

func TestCheck5Removals(t *testing.T) {
	b := newBase(t)
	w := b.w
	trust := b.trust(t)
	// A list that drops A and carries A's authorisation: the entries that are broken in turn.
	good := listOf(8, w.b).withRemovals(removalOf(t, w.a))
	jgood := good.json()
	if v := rootlist.Verify(signedBytes(t, jgood, w.a, w.b), trust, now); !v.Accepted {
		t.Fatalf("the witness is refused: %+v", v)
	}
	r := good.removals[0]
	entryText := `{"authorisation":"` + r.auth + `","label":"A","x509_spki_sha256":"` + r.pin + `"}`
	if !strings.Contains(string(jgood), entryText) {
		t.Fatal("the entry is not where the test expects it")
	}
	for _, e := range []edit{
		sub("an entry with no authorisation", `"authorisation":"`+r.auth+`",`, ``),
		sub("an entry with an empty authorisation", `"authorisation":"`+r.auth+`"`, `"authorisation":""`),
		sub("an entry with a null authorisation", `"authorisation":"`+r.auth+`"`, `"authorisation":null`),
		sub("an entry with a number for the authorisation", `"authorisation":"`+r.auth+`"`, `"authorisation":1`),
		sub("an entry with no label", `,"label":"A","x509_spki_sha256":"`+r.pin+`"}`, `,"x509_spki_sha256":"`+r.pin+`"}`),
		sub("an entry with no pin", `,"x509_spki_sha256":"`+r.pin+`"}`, `}`),
		sub("an entry with a pin in upper case", `,"x509_spki_sha256":"`+r.pin+`"}`, `,"x509_spki_sha256":"`+upperFirstLetter(r.pin)+`"}`),
		sub("an entry with a label of two letters", `"label":"A","x509`, `"label":"AA","x509`),
		sub("an entry with a lower-case label", `"label":"A","x509`, `"label":"a","x509`),
		sub("an entry with an unknown member", `{"authorisation":"`, `{"x":1,"authorisation":"`),
		sub("an entry with the authorisation twice", `{"authorisation":"`, `{"authorisation":"x","authorisation":"`),
		sub("the entry twice", entryText, entryText+`,`+entryText),
		sub("the pin twice with another label", entryText, entryText+`,{"authorisation":"`+r.auth+`","label":"Q","x509_spki_sha256":"`+r.pin+`"}`),
		sub("removals null", `"removals":[`+entryText+`]`, `"removals":null`),
		sub("removals an object", `"removals":[`+entryText+`]`, `"removals":{}`),
		sub("removals a string", `"removals":[`+entryText+`]`, `"removals":"x"`),
		sub("an entry that is null", `"removals":[`, `"removals":[null,`),
		sub("an entry that is a string", `"removals":[`, `"removals":["x",`),
		sub("removals twice", `"removals":[`, `"removals":[],"removals":[`),
	} {
		t.Run(e.name, func(t *testing.T) {
			data := e.f(t, jgood)
			refuses(t, rootlist.Verify(signedBytes(t, data, w.a, w.b), trust, now), rootlist.Malformed, 5)
		})
	}
}

func TestCheck5WhatIsAcceptedThoughtItLooksOdd(t *testing.T) {
	b := newBase(t)
	w := b.w
	trust := b.trust(t)
	j := b.cand.json()
	t.Run("an empty removals member", func(t *testing.T) {
		accepts(t, rootlist.Verify(signedBytes(t, replace(t, j, `"roots":[`, `"removals":[],"roots":[`), w.a), trust, now))
	})
	t.Run("an entry with no fingerprint", func(t *testing.T) {
		held := listOf(7, w.a, w.b)
		held.roots[0].noFP = true
		cand := listOf(8, w.a, w.b)
		cand.roots[0].noFP = true
		accepts(t, rootlist.Verify(signed(t, cand, w.a), heldOf(t, held), now))
	})
	t.Run("a list with no fingerprint at all", func(t *testing.T) {
		cand := listOf(1, w.a)
		cand.roots[0].noFP = true
		accepts(t, rootlist.Verify(signed(t, cand, w.a), pinsOf(t, w.a.pin), now))
	})
	t.Run("a first list that has a last_record_sha256 and a later one that has none", func(t *testing.T) {
		// The page says the member is required except in the first list; the host does not enforce
		// it. The page leaves this to the writer, so a change of the rule is a change of the format, and this test shows it.
		cand := listOf(8, w.a, w.b)
		cand.noLast = true
		accepts(t, rootlist.Verify(signed(t, cand, w.a), trust, now))
	})
	t.Run("the canonical form is not required of a signed list", func(t *testing.T) {
		pretty := []byte("{\n  \"version\": 1,\n  \"sequence\": 8,\n" + `  "signed_at": "` + signedAt + `",` + "\n" + `  "expires_at": "` + expiresAt + `",` + "\n" +
			`  "roots": [` + string(rootsText(t, w.a, w.b)) + "]\n}\n")
		accepts(t, rootlist.Verify(signedBytes(t, pretty, w.a), trust, now))
	})
	t.Run("the dates of a list are checked against each other and against the clock", func(t *testing.T) {
		// expires_at is exactly 13 calendar months after signed_at, and signed_at is not later than the
		// host's clock. Each is malformed, at check 5; dates_test.go has the arithmetic and the edges.
		for name, s := range map[string]spec{
			"expires before it is signed": func() spec {
				s := listOf(8, w.a, w.b)
				s.expiresAt = `"2026-11-14T12:00:00Z"`
				s.signedAt = `"2026-11-15T12:00:00Z"`
				return s
			}(),
			"expires a month after":     func() spec { s := listOf(8, w.a, w.b); s.expiresAt = `"2026-12-15T12:00:00Z"`; return s }(),
			"expires far away":          func() spec { s := listOf(8, w.a, w.b); s.expiresAt = `"9999-12-31T00:00:00Z"`; return s }(),
			"signed in the future":      listOf(8, w.a, w.b).at("2026-12-30T12:00:00Z"),
			"a list of the right shape": listOf(8, w.a, w.b).at("2026-11-30T12:00:00Z"),
		} {
			t.Run(name, func(t *testing.T) {
				v := rootlist.Verify(signed(t, s, w.a), trust, now)
				if name == "a list of the right shape" {
					accepts(t, v)
					return
				}
				refuses(t, v, rootlist.Malformed, 5)
			})
		}
	})
	t.Run("a sequence far above the held one", func(t *testing.T) {
		cand := listOf(1, w.a, w.b)
		cand.sequence = "9007199254740991"
		accepts(t, rootlist.Verify(signed(t, cand, w.a), trust, now))
	})
	t.Run("the roots of the list in any order", func(t *testing.T) {
		accepts(t, rootlist.Verify(signed(t, listOf(8, w.b, w.a), w.a), trust, now))
	})
	t.Run("a pin of one list used as the label of nothing: any single capital letter", func(t *testing.T) {
		held := listOf(7, w.a)
		held.roots[0].label = "Q"
		cand := listOf(8, w.a)
		cand.roots[0].label = "Q"
		accepts(t, rootlist.Verify(signed(t, cand, w.a), heldOf(t, held), now))
	})
	t.Run("an escape that spells a plain letter is read as the letter", func(t *testing.T) {
		accepts(t, rootlist.Verify(signedBytes(t, replace(t, j, `"label":"A"`, `"label":"\u0041"`), w.a), trust, now))
	})
}
