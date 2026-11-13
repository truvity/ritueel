package jsonset

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Quote and Shown as tables. Every expected text is built with qesc, so that no escape of the form
// backslash, u and four digits is written out in this file.

func TestQuote(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	e9, euro, emoji := string(rune(0xE9)), string(rune(0x20AC)), string(rune(0x1F600))
	cases := []struct {
		name, in, want string
	}{
		{"plain letters are quoted too", "abc", `"abc"`},
		{"empty", "", `""`},
		{"a space and punctuation as they are", "a b.c[0]$", `"a b.c[0]$"`},
		{"the lowest printable character", " ", `" "`},
		{"the highest printable character", "~", `"~"`},
		{"a quote", `a"b`, `"a\"b"`},
		{"a backslash", `a\b`, `"a\\b"`},
		{"a quote and a backslash together", `\"`, `"\\\""`},
		{"a backslash before an n is not a line feed", `a\n`, `"a\\n"`},
		{"a line feed", "a\nb", `"a` + qesc(10) + `b"`},
		{"a tab", "\t", `"` + qesc(9) + `"`},
		{"a NUL", "\x00", `"` + qesc(0) + `"`},
		{"the escape character", "\x1b", `"` + qesc(0x1b) + `"`},
		{"the delete character", "\x7f", `"` + qesc(0x7f) + `"`},
		{"a letter outside ASCII", e9, `"` + qesc(0xE9) + `"`},
		{"a Cyrillic a", string(rune(0x0430)), `"` + qesc(0x0430) + `"`},
		{"the Kelvin sign", string(rune(0x212A)), `"` + qesc(0x212A) + `"`},
		{"a character of three bytes", euro, `"` + qesc(0x20AC) + `"`},
		{"the last character of the BMP", string(rune(0xFFFF)), `"` + qesc(0xFFFF) + `"`},
		{"the first character above the BMP, a pair of surrogates", string(rune(0x10000)), `"` + qesc(0xD800) + qesc(0xDC00) + `"`},
		{"an emoji, a pair of surrogates", emoji, `"` + qesc(0xD83D) + qesc(0xDE00) + `"`},
		{"the last character of Unicode", string(rune(0x10FFFF)), `"` + qesc(0xDBFF) + qesc(0xDFFF) + `"`},
		{"the escapes of an emoji are lower case", emoji, `"` + strings.ToLower(qesc(0xD83D)+qesc(0xDE00)) + `"`},
		{"an invalid byte is the replacement character", "a\xffb", `"a` + qesc(0xFFFD) + `b"`},
		{"each invalid byte is one replacement character", "\xff\xfe", `"` + qesc(0xFFFD) + qesc(0xFFFD) + `"`},
		{"a truncated character", "a\xc3", `"a` + qesc(0xFFFD) + `"`},
		{"an encoded surrogate is not UTF-8", "\xed\xa0\x80", `"` + qesc(0xFFFD) + qesc(0xFFFD) + qesc(0xFFFD) + `"`},
		{"an overlong NUL is not UTF-8", "\xc0\x80", `"` + qesc(0xFFFD) + qesc(0xFFFD) + `"`},
		{"the replacement character itself", string(rune(0xFFFD)), `"` + qesc(0xFFFD) + `"`},

		// A text of 40 bytes is whole; one of 41 is cut, at a character, and "..." is told.
		{"forty bytes are whole", a(40), `"` + a(40) + `"`},
		{"41 bytes are cut at 40", a(41), `"` + a(40) + `..."`},
		{"a long text is cut at 40", a(500), `"` + a(40) + `..."`},
		{"forty bytes that end in a two-byte character are whole", a(38) + e9, `"` + a(38) + qesc(0xE9) + `"`},
		{"a cut that falls just after a two-byte character keeps it", a(38) + e9 + "a", `"` + a(38) + qesc(0xE9) + `..."`},
		{"a cut inside a two-byte character drops it", a(39) + e9, `"` + a(39) + `..."`},
		{"a cut inside a two-byte character, the character first", a(39) + e9 + a(5), `"` + a(39) + `..."`},
		{"a cut inside a three-byte character, after its first byte", a(39) + euro, `"` + a(39) + `..."`},
		{"a cut inside a three-byte character, after its second byte", a(38) + euro, `"` + a(38) + `..."`},
		{"forty bytes that end in a three-byte character are whole", a(37) + euro, `"` + a(37) + qesc(0x20AC) + `"`},
		{"a cut just after a three-byte character keeps it", a(37) + euro + "a", `"` + a(37) + qesc(0x20AC) + `..."`},
		{"a cut inside a four-byte character, after its first byte", a(39) + emoji, `"` + a(39) + `..."`},
		{"a cut inside a four-byte character, after its second byte", a(38) + emoji, `"` + a(38) + `..."`},
		{"a cut inside a four-byte character, after its third byte", a(37) + emoji, `"` + a(37) + `..."`},
		{"forty bytes that end in a four-byte character are whole", a(36) + emoji, `"` + a(36) + qesc(0xD83D) + qesc(0xDE00) + `"`},
		{"a cut just after a four-byte character keeps it", a(36) + emoji + "a", `"` + a(36) + qesc(0xD83D) + qesc(0xDE00) + `..."`},
		{"a cut that needs a quote escaped", strings.Repeat(`"`, 41), `"` + strings.Repeat(`\"`, 40) + `..."`},
		{"a text of invalid bytes is cut at 40 bytes", strings.Repeat("\xff", 50), `"` + strings.Repeat(qesc(0xFFFD), 40) + `..."`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Quote(tc.in)
			if got != tc.want {
				t.Errorf("Quote(%q)\n  = %s\nwant %s", tc.in, got, tc.want)
			}
			if !utf8.ValidString(got) || strings.ContainsFunc(got, func(r rune) bool { return r < 0x20 || r >= 0x7f }) {
				t.Errorf("the text is not printable ASCII: %q", got)
			}
		})
	}
}

// Shown is the name itself when it is plain (ASCII letters, digits, underscores and hyphens, at
// most 40 bytes), else Quote of it.
func TestShownAgainstQuote(t *testing.T) {
	cases := []struct {
		name, in string
		plain    bool
	}{
		{"letters", "abc", true},
		{"all the plain bytes", "AZaz09_-", true},
		{"forty plain bytes", strings.Repeat("a-", 20), true},
		{"41 plain bytes", strings.Repeat("a", 41), false},
		{"empty", "", false},
		{"a dot", "a.b", false},
		{"a space", "a b", false},
		{"a quote", `a"b`, false},
		{"a backslash", `a\b`, false},
		{"a control", "a\x01", false},
		{"the delete character", "a\x7f", false},
		{"a letter outside ASCII", "caf" + string(rune(0xE9)), false},
		{"a look-alike of k", string(rune(0x212A)), false},
		{"an emoji", string(rune(0x1F600)), false},
		{"invalid UTF-8", "a\xff", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := Quote(tc.in)
			if tc.plain {
				want = tc.in
			}
			if got := Shown(tc.in); got != want {
				t.Errorf("Shown(%q) = %s, want %s", tc.in, got, want)
			}
		})
	}
}
