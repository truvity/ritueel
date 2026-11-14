package jsonset

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// EscapeExact writes a text as Escape does, with a backslash twice, so that a backslash in the
// output always starts an escape and two different texts do not give the same output. The expected
// texts are built with qesc and bs, so that no escape is written out in this file.

const bs = string(rune(0x5c))

// unescapeExact reads the output of EscapeExact back: a doubled backslash is a backslash, an
// escape of four hexadecimal digits is a UTF-16 code unit (a pair of them one character), and an
// escape of x and two digits is one byte. It is the other half of the rule, written out again, and
// fails the test on text that EscapeExact cannot have written. Every text, bytes that are not UTF-8
// included, reads back to itself: that is what makes the function one to one.
func unescapeExact(t testing.TB, out string) string {
	t.Helper()
	var b strings.Builder
	var units []uint16
	flush := func() {
		b.WriteString(string(utf16.Decode(units)))
		units = units[:0]
	}
	for i := 0; i < len(out); {
		if out[i] != '\\' {
			flush()
			if out[i] < 0x20 || out[i] > 0x7e {
				t.Fatalf("a byte beyond printable ASCII in %q", out)
			}
			b.WriteByte(out[i])
			i++
			continue
		}
		switch {
		case strings.HasPrefix(out[i:], bs+bs):
			flush()
			b.WriteString(bs)
			i += 2
		case strings.HasPrefix(out[i:], bs+"x") && len(out) >= i+4:
			flush()
			v, err := strconv.ParseUint(out[i+2:i+4], 16, 8)
			if err != nil {
				t.Fatalf("a bad escape in %q", out)
			}
			b.WriteByte(byte(v))
			i += 4
		case strings.HasPrefix(out[i:], bs+"u") && len(out) >= i+6:
			v, err := strconv.ParseUint(out[i+2:i+6], 16, 16)
			if err != nil {
				t.Fatalf("a bad escape in %q", out)
			}
			units = append(units, uint16(v))
			i += 6
		default:
			t.Fatalf("a backslash that starts nothing in %q at %d", out, i)
		}
	}
	flush()
	return b.String()
}

func TestEscapeExactDoublesTheBackslashAndEscapesAsEscapeDoes(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"ASCII is unchanged but for the space", "abc XYZ 019 _-.:/", "abc" + bs + "x20XYZ" + bs + "x20019" + bs + "x20_-.:/"},
		{"a space is the escape of the byte 0x20", " ", bs + "x20"},
		{"a space beside a colon", "a: b", "a:" + bs + "x20b"},
		{"the text of an escape of a space, typed", bs + "x20", bs + bs + "x20"},
		{"a backslash is doubled", "a" + bs + "b", "a" + bs + bs + "b"},
		{"two backslashes", bs + bs, bs + bs + bs + bs},
		{"a backslash that looks like an escape", "a" + bs + "u0430", "a" + bs + bs + "u0430"},
		{"the letter that the look-alike names", "a" + string(rune(0x430)), "a" + qesc(0x430)},
		{"a control character", "a\x1bb", "a" + qesc(0x1b) + "b"},
		{"a character beyond the first plane", string(rune(0x1f600)), qesc(0xd83d) + qesc(0xde00)},
		{"a byte that is not UTF-8", "a\xffb", "a" + bs + "xffb"},
		{"a cut character", "a\xc3", "a" + bs + "xc3"},
		{"two bytes that are not UTF-8", "\xed\xa0", bs + "xed" + bs + "xa0"},
		{"the character U+FFFD", "a" + string(rune(0xfffd)), "a" + qesc(0xfffd)},
		{"a backslash and the text of a byte", bs + "xff", bs + bs + "xff"},
		{"a backslash before a control character", bs + "\n", bs + bs + qesc(10)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EscapeExact(c.in); got != c.want {
				t.Errorf("EscapeExact(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestEscapeExactIsEscapeForAValidTextWithNoBackslashAndNoSpace(t *testing.T) {
	for _, s := range []string{"", "plain", "\x00\x01\x7f", string(rune(0x202e)) + "x", string(rune(0x1f600)), string(rune(0xfffd))} {
		if got, want := EscapeExact(s), Escape(s); got != want {
			t.Errorf("EscapeExact(%q) = %q, Escape = %q", s, got, want)
		}
	}
}

// Two names that differ give two outputs, over names that a hostile stick could hold, bytes that are
// not UTF-8 among them.
func hostileTexts() []string {
	r := func(c rune) string { return string(rune(c)) }
	return []string{
		"", "a", "a b", "a\tb", "a\nb", "a\rb", "a\x01b", "a\x7fb", "a\x1b[31mred", "a" + bs + "b", bs, bs + bs, bs + bs + bs,
		"a" + bs + "u0430", "a" + r(0x430), r(0x430) + "bc", "tr" + r(0x443) + "st", "a" + r(0x202e) + "b", "a" + r(0x200b) + "b",
		"caf" + r(0xe9), "a" + r(0x1f600), "a%2e%2eb", "C:x", "a*b", "CON", "aux.txt", "x.", "...", ".rt-abc", ".RT-abc",
		bs + "u0000", r(0), bs + "n", bs + "x1b", r(0x1b), "u0430", bs + "u", bs + "u04", bs + "ud83d" + bs + "ude00", r(0x1f600),
		bs + "ud83d", r(0xd7ff), r(0xe000), r(0xfffd), "a" + r(0xfffd) + "b", strings.Repeat("a", 255), strings.Repeat("a", 256),
		strings.Repeat(bs, 255), bs + r(0x430), bs + bs + r(0x430),
	}
}

func TestEscapeExactGivesDifferentTextsForDifferentNames(t *testing.T) {
	seen := map[string]string{}
	for _, s := range hostileTexts() {
		out := EscapeExact(s)
		if !printableOnly(out) || strings.Contains(out, " ") {
			t.Errorf("EscapeExact(%q) = %q is not printable ASCII without a space", s, out)
		}
		if prev, ok := seen[out]; ok && prev != s {
			t.Errorf("the names %q and %q give the same text %q", prev, s, out)
		}
		seen[out] = s
		if back := unescapeExact(t, out); back != s {
			t.Errorf("EscapeExact(%q) = %q reads back as %q", s, out, back)
		}
	}
}

func printableOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Each byte that is not UTF-8 is its own escape, so the names that shared one text before do not:
// "a\xffb" and "a\xfeb", the character U+FFFD, and three invalid bytes against three others.
func TestEscapeExactOfBytesThatAreNotUTF8GivesOneTextForEachName(t *testing.T) {
	pairs := [][2]string{
		{"a\xffb", "a\xfeb"},
		{"a\xffb", "a" + string(rune(0xfffd)) + "b"},
		{"\xed\xa0\x80", "\xff\xff\xff"},
		{"\xff", bs + "xff"},
		{"\xc3", "\xc3\xc3"},
	}
	for _, p := range pairs {
		a, b := EscapeExact(p[0]), EscapeExact(p[1])
		if a == b {
			t.Errorf("%q and %q give the same text %q", p[0], p[1], a)
		}
		if unescapeExact(t, a) != p[0] || unescapeExact(t, b) != p[1] {
			t.Errorf("%q or %q does not read back", a, b)
		}
	}
	// No text of valid UTF-8 can give the escape of a byte: its backslash is doubled.
	for _, s := range hostileTexts() {
		// A valid text gives \x only for a space (the byte 0x20 is its own escape), never for a byte of
		// an invalid sequence.
		rest := strings.ReplaceAll(strings.ReplaceAll(EscapeExact(s), bs+bs, ""), bs+"x20", "")
		if utf8.ValidString(s) && strings.Contains(rest, bs+"x") {
			t.Errorf("EscapeExact(%q) = %q holds the escape of a byte", s, EscapeExact(s))
		}
	}
}

// For every pair of texts that differ, bytes that are not UTF-8 included, the outputs differ; and the
// output reads back to the text, which is what makes the function one to one. The fuzz target looks
// for a pair that does not.
func FuzzEscapeExactPairsOfNames(f *testing.F) {
	h := hostileTexts()
	for i := range h {
		f.Add(h[i], h[(i+1)%len(h)])
	}
	f.Add("a"+bs+"u0430", "a"+string(rune(0x430)))
	f.Add("a\xffb", "a\xfeb")
	f.Add("a b", "a"+bs+"x20b")
	f.Add("x: fork history", "x:"+bs+"x20fork"+bs+"x20history")
	f.Fuzz(func(t *testing.T, a, b string) {
		ea, eb := EscapeExact(a), EscapeExact(b)
		if !printableOnly(ea) || !printableOnly(eb) {
			t.Fatalf("not printable ASCII: %q, %q", ea, eb)
		}
		if strings.Contains(ea, " ") || strings.Contains(eb, " ") {
			t.Fatalf("a space in the output: %q, %q", ea, eb)
		}
		if a != b && ea == eb {
			t.Fatalf("%q and %q give the same text %q", a, b, ea)
		}
		if back := unescapeExact(t, ea); back != a {
			t.Fatalf("EscapeExact(%q) = %q reads back as %q", a, ea, back)
		}
	})
}
