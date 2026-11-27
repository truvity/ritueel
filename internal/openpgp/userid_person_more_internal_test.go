package openpgp

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// The rules for the text of a person's own user ID: a new one is printable ASCII (checkPersonUserID), one that the
// key already has keeps its exact bytes and is held to checkExistingUserID. Each class that is refused, each
// that passes, and the edges of the length.

func TestQACheckPersonUserIDIsPrintableASCII(t *testing.T) {
	// every byte of ASCII in the middle of a text
	for c := 0; c < 0x80; c++ {
		id := "Quokka" + string(rune(c)) + "Tester"
		err := checkPersonUserID(id)
		want := c >= 0x20 && c <= 0x7E
		if (err == nil) != want {
			t.Errorf("byte %#x: error %v, want accepted=%v", c, err, want)
		}
		if err != nil && !isParams(err) {
			t.Errorf("byte %#x: %v is not an ErrParams", c, err)
		}
	}
	// every code point beyond ASCII is refused, whatever its class
	for r := rune(0x80); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		if err := checkPersonUserID("Quokka" + string(r) + "Tester"); err == nil {
			t.Fatalf("U+%04X is accepted", r)
		}
	}
	for _, c := range []struct {
		name string
		id   string
		ok   bool
	}{
		{"a name and an address", "Quokka Tester <quokka@example.org>", true},
		{"a comment in brackets", "Quokka Tester (work) <quokka@example.org>", true},
		{"no address", "Quokka Tester", true},
		{"a release root's shape", "Example Release Root A <release@example.org>", true},
		{"two spaces in a row", "Quokka  Tester", true},
		{"one character", "q", true},
		{"empty", "", false},
		{"one space", " ", false},
		{"a space at the start", " Quokka", false},
		{"a space at the end", "Quokka ", false},
		{"a tab", "Quokka\tTester", false},
		{"a line break", "Quokka\nTester", false},
		{"a carriage return", "Quokka\rTester", false},
		{"a NUL", "Quokka\x00Tester", false},
		{"another control character", "Quokka\x1bTester", false},
		{"DEL", "Quokka\x7fTester", false},
		{"a C1 control", "Quokka\u0085Tester", false},
		{"a left-to-right mark", "Quokka\u200eTester", false},
		{"a right-to-left mark", "Quokka\u200fTester", false},
		{"an Arabic letter mark", "Quokka\u061cTester", false},
		{"a bidirectional embedding", "Quokka\u202aTester", false},
		{"a bidirectional override", "Quokka\u202eTester", false},
		{"a bidirectional isolate", "Quokka\u2066Tester", false},
		{"the end of an isolate", "Quokka\u2069Tester", false},
		{"a zero-width space", "Quokka\u200bTester", false},
		{"a zero-width non-joiner", "Quokka\u200cTester", false},
		{"a zero-width joiner", "Quokka\u200dTester", false},
		{"a word joiner", "Quokka\u2060Tester", false},
		{"a soft hyphen", "Quokka\u00adTester", false},
		{"a byte order mark", "\xef\xbb\xbfQuokka Tester", false},
		{"a byte order mark in the middle", "Quokka\xef\xbb\xbfTester", false},
		{"a line separator", "Quokka\u2028Tester", false},
		{"a paragraph separator", "Quokka\u2029Tester", false},
		{"a no-break space", "Quokka\u00a0Tester", false},
		{"an ideographic space", "Quokka\u3000Tester", false},
		{"an unassigned code point", "Quokka\u0378Tester", false},
		{"the last code point", "Quokka\U0010ffffTester", false},
		{"a surrogate half as bytes", "Quokka\xed\xa0\x80Tester", false},
		{"the other half as bytes", "Quokka\xed\xbf\xbfTester", false},
		{"a lone byte of a sequence", "Quokka\xc3Tester", false},
		{"an overlong encoding", "Quokka\xc0\xafTester", false},
		{"a private-use character", "Quokka\ue000Tester", false},
		{"a private-use character of the last planes", "Quokka\U00100000Tester", false},
		{"a combining accent", "Zoe\u0308 Tester", false},
		{"a letter with an accent", "Zo\u00eb Tester", false},
		{"a letter of another script", "\u03a9mega", false},
		{"a language tag", "Quokka\U000e0001Tester", false},
		{"as long as it may be", strings.Repeat("a", maxUserID), true},
		{"as long as it may be, with a space inside", strings.Repeat("a", 500) + " " + strings.Repeat("a", maxUserID-501), true},
		{"as long as it may be, ending with a space", strings.Repeat("a", maxUserID-1) + " ", false},
		{"one byte too long", strings.Repeat("a", maxUserID+1), false},
	} {
		err := checkPersonUserID(c.id)
		if (err == nil) != c.ok {
			t.Errorf("%s: %q: error %v, want accepted=%v", c.name, c.id, err, c.ok)
		}
		if err != nil && !isParams(err) {
			t.Errorf("%s: %v is not an ErrParams", c.name, err)
		}
	}
}

// For a user ID that the key already has: exactly the controls, the format characters, the line and paragraph
// separators and bytes that are not UTF-8 are refused; whatever else is there stays, in any script, with any
// shape, and so do unassigned and private-use code points (which a person's old key may hold).
func TestQACheckExistingUserIDEveryCodePoint(t *testing.T) {
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		want := !unicode.IsControl(r) && !unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
		err := checkExistingUserID([]byte("Quokka" + string(r) + "Tester"))
		if (err == nil) != want {
			t.Fatalf("U+%04X: error %v, want accepted=%v", r, err, want)
		}
		if err != nil && !isParams(err) {
			t.Fatalf("U+%04X: %v is not an ErrParams", r, err)
		}
	}
}

func TestQACheckExistingUserIDTable(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		ok   bool
	}{
		{"a name and an address", "Quokka Tester <quokka@example.org>", true},
		{"a comment in brackets", "Quokka Tester (the old key) <quokka@example.org>", true},
		{"no address", "Quokka Tester", true},
		{"Latin letters with accents", "Zo\u00eb M\u00fcller-\u0141ukasiewicz <zoe@example.org>", true},
		{"a decomposed accent", "Zoe\u0308 Tester", true},
		{"Cyrillic", "\u0418\u0432\u0430\u043d <ivan@example.org>", true},
		{"Greek", "\u03a9\u03bc\u03ad\u03b3\u03b1", true},
		{"Han", "\u4f8b\u793a <person@example.org>", true},
		{"Arabic", "\u0645\u062d\u0645\u062f", true},
		{"Hebrew", "\u05d3\u05d5\u05d3", true},
		{"Devanagari with vowel signs", "\u0928\u092e\u0938\u094d\u0924\u0947", true},
		{"Thai with vowel marks", "\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35", true},
		{"a no-break space", "Quokka\u00a0Tester", true},
		{"a tab-free space of another width", "Quokka\u2003Tester", true},
		{"an unassigned code point", "Quokka\u0378Tester", true},
		{"a noncharacter", "Quokka\ufdd0Tester", true},
		{"the replacement character", "Quokka\ufffdTester", true},
		{"a private-use character", "Quokka\ue000Tester", true},
		{"one byte", "q", true},
		{"a space alone", " ", true},
		{"empty", "", false},
		{"a tab", "Quokka\tTester", false},
		{"a line break", "Quokka\nTester", false},
		{"a carriage return", "Quokka\rTester", false},
		{"a NUL", "Quokka\x00Tester", false},
		{"an escape", "Quokka\x1b[0mTester", false},
		{"DEL", "Quokka\x7fTester", false},
		{"a C1 control", "Quokka\u009bTester", false},
		{"a bidirectional override", "Quokka\u202eTester", false},
		{"a bidirectional isolate", "Quokka\u2067Tester", false},
		{"a left-to-right mark", "Quokka\u200eTester", false},
		{"a zero-width space", "Quokka\u200bTester", false},
		{"a zero-width joiner", "Quokka\u200dTester", false},
		{"a word joiner", "Quokka\u2060Tester", false},
		{"a soft hyphen", "Quokka\u00adTester", false},
		{"a byte order mark", "\xef\xbb\xbfQuokka", false},
		{"a language tag", "Quokka\U000e0001Tester", false},
		{"a line separator", "Quokka\u2028Tester", false},
		{"a paragraph separator", "Quokka\u2029Tester", false},
		{"a surrogate half as bytes", "Quokka\xed\xa0\x80Tester", false},
		{"a lone continuation byte", "Quokka\x80Tester", false},
		{"an overlong encoding", "Quokka\xc0\xafTester", false},
		{"a code point past the last", "Quokka\xf4\x90\x80\x80Tester", false},
		{"a text cut in a sequence", "Quokka\xe2\x82", false},
		{"as long as the reader reads", strings.Repeat("a", MaxForeignUserIDBytes), true},
		{"the last character of two bytes ends at the limit", strings.Repeat("a", MaxForeignUserIDBytes-2) + "\u00eb", true},
		{"the last character of two bytes passes the limit by one", strings.Repeat("a", MaxForeignUserIDBytes-1) + "\u00eb", false},
		{"one byte past the limit", strings.Repeat("a", MaxForeignUserIDBytes+1), false},
		{"as many characters as the limit, twice the bytes", strings.Repeat("\u00eb", MaxForeignUserIDBytes), false},
		{"a thousand characters of two bytes", strings.Repeat("\u00eb", MaxForeignUserIDBytes/2), true},
	} {
		err := checkExistingUserID([]byte(c.text))
		if (err == nil) != c.ok {
			t.Errorf("%s: %q: error %v, want accepted=%v", c.name, c.text, err, c.ok)
		}
		if err != nil && !isParams(err) {
			t.Errorf("%s: %v is not an ErrParams", c.name, err)
		}
	}
	// the text is read and not kept: a slice that the caller changes afterwards changes nothing
	b := []byte("Quokka")
	if checkExistingUserID(b) != nil || string(b) != "Quokka" {
		t.Error("the check changed or refused its input")
	}
}
