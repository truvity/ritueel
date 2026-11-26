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
		{"a left-to-right mark", "Quokka‎Tester", false},
		{"a right-to-left mark", "Quokka‏Tester", false},
		{"an Arabic letter mark", "Quokka؜Tester", false},
		{"a bidirectional embedding", "Quokka‪Tester", false},
		{"a bidirectional override", "Quokka‮Tester", false},
		{"a bidirectional isolate", "Quokka⁦Tester", false},
		{"the end of an isolate", "Quokka⁩Tester", false},
		{"a zero-width space", "Quokka​Tester", false},
		{"a zero-width non-joiner", "Quokka‌Tester", false},
		{"a zero-width joiner", "Quokka‍Tester", false},
		{"a word joiner", "Quokka⁠Tester", false},
		{"a soft hyphen", "Quokka­Tester", false},
		{"a byte order mark", "\xef\xbb\xbfQuokka Tester", false},
		{"a byte order mark in the middle", "Quokka\xef\xbb\xbfTester", false},
		{"a line separator", "Quokka Tester", false},
		{"a paragraph separator", "Quokka Tester", false},
		{"a no-break space", "Quokka Tester", false},
		{"an ideographic space", "Quokka　Tester", false},
		{"an unassigned code point", "Quokka͸Tester", false},
		{"the last code point", "Quokka\U0010ffffTester", false},
		{"a surrogate half as bytes", "Quokka\xed\xa0\x80Tester", false},
		{"the other half as bytes", "Quokka\xed\xbf\xbfTester", false},
		{"a lone byte of a sequence", "Quokka\xc3Tester", false},
		{"an overlong encoding", "Quokka\xc0\xafTester", false},
		{"a private-use character", "QuokkaTester", false},
		{"a private-use character of the last planes", "Quokka\U00100000Tester", false},
		{"a combining accent", "Zoë Tester", false},
		{"a letter with an accent", "Zoë Tester", false},
		{"a letter of another script", "Ωmega", false},
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
		want := !(unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp))
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
		{"Latin letters with accents", "Zoë Müller-Łukasiewicz <zoe@example.org>", true},
		{"a decomposed accent", "Zoë Tester", true},
		{"Cyrillic", "Иван <ivan@example.org>", true},
		{"Greek", "Ωμέγα", true},
		{"Han", "例示 <person@example.org>", true},
		{"Arabic", "محمد", true},
		{"Hebrew", "דוד", true},
		{"Devanagari with vowel signs", "नमस्ते", true},
		{"Thai with vowel marks", "สวัสดี", true},
		{"a no-break space", "Quokka Tester", true},
		{"a tab-free space of another width", "Quokka Tester", true},
		{"an unassigned code point", "Quokka͸Tester", true},
		{"a noncharacter", "Quokka﷐Tester", true},
		{"the replacement character", "Quokka�Tester", true},
		{"a private-use character", "QuokkaTester", true},
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
		{"a bidirectional override", "Quokka‮Tester", false},
		{"a bidirectional isolate", "Quokka⁧Tester", false},
		{"a left-to-right mark", "Quokka‎Tester", false},
		{"a zero-width space", "Quokka​Tester", false},
		{"a zero-width joiner", "Quokka‍Tester", false},
		{"a word joiner", "Quokka⁠Tester", false},
		{"a soft hyphen", "Quokka­Tester", false},
		{"a byte order mark", "\xef\xbb\xbfQuokka", false},
		{"a language tag", "Quokka\U000e0001Tester", false},
		{"a line separator", "Quokka Tester", false},
		{"a paragraph separator", "Quokka Tester", false},
		{"a surrogate half as bytes", "Quokka\xed\xa0\x80Tester", false},
		{"a lone continuation byte", "Quokka\x80Tester", false},
		{"an overlong encoding", "Quokka\xc0\xafTester", false},
		{"a code point past the last", "Quokka\xf4\x90\x80\x80Tester", false},
		{"a text cut in a sequence", "Quokka\xe2\x82", false},
		{"as long as the reader reads", strings.Repeat("a", MaxForeignUserIDBytes), true},
		{"the last character of two bytes ends at the limit", strings.Repeat("a", MaxForeignUserIDBytes-2) + "ë", true},
		{"the last character of two bytes passes the limit by one", strings.Repeat("a", MaxForeignUserIDBytes-1) + "ë", false},
		{"one byte past the limit", strings.Repeat("a", MaxForeignUserIDBytes+1), false},
		{"as many characters as the limit, twice the bytes", strings.Repeat("ë", MaxForeignUserIDBytes), false},
		{"a thousand characters of two bytes", strings.Repeat("ë", MaxForeignUserIDBytes/2), true},
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
