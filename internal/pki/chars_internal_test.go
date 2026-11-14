package pki

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The rule for the text of a subject in version 1 of the contract is one function, subjectTextFault: the characters
// U+0020 to U+007E, no space at the start or the end, no two spaces in a row. These tests state the rule in words that
// are not those of the function (a table of bytes and a table of edges) and compare them with it, over every code point of
// Unicode. They replace the tests of the earlier rule by kind of character (refusedRune and its Unicode tables), which is
// gone: the new rule has no kind of character, only a range.

// Every code point of Unicode, put in the middle of a text ("a" before and "b" after, so that no rule about spaces at the
// ends fires), is accepted exactly when it is in U+0020 to U+007E. A single space inside is accepted: the rule about
// spaces is for the ends and for two in a row, and that is tested below.
func TestSubjectTextFaultOverEveryCodePoint(t *testing.T) {
	var refused, accepted int
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // a surrogate is not a character of UTF-8
		}
		text := []byte("a" + string(r) + "b")
		got := subjectTextFault(text) == ""
		want := r >= 0x20 && r <= 0x7E
		if got != want {
			t.Errorf("U+%04X: accepted = %v, want %v", r, got, want)
			if t.Failed() && (refused+accepted)%1000 == 0 {
				t.FailNow()
			}
		}
		if got {
			accepted++
		} else {
			refused++
		}
	}
	if accepted != 95 {
		t.Errorf("%d code points accepted, want the 95 of U+0020 to U+007E", accepted)
	}
	if total := refused + accepted; total != 0x110000-0x800 {
		t.Errorf("%d code points scanned, want %d", total, 0x110000-0x800)
	}
}

// The same by byte, for a text that is not UTF-8 at all (the function reads the content octets): every byte value alone
// in the middle is accepted exactly when it is U+0020 to U+007E.
func TestSubjectTextFaultOverEveryByte(t *testing.T) {
	for b := 0; b <= 0xFF; b++ {
		got := subjectTextFault([]byte{'a', byte(b), 'b'}) == ""
		if want := b >= 0x20 && b <= 0x7E; got != want {
			t.Errorf("byte 0x%02X: accepted = %v, want %v", b, got, want)
		}
	}
}

// The edges of the rule about spaces and the empty text: one space inside is the text of a name; a space at either end, a
// text of spaces only and two spaces in a row anywhere are not; the empty text holds the rule (the length of a value is
// another check, in readName).
func TestSubjectTextFaultSpaces(t *testing.T) {
	for _, c := range []struct {
		text string
		want bool
	}{
		{"", true}, {"a", true}, {"a b", true}, {"a b c", true}, {"a-b", true}, {"~", true}, {"!", true},
		{" ", false}, {"  ", false}, {" a", false}, {"a ", false}, {" a ", false}, {"a  b", false}, {"a   b", false},
		{"a b  c", false}, {"a  b c", false}, {"a b c ", false}, {" a b c", false},
		{"a\tb", false}, {"a\nb", false}, {"a\x00b", false}, {"a\x7fb", false}, {"a b", false}, {"aéb", false},
		{"a\xffb", false}, {"a\xc3b", false},
	} {
		if got := subjectTextFault([]byte(c.text)) == ""; got != c.want {
			t.Errorf("%q: accepted = %v, want %v", c.text, got, c.want)
		}
	}
	if subjectTextFault([]byte("aéb")) == "" || subjectTextFault([]byte("a  b")) == "" || subjectTextFault([]byte(" a")) == "" {
		t.Error("a fault has no words")
	}
	// The three faults say different things, so a person is told which rule held a text back.
	words := map[string]bool{
		subjectTextFault([]byte("é")): true, subjectTextFault([]byte(" a")): true, subjectTextFault([]byte("a  b")): true,
	}
	if len(words) != 3 {
		t.Errorf("the three kinds of fault have %d different texts, want 3: %v", len(words), words)
	}
	// A very long text of the allowed characters is accepted: the rule has no length.
	if f := subjectTextFault([]byte(strings.Repeat("ab ", 1000) + "c")); f != "" {
		t.Errorf("a long text of the allowed characters: %s", f)
	}
}
