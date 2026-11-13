package jsonset

import (
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// Escape writes a text with every character outside printable ASCII as \uXXXX in lower case (a
// character above U+FFFF as the pair of escapes of its surrogates, each byte that is not UTF-8 as
// the escape of U+FFFD), and changes nothing else: no quotes, and a quote or a backslash stays what
// it is. The expected texts are built with qesc, so that no escape is written out in this file.

// referenceEscape is the rule written out again, byte by byte, with utf8.DecodeRuneInString.
func referenceEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1: // a byte that is not UTF-8
			b.WriteString(qesc(0xFFFD))
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		default:
			b.WriteString(qesc(r))
		}
		i += n
	}
	return b.String()
}

func TestEscape(t *testing.T) {
	bad := string([]byte{0xff})
	trunc := string([]byte{0xc3})
	fffd := qesc(0xFFFD)
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"ASCII is unchanged", "abc XYZ 019 _-.:/", "abc XYZ 019 _-.:/"},
		{"every printable ASCII byte", printableASCIIRun(), printableASCIIRun()},
		{"a quote is not escaped", `a"b`, `a"b`},
		{"a backslash is not escaped", `a\b`, `a\b`},
		{"a backslash and an escape-looking text stay what they are", qesc(0xE9), qesc(0xE9)},
		{"the space and the tilde", " ~", " ~"},
		{"a NUL", "a\x00b", "a" + qesc(0) + "b"},
		{"a control character", "a\x01b", "a" + qesc(1) + "b"},
		{"ESC", "\x1b[31m", qesc(0x1B) + "[31m"},
		{"a line feed, a carriage return and a tab", "a\n\r\tb", "a" + qesc(10) + qesc(13) + qesc(9) + "b"},
		{"the last control character", "\x1f", qesc(0x1F)},
		{"DEL", "a\x7fb", "a" + qesc(0x7F) + "b"},
		{"the first character outside ASCII", string(rune(0x80)), qesc(0x80)},
		{"an accented letter", "caf" + string(rune(0xE9)), "caf" + qesc(0xE9)},
		{"a Cyrillic letter that looks like a Latin one", "v" + string(rune(0x0435)) + "rsion", "v" + qesc(0x0435) + "rsion"},
		{"the Kelvin sign", string(rune(0x212A)), qesc(0x212A)},
		{"the line separator", string(rune(0x2028)), qesc(0x2028)},
		{"the byte order mark", string(rune(0xFEFF)), qesc(0xFEFF)},
		{"the last character of the BMP", string(rune(0xFFFF)), qesc(0xFFFF)},
		{"the replacement character itself", string(rune(0xFFFD)), fffd},
		{"the first character above the BMP", string(rune(0x10000)), qesc(0xD800) + qesc(0xDC00)},
		{"an emoji", "a" + string(rune(0x1F600)) + "b", "a" + qesc(0xD83D) + qesc(0xDE00) + "b"},
		{"the last character of Unicode", string(rune(0x10FFFF)), qesc(0xDBFF) + qesc(0xDFFF)},
		{"a bad byte alone", bad, fffd},
		{"a bad byte at the start", bad + "abc", fffd + "abc"},
		{"a bad byte in the middle", "ab" + bad + "cd", "ab" + fffd + "cd"},
		{"a bad byte at the end", "abc" + bad, "abc" + fffd},
		{"two bad bytes, each one escape", bad + bad, fffd + fffd},
		{"a bad byte between two characters outside ASCII", string(rune(0xE9)) + bad + string(rune(0xE9)), qesc(0xE9) + fffd + qesc(0xE9)},
		{"a truncated character at the end", "a" + trunc, "a" + fffd},
		{"a truncated character in the middle", "a" + trunc + "b", "a" + fffd + "b"},
		{"a continuation byte alone", string([]byte{0x80}), fffd},
		{"an overlong NUL", "\xc0\x80", fffd + fffd},
		{"an encoded surrogate is three bad bytes", "\xed\xa0\x80", fffd + fffd + fffd},
		{"a character above Unicode is four bad bytes", "\xf4\x90\x80\x80", fffd + fffd + fffd + fffd},
		{"a long text is not cut", strings.Repeat("n", 1000) + string(rune(0xE9)) + strings.Repeat("n", 1000), strings.Repeat("n", 1000) + qesc(0xE9) + strings.Repeat("n", 1000)},
		{"a long text of characters outside ASCII", strings.Repeat(string(rune(0x1F600)), 50), strings.Repeat(qesc(0xD83D)+qesc(0xDE00), 50)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Escape(tc.in)
			if got != tc.want {
				t.Errorf("Escape(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if ref := referenceEscape(tc.in); got != ref {
				t.Errorf("Escape(%q) = %q, the reference rule gives %q", tc.in, got, ref)
			}
			for i := 0; i < len(got); i++ {
				if got[i] < 0x20 || got[i] >= 0x7f {
					t.Fatalf("byte %d of %q is %#x, not printable ASCII", i, got, got[i])
				}
			}
		})
	}
	t.Run("a text that is printable ASCII is its own escape", func(t *testing.T) {
		for _, s := range []string{"", "a", "a b", `"\`, printableASCIIRun()} {
			if got := Escape(s); got != s {
				t.Errorf("Escape(%q) = %q", s, got)
			}
		}
	})
	t.Run("every code point of the BMP, one by one, is its own reference", func(t *testing.T) {
		for r := rune(0); r <= 0xFFFF; r++ {
			if r >= 0xD800 && r <= 0xDFFF { // not a character of a Go string
				continue
			}
			if got, want := Escape(string(r)), referenceEscape(string(r)); got != want {
				t.Fatalf("U+%04X: %q, want %q", r, got, want)
			}
		}
	})
	t.Run("every byte that is not UTF-8 alone", func(t *testing.T) {
		for b := 0x80; b <= 0xFF; b++ {
			if got := Escape(string([]byte{byte(b)})); got != fffd {
				t.Errorf("%#x: %q", b, got)
			}
		}
	})
}

func printableASCIIRun() string {
	var b strings.Builder
	for c := 0x20; c < 0x7f; c++ {
		b.WriteByte(byte(c))
	}
	return b.String()
}

// TypeName is Escape of the text of the type.
func TestTypeNameIsEscapeOfTheTextOfTheType(t *testing.T) {
	types := []reflect.Type{
		typeOf[int](), typeOf[[]string](), typeOf[map[string]*pair](), typeOf[struct{}](), typeOf[any](), typeOf[shower](),
		typeOf[Écart](), typeOf[[]Ünit](), typeOf[map[Ключ]Ӆist](), typeOf[*Ünion](),
		reflect.StructOf([]reflect.StructField{{Name: string(rune(0xC9)), Type: typeOf[int](), Tag: reflect.StructTag(`json:"` + string(rune(0xE9)) + `"`)}}),
		fakeType{typeOf[int](), "a\x00\x7f" + string(rune(0x1F600)) + "\xff"},
	}
	for _, typ := range types {
		if got, want := TypeName(typ), Escape(typ.String()); got != want {
			t.Errorf("TypeName(%s) = %q, Escape of its text = %q", typ, got, want)
		}
	}
}
