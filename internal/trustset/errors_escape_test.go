package trustset

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
)

// A text that ends in a part of an escape loses that part, and nothing else.
func TestDropPartialEscape(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"empty", "", ""},
		{"plain text", "abc", "abc"},
		{"a whole escape", `ab\u00e9`, `ab\u00e9`},
		{"a whole escape of a control character", `\u001b`, `\u001b`},
		{"a lone backslash", `ab\`, "ab"},
		{"a backslash only", `\`, ""},
		{"a backslash and u", `ab\u`, "ab"},
		{"one hexadecimal digit", `ab\u0`, "ab"},
		{"two hexadecimal digits", `ab\u00`, "ab"},
		{"three hexadecimal digits", `ab\u00e`, "ab"},
		{"three digits, upper case", `ab\u00E`, "ab"},
		{"a whole escape and a half", `\u00e9\u00e`, `\u00e9`},
		{"a whole escape and a backslash", `\u00e9\`, `\u00e9`},
		{"a whole escape and a backslash and u", `\u00e9\u`, `\u00e9`},
		{"three digits that are not all hexadecimal", `ab\u00g`, `ab\u00g`},
		{"a backslash and a letter that is not u", `ab\x`, `ab\x`},
		{"a backslash in the middle", `a\b c`, `a\b c`},
		{"a backslash followed by plain text", `a\bcd`, `a\bcd`},
		{"a backslash and u and four digits", `a\u00e9`, `a\u00e9`},
		{"a backslash and u, four digits and one more", `a\u00e9f`, `a\u00e9f`},
		{"the high half of a pair", `ab\ud83d`, "ab"},
		{"the high half of a pair, upper case", `ab\uD83D`, "ab"},
		{"the first of the high halves at the end", `ab\ud800`, "ab"},
		{"the last of the high halves at the end", `ab\udbff`, "ab"},
		{"the first and the last of the high halves", `\ud800|\udbff`, `\ud800|`},
		{"the high half of a pair and a backslash", `ab\ud83d\`, "ab"},
		{"the high half of a pair and a backslash and u", `ab\ud83d\u`, "ab"},
		{"the high half of a pair and a half escape", `ab\ud83d\ude0`, "ab"},
		{"a whole pair", `ab\ud83d\ude00`, `ab\ud83d\ude00`},
		{"a whole pair, upper case", `ab\uD83D\uDE00`, `ab\uD83D\uDE00`},
		{"the low half of a pair, alone", `ab\ude00`, `ab\ude00`},
		{"an escape just under the high halves", `ab\ud7ff`, `ab\ud7ff`},
		{"an escape just over the high halves", `ab\ue000`, `ab\ue000`},
		{"the first low half", `ab\udc00`, `ab\udc00`},
		{"a whole pair and the high half of another", `\ud83d\ude00\ud83d`, `\ud83d\ude00`},
		{"the high half in the middle", `\ud83dx`, `\ud83dx`},
		{"five bytes of a half escape", `\u00e`, ""},
		{"six bytes of a whole escape", `\u00e9`, `\u00e9`},
		{"a character of two bytes", "ab\u00e9", "ab\u00e9"},
		{"dots are plain text", "ab...", "ab..."},
		// A backslash that a drop uncovers is dropped as well, and so is a half escape that the
		// backslash was closing: the text never ends in a part of an escape.
		{"a backslash before the high half of a pair", `ab\\ud83d`, "ab"},
		{"two backslashes", `ab\\`, "ab"},
		{"a half escape closed by a backslash", `ab\u0\`, "ab"},
		{"a backslash and u closed by a backslash", `ab\u\`, "ab"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if want := dropTail(c.in); want != c.want {
				t.Fatalf("the test has a row that the plain model refuses: %q gives %q, the row says %q", c.in, want, c.want)
			}
			if got := dropPartialEscape(c.in); got != c.want {
				t.Errorf("dropPartialEscape(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// The hexadecimal reader takes digits only, in both cases, and says no for any other byte.
func TestHexValue(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		isOK bool
	}{
		{"", 0, true},
		{"0", 0, true},
		{"9", 9, true},
		{"a", 10, true},
		{"f", 15, true},
		{"A", 10, true},
		{"F", 15, true},
		{"00e9", 0xe9, true},
		{"D83D", 0xd83d, true},
		{"d83d", 0xd83d, true},
		{"ffff", 0xffff, true},
		{"g", 0, false},
		{"G", 0, false},
		{"/", 0, false}, // just under '0'
		{":", 0, false}, // just over '9'
		{"`", 0, false}, // just under 'a'
		{"@", 0, false}, // just under 'A'
		{"0g", 0, false},
		{"g0", 0, false},
		{" 0", 0, false},
		{"-1", 0, false},
		{"+1", 0, false},
		{"0x1", 0, false},
		{"\xff", 0, false},
		{"\u00e9", 0, false},
	} {
		n, ok := hexValue(c.in)
		if ok != c.isOK || (ok && n != c.n) {
			t.Errorf("hexValue(%q) = %d, %v; want %d, %v", c.in, n, ok, c.n, c.isOK)
		}
		if got := isHex(c.in); got != c.isOK {
			t.Errorf("isHex(%q) = %v, want %v", c.in, got, c.isOK)
		}
	}
}

var (
	pairToken   = regexp.MustCompile(`^\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}`)
	escapeToken = regexp.MustCompile(`^\\u[0-9a-fA-F]{4}`)
)

// cutByTokens is a model of the cut that reads the text from the left: a text of printable ASCII in
// which every backslash starts a whole escape. A pair of surrogates is one token, an escape is one
// token and any other byte is one token. The text is shown as it is when it fits the bound, and
// otherwise as the most whole tokens that fit, followed by the dots.
func cutByTokens(f string) string {
	if len(f) <= maxCauseText {
		return f
	}
	var b strings.Builder
	for i := 0; i < len(f); {
		n := 1
		if m := pairToken.FindString(f[i:]); m != "" {
			n = len(m)
		} else if m := escapeToken.FindString(f[i:]); m != "" {
			n = len(m)
		}
		if b.Len()+n > maxCauseText {
			break
		}
		b.WriteString(f[i : i+n])
		i += n
	}
	return b.String() + "..."
}

// endsInPartOfAnEscape reports whether a text ends in a backslash, a backslash and u, a backslash
// and u with one to three hexadecimal digits, or the high half of a pair of surrogates.
func endsInPartOfAnEscape(s string) bool {
	return tailPartialEscape.MatchString(s) || tailHighSurrogate.MatchString(s)
}

// The cause is an error of this package whose text holds escapes already (a cause of a cause).
// The cut of the outer text falls on every residue of the escapes (6 bytes for a character of two
// or three bytes, 12 for a pair) and never inside one: the text is the model, no part of an escape
// is left at the end, at most 200 bytes are shown, and what is shown is the start of the whole text.
func TestCauseTextOfAnErrorOfThisPackageIsNeverCutInsideAnEscape(t *testing.T) {
	fillers := []string{"\u00e9", "\u20ac", "\U0001f600", "\x1b", "\xff", "\u00e9\U0001f600", "a\u20ac", "\u202e\U0001f600b"}
	for _, filler := range fillers {
		for pad := 0; pad <= 13; pad++ {
			for n := 0; n <= 70; n++ {
				checkNestedCut(t, strings.Repeat("a", pad)+strings.Repeat(filler, n))
			}
		}
	}
	rng := rand.New(rand.NewPCG(3, 5))
	alphabet := []string{"a", "Z", " ", "%", "\x00", "\x1b", "\x7f", "\xff", "\xc3", "\u00e9", "\u20ac", "\u202e", "\U0001f600", "\U0010ffff"}
	for n := 0; n < 4000; n++ {
		var b strings.Builder
		for want := rng.IntN(260); b.Len() < want; {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		checkNestedCut(t, b.String())
	}
}

// checkNestedCut makes an error of this package from text, makes another with it as the cause, and
// checks the text that the second one shows. The text holds no backslash, so every backslash of the
// error of this package starts an escape.
func checkNestedCut(t *testing.T, text string) {
	t.Helper()
	inner := failWith(ErrSign, "in", errors.New(text))
	outer := failWith(ErrSign, "what", inner)
	got := shown(t, outer)
	whole := inner.Error()
	if want := cutByTokens(whole); got != want {
		t.Fatalf("text %+q: shown %q, want %q", text, got, want)
	}
	body := strings.TrimSuffix(got, "...")
	if endsInPartOfAnEscape(body) {
		t.Fatalf("text %+q: shown %q ends in a part of an escape", text, got)
	}
	if len(got) > maxCauseText+len("...") || !strings.HasPrefix(whole, body) {
		t.Fatalf("text %+q: shown %q is not a start of %q within the bound", text, got, whole)
	}
	if len(whole) <= maxCauseText && got != whole {
		t.Fatalf("text %+q: a text that was not cut is changed: %q", text, got)
	}
	kindOf(t, outer, ErrSign)
}

// Exact rows of the nested cut, with every residue of the bound against the escapes. The words of
// the inner error take 30 bytes; the padding and then 6-byte escapes take the rest of the 200 bytes.
func TestCauseTextNestedCutRows(t *testing.T) {
	const words = "trustset: signing failed: in: " // 30 bytes
	e9 := func(n int) string { return strings.Repeat(`\u00e9`, n) }
	for _, c := range []struct {
		name string
		pad  int
		n    int // whole escapes that are shown
	}{
		{"a backslash left at the bound", 7, 27},
		{"a backslash and u left at the bound", 6, 27},
		{"a backslash, u and one digit left", 5, 27},
		{"a backslash, u and two digits left", 4, 27},
		{"a backslash, u and three digits left", 3, 27},
		{"a whole escape at the bound", 2, 28},
		{"one byte after a whole escape", 1, 28},
		{"the bound falls on the end of an escape", 8, 27},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := strings.Repeat("a", c.pad) + strings.Repeat("\u00e9", 120)
			outer := failWith(ErrSign, "what", failWith(ErrSign, "in", errors.New(text)))
			want := ErrSign.Error() + ": what: " + words + strings.Repeat("a", c.pad) + e9(c.n) + "..."
			if got := outer.Error(); got != want {
				t.Errorf("the error says %q, want %q", got, want)
			}
		})
	}
}

// A pair of surrogates is a whole character: when the cut falls inside the second escape, or
// between the two, the first is dropped too. The pair starts at byte 30+pad of the text of the inner
// error (after its words), so the bound of 200 bytes falls after k bytes of the pair.
func TestCauseTextNestedCutInAPair(t *testing.T) {
	const words = "trustset: signing failed: in: " // 30 bytes
	const pair = `\ud83d\ude00`
	for k := 0; k <= 13; k++ {
		t.Run(fmt.Sprintf("%d bytes of the pair fit", k), func(t *testing.T) {
			pad := maxCauseText - len(words) - k
			text := strings.Repeat("a", pad) + "\U0001f600" + strings.Repeat("b", 30)
			outer := failWith(ErrSign, "what", failWith(ErrSign, "in", errors.New(text)))
			want := words + strings.Repeat("a", pad)
			if k >= len(pair) {
				want += pair + strings.Repeat("b", k-len(pair))
			}
			if got := shown(t, outer); got != want+"..." {
				t.Errorf("shown %q, want %q", got, want+"...")
			}
			checkNestedCut(t, text)
		})
	}
}

// A literal backslash in front of a character of four bytes: the inner error shows the backslash
// as it is and then the two escapes. When the outer cut falls after the first escape of the pair, the
// pair is dropped, the backslash is then a lone backslash, which is a part of an escape too, and it
// goes with the pair. The doc says that a shown text never ends in a part of an escape.
func TestCauseTextNestedBackslashBeforeAPair(t *testing.T) {
	const words = "trustset: signing failed: in: " // 30 bytes
	for k := 0; k <= 13; k++ {
		t.Run(fmt.Sprintf("%d bytes of the pair fit", k), func(t *testing.T) {
			pad := maxCauseText - len(words) - 1 - k // one byte for the backslash, then k bytes of the pair
			text := strings.Repeat("a", pad) + `\` + "\U0001f600" + strings.Repeat("b", 30)
			outer := failWith(ErrSign, "what", failWith(ErrSign, "in", errors.New(text)))
			got := shown(t, outer)
			if body := strings.TrimSuffix(got, "..."); endsInPartOfAnEscape(body) {
				t.Errorf("shown %q ends in a part of an escape", got)
			}
		})
	}
}

// The drop reaches the end: a pair that is cut is dropped, and then a backslash that stood in
// front of it is a lone backslash and is dropped too; a half escape that a lone backslash was
// closing is dropped with it, and so is the second of two backslashes.
func TestCauseTextDropsEveryPartOfAnEscapeAtTheEnd(t *testing.T) {
	for _, c := range []struct {
		name  string
		cause string // the text of the cause
		want  string // the text shown for it
	}{
		{"a backslash before the high half of a pair", strings.Repeat("a", 193) + `\\ud83d` + "tail", strings.Repeat("a", 193) + "..."},
		{"half an escape that a backslash closes", strings.Repeat("a", 196) + `\u0\` + "tail", strings.Repeat("a", 196) + "..."},
		{"a backslash and u that a backslash closes", strings.Repeat("a", 197) + `\u\` + "tail", strings.Repeat("a", 197) + "..."},
		{"two backslashes at the cut", strings.Repeat("a", 198) + `\\` + "tail", strings.Repeat("a", 198) + "..."},
		{"three backslashes at the cut", strings.Repeat("a", 197) + `\\\` + "tail", strings.Repeat("a", 197) + "..."},
	} {
		t.Run(c.name, func(t *testing.T) {
			if want := dropTail(c.cause[:maxCauseText]) + "..."; want != c.want {
				t.Fatalf("the row is wrong: the plain model says %q, the row says %q", want, c.want)
			}
			if got := causeText(errors.New(c.cause)); got != c.want {
				t.Errorf("shown %q, want %q", got, c.want)
			}
		})
	}
}

// A literal backslash in the text of a cause is a backslash like any other: jsonset.Escape keeps
// it as it is, so a plain cause that is cut right after one shows no backslash before the dots,
// and one that is not cut keeps it.
func TestCauseTextLiteralBackslashAtTheCut(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	for _, c := range []struct{ name, text, want string }{
		{"cut right after a backslash", a(199) + `\` + "x", a(199) + "..."},
		{"cut after a backslash, many follow", a(199) + `\\\\`, a(199) + "..."},
		{"not cut, ends in a backslash", a(199) + `\`, a(199) + `\`},
		{"not cut, short, ends in a backslash", `a\`, `a\`},
		{"not cut, ends in a backslash and u", `a\u`, `a\u`},
		{"not cut, ends in a backslash and u and a digit", `a\u0`, `a\u0`},
		{"not cut, ends in the high half of a pair", `a\ud83d`, `a\ud83d`},
		{"not cut, 200 bytes ending in a half escape", a(195) + `\u00e`, a(195) + `\u00e`},
		{"cut, the backslash is in the middle", `a\b` + strings.Repeat("c", 250), `a\b` + strings.Repeat("c", 197) + "..."},
		{"cut after a backslash and u", a(198) + `\u` + "x", a(198) + "..."},
		{"cut after a backslash, u and a digit", a(197) + `\u0` + "x", a(197) + "..."},
		{"cut after three digits", a(195) + `\u00e` + "x", a(195) + "..."},
		{"cut after four digits", a(194) + `\u00e9` + "x", a(194) + `\u00e9...`},
		{"cut after a high half", a(194) + `\ud83d` + "x", a(194) + "..."},
		{"cut after a whole pair", a(188) + `\ud83d\ude00` + "x", a(188) + `\ud83d\ude00...`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := causeText(errors.New(c.text)); got != c.want {
				t.Errorf("shown %q, want %q", got, c.want)
			}
		})
	}
}

// The cut works the same when the text is three errors of this package deep.
func TestCauseTextNestedThreeDeep(t *testing.T) {
	for pad := 0; pad < 14; pad++ {
		text := strings.Repeat("a", pad) + strings.Repeat("\U0001f600", 40)
		inner := failWith(ErrSign, "one", errors.New(text))
		middle := failWith(ErrSign, "two", inner)
		outer := failWith(ErrSign, "three", middle)
		prefix := ErrSign.Error() + ": three: "
		got := strings.TrimPrefix(outer.Error(), prefix)
		if want := cutByTokens(middle.Error()); got != want {
			t.Errorf("pad %d: shown %q, want %q", pad, got, want)
		}
		if endsInPartOfAnEscape(strings.TrimSuffix(got, "...")) {
			t.Errorf("pad %d: shown %q ends in a part of an escape", pad, got)
		}
		kindOf(t, outer, ErrSign)
		if got, want := fmt.Sprint(errors.Unwrap(outer)), ErrSign.Error(); got != want {
			t.Errorf("pad %d: the chain holds %q, want the kind %q", pad, got, want)
		}
	}
}
