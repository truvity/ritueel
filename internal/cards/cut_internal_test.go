package cards

import (
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jsonset"
)

// The cut of a detail never leaves half of an escape: not a backslash at the end, not a part of a \uXXXX and
// not the first escape of the pair of a character above U+FFFF without its second half. The cut then moves
// back to the start of that escape or pair. The tests state the expected text from the length of the escapes
// (6 bytes for a character below U+10000, 12 for one above), not from the code.

// cutAt is the length of the text before the mark when the cut falls at 237 bytes.
const cutAt = wantMaxDetail - len(wantCutMark)

func TestCutDetailMovesBackToTheStartOfTheEscapeOrPairThatTheCutSplits(t *testing.T) {
	for _, c := range []struct {
		name   string
		char   string
		length int // bytes of the escape of one character
	}{
		{"a character below U+10000", "\u00e9", 6},
		{"a character above U+FFFF", "\U0001f600", 12},
		// The first escape of a pair holds a high surrogate d800 to dbff: its fourth character is 8, 9, a or b.
		{"a pair with a high surrogate starting d9", "\U00050000", 12},
		{"a pair with a high surrogate starting da", "\U00090000", 12},
		{"a pair with a high surrogate starting db", "\U0010ffff", 12},
		{"a pair with a high surrogate starting d8 and a low one dc", "\U00010000", 12},
	} {
		for pad := range 2 * c.length {
			t.Run(fmt.Sprintf("%s pad %d", c.name, pad), func(t *testing.T) {
				in := strings.Repeat("a", pad) + strings.Repeat(c.char, 100)
				whole := jsonset.Escape(in)
				// The first cut is at byte 237 of the whole text. Offset is how far it is into an escape (or a pair).
				offset := (cutAt - pad) % c.length
				want := whole[:cutAt-offset] + wantCutMark
				if got := cutDetail(in); got != want {
					t.Errorf("offset %d: got %q\nwant %q", offset, got[len(got)-24:], want[len(want)-24:])
				}
			})
		}
	}
}

// The five places that the cut can fall at in a pair of escapes (12 bytes): right after the backslash of the
// first, in the first, between the two, after the backslash of the second, in the second.
func TestCutDetailInAPairOfEscapesAtEveryPlaceMovesToTheStartOfThePair(t *testing.T) {
	const pair = `\ud83d\ude00`
	for offset := 0; offset < len(pair); offset++ {
		in := strings.Repeat("a", cutAt-offset) + "\U0001f600" + "bcd"
		got := cutDetail(in)
		want := strings.Repeat("a", cutAt-offset) + wantCutMark
		if offset == 0 {
			// The cut falls before the pair: nothing of it is in the text.
			want = strings.Repeat("a", cutAt) + wantCutMark
		}
		if got != want {
			t.Errorf("a cut %d bytes into the pair: got %q, want a cut at the start of the pair", offset, got[len(got)-16:])
		}
	}
}

func TestCutDetailKeepsAWholeEscapeAndAWholePairThatEndAtTheCut(t *testing.T) {
	// A whole escape of a character below U+10000 that ends at byte 237.
	in := strings.Repeat("a", cutAt-6) + "\u00e9" + "xyz" + strings.Repeat("b", 20)
	want := strings.Repeat("a", cutAt-6) + `\u00e9` + wantCutMark
	if got := cutDetail(in); got != want {
		t.Errorf("a whole escape at the cut: got %q", got[len(got)-16:])
	}
	// A whole pair that ends at byte 237.
	in = strings.Repeat("a", cutAt-12) + "\U0001f600" + "xyz" + strings.Repeat("b", 20)
	want = strings.Repeat("a", cutAt-12) + `\ud83d\ude00` + wantCutMark
	if got := cutDetail(in); got != want {
		t.Errorf("a whole pair at the cut: got %q", got[len(got)-24:])
	}
	// A whole escape that ends one byte before the cut and a letter after it.
	in = strings.Repeat("a", cutAt-7) + "\u00e9" + "xyz" + strings.Repeat("b", 20)
	want = strings.Repeat("a", cutAt-7) + `\u00e9` + "x" + wantCutMark
	if got := cutDetail(in); got != want {
		t.Errorf("a letter after a whole escape: got %q", got[len(got)-16:])
	}
}

// A pair whose second escape ends at the cut is whole, whatever its second half is: dc00 to dfff, so the
// fourth character of the second escape is c, d, e or f.
func TestCutDetailKeepsAWholePairThatEndsAtTheCutForEverySecondHalf(t *testing.T) {
	for name, char := range map[string]string{"dc": "\U00010000", "dd": "\U00010100", "de": "\U0001f600", "df": "\U00010300", "last": "\U0010ffff"} {
		in := strings.Repeat("a", cutAt-12) + char + "xyz" + strings.Repeat("b", 20)
		whole := jsonset.Escape(in)
		if want := whole[:cutAt] + wantCutMark; cutDetail(in) != want {
			t.Errorf("%s: got %q, want %q", name, cutDetail(in)[cutAt-12:], want[cutAt-12:])
		}
	}
}

// A whole escape that is not the first half of a pair is kept at the cut, even when its digits look like
// the start of one: \u08a0 and \u8a00 are characters of their own.
func TestCutDetailKeepsAWholeEscapeWhoseDigitsLookLikeAHighSurrogate(t *testing.T) {
	for _, char := range []string{"\u08a0", "\u08b0", "\u8a00", "\u9a00", "\uab00", "\ub800", "\u0900", "\ue000"} {
		in := strings.Repeat("a", cutAt-6) + char + "xyz" + strings.Repeat("b", 20)
		whole := jsonset.Escape(in)
		if want := whole[:cutAt] + wantCutMark; cutDetail(in) != want {
			t.Errorf("%+q: got %q, want %q", char, cutDetail(in)[cutAt-6:], want[cutAt-6:])
		}
	}
}

// A backslash of the text that is followed by more than five characters is not half of anything: the whole
// escape-like text before the cut is kept, whatever it spells.
func TestCutDetailKeepsATextThatSpellsAnEscapeAndGoesOn(t *testing.T) {
	for _, spelled := range []string{`\ud83dabc`, `\ud83dxy`, `\u00e9abc`, `\ud800\ud800abc`, `\ud83d12345`} {
		in := strings.Repeat("a", cutAt-len(spelled)) + spelled + strings.Repeat("b", 20)
		if want := jsonset.Escape(in)[:cutAt] + wantCutMark; cutDetail(in) != want {
			t.Errorf("%q: got %q", spelled, cutDetail(in)[cutAt-12:])
		}
	}
}

func TestCutDetailNeverEndsInABackslashOrAHalfEscapeWhateverTheTextHolds(t *testing.T) {
	for name, in := range map[string]string{
		"only letters and a backslash at the cut": strings.Repeat("a", cutAt-1) + `\` + strings.Repeat("b", 20),
		"letters, an escape and a backslash":      strings.Repeat("a", cutAt-7) + "\u00e9" + `\` + strings.Repeat("b", 20),
		"a backslash of the text then u and two":  strings.Repeat("a", cutAt-4) + `\u12` + strings.Repeat("b", 20),
		"a backslash of the text then u":          strings.Repeat("a", cutAt-2) + `\u` + strings.Repeat("b", 20),
		"a backslash of the text then u three":    strings.Repeat("a", cutAt-5) + `\u123` + strings.Repeat("b", 20),
		"a backslash of the text and a letter":    strings.Repeat("a", cutAt-2) + `\n` + strings.Repeat("b", 20),
		"two backslashes at the cut":              strings.Repeat("a", cutAt-2) + `\\` + strings.Repeat("b", 20),
		"an escape, a backslash, a backslash":     strings.Repeat("a", cutAt-8) + "\u00e9" + `\\` + strings.Repeat("b", 20),
		"all letters":                             strings.Repeat("a", 500),
	} {
		t.Run(name, func(t *testing.T) {
			got := cutDetail(in)
			whole := jsonset.Escape(in)
			body := strings.TrimSuffix(got, wantCutMark)
			if len(got) > wantMaxDetail || !strings.HasSuffix(got, wantCutMark) || !strings.HasPrefix(whole, body) {
				t.Fatalf("got %q", got)
			}
			if strings.HasSuffix(body, `\`) {
				t.Errorf("the cut ends in a backslash: %q", got[len(got)-12:])
			}
			if halfEscape.MatchString(body) {
				t.Errorf("the cut ends in half of an escape: %q", got[len(got)-12:])
			}
		})
	}
	// A backslash of the text that is not at the end of the cut is kept: the cut is just before it.
	in := strings.Repeat("a", cutAt-2) + `\n` + strings.Repeat("b", 20)
	if want := strings.Repeat("a", cutAt-2) + `\n` + wantCutMark; cutDetail(in) != want {
		t.Errorf("a backslash and a letter of the text were cut: %q", cutDetail(in)[cutAt-8:])
	}
}

// A detail of nothing but a backslash cannot be told from the first half of an escape: the cut drops every
// backslash at its end, and the text keeps no backslash at its end.
func TestCutDetailOfNothingButBackslashesEndsWithoutOne(t *testing.T) {
	got := cutDetail(strings.Repeat(`\`, 300))
	if len(got) > wantMaxDetail || !strings.HasSuffix(got, wantCutMark) || strings.HasSuffix(strings.TrimSuffix(got, wantCutMark), `\`) {
		t.Errorf("got %q", got)
	}
}

// The text is a detail of a reader, whole, when it fits: a backslash or a half escape at the end of a text
// that is not cut is the text as it is.
func TestCutDetailKeepsAShortTextWhateverItEndsIn(t *testing.T) {
	for _, in := range []string{`\`, `\u`, `\u12`, `\ud83d`, "a\\", strings.Repeat("a", 239) + `\`, strings.Repeat("a", 240)} {
		if got := cutDetail(in); got != in {
			t.Errorf("cutDetail(%q) = %q", in, got)
		}
	}
	// The text that is 241 bytes with one backslash at the end is cut, and the backslash goes.
	in := strings.Repeat("a", 240) + `\`
	if got, want := cutDetail(in), strings.Repeat("a", cutAt)+wantCutMark; got != want {
		t.Errorf("a text of 241 bytes: %q", got)
	}
}
