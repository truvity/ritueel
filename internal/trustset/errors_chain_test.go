package trustset

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A drop can uncover another part of an escape, and that one another, for as long as the text
// ends in parts. The drop goes on until none is left, however many there are: a run of backslashes
// of any length, a run of half escapes, a run of high halves, and a mix of them.
func TestDropPartialEscapeGoesOnForAnyNumberOfParts(t *testing.T) {
	parts := []struct{ name, part string }{
		{"backslash", `\`},
		{"backslash and u", `\u`},
		{"one digit", `\u0`},
		{"two digits", `\u00`},
		{"three digits", `\u00e`},
		{"high half", `\ud83d`},
		{"high half, upper case", `\uD83D`},
		{"half escape closed by a backslash", `\u0\`},
		{"high half and a backslash", `\ud83d\`},
	}
	kept := []struct{ name, text string }{
		{"nothing", ""},
		{"plain text", "ab"},
		{"a whole escape", `ab\u00e9`},
		{"a whole pair", `ab\ud83d\ude00`},
		{"a low half", `ab\ude00`},
	}
	for _, p := range parts {
		for _, k := range kept {
			for n := 0; n <= 70; n++ {
				in := k.text + strings.Repeat(p.part, n)
				if got := dropPartialEscape(in); got != k.text {
					t.Fatalf("%d x %s after %s: dropPartialEscape(%q) = %q, want %q", n, p.name, k.name, in, got, k.text)
				}
			}
		}
	}
}

// Parts of different kinds, one behind the other: each drop uncovers the next.
func TestDropPartialEscapeGoesOnThroughMixedParts(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"a backslash, a half escape, a backslash", `ab\u0\\`, "ab"},
		{"a half escape closed by two backslashes", `ab\u00\\`, "ab"},
		{"three half escapes in a row", `ab\u00e\u0\u`, "ab"},
		{"a high half before a half escape before a backslash", `ab\ud83d\u00\`, "ab"},
		{"a high half behind a whole escape and a backslash", `ab\u00e9\\ud83d`, `ab\u00e9`},
		{"two high halves behind a backslash", `ab\\ud83d\ud83d`, "ab"},
		{"a whole pair behind a run of backslashes", `\ud83d\ude00\\\\\\\\`, `\ud83d\ude00`},
		{"a whole pair, a high half, a backslash", `\ud83d\ude00\ud83d\`, `\ud83d\ude00`},
		{"eight backslashes", strings.Repeat(`\`, 8), ""},
		{"eight backslashes and u, the last two are a half escape", strings.Repeat(`\`, 8) + "u", ""},
		{"eight backslashes and a letter", strings.Repeat(`\`, 8) + "x", strings.Repeat(`\`, 8) + "x"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := dropPartialEscape(c.in); got != c.want {
				t.Errorf("dropPartialEscape(%q) = %q, want %q", c.in, got, c.want)
			}
			if want := dropTail(c.in); want != c.want {
				t.Fatalf("the plain model gives %q for %q, the row says %q", want, c.in, c.want)
			}
		})
	}
}

// A cause whose text has a run of backslashes at the cut shows none of them: the shown text stops
// at the last character that is not a backslash.
func TestCauseTextRunOfBackslashesAtTheCut(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 9, 12, 20, 50, 100, 199, 200} {
		text := strings.Repeat("a", 200-n) + strings.Repeat(`\`, n) + "tail"
		want := strings.Repeat("a", 200-n) + "..."
		if got := causeText(errors.New(text)); got != want {
			t.Errorf("%d backslashes at the cut: shown %q, want %q", n, got, want)
		}
	}
}

// The same with a run of backslashes and u (the text of half escapes, written by hand) at the cut.
func TestCauseTextRunOfHalfEscapesAtTheCut(t *testing.T) {
	for _, part := range []string{`\u`, `\u0`, `\u00`, `\u00e`, `\u0\`} {
		for k := 1; k <= 200/len(part); k++ {
			pad := 200 - k*len(part)
			text := strings.Repeat("a", pad) + strings.Repeat(part, k) + "tail"
			want := strings.Repeat("a", pad) + "..."
			if got := causeText(errors.New(text)); got != want {
				t.Fatalf("%d x %q at the cut: shown %q, want %q", k, part, got, want)
			}
		}
	}
}

// A run of backslashes behind a whole escape keeps the escape and drops the run.
func TestCauseTextRunOfBackslashesBehindAWholeEscape(t *testing.T) {
	for n := 1; n <= 40; n++ {
		text := strings.Repeat("a", 194-n) + `\u00e9` + strings.Repeat(`\`, n) + "tail"
		want := strings.Repeat("a", 194-n) + `\u00e9...`
		if got := causeText(errors.New(text)); got != want {
			t.Errorf("%d backslashes behind an escape: shown %q, want %q", n, got, want)
		}
	}
	// The same through the error of another signer: its text holds escapes already.
	for n := 1; n <= 12; n++ {
		inner := failWith(ErrSign, "inner", errors.New(strings.Repeat("a", 10)+"\u00e9"+strings.Repeat(`\`, n)+strings.Repeat("b", 300)))
		outer := failWith(ErrSign, "outer", inner)
		got := strings.TrimPrefix(outer.Error(), ErrSign.Error()+": outer: ")
		if body := strings.TrimSuffix(got, "..."); endsInPartOfAnEscape(body) || !strings.HasSuffix(got, "...") {
			t.Errorf("%d backslashes: shown %q", n, fmt.Sprintf("%.60s", got))
		}
	}
}
