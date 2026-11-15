package trustset

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/jsonset"
)

func TestFailWrapsOneKindAndSaysFixedWords(t *testing.T) {
	err := fail(ErrParams, "the sequence %d is bad", 7)
	kindOf(t, err, ErrParams)
	if !strings.HasSuffix(err.Error(), ": the sequence 7 is bad") || !strings.HasPrefix(err.Error(), ErrParams.Error()) {
		t.Errorf("text %q", err)
	}
	kindOf(t, fail(ErrSign, "x"), ErrSign)
}

// A cause that came from outside is shown with every character outside printable ASCII escaped.
// It is shown and it is not part of the chain: errors.Is and errors.As see the kind only.
func TestFailWithShowsTheCauseEscapedAndKeepsOnlyTheKind(t *testing.T) {
	cause := errors.New("bad \x1b[31m \xff \u00e9 \u202e \n")
	err := failWith(ErrSign, "the signer of A failed", cause)
	kindOf(t, err, ErrSign)
	if errors.Is(err, cause) {
		t.Errorf("the cause is in the chain")
	}
	if !errors.Is(errors.Unwrap(err), ErrSign) || errors.Unwrap(errors.Unwrap(err)) != nil {
		t.Errorf("Unwrap gives %v, want the kind only", errors.Unwrap(err))
	}
	for i := 0; i < len(err.Error()); i++ {
		if c := err.Error()[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("the text %+q has the byte %#x", err.Error(), c)
		}
	}
	if !strings.HasPrefix(err.Error(), ErrSign.Error()+": the signer of A failed: bad ") {
		t.Errorf("the text %q does not say the kind, what failed and the printable part of the cause", err)
	}
	if strings.Contains(err.Error(), "\x1b") || strings.Contains(err.Error(), "\n") {
		t.Errorf("the text %q holds a raw control character", err)
	}
	// errors.As does not reach the type of the cause.
	typed := &typedCause{}
	var found *typedCause
	if errors.As(failWith(ErrSign, "what", typed), &found) {
		t.Errorf("errors.As finds the type of the cause")
	}
}

// A cause that wraps the other kind of the package, or a chain of its own, changes nothing: the
// error has the kind it was made with and no other.
func TestFailWithIgnoresTheKindsAndTheChainOfTheCause(t *testing.T) {
	other := errors.New("a sentinel of the caller")
	for _, c := range []struct {
		name  string
		kind  error
		cause error
	}{
		{"a signer error that wraps the other kind", ErrSign, fmt.Errorf("%w: lies", ErrParams)},
		{"a reader error that wraps the sign kind", ErrParams, fmt.Errorf("%w: lies", ErrSign)},
		{"both kinds joined", ErrSign, errors.Join(ErrParams, ErrSign, other)},
		{"the kind itself", ErrParams, ErrParams},
		{"a joined chain", ErrSign, errors.Join(other, errors.New("second"))},
		{"a deep chain", ErrParams, fmt.Errorf("a: %w", fmt.Errorf("b: %w", fmt.Errorf("c: %w", ErrSign)))},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := failWith(c.kind, "something failed", c.cause)
			kindOf(t, err, c.kind)
			if errors.Is(err, other) {
				t.Errorf("a sentinel of the cause is in the chain")
			}
			var multi interface{ Unwrap() []error }
			if errors.As(err, &multi) {
				t.Errorf("the error unwraps to a list")
			}
		})
	}
}

// The text of the cause is cut at maxCauseText bytes of the escaped text, and "..." follows a cut.
func TestFailWithCutsTheCauseAtTheBound(t *testing.T) {
	if maxCauseText != 200 {
		t.Fatalf("the bound is %d bytes, the documented value is 200", maxCauseText)
	}
	prefix := ErrSign.Error() + ": what: "
	for _, c := range []struct {
		name string
		text string
		want string
	}{
		{"empty", "", ""},
		{"one byte", "x", "x"},
		{"199 bytes", strings.Repeat("a", 199), strings.Repeat("a", 199)},
		{"200 bytes", strings.Repeat("a", 200), strings.Repeat("a", 200)},
		{"201 bytes", strings.Repeat("a", 201), strings.Repeat("a", 200) + "..."},
		{"100000 bytes", strings.Repeat("a", 100000), strings.Repeat("a", 200) + "..."},
		// The escape of one character is longer than the character: the cut is on the escaped
		// text and never inside an escape, so 100 control characters (6 bytes each) stop after 33
		// of them (198 bytes), before the escape that would pass 200 bytes.
		{"escaped characters", strings.Repeat("\x1b", 100), strings.Repeat(`\u001b`, 33) + "..."},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := failWith(ErrSign, "what", errors.New(c.text))
			got := err.Error()
			if !strings.HasPrefix(got, prefix) {
				t.Fatalf("text %q", got)
			}
			if rest := got[len(prefix):]; rest != c.want {
				t.Errorf("the cause is shown as %q, want %q", rest, c.want)
			}
			if !asciiOnly(got) {
				t.Errorf("the text is not printable ASCII: %+q", got)
			}
		})
	}
}

// Whatever bytes the cause holds, the text of the error stays printable ASCII and at most the
// kind, the words, the bound and the three dots long.
func TestFailWithStaysShortAndPrintableForAnyCause(t *testing.T) {
	for _, text := range []string{
		strings.Repeat("\xff", 4096), strings.Repeat("\u202e", 4096), strings.Repeat("\x00", 4096),
		strings.Repeat("\U0001f600", 4096), "\xed\xa0\x80" + strings.Repeat("a", 4096), strings.Repeat("%s%d%w", 1000),
	} {
		err := failWith(ErrParams, "a reader refused", errors.New(text))
		if !asciiOnly(err.Error()) {
			t.Errorf("not printable: %.60q", err.Error())
		}
		if max := len(ErrParams.Error()) + len(": a reader refused: ") + maxCauseText + len("..."); len(err.Error()) > max {
			t.Errorf("the text is %d bytes, more than %d", len(err.Error()), max)
		}
	}
}

// failWith and fail format nothing from the cause: a percent sign in the cause is only a character.
func TestFailWithTakesNoFormatFromTheCause(t *testing.T) {
	err := failWith(ErrSign, "what", errors.New("%s %d %!x(MISSING) %w"))
	if !strings.HasSuffix(err.Error(), ": %s %d %!x(MISSING) %w") {
		t.Errorf("text %q", err)
	}
}

// asciiOnly reports whether s holds printable ASCII only: 0x20 to 0x7e.
func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// typedCause is an error type of the caller.
type typedCause struct{}

func (*typedCause) Error() string { return "typed" }

// shown is the text that failWith shows for a cause, without the kind and the words.
func shown(t testing.TB, err error) string {
	t.Helper()
	prefix := ErrSign.Error() + ": what: "
	if !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("text %q does not start with %q", err, prefix)
	}
	return err.Error()[len(prefix):]
}

// The cut is on the escaped text, in whole characters of the cause and whole escapes, and "..."
// follows every cut: one that is made on the text of the cause and one that is made on the escapes.
func TestFailWithCutsInWholeCharactersAndWholeEscapes(t *testing.T) {
	emoji := `\ud83d\ude00` // one 4-byte character, written as the escapes of its two surrogates (12 bytes)
	for _, c := range []struct {
		name string
		text string
		want string
	}{
		// The escapes fill the bound exactly: nothing is cut, no dots.
		{"escapes that end on the bound", "aa" + strings.Repeat("\x1b", 33), "aa" + strings.Repeat(`\u001b`, 33)},
		// One byte more than the bound, in the escapes of a text that is shorter than the bound.
		{"escapes that pass the bound by one byte", strings.Repeat("a", 195) + "\x1b", strings.Repeat("a", 195) + "..."},
		{"escapes that end on the bound after plain text", strings.Repeat("a", 194) + "\x1b", strings.Repeat("a", 194) + `\u001b`},
		{"escapes that pass the bound by five bytes", strings.Repeat("a", 199) + "\x1b", strings.Repeat("a", 199) + "..."},
		// 4-byte characters: 12 bytes each once escaped, 16 of them are 192 bytes, a 17th would pass 200.
		{"50 characters of 4 bytes (200 bytes)", strings.Repeat("\U0001f600", 50), strings.Repeat(emoji, 16) + "..."},
		{"51 characters of 4 bytes (204 bytes)", strings.Repeat("\U0001f600", 51), strings.Repeat(emoji, 16) + "..."},
		{"1000 characters of 4 bytes", strings.Repeat("\U0001f600", 1000), strings.Repeat(emoji, 16) + "..."},
		{"one character of 4 bytes", "\U0001f600", emoji},
		// A character that is cut short by the 200th byte is dropped, not shown as a replacement.
		{"2-byte character on bytes 199 and 200", strings.Repeat("a", 199) + "\u00e9", strings.Repeat("a", 199) + "..."},
		{"3-byte character on bytes 198 to 200", strings.Repeat("a", 198) + "\u20ac", strings.Repeat("a", 198) + "..."},
		{"4-byte character on bytes 197 to 200", strings.Repeat("a", 197) + "\U0001f600", strings.Repeat("a", 197) + "..."},
		{"2-byte character that fits", strings.Repeat("a", 193) + "\u00e9", strings.Repeat("a", 193) + `\u00e9`},
		{"2-byte character that passes the bound by one", strings.Repeat("a", 195) + "\u00e9", strings.Repeat("a", 195) + "..."},
		// After an escape that does not fit, nothing more is shown, not even a character that would fit.
		{"a small character after one that did not fit", strings.Repeat("a", 199) + "\x1b" + "b", strings.Repeat("a", 199) + "..."},
		{"plain characters after an escape that did not fit", strings.Repeat("a", 195) + "\x1b" + "bcd", strings.Repeat("a", 195) + "..."},
		{"a small character after a 2-byte one that did not fit", strings.Repeat("a", 198) + "\u00e9" + "b", strings.Repeat("a", 198) + "..."},
		// Bytes that are not UTF-8 are one escape each.
		{"bytes that are not UTF-8", "\xff\xfe", `\ufffd\ufffd`},
		{"100 bytes that are not UTF-8", strings.Repeat("\xff", 100), strings.Repeat(`\ufffd`, 33) + "..."},
		{"a character cut short in the cause itself", "ab\xe2\x82", `ab\ufffd\ufffd`},
		// A backslash and a space stand as they are.
		{"a backslash and a space", `a b\c`, `a b\c`},
		// Exactly the bound of printable text has no dots, one byte more has.
		{"200 bytes of printable text", strings.Repeat("ab", 100), strings.Repeat("ab", 100)},
		{"201 bytes of printable text", strings.Repeat("ab", 100) + "c", strings.Repeat("ab", 100) + "..."},
		{"dots in the cause are not a cut", "...", "..."},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := shown(t, failWith(ErrSign, "what", errors.New(c.text)))
			if got != c.want {
				t.Errorf("the cause is shown as %q, want %q", got, c.want)
			}
			if strings.Contains(got, `\ufffd`) && !strings.Contains(c.text, "\xff") && !strings.Contains(c.text, "\xe2") {
				t.Errorf("a character that was cut short is shown as a replacement: %q", got)
			}
		})
	}
}

var (
	// tailPartialEscape matches a backslash, a backslash and u, or a backslash and u with one to
	// three hexadecimal digits, at the end of a text.
	tailPartialEscape = regexp.MustCompile(`\\(?:u[0-9a-fA-F]{0,3})?$`)
	// tailHighSurrogate matches a whole escape of a high surrogate at the end of a text.
	tailHighSurrogate = regexp.MustCompile(`\\u[dD][89abAB][0-9a-fA-F]{2}$`)
)

// dropTail removes parts of an escape from the end of s, as the doc of causeText says: a backslash,
// a backslash and u with fewer than four hexadecimal digits, and the first escape of a pair whose
// second is not whole. It goes on until the text ends in none of them, so that a text never ends in
// a part of an escape.
func dropTail(s string) string {
	for {
		t := tailHighSurrogate.ReplaceAllString(tailPartialEscape.ReplaceAllString(s, ""), "")
		if t == s {
			return s
		}
		s = t
	}
}

// reference is the text that failWith must show for a cause text, worked out the plain way: the
// escape of each character in turn, as many whole escapes as fit in the bound, any part of an
// escape dropped from the end after a cut, and dots after a cut, which is a text longer than the
// bound or an escape that did not fit.
func reference(text string) string {
	var b strings.Builder
	cut := len(text) > maxCauseText
	for i, r := range text {
		if i >= maxCauseText {
			break
		}
		piece := jsonset.Escape(string(r))
		if _, size := utf8.DecodeRuneInString(text[i:]); i+size > maxCauseText {
			break // a character that does not end inside the first maxCauseText bytes is dropped
		}
		if b.Len()+len(piece) > maxCauseText {
			cut = true
			break
		}
		b.WriteString(piece)
	}
	if cut {
		return dropTail(b.String()) + "..."
	}
	return b.String()
}

// Over many texts made of every kind of character, the text shown is the reference, is printable
// ASCII, and is never more than the kind, the words, the bound and the dots.
func TestFailWithMatchesTheReferenceForManyTexts(t *testing.T) {
	alphabet := []string{"a", "Z", "0", " ", "\\", "%", "\x00", "\x1b", "\x7f", "\xff", "\xc3", "\xe2\x82", "\u00e9", "\u20ac",
		"\u202e", "\U0001f600", "\ufffd", "\ud7ff", "\U0010ffff"}
	rng := rand.New(rand.NewPCG(7, 11))
	prefixLen := len(ErrSign.Error() + ": what: ")
	for n := 0; n < 3000; n++ {
		var b strings.Builder
		for want := rng.IntN(300); b.Len() < want; {
			b.WriteString(alphabet[rng.IntN(len(alphabet))])
		}
		text := b.String()
		err := failWith(ErrSign, "what", errors.New(text))
		got := shown(t, err)
		if want := reference(text); got != want {
			t.Fatalf("text %+q: shown %q, want %q", text, got, want)
		}
		if !asciiOnly(err.Error()) {
			t.Fatalf("text %+q: the error is not printable ASCII: %+q", text, err)
		}
		if len(err.Error()) > prefixLen+maxCauseText+len("...") {
			t.Fatalf("text %+q: the error is %d bytes", text, len(err.Error()))
		}
	}
}

// panicCause is an error whose Error method panics.
type panicCause struct{}

func (panicCause) Error() string { panic("the cause panics") }

// panicNilCause panics with nil, which the runtime turns into a panic value of its own.
type panicNilCause struct{}

func (panicNilCause) Error() string { panic(nil) }

// panicErrorCause panics with an error whose own Error method panics.
type panicErrorCause struct{}

func (panicErrorCause) Error() string { panic(panicCause{}) }

// pointerPanicCause is a pointer that is not nil, whose Error method panics.
type pointerPanicCause struct{ n int }

func (p *pointerPanicCause) Error() string { panic(p.n) }

// valueRecvCause has a value receiver: a nil pointer to it panics when Error is called.
type valueRecvCause struct{ msg string }

func (v valueRecvCause) Error() string { return v.msg }

// nilOKCause has a pointer receiver that copes with a nil pointer and says words of its own.
type nilOKCause struct{}

func (c *nilOKCause) Error() string {
	if c == nil {
		return "a nil pointer that says something"
	}
	return "not nil"
}

// plainValueCause is a struct that is not a pointer and has a working Error method.
type plainValueCause struct{ a, b int }

func (c plainValueCause) Error() string { return fmt.Sprintf("plain %d %d", c.a, c.b) }

type stringCause string

func (c stringCause) Error() string { return string(c) }

type funcCause func() string

func (c funcCause) Error() string { return c() }

type mapCause map[string]string

func (c mapCause) Error() string { return "map of " + fmt.Sprint(len(c)) }

type intCause int

func (c intCause) Error() string { return fmt.Sprintf("int %d", int(c)) }

// countingCause counts the calls of its Error method and answers differently each time.
type countingCause struct{ calls *int }

func (c countingCause) Error() string {
	*c.calls++
	return fmt.Sprintf("answer %d", *c.calls)
}

// A cause that has no text to give is replaced with fixed words, and the error still has its kind
// and its words. This holds for a nil cause, a typed nil pointer (whatever its method does) and a
// cause whose Error method panics, with any panic value.
func TestFailWithCauseThatCannotBeShown(t *testing.T) {
	var nilValueRecv *valueRecvCause
	var nilOK *nilOKCause
	var nilPanic *pointerPanicCause
	for _, c := range []struct {
		name  string
		cause error
	}{
		{"nil", nil},
		{"Error panics", panicCause{}},
		{"Error panics with nil", panicNilCause{}},
		{"Error panics with an error that panics", panicErrorCause{}},
		{"Error of a pointer that is not nil panics", &pointerPanicCause{}},
		{"typed nil pointer, value receiver", nilValueRecv},
		{"typed nil pointer, receiver that copes with nil", nilOK},
		{"typed nil pointer, Error that panics", nilPanic},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := failWith(ErrSign, "the signer of A failed", c.cause)
			want := ErrSign.Error() + ": the signer of A failed: the cause could not be shown"
			if err == nil || err.Error() != want {
				t.Fatalf("text %v, want %q", err, want)
			}
			kindOf(t, err, ErrSign)
			// Nothing a caller does with the error calls a method of the cause again.
			for _, verb := range []string{"%v", "%+v", "%s", "%q", "%x", "%X", "%d", "%#v", "%T", "%p", "%10.3v", "%-40s"} {
				if got := fmt.Sprintf(verb, err); got == "" {
					t.Errorf("verb %s prints nothing", verb)
				}
			}
			_ = fmt.Sprint(err, err)
			_ = fmt.Sprintln(err)
			if got := fmt.Sprintf("%v", err); got != want {
				t.Errorf("%%v prints %q, want %q", got, want)
			}
			if got := fmt.Sprintf("%s", err); got != want {
				t.Errorf("%%s prints %q, want %q", got, want)
			}
			var typed *typedCause
			if errors.As(err, &typed) || errors.Is(err, ErrParams) || errors.Is(err, c.cause) && c.cause != nil {
				t.Errorf("the chain holds more than the kind")
			}
			if !errors.Is(errors.Unwrap(err), ErrSign) || errors.Unwrap(errors.Unwrap(err)) != nil {
				t.Errorf("Unwrap gives %v, want the kind", errors.Unwrap(err))
			}
		})
	}
}

// A cause that is not a pointer is asked for its text, whatever its type: a struct, a string, an
// int, a func and a map are not mistaken for a nil pointer.
func TestFailWithCauseOfEveryKindOfType(t *testing.T) {
	var nilMap mapCause
	for _, c := range []struct {
		name  string
		cause error
		want  string
	}{
		{"struct", plainValueCause{1, 2}, "plain 1 2"},
		{"zero struct", plainValueCause{}, "plain 0 0"},
		{"pointer to struct", &plainValueCause{3, 4}, "plain 3 4"},
		{"string type", stringCause("a string"), "a string"},
		{"empty string type", stringCause(""), ""},
		{"int type", intCause(0), "int 0"},
		{"func type", funcCause(func() string { return "from a func" }), "from a func"},
		{"map type", mapCause{"a": "b"}, "map of 1"},
		{"nil map type", nilMap, "map of 0"},
		{"struct with a value receiver, through a pointer that is not nil", &valueRecvCause{"v"}, "v"},
		{"pointer that is not nil, receiver that copes with nil", &nilOKCause{}, "not nil"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := shown(t, failWith(ErrSign, "what", c.cause)); got != c.want {
				t.Errorf("shown as %q, want %q", got, c.want)
			}
		})
	}
}

// The text of the cause is taken once, when the error is made. Nothing the caller does with the
// error asks the cause again, so a cause that answers differently each time shows one answer.
func TestFailWithAsksTheCauseExactlyOnce(t *testing.T) {
	calls := 0
	err := failWith(ErrSign, "what", countingCause{&calls})
	if calls != 1 {
		t.Fatalf("the cause was asked %d times to make the error, want 1", calls)
	}
	first := err.Error()
	for i := 0; i < 5; i++ {
		if got := err.Error(); got != first {
			t.Fatalf("the text changed: %q then %q", first, got)
		}
		_ = fmt.Sprintf("%v %+v %#v %q %x", err, err, err, err, err)
		_ = errors.Is(err, ErrSign)
		_ = errors.Is(err, ErrParams)
		var typed *typedCause
		_ = errors.As(err, &typed)
		_ = errors.Unwrap(err)
	}
	if calls != 1 {
		t.Errorf("the cause was asked %d times in all, want 1", calls)
	}
	if got := shown(t, err); got != "answer 1" {
		t.Errorf("shown as %q, want the first answer", got)
	}
}

// bigCause gives a text of tens of megabytes.
type bigCause struct{ text string }

func (c bigCause) Error() string { return c.text }

// The work to make the error and to show it does not grow with the text of the cause: a cause of
// 32 MiB gives a short text at once, the first time and every time after, with the same number of
// allocations as a cause of 1 KiB.
func TestFailWithCostDoesNotGrowWithTheCause(t *testing.T) {
	big := bigCause{strings.Repeat("\U0001f600", 8<<20)} // 32 MiB of 4-byte characters
	small := bigCause{strings.Repeat("\U0001f600", 256)} // 1 KiB
	if len(big.text) != 32<<20 {
		t.Fatalf("the big cause is %d bytes", len(big.text))
	}
	err := failWith(ErrSign, "what", big)
	max := len(ErrSign.Error()+": what: ") + maxCauseText + len("...")
	for i := 0; i < 3; i++ {
		if got := len(err.Error()); got > max {
			t.Fatalf("call %d: the text is %d bytes, more than %d", i, got, max)
		}
	}
	if got, want := shown(t, err), strings.Repeat(`\ud83d\ude00`, 16)+"..."; got != want {
		t.Errorf("shown as %q, want %q", got, want)
	}
	// Allocations: the same for 32 MiB as for 1 KiB, and few. The race detector allocates on its own,
	// so the counts are not asserted under it.
	if !raceEnabled {
		var sink error
		allocsBig := testing.AllocsPerRun(20, func() { sink = failWith(ErrSign, "what", big) })
		allocsSmall := testing.AllocsPerRun(20, func() { sink = failWith(ErrSign, "what", small) })
		if allocsBig != allocsSmall {
			t.Errorf("a cause of 32 MiB costs %v allocations, one of 1 KiB costs %v", allocsBig, allocsSmall)
		}
		if allocsBig > 100 {
			t.Errorf("the error costs %v allocations", allocsBig)
		}
		allocsError := testing.AllocsPerRun(20, func() { _ = sink.Error() })
		if allocsError > 3 {
			t.Errorf("Error() costs %v allocations", allocsError)
		}
	}
	// A plain 32 MiB text of one byte characters is the same.
	plain := bigCause{strings.Repeat("a", 32<<20)}
	if got, want := shown(t, failWith(ErrSign, "what", plain)), strings.Repeat("a", 200)+"..."; got != want {
		t.Errorf("shown as %.60q (%d bytes), want 200 bytes and dots", got, len(got))
	}
}

// causeText is the whole of the rules: a nil cause and a typed nil pointer are not asked at all.
func TestCauseTextDoesNotAskANilPointer(t *testing.T) {
	var nilOK *nilOKCause
	if got := causeText(nilOK); got != causeUnshown {
		t.Errorf("a typed nil pointer is shown as %q, want %q", got, causeUnshown)
	}
	if got := causeText(nil); got != causeUnshown {
		t.Errorf("nil is shown as %q, want %q", got, causeUnshown)
	}
	if causeUnshown != "the cause could not be shown" {
		t.Errorf("the words are %q", causeUnshown)
	}
	if got := causeText(&nilOKCause{}); got != "not nil" {
		t.Errorf("a pointer that is not nil is shown as %q", got)
	}
}
