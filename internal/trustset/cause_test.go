package trustset_test

import (
	"crypto"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/trustset"
)

// Errors that a signer or a key may return and that have no text to show.

type erroringPanic struct{}

func (erroringPanic) Error() string { panic("the error panics") }

type erroringPanicNil struct{}

func (erroringPanicNil) Error() string { panic(nil) }

type erroringValue struct{ text string }

func (e erroringValue) Error() string { return e.text }

type erroringNilOK struct{}

func (e *erroringNilOK) Error() string {
	if e == nil {
		return "nil is fine for this one"
	}
	return "not nil"
}

// erroringCounted counts the calls of its Error method.
type erroringCounted struct{ calls *int }

func (e erroringCounted) Error() string {
	*e.calls++
	return fmt.Sprintf("answer %d", *e.calls)
}

// unshowable is the errors that are shown as "the cause could not be shown".
func unshowable() []struct {
	name string
	err  error
} {
	var nilValue *erroringValue
	var nilOK *erroringNilOK
	return []struct {
		name string
		err  error
	}{
		{"Error panics", erroringPanic{}},
		{"Error panics with nil", erroringPanicNil{}},
		{"typed nil pointer, value receiver", nilValue},
		{"typed nil pointer, receiver that copes with nil", nilOK},
	}
}

// checkNoPanicWhenPrinted prints the error with every verb and asks the chain, as a caller does.
func checkNoPanicWhenPrinted(t *testing.T, err error, want string) {
	t.Helper()
	for _, verb := range []string{"%v", "%+v", "%s", "%q", "%x", "%d", "%#v", "%T"} {
		if fmt.Sprintf(verb, err) == "" {
			t.Errorf("verb %s prints nothing", verb)
		}
	}
	if got := fmt.Sprintf("%v", err); got != want {
		t.Errorf("%%v prints %q, want %q", got, want)
	}
	if got := fmt.Sprintf("%s", err); got != want {
		t.Errorf("%%s prints %q, want %q", got, want)
	}
	if errors.Is(err, trustset.ErrParams) {
		t.Errorf("the error is ErrParams as well")
	}
	var target interface{ Timeout() bool }
	if errors.As(err, &target) {
		t.Errorf("errors.As found a type of the cause")
	}
}

// An error of a signer that cannot give its text (a panic in Error, a nil pointer in the interface)
// does not bring down NewRemoval or the caller that prints the error: the error is ErrSign with
// fixed words in place of the text.
func TestNewRemovalSignerErrorThatCannotBeShown(t *testing.T) {
	a := newRoot(t, "A", true)
	for _, c := range unshowable() {
		t.Run(c.name, func(t *testing.T) {
			s := counting(a.signer(t))
			s.sign = func([]byte) ([]byte, error) { return nil, c.err }
			text, err := trustset.NewRemoval(s)
			if text != "" {
				t.Errorf("a text comes with the error")
			}
			wantSign(t, err)
			want := trustset.ErrSign.Error() + ": the signer of A failed: the cause could not be shown"
			if err.Error() != want {
				t.Errorf("text %q, want %q", err, want)
			}
			checkNoPanicWhenPrinted(t, err, want)
			if s.count() != 1 {
				t.Errorf("the key was asked %d times", s.count())
			}
		})
	}
}

// A signer that panics with an error whose Error method panics is one fault, "the signer panicked",
// and the panic value is never asked for its text.
func TestNewRemovalSignerPanicWithAnErrorThatPanics(t *testing.T) {
	a := newRoot(t, "A", true)
	for _, value := range []any{erroringPanic{}, erroringPanicNil{}, errors.New("x"), "text", 7, nil} {
		s := counting(a.signer(t))
		s.sign = func([]byte) ([]byte, error) { panic(value) }
		text, err := trustset.NewRemoval(s)
		if text != "" {
			t.Errorf("a text comes with the error")
		}
		wantSign(t, err)
		want := trustset.ErrSign.Error() + ": the signer of A panicked"
		if err.Error() != want {
			t.Errorf("panic %v: text %q, want %q", value, err, want)
		}
	}
}

// The error of a key that cannot give its text is shown the same way by the signer over a key, by
// itself and under NewRemoval.
func TestKeySignerErrorThatCannotBeShown(t *testing.T) {
	r := newRoot(t, "D", true)
	for _, c := range unshowable() {
		t.Run(c.name, func(t *testing.T) {
			s, _ := fakeSigner(t, r, func([]byte, crypto.SignerOpts) ([]byte, error) { return nil, c.err })
			got, err := s.SignES384([]byte("x"))
			if got != nil {
				t.Errorf("a signature comes with the error")
			}
			wantSign(t, err)
			want := trustset.ErrSign.Error() + ": the key could not sign: the cause could not be shown"
			if err.Error() != want {
				t.Errorf("text %q, want %q", err, want)
			}
			checkNoPanicWhenPrinted(t, err, want)

			// Under NewRemoval the error of the key is the cause of the error of the signer.
			text, err := trustset.NewRemoval(s)
			if text != "" {
				t.Errorf("a text comes with the error")
			}
			wantSign(t, err)
			want = trustset.ErrSign.Error() + ": the signer of D failed: " + trustset.ErrSign.Error() +
				": the key could not sign: the cause could not be shown"
			if err.Error() != want {
				t.Errorf("under NewRemoval: text %q, want %q", err, want)
			}
			checkNoPanicWhenPrinted(t, err, want)
		})
	}
}

// The text of the error of a signer or a key is asked once, and the error made from it does not
// ask again.
func TestSignerErrorIsAskedForItsTextOnce(t *testing.T) {
	a := newRoot(t, "A", true)
	calls := 0
	s := counting(a.signer(t))
	s.sign = func([]byte) ([]byte, error) { return nil, erroringCounted{&calls} }
	_, err := trustset.NewRemoval(s)
	wantSign(t, err)
	first := err.Error()
	for i := 0; i < 4; i++ {
		_ = fmt.Sprintf("%v %+v %#v %q", err, err, err, err)
		_ = errors.Is(err, trustset.ErrSign)
		if err.Error() != first {
			t.Fatalf("the text changed: %q, then %q", first, err)
		}
	}
	if calls != 1 {
		t.Errorf("the error of the signer was asked %d times, want 1", calls)
	}
	if !strings.HasSuffix(first, ": answer 1") {
		t.Errorf("text %q does not show the first answer", first)
	}

	calls = 0
	key, _ := fakeSigner(t, newRoot(t, "D", true), func([]byte, crypto.SignerOpts) ([]byte, error) {
		return nil, erroringCounted{&calls}
	})
	_, err = key.SignES384([]byte("x"))
	wantSign(t, err)
	_ = fmt.Sprintf("%v %+v %#v", err, err, err)
	if calls != 1 {
		t.Errorf("the error of the key was asked %d times, want 1", calls)
	}
}

// An error of tens of megabytes from a signer or a key gives a short text at once, and the same
// text every time it is read.
func TestSignerErrorOfTensOfMegabytes(t *testing.T) {
	big := errors.New(strings.Repeat("\U0001f600", 8<<20)) // 32 MiB
	a := newRoot(t, "A", true)
	s := counting(a.signer(t))
	s.sign = func([]byte) ([]byte, error) { return nil, big }
	_, err := trustset.NewRemoval(s)
	wantSign(t, err)
	for i := 0; i < 3; i++ {
		if len(err.Error()) > 300 {
			t.Fatalf("call %d: the text is %d bytes", i, len(err.Error()))
		}
	}
	if !strings.HasSuffix(err.Error(), "...") {
		t.Errorf("a cut is not marked: %.100q", err)
	}
	key, _ := fakeSigner(t, newRoot(t, "D", true), func([]byte, crypto.SignerOpts) ([]byte, error) { return nil, big })
	_, err = key.SignES384([]byte("x"))
	wantSign(t, err)
	if len(err.Error()) > 300 || !strings.HasSuffix(err.Error(), "...") {
		t.Errorf("text of %d bytes: %.100q", len(err.Error()), err)
	}
}

// What the error of a signer holds that came from outside is shown escaped and cut, whatever the
// bytes are, and the text stays printable ASCII.
func TestSignerErrorTextIsEscapedAndCut(t *testing.T) {
	a := newRoot(t, "A", true)
	for _, text := range []string{
		"\x1b[2J\x1b[31mred", "\xff\xfe\xfd", "\u202eevil\u202c", "line\nbreak\rhere", "a\x00b",
		strings.Repeat("\U0001f600", 400), strings.Repeat("\xe2\x82", 400), "%s%d%v%!",
	} {
		s := counting(a.signer(t))
		s.sign = func([]byte) ([]byte, error) { return nil, errors.New(text) }
		_, err := trustset.NewRemoval(s)
		wantSign(t, err)
		if len(err.Error()) > len(trustset.ErrSign.Error()+": the signer of A failed: ")+200+3 {
			t.Errorf("text %+q: the error is %d bytes", text, len(err.Error()))
		}
	}
}

// wholeEscapes checks that every backslash in text starts an escape of the form \uXXXX, so that
// the text does not end in half of one.
func wholeEscapes(t *testing.T, text string) {
	t.Helper()
	whole := regexp.MustCompile(`\\u[0-9a-f]{4}`)
	if got, want := len(whole.FindAllString(text, -1)), strings.Count(text, `\`); got != want {
		t.Errorf("the text %q has %d backslashes and %d whole escapes: it is cut inside an escape", text, want, got)
	}
}

// The cut of the text of a cause never falls inside an escape. The error of a key that failed is
// the cause of the error of the signer, and its text holds escapes already: the cut of the outer
// text has to keep them whole too. A key that fails with a text of 2-byte characters (6 bytes each
// once escaped) shows the most whole escapes that fit, in the error of the key itself and under
// NewRemoval.
func TestSignerErrorIsNeverCutInsideAnEscape(t *testing.T) {
	r := newRoot(t, "D", true)
	for _, n := range []int{10, 33, 34, 35, 36, 37, 100, 120, 400} {
		text := "a" + strings.Repeat("\u00e9", n)
		s, _ := fakeSigner(t, r, func([]byte, crypto.SignerOpts) ([]byte, error) { return nil, errors.New(text) })
		_, err := s.SignES384([]byte("x"))
		wantSign(t, err)
		wholeEscapes(t, strings.TrimSuffix(err.Error(), "..."))
		_, err = trustset.NewRemoval(s)
		wantSign(t, err)
		wholeEscapes(t, strings.TrimSuffix(err.Error(), "..."))
	}
}

var (
	keyPairToken   = regexp.MustCompile(`^\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}`)
	keyEscapeToken = regexp.MustCompile(`^\\u[0-9a-fA-F]{4}`)
)

// wholeTokens is a model of what the error of a signer shows of the error of a key: the text of
// the error of the key (printable ASCII, every backslash the start of a whole escape) in whole
// escapes and whole pairs of surrogates, at most 200 bytes, and the dots when it was cut.
func wholeTokens(f string) string {
	if len(f) <= 200 {
		return f
	}
	n := 0
	for n < len(f) {
		size := 1
		if m := keyPairToken.FindString(f[n:]); m != "" {
			size = len(m)
		} else if m := keyEscapeToken.FindString(f[n:]); m != "" {
			size = len(m)
		}
		if n+size > 200 {
			break
		}
		n += size
	}
	return f[:n] + "..."
}

// The error of a key that failed is the cause of the error of the signer, and its text holds
// escapes already. What the signer shows of it is the model: whole escapes and whole pairs, at
// most 200 bytes, then the dots, whichever byte of an escape the bound falls on. The padding moves
// the bound over each byte of the escapes (6 bytes for a character of two or three bytes, 12 for a
// character of four bytes).
func TestSignerErrorShowsTheErrorOfTheKeyInWholeEscapes(t *testing.T) {
	r := newRoot(t, "D", true)
	prefix := trustset.ErrSign.Error() + ": the signer of D failed: "
	for _, filler := range []string{"\xc3\xa9", "\xe2\x82\xac", "\U0001f600"} {
		for pad := 0; pad < 14; pad++ {
			text := strings.Repeat("a", pad) + strings.Repeat(filler, 60)
			s, _ := fakeSigner(t, r, func([]byte, crypto.SignerOpts) ([]byte, error) { return nil, errors.New(text) })
			_, keyErr := s.SignES384([]byte("x"))
			wantSign(t, keyErr)
			_, err := trustset.NewRemoval(s)
			wantSign(t, err)
			if !strings.HasPrefix(err.Error(), prefix) {
				t.Fatalf("the error says %q", err)
			}
			got := strings.TrimPrefix(err.Error(), prefix)
			if want := wholeTokens(keyErr.Error()); got != want {
				t.Errorf("filler %q, pad %d: the error of the key is shown as %q, want %q", filler, pad, got, want)
			}
			wholeEscapes(t, strings.TrimSuffix(got, "..."))
			if strings.HasSuffix(strings.TrimSuffix(got, "..."), `\ud83d`) {
				t.Errorf("filler %q, pad %d: the shown text ends in the high half of a pair: %q", filler, pad, got)
			}
		}
	}
}
