package trustset

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/jsonset"
)

var (
	// ErrParams is wrapped by an error for a parameter that is wrong, or for a value from
	// outside that breaks the form of the pages: a number, a label, a pin, a time, a certificate,
	// a document over its limit, OpenPGP certificates that the reader of the keyring file refuses
	// or that do not fit the roots, a draft, a set or a writer that is nil or empty. A signer that is
	// nil or has no usable certificate is ErrSigners, not ErrParams.
	ErrParams = errors.New("trustset: invalid parameter")
	// ErrSign is wrapped by an error for a signer that failed, returned a signature of the wrong
	// size or one that does not verify, or panicked, and for an after function that failed or
	// panicked. A set that the reader of the page refuses, after it was signed, is ErrSelf.
	ErrSign = errors.New("trustset: signing failed")
	// ErrSigners is wrapped by an error of Draft.Sign for signers that are not the signers the
	// list needs: one missing, one too many, two of the one-of group, a signer for a revoked key
	// whose authorisation stands for its signature, a certificate with another pin than the label's,
	// a nil signer, a label twice. No key has been asked when it is returned.
	ErrSigners = errors.New("trustset: the signers are not the signers the list needs")
	// ErrReturns is wrapped by an error of NewDraft for a list that adds a root key that left
	// (record 0006, rule 54). Its text starts with CodeRootReturns.
	ErrReturns = errors.New("trustset: a root key that left comes back")
	// ErrSelf is wrapped by an error of NewDraft or Draft.Sign when the reader of the page refuses
	// what the builder itself wrote. It is a fault of the builder, not of the caller.
	ErrSelf = errors.New("trustset: the builder's own output was refused by the reader")
)

// CodeRootReturns is the reason code of record 0006, rule 54, for a list that adds a root key that
// left. The text of an error that wraps ErrReturns holds it.
const CodeRootReturns = "root-returns"

// fail returns an error that wraps kind and no other kind of this package. The text is fixed
// words and numbers; a text that comes from outside is passed through [jsonset.Escape] or
// [jsonset.EscapeExact] by the caller before it is given here.
func fail(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}

// maxCauseText is the most bytes of the text of a cause that an error of this package shows, and
// also the most bytes of it that are read.
const maxCauseText = 200

// causeUnshown is shown in place of the text of a cause that has none to give: a nil cause, a typed
// nil pointer, or a cause whose Error method panics.
const causeUnshown = "the cause could not be shown"

// causeError is an error of this package that shows the error that caused it, such as the error
// of a signer or of a reader, and wraps exactly one kind of this package. The cause itself is not
// kept: failWith takes its text once, under a recover, and the error holds only that string. No
// method of the cause is called after the error is made, so a cause that panics, or that is a typed
// nil pointer, cannot bring down the caller's Error, print, errors.Is or errors.As. The cause is
// not part of the chain: errors.Is and errors.As see the kind and nothing the cause wraps, so a
// signer that returns another kind of this package, or any other error value, cannot change the
// kind. The text shows the cause with every character outside printable ASCII escaped, because a
// cause may carry bytes that came from outside, and cuts it at maxCauseText bytes.
type causeError struct {
	kind error
	what string
	text string
}

func (e *causeError) Error() string {
	return e.kind.Error() + ": " + e.what + ": " + e.text
}

// Unwrap gives the kind only.
func (e *causeError) Unwrap() error { return e.kind }

// causeText takes the text of a cause once. At most maxCauseText bytes of it are read (to a
// character boundary), escaped with [jsonset.Escape] one character at a time, and the shown text
// stops before the escape that would pass maxCauseText bytes. A cause that is itself an error of
// this package already holds escapes, and the cut can fall inside one of them: after a cut, any part
// of an escape at the end of the shown text is dropped, again and again until none is left (see
// [dropPartialEscape]), so a shown text never ends in a backslash, in a backslash and u, in a
// backslash and u with fewer than four hexadecimal digits, or in the first escape of a pair without
// its second. At most maxCauseText bytes are shown, and "..." follows a cut.
// A text that was not cut is not changed. The work does not depend on the length of the text of the
// cause. A nil cause, a typed nil pointer and a cause whose Error method panics give causeUnshown.
func causeText(cause error) (text string) {
	if cause == nil {
		return causeUnshown
	}
	if v := reflect.ValueOf(cause); v.Kind() == reflect.Pointer && v.IsNil() {
		return causeUnshown
	}
	defer func() {
		if recover() != nil {
			text = causeUnshown
		}
	}()
	full := cause.Error()
	head := full
	cut := false
	if len(head) > maxCauseText {
		head = head[:wholeCharacters(head[:maxCauseText])]
		cut = true
	}
	var b strings.Builder
	for i := 0; i < len(head); {
		_, size := utf8.DecodeRuneInString(head[i:])
		piece := jsonset.Escape(head[i : i+size])
		if b.Len()+len(piece) > maxCauseText {
			cut = true
			break
		}
		b.WriteString(piece)
		i += size
	}
	if cut {
		return dropPartialEscape(b.String()) + "..."
	}
	return b.String()
}

// dropPartialEscape removes from the end of s every part of an escape in the forms that
// [jsonset.Escape] writes: a backslash, a backslash and u, a backslash and u with fewer than four
// hexadecimal digits, and the first escape of a pair of surrogates whose second escape is not
// whole. One step can leave a new end of the same kind (a backslash that stood before the dropped
// part, or a half escape before a backslash), so the step is repeated until the text no longer
// changes. Each step returns the text as it is or a shorter text, so the repeat ends. After the
// call s never ends in one of these forms. A text that ends in a whole escape or in plain
// characters is returned as it is.
func dropPartialEscape(s string) string {
	for {
		t := dropPartialEscapeOnce(s)
		if t == s {
			return s
		}
		s = t
	}
}

// dropPartialEscapeOnce drops a part of an escape from the end of s once, in the forms that
// dropPartialEscape names. It returns s as it is or a shorter text, never a longer one.
func dropPartialEscapeOnce(s string) string {
	const escapeLen = len(`\uXXXX`)
	lo := max(len(s)-(escapeLen-1), 0)
	if j := strings.LastIndexByte(s[lo:], '\\'); j >= 0 {
		j += lo
		if rest := s[j+1:]; rest == "" || (rest[0] == 'u' && len(rest) < escapeLen-1 && isHex(rest[1:])) {
			s = s[:j]
		}
	}
	if len(s) >= escapeLen && s[len(s)-escapeLen:len(s)-4] == `\u` {
		if n, ok := hexValue(s[len(s)-4:]); ok && n >= 0xd800 && n < 0xdc00 {
			s = s[:len(s)-escapeLen]
		}
	}
	return s
}

// isHex reports whether s holds hexadecimal digits only (it may be empty).
func isHex(s string) bool {
	_, ok := hexValue(s)
	return ok
}

// hexValue reads s as hexadecimal digits; ok is false for any other byte.
func hexValue(s string) (n int, ok bool) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			n = n<<4 | int(c-'0')
		case c >= 'a' && c <= 'f':
			n = n<<4 | int(c-'a'+10)
		case c >= 'A' && c <= 'F':
			n = n<<4 | int(c-'A'+10)
		default:
			return 0, false
		}
	}
	return n, true
}

// wholeCharacters returns the length of s without a last character that is cut short.
func wholeCharacters(s string) int {
	for i := len(s) - 1; i >= 0 && i >= len(s)-utf8.UTFMax; i-- {
		if utf8.RuneStart(s[i]) {
			if utf8.FullRuneInString(s[i:]) {
				return len(s)
			}
			return i
		}
	}
	return len(s)
}

// failWith returns an error of the given kind that shows the error that caused it. It takes the
// text of the cause now and keeps no reference to the cause.
func failWith(kind error, what string, cause error) error {
	return &causeError{kind: kind, what: what, text: causeText(cause)}
}
