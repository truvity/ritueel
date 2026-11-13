// Package jsonset holds what the writer of ritueel's JSON (package canonjson) and its reader
// (package strictjson) must agree on, so that they cannot drift apart: the closed set of Go types
// that both accept, the way a struct names its members, and the path that their errors show.
//
// The name of a member of a struct is the tag name or else the Go name of the field, and holds
// only ASCII letters, digits and underscores. The set is small on purpose: a name is part of a
// signed format, and a person must be able to tell two names apart, which no one can for a letter
// that looks like another one (a Cyrillic "a", the Kelvin sign for "K") or for a name with a space
// or a quote in it. Every member name of the decided formats (the pages of docs/reference) is
// lower-case ASCII, digits and underscores, so nothing they need is left out. The rule is about
// the fields of a struct; the keys of a map and the members of an interface are whatever a
// document has. A field with no tag has its Go name for a member name, which starts with an
// upper-case letter because the field is exported; that is allowed, and a format struct whose
// field lacks its tag writes or expects "Version" where the page says "version", which the
// reader's exact match refuses at the first real file. A tag is therefore not required. A name
// is never empty when the rule is asked: a tag without a name takes the Go name of the field.
// Every text of this package that shows a name, a field name or a type shows a character outside
// printable ASCII as \uXXXX, so that a look-alike cannot pass for the letter it resembles.
//
// A Checker answers, for a Go type, whether it is in the set. The answer is the same for writing
// and for reading but for one thing, an interface with methods, which can be written (the value
// it holds is judged) and cannot be read (there is no value to judge). An interface that declares
// MarshalJSON, MarshalText, UnmarshalJSON or UnmarshalText (a field of type json.Marshaler) is
// refused in both directions, as a type with one of those methods is. Both packages call the
// Checker before they look at a value or at a byte, so a type that is outside the set is refused
// whatever the data, and the error names the Go type and the path to it.
package jsonset

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrMalformed is wrapped by every error that the writer and the reader return for a value, a
// type or an input that breaks a rule. Package strictjson exports it under the same name.
var ErrMalformed = errors.New("malformed JSON")

// maxPathSteps is how many steps of the path to a value an error shows; a longer path shows its end.
const maxPathSteps = 8

// Step is one move from a value to a part of it: a member name or a list index.
type Step struct {
	Name    string
	Index   int
	IsIndex bool
}

// Member is the step to the member of an object that has this name.
func Member(name string) Step { return Step{Name: name} }

// Element is the step to the element of a list that has this index.
func Element(index int) Step { return Step{Index: index, IsIndex: true} }

// Path is the way from the top of a document to one of its values. Its text is $ for the top and
// then one step after another: .name for a member and [3] for an element.
type Path []Step

// String shows the path as $.name[3]. A path of more than eight steps shows its last eight after
// "$...".
func (p Path) String() string {
	var b strings.Builder
	b.WriteByte('$')
	steps := p
	if len(steps) > maxPathSteps {
		b.WriteString("...")
		steps = steps[len(steps)-maxPathSteps:]
	}
	for _, s := range steps {
		if s.IsIndex {
			fmt.Fprintf(&b, "[%d]", s.Index)
			continue
		}
		b.WriteByte('.')
		b.WriteString(Shown(s.Name))
	}
	return b.String()
}

// most is how many bytes of a name an error shows.
const most = 40

// Shown writes a member name for an error: as it is when it is plain (ASCII letters, digits,
// underscores and hyphens, and short), else quoted by Quote.
func Shown(name string) string {
	plain := name != "" && len(name) <= most
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '_' && c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			plain = false
		}
	}
	if plain {
		return name
	}
	return Quote(name)
}

// Quote writes a text for an error: in double quotes, cut short with "..." when it is long, with
// the quote and the backslash escaped by a backslash and every character that is not printable
// ASCII written as \uXXXX (a character above U+FFFF as the pair of escapes of its surrogates), so
// that a look-alike of an ASCII letter, a control character or bytes that are not UTF-8 cannot
// pass for what they are not. Bytes that are not UTF-8 are shown as \ufffd.
func Quote(s string) string {
	suffix := ""
	if len(s) > most {
		cut := most
		for cut > 0 && !utf8.RuneStart(s[cut]) { // not inside a character
			cut--
		}
		s, suffix = s[:cut], "..."
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r >= 0x10000:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, "\\u%04x\\u%04x", hi, lo)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	b.WriteString(suffix)
	b.WriteByte('"')
	return b.String()
}

// CompareUTF16 orders two strings by their UTF-16 code units, as RFC 8785 section 3.2.3 sorts
// member names. It differs from the byte order of UTF-8 for characters above U+FFFF against
// U+E000 to U+FFFF.
func CompareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// Error is the one form of the errors of both packages: the text is "malformed JSON: " and the
// path and then what is wrong. It wraps ErrMalformed.
type Error struct {
	// Path is the way to the value at fault, from the top of the document.
	Path Path
	// What says what is wrong.
	What string
}

// Error returns the text: malformed JSON: <path>: <what>.
func (e *Error) Error() string {
	return ErrMalformed.Error() + ": " + e.Path.String() + ": " + e.What
}

// Unwrap returns ErrMalformed.
func (e *Error) Unwrap() error { return ErrMalformed }

// Errorf returns an *Error for the value at the path. The error keeps a copy of the path.
func Errorf(path Path, format string, args ...any) error {
	return &Error{Path: slices.Clone(path), What: fmt.Sprintf(format, args...)}
}

// TypeName writes the name of a Go type for an error, as reflect.Type.String does, with every
// character outside printable ASCII (a look-alike in the name of a type or of a field of a
// struct type) written as \uXXXX.
func TypeName(t reflect.Type) string { return Escape(t.String()) }

// Escape writes s with every character outside printable ASCII as \uXXXX (a character above
// U+FFFF as the pair of escapes of its surrogates, bytes that are not UTF-8 as \ufffd) and
// nothing else changed: no quotes, and a backslash stays one. It is for a text that comes from a
// caller or a document and is shown inside a sentence.
func Escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		case r >= 0x10000:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, "\\u%04x\\u%04x", hi, lo)
		default:
			fmt.Fprintf(&b, "\\u%04x", r)
		}
	}
	return b.String()
}
