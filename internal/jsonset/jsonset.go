// Package jsonset holds what the writer of ritueel's JSON (package canonjson) and its reader
// (package strictjson) must agree on, so that they cannot drift apart: the closed set of Go types
// that both accept, the way a struct names its members, and the path that their errors show.
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
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
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

// Shown writes a member name for an error: as it is when it is plain, else quoted and cut short.
func Shown(name string) string {
	const most = 40
	plain := name != "" && len(name) <= most
	for _, c := range name {
		if c != '_' && c != '-' && !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			plain = false
		}
	}
	if plain {
		return name
	}
	if len(name) > most {
		name = name[:most] + "..."
	}
	return strconv.QuoteToASCII(name)
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
