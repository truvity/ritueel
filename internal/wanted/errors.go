package wanted

import (
	"strconv"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/jsonset"
)

// Error is every fault of a wanted file: the path of the file, the line (0 when there is none) and a text
// of fixed words and numbers. Any text that came from the file is escaped and cut before it is in Msg.
type Error struct {
	// Path is the path of the file in the bundle, with "/" as the separator: "ritueel.yaml" or
	// "want/delegations/example.yaml". It can hold a name that came from a caller, so [Error.Error]
	// escapes it.
	Path string
	// Line is the line of the file, counted from 1, or 0 when the fault has no line.
	Line int
	// Msg says what is wrong, in printable ASCII.
	Msg string

	cause error
}

// Error returns the path, the line and the text, in printable ASCII.
func (e *Error) Error() string {
	if e == nil {
		return "wanted: no error"
	}
	s := jsonset.Escape(e.Path)
	if e.Line > 0 {
		s += ":" + strconv.Itoa(e.Line)
	}
	return s + ": " + jsonset.Escape(e.Msg)
}

// Unwrap returns the error of the file system when the file could not be read (so that a caller can ask
// errors.Is(err, fs.ErrNotExist)), and nil for a fault of the text of a file.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// maxShown is the most characters of a text from a file that a message holds.
const maxShown = 40

// shown returns a text that came from outside, cut at [maxShown] characters and escaped, so that it can
// stand in a message.
func shown(s string) string { return shownN(s, maxShown) }

// shownN returns s cut at limit characters and escaped.
func shownN(s string, limit int) string {
	cut := false
	if utf8.RuneCountInString(s) > limit {
		n := 0
		for i := range s {
			if n == limit {
				s = s[:i]
				break
			}
			n++
		}
		cut = true
	}
	out := jsonset.Escape(s)
	if cut {
		out += "..."
	}
	return out
}

// errorf makes an error at a line.
func errorf(path string, line int, msg string) *Error {
	return &Error{Path: path, Line: line, Msg: msg}
}
