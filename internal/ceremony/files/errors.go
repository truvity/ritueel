package files

import (
	"fmt"

	"ritueel.id/ritueel/internal/jsonset"
)

// VersionError is the error of a file whose version is an integer other than [FormatVersion]. The
// reader read the version and nothing else of the file. The text names the version, as the
// page asks ("refuses it and names it").
type VersionError struct {
	// What is the kind of file: "ceremony record", "attempt" or "plan".
	What string
	// Version is the integer the file carries.
	Version int64
}

// Error says which file and which version.
func (e *VersionError) Error() string {
	return fmt.Sprintf("%s: version %d is not known; this release reads version %d", e.What, e.Version, FormatVersion)
}

// FormatError is the error of a file that is one valid JSON object under the rules of
// strictjson and still breaks a rule of the page: a member that the reader requires is missing,
// a value is not one of those the page lists, a digest, a time or a path is not in its form, or
// two members contradict each other.
type FormatError struct {
	// What is the kind of file: "ceremony record", "attempt" or "plan".
	What string
	// Member is the name of the member at fault, with a path inside it when it is nested, such
	// as "artifacts[3].path". It is written by this package from the names of the format and
	// from list indexes, never from the document.
	Member string
	// Reason says what is wrong, in printable ASCII; a text from the document is quoted and cut
	// short.
	Reason string
}

// Error says which file, which member and what is wrong.
func (e *FormatError) Error() string {
	return fmt.Sprintf("%s: member %s: %s", e.What, jsonset.Escape(e.Member), e.Reason)
}

func formatError(what, member, format string, args ...any) *FormatError {
	return &FormatError{What: what, Member: member, Reason: fmt.Sprintf(format, args...)}
}
