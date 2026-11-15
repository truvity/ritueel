package ceremony

import (
	"errors"
	"strings"
)

// The faults of the engine that a caller maps to an exit code. The package imports nothing of
// internal/cli, so it cannot return the types of that package; the command maps each type here to
// one exit code of docs/reference/cli.md, and any other error is a failure (exit code 1).
//
// The texts are printable ASCII: a name that came from a file is given to a text through
// jsonset.EscapeExact, and the command writes the text through the escape of the program once more.

// UsageError is a command line that cannot be run as it was given: exit code 2.
type UsageError struct{ Msg string }

// Error returns the text.
func (e *UsageError) Error() string { return e.Msg }

// RefusedError is a refusal by a check or by the policy: exit code 3. Reasons are the codes of the
// refusal, at least one; Msg is the line for a person.
type RefusedError struct {
	Reasons []string
	Msg     string
}

// Error returns the text, or the reasons when there is none.
func (e *RefusedError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "refused: " + strings.Join(e.Reasons, ", ")
}

// BackendError is a refusal by the key store backend: exit code 4. Reasons are the codes of the
// refusal, at least one; Msg is the line for a person.
type BackendError struct {
	Reasons []string
	Msg     string
}

// Error returns the text, or the reasons when there is none.
func (e *BackendError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "refused by the key store: " + strings.Join(e.Reasons, ", ")
}

// ErrNotConfirmed is a ceremony that the person did not confirm: exit code 5. It is built with the
// confirmation and is not returned by this version.
var ErrNotConfirmed = errors.New("not confirmed")

// ErrNotBuilt is the kind of a refusal of something that the first apply of this version does not
// make: a root of a kind that is not built, a root that is not a test root, a personal bundle. It is
// a failure (exit code 1), and nothing was written. Callers tell it with errors.Is.
var ErrNotBuilt = errors.New("this version does not build that yet")

// ErrNotFirst is the kind of the refusal of a bundle that is not in the first state: this version
// makes the first apply only. It is a failure (exit code 1), and nothing was written.
var ErrNotFirst = errors.New("this version makes the first apply only")
