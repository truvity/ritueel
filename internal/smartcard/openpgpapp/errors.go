package openpgpapp

import (
	"errors"
	"fmt"

	"ritueel.id/ritueel/internal/smartcard/apdu"
)

var (
	// ErrNotAllowed marks a command that is not on the allowlist of the layer: the layer would never
	// send it, in any mode, and sent nothing. The text names no byte of the command.
	ErrNotAllowed = errors.New("openpgpapp: the command is not on the allowlist")
	// ErrReadOnly marks a command that is on the allowlist but not allowed in a read-only session.
	// The text names the operation. Nothing was sent.
	ErrReadOnly = errors.New("openpgpapp: the command is not allowed in a read-only session")
	// ErrSessionDead marks every call after an exchange failed: the transport returned an error, or
	// the answer could not be read or was too long, so the state of the card is unknown. Nothing is
	// sent after it. The caller opens a new session and reads the card again.
	ErrSessionDead = errors.New("openpgpapp: the session is dead: an earlier exchange failed")
	// ErrSessionClosed marks a call on a session that was closed.
	ErrSessionClosed = errors.New("openpgpapp: the session is closed")
	// ErrNotSelected marks a command that is sent before the application was selected, or after a
	// failed selection. Nothing was sent: it would go to whatever the card has selected.
	ErrNotSelected = errors.New("openpgpapp: the application is not selected")
	// ErrNoTransport marks a session that was asked for without a transport.
	ErrNoTransport = errors.New("openpgpapp: no transport")
	// ErrBadOptions marks options that are out of range: a negative budget, or one above [MaxBudget].
	ErrBadOptions = errors.New("openpgpapp: options out of range")
	// ErrResponseTooLong marks a response that is longer than [MaxResponse], or that needs more
	// than the allowed number of GET RESPONSE commands. It is the cause inside a [*LostError].
	ErrResponseTooLong = errors.New("openpgpapp: the response is longer than the limit")
	// ErrMalformedResponse marks a response of fewer than two bytes: no status word. It is the
	// cause inside a [*LostError].
	ErrMalformedResponse = errors.New("openpgpapp: the response has no status word")
)

// StatusError is the answer of the card when it is not success: a final status word. Op is the name of
// the operation that the allowlist gives the command, never a command byte; SW is the status word.
// The layer returns it for every word but 9000 (and 61xx, which it follows): there is no retry and no
// second reading of a word.
type StatusError struct {
	Op string
	SW uint16
}

// Error says which operation the card refused and with which word.
func (e *StatusError) Error() string {
	return fmt.Sprintf("openpgpapp: %s: the card answered %s", e.Op, apdu.Status(e.SW))
}

// Status returns the status word.
func (e *StatusError) Status() apdu.Status { return apdu.Status(e.SW) }

// LostError is the error of the call during which the session was lost. Op is the name of the
// operation. OutcomeUnknown is true when that operation is one that changes the card: the card may
// have carried it out, so the caller opens a new session and reads the card before it decides what
// happened, and never sends the command a second time on a guess. Err is the cause, from the
// transport, [ErrResponseTooLong], [ErrMalformedResponse], or the [*StatusError] of an exchange that
// failed after the card had begun to answer (a refused block in a chain, or an error status to GET
// RESPONSE; Op is then the operation that failed). errors.Is finds [ErrSessionDead] in it. For a command
// that holds a secret the text does not show the cause: it stays reachable through errors.Is and As.
type LostError struct {
	Op             string
	OutcomeUnknown bool
	Err            error
	// secret: the command held a PIN. Its error text then does not show the cause, whose text came
	// from outside and cannot be trusted to hold no byte of the command.
	secret bool
}

// Error says that the session was lost and whether the card may have changed.
func (e *LostError) Error() string {
	if e.secret {
		return fmt.Sprintf("openpgpapp: %s: the session is lost and the card may have carried out the command", e.Op)
	}
	if e.OutcomeUnknown {
		return fmt.Sprintf("openpgpapp: %s: the session is lost and the card may have carried out the command: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("openpgpapp: %s: the session is lost: %v", e.Op, e.Err)
}

// Unwrap gives the cause and [ErrSessionDead].
func (e *LostError) Unwrap() []error { return []error{e.Err, ErrSessionDead} }
