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
// have carried out the command, so the caller opens a new session and reads the card before it decides what
// happened, and never sends the command a second time on a guess. The cause is, from the
// transport, [ErrResponseTooLong], [ErrMalformedResponse], or the [*StatusError] of an exchange that
// failed after the card had begun to answer (a refused block in a chain, or an error status to GET
// RESPONSE; Op is then the operation that failed). errors.Is finds [ErrSessionDead] and the cause.
//
// A cause that came from the transport is text from outside, and nothing enforces that it holds no
// byte of a command. So when the command held a PIN, the error keeps the cause in an unexported field,
// Err is nil, there is no Unwrap, and no way of printing it (Error, %v, %+v, %#v, %x) shows the cause:
// errors.Is and errors.As reach it through the methods Is and As below, and the caller who wants its
// text asks for it deliberately. This is the smaller of the two ways to do it: no wrapper type. For a
// command that holds no secret Err is the cause, Unwrap gives it, and the text shows it.
type LostError struct {
	Op             string
	OutcomeUnknown bool
	// Err is the cause, for a command that holds no secret; nil for one that does.
	Err error
	// cause is the cause, always; secret: the command held a PIN.
	cause  error
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

// Unwrap gives the cause and [ErrSessionDead], for a command that holds no secret; for one that does it
// gives nothing, and Is and As answer instead.
func (e *LostError) Unwrap() []error {
	if e.secret {
		return nil
	}
	return []error{e.Err, ErrSessionDead}
}

// Is answers errors.Is for a command that holds a secret: [ErrSessionDead] and the hidden cause.
func (e *LostError) Is(target error) bool {
	return e.secret && (target == ErrSessionDead || errors.Is(e.cause, target))
}

// As answers errors.As for a command that holds a secret, through the hidden cause.
func (e *LostError) As(target any) bool { return e.secret && errors.As(e.cause, target) }

// GoString is the text of the error, for %#v: for a secret command no field is shown. It has a value
// receiver, so that a LostError that was copied into a value is held to the same rule.
func (e LostError) GoString() string {
	if e.secret {
		return e.Error()
	}
	type plain LostError
	return fmt.Sprintf("%#v", plain(e))
}

// Format writes the text of the error for every verb of a secret command, so that no verb shows its
// cause; for another command it is the text, and the fields for %#v. It has a value receiver, as GoString.
func (e LostError) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = f.Write([]byte(e.GoString()))
		return
	}
	_, _ = f.Write([]byte(e.Error()))
}
