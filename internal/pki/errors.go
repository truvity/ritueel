package pki

import (
	"errors"
	"fmt"
	"strings"

	"ritueel.id/ritueel/internal/jsonset"
)

var (
	// ErrParams is wrapped by an error for a parameter that the caller got wrong: a name, a
	// label, a time with a fraction, a serial that does not fit the profile, a key that is not
	// ECDSA on P-384, a body that [SignRoot] or [SignIntermediate] is given and is not the one of
	// the parameters, a signer whose key is not the key of the parameters, a reader or a signer that is
	// a nil pointer, a month count that leaves the years of a certificate, a ceremony time that would
	// end a validity on 9999-12-31 23:59:59Z.
	ErrParams = errors.New("pki: invalid parameter")
	// ErrRequest is wrapped by an error for a certificate request that asks for something the
	// builder does not issue: an extension outside the profile, a value other than the profile's,
	// a request that does not verify or is not read in full, a name or a name constraint that the
	// rules refuse, a request that has no name constraints, a request larger than [MaxRequestSize], a
	// request file that is not exactly one PEM block.
	ErrRequest = errors.New("pki: certificate request refused")
	// ErrSignature is wrapped by an error for a signature that does not verify with the key
	// that made it, or that is not a DER ECDSA value, and for a certificate that cannot be
	// assembled: a body that no builder returned, a key that is not the issuer of the body.
	ErrSignature = errors.New("pki: invalid signature or certificate")
)

// fail returns an error that wraps kind. The text is fixed words and numbers.
func fail(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, sprintf(format, args...))
}

// sprintf is fmt.Sprintf.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// causeError is an error of this package that also holds the error that caused it, such as the
// error of a signer or of a parser. errors.Is and errors.As see both the kind and the cause; the
// text shows the cause with every character outside printable ASCII escaped, because the cause may
// carry bytes that came from outside.
type causeError struct {
	kind  error
	what  string
	cause error
}

func (e *causeError) Error() string {
	return e.kind.Error() + ": " + e.what + ": " + jsonset.Escape(e.cause.Error())
}

func (e *causeError) Unwrap() []error { return []error{e.kind, e.cause} }

// failWith returns an error of the given kind that holds the error that caused it.
func failWith(kind error, what string, cause error) error {
	return &causeError{kind: kind, what: what, cause: cause}
}

// rekind returns an error of the given kind for a refusal that came from a check of another kind
// (or of none, a parser's). Every error of this package wraps exactly one kind, so a function of one
// kind that reuses a check of another says what the check said in its own kind, and never passes the
// other kind on: a caller that tests errors.Is(err, ErrRequest) is not told that a request was refused
// when a body was. An error of the package keeps its words (without the words of its kind) and the
// cause of its cause, when it has one; any other error is kept as the cause, as failWith keeps it.
func rekind(kind error, what string, err error) error {
	var ce *causeError
	if errors.As(err, &ce) {
		return rekind(kind, what+": "+ce.what, ce.cause)
	}
	for _, k := range []error{ErrParams, ErrRequest, ErrSignature} {
		if errors.Is(err, k) {
			return fail(kind, "%s: %s", what, strings.TrimPrefix(err.Error(), k.Error()+": "))
		}
	}
	return failWith(kind, what, err)
}
