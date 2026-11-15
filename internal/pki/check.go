package pki

import "errors"

// Check names the check of the hand-off contract ("What the certifier checks", docs/reference/hand-off-contract.md)
// that refused a request, for the reason code that the contract gives it. It is a second question that
// an error answers, beside its kind: every error of this package still wraps exactly one of
// [ErrParams], [ErrRequest], [ErrSignature] and [ErrPEM], and an [ErrRequest] that comes from reading a request
// also says which check it is, so that the later code needs no text to tell them apart. See [CheckOf].
type Check int

const (
	// CheckNone is no check: the error is not a refusal of a request by one of the contract's checks
	// (it is a parameter of the caller, a fault of this package, or not an error of this package).
	CheckNone Check = iota
	// CheckMalformed is check 2, reason code "malformed": the request does not parse, or has a form that
	// the contract does not allow (not one DER request of version 0, more than one attribute, an
	// extension that is not in its form, a name that is not a name, a request larger than
	// [MaxRequestSize], a request file that is not one PEM block).
	CheckMalformed
	// CheckAlgorithm is check 4, reason code "algorithm-unsupported": the key is not ECDSA on P-384.
	CheckAlgorithm
	// CheckPossession is check 5, reason code "possession-invalid": the request is not signed with
	// ecdsa-with-SHA384, or its signature does not verify with its own key.
	CheckPossession
	// CheckPolicy is check 9, reason code "policy": what the request asks for is not issued (the
	// subject, its strings and its text, the extensions and their values, the name constraints, the key
	// or the subject of the issuer).
	CheckPolicy
)

// Code returns the reason code of the check, as the contract writes it: "malformed",
// "algorithm-unsupported", "possession-invalid" or "policy"; the empty string for [CheckNone].
func (c Check) Code() string {
	switch c {
	case CheckMalformed:
		return "malformed"
	case CheckAlgorithm:
		return "algorithm-unsupported"
	case CheckPossession:
		return "possession-invalid"
	case CheckPolicy:
		return "policy"
	}
	return ""
}

// String is the reason code.
func (c Check) String() string { return c.Code() }

// CheckOf says which check of the contract refused a request, for an error that [ParseRequest],
// [ParseRequestFile] or [IntermediateTBS] returned for it; it returns [CheckNone] for any other
// error. An error that says a check is an [ErrRequest] and nothing else: errors.Is(err, ErrParams) and
// errors.Is(err, ErrSignature) are false. The check is found through the wrappers that a caller adds
// (fmt.Errorf with %w, errors.Join) and never through the cause of an error of this package: the
// error of a signer, or of a parser, that this package holds as a cause says no check, whatever it wraps
// itself, so an error that comes from a signer or from a parameter is [CheckNone].
//
// The later code calls pki.CheckOf(err).Code() to get the reason code of the contract. The check that
// the package finds first is the first in the contract's order for what this package reads: the form
// (2), then the key (4), then the signature (5), then the content (9); see [ParseRequest] and
// [RequestKey] for the order against checks 6 to 8, which this package does not make.
func CheckOf(err error) Check {
	//nolint:errorlint // the walk is by hand on purpose: it stops at the cause of an error of this package
	switch e := err.(type) {
	case nil:
		return CheckNone
	case *requestError:
		return e.check
	case *causeError:
		// The cause of an error of this package is what a signer or a parser returned, which is not
		// this package's word on a request: whatever it wraps (a signer may return an error that a
		// request reader made), it says no check.
		return CheckNone
	case interface{ Unwrap() []error }:
		for _, w := range e.Unwrap() {
			if c := CheckOf(w); c != CheckNone {
				return c
			}
		}
	case interface{ Unwrap() error }:
		return CheckOf(e.Unwrap())
	}
	return CheckNone
}

// requestError is an [ErrRequest] that also holds the check that refused the request. Its text is the
// text of fail(ErrRequest, ...), and it wraps the one kind and nothing else.
type requestError struct {
	check Check
	msg   string
}

func (e *requestError) Error() string { return ErrRequest.Error() + ": " + e.msg }
func (e *requestError) Unwrap() error { return ErrRequest }

// failRequest returns a refusal of a request by the given check. The text is fixed words and numbers.
func failRequest(check Check, format string, args ...any) error {
	return &requestError{check: check, msg: sprintf(format, args...)}
}

// nameFail is fail for a name that is read as an issuer, a subject or a name of SameName: a name of a
// request (kind ErrRequest) also says the check, the others only their kind.
func nameFail(kind error, check Check, format string, args ...any) error {
	if errors.Is(kind, ErrRequest) {
		return failRequest(check, format, args...)
	}
	return fail(kind, format, args...)
}
