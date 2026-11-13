// Package cli is the ritueel command line: the commands, the exit codes and the JSON output
// of docs/reference/cli.md. It writes only to the streams it is given and never exits.
package cli

import (
	"errors"
	"strings"
)

// ExitCode is the number the program returns to its caller.
type ExitCode int

// The exit codes of the table "Exit codes" in docs/reference/cli.md.
const (
	// ExitOK is success; for status, nothing due.
	ExitOK ExitCode = 0
	// ExitFailure is a failure.
	ExitFailure ExitCode = 1
	// ExitUsage is a usage error.
	ExitUsage ExitCode = 2
	// ExitRefused is a refusal by a check or by the policy.
	ExitRefused ExitCode = 3
	// ExitBackend is a refusal by the card, its PIN state or the key store backend.
	ExitBackend ExitCode = 4
	// ExitNotConfirmed is a ceremony that the person did not confirm.
	ExitNotConfirmed ExitCode = 5
	// ExitNotice is status only: the highest finding is a notice.
	ExitNotice ExitCode = 10
	// ExitAlert is status only: the highest finding is an alert.
	ExitAlert ExitCode = 11
	// ExitCritical is status only: the highest finding is critical.
	ExitCritical ExitCode = 12
)

// Outcome is the word of the "outcome" member of the JSON output.
type Outcome string

// The outcomes of the JSON output. Each matches an exit code.
const (
	// OutcomeDone matches the exit codes 0, 10, 11 and 12.
	OutcomeDone Outcome = "done"
	// OutcomeRefused matches the exit codes 3 and 4.
	OutcomeRefused Outcome = "refused"
	// OutcomeNotConfirmed matches the exit code 5.
	OutcomeNotConfirmed Outcome = "not-confirmed"
	// OutcomeUsage matches the exit code 2.
	OutcomeUsage Outcome = "usage"
	// OutcomeFailed matches the exit code 1.
	OutcomeFailed Outcome = "failed"
)

// Coded is an error that carries its exit code. A command returns one to end with that code;
// any other error ends with ExitFailure.
type Coded interface {
	error
	// ExitCode is the code the program returns.
	ExitCode() ExitCode
	// Outcome is the word of the "outcome" member.
	Outcome() Outcome
	// ReasonCodes are the codes of the "reasons" member; empty unless refused.
	ReasonCodes() []string
}

// UsageError is a wrong command line: exit code 2.
type UsageError struct{ Msg string }

// Error returns the message.
func (e UsageError) Error() string { return e.Msg }

// ExitCode returns ExitUsage.
func (UsageError) ExitCode() ExitCode { return ExitUsage }

// Outcome returns OutcomeUsage.
func (UsageError) Outcome() Outcome { return OutcomeUsage }

// ReasonCodes returns none.
func (UsageError) ReasonCodes() []string { return nil }

// Refusal is a refusal by a check or by the policy: exit code 3.
type Refusal struct {
	// Reasons are the codes of the refusal.
	Reasons []string
	// Msg is the message for a person; when empty the codes stand in.
	Msg string
}

// Error returns the message, or the reasons when there is none.
func (e Refusal) Error() string { return refusalText("refused", e.Msg, e.Reasons) }

// ExitCode returns ExitRefused.
func (Refusal) ExitCode() ExitCode { return ExitRefused }

// Outcome returns OutcomeRefused.
func (Refusal) Outcome() Outcome { return OutcomeRefused }

// ReasonCodes returns the reasons.
func (e Refusal) ReasonCodes() []string { return e.Reasons }

// BackendRefusal is a refusal by the card, its PIN state or the key store backend: exit code 4.
type BackendRefusal struct {
	// Reasons are the codes of the refusal.
	Reasons []string
	// Msg is the message for a person; when empty the codes stand in.
	Msg string
}

// Error returns the message, or the reasons when there is none.
func (e BackendRefusal) Error() string {
	return refusalText("refused by the card or the backend", e.Msg, e.Reasons)
}

// ExitCode returns ExitBackend.
func (BackendRefusal) ExitCode() ExitCode { return ExitBackend }

// Outcome returns OutcomeRefused.
func (BackendRefusal) Outcome() Outcome { return OutcomeRefused }

// ReasonCodes returns the reasons.
func (e BackendRefusal) ReasonCodes() []string { return e.Reasons }

// NotConfirmed is a ceremony that the person did not confirm: exit code 5.
type NotConfirmed struct{}

// Error says that nothing was confirmed.
func (NotConfirmed) Error() string { return "not confirmed" }

// ExitCode returns ExitNotConfirmed.
func (NotConfirmed) ExitCode() ExitCode { return ExitNotConfirmed }

// Outcome returns OutcomeNotConfirmed.
func (NotConfirmed) Outcome() Outcome { return OutcomeNotConfirmed }

// ReasonCodes returns none.
func (NotConfirmed) ReasonCodes() []string { return nil }

// ExitFor maps the error a command returned to its exit code and outcome. No error is
// ExitOK and OutcomeDone; an error that carries a code (Coded) gives that code; any other
// error is ExitFailure and OutcomeFailed.
func ExitFor(err error) (ExitCode, Outcome) {
	if err == nil {
		return ExitOK, OutcomeDone
	}
	var c Coded
	if errors.As(err, &c) {
		return c.ExitCode(), c.Outcome()
	}
	return ExitFailure, OutcomeFailed
}

// reasonsOf returns the reason codes of the error, if it carries any.
func reasonsOf(err error) []string {
	var c Coded
	if errors.As(err, &c) {
		return c.ReasonCodes()
	}
	return nil
}

func refusalText(prefix, msg string, reasons []string) string {
	if msg != "" {
		return msg
	}
	if len(reasons) == 0 {
		return prefix
	}
	return prefix + ": " + strings.Join(reasons, ", ")
}
