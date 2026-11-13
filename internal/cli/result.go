package cli

import (
	"encoding/json"
	"io"
)

// OutputMode is the value of --output.
type OutputMode string

// The two values of --output.
const (
	// OutputText is the default: text for people.
	OutputText OutputMode = "text"
	// OutputJSON prints one JSON object on standard output when the command ends.
	OutputJSON OutputMode = "json"
)

// FormatVersion is the value of the "output" member: the version of the JSON format.
const FormatVersion = 1

// Result is the JSON object of --output json: the members of the section "Machine-readable
// output" in docs/reference/cli.md. Members for later commands are added there and here
// together, as pointers or slices with omitempty.
//
// A command returns a Result when it ended as it should, and sets Reasons, Warnings and its own
// members. A Result is never written with an "error" member: only a failed or a misused command
// has one, and it comes from the error that the command returns (see ExitFor and WithWarnings).
type Result struct {
	// Output is the version of this format, FormatVersion.
	Output int `json:"output"`
	// Command is the command word; empty when no command was named.
	Command string `json:"command"`
	// ExitCode is the exit code the command returns.
	ExitCode ExitCode `json:"exit_code"`
	// Outcome matches the exit code.
	Outcome Outcome `json:"outcome"`
	// Reasons are the codes of a refusal. The member is written when the list is not empty.
	Reasons []string `json:"reasons,omitempty"`
	// Warnings are the warnings of the command, one string for each, in the order given and with
	// a repeated one repeated. A warning does not change the exit code. The member is always
	// written, as [] when there is none (the member "warnings" of docs/reference/cli.md); a
	// command sets it only to give warnings, and never makes the empty list itself. Each warning
	// is also printed on standard error, in both output modes. A command that ends with an error
	// gives its warnings with WithWarnings instead: the Result of a command that returns an
	// error is not used.
	Warnings []string `json:"warnings"`
	// Error is a message for a person when the command failed or was misused, and only then: the
	// object of a refusal or of a command that was not confirmed has none (its message goes to
	// standard error alone). Run sets it from the error; a command does not.
	Error string `json:"error,omitempty"`
	// Version is the release version (version only).
	Version string `json:"version,omitempty"`
	// Commit is the commit of the build (version only).
	Commit string `json:"commit,omitempty"`

	// Text is what the command prints on standard output with --output text. It is not
	// part of the JSON object.
	Text string `json:"-"`
}

// writeJSON writes the object and a newline, and nothing else.
func writeJSON(w io.Writer, r *Result) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
