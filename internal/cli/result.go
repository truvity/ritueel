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
type Result struct {
	// Output is the version of this format, FormatVersion.
	Output int `json:"output"`
	// Command is the command word; empty when no command was named.
	Command string `json:"command"`
	// ExitCode is the exit code the command returns.
	ExitCode ExitCode `json:"exit_code"`
	// Outcome matches the exit code.
	Outcome Outcome `json:"outcome"`
	// Reasons are the codes of a refusal.
	Reasons []string `json:"reasons,omitempty"`
	// Error is a message for a person when the command failed or was misused.
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
