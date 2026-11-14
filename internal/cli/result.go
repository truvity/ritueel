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
	// Reasons are the codes of a refusal. The object of a refused command (the exit codes 3 and
	// 4) always has at least one, and no other object has any: either is a mistake of the
	// programmer, and Run panics (exit code 1) with a text that says so.
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
	// Checked names the bytes that a command checked and accepted, one entry for each file, in the
	// order the command names them; the member is there for an accepted list and for nothing
	// else (the member "checked" of docs/reference/cli.md, built by verify root-list).
	Checked []CheckedFile `json:"checked,omitempty"`
	// Again is true for an accepted list that is the list the host holds, byte for byte, coming
	// again (the member "again" of docs/reference/cli.md); the member is absent otherwise.
	Again bool `json:"again,omitempty"`
	// Version is the release version (version only).
	Version string `json:"version,omitempty"`
	// Commit is the commit of the build (version only).
	Commit string `json:"commit,omitempty"`

	// Text is what the command prints on standard output with --output text. It is not
	// part of the JSON object.
	Text string `json:"-"`
}

// CheckedFile is one entry of Result.Checked: a file that was read and checked, and the digest
// of the bytes that were read.
type CheckedFile struct {
	// Name is the base name of the file as the command was given it. A name that is not plain
	// never gets here: the reader of files refuses it before the file is read.
	Name string `json:"name"`
	// SHA256 is the SHA-256 of the bytes that were read and checked, in lower-case hexadecimal;
	// the file is not read a second time for it.
	SHA256 string `json:"sha256"`
}

// writeJSON writes the object and a newline, and nothing else.
func writeJSON(w io.Writer, r *Result) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
