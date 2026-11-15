package ceremony

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// The words of the member by of a confirmation in the record (docs/reference/ceremony-record.md, "The
// record").
const (
	// ConfirmedTyped is a plan that a person confirmed by typing the first eight characters of its
	// digest.
	ConfirmedTyped = "typed"
	// ConfirmedFlag is a plan that a script confirmed with --confirm and the whole digest.
	ConfirmedFlag = "flag"
)

// maxTypedLine is the most bytes that the typed confirmation reads: the eight characters, the line
// ending, and room for a mistake. A line longer than this is not a confirmation (record 0005, rule 9).
const maxTypedLine = 64

// typedLength is the number of characters that a person types: the first eight of the digest.
const typedLength = 8

// Confirm is how the plan is confirmed. The zero value is the typed confirmation, which is read only
// from a terminal: a Confirm that holds nothing confirms nothing without a person.
type Confirm struct {
	// Flag is true when the confirmation is the flag --confirm: a script, with the whole digest.
	Flag bool
	// Digest is the value of --confirm. It is read only when Flag is true, and it confirms only when
	// it is exactly the plan digest in 64 lower-case hexadecimal digits: a value that is missing,
	// empty, malformed or wrong is not a confirmation (exit code 5).
	Digest string
}

// by is the word of the record for this confirmation.
func (c Confirm) by() string {
	if c.Flag {
		return ConfirmedFlag
	}
	return ConfirmedTyped
}

// confirm judges the confirmation against the plan digest, after the plan in words and the digest were
// printed. It returns nil for a confirmation and [ErrNotConfirmed] for anything else, and prints the
// reason on the console first, so a person sees why. It writes no file. A typed confirmation is read
// only when standard input is a terminal (record 0005, rule 9; record 0010, rule 13): a line from a pipe
// is not a person. The typed line is not printed again and is not kept.
func (r *run) confirm() error {
	c := r.in.Confirm
	out := r.in.Env.Out
	if c.Flag {
		if c.Digest != r.plan.SHA256 {
			out.Err("not confirmed: --confirm is not the digest of this plan, which is the 64 digits above")
			return ErrNotConfirmed
		}
		out.Err("confirmed with --confirm, the whole plan digest")
		return nil
	}
	if !r.in.Env.InIsTerminal || r.in.Env.In == nil {
		out.Err("not confirmed: standard input is not a terminal: a script passes --confirm DIGEST")
		return ErrNotConfirmed
	}
	out.Err("type the first %d characters of the plan digest, and nothing more, and press Enter:", typedLength)
	line, err := readTypedLine(r.in.Env.In)
	if err != nil {
		out.Err("not confirmed: no line of at most %d bytes was read", maxTypedLine)
		return ErrNotConfirmed
	}
	if !typedMatches(line, r.plan.SHA256) {
		out.Err("not confirmed: what was typed is not the first %d characters of the plan digest", typedLength)
		return ErrNotConfirmed
	}
	out.Err("confirmed by typing the first %d characters of the plan digest", typedLength)
	return nil
}

// readTypedLine reads one line of at most [maxTypedLine] bytes, the line ending included, from in and
// returns it without its line feed and without the carriage return before it. A line that has no line
// feed within the limit, an empty reader and a reader that fails are errors: a key press that is not a
// line is not a confirmation.
func readTypedLine(in io.Reader) (string, error) {
	br := bufio.NewReaderSize(io.LimitReader(in, maxTypedLine), maxTypedLine)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", errors.New("no whole line was read")
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	return line, nil
}

// typedMatches reports whether line is the first eight characters of digest, in hexadecimal digits of
// either case and nothing more.
func typedMatches(line, digest string) bool {
	if len(line) != typedLength || len(digest) < typedLength {
		return false
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return strings.EqualFold(line, digest[:typedLength])
}
