package ceremony

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"ritueel.id/ritueel/internal/jsonset"
)

// Faults of a [Console], seen at [Console.Transcript]. A transcript that is not what was printed
// is never handed out.
var (
	// ErrNoConsole is the fault of a nil or zero Console.
	ErrNoConsole = errors.New("the console was not made by NewConsole")
	// ErrTranscriptLimit is the fault of a Console that was given more than a transcript holds.
	ErrTranscriptLimit = errors.New("the transcript is longer than its limits")
	// ErrPrintFailed is the fault of a Console whose stream refused a line, or that has no stream:
	// the line was kept, but it was not printed, so the transcript would say what no person read.
	ErrPrintFailed = errors.New("a line of the console was not printed")
)

// Console prints the lines of a ceremony and keeps them, so that the transcript is what was
// printed (record 0006, rule 9). A line is one call: the text is made with the format and the
// arguments, every character outside printable ASCII is written as an escape (\uXXXX, as
// jsonset.Escape writes it: a control code, the escape character, a bidirectional control and
// every letter of another script), a line over [MaxTranscriptLineBytes] is cut and ends with
// "...", and one line feed is added. The same bytes go to the stream and into the kept lines. A
// line is printed and kept under one lock, so two goroutines that print keep every line whole, and
// the lines of the two streams are in the order they were printed in.
//
// A Console writes no file and reads no input: the caller hands [Console.Transcript] to
// Folder.WriteTranscript. The zero value and a nil Console print nothing and keep nothing.
//
// The text is escaped by jsonset.Escape, which keeps a backslash as it is: two names that differ
// only in a backslash, a space or a byte that is not UTF-8 can print as one line. A caller that
// gives a name that came from a file system (a file name, a path) to a line gives it through
// jsonset.EscapeExact, which doubles a backslash and writes a space and such a byte as an escape
// that can be read back.
type Console struct {
	made           bool
	stderr, stdout io.Writer

	mu    sync.Mutex
	lines []string
	size  int
	fault error
}

// NewConsole makes a Console that prints the lines of Err to stderr and those of Out to stdout. A
// stream that is nil is a fault: the lines for it are kept and not printed, and Transcript returns
// [ErrPrintFailed].
func NewConsole(stderr, stdout io.Writer) *Console {
	return &Console{made: true, stderr: stderr, stdout: stdout}
}

// Err prints one line on standard error. The line feed is added.
func (c *Console) Err(format string, args ...any) {
	if c == nil || !c.made {
		return
	}
	c.print(c.stderr, format, args)
}

// Out prints one line on standard output. The line feed is added.
func (c *Console) Out(format string, args ...any) {
	if c == nil || !c.made {
		return
	}
	c.print(c.stdout, format, args)
}

func (c *Console) print(w io.Writer, format string, args []any) {
	line := lineText(format, args)
	c.mu.Lock()
	defer c.mu.Unlock()
	if w == nil {
		c.failOnce(ErrPrintFailed, "there is no stream")
	} else if err := safeWrite(w, line+"\n"); err != nil {
		c.failOnce(ErrPrintFailed, causeText(err))
	}
	switch {
	case len(c.lines) >= MaxTranscriptLines || c.size+len(line)+1 > MaxTranscriptBytes:
		c.failOnce(ErrTranscriptLimit, "")
	default:
		c.lines = append(c.lines, line)
		c.size += len(line) + 1
	}
}

// failOnce keeps the first fault.
func (c *Console) failOnce(kind error, text string) {
	if c.fault != nil {
		return
	}
	if text == "" {
		c.fault = kind
		return
	}
	c.fault = fmt.Errorf("%w: %s", kind, text)
}

// Transcript returns every line that was printed, on either stream, in order, each ended by one
// line feed: the bytes of transcript.txt. A Console that was not made by NewConsole, one that was
// given more than the limits of a transcript, and one whose stream refused a line return an error
// and no text.
func (c *Console) Transcript() ([]byte, error) {
	if c == nil || !c.made {
		return nil, ErrNoConsole
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil {
		return nil, c.fault
	}
	out := make([]byte, 0, c.size)
	for _, l := range c.lines {
		out = append(out, l...)
		out = append(out, '\n')
	}
	if len(out) > 0 {
		if err := checkTranscript(out); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrTranscriptLimit, causeText(err))
		}
	}
	return out, nil
}

// lineText makes the text of a line: formatted, escaped to printable ASCII, cut. A panic of a
// method of an argument is turned into text by fmt, and one that escapes it is caught here.
func lineText(format string, args []any) (text string) {
	defer func() {
		if recover() != nil {
			text = "(a line could not be formatted)"
		}
	}()
	s := jsonset.Escape(fmt.Sprintf(format, args...))
	if len(s) > MaxTranscriptLineBytes {
		s = s[:MaxTranscriptLineBytes-3] + "..."
	}
	return s
}

// safeWrite writes s in one call and turns a panic of the writer into an error. A short write is
// an error.
func safeWrite(w io.Writer, s string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("the stream panicked")
		}
	}()
	n, err := io.WriteString(w, s)
	if err == nil && n < len(s) {
		err = io.ErrShortWrite
	}
	return err
}
