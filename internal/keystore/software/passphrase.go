package software

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode"
	"unicode/utf8"
)

// The limits of a passphrase, each stated once (record 0002, rule 28).
const (
	// MaxPassphraseBytes is the most bytes of a passphrase.
	MaxPassphraseBytes = 1024
	// MinPassphraseChars is the fewest characters (Unicode code points) of a passphrase.
	MinPassphraseChars = 15
)

// maxPassphraseLine is the most bytes that [ReaderSource] reads for one line: the passphrase, one
// carriage return and the line feed.
const maxPassphraseLine = MaxPassphraseBytes + 2

// maxEmptyReads is how many reads in a row may return nothing before the reader is given up.
const maxEmptyReads = 100

// errPassphraseRule is the one error of a passphrase that is refused. It names the rule and holds
// no byte of the passphrase.
func errPassphraseRule(rule string) error {
	return refuse(ErrPassphrase, "%s", rule)
}

// CheckPassphrase says whether p is acceptable as the passphrase of a key file (record 0002, rule
// 28): valid UTF-8, no control character (a code point below U+0020 or from U+007F to U+009F) and
// no format character (the category Cf, which holds the right-to-left override and the zero-width
// joiner), at least [MinPassphraseChars] characters and at most [MaxPassphraseBytes] bytes. Spaces
// inside it are kept and nothing is trimmed: a leading or a trailing space is a character of the
// passphrase.
//
// The package judges neither randomness nor strength: "generated and not chosen" is advice that a
// program cannot check. A passphrase that fails gets an [ErrPassphrase] whose text names the rule
// and never the passphrase or a part of it.
func CheckPassphrase(p []byte) error {
	if len(p) > MaxPassphraseBytes {
		return errPassphraseRule("the passphrase is longer than 1024 bytes")
	}
	if !utf8.Valid(p) {
		return errPassphraseRule("the passphrase is not valid UTF-8")
	}
	chars := 0
	for rest := p; len(rest) > 0; {
		r, n := utf8.DecodeRune(rest)
		rest = rest[n:]
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return errPassphraseRule("the passphrase holds a control or a format character")
		}
		chars++
	}
	if chars < MinPassphraseChars {
		return errPassphraseRule("the passphrase is shorter than 15 characters")
	}
	return nil
}

// ReaderSource gives one passphrase for each call from r, one line each: the bytes up to the first
// line feed, with one carriage return in front of the line feed removed. A line that ends at the
// end of the input with no line feed is accepted. The passphrase goes through [CheckPassphrase]
// before it is returned.
//
// A call reads at most MaxPassphraseBytes + 2 bytes, one byte at a time, and no byte after the
// line feed, so the next call gets the next line (a descriptor that holds the passphrases of
// several keys is read in the order that the store asks for them). It refuses a reader that gives
// more than that before a line feed, an empty line, a nil reader, and an error of the reader (an
// [ErrPassphrase] that wraps it). It never closes r: r is the caller's, for example the
// descriptor of --passphrase-fd. A ReaderSource is safe for several goroutines; calls run one at a
// time.
//
// A line over the limit is refused, but the bytes after the ones that were read stay in the reader:
// the next call reads that tail as a line of its own, so a caller that gets this refusal must
// throw the reader away or read it to the next line feed itself. A Read that blocks is not
// interrupted: the call looks at the context before its first read and not while a read waits, so
// a caller that reads from a pipe that may never be written runs the call in its own goroutine.
// A [Store] holds its lock while it asks a source, so its Close waits as long as the source does.
//
// The line that the reader gave is a new slice that the caller clears after use; the buffer that
// the call read it into is cleared on every path out. The source prints as fixed words with every
// verb of the formatter, never the bytes of its reader.
func ReaderSource(r io.Reader) PassphraseSource {
	return &readerSource{r: r}
}

// readerSource is the PassphraseSource that [ReaderSource] returns.
type readerSource struct {
	mu sync.Mutex
	r  io.Reader
}

// Passphrase reads the next line of the reader. The purpose is not used: the order of the lines is
// the order in which the store asks.
func (s *readerSource) Passphrase(ctx context.Context, _ Purpose) ([]byte, error) {
	if ctx == nil {
		return nil, refuse(ErrParams, "the context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.r == nil {
		return nil, refuse(ErrPassphrase, "there is no reader to read a passphrase from")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	line := make([]byte, 0, maxPassphraseLine)
	defer func() { clear(line[:cap(line)]) }()
	var one [1]byte
	empty := 0
	terminated := false
	for len(line) < maxPassphraseLine {
		n, err := s.r.Read(one[:])
		if n > 0 {
			empty = 0
			if one[0] == '\n' {
				terminated = true
				break
			}
			line = append(line, one[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("%w: the reader of passphrases failed: %w", ErrPassphrase, err)
		}
		if n == 0 {
			if empty++; empty >= maxEmptyReads {
				return nil, refuse(ErrPassphrase, "the reader of passphrases gives nothing")
			}
		}
	}
	if !terminated && len(line) >= maxPassphraseLine {
		return nil, errPassphraseRule("the line of the passphrase is longer than the limit")
	}
	if terminated {
		line = bytes.TrimSuffix(line, []byte{'\r'})
	}
	if len(line) == 0 {
		return nil, errPassphraseRule("the line of the passphrase is empty")
	}
	if err := CheckPassphrase(line); err != nil {
		return nil, err
	}
	return bytes.Clone(line), nil
}

// String is the text of a source with every verb of the formatter: fixed words, so that printing
// a source never shows bytes of the reader inside it (a bytes.Reader prints its content).
func (*readerSource) String() string { return "software.ReaderSource" }

// Format prints the fixed words for every verb, whatever the verb and the flags are.
func (s *readerSource) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.String())
}

var _ PassphraseSource = (*readerSource)(nil)
