package ceremony

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

// The limits of a transcript (record 0006, rule 9): a transcript is a text a
// person reads, so it is bounded before a line is kept or a file is written.
const (
	// MaxTranscriptLines is the most lines of a transcript: 4,096.
	MaxTranscriptLines = 4096
	// MaxTranscriptLineBytes is the most bytes of one line, without its line feed: 1,024. [Console]
	// cuts a longer line and ends it with "...".
	MaxTranscriptLineBytes = 1024
	// MaxTranscriptBytes is the most bytes of a transcript: 1 MiB.
	MaxTranscriptBytes = 1 << 20
)

// checkTranscript judges the text of transcript.txt under the rules of the page "The transcript":
// UTF-8 text with LF line endings and no terminal control sequence. A character that a terminal
// acts on is refused whatever the character is: a control code (the line feed is the line ending
// and the one control code allowed), the escape, a carriage return, a tab, a character of the
// category format (the bidirectional controls, the zero-width characters and the byte order mark)
// and the line and paragraph separators. The text is at most [MaxTranscriptBytes] bytes and
// [MaxTranscriptLines] lines of at most [MaxTranscriptLineBytes] bytes, and it ends with a line
// feed. An empty text is refused: a transcript has at least one line. The error never holds the
// text.
func checkTranscript(b []byte) error {
	if len(b) == 0 {
		return errors.New("the transcript is empty")
	}
	if len(b) > MaxTranscriptBytes {
		return fmt.Errorf("the transcript is longer than %d bytes", MaxTranscriptBytes)
	}
	if !utf8.Valid(b) {
		return errors.New("the transcript is not UTF-8")
	}
	if b[len(b)-1] != '\n' {
		return errors.New("the transcript does not end with a line feed")
	}
	lines, width := 0, 0
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		i += size
		if r == '\n' {
			lines++
			if lines > MaxTranscriptLines {
				return fmt.Errorf("the transcript has more than %d lines", MaxTranscriptLines)
			}
			width = 0
			continue
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return fmt.Errorf("line %d holds a control or format character (U+%04X)", lines+1, r)
		}
		width += size
		if width > MaxTranscriptLineBytes {
			return fmt.Errorf("line %d is longer than %d bytes", lines+1, MaxTranscriptLineBytes)
		}
	}
	return nil
}
