package strictjson

import (
	"strconv"
	"strings"
)

// The range of an integer in a record is -(2^53 - 1) to 2^53 - 1, what RFC 8785 can hold exactly
// (RFC 7493, section 2.2). The values are written out here as literals, and not taken from the
// constants of the package, so that a wrong constant is a failure of a test and not a change that
// every test follows.
const (
	safeMaxText = "9007199254740991"
	safeMinText = "-9007199254740991"
	safeMax     = int64(9007199254740991)
	safeMin     = int64(-9007199254740991)
	// rangeWords is the end of the text that every refusal for the range has.
	rangeWords = "is outside the range -9007199254740991 to 9007199254740991, which RFC 8785 can hold"
)

// outside is the text of the refusal of the integer whose digits are given, written out again here:
// the integer, cut at 40 characters and followed by "..." when it is longer, then rangeWords.
func outside(digits string) string {
	shown := digits
	if len(shown) > 40 {
		shown = shown[:40] + "..."
	}
	return "the integer " + shown + " " + rangeWords
}

// isOutside says whether the text of an integer is outside the range, by arithmetic on the text
// (an integer of more than 64 bits is outside).
func isOutside(text string) bool {
	n, err := strconv.ParseInt(text, 10, 64)
	return err != nil || n > safeMax || n < safeMin
}

// repeat is strings.Repeat, short for the tables.
func repeat(s string, n int) string { return strings.Repeat(s, n) }
