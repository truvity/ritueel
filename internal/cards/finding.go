package cards

import (
	"strings"

	"ritueel.id/ritueel/internal/jsonset"
)

// Code is the name of one finding. The names are proposed: no page lists them yet.
type Code string

const (
	// FileInvalid is a card file that fails its reader, or is longer than the limit of a read. The detail is
	// the reader's sentence, with the line when there is one.
	FileInvalid Code = "card-file-invalid"
	// SerialTwice is a second file that names a card that an earlier file already names: one serial,
	// whatever the kinds (record 0003, rule 5). The path is the later file.
	SerialTwice Code = "card-serial-twice"
)

// codes is the table of the codes, in the order that findings are reported in.
var codes = []Code{FileInvalid, SerialTwice}

// refuses is the table of the codes that stop apply (record 0005, rule 19). Both codes of this version do.
var refuses = map[Code]bool{
	FileInvalid: true,
	SerialTwice: true,
}

// levels is the one table of the weight of a finding for status. Both codes are alerts: the pages give no
// level for a wanted file that fails its check, and a later change may replace this table.
var levels = map[Code]Level{
	FileInvalid: LevelAlert,
	SerialTwice: LevelAlert,
}

// Codes returns every code, in the order that findings are reported in. The list is a copy.
func Codes() []Code { return append([]Code(nil), codes...) }

// Refuses reports whether a finding of this code stops apply (record 0005, rule 19). It fails closed: it is
// true for a code that is not in the table and for the zero Code.
func (c Code) Refuses() bool {
	v, ok := refuses[c]
	return !ok || v
}

// Level is the weight a finding has for status: notice, alert or critical. The zero Level is none of the
// three, and a Finding whose Level is not one of them is not usable.
type Level string

// The three levels.
const (
	// LevelNotice is the lowest weight.
	LevelNotice Level = "notice"
	// LevelAlert is the middle weight.
	LevelAlert Level = "alert"
	// LevelCritical is the highest weight.
	LevelCritical Level = "critical"
)

// Valid reports whether l is one of the three levels.
func (l Level) Valid() bool {
	switch l {
	case LevelNotice, LevelAlert, LevelCritical:
		return true
	}
	return false
}

// levelOf returns the level of a code from the one table, and the zero Level for a code that is not in it.
func levelOf(c Code) Level { return levels[c] }

// maxDetail is the most bytes of the detail of a finding.
const maxDetail = 240

// cutMark ends a detail that was cut.
const cutMark = "..."

// Finding is one finding about the card files.
type Finding struct {
	// Code names the finding.
	Code Code
	// Level is the weight of the finding, from one table of the package.
	Level Level
	// Path is a path of the bundle, "/" separated, printable ASCII: want/cards/NAME.yaml with a NAME that
	// passed wanted.ValidName.
	Path string
	// Detail is a few words of printable ASCII, at most 240 bytes. A longer text is cut and ends with "...".
	Detail string
}

// Line is the line a person reads: the code, the path, a colon and the detail, with every character beyond
// printable ASCII written as an escape. It has no line break.
func (f Finding) Line() string {
	return jsonset.Escape(string(f.Code)) + " " + jsonset.EscapeExact(f.Path) + ": " + jsonset.Escape(f.Detail)
}

// newFinding makes a finding with its level from the table and a detail that is printable ASCII and at most
// [maxDetail] bytes.
func newFinding(c Code, path, detail string) Finding {
	return Finding{Code: c, Level: levelOf(c), Path: path, Detail: cutDetail(detail)}
}

// cutDetail writes s as printable ASCII and cuts it so that the result is at most [maxDetail] bytes and
// ends with "..." when it was cut. A cut never leaves half of an escape: not a backslash at the end, not a
// part of a \uXXXX, and not the first escape of the pair of a character above U+FFFF; the cut then moves
// one escape earlier.
func cutDetail(s string) string {
	s = jsonset.Escape(s)
	if len(s) <= maxDetail {
		return s
	}
	s = s[:maxDetail-len(cutMark)]
	// A cut inside the second escape of a pair drops that part, and then the first escape of the pair.
	for {
		i := strings.LastIndexByte(s, '\\')
		if i < 0 || !endsInHalfEscape(s[i:]) {
			break
		}
		s = s[:i]
	}
	return s + cutMark
}

// endsInHalfEscape reports whether tail, which starts with the last backslash of a cut text, is half of an
// escape: a lone backslash, a \uXXXX that is not whole, or the whole escape of a high surrogate, whose
// second half would be cut off.
func endsInHalfEscape(tail string) bool {
	switch {
	case len(tail) == 1:
		return true
	case tail[1] != 'u':
		return false
	case len(tail) < 6:
		return true
	}
	return len(tail) == 6 && tail[2] == 'd' && strings.ContainsRune("89ab", rune(tail[3]))
}
