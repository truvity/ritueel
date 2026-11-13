package fsx_test

// The names and paths the writer refuses before it touches the file system, with the exact text
// of each refusal, and the ones it accepts and then really writes. The rule is one positive rule
// (record 0006, the owner's decision): a name holds only the ASCII letters, the digits, the dot,
// the hyphen and the underscore, and besides: it is not empty, not "." or "..", not longer than
// 255 bytes, not a device name of Windows (the whole name or the part before the first dot, in any
// case), does not end with a dot, and, for a final name that is written, does not start with the
// temporary prefix (in any case). Two names of one set that differ only by case are refused.
//
// The rules apply to every element of a path and to every name of a set, except the
// temporary-name prefix, which only the last element of a path and any name of a set must not
// have.
//
// Every refused row holds one fault only, so that removing one rule from the writer fails the
// row of that rule and is not hidden by another rule that refuses the same name. One table input
// has one exact text: the refusal is checked for its text, in every method, in every place of a
// path, and as the name of a file of a set, so a break of one rule of an overlapping pair (a
// trailing separator and an empty element; "." and ".." and a trailing dot; a device name with a
// trailing dot) changes a text and is seen.

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// ---- the texts ------------------------------------------------------------------------------

const (
	invalidPrefix = "fsx: invalid argument: "
	whyNotPlain   = "is not one plain name"
	whyDevice     = "is a device name that Windows reserves"
	whyTrailing   = "ends with a dot, which the stick's file system can remove"
	nameRuleText  = "which is not a letter, a digit, a dot, a hyphen or an underscore"
)

// charName is how a character stands in a text: U+XXXX, and the character itself in parentheses
// only when it is printable ASCII (a letter, a digit, a punctuation mark or a symbol of ASCII,
// not the space).
func charName(r rune) string {
	if r > 0x20 && r < 0x7f {
		return fmt.Sprintf("U+%04X (%c)", r, r)
	}
	return fmt.Sprintf("U+%04X", r)
}

func hasChar(r rune) string {
	return fmt.Sprintf("has the character %s, %s", charName(r), nameRuleText)
}
func hasByte(b byte) string { return fmt.Sprintf("has the byte 0x%02X, %s", b, nameRuleText) }
func tooLong(n int) string {
	return fmt.Sprintf("is %d bytes long, more than the 255 a workstation file system holds", n)
}

// pathText is the text of a refusal of path p: tail follows the quoted path.
func pathText(p, tail string) string {
	return fmt.Sprintf("%spath %s %s", invalidPrefix, strconv.QuoteToASCII(p), tail)
}

// elemText is the text of a refusal of an element of path p.
func elemText(p, why string) string { return pathText(p, "has an element that "+why) }

// fileText is the text of a refusal of the name of a file of a set.
func fileText(name, tail string) string {
	return fmt.Sprintf("%sfile name %s %s", invalidPrefix, strconv.QuoteToASCII(name), tail)
}

const (
	tailSeparator = "ends with a separator"
	tailEmptyElem = "has an empty element (a doubled separator)"
	tailDot       = `has a "." element`
	tailDotDot    = `has a ".." element`
	tailPrefix    = "has the prefix of a temporary name"
	tailAbsolute  = "is absolute; a path is relative to the root"
)

// requirePrintableASCII fails when a byte of the text is not printable ASCII (0x20 to 0x7E): no
// raw control code, no raw invisible character, no raw character that a terminal could draw
// in a way that hides the text, no raw byte that is not UTF-8.
func requirePrintableASCII(t testing.TB, text string) {
	t.Helper()
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7e {
			t.Fatalf("the text %q has the byte %#x at %d, which is not printable ASCII", text, text[i], i)
		}
	}
}

// ---- the tables -----------------------------------------------------------------------------

func rep(s string, n int) string { return strings.Repeat(s, n) }

// nameRow is one name, the label of what it tests, and the reason that the refusal gives (the
// text after "has an element that" in a path and after the quoted name in a set).
type nameRow struct {
	why, name, reason string
}

// allowedByte is the rule, said again in the test, once, in the way the brief gives it.
func allowedByte(b byte) bool {
	return 'a' <= b && b <= 'z' || 'A' <= b && b <= 'Z' || '0' <= b && b <= '9' || b == '.' || b == '-' || b == '_'
}

// refusedBytes holds, for every byte of ASCII (0x00 to 0x7F) that a name may not hold, the name
// with it in the first place, in an inner place and in the last place.
func refusedBytes(withSlash bool) []nameRow {
	var out []nameRow
	for b := 0; b < 0x80; b++ {
		if allowedByte(byte(b)) || (b == '/' && !withSlash) {
			continue
		}
		c := string(rune(b))
		why := fmt.Sprintf("byte 0x%02X", b)
		out = append(out,
			nameRow{why + " first", c + "ab", hasChar(rune(b))},
			nameRow{why + " inside", "a" + c + "b", hasChar(rune(b))},
			nameRow{why + " last", "ab" + c, hasChar(rune(b))},
		)
	}
	return out
}

// refusedOther are the names that fail by another rule, each with one fault.
var refusedOther = []nameRow{
	// valid characters beyond ASCII, printable or not: the rule does not tell them apart
	{"U+00E9, a Latin letter with an accent", "é.json", hasChar(0xe9)},
	{"U+00E9 alone", "é", hasChar(0xe9)},
	{"Cyrillic", "ключ", hasChar(0x43a)},
	{"Chinese", "鍵", hasChar(0x9375)},
	{"an emoji, beyond the BMP", "a😀b", hasChar(0x1f600)},
	{"the Kelvin sign", "\u212a.json", hasChar(0x212a)},
	{"a decomposed accent, the combining mark", "e\u0301.json", hasChar(0x301)},
	{"the no-break space", "a\u00a0b", hasChar(0xa0)},
	{"the soft hyphen", "a\u00adb", hasChar(0xad)},
	{"the zero-width space", "a\u200bb", hasChar(0x200b)},
	{"the zero-width joiner", "\u200d", hasChar(0x200d)},
	{"the right-to-left override", "a\u202eb", hasChar(0x202e)},
	{"the line separator", "a\u2028b", hasChar(0x2028)},
	{"the byte order mark", "\ufeffa", hasChar(0xfeff)},
	{"a private use character", "a\ue000", hasChar(0xe000)},
	{"U+FFFD, the replacement character, validly encoded", "\ufffd.json", hasChar(0xfffd)},
	{"U+FFFE", "a\ufffeb", hasChar(0xfffe)},
	{"U+FFFF", "a\uffffb", hasChar(0xffff)},
	{"the first C1 control, U+0080", "a\u0080b", hasChar(0x80)},
	{"the last C1 control, U+009F", "a\u009fb", hasChar(0x9f)},
	{"U+00A1, just above the no-break space", "a\u00a1b", hasChar(0xa1)},
	{"a superscript digit, COM with U+00B2", "COM\u00b2", hasChar(0xb2)},
	{"a superscript digit, LPT with U+00B9", "lpt\u00b9.tar.gz", hasChar(0xb9)},
	{"a heart with the variation selector U+FE0F", "\u2764\ufe0f", hasChar(0x2764)},
	{"an emoji sequence joined with U+200D", "\U0001f468\u200d\U0001f469", hasChar(0x1f468)},
	{"the last code point, U+10FFFF", "\U0010ffff", hasChar(0x10ffff)},
	{"a space before a device name's extension", "nul .txt", hasChar(' ')},
	{"a trailing space after a device name", "com1 ", hasChar(' ')},
	{"a drive, C:x", "C:x", hasChar(':')},
	{"a drive path, C:\\x", `C:\x`, hasChar(':')},

	// bytes that are not UTF-8: named by the byte, never by a character
	{"a lone 0xff byte", "\xff", hasByte(0xff)},
	{"0xff inside", "a\xffb", hasByte(0xff)},
	{"a lone continuation byte, 0x80", "\x80", hasByte(0x80)},
	{"a truncated two-byte sequence", "\xc3", hasByte(0xc3)},
	{"a truncated three-byte sequence inside", "a\xe2\x82b", hasByte(0xe2)},
	{"an overlong encoding of a slash", "\xc0\xaf", hasByte(0xc0)},
	{"an encoded surrogate", "\xed\xa0\x80", hasByte(0xed)},
	{"a code point above U+10FFFF", "\xf4\x90\x80\x80", hasByte(0xf4)},
	{"invalid UTF-8 at the end of an otherwise fine name", "abc.json\x80", hasByte(0x80)},
	{"invalid UTF-8 after valid UTF-8 (the first bad byte is named)", "é\xff", hasChar(0xe9)},

	// the first bad byte wins over the length: a name that is too long and also holds one
	{"a bad byte in a name of 300 bytes", rep("a", 299) + " ", hasChar(' ')},

	// length, in bytes: the 256th byte is refused
	{"256 ASCII bytes", rep("a", 256), tooLong(256)},
	{"1000 ASCII bytes", rep("a", 1000), tooLong(1000)},
	{"256 dots and a letter", rep(".", 255) + "a", tooLong(256)},
	{"256 hyphens", rep("-", 256), tooLong(256)},

	// an end with a dot
	{"trailing dot", "a.", whyTrailing},
	{"trailing dot after an extension", "a.json.", whyTrailing},
	{"two trailing dots", "a..", whyTrailing},
	{"only dots, three of them", "...", whyTrailing},
	{"a dot file with a trailing dot", ".a.", whyTrailing},
	{"254 letters and a trailing dot, 255 bytes", rep("a", 254) + ".", whyTrailing},
}

// deviceNames are the names that Windows reserves for a device (Microsoft, "Naming Files, Paths,
// and Namespaces"): CON, PRN, AUX, NUL, COM1 to COM9, LPT1 to LPT9 (the superscript digits cannot
// be in a name).
var deviceNames = func() []string {
	out := []string{"CON", "PRN", "AUX", "NUL"}
	for d := '1'; d <= '9'; d++ {
		out = append(out, "COM"+string(d), "LPT"+string(d))
	}
	return out
}()

// caseForms gives a name in upper case, lower case, with a capital first letter and in
// alternating case (the first letter lower).
func caseForms(s string) []string {
	title, alt := []byte(strings.ToLower(s)), []byte(strings.ToLower(s))
	title[0] -= 'a' - 'A'
	for i := 1; i < len(alt); i += 2 {
		alt[i] = strings.ToUpper(string(alt[i]))[0]
	}
	return []string{strings.ToUpper(s), strings.ToLower(s), string(title), string(alt)}
}

// refusedDeviceNames holds every device name in four spellings of case, alone, with one
// extension, with two extensions, with a hidden-looking extension and with a trailing dot (a name
// that the rule of the trailing dot refuses as well: the device rule comes first).
var refusedDeviceNames = func() []nameRow {
	var out []nameRow
	for _, d := range deviceNames {
		for _, n := range caseForms(d) {
			out = append(out,
				nameRow{"device name " + n, n, whyDevice},
				nameRow{"device name " + n + " with an extension", n + ".txt", whyDevice},
				nameRow{"device name " + n + " with two extensions", n + ".tar.gz", whyDevice},
				nameRow{"device name " + n + " with an extension that is a dot", n + "..", whyDevice},
				nameRow{"device name " + n + " with a trailing dot", n + ".", whyDevice},
			)
		}
	}
	return out
}()

// refusedPathForms are paths that are refused because of their shape and not because of one
// name. Every one is refused by every method that takes a path, with the text of its shape.
var refusedPathForms = []struct{ why, path, text string }{
	{"empty", "", invalidPrefix + "empty path"},
	{"a separator alone", "/", pathText("/", tailAbsolute)},
	{"two separators", "//", pathText("//", tailAbsolute)},
	{"three separators", "///", pathText("///", tailAbsolute)},
	{"an absolute path", "/b/d/x", pathText("/b/d/x", tailAbsolute)},
	{"an absolute path with a doubled leading separator", "//b/d/f", pathText("//b/d/f", tailAbsolute)},
	{"an absolute path with a dot", "/./b", pathText("/./b", tailAbsolute)},
	{"trailing separator", "b/d/x/", pathText("b/d/x/", tailSeparator)},
	{"trailing separator, no folder", "x/", pathText("x/", tailSeparator)},
	{"two trailing separators", "b/d/x//", pathText("b/d/x//", tailSeparator)},
	{"a dot as the last element", "b/d/.", pathText("b/d/.", tailDot)},
	{"a dot as a middle element", "b/d/./f", pathText("b/d/./f", tailDot)},
	{"a dot as the first element", "./f", pathText("./f", tailDot)},
	{"a dot alone", ".", pathText(".", tailDot)},
	{"two dots as the last element", "b/d/..", pathText("b/d/..", tailDotDot)},
	{"two dots as a middle element", "b/d/../f", pathText("b/d/../f", tailDotDot)},
	{"two dots as the first element", "../f", pathText("../f", tailDotDot)},
	{"two dots alone", "..", pathText("..", tailDotDot)},
	{"two dots after a folder", "b/../d/f", pathText("b/../d/f", tailDotDot)},
	{"an empty element in the middle", "b/d//f", pathText("b/d//f", tailEmptyElem)},
	{"an empty element near the start", "b//d/f", pathText("b//d/f", tailEmptyElem)},
	{"an empty element in a short path", "a//b", pathText("a//b", tailEmptyElem)},
	{"a backslash, as a separator on Windows, is a character that a name may not hold", `b\d\x`, elemText(`b\d\x`, hasChar('\\'))},
	{"a drive", "C:x", elemText("C:x", hasChar(':'))},
	{"a drive with a backslash path", `C:\x`, elemText(`C:\x`, hasChar(':'))},
	{"a network name", `\\host\share`, elemText(`\\host\share`, hasChar('\\'))},
	{"the prefix of a temporary name, the last element", "b/d/.rt-abcdefghijk", pathText("b/d/.rt-abcdefghijk", tailPrefix)},
	{"the prefix alone, the last element", "b/d/.rt-", pathText("b/d/.rt-", tailPrefix)},
	{"the prefix in capitals, the last element", "b/d/.RT-x", pathText("b/d/.RT-x", tailPrefix)},
	{"the prefix with a capital R, the last element", "b/d/.Rt-x", pathText("b/d/.Rt-x", tailPrefix)},
	{"the prefix with a capital T, the last element", "b/d/.rT-abcdefghijk", pathText("b/d/.rT-abcdefghijk", tailPrefix)},
	{"the prefix in capitals alone, the last element", "b/d/.RT-", pathText("b/d/.RT-", tailPrefix)},
	{"the prefix, a path of one element", ".rt-x", pathText(".rt-x", tailPrefix)},
	{"the prefix in capitals, a path of one element", ".RT-x", pathText(".RT-x", tailPrefix)},
}

// ---- where a name stands --------------------------------------------------------------------

// nameUse is one place a name can stand in a call.
type nameUse struct {
	label string
	// do makes the call. p is the whole path given to it.
	do func(t *testing.T, w *fsx.Writer, p string) error
	// extra lists what a success leaves besides the path itself, relative to it.
	extra []string
	// check says what the path must hold after a success.
	check func(t *testing.T, img *image, at string)
}

var pathUses = []nameUse{
	{
		label: "WriteFile",
		do: func(_ *testing.T, w *fsx.Writer, p string) error {
			return w.WriteFile(p, []byte("data"), 0o600)
		},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			if got := mustFile(t, img, at); string(got) != "data" {
				t.Fatalf("%s holds %q", at, got)
			}
		},
	},
	{
		label: "Mkdir",
		do: func(_ *testing.T, w *fsx.Writer, p string) error {
			return w.Mkdir(p, 0o700)
		},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			if !img.isDir(at) {
				t.Fatalf("%s is not a folder", at)
			}
		},
	},
	{
		label: "CreateJournal",
		do: func(t *testing.T, w *fsx.Writer, p string) error {
			j, err := w.CreateJournal(p)
			if err != nil {
				if j != nil {
					t.Errorf("CreateJournal %q returned a journal with an error", p)
				}
				return err
			}
			if err := j.Append([]byte("one")); err != nil {
				_ = j.Close()
				return err
			}
			return j.Close()
		},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			lines, partial, err := img.readJournal(at)
			if err != nil || len(lines) != 1 || string(lines[0]) != "one" || partial != nil {
				t.Fatalf("the journal %s holds %q and %q (%v)", at, lines, partial, err)
			}
		},
	},
	{
		label: "WriteSet folder",
		do: func(_ *testing.T, w *fsx.Writer, p string) error {
			return w.WriteSet(p, []fsx.NewFile{{Name: "a.json", Data: []byte("data"), Perm: 0o600}})
		},
		extra: []string{"a.json"},
		check: func(t *testing.T, img *image, at string) {
			t.Helper()
			if got := mustFile(t, img, at+"/a.json"); string(got) != "data" {
				t.Fatalf("%s/a.json holds %q", at, got)
			}
		},
	},
}

// placement is the place of a name in a path: the last element, the folder in the middle, the
// first element of a path with a file in it, and a path that is the name alone.
type placement struct {
	label string
	// dirs are the folders that exist before, parents first, for the name n.
	dirs func(n string) []string
	path func(n string) string
	// last says that n is the last element of the path (the temporary-name rule applies to it).
	last bool
}

var placements = []placement{
	{"last element", func(string) []string { return []string{"b", "b/d"} }, func(n string) string { return "b/d/" + n }, true},
	{"middle element", func(n string) []string { return []string{"b", "b/" + n} }, func(n string) string { return "b/" + n + "/f" }, false},
	{"first element", func(n string) []string { return []string{n} }, func(n string) string { return n + "/f" }, false},
	{"the name alone", func(string) []string { return nil }, func(n string) string { return n }, true},
}

// requireRefused checks what every refused call has in common: an error that wraps ErrInvalid
// and is not a stop, no call to the file system, and a writer that goes on.
func requireRefused(t *testing.T, f *memFS, w *fsx.Writer, err error) {
	t.Helper()
	if !errors.Is(err, fsx.ErrInvalid) {
		t.Fatalf("got %v, want an error that wraps ErrInvalid", err)
	}
	var fe *fsx.Error
	if errors.As(err, &fe) || errors.Is(err, fsx.ErrStopped) {
		t.Fatalf("a refused argument is an *fsx.Error (a stop): %v", err)
	}
	if f.opCount() != 0 {
		t.Fatalf("a refused argument reached the file system: %v", f.opList())
	}
	requireOpen(t, f, 0)
	requirePrintableASCII(t, err.Error())
	if err := w.WriteFile("b/d/ok.json", []byte("ok"), 0o600); err != nil {
		t.Fatalf("the writer stopped after a refused argument: %v", err)
	}
	if got := mustFile(t, f.Live(), "b/d/ok.json"); string(got) != "ok" {
		t.Fatalf("the following write holds %q", got)
	}
}

// refuseInEveryElementOfEveryPath: each refused name, in the last element, in a folder in the
// middle, in the first element and alone, for each method that takes a path: the refusal is
// ErrInvalid with the exact text, no file system call is made, and the writer goes on.
func refuseInEveryElementOfEveryPath(t *testing.T, rows []nameRow) {
	t.Helper()
	for _, row := range rows {
		for _, use := range pathUses {
			for _, pl := range placements {
				t.Run(row.why+"/"+use.label+"/"+pl.label, func(t *testing.T) {
					f := newMemFS("b", "b/d")
					w := newWriter(t, f, 1)
					p := pl.path(row.name)
					err := use.do(t, w, p)
					requireRefused(t, f, w, err)
					if want := elemText(p, row.reason); err.Error() != want {
						t.Fatalf("the text is\n  %s\nwant\n  %s", err.Error(), want)
					}
				})
			}
		}
	}
}

// refuseAsSetFiles: each refused name as the name of a file of a set: alone, last after a good
// name, first before one, and between good names; with the exact text.
func refuseAsSetFiles(t *testing.T, rows []nameRow) {
	t.Helper()
	good := fsx.NewFile{Name: "good.json", Data: []byte("x"), Perm: 0o600}
	for _, row := range rows {
		bad := fsx.NewFile{Name: row.name, Data: []byte("x"), Perm: 0o600}
		for label, files := range map[string][]fsx.NewFile{
			"alone":              {bad},
			"after a good name":  {good, bad},
			"before a good name": {bad, good},
			"between good names": {good, bad, {Name: "also-good.json", Data: []byte("x"), Perm: 0o600}},
		} {
			t.Run(row.why+"/"+label, func(t *testing.T) {
				f := newMemFS("b", "b/d")
				w := newWriter(t, f, 1)
				err := w.WriteSet("b/d/s", files)
				requireRefused(t, f, w, err)
				if want := fileText(row.name, row.reason); err.Error() != want {
					t.Fatalf("the text is\n  %s\nwant\n  %s", err.Error(), want)
				}
			})
		}
	}
}

func TestRefusedBytesInEveryElementOfEveryPath(t *testing.T) {
	refuseInEveryElementOfEveryPath(t, refusedBytes(false))
}

func TestRefusedBytesAsSetFiles(t *testing.T) { refuseAsSetFiles(t, refusedBytes(true)) }

func TestRefusedOtherNamesInEveryElementOfEveryPath(t *testing.T) {
	refuseInEveryElementOfEveryPath(t, refusedOther)
}

func TestRefusedOtherNamesAsSetFiles(t *testing.T) { refuseAsSetFiles(t, refusedOther) }

func TestRefusedDeviceNamesInEveryElementOfEveryPath(t *testing.T) {
	refuseInEveryElementOfEveryPath(t, refusedDeviceNames)
}

func TestRefusedDeviceNamesAsSetFiles(t *testing.T) { refuseAsSetFiles(t, refusedDeviceNames) }

// TestTheTextsAreTheseWords pins a few texts word for word, so that the helpers above, which
// build the others, cannot drift with the source.
func TestTheTextsAreTheseWords(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{elemText("b/a b/f", hasChar(' ')), `fsx: invalid argument: path "b/a b/f" has an element that has the character U+0020, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{elemText("b/a:b", hasChar(':')), `fsx: invalid argument: path "b/a:b" has an element that has the character U+003A (:), which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{elemText("b/a\x01b", hasChar(1)), `fsx: invalid argument: path "b/a\x01b" has an element that has the character U+0001, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{elemText("b/\xffb", hasByte(0xff)), `fsx: invalid argument: path "b/\xffb" has an element that has the byte 0xFF, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{elemText("é", hasChar(0xe9)), `fsx: invalid argument: path "\u00e9" has an element that has the character U+00E9, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{fileText("a/b", hasChar('/')), `fsx: invalid argument: file name "a/b" has the character U+002F (/), which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{fileText("a.", whyTrailing), `fsx: invalid argument: file name "a." ends with a dot, which the stick's file system can remove`},
		{fileText("aux", whyDevice), `fsx: invalid argument: file name "aux" is a device name that Windows reserves`},
		{fileText("", whyNotPlain), `fsx: invalid argument: file name "" is not one plain name`},
		{elemText("b/"+rep("a", 256), tooLong(256)), `fsx: invalid argument: path "b/` + rep("a", 256) + `" has an element that is 256 bytes long, more than the 255 a workstation file system holds`},
		{pathText("b/.rt-x", tailPrefix), `fsx: invalid argument: path "b/.rt-x" has the prefix of a temporary name`},
		{pathText("/b", tailAbsolute), `fsx: invalid argument: path "/b" is absolute; a path is relative to the root`},
		{invalidPrefix + "empty path", `fsx: invalid argument: empty path`},
	} {
		if c.got != c.want {
			t.Errorf("the helper says\n  %s\nthe pinned text is\n  %s", c.got, c.want)
		}
	}
}

// TestRefusedShapesOfAPath: the paths that mean more than one thing, for each method, with the
// text of their shape.
func TestRefusedShapesOfAPath(t *testing.T) {
	for _, row := range refusedPathForms {
		for _, use := range pathUses {
			t.Run(row.why+"/"+use.label, func(t *testing.T) {
				f := newMemFS("b", "b/d")
				w := newWriter(t, f, 1)
				err := use.do(t, w, row.path)
				requireRefused(t, f, w, err)
				if err.Error() != row.text {
					t.Fatalf("the text is\n  %s\nwant\n  %s", err.Error(), row.text)
				}
			})
		}
	}
}

// notPlainNames are names of a file of a set that are not one plain name.
var notPlainNames = []struct{ why, name, text string }{
	{"empty", "", fileText("", whyNotPlain)},
	{"a dot", ".", fileText(".", whyNotPlain)},
	{"two dots", "..", fileText("..", whyNotPlain)},
	{"a slash inside", "a/b", fileText("a/b", hasChar('/'))},
	{"a leading slash", "/a", fileText("/a", hasChar('/'))},
	{"a trailing slash", "a/", fileText("a/", hasChar('/'))},
	{"a doubled slash", "a//b", fileText("a//b", hasChar('/'))},
	{"a parent and a name", "../a", fileText("../a", hasChar('/'))},
	{"a current folder and a name", "./a", fileText("./a", hasChar('/'))},
	{"a slash alone", "/", fileText("/", hasChar('/'))},
	{"the prefix of a temporary name", ".rt-abcdefghijk", fileText(".rt-abcdefghijk", whyNotPlain)},
	{"the prefix of a temporary name, short", ".rt-x", fileText(".rt-x", whyNotPlain)},
	{"the prefix alone", ".rt-", fileText(".rt-", whyNotPlain)},
	{"the prefix in capitals", ".RT-x", fileText(".RT-x", whyNotPlain)},
	{"the prefix with a capital R", ".Rt-x", fileText(".Rt-x", whyNotPlain)},
	{"the prefix with a capital T", ".rT-abcdefghijk", fileText(".rT-abcdefghijk", whyNotPlain)},
	{"the prefix in capitals alone", ".RT-", fileText(".RT-", whyNotPlain)},
}

func TestRefusedNamesThatAreNotOnePlainNameAsSetFiles(t *testing.T) {
	for _, c := range notPlainNames {
		t.Run(c.why, func(t *testing.T) {
			f := newMemFS("b", "b/d")
			w := newWriter(t, f, 1)
			err := w.WriteSet("b/d/s", []fsx.NewFile{{Name: "good", Perm: 0o600}, {Name: c.name, Perm: 0o600}})
			requireRefused(t, f, w, err)
			if err.Error() != c.text {
				t.Fatalf("the text is\n  %s\nwant\n  %s", err.Error(), c.text)
			}
		})
	}
}

// TestTheFirstFaultOfAPathIsTheOneNamed: a path with two faults is refused for the first element
// that has one, left to right, and the shape of the whole path (a trailing separator, an
// absolute path) before any element.
func TestTheFirstFaultOfAPathIsTheOneNamed(t *testing.T) {
	for _, c := range []struct{ path, text string }{
		{"a b/c d", elemText("a b/c d", hasChar(' '))},
		{"ok/a:b/c.", elemText("ok/a:b/c.", hasChar(':'))},
		{"aux/c.", elemText("aux/c.", whyDevice)},
		{"a./aux", elemText("a./aux", whyTrailing)},
		{"b//a b", pathText("b//a b", tailEmptyElem)},
		{"a b//c", elemText("a b//c", hasChar(' '))},
		{"a b/../c", elemText("a b/../c", hasChar(' '))},
		{"a b/", pathText("a b/", tailSeparator)},
		{"/a b", pathText("/a b", tailAbsolute)},
		{"a b/.rt-x", elemText("a b/.rt-x", hasChar(' '))},
	} {
		f := newMemFS("b")
		w := newWriter(t, f, 1)
		err := w.WriteFile(c.path, nil, 0o600)
		if err == nil || err.Error() != c.text {
			t.Errorf("WriteFile(%q): %v, want\n  %s", c.path, err, c.text)
		}
	}
}

// TestSetNamesThatDifferOnlyByCaseAreRefused: exFAT compares names after up-casing them, so
// two such names are one entry there. Within one set the writer refuses the pair itself.
func TestSetNamesThatDifferOnlyByCaseAreRefused(t *testing.T) {
	nf := func(n string) fsx.NewFile { return fsx.NewFile{Name: n, Data: []byte("x"), Perm: 0o600} }
	for _, c := range []struct {
		why    string
		files  []fsx.NewFile
		second string // the name that the text names: the one that came second
	}{
		{"the first upper, the second lower", []fsx.NewFile{nf("Keys.json"), nf("keys.json")}, "keys.json"},
		{"the first lower, the second upper", []fsx.NewFile{nf("keys.json"), nf("Keys.json")}, "Keys.json"},
		{"all upper against all lower", []fsx.NewFile{nf("KEYS.JSON"), nf("keys.json")}, "keys.json"},
		{"a case that differs inside", []fsx.NewFile{nf("kEys.json"), nf("keYs.json")}, "keYs.json"},
		{"not next to each other", []fsx.NewFile{nf("keys.json"), nf("root.json"), nf("KEYS.json")}, "KEYS.json"},
		{"the last against the first of four", []fsx.NewFile{nf("a"), nf("b"), nf("c"), nf("A")}, "A"},
		{"a pair after a good name", []fsx.NewFile{nf("good.json"), nf("Ab"), nf("aB")}, "aB"},
		{"the same name twice", []fsx.NewFile{nf("a"), nf("a")}, "a"},
		{"digits and the other characters are their own case", []fsx.NewFile{nf("a-1_B"), nf("A-1_b")}, "A-1_b"},
	} {
		t.Run(c.why, func(t *testing.T) {
			f := newMemFS("b", "b/d")
			w := newWriter(t, f, 1)
			err := w.WriteSet("b/d/s", c.files)
			requireRefused(t, f, w, err)
			if want := fileText(c.second, "is given twice"); err.Error() != want {
				t.Fatalf("the text is\n  %s\nwant\n  %s", err.Error(), want)
			}
		})
	}
}

// TestSetNamesThatAreNotTheSameEntryAreAccepted: names that differ by more than case, and names
// that stand for the same letters in no way.
func TestSetNamesThatAreNotTheSameEntryAreAccepted(t *testing.T) {
	nf := func(n string) fsx.NewFile { return fsx.NewFile{Name: n, Data: []byte("x" + n), Perm: 0o600} }
	for _, c := range []struct {
		why   string
		names []string
	}{
		{"names that differ by more than case", []string{"keys.json", "keys.json.bak", "key.json"}},
		{"a name and the same name in a longer form", []string{"a", "aa", "A.b"}},
		{"dot files", []string{".a", ".b", "a", "b"}},
		{"a hyphen and an underscore are two names", []string{"a-b", "a_b", "a.b"}},
		{"the digit zero and the letter o", []string{"0", "o", "O1"}},
	} {
		t.Run(c.why, func(t *testing.T) {
			f := newMemFS("b", "b/d")
			w := newWriter(t, f, 1)
			var files []fsx.NewFile
			for _, n := range c.names {
				files = append(files, nf(n))
			}
			if err := w.WriteSet("b/d/s", files); err != nil {
				t.Fatalf("WriteSet: %v", err)
			}
			live := f.Live()
			for _, n := range c.names {
				if got := mustFile(t, live, "b/d/s/"+n); string(got) != "x"+n {
					t.Fatalf("%q holds %q", n, got)
				}
			}
		})
	}
}

// acceptedNames are single names that the writer must accept and then write under exactly that
// name. A leading dot, dots inside, and ".rt" without the hyphen are not refused; nor is a name
// of 255 bytes.
var acceptedNames = []struct{ why, name string }{
	{"one letter", "x"},
	{"one digit", "7"},
	{"one hyphen", "-"},
	{"one underscore", "_"},
	{"an extension", "a.b"},
	{"a dot file", ".hidden"},
	{"a dot file with an extension", ".a.json"},
	{"two dots at the start", "..a"},
	{"two dots inside", "a..b"},
	{"a layout name, yaml", "ritueel.yaml"},
	{"a layout name, journal", "births.jsonl"},
	{"a layout name, record", "record.json"},
	{"a layout name, a numbered trust set", "0007-acme"},
	{"hyphens and underscores", "a-b_c"},
	{"a hyphen first", "-a"},
	{"an underscore first", "_a"},
	{"a hyphen last", "a-"},
	{"an underscore last", "a_"},
	{"upper case", "Keys.json"},
	{"every kind at once", "Az09._-"},
	{"the temporary prefix without its hyphen", ".rt"},
	{"the temporary prefix with another character", ".rt_a"},
	{"the temporary prefix not at the start", "x.rt-abcdefghijk"},
	{"the temporary prefix in capitals without its hyphen", ".RT"},
	{"the temporary prefix in capitals not at the start", "x.RT-abcdefghijk"},
	{"rt with a hyphen and no dot", "rt-abc"},
	{"254 ASCII bytes", rep("a", 254)},
	{"255 ASCII bytes", rep("a", 255)},
	{"255 bytes of every kind", rep("A0._-", 51)},
	{"254 dots and a letter, 255 bytes", rep(".", 254) + "a"},

	// names that contain a device name and are not one: Windows reserves the whole name, or the
	// part before the first dot
	{"auxiliary", "auxiliary"},
	{"Auxiliary", "Auxiliary"},
	{"com10, two digits", "com10"},
	{"COM10 in capitals", "COM10"},
	{"lpt0, the digit zero, not on Microsoft's list", "lpt0"},
	{"com0, the digit zero, not on Microsoft's list", "com0"},
	{"com alone", "com"},
	{"lpt alone", "lpt"},
	{"conn", "conn"},
	{"console", "console"},
	{"con1, not a device name", "con1"},
	{"CON1 in capitals", "CON1"},
	{"a dot file named con", ".con"},
	{"a dot file named nul with an extension", ".nul.txt"},
	{"a device name after the first dot", "a.con"},
	{"a device name in the middle", "a.nul.txt"},
	{"nul with a hyphen and a digit", "nul-1"},
	{"nul with a digit", "nul1"},
	{"aux with a digit", "aux1"},
	{"prn with an underscore", "prn_a"},
	{"con with a hyphen", "con-1"},
	{"com1 with a letter", "com1x"},
	{"a device name before a hyphen", "nul-x.txt"},
}

// acceptedNotLast are names that are fine for a folder but not as the last element of a path
// nor as the name of a file of a set: the prefix of a temporary name.
var acceptedNotLast = []struct{ why, name string }{
	{"the temporary prefix and 11 characters", ".rt-abcdefghijk"},
	{"the temporary prefix and one character", ".rt-x"},
	{"the temporary prefix alone", ".rt-"},
	{"the temporary prefix in capitals", ".RT-x"},
	{"the temporary prefix with a capital R", ".Rt-x"},
	{"the temporary prefix with a capital T", ".rT-abcdefghijk"},
	{"the temporary prefix in capitals alone", ".RT-"},
}

// TestAcceptedNamesAreWrittenAtExactlyThatName: each accepted name, in each place and for each
// method, makes a write that succeeds and leaves the file or the folder at exactly that name,
// and nothing else but the folders that were there before: no temporary name is left.
func TestAcceptedNamesAreWrittenAtExactlyThatName(t *testing.T) {
	for _, group := range []struct {
		rows    []struct{ why, name string }
		lastToo bool
	}{
		{rows: acceptedNames, lastToo: true},
		{rows: acceptedNotLast, lastToo: false},
	} {
		for _, row := range group.rows {
			for _, use := range pathUses {
				for _, pl := range placements {
					if pl.last && !group.lastToo {
						continue
					}
					t.Run(row.why+"/"+use.label+"/"+pl.label, func(t *testing.T) {
						acceptedAt(t, use, pl, row.name)
					})
				}
			}
		}
	}
}

// acceptedAt writes the name in the place with the method, and checks the tree.
func acceptedAt(t *testing.T, use nameUse, pl placement, name string) {
	t.Helper()
	f := newMemFS(pl.dirs(name)...)
	w := newWriter(t, f, 1)
	p := pl.path(name)
	if err := use.do(t, w, p); err != nil {
		t.Fatalf("%s %q: got %v, want the write to succeed", use.label, p, err)
	}
	use.check(t, f.Live(), p)
	want := slices.Clone(pl.dirs(name))
	want = append(want, p)
	for _, x := range use.extra {
		want = append(want, p+"/"+x)
	}
	slices.Sort(want)
	want = slices.Compact(want)
	if got := f.Live().list(); !slices.Equal(got, want) {
		t.Fatalf("the tree holds %q, want %q", got, want)
	}
	// the stop is not set: another write goes on
	if err := w.WriteFile("after.json", []byte("x"), 0o600); err != nil {
		t.Fatalf("the writer stopped: %v", err)
	}
}

// TestAcceptedNamesAsTheNameOfAFileOfASet: each accepted name as a file of a set (the folder
// of the set stays plain), beside two others.
func TestAcceptedNamesAsTheNameOfAFileOfASet(t *testing.T) {
	for _, row := range acceptedNames {
		t.Run(row.why, func(t *testing.T) {
			f := newMemFS("b", "b/d")
			w := newWriter(t, f, 1)
			files := []fsx.NewFile{
				{Name: "first.json", Data: []byte("1"), Perm: 0o600},
				{Name: row.name, Data: []byte("name " + row.name), Perm: 0o600},
				{Name: "last.json", Data: []byte("3"), Perm: 0o400},
			}
			if err := w.WriteSet("b/d/s", files); err != nil {
				t.Fatalf("got %v, want the write to succeed", err)
			}
			want := []string{"b", "b/d", "b/d/s", "b/d/s/first.json", "b/d/s/" + row.name, "b/d/s/last.json"}
			slices.Sort(want)
			if got := f.Live().list(); !slices.Equal(got, want) {
				t.Fatalf("the tree holds %q, want %q", got, want)
			}
			if got := mustFile(t, f.Live(), "b/d/s/"+row.name); string(got) != "name "+row.name {
				t.Fatalf("the file holds %q", got)
			}
		})
	}
}

// allowedChars are the 65 characters that a name may hold.
func allowedChars() []byte {
	var out []byte
	for b := 0; b < 0x80; b++ {
		if allowedByte(byte(b)) {
			out = append(out, byte(b))
		}
	}
	return out
}

func TestThereAreSixtyFiveAllowedCharacters(t *testing.T) {
	if got := len(allowedChars()); got != 65 {
		t.Fatalf("%d allowed characters, want 26 + 26 + 10 + 3 = 65", got)
	}
}

// TestEveryAllowedCharacterIsWrittenInTheFirstInnerAndLastPlace: a real write of each, with every
// method, in every place of a path, and as the name of a file of a set. The last place of the dot
// is refused by another rule (a trailing dot) and is left out; the others are named by the rest of
// the name, which holds no device name and not the temporary prefix.
func TestEveryAllowedCharacterIsWrittenInTheFirstInnerAndLastPlace(t *testing.T) {
	for _, c := range allowedChars() {
		ch := string(rune(c))
		for _, place := range []string{"first", "inner", "last", "alone"} {
			name := map[string]string{"first": ch + "x1", "inner": "x" + ch + "1", "last": "x1" + ch, "alone": ch}[place]
			if (place == "last" || place == "alone") && c == '.' {
				continue
			}
			t.Run(fmt.Sprintf("%q/%s", ch, place), func(t *testing.T) {
				for _, use := range pathUses {
					for _, pl := range placements {
						acceptedAt(t, use, pl, name)
					}
				}
				f := newMemFS("b", "b/d")
				w := newWriter(t, f, 1)
				files := []fsx.NewFile{{Name: name, Data: []byte("set " + name), Perm: 0o600}}
				if err := w.WriteSet("b/d/s", files); err != nil {
					t.Fatalf("a set file named %q: %v", name, err)
				}
				if got := mustFile(t, f.Live(), "b/d/s/"+name); string(got) != "set "+name {
					t.Fatalf("the set file holds %q", got)
				}
			})
		}
	}
}

// TestThePlainFormsOfAPathAreAccepted pins the forms that look like the refused ones but are
// not: a path with no folder, the prefix of a temporary name in a folder that is not the last
// element, a dot file.
func TestThePlainFormsOfAPathAreAccepted(t *testing.T) {
	f := newMemFS("b", "b/d", "b/.rt-dir", "b/.hidden")
	w := newWriter(t, f, 1)
	paths := []string{"b/d/x.json", "z.json", "b/.rt-dir/q.json", "b/.hidden/.s", "z"}
	for _, p := range paths {
		if err := w.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Errorf("WriteFile %q: %v", p, err)
		}
	}
	live := f.Live()
	for _, p := range paths {
		if got := mustFile(t, live, p); string(got) != p {
			t.Errorf("%s holds %q, want %q", p, got, p)
		}
	}
}

// TestLongNamesAreRefusedByTheByteLimit pins the one length limit, 255 bytes: 254 and 255 are
// accepted, 256 is refused, as the last element, as a folder, and as the name of a file of a set.
func TestLongNamesAreRefusedByTheByteLimit(t *testing.T) {
	for _, c := range []struct {
		n      int
		accept bool
	}{{1, true}, {254, true}, {255, true}, {256, false}, {257, false}, {1024, false}, {4096, false}} {
		name := rep("a", c.n)
		// as the last element, as a folder, and as the name of a file of a set
		for what, do := range map[string]func(w *fsx.Writer) error{
			"last element": func(w *fsx.Writer) error { return w.WriteFile("b/d/"+name, []byte("x"), 0o600) },
			"folder":       func(w *fsx.Writer) error { return w.WriteFile("b/"+name+"/f", []byte("x"), 0o600) },
			"set file": func(w *fsx.Writer) error {
				return w.WriteSet("b/d/s", []fsx.NewFile{{Name: name, Data: []byte("x"), Perm: 0o600}})
			},
			"set folder": func(w *fsx.Writer) error { return w.WriteSet("b/d/"+name, nil) },
			"journal":    func(w *fsx.Writer) error { _, err := w.CreateJournal("b/d/" + name); return err },
			"mkdir":      func(w *fsx.Writer) error { return w.Mkdir("b/d/"+name, 0o700) },
		} {
			f := newMemFS("b", "b/d", "b/"+name)
			w := newWriter(t, f, 1)
			err := do(w)
			switch {
			case c.accept && err != nil:
				t.Errorf("a name of %d bytes as a %s: %v, want it accepted", c.n, what, err)
			case !c.accept && !errors.Is(err, fsx.ErrInvalid):
				t.Errorf("a name of %d bytes as a %s: %v, want ErrInvalid", c.n, what, err)
			case !c.accept && !strings.Contains(err.Error(), strconv.Itoa(c.n)+" bytes long"):
				t.Errorf("a name of %d bytes as a %s: %v, want the text to say %d bytes long", c.n, what, err, c.n)
			}
		}
	}
}

// TestRefusedNameBetweenGoodWritesChangesNothing: a refusal in the middle of a run, between
// good writes, leaves the earlier files and the later writes alone.
func TestRefusedNameBetweenGoodWritesChangesNothing(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	if err := w.WriteFile("b/d/one.json", []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.opCount()
	for _, bad := range []string{"b/d/two.json.", "b/d/t:wo.json", "b/d/" + rep("a", 256), "b/d\x00/x", "b/d/\xff", "b/d/a b", "b/d/é"} {
		if err := w.WriteFile(bad, []byte("2"), 0o600); !errors.Is(err, fsx.ErrInvalid) {
			t.Fatalf("WriteFile %q = %v, want ErrInvalid", bad, err)
		}
	}
	if f.opCount() != before {
		t.Fatalf("refused names reached the file system: %v", f.opsAfter(before))
	}
	if err := w.WriteFile("b/d/three.json", []byte("3"), 0o600); err != nil {
		t.Fatal(err)
	}
	live := f.Live()
	for p, want := range map[string]string{"b/d/one.json": "1", "b/d/three.json": "3"} {
		if got := mustFile(t, live, p); string(got) != want {
			t.Fatalf("%s holds %q", p, got)
		}
	}
	want := []string{"b", "b/d", "b/d/one.json", "b/d/three.json"} // and no temporary name
	if got := live.list(); !slices.Equal(got, want) {
		t.Fatalf("the tree holds %q, want %q", got, want)
	}
}
