package fsx_test

// The exact text of the error of each rule, once. Several rules overlap (a trailing separator
// and an empty element; "." and ".." and a trailing dot; a device name with a trailing dot) and
// stay in the code because each gives its own, clearer text. A test that only asks for ErrInvalid
// cannot see which of the two refused the name, so a break of one rule of a pair would pass; the
// text sees it. The texts are those of writer.go; if one is reworded, change it here and say so.

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/fsx"
)

const (
	invalidPrefix = "fsx: invalid argument: "
	whyTrailing   = "ends with a dot or a space, which the stick's file system can remove"
	whyDevice     = "is a device name that Windows reserves"
	whyUTF8       = "is not valid UTF-8"
)

// charName is how a character stands in a text: U+XXXX, and the character itself in
// parentheses only when it is printable ASCII (a letter, a digit, a punctuation mark or a symbol
// of ASCII, not the space).
func charName(r rune) string {
	if r > 0x20 && r < 0x7f {
		return fmt.Sprintf("U+%04X (%c)", r, r)
	}
	return fmt.Sprintf("U+%04X", r)
}

func whyChar(r rune) string {
	return fmt.Sprintf("has the character %s, which the stick's file system cannot hold", charName(r))
}
func whyNotPrintable(r rune) string {
	return fmt.Sprintf("has the character %s, which is not a printable character", charName(r))
}
func whyLong(n int) string {
	return fmt.Sprintf("is %d bytes long, more than the %d a workstation file system holds", n, 255)
}

// pathText is the text of a refusal of path p: tail follows the quoted path.
func pathText(p, tail string) string { return fmt.Sprintf("%spath %q %s", invalidPrefix, p, tail) }

// elemText is the text of a refusal of an element of path p.
func elemText(p, why string) string { return pathText(p, "has an element that "+why) }

// fileText is the text of a refusal of the name of a file of a set.
func fileText(name, tail string) string {
	return fmt.Sprintf("%sfile name %q %s", invalidPrefix, name, tail)
}

const (
	tailSeparator = "ends with a separator"
	tailEmptyElem = "has an empty element (a doubled separator)"
	tailDot       = `has a "." element`
	tailDotDot    = `has a ".." element`
	tailPrefix    = "has the prefix of a temporary name"
)

// asciiAround reports whether s holds no printable character beyond ASCII: bytes that are not
// UTF-8 and characters that are not printable are written in an error text as escapes, so the
// text of an error about such a name must be printable ASCII from end to end.
func asciiAround(s string) bool {
	if !utf8.ValidString(s) {
		for _, r := range s {
			if r != utf8.RuneError && r >= 0x80 && unicode.IsPrint(r) {
				return false
			}
		}
		return true
	}
	for _, r := range s {
		if r >= 0x80 && unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// requirePrintableASCII fails when a byte of the text is not printable ASCII (0x20 to 0x7E): no
// raw control code, no raw invisible character, no raw character that a terminal could draw
// in a way that hides the text.
func requirePrintableASCII(t *testing.T, text string) {
	t.Helper()
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7e {
			t.Fatalf("the text %q has the byte %#x at %d, which is not printable ASCII", text, text[i], i)
		}
	}
}

// TestTextOfEveryRuleForAPath: each rule, once or more, with the text it gives. The same text
// comes from every method that takes a path.
func TestTextOfEveryRuleForAPath(t *testing.T) {
	rows := []struct{ input, want string }{
		{"", invalidPrefix + "empty path"},

		// the pair: a trailing separator and an empty element
		{"/b/d/x/", pathText("/b/d/x/", tailSeparator)},
		{"b/d/x/", pathText("b/d/x/", tailSeparator)},
		{"x/", pathText("x/", tailSeparator)},
		{"/", pathText("/", tailSeparator)},
		{"/b/d/x//", pathText("/b/d/x//", tailSeparator)},
		{"a//b", pathText("a//b", tailEmptyElem)},
		{"//x", pathText("//x", tailEmptyElem)},
		{"/b/d//f", pathText("/b/d//f", tailEmptyElem)},
		{"/b//d/f", pathText("/b//d/f", tailEmptyElem)},

		// the pair: "." and ".." against a trailing dot
		{"a/./b", pathText("a/./b", tailDot)},
		{"/b/d/.", pathText("/b/d/.", tailDot)},
		{".", pathText(".", tailDot)},
		{"a/../b", pathText("a/../b", tailDotDot)},
		{"/b/d/..", pathText("/b/d/..", tailDotDot)},
		{"..", pathText("..", tailDotDot)},
		{"a.", elemText("a.", whyTrailing)},
		{"/b/d/a.json.", elemText("/b/d/a.json.", whyTrailing)},
		{"/b/a./c", elemText("/b/a./c", whyTrailing)},
		{"a ", elemText("a ", whyTrailing)},
		{"...", elemText("...", whyTrailing)},

		// one name
		{"a\xffb", elemText("a\xffb", whyUTF8)},
		{"/b/\xff/f", elemText("/b/\xff/f", whyUTF8)},
		// the form of a character, written out and not built by the helpers: U+XXXX, with the
		// character in parentheses only when it is printable ASCII
		{"a\x00b", `fsx: invalid argument: path "a\x00b" has an element that has the character U+0000, which the stick's file system cannot hold`},
		{"/b/d/a:b", `fsx: invalid argument: path "/b/d/a:b" has an element that has the character U+003A (:), which the stick's file system cannot hold`},
		{`/b/d/a\b`, `fsx: invalid argument: path "/b/d/a\\b" has an element that has the character U+005C (\), which the stick's file system cannot hold`},
		{"/b/d/a\u007fb", `fsx: invalid argument: path "/b/d/a\x7fb" has an element that has the character U+007F, which is not a printable character`},
		{"/b/d/a\u00a0b", `fsx: invalid argument: path "/b/d/a\u00a0b" has an element that has the character U+00A0, which is not a printable character`},
		{"/b/d/a\u200bb", `fsx: invalid argument: path "/b/d/a\u200bb" has an element that has the character U+200B, which is not a printable character`},
		{"/b/d/a\ue000b", `fsx: invalid argument: path "/b/d/a\ue000b" has an element that has the character U+E000, which is not a printable character`},
		{"/b/d/a\u0378b", `fsx: invalid argument: path "/b/d/a\u0378b" has an element that has the character U+0378, which is not a printable character`},
		{"a\x00b", elemText("a\x00b", whyChar(0))},
		{"/b/d/a\x1f", elemText("/b/d/a\x1f", whyChar(0x1f))},
		{"/b/d/a\tb", elemText("/b/d/a\tb", whyChar('\t'))},
		{`/b/d/a"b`, elemText(`/b/d/a"b`, whyChar('"'))},
		{"/b/d/a*b", elemText("/b/d/a*b", whyChar('*'))},
		{"/b/d/a:b", elemText("/b/d/a:b", whyChar(':'))},
		{"/b/d/a<b", elemText("/b/d/a<b", whyChar('<'))},
		{"/b/d/a>b", elemText("/b/d/a>b", whyChar('>'))},
		{"/b/d/a?b", elemText("/b/d/a?b", whyChar('?'))},
		{`/b/d/a\b`, elemText(`/b/d/a\b`, whyChar('\\'))},
		{"/b/d/a|b", elemText("/b/d/a|b", whyChar('|'))},
		{"/b/a:b/f", elemText("/b/a:b/f", whyChar(':'))},
		{"/b/d/a\u007fb", elemText("/b/d/a\u007fb", whyNotPrintable(0x7f))},
		{"/b/d/a\u0080b", elemText("/b/d/a\u0080b", whyNotPrintable(0x80))},
		{"/b/d/a\u009fb", elemText("/b/d/a\u009fb", whyNotPrintable(0x9f))},
		{"/b/d/a\ufffeb", elemText("/b/d/a\ufffeb", whyNotPrintable(0xfffe))},
		{"/b/d/a\uffffb", elemText("/b/d/a\uffffb", whyNotPrintable(0xffff))},
		{"/b/d/a\u00adb", elemText("/b/d/a\u00adb", whyNotPrintable(0xad))},
		{"/b/d/a\u200db", elemText("/b/d/a\u200db", whyNotPrintable(0x200d))},
		{"/b/d/a\u200eb", elemText("/b/d/a\u200eb", whyNotPrintable(0x200e))},
		{"/b/d/a\u200fb", elemText("/b/d/a\u200fb", whyNotPrintable(0x200f))},
		{"/b/d/a\u2028b", elemText("/b/d/a\u2028b", whyNotPrintable(0x2028))},
		{"/b/d/a\u2029b", elemText("/b/d/a\u2029b", whyNotPrintable(0x2029))},
		{"/b/d/a\ufeffb", elemText("/b/d/a\ufeffb", whyNotPrintable(0xfeff))},
		{"/b/d/a\u3000b", elemText("/b/d/a\u3000b", whyNotPrintable(0x3000))},
		{"/b/d/a\U000f0000b", elemText("/b/d/a\U000f0000b", whyNotPrintable(0xf0000))},
		{"/b/d/a\U0010ffffb", elemText("/b/d/a\U0010ffffb", whyNotPrintable(0x10ffff))},
		{"/b/d/\U0001f468\u200d\U0001f469", elemText("/b/d/\U0001f468\u200d\U0001f469", whyNotPrintable(0x200d))},
		{"/b/d/" + ascii256, elemText("/b/d/"+ascii256, whyLong(256))},
		{"/b/" + eAcute128 + "/f", elemText("/b/"+eAcute128+"/f", whyLong(256))},
		{"/b/d/" + emoji127a, elemText("/b/d/"+emoji127a, whyLong(509))},

		// the device names, with the device text and in every position
		{"/b/d/aux", elemText("/b/d/aux", whyDevice)},
		{"/b/d/Nul.txt", elemText("/b/d/Nul.txt", whyDevice)},
		{"/b/d/cOm1.tar.gz", elemText("/b/d/cOm1.tar.gz", whyDevice)},
		{"/b/d/LPT9", elemText("/b/d/LPT9", whyDevice)},
		{"/b/d/COM¹", elemText("/b/d/COM¹", whyDevice)},
		{"/b/d/lpt³.txt", elemText("/b/d/lpt³.txt", whyDevice)},
		{"/b/CON/f", elemText("/b/CON/f", whyDevice)},
		{"prn/d/f", elemText("prn/d/f", whyDevice)},
		// a device name with a trailing dot meets two rules; the device rule comes first
		{"/b/d/nul.", elemText("/b/d/nul.", whyDevice)},
		// spaces before the extension or at the end: Windows removes them, and the device
		// rule comes before the rule of the trailing space
		{"/b/d/nul .txt", elemText("/b/d/nul .txt", whyDevice)},
		{"/b/d/NUL  .tar.gz", elemText("/b/d/NUL  .tar.gz", whyDevice)},
		{"/b/d/nul  ", elemText("/b/d/nul  ", whyDevice)},
		{"/b/d/com1 ", elemText("/b/d/com1 ", whyDevice)},
		{"/b/d/LPT\u00b2 .txt", elemText("/b/d/LPT\u00b2 .txt", whyDevice)},
		// a name with a space in front of a device name, or a letter after the space, is not one
		// (see the accepted names), and a name that only ends with spaces keeps the other text
		{"/b/d/a  ", elemText("/b/d/a  ", whyTrailing)},

		// the prefix of a temporary name, without case, on the last element only
		{"/b/d/.rt-x", pathText("/b/d/.rt-x", tailPrefix)},
		{"/b/d/.RT-x", pathText("/b/d/.RT-x", tailPrefix)},
		{"/b/d/.Rt-abcdefghijk", pathText("/b/d/.Rt-abcdefghijk", tailPrefix)},
		{"/b/d/.rT-", pathText("/b/d/.rT-", tailPrefix)},
		{".RT-x", pathText(".RT-x", tailPrefix)},
	}
	for _, row := range rows {
		for _, use := range pathUses {
			t.Run(fmt.Sprintf("%q/%s", row.input, use.label), func(t *testing.T) {
				f := newMemFS("/b", "/b/d")
				w := &fsx.Writer{FS: cwdFS{memFS: f, base: "/b"}, Rand: newDetRand(1)}
				err := use.do(t, w, row.input)
				if !errors.Is(err, fsx.ErrInvalid) {
					t.Fatalf("got %v, want ErrInvalid", err)
				}
				got := err.Error()
				if got != row.want {
					t.Fatalf("the text is\n  %q\nwant\n  %q", got, row.want)
				}
				if asciiAround(row.input) {
					requirePrintableASCII(t, got)
				}
			})
		}
	}
}

// TestTextOfEveryRuleForTheNamesOfASet: the same for the name of a file of a set, which also
// has its own rule "one plain name" and the pair of names that differ only by case.
func TestTextOfEveryRuleForTheNamesOfASet(t *testing.T) {
	plain := func(n string) string { return fileText(n, "is not one plain name") }
	rows := []struct{ name, want string }{
		{"", plain("")},
		{".", plain(".")},
		{"..", plain("..")},
		{".rt-abcdefghijk", plain(".rt-abcdefghijk")},
		{".RT-x", plain(".RT-x")},
		{".Rt-abcdefghijk", plain(".Rt-abcdefghijk")},
		{".rT-", plain(".rT-")},
		{"a/b", fileText("a/b", whyChar('/'))},
		{"/a", fileText("/a", whyChar('/'))},
		{"a/", fileText("a/", whyChar('/'))},
		{"a\xffb", fileText("a\xffb", whyUTF8)},
		{"a\x00b", fileText("a\x00b", whyChar(0))},
		{"a\x1f", fileText("a\x1f", whyChar(0x1f))},
		{`a"b`, fileText(`a"b`, whyChar('"'))},
		{"a*b", fileText("a*b", whyChar('*'))},
		{"a:b", fileText("a:b", whyChar(':'))},
		{"a<b", fileText("a<b", whyChar('<'))},
		{"a>b", fileText("a>b", whyChar('>'))},
		{"a?b", fileText("a?b", whyChar('?'))},
		{`a\b`, fileText(`a\b`, whyChar('\\'))},
		{"a|b", fileText("a|b", whyChar('|'))},
		{"a\x00b", `fsx: invalid argument: file name "a\x00b" has the character U+0000, which the stick's file system cannot hold`},
		{"a:b", `fsx: invalid argument: file name "a:b" has the character U+003A (:), which the stick's file system cannot hold`},
		{"a/b", `fsx: invalid argument: file name "a/b" has the character U+002F (/), which the stick's file system cannot hold`},
		{"a\u007fb", `fsx: invalid argument: file name "a\x7fb" has the character U+007F, which is not a printable character`},
		{"a\u00a0b", `fsx: invalid argument: file name "a\u00a0b" has the character U+00A0, which is not a printable character`},
		{"a\u200bb", `fsx: invalid argument: file name "a\u200bb" has the character U+200B, which is not a printable character`},
		{"a\u007fb", fileText("a\u007fb", whyNotPrintable(0x7f))},
		{"a\u00adb", fileText("a\u00adb", whyNotPrintable(0xad))},
		{"a\u200db", fileText("a\u200db", whyNotPrintable(0x200d))},
		{"a\u200eb", fileText("a\u200eb", whyNotPrintable(0x200e))},
		{"a\u200fb", fileText("a\u200fb", whyNotPrintable(0x200f))},
		{"a\u2028b", fileText("a\u2028b", whyNotPrintable(0x2028))},
		{"a\u2029b", fileText("a\u2029b", whyNotPrintable(0x2029))},
		{"a\ufeffb", fileText("a\ufeffb", whyNotPrintable(0xfeff))},
		{"a\ue000b", fileText("a\ue000b", whyNotPrintable(0xe000))},
		{"a\u0378b", fileText("a\u0378b", whyNotPrintable(0x378))},
		{"nul .txt", fileText("nul .txt", whyDevice)},
		{"NUL  .tar.gz", fileText("NUL  .tar.gz", whyDevice)},
		{"nul  ", fileText("nul  ", whyDevice)},
		{"com1 ", fileText("com1 ", whyDevice)},
		{"a\u0080b", fileText("a\u0080b", whyNotPrintable(0x80))},
		{"a\u009fb", fileText("a\u009fb", whyNotPrintable(0x9f))},
		{"a\ufffeb", fileText("a\ufffeb", whyNotPrintable(0xfffe))},
		{"a\uffffb", fileText("a\uffffb", whyNotPrintable(0xffff))},
		{ascii256, fileText(ascii256, whyLong(256))},
		{eAcute128, fileText(eAcute128, whyLong(256))},
		{"aux", fileText("aux", whyDevice)},
		{"Nul.txt", fileText("Nul.txt", whyDevice)},
		{"cOm1.tar.gz", fileText("cOm1.tar.gz", whyDevice)},
		{"COM²", fileText("COM²", whyDevice)},
		{"nul.", fileText("nul.", whyDevice)},
		{"a.", fileText("a.", whyTrailing)},
		{"a ", fileText("a ", whyTrailing)},
	}
	for _, row := range rows {
		t.Run(fmt.Sprintf("%q", row.name), func(t *testing.T) {
			f := newMemFS("/b", "/b/d")
			w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
			err := w.WriteSet("/b/d/s", []fsx.NewFile{{Name: "good", Data: []byte("x"), Perm: 0o600}, {Name: row.name, Data: []byte("x"), Perm: 0o600}})
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
			got := err.Error()
			if got != row.want {
				t.Fatalf("the text is\n  %q\nwant\n  %q", got, row.want)
			}
			if asciiAround(row.name) {
				requirePrintableASCII(t, got)
			}
		})
	}
	// the pair that differs only by case: the second name is the one reported
	for _, c := range []struct{ first, second string }{{"Keys.json", "keys.json"}, {"é", "É"}, {"a", "a"}} {
		f := newMemFS("/b", "/b/d")
		w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
		err := w.WriteSet("/b/d/s", []fsx.NewFile{
			{Name: c.first, Data: []byte("x"), Perm: 0o600}, {Name: c.second, Data: []byte("x"), Perm: 0o600},
		})
		if want := fileText(c.second, "is given twice"); err == nil || err.Error() != want {
			t.Errorf("%q and %q: %v, want %q", c.first, c.second, err, want)
		}
	}
}

// TestTextOfAControlCodeIsTheTableTextAndOfTheNextUnprintableOnesIsThePrintableText: every code
// below U+0020 is in exFAT's table of invalid characters and keeps its text, whatever the
// printable rule says; U+007F and U+0080 to U+009F are not in the table and get the text of
// the printable rule. In a path and as the name of a file of a set.
func TestTextOfAControlCodeIsTheTableTextAndOfTheNextUnprintableOnesIsThePrintableText(t *testing.T) {
	var runes []rune
	for r := rune(0); r < 0x20; r++ {
		runes = append(runes, r)
	}
	for r := rune(0x7f); r <= 0x9f; r++ {
		runes = append(runes, r)
	}
	for _, r := range runes {
		why := whyNotPrintable(r)
		if r < 0x20 {
			why = whyChar(r)
		}
		name := "a" + string(r) + "b"
		f := newMemFS("/b", "/b/d")
		w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
		p := "/b/d/" + name
		if err := w.WriteFile(p, []byte("x"), 0o600); err == nil || err.Error() != elemText(p, why) {
			t.Errorf("WriteFile U+%04X: %v, want %q", r, err, elemText(p, why))
		} else {
			requirePrintableASCII(t, err.Error())
		}
		err := w.WriteSet("/b/d/s", []fsx.NewFile{{Name: name, Data: []byte("x"), Perm: 0o600}})
		if want := fileText(name, why); err == nil || err.Error() != want {
			t.Errorf("WriteSet U+%04X: %v, want %q", r, err, want)
		}
	}
}

// TestNoErrorTextHoldsARawUnprintableCharacter: for every refused name that holds no printable
// character beyond ASCII, the whole text of the error is printable ASCII, whatever the name
// holds (control codes, invisible characters, bytes that are not UTF-8): the character is
// written as U+XXXX, and the name as Go's quoted form.
func TestNoErrorTextHoldsARawUnprintableCharacter(t *testing.T) {
	rows := slices.Concat(refusedNames, unprintableRows(), refusedDeviceNames, notPlainNames)
	for _, row := range rows {
		if !asciiAround(row.name) {
			continue
		}
		f := newMemFS("/b", "/b/d")
		w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
		if !strings.Contains(row.name, "/") && row.name != "" && row.name != "." && row.name != ".." {
			err := w.WriteFile("/b/d/"+row.name, []byte("x"), 0o600)
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s: WriteFile = %v, want ErrInvalid", row.why, err)
				continue
			}
			requirePrintableASCII(t, err.Error())
		}
		err := w.WriteSet("/b/d/s", []fsx.NewFile{{Name: row.name, Data: []byte("x"), Perm: 0o600}})
		if !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("%s: WriteSet = %v, want ErrInvalid", row.why, err)
			continue
		}
		requirePrintableASCII(t, err.Error())
	}
}
