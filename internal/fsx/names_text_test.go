package fsx_test

// The exact text of the error of each rule, once. Several rules overlap (a trailing separator
// and an empty element; "." and ".." and a trailing dot; a device name with a trailing dot) and
// stay in the code because each gives its own, clearer text. A test that only asks for ErrInvalid
// cannot see which of the two refused the name, so a break of one rule of a pair would pass; the
// text sees it. The texts are those of writer.go; if one is reworded, change it here and say so.

import (
	"errors"
	"fmt"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

const (
	invalidPrefix = "fsx: invalid argument: "
	whyTrailing   = "ends with a dot or a space, which the stick's file system can remove"
	whyDevice     = "is a device name that Windows reserves"
	whyUTF8       = "is not valid UTF-8"
)

func whyChar(r rune) string {
	return fmt.Sprintf("has the character %q, which the stick's file system cannot hold", r)
}
func whyUnseen(r rune) string {
	return fmt.Sprintf("has the character %q, which a person cannot see or type", r)
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
		{"/b/d/a\u007fb", elemText("/b/d/a\u007fb", whyUnseen(0x7f))},
		{"/b/d/a\u0080b", elemText("/b/d/a\u0080b", whyUnseen(0x80))},
		{"/b/d/a\u009fb", elemText("/b/d/a\u009fb", whyUnseen(0x9f))},
		{"/b/d/a￾b", elemText("/b/d/a￾b", whyUnseen(0xfffe))},
		{"/b/d/a￿b", elemText("/b/d/a￿b", whyUnseen(0xffff))},
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
				if got := err.Error(); got != row.want {
					t.Fatalf("the text is\n  %q\nwant\n  %q", got, row.want)
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
		{"a\u007fb", fileText("a\u007fb", whyUnseen(0x7f))},
		{"a\u0080b", fileText("a\u0080b", whyUnseen(0x80))},
		{"a\u009fb", fileText("a\u009fb", whyUnseen(0x9f))},
		{"a￾b", fileText("a￾b", whyUnseen(0xfffe))},
		{"a￿b", fileText("a￿b", whyUnseen(0xffff))},
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
			if got := err.Error(); got != row.want {
				t.Fatalf("the text is\n  %q\nwant\n  %q", got, row.want)
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
