package fsx_test

// The one escape form of the text of an error: everything that is not printable ASCII (0x20 to
// 0x7E) is written as \xNN (an ASCII control code, 0x7F, and a byte that is not valid UTF-8),
// \uXXXX (any other character up to U+FFFF) or \UXXXXXXXX (above), in lower case; what is
// printable ASCII, a backslash and a quote character included, stays as it is. The path of an
// *fsx.Error is quoted with strconv.QuoteToASCII, and the names that a refusal quotes with %+q.
// These tests pin the forms with literal texts.

import (
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// textOf is the text of an *fsx.Error with the path "p" and a cause that says msg.
func textOf(msg string) string {
	return (&fsx.Error{Step: fsx.StepRead, Path: "p", Err: errors.New(msg)}).Error()
}

func TestTheCauseOfAnErrorIsEscapedInOneForm(t *testing.T) {
	for _, c := range []struct{ why, msg, want string }{
		// \xNN: an ASCII control code, DEL, and a byte that is not UTF-8
		{"a control code", "a\x01b", `a\x01b`},
		{"NUL", "a\x00b", `a\x00b`},
		{"the escape character", "\x1b[31mred", `\x1b[31mred`},
		{"a bell", "a\x07b", `a\x07b`},
		{"a line break", "a\nb", `a\x0ab`},
		{"a carriage return and a tab", "a\r\tb", `a\x0d\x09b`},
		{"DEL", "a\x7fb", `a\x7fb`},
		{"a byte 0x80 that is not UTF-8", "a\x80b", `a\x80b`},
		{"a byte 0xff", "a\xffb", `a\xffb`},
		{"a lone lead byte of a longer character", "a\xc3", `a\xc3`},
		{"an overlong encoding", "\xc0\xaf", `\xc0\xaf`},
		{"an encoded surrogate", "\xed\xa0\x80", `\xed\xa0\x80`},
		// \uXXXX: any other character up to U+FFFF, in lower case
		{"U+0080", "a\u0080b", `a\u0080b`},
		{"U+0085, the next line", "a\u0085b", `a\u0085b`},
		{"U+00A0, the no-break space", "a\u00a0b", `a\u00a0b`},
		{"U+00E9, an accent", "caf\u00e9", `caf\u00e9`},
		{"U+00FF, the last of the range", "\u00ff", `\u00ff`},
		{"U+0100, the first above it", "\u0100", `\u0100`},
		{"a Cyrillic letter that looks Latin", "\u0430", `\u0430`},
		{"a Chinese character", "\u9375", `\u9375`},
		{"the zero-width space", "a\u200bb", `a\u200bb`},
		{"the right-to-left override", "\u202e", `\u202e`},
		{"U+FFFD, validly encoded", "\ufffd", `\ufffd`},
		{"U+FFFF", "\uffff", `\uffff`},
		// \UXXXXXXXX: above U+FFFF
		{"an emoji", "a\U0001f600b", `a\U0001f600b`},
		{"U+10000", "\U00010000", `\U00010000`},
		{"U+10FFFF", "\U0010ffff", `\U0010ffff`},
		// left as they are: printable ASCII, the backslash and the quote characters
		{"printable ASCII", " !#$%&()*+,-./09:;<=>?@AZ[]^_`az{|}~", ` !#$%&()*+,-./09:;<=>?@AZ[]^_` + "`" + `az{|}~`},
		{"a backslash", `a\b`, `a\b`},
		{"a backslash and an n", `a\nb`, `a\nb`},
		{"double quotes", `say "hi"`, `say "hi"`},
		{"single quotes", `it's 'x'`, `it's 'x'`},
		{"a foreign message with a backslash and quotes", `open "C:\x\y": it's gone`, `open "C:\x\y": it's gone`},
		{"empty", "", ``},
	} {
		t.Run(c.why, func(t *testing.T) {
			if got, want := textOf(c.msg), `fsx: read "p": `+c.want; got != want {
				t.Fatalf("the text is\n  %s\nwant\n  %s", got, want)
			}
		})
	}
}

// The range U+0080 to U+00FF is written \u00NN and a byte 0x80 to 0xFF that is not UTF-8 is
// written \xNN: the two forms do not collide, and one text shows both.
func TestACharacterAndAnInvalidByteOfTheSameNumberAreTold(t *testing.T) {
	for _, c := range []struct{ msg, want string }{
		{"\u00e9\xe9", `\u00e9\xe9`},       // the letter é, then the byte 0xE9 alone
		{"\xe9\u00e9", `\xe9\u00e9`},       // the byte first
		{"\u0080\x80", `\u0080\x80`},       // the first of the range
		{"\u00ff\xff", `\u00ff\xff`},       // the last of the range
		{"\xc3\xa9\xc3", `\u00e9\xc3`},     // a whole é (two bytes), then a lone lead byte
		{"\u00c3\xc3", `\u00c3\xc3`},       // the letter Ã, then the byte 0xC3 alone
		{"\xc3\u00a9", `\xc3\u00a9`},       // a lone lead byte, then the letter ©: not joined into one
		{"\x1f\u001f\x7f", `\x1f\x1f\x7f`}, // an ASCII control code is \xNN whichever way it was written
	} {
		if got, want := textOf(c.msg), `fsx: read "p": `+c.want; got != want {
			t.Errorf("%q: the text is\n  %s\nwant\n  %s", c.msg, got, want)
		}
	}
}

func TestThePathOfAnErrorIsQuotedWithTheEscapesOfGo(t *testing.T) {
	for _, c := range []struct{ why, path, want string }{
		{"plain", "b/d/f.json", `"b/d/f.json"`},
		{"an accent", "b/\u00e9", `"b/\u00e9"`},
		{"U+0080", "\u0080", `"\u0080"`},
		{"an emoji", "\U0001f600", `"\U0001f600"`},
		{"a Chinese character", "\u9375", `"\u9375"`},
		{"a bell", "\a", `"\a"`},
		{"a line break", "a\nb", `"a\nb"`},
		{"the escape character", "\x1b[0m", `"\x1b[0m"`},
		{"DEL", "\x7f", `"\x7f"`},
		{"an invalid byte", "a\xffb", `"a\xffb"`},
		{"a quote and a backslash", `a"b\c`, `"a\"b\\c"`},
		{"empty", "", `""`},
	} {
		t.Run(c.why, func(t *testing.T) {
			e := &fsx.Error{Step: fsx.StepMkdir, Path: c.path, Err: errors.New("x")}
			if got, want := e.Error(), "fsx: mkdir "+c.want+": x"; got != want {
				t.Fatalf("the text is\n  %s\nwant\n  %s", got, want)
			}
		})
	}
}

// The error of the random source in TempName, and the same error as the cause of a stop, is
// escaped, and what it wraps is still found.
func TestTheErrorOfTheRandomSourceIsEscapedAndStillFound(t *testing.T) {
	cause := errors.New("no entropy \u00e9 \U0001f600 \x1b[0m \xff")
	_, err := (&fsx.Writer{Rand: failingReader{cause}}).TempName()
	const want = `fsx: random part of a temporary name: no entropy \u00e9 \U0001f600 \x1b[0m \xff`
	if err == nil || err.Error() != want {
		t.Fatalf("TempName: %v, want\n  %s", err, want)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("TempName: %v does not wrap the cause", err)
	}
	f := newMemFS("b")
	w := &fsx.Writer{FS: f.Root(), Rand: failingReader{cause}}
	defer func() { _ = w.Close() }()
	err = w.WriteFile("b/f", nil, 0o600)
	fe := requireFailed(t, err)
	if !strings.HasSuffix(fe.Error(), `: `+want) || !errors.Is(err, cause) {
		t.Fatalf("WriteFile: %v, want a stop whose text ends with %s and which wraps the cause", err, want)
	}
	requireStoppedBy(t, w.Mkdir("b/m", 0o700), fe)
}

// The names that a refusal quotes, word for word.
func TestTheNamesInARefusalAreQuotedWithPlusQ(t *testing.T) {
	f := newMemFS("b")
	w := newWriter(t, f, 1)
	for _, c := range []struct {
		do   func() error
		want string
	}{
		{func() error { return w.WriteFile("b/\u00e9", nil, 0o600) }, `fsx: invalid argument: path "b/\u00e9" has an element that has the character U+00E9, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteFile("b/\U0001f600", nil, 0o600) }, `fsx: invalid argument: path "b/\U0001f600" has an element that has the character U+1F600, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteFile("b/\u0080", nil, 0o600) }, `fsx: invalid argument: path "b/\u0080" has an element that has the character U+0080, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteFile("b/\xe9", nil, 0o600) }, `fsx: invalid argument: path "b/\xe9" has an element that has the byte 0xE9, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteFile("b/a\x07b", nil, 0o600) }, `fsx: invalid argument: path "b/a\ab" has an element that has the character U+0007, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteFile("/\u00e9", nil, 0o600) }, `fsx: invalid argument: path "/\u00e9" is absolute; a path is relative to the root`},
		{func() error { return w.WriteFile("\u00e9//x", nil, 0o600) }, `fsx: invalid argument: path "\u00e9//x" has an element that has the character U+00E9, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteFile("b//\u00e9", nil, 0o600) }, `fsx: invalid argument: path "b//\u00e9" has an empty element (a doubled separator)`},
		{func() error { return w.WriteFile("\u00e9/", nil, 0o600) }, `fsx: invalid argument: path "\u00e9/" ends with a separator`},
		{func() error { return w.WriteFile("b/\u00e9/../x", nil, 0o600) }, `fsx: invalid argument: path "b/\u00e9/../x" has an element that has the character U+00E9, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteSet("b/s", []fsx.NewFile{{Name: "\u00e9"}}) }, `fsx: invalid argument: file name "\u00e9" has the character U+00E9, which is not a letter, a digit, a dot, a hyphen or an underscore`},
		{func() error { return w.WriteSet("b/s", []fsx.NewFile{{Name: "a"}, {Name: "A"}, {Name: "\u00e9"}}) }, `fsx: invalid argument: file name "A" is given twice`},
		{func() error { return w.WriteSet("b/s", []fsx.NewFile{{Name: ".rt-\u00e9"}}) }, `fsx: invalid argument: file name ".rt-\u00e9" is not one plain name`},
	} {
		if err := c.do(); err == nil || err.Error() != c.want {
			t.Errorf("got %v, want\n  %s", err, c.want)
		}
	}
	// the name of a file of a set that %+q writes with a quote and a backslash in it
	err := w.WriteSet("b/s", []fsx.NewFile{{Name: `a"b\c`}})
	const want = `fsx: invalid argument: file name "a\"b\\c" has the character U+0022 ("), which is not a letter, a digit, a dot, a hyphen or an underscore`
	if err == nil || err.Error() != want {
		t.Errorf("got %v, want\n  %s", err, want)
	}
}
