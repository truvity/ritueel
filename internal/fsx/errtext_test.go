package fsx_test

// The text of an error is safe to print: a hostile path or name (an escape code, a bell, a line
// break, a byte that is not UTF-8) never appears raw in Error() of any error the package returns:
// for a refusal of an argument, for a stop, for the error of the operating system on a read. No
// error text holds a raw byte that is not printable ASCII (the brief of the tests; a printable
// character beyond ASCII must be escaped as well: see the last test).

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// controlHostile are names and messages with what must never reach a terminal: escape codes, a
// bell, line breaks, a NUL, a byte that is not UTF-8, characters that reorder or hide text.
var controlHostile = []string{
	"\x1b[31mred\x1b[0m",
	"\x1b]0;title\x07",
	"a\x07b",
	"a\nb",
	"a\r\nb",
	"a\x00b",
	"\xff\xfe",
	"a\xc3",
	"a\u202eb",
	"a\u2028b",
	"a\u200bb",
	"a\u0085b",
	"a\u00a0b",
	"\ufeffa",
	"a\u009bb", // the C1 control sequence introducer
}

// printableBeyondASCII are characters that print: a refusal or an error must still not show them
// raw, because two names that look alike are not told apart on a terminal, and the text of an
// error is the one place that a person sees a name in.
var printableBeyondASCII = []string{"é", "ключ", "鍵", "a😀b", "K", "COM²", "аbc"}

// refusalsOf runs every call that takes a path or a name with s and returns the errors.
func refusalsOf(t *testing.T, s string) map[string]error {
	t.Helper()
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	out := map[string]error{
		"WriteFile":                w.WriteFile("b/d/"+s, nil, 0o600),
		"WriteFile in the middle":  w.WriteFile("b/"+s+"/f", nil, 0o600),
		"Mkdir":                    w.Mkdir("b/d/"+s, 0o700),
		"WriteSet":                 w.WriteSet("b/d/"+s, nil),
		"WriteSet file":            w.WriteSet("b/d/x", []fsx.NewFile{{Name: s}}),
		"WriteSet duplicate":       w.WriteSet("b/d/x", []fsx.NewFile{{Name: "a" + s}, {Name: "A" + s}}),
		"WriteSet name with a dot": w.WriteSet("b/d/x", []fsx.NewFile{{Name: s + "."}}),
	}
	_, out["CreateJournal"] = w.CreateJournal("b/d/" + s)
	root := f.Root()
	defer func() { _ = root.Close() }()
	_, out["ReadFile"] = fsx.ReadFile(root, "b/d/"+s)
	_, out["ReadDir"] = fsx.ReadDir(root, "b/d/"+s)
	_, _, out["ReadJournal"] = fsx.ReadJournal(root, "b/d/"+s)
	if f.opCount() != 0 {
		t.Fatalf("a refusal reached the file system: %v", f.opList())
	}
	return out
}

func TestAHostilePathOrNameNeverAppearsRawInARefusal(t *testing.T) {
	for _, s := range controlHostile {
		for name, err := range refusalsOf(t, s) {
			if err == nil {
				t.Errorf("%s with %q: no error", name, s)
				continue
			}
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s with %q: %v, want ErrInvalid", name, s, err)
			}
			for i := 0; i < len(err.Error()); i++ {
				if c := err.Error()[i]; c < 0x20 || c > 0x7e {
					t.Errorf("%s with %q: the text %q holds the raw byte %#x", name, s, err.Error(), c)
					break
				}
			}
		}
	}
}

// The text shows what was meant: the escape, not the raw byte, and not nothing.
func TestAHostileNameIsShownAsAnEscape(t *testing.T) {
	err := refusalsOf(t, "a\x1b[31mred")["WriteFile"]
	if err == nil || !strings.Contains(err.Error(), `a\x1b[31mred`) {
		t.Fatalf("got %v, want the text to show the escape code as \\x1b", err)
	}
	err = refusalsOf(t, "a\nb")["WriteSet file"]
	if err == nil || !strings.Contains(err.Error(), `a\nb`) {
		t.Fatalf("got %v, want the text to show the line break as \\n", err)
	}
	err = refusalsOf(t, "a\xffb")["Mkdir"]
	if err == nil || !strings.Contains(err.Error(), `a\xffb`) || !strings.Contains(err.Error(), "the byte 0xFF") {
		t.Fatalf("got %v, want the text to show the byte as \\xff and to name it", err)
	}
}

// TestAHostileMessageOfTheFileSystemNeverAppearsRawInAStop makes the file system fail with a
// message that holds what must not reach a terminal, at each step, and looks at every text that
// the failure gives: the failing call's, and a later call's, which holds the first.
func TestAHostileMessageOfTheFileSystemNeverAppearsRawInAStop(t *testing.T) {
	steps := []struct {
		name string
		kind opKind
		nth  int
		do   func(w *fsx.Writer) error
	}{
		{"walk", kOpenDir, 2, func(w *fsx.Writer) error { return w.WriteFile("b/d/f", []byte("x"), 0o600) }},
		{"mkdir", kMkdir, 1, func(w *fsx.Writer) error { return w.Mkdir("b/d/new", 0o700) }},
		{"create", kCreate, 1, func(w *fsx.Writer) error { return w.WriteFile("b/d/f", []byte("x"), 0o600) }},
		{"write", kWrite, 1, func(w *fsx.Writer) error { return w.WriteFile("b/d/f", []byte("x"), 0o600) }},
		{"flush of a file", kSync, 1, func(w *fsx.Writer) error { return w.WriteFile("b/d/f", []byte("x"), 0o600) }},
		{"close of a file", kClose, 1, func(w *fsx.Writer) error { return w.WriteFile("b/d/f", []byte("x"), 0o600) }},
		{"rename", kRename, 1, func(w *fsx.Writer) error { return w.WriteFile("b/d/f", []byte("x"), 0o600) }},
		{"flush of a folder", kSyncDir, 1, func(w *fsx.Writer) error { return w.WriteFile("b/d/f", []byte("x"), 0o600) }},
		{"set", kRename, 1, func(w *fsx.Writer) error {
			return w.WriteSet("b/d/s", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}})
		}},
	}
	for _, s := range controlHostile {
		cause := errors.New("evil " + s + " end")
		for _, c := range steps {
			f := newMemFS("b", "b/d", "b/t")
			w := newWriter(t, f, 1)
			f.failOn(c.kind, c.nth, cause)
			err := c.do(w)
			if !errors.Is(err, cause) {
				t.Fatalf("%s with %q: %v, want the cause", c.name, s, err)
			}
			later := w.Mkdir("b/d/more", 0o700)
			for what, e := range map[string]error{"the failing call": err, "a later call": later} {
				text := e.Error()
				for i := 0; i < len(text); i++ {
					if text[i] < 0x20 || text[i] > 0x7e {
						t.Errorf("%s, %s, %q: the text %q holds the raw byte %#x", c.name, what, s, text, text[i])
						break
					}
				}
				if !strings.Contains(text, "evil") || !strings.Contains(text, "end") {
					t.Errorf("%s, %s: the text %q lost the message", c.name, what, text)
				}
			}
		}
	}
}

// TestAHostileMessageOfTheFileSystemNeverAppearsRawInARead: the operating system's own error on a
// read (a model of it here, with a hostile text; the real file system is in os_read_test.go).
func TestAHostileMessageOfTheFileSystemNeverAppearsRawInARead(t *testing.T) {
	for _, s := range controlHostile {
		cause := errors.New("evil " + s + " end")
		for what, kind := range map[string]opKind{"ReadFile": kReadFile, "ReadDir": kReadDir, "ReadJournal": kReadFile, "walk": kOpenDir} {
			f := newMemFS("b", "b/d")
			f.addFile("b/d/f", []byte("x\n"))
			root := f.Root()
			f.failOn(kind, 1, cause)
			var err error
			switch what {
			case "ReadFile":
				_, err = fsx.ReadFile(root, "b/d/f")
			case "ReadDir":
				_, err = fsx.ReadDir(root, "b/d")
			case "ReadJournal":
				_, _, err = fsx.ReadJournal(root, "b/d/f")
			case "walk":
				_, err = fsx.ReadFile(root, "b/d/f")
			}
			_ = root.Close()
			if !errors.Is(err, cause) {
				t.Errorf("%s: %v, want the cause", what, err)
				continue
			}
			var fe *fsx.Error
			if !errors.As(err, &fe) {
				t.Errorf("%s: %v is not an *fsx.Error", what, err)
			}
			text := err.Error()
			for i := 0; i < len(text); i++ {
				if text[i] < 0x20 || text[i] > 0x7e {
					t.Errorf("%s with %q: the text %q holds the raw byte %#x", what, s, text, text[i])
					break
				}
			}
		}
	}
}

// TestAHostileMessageOfTheFileSystemNeverAppearsRawInAClose: the error of a close of the root or
// of a journal, in Writer.Close.
func TestAHostileMessageOfTheFileSystemNeverAppearsRawInAClose(t *testing.T) {
	for _, s := range controlHostile {
		cause := errors.New("evil " + s + " end")
		for _, kind := range []opKind{kClose, kCloseDir} {
			f := newMemFS("b")
			w := &fsx.Writer{FS: f.Root(), Rand: newDetRand(1)}
			if _, err := w.CreateJournal("b/j"); err != nil {
				t.Fatal(err)
			}
			f.failOn(kind, 1, cause)
			err := w.Close()
			if !errors.Is(err, cause) {
				t.Fatalf("%s: Close returned %v, want the cause", kind, err)
			}
			text := err.Error()
			for i := 0; i < len(text); i++ {
				if text[i] < 0x20 || text[i] > 0x7e {
					t.Errorf("%s with %q: the text %q holds the raw byte %#x", kind, s, text, text[i])
					break
				}
			}
			// the other close fails as well: the cause is the same, and the text of the second
			f.failOn(kCloseDir, 1, cause)
			requireClean(t, f)
		}
	}
}

// TestNoErrorTextHoldsARawByteBeyondPrintableASCII: a printable character beyond ASCII ("é", an
// emoji, a Cyrillic letter that looks like a Latin one) is shown as an escape too, so that no
// error text holds a raw byte that is not printable ASCII.
//
// This test fails for as long as the quoting leaves a printable character as it is: %q and
// strconv.Quote write "é" as it stands, and the text of Err goes through unicode.IsPrint, which
// keeps it. See the report: strconv.QuoteToASCII (and %+q) is the one-word change in each place.
func TestNoErrorTextHoldsARawByteBeyondPrintableASCII(t *testing.T) {
	check := func(t *testing.T, what, text string) {
		t.Helper()
		for i := 0; i < len(text); i++ {
			if text[i] < 0x20 || text[i] > 0x7e {
				t.Errorf("%s: the text %q holds the raw byte %#x at %d", what, text, text[i], i)
				return
			}
		}
	}
	for _, s := range printableBeyondASCII {
		for name, err := range refusalsOf(t, s) {
			if err == nil {
				t.Errorf("%s with %q: no error", name, s)
				continue
			}
			check(t, fmt.Sprintf("%s with %q", name, s), err.Error())
		}
		// the text of the file system's error, through Error()
		cause := errors.New("evil " + s + " end")
		f := newMemFS("b", "b/d")
		w := newWriter(t, f, 1)
		f.failOn(kCreate, 1, cause)
		err := w.WriteFile("b/d/f", []byte("x"), 0o600)
		check(t, fmt.Sprintf("a stop with the cause %q", s), err.Error())
		check(t, fmt.Sprintf("a later call after a stop with the cause %q", s), w.Mkdir("b/d/m", 0o700).Error())
		root := f.Root()
		f.failOn(kReadDir, 1, cause)
		_, err = fsx.ReadDir(root, "b/d")
		_ = root.Close()
		check(t, fmt.Sprintf("a read with the cause %q", s), err.Error())
	}
}
