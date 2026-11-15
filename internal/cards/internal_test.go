package cards

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/wanted"
)

// Tests of the unexported parts: the cut of a detail, the sort of the findings, the way an error of the
// reader is told as a finding or as a fault of the check, and the one table of levels.

// escaped is a text that is only printable ASCII and whole \uXXXX escapes.
var escaped = regexp.MustCompile(`^(?:[ -\[\]-~]|\\u[0-9a-f]{4}|\\)*$`)

// halfEscape finds the start of an escape that the text ends in the middle of: a backslash, or a backslash
// and a u and fewer than four hexadecimal digits. The texts of these tests hold no backslash of their own.
var halfEscape = regexp.MustCompile(`\\(?:u[0-9a-f]{0,3})?$`)

func TestCutDetailKeepsAShortDetailAndCutsALongOneAtTwoHundredFortyBytes(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"short":            "line 3: the kind is not one of the four",
		"239 bytes":        strings.Repeat("a", 239),
		"exactly 240":      strings.Repeat("a", 240),
		"241":              strings.Repeat("a", 241),
		"1000":             strings.Repeat("a", 1000),
		"240 of escapes":   strings.Repeat("\u00e9", 40),
		"escapes over":     strings.Repeat("\u00e9", 41),
		"emoji":            strings.Repeat("\U0001f600", 30),
		"long unprintable": strings.Repeat("\x01", 500),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := cutDetail(in)
			whole := escapeAll(in)
			if len(whole) <= wantMaxDetail {
				if got != whole {
					t.Errorf("a detail of %d bytes was changed: %q", len(whole), got)
				}
				return
			}
			if len(got) > wantMaxDetail || !strings.HasSuffix(got, wantCutMark) {
				t.Fatalf("cut = %d bytes %q, want at most %d and ending with %q", len(got), got, wantMaxDetail, wantCutMark)
			}
			body := strings.TrimSuffix(got, wantCutMark)
			if !strings.HasPrefix(whole, body) {
				t.Errorf("the cut is not a prefix of the whole text")
			}
			if halfEscape.MatchString(body) {
				t.Errorf("the cut leaves half of an escape: %q", got[len(got)-12:])
			}
			if !escaped.MatchString(body) {
				t.Errorf("the cut is not printable ASCII: %+q", got)
			}
			// The cut moves back at most the part of one escape (5 bytes), or, in a character above U+FFFF,
			// the part of the second escape of its pair and the whole first escape (11 bytes).
			slack := 6
			if strings.ContainsFunc(in, func(r rune) bool { return r > 0xffff }) {
				slack = 12
			}
			if len(body) < wantMaxDetail-len(wantCutMark)-slack {
				t.Errorf("the cut keeps only %d bytes, it cut more than the part of one escape (%d bytes at most)", len(body), slack-1)
			}
		})
	}
}

// escapeAll is the text as the detail would be written whole.
func escapeAll(s string) string { return jsonset.Escape(s) }

func TestCutDetailAtEveryOffsetOfAnEscapeNeverLeavesHalfOfOne(t *testing.T) {
	for pad := range 14 {
		in := strings.Repeat("a", pad) + strings.Repeat("\u00e9", 60)
		got := cutDetail(in)
		if len(got) > wantMaxDetail || !strings.HasSuffix(got, wantCutMark) {
			t.Fatalf("pad %d: %q", pad, got)
		}
		body := strings.TrimSuffix(got, wantCutMark)
		if halfEscape.MatchString(body) {
			t.Errorf("pad %d: half of an escape at the end: %q", pad, body[len(body)-8:])
		}
	}
}

func TestNewFindingTakesItsLevelFromTheTableAndCutsTheDetail(t *testing.T) {
	f := newFinding(SerialTwice, "want/cards/b.yaml", strings.Repeat("x", 500))
	if f.Code != SerialTwice || f.Path != "want/cards/b.yaml" || f.Level != levels[SerialTwice] || len(f.Detail) != wantMaxDetail {
		t.Errorf("finding = %+v", f)
	}
	for _, c := range Codes() {
		if !levelOf(c).Valid() {
			t.Errorf("the code %s has no level in the table", c)
		}
		if _, ok := levels[c]; !ok {
			t.Errorf("the code %s is not in the table of levels", c)
		}
		if _, ok := refuses[c]; !ok {
			t.Errorf("the code %s is not in the table of refusals", c)
		}
	}
	if len(levels) != len(codes) || len(refuses) != len(codes) {
		t.Errorf("the tables hold %d levels and %d refusals for %d codes", len(levels), len(refuses), len(codes))
	}
	if got := levelOf("card-unknown"); got != "" || got.Valid() {
		t.Errorf("levelOf(unknown) = %q, want the zero level", got)
	}
}

func TestACodeOfTheTableThatDoesNotRefuseDoesNotRefuse(t *testing.T) {
	// The fail-closed rule is for a code that is not in the table. A code that the table lists as not
	// refusing (the findings of a later part) is read as it is listed.
	refuses["card-test-only"] = false
	defer delete(refuses, "card-test-only")
	if Code("card-test-only").Refuses() {
		t.Error("a listed code that does not refuse refuses")
	}
	rep := &Report{made: true, Findings: []Finding{{Code: "card-test-only", Path: "p", Detail: "d"}, {Code: FileInvalid, Path: "q", Detail: "e"}}}
	if got := rep.Refusals(); len(got) != 1 || got[0].Code != FileInvalid {
		t.Errorf("Refusals() = %+v, want the one that refuses", got)
	}
	if rep.Clean() {
		t.Error("Clean() with a refusing finding")
	}
	rep.Findings = rep.Findings[:1]
	if !rep.Clean() || rep.Refusals() != nil {
		t.Errorf("a report whose findings do not refuse: Clean %v, Refusals %+v", rep.Clean(), rep.Refusals())
	}
}

func TestCompareFindingsOrdersByTheCodeThenThePathThenTheDetail(t *testing.T) {
	a := Finding{Code: FileInvalid, Path: "a", Detail: "x"}
	cases := []struct {
		x, y Finding
		want int
	}{
		{a, a, 0},
		{Finding{Code: FileInvalid, Path: "z"}, Finding{Code: SerialTwice, Path: "a"}, -1},
		{Finding{Code: SerialTwice, Path: "a"}, Finding{Code: FileInvalid, Path: "z"}, 1},
		{Finding{Code: FileInvalid, Path: "a"}, Finding{Code: FileInvalid, Path: "b"}, -1},
		{Finding{Code: FileInvalid, Path: "b"}, Finding{Code: FileInvalid, Path: "a"}, 1},
		{Finding{Code: FileInvalid, Path: "a", Detail: "a"}, Finding{Code: FileInvalid, Path: "a", Detail: "b"}, -1},
		{Finding{Code: FileInvalid, Path: "a", Detail: "b"}, Finding{Code: FileInvalid, Path: "a", Detail: "a"}, 1},
		// A code that is not in the table sorts before the codes of the table; the order is still fixed.
		{Finding{Code: "zzz", Path: "a"}, Finding{Code: FileInvalid, Path: "a"}, -1},
	}
	for i, c := range cases {
		got := compareFindings(c.x, c.y)
		if (got < 0) != (c.want < 0) || (got > 0) != (c.want > 0) {
			t.Errorf("case %d: compare = %d, want sign %d", i, got, c.want)
		}
	}
}

// cause is an error that wraps another and counts how many times its text was asked for.
type cause struct {
	asked *int
	under error
}

func (c cause) Error() string { *c.asked++; return "text of the cause" }
func (c cause) Unwrap() error { return c.under }

func TestFileFindingTellsAFaultOfTheFileFromAFaultOfTheSystem(t *testing.T) {
	asked := 0
	read := func(under error) error {
		// The shape that wanted.LoadCard gives for a read that failed: a *wanted.Error whose cause is the
		// error of the file system. Only the reader can set the cause, so a real read makes it.
		return readThrough(t, &asked, under)
	}
	cases := []struct {
		name    string
		err     error
		finding bool
		line    int
		detail  string
	}{
		{"a fault of the text with a line", &wanted.Error{Path: "p", Line: 4, Msg: "bad"}, true, 4, "line 4: bad"},
		{"a fault of the text with no line", &wanted.Error{Path: "p", Msg: "bad"}, true, 0, "bad"},
		{"a fault of the text with a negative line", &wanted.Error{Path: "p", Line: -2, Msg: "bad"}, true, 0, "bad"},
		{"a wrapped fault of the text", fmt.Errorf("x: %w", &wanted.Error{Path: "p", Line: 1, Msg: "bad"}), true, 1, "line 1: bad"},
		{"not a *wanted.Error", errors.New("plain"), false, 0, ""},
		{"a nil *wanted.Error", (*wanted.Error)(nil), false, 0, ""},
		{"a wrapped nil *wanted.Error", fmt.Errorf("x: %w", (*wanted.Error)(nil)), false, 0, ""},
		{"a read fault", read(errors.New("disk")), false, 0, ""},
		{"a missing file", read(fs.ErrNotExist), false, 0, ""},
		{"a link", read(fsx.ErrLink), false, 0, ""},
		{"too large", read(fsx.ErrTooLarge), true, 0, "the file cannot be read: it is too long"},
		{"too large, wrapped", read(fmt.Errorf("w: %w", fsx.ErrTooLarge)), true, 0, "the file cannot be read: it is too long"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			asked = 0
			f, err := fileFinding("a", c.err)
			if c.finding {
				if err != nil {
					t.Fatalf("an error: %v", err)
				}
				if f.Code != FileInvalid || f.Path != "want/cards/a.yaml" || f.Detail != c.detail || !f.Level.Valid() {
					t.Errorf("finding = %+v, want detail %q", f, c.detail)
				}
			} else {
				if err == nil || (f != Finding{}) {
					t.Fatalf("finding %+v, error %v; want an error and no finding", f, err)
				}
				if !errors.Is(err, c.err) {
					t.Errorf("the error was changed: %v", err)
				}
			}
			if asked != 0 {
				t.Errorf("the text of a cause was asked %d times", asked)
			}
		})
	}
}

// readThrough makes the error that wanted.LoadCard makes for a read that failed with under: it reads a file
// through a folder that fails with it.
func readThrough(t *testing.T, asked *int, under error) error {
	t.Helper()
	_, err := wanted.LoadCard(failingFS{err: cause{asked: asked, under: under}}, "a")
	if err == nil {
		t.Fatal("LoadCard gave no error")
	}
	return err
}

// failingFS is a folder in which every file read fails with err. It has no other use.
type failingFS struct {
	fsx.FS
	err error
}

func (f failingFS) OpenDir(string) (fsx.FS, error)  { return f, nil }
func (f failingFS) ReadFile(string) ([]byte, error) { return nil, f.err }
func (f failingFS) Close() error                    { return nil }

func TestSerialTwiceHoldsOneMapAndNamesTheFirstFileOfEachCard(t *testing.T) {
	mk := func(name, serial string, kind wanted.CardKind) *wanted.Card {
		text := "version: 1\nserial: \"" + serial + "\"\nkind: " + string(kind) + "\napplications: [piv]\n"
		c, err := wanted.ParseCard(name, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	list := []*wanted.Card{
		mk("a", "7", wanted.CardServer), mk("b", "007", wanted.CardServer), mk("c", "7", wanted.CardRoot),
		mk("d", "8", wanted.CardServer), mk("e", "08", wanted.CardRoot),
	}
	got := serialTwice(list)
	if len(got) != 3 {
		t.Fatalf("findings = %+v", got)
	}
	want := []struct{ path, detail string }{
		{"want/cards/b.yaml", "the same card as want/cards/a.yaml"},
		{"want/cards/c.yaml", "the same card as want/cards/a.yaml; the kinds differ"},
		{"want/cards/e.yaml", "the same card as want/cards/d.yaml; the kinds differ"},
	}
	for i, w := range want {
		if got[i].Path != w.path || got[i].Detail != w.detail || got[i].Code != SerialTwice {
			t.Errorf("finding %d = %+v, want %+v", i, got[i], w)
		}
	}
	if serialTwice(nil) != nil || serialTwice(list[:1]) != nil {
		t.Error("an empty set or a set of one has a finding")
	}
}

// The limits as the page of the finding says them, spelled out here so that the tests do not stand on the
// constants that they check.
const (
	wantMaxDetail = 240
	wantCutMark   = "..."
)
