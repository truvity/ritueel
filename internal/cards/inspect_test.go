package cards_test

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/wanted"
)

// Inspect reads every card file of a bundle once and returns the cards that passed their reader and the
// findings about the files (record 0005, rule 19; record 0003, rule 5; docs/reference/cards.md, "The card
// file").

func TestInspectOfTheGoodSetGivesTheFiveCardsAndNoFinding(t *testing.T) {
	rep := mustInspect(t, memBundle(goodSet()).open(nil))
	if got := names(rep); !slices.Equal(got, goodNames) {
		t.Errorf("cards = %q, want %q", got, goodNames)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("findings = %+v, want none", rep.Findings)
	}
	if !rep.Clean() || len(rep.Refusals()) != 0 {
		t.Errorf("Clean = %v, Refusals = %+v", rep.Clean(), rep.Refusals())
	}
	want := map[string]struct {
		serial, kind string
		rows         []int
	}{
		"root-a":       {"10000001", "root", []int{3}},
		"root-b":       {"10000002", "root", nil},
		"day-one":      {"10000003", "day-to-day", nil},
		"server-one":   {"10000004", "server", nil},
		"practice-one": {"10000005", "rehearsal", nil},
	}
	texts := goodSet()
	for _, c := range rep.Cards {
		w := want[c.Name]
		if !c.Valid() || c.Serial != w.serial || string(c.Kind) != w.kind || !slices.Equal(c.OtherRows, w.rows) {
			t.Errorf("card %q = %+v, want %+v", c.Name, c, w)
		}
		if string(c.File.Data) != texts[cardFile(c.Name)] || c.File.Path != cardFile(c.Name) {
			t.Errorf("card %q: the file is %q with %d bytes", c.Name, c.File.Path, len(c.File.Data))
		}
	}
	if err := cards.Check(t.Context(), memBundle(goodSet()).open(nil)); err != nil {
		t.Errorf("Check of the good set: %v", err)
	}
}

func TestInspectOfABundleWithNoCardFilesIsNoCardNoFindingAndNoError(t *testing.T) {
	cases := map[string]*node{
		"no want folder":         memBundle(map[string]string{"ritueel.yaml": "x"}),
		"a want folder, no card": memBundle(map[string]string{"want/roots/a.yaml": "x"}),
		"an empty cards folder":  func() *node { n := newDir(); n.put("want/cards", newDir()); return n }(),
		"an empty bundle":        newDir(),
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			rep := mustInspect(t, n.open(nil))
			if len(rep.Cards) != 0 || len(rep.Findings) != 0 || !rep.Clean() {
				t.Errorf("report = %+v, clean %v", rep, rep.Clean())
			}
			if err := cards.Check(t.Context(), n.open(nil)); err != nil {
				t.Errorf("Check: %v", err)
			}
		})
	}
}

func TestInspectDoesNotJudgeTheFilesOfOtherFolders(t *testing.T) {
	// The other wanted files, the history and the cards are not card files: whatever they hold, the card
	// check does not look.
	files := with(goodSet(), map[string]string{
		"ritueel.yaml":            "this is not settings",
		"want/roots/x509.yaml":    "{",
		"want/delegations/a.yaml": "{",
		"seen/cards/root-a.json":  "{",
		"history/x/plan.json":     "{",
		"cards/root-a.yaml":       "{",
		"want/cards-old/a.yaml":   "{",
	})
	rep := mustInspect(t, memBundle(files).open(nil))
	if !rep.Clean() || len(rep.Cards) != 5 {
		t.Errorf("report = %+v", rep)
	}
}

// badCard is one family of faults of a card file, with the line of the first fault (0: no line) and a word
// that its sentence holds.
type badCard struct {
	name  string
	text  string
	line  int
	words string
}

// The base file has the members on lines 1 to 5.
const base = "version: 1\nserial: \"10000009\"\nkind: server\napplications: [piv]\n"

func badCards() []badCard {
	return []badCard{
		{"version two", strings.Replace(base, "version: 1", "version: 2", 1), 1, "version"},
		{"version a string", strings.Replace(base, "version: 1", "version: \"1\"", 1), 1, "version"},
		{"version missing", strings.Replace(base, "version: 1\n", "", 1), 0, "version"},
		{"serial unquoted", strings.Replace(base, "\"10000009\"", "10000009", 1), 2, "serial"},
		{"serial of eleven digits", strings.Replace(base, "10000009", "10000000009", 1), 2, "serial"},
		{"serial of a letter", strings.Replace(base, "10000009", "1000000a", 1), 2, "serial"},
		{"serial of ten thousand digits", strings.Replace(base, "10000009", strings.Repeat("7", 10000), 1), 2, "serial"},
		{"serial empty", strings.Replace(base, "\"10000009\"", "\"\"", 1), 2, "serial"},
		{"serial missing", strings.Replace(base, "serial: \"10000009\"\n", "", 1), 0, "serial"},
		{"kind unknown", strings.Replace(base, "kind: server", "kind: hsm", 1), 3, "kind"},
		{"kind upper case", strings.Replace(base, "kind: server", "kind: Root", 1), 3, "kind"},
		{"applications empty", strings.Replace(base, "[piv]", "[]", 1), 4, "applications"},
		{"applications unknown", strings.Replace(base, "[piv]", "[gpg]", 1), 4, "applications"},
		{"applications twice", strings.Replace(base, "[piv]", "[piv, piv]", 1), 4, "applications"},
		{"applications four", strings.Replace(base, "[piv]", "[piv, openpgp, fido2, piv]", 1), 4, "applications"},
		{"other_rows without piv", strings.Replace(base, "[piv]", "[fido2]", 1) + "other_rows: [3]\n", 5, "other_rows"},
		{"other_rows row one", base + "other_rows: [1]\n", 5, "other_rows"},
		{"other_rows row seven", base + "other_rows: [7]\n", 5, "other_rows"},
		{"other_rows twice", base + "other_rows: [3, 3]\n", 5, "other_rows"},
		{"other_rows six entries", base + "other_rows: [2, 3, 4, 5, 6, 2]\n", 5, "other_rows"},
		{"other_rows a string", base + "other_rows: [\"3\"]\n", 5, "other_rows"},
		{"holder key", base + "holder: Example Person\n", 5, "not read in this version"},
		{"kept key", base + "kept: drawer\n", 5, "not read in this version"},
		{"unknown key", base + "colour: red\n", 5, "colour"},
		{"key twice", base + "kind: root\n", 5, "kind"},
		{"empty file", "", 0, ""},
		{"only a comment", "# nothing\n", 0, ""},
		{"a list", "- a\n- b\n", 0, ""},
		{"a scalar", "just text\n", 0, ""},
		{"an alias", "x: &a [1]\ny: *a\n" + base, 0, ""},
		{"a merge key", "<<: {a: 1}\n" + base, 0, ""},
		{"a tag", "version: !!str 1\n" + base[len("version: 1\n"):], 0, ""},
		{"a null", strings.Replace(base, "kind: server", "kind: null", 1), 3, "empty value"},
		{"a second document", base + "---\n" + base, 0, ""},
		{"a tab", strings.Replace(base, "version: 1", "version:\t1", 1), 0, ""},
		{"a carriage return", strings.Replace(base, "\n", "\r\n", 1), 0, ""},
		{"a byte order mark", "\ufeff" + base, 0, ""},
		{"a bidirectional control in a comment", base + "# \u202e\n", 0, ""},
		{"bytes that are not UTF-8", base + "# \xff\xfe\n", 0, ""},
		{"a NUL byte", base + "# \x00\n", 0, ""},
		{"a control code in a value", strings.Replace(base, "kind: server", "kind: \"ser\\aver\"", 1), 3, "kind"},
		{"a value of non-ASCII letters", strings.Replace(base, "kind: server", "kind: s\u00e9rver\u202e", 1), 3, "U+202E"},
		{"nesting 400 deep", strings.Repeat("[", 400), 0, ""},
		{"nesting 400 deep as members", strings.Repeat("a: {", 400), 0, ""},
		{"ten thousand members", func() string {
			var b strings.Builder
			for i := range 12000 {
				fmt.Fprintf(&b, "k%d: 1\n", i)
			}
			return b.String()
		}(), 0, ""},
		{"a line of 200 KiB", base + "# " + strings.Repeat("x", 200<<10) + "\n", -1, ""}, // accepted: a comment (control)
	}
}

// expectedDetail is the sentence that the reader of the card file gives for a text, the way a finding
// states it: "line N: sentence" when the reader names a line.
func expectedDetail(t testing.TB, name, text string) (detail string, ok bool) {
	t.Helper()
	_, err := wanted.ParseCard(name, []byte(text))
	if err == nil {
		return "", true
	}
	var we *wanted.Error
	if !errors.As(err, &we) {
		t.Fatalf("the reader gave an error that is not a *wanted.Error: %T", err)
	}
	detail = we.Msg
	if we.Line > 0 {
		detail = "line " + strconv.Itoa(we.Line) + ": " + detail
	}
	return detail, false
}

func TestOneBadFileIsAFindingAndTheOtherFourCardsAreStillReturned(t *testing.T) {
	for _, c := range badCards() {
		t.Run(c.name, func(t *testing.T) {
			want, accepted := expectedDetail(t, "bad", c.text)
			if c.line == -1 {
				// The control case: a long comment is a good file. The finding of the others does not
				// appear.
				if !accepted {
					t.Fatalf("the control file is refused: %s", want)
				}
				rep := mustInspect(t, memBundle(with(goodSet(), map[string]string{cardFile("bad"): c.text})).open(nil))
				if !rep.Clean() || len(rep.Cards) != 6 {
					t.Errorf("report = %+v", rep.Findings)
				}
				return
			}
			if accepted {
				t.Fatal("the reader accepts the file that the test calls bad")
			}
			files := with(goodSet(), map[string]string{cardFile("bad"): c.text})
			rep := mustInspect(t, memBundle(files).open(nil))
			if len(rep.Findings) != 1 {
				t.Fatalf("findings = %+v, want one", rep.Findings)
			}
			f := rep.Findings[0]
			if f.Code != cards.FileInvalid || f.Path != cardFile("bad") || f.Level != cards.LevelAlert {
				t.Errorf("finding = %+v", f)
			}
			if f.Detail != want {
				t.Errorf("detail = %q, want the sentence of the reader %q", f.Detail, want)
			}
			if c.line > 0 && !strings.HasPrefix(f.Detail, "line "+strconv.Itoa(c.line)+": ") {
				t.Errorf("detail %q does not start with line %d", f.Detail, c.line)
			}
			if c.line == 0 && strings.HasPrefix(f.Detail, "line 0") {
				t.Errorf("detail %q names line 0", f.Detail)
			}
			if c.words != "" && !strings.Contains(f.Detail, c.words) {
				t.Errorf("detail %q lacks %q", f.Detail, c.words)
			}
			if !printable(f.Detail) || !printable(f.Path) || !printable(f.Line()) || len(f.Detail) > 240 {
				t.Errorf("the finding is not printable ASCII of at most 240 bytes: %+q", f.Line())
			}
			if got := names(rep); !slices.Equal(got, goodNames) {
				t.Errorf("cards = %q, want the five good ones %q", got, goodNames)
			}
			if rep.Clean() || !slices.Equal(rep.Refusals(), rep.Findings) {
				t.Errorf("Clean = %v, Refusals = %+v", rep.Clean(), rep.Refusals())
			}
			// The negative control: the same name with a good file has no finding.
			ok := mustInspect(t, memBundle(with(goodSet(), map[string]string{cardFile("bad"): base})).open(nil))
			if len(ok.Findings) != 0 || len(ok.Cards) != 6 {
				t.Errorf("the good file under the same name: %+v", ok.Findings)
			}
			// Check names the file and says what the finding says.
			err := cards.Check(t.Context(), memBundle(files).open(nil))
			var we *wanted.Error
			if !errors.As(err, &we) || we.Path != cardFile("bad") || we.Msg != f.Detail {
				t.Errorf("Check = %v, want a *wanted.Error at %s with the detail", err, cardFile("bad"))
			}
		})
	}
}

func TestAFileOfTheLargestSizeIsACardAndOneByteMoreIsAFinding(t *testing.T) {
	pad := func(n int) string {
		text := base
		for len(text)+60 < n {
			text += "# " + strings.Repeat("x", 56) + "\n"
		}
		return text + "#" + strings.Repeat("y", n-len(text)-2) + "\n"
	}
	ok := pad(wanted.MaxBytes)
	if len(ok) != wanted.MaxBytes {
		t.Fatalf("the test file has %d bytes", len(ok))
	}
	rep := mustInspect(t, memBundle(map[string]string{cardFile("big"): ok}).open(nil))
	if len(rep.Cards) != 1 || len(rep.Findings) != 0 {
		t.Errorf("a file of MaxBytes: cards %d, findings %+v", len(rep.Cards), rep.Findings)
	}
	rep = mustInspect(t, memBundle(map[string]string{cardFile("big"): pad(wanted.MaxBytes + 1), cardFile("ok"): base}).open(nil))
	if len(rep.Cards) != 1 || len(rep.Findings) != 1 || rep.Findings[0].Code != cards.FileInvalid ||
		!strings.Contains(rep.Findings[0].Detail, strconv.Itoa(wanted.MaxBytes)) {
		t.Errorf("a file of MaxBytes+1: cards %d, findings %+v", len(rep.Cards), rep.Findings)
	}
}

func TestAFileOverTheLimitOfAReadIsAFindingAndTheOtherCardsAreReturned(t *testing.T) {
	n := memBundle(goodSet())
	n.put(cardFile("long"), &node{kind: "file", long: true})
	rep := mustInspect(t, n.open(nil))
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	f := rep.Findings[0]
	if f.Code != cards.FileInvalid || f.Path != cardFile("long") || !strings.Contains(f.Detail, "too long") || strings.Contains(f.Detail, "line ") {
		t.Errorf("finding = %+v", f)
	}
	if got := names(rep); !slices.Equal(got, goodNames) {
		t.Errorf("cards = %q", got)
	}
	// A cause that only says the same in words is not the error of the package: it is a fault of the read.
	m := memBundle(goodSet())
	m.put(cardFile("long"), &node{kind: "file", err: errors.New("the file is longer than the limit of a read")})
	if rep, err := cards.Inspect(t.Context(), m.open(nil)); err == nil || rep != nil {
		t.Errorf("a read error that only has the words of a long file = %+v, %v", rep, err)
	}
	// A long file wrapped in another error is still the fault of the file.
	m = memBundle(goodSet())
	m.put(cardFile("long"), &node{kind: "file", long: true})
	if err := cards.Check(t.Context(), m.open(nil)); err == nil || !strings.Contains(err.Error(), cardFile("long")) {
		t.Errorf("Check = %v", err)
	}
}

func TestTwoBadFilesAreTwoFindingsInTheOrderOfThePathsAndCheckNamesTheFirst(t *testing.T) {
	files := with(goodSet(), map[string]string{
		cardFile("zz-bad"): strings.Replace(base, "version: 1", "version: 2", 1),
		cardFile("aa-bad"): strings.Replace(base, "kind: server", "kind: hsm", 1),
	})
	rep := mustInspect(t, memBundle(files).open(nil))
	if got := paths(rep.Findings); !slices.Equal(got, []string{cardFile("aa-bad"), cardFile("zz-bad")}) {
		t.Fatalf("paths = %q", got)
	}
	if rep.Clean() || len(rep.Refusals()) != 2 || len(rep.Cards) != 5 {
		t.Errorf("Clean %v, refusals %d, cards %d", rep.Clean(), len(rep.Refusals()), len(rep.Cards))
	}
	err := cards.Check(t.Context(), memBundle(files).open(nil))
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != cardFile("aa-bad") {
		t.Fatalf("Check = %v, want the first file", err)
	}
	if !strings.Contains(we.Msg, rep.Findings[0].Detail) || !strings.Contains(we.Msg, "and 1 more") {
		t.Errorf("text %q does not hold the first detail and \"and 1 more\"", we.Msg)
	}
	if strings.Contains(we.Msg, rep.Findings[1].Detail) {
		t.Errorf("text %q holds the detail of the second file", we.Msg)
	}
	// One file: no "more".
	delete(files, cardFile("zz-bad"))
	err = cards.Check(t.Context(), memBundle(files).open(nil))
	if !errors.As(err, &we) || strings.Contains(we.Msg, "more") {
		t.Errorf("Check of one bad file = %v, want no count", err)
	}
	// Three: the count is of the others.
	files[cardFile("zz-bad")] = strings.Replace(base, "version: 1", "version: 2", 1)
	files[cardFile("mm-bad")] = strings.Replace(base, "version: 1", "version: 3", 1)
	err = cards.Check(t.Context(), memBundle(files).open(nil))
	if !errors.As(err, &we) || !strings.Contains(we.Msg, "and 2 more findings") {
		t.Errorf("Check of three bad files = %v, want \"and 2 more findings\"", err)
	}
}

func TestSixtyFourBadFilesAreSixtyFourFindingsAndNothingMore(t *testing.T) {
	files := map[string]string{}
	for i := range wanted.MaxCards {
		files[fmt.Sprintf("want/cards/c%04d.yaml", i)] = "version: 2\n"
	}
	rep := mustInspect(t, memBundle(files).open(nil))
	if len(rep.Findings) != wanted.MaxCards || len(rep.Cards) != 0 {
		t.Fatalf("findings %d, cards %d", len(rep.Findings), len(rep.Cards))
	}
	if !slices.IsSorted(paths(rep.Findings)) {
		t.Error("the findings are not in the order of the paths")
	}
	err := cards.Check(t.Context(), memBundle(files).open(nil))
	if err == nil || !strings.Contains(err.Error(), "and 63 more findings") {
		t.Errorf("Check = %v", err)
	}
}

func TestACardNamedTwiceIsFoundAtTheLaterFileAndNamesTheFirst(t *testing.T) {
	type tc struct {
		name   string
		files  map[string]string
		want   []string // the paths of the findings
		detail []string // what each detail holds
		not    []string // what no detail holds
	}
	cases := []tc{
		{"one serial in two files",
			map[string]string{cardFile("a"): cardText("10000001", "server"), cardFile("b"): cardText("10000001", "server")},
			[]string{cardFile("b")}, []string{"the same card as " + cardFile("a")}, []string{"kinds differ"}},
		{"the same number with leading zeros",
			map[string]string{cardFile("a"): cardText("0123", "server"), cardFile("b"): cardText("123", "server")},
			[]string{cardFile("b")}, []string{"the same card as " + cardFile("a")}, nil},
		{"the same number with other leading zeros, the other way",
			map[string]string{cardFile("a"): cardText("123", "server"), cardFile("b"): cardText("00123", "server")},
			[]string{cardFile("b")}, []string{"the same card as " + cardFile("a")}, nil},
		{"zero written two ways",
			map[string]string{cardFile("a"): cardText("0", "server"), cardFile("b"): cardText("0000", "server")},
			[]string{cardFile("b")}, []string{"the same card as " + cardFile("a")}, nil},
		{"the longest serial in two forms",
			map[string]string{cardFile("a"): cardText("1234567890", "server"), cardFile("b"): cardText("1234567890", "server")},
			[]string{cardFile("b")}, nil, nil},
		{"one serial and two kinds",
			map[string]string{cardFile("a"): cardText("10000001", "server"), cardFile("b"): cardText("10000001", "root")},
			[]string{cardFile("b")}, []string{"the same card as " + cardFile("a"), "the kinds differ"}, nil},
		{"the order of the names and not of the writing",
			map[string]string{cardFile("zz"): cardText("10000001", "server"), cardFile("aa"): cardText("10000001", "root"), cardFile("mm"): cardText("2", "server")},
			[]string{cardFile("zz")}, []string{"the same card as " + cardFile("aa"), "the kinds differ"}, nil},
		{"three files with one serial",
			map[string]string{cardFile("a"): cardText("10000001", "server"), cardFile("b"): cardText("10000001", "server"), cardFile("c"): cardText("10000001", "server")},
			[]string{cardFile("b"), cardFile("c")}, []string{"the same card as " + cardFile("a"), "the same card as " + cardFile("a")}, []string{cardFile("b") + "."}},
		{"three files, the kind is compared with the first",
			map[string]string{cardFile("a"): cardText("10000001", "root"), cardFile("b"): cardText("10000001", "server"), cardFile("c"): cardText("10000001", "server")},
			[]string{cardFile("b"), cardFile("c")}, []string{"the kinds differ", "the kinds differ"}, nil},
		{"two cards twice",
			map[string]string{cardFile("a"): cardText("1", "server"), cardFile("b"): cardText("1", "server"), cardFile("c"): cardText("2", "server"), cardFile("d"): cardText("2", "server")},
			[]string{cardFile("b"), cardFile("d")}, []string{cardFile("a"), cardFile("c")}, nil},
		// The negative controls.
		{"serials that differ by one digit", map[string]string{cardFile("a"): cardText("10000001", "server"), cardFile("b"): cardText("10000010", "server")}, nil, nil, nil},
		{"serials that are a prefix of each other", map[string]string{cardFile("a"): cardText("123", "server"), cardFile("b"): cardText("1230", "server")}, nil, nil, nil},
		{"serials that are a suffix of each other", map[string]string{cardFile("a"): cardText("23", "server"), cardFile("b"): cardText("123", "server")}, nil, nil, nil},
		{"one file", map[string]string{cardFile("a"): cardText("10000001", "server")}, nil, nil, nil},
		{"the good set", goodSet(), nil, nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := mustInspect(t, memBundle(c.files).open(nil))
			if got := paths(rep.Findings); !slices.Equal(got, c.want) && (len(got) != 0 || len(c.want) != 0) {
				t.Fatalf("paths = %q, want %q (%+v)", got, c.want, rep.Findings)
			}
			for i, f := range rep.Findings {
				if f.Code != cards.SerialTwice || f.Level != cards.LevelAlert {
					t.Errorf("finding %+v", f)
				}
				if i < len(c.detail) && !strings.Contains(f.Detail, c.detail[i]) {
					t.Errorf("detail %q lacks %q", f.Detail, c.detail[i])
				}
				for _, n := range c.not {
					if strings.Contains(f.Detail, n) {
						t.Errorf("detail %q holds %q", f.Detail, n)
					}
				}
				if !printable(f.Line()) {
					t.Errorf("line %+q", f.Line())
				}
			}
			// A card in a finding of the set is a valid file: it stays in the list of cards.
			if len(rep.Cards) != len(c.files) {
				t.Errorf("cards = %d, want %d", len(rep.Cards), len(c.files))
			}
			if rep.Clean() != (len(c.want) == 0) {
				t.Errorf("Clean = %v for %d findings", rep.Clean(), len(c.want))
			}
		})
	}
}

func TestACardNamedTwiceIsARefusalAndCheckSaysSo(t *testing.T) {
	files := map[string]string{cardFile("a"): cardText("0123", "server"), cardFile("b"): cardText("123", "root")}
	err := cards.Check(t.Context(), memBundle(files).open(nil))
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != cardFile("b") || !strings.Contains(we.Msg, cardFile("a")) {
		t.Fatalf("Check = %v, want a *wanted.Error at %s that names %s", err, cardFile("b"), cardFile("a"))
	}
	if !printable(err.Error()) {
		t.Errorf("text %+q", err.Error())
	}
}

func TestABadFileTakesNoPartInTheCheckOfTheSet(t *testing.T) {
	// A file that fails its reader names no card, even when its text holds the serial of another file.
	files := map[string]string{
		cardFile("a"): cardText("10000001", "server"),
		cardFile("b"): "version: 2\nserial: \"10000001\"\nkind: server\napplications: [piv]\n",
	}
	rep := mustInspect(t, memBundle(files).open(nil))
	if len(rep.Findings) != 1 || rep.Findings[0].Code != cards.FileInvalid {
		t.Errorf("findings = %+v, want the one of the bad file", rep.Findings)
	}
}

func TestFindingsAreInTheOrderOfTheCodesThenThePathThenTheDetail(t *testing.T) {
	files := map[string]string{
		cardFile("a"):     cardText("1", "server"),
		cardFile("b"):     cardText("1", "server"), // twice, at b
		cardFile("c"):     cardText("2", "server"),
		cardFile("d"):     cardText("2", "root"), // twice, at d
		cardFile("zz"):    "version: 2\n",        // invalid, last by path, first by code
		cardFile("mm"):    "version: 3\n",
		cardFile("a-bad"): "version: 4\n",
	}
	rep := mustInspect(t, memBundle(files).open(nil))
	want := []string{cardFile("a-bad"), cardFile("mm"), cardFile("zz"), cardFile("b"), cardFile("d")}
	if got := paths(rep.Findings); !slices.Equal(got, want) {
		t.Fatalf("paths = %q, want %q", got, want)
	}
	for i, f := range rep.Findings {
		wantCode := cards.FileInvalid
		if i >= 3 {
			wantCode = cards.SerialTwice
		}
		if f.Code != wantCode || !f.Level.Valid() {
			t.Errorf("finding %d = %+v", i, f)
		}
	}
	// A second run gives the same bytes.
	again := mustInspect(t, memBundle(files).open(nil))
	var a, b []string
	for _, f := range rep.Findings {
		a = append(a, f.Line())
	}
	for _, f := range again.Findings {
		b = append(b, f.Line())
	}
	if !slices.Equal(a, b) {
		t.Errorf("two runs differ:\n%q\n%q", a, b)
	}
	// The first refusal that Check names is the first of Refusals: the invalid file that sorts first.
	err := cards.Check(t.Context(), memBundle(files).open(nil))
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != cardFile("a-bad") || !strings.Contains(we.Msg, "and 4 more findings") {
		t.Errorf("Check = %v", err)
	}
}

func TestEveryFindingHasALevelFromTheTable(t *testing.T) {
	files := with(goodSet(), map[string]string{
		cardFile("bad"):  "version: 2\n",
		cardFile("twin"): cardRootB,
	})
	rep := mustInspect(t, memBundle(files).open(nil))
	if len(rep.Findings) != 2 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	for _, f := range rep.Findings {
		if !f.Level.Valid() {
			t.Errorf("finding %+v has no level", f)
		}
		// Proposed: both codes are alerts until the status command gives them another weight.
		if f.Level != cards.LevelAlert {
			t.Errorf("level %q of %s, want alert", f.Level, f.Code)
		}
	}
}

func TestTheCardsOfAReportAreOwnCopies(t *testing.T) {
	n := memBundle(goodSet())
	rep := mustInspect(t, n.open(nil))
	rep.Cards[0].File.Data[0] ^= 0xff
	rep.Cards[0].Applications[0] = "x"
	again := mustInspect(t, n.open(nil))
	if string(again.Cards[0].File.Data) != cardDayOne || again.Cards[0].Applications[0] != "openpgp" {
		t.Errorf("a second Inspect was changed by a change of the first result")
	}
}

func TestFindingsAreInTheOrderOfThePathsAndNotOfTheNames(t *testing.T) {
	// The names a and a-b sort as a, a-b; the paths want/cards/a.yaml and want/cards/a-b.yaml sort the other
	// way (a hyphen comes before a dot). The findings are ordered by path.
	files := map[string]string{cardFile("a"): "version: 2\n", cardFile("a-b"): "version: 3\n", cardFile("a-c"): "version: 4\n"}
	rep := mustInspect(t, memBundle(files).open(nil))
	want := []string{cardFile("a-b"), cardFile("a-c"), cardFile("a")}
	if got := paths(rep.Findings); !slices.Equal(got, want) {
		t.Errorf("paths = %q, want %q", got, want)
	}
	err := cards.Check(t.Context(), memBundle(files).open(nil))
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != cardFile("a-b") {
		t.Errorf("Check = %v, want the first path %s", err, cardFile("a-b"))
	}
	// The cards are in the order of the names.
	rep = mustInspect(t, memBundle(map[string]string{cardFile("a"): cardText("1", "server"), cardFile("a-b"): cardText("2", "server")}).open(nil))
	if got := names(rep); !slices.Equal(got, []string{"a", "a-b"}) {
		t.Errorf("cards = %q, want the order of the names", got)
	}
}
