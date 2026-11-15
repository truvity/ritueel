package cards_test

import (
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/wanted"
)

// A zero value fails closed: a report that Inspect did not make is not valid and is never
// clean, so a caller that forgot to run the check cannot read "no finding" from it.

func TestAReportThatInspectDidNotMakeIsNotValidAndNeverClean(t *testing.T) {
	good := mustInspect(t, memBundle(goodSet()).open(nil))
	copyOf := *good
	card := good.Cards[0]
	refusing := []cards.Finding{{Code: cards.FileInvalid, Level: cards.LevelAlert, Path: cardFile("x"), Detail: "d"}}
	cases := map[string]*cards.Report{
		"a nil report":                     nil,
		"the zero report":                  {},
		"cards by a literal":               {Cards: []*wanted.Card{card}},
		"cards and findings by a literal":  {Cards: []*wanted.Card{card}, Findings: refusing},
		"findings by a literal":            {Findings: refusing},
		"the empty slices by a literal":    {Cards: []*wanted.Card{}, Findings: []cards.Finding{}},
		"a copy of a report that was made": &copyOf,
		"a report with a zero valid field": {Cards: good.Cards},
	}
	// A copy of a valid report keeps its mark (the value is copied whole): it is the one entry that is
	// valid, so it is handled apart.
	delete(cases, "a copy of a report that was made")
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if r.Valid() {
				t.Error("Valid() is true")
			}
			if r.Clean() {
				t.Error("Clean() is true")
			}
			if got := r.Refusals(); got != nil {
				t.Errorf("Refusals() = %+v, want nil", got)
			}
		})
	}
	if !copyOf.Valid() || !copyOf.Clean() {
		t.Error("a copy of a valid report lost its mark")
	}
	// A report that was made and holds no refusing finding is clean; one that holds one is not, and its
	// Refusals are the refusing findings in order.
	if !good.Valid() || !good.Clean() {
		t.Error("the report of the good set is not valid and clean")
	}
}

func TestACodeThatIsNotInTheTableRefuses(t *testing.T) {
	for _, c := range []cards.Code{"", "card-unknown", "card-file-invalid ", "CARD-FILE-INVALID", "card-serial-twice\n", "x"} {
		if !c.Refuses() {
			t.Errorf("Code(%q).Refuses() is false", string(c))
		}
	}
	var zero cards.Code
	if !zero.Refuses() {
		t.Error("the zero Code does not refuse")
	}
	for _, c := range []cards.Code{cards.FileInvalid, cards.SerialTwice} {
		if !c.Refuses() {
			t.Errorf("%s does not refuse", c)
		}
	}
}

func TestTheCodesAreTheTwoNamesInTheOrderOfTheReportAndTheListIsACopy(t *testing.T) {
	got := cards.Codes()
	if want := []cards.Code{"card-file-invalid", "card-serial-twice"}; !slices.Equal(got, want) {
		t.Fatalf("Codes() = %q, want %q", got, want)
	}
	if cards.FileInvalid != "card-file-invalid" || cards.SerialTwice != "card-serial-twice" {
		t.Errorf("the names are %q and %q", cards.FileInvalid, cards.SerialTwice)
	}
	got[0] = "changed"
	_ = append(got[:1], "more")
	if again := cards.Codes(); !slices.Equal(again, []cards.Code{"card-file-invalid", "card-serial-twice"}) {
		t.Errorf("a change of the result changed the table: %q", again)
	}
	for _, c := range cards.Codes() {
		if strings.ToLower(string(c)) != string(c) || strings.ContainsAny(string(c), " \t\n_") || !strings.HasPrefix(string(c), "card-") {
			t.Errorf("the code %q is not of the form card-word", c)
		}
	}
}

func TestOnlyTheThreeLevelsAreLevels(t *testing.T) {
	for _, l := range []cards.Level{cards.LevelNotice, cards.LevelAlert, cards.LevelCritical} {
		if !l.Valid() {
			t.Errorf("%q is not valid", string(l))
		}
	}
	if cards.LevelNotice != "notice" || cards.LevelAlert != "alert" || cards.LevelCritical != "critical" {
		t.Errorf("the levels are %q %q %q", cards.LevelNotice, cards.LevelAlert, cards.LevelCritical)
	}
	for _, l := range []cards.Level{"", "Alert", "alert ", "warning", "info", "critical\n", "none"} {
		if l.Valid() {
			t.Errorf("%q is valid", string(l))
		}
	}
	// A finding that was built by hand has the zero level, which is none of the three, and Inspect never
	// makes one.
	var f cards.Finding
	if f.Level.Valid() {
		t.Error("the zero level is valid")
	}
	rep := mustInspect(t, memBundle(map[string]string{cardFile("a"): "{", cardFile("b"): cardRootB, cardFile("c"): cardRootB}).open(nil))
	if len(rep.Findings) != 2 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	for _, f := range rep.Findings {
		if !f.Level.Valid() {
			t.Errorf("Inspect made %+v", f)
		}
	}
}

func TestALineHoldsTheCodeThePathAndTheDetailAndNoLevelAndNoLineBreak(t *testing.T) {
	f := cards.Finding{Code: cards.FileInvalid, Level: cards.LevelCritical, Path: "want/cards/a.yaml", Detail: "line 2: serial must be 1 to 10 digits and nothing else"}
	if got, want := f.Line(), "card-file-invalid want/cards/a.yaml: line 2: serial must be 1 to 10 digits and nothing else"; got != want {
		t.Errorf("Line() = %q, want %q", got, want)
	}
	if strings.Contains(f.Line(), "critical") {
		t.Error("the line shows the level")
	}
	hostile := []cards.Finding{
		{Code: "card-x\n", Path: "want/cards/a\nb.yaml", Detail: "x\r\ny\u202e\x00\x7f\xff"},
		{Code: "\u202e", Path: "\u2028", Detail: "\u2029"},
		{Code: "", Path: "", Detail: ""},
		{Code: cards.SerialTwice, Path: strings.Repeat("\x01", 100), Detail: strings.Repeat("\U0001f600", 100)},
	}
	for _, h := range hostile {
		got := h.Line()
		if !printable(got) || strings.ContainsAny(got, "\r\n") {
			t.Errorf("Line() of %+q is not printable ASCII on one line: %+q", h, got)
		}
	}
}

func TestTwoDifferentPathsNeverGiveTheSameLine(t *testing.T) {
	// The path is a name from a file system: a backslash is doubled, a space is written \x20, a byte that is
	// not UTF-8 is written \xNN and is not the character U+FFFD.
	pathsList := []string{
		"want/cards/a b.yaml", "want/cards/a\\x20b.yaml", "want/cards/a\x01b.yaml", "want/cards/a\\u0001b.yaml",
		"want/cards/a\xffb.yaml", "want/cards/a\ufffdb.yaml", "want/cards/a\\xffb.yaml", "want/cards/a\\ufffdb.yaml",
		"want/cards/a\\b.yaml", "want/cards/a\\\\b.yaml", "want/cards/a:b.yaml", "want/cards/a\u202eb.yaml", "want/cards/a\\u202eb.yaml",
	}
	seen := map[string]string{}
	for _, p := range pathsList {
		line := cards.Finding{Code: cards.FileInvalid, Path: p, Detail: "d"}.Line()
		if other, ok := seen[line]; ok {
			t.Errorf("the paths %+q and %+q give one line %q", other, p, line)
		}
		seen[line] = p
	}
}
