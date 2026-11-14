//go:build linux || darwin

package history

import (
	"strings"
	"testing"
)

// A name from the stick is shown with its space written as \x20, in every place a name is walked:
// history/, trust/, a ceremony folder, a trust set (at the first level and below it) and the folder
// of copies. So no finding line holds a space inside a path, a name cannot start a second line or
// put the words of the end line or of another finding into one, and two names never give one line.
// Before, the space was shown as it is, and a leftover name such as
// ".rt-x history: 3 ceremony records, end a36562f0" was found by a search of the output for the end.

// namesWithWords are names that carry the text of the end line, of a finding line, of a plain
// space, and a space beside a colon, a tab, and at either end.
var namesWithWords = []string{
	"a b",
	"history: 3 ceremony records, end a36562f0",
	"history: 3 ceremony records, end a36562f0 and more",
	"unexpected-name history x: y",
	"file-unlisted trust 1-3fa9c1d3 a.pem: no record lists it",
	"chain-broken history",
	"x: fork history c1",
	" leading",
	"trailing ",
	"two  spaces",
	"a\tb",
	".rt-x history: 3 ceremony records, end a36562f0",
	".RT-a b",
	".rt- ",
}

// shownIn is a place that a name can be walked, with the code that a bad name and a leftover
// temporary name get there.
type shownIn struct {
	label string
	dir   func(r [3]*rec) string
	bad   Code
	temp  Code
}

var shownPlaces = []shownIn{
	{"history", func([3]*rec) string { return "history" }, UnexpectedName, UnexpectedFile},
	{"trust", func([3]*rec) string { return "trust" }, UnexpectedName, UnexpectedFile},
	{"ceremony folder", func(r [3]*rec) string { return "history/" + r[0].folder }, UnexpectedName, UnexpectedFile},
	{"wanted", func(r [3]*rec) string { return "history/" + r[0].folder + "/wanted" }, UnexpectedName, UnexpectedFile},
	{"trust set", func(r [3]*rec) string { return "trust/" + r[2].set }, UnexpectedName, FileUnlisted},
	{"below a trust set", func(r [3]*rec) string { return "trust/" + r[2].set + "/keyring" }, UnexpectedName, FileUnlisted},
}

func TestNameWithAWordOrASpaceIsShownWithTheEscapeOfASpaceInEveryPlace(t *testing.T) {
	for _, place := range shownPlaces {
		for _, name := range namesWithWords {
			for _, folder := range []bool{false, true} {
				kind := map[bool]string{false: "file", true: "folder"}[folder]
				t.Run(place.label+" "+kind+" "+name, func(t *testing.T) {
					b, r := threeRecords(t)
					dir := place.dir(r)
					b.mkdir(dir)
					entry(t, b, dir, name, folder)
					rep := b.run()
					code := place.bad
					if hasTempPrefix(name) {
						code = place.temp
					}
					p := dir + "/" + escaped(name)
					wantFindings(t, rep, []wf{{code, p}})
					for _, f := range rep.Findings {
						if strings.Contains(f.Path, " ") {
							t.Errorf("the path holds a space: %q", f.Path)
						}
						if !strings.HasPrefix(f.Line(), string(f.Code)+" "+p+": ") {
							t.Errorf("the line %q does not start with the code and the path", f.Line())
						}
					}
				})
			}
		}
	}
}

// All the names in all the places at once: every line is different, and no line begins with
// anything but the code of a finding.
func TestNamesWithWordsGiveDifferentLinesThatAllStartWithACode(t *testing.T) {
	b, r := threeRecords(t)
	for _, place := range shownPlaces {
		dir := place.dir(r)
		b.mkdir(dir)
		for _, name := range namesWithWords {
			entry(t, b, dir, name, false)
		}
	}
	rep := b.run()
	if want := len(shownPlaces) * len(namesWithWords); len(rep.Findings) != want {
		t.Fatalf("%d findings, want %d: %v", len(rep.Findings), want, findingsOf(rep))
	}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		line := f.Line()
		if seen[line] {
			t.Errorf("two findings give one line: %q", line)
		}
		seen[line] = true
		if strings.Contains(f.Path, " ") {
			t.Errorf("the path holds a space: %q", f.Path)
		}
		code, _, _ := strings.Cut(line, " ")
		if !isCodeWord(code) {
			t.Errorf("the line %q does not start with a code", line)
		}
		if strings.HasPrefix(line, "history:") {
			t.Errorf("the line %q starts like the end line", line)
		}
	}
	checkForm(t, rep)
}

// A name with the text of the escape typed out (a backslash, x, 2, 0) is not the name with a
// space: the two are shown differently, so one line stands for one name.
func TestSpaceAndTheTypedEscapeOfASpaceAreShownApart(t *testing.T) {
	b, r := threeRecords(t)
	dir := "trust/" + r[2].set
	entry(t, b, dir, "a b", false)
	entry(t, b, dir, `a\x20b`, false)
	rep := b.run()
	wantFindings(t, rep, []wf{
		{UnexpectedName, dir + `/a\x20b`},
		{UnexpectedName, dir + `/a\\x20b`},
	})
}

// A temporary name with no space inside a trust set, as a file and as a folder, was a notice and its
// contents were never looked at; elsewhere it is a notice, as a file too. (The folder form is held in
// TestTemporaryNameInsideATrustSetFailsAndElsewhereIsANotice.)
func TestTemporaryNameThatIsAFileIsANoticeInHistoryTrustCeremonyAndCopies(t *testing.T) {
	b, r := threeRecords(t)
	var want []wf
	for _, p := range []string{
		"history/.rt-abcdefghijk",
		"history/.RT-abcdefghijk",
		"trust/.rt-abcdefghijk",
		"history/" + r[0].folder + "/.rt-abcdefghijk",
		"history/" + r[0].folder + "/wanted/.rt-abcdefghijk",
		"history/" + r[0].folder + "/wanted/.rt-",
	} {
		b.put(p, []byte("x"))
		want = append(want, wf{UnexpectedFile, p})
	}
	rep := b.run()
	wantFindings(t, rep, want)
	if !rep.Clean() {
		t.Error("a notice makes the history unclean")
	}
}
