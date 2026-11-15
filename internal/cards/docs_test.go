package cards_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/testrepo"
)

// The comments of the package are read as the pages are: a comment that names a later part of the work by
// its number goes stale when a later change replaces what it points at, so no comment of a Go file of the
// package names one. And the doc comment of the report says what a caller may do with it.

// numberedPart finds a part named by its number ("part 16", "parts 7a and 7b", "7c"), a step or a phase
// named by number, or a number and a letter that names a part ("16a").
var numberedPart = regexp.MustCompile(`(?i)\b(?:parts?|steps?|phases?|milestones?)\s+#?\d+[a-z]?\b|\b\d{1,2}[a-e]\b`)

// commentsOf returns every comment of every non-test Go file of a package folder, with the file name, and the
// number of files read.
func commentsOf(t testing.TB, dir string) (map[string][]string, int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	files := 0
	fset := token.NewFileSet()
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		files++
		for _, g := range f.Comments {
			out[name] = append(out[name], g.Text())
		}
	}
	return out, files
}

func TestNoCommentOfThePackageNamesALaterPartByItsNumber(t *testing.T) {
	comments, files := commentsOf(t, testrepo.Path(t, "internal", "cards"))
	if files == 0 || len(comments) == 0 {
		t.Fatalf("the guard found %d files and %d files with comments", files, len(comments))
	}
	for name, list := range comments {
		for _, c := range list {
			if m := numberedPart.FindString(c); m != "" {
				t.Errorf("%s: a comment names a later part by number (%q): %q", name, m, c)
			}
		}
	}
}

func TestTheGuardOfTheNumberOfAPartSeesWhatItMustAndLeavesTheRest(t *testing.T) {
	for _, bad := range []string{"part 16 may replace this table", "Part 7b reads it", "parts 7a and 7b", "see 7c", "step 3", "milestone 2", "phase 4", "the 16a table"} {
		if !numberedPart.MatchString(bad) {
			t.Errorf("the guard lets %q in", bad)
		}
	}
	for _, good := range []string{"a later change may replace this table", "the first part of the name", "a part of a file", "record 0006, rule 45", "the 240 bytes", "ends at 237 bytes", "a card of 8 MiB", "item 3"} {
		if numberedPart.MatchString(good) {
			t.Errorf("the guard refuses %q", good)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("package x\n\n// Part 16 may change this.\nvar a int\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "y_test.go"), []byte("package x\n\n// part 17.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	comments, files := commentsOf(t, dir)
	if files != 1 || len(comments["x.go"]) != 1 || !numberedPart.MatchString(comments["x.go"][0]) {
		t.Errorf("files %d, comments %q", files, comments)
	}
}

// The doc comment of Report says that a caller treats the report and its cards as read-only.
func TestTheDocCommentOfTheReportSaysACallerTreatsItAsReadOnly(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(testrepo.Path(t, "internal", "cards"), "inspect.go"), nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var doc string
	ast.Inspect(f, func(n ast.Node) bool {
		if g, ok := n.(*ast.GenDecl); ok && g.Tok == token.TYPE {
			for _, s := range g.Specs {
				if ts, ok := s.(*ast.TypeSpec); ok && ts.Name.Name == "Report" {
					doc = g.Doc.Text()
				}
			}
		}
		return true
	})
	if doc == "" {
		t.Fatal("type Report has no doc comment")
	}
	flat := strings.Join(strings.Fields(doc), " ")
	if !strings.Contains(flat, "read-only") || !strings.Contains(flat, "caller treats a Report and its cards as read-only") {
		t.Errorf("the doc comment of Report does not say that a caller treats it as read-only: %q", flat)
	}
}

// Two runs of Inspect share no memory: a caller that changes a report, a card or the bytes of a card file
// changes nothing that a later run returns.
func TestAReportSharesNoMemoryWithAnotherRun(t *testing.T) {
	n := memBundle(with(goodSet(), map[string]string{cardFile("zz-bad"): "version: 2\n"}))
	first := mustInspect(t, n.open(nil))
	wantNames, wantFindings := names(first), slices.Clone(first.Findings)
	wantData := string(first.Cards[0].File.Data)
	// A caller that breaks the rule: change everything it can reach.
	for i := range first.Cards {
		for j := range first.Cards[i].File.Data {
			first.Cards[i].File.Data[j] = 'x'
		}
		first.Cards[i].Name = "changed"
	}
	for i := range first.Findings {
		first.Findings[i].Detail = "changed"
		first.Findings[i].Path = "changed"
	}
	first.Cards = nil
	first.Findings = nil
	second := mustInspect(t, n.open(nil))
	if !slices.Equal(names(second), wantNames) || len(second.Findings) != len(wantFindings) {
		t.Fatalf("second run: cards %q findings %+v", names(second), second.Findings)
	}
	for i := range wantFindings {
		if second.Findings[i] != wantFindings[i] {
			t.Errorf("finding %d = %+v, want %+v", i, second.Findings[i], wantFindings[i])
		}
	}
	if string(second.Cards[0].File.Data) != wantData {
		t.Errorf("the bytes of a card file were changed through another report")
	}
	if cards.Check(t.Context(), n.open(nil)) == nil {
		t.Error("Check accepts a set with a bad file after a report was changed")
	}
}
