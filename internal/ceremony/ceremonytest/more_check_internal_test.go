package ceremonytest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/wanted"
)

// More reads the history of the bundle it made, so a later change of a rule of the check shows up at
// its cause. A ceremony is made here the way More makes one, with a hook that edits it before it is
// written (a broken root list), and the check at the end of More is called on the result.

// madeWith makes one more ceremony on a bundle of one recorded ceremony as more does, after edit
// has changed the hand-made ceremony, and returns the bundle.
func madeWith(t *testing.T, edit func(s *synth)) *Made {
	t.Helper()
	m := Bundle(t, Options{Step: Recorded})
	st := stateOf(t, m.Dir)
	s := &synth{end: st.End, seq: st.Newest.Number + 1}
	s.at = m.at.Add(time.Duration(st.Records) * time.Hour)
	s.name = s.at.Format("20060102T150405Z") + "-" + files.CommandApply
	s.label = nextLabel(t, m.Dir)
	sum := sha256.Sum256([]byte("a synthetic key for a test " + s.label))
	s.pin = hex.EncodeToString(sum[:])
	for _, p := range []string{"ritueel.yaml", "want/roots/x509.yaml"} {
		data, err := os.ReadFile(filepath.Join(m.Dir, filepath.FromSlash(p)))
		if err != nil {
			t.Fatal(err)
		}
		s.copies = append(s.copies, wanted.File{Path: p, Data: data, SHA256: files.Digest(data)})
	}
	s.rootList = s.nextList(t, st.Newest.ListJSON)
	s.setName = fmt.Sprintf("%d-%s", s.seq, files.Digest(s.rootList)[:8])
	if edit != nil {
		edit(s)
	}
	w, err := fsx.Open(m.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	s.write(t, w)
	m.Ceremony, m.Set = s.name, s.setName
	return m
}

// renameSet gives the set the name that its edited list makes.
func (s *synth) renameSet() { s.setName = fmt.Sprintf("%d-%s", s.seq, files.Digest(s.rootList)[:8]) }

func TestCheckMadeAcceptsAWholeCeremony(t *testing.T) {
	m := madeWith(t, nil)
	if msg := failingOrNot(t, func(tb testing.TB) { checkMade(tb, m, 2) }); msg != "" {
		t.Errorf("a whole ceremony failed: %s", msg)
	}
}

// A ceremony whose root list the check of the history fails makes More fail the test, and the message
// names the ceremony and the first finding.
func TestCheckMadeFailsOnABrokenRootList(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		edit       func(s *synth)
	}{
		{"a name that is not the sequence of the list", "trust-sequence", func(s *synth) {
			s.setName = "9-" + files.Digest(s.rootList)[:8]
		}},
		{"a list with no sequence", "anchor-unknown", func(s *synth) {
			s.rootList = []byte(strings.Replace(string(s.rootList), `"sequence":2,`, "", 1))
			s.renameSet()
		}},
		{"a list that has no anchor", "anchor-unknown", func(s *synth) {
			s.rootList = []byte(strings.Replace(string(s.rootList), `"last_record_sha256":"`+s.end+`",`, "", 1))
			s.renameSet()
		}},
		{"a list that names a record that is not the one before", "anchor-unknown", func(s *synth) {
			s.rootList = []byte(strings.Replace(string(s.rootList), s.end, strings.Repeat("0", 64), 1))
			s.renameSet()
		}},
		{"a name with no trust number", "trust-sequence", func(s *synth) { s.setName = "latest" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := madeWith(t, tc.edit)
			msg := failing(t, func(tb testing.TB) { checkMade(tb, m, 2) })
			for _, want := range []string{m.Ceremony, "the check of the history fails", "failing findings", tc.code} {
				if !strings.Contains(msg, want) {
					t.Errorf("the message does not hold %q: %s", want, msg)
				}
			}
		})
	}
}

// With two failing findings the message counts both and names the first one of the report.
func TestCheckMadeNamesTheFirstFailingFinding(t *testing.T) {
	m := madeWith(t, func(s *synth) {
		s.rootList = []byte(strings.Replace(string(s.rootList), `"last_record_sha256":"`+s.end+`",`, "", 1))
		s.setName = "9-" + files.Digest(s.rootList)[:8]
	})
	fsys, err := fsx.OpenFS(m.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	in, err := history.Inspect(context.Background(), fsys)
	if err != nil {
		t.Fatal(err)
	}
	failed := in.Report.Failing()
	if len(failed) < 2 {
		t.Fatalf("the bundle has %d failing findings, the test needs two", len(failed))
	}
	msg := failing(t, func(tb testing.TB) { checkMade(tb, m, 2) })
	if want := fmt.Sprintf("(%d failing findings, the first: %s)", len(failed), failed[0].Line()); !strings.Contains(msg, want) {
		t.Errorf("message %q does not hold %q", msg, want)
	}
}

// The other three ways in which the bundle that More made can be refused.
func TestCheckMadeRefuses(t *testing.T) {
	t.Run("a count of records that is not the one that was asked", func(t *testing.T) {
		m := madeWith(t, nil)
		for _, want := range []int{1, 3} {
			msg := failing(t, func(tb testing.TB) { checkMade(tb, m, want) })
			if !strings.Contains(msg, "2 records (want "+fmt.Sprint(want)+")") {
				t.Errorf("want %d: message %q", want, msg)
			}
		}
	})
	t.Run("an open attempt", func(t *testing.T) {
		m := madeWith(t, nil)
		if err := os.Remove(filepath.Join(m.Dir, "history", m.Ceremony, "record.json")); err != nil {
			t.Fatal(err)
		}
		// One record is left, and one is wanted: only the attempt is wrong.
		msg := failing(t, func(tb testing.TB) { checkMade(tb, m, 1) })
		if !strings.Contains(msg, "1 open attempts") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a bundle that is gone", func(t *testing.T) {
		m := &Made{Dir: filepath.Join(t.TempDir(), "gone"), Ceremony: "x"}
		msg := failing(t, func(tb testing.TB) { checkMade(tb, m, 1) })
		if !strings.Contains(msg, "cannot be") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a folder that is no bundle", func(t *testing.T) {
		msg := failing(t, func(tb testing.TB) { checkMade(tb, &Made{Dir: t.TempDir()}, 1) })
		if !strings.Contains(msg, "cannot be inspected") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a bundle folder that is a file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		failing(t, func(tb testing.TB) { checkMade(tb, &Made{Dir: p}, 1) })
	})
}

// More itself calls the check as the last thing it does, with the count of records that it makes:
// the number it read plus one. No bundle can be made that passes the reading before it and fails
// the reading after it by the means that a test has (the clock, the wanted files and the label do not
// change a finding), so the call is held by reading the source of the function.
func TestMoreEndsWithTheCheckOfTheBundleItMade(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "more.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "more" && fn.Recv == nil {
			body = fn.Body
		}
	}
	if body == nil || len(body.List) == 0 {
		t.Fatal("no function more")
	}
	last, ok := body.List[len(body.List)-1].(*ast.ExprStmt)
	if !ok {
		t.Fatalf("the last statement of more is %T, not a call", body.List[len(body.List)-1])
	}
	call, ok := last.X.(*ast.CallExpr)
	if !ok {
		t.Fatalf("the last statement of more is not a call")
	}
	if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "checkMade" || len(call.Args) != 3 {
		t.Fatalf("the last statement of more is not checkMade(t, m, n)")
	}
	// The count is the records that were read before, plus one.
	bin, ok := call.Args[2].(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		t.Fatalf("the count is not a sum")
	}
	sel, ok := bin.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Records" {
		t.Errorf("the count does not start from the records that were read")
	}
	if lit, ok := bin.Y.(*ast.BasicLit); !ok || lit.Value != "1" {
		t.Errorf("the count does not add one")
	}
}
