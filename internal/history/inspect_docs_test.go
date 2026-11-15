//go:build linux || darwin

package history

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// The comments of Inspect say when there is a State and how the labels are used. They are part of
// the contract for a caller, so a test reads them from the source and holds the words that the
// rule needs: the newest set is the last of the chain and holds the highest sequence, a label is
// for display only, and the caller reads an attempt before it takes a ceremony as open.

func docWords(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return strings.Join(strings.Fields(g.Text()), " ")
}

func TestInspectCommentsSayWhenThereIsAState(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "inspect.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]string{}
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, sp := range gd.Specs {
			switch s := sp.(type) {
			case *ast.ValueSpec:
				for _, n := range s.Names {
					docs[n.Name] = docWords(gd.Doc)
				}
			case *ast.TypeSpec:
				docs[s.Name.Name] = docWords(gd.Doc)
				if st, ok := s.Type.(*ast.StructType); ok {
					for _, f := range st.Fields.List {
						for _, n := range f.Names {
							docs[s.Name.Name+"."+n.Name] = docWords(f.Doc)
						}
					}
				}
			}
		}
	}
	want := map[string][]string{
		"ErrOrder":         {"highest sequence", "sequence of a list of the chain cannot be read", "number that is in use"},
		"State.Newest":     {"last of the chain", "highest sequence"},
		"SetInfo":          {"last set of the chain", "highest sequence"},
		"State.Lists":      {"control characters", "escape of internal/jsonset", "Newest.ListJSON", "never from these labels"},
		"State.Unfinished": {"a file named attempt.json", "the caller reads the attempt before it takes the ceremony as open"},
	}
	for name, words := range want {
		got, ok := docs[name]
		if !ok || got == "" {
			t.Errorf("%s has no doc comment", name)
			continue
		}
		for _, w := range words {
			if !strings.Contains(got, w) {
				t.Errorf("the doc of %s does not say %q:\n%s", name, w, got)
			}
		}
	}
	for _, w := range []string{"later part", "a person or a later part", "who reads"} {
		if strings.Contains(docs["State.Unfinished"], w) {
			t.Errorf("the doc of State.Unfinished still says %q", w)
		}
	}
}

func TestInspectPackageDocSaysWhenThereIsAState(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "doc.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	got := docWords(file.Doc)
	for _, w := range []string{"the last list of the chain holds the highest sequence", "Inspection.OrderErr"} {
		if !strings.Contains(got, w) {
			t.Errorf("the package doc does not say %q", w)
		}
	}
}
