package strictjson

import (
	"go/ast"
	goparser "go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A switch over a kind (the kind of a Go type, or the kind of a parsed value) must not have a
// default branch that does nothing: a kind that no case names would then be passed over without a
// word, and the writer and the reader would drift apart from the judge of the types (package
// jsonset) without any test noticing. The default of such a switch panics, or returns an error or a
// refusal that it builds there. This test reads the source of the three packages, and fails for a
// default that is silent. It looks at the syntax only (no types), so what it takes for "a switch over
// a kind" is a switch whose tag is a call or a field called Kind, or one whose cases name a
// reflect kind (reflect.Struct) or a kind of this package's parsed values (Object, List, String,
// Integer, Bool, Fraction, Null).

// kindWords are the names that a case of a switch over a kind of a parsed value has.
var kindWords = []string{"Object", "List", "String", "Integer", "Bool", "Fraction", "Null"}

// silentDefaults is the allowlist: the functions whose switch over a kind has a default that
// returns a plain value on purpose, with the reason.
var silentDefaults = map[string]string{
	// isEmpty says whether a value is empty for omitempty: a struct, and any other kind that is not
	// a collection, a string, a number, a bool or a nilable, is never empty. The kinds that the
	// type judge refuses never get here, so there is no unnamed kind to pass over in silence.
	"isEmpty": "every kind that is not named is never empty, and the judge has refused the rest",
}

// overAKind reports whether the switch looks like one over a kind.
func overAKind(sw *ast.SwitchStmt) bool {
	switch tag := sw.Tag.(type) {
	case *ast.CallExpr:
		if sel, ok := tag.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Kind" {
			return true
		}
	case *ast.SelectorExpr:
		if tag.Sel.Name == "Kind" {
			return true
		}
	}
	for _, c := range sw.Body.List {
		for _, e := range c.(*ast.CaseClause).List {
			switch e := e.(type) {
			case *ast.SelectorExpr:
				if id, ok := e.X.(*ast.Ident); ok && id.Name == "reflect" {
					return true
				}
			case *ast.Ident:
				if sw.Tag != nil && slices.Contains(kindWords, e.Name) {
					return true
				}
			}
		}
	}
	return false
}

// loud reports whether the statements panic or return a value that is built there: an error, a
// refusal, a call or a literal, and not nil, false or true or a name.
func loud(body []ast.Stmt) bool {
	found := false
	for _, s := range body {
		ast.Inspect(s, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "panic" {
					found = true
				}
			case *ast.ReturnStmt:
				if len(n.Results) == 0 {
					return true
				}
				switch last := n.Results[len(n.Results)-1].(type) {
				case *ast.CallExpr, *ast.CompositeLit:
					found = true
				case *ast.UnaryExpr:
					if last.Op == token.AND {
						found = true
					}
				}
			}
			return true
		})
	}
	return found
}

// silentKindDefaults parses the source and lists the switches over a kind whose default is silent,
// as "function:line", and counts the switches over a kind that it looked at.
func silentKindDefaults(t *testing.T, name string, src any) (silent []string, looked int) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := goparser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || !overAKind(sw) {
				return true
			}
			for _, c := range sw.Body.List {
				cc := c.(*ast.CaseClause)
				if cc.List != nil {
					continue
				}
				looked++
				if _, allowed := silentDefaults[fn.Name.Name]; !allowed && !loud(cc.Body) {
					silent = append(silent, fn.Name.Name+":"+strconv.Itoa(fset.Position(cc.Pos()).Line))
				}
			}
			return true
		})
	}
	return silent, looked
}

func TestNoSwitchOverAKindHasASilentDefault(t *testing.T) {
	total := 0
	for _, dir := range []string{"../jsonset", "../strictjson", "../canonjson"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no Go file in %s: %v", dir, err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			silent, looked := silentKindDefaults(t, f, data)
			total += looked
			for _, s := range silent {
				t.Errorf("%s: the default of a switch over a kind is silent (%s): make it panic, or return an error", f, s)
			}
		}
	}
	// A check that looks at nothing is no check: these are the switches over a kind with a default
	// that the three packages hold (the judge, the reader's kind names, its filler, the writer's
	// value switch, the canonical writer and isEmpty).
	if total < 7 {
		t.Errorf("only %d switches over a kind with a default were found, want at least 7: the test no longer sees the source it guards", total)
	}
}

// The check itself, on small sources: what it must fail and what it must pass.
func TestTheGuardAgainstASilentDefaultSeesWhatItShould(t *testing.T) {
	const head = "package p\nimport \"reflect\"\nvar _ = reflect.Bool\n"
	cases := []struct {
		name   string
		body   string
		silent bool
		looked int
	}{
		{"a default that returns nil", "func f(t reflect.Type) error {\nswitch t.Kind() {\ncase reflect.Bool:\nreturn nil\ndefault:\nreturn nil\n}\nreturn nil\n}", true, 1},
		{"an empty default", "func f(t reflect.Type) {\nswitch t.Kind() {\ncase reflect.Bool:\ndefault:\n}\n}", true, 1},
		{"a default that only breaks", "func f(t reflect.Type) {\nswitch t.Kind() {\ncase reflect.Bool:\ndefault:\nbreak\n}\n}", true, 1},
		{"a default that returns false", "func f(t reflect.Type) bool {\nswitch t.Kind() {\ncase reflect.Bool:\nreturn true\ndefault:\nreturn false\n}\n}", true, 1},
		{"a default that panics", "func f(t reflect.Type) {\nswitch t.Kind() {\ncase reflect.Bool:\ndefault:\npanic(\"x\")\n}\n}", false, 1},
		{"a default that returns an error built there", "func f(t reflect.Type) error {\nswitch t.Kind() {\ncase reflect.Bool:\nreturn nil\ndefault:\nreturn errorf(\"x\")\n}\n}\nfunc errorf(string) error { return nil }", false, 1},
		{"a default that returns a refusal literal", "type R struct{}\nfunc f(t reflect.Type) *R {\nswitch t.Kind() {\ncase reflect.Bool:\nreturn nil\ndefault:\nreturn &R{}\n}\n}", false, 1},
		{"a switch whose tag is a field Kind, with a silent default", "type v struct{ Kind int }\nfunc f(x v) {\nswitch x.Kind {\ncase 1:\ndefault:\n}\n}", true, 1},
		{"a switch whose cases name a reflect kind, with no tag call", "func f(k reflect.Kind) bool {\nswitch k {\ncase reflect.Bool:\nreturn true\ndefault:\nreturn false\n}\n}", true, 1},
		{"a switch whose cases are the kinds of a parsed value", "type K int\nconst (Object K = iota; List)\nfunc f(k K) bool {\nswitch k {\ncase Object:\nreturn true\ndefault:\nreturn false\n}\n}", true, 1},
		{"a switch over something else is not looked at", "func f(c byte) bool {\nswitch c {\ncase ' ':\nreturn true\ndefault:\nreturn false\n}\n}", false, 0},
		{"a switch with no tag is not looked at", "func f(r rune) bool {\nswitch {\ncase r < 0x20:\nreturn true\ndefault:\nreturn false\n}\n}", false, 0},
		{"a switch over a kind with no default is not looked at", "func f(t reflect.Type) bool {\nswitch t.Kind() {\ncase reflect.Bool:\nreturn true\n}\nreturn false\n}", false, 0},
		{"a silent default in isEmpty is allowed, and still counted", "func isEmpty(t reflect.Type) bool {\nswitch t.Kind() {\ncase reflect.Bool:\nreturn true\ndefault:\nreturn false\n}\n}", false, 1},
		{"a silent default in a function of another name is not", "func isEmptyNot(t reflect.Type) bool {\nswitch t.Kind() {\ncase reflect.Bool:\nreturn true\ndefault:\nreturn false\n}\n}", true, 1},
		{"a nested switch is found", "func f(t reflect.Type) {\nswitch t.Kind() {\ncase reflect.Bool:\nswitch t.Elem().Kind() {\ncase reflect.Int:\ndefault:\n}\ndefault:\npanic(1)\n}\n}", true, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			silent, looked := silentKindDefaults(t, "x.go", head+tc.body)
			if (len(silent) > 0) != tc.silent || looked != tc.looked {
				t.Errorf("silent %v, looked at %d; want silent %v, looked at %d", silent, looked, tc.silent, tc.looked)
			}
		})
	}
}
