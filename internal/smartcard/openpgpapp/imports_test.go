package openpgpapp

import (
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// This package speaks to a Transport that it is given and imports no reader, no device code and no
// outside program. The imports of its files are the standard library packages and the packages of this
// list, and nothing else; a new import fails this test, and the person who adds it says why.
var allowedImports = []string{
	"bytes", "errors", "fmt", "slices", "sync", "time", // the standard library
	"ritueel.id/ritueel/internal/smartcard/apdu",
}

func TestImports(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := 0
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		files++
		for _, im := range f.Imports {
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(allowedImports, p) {
				t.Errorf("%s imports %s", name, p)
			}
		}
	}
	if files == 0 {
		t.Fatal("no file was read")
	}
}
