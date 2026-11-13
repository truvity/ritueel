package canonjson

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

// The package comments say that neither writing nor reading calls encoding/json: the three packages
// read and write the files that are signed, and what they do not call, they cannot change a value
// by. This reads the imports of their files and checks it.
func TestNoPackageOfTheThreeImportsEncodingJSON(t *testing.T) {
	checked := 0
	for _, pkg := range []string{"jsonset", "strictjson", "canonjson"} {
		dir := testrepo.Path(t, "internal", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "encoding/json" || strings.HasPrefix(path, "encoding/json/") {
					t.Errorf("%s/%s imports %s", pkg, e.Name(), path)
				}
				// jsonset is what the other two share, so it imports neither of them.
				if pkg == "jsonset" && strings.HasPrefix(path, "ritueel.id/") {
					t.Errorf("jsonset/%s imports %s", e.Name(), path)
				}
				// strictjson does not import canonjson: canonjson imports it.
				if pkg == "strictjson" && strings.HasSuffix(path, "/canonjson") {
					t.Errorf("strictjson/%s imports %s", e.Name(), path)
				}
			}
			checked++
		}
	}
	if checked < 7 {
		t.Errorf("only %d files were looked at", checked)
	}
}
