package cards_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

// This part reads no card: no PC/SC, no USB, no card library, no outside program. The packages that read a
// card file may import the standard library packages and the packages of this list, and nothing else. A new
// import fails this test, and the person who adds it says why.
var allowedImports = []string{
	// The standard library.
	"bytes", "cmp", "context", "crypto/sha256", "encoding/hex", "errors", "fmt", "io", "io/fs",
	"net/mail", // used by settings.go for the release address; it is not the network
	"regexp", "slices", "sort", "strconv", "strings", "unicode", "unicode/utf8",
	"time", // the date of a key of a root file and the time that the caller gives; a value type, no clock is read
	// The strict YAML reader.
	"go.yaml.in/yaml/v3",
	// The packages of this module that read a bundle.
	"ritueel.id/ritueel/internal/fsx", "ritueel.id/ritueel/internal/jsonset", "ritueel.id/ritueel/internal/pki",
	"ritueel.id/ritueel/internal/wanted",
}

// importsOf returns the import paths of every non-test Go file of a package folder and the number of
// files that it read.
func importsOf(t testing.TB, dir string) (imports []string, files int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		files++
		for _, im := range f.Imports {
			p, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			imports = append(imports, p)
		}
	}
	return imports, files
}

// outside returns the imports that are not in the list.
func outside(imports []string) []string {
	var bad []string
	for _, p := range imports {
		if !slices.Contains(allowedImports, p) {
			bad = append(bad, p)
		}
	}
	return bad
}

func TestNoPackageThatReadsACardFileImportsAnythingThatCouldReachACard(t *testing.T) {
	for _, pkg := range []string{"cards", "wanted"} {
		imports, files := importsOf(t, testrepo.Path(t, "internal", pkg))
		if files == 0 {
			t.Fatalf("internal/%s: the guard found no Go file", pkg)
		}
		if len(imports) == 0 {
			t.Fatalf("internal/%s: the guard found no import", pkg)
		}
		if bad := outside(imports); len(bad) != 0 {
			t.Errorf("internal/%s imports %q, which is not in the list of imports that cannot reach a card", pkg, bad)
		}
	}
}

func TestTheGuardSeesAnImportThatCouldReachACard(t *testing.T) {
	// The negative control: the names that a reader of a card would need are all outside the list.
	for _, p := range []string{
		"os/exec", "net", "net/http", "syscall", "golang.org/x/sys/unix", "github.com/go-piv/piv-go/v2/piv",
		"github.com/ebfe/scard", "os", "unsafe", "plugin", "ritueel.id/ritueel/internal/keystore",
		"ritueel.id/ritueel/internal/ceremony", "ritueel.id/ritueel/internal/openpgp",
	} {
		if len(outside([]string{p})) != 1 {
			t.Errorf("the list lets %q in", p)
		}
	}
	// And the guard reads the files: it fails when a folder has none.
	dir := t.TempDir()
	if _, files := importsOf(t, dir); files != 0 {
		t.Errorf("an empty folder has %d files", files)
	}
	src := "package x\n\nimport (\n\t\"os/exec\"\n\t\"fmt\"\n)\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "y_test.go"), []byte("package x\n\nimport \"net\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	imports, files := importsOf(t, dir)
	if files != 1 || !slices.Equal(imports, []string{"os/exec", "fmt"}) || !slices.Equal(outside(imports), []string{"os/exec"}) {
		t.Errorf("files %d, imports %q, outside %q", files, imports, outside(imports))
	}
}
