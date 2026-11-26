package atoomsoftware_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

// ritueel is not a network service (record 0012, rule 1): no Go file of the program, apart from the tests, makes a
// listener, serves HTTP or serves the socket of atom, and only this package links the in-process driver.
func TestNoFileOfTheProgramListensOnASocketOrServesTheKeyPort(t *testing.T) {
	root := testrepo.Root(t)
	banned := map[string][]string{
		"net":    {"Listen", "ListenPacket", "ListenTCP", "ListenUDP", "ListenUnix", "ListenUnixgram", "ListenIP", "ListenMulticastUDP", "ListenConfig"},
		"http":   {"ListenAndServe", "ListenAndServeTLS", "Serve", "ServeTLS", "Server"},
		"socket": {"Serve", "Listen", "ServeUnix"},
	}
	checked := 0
	for _, top := range []string{"cmd", "internal", "tools"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if err != nil {
				return err
			}
			checked++
			rel, _ := filepath.Rel(root, p)
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if path == "github.com/truvity/atoom/socket" && !strings.HasPrefix(rel, "internal/keystore/atoomsoftware/") {
					t.Errorf("%s imports the socket package of atom: only internal/keystore/atoomsoftware links the driver", rel)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && slices.Contains(banned[id.Name], sel.Sel.Name) {
					t.Errorf("%s uses %s.%s", rel, id.Name, sel.Sel.Name)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 50 {
		t.Fatalf("only %d files were looked at", checked)
	}
}
