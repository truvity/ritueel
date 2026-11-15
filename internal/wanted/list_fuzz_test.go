//go:build linux || darwin

package wanted_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// FuzzListRoots lists a folder whose file names and contents come from the fuzzer. No outside
// program is started and nothing is written outside the folder of the iteration.
func FuzzListRoots(f *testing.F) {
	f.Add("a.yaml", lstRootText, "b.yaml", "version: 1\nkind: ssh\n", byte(0))
	f.Add("a.yaml", lstRootText, "A.yaml", lstRootText, byte(0))
	f.Add("a.yaml", "", "b.txt", "x", byte(1))
	f.Add("x\x01.yaml", lstRootText, "y", "", byte(2))
	f.Add("a.yaml", lstRootText, "b.yaml", "version: 1\nkind: x509\nkeys: 2\n", byte(4))
	f.Fuzz(func(t *testing.T, n1, t1, n2, t2 string, flags byte) {
		dir := t.TempDir()
		roots := filepath.Join(dir, "want", "roots")
		if err := os.MkdirAll(roots, 0o755); err != nil {
			t.Fatal(err)
		}
		for i, n := range []string{n1, n2} {
			if n == "" || strings.ContainsAny(n, "/\x00") || n == "." || n == ".." || len(n) > 200 {
				continue
			}
			text := []string{t1, t2}[i]
			if flags&(1<<i) != 0 {
				// A folder in place of the file.
				if err := os.Mkdir(filepath.Join(roots, n), 0o755); err != nil {
					continue
				}
				continue
			}
			if err := os.WriteFile(filepath.Join(roots, n), []byte(text), 0o644); err != nil {
				continue
			}
		}
		fsys, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fsys.Close() }()
		list, err := wanted.ListRoots(fsys)
		if err != nil {
			if list != nil {
				t.Fatalf("an error with %d roots", len(list))
			}
			return
		}
		var names []string
		for _, r := range list {
			if !r.Valid() || wanted.ValidName(r.Name) != nil || r.File.Path != "want/roots/"+r.Name+".yaml" {
				t.Fatalf("a root that is not what the reader makes: %+v", r)
			}
			names = append(names, r.Name)
		}
		if !slices.IsSorted(names) {
			t.Fatalf("the names are not in order: %q", names)
		}
		ds, err := wanted.ListDelegations(fsys, mustSettings(t, goodSettings))
		if err != nil && ds != nil {
			t.Fatalf("an error with %d delegations", len(ds))
		}
	})
}
