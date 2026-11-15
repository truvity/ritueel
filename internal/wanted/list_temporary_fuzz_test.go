//go:build linux || darwin

package wanted_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// tlIsTemporary is the test of the record, written by hand and apart from the code under test: the
// name starts with a period, the letters r and t in either case, and a hyphen.
func tlIsTemporary(name string) bool {
	if len(name) < 4 || name[0] != '.' || name[3] != '-' {
		return false
	}
	lower := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			return c + 'a' - 'A'
		}
		return c
	}
	return lower(name[1]) == 'r' && lower(name[2]) == 't'
}

// FuzzListersSkipTemporaryNames makes two copies of a bundle from the fuzzer's names and contents: one
// with every entry, a leftover name among them (a file, a folder, a link or a FIFO), and one without
// the entries whose names start with ".rt-". Every lister must answer the same for both, with the
// same words for a refusal, and must leave the leftover where it is.
func FuzzListersSkipTemporaryNames(f *testing.F) {
	f.Add("a.yaml", lstRootText, "b.yaml", "version: 1\nkind: ssh\n", "k3j9x0a1b2c", byte(0), byte(0))
	f.Add("A.yaml", lstRootText, ".RT-x", "", "x", byte(1), byte(0x13))
	f.Add("x\x01.yaml", "", "y", "x", "\xff", byte(2), byte(0x21))
	f.Add(".rt-k3j9x0a1b2c.yaml", lstRootText, "a.yaml", lstRootText, "", byte(0), byte(0x32))
	f.Add("a.yaml", lstRootText, "a.yaml.yaml", lstRootText, ".rt-", byte(8), byte(0x03))
	f.Fuzz(func(t *testing.T, n1, t1, n2, t2, stem string, flags, kinds byte) {
		type entry struct{ name, text string }
		left := []byte(".rt-")
		if kinds&1 != 0 {
			left[1] = 'R'
		}
		if kinds&2 != 0 {
			left[2] = 'T'
		}
		leftName := string(left) + stem
		entries := []entry{{"good.yaml", lstRootText}, {n1, t1}, {n2, t2}, {leftName, "x"}}
		for _, e := range entries {
			if e.name == "" || strings.ContainsAny(e.name, "/\x00") || e.name == "." || e.name == ".." || len(e.name) > 200 {
				return
			}
		}
		makeEntry := func(p string, i int, text string) bool {
			if flags&(1<<i) != 0 && i < 4 {
				return os.Mkdir(p, 0o755) == nil
			}
			if i == 3 {
				switch (kinds >> 4) & 3 {
				case 1:
					return os.Mkdir(p, 0o755) == nil
				case 2:
					return os.Symlink("good.yaml", p) == nil
				case 3:
					return syscall.Mkfifo(p, 0o644) == nil
				}
			}
			return os.WriteFile(p, []byte(text), 0o644) == nil
		}
		build := func(withTemporary bool) ([]string, fsx.FS) {
			var made []string
			dir := t.TempDir()
			for _, folder := range []string{wanted.RootsDir, wanted.DelegationsDir, wanted.CardsDir} {
				full := filepath.Join(dir, filepath.FromSlash(folder))
				if err := os.MkdirAll(full, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "want", "roots", "acme-tls.yaml"), []byte(lstRootText), 0o644); err != nil {
				t.Fatal(err)
			}
			for i, e := range entries {
				if tlIsTemporary(e.name) && !withTemporary {
					continue
				}
				for _, folder := range []string{wanted.RootsDir, wanted.DelegationsDir, wanted.CardsDir} {
					p := filepath.Join(dir, filepath.FromSlash(folder), e.name)
					text := e.text
					if folder == wanted.DelegationsDir && e.name == "good.yaml" {
						text = lstDelegation
					}
					if makeEntry(p, i, text) {
						made = append(made, p)
					}
				}
			}
			fsys, err := fsx.OpenFS(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = fsys.Close() })
			return made, fsys
		}
		made, with := build(true)
		_, without := build(false)
		s := mustSettings(t, goodSettings)
		for _, l := range tlListers() {
			g1, e1 := l.run(with, s)
			g2, e2 := l.run(without, s)
			if (e1 == nil) != (e2 == nil) || (e1 != nil && e1.Error() != e2.Error()) {
				t.Fatalf("%s: with the leftovers %v, without %v", l.name, e1, e2)
			}
			if !slices.Equal(g1, g2) {
				t.Fatalf("%s: with the leftovers %q, without %q", l.name, g1, g2)
			}
			if e1 != nil && g1 != nil {
				t.Fatalf("%s: names with an error", l.name)
			}
		}
		for _, p := range made {
			if _, err := os.Lstat(p); err != nil {
				t.Fatalf("a lister removed or changed an entry: %v", err)
			}
		}
	})
}
