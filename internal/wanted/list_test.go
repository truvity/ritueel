//go:build linux || darwin

package wanted_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// ListRoots and ListDelegations read a whole folder of wanted files through package fsx. The folder
// is listed once, a name that is not NAME.yaml is refused, a link, a folder and a FIFO are refused,
// and an error returns no root and no delegation (docs/reference/bundle.md, "The wanted files").

const lstRootText = "version: 1\nkind: x509\ntest: true\n"

// lstTree is every entry under dir with its kind and, for a file, its bytes, sorted.
func lstTree(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		line := rel + " " + info.Mode().Type().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			line += " " + sha256hex(b)
		}
		out = append(out, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// lstOpenFS opens dir through package fsx.
func lstOpenFS(t testing.TB, dir string) fsx.FS {
	t.Helper()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsys.Close() })
	return fsys
}

func TestListRootsReturnsTheRootFilesInTheOrderOfTheirNames(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{
		"want/roots/zeta.yaml":  "version: 1\nkind: ssh\n",
		"want/roots/alpha.yaml": "version: 1\nkind: x509\ntest: true\n",
		"want/roots/m1-2.yaml":  "version: 1\nkind: openpgp\n",
		"want/roots/0day.yaml":  lstRootText,
	})
	roots, err := wanted.ListRoots(fsys)
	if err != nil {
		t.Fatalf("ListRoots: %v", err)
	}
	var names []string
	for _, r := range roots {
		if !r.Valid() {
			t.Errorf("root %q was not made by the reader", r.Name)
		}
		names = append(names, r.Name)
		if r.File.Path != "want/roots/"+r.Name+".yaml" {
			t.Errorf("root %q has the path %q", r.Name, r.File.Path)
		}
	}
	if want := []string{"0day", "alpha", "m1-2", "zeta"}; !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
	kinds := map[string]wanted.RootKind{"0day": wanted.RootX509, "alpha": wanted.RootX509, "m1-2": wanted.RootOpenPGP, "zeta": wanted.RootSSH}
	for _, r := range roots {
		if r.Kind != kinds[r.Name] {
			t.Errorf("root %q is of the kind %q", r.Name, r.Kind)
		}
	}
	if !roots[1].Test || roots[2].Test {
		t.Errorf("the test member was not kept: %v %v", roots[1].Test, roots[2].Test)
	}
}

func TestListRootsOrdersByTheNameAndNotByTheNameOfTheFile(t *testing.T) {
	// The file acme-tls.yaml sorts before acme.yaml (a hyphen comes before a dot), and the root acme
	// sorts before the root acme-tls.
	_, fsys := bundleDir(t, map[string]string{
		"want/roots/acme-tls.yaml": lstRootText,
		"want/roots/acme.yaml":     lstRootText,
		"want/roots/acme-a.yaml":   lstRootText,
	})
	roots, err := wanted.ListRoots(fsys)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range roots {
		names = append(names, r.Name)
	}
	if want := []string{"acme", "acme-a", "acme-tls"}; !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
}

func TestListRootsKeepsTheBytesThatWereRead(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{"want/roots/acme.yaml": lstRootText})
	roots, err := wanted.ListRoots(fsys)
	if err != nil || len(roots) != 1 {
		t.Fatalf("ListRoots: %v %v", roots, err)
	}
	if string(roots[0].File.Data) != lstRootText || roots[0].File.SHA256 != sha256hex([]byte(lstRootText)) {
		t.Errorf("the file kept %q with the digest %s", roots[0].File.Data, roots[0].File.SHA256)
	}
}

func TestAMissingOrEmptyFolderOfRootsIsAnEmptyList(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no want folder":        {"ritueel.yaml": goodSettings},
		"no roots folder":       {"want/delegations/x.yaml": "x"},
		"an empty roots folder": nil,
	} {
		t.Run(name, func(t *testing.T) {
			dir, fsys := bundleDir(t, files)
			if files == nil {
				if err := os.MkdirAll(filepath.Join(dir, "want", "roots"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			roots, err := wanted.ListRoots(fsys)
			if err != nil || len(roots) != 0 {
				t.Errorf("ListRoots = %v, %v; want an empty list and no error", roots, err)
			}
		})
	}
}

func TestListRootsRefusesWhatIsNotARootFileAndReturnsNothing(t *testing.T) {
	type tc struct {
		name  string
		setup func(t *testing.T, roots string)
		path  string // the path the error names, escaped
		words string // a word of the fixed text
	}
	file := func(name, text string) func(*testing.T, string) {
		return func(t *testing.T, roots string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(roots, name), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []tc{
		{"upper-case name", file("X.yaml", lstRootText), "want/roots/X.yaml", "lower-case"},
		{"another extension", file("a.txt", lstRootText), "want/roots/a.txt", "NAME.yaml"},
		{"the yml spelling", file("a.yml", lstRootText), "want/roots/a.yml", "NAME.yaml"},
		{"no name", file(".yaml", lstRootText), "want/roots/.yaml", "1 to 63"},
		{"two extensions", file("a.yaml.yaml", lstRootText), "want/roots/a.yaml.yaml", "lower-case"},
		// A name that starts with ".rt-" is not refused: it is skipped (list_temporary_test.go).
		{"a name that only looks like a leftover", file(".rtx.yaml", lstRootText), "want/roots/.rtx.yaml", "lower-case"},
		{"a name of 64 characters", file(strings.Repeat("a", 64)+".yaml", lstRootText), "want/roots/" + strings.Repeat("a", 64) + ".yaml", "1 to 63"},
		{"a space in the name", file("a b.yaml", lstRootText), `want/roots/a\x20b.yaml`, "lower-case"},
		{"a hyphen first", file("-a.yaml", lstRootText), "want/roots/-a.yaml", "lower-case"},
		{"a folder with a good name", func(t *testing.T, roots string) {
			if err := os.Mkdir(filepath.Join(roots, "a.yaml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml", "not a regular file"},
		{"a link to a good file", func(t *testing.T, roots string) {
			file("real.yaml", lstRootText)(t, roots)
			if err := os.Symlink("real.yaml", filepath.Join(roots, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml", "not a regular file"},
		{"a dangling link", func(t *testing.T, roots string) {
			if err := os.Symlink("nothing.yaml", filepath.Join(roots, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml", "not a regular file"},
		{"a FIFO", func(t *testing.T, roots string) {
			if err := syscall.Mkfifo(filepath.Join(roots, "a.yaml"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml", "not a regular file"},
		{"a file that fails its own check", file("a.yaml", "version: 1\nkind: nonsense\n"), "want/roots/a.yaml", "kind"},
		{"an empty file", file("a.yaml", ""), "want/roots/a.yaml", ""},
		{"a member that is read later", file("a.yaml", "version: 1\nkind: x509\nretire_at: 2\n"), "want/roots/a.yaml", "not read yet"},
		{"a file that is not UTF-8", file("a.yaml", "version: 1\nkind: x509\n\xff\xfe\n"), "want/roots/a.yaml", ""},
		{"a name with a control character", file("a\x01b.yaml", lstRootText), "want/roots/a\\u0001b.yaml", "lower-case"},
		{"a name that is not UTF-8", file("a\xffb.yaml", lstRootText), "want/roots/a", "lower-case"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, fsys := bundleDir(t, map[string]string{"want/roots/good.yaml": lstRootText})
			roots := filepath.Join(dir, "want", "roots")
			c.setup(t, roots)
			before := lstTree(t, dir)
			got, err := wanted.ListRoots(fsys)
			if err == nil {
				t.Fatalf("ListRoots accepted the folder and returned %d roots", len(got))
			}
			if got != nil {
				t.Errorf("ListRoots returned %d roots with an error; an error returns nothing", len(got))
			}
			msg := err.Error()
			if !strings.Contains(msg, c.path) {
				t.Errorf("the error %q does not name the path %q", msg, c.path)
			}
			if c.words != "" && !strings.Contains(msg, c.words) {
				t.Errorf("the error %q does not hold %q", msg, c.words)
			}
			if !printableASCII(msg) {
				t.Errorf("the error is not printable ASCII: %+q", msg)
			}
			var e *wanted.Error
			if !errors.As(err, &e) {
				t.Errorf("the error is %T, want *wanted.Error", err)
			}
			if after := lstTree(t, dir); !slices.Equal(before, after) {
				t.Errorf("ListRoots changed the folder")
			}
		})
	}
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func TestListRootsRefusesAFolderThatCannotBeListedAsAFolder(t *testing.T) {
	t.Run("want/roots is a file", func(t *testing.T) {
		_, fsys := bundleDir(t, map[string]string{"want/roots": "x"})
		roots, err := wanted.ListRoots(fsys)
		if err == nil || roots != nil || !strings.Contains(err.Error(), "want/roots") {
			t.Errorf("ListRoots = %v, %v", roots, err)
		}
		if errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a file in place of the folder was told as a missing folder: %v", err)
		}
	})
	t.Run("want/roots is a link to a folder", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"elsewhere/a.yaml": lstRootText})
		if err := os.MkdirAll(filepath.Join(dir, "want"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../elsewhere", filepath.Join(dir, "want", "roots")); err != nil {
			t.Fatal(err)
		}
		roots, err := wanted.ListRoots(fsys)
		if err == nil || roots != nil {
			t.Fatalf("ListRoots followed a link: %v, %v", roots, err)
		}
		if !strings.Contains(err.Error(), "link") {
			t.Errorf("the error does not say a link: %v", err)
		}
	})
	t.Run("want is a link", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"elsewhere/roots/a.yaml": lstRootText})
		if err := os.Symlink("elsewhere", filepath.Join(dir, "want")); err != nil {
			t.Fatal(err)
		}
		roots, err := wanted.ListRoots(fsys)
		if err == nil || roots != nil {
			t.Errorf("ListRoots followed a link in the path: %v, %v", roots, err)
		}
	})
	t.Run("no folder", func(t *testing.T) {
		roots, err := wanted.ListRoots(nil)
		if err == nil || roots != nil {
			t.Errorf("ListRoots(nil) = %v, %v", roots, err)
		}
	})
}

func TestListRootsStopsAtTheLimitOfFiles(t *testing.T) {
	files := map[string]string{}
	for i := range wanted.MaxFiles {
		files[fmt.Sprintf("want/roots/r%04d.yaml", i)] = "version: 1\nkind: x509\n"
	}
	_, fsys := bundleDir(t, files)
	roots, err := wanted.ListRoots(fsys)
	if err != nil || len(roots) != wanted.MaxFiles {
		t.Fatalf("ListRoots of exactly %d files = %d roots, %v", wanted.MaxFiles, len(roots), err)
	}
	if !slices.IsSortedFunc(roots, func(a, b *wanted.Root) int { return strings.Compare(a.Name, b.Name) }) {
		t.Errorf("the roots are not in the order of their names")
	}
}

func TestListRootsRefusesMoreFilesThanTheLimit(t *testing.T) {
	files := map[string]string{}
	for i := 0; i <= wanted.MaxFiles; i++ {
		files[fmt.Sprintf("want/roots/r%04d.yaml", i)] = "version: 1\nkind: x509\n"
	}
	_, fsys := bundleDir(t, files)
	roots, err := wanted.ListRoots(fsys)
	if err == nil || roots != nil {
		t.Fatalf("ListRoots of %d files = %d roots, %v", wanted.MaxFiles+1, len(roots), err)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(wanted.MaxFiles)) || !strings.Contains(err.Error(), "want/roots") {
		t.Errorf("the error does not name the folder and the limit: %v", err)
	}
}

func TestListRootsRefusesAHostileFolderOfMoreNamesThanAnyFolderHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("makes 70,000 files")
	}
	dir := t.TempDir()
	roots := filepath.Join(dir, "want", "roots")
	if err := os.MkdirAll(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 70000 {
		f, err := os.Create(filepath.Join(roots, fmt.Sprintf("n%05d.yaml", i)))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	fsys := lstOpenFS(t, dir)
	got, err := wanted.ListRoots(fsys)
	if err == nil || got != nil {
		t.Fatalf("ListRoots of 70,000 names = %d roots, %v", len(got), err)
	}
	if !strings.Contains(err.Error(), "want/roots") || !strings.Contains(err.Error(), "too many names") {
		t.Errorf("the error does not name the folder and say that it holds too many names: %v", err)
	}
	if !errors.Is(err, fsx.ErrTooMany) {
		t.Errorf("the error does not wrap fsx.ErrTooMany: %v", err)
	}
}

func TestListRootsReadsOneLongLineOrAWideFileWithoutAPanic(t *testing.T) {
	long := "version: 1\nkind: x509\n# " + strings.Repeat("x", 1<<20) + "\n"
	_, fsys := bundleDir(t, map[string]string{"want/roots/a.yaml": long})
	roots, err := wanted.ListRoots(fsys)
	if err == nil || roots != nil {
		t.Fatalf("a file of one megabyte was accepted: %v, %v", roots, err)
	}
	if !strings.Contains(err.Error(), "want/roots/a.yaml") {
		t.Errorf("the error does not name the file: %v", err)
	}
	// A name of 255 bytes is a name; the folder accepts nothing that ValidName refuses.
	name := strings.Repeat("a", 250) + ".yaml"
	_, fsys = bundleDir(t, map[string]string{"want/roots/" + name: lstRootText})
	if roots, err := wanted.ListRoots(fsys); err == nil || roots != nil {
		t.Errorf("a name of 255 bytes was accepted: %v, %v", roots, err)
	}
}

func TestListRootsGivesTheSameListTwiceAndLeavesTheFolderAlone(t *testing.T) {
	dir, fsys := bundleDir(t, map[string]string{
		"want/roots/a.yaml": lstRootText,
		"want/roots/b.yaml": "version: 1\nkind: ssh\n",
	})
	before := lstTree(t, dir)
	first, err := wanted.ListRoots(fsys)
	if err != nil {
		t.Fatal(err)
	}
	first[0] = nil
	second, err := wanted.ListRoots(fsys)
	if err != nil || len(second) != 2 || second[0] == nil || second[0].Name != "a" {
		t.Fatalf("the second call = %v, %v", second, err)
	}
	if after := lstTree(t, dir); !slices.Equal(before, after) {
		t.Errorf("ListRoots changed the folder")
	}
}

// Delegations.

const lstDelegation = `version: 1
type: x509-intermediate
root: acme-tls
permitted_uri_hosts: [example.org]
permitted_dns_names: [example.org]
`

func lstSettings(t testing.TB) *wanted.Settings { return mustSettings(t, goodSettings) }

func TestListDelegationsReturnsTheDelegationsInTheOrderOfTheirNames(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{
		"want/roots/acme-tls.yaml":           "version: 1\nkind: x509\n",
		"want/roots/acme-release.yaml":       "version: 1\nkind: openpgp\n",
		"want/delegations/zz-tls.yaml":       lstDelegation,
		"want/delegations/acme-release.yaml": goodOpenPGPDelegation,
		"want/delegations/mid-tls.yaml":      lstDelegation,
	})
	ds, err := wanted.ListDelegations(fsys, lstSettings(t))
	if err != nil {
		t.Fatalf("ListDelegations: %v", err)
	}
	var names []string
	for _, d := range ds {
		if !d.Valid() {
			t.Errorf("delegation %q was not made by the reader", d.Name)
		}
		names = append(names, d.Name)
	}
	if want := []string{"acme-release", "mid-tls", "zz-tls"}; !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
}

func TestListDelegationsOrdersByTheNameAndNotByTheNameOfTheFile(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{
		"want/roots/acme-tls.yaml":           "version: 1\nkind: x509\n",
		"want/delegations/acme-tls-b.yaml":   lstDelegation,
		"want/delegations/acme-tls.yaml":     lstDelegation,
		"want/delegations/acme-tls-a-b.yaml": lstDelegation,
	})
	ds, err := wanted.ListDelegations(fsys, lstSettings(t))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range ds {
		names = append(names, d.Name)
	}
	if want := []string{"acme-tls", "acme-tls-a-b", "acme-tls-b"}; !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
}

func TestAMissingFolderOfDelegationsIsAnEmptyList(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{"want/roots/a.yaml": lstRootText})
	ds, err := wanted.ListDelegations(fsys, lstSettings(t))
	if err != nil || len(ds) != 0 {
		t.Errorf("ListDelegations = %v, %v", ds, err)
	}
}

func TestListDelegationsNeedsSettingsThatTheReaderMade(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{
		"want/roots/acme-tls.yaml":       "version: 1\nkind: x509\n",
		"want/delegations/acme-tls.yaml": lstDelegation,
	})
	for name, s := range map[string]*wanted.Settings{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			ds, err := wanted.ListDelegations(fsys, s)
			if err == nil || ds != nil {
				t.Errorf("ListDelegations with %s settings = %v, %v", name, ds, err)
			}
		})
	}
	t.Run("settings that the reader did not make and a missing folder is still an error", func(t *testing.T) {
		_, empty := bundleDir(t, map[string]string{"x": "x"})
		for _, s := range []*wanted.Settings{nil, {}} {
			if ds, err := wanted.ListDelegations(empty, s); err == nil || ds != nil {
				t.Errorf("ListDelegations(%v) = %v, %v", s, ds, err)
			}
		}
	})
}

func TestListDelegationsRefusesWhatIsNotADelegationAndReturnsNothing(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		path  string
	}{
		{"its root file is missing", map[string]string{"want/delegations/acme-tls.yaml": lstDelegation}, "want/roots/acme-tls.yaml"},
		{"its root file fails its check", map[string]string{"want/delegations/acme-tls.yaml": lstDelegation, "want/roots/acme-tls.yaml": "version: 1\nkind: nonsense\n"}, "want/roots/acme-tls.yaml"},
		{"its root is of the wrong kind", map[string]string{"want/delegations/acme-tls.yaml": lstDelegation, "want/roots/acme-tls.yaml": "version: 1\nkind: ssh\n"}, "want/delegations/acme-tls.yaml"},
		{"upper-case name", map[string]string{"want/delegations/Acme.yaml": lstDelegation}, "want/delegations/Acme.yaml"},
		{"another extension", map[string]string{"want/delegations/acme.yml": lstDelegation}, "want/delegations/acme.yml"},
		{"a name of the SSH key list", map[string]string{"want/delegations/break-glass-1.yaml": lstDelegation, "want/roots/acme-tls.yaml": "version: 1\nkind: x509\n"}, "want/delegations/break-glass-1.yaml"},
		{"a file that fails its check", map[string]string{"want/delegations/acme-tls.yaml": "version: 1\ntype: nonsense\n"}, "want/delegations/acme-tls.yaml"},
		{"a delegation that needs a permitted name", map[string]string{"want/delegations/acme-tls.yaml": "version: 1\ntype: x509-intermediate\nroot: acme-tls\n", "want/roots/acme-tls.yaml": "version: 1\nkind: x509\n"}, "want/delegations/acme-tls.yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, fsys := bundleDir(t, c.files)
			ds, err := wanted.ListDelegations(fsys, lstSettings(t))
			if err == nil || ds != nil {
				t.Fatalf("ListDelegations = %v, %v", ds, err)
			}
			if !strings.Contains(err.Error(), c.path) {
				t.Errorf("the error %q does not name %q", err, c.path)
			}
			if !printableASCII(err.Error()) {
				t.Errorf("the error is not printable ASCII: %+q", err.Error())
			}
		})
	}
	for _, kind := range []string{"folder", "link", "fifo"} {
		t.Run("an entry that is a "+kind, func(t *testing.T) {
			dir, fsys := bundleDir(t, map[string]string{"want/delegations/other.yaml": lstDelegation, "want/roots/acme-tls.yaml": "version: 1\nkind: x509\n"})
			p := filepath.Join(dir, "want", "delegations", "a.yaml")
			var err error
			switch kind {
			case "folder":
				err = os.Mkdir(p, 0o755)
			case "link":
				err = os.Symlink("other.yaml", p)
			case "fifo":
				err = syscall.Mkfifo(p, 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			ds, err := wanted.ListDelegations(fsys, lstSettings(t))
			if err == nil || ds != nil || !strings.Contains(err.Error(), "want/delegations/a.yaml") {
				t.Errorf("ListDelegations = %v, %v", ds, err)
			}
		})
	}
}

func TestListDelegationsRefusesMoreFilesThanTheLimit(t *testing.T) {
	files := map[string]string{}
	for i := 0; i <= wanted.MaxFiles; i++ {
		files[fmt.Sprintf("want/delegations/d%04d.yaml", i)] = lstDelegation
	}
	_, fsys := bundleDir(t, files)
	ds, err := wanted.ListDelegations(fsys, lstSettings(t))
	if err == nil || ds != nil || !strings.Contains(err.Error(), "want/delegations") {
		t.Errorf("ListDelegations = %d, %v", len(ds), err)
	}
}

func TestListDelegationsGivesNothingForANilFolder(t *testing.T) {
	ds, err := wanted.ListDelegations(nil, lstSettings(t))
	if err == nil || ds != nil {
		t.Errorf("ListDelegations(nil) = %v, %v", ds, err)
	}
}
