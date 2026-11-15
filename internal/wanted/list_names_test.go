//go:build linux || darwin

package wanted_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// ListRootNames lists the root files and reads none of them; LoadRoots reads the named files;
// CheckDelegations checks every delegation file and keeps none. A caller that can use only a few
// root files judges the names first and reads the bytes only of the few (docs/reference/bundle.md,
// "The wanted files"). The names of this file start with nm.

// nmReads records the path of every file that was read through a counting folder.
type nmReads struct {
	mu    sync.Mutex
	paths []string
}

func (r *nmReads) add(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, p)
}

// count is the number of reads so far.
func (r *nmReads) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

// under is the number of reads of files below the folder dir ("want/roots").
func (r *nmReads) under(dir string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, p := range r.paths {
		if strings.HasPrefix(p, dir+"/") {
			n++
		}
	}
	return n
}

// nmFS is a folder of the disk that counts the files that are read through it, in this folder and
// in every folder opened from it.
type nmFS struct {
	fsx.FS
	dir   string
	reads *nmReads
}

func (f nmFS) OpenDir(name string) (fsx.FS, error) {
	sub, err := f.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return nmFS{FS: sub, dir: f.dir + name + "/", reads: f.reads}, nil
}

func (f nmFS) ReadFile(name string) ([]byte, error) {
	f.reads.add(f.dir + name)
	return f.FS.ReadFile(name)
}

// nmOpen makes a bundle on the disk and opens it through a counting folder.
func nmOpen(t testing.TB, files map[string]string) (string, nmFS, *nmReads) {
	t.Helper()
	dir, fsys := bundleDir(t, files)
	r := &nmReads{}
	return dir, nmFS{FS: fsys, reads: r}, r
}

// nmRoots is the files of n root files with the names r0000, r0001, ... that all pass their check.
func nmRoots(n int) map[string]string {
	files := map[string]string{}
	for i := range n {
		files[fmt.Sprintf("want/roots/r%04d.yaml", i)] = lstRootText
	}
	return files
}

func TestListRootNamesGivesTheNamesInOrderAndReadsNoFile(t *testing.T) {
	_, fsys, reads := nmOpen(t, map[string]string{
		"want/roots/acme.yaml":     lstRootText,
		"want/roots/acme-tls.yaml": lstRootText,
		"want/roots/b.yaml":        "this is not a root file, and nothing reads it",
		"want/roots/a1.yaml":       "",
	})
	names, err := wanted.ListRootNames(fsys)
	if err != nil {
		t.Fatalf("ListRootNames: %v", err)
	}
	// The order is the order of the names, and "acme-tls" sorts before "acme" by file name only.
	want := []string{"a1", "acme", "acme-tls", "b"}
	if !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
	if reads.count() != 0 {
		t.Errorf("ListRootNames read %d files: %q", reads.count(), reads.paths)
	}
}

func TestListRootNamesOfAMissingOrEmptyFolderIsNoNameAndNoError(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no want folder":    {"ritueel.yaml": goodSettings},
		"want but no roots": {"want/delegations/.keep": ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, fsys, _ := nmOpen(t, files)
			names, err := wanted.ListRootNames(fsys)
			if err != nil || len(names) != 0 {
				t.Errorf("ListRootNames = %q, %v", names, err)
			}
		})
	}
	t.Run("an empty roots folder", func(t *testing.T) {
		dir, fsys, _ := nmOpen(t, map[string]string{"ritueel.yaml": goodSettings})
		if err := os.MkdirAll(filepath.Join(dir, "want", "roots"), 0o755); err != nil {
			t.Fatal(err)
		}
		names, err := wanted.ListRootNames(fsys)
		if err != nil || len(names) != 0 {
			t.Errorf("ListRootNames = %q, %v", names, err)
		}
	})
}

func TestListRootNamesRefusesWhatIsNotARootFileAndGivesNoName(t *testing.T) {
	type tc struct {
		name  string
		setup func(t *testing.T, roots string)
		path  string
	}
	file := func(name string) func(*testing.T, string) {
		return func(t *testing.T, roots string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(roots, name), []byte(lstRootText), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []tc{
		{"upper-case name", file("X.yaml"), "want/roots/X.yaml"},
		{"another extension", file("a.txt"), "want/roots/a.txt"},
		{"the yml spelling", file("a.yml"), "want/roots/a.yml"},
		{"no name", file(".yaml"), "want/roots/.yaml"},
		{"a leftover of a stop", file(".rt-abc.yaml"), "want/roots/.rt-abc.yaml"},
		{"a name of 64 characters", file(strings.Repeat("a", 64) + ".yaml"), "want/roots/" + strings.Repeat("a", 64) + ".yaml"},
		{"a name with a control character", file("a\x01b.yaml"), "want/roots/a\\u0001b.yaml"},
		{"a folder with a good name", func(t *testing.T, roots string) {
			if err := os.Mkdir(filepath.Join(roots, "a.yaml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml"},
		{"a link to a good file", func(t *testing.T, roots string) {
			file("real.yaml")(t, roots)
			if err := os.Symlink("real.yaml", filepath.Join(roots, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml"},
		{"a dangling link", func(t *testing.T, roots string) {
			if err := os.Symlink("nothing.yaml", filepath.Join(roots, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml"},
		{"a FIFO", func(t *testing.T, roots string) {
			if err := syscall.Mkfifo(filepath.Join(roots, "a.yaml"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "want/roots/a.yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, fsys, reads := nmOpen(t, map[string]string{"want/roots/good.yaml": lstRootText})
			c.setup(t, filepath.Join(dir, "want", "roots"))
			before := lstTree(t, dir)
			names, err := wanted.ListRootNames(fsys)
			if err == nil || names != nil {
				t.Fatalf("ListRootNames = %q, %v", names, err)
			}
			if !strings.Contains(err.Error(), c.path) || !printableASCII(err.Error()) {
				t.Errorf("the error %+q does not name %q in printable ASCII", err.Error(), c.path)
			}
			var e *wanted.Error
			if !errors.As(err, &e) {
				t.Errorf("the error is %T, want *wanted.Error", err)
			}
			if reads.count() != 0 {
				t.Errorf("a file was read before the names were judged: %q", reads.paths)
			}
			if !slices.Equal(before, lstTree(t, dir)) {
				t.Error("ListRootNames changed the folder")
			}
		})
	}
}

func TestListRootNamesStopsAtTheLimitBeforeReadingAnyFile(t *testing.T) {
	t.Run("exactly the limit", func(t *testing.T) {
		_, fsys, reads := nmOpen(t, nmRoots(wanted.MaxFiles))
		names, err := wanted.ListRootNames(fsys)
		if err != nil || len(names) != wanted.MaxFiles || !slices.IsSorted(names) {
			t.Fatalf("ListRootNames of %d files = %d names, %v", wanted.MaxFiles, len(names), err)
		}
		if reads.count() != 0 {
			t.Errorf("%d files were read", reads.count())
		}
	})
	t.Run("one more than the limit", func(t *testing.T) {
		_, fsys, reads := nmOpen(t, nmRoots(wanted.MaxFiles+1))
		names, err := wanted.ListRootNames(fsys)
		if err == nil || names != nil {
			t.Fatalf("ListRootNames of %d files = %d names, %v", wanted.MaxFiles+1, len(names), err)
		}
		if !strings.Contains(err.Error(), fmt.Sprint(wanted.MaxFiles)) || !strings.Contains(err.Error(), "want/roots") {
			t.Errorf("the error does not name the folder and the limit: %v", err)
		}
		if reads.count() != 0 {
			t.Errorf("%d files were read", reads.count())
		}
	})
}

func TestListRootNamesOfANilFolderIsAnError(t *testing.T) {
	names, err := wanted.ListRootNames(nil)
	if err == nil || names != nil {
		t.Errorf("ListRootNames(nil) = %q, %v", names, err)
	}
}

func TestLoadRootsReadsTheNamedFilesInTheOrderOfTheNames(t *testing.T) {
	_, fsys, reads := nmOpen(t, map[string]string{
		"want/roots/a.yaml": lstRootText,
		"want/roots/b.yaml": "version: 1\nkind: ssh\n",
		"want/roots/c.yaml": "version: 1\nkind: openpgp\n",
	})
	roots, err := wanted.LoadRoots(fsys, []string{"c", "a"})
	if err != nil || len(roots) != 2 {
		t.Fatalf("LoadRoots = %d roots, %v", len(roots), err)
	}
	if roots[0].Name != "c" || roots[1].Name != "a" || roots[0].Kind != wanted.RootOpenPGP || roots[1].Kind != wanted.RootX509 {
		t.Errorf("the roots are %q/%v and %q/%v, not the roots of c and a in that order", roots[0].Name, roots[0].Kind, roots[1].Name, roots[1].Kind)
	}
	if want := []string{"want/roots/c.yaml", "want/roots/a.yaml"}; !slices.Equal(reads.paths, want) {
		t.Errorf("the files read are %q, want %q (only the named files, in order)", reads.paths, want)
	}
	for _, r := range roots {
		if !r.Valid() || r.File.Path != "want/roots/"+r.Name+".yaml" || r.File.SHA256 != sha256hex(r.File.Data) {
			t.Errorf("a root that is not what the reader makes: %+v", r)
		}
	}
}

func TestLoadRootsOfNoNameIsAnEmptyListAndReadsNothing(t *testing.T) {
	_, fsys, reads := nmOpen(t, map[string]string{"want/roots/a.yaml": lstRootText})
	for _, names := range [][]string{nil, {}} {
		roots, err := wanted.LoadRoots(fsys, names)
		if err != nil || len(roots) != 0 {
			t.Errorf("LoadRoots(%q) = %d roots, %v", names, len(roots), err)
		}
	}
	if reads.count() != 0 {
		t.Errorf("%d files were read", reads.count())
	}
}

func TestLoadRootsGivesNoRootWhenOneFileFailsAndStopsAtThatFile(t *testing.T) {
	_, fsys, reads := nmOpen(t, map[string]string{
		"want/roots/a.yaml": lstRootText,
		"want/roots/b.yaml": "version: 1\nkind: nonsense\n",
		"want/roots/c.yaml": lstRootText,
	})
	roots, err := wanted.LoadRoots(fsys, []string{"a", "b", "c"})
	if err == nil || roots != nil {
		t.Fatalf("LoadRoots = %d roots, %v", len(roots), err)
	}
	if !strings.Contains(err.Error(), "want/roots/b.yaml") || !printableASCII(err.Error()) {
		t.Errorf("the error %+q does not name the failing file", err.Error())
	}
	if reads.under("want/roots") != 2 {
		t.Errorf("the files read are %q; the first fault should stop the reading after two files", reads.paths)
	}
}

func TestLoadRootsRefusesANameThatIsNotAGoodNameOrHasNoFile(t *testing.T) {
	_, fsys, _ := nmOpen(t, map[string]string{"want/roots/a.yaml": lstRootText})
	for _, name := range []string{"missing", "A", "", "../a", "a/b", "a.yaml", "a\x00", strings.Repeat("a", 64), "a\nb"} {
		t.Run(fmt.Sprintf("%+q", name), func(t *testing.T) {
			roots, err := wanted.LoadRoots(fsys, []string{"a", name})
			if err == nil || roots != nil {
				t.Errorf("LoadRoots(a, %+q) = %d roots, %v", name, len(roots), err)
			}
			if err != nil && !printableASCII(err.Error()) {
				t.Errorf("the error is not printable ASCII: %+q", err.Error())
			}
		})
	}
	t.Run("a nil folder", func(t *testing.T) {
		roots, err := wanted.LoadRoots(nil, []string{"a"})
		if err == nil || roots != nil {
			t.Errorf("LoadRoots(nil) = %v, %v", roots, err)
		}
	})
}

func TestListRootsIsTheNamesThenTheFilesAndReadsNothingForAFolderThatIsRefused(t *testing.T) {
	files := map[string]string{
		"want/roots/acme.yaml":     lstRootText,
		"want/roots/acme-tls.yaml": "version: 1\nkind: ssh\n",
	}
	_, fsys, _ := nmOpen(t, files)
	whole, err := wanted.ListRoots(fsys)
	if err != nil {
		t.Fatal(err)
	}
	names, err := wanted.ListRootNames(fsys)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := wanted.LoadRoots(fsys, names)
	if err != nil || len(whole) != len(loaded) {
		t.Fatalf("ListRoots = %d roots, the two calls = %d, %v", len(whole), len(loaded), err)
	}
	for i := range whole {
		if whole[i].Name != loaded[i].Name || whole[i].Kind != loaded[i].Kind || whole[i].File.SHA256 != loaded[i].File.SHA256 {
			t.Errorf("root %d differs between ListRoots and the two calls", i)
		}
	}
	// A folder that is refused by its names is refused before any file is read: 1,001 names, and a
	// name that is not a root name beside one good file.
	for name, bad := range map[string]map[string]string{
		"more names than the limit": nmRoots(wanted.MaxFiles + 1),
		"a name of another form":    {"want/roots/good.yaml": lstRootText, "want/roots/BAD.yaml": lstRootText},
	} {
		t.Run(name, func(t *testing.T) {
			_, fsys, reads := nmOpen(t, bad)
			got, err := wanted.ListRoots(fsys)
			if err == nil || got != nil {
				t.Fatalf("ListRoots = %d roots, %v", len(got), err)
			}
			if reads.count() != 0 {
				t.Errorf("ListRoots read %d files before it judged the names", reads.count())
			}
		})
	}
}

func TestListRootsOfTheLimitReadsEveryFileOnce(t *testing.T) {
	_, fsys, reads := nmOpen(t, nmRoots(wanted.MaxFiles))
	roots, err := wanted.ListRoots(fsys)
	if err != nil || len(roots) != wanted.MaxFiles {
		t.Fatalf("ListRoots = %d roots, %v", len(roots), err)
	}
	if reads.count() != wanted.MaxFiles {
		t.Errorf("%d reads for %d files", reads.count(), wanted.MaxFiles)
	}
}

// nmDelegationBundle is a bundle with the root file that lstDelegation names and n delegation files.
func nmDelegationBundle(n int) map[string]string {
	files := map[string]string{"want/roots/acme-tls.yaml": lstRootText}
	for i := range n {
		files[fmt.Sprintf("want/delegations/d%04d.yaml", i)] = lstDelegation
	}
	return files
}

func TestCheckDelegationsAcceptsWhatListDelegationsAcceptsAndRefusesWhatItRefuses(t *testing.T) {
	cases := map[string]map[string]string{
		"no folder":                     {"want/roots/acme-tls.yaml": lstRootText},
		"one good file":                 nmDelegationBundle(1),
		"a hundred good files":          nmDelegationBundle(100),
		"exactly the limit":             nmDelegationBundle(wanted.MaxFiles),
		"one more than the limit":       nmDelegationBundle(wanted.MaxFiles + 1),
		"its root file is missing":      {"want/delegations/acme-tls.yaml": lstDelegation},
		"its root fails its check":      {"want/delegations/acme-tls.yaml": lstDelegation, "want/roots/acme-tls.yaml": "version: 1\nkind: nonsense\n"},
		"its root is of the wrong kind": {"want/delegations/acme-tls.yaml": lstDelegation, "want/roots/acme-tls.yaml": "version: 1\nkind: ssh\n"},
		"upper-case name":               {"want/delegations/Acme.yaml": lstDelegation},
		"another extension":             {"want/delegations/acme.yml": lstDelegation},
		"a name of the SSH key list":    {"want/delegations/break-glass-1.yaml": lstDelegation, "want/roots/acme-tls.yaml": lstRootText},
		"a file that fails its check":   {"want/delegations/acme-tls.yaml": "version: 1\ntype: nonsense\n"},
		"a permitted name is missing":   {"want/delegations/acme-tls.yaml": "version: 1\ntype: x509-intermediate\nroot: acme-tls\n", "want/roots/acme-tls.yaml": lstRootText},
		"an empty file":                 {"want/delegations/acme-tls.yaml": "", "want/roots/acme-tls.yaml": lstRootText},
		"not UTF-8":                     {"want/delegations/acme-tls.yaml": lstDelegation + "# \xff\xfe\n", "want/roots/acme-tls.yaml": lstRootText},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			_, fsys := bundleDir(t, files)
			want, wantErr := wanted.ListDelegations(fsys, lstSettings(t))
			gotErr := wanted.CheckDelegations(fsys, lstSettings(t))
			if (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("CheckDelegations = %v, ListDelegations = %d delegations, %v", gotErr, len(want), wantErr)
			}
			if gotErr != nil && gotErr.Error() != wantErr.Error() {
				t.Errorf("the two refuse with different words:\n%s\n%s", gotErr, wantErr)
			}
			if gotErr != nil && !printableASCII(gotErr.Error()) {
				t.Errorf("the error is not printable ASCII: %+q", gotErr.Error())
			}
		})
	}
}

func TestCheckDelegationsJudgesTheNamesBeforeItReadsAnyFile(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"more names than the limit": nmDelegationBundle(wanted.MaxFiles + 1),
		"a name of another form":    {"want/delegations/good.yaml": lstDelegation, "want/delegations/BAD.yaml": lstDelegation, "want/roots/acme-tls.yaml": lstRootText},
	} {
		t.Run(name, func(t *testing.T) {
			_, fsys, reads := nmOpen(t, files)
			if err := wanted.CheckDelegations(fsys, lstSettings(t)); err == nil {
				t.Fatal("CheckDelegations accepted the folder")
			}
			if reads.count() != 0 {
				t.Errorf("%d files were read before the names were judged", reads.count())
			}
		})
	}
}

func TestCheckDelegationsReadsEachDelegationOnceAndItsRoot(t *testing.T) {
	_, fsys, reads := nmOpen(t, nmDelegationBundle(3))
	if err := wanted.CheckDelegations(fsys, lstSettings(t)); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		p := fmt.Sprintf("want/delegations/d%04d.yaml", i)
		n := 0
		for _, r := range reads.paths {
			if r == p {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s was read %d times", p, n)
		}
	}
}

func TestCheckDelegationsNeedsSettingsThatTheReaderMade(t *testing.T) {
	_, fsys, reads := nmOpen(t, nmDelegationBundle(1))
	for name, s := range map[string]*wanted.Settings{"nil": nil, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			err := wanted.CheckDelegations(fsys, s)
			if err == nil || !printableASCII(err.Error()) {
				t.Errorf("CheckDelegations = %v", err)
			}
		})
	}
	if reads.count() != 0 {
		t.Errorf("%d files were read", reads.count())
	}
	t.Run("a nil folder", func(t *testing.T) {
		if err := wanted.CheckDelegations(nil, lstSettings(t)); err == nil {
			t.Error("CheckDelegations(nil) accepted")
		}
	})
}

func TestCheckDelegationsNamesTheFirstFailingFileAndStopsThere(t *testing.T) {
	files := nmDelegationBundle(4)
	files["want/delegations/d0001.yaml"] = "version: 1\ntype: nonsense\n"
	_, fsys, reads := nmOpen(t, files)
	err := wanted.CheckDelegations(fsys, lstSettings(t))
	if err == nil || !strings.Contains(err.Error(), "want/delegations/d0001.yaml") {
		t.Fatalf("CheckDelegations = %v", err)
	}
	for _, p := range reads.paths {
		if p == "want/delegations/d0002.yaml" || p == "want/delegations/d0003.yaml" {
			t.Errorf("%s was read after the fault", p)
		}
	}
}

// FuzzListRootNames lists a folder whose file names and contents come from the fuzzer. It reads no
// file; an error gives no name; every name is a good name in order; and ListRoots of the same folder
// is the roots of those names, or the fault of one of the files.
func FuzzListRootNames(f *testing.F) {
	f.Add("a.yaml", lstRootText, "b.yaml", "version: 1\nkind: ssh\n", byte(0))
	f.Add("a.yaml", lstRootText, "A.yaml", lstRootText, byte(0))
	f.Add("a.yaml", "", "b.txt", "x", byte(1))
	f.Add("x\x01.yaml", lstRootText, "y", "", byte(2))
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
			if flags&(1<<i) != 0 {
				_ = os.Mkdir(filepath.Join(roots, n), 0o755)
				continue
			}
			_ = os.WriteFile(filepath.Join(roots, n), []byte([]string{t1, t2}[i]), 0o644)
		}
		fsys, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fsys.Close() }()
		reads := &nmReads{}
		counted := nmFS{FS: fsys, reads: reads}
		names, err := wanted.ListRootNames(counted)
		if reads.count() != 0 {
			t.Fatalf("ListRootNames read %d files", reads.count())
		}
		if err != nil {
			if names != nil {
				t.Fatalf("an error with %d names", len(names))
			}
			if _, lerr := wanted.ListRoots(fsys); lerr == nil {
				t.Fatal("ListRootNames refuses a folder that ListRoots accepts")
			}
			return
		}
		if !slices.IsSorted(names) {
			t.Fatalf("the names are not in order: %q", names)
		}
		for _, n := range names {
			if wanted.ValidName(n) != nil {
				t.Fatalf("a name that is not a good name: %q", n)
			}
		}
		whole, werr := wanted.ListRoots(fsys)
		loaded, lerr := wanted.LoadRoots(fsys, names)
		if (werr == nil) != (lerr == nil) || len(whole) != len(loaded) {
			t.Fatalf("ListRoots = %d, %v and LoadRoots = %d, %v", len(whole), werr, len(loaded), lerr)
		}
	})
}

// FuzzCheckDelegations checks a folder of delegation files from the fuzzer. It accepts exactly what
// ListDelegations accepts, with the same words for a refusal.
func FuzzCheckDelegations(f *testing.F) {
	f.Add(lstDelegation, lstRootText, "acme-tls.yaml")
	f.Add("version: 1\ntype: nonsense\n", lstRootText, "acme-tls.yaml")
	f.Add(lstDelegation, "version: 1\nkind: ssh\n", "Bad.yaml")
	f.Add("", "", "x.yaml")
	f.Fuzz(func(t *testing.T, delegation, root, name string) {
		if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." || len(name) > 200 {
			return
		}
		dir := t.TempDir()
		for p, text := range map[string]string{
			filepath.Join("want", "delegations", name):      delegation,
			filepath.Join("want", "roots", "acme-tls.yaml"): root,
		} {
			full := filepath.Join(dir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
				return
			}
		}
		fsys, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fsys.Close() }()
		s := mustSettings(t, goodSettings)
		ds, lerr := wanted.ListDelegations(fsys, s)
		cerr := wanted.CheckDelegations(fsys, s)
		if (lerr == nil) != (cerr == nil) {
			t.Fatalf("ListDelegations = %d, %v and CheckDelegations = %v", len(ds), lerr, cerr)
		}
		if cerr != nil && cerr.Error() != lerr.Error() {
			t.Fatalf("different words: %q and %q", cerr, lerr)
		}
	})
}
