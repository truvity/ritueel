//go:build linux || darwin

package wanted_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// A name that starts with ".rt-", in any case of the letters, is the leftover of a stopped write. A
// lister of want/roots, want/delegations or want/cards skips it: it is not listed, not read and no
// error, whatever kind of entry it is, and it does not count toward the limit of names (record 0006,
// rule 45; docs/reference/bundle.md, "How a file is written"). Every other name that is not NAME.yaml
// stays an error, and a reader of one file still refuses a name that is not valid. The names of this
// file start with tl.

// tlLister is one of the five calls that list a wanted folder. It returns the names that the call
// gives (nil for a call that gives none) and its error.
type tlLister struct {
	name string
	dir  string // the folder that the call lists
	run  func(fsys fsx.FS, s *wanted.Settings) ([]string, error)
}

func tlListers() []tlLister {
	return []tlLister{
		{"ListRootNames", wanted.RootsDir, func(fsys fsx.FS, _ *wanted.Settings) ([]string, error) {
			return wanted.ListRootNames(fsys)
		}},
		{"ListRoots", wanted.RootsDir, func(fsys fsx.FS, _ *wanted.Settings) ([]string, error) {
			rs, err := wanted.ListRoots(fsys)
			var names []string
			for _, r := range rs {
				names = append(names, r.Name)
			}
			return names, err
		}},
		{"ListDelegations", wanted.DelegationsDir, func(fsys fsx.FS, s *wanted.Settings) ([]string, error) {
			ds, err := wanted.ListDelegations(fsys, s)
			var names []string
			for _, d := range ds {
				names = append(names, d.Name)
			}
			return names, err
		}},
		{"CheckDelegations", wanted.DelegationsDir, func(fsys fsx.FS, s *wanted.Settings) ([]string, error) {
			return nil, wanted.CheckDelegations(fsys, s)
		}},
		{"ListCardNames", wanted.CardsDir, func(fsys fsx.FS, _ *wanted.Settings) ([]string, error) {
			return wanted.ListCardNames(fsys)
		}},
	}
}

// tlFiles is a bundle whose three folders each hold good files.
func tlFiles() map[string]string {
	return map[string]string{
		"want/roots/acme-tls.yaml":     lstRootText,
		"want/roots/good.yaml":         lstRootText,
		"want/delegations/d-good.yaml": lstDelegation,
		"want/cards/root-a.yaml":       cardRootA,
	}
}

// tlExpected is what a call gives on tlFiles.
func tlExpected(l tlLister) []string {
	switch l.name {
	case "ListRootNames", "ListRoots":
		return []string{"acme-tls", "good"}
	case "ListDelegations":
		return []string{"d-good"}
	case "ListCardNames":
		return []string{"root-a"}
	}
	return nil
}

// tlKind makes one entry of a kind at path.
type tlKind struct {
	name string
	make func(t *testing.T, p string)
}

func tlKinds() []tlKind {
	write := func(text string) func(*testing.T, string) {
		return func(t *testing.T, p string) {
			t.Helper()
			if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
		}
	}
	return []tlKind{
		{"a file that holds a root", write(lstRootText)},
		{"an empty file", write("")},
		{"a file of bytes that are not text", write("\xff\xfe\x00 not yaml: [")},
		{"a folder", func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
		}},
		{"a folder with whole files under ordinary names", func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
			for _, n := range []string{"acme-tls.yaml", "good.yaml", "d-good.yaml", "root-a.yaml"} {
				if err := os.WriteFile(filepath.Join(p, n), []byte(lstRootText), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(p, "nested.yaml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"a link to a good file", func(t *testing.T, p string) {
			if err := os.Symlink("good.yaml", p); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
		}},
		{"a dangling link", func(t *testing.T, p string) {
			if err := os.Symlink("nothing-here.yaml", p); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
		}},
		{"a link to a folder outside the bundle", func(t *testing.T, p string) {
			if err := os.Symlink(t.TempDir(), p); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
		}},
		{"a link to itself", func(t *testing.T, p string) {
			if err := os.Symlink(filepath.Base(p), p); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
		}},
		{"a FIFO", func(t *testing.T, p string) {
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
		}},
	}
}

// tlNames are names that start with ".rt-" in some case of the letters, in forms that a write makes
// and in forms that no write makes.
func tlNames() []string {
	return []string{
		".rt-k3j9x0a1b2c", // the form that a write makes: ".rt-" and 11 characters
		".rt-k3j9x0a1b2c.yaml",
		".rt-abc.yaml",
		".rt-abc",
		".rt-",
		".rt-.yaml",
		".rt--",
		".RT-x",
		".Rt-x",
		".rT-x",
		".RT-X.YAML",
		".rT-X.yaml",
		".RT-K3J9X0A1B2C",
		".rt-a b.yaml",
		".rt-x.yml",
		".rt-x.txt",
		".rt-.rt-.yaml",
		".rt-café.yaml",
		".rt-\xff.yaml",
		".rt-\x01.yaml",
		".rt-a\nb.yaml",
		".rt-\u202e.yaml",
		".rt-" + strings.Repeat("a", 246) + ".yaml", // 255 bytes, the longest name
	}
}

func TestAListerSkipsEveryLeftoverWhateverItsNameAndItsKind(t *testing.T) {
	s := lstSettings(t)
	for _, kind := range tlKinds() {
		for _, name := range tlNames() {
			t.Run(fmt.Sprintf("%s/%+q", kind.name, name), func(t *testing.T) {
				dir, fsys, reads := nmOpen(t, tlFiles())
				for _, folder := range []string{wanted.RootsDir, wanted.DelegationsDir, wanted.CardsDir} {
					kind.make(t, filepath.Join(dir, filepath.FromSlash(folder), name))
				}
				before := lstTree(t, dir)
				for _, l := range tlListers() {
					got, err := l.run(fsys, s)
					if err != nil {
						t.Errorf("%s: %v", l.name, err)
						continue
					}
					if want := tlExpected(l); !slices.Equal(got, want) {
						t.Errorf("%s = %q, want %q", l.name, got, want)
					}
				}
				for _, p := range reads.paths {
					if strings.Contains(strings.ToLower(p), "/.rt-") {
						t.Errorf("the leftover was read: %q", p)
					}
				}
				if after := lstTree(t, dir); !slices.Equal(before, after) {
					t.Errorf("a lister changed the folder")
				}
			})
		}
	}
}

// The names that the lister of roots gives are the names of the same folder without the leftover, for
// each place of the leftover among the other names.
func TestALeftoverDoesNotChangeTheListWhereverItSorts(t *testing.T) {
	good := map[string]string{
		"want/roots/0a.yaml":    lstRootText,
		"want/roots/m.yaml":     lstRootText,
		"want/roots/zz.yaml":    lstRootText,
		"want/roots/rt-ok.yaml": lstRootText,
	}
	want := []string{"0a", "m", "rt-ok", "zz"}
	for _, left := range []string{".rt-a", ".RT-0", ".rt-m.yaml", ".rt-zz", ".rt-~", ".rt-\x7f", ".rt-\xff", ".rt-z.yaml"} {
		t.Run(fmt.Sprintf("%+q", left), func(t *testing.T) {
			dir, fsys, _ := nmOpen(t, good)
			if err := os.WriteFile(filepath.Join(dir, "want", "roots", left), []byte("x"), 0o644); err != nil {
				t.Skipf("this system does not make the name: %v", err)
			}
			got, err := wanted.ListRootNames(fsys)
			if err != nil || !slices.Equal(got, want) {
				t.Errorf("ListRootNames = %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestAFolderOfNothingButLeftoversIsAnEmptyListAndNoError(t *testing.T) {
	s := lstSettings(t)
	files := map[string]string{
		"want/roots/.rt-k3j9x0a1b2c":       lstRootText,
		"want/roots/.RT-x.yaml":            lstRootText,
		"want/delegations/.rt-abc.yaml":    lstDelegation,
		"want/delegations/.Rt-abc":         "x",
		"want/cards/.rt-k3j9x0a1b2c.yaml":  cardRootA,
		"want/cards/.rT-":                  "",
		"want/delegations/.rt-nested/a.go": "x",
	}
	dir, fsys, reads := nmOpen(t, files)
	before := lstTree(t, dir)
	for _, l := range tlListers() {
		got, err := l.run(fsys, s)
		if err != nil || len(got) != 0 {
			t.Errorf("%s = %q, %v; want no name and no error", l.name, got, err)
		}
	}
	if reads.count() != 0 {
		t.Errorf("files were read: %q", reads.paths)
	}
	if !slices.Equal(before, lstTree(t, dir)) {
		t.Error("a lister changed the folder")
	}
}

// A leftover never hides a fault that a lister refuses: the fault is told, with its own path, and the
// path of the leftover is not told.
func TestALeftoverBesideAnEntryThatIsRefusedStillGivesTheRefusal(t *testing.T) {
	s := lstSettings(t)
	type bad struct {
		name  string
		make  func(t *testing.T, p string)
		words string
	}
	file := func(t *testing.T, p string) {
		if err := os.WriteFile(p, []byte(lstRootText), 0o644); err != nil {
			t.Skipf("this system does not make the name: %v", err)
		}
	}
	bads := []bad{
		{"Bad.yaml", file, "lower-case"},
		{"x.yml", file, "NAME.yaml"},
		{"a.txt", file, "NAME.yaml"},
		{".yaml", file, "1 to 63"},
		{"x.rt-y.yaml", file, "lower-case"},
		{"a.rt-.yaml", file, "lower-case"},
		{"rt-x.yaml.yaml", file, "lower-case"},
		// A name that nearly starts with the prefix is not a leftover.
		{".rt.yaml", file, "lower-case"},
		{".rtx.yaml", file, "lower-case"},
		{".r.yaml", file, "lower-case"},
		{".rt_x.yaml", file, "lower-case"},
		{"..rt-x.yaml", file, "lower-case"},
		{" .rt-x.yaml", file, "lower-case"},
		{"-.rt-x.yaml", file, "lower-case"},
		{".r-t-x.yaml", file, "lower-case"},
		{".rt‐x.yaml", file, "lower-case"},       // a hyphen of another kind
		{".r\u200bt-x.yaml", file, "lower-case"}, // a zero-width character inside the prefix
		{".гt-x.yaml", file, "lower-case"},       // a Cyrillic letter in place of the r
		{"\u00ad.rt-x.yaml", file, "lower-case"}, // a soft hyphen before the prefix
		{"\u202e.rt-x.yaml", file, "lower-case"}, // a reordering control before the prefix
		{"a.yaml", func(t *testing.T, p string) { // a folder with a good name
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		{"a.yaml", func(t *testing.T, p string) { // a FIFO with a good name
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
		{"a.yaml", func(t *testing.T, p string) { // a link with a good name
			if err := os.Symlink("good.yaml", p); err != nil {
				t.Fatal(err)
			}
		}, "not a regular file"},
	}
	for _, b := range bads {
		for _, left := range []string{".rt-k3j9x0a1b2c", ".RT-x.yaml"} {
			t.Run(fmt.Sprintf("%+q beside %q", b.name, left), func(t *testing.T) {
				dir, fsys, reads := nmOpen(t, tlFiles())
				for _, folder := range []string{wanted.RootsDir, wanted.DelegationsDir, wanted.CardsDir} {
					if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(folder), left), []byte("x"), 0o644); err != nil {
						t.Fatal(err)
					}
					b.make(t, filepath.Join(dir, filepath.FromSlash(folder), b.name))
				}
				before := lstTree(t, dir)
				for _, l := range tlListers() {
					got, err := l.run(fsys, s)
					if err == nil || got != nil {
						t.Errorf("%s = %q, %v; want a refusal and no name", l.name, got, err)
						continue
					}
					var e *wanted.Error
					if !errors.As(err, &e) {
						t.Errorf("%s: the error is %T, want *wanted.Error", l.name, err)
						continue
					}
					msg := err.Error()
					if !strings.Contains(msg, l.dir+"/") {
						t.Errorf("%s: the error %q does not name the folder %s", l.name, msg, l.dir)
					}
					if !strings.Contains(msg, b.words) {
						t.Errorf("%s: the error %q does not hold %q", l.name, msg, b.words)
					}
					if strings.Contains(strings.ToLower(msg), ".rt-k3j9") || strings.Contains(strings.ToLower(msg), "/.rt-x") {
						t.Errorf("%s: the error names the leftover: %q", l.name, msg)
					}
					if !printableASCII(msg) {
						t.Errorf("%s: the error is not printable ASCII: %+q", l.name, msg)
					}
				}
				if reads.count() != 0 {
					t.Errorf("files were read before the names were judged: %q", reads.paths)
				}
				if !slices.Equal(before, lstTree(t, dir)) {
					t.Error("a lister changed the folder")
				}
			})
		}
	}
}

// The fault that a lister tells is the one of the entry that is refused, and it is the same when the
// folder holds leftovers and when it does not.
func TestTheRefusalIsTheSameWithAndWithoutALeftover(t *testing.T) {
	s := lstSettings(t)
	for _, l := range tlListers() {
		t.Run(l.name, func(t *testing.T) {
			with := tlFiles()
			without := tlFiles()
			for _, f := range []string{"want/roots/", "want/delegations/", "want/cards/"} {
				with[f+"Bad.yaml"] = "x"
				without[f+"Bad.yaml"] = "x"
				with[f+".rt-k3j9x0a1b2c"] = "x"
				with[f+".RT-zz.yaml"] = "x"
			}
			_, f1, _ := nmOpen(t, with)
			_, f2, _ := nmOpen(t, without)
			_, e1 := l.run(f1, s)
			_, e2 := l.run(f2, s)
			if e1 == nil || e2 == nil || e1.Error() != e2.Error() {
				t.Errorf("with a leftover: %v; without: %v", e1, e2)
			}
		})
	}
}

// A good file that fails its own check is still told by the call that reads it, and the leftover
// beside it is not read.
func TestAFileThatFailsItsCheckIsToldAndTheLeftoverBesideItIsNotRead(t *testing.T) {
	files := tlFiles()
	files["want/roots/bad.yaml"] = "version: 1\nkind: nonsense\n"
	files["want/roots/.rt-k3j9x0a1b2c"] = "this is not a root file"
	files["want/delegations/bad.yaml"] = "version: 1\ntype: nonsense\n"
	files["want/delegations/.RT-x.yaml"] = "this is not a delegation file"
	_, fsys, reads := nmOpen(t, files)
	if _, err := wanted.ListRoots(fsys); err == nil || !strings.Contains(err.Error(), "want/roots/bad.yaml") {
		t.Errorf("ListRoots = %v, want the fault of bad.yaml", err)
	}
	if err := wanted.CheckDelegations(fsys, lstSettings(t)); err == nil || !strings.Contains(err.Error(), "want/delegations/bad.yaml") {
		t.Errorf("CheckDelegations = %v, want the fault of bad.yaml", err)
	}
	for _, p := range reads.paths {
		if strings.Contains(strings.ToLower(p), "/.rt-") {
			t.Errorf("the leftover was read: %q", p)
		}
	}
	// The list of names is judged without reading, and it is clean.
	if names, err := wanted.ListRootNames(fsys); err != nil || !slices.Equal(names, []string{"acme-tls", "bad", "good"}) {
		t.Errorf("ListRootNames = %q, %v", names, err)
	}
}

// A delegation file with a name of its own kind of fault is still refused beside a leftover.
func TestADelegationNameThatTheSshKeyListUsesIsStillRefusedBesideALeftover(t *testing.T) {
	files := tlFiles()
	files["want/delegations/break-glass-one.yaml"] = lstDelegation
	files["want/delegations/.rt-k3j9x0a1b2c"] = "x"
	_, fsys, _ := nmOpen(t, files)
	err := wanted.CheckDelegations(fsys, lstSettings(t))
	if err == nil || !strings.Contains(err.Error(), "want/delegations/break-glass-one.yaml") || !strings.Contains(err.Error(), "break-glass-") {
		t.Errorf("CheckDelegations = %v", err)
	}
}

// Names that look like the prefix but are not it are not skipped: a name that is a good NAME is listed
// and any other is an error.
func TestANameThatOnlyLooksLikeThePrefixIsNotSkipped(t *testing.T) {
	_, fsys, _ := nmOpen(t, map[string]string{
		"want/roots/rt-x.yaml":    lstRootText,
		"want/roots/rt-.yaml":     lstRootText,
		"want/roots/0rt-x.yaml":   lstRootText,
		"want/roots/a-rt-x.yaml":  lstRootText,
		"want/roots/rt-rt-.yaml":  lstRootText,
		"want/roots/.rtx.yaml.zz": lstRootText,
	})
	// The last name is not NAME.yaml and is refused; the rest are good names.
	if got, err := wanted.ListRootNames(fsys); err == nil || got != nil || !strings.Contains(err.Error(), "want/roots/.rtx.yaml.zz") {
		t.Fatalf("ListRootNames = %q, %v", got, err)
	}
	_, fsys, _ = nmOpen(t, map[string]string{
		"want/roots/rt-x.yaml":   lstRootText,
		"want/roots/rt-.yaml":    lstRootText,
		"want/roots/0rt-x.yaml":  lstRootText,
		"want/roots/a-rt-x.yaml": lstRootText,
		"want/roots/rt-rt-.yaml": lstRootText,
	})
	want := []string{"0rt-x", "a-rt-x", "rt-", "rt-rt-", "rt-x"}
	if got, err := wanted.ListRootNames(fsys); err != nil || !slices.Equal(got, want) {
		t.Errorf("ListRootNames = %q, %v; want %q", got, err, want)
	}
}

// The names that a skipped leftover has do not count toward the limit of names, and a folder of the
// limit is accepted with any number of leftovers beside it.
func TestLeftoversDoNotCountTowardTheLimitOfNames(t *testing.T) {
	s := lstSettings(t)
	const left = 300
	addLeft := func(files map[string]string, folder string) {
		for i := range left {
			switch i % 3 {
			case 0:
				files[fmt.Sprintf("%s/.rt-%011d", folder, i)] = "x"
			case 1:
				files[fmt.Sprintf("%s/.RT-%011d.yaml", folder, i)] = "x"
			default:
				files[fmt.Sprintf("%s/.Rt-%011d.tmp", folder, i)] = "x"
			}
		}
	}
	t.Run("roots: exactly the limit of good names and many leftovers", func(t *testing.T) {
		files := nmRoots(wanted.MaxFiles)
		addLeft(files, "want/roots")
		_, fsys, reads := nmOpen(t, files)
		names, err := wanted.ListRootNames(fsys)
		if err != nil || len(names) != wanted.MaxFiles || !slices.IsSorted(names) {
			t.Fatalf("ListRootNames = %d names, %v", len(names), err)
		}
		if reads.count() != 0 {
			t.Errorf("%d files were read", reads.count())
		}
		roots, err := wanted.ListRoots(fsys)
		if err != nil || len(roots) != wanted.MaxFiles {
			t.Errorf("ListRoots = %d roots, %v", len(roots), err)
		}
	})
	t.Run("roots: one more than the limit of good names is refused whatever the leftovers", func(t *testing.T) {
		files := nmRoots(wanted.MaxFiles + 1)
		addLeft(files, "want/roots")
		_, fsys, reads := nmOpen(t, files)
		names, err := wanted.ListRootNames(fsys)
		if err == nil || names != nil || !strings.Contains(err.Error(), fmt.Sprint(wanted.MaxFiles)) || !strings.Contains(err.Error(), "want/roots") {
			t.Fatalf("ListRootNames = %d names, %v", len(names), err)
		}
		if reads.count() != 0 {
			t.Errorf("%d files were read", reads.count())
		}
	})
	t.Run("roots: more leftovers than the limit and one good name", func(t *testing.T) {
		files := map[string]string{"want/roots/good.yaml": lstRootText}
		for i := range wanted.MaxFiles + 200 {
			files[fmt.Sprintf("want/roots/.rt-%011d", i)] = "x"
		}
		_, fsys, _ := nmOpen(t, files)
		names, err := wanted.ListRootNames(fsys)
		if err != nil || !slices.Equal(names, []string{"good"}) {
			t.Errorf("ListRootNames = %q, %v", names, err)
		}
	})
	t.Run("delegations: exactly the limit and many leftovers", func(t *testing.T) {
		files := nmDelegationBundle(wanted.MaxFiles)
		addLeft(files, "want/delegations")
		_, fsys, _ := nmOpen(t, files)
		ds, err := wanted.ListDelegations(fsys, s)
		if err != nil || len(ds) != wanted.MaxFiles {
			t.Fatalf("ListDelegations = %d, %v", len(ds), err)
		}
		if err := wanted.CheckDelegations(fsys, s); err != nil {
			t.Errorf("CheckDelegations = %v", err)
		}
	})
	t.Run("delegations: one more than the limit is refused before any file is read", func(t *testing.T) {
		files := nmDelegationBundle(wanted.MaxFiles + 1)
		addLeft(files, "want/delegations")
		_, fsys, reads := nmOpen(t, files)
		err := wanted.CheckDelegations(fsys, s)
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(wanted.MaxFiles)) || !strings.Contains(err.Error(), "want/delegations") {
			t.Fatalf("CheckDelegations = %v", err)
		}
		if reads.count() != 0 {
			t.Errorf("%d files were read", reads.count())
		}
	})
	t.Run("cards: exactly the limit and many leftovers", func(t *testing.T) {
		files := cardNumbered(wanted.MaxFiles)
		addLeft(files, "want/cards")
		_, fsys, _ := nmOpen(t, files)
		names, err := wanted.ListCardNames(fsys)
		if err != nil || len(names) != wanted.MaxFiles {
			t.Errorf("ListCardNames = %d names, %v", len(names), err)
		}
	})
	t.Run("cards: one more than the limit is refused", func(t *testing.T) {
		files := cardNumbered(wanted.MaxFiles + 1)
		addLeft(files, "want/cards")
		_, fsys, _ := nmOpen(t, files)
		names, err := wanted.ListCardNames(fsys)
		if err == nil || names != nil || !strings.Contains(err.Error(), "want/cards") {
			t.Errorf("ListCardNames = %d names, %v", len(names), err)
		}
	})
}

// tlEntry is an entry of a listing that a real folder cannot always give.
type tlEntry struct {
	name string
	mode fs.FileMode
}

func (e tlEntry) Name() string               { return e.name }
func (e tlEntry) IsDir() bool                { return e.mode.IsDir() }
func (e tlEntry) Type() fs.FileMode          { return e.mode.Type() }
func (e tlEntry) Info() (fs.FileInfo, error) { return tlInfo{e}, nil }

type tlInfo struct{ e tlEntry }

func (i tlInfo) Name() string       { return i.e.name }
func (i tlInfo) Size() int64        { return 0 }
func (i tlInfo) Mode() fs.FileMode  { return i.e.mode }
func (i tlInfo) ModTime() time.Time { return time.Time{} }
func (i tlInfo) IsDir() bool        { return i.e.mode.IsDir() }
func (i tlInfo) Sys() any           { return nil }

// tlInject is a folder that adds entries to the listing of one folder below it, and changes nothing else.
type tlInject struct {
	fsx.FS
	here   string // the path of this folder, "" for the root
	target string // the path of the folder whose listing gets the extra entries
	extra  func() []fs.DirEntry
}

func (f tlInject) OpenDir(name string) (fsx.FS, error) {
	sub, err := f.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return tlInject{FS: sub, here: path.Join(f.here, name), target: f.target, extra: f.extra}, nil
}

func (f tlInject) ReadDir() ([]fs.DirEntry, error) {
	ents, err := f.FS.ReadDir()
	if err != nil || f.here != f.target {
		return ents, err
	}
	ents = append(ents, f.extra()...)
	slices.SortFunc(ents, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return ents, nil
}

func tlInjected(t testing.TB, folder string, extra func() []fs.DirEntry) fsx.FS {
	t.Helper()
	_, fsys := bundleDir(t, tlFiles())
	return tlInject{FS: fsys, target: folder, extra: extra}
}

// A leftover of a kind that a real folder gives only to a privileged program, or on some systems only:
// a device, a socket, an entry of an unknown kind.
func TestALeftoverOfAnyKindOfEntryIsSkippedAndTheSameKindWithAGoodNameIsRefused(t *testing.T) {
	s := lstSettings(t)
	kinds := map[string]fs.FileMode{
		"a device":           fs.ModeDevice,
		"a character device": fs.ModeDevice | fs.ModeCharDevice,
		"a socket":           fs.ModeSocket,
		"an irregular file":  fs.ModeIrregular,
		"a FIFO":             fs.ModeNamedPipe,
		"a link":             fs.ModeSymlink,
		"a folder":           fs.ModeDir,
		"a file with setuid": fs.ModeSetuid,
		"a plain file":       0,
	}
	for kname, mode := range kinds {
		for _, l := range tlListers() {
			t.Run(kname+"/"+l.name, func(t *testing.T) {
				leftover := tlInjected(t, l.dir, func() []fs.DirEntry {
					return []fs.DirEntry{tlEntry{".rt-k3j9x0a1b2c", mode}, tlEntry{".RT-x.yaml", mode}}
				})
				got, err := l.run(leftover, s)
				if err != nil {
					t.Fatalf("%s: %v", l.name, err)
				}
				if want := tlExpected(l); !slices.Equal(got, want) {
					t.Errorf("%s = %q, want %q", l.name, got, want)
				}
				if mode.Type() == 0 {
					return // a plain file with a good name is the good case
				}
				named := tlInjected(t, l.dir, func() []fs.DirEntry { return []fs.DirEntry{tlEntry{"zz.yaml", mode}} })
				got, err = l.run(named, s)
				if err == nil || got != nil || !strings.Contains(err.Error(), l.dir+"/zz.yaml") || !strings.Contains(err.Error(), "not a regular file") {
					t.Errorf("%s with a good name of this kind = %q, %v; want a refusal", l.name, got, err)
				}
			})
		}
	}
}

// Names that a real folder of some systems does not hold, and that the listing of a hostile stick can.
func TestAListingOfOddNamesSkipsOnlyThoseThatStartWithThePrefix(t *testing.T) {
	skipped := []string{
		".rt-", ".RT-", ".Rt-", ".rT-", ".rt-\x00", ".rt-\xff\xfe", ".rt-\u202e\u2066", ".rt-\U0001F600", ".rt-/x",
		".rt-" + strings.Repeat("é", 200), ".rt-İ", ".rt-K",
	}
	refused := []string{
		"", " ", ".", "..", ".rt", ".rT", ".r", "rt-", ".rt‑x", ".K", "ſrt-", ".ｒｔ-",
		".ŕt-", "\x00.rt-x", ".\xffrt-x",
	}
	for _, n := range skipped {
		t.Run(fmt.Sprintf("skipped %+q", n), func(t *testing.T) {
			fsys := tlInjected(t, wanted.RootsDir, func() []fs.DirEntry { return []fs.DirEntry{tlEntry{n, 0}} })
			got, err := wanted.ListRootNames(fsys)
			if err != nil || !slices.Equal(got, []string{"acme-tls", "good"}) {
				t.Errorf("ListRootNames = %q, %v", got, err)
			}
		})
	}
	for _, n := range refused {
		t.Run(fmt.Sprintf("refused %+q", n), func(t *testing.T) {
			fsys := tlInjected(t, wanted.RootsDir, func() []fs.DirEntry { return []fs.DirEntry{tlEntry{n, 0}} })
			got, err := wanted.ListRootNames(fsys)
			if err == nil || got != nil {
				t.Fatalf("ListRootNames = %q, %v; want a refusal", got, err)
			}
			if !printableASCII(err.Error()) {
				t.Errorf("the error is not printable ASCII: %+q", err.Error())
			}
		})
	}
}

// The listing is bounded by the bound of package fsx, and a folder of very many leftovers meets it.
func TestAFolderOfVeryManyLeftoversIsBoundedByTheBoundOfTheFilesystemPackage(t *testing.T) {
	s := lstSettings(t)
	many := func(n int) func() []fs.DirEntry {
		return func() []fs.DirEntry {
			out := make([]fs.DirEntry, 0, n)
			for i := range n {
				out = append(out, tlEntry{fmt.Sprintf(".rt-%011d", i), 0})
			}
			return out
		}
	}
	for _, l := range tlListers() {
		t.Run(l.name, func(t *testing.T) {
			// The folder holds the good files too, so a folder of exactly the bound is one name short of
			// the leftovers that the test adds.
			existing := len(tlExpected(l))
			if l.name == "CheckDelegations" {
				existing = 1
			}
			atBound := tlInjected(t, l.dir, many(fsx.MaxDirEntries-existing))
			got, err := l.run(atBound, s)
			if err != nil || !slices.Equal(got, tlExpected(l)) {
				t.Errorf("at the bound: %q, %v", got, err)
			}
			over := tlInjected(t, l.dir, many(fsx.MaxDirEntries-existing+1))
			got, err = l.run(over, s)
			if err == nil || got != nil {
				t.Fatalf("over the bound: %q, %v", got, err)
			}
			if !errors.Is(err, fsx.ErrTooMany) || !strings.Contains(err.Error(), l.dir) || !strings.Contains(err.Error(), "too many names") {
				t.Errorf("the error %q does not say that %s holds too many names", err, l.dir)
			}
			if !printableASCII(err.Error()) {
				t.Errorf("the error is not printable ASCII: %+q", err.Error())
			}
		})
	}
}

// The same on the disk, where the bound is met while the folder is read.
func TestAFolderOfVeryManyLeftoversOnTheDiskIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("makes 65,537 files")
	}
	dir, fsys := bundleDir(t, map[string]string{"want/roots/good.yaml": lstRootText})
	roots := filepath.Join(dir, "want", "roots")
	for i := range fsx.MaxDirEntries {
		f, err := os.Create(filepath.Join(roots, fmt.Sprintf(".rt-%011d", i)))
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// 65,536 leftovers and one good file: 65,537 names.
	got, err := wanted.ListRootNames(fsys)
	if err == nil || got != nil || !errors.Is(err, fsx.ErrTooMany) || !strings.Contains(err.Error(), "too many names") {
		t.Errorf("ListRootNames = %q, %v", got, err)
	}
	if err := os.Remove(filepath.Join(roots, "good.yaml")); err != nil {
		t.Fatal(err)
	}
	// 65,536 leftovers alone are at the bound and are all skipped.
	got, err = wanted.ListRootNames(fsys)
	if err != nil || len(got) != 0 {
		t.Errorf("ListRootNames of exactly the bound of leftovers = %q, %v", got, err)
	}
}

// A reader of one file still refuses a name that is not valid, a leftover name included, whether the
// file exists or not, and it reads nothing for it.
func TestTheReadersOfOneFileStillRefuseALeftoverName(t *testing.T) {
	s := lstSettings(t)
	for _, name := range []string{".rt-abc", ".rt-k3j9x0a1b2c", ".RT-abc", ".Rt-abc", ".rt-", ".rt-abc.yaml", ".rt-abc.yaml.yaml"} {
		t.Run(fmt.Sprintf("%+q", name), func(t *testing.T) {
			files := tlFiles()
			for _, folder := range []string{"want/roots/", "want/delegations/", "want/cards/"} {
				files[folder+name] = lstRootText
				files[folder+name+".yaml"] = lstRootText
			}
			_, fsys, reads := nmOpen(t, files)
			r, err := wanted.LoadRoot(fsys, name)
			if err == nil || r != nil {
				t.Errorf("LoadRoot = %v, %v", r, err)
			}
			_ = wantFault(t, err, "want/roots/"+name+".yaml", 0, "lower-case")
			d, err := wanted.LoadDelegation(fsys, name, s)
			if err == nil || d != nil {
				t.Errorf("LoadDelegation = %v, %v", d, err)
			}
			_ = wantFault(t, err, "want/delegations/"+name+".yaml", 0)
			c, err := wanted.LoadCard(fsys, name)
			if err == nil || c != nil {
				t.Errorf("LoadCard = %v, %v", c, err)
			}
			_ = wantFault(t, err, "want/cards/"+name+".yaml", 0, "lower-case")
			if rs, err := wanted.LoadRoots(fsys, []string{"good", name}); err == nil || rs != nil {
				t.Errorf("LoadRoots with the name = %v, %v", rs, err)
			}
			if reads.count() > 1 { // LoadRoots reads "good" before it meets the name
				t.Errorf("files were read for a refused name: %q", reads.paths)
			}
		})
	}
}

// A lister of a folder that does not exist is still no name and no error, and a leftover in one folder
// has no effect on another.
func TestALeftoverInOneFolderHasNoEffectOnAnother(t *testing.T) {
	s := lstSettings(t)
	_, fsys, _ := nmOpen(t, map[string]string{"want/roots/.rt-abc": "x", "want/roots/good.yaml": lstRootText})
	if names, err := wanted.ListCardNames(fsys); err != nil || len(names) != 0 {
		t.Errorf("ListCardNames = %q, %v", names, err)
	}
	if ds, err := wanted.ListDelegations(fsys, s); err != nil || len(ds) != 0 {
		t.Errorf("ListDelegations = %v, %v", ds, err)
	}
	if err := wanted.CheckDelegations(fsys, s); err != nil {
		t.Errorf("CheckDelegations = %v", err)
	}
	// A folder named like the leftover, in the place of the folder of roots, is not a leftover folder.
	dir, fsys2, _ := nmOpen(t, map[string]string{"want/.rt-roots/good.yaml": lstRootText})
	if names, err := wanted.ListRootNames(fsys2); err != nil || len(names) != 0 {
		t.Errorf("ListRootNames = %q, %v", names, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "want", "roots"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if names, err := wanted.ListRootNames(fsys2); err == nil || names != nil {
		t.Errorf("a file in place of the folder = %q, %v; want a refusal", names, err)
	}
}

// A list is the same twice and a leftover that appears between two calls changes nothing but the
// folder it is in.
func TestAListIsTheSameBeforeAndAfterALeftoverAppears(t *testing.T) {
	dir, fsys, _ := nmOpen(t, tlFiles())
	s := lstSettings(t)
	var before [][]string
	for _, l := range tlListers() {
		got, err := l.run(fsys, s)
		if err != nil {
			t.Fatalf("%s: %v", l.name, err)
		}
		before = append(before, got)
	}
	for _, folder := range []string{wanted.RootsDir, wanted.DelegationsDir, wanted.CardsDir} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(folder), ".rt-k3j9x0a1b2c"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, l := range tlListers() {
		got, err := l.run(fsys, s)
		if err != nil || !slices.Equal(got, before[i]) {
			t.Errorf("%s = %q, %v; before the leftover %q", l.name, got, err, before[i])
		}
	}
}

// A leftover that cannot be opened (a file or a folder with no permission) is never opened.
func TestALeftoverThatCannotBeOpenedIsNeverOpened(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a privileged user opens everything")
	}
	s := lstSettings(t)
	dir, fsys, _ := nmOpen(t, tlFiles())
	for _, folder := range []string{wanted.RootsDir, wanted.DelegationsDir, wanted.CardsDir} {
		f := filepath.Join(dir, filepath.FromSlash(folder), ".rt-secret")
		if err := os.WriteFile(f, []byte("x"), 0o000); err != nil {
			t.Fatal(err)
		}
		d := filepath.Join(dir, filepath.FromSlash(folder), ".RT-closed")
		if err := os.Mkdir(d, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(d, 0o755) })
	}
	for _, l := range tlListers() {
		got, err := l.run(fsys, s)
		if err != nil || !slices.Equal(got, tlExpected(l)) {
			t.Errorf("%s = %q, %v", l.name, got, err)
		}
	}
}
