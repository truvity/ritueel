//go:build linux || darwin

package bundle

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A bundle is not made inside a bundle: a folder above the parent of DIR that holds a name ritueel.yaml, of any kind,
// refuses Create before anything is made. The seams bundleAbove and holdsSettings are driven here with folders on the
// disk; the command has its own tests of the text a person reads.

func mustDo(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// kindsOfTheName make a name ritueel.yaml of each kind of thing that can stand there.
var kindsOfTheName = map[string]func(t *testing.T, p string){
	"a file":                     func(t *testing.T, p string) { mustDo(t, os.WriteFile(p, []byte("version: 1\n"), 0o644)) },
	"an empty file":              func(t *testing.T, p string) { mustDo(t, os.WriteFile(p, nil, 0o644)) },
	"a folder":                   func(t *testing.T, p string) { mustDo(t, os.Mkdir(p, 0o755)) },
	"a link to a folder":         func(t *testing.T, p string) { mustDo(t, os.Symlink(filepath.Dir(p), p)) },
	"a link to nothing":          func(t *testing.T, p string) { mustDo(t, os.Symlink("nowhere", p)) },
	"a link to itself":           func(t *testing.T, p string) { mustDo(t, os.Symlink(filepath.Base(p), p)) },
	"a pipe":                     func(t *testing.T, p string) { mustDo(t, syscall.Mkfifo(p, 0o644)) },
	"a file that cannot be read": func(t *testing.T, p string) { mustDo(t, os.WriteFile(p, []byte("x"), 0o000)) },
}

func TestHoldsSettingsIsTrueForEveryKindOfThingThatStandsInThePlaceOfTheName(t *testing.T) {
	for kind, put := range kindsOfTheName {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if held, err := holdsSettings(dir); held || err != nil {
				t.Fatalf("an empty folder: (%v, %v), want (false, nil)", held, err)
			}
			put(t, filepath.Join(dir, "ritueel.yaml"))
			if held, err := holdsSettings(dir); !held || err != nil {
				t.Errorf("a folder with %s in the place of ritueel.yaml: (%v, %v), want (true, nil)", kind, held, err)
			}
		})
	}
}

// Only a name that does not exist is absent. A path that does not exist, a folder with other names, and a link as the
// last element (the name is looked at inside what it points to) all answer "absent", with no error.
func TestHoldsSettingsIsFalseWithNoErrorForWhatHoldsOtherNamesOrIsNotThere(t *testing.T) {
	root := t.TempDir()
	mustDo(t, os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644))
	mustDo(t, os.Mkdir(filepath.Join(root, "other"), 0o755))
	for _, name := range []string{"ritueel.yml", "ritueel.yaml.bak", "xritueel.yaml", "want", "RITUEEL.YAML.x"} {
		mustDo(t, os.WriteFile(filepath.Join(root, "other", name), nil, 0o644))
	}
	mustDo(t, os.Symlink(filepath.Join(root, "other"), filepath.Join(root, "link")))
	mustDo(t, os.Symlink("nowhere", filepath.Join(root, "dangling")))
	for name, p := range map[string]string{
		"a path that does not exist":  filepath.Join(root, "missing"),
		"a folder with other names":   filepath.Join(root, "other"),
		"a link to a folder":          filepath.Join(root, "link"),
		"a link to nothing":           filepath.Join(root, "dangling"),
		"a path that ends with a dot": filepath.Join(root, "other") + "/.",
	} {
		if held, err := holdsSettings(p); held || err != nil {
			t.Errorf("%s: (%v, %v), want (false, nil)", name, held, err)
		}
	}
}

// Anything else than "does not exist" is a folder that cannot be examined: the answer is not "absent", it is an
// error that names the folder, and the answer is never true.
func TestHoldsSettingsOfWhatCannotBeExaminedIsAnErrorAndNeverAbsent(t *testing.T) {
	root := t.TempDir()
	mustDo(t, os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644))
	mustDo(t, os.Symlink("loop", filepath.Join(root, "loop")))
	for name, tc := range map[string]struct {
		path string
		want string
	}{
		"a path that is a file":      {filepath.Join(root, "file"), "not a directory"},
		"a link to itself as folder": {filepath.Join(root, "loop"), "too many levels of symbolic links"},
		"a name with a NUL":          {filepath.Join(root, "a\x00b"), "invalid argument"},
		"a path too long":            {root + strings.Repeat("/aaaaaaaaaa", 600), "file name too long"},
	} {
		held, err := holdsSettings(tc.path)
		if held || err == nil {
			t.Errorf("%s: (%v, %v), want (false, an error)", name, held, err)
			continue
		}
		if errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: the error says the name does not exist: %v", name, err)
		}
		if !strings.Contains(err.Error(), "cannot be examined for ritueel.yaml: ") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %q, want the words %q and %q", name, err.Error(), "cannot be examined for ritueel.yaml: ", tc.want)
		}
	}
}

// The empty path has no folder in it. holdsSettings joins the name to it and so looks at the working folder; the
// function is never given "", and what it answers for it is the answer for the working folder.
func TestHoldsSettingsOfTheEmptyPathLooksAtTheWorkingFolder(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	if held, err := holdsSettings(""); held || err != nil {
		t.Errorf("an empty working folder: (%v, %v), want (false, nil)", held, err)
	}
	mustDo(t, os.WriteFile(filepath.Join(cwd, "ritueel.yaml"), nil, 0o644))
	if held, err := holdsSettings(""); !held || err != nil {
		t.Errorf("a working folder that holds the name: (%v, %v), want (true, nil)", held, err)
	}
}

func TestBundleAboveReturnsTheNearestFolderThatHoldsTheNameOrNothing(t *testing.T) {
	root := t.TempDir()
	root, err := filepath.EvalSymlinks(root)
	mustDo(t, err)
	a := filepath.Join(root, "a")
	b := filepath.Join(a, "b")
	c := filepath.Join(b, "c")
	mustDo(t, os.MkdirAll(c, 0o755))

	if got, err := bundleAbove(c); err != nil || got != "" {
		t.Fatalf("with no holder: (%q, %v), want nothing", got, err)
	}
	mustDo(t, os.WriteFile(filepath.Join(a, "ritueel.yaml"), nil, 0o644))
	for _, p := range []string{a, b, c, c + "/", c + "/.", filepath.Join(c, "..", "c")} {
		if got, err := bundleAbove(p); err != nil || got != a {
			t.Errorf("bundleAbove(%q) = (%q, %v), want %q", p, got, err, a)
		}
	}
	mustDo(t, os.WriteFile(filepath.Join(b, "ritueel.yaml"), nil, 0o644))
	if got, err := bundleAbove(c); err != nil || got != b {
		t.Errorf("with two holders: (%q, %v), want the nearest, %q", got, err, b)
	}
	if got, err := bundleAbove(b); err != nil || got != b {
		t.Errorf("the parent itself holds the name: (%q, %v), want %q", got, err, b)
	}
	// The folders beside the parent and below it do not count.
	if got, err := bundleAbove(root); err != nil || got != "" {
		t.Errorf("above the holders: (%q, %v), want nothing", got, err)
	}
}

func TestBundleAboveReadsARelativePathFromTheCurrentFolderAndTheDiskNotTheLinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	mustDo(t, err)
	holder := filepath.Join(root, "holder")
	mustDo(t, os.MkdirAll(filepath.Join(holder, "sub"), 0o755))
	mustDo(t, os.WriteFile(filepath.Join(holder, "ritueel.yaml"), nil, 0o644))
	mustDo(t, os.Symlink(holder, filepath.Join(root, "link")))

	cwd, err := os.Getwd()
	mustDo(t, err)
	rel, err := filepath.Rel(cwd, filepath.Join(holder, "sub"))
	if err != nil {
		t.Skipf("no relative path from %s: %v", cwd, err)
	}
	if got, err := bundleAbove(rel); err != nil || got != holder {
		t.Errorf("bundleAbove(%q) = (%q, %v), want %q", rel, got, err, holder)
	}
	// A link on the way is followed: the folder that is named is the one on the disk.
	if got, err := bundleAbove(filepath.Join(root, "link", "sub")); err != nil || got != holder {
		t.Errorf("through a link: (%q, %v), want %q", got, err, holder)
	}
}

func TestBundleAboveEndsAtTheRootOfTheFileSystem(t *testing.T) {
	// The loop stops at the root, with no holder, for the root itself and for a path that does not exist.
	for _, p := range []string{"/", "/no/such/folder/at/all"} {
		got, err := bundleAbove(p)
		if err != nil || got != "" {
			t.Errorf("bundleAbove(%q) = (%q, %v), want nothing", p, got, err)
		}
	}
}

func TestCreateRefusesWhenAFolderAboveHoldsTheNameAndMakesNothing(t *testing.T) {
	for kind, put := range kindsOfTheName {
		t.Run(kind, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			mustDo(t, err)
			holder := filepath.Join(root, "holder")
			parent := filepath.Join(holder, "mid")
			mustDo(t, os.MkdirAll(parent, 0o755))
			put(t, filepath.Join(holder, "ritueel.yaml"))
			files, err := Create(filepath.Join(parent, "acme"), StarterOptions{})
			if err == nil || files != nil {
				t.Fatalf("(%v, %v), want an error and no files", files, err)
			}
			var ce *CreateError
			if !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 {
				t.Fatalf("the error is %#v, want a CreateError for a folder that was not made", err)
			}
			want := "bundle: cannot make the bundle " + filepath.Join(parent, "acme") + ": the folder was not made: the folder " + holder + " holds ritueel.yaml: a bundle is not made inside a bundle"
			if err.Error() != want {
				t.Errorf("error = %q, want %q", err.Error(), want)
			}
			if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
				t.Errorf("the parent holds %v (%v), want nothing", entries, err)
			}
		})
	}
}

func TestCreateEscapesTheNameOfTheFolderAboveThatHoldsTheName(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	mustDo(t, err)
	holder := filepath.Join(root, "ho\nlder\x1b[31m")
	parent := filepath.Join(holder, "mid")
	mustDo(t, os.MkdirAll(parent, 0o755))
	mustDo(t, os.WriteFile(filepath.Join(holder, "ritueel.yaml"), nil, 0o644))
	_, err = Create(filepath.Join(parent, "acme"), StarterOptions{})
	if err == nil {
		t.Fatal("no error")
	}
	if strings.ContainsAny(err.Error(), "\n\x1b") {
		t.Errorf("the text holds a raw control character: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "holds ritueel.yaml") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestCreateWithNoHolderAboveMakesTheBundleAndASiblingBundleDoesNotStopIt(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	mustDo(t, err)
	mustDo(t, os.MkdirAll(filepath.Join(root, "sibling"), 0o755))
	mustDo(t, os.WriteFile(filepath.Join(root, "sibling", "ritueel.yaml"), nil, 0o644))
	mustDo(t, os.Mkdir(filepath.Join(root, "parent"), 0o755))
	files, err := Create(filepath.Join(root, "parent", "acme"), StarterOptions{})
	if err != nil || len(files) != 3 {
		t.Fatalf("(%d files, %v)", len(files), err)
	}
	b, err := Open(filepath.Join(root, "parent", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	// The bundle that Create made is now a holder.
	if _, err := Create(filepath.Join(root, "parent", "acme", "want", "inner"), StarterOptions{}); err == nil || !strings.Contains(err.Error(), "a bundle is not made inside a bundle") {
		t.Errorf("a second Create inside the first: %v", err)
	}
	// An error of the name is told before the folders above are read, and the parent that cannot be opened before both.
	if _, err := Create(filepath.Join(root, "missing", "acme"), StarterOptions{}); err == nil || strings.Contains(err.Error(), "inside a bundle") {
		t.Errorf("a missing parent: %v", err)
	}
}
