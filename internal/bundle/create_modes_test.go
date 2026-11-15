//go:build linux || darwin

package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A bundle is not made inside a bundle, and a folder above DIR is looked at by the name ritueel.yaml and not by
// listing it (cli.md, the bullet of new; record 0006, rule 42: a name that exists holds the name). So a folder that
// can be passed but not listed (no read bit) is looked at too. A folder that cannot be examined at all stops the call
// with an error that names it, and nothing is written: a check that cannot run is not a pass.
//
// The tests of modes skip when the process is root: root passes every mode, so no folder is one that cannot be
// passed or listed for it.

func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the process is root: root passes and lists every folder whatever its mode")
	}
}

// restoreMode makes the folder p readable again when the test ends, so that the folder of the test can be removed.
// It is registered after the folder of the test was made, so it runs before the removal.
func restoreMode(t *testing.T, p string) {
	t.Helper()
	t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
}

// modeTree makes root/d1/inner/deep and returns the real paths of root, d1 and deep.
func modeTree(t *testing.T) (root, d1, deep string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	mustDo(t, err)
	d1 = filepath.Join(root, "d1")
	deep = filepath.Join(d1, "inner", "deep")
	mustDo(t, os.MkdirAll(deep, 0o755))
	return root, d1, deep
}

// entriesOf lists the names in a folder.
func entriesOf(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	mustDo(t, err)
	var out []string
	for _, e := range list {
		out = append(out, e.Name())
	}
	return out
}

// foldersAboveThatCanBePassed are the modes of a folder above DIR that the process can pass.
var foldersAboveThatCanBePassed = []os.FileMode{0o311, 0o111, 0o711, 0o755, 0o555, 0o511, 0o333}

func TestCreateRefusesAFolderAboveThatHoldsTheNameWhateverItsModeAndWhateverIsInThePlaceOfTheName(t *testing.T) {
	skipAsRoot(t)
	for _, mode := range foldersAboveThatCanBePassed {
		for kind, put := range kindsOfTheName {
			t.Run(mode.String()+" "+kind, func(t *testing.T) {
				_, d1, deep := modeTree(t)
				put(t, filepath.Join(d1, "ritueel.yaml"))
				mustDo(t, os.Chmod(d1, mode))
				restoreMode(t, d1)

				dir := filepath.Join(deep, "dir")
				files, err := Create(dir, StarterOptions{})
				if err == nil || files != nil {
					t.Fatalf("(%v, %v), want an error and no files", files, err)
				}
				var ce *CreateError
				if !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 || ce.Dir != dir {
					t.Fatalf("the error is %#v, want a CreateError for a folder that was not made", err)
				}
				want := "bundle: cannot make the bundle " + dir + ": the folder was not made: the folder " + d1 +
					" holds ritueel.yaml: a bundle is not made inside a bundle"
				if err.Error() != want {
					t.Errorf("error = %q, want %q", err.Error(), want)
				}
				mustDo(t, os.Chmod(d1, 0o755))
				if got := entriesOf(t, deep); len(got) != 0 {
					t.Errorf("the parent holds %v, want nothing", got)
				}
			})
		}
	}
}

// The neighbours of the fault: a folder above that can be passed and holds no such name does not stop the call, in
// any of the modes, and the bundle is made in whole.
func TestCreateMakesTheBundleBelowAFolderAboveThatHoldsNoNameWhateverItsMode(t *testing.T) {
	skipAsRoot(t)
	for _, mode := range foldersAboveThatCanBePassed {
		t.Run(mode.String(), func(t *testing.T) {
			_, d1, deep := modeTree(t)
			// Names that only look like the name are not the name.
			for _, name := range []string{"ritueel.yml", "ritueel.yaml.bak", "xritueel.yaml"} {
				mustDo(t, os.WriteFile(filepath.Join(d1, name), nil, 0o644))
			}
			mustDo(t, os.Chmod(d1, mode))
			restoreMode(t, d1)
			files, err := Create(filepath.Join(deep, "dir"), StarterOptions{})
			if err != nil || len(files) != 3 {
				t.Fatalf("(%d files, %v), want the three starter files", len(files), err)
			}
			mustDo(t, os.Chmod(d1, 0o755))
			b, err := Open(filepath.Join(deep, "dir"))
			if err != nil {
				t.Fatalf("the bundle that was made does not open: %v", err)
			}
			_ = b.Close()
		})
	}
}

// A folder above with no pass bit cannot be passed, so the parent below it cannot be opened by its path: the call
// stops at the parent with exit-code-1 text, before the folders above are looked at, and writes nothing. One case
// of each mode that has no pass bit, with the name in the folder and without.
func TestCreateStopsAtAParentThatCannotBeReachedAndWritesNothing(t *testing.T) {
	skipAsRoot(t)
	for _, mode := range []os.FileMode{0o000, 0o600, 0o400, 0o200, 0o644} {
		for _, holds := range []bool{true, false} {
			name := mode.String() + " without the name"
			if holds {
				name = mode.String() + " with the name"
			}
			t.Run(name, func(t *testing.T) {
				_, d1, deep := modeTree(t)
				if holds {
					mustDo(t, os.WriteFile(filepath.Join(d1, "ritueel.yaml"), nil, 0o644))
				}
				mustDo(t, os.Chmod(d1, mode))
				restoreMode(t, d1)
				files, err := Create(filepath.Join(deep, "dir"), StarterOptions{})
				var ce *CreateError
				if err == nil || files != nil || !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 {
					t.Fatalf("(%v, %v), want a CreateError for a folder that was not made", files, err)
				}
				if !strings.Contains(err.Error(), "the parent folder cannot be opened") {
					t.Errorf("error = %q, want the words that the parent folder cannot be opened", err.Error())
				}
				mustDo(t, os.Chmod(d1, 0o755))
				if got := entriesOf(t, deep); len(got) != 0 {
					t.Errorf("the parent holds %v, want nothing", got)
				}
			})
		}
	}
}

// A parent that can be passed and not listed (mode 311) cannot be opened to write into either: the call stops with
// the same words, whether or not it holds the name, and nothing is written.
func TestCreateStopsAtAParentThatCanBePassedButNotOpened(t *testing.T) {
	skipAsRoot(t)
	for _, holds := range []bool{false, true} {
		_, _, deep := modeTree(t)
		if holds {
			mustDo(t, os.WriteFile(filepath.Join(deep, "ritueel.yaml"), nil, 0o644))
		}
		mustDo(t, os.Chmod(deep, 0o311))
		restoreMode(t, deep)
		_, err := Create(filepath.Join(deep, "dir"), StarterOptions{})
		var ce *CreateError
		if err == nil || !errors.As(err, &ce) || ce.Made || !strings.Contains(err.Error(), "the parent folder cannot be opened") {
			t.Errorf("name %v: error = %v, want the parent folder cannot be opened", holds, err)
		}
		mustDo(t, os.Chmod(deep, 0o755))
		want := 0
		if holds {
			want = 1
		}
		if got := entriesOf(t, deep); len(got) != want {
			t.Errorf("name %v: the parent holds %v", holds, got)
		}
	}
}

// bundleAbove on a folder whose way is not passable: the links of the path cannot be followed, so the answer is an
// error that says the parent folder cannot be resolved and names it, even when a folder further up holds the name. The
// answer is never "none", and it is never the folder further up that holds the name (that folder cannot be reached
// through this path); the folders of a path that was not resolved are not looked at.
func TestBundleAboveOfAFolderThatCannotBeExaminedIsAnErrorThatNamesItAndNeverNone(t *testing.T) {
	skipAsRoot(t)
	for _, mode := range []os.FileMode{0o000, 0o600, 0o644} {
		for _, aboveHolds := range []bool{false, true} {
			t.Run(mode.String(), func(t *testing.T) {
				root, d1, deep := modeTree(t)
				if aboveHolds {
					mustDo(t, os.WriteFile(filepath.Join(root, "ritueel.yaml"), nil, 0o644))
				}
				mustDo(t, os.Chmod(d1, mode))
				restoreMode(t, d1)
				got, err := bundleAbove(deep)
				if err == nil || got != "" {
					t.Fatalf("(%q, %v), want an error and no folder", got, err)
				}
				if !errors.Is(err, os.ErrPermission) {
					t.Errorf("error = %v, want one that says permission denied", err)
				}
				want := "the parent folder " + deep + " cannot be resolved: permission denied"
				if err.Error() != want {
					t.Errorf("error = %q, want %q", err.Error(), want)
				}
			})
		}
	}
}

// Create with a relative DIR, run from a folder that was reached before a folder above it lost its pass bit. The
// parent can be opened (by the relative path), so the call reaches the folders above; the links of the path cannot be
// followed, and the call stops with an error that names the parent, makes nothing and says that the folder was not made.
func TestCreateStopsWhenAFolderAboveCannotBeExaminedAndWritesNothing(t *testing.T) {
	skipAsRoot(t)
	_, d1, deep := modeTree(t)
	t.Chdir(deep)
	mustDo(t, os.Chmod(d1, 0o600))
	restoreMode(t, d1)
	files, err := Create("dir", StarterOptions{})
	var ce *CreateError
	if err == nil || files != nil || !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 || ce.Dir != "dir" {
		t.Fatalf("(%v, %v), want a CreateError for a folder that was not made", files, err)
	}
	want := "bundle: cannot make the bundle dir: the folder was not made: the parent folder " + deep + " cannot be resolved: permission denied"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
	mustDo(t, os.Chmod(d1, 0o755))
	if got := entriesOf(t, deep); len(got) != 0 {
		t.Errorf("the folder holds %v, want nothing", got)
	}
}

// A relative DIR is read from the working folder, and the folders above are the ones on the disk.
func TestCreateReadsARelativeDirFromTheWorkingFolder(t *testing.T) {
	root, d1, deep := modeTree(t)
	mustDo(t, os.WriteFile(filepath.Join(d1, "ritueel.yaml"), nil, 0o644))
	t.Chdir(root)
	for _, rel := range []string{"d1/inner/deep/dir", "./d1/inner/deep/dir", "d1//inner/deep/dir"} {
		_, err := Create(rel, StarterOptions{})
		want := "the folder " + d1 + " holds ritueel.yaml: a bundle is not made inside a bundle"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %v, want %q", rel, err, want)
		}
	}
	t.Chdir(deep)
	_, err := Create("dir", StarterOptions{})
	if err == nil || !strings.Contains(err.Error(), "the folder "+d1+" holds ritueel.yaml") {
		t.Errorf("a name with no folder: error = %v", err)
	}
	if got := entriesOf(t, deep); len(got) != 0 {
		t.Errorf("the parent holds %v, want nothing", got)
	}
}

// A DIR reached through a link: the folders above are those of the disk, so the folder that holds the name is named
// by its real path; and a link out of a bundle leaves the bundle.
func TestCreateReachedThroughALinkNamesTheFolderOnTheDisk(t *testing.T) {
	root, d1, deep := modeTree(t)
	mustDo(t, os.WriteFile(filepath.Join(d1, "ritueel.yaml"), nil, 0o644))
	link := filepath.Join(root, "link")
	mustDo(t, os.Symlink(d1, link))
	// The link is in the middle of the way (a link as the last element of the parent is refused by its own rule).
	_, err := Create(filepath.Join(link, "inner", "deep", "dir"), StarterOptions{})
	want := "the folder " + d1 + " holds ritueel.yaml: a bundle is not made inside a bundle"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("error = %v, want %q", err, want)
	}
	if got := entriesOf(t, deep); len(got) != 0 {
		t.Errorf("the parent holds %v, want nothing", got)
	}

	// A link out of a bundle leaves it: the folders above the real parent do not hold the name.
	other := filepath.Join(root, "other")
	mustDo(t, os.MkdirAll(filepath.Join(other, "sub"), 0o755))
	mustDo(t, os.WriteFile(filepath.Join(d1, "inner", "ritueel.yaml"), nil, 0o644))
	mustDo(t, os.Symlink(other, filepath.Join(d1, "inner", "out")))
	if _, err := Create(filepath.Join(d1, "inner", "out", "sub", "dir"), StarterOptions{}); err != nil {
		t.Errorf("a link out of a bundle: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(other, "sub", "dir", "ritueel.yaml")); err != nil {
		t.Errorf("the bundle is not where the disk says: %v", err)
	}
}

// The names in the texts are written by the exact escape of a name from a file system: a space as \x20, a backslash
// doubled, a byte that is not UTF-8 as \xNN, a control character as \uXXXX. The text of a folder name that is not
// escaped this way would be read back as another name. The expected text is written here with a replacer of its
// own, not with the function under test.
func TestTheNamesInTheTextsOfCreateAreEscapedOneToOne(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	mustDo(t, err)
	holder := filepath.Join(root, "ho lder\\x\xff\x1b")
	parent := filepath.Join(holder, "my dir")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Skipf("this file system does not take the name: %v", err)
	}
	mustDo(t, os.WriteFile(filepath.Join(holder, "ritueel.yaml"), nil, 0o644))
	dir := filepath.Join(parent, "ab")
	_, err = Create(dir, StarterOptions{})
	if err == nil {
		t.Fatal("no error")
	}
	exact := strings.NewReplacer(`\`, `\\`, " ", `\x20`, "\xff", `\xff`, "\x1b", `\u001b`)
	want := "bundle: cannot make the bundle " + exact.Replace(dir) + ": the folder was not made: the folder " + exact.Replace(holder) +
		" holds ritueel.yaml: a bundle is not made inside a bundle"
	if err.Error() != want {
		t.Errorf("error = %q\nwant      %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), "\xff") || strings.Contains(err.Error(), "\x1b") {
		t.Errorf("the text holds a raw control or non-UTF-8 byte: %q", err.Error())
	}
	// Two names that Escape would write alike are different here: the byte 0xff and the character U+FFFD.
	holder2 := filepath.Join(root, "h\xff")
	holder3 := filepath.Join(root, "h�")
	var texts []string
	for _, h := range []string{holder2, holder3} {
		mustDo(t, os.MkdirAll(filepath.Join(h, "p"), 0o755))
		mustDo(t, os.WriteFile(filepath.Join(h, "ritueel.yaml"), nil, 0o644))
		_, err := Create(filepath.Join(h, "p", "x"), StarterOptions{})
		if err == nil {
			t.Fatal("no error")
		}
		texts = append(texts, err.Error())
	}
	if texts[0] == texts[1] {
		t.Errorf("the folders %q and %q give one text: %q", holder2, holder3, texts[0])
	}
}

// The texts of the error that names what was made, written for a stop in the middle: every name goes through the
// exact escape (the Dir and each name that was written).
func TestTheTextOfACreateErrorThatMadeSomethingEscapesTheDirAndEachName(t *testing.T) {
	err := &CreateError{Dir: "a b\\c\xff", Made: true, Written: []string{"want/", "x y", "p\\q\x1b"}, Err: errors.New("boom")}
	want := `bundle: cannot make the bundle a\x20b\\c\xff: the folder was made and 3 things were written in it (want/, x\x20y, p\\q\u001b): boom`
	if got := err.Error(); got != want {
		t.Errorf("error = %q\nwant    %q", got, want)
	}
	one := &CreateError{Dir: "d e", Made: true, Written: []string{"w w"}, Err: errors.New("boom")}
	if want := `bundle: cannot make the bundle d\x20e: the folder was made and 1 thing was written in it (w\x20w): boom`; one.Error() != want {
		t.Errorf("error = %q, want %q", one.Error(), want)
	}
	none := &CreateError{Dir: "d e", Made: true, Err: errors.New("boom")}
	if want := `bundle: cannot make the bundle d\x20e: the folder was made and 0 things were written in it: boom`; none.Error() != want {
		t.Errorf("error = %q, want %q", none.Error(), want)
	}
}

// Hostile DIRs: no panic, an error, and nothing made.
func TestCreateRefusesHostileDirsAndMakesNothing(t *testing.T) {
	root, _, deep := modeTree(t)
	file := filepath.Join(root, "afile")
	mustDo(t, os.WriteFile(file, nil, 0o644))
	mustDo(t, os.Symlink(file, filepath.Join(root, "linkfile")))
	for name, dir := range map[string]string{
		"the empty path":                  "",
		"a NUL in the parent":             filepath.Join(deep, "a\x00b", "dir"),
		"a NUL in the name":               filepath.Join(deep, "di\x00r"),
		"a dot dot element":               deep + "/../deep/dir",
		"a parent that is a file":         filepath.Join(file, "dir"),
		"a parent that does not exist":    filepath.Join(root, "missing", "dir"),
		"a path too long":                 deep + strings.Repeat("/aaaaaaaaaa", 600) + "/dir",
		"a name that is a dot":            deep + "/.",
		"a name that starts with .rt-":    filepath.Join(deep, ".rt-abc"),
		"a name of 300 bytes":             filepath.Join(deep, strings.Repeat("a", 300)),
		"only a slash":                    "/",
		"a name that holds a line break":  filepath.Join(deep, "a\nb"),
		"a name that is not valid UTF-8":  filepath.Join(deep, "\xff\xfe"),
		"a parent that is a link to file": filepath.Join(root, "linkfile", "dir"),
	} {
		t.Run(name, func(t *testing.T) {
			files, err := Create(dir, StarterOptions{})
			if name == "a name that holds a line break" || name == "a name that is not valid UTF-8" {
				// These names may or may not be names of a bundle; whatever the answer, nothing partial is left.
				if err != nil && len(entriesOf(t, deep)) != 0 {
					t.Errorf("an error and the parent holds %v", entriesOf(t, deep))
				}
				return
			}
			var ce *CreateError
			if err == nil || files != nil || !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 {
				t.Fatalf("(%v, %v), want a CreateError for a folder that was not made", files, err)
			}
			if got := entriesOf(t, deep); len(got) != 0 {
				t.Errorf("the parent holds %v", got)
			}
		})
	}
}

// The name of the parent that cannot be resolved is written by the exact escape too: a space, a backslash and a byte
// that is not UTF-8 in its name read back as that one name.
func TestTheFolderThatCannotBeExaminedIsNamedOneToOne(t *testing.T) {
	skipAsRoot(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	mustDo(t, err)
	d1 := filepath.Join(root, "d 1")
	deep := filepath.Join(d1, "in\\ner\xff")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Skipf("this file system does not take the name: %v", err)
	}
	mustDo(t, os.Chmod(d1, 0o600))
	restoreMode(t, d1)
	_, err = bundleAbove(deep)
	want := `the parent folder ` + root + `/d\x201/in\\ner\xff cannot be resolved: permission denied`
	if err == nil || err.Error() != want {
		t.Errorf("error = %v, want %q", err, want)
	}
}
