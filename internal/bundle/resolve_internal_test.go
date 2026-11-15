//go:build linux || darwin

package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bundleAbove follows the links of the parent folder before it looks at the folders above it. A parent whose links
// cannot be followed (a link that leads to itself, a link to nothing, a name that is not there, a folder that cannot be
// passed) is an error: the folders above it are not known, so the walk is not made, and the answer is never "none" and
// never a folder that the text of the path happens to name. The sentence says that the parent folder cannot be
// resolved and names it, made absolute, by the exact escape.

// exactEscape writes a name the way the exact escape does for the names of these tests: a space, a backslash, a line
// feed and a byte that is not UTF-8. The tests do not call the function that they hold.
var exactEscape = strings.NewReplacer(` `, `\x20`, `\`, `\\`, "\n", `\u000a`, "\xff", `\xff`)

// resolveTree makes a folder with a good link, a link to itself, links to nothing, a plain file and a folder that
// holds the name, and returns the real path of it.
func resolveTree(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	mustDo(t, err)
	mustDo(t, os.MkdirAll(filepath.Join(root, "holder", "sub"), 0o755))
	mustDo(t, os.WriteFile(filepath.Join(root, "holder", "ritueel.yaml"), nil, 0o644))
	mustDo(t, os.MkdirAll(filepath.Join(root, "plain", "sub"), 0o755))
	mustDo(t, os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644))
	mustDo(t, os.Symlink(filepath.Join(root, "loop"), filepath.Join(root, "loop")))
	mustDo(t, os.Symlink("loop2", filepath.Join(root, "loop1")))
	mustDo(t, os.Symlink("loop1", filepath.Join(root, "loop2")))
	mustDo(t, os.Symlink(filepath.Join(root, "nowhere"), filepath.Join(root, "dangling")))
	mustDo(t, os.Symlink("../nowhere/deeper", filepath.Join(root, "holder", "sub", "dangling")))
	mustDo(t, os.Symlink(filepath.Join(root, "plain", "sub"), filepath.Join(root, "good")))
	mustDo(t, os.Symlink("good", filepath.Join(root, "good2")))
	mustDo(t, os.Symlink("../holder/sub", filepath.Join(root, "plain", "rel")))
	return root
}

func TestBundleAboveOfAParentThatCannotBeResolvedIsAnErrorThatNamesItAndNeverNone(t *testing.T) {
	root := resolveTree(t)
	for name, tc := range map[string]struct {
		parent string
		cause  string // "" when the cause is the text of the library, which a test does not copy
	}{
		"a link that leads to itself":                                 {filepath.Join(root, "loop"), ""},
		"two links that lead to each other":                           {filepath.Join(root, "loop1"), ""},
		"a link to itself in the middle":                              {filepath.Join(root, "loop", "sub", "deep"), ""},
		"a link to nothing":                                           {filepath.Join(root, "dangling"), "no such file or directory"},
		"a link to nothing in the middle":                             {filepath.Join(root, "dangling", "sub"), "no such file or directory"},
		"a link to nothing in the middle, far from the end":           {filepath.Join(root, "dangling", "a", "b", "c", "d"), "no such file or directory"},
		"a name that is not there":                                    {filepath.Join(root, "missing", "sub"), "no such file or directory"},
		"a plain file in the middle":                                  {filepath.Join(root, "file", "sub"), "not a directory"},
		"a link to nothing under a folder that holds the name":        {filepath.Join(root, "holder", "sub", "dangling", "x"), "no such file or directory"},
		"a name that is not there under a folder that holds the name": {filepath.Join(root, "holder", "sub", "missing"), "no such file or directory"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := bundleAbove(tc.parent)
			if err == nil || got != "" {
				t.Fatalf("bundleAbove(%q) = (%q, %v), want an error and no folder", tc.parent, got, err)
			}
			prefix := "the parent folder " + tc.parent + " cannot be resolved: "
			if !strings.HasPrefix(err.Error(), prefix) || len(err.Error()) == len(prefix) {
				t.Errorf("error = %q, want it to start with %q and give a cause", err.Error(), prefix)
			}
			if tc.cause != "" && err.Error() != prefix+tc.cause {
				t.Errorf("error = %q, want %q", err.Error(), prefix+tc.cause)
			}
			// The folders of the text of the path are not looked at: no folder is named as one that holds the name.
			if strings.Contains(err.Error(), "holds") || strings.Contains(err.Error(), "examined") {
				t.Errorf("the error speaks of a walk that was not made: %q", err.Error())
			}
			if strings.ContainsAny(err.Error(), "\n\r\t") {
				t.Errorf("the error is not one line: %q", err.Error())
			}
		})
	}
}

// The parent is named as it was made absolute: a relative path is read from the working folder, and the name is the
// absolute one. A path with an element that is not a clean name is cleaned before it is named.
func TestBundleAboveNamesAParentThatCannotBeResolvedByItsAbsolutePath(t *testing.T) {
	root := resolveTree(t)
	t.Chdir(root)
	for given, want := range map[string]string{
		"dangling":              root + "/dangling",
		"./dangling/sub":        root + "/dangling/sub",
		"dangling//sub/":        root + "/dangling/sub",
		"holder/./missing":      root + "/holder/missing",
		"holder/sub/../missing": root + "/holder/missing",
	} {
		got, err := bundleAbove(given)
		if err == nil || got != "" {
			t.Fatalf("bundleAbove(%q) = (%q, %v), want an error and no folder", given, got, err)
		}
		if !strings.HasPrefix(err.Error(), "the parent folder "+want+" cannot be resolved: ") {
			t.Errorf("bundleAbove(%q): error = %q, want the parent %q", given, err.Error(), want)
		}
	}
}

// A name that comes from a file system is written by the exact escape: a space, a backslash, a line feed and a byte
// that is not UTF-8 read back as that one name.
func TestBundleAboveNamesAParentThatCannotBeResolvedByTheExactEscape(t *testing.T) {
	root := resolveTree(t)
	for name, element := range map[string]string{
		"a space":                 "a b",
		"a backslash":             `a\b`,
		"a line feed":             "a\nb",
		"a byte that is no UTF-8": "a\xffb",
		"all of them":             "a b\\c\n\xff",
	} {
		t.Run(name, func(t *testing.T) {
			link := filepath.Join(root, element)
			if err := os.Symlink(filepath.Join(root, "nowhere"), link); err != nil {
				t.Skipf("this file system does not take the name: %v", err)
			}
			for _, parent := range []string{link, filepath.Join(link, "inner")} {
				got, err := bundleAbove(parent)
				if err == nil || got != "" {
					t.Fatalf("bundleAbove(%q) = (%q, %v), want an error and no folder", parent, got, err)
				}
				want := "the parent folder " + root + "/" + exactEscape.Replace(strings.TrimPrefix(parent, root+"/")) + " cannot be resolved: no such file or directory"
				if err.Error() != want {
					t.Errorf("error = %q, want %q", err.Error(), want)
				}
				for _, b := range []byte(err.Error()) {
					if b < 0x20 || b > 0x7e {
						t.Errorf("the error holds the raw byte %#x: %q", b, err.Error())
						break
					}
				}
			}
		})
	}
}

// A parent that is reached through good links is as it was: the folders above it are those of the disk, a holder is
// named by its real path, and no holder is "none" with no error.
func TestBundleAboveOfAParentReachedThroughGoodLinksIsUnchanged(t *testing.T) {
	root := resolveTree(t)
	for name, tc := range map[string]struct {
		parent string
		want   string
	}{
		"a link to a folder with no holder above":    {filepath.Join(root, "good"), ""},
		"a link to a link":                           {filepath.Join(root, "good2"), ""},
		"a folder under the link":                    {filepath.Join(root, "good", "."), ""},
		"a relative link to a folder under a holder": {filepath.Join(root, "plain", "rel"), filepath.Join(root, "holder")},
		"the folder under a holder, by its own name": {filepath.Join(root, "holder", "sub"), filepath.Join(root, "holder")},
		"the holder itself":                          {filepath.Join(root, "holder"), filepath.Join(root, "holder")},
		"the root of the temporary folder":           {root, ""},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := bundleAbove(tc.parent)
			if err != nil || got != tc.want {
				t.Errorf("bundleAbove(%q) = (%q, %v), want (%q, nil)", tc.parent, got, err, tc.want)
			}
		})
	}
	// The same through a relative path.
	t.Chdir(filepath.Join(root, "plain"))
	if got, err := bundleAbove("rel"); err != nil || got != filepath.Join(root, "holder") {
		t.Errorf("bundleAbove(rel) = (%q, %v), want the holder", got, err)
	}
	if got, err := bundleAbove("sub"); err != nil || got != "" {
		t.Errorf("bundleAbove(sub) = (%q, %v), want nothing", got, err)
	}
}

// The error of the library is the cause, with no path of the library in it: the text names the parent once.
func TestBundleAboveNamesTheParentOnceAndGivesTheCauseOfTheSystem(t *testing.T) {
	root := resolveTree(t)
	parent := filepath.Join(root, "dangling", "sub")
	_, err := bundleAbove(parent)
	if err == nil {
		t.Fatal("no error")
	}
	if n := strings.Count(err.Error(), root); n != 1 {
		t.Errorf("the text names the folder %d times: %q", n, err.Error())
	}
	if strings.Contains(err.Error(), "lstat") || strings.Contains(err.Error(), "nowhere") {
		t.Errorf("the text holds a path or a call of the library: %q", err.Error())
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the cause is not kept: %v", err)
	}
}

// Create ends with an error, makes nothing, and says that the folder was not made, for each parent that cannot be
// resolved: no folder is made under it, behind a link or in a folder that it names.
func TestCreateOfAParentThatCannotBeResolvedMakesNothing(t *testing.T) {
	root := resolveTree(t)
	for name, parent := range map[string]string{
		"a link that leads to itself":     filepath.Join(root, "loop"),
		"a link to nothing":               filepath.Join(root, "dangling"),
		"a link to nothing in the middle": filepath.Join(root, "dangling", "sub"),
		"a name that is not there":        filepath.Join(root, "missing", "sub"),
		"a plain file in the middle":      filepath.Join(root, "file", "sub"),
		"a link to nothing in a holder":   filepath.Join(root, "holder", "sub", "dangling"),
	} {
		t.Run(name, func(t *testing.T) {
			before := tree(t, root)
			files, err := Create(filepath.Join(parent, "dir"), StarterOptions{})
			var ce *CreateError
			if err == nil || files != nil || !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 {
				t.Fatalf("(%v, %v), want a CreateError for a folder that was not made", files, err)
			}
			if !strings.Contains(err.Error(), "the folder was not made") {
				t.Errorf("the error does not say that the folder was not made: %q", err.Error())
			}
			if after := tree(t, root); strings.Join(before, "\n") != strings.Join(after, "\n") {
				t.Errorf("the tree changed:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

// tree lists every path under root, with links as links, so that a test sees what a call made.
func tree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		kind := "f"
		switch {
		case d.Type()&os.ModeSymlink != 0:
			kind = "l"
		case d.IsDir():
			kind = "d"
		}
		out = append(out, kind+" "+p)
		return nil
	})
	mustDo(t, err)
	return out
}

// The parent of the bundle is any text under a folder of the test: Create never panics, and a parent whose links cannot
// be followed is an error that changes nothing. The paths are kept inside the folder of the test: an element ".." and a
// leading slash are taken out, so that no write can leave it, and the only links are those made here.
func FuzzCreateParent(f *testing.F) {
	root, err := filepath.EvalSymlinks(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	for _, d := range []string{"real/inner", "holder/sub"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			f.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "holder", "ritueel.yaml"), nil, 0o644); err != nil {
		f.Fatal(err)
	}
	for name, target := range map[string]string{"loop": filepath.Join(root, "loop"), "dangling": filepath.Join(root, "nowhere"), "good": filepath.Join(root, "real"), "up": filepath.Join(root, "holder")} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			f.Fatal(err)
		}
	}
	for _, s := range []string{"real/inner", "good/inner", "loop", "loop/x", "dangling", "dangling/x/y", "missing/x", "holder/sub", "up/sub", "good", "", ".", "a b", "a\x00b", "\xff", "real/inner/x/y/z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rel string) {
		rel = strings.ReplaceAll(rel, "..", "_")
		rel = strings.TrimLeft(rel, "/")
		parent := root + "/" + rel
		before := snapshot(t, root)
		files, err := Create(parent+"/dir", StarterOptions{})
		abs, absErr := filepath.Abs(parent)
		resolved := false
		if absErr == nil {
			_, resErr := filepath.EvalSymlinks(abs)
			resolved = resErr == nil
		}
		if err != nil {
			var ce *CreateError
			if !errors.As(err, &ce) {
				t.Fatalf("Create(%q) = %v, want a CreateError", parent, err)
			}
			if files != nil {
				t.Fatalf("Create(%q) gave files beside an error", parent)
			}
			for _, b := range []byte(err.Error()) {
				if b < 0x20 || b > 0x7e {
					t.Fatalf("Create(%q): the error holds the raw byte %#x: %q", parent, b, err.Error())
				}
			}
			if !ce.Made && snapshot(t, root) != before {
				t.Fatalf("Create(%q) failed with a folder that was not made, and the tree changed", parent)
			}
			return
		}
		if !resolved {
			t.Fatalf("Create(%q) made a bundle under a parent that cannot be resolved", parent)
		}
		// The folder was made: clear it, so that the next run starts from the same tree.
		mustDo(t, os.RemoveAll(parent+"/dir"))
	})
}

// snapshot is the tree under root as one text.
func snapshot(t *testing.T, root string) string {
	t.Helper()
	return strings.Join(tree(t, root), "\n")
}
