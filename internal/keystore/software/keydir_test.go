package software

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// folders makes the folders of a test of the key directory under one temporary folder that is
// not in a work tree: root/bundle (with history/deep/), root/keys, root/outside and a file.
type folders struct {
	root, bundle, keys, outside, file string
}

func newFolders(t *testing.T) folders {
	t.Helper()
	bundle, keys := newBundle(t)
	root := filepath.Dir(bundle)
	f := folders{root: root, bundle: bundle, keys: keys, outside: filepath.Join(root, "outside"), file: filepath.Join(root, "a-file")}
	for _, d := range []string{filepath.Join(bundle, "history", "deep"), f.outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func link(t *testing.T, target, name string) string {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestCheckKeyDirRefusesTheBundleAndAnythingInsideItInEverySpelling(t *testing.T) {
	f := newFolders(t)
	inLink := link(t, filepath.Join(f.bundle, "history"), filepath.Join(f.root, "link-into-the-bundle"))
	inLinkOfLink := link(t, inLink, filepath.Join(f.root, "link-of-link"))
	toBundle := link(t, f.bundle, filepath.Join(f.outside, "the-bundle"))
	chain := link(t, filepath.Join(f.outside, "the-bundle", "history"), filepath.Join(f.outside, "chain"))
	dotted := f.root + "/keys/../bundle"
	dotted2 := f.bundle + "/history/./deep/../.."
	t.Chdir(f.root)
	cases := []struct{ name, dir string }{
		{"the bundle folder", f.bundle},
		{"the bundle with a trailing slash", f.bundle + "/"},
		{"the bundle with two trailing slashes", f.bundle + "//"},
		{"the bundle spelled with a dotted path", dotted},
		{"the bundle spelled from inside itself", dotted2},
		{"the bundle as a relative path", "bundle"},
		{"the bundle as ./bundle/.", "./bundle/."},
		{"a folder inside the bundle", filepath.Join(f.bundle, "history")},
		{"two levels inside the bundle", filepath.Join(f.bundle, "history", "deep")},
		{"a relative path inside the bundle", "bundle/history/deep"},
		{"a link outside that points into the bundle", inLink},
		{"a link to a link into the bundle", inLinkOfLink},
		{"a link to the bundle itself", toBundle},
		{"a path through a link to the bundle", filepath.Join(toBundle, "history", "deep")},
		{"a link that points through a link into the bundle", chain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckKeyDir(c.dir, f.bundle)
			if !errors.Is(err, ErrKeyDir) || errors.Is(err, ErrKeyExists) || Code(err) != "key-dir" {
				t.Fatalf("not refused as ErrKeyDir: %v", err)
			}
			if strings.Contains(err.Error(), f.root) {
				t.Errorf("the error holds a path: %v", err)
			}
			// The same through Open: no Store.
			if s, err := Open(Config{KeyDir: c.dir, BundleDir: f.bundle, Mode: ModeTest}); err == nil {
				_ = s.Close()
				t.Error("Open accepted it")
			}
		})
	}
	// The bundle may be given in any of those spellings too.
	for _, spelling := range []string{f.bundle + "/", dotted, "bundle", toBundle} {
		if err := CheckKeyDir(filepath.Join(f.bundle, "history"), spelling); !errors.Is(err, ErrKeyDir) {
			t.Errorf("the bundle spelled %q: %v", spelling, err)
		}
		if err := CheckKeyDir(f.keys, spelling); err != nil {
			t.Errorf("the key folder with the bundle spelled %q: %v", spelling, err)
		}
	}
}

func TestCheckKeyDirAcceptsASiblingAParentAndALinkOutOfTheBundle(t *testing.T) {
	f := newFolders(t)
	outLink := link(t, f.outside, filepath.Join(f.bundle, "link-out"))
	keysLink := link(t, f.keys, filepath.Join(f.root, "keys-link"))
	t.Chdir(f.root)
	cases := []struct{ name, dir string }{
		{"a sibling of the bundle", f.keys},
		{"another sibling", f.outside},
		{"a sibling with a trailing slash", f.keys + "/"},
		{"a sibling spelled with a dotted path", f.root + "/bundle/../keys"},
		{"a sibling as a relative path", "keys"},
		{"a link inside the bundle that points to a folder outside", outLink},
		{"a link beside the bundle to the key folder", keysLink},
		{"the parent of the bundle", f.root},
		{"the parent as a relative path", "."},
		{"the parent spelled with a dotted path", f.bundle + "/.."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := CheckKeyDir(c.dir, f.bundle); err != nil {
				t.Fatalf("refused: %v", err)
			}
			s, err := Open(Config{KeyDir: c.dir, BundleDir: f.bundle, Mode: ModeTest})
			if err != nil {
				t.Fatalf("Open refused: %v", err)
			}
			_ = s.Close()
		})
	}
}

func TestCheckKeyDirRefusesAFolderThatIsMissingNotAFolderOrEmptyAndABundleThatIsMissingOrEmpty(t *testing.T) {
	f := newFolders(t)
	dangling := link(t, filepath.Join(f.root, "nowhere"), filepath.Join(f.root, "dangling"))
	toFile := link(t, f.file, filepath.Join(f.root, "to-a-file"))
	loopA := filepath.Join(f.root, "loop-a")
	link(t, filepath.Join(f.root, "loop-b"), loopA)
	link(t, loopA, filepath.Join(f.root, "loop-b"))
	cases := []struct {
		name        string
		dir, bundle string
		is          error
	}{
		{"a key folder that does not exist", filepath.Join(f.root, "nowhere"), f.bundle, ErrKeyDir},
		{"a key folder below one that does not exist", filepath.Join(f.root, "nowhere", "deeper"), f.bundle, ErrKeyDir},
		{"a key folder that is a file", f.file, f.bundle, ErrKeyDir},
		{"a key folder that is a link to a file", toFile, f.bundle, ErrKeyDir},
		{"a key folder that is a dangling link", dangling, f.bundle, ErrKeyDir},
		{"a key folder that is a loop of links", loopA, f.bundle, ErrKeyDir},
		{"a key folder below a file", filepath.Join(f.file, "x"), f.bundle, ErrKeyDir},
		{"an empty key folder text", "", f.bundle, ErrKeyDir},
		{"a key folder of one space", " ", f.bundle, ErrKeyDir},
		{"a key folder with a NUL", f.keys + "\x00", f.bundle, ErrKeyDir},
		{"a key folder with a very long name", filepath.Join(f.root, strings.Repeat("a", 5000)), f.bundle, ErrKeyDir},
		{"an empty bundle folder", f.keys, "", ErrParams},
		{"a bundle folder that does not exist", f.keys, filepath.Join(f.root, "nowhere"), ErrKeyDir},
		{"a bundle folder that is a file", f.keys, f.file, ErrKeyDir},
		{"a bundle folder that is a dangling link", f.keys, dangling, ErrKeyDir},
		{"both empty", "", "", ErrParams},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckKeyDir(c.dir, c.bundle)
			if !errors.Is(err, c.is) || errors.Is(err, ErrKeyExists) {
				t.Fatalf("the error is %v, want %v", err, c.is)
			}
			if errors.Is(c.is, ErrKeyDir) && Code(err) != "key-dir" {
				t.Errorf("code %q", Code(err))
			}
			if strings.Contains(err.Error(), f.root) {
				t.Errorf("the error holds a path: %v", err)
			}
		})
	}
}

func TestCheckKeyDirRefusesAFolderInsideTheWorkTreeOfTheRepositoryThatHoldsTheBundle(t *testing.T) {
	for _, kind := range []string{"a .git folder", "a .git file as a worktree has"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			repo := filepath.Join(root, "repo")
			bundle := filepath.Join(repo, "deep", "bundle")
			for _, d := range []string{bundle, filepath.Join(repo, "keys"), filepath.Join(repo, "deep", "keys"), filepath.Join(root, "beside"), filepath.Join(bundle, "history")} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if insideWorkTree(root) {
				t.Skip("the temporary folder is inside a work tree")
			}
			git := filepath.Join(repo, ".git")
			if kind == "a .git folder" {
				if err := os.Mkdir(git, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(git, []byte("gitdir: ../elsewhere\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			refused := map[string]string{
				"a sibling of the repository's folder": filepath.Join(repo, "keys"),
				"a folder beside the bundle":           filepath.Join(repo, "deep", "keys"),
				"the root of the work tree itself":     repo,
				"the work tree with a dotted path":     repo + "/deep/..",
			}
			for name, dir := range refused {
				if err := CheckKeyDir(dir, bundle); !errors.Is(err, ErrKeyDir) {
					t.Errorf("%s: %v", name, err)
				}
			}
			accepted := map[string]string{
				"a folder outside the work tree":  filepath.Join(root, "beside"),
				"the parent of the work tree":     root,
				"the same folder, other spelling": filepath.Join(root, "beside") + "/",
			}
			for name, dir := range accepted {
				if err := CheckKeyDir(dir, bundle); err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
			// The same folders with no repository above the bundle are accepted.
			if err := os.RemoveAll(git); err != nil {
				t.Fatal(err)
			}
			for name, dir := range refused {
				if err := CheckKeyDir(dir, bundle); err != nil {
					t.Errorf("%s, with no repository: %v", name, err)
				}
			}
		})
	}
}

// Case 19. A file system that ignores case, a bind of the same folder and a link are the same file
// under two names. The check asks the file system (os.SameFile) and never compares strings: here a
// stub stat gives the one folder for two spellings that no string comparison would join.
func TestCheckKeyDirTellsTheSameFolderByOSSameFileAndNotByTheText(t *testing.T) {
	f := newFolders(t)
	bundleInfo, err := os.Stat(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	// The key folder is another folder on the disk, but the stub says it is the bundle (as a bind
	// mount or a case-insensitive spelling would): it must be refused.
	same := func(path string) (fs.FileInfo, error) {
		if path == f.keys {
			return bundleInfo, nil
		}
		return os.Stat(path)
	}
	if _, err := checkKeyDir(same, f.keys, f.bundle); !errors.Is(err, ErrKeyDir) {
		t.Errorf("two spellings of one file are not told: %v", err)
	}
	// The same stub with an honest answer accepts the folder: the refusal came from SameFile.
	if _, err := checkKeyDir(os.Stat, f.keys, f.bundle); err != nil {
		t.Errorf("the control is refused: %v", err)
	}
	// The folder above the key folder is the bundle for the stub: a walk up finds it.
	up := func(path string) (fs.FileInfo, error) {
		if path == f.root {
			return bundleInfo, nil
		}
		return os.Stat(path)
	}
	deep := filepath.Join(f.keys, "x")
	if err := os.Mkdir(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := checkKeyDir(up, deep, f.bundle); !errors.Is(err, ErrKeyDir) {
		t.Errorf("a folder above the key folder that is the bundle is not found: %v", err)
	}
	// A stat that fails is a refusal and not an acceptance.
	failing := func(path string) (fs.FileInfo, error) {
		if path == f.root {
			return nil, errors.New("an injected fault")
		}
		return os.Stat(path)
	}
	if _, err := checkKeyDir(failing, f.keys, f.bundle); !errors.Is(err, ErrKeyDir) {
		t.Errorf("a stat that fails is accepted: %v", err)
	}
	// Two names that differ only in case are two folders on a case-sensitive disk and one on a
	// case-insensitive one: whichever this disk is, the answer is the disk's.
	upper := strings.ToUpper(f.bundle[:len(f.bundle)-6]) + "bundle"
	if _, err := os.Stat(upper); err == nil {
		if err := CheckKeyDir(filepath.Join(f.bundle, "history"), upper); !errors.Is(err, ErrKeyDir) {
			t.Errorf("the bundle spelled in another case on a disk that ignores case: %v", err)
		}
	}
}

func TestCheckKeyDirReadsNoFileAndMakesNoFolder(t *testing.T) {
	f := newFolders(t)
	before := snapshot(t, f.root)
	_ = CheckKeyDir(f.keys, f.bundle)
	_ = CheckKeyDir(filepath.Join(f.root, "nowhere"), f.bundle)
	_ = CheckKeyDir(f.bundle, f.bundle)
	if after := snapshot(t, f.root); after != before {
		t.Errorf("the folders changed:\n%s\nafter:\n%s", before, after)
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		b.WriteString(strings.TrimPrefix(path, dir) + " " + info.Mode().String() + "\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Lesson 3: after the check the folder is opened with fsx, which refuses a link as the last
// element; a link put in the place of the resolved path after the check is not followed.
func TestAfterTheCheckTheFolderIsOpenedWithFsxWhichRefusesALinkAsTheLastElement(t *testing.T) {
	f := newFolders(t)
	swap := filepath.Join(f.root, "swapped")
	link(t, f.outside, swap)
	if _, err := fsx.Open(swap); !errors.Is(err, fsx.ErrLink) {
		t.Errorf("fsx.Open follows a link at the last element: %v", err)
	}
	// Open resolves the key folder first, so a link given as KeyDir is followed once, by the
	// check, and the Store works on the real folder.
	s, err := Open(Config{KeyDir: swap, BundleDir: f.bundle, Mode: ModeTest})
	if err != nil {
		t.Fatalf("a link to a folder outside the bundle is refused: %v", err)
	}
	defer func() { _ = s.Close() }()
	if err := s.SaveX509("A", mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.outside, "A.x509.key.pem")); err != nil {
		t.Errorf("the key file is not in the real folder: %v", err)
	}
}

// The folder's own mode is not checked or changed (it means nothing on exFAT).
func TestOpenDoesNotChangeTheModeOfTheKeyFolder(t *testing.T) {
	f := newFolders(t)
	for _, mode := range []fs.FileMode{0o700, 0o755, 0o777} {
		if err := os.Chmod(f.keys, mode); err != nil {
			t.Fatal(err)
		}
		s, err := Open(Config{KeyDir: f.keys, BundleDir: f.bundle, Mode: ModeTest})
		if err != nil {
			t.Fatalf("a folder of mode %v is refused: %v", mode, err)
		}
		_ = s.Close()
		info, err := os.Stat(f.keys)
		if err != nil || info.Mode().Perm() != mode {
			t.Errorf("the mode went from %v to %v (%v)", mode, info.Mode().Perm(), err)
		}
	}
}
