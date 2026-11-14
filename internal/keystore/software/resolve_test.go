package software

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A path is resolved as the operating system resolves it: element by element, in order, so that a
// ".." after a link is taken from the folder the link leads to. Cleaning the text first ("L/../b"
// becomes "b" whatever L is) would check another folder than the one that Open uses. The oracle
// of these tests is the kernel itself: the folder that open(2) reaches, named by /proc.

// spellTree is a set of folders and links under one temporary folder that is not in a work tree.
//
//	real/deep/dir/              the target of L
//	real/deep/b/                a bundle (ritueel.yaml, history, keys)
//	real/b2/                    another bundle, one level up
//	b/, b2/                     decoys: where the cleaned text "L/../b" would go
//	L -> <abs>/real/deep/dir    Lrel -> real/deep/dir (relative)    Lchain -> L (a link to a link)
//	F (a file), loop -> loop, dangling -> nowhere
type spellTree struct{ root string }

func newSpellTree(t testing.TB) spellTree {
	t.Helper()
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	for _, d := range []string{
		"real/deep/dir", "real/deep/b/history", "real/deep/b/keys", "real/deep/keys-ok", "real/b2/keys",
		"b/keys", "b2/keys", "other",
	} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"real/deep/b/ritueel.yaml", "real/b2/ritueel.yaml", "b/ritueel.yaml", "b2/ritueel.yaml", "F"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("name: Example Test\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"L": filepath.Join(root, "real/deep/dir"), "Lrel": "real/deep/dir", "Lchain": "L", "loop": "loop", "dangling": "nowhere",
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return spellTree{root}
}

// kernelFolder opens a path as the kernel does and says which folder it is: its real absolute
// path and its stat. It is false when the kernel cannot open the path as a folder.
func kernelFolder(path string) (string, fs.FileInfo, bool) {
	if runtime.GOOS != "linux" {
		return "", nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", nil, false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.IsDir() {
		return "", nil, false
	}
	real, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil {
		return "", nil, false
	}
	return real, info, true
}

// kernelInside says whether the folder at key is the folder at bundle or inside it, by what the
// kernel resolves and os.SameFile, never by text. ok is false when the kernel cannot open either.
func kernelInside(key, bundle string) (inside, ok bool) {
	realKey, _, ok1 := kernelFolder(key)
	_, bundleInfo, ok2 := kernelFolder(bundle)
	if !ok1 || !ok2 {
		return false, false
	}
	for cur := realKey; ; cur = filepath.Dir(cur) {
		if info, err := os.Stat(cur); err == nil && os.SameFile(info, bundleInfo) {
			return true, true
		}
		if filepath.Dir(cur) == cur {
			return false, true
		}
	}
}

func (s spellTree) at(abs bool, spelling string) string {
	if abs {
		return s.root + "/" + spelling
	}
	return spelling
}

func TestAPathIsFollowedInOrderSoThatDotDotAfterALinkIsTakenFromTheLinksTarget(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the oracle reads /proc")
	}
	s := newSpellTree(t)
	cases := []struct {
		name, key, bundle string
		refused           bool
	}{
		{"a key folder in the real bundle, the bundle spelled through a link and ..", "real/deep/b/keys", "L/../b", true},
		{"a key folder in the decoy of that spelling", "b/keys", "L/../b", false},
		{"the key folder spelled through a link and .. is the bundle", "L/../b", "real/deep/b", true},
		{"the key folder spelled so, inside the bundle", "L/../b/keys", "real/deep/b", true},
		{"the same spelling, the decoy as the bundle", "L/../b/keys", "b", false},
		{"both spelled through the link", "L/../b/keys", "L/../b", true},
		{"both spelled through the link, the same folder", "L/../b", "L/../b", true},
		{"a relative link in the bundle spelling", "real/deep/b/keys", "Lrel/../b", true},
		{"a link to a link in the bundle spelling", "real/deep/b/keys", "Lchain/../b", true},
		{"a link to a link in the key spelling", "Lchain/../b/history", "real/deep/b", true},
		{"two levels up after the link", "real/b2/keys", "L/../../b2", true},
		{"two levels up, the decoy folder", "b2/keys", "L/../../b2", false},
		{"the parent of the bundle, through the link", "L/..", "real/deep/b", false},
		{"a sibling of the bundle, through the link", "L/../keys-ok", "real/deep/b", false},
		{"a spelling that cleaned would not exist", "other", "L/../../../nowhere", true},
	}
	for _, abs := range []bool{true, false} {
		for _, c := range cases {
			name := c.name + map[bool]string{true: " (absolute)", false: " (relative)"}[abs]
			t.Run(name, func(t *testing.T) {
				if !abs {
					t.Chdir(s.root)
				}
				key, bundle := s.at(abs, c.key), s.at(abs, c.bundle)
				// The table is checked against the kernel first, so that a wrong row cannot hide a fault.
				if in, ok := kernelInside(key, bundle); ok && in != c.refused {
					t.Fatalf("the table says refused=%v, the kernel says inside=%v", c.refused, in)
				}
				err := CheckKeyDir(key, bundle)
				st, openErr := Open(Config{KeyDir: key, BundleDir: bundle, Mode: ModeTest})
				if st != nil {
					_ = st.Close()
				}
				if c.refused {
					for who, e := range map[string]error{"CheckKeyDir": err, "Open": openErr} {
						if !errors.Is(e, ErrKeyDir) || Code(e) != "key-dir" || errors.Is(e, ErrKeyExists) {
							t.Errorf("%s: not refused as a key directory: %v", who, e)
						}
						if e != nil && strings.Contains(e.Error(), s.root) {
							t.Errorf("%s: the error holds a path: %v", who, e)
						}
					}
					return
				}
				if err != nil || openErr != nil {
					t.Errorf("refused: %v / %v", err, openErr)
				}
			})
		}
	}
}

// A path that the system cannot resolve is refused, whatever follows a link in it.
func TestAPathThroughAFileALoopOrADanglingLinkIsRefusedAsAKeyDirectoryInBothPlaces(t *testing.T) {
	s := newSpellTree(t)
	for _, bad := range []string{"F/../b", "F", "loop", "loop/../b", "dangling", "dangling/../b", "L/../nowhere", "L/../F/.."} {
		for _, abs := range []bool{true, false} {
			if !abs {
				t.Chdir(s.root)
			}
			p := s.at(abs, bad)
			if err := CheckKeyDir(p, s.at(abs, "real/deep/b")); !errors.Is(err, ErrKeyDir) {
				t.Errorf("key folder %q: %v", p, err)
			}
			if err := CheckKeyDir(s.at(abs, "other"), p); !errors.Is(err, ErrKeyDir) {
				t.Errorf("bundle %q: %v", p, err)
			}
			if st, err := Open(Config{KeyDir: p, BundleDir: s.at(abs, "real/deep/b"), Mode: ModeTest}); err == nil {
				_ = st.Close()
				t.Errorf("Open accepted the key folder %q", p)
			}
		}
	}
}

// When the working folder is itself reached through a link, a relative path is still taken from
// the folder that the system sees, and ".." goes up from the link's target.
func TestARelativePathFromAWorkingFolderThatIsALinkIsTakenFromTheRealFolder(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the oracle reads /proc")
	}
	s := newSpellTree(t)
	t.Chdir(filepath.Join(s.root, "L")) // real/deep/dir
	cases := []struct {
		key, bundle string
		refused     bool
	}{
		{"../b/keys", "../b", true},
		{"../b", "../b", true},
		{"../b/history", "../b", true},
		{"../../../b/keys", "../b", false}, // R/b/keys, the decoy
		{"../keys-ok", "../b", false},
		{"..", "../b", false},
		{"../../b2/keys", "../b", false},
	}
	for _, c := range cases {
		if in, ok := kernelInside(c.key, c.bundle); ok && in != c.refused {
			t.Fatalf("%q in %q: the table says refused=%v, the kernel says %v", c.key, c.bundle, c.refused, in)
		}
		err := CheckKeyDir(c.key, c.bundle)
		if c.refused != errors.Is(err, ErrKeyDir) || (!c.refused && err != nil) {
			t.Errorf("key %q, bundle %q: refused=%v, got %v", c.key, c.bundle, c.refused, err)
		}
	}
}

// Every repository above the bundle counts, not only the nearest: a bundle in a clone that sits in
// another work tree must not hide the outer one.
func TestEveryRepositoryAboveTheBundleCountsAndNotOnlyTheNearest(t *testing.T) {
	for _, kinds := range []struct{ outer, inner string }{{"dir", "file"}, {"file", "dir"}, {"dir", "dir"}, {"file", "file"}, {"dangling link", "dir"}} {
		t.Run("outer "+kinds.outer+", inner "+kinds.inner, func(t *testing.T) {
			root := t.TempDir()
			if insideWorkTree(root) {
				t.Skip("the temporary folder is inside a work tree")
			}
			for _, d := range []string{"outer/mid/inner/bundle/history", "outer/mid/inner/keys", "outer/mid/keys", "outer/keys", "beside", "outer/x"} {
				if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			mark := func(at, kind string) {
				p := filepath.Join(at, ".git")
				var err error
				switch kind {
				case "dir":
					err = os.Mkdir(p, 0o700)
				case "file":
					err = os.WriteFile(p, []byte("gitdir: ../elsewhere\n"), 0o600)
				default:
					err = os.Symlink(filepath.Join(root, "nowhere"), p)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			mark(filepath.Join(root, "outer"), kinds.outer)
			mark(filepath.Join(root, "outer/mid/inner"), kinds.inner)
			bundle := filepath.Join(root, "outer/mid/inner/bundle")
			refused := []string{
				"outer/mid/inner/keys", // the nearest work tree
				"outer/mid/inner",      // its root
				"outer/mid/keys",       // the outer work tree only
				"outer/keys",
				"outer",
				"outer/x",
				"outer/mid/inner/../../keys",
			}
			for _, r := range refused {
				if err := CheckKeyDir(filepath.Join(root, r), bundle); !errors.Is(err, ErrKeyDir) {
					t.Errorf("%s: %v", r, err)
				}
				if st, err := Open(Config{KeyDir: filepath.Join(root, r), BundleDir: bundle, Mode: ModeTest}); err == nil {
					_ = st.Close()
					t.Errorf("Open accepted %s", r)
				}
			}
			for _, a := range []string{"beside", "."} {
				if err := CheckKeyDir(filepath.Join(root, a), bundle); err != nil {
					t.Errorf("%s: %v", a, err)
				}
			}
			// Take the nearest mark away: the outer work tree still holds the key folder out.
			if err := os.RemoveAll(filepath.Join(root, "outer/mid/inner/.git")); err != nil {
				t.Fatal(err)
			}
			if err := CheckKeyDir(filepath.Join(root, "outer/keys"), bundle); !errors.Is(err, ErrKeyDir) {
				t.Errorf("with the inner mark gone: %v", err)
			}
			// And with both gone nothing is refused.
			if err := os.RemoveAll(filepath.Join(root, "outer/.git")); err != nil {
				t.Fatal(err)
			}
			for _, r := range refused[:6] {
				if err := CheckKeyDir(filepath.Join(root, r), bundle); err != nil {
					t.Errorf("%s with no repository: %v", r, err)
				}
			}
		})
	}
}

// Three work trees, one in another, and a mark at the very top of the temporary folder's tree.
func TestThreeWorkTreesOneInAnotherAreAllLookedAt(t *testing.T) {
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	a, b, c := filepath.Join(root, "a"), filepath.Join(root, "a/b"), filepath.Join(root, "a/b/c")
	bundle := filepath.Join(c, "bundle")
	for _, d := range []string{bundle, filepath.Join(a, "ka"), filepath.Join(b, "kb"), filepath.Join(c, "kc"), filepath.Join(root, "beside")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{a, b, c} {
		if err := os.Mkdir(filepath.Join(d, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"a/ka", "a/b/kb", "a/b/c/kc"} {
		if err := CheckKeyDir(filepath.Join(root, k), bundle); !errors.Is(err, ErrKeyDir) {
			t.Errorf("%s: %v", k, err)
		}
	}
	if err := CheckKeyDir(filepath.Join(root, "beside"), bundle); err != nil {
		t.Errorf("beside: %v", err)
	}
}

// A stat that fails on a work tree further up is an error, not a pass: the key folder cannot be
// compared with that work tree.
func TestACheckThatCannotLookAtAnOuterWorkTreeRefusesAndDoesNotPass(t *testing.T) {
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	outer, inner := filepath.Join(root, "outer"), filepath.Join(root, "outer/inner")
	bundle := filepath.Join(inner, "bundle")
	for _, d := range []string{bundle, filepath.Join(root, "beside")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{outer, inner} {
		if err := os.Mkdir(filepath.Join(d, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(root, "beside")
	if _, err := checkKeyDir(os.Stat, key, bundle); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	real, err := filepath.EvalSymlinks(outer)
	if err != nil {
		t.Fatal(err)
	}
	failOuter := func(path string) (fs.FileInfo, error) {
		if path == real {
			return nil, errors.New("an injected fault")
		}
		return os.Stat(path)
	}
	if _, err := checkKeyDir(failOuter, key, bundle); !errors.Is(err, ErrKeyDir) {
		t.Errorf("a stat that fails on the outer work tree: %v", err)
	}
}

// The kinds of spelling that a person can type, tried against the kernel, never for a crash and
// never for a pass that the kernel would not give. The target is built once.
func FuzzCheckKeyDirSpellingAgainstTheKernel(f *testing.F) {
	if runtime.GOOS != "linux" {
		f.Skip("the oracle reads /proc")
	}
	s := newSpellTree(f)
	f.Chdir(s.root)
	parts := []string{"L", "Lrel", "Lchain", "..", ".", "b", "b2", "keys", "keys-ok", "real", "deep", "dir", "other", "F", "history", "", "loop", "dangling"}
	spell := func(sel []byte, abs bool) string {
		var els []string
		for i, c := range sel {
			if i == 10 {
				break
			}
			els = append(els, parts[int(c)%len(parts)])
		}
		p := strings.Join(els, "/")
		if abs {
			return s.root + "/" + p
		}
		return p
	}
	f.Add([]byte{0, 3, 5, 7}, []byte{9, 10, 11, 5}, true)
	f.Add([]byte{0, 3, 5}, []byte{9, 10, 5}, false)
	f.Add([]byte{2, 3, 5, 7}, []byte{9, 10, 5}, true)
	f.Add([]byte{0, 3, 3, 5}, []byte{1, 3, 5}, false)
	f.Add([]byte{13, 3, 5}, []byte{9, 10, 5}, true)
	f.Fuzz(func(t *testing.T, ks, bs []byte, abs bool) {
		key, bundle := spell(ks, abs), spell(bs, abs)
		if key == "" || bundle == "" {
			return
		}
		err := CheckKeyDir(key, bundle)
		if err != nil && !errors.Is(err, ErrKeyDir) && !errors.Is(err, ErrParams) {
			t.Fatalf("an error of no kind: %v", err)
		}
		inside, ok := kernelInside(key, bundle)
		if !ok {
			return // the kernel cannot open one of them as a folder (a loop, a file, a missing name)
		}
		switch {
		case inside && err == nil:
			t.Fatalf("key %q is the bundle %q or inside it by the kernel, and the check passed it", key, bundle)
		case !inside && err != nil:
			t.Fatalf("key %q is outside the bundle %q by the kernel, and the check refused it: %v", key, bundle, err)
		}
	})
}

// A relative path needs the working folder. When there is none (it was removed), the path cannot
// be resolved and is refused, in words that hold no path.
func TestARelativePathWhenTheWorkingFolderIsGoneIsRefusedAsAKeyDirectory(t *testing.T) {
	s := newSpellTree(t)
	gone := filepath.Join(s.root, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("this system still names a removed working folder")
	}
	abs := filepath.Join(s.root, "real/deep/b")
	for who, err := range map[string]error{
		"key folder relative": CheckKeyDir("keys", abs),
		"bundle relative":     CheckKeyDir(filepath.Join(s.root, "other"), "b"),
		"Open":                openErr(Config{KeyDir: "keys", BundleDir: abs, Mode: ModeTest}),
	} {
		if !errors.Is(err, ErrKeyDir) || strings.Contains(err.Error(), s.root) {
			t.Errorf("%s: %v", who, err)
		}
	}
	// An absolute path still works.
	if err := CheckKeyDir(filepath.Join(s.root, "other"), abs); err != nil {
		t.Errorf("an absolute key folder: %v", err)
	}
}

func openErr(cfg Config) error {
	st, err := Open(cfg)
	if st != nil {
		_ = st.Close()
	}
	return err
}

// Hostile spellings of a path: very deep, very long, odd bytes. None crashes, each is refused, and
// no error repeats the text.
func TestHostileSpellingsOfAKeyDirectoryAreRefusedAndNeverRepeated(t *testing.T) {
	s := newSpellTree(t)
	t.Chdir(s.root)
	bundle := filepath.Join(s.root, "real/deep/b")
	spellings := map[string]string{
		"five thousand parents":            strings.Repeat("../", 5000),
		"five thousand parents and a name": strings.Repeat("../", 5000) + "other/nowhere",
		"a thousand dot elements":          strings.Repeat("./", 1000) + "nowhere",
		"a name of 300 bytes":              strings.Repeat("x", 300),
		"a path of 100000 bytes":           strings.Repeat("ab/", 33000),
		"a name that is not UTF-8":         "nowhere\xff\xfe",
		"a name with a newline":            "no\nwhere",
		"a name with a tab and spaces":     " \t no where ",
		"a name that starts with a dash":   "-rf",
		"a NUL inside":                     "other\x00/..",
		"only slashes beyond the root":     "////",
		"a link element with a dot dot":    "L/../../../../../../../../../../../../../nowhere",
	}
	for name, p := range spellings {
		for _, role := range []string{"key", "bundle"} {
			var err error
			if role == "key" {
				err = CheckKeyDir(p, bundle)
			} else {
				err = CheckKeyDir(filepath.Join(s.root, "other"), p)
			}
			// Some of these resolve to real folders (the root of the file system, the parent);
			// the rest must be refused. Either way the call returns and the text holds no input.
			if err != nil {
				if !errors.Is(err, ErrKeyDir) {
					t.Errorf("%s as %s: %v", name, role, err)
				}
				if strings.Contains(err.Error(), strings.TrimSpace(p)) && len(strings.TrimSpace(p)) > 3 {
					t.Errorf("%s as %s: the error repeats the input", name, role)
				}
			}
		}
	}
}

// A relative path is made absolute before anything is walked, so that the work tree that stands
// above the working folder is found: a relative bundle in a working folder inside a repository.
func TestARelativeBundleInAWorkingFolderInsideAWorkTreeFindsTheWorkTreeAboveIt(t *testing.T) {
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	for _, d := range []string{"repo/.git", "repo/sub/bundle", "repo/keys", "repo/sub/keys", "beside"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(filepath.Join(root, "repo/sub"))
	cases := []struct {
		key, bundle string
		refused     bool
	}{
		{"../keys", "bundle", true},
		{"keys", "bundle", true},
		{"../../beside", "bundle", false},
		{"../..", "bundle", false},
		{"../keys", "./bundle/", true},
		{filepath.Join(root, "repo/keys"), "bundle", true},
		{"../keys", filepath.Join(root, "repo/sub/bundle"), true},
		{"../../beside", filepath.Join(root, "repo/sub/bundle"), false},
	}
	for _, c := range cases {
		err := CheckKeyDir(c.key, c.bundle)
		if c.refused != errors.Is(err, ErrKeyDir) || (!c.refused && err != nil) {
			t.Errorf("key %q, bundle %q: refused=%v, got %v", c.key, c.bundle, c.refused, err)
		}
	}
}

// Whichever look at the file system fails, the key folder is refused and never passed. The calls of
// a control run are counted, then each one is made to fail in turn, on a tree that holds a bundle
// inside two work trees.
func TestWhicheverStatFailsTheCheckRefusesAndNeverPasses(t *testing.T) {
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	for _, d := range []string{"outer/.git", "outer/inner/.git", "outer/inner/bundle", "beside/keys"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key, bundle := filepath.Join(root, "beside/keys"), filepath.Join(root, "outer/inner/bundle")
	calls := 0
	count := func(p string) (fs.FileInfo, error) { calls++; return os.Stat(p) }
	if _, err := checkKeyDir(count, key, bundle); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	total := calls
	if total < 6 {
		t.Fatalf("only %d stat calls", total)
	}
	for failAt := 1; failAt <= total; failAt++ {
		n := 0
		stat := func(p string) (fs.FileInfo, error) {
			n++
			if n == failAt {
				return nil, errors.New("an injected fault")
			}
			return os.Stat(p)
		}
		if _, err := checkKeyDir(stat, key, bundle); !errors.Is(err, ErrKeyDir) {
			t.Errorf("a stat that fails at call %d of %d: %v", failAt, total, err)
		}
	}
}
