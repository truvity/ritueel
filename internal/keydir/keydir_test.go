package keydir

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tree is the folders of a test under one temporary folder that is not in a work tree:
// root/bundle (with history/deep/), root/keys, root/outside and a file root/a-file.
type tree struct {
	root, bundle, keys, outside, file string
}

func newTree(t *testing.T) tree {
	t.Helper()
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	// Both sides are compared as the operating system names them, so a temporary folder that
	// is itself reached through a link does not change what a test expects.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	f := tree{
		root: root, bundle: filepath.Join(root, "bundle"), keys: filepath.Join(root, "keys"),
		outside: filepath.Join(root, "outside"), file: filepath.Join(root, "a-file"),
	}
	for _, d := range []string{filepath.Join(f.bundle, "history", "deep"), f.keys, f.outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(f.file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func symlink(t *testing.T, target, name string) string {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Fatal(err)
	}
	return name
}

// refusedAs holds what every refusal of the package has: the kind, only that kind, a *Refusal
// with a reason, and a text of the kind and the reason.
func refusedAs(t *testing.T, err, kind error) *Refusal {
	t.Helper()
	if err == nil {
		t.Fatal("accepted, want a refusal")
	}
	other := ErrParams
	if kind == ErrParams {
		other = ErrKeyDir
	}
	if !errors.Is(err, kind) || errors.Is(err, other) {
		t.Fatalf("the error is not of the kind %v alone: %v", kind, err)
	}
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("the error is not a *Refusal: %T %v", err, err)
	}
	if r.Kind != kind {
		t.Errorf("the Kind is %v, want %v", r.Kind, kind)
	}
	if strings.TrimSpace(r.Reason) == "" {
		t.Errorf("the refusal has no reason: %#v", r)
	}
	if want := kind.Error() + ": " + r.Reason; err.Error() != want {
		t.Errorf("the text is %q, want %q", err.Error(), want)
	}
	return r
}

// checkBoth runs Check and CheckStat with os.Stat and requires the same answer of both.
func checkBoth(t *testing.T, keyDir, bundleDir string) (string, error) {
	t.Helper()
	errCheck := Check(keyDir, bundleDir)
	got, errStat := CheckStat(os.Stat, keyDir, bundleDir)
	if (errCheck == nil) != (errStat == nil) || (errCheck != nil && errCheck.Error() != errStat.Error()) {
		t.Errorf("Check says %v and CheckStat says %v", errCheck, errStat)
	}
	if errStat != nil && got != "" {
		t.Errorf("a refusal returns the folder %q", got)
	}
	return got, errStat
}

func TestCheckRefusesTheBundleAndAnythingInsideItInEverySpelling(t *testing.T) {
	f := newTree(t)
	inLink := symlink(t, filepath.Join(f.bundle, "history"), filepath.Join(f.root, "link-into-the-bundle"))
	inLinkOfLink := symlink(t, inLink, filepath.Join(f.root, "link-of-link"))
	toBundle := symlink(t, f.bundle, filepath.Join(f.outside, "the-bundle"))
	chain := symlink(t, filepath.Join(f.outside, "the-bundle", "history"), filepath.Join(f.outside, "chain"))
	t.Chdir(f.root)
	cases := []struct{ name, dir string }{
		{"the bundle folder", f.bundle},
		{"the bundle with a trailing slash", f.bundle + "/"},
		{"the bundle with two trailing slashes", f.bundle + "//"},
		{"the bundle spelled with a dotted path", f.root + "/keys/../bundle"},
		{"the bundle spelled from inside itself", f.bundle + "/history/./deep/../.."},
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
			_, err := checkBoth(t, c.dir, f.bundle)
			refusedAs(t, err, ErrKeyDir)
		})
	}
	// The bundle may be given in any of those spellings too.
	for _, spelling := range []string{f.bundle + "/", f.root + "/keys/../bundle", "bundle", toBundle} {
		_, err := checkBoth(t, filepath.Join(f.bundle, "history"), spelling)
		refusedAs(t, err, ErrKeyDir)
		if _, err := checkBoth(t, f.keys, spelling); err != nil {
			t.Errorf("the key folder with the bundle spelled %q: %v", spelling, err)
		}
	}
}

func TestCheckAcceptsASiblingAParentAndALinkOutOfTheBundle(t *testing.T) {
	f := newTree(t)
	outLink := symlink(t, f.outside, filepath.Join(f.bundle, "link-out"))
	keysLink := symlink(t, f.keys, filepath.Join(f.root, "keys-link"))
	t.Chdir(f.root)
	cases := []struct{ name, dir, want string }{
		{"a sibling of the bundle", f.keys, f.keys},
		{"another sibling", f.outside, f.outside},
		{"a sibling with a trailing slash", f.keys + "/", f.keys},
		{"a sibling spelled with a dotted path", f.root + "/bundle/../keys", f.keys},
		{"a sibling as a relative path", "keys", f.keys},
		{"a link inside the bundle that points to a folder outside", outLink, f.outside},
		{"a link beside the bundle to the key folder", keysLink, f.keys},
		{"the parent of the bundle", f.root, f.root},
		{"the parent as a relative path", ".", f.root},
		{"the parent spelled with a dotted path", f.bundle + "/..", f.root},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := checkBoth(t, c.dir, f.bundle)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got != c.want {
				t.Errorf("the checked folder is %q, want %q", got, c.want)
			}
		})
	}
}

func TestCheckStatReturnsTheResolvedFolderAndNothingWhenItRefuses(t *testing.T) {
	f := newTree(t)
	hop := symlink(t, f.keys, filepath.Join(f.root, "hop"))
	hop2 := symlink(t, hop, filepath.Join(f.root, "hop2"))
	got, err := CheckStat(os.Stat, hop2+"/", f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got != f.keys {
		t.Errorf("the resolved folder is %q, want %q", got, f.keys)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("the resolved folder %q is not absolute", got)
	}
	// A relative path comes back absolute.
	t.Chdir(f.root)
	if got, err := CheckStat(os.Stat, "hop2", "bundle"); err != nil || got != f.keys {
		t.Errorf("a relative path gives %q (%v), want %q", got, err, f.keys)
	}
	// A refusal gives no folder.
	got, err = CheckStat(os.Stat, f.bundle, f.bundle)
	refusedAs(t, err, ErrKeyDir)
	if got != "" {
		t.Errorf("a refusal returns the folder %q", got)
	}
}

func TestCheckRefusesAFolderThatIsMissingNotAFolderOrEmptyAndABundleThatIsMissingOrEmpty(t *testing.T) {
	f := newTree(t)
	dangling := symlink(t, filepath.Join(f.root, "nowhere"), filepath.Join(f.root, "dangling"))
	toFile := symlink(t, f.file, filepath.Join(f.root, "to-a-file"))
	loopA := filepath.Join(f.root, "loop-a")
	symlink(t, filepath.Join(f.root, "loop-b"), loopA)
	symlink(t, loopA, filepath.Join(f.root, "loop-b"))
	cases := []struct {
		name        string
		dir, bundle string
		kind        error
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
		{"a bundle folder that is a loop of links", f.keys, loopA, ErrKeyDir},
		{"both empty, the bundle is judged first", "", "", ErrParams},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := checkBoth(t, c.dir, c.bundle)
			refusedAs(t, err, c.kind)
		})
	}
}

func TestACheckGivesTheEmptyBundleAsAParameterFaultAndNoOtherRefusalIsOne(t *testing.T) {
	f := newTree(t)
	_, err := CheckStat(os.Stat, f.keys, "")
	refusedAs(t, err, ErrParams)
	if errors.Is(err, ErrKeyDir) {
		t.Errorf("a parameter fault is a refused key directory: %v", err)
	}
	// The empty bundle is told before the stat function is asked anything.
	asked := 0
	counted := func(string) (fs.FileInfo, error) { asked++; return nil, errors.New("not to be called") }
	if _, err := CheckStat(counted, f.keys, ""); !errors.Is(err, ErrParams) || asked != 0 {
		t.Errorf("an empty bundle: %v after %d stat calls", err, asked)
	}
	if _, err := CheckStat(counted, "", f.bundle); !errors.Is(err, ErrKeyDir) || asked != 0 {
		t.Errorf("an empty key folder: %v after %d stat calls", err, asked)
	}
}

func TestAPathIsFollowedInOrderSoThatDotDotAfterALinkIsTakenFromTheTargetOfTheLink(t *testing.T) {
	f := newTree(t)
	// root/real/deep/{dir,b,keys-ok} and root/{b,keys-ok} as decoys: the cleaned text of "L/../b"
	// is "b" at the working folder, but the operating system gives the folder beside the target.
	for _, d := range []string{"real/deep/dir", "real/deep/b/history", "real/deep/keys-ok", "b", "keys-ok"} {
		if err := os.MkdirAll(filepath.Join(f.root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	symlink(t, filepath.Join(f.root, "real", "deep", "dir"), filepath.Join(f.root, "L"))
	t.Chdir(f.root)
	bundle := filepath.Join(f.root, "real", "deep", "b")
	// "L/../b" is the bundle for the system; its cleaned text "b" is the decoy, which would pass.
	_, err := checkBoth(t, "L/../b", bundle)
	refusedAs(t, err, ErrKeyDir)
	// "L/../keys-ok" is a folder beside the bundle for the system: accepted, and resolved there.
	got, err := checkBoth(t, "L/../keys-ok", bundle)
	if err != nil {
		t.Fatalf("a folder beside the bundle is refused: %v", err)
	}
	if want := filepath.Join(f.root, "real", "deep", "keys-ok"); got != want {
		t.Errorf("the checked folder is %q, want %q", got, want)
	}
	// The same for the bundle: "L/../b" is the bundle, and so the key folder inside it is refused.
	_, err = checkBoth(t, filepath.Join(bundle, "history"), "L/../b")
	refusedAs(t, err, ErrKeyDir)
	_, err = checkBoth(t, bundle, "L/../b")
	refusedAs(t, err, ErrKeyDir)
	// "L/../nowhere" does not exist beside the target, although "nowhere" would not exist here either:
	// the decoy "b" at the working folder must not rescue a name that is missing there.
	_, err = checkBoth(t, "L/../nowhere", bundle)
	refusedAs(t, err, ErrKeyDir)
}

func TestARelativePathNeedsTheWorkingFolderAndIsRefusedWhenItIsGone(t *testing.T) {
	f := newTree(t)
	gone := filepath.Join(f.root, "gone")
	if err := os.Mkdir(gone, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(gone)
	if err := os.Remove(gone); err != nil {
		t.Skipf("the working folder cannot be removed: %v", err)
	}
	if _, err := os.Getwd(); err == nil {
		t.Skip("this system still names a removed working folder")
	}
	for _, c := range []struct{ key, bundle string }{{"keys", f.bundle}, {f.keys, "bundle"}} {
		_, err := checkBoth(t, c.key, c.bundle)
		refusedAs(t, err, ErrKeyDir)
	}
	// An absolute pair needs no working folder.
	if _, err := checkBoth(t, f.keys, f.bundle); err != nil {
		t.Errorf("an absolute pair is refused with no working folder: %v", err)
	}
}

func TestCheckRefusesAFolderInsideTheWorkTreeOfTheRepositoryThatHoldsTheBundle(t *testing.T) {
	for _, kind := range []string{"a .git folder", "a .git file as a worktree has", "a .git link that points nowhere"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if insideWorkTree(root) {
				t.Skip("the temporary folder is inside a work tree")
			}
			repo := filepath.Join(root, "repo")
			bundle := filepath.Join(repo, "deep", "bundle")
			for _, d := range []string{bundle, filepath.Join(repo, "keys"), filepath.Join(repo, "deep", "keys"), filepath.Join(root, "beside"), filepath.Join(bundle, "history")} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			git := filepath.Join(repo, ".git")
			switch kind {
			case "a .git folder":
				if err := os.Mkdir(git, 0o700); err != nil {
					t.Fatal(err)
				}
			case "a .git file as a worktree has":
				if err := os.WriteFile(git, []byte("gitdir: ../elsewhere\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				symlink(t, filepath.Join(root, "nowhere"), git)
			}
			refused := map[string]string{
				"a sibling of the repository's folder": filepath.Join(repo, "keys"),
				"a folder beside the bundle":           filepath.Join(repo, "deep", "keys"),
				"the root of the work tree itself":     repo,
				"the work tree with a dotted path":     repo + "/deep/..",
			}
			for name, dir := range refused {
				_, err := checkBoth(t, dir, bundle)
				if err == nil {
					t.Errorf("%s: accepted", name)
					continue
				}
				refusedAs(t, err, ErrKeyDir)
			}
			accepted := map[string]string{
				"a folder outside the work tree":  filepath.Join(root, "beside"),
				"the parent of the work tree":     root,
				"the same folder, other spelling": filepath.Join(root, "beside") + "/",
			}
			for name, dir := range accepted {
				if _, err := checkBoth(t, dir, bundle); err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
			// The same folders with no repository above the bundle are accepted.
			if err := os.RemoveAll(git); err != nil {
				t.Fatal(err)
			}
			for name, dir := range refused {
				if _, err := checkBoth(t, dir, bundle); err != nil {
					t.Errorf("%s, with no repository: %v", name, err)
				}
			}
		})
	}
}

func TestEveryRepositoryAboveTheBundleCountsAndNotOnlyTheNearest(t *testing.T) {
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	outer, inner := filepath.Join(root, "outer"), filepath.Join(root, "outer", "inner")
	bundle := filepath.Join(inner, "bundle")
	for _, d := range []string{bundle, filepath.Join(root, "outer", "keys"), filepath.Join(inner, "keys"), filepath.Join(root, "beside")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A nested clone inside a repository: a folder of the outer one that is not in the inner one.
	for _, d := range []string{outer, inner} {
		if err := os.Mkdir(filepath.Join(d, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, dir := range map[string]string{
		"a folder of the nearest repository":    filepath.Join(inner, "keys"),
		"a folder of the outer repository only": filepath.Join(outer, "keys"),
		"the root of the outer repository":      outer,
	} {
		_, err := checkBoth(t, dir, bundle)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		refusedAs(t, err, ErrKeyDir)
	}
	if _, err := checkBoth(t, filepath.Join(root, "beside"), bundle); err != nil {
		t.Errorf("a folder outside both is refused: %v", err)
	}
}

func TestACheckThatCannotLookAtAnOuterWorkTreeRefusesAndDoesNotPass(t *testing.T) {
	root := t.TempDir()
	if insideWorkTree(root) {
		t.Skip("the temporary folder is inside a work tree")
	}
	outer := filepath.Join(root, "outer")
	bundle := filepath.Join(outer, "inner", "bundle")
	key := filepath.Join(root, "beside")
	for _, d := range []string{bundle, key} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{outer, filepath.Join(outer, "inner")} {
		if err := os.Mkdir(filepath.Join(d, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := CheckStat(os.Stat, key, bundle); err != nil {
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
	_, err = CheckStat(failOuter, key, bundle)
	refusedAs(t, err, ErrKeyDir)
}

// The key folder is another folder on the disk, but the stub says it is the bundle, as a bind
// mount or a spelling on a disk that ignores case would: the answer is os.SameFile's, never the
// text's.
func TestCheckStatTellsTheSameFolderByOSSameFileAndNotByTheText(t *testing.T) {
	f := newTree(t)
	bundleInfo, err := os.Stat(f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	same := func(path string) (fs.FileInfo, error) {
		if path == f.keys {
			return bundleInfo, nil
		}
		return os.Stat(path)
	}
	_, err = CheckStat(same, f.keys, f.bundle)
	refusedAs(t, err, ErrKeyDir)
	// The same folders with an honest stat are accepted: the refusal came from SameFile.
	if _, err := CheckStat(os.Stat, f.keys, f.bundle); err != nil {
		t.Errorf("the control is refused: %v", err)
	}
	// The folder above the key folder is the bundle for the stub: the walk up finds it.
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
	_, err = CheckStat(up, deep, f.bundle)
	refusedAs(t, err, ErrKeyDir)
	// The stub that gives the bundle for a folder that is not above the key folder changes nothing.
	beside := func(path string) (fs.FileInfo, error) {
		if path == f.outside {
			return bundleInfo, nil
		}
		return os.Stat(path)
	}
	if _, err := CheckStat(beside, f.keys, f.bundle); err != nil {
		t.Errorf("a folder that is not above the key folder was looked at: %v", err)
	}
}

// Whichever look at the file system fails, the key folder is refused and never passed. The calls
// of a control run are counted, then each one is made to fail in turn, with three kinds of error.
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
	plainKey, plainBundle := filepath.Join(root, "beside/keys"), filepath.Join(root, "beside")
	for _, pair := range []struct{ name, key, bundle string }{
		{"a bundle in two work trees", key, bundle},
		{"a bundle in no work tree", plainKey, plainBundle},
	} {
		calls := 0
		count := func(p string) (fs.FileInfo, error) { calls++; return os.Stat(p) }
		if _, err := CheckStat(count, pair.key, pair.bundle); pair.name == "a bundle in two work trees" && err != nil {
			t.Fatalf("%s: the control is refused: %v", pair.name, err)
		}
		total := calls
		if total < 3 {
			t.Fatalf("%s: only %d stat calls", pair.name, total)
		}
		for _, injected := range []error{
			errors.New("an injected fault"),
			&fs.PathError{Op: "stat", Path: root + "/secret-place", Err: fs.ErrPermission},
			&fs.PathError{Op: "stat", Path: root + "/secret-place", Err: fs.ErrNotExist},
		} {
			for failAt := 1; failAt <= total; failAt++ {
				n := 0
				stat := func(p string) (fs.FileInfo, error) {
					n++
					if n == failAt {
						return nil, injected
					}
					return os.Stat(p)
				}
				got, err := CheckStat(stat, pair.key, pair.bundle)
				if err == nil {
					t.Errorf("%s: a stat that fails at call %d of %d (%v) is accepted", pair.name, failAt, total, injected)
					continue
				}
				refusedAs(t, err, ErrKeyDir)
				if got != "" {
					t.Errorf("%s: a refusal returns the folder %q", pair.name, got)
				}
				if strings.Contains(err.Error(), "secret-place") || strings.Contains(err.Error(), injected.Error()) {
					t.Errorf("%s: the error repeats the text of the fault: %v", pair.name, err)
				}
			}
		}
	}
}

// A folder that the user may not search cannot be resolved: that is a refusal in fixed words, not
// a pass and not the text of the system's error.
func TestAFolderThatCannotBeReadIsRefusedInWordsThatHoldNoPath(t *testing.T) {
	f := newTree(t)
	locked := filepath.Join(f.root, "locked")
	if err := os.MkdirAll(filepath.Join(locked, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if _, err := os.Stat(filepath.Join(locked, "keys")); err == nil {
		t.Skip("this user can search a folder of mode 0")
	}
	for _, role := range []string{"key", "bundle"} {
		var err error
		if role == "key" {
			_, err = checkBoth(t, filepath.Join(locked, "keys"), f.bundle)
		} else {
			_, err = checkBoth(t, f.keys, filepath.Join(locked, "keys"))
		}
		r := refusedAs(t, err, ErrKeyDir)
		if !strings.Contains(r.Reason, role) {
			t.Errorf("the %s is not named in the reason: %q", role, r.Reason)
		}
		if strings.Contains(err.Error(), f.root) || strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: the error holds a path or the text of the system: %v", role, err)
		}
	}
}

// A refusal says why in fixed words: no path, no spelling that the caller gave, no text of the
// system's error.
func TestARefusalNamesNoPartOfTheFileSystemAndNoInputText(t *testing.T) {
	f := newTree(t)
	dangling := symlink(t, filepath.Join(f.root, "nowhere"), filepath.Join(f.root, "dangling"))
	loop := filepath.Join(f.root, "loop")
	symlink(t, loop, loop)
	t.Chdir(f.root)
	pairs := []struct{ key, bundle string }{
		{f.bundle, f.bundle},
		{filepath.Join(f.bundle, "history", "deep"), f.bundle},
		{filepath.Join(f.root, "nowhere"), f.bundle},
		{f.file, f.bundle},
		{dangling, f.bundle},
		{loop, f.bundle},
		{f.keys, filepath.Join(f.root, "nowhere")},
		{f.keys, f.file},
		{f.keys, ""},
		{"", f.bundle},
		{strings.Repeat("../", 5000), f.bundle},
		{strings.Repeat("../", 5000) + "other/nowhere", f.bundle},
		{strings.Repeat("x", 300), f.bundle},
		{"nowhere\xff\xfe", f.bundle},
		{"no\nwhere", f.bundle},
		{"-rf", f.bundle},
		{"other\x00/..", f.bundle},
	}
	// A repository above the bundle, and a key folder inside it.
	repo := t.TempDir()
	if !insideWorkTree(repo) {
		if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}
		inRepoBundle := filepath.Join(repo, "bundle")
		if err := os.MkdirAll(filepath.Join(inRepoBundle, "history"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(repo, "keys"), 0o700); err != nil {
			t.Fatal(err)
		}
		pairs = append(pairs, struct{ key, bundle string }{filepath.Join(repo, "keys"), inRepoBundle})
	}
	seen := map[string]bool{}
	for _, p := range pairs {
		err := Check(p.key, p.bundle)
		if err == nil {
			continue // some spellings are real folders; the others must be refused
		}
		var r *Refusal
		if !errors.As(err, &r) || strings.TrimSpace(r.Reason) == "" {
			t.Errorf("key %q, bundle %q: no reason: %v", p.key, p.bundle, err)
			continue
		}
		seen[r.Reason] = true
		text := err.Error()
		for _, banned := range []string{f.root, repo, os.TempDir(), "/tmp", "no such file", "permission denied", "too many levels", "invalid argument", "not a directory", "\n"} {
			if banned != "" && strings.Contains(text, banned) {
				t.Errorf("key %.20q, bundle %.20q: the error holds %q: %q", p.key, p.bundle, banned, text)
			}
		}
		for _, in := range []string{p.key, p.bundle} {
			if word := strings.TrimSpace(in); len(word) > 3 && strings.Contains(text, word) {
				t.Errorf("key %.20q, bundle %.20q: the error repeats the input", p.key, p.bundle)
			}
		}
		if len(text) > 200 {
			t.Errorf("key %.20q, bundle %.20q: the text is %d bytes long", p.key, p.bundle, len(text))
		}
	}
	// The reasons are a small fixed set: many inputs, few sentences.
	if len(seen) < 5 || len(seen) > 12 {
		t.Errorf("%d different reasons: %v", len(seen), seen)
	}
}

func TestCheckReadsNoFileAndMakesNoFolder(t *testing.T) {
	f := newTree(t)
	before := snapshot(t, f.root)
	_ = Check(f.keys, f.bundle)
	_ = Check(filepath.Join(f.root, "nowhere"), f.bundle)
	_ = Check(f.bundle, f.bundle)
	_ = Check(f.file, f.bundle)
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

func TestARefusalIsAnErrorOfItsKindThatUnwrapsToIt(t *testing.T) {
	for _, kind := range []error{ErrKeyDir, ErrParams} {
		err := error(&Refusal{Kind: kind, Reason: "in fixed words"})
		if !errors.Is(err, kind) {
			t.Errorf("a refusal of %v is not that kind", kind)
		}
		if got := errors.Unwrap(err); got != kind {
			t.Errorf("Unwrap gives %v, want %v", got, kind)
		}
		if want := kind.Error() + ": in fixed words"; err.Error() != want {
			t.Errorf("the text is %q, want %q", err.Error(), want)
		}
		wrapped := errors.Join(errors.New("context"), err)
		var r *Refusal
		if !errors.As(wrapped, &r) || r.Kind != kind {
			t.Errorf("a wrapped refusal of %v is not found", kind)
		}
	}
	if errors.Is(ErrKeyDir, ErrParams) || errors.Is(ErrParams, ErrKeyDir) {
		t.Error("the two kinds are one")
	}
}

// A Refusal that is built by hand with no kind is still an error that can be printed: it does not
// panic, its text holds the reason, it is neither kind and it unwraps to nothing.
func TestARefusalWithNoKindDoesNotPanicAndIsNeitherKind(t *testing.T) {
	var err error = &Refusal{Reason: "in fixed words"}
	text := err.Error()
	if !strings.Contains(text, "in fixed words") {
		t.Errorf("the text does not hold the reason: %q", text)
	}
	if errors.Is(err, ErrKeyDir) || errors.Is(err, ErrParams) {
		t.Errorf("a refusal with no kind is of a kind: %v", err)
	}
	if got := errors.Unwrap(err); got != nil {
		t.Errorf("Unwrap gives %v, want nil", got)
	}
	var r *Refusal
	if !errors.As(err, &r) {
		t.Error("the refusal is not found by errors.As")
	}
	if text := (&Refusal{}).Error(); text == "" {
		t.Error("a refusal with no kind and no reason has no text")
	}
}
