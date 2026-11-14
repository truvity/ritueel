package software

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// After fsx has opened the folder, Open looks at the path again. A link put into a parent of the
// key directory between the check and the open is followed by the open, so the folder that the
// path gives now must be the checked one. These tests make the swap by hand, between the two
// looks, which a call of Open cannot be stopped in.

type recheckSetup struct {
	f       folders
	dir     string      // the resolved key directory that was checked
	checked fs.FileInfo // what Open saw of it
}

// A key directory root/p/keys, which is checked and statted as Open does it.
func newRecheck(t *testing.T) recheckSetup {
	t.Helper()
	f := newFolders(t)
	if err := os.MkdirAll(filepath.Join(f.root, "p", "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := checkKeyDir(os.Stat, filepath.Join(f.root, "p", "keys"), f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	return recheckSetup{f: f, dir: dir, checked: checked}
}

func wantNotTheCheckedFolder(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, ErrKeyDir) || Code(err) != "key-dir" || errors.Is(err, ErrKeyExists) {
		t.Fatalf("%s: not refused as ErrKeyDir: %v", what, err)
	}
}

func TestTheLookAfterTheOpenAcceptsTheFolderThatWasChecked(t *testing.T) {
	r := newRecheck(t)
	if err := stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked); err != nil {
		t.Fatal(err)
	}
	// A relative or odd spelling of the bundle does not matter: the folder is the same.
	t.Chdir(r.f.root)
	if err := stillTheCheckedFolder(os.Stat, r.dir, "bundle/", r.checked); err != nil {
		t.Fatal(err)
	}
}

func TestTheLookAfterTheOpenRefusesAFolderThatIsNotTheCheckedOne(t *testing.T) {
	r := newRecheck(t)
	other, err := os.Stat(r.f.outside)
	if err != nil {
		t.Fatal(err)
	}
	err = stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, other)
	wantNotTheCheckedFolder(t, "another FileInfo", err)
	if !strings.Contains(err.Error(), "not the folder that was checked") {
		t.Errorf("the text: %v", err)
	}
	// A file of the same name is not the folder either.
	file, err := os.Stat(r.f.file)
	if err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "a file", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, file))
}

// The same path, a new folder: the old one was moved away and another made at its name.
func TestTheLookAfterTheOpenRefusesTheSamePathWhenTheFolderWasReplaced(t *testing.T) {
	r := newRecheck(t)
	if err := os.Rename(r.dir, r.dir+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(r.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "a replaced folder", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
	// The moved folder is the checked one, and it stands elsewhere: the path is not its path any more.
	if err := os.Remove(r.dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(r.dir+".old", r.dir); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "a link to the old folder", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
}

// A parent of the key directory swapped for a link into the bundle: the path now leads into it.
func TestTheLookAfterTheOpenRefusesAParentSwappedForALinkIntoTheBundle(t *testing.T) {
	r := newRecheck(t)
	parent := filepath.Dir(r.dir)
	if err := os.Rename(parent, parent+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(r.f.bundle, parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(r.f.bundle, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "a parent linked into the bundle", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
	// The same swap read through the bundle's own folder, as the bundle given in another spelling.
	wantNotTheCheckedFolder(t, "the bundle spelled with a trailing slash", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle+"/", r.checked))
}

// A parent swapped for a link to a harmless folder that holds a folder of the same name: the path
// leads to another folder, outside the bundle, which the check alone would pass.
func TestTheLookAfterTheOpenRefusesAParentSwappedForALinkToAnotherFolderOutsideTheBundle(t *testing.T) {
	r := newRecheck(t)
	parent := filepath.Dir(r.dir)
	if err := os.MkdirAll(filepath.Join(r.f.outside, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(parent, parent+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(r.f.outside, parent); err != nil {
		t.Fatal(err)
	}
	if err := CheckKeyDir(r.dir, r.f.bundle); err != nil {
		t.Fatalf("the swapped path would pass the check alone: %v", err)
	}
	wantNotTheCheckedFolder(t, "a parent linked to another folder", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
}

func TestTheLookAfterTheOpenRefusesAFolderThatIsGoneAndABundleThatIsGone(t *testing.T) {
	r := newRecheck(t)
	bundleKept := r.f.bundle + ".kept"
	if err := os.Rename(r.f.bundle, bundleKept); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "no bundle", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
	if err := os.WriteFile(r.f.bundle, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "a file for a bundle", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
	if err := os.Remove(r.f.bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(bundleKept, r.f.bundle); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(r.dir); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "no key folder", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
	if err := os.WriteFile(r.dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "a file for the key folder", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
}

// A stat that fails at any one look of the second check is a refusal and never a pass. The calls
// are counted on a control run, then each one is made to fail in turn.
func TestTheLookAfterTheOpenRefusesWhicheverStatFails(t *testing.T) {
	r := newRecheck(t)
	calls := 0
	count := func(p string) (fs.FileInfo, error) { calls++; return os.Stat(p) }
	if err := stillTheCheckedFolder(count, r.dir, r.f.bundle, r.checked); err != nil {
		t.Fatal(err)
	}
	total := calls
	if total < 3 {
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
		wantNotTheCheckedFolder(t, "a failing stat", stillTheCheckedFolder(stat, r.dir, r.f.bundle, r.checked))
	}
	// The last look is the one of the folder itself: another folder at that moment is refused.
	n := 0
	other, _ := os.Stat(r.f.outside)
	last := func(p string) (fs.FileInfo, error) {
		n++
		if n == total {
			return other, nil
		}
		return os.Stat(p)
	}
	wantNotTheCheckedFolder(t, "another folder at the last look", stillTheCheckedFolder(last, r.dir, r.f.bundle, r.checked))
}

// The check of Open stands: a key directory inside the bundle is refused before anything is opened,
// and a good one opens. Open leaves no handle behind when the second look refuses (the folder
// that was opened is closed): a Store is never made.
func TestOpenMakesAStoreOnlyWhenBothLooksAgreeAndTheStoreWorks(t *testing.T) {
	r := newRecheck(t)
	s, err := Open(Config{KeyDir: r.dir, BundleDir: r.f.bundle, Mode: ModeTest})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.dir, "A.x509.key.pem")); err != nil {
		t.Errorf("the file is not in the checked folder: %v", err)
	}
}

// The same folder under another path is refused too: the path that Open checked is the path that it
// opened, and a parent that now leads elsewhere (even to the same folder, moved) is a change.
func TestTheLookAfterTheOpenRefusesTheVeryFolderThatWasCheckedWhenItNowStandsUnderAnotherPath(t *testing.T) {
	r := newRecheck(t)
	parent := filepath.Dir(r.dir)
	if err := os.Rename(parent, parent+".moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent+".moved", parent); err != nil {
		t.Fatal(err)
	}
	now, err := os.Stat(r.dir)
	if err != nil || !os.SameFile(now, r.checked) {
		t.Fatalf("the control: the folder is not the same (%v)", err)
	}
	wantNotTheCheckedFolder(t, "the same folder, another path", stillTheCheckedFolder(os.Stat, r.dir, r.f.bundle, r.checked))
}

// The folder is the checked one, and the bundle's spelling now leads to a folder that holds it:
// the second look repeats the whole check, not only the identity of the folder.
func TestTheLookAfterTheOpenRepeatsTheWholeCheckSoABundleThatNowHoldsTheKeyDirectoryIsRefused(t *testing.T) {
	f := newFolders(t)
	spelling := filepath.Join(f.root, "bundle-link")
	link(t, f.bundle, spelling)
	dir, err := checkKeyDir(os.Stat, f.keys, spelling)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := stillTheCheckedFolder(os.Stat, dir, spelling, checked); err != nil {
		t.Fatalf("the control: %v", err)
	}
	if err := os.Remove(spelling); err != nil {
		t.Fatal(err)
	}
	link(t, f.root, spelling) // the key folder is inside the folder that the spelling leads to now
	wantNotTheCheckedFolder(t, "a bundle that now holds the key directory", stillTheCheckedFolder(os.Stat, dir, spelling, checked))
	// And a key folder that is a work tree's: a repository mark put above the bundle after the check.
	if err := os.Remove(spelling); err != nil {
		t.Fatal(err)
	}
	link(t, f.bundle, spelling)
	if err := os.Mkdir(filepath.Join(f.root, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	wantNotTheCheckedFolder(t, "a repository mark put above after the check", stillTheCheckedFolder(os.Stat, dir, spelling, checked))
}
