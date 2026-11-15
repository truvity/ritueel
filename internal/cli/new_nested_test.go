//go:build linux || darwin

package cli

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// "new" does not make a bundle inside a bundle: a folder above DIR that holds the name ritueel.yaml, of any kind,
// refuses it with exit code 1, names that folder, writes nothing and does not tell the person to remove a folder
// that was never made. The names of the folders above are read as they are on the disk, so a link on the way
// counts for what it points to.

// crqShape is every entry of a folder as "path mode size", links not followed and no file read, so that it works on
// a folder that holds a file that cannot be read.
func crqShape(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, rel+" "+info.Mode().String()+" "+strconv.FormatInt(info.Size(), 10))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

func jsonNumber(s string) json.Number { return json.Number(s) }

const nestedMark = "a bundle is not made inside a bundle"

// settingsKinds make a name ritueel.yaml of each kind of thing that can stand there.
var settingsKinds = map[string]func(t *testing.T, p string){
	"a file with settings": func(t *testing.T, p string) { must(t, os.WriteFile(p, []byte(newSettingsText), 0o644)) },
	"an empty file":        func(t *testing.T, p string) { must(t, os.WriteFile(p, nil, 0o644)) },
	"a file that is not settings": func(t *testing.T, p string) {
		must(t, os.WriteFile(p, []byte("\xff\xfe not yaml \x00"), 0o644))
	},
	"a folder": func(t *testing.T, p string) { must(t, os.Mkdir(p, 0o755)) },
	"a link to a file": func(t *testing.T, p string) {
		must(t, os.Symlink("elsewhere", p))
		must(t, os.WriteFile(filepath.Join(filepath.Dir(p), "elsewhere"), nil, 0o644))
	},
	"a link to nothing":          func(t *testing.T, p string) { must(t, os.Symlink("nowhere", p)) },
	"a link to itself":           func(t *testing.T, p string) { must(t, os.Symlink(filepath.Base(p), p)) },
	"a pipe":                     func(t *testing.T, p string) { must(t, syscall.Mkfifo(p, 0o644)) },
	"a file that cannot be read": func(t *testing.T, p string) { must(t, os.WriteFile(p, []byte("x"), 0o000)) },
}

func TestNewRefusesADirUnderAFolderThatHoldsAFileNamedRitueelYaml(t *testing.T) {
	for kind, put := range settingsKinds {
		for _, depth := range []int{0, 1, 3} {
			t.Run(kind+" holder "+strings.Repeat("above ", depth)+"the parent", func(t *testing.T) {
				root := t.TempDir()
				holder := filepath.Join(root, "holder")
				must(t, os.Mkdir(holder, 0o755))
				put(t, filepath.Join(holder, "ritueel.yaml"))
				parent := holder
				for i := 0; i < depth; i++ {
					parent = filepath.Join(parent, "below")
					must(t, os.Mkdir(parent, 0o755))
				}
				before := crqShape(t, root)
				for _, args := range [][]string{{"new", filepath.Join(parent, "acme")}, {"--output", "json", "new", "--test-root", filepath.Join(parent, "acme")}} {
					r := run(t, args...)
					asJSON := args[0] == "--output"
					if r.code != ExitFailure || (!asJSON && r.stdout != "") || (asJSON && !strings.HasPrefix(r.stdout, "{")) {
						t.Fatalf("%v: (%d, %q, %q), want exit code 1", args, int(r.code), r.stdout, r.stderr)
					}
					if !strings.HasPrefix(r.stderr, "ritueel: ") || !strings.Contains(r.stderr, "the folder "+holder+" holds ritueel.yaml: "+nestedMark) {
						t.Errorf("%v: standard error = %q, want the folder that holds the file and the reason", args, r.stderr)
					}
					if strings.Contains(r.stderr, "remove it") || strings.Contains(r.stderr, "the folder was made") || !strings.Contains(r.stderr, "the folder was not made") {
						t.Errorf("%v: standard error = %q, the folder was never made", args, r.stderr)
					}
					if strings.Count(r.stderr, "\n") != 1 || !onlyPrintable(r.stderr) {
						t.Errorf("%v: standard error = %q, want one printable line", args, r.stderr)
					}
					if asJSON {
						obj := object(t, r.stdout)
						if msg, _ := obj["error"].(string); obj["outcome"] != "failed" || obj["exit_code"] != jsonNumber("1") || !strings.Contains(msg, "holds ritueel.yaml") {
							t.Errorf("object = %v", obj)
						}
						if _, ok := obj["checks"]; ok {
							t.Errorf("a failed new has checks: %v", obj)
						}
					}
					crqSame(t, "new", before, crqShape(t, root))
				}
			})
		}
	}
}

// The nearest folder above that holds the name is the one that is named.
func TestNewNamesTheNearestFolderThatHoldsRitueelYaml(t *testing.T) {
	root := t.TempDir()
	far, near := filepath.Join(root, "far"), filepath.Join(root, "far", "near")
	must(t, os.MkdirAll(filepath.Join(near, "x"), 0o755))
	must(t, os.WriteFile(filepath.Join(far, "ritueel.yaml"), nil, 0o644))
	must(t, os.WriteFile(filepath.Join(near, "ritueel.yaml"), nil, 0o644))
	r := run(t, "new", filepath.Join(near, "x", "acme"))
	if r.code != ExitFailure || !strings.Contains(r.stderr, "the folder "+near+" holds ritueel.yaml") {
		t.Errorf("(%d, %q), want the nearest folder %s", int(r.code), r.stderr, near)
	}
}

// A bundle that "new" made is itself such a folder: a second "new" in it, or in one of its folders, is refused.
func TestNewDoesNotMakeABundleInsideABundleThatNewMade(t *testing.T) {
	root := t.TempDir()
	outer := filepath.Join(root, "outer")
	if r := run(t, "new", outer); r.code != ExitOK {
		t.Fatalf("(%d, %q)", int(r.code), r.stderr)
	}
	before := crqSnapshot(t, root)
	for _, rel := range []string{"inner", "want/inner", "want/roots/inner"} {
		r := run(t, "new", filepath.Join(outer, rel))
		if !strings.Contains(r.stderr, "the folder "+outer+" holds ritueel.yaml") {
			t.Errorf("%s: (%d, %q)", rel, int(r.code), r.stderr)
		}
		if r.code != ExitFailure {
			t.Errorf("%s: exit code %d, want 1", rel, int(r.code))
		}
	}
	crqSame(t, "new", before, crqSnapshot(t, root))
}

// A name that only looks like the name, and a folder beside the folders above, do not stop "new".
func TestNewIsNotStoppedByANameThatOnlyLooksLikeRitueelYamlOrByASiblingBundle(t *testing.T) {
	root := t.TempDir()
	above := filepath.Join(root, "above")
	parent := filepath.Join(above, "parent")
	must(t, os.MkdirAll(parent, 0o755))
	for _, name := range []string{"ritueel.yml", "ritueel.yaml.bak", "xritueel.yaml", "ritueel.yaml~", ".ritueel.yaml", "ritueel.yaml "} {
		must(t, os.WriteFile(filepath.Join(above, name), []byte(newSettingsText), 0o644))
		must(t, os.WriteFile(filepath.Join(parent, name), []byte(newSettingsText), 0o644))
	}
	// A bundle beside the parent, and one beside the folder above it, are not folders above.
	must(t, os.MkdirAll(filepath.Join(above, "sibling"), 0o755))
	must(t, os.WriteFile(filepath.Join(above, "sibling", "ritueel.yaml"), []byte(newSettingsText), 0o644))
	must(t, os.MkdirAll(filepath.Join(root, "uncle"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "uncle", "ritueel.yaml"), []byte(newSettingsText), 0o644))
	r := run(t, "new", filepath.Join(parent, "acme"))
	if r.code != ExitOK {
		t.Fatalf("(%d, %q, %q), want exit code 0", int(r.code), r.stdout, r.stderr)
	}
	if info, err := os.Lstat(filepath.Join(parent, "acme", "ritueel.yaml")); err != nil || !info.Mode().IsRegular() {
		t.Errorf("no bundle was made: %v", err)
	}
}

// The folders above are the ones on the disk: a link on the way is followed for the folders above, and a link that
// leads out of a bundle leaves it.
func TestNewReadsTheFoldersAboveAsTheyAreOnTheDisk(t *testing.T) {
	t.Run("a link into a bundle", func(t *testing.T) {
		root := t.TempDir()
		bundleDir := filepath.Join(root, "bundle")
		must(t, os.MkdirAll(filepath.Join(bundleDir, "sub"), 0o755))
		must(t, os.WriteFile(filepath.Join(bundleDir, "ritueel.yaml"), []byte(newSettingsText), 0o644))
		must(t, os.Symlink(bundleDir, filepath.Join(root, "link")))
		before := crqSnapshot(t, root)
		realBundle, err := filepath.EvalSymlinks(bundleDir)
		must(t, err)
		r := run(t, "new", filepath.Join(root, "link", "sub", "acme"))
		if r.code != ExitFailure || !strings.Contains(r.stderr, "the folder "+realBundle+" holds ritueel.yaml") {
			t.Errorf("(%d, %q), want the folder on the disk %s", int(r.code), r.stderr, realBundle)
		}
		crqSame(t, "new", before, crqSnapshot(t, root))
	})
	t.Run("a link out of a bundle", func(t *testing.T) {
		root := t.TempDir()
		bundleDir, other := filepath.Join(root, "bundle"), filepath.Join(root, "other")
		must(t, os.MkdirAll(bundleDir, 0o755))
		must(t, os.MkdirAll(filepath.Join(other, "sub"), 0o755))
		must(t, os.WriteFile(filepath.Join(bundleDir, "ritueel.yaml"), []byte(newSettingsText), 0o644))
		must(t, os.Symlink(other, filepath.Join(bundleDir, "out")))
		r := run(t, "new", filepath.Join(bundleDir, "out", "sub", "acme"))
		if r.code != ExitOK {
			t.Fatalf("(%d, %q), want exit code 0: the folder on the disk is not in the bundle", int(r.code), r.stderr)
		}
		if _, err := os.Lstat(filepath.Join(other, "sub", "acme", "ritueel.yaml")); err != nil {
			t.Errorf("the bundle is not where the disk says: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(bundleDir, "acme")); err == nil {
			t.Error("something was made in the folder that holds the link")
		}
	})
}

// A folder above that can be passed but not listed (no read bit) is looked at by the name, and the folders above it are
// still read. The folder that holds the name and cannot be listed refuses too: new_small_test.go.
func TestNewStillReadsTheFoldersAboveOneThatCannotBeOpened(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a process that is root opens every folder")
	}
	root := t.TempDir()
	top := filepath.Join(root, "top")
	mid := filepath.Join(top, "mid")
	low := filepath.Join(mid, "low")
	must(t, os.MkdirAll(low, 0o755))
	must(t, os.WriteFile(filepath.Join(top, "ritueel.yaml"), []byte(newSettingsText), 0o644))
	must(t, os.Chmod(mid, 0o300)) // search and write, no read
	t.Cleanup(func() { _ = os.Chmod(mid, 0o755) })
	r := run(t, "new", filepath.Join(low, "acme"))
	if r.code != ExitFailure || !strings.Contains(r.stderr, "the folder "+top+" holds ritueel.yaml") {
		t.Errorf("(%d, %q), want the folder %s above the one that cannot be opened", int(r.code), r.stderr, top)
	}
}

// The parent folder itself holds the name: DIR is made inside a bundle's own folder.
func TestNewInTheFolderOfABundleIsRefusedAndDoesNotTouchTheBundle(t *testing.T) {
	root := t.TempDir()
	bundleDir := filepath.Join(root, "b")
	if r := run(t, "new", bundleDir); r.code != ExitOK {
		t.Fatal(r.stderr)
	}
	before := crqSnapshot(t, root)
	r := run(t, "--output", "json", "new", filepath.Join(bundleDir, "other"))
	if r.code != ExitFailure {
		t.Fatalf("(%d, %q)", int(r.code), r.stderr)
	}
	obj := object(t, r.stdout)
	msg, _ := obj["error"].(string)
	if !strings.Contains(msg, "the folder "+bundleDir+" holds ritueel.yaml") {
		t.Errorf("error = %q", msg)
	}
	crqSame(t, "new", before, crqSnapshot(t, root))
	// check history still reads the bundle that was not changed.
	if h := chHist(t, bundleDir); h.code != ExitOK {
		t.Errorf("check history: (%d, %q)", int(h.code), h.stderr)
	}
}

// The name of the folder that holds ritueel.yaml is a text of a person and goes through the escape, in both modes.
func TestTheNameOfTheFolderThatHoldsRitueelYamlIsEscaped(t *testing.T) {
	root := t.TempDir()
	holder := filepath.Join(root, "ho\nl\x1b[31m\u0435der")
	parent := filepath.Join(holder, "mid")
	must(t, os.MkdirAll(parent, 0o755))
	must(t, os.WriteFile(filepath.Join(holder, "ritueel.yaml"), nil, 0o644))
	for _, args := range [][]string{{"new", filepath.Join(parent, "acme")}, {"--output", "json", "new", filepath.Join(parent, "acme")}} {
		r := run(t, args...)
		if r.code != ExitFailure || !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Fatalf("%v: (%d, %q, %q)", args, int(r.code), r.stdout, r.stderr)
		}
		bs := string(rune(92))
		if !strings.Contains(r.stderr, "ho"+bs+"u000al"+bs+"u001b[31m"+bs+"u0435der") || strings.Count(r.stderr, "\n") != 1 {
			t.Errorf("%v: standard error = %q, want the name escaped on one line", args, r.stderr)
		}
	}
}
