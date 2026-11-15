//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Small faults of "new": a folder above DIR that can be passed but not listed (point 1), and the names of folders and
// files in the texts (point 5). Every mode test skips when the process is root, because root passes and lists every
// folder whatever its mode.

func skipMode(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the process is root: root passes and lists every folder whatever its mode")
	}
}

// exact writes a name the way the one-to-one escape of a name from a file system does, with a table of its own so that
// the expected text does not come from the code under test: a backslash doubled, a space as \x20, a byte that is not
// UTF-8 as \xNN, a control character as \uXXXX.
var exact = strings.NewReplacer(`\`, `\\`, " ", `\x20`, "\xff", `\xff`, "\x1b", `\u001b`, "\n", `\u000a`)

// nestedTree makes root/d1/inner/deep and returns the real paths.
func nestedTree(t *testing.T) (root, d1, deep string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	d1 = filepath.Join(root, "d1")
	deep = filepath.Join(d1, "inner", "deep")
	must(t, os.MkdirAll(deep, 0o755))
	return root, d1, deep
}

func restore(t *testing.T, p string) {
	t.Helper()
	t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
}

// A folder above that is passed and not listed and that holds the name stops "new": exit code 1, the folder is
// named, nothing is written, and the person is not told to remove a folder that was never made. Every kind of thing in
// the place of the name, in the modes that were passed over before.
func TestNewRefusesAHolderThatCanBePassedButNotListed(t *testing.T) {
	skipMode(t)
	for _, mode := range []os.FileMode{0o311, 0o111, 0o711, 0o755, 0o555} {
		for kind, put := range settingsKinds {
			t.Run(mode.String()+" "+kind, func(t *testing.T) {
				root, d1, deep := nestedTree(t)
				put(t, filepath.Join(d1, "ritueel.yaml"))
				before := crqShape(t, root)
				must(t, os.Chmod(d1, mode))
				restore(t, d1)
				dir := filepath.Join(deep, "dir")
				for _, args := range [][]string{{"new", dir}, {"--output", "json", "new", "--test-root", dir}} {
					r := run(t, args...)
					if r.code != ExitFailure {
						t.Fatalf("%v: (%d, %q, %q), want exit code 1", args, int(r.code), r.stdout, r.stderr)
					}
					want := "ritueel: bundle: cannot make the bundle " + dir + ": the folder was not made: the folder " + d1 +
						" holds ritueel.yaml: " + nestedMark + "\n"
					if r.stderr != want {
						t.Errorf("%v: standard error = %q, want %q", args, r.stderr, want)
					}
					if args[0] == "--output" {
						obj := object(t, r.stdout)
						if msg, _ := obj["error"].(string); msg != strings.TrimSuffix(strings.TrimPrefix(want, "ritueel: "), "\n") || obj["outcome"] != "failed" {
							t.Errorf("object = %v", obj)
						}
					} else if r.stdout != "" {
						t.Errorf("standard output = %q", r.stdout)
					}
				}
				must(t, os.Chmod(d1, 0o755))
				crqSame(t, "new", before, crqShape(t, root))
			})
		}
	}
}

// The neighbours: a folder above that can be passed and holds no such name does not stop "new", in any mode.
func TestNewMakesTheBundleBelowAFolderThatCanBePassedButNotListedAndHoldsNoName(t *testing.T) {
	skipMode(t)
	for _, mode := range []os.FileMode{0o311, 0o111, 0o711, 0o755, 0o555} {
		t.Run(mode.String(), func(t *testing.T) {
			_, d1, deep := nestedTree(t)
			must(t, os.WriteFile(filepath.Join(d1, "ritueel.yml"), nil, 0o644))
			must(t, os.Chmod(d1, mode))
			restore(t, d1)
			r := run(t, "new", filepath.Join(deep, "dir"))
			if r.code != ExitOK || !strings.HasPrefix(r.stdout, "made the bundle "+filepath.Join(deep, "dir")+"\n") {
				t.Fatalf("(%d, %q, %q), want exit code 0", int(r.code), r.stdout, r.stderr)
			}
			must(t, os.Chmod(d1, 0o755))
			if _, err := os.Stat(filepath.Join(deep, "dir", "ritueel.yaml")); err != nil {
				t.Error(err)
			}
		})
	}
}

// A folder above with no pass bit: the parent cannot be reached by its path, the command stops at the parent, exit
// code 1, nothing written. One case for the mode 000 and one for a mode that has read and no pass bit.
func TestNewStopsAtAParentThatCannotBeReached(t *testing.T) {
	skipMode(t)
	for _, mode := range []os.FileMode{0o000, 0o644} {
		t.Run(mode.String(), func(t *testing.T) {
			root, d1, deep := nestedTree(t)
			must(t, os.WriteFile(filepath.Join(d1, "ritueel.yaml"), nil, 0o644))
			before := crqShape(t, root)
			must(t, os.Chmod(d1, mode))
			restore(t, d1)
			for _, args := range [][]string{{"new", filepath.Join(deep, "dir")}, {"--output", "json", "new", filepath.Join(deep, "dir")}} {
				r := run(t, args...)
				if r.code != ExitFailure || !strings.Contains(r.stderr, "the parent folder cannot be opened") || strings.Contains(r.stderr, "remove it") {
					t.Errorf("%v: (%d, %q), want exit code 1 and the words that the parent cannot be opened", args, int(r.code), r.stderr)
				}
			}
			must(t, os.Chmod(d1, 0o755))
			crqSame(t, "new", before, crqShape(t, root))
		})
	}
}

// The parent can be opened by a relative path but a folder above it cannot be examined: the command stops with exit
// code 1, names the folder that could not be examined, and writes nothing. A check that cannot run is not a pass.
func TestNewStopsWhenAFolderAboveCannotBeExaminedAndNamesIt(t *testing.T) {
	skipMode(t)
	root, d1, deep := nestedTree(t)
	// A holder further up makes the point: the answer is an error and not "the name is not in the reach".
	must(t, os.WriteFile(filepath.Join(root, "ritueel.yaml"), nil, 0o644))
	t.Chdir(deep)
	must(t, os.Chmod(d1, 0o600))
	restore(t, d1)
	want := "the folder " + deep + " cannot be examined for ritueel.yaml: permission denied"
	for _, args := range [][]string{{"new", "dir"}, {"--output", "json", "new", "dir"}} {
		r := run(t, args...)
		if r.code != ExitFailure || !strings.Contains(r.stderr, want) || !strings.Contains(r.stderr, "the folder was not made") || strings.Contains(r.stderr, "remove it") {
			t.Errorf("%v: (%d, %q, %q), want exit code 1 and %q", args, int(r.code), r.stdout, r.stderr, want)
		}
		if strings.Count(r.stderr, "\n") != 1 || !onlyPrintable(r.stderr) {
			t.Errorf("%v: standard error = %q, want one printable line", args, r.stderr)
		}
		if args[0] == "--output" {
			obj := object(t, r.stdout)
			if msg, _ := obj["error"].(string); !strings.Contains(msg, want) || obj["outcome"] != "failed" || obj["exit_code"] != jsonNumber("1") {
				t.Errorf("object = %v", obj)
			}
		}
	}
	must(t, os.Chmod(d1, 0o755))
	if entries, err := os.ReadDir(deep); err != nil || len(entries) != 0 {
		t.Errorf("the folder holds %v (%v), want nothing", entries, err)
	}
}

// A relative DIR, and a DIR reached through a link, name the folder on the disk.
func TestNewWithARelativeDirOrADirThroughALinkNamesTheHolderOnTheDisk(t *testing.T) {
	skipMode(t)
	root, d1, deep := nestedTree(t)
	must(t, os.WriteFile(filepath.Join(d1, "ritueel.yaml"), nil, 0o644))
	must(t, os.Symlink(d1, filepath.Join(root, "link")))
	must(t, os.Chmod(d1, 0o311))
	restore(t, d1)
	want := "the folder " + d1 + " holds ritueel.yaml: " + nestedMark
	t.Chdir(root)
	for _, dir := range []string{"d1/inner/deep/dir", "./d1/inner/deep/dir", "link/inner/deep/dir", filepath.Join(root, "link", "inner", "deep", "dir")} {
		r := run(t, "new", dir)
		if r.code != ExitFailure || !strings.Contains(r.stderr, want) {
			t.Errorf("%s: (%d, %q), want exit code 1 and %q", dir, int(r.code), r.stderr, want)
		}
	}
	must(t, os.Chmod(d1, 0o755))
	if entries, _ := os.ReadDir(deep); len(entries) != 0 {
		t.Errorf("the parent holds %v", entries)
	}
}

// The names that "new" prints are written one to one. A DIR whose folders have a space, a backslash and a byte that
// is not UTF-8 reads back as the one name: the success line, and the folder above that holds the name.
func TestTheNamesThatNewPrintsAreEscapedOneToOne(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	must(t, err)
	parent := filepath.Join(root, "my par\\ent\xff")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Skipf("this file system does not take the name: %v", err)
	}
	dir := filepath.Join(parent, "acme")
	r := run(t, "new", dir)
	if r.code != ExitOK {
		t.Fatalf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	line := strings.SplitN(r.stdout, "\n", 2)[0]
	if want := "made the bundle " + exact.Replace(dir); line != want {
		t.Errorf("the first line = %q, want %q", line, want)
	}
	for _, l := range strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")[1:] {
		if strings.Contains(l, `\x`) && !strings.HasPrefix(l, "no key") && !strings.HasPrefix(l, "this is") {
			t.Errorf("the line of a file holds an escape: %q", l)
		}
	}
	if !onlyPrintable(r.stdout) {
		t.Errorf("standard output is not printable ASCII: %q", r.stdout)
	}
	// The folder that holds the name is written the same way.
	r = run(t, "new", filepath.Join(dir, "want", "inner"))
	want := "the folder " + exact.Replace(dir) + " holds ritueel.yaml: " + nestedMark
	if r.code != ExitFailure || !strings.Contains(r.stderr, want) {
		t.Errorf("(%d, %q), want exit code 1 and %q", int(r.code), r.stderr, want)
	}
	// Two folders that Escape would write alike are two texts: the byte 0xff and the character U+FFFD.
	other := filepath.Join(root, "my par\\ent�")
	must(t, os.Mkdir(other, 0o755))
	r2 := run(t, "new", filepath.Join(other, "acme"))
	line2 := strings.SplitN(r2.stdout, "\n", 2)[0]
	if r2.code != ExitOK || line2 == line {
		t.Errorf("the lines for two different folders are alike: %q and %q", line, line2)
	}
}
