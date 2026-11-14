package bundle_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The starter files of `new`: the text, as the page of the command gives it, byte for byte, with ASCII, LF line
// ends, a final line feed and no trailing space. The name and the address are examples that are not real.

const goldenSettings = `# The settings of this bundle. A person writes this file; ritueel never changes it.
version: 1
name: Example                    # in the names of the root keys; 1 to 45 characters
release_address: release@example.org
policy:
  stores: [piv, openpgp-card, aws-kms]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`

const goldenSettingsTest = `# The settings of this bundle. A person writes this file; ritueel never changes it.
version: 1
name: Example                    # in the names of the root keys; 1 to 45 characters
release_address: release@example.org
policy:
  stores: [piv, openpgp-card, aws-kms, software]
  min_firmware: 5.7.0
  pin_policy: [once, always]
  require_name_constraints: true
  validity_months: 13
`

const goldenX509 = `# One X.509 root. Its keys are made by the first apply.
version: 1
kind: x509
test: false
`

const goldenOpenPGP = `# One OpenPGP root. Its keys are made by the first apply.
version: 1
kind: openpgp
test: false
`

const goldenX509Test = `# One X.509 root. Its keys are made by the first apply.
version: 1
kind: x509
test: true  # set at birth; a real root never becomes a test root
`

const goldenOpenPGPTest = `# One OpenPGP root. Its keys are made by the first apply.
version: 1
kind: openpgp
test: true  # set at birth; a real root never becomes a test root
`

type starterWant struct {
	path, text string
}

func goldenFor(testRoot bool) []starterWant {
	if testRoot {
		return []starterWant{{"want/roots/x509.yaml", goldenX509Test}, {"want/roots/openpgp.yaml", goldenOpenPGPTest}, {"ritueel.yaml", goldenSettingsTest}}
	}
	return []starterWant{{"want/roots/x509.yaml", goldenX509}, {"want/roots/openpgp.yaml", goldenOpenPGP}, {"ritueel.yaml", goldenSettings}}
}

func TestTheStarterFilesAreTheFilesOfThePage(t *testing.T) {
	for _, testRoot := range []bool{false, true} {
		files, err := bundle.Starter(bundle.StarterOptions{TestRoot: testRoot})
		if err != nil {
			t.Fatalf("test root %v: %v", testRoot, err)
		}
		want := goldenFor(testRoot)
		if len(files) != len(want) {
			t.Fatalf("test root %v: %d files, want %d", testRoot, len(files), len(want))
		}
		for i, f := range files {
			if f.Path != want[i].path {
				t.Errorf("test root %v: file %d is %s, want %s (ritueel.yaml is last)", testRoot, i, f.Path, want[i].path)
			}
			if string(f.Data) != want[i].text {
				t.Errorf("test root %v: %s differs from the golden text:\n%s", testRoot, f.Path, f.Data)
			}
			if f.SHA256 != sha256hex(f.Data) {
				t.Errorf("%s: digest %s", f.Path, f.SHA256)
			}
		}
	}
}

func TestEveryStarterFilePassesItsOwnReaderAndReadsAsMeant(t *testing.T) {
	for _, testRoot := range []bool{false, true} {
		files, err := bundle.Starter(bundle.StarterOptions{TestRoot: testRoot})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if !isPlainASCII(f.Data) || !bytes.HasSuffix(f.Data, []byte("\n")) || bytes.Contains(f.Data, []byte("\r")) || bytes.Contains(f.Data, []byte("\t")) {
				t.Errorf("%s: not plain ASCII with LF and a final LF", f.Path)
			}
			for i, line := range strings.Split(strings.TrimSuffix(string(f.Data), "\n"), "\n") {
				if strings.HasSuffix(line, " ") {
					t.Errorf("%s:%d ends with a space", f.Path, i+1)
				}
			}
			switch f.Path {
			case wanted.SettingsPath:
				s, err := wanted.ParseSettings(f.Path, f.Data)
				if err != nil || s.Name != "Example" || s.ReleaseAddress != "release@example.org" || s.Personal ||
					slices.Contains(s.Policy.Stores, "software") != testRoot || s.File.SHA256 != f.SHA256 {
					t.Errorf("%s: %+v %v", f.Path, s, err)
				}
			default:
				name := strings.TrimSuffix(filepath.Base(f.Path), ".yaml")
				r, err := wanted.ParseRoot(name, f.Data)
				if err != nil || r.Test != testRoot || string(r.Kind) != name || r.File.SHA256 != f.SHA256 {
					t.Errorf("%s: %+v %v", f.Path, r, err)
				}
			}
		}
		// Two calls give the same bytes and share no memory.
		again, _ := bundle.Starter(bundle.StarterOptions{TestRoot: testRoot})
		again[0].Data[0] ^= 0xff
		if files[0].Data[0] == again[0].Data[0] {
			t.Error("two calls share memory")
		}
	}
}

func isPlainASCII(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 && c != '\n') || c > 0x7e {
			return false
		}
	}
	return true
}

// The roots of a test bundle are marked, and those of a real one are not; software is a store of the policy only
// in a test bundle.
func TestOnlyATestBundleMarksItsRootsAndAllowsSoftware(t *testing.T) {
	real, _ := bundle.Starter(bundle.StarterOptions{})
	test, _ := bundle.Starter(bundle.StarterOptions{TestRoot: true})
	for _, f := range real {
		if bytes.Contains(f.Data, []byte("software")) || bytes.Contains(f.Data, []byte("test: true")) || bytes.Contains(f.Data, []byte("TEST")) {
			t.Errorf("%s of a real bundle holds a mark of a test bundle", f.Path)
		}
	}
	marks := 0
	for _, f := range test {
		if bytes.Contains(f.Data, []byte("test: true")) {
			marks++
		}
	}
	if marks != 2 {
		t.Errorf("%d root files are marked as test roots, want 2", marks)
	}
}

// Create.

func currentUmask() fs.FileMode {
	old := syscall.Umask(0)
	syscall.Umask(old)
	return fs.FileMode(old)
}

func TestCreateWritesTheStarterFilesAndNothingElse(t *testing.T) {
	for _, testRoot := range []bool{false, true} {
		parent := t.TempDir()
		dir := filepath.Join(parent, "acme")
		files, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: testRoot})
		if err != nil {
			t.Fatal(err)
		}
		want := goldenFor(testRoot)
		if len(files) != len(want) {
			t.Fatalf("%d files returned", len(files))
		}
		mask := currentUmask()
		for i, w := range want {
			got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(w.path)))
			if err != nil || string(got) != w.text {
				t.Errorf("%s: %v\n%s", w.path, err, got)
			}
			if files[i].Path != w.path || string(files[i].Data) != w.text {
				t.Errorf("the returned file %d is %s", i, files[i].Path)
			}
			info, err := os.Stat(filepath.Join(dir, filepath.FromSlash(w.path)))
			if err != nil || info.Mode().Perm() != 0o644&^mask {
				t.Errorf("%s: mode %v, want %v", w.path, info.Mode().Perm(), 0o644&^mask)
			}
		}
		// The folders, with their modes, and no other entry: no seen/, sealed/, roots/, requests/, history/, trust/,
		// drills/, no want/delegations or want/cards, and no leftover temporary name.
		var names []string
		for _, e := range listFiles(t, dir) {
			names = append(names, strings.Fields(e)[0])
		}
		wantNames := []string{"ritueel.yaml", "want/", "want/roots/", "want/roots/openpgp.yaml", "want/roots/x509.yaml"}
		if !slices.Equal(names, wantNames) {
			t.Errorf("the folder holds %v, want %v", names, wantNames)
		}
		for _, folder := range []string{dir, filepath.Join(dir, "want"), filepath.Join(dir, "want/roots")} {
			info, err := os.Stat(folder)
			if err != nil || info.Mode().Perm() != 0o755&^mask {
				t.Errorf("%s: mode %v", folder, info.Mode().Perm())
			}
		}
		// The parent holds the folder and nothing else.
		if ents, _ := os.ReadDir(parent); len(ents) != 1 || ents[0].Name() != "acme" {
			t.Errorf("the parent holds %d entries", len(ents))
		}
		// A bundle that Create made opens, and its files read as the starter says.
		b, err := bundle.Open(dir)
		if err != nil {
			t.Fatalf("Open of a new bundle: %v", err)
		}
		if b.Settings().File.SHA256 != files[2].SHA256 {
			t.Error("the digest of the settings differs from the one Create returned")
		}
		_ = b.Close()
		// The files are as Starter gives them: the digests are those of the bytes written.
		for _, f := range files {
			disk, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
			if sha256hex(disk) != f.SHA256 {
				t.Errorf("%s: the digest is not the digest of the file", f.Path)
			}
		}
	}
}

func TestCreateNeverWritesIntoWhatIsThere(t *testing.T) {
	parent := t.TempDir()
	type setup struct {
		name string
		make func(path string) error
	}
	for _, s := range []setup{
		{"a file", func(p string) error { return os.WriteFile(p, []byte("keep"), 0o644) }},
		{"an empty folder", func(p string) error { return os.Mkdir(p, 0o755) }},
		{"a folder with a file", func(p string) error {
			if err := os.Mkdir(p, 0o755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(p, "keep.txt"), []byte("keep"), 0o644)
		}},
		{"a link to a folder", func(p string) error { return os.Symlink(t.TempDir(), p) }},
		{"a link to nothing", func(p string) error { return os.Symlink(filepath.Join(parent, "nothing"), p) }},
		{"a link to a file", func(p string) error { return os.Symlink(filepath.Join(parent, "keep"), p) }},
		{"a pipe", func(p string) error { return syscall.Mkfifo(p, 0o644) }},
		{"a bundle", func(p string) error { _, err := bundle.Create(p, bundle.StarterOptions{}); return err }},
	} {
		t.Run(s.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(parent, "keep"), []byte("keep"), 0o644); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, strings.ReplaceAll(s.name, " ", "-"))
			if err := s.make(dir); err != nil {
				t.Fatal(err)
			}
			beforeParent := listFiles(t, parent)
			var beforeInside []string
			if info, err := os.Lstat(dir); err == nil && info.IsDir() {
				beforeInside = listFiles(t, dir)
			}
			files, err := bundle.Create(dir, bundle.StarterOptions{})
			if files != nil || err == nil {
				t.Fatalf("Create returned %v, %v", files, err)
			}
			var ce *bundle.CreateError
			if !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 || ce.Dir != dir {
				t.Errorf("error %T %+v", err, ce)
			}
			if !errors.Is(err, fs.ErrExist) {
				t.Errorf("the error does not say that the name is taken: %v", err)
			}
			if got := listFiles(t, parent); !slices.Equal(got, beforeParent) {
				t.Errorf("the parent changed: %v -> %v", beforeParent, got)
			}
			if info, err := os.Lstat(dir); err == nil && info.IsDir() {
				if got := listFiles(t, dir); !slices.Equal(got, beforeInside) {
					t.Errorf("the folder changed: %v -> %v", beforeInside, got)
				}
			}
			if s.name == "a link to a folder" {
				target, _ := os.Readlink(dir)
				if ents, _ := os.ReadDir(target); len(ents) != 0 {
					t.Errorf("something was written through the link: %d entries", len(ents))
				}
			}
			if got, _ := os.ReadFile(filepath.Join(parent, "keep")); string(got) != "keep" {
				t.Error("another file changed")
			}
		})
		_ = os.RemoveAll(filepath.Join(parent, strings.ReplaceAll(s.name, " ", "-")))
	}
}

func TestCreateTwiceMakesOneBundleAndFailsTheSecondTime(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	if _, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: true}); err != nil {
		t.Fatal(err)
	}
	before := listFiles(t, dir)
	read := func() []byte { b, _ := os.ReadFile(filepath.Join(dir, "ritueel.yaml")); return b }
	first := read()
	_, err := bundle.Create(dir, bundle.StarterOptions{})
	var ce *bundle.CreateError
	if !errors.As(err, &ce) || ce.Made {
		t.Fatalf("the second call: %v", err)
	}
	if !slices.Equal(listFiles(t, dir), before) || !bytes.Equal(read(), first) {
		t.Error("the second call changed the bundle")
	}
}

func TestCreateRefusesADirectoryItCannotMake(t *testing.T) {
	parent := t.TempDir()
	file := filepath.Join(parent, "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	realParent := t.TempDir()
	linkParent := filepath.Join(parent, "linkparent")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{
		"an empty name":                  "",
		"the root":                       "/",
		"a dot":                          ".",
		"a name with a space":            filepath.Join(parent, "a b"),
		"a name with a Cyrillic letter":  filepath.Join(parent, "\u0430cme"),
		"a name with an accent":          filepath.Join(parent, "caf\u00e9"),
		"a temporary name":               filepath.Join(parent, ".rt-abcdefghijk"),
		"a temporary name in upper case": filepath.Join(parent, ".RT-abcdefghijk"),
		"a name of 256 bytes":            filepath.Join(parent, strings.Repeat("a", 256)),
		"a device name of Windows":       filepath.Join(parent, "con"),
		"a name with a trailing dot":     filepath.Join(parent, "acme."),
		"a name with a newline":          filepath.Join(parent, "a\nb"),
		"a name with a backslash":        filepath.Join(parent, "a\\b"),
		"a name with a colon":            filepath.Join(parent, "a:b"),
		"a name with a NUL":              filepath.Join(parent, "a\x00b"),
		"a parent element":               parent + "/../x",
		"a parent at the end":            parent + "/..",
		"a parent in the middle":         parent + "/a/../b",
		"a parent that does not exist":   filepath.Join(parent, "nothing", "acme"),
		"a parent that is a file":        filepath.Join(file, "acme"),
		"a parent that is a link":        filepath.Join(linkParent, "acme"),
	} {
		t.Run(name, func(t *testing.T) {
			before := listFiles(t, parent)
			beforeReal := listFiles(t, realParent)
			files, err := bundle.Create(dir, bundle.StarterOptions{})
			if files != nil || err == nil {
				t.Fatalf("Create returned %v, %v", files, err)
			}
			var ce *bundle.CreateError
			if !errors.As(err, &ce) || ce.Made || len(ce.Written) != 0 {
				t.Errorf("error %T %v", err, err)
			}
			if !printableText(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII: %q", err.Error())
			}
			if got := listFiles(t, parent); !slices.Equal(got, before) {
				t.Errorf("the parent changed: %v -> %v", before, got)
			}
			if got := listFiles(t, realParent); !slices.Equal(got, beforeReal) {
				t.Errorf("the target of a link changed: %v", got)
			}
		})
	}
}

func printableText(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func TestCreateAcceptsEveryNameThatCheckNameAccepts(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{"acme", "a", "A", "acme-1", "acme_1", "acme.d", "9", strings.Repeat("a", 255)} {
		if fsx.CheckName(name) != nil {
			t.Fatalf("the test name %q is refused by CheckName", name)
		}
		if _, err := bundle.Create(filepath.Join(parent, name), bundle.StarterOptions{}); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	// A trailing separator and a doubled one are the same folder.
	if _, err := bundle.Create(filepath.Join(parent, "acme2")+"/", bundle.StarterOptions{}); err != nil {
		t.Errorf("a trailing separator: %v", err)
	}
	if _, err := bundle.Create(parent+"//acme3", bundle.StarterOptions{}); err != nil {
		t.Errorf("a doubled separator: %v", err)
	}
}

func TestACreateErrorTellsWhatItMadeAndWrapsItsCause(t *testing.T) {
	var none *bundle.CreateError
	if none.Error() == "" || none.Unwrap() != nil {
		t.Errorf("nil: %q %v", none.Error(), none.Unwrap())
	}
	cause := errors.New("disk full")
	notMade := &bundle.CreateError{Dir: "acme", Err: cause}
	if !errors.Is(notMade, cause) || !strings.Contains(notMade.Error(), "was not made") || !strings.Contains(notMade.Error(), "disk full") {
		t.Errorf("not made: %q", notMade.Error())
	}
	made := &bundle.CreateError{Dir: "ac\u202eme", Made: true, Written: []string{"want/", "want/roots/"}, Err: cause}
	if !strings.Contains(made.Error(), "was made") || !strings.Contains(made.Error(), "2 things") || !printableText(made.Error()) {
		t.Errorf("made: %q", made.Error())
	}
	if strings.Contains(made.Error(), "\u202e") {
		t.Error("the directory is not escaped")
	}
}
