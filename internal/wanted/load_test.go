package wanted_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The loaders read through package fsx: no link is followed, only a regular file is read, and a file over the
// limit is refused.

func bundleFiles() map[string]string {
	return map[string]string{
		"ritueel.yaml":                       goodSettings,
		"want/roots/acme-tls.yaml":           "version: 1\nkind: x509\n",
		"want/roots/acme-release.yaml":       "version: 1\nkind: openpgp\n",
		"want/roots/acme-ssh.yaml":           "version: 1\nkind: ssh\n",
		"want/delegations/acme-tls.yaml":     goodX509Delegation,
		"want/delegations/acme-release.yaml": goodOpenPGPDelegation,
		"want/delegations/acme-ssh.yaml":     goodSSHDelegation,
	}
}

func TestEveryLoaderReadsItsFileThroughTheFolder(t *testing.T) {
	_, fsys := bundleDir(t, bundleFiles())
	s, err := wanted.LoadSettings(fsys)
	if err != nil || !s.Valid() || s.File.Path != "ritueel.yaml" || string(s.File.Data) != goodSettings {
		t.Fatalf("settings %+v, error %v", s, err)
	}
	for name, typ := range map[string]string{"acme-tls": wanted.TypeX509Intermediate, "acme-release": wanted.TypeOpenPGPSubkey, "acme-ssh": wanted.TypeSSHCAKey} {
		d, err := wanted.LoadDelegation(fsys, name, s)
		if err != nil || !d.Valid() || d.Type != typ || d.Name != name {
			t.Errorf("delegation %s: %+v, %v", name, d, err)
		}
	}
	for name, kind := range map[string]wanted.RootKind{"acme-tls": wanted.RootX509, "acme-release": wanted.RootOpenPGP, "acme-ssh": wanted.RootSSH} {
		r, err := wanted.LoadRoot(fsys, name)
		if err != nil || !r.Valid() || r.Kind != kind || r.Name != name {
			t.Errorf("root %s: %+v, %v", name, r, err)
		}
	}
}

func TestAMissingFileIsAnErrorThatSaysSo(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{"x": "x"})
	s := mustSettings(t, goodSettings)
	_, err := wanted.LoadSettings(fsys)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("settings: %v", err)
	}
	_ = wantFault(t, err, "ritueel.yaml", 0, "it does not exist")
	_, err = wanted.LoadDelegation(fsys, "acme-tls", s)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("delegation: %v", err)
	}
	_ = wantFault(t, err, "want/delegations/acme-tls.yaml", 0, "it does not exist")
	_, err = wanted.LoadRoot(fsys, "acme-tls")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("root: %v", err)
	}
	_ = wantFault(t, err, "want/roots/acme-tls.yaml", 0, "it does not exist")
}

func TestAFaultOfTheTextHasNoCause(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{"ritueel.yaml": "version: 2\n"})
	_, err := wanted.LoadSettings(fsys)
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error %v", err)
	}
	var e *wanted.Error
	if !errors.As(err, &e) || e.Unwrap() != nil {
		t.Errorf("the fault of a text wraps %v", e.Unwrap())
	}
}

func TestADelegationWhoseRootIsMissingNamesTheDelegation(t *testing.T) {
	files := bundleFiles()
	delete(files, "want/roots/acme-tls.yaml")
	_, fsys := bundleDir(t, files)
	_, err := wanted.LoadDelegation(fsys, "acme-tls", mustSettings(t, goodSettings))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error %v", err)
	}
	_ = wantFault(t, err, "want/roots/acme-tls.yaml", 0, "it does not exist", "the root of the delegation acme-tls")
}

func TestADelegationWhoseRootIsOfAnotherKindIsRefused(t *testing.T) {
	s := mustSettings(t, goodSettings)
	for _, tc := range []struct {
		delegation, rootKind string
		ok                   bool
	}{
		{goodX509Delegation, "x509", true}, {goodX509Delegation, "openpgp", false}, {goodX509Delegation, "ssh", false},
		{goodOpenPGPDelegation, "openpgp", true}, {goodOpenPGPDelegation, "x509", false}, {goodOpenPGPDelegation, "ssh", false},
		{goodSSHDelegation, "ssh", true}, {goodSSHDelegation, "x509", false}, {goodSSHDelegation, "openpgp", false},
	} {
		root := "acme-tls"
		if strings.Contains(tc.delegation, "openpgp") {
			root = "acme-release"
		} else if strings.Contains(tc.delegation, "ssh-ca") {
			root = "acme-ssh"
		}
		_, fsys := bundleDir(t, map[string]string{
			"want/delegations/example.yaml": tc.delegation,
			"want/roots/" + root + ".yaml":  "version: 1\nkind: " + tc.rootKind + "\n",
		})
		d, err := wanted.LoadDelegation(fsys, "example", s)
		if tc.ok {
			if err != nil || !d.Valid() {
				t.Errorf("%s over %s: %v", tc.delegation, tc.rootKind, err)
			}
			continue
		}
		if d != nil {
			t.Errorf("a value beside the error")
		}
		_ = wantFault(t, err, delegationPath, 0, "is of the kind "+tc.rootKind, "needs the kind")
	}
}

func TestADelegationWhoseRootFailsItsOwnCheckIsRefusedWithTheRootsPath(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{
		"want/delegations/example.yaml": goodX509Delegation,
		"want/roots/acme-tls.yaml":      "version: 1\nkind: x509\nretire_at: 2\n",
	})
	d, err := wanted.LoadDelegation(fsys, "example", mustSettings(t, goodSettings))
	if d != nil {
		t.Error("a value beside the error")
	}
	_ = wantFault(t, err, "want/roots/acme-tls.yaml", 3, "not read yet", "the root of the delegation example")
}

func TestALoaderRefusesALinkAFolderAndAPipeInPlaceOfAFile(t *testing.T) {
	dir, fsys := bundleDir(t, bundleFiles())
	s := mustSettings(t, goodSettings)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "real.yaml"), []byte(goodRoot), 0o644); err != nil {
		t.Fatal(err)
	}
	rootsDir := filepath.Join(dir, "want", "roots")
	delDir := filepath.Join(dir, "want", "delegations")
	// A link as the file.
	if err := os.Symlink(filepath.Join(outside, "real.yaml"), filepath.Join(rootsDir, "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	_, err := wanted.LoadRoot(fsys, "linked")
	if !errors.Is(err, fsx.ErrLink) {
		t.Errorf("a link: %v", err)
	}
	_ = wantFault(t, err, "want/roots/linked.yaml", 0, "a link is not followed")
	// A link to a file inside the bundle is a link as well.
	if err := os.Symlink(filepath.Join(rootsDir, "acme-tls.yaml"), filepath.Join(rootsDir, "inside.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := wanted.LoadRoot(fsys, "inside"); !errors.Is(err, fsx.ErrLink) {
		t.Errorf("a link inside the bundle: %v", err)
	}
	// A dangling link.
	if err := os.Symlink(filepath.Join(outside, "nothing"), filepath.Join(rootsDir, "dangling.yaml")); err != nil {
		t.Fatal(err)
	}
	if r, err := wanted.LoadRoot(fsys, "dangling"); r != nil || err == nil {
		t.Errorf("a dangling link: %v %v", r, err)
	}
	// A folder named x.yaml.
	if err := os.Mkdir(filepath.Join(delDir, "folder.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = wanted.LoadDelegation(fsys, "folder", s)
	if !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("a folder: %v", err)
	}
	_ = wantFault(t, err, "want/delegations/folder.yaml", 0, "not a regular file")
	// A pipe: the read does not wait for a writer.
	if err := syscall.Mkfifo(filepath.Join(rootsDir, "pipe.yaml"), 0o644); err != nil {
		t.Skipf("no pipe: %v", err)
	}
	_, err = wanted.LoadRoot(fsys, "pipe")
	if !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("a pipe: %v", err)
	}
	_ = wantFault(t, err, "want/roots/pipe.yaml", 0, "not a regular file")
	// ritueel.yaml as a link, and as a folder.
	dir2, fsys2 := bundleDir(t, nil)
	if err := os.Symlink(filepath.Join(dir, "ritueel.yaml"), filepath.Join(dir2, "ritueel.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := wanted.LoadSettings(fsys2); !errors.Is(err, fsx.ErrLink) {
		t.Errorf("ritueel.yaml as a link: %v", err)
	}
	dir3, fsys3 := bundleDir(t, nil)
	if err := os.Mkdir(filepath.Join(dir3, "ritueel.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := wanted.LoadSettings(fsys3); !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("ritueel.yaml as a folder: %v", err)
	}
	// A link as a folder of the path: want/ itself is a link to a folder.
	dir4, fsys4 := bundleDir(t, map[string]string{})
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "roots"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "roots", "x509.yaml"), []byte(goodRoot), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir4, "want")); err != nil {
		t.Fatal(err)
	}
	r, err := wanted.LoadRoot(fsys4, "x509")
	if r != nil || err == nil {
		t.Errorf("a root under a linked want/: %v %v", r, err)
	}
}

func TestOnlyTheNamedFileIsRead(t *testing.T) {
	// A bad file beside the one that is asked for fails nothing: no loader lists a folder.
	files := bundleFiles()
	files["want/delegations/bad.yaml"] = "not: [valid"
	files["want/roots/bad.yaml"] = "- nope"
	files["want/delegations/other.yml"] = "x"
	files["want/roots/Upper.yaml"] = "x"
	_, fsys := bundleDir(t, files)
	s, err := wanted.LoadSettings(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wanted.LoadDelegation(fsys, "acme-tls", s); err != nil {
		t.Errorf("a bad neighbour stopped the load: %v", err)
	}
}

func TestAFileWithTheWrongExtensionOrCaseIsNotTheFileOfAName(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{
		"want/roots/x509.yml":    goodRoot,
		"want/roots/X509.yaml":   goodRoot,
		"want/roots/other.YAML":  goodRoot,
		"want/roots/another.txt": goodRoot,
	})
	for _, name := range []string{"x509", "X509", "other", "another"} {
		if r, err := wanted.LoadRoot(fsys, name); r != nil || err == nil {
			t.Errorf("%s: %v %v", name, r, err)
		}
	}
}

func TestALoaderRefusesAFileOverTheLimitBeforeParsingIt(t *testing.T) {
	big := goodSettings + "# " + strings.Repeat("x", wanted.MaxBytes)
	_, fsys := bundleDir(t, map[string]string{"ritueel.yaml": big})
	_, err := wanted.LoadSettings(fsys)
	_ = wantFault(t, err, "ritueel.yaml", 0, "longer than")
	// A file over what package fsx reads at all.
	huge := strings.Repeat("a", fsx.MaxReadSize+1)
	_, fsys = bundleDir(t, map[string]string{"ritueel.yaml": huge})
	_, err = wanted.LoadSettings(fsys)
	if !errors.Is(err, fsx.ErrTooLarge) {
		t.Errorf("a file over the read limit: %v", err)
	}
	_ = wantFault(t, err, "ritueel.yaml", 0, "too long")
	// A file of MaxBytes is read.
	exact := goodSettings + "# " + strings.Repeat("x", wanted.MaxBytes-len(goodSettings)-3) + "\n"
	_, fsys = bundleDir(t, map[string]string{"ritueel.yaml": exact})
	if s, err := wanted.LoadSettings(fsys); err != nil || len(s.File.Data) != wanted.MaxBytes {
		t.Errorf("a file of the limit: %v", err)
	}
}

func TestALoaderWithNoFolderOrAClosedOneIsAnError(t *testing.T) {
	if s, err := wanted.LoadSettings(nil); s != nil || err == nil {
		t.Errorf("a nil folder: %v %v", s, err)
	} else {
		_ = wantFault(t, err, "ritueel.yaml", 0, "no folder")
	}
	if d, err := wanted.LoadDelegation(nil, "x", mustSettings(t, goodSettings)); d != nil || err == nil {
		t.Errorf("a nil folder: %v %v", d, err)
	}
	if r, err := wanted.LoadRoot(nil, "x"); r != nil || err == nil {
		t.Errorf("a nil folder: %v %v", r, err)
	}
	_, fsys := bundleDir(t, bundleFiles())
	if err := fsys.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := wanted.LoadSettings(fsys); s != nil || err == nil {
		t.Errorf("a closed folder: %v %v", s, err)
	}
}

func TestADelegationNameThatIsNotAFileNameIsRefusedBeforeAnyRead(t *testing.T) {
	_, fsys := bundleDir(t, bundleFiles())
	s := mustSettings(t, goodSettings)
	for _, name := range []string{"", "../ritueel", "a/b", "break-glass-x", "A", ".rt-x", "a.yaml"} {
		d, err := wanted.LoadDelegation(fsys, name, s)
		if d != nil || err == nil {
			t.Errorf("%q: %v %v", name, d, err)
		}
		if errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%q was looked for in the folder: %v", name, err)
		}
	}
}

func TestTheBytesAndTheDigestAreOfTheFileAsStored(t *testing.T) {
	// The bytes are kept as they are: no final line feed, comments, quotes and spaces as written.
	for name, text := range map[string]string{
		"a plain file":        goodSettings,
		"no final line feed":  strings.TrimSuffix(goodSettings, "\n"),
		"comments and quotes": "# a\n---\n" + strings.Replace(goodSettings, "name: Example", `name: "Example" # b`, 1),
		"trailing spaces":     strings.Replace(goodSettings, "version: 1\n", "version: 1   \n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			in := []byte(text)
			s, err := wanted.ParseSettings(settingsPath, in)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(s.File.Data, in) || s.File.Path != settingsPath {
				t.Errorf("the bytes or the path differ: %q", s.File.Data)
			}
			if s.File.SHA256 != sha256hex(in) || len(s.File.SHA256) != 64 || s.File.SHA256 != strings.ToLower(s.File.SHA256) {
				t.Errorf("digest %s", s.File.SHA256)
			}
			// The reader keeps its own copy: a change to the caller's bytes changes nothing in the value.
			for i := range in {
				in[i] = 'Z'
			}
			if string(s.File.Data) != text || s.File.SHA256 != sha256hex([]byte(text)) {
				t.Error("the value shares memory with the caller's bytes")
			}
			// A second reading gives equal values with no shared memory.
			again, err := wanted.ParseSettings(settingsPath, []byte(text))
			if err != nil {
				t.Fatal(err)
			}
			if again.File.SHA256 != s.File.SHA256 || !bytes.Equal(again.File.Data, s.File.Data) || !equalSettings(s, again) {
				t.Error("two readings of the same bytes differ")
			}
			again.File.Data[0] = 'Q'
			if s.File.Data[0] == 'Q' {
				t.Error("two values share memory")
			}
		})
	}
	// Two files that differ in one byte have two digests, and so do two that differ in the final line feed.
	a := mustSettings(t, goodSettings)
	b := mustSettings(t, strings.TrimSuffix(goodSettings, "\n"))
	if a.File.SHA256 == b.File.SHA256 {
		t.Error("a final line feed does not change the digest")
	}
	// The same holds for a delegation and a root.
	d := mustDelegation(t, "example", goodX509Delegation)
	if d.File.SHA256 != sha256hex([]byte(goodX509Delegation)) || string(d.File.Data) != goodX509Delegation {
		t.Errorf("delegation file %+v", d.File)
	}
	r := mustRoot(t, "x509", goodRoot)
	if r.File.SHA256 != sha256hex([]byte(goodRoot)) || string(r.File.Data) != goodRoot || r.File.Path != rootFilePath {
		t.Errorf("root file %+v", r.File)
	}
}

func TestALoaderGivesTheBytesOfTheFileOnDisk(t *testing.T) {
	text := "# comment\n" + goodSettings
	dir, fsys := bundleDir(t, map[string]string{"ritueel.yaml": text})
	s, err := wanted.LoadSettings(fsys)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(filepath.Join(dir, "ritueel.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.File.Data, disk) || s.File.SHA256 != sha256hex(disk) {
		t.Error("the bytes or the digest are not those of the file")
	}
	// The loader never writes: the file is as it was, with its mode and time.
	after, err := os.ReadFile(filepath.Join(dir, "ritueel.yaml"))
	if err != nil || !bytes.Equal(after, disk) {
		t.Errorf("the file changed: %v", err)
	}
}
