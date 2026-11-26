//go:build linux || darwin

package keydir_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/keydir"
)

// The Dir that Open gives: whether the key directory was used (the table in the comment of Used, one case
// for each line), and the removal authorisations that ritueel keeps beside the folder of the keys.

const (
	jws      = "eyJhbGciOiJFUzM4NCJ9.eyJ2IjoxfQ.c2ln"
	jwsOther = "eyJhbGciOiJFUzM4NCJ9.eyJ2IjoyfQ.c2ln"
)

// open makes a bundle folder and a key directory side by side and opens the key directory.
func open(t *testing.T) (*keydir.Dir, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle, keys := filepath.Join(root, "bundle"), filepath.Join(root, "keys")
	for _, d := range []string{bundle, keys} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	d, err := keydir.Open(keys, bundle)
	if err != nil {
		t.Skipf("the key directory is refused (%v): the temporary folder is inside a work tree", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, keys
}

func names(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func folder(mode fs.FileMode) func(t *testing.T, keys string) {
	return func(t *testing.T, keys string) {
		t.Helper()
		p := filepath.Join(keys, keydir.TestOnlyFolder)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
}

func file(name string) func(t *testing.T, keys string) {
	return func(t *testing.T, keys string) {
		t.Helper()
		write(t, filepath.Join(keys, name), "x")
	}
}

func TestOpenRefusesWhatTheCheckRefusesAndGivesTheResolvedPath(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bundle, keys := filepath.Join(root, "bundle"), filepath.Join(root, "keys")
	for _, d := range []string{bundle, keys} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(root, "afile"), "x")
	for name, tc := range map[string][2]string{
		"missing":              {filepath.Join(root, "none"), bundle},
		"a file":               {filepath.Join(root, "afile"), bundle},
		"the bundle itself":    {bundle, bundle},
		"inside the bundle":    {filepath.Join(bundle, "inner"), bundle},
		"no key directory":     {"", bundle},
		"no bundle and no key": {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "inside the bundle" {
				if err := os.Mkdir(tc[0], 0o700); err != nil {
					t.Fatal(err)
				}
			}
			d, err := keydir.Open(tc[0], tc[1])
			if d != nil || err == nil {
				t.Fatalf("Open = %v, %v", d, err)
			}
			var r *keydir.Refusal
			if !errors.As(err, &r) || (!errors.Is(err, keydir.ErrKeyDir) && !errors.Is(err, keydir.ErrParams)) {
				t.Errorf("the error is %T %v, want a *Refusal of ErrKeyDir or ErrParams", err, err)
			}
			if strings.Contains(err.Error(), root) {
				t.Errorf("the text holds a path: %q", err)
			}
		})
	}
	// A link to the key directory is followed by the check, and the Dir holds the path that was checked.
	link := filepath.Join(root, "link")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	d, err := keydir.Open(link, bundle)
	if err != nil {
		t.Skipf("the temporary folder is inside a work tree: %v", err)
	}
	defer func() { _ = d.Close() }()
	if d.Path() != keys {
		t.Errorf("Path = %q, want the resolved %q", d.Path(), keys)
	}
}

func TestADirThatWasClosedOrWasNeverOpenedRefusesEveryCall(t *testing.T) {
	d, keys := open(t)
	if err := d.SaveRemoval("A", []byte(jws)); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Errorf("a second Close: %v", err)
	}
	for name, dir := range map[string]*keydir.Dir{"closed": d, "never opened": {}, "nil": nil} {
		t.Run(name, func(t *testing.T) {
			if _, err := dir.Used(); !errors.Is(err, keydir.ErrParams) {
				t.Errorf("Used = %v, want ErrParams", err)
			}
			if err := dir.SaveRemoval("B", []byte(jws)); !errors.Is(err, keydir.ErrParams) {
				t.Errorf("SaveRemoval = %v, want ErrParams", err)
			}
			if _, err := dir.ReadRemoval("A"); !errors.Is(err, keydir.ErrParams) {
				t.Errorf("ReadRemoval = %v, want ErrParams", err)
			}
		})
	}
	if got := names(t, keys); !slices.Equal(got, []string{"A.removal.jws"}) {
		t.Errorf("the key directory holds %q", got)
	}
	if got := (*keydir.Dir)(nil).Path(); got != "" {
		t.Errorf("Path of a nil Dir = %q", got)
	}
	if err := (*keydir.Dir)(nil).Close(); err != nil {
		t.Errorf("Close of a nil Dir = %v", err)
	}
}

// One case for each line of the table in the comment of Used.
func TestUsedSaysWhatTheCommentOfUsedSays(t *testing.T) {
	// The names of a removal authorisation and of a key file of the naming of earlier versions, one case each.
	var used, notUsed []struct {
		name string
		make func(t *testing.T, keys string)
	}
	add := func(list *[]struct {
		name string
		make func(t *testing.T, keys string)
	}, name string, make func(t *testing.T, keys string)) {
		*list = append(*list, struct {
			name string
			make func(t *testing.T, keys string)
		}{name, make})
	}

	// Used.
	for _, n := range []string{
		"A.removal.jws", "Z.removal.jws", "M.removal.jws.age",
		"A.x509.key.pem", "B.x509.key.age", "A.openpgp.key.asc", "C.openpgp.key.age",
		"A.revocation.0123abcd.asc", "A.revocation.x.pgp.age", "Z.revocation..asc",
		// The names are compared without regard to case, since a file system may fold it.
		"a.removal.jws", "Z.REMOVAL.JWS", "b.x509.key.pem", "A.X509.KEY.PEM", "c.openpgp.key.asc", "D.Openpgp.Key.Age", "e.revocation.x.asc",
	} {
		add(&used, "a file named "+n, file(n))
	}
	for _, n := range []string{"Test-only-keys", "TEST-ONLY-KEYS", "test-only-Keys"} {
		add(&used, "a file named "+n+" (the name of the folder of the keys in another case)", file(n))
		add(&used, "an empty folder named "+n+" of the mode 0700 (the name of the folder of the keys in another case)", func(t *testing.T, keys string) {
			if err := os.Mkdir(filepath.Join(keys, n), 0o700); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Any entry of a used name is a use, whatever its type: a folder, a link or a pipe is no file that can be written over.
	for _, n := range []string{"A.removal.jws", "a.REMOVAL.jws", "A.x509.key.pem", "B.x509.key.age", "A.openpgp.key.asc", "A.revocation.x.asc"} {
		add(&used, "a folder named "+n, func(t *testing.T, keys string) {
			if err := os.Mkdir(filepath.Join(keys, n), 0o700); err != nil {
				t.Fatal(err)
			}
		})
		add(&used, "a link named "+n, func(t *testing.T, keys string) {
			if err := os.Symlink(filepath.Join(keys, "nowhere"), filepath.Join(keys, n)); err != nil {
				t.Fatal(err)
			}
		})
		add(&used, "a pipe named "+n, func(t *testing.T, keys string) {
			if err := syscall.Mkfifo(filepath.Join(keys, n), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	add(&used, "the folder test-only-keys with a key in it", func(t *testing.T, keys string) {
		folder(0o700)(t, keys)
		write(t, filepath.Join(keys, keydir.TestOnlyFolder, "x509-root-a.p8"), "x")
	})
	add(&used, "the folder test-only-keys with an empty folder in it", func(t *testing.T, keys string) {
		folder(0o700)(t, keys)
		if err := os.Mkdir(filepath.Join(keys, keydir.TestOnlyFolder, "inner"), 0o700); err != nil {
			t.Fatal(err)
		}
	})
	add(&used, "the folder test-only-keys with a temporary file in it", func(t *testing.T, keys string) {
		folder(0o700)(t, keys)
		write(t, filepath.Join(keys, keydir.TestOnlyFolder, ".tmp-x509-root-a"), "x")
	})
	for _, m := range []fs.FileMode{0o755, 0o750, 0o770, 0o500, 0o600, 0o777, 0o700 | fs.ModeSticky, 0o700 | fs.ModeSetgid} {
		add(&used, "the empty folder test-only-keys of the mode "+m.String(), folder(m))
	}
	add(&used, "a file named test-only-keys", file(keydir.TestOnlyFolder))
	add(&used, "an empty file named test-only-keys", func(t *testing.T, keys string) { write(t, filepath.Join(keys, keydir.TestOnlyFolder), "") })
	add(&used, "a link named test-only-keys to an empty folder of the mode 0700", func(t *testing.T, keys string) {
		target := filepath.Join(keys, "elsewhere")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(keys, keydir.TestOnlyFolder)); err != nil {
			t.Fatal(err)
		}
	})
	add(&used, "a link named test-only-keys to nothing", func(t *testing.T, keys string) {
		if err := os.Symlink(filepath.Join(keys, "nowhere"), filepath.Join(keys, keydir.TestOnlyFolder)); err != nil {
			t.Fatal(err)
		}
	})
	add(&used, "a pipe named test-only-keys", func(t *testing.T, keys string) {
		if err := syscall.Mkfifo(filepath.Join(keys, keydir.TestOnlyFolder), 0o600); err != nil {
			t.Fatal(err)
		}
	})
	add(&used, "a removal authorisation beside an empty folder that fits", func(t *testing.T, keys string) {
		folder(0o700)(t, keys)
		write(t, filepath.Join(keys, "A.removal.jws"), jws)
	})

	// Not used.
	add(&notUsed, "an empty key directory", func(*testing.T, string) {})
	add(&notUsed, "the empty folder test-only-keys of the mode 0700, owned by this user", folder(0o700))
	for _, n := range []string{
		".rt-0123456789", ".tmp-x509-root-a", "README", "x509-root-a.p8", "test-only-keys.bak", "test-only-key", "xtest-only-keys",
		"AB.removal.jws", "1.removal.jws", "A.removal.jws.bak", "A.removal.jws.", "A.x509.key.pem.bak", "A.x509.key",
		"A.revocation.asc", "A.revocation.", "A.revocation.x.gpg", "A.openpgp.key", "removal.jws", ".removal.jws", "A_removal.jws",
	} {
		add(&notUsed, "a file named "+n, file(n))
	}
	for _, group := range []struct {
		want  bool
		cases []struct {
			name string
			make func(t *testing.T, keys string)
		}
	}{{true, used}, {false, notUsed}} {
		for _, c := range group.cases {
			t.Run(c.name, func(t *testing.T) {
				d, keys := open(t)
				c.make(t, keys)
				before := entries(t, keys)
				got, err := d.Used()
				if err != nil {
					t.Fatalf("Used: %v", err)
				}
				if got != group.want {
					t.Errorf("Used = %v, want %v", got, group.want)
				}
				if after := entries(t, keys); !slices.Equal(before, after) {
					t.Errorf("Used changed the key directory:\n%q\nto\n%q", before, after)
				}
			})
		}
	}
}

// entries lists every path under dir with its mode, so that a change of a mode shows.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, rel+" "+fi.Mode().String())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The folder of the keys that is empty and fit is owned by the user of the process: the check of the owner
// reads the owner on this system, and a folder that this user made passes it.
func TestTheEmptyFolderThatThisUserMadeIsOwnedByThisUser(t *testing.T) {
	d, keys := open(t)
	folder(0o700)(t, keys)
	fi, err := os.Lstat(filepath.Join(keys, keydir.TestOnlyFolder))
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		t.Fatalf("the folder is not owned by this user: %v", fi.Sys())
	}
	if used, err := d.Used(); err != nil || used {
		t.Errorf("Used = %v, %v for an empty folder of this user with the mode 0700", used, err)
	}
}

// Used looks again at each call: a folder that was fit and gets a key, or a removal authorisation
// that is saved, makes the directory used.
func TestUsedLooksAtTheDirectoryAtEachCall(t *testing.T) {
	d, keys := open(t)
	if used, _ := d.Used(); used {
		t.Fatal("a new key directory is used")
	}
	folder(0o700)(t, keys)
	if used, _ := d.Used(); used {
		t.Fatal("an empty fit folder is used")
	}
	write(t, filepath.Join(keys, keydir.TestOnlyFolder, "x509-root-a.p8"), "x")
	if used, err := d.Used(); err != nil || !used {
		t.Fatalf("a folder with a key is not used: %v, %v", used, err)
	}
	d2, keys2 := open(t)
	if err := d2.SaveRemoval("A", []byte(jws)); err != nil {
		t.Fatal(err)
	}
	if used, err := d2.Used(); err != nil || !used {
		t.Errorf("a key directory that holds a removal authorisation that SaveRemoval wrote is not used: %v, %v", used, err)
	}
	_ = keys2
}

func TestARemovalAuthorisationIsWrittenWithTheMode0600AndReadBackAsItWas(t *testing.T) {
	d, keys := open(t)
	if got := keydir.RemovalName("A"); got != "A.removal.jws" {
		t.Fatalf("RemovalName(A) = %q", got)
	}
	if err := d.SaveRemoval("A", []byte(jws)); err != nil {
		t.Fatalf("SaveRemoval: %v", err)
	}
	if got := names(t, keys); !slices.Equal(got, []string{"A.removal.jws"}) {
		t.Errorf("the key directory holds %q, want only the file and no temporary file", got)
	}
	st, err := os.Lstat(filepath.Join(keys, "A.removal.jws"))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Errorf("the file is %v, %v; want a regular file of the mode 0600", st, err)
	}
	raw, err := os.ReadFile(filepath.Join(keys, "A.removal.jws"))
	if err != nil || string(raw) != jws {
		t.Errorf("the file holds %q, %v; want the text as it was given, with no line feed", raw, err)
	}
	back, err := d.ReadRemoval("A")
	if err != nil || string(back) != jws {
		t.Errorf("ReadRemoval = %q, %v", back, err)
	}
	// Another label is another file.
	if err := d.SaveRemoval("B", []byte(jwsOther)); err != nil {
		t.Fatalf("SaveRemoval of B: %v", err)
	}
	if b, err := d.ReadRemoval("B"); err != nil || string(b) != jwsOther {
		t.Errorf("ReadRemoval of B = %q, %v", b, err)
	}
}

func TestAFileOfTheKeyDirectoryIsNeverReplaced(t *testing.T) {
	d, keys := open(t)
	if err := d.SaveRemoval("A", []byte(jws)); err != nil {
		t.Fatal(err)
	}
	err := d.SaveRemoval("A", []byte("aaaa.bbbb.cccc"))
	if !errors.Is(err, keydir.ErrKeyExists) {
		t.Fatalf("a second SaveRemoval of A = %v, want ErrKeyExists", err)
	}
	if raw, _ := os.ReadFile(filepath.Join(keys, "A.removal.jws")); string(raw) != jws {
		t.Errorf("the file was changed: %q", raw)
	}
	// A folder, a link or a pipe of that name is not replaced either, and nothing is written through it.
	for _, kind := range []string{"folder", "link", "pipe"} {
		t.Run(kind, func(t *testing.T) {
			d, keys := open(t)
			p := filepath.Join(keys, "B.removal.jws")
			switch kind {
			case "folder":
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink(filepath.Join(keys, "elsewhere"), p); err != nil {
					t.Fatal(err)
				}
			case "pipe":
				if err := syscall.Mkfifo(p, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := entries(t, keys)
			if err := d.SaveRemoval("B", []byte(jws)); !errors.Is(err, keydir.ErrKeyExists) {
				t.Errorf("SaveRemoval over a %s = %v, want ErrKeyExists", kind, err)
			}
			if after := entries(t, keys); !slices.Equal(before, after) {
				t.Errorf("the key directory changed:\n%q\nto\n%q", before, after)
			}
			if _, err := os.Stat(filepath.Join(keys, "elsewhere")); err == nil {
				t.Error("a file was written through the link")
			}
			if _, err := d.ReadRemoval("B"); !errors.Is(err, keydir.ErrKeyFile) {
				t.Errorf("ReadRemoval of a %s = %v, want ErrKeyFile", kind, err)
			}
		})
	}
}

func TestTwoSavesOfOneRemovalAuthorisationAtOnceWriteOneFile(t *testing.T) {
	d, keys := open(t)
	var wg sync.WaitGroup
	errs := make([]error, 6)
	start := make(chan struct{})
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = d.SaveRemoval("A", []byte(jws))
		}()
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, keydir.ErrKeyExists):
			t.Errorf("a save failed with %v, want nil or ErrKeyExists", err)
		}
	}
	if ok != 1 {
		t.Errorf("%d saves won, want exactly one", ok)
	}
	if got := names(t, keys); !slices.Equal(got, []string{"A.removal.jws"}) {
		t.Errorf("the key directory holds %q", got)
	}
}

func TestTheLabelOfARemovalAuthorisationIsOneUpperCaseLetter(t *testing.T) {
	d, keys := open(t)
	for _, label := range []string{"", "a", "AB", "1", "-", " ", "A ", "\x00", "A\n", "Ä", "../A", "A/", "\\", "AA", "z", "A.removal.jws"} {
		if got := keydir.RemovalName(label); got != "" {
			t.Errorf("RemovalName(%+q) = %q, want none", label, got)
		}
		if err := d.SaveRemoval(label, []byte(jws)); !errors.Is(err, keydir.ErrParams) {
			t.Errorf("SaveRemoval(%+q) = %v, want ErrParams", label, err)
		}
		if _, err := d.ReadRemoval(label); !errors.Is(err, keydir.ErrParams) {
			t.Errorf("ReadRemoval(%+q) = %v, want ErrParams", label, err)
		}
	}
	for l := 'A'; l <= 'Z'; l++ {
		if got := keydir.RemovalName(string(l)); got != string(l)+".removal.jws" {
			t.Errorf("RemovalName(%c) = %q", l, got)
		}
	}
	if got := names(t, keys); len(got) != 0 {
		t.Errorf("a bad label wrote %q", got)
	}
}

// The limits of the shape that SaveRemoval and ReadRemoval check: three non-empty parts of Base64url text
// without padding, two dots, at most 4 KiB. Nothing is written for a text that is refused.
func TestTheShapeOfARemovalAuthorisationIsCheckedAtItsLimits(t *testing.T) {
	part := func(n int) string { return strings.Repeat("A", n) } // "A" x n is Base64url text of n characters; n % 4 must not be 1
	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"the usual three parts", jws, true},
		{"the smallest: three parts of two characters", "AA.AA.AA", true},
		{"exactly 4096 bytes", part(2048) + "." + part(1024) + "." + part(4096-2048-1024-2), true},
		{"4097 bytes", part(2048) + "." + part(1024) + "." + part(4097-2048-1024-2), false},
		{"far more than 4 KiB", part(70000) + ".AA.AA", false},
		{"empty", "", false},
		{"one part", "AAAA", false},
		{"two parts", "AAAA.BBBB", false},
		{"four parts", "AAAA.BBBB.CCCC.DDDD", false},
		{"an empty first part", ".BBBB.CCCC", false},
		{"an empty middle part", "AAAA..CCCC", false},
		{"an empty last part", "AAAA.BBBB.", false},
		{"only dots", "..", false},
		{"a padded part", "AA==.BBBB.CCCC", false},
		{"a space", "AAAA.BB BB.CCCC", false},
		{"a trailing line feed", jws + "\n", false},
		{"a carriage return", "AAAA.BBBB.CC\rCC", false},
		{"a line feed inside a part", "AAAA.BB\nBB.CCCC", false},
		{"a NUL", "AAAA.BBBB.CC\x00C", false},
		{"a plus sign", "AAAA.BB+B.CCCC", false},
		{"a slash", "AAAA.BB/B.CCCC", false},
		{"a character outside ASCII", "AAAA.BBBB.CCCÄ", false},
		{"a part of one character", "A.BBBB.CCCC", false},
		{"a part with bits left over at its end", "AAAA.BBBB.AB", false}, // "AB" has non-zero bits after the byte: not the one spelling
		{"the path of a file", "../../etc/passwd", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, keys := open(t)
			err := d.SaveRemoval("A", []byte(c.text))
			switch {
			case c.ok && err != nil:
				t.Fatalf("SaveRemoval = %v, want it accepted", err)
			case !c.ok && !errors.Is(err, keydir.ErrKeyFile):
				t.Fatalf("SaveRemoval = %v, want ErrKeyFile", err)
			}
			if err != nil {
				if got := names(t, keys); len(got) != 0 {
					t.Errorf("a refused text wrote %q", got)
				}
				if strings.Contains(err.Error(), keys) {
					t.Errorf("the text holds a path: %q", err)
				}
				return
			}
			if b, err := d.ReadRemoval("A"); err != nil || string(b) != c.text {
				t.Errorf("ReadRemoval: %d bytes, %v", len(b), err)
			}
		})
	}
}

// A file that was changed after it was written is refused when it is read: the shape is checked on the way out too.
func TestAFileThatIsMissingOrChangedIsRefusedWhenItIsRead(t *testing.T) {
	d, keys := open(t)
	if _, err := d.ReadRemoval("A"); !errors.Is(err, keydir.ErrKeyFile) {
		t.Errorf("a missing file: %v, want ErrKeyFile", err)
	}
	for name, text := range map[string]string{
		"empty":           "",
		"two parts":       "AAAA.BBBB",
		"a line feed":     jws + "\n",
		"not Base64url":   "AAAA.BB+B.CCCC",
		"longer than 4 K": strings.Repeat("A", 5000) + ".AA.AA",
	} {
		t.Run(name, func(t *testing.T) {
			write(t, filepath.Join(keys, "C.removal.jws"), text)
			if b, err := d.ReadRemoval("C"); !errors.Is(err, keydir.ErrKeyFile) || b != nil {
				t.Errorf("ReadRemoval = %q, %v; want ErrKeyFile and no bytes", b, err)
			}
		})
	}
	// A link that points at a good file is not read through.
	good := filepath.Join(keys, "good")
	write(t, good, jws)
	if err := os.Symlink(good, filepath.Join(keys, "D.removal.jws")); err != nil {
		t.Fatal(err)
	}
	if b, err := d.ReadRemoval("D"); err == nil || bytes.Equal(b, []byte(jws)) {
		t.Errorf("ReadRemoval through a link = %q, %v; want a refusal", b, err)
	}
}
