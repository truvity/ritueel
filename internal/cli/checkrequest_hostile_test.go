//go:build linux || darwin

package cli

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// Hostile bundles for "check request": a file of the bundle that is a pipe, a link, a folder, too large, a bomb
// or not UTF-8. The command refuses each one with exit code 1 (or the code of a refusal for the request itself),
// says so in printable ASCII, writes nothing, and never waits for a pipe that nobody writes to.

func TestHostileFilesOfTheBundleStopTheCommandAndAreNeverFollowed(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "x509-software-valid")
	stem := c.stem(t)
	big := bytes.Repeat([]byte("# comment\n"), 30_000) // 300 000 bytes, over the limit of a wanted file
	bomb := "version: 1\nname: Example\nrelease_address: release@example.org\na: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: &d [*c, *c]\ne: [*d, *d]\n"
	deep := strings.Repeat("[", 20_000) + strings.Repeat("]", 20_000)
	type mk func(t *testing.T, dir, rel string)
	pipe := func(t *testing.T, dir, rel string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o644); err != nil {
			t.Skipf("cannot make a pipe: %v", err)
		}
	}
	link := func(t *testing.T, dir, rel string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		moved := p + ".moved"
		if err := os.Rename(p, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, p); err != nil {
			t.Fatal(err)
		}
	}
	folder := func(t *testing.T, dir, rel string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	content := func(data []byte) mk {
		return func(t *testing.T, dir, rel string) {
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	files := map[string]string{
		"settings":   "ritueel.yaml",
		"delegation": "want/delegations/" + crqDelegation + ".yaml",
		"root":       "want/roots/" + crqRoot + ".yaml",
		"list":       "trust/" + crqTrustSet + "/root-list.json",
		"bundle":     "trust/" + crqTrustSet + "/ca-bundle.pem",
	}
	for what, rel := range files {
		for name, make := range map[string]mk{
			"a pipe":                   pipe,
			"a link":                   link,
			"a folder":                 folder,
			"a file over the limit":    content(big),
			"a yaml bomb":              content([]byte(bomb)),
			"nesting 20000 deep":       content([]byte(deep)),
			"bytes that are not UTF-8": content([]byte("version: 1\nname: \xff\xfe\xfd\n")),
			"a byte order mark":        content([]byte("\xef\xbb\xbfversion: 1\n")),
			"a NUL":                    content([]byte("version: 1\x00\n")),
			"empty":                    content(nil),
		} {
			t.Run(what+" is "+name, func(t *testing.T) {
				dir := crqBundle(t, m, c)
				make(t, dir, rel)
				before := crqSnapshot(t, dir)
				r := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir, "--output", "json")
				if r.code == ExitOK {
					t.Fatalf("a hostile file is not refused: %s%s", r.stdout, r.stderr)
				}
				if r.code != ExitFailure {
					t.Errorf("exit code %d, want 1\n%s%s", int(r.code), r.stdout, r.stderr)
				}
				if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
					t.Errorf("a byte that is not printable ASCII: %q %q", r.stdout, r.stderr)
				}
				if len(r.stderr) > 4096 {
					t.Errorf("standard error is %d bytes long", len(r.stderr))
				}
				crqSame(t, "check request", before, crqSnapshot(t, dir))
			})
		}
	}
}

// A trust set that is a link, a pipe or a folder in the place of a file, and a folder with too many sets.
func TestAHostileTrustFolderStopsTheCommand(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "x509-software-valid")
	stem := c.stem(t)
	for name, make := range map[string]func(t *testing.T, dir string){
		"the trust folder is a link": func(t *testing.T, dir string) {
			if err := os.Rename(filepath.Join(dir, "trust"), filepath.Join(dir, "moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("moved", filepath.Join(dir, "trust")); err != nil {
				t.Fatal(err)
			}
		},
		"the trust folder is a file": func(t *testing.T, dir string) {
			if err := os.RemoveAll(filepath.Join(dir, "trust")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "trust"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"the newest set is a link": func(t *testing.T, dir string) {
			set := filepath.Join(dir, "trust", crqTrustSet)
			if err := os.Rename(set, filepath.Join(dir, "moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(dir, "moved"), set); err != nil {
				t.Fatal(err)
			}
		},
		"the newest set is a file": func(t *testing.T, dir string) {
			set := filepath.Join(dir, "trust", crqTrustSet)
			if err := os.RemoveAll(set); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(set, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a newer set is empty": func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "trust", "9-aaaaaaaa"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a second set has the same number": func(t *testing.T, dir string) {
			if err := os.Mkdir(filepath.Join(dir, "trust", "7-aaaaaaaa"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"too many names in the trust folder": func(t *testing.T, dir string) {
			for i := 0; i <= fsx.MaxDirEntries; i++ {
				f, err := os.Create(filepath.Join(dir, "trust", "x"+strconv.Itoa(i)))
				if err != nil {
					t.Fatal(err)
				}
				_ = f.Close()
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := crqBundle(t, m, c)
			make(t, dir)
			before := crqSnapshot(t, dir)
			r := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir)
			if r.code != ExitFailure || r.stdout != "" || !onlyPrintable(r.stderr) {
				t.Errorf("(%d, %q, %q), want exit code 1, nothing on standard output and printable text on standard error", int(r.code), r.stdout, r.stderr)
			}
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

// The command writes nothing and takes no lock: on a bundle that nothing can be written into, and whose folders
// nothing can be made in, it gives the same answers as on a bundle that can be written.
func TestTheCommandWorksOnABundleThatCannotBeWrittenInto(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a process of the superuser writes anywhere: the test cannot make a folder that refuses a write")
	}
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, tc := range []struct {
		id   string
		want ExitCode
	}{
		{"x509-software-valid", ExitOK},
		{"x509-csr-bad-signature", ExitRefused},
		{"x509-piv-valid", ExitFailure},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c := m.byID(t, tc.id)
			dir := crqBundle(t, m, c)
			args := []string{"check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json"}
			open := crqRun(t, now, args...)
			readOnly(t, dir)
			closed := crqRun(t, now, args...)
			if open.code != tc.want || closed != open {
				t.Errorf("writable: (%d, %q, %q)\nread-only: (%d, %q, %q)", int(open.code), open.stdout, open.stderr, int(closed.code), closed.stdout, closed.stderr)
			}
		})
	}
}

// readOnly takes the write bit from every file and folder under dir, and gives it back when the test ends.
func readOnly(t *testing.T, dir string) {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range paths {
			_ = os.Chmod(p, 0o755)
		}
	})
	for i := len(paths) - 1; i >= 0; i-- {
		info, err := os.Lstat(paths[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(paths[i], info.Mode().Perm()&^0o222); err != nil {
			t.Fatal(err)
		}
	}
}
