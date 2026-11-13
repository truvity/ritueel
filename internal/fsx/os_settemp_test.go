//go:build linux || darwin

package fsx_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// plantFS is the real file system with another actor in it: after a Mkdir of a temporary folder it
// puts something into the folder before the writer opens it. The FS interface is the hook: a
// wrapper that passes every call to the real one.
type plantFS struct {
	fsx.FS
	dir   string // the real path of this folder
	plant func(inside string)
}

func (p plantFS) OpenDir(name string) (fsx.FS, error) {
	c, err := p.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return plantFS{FS: c, dir: filepath.Join(p.dir, name), plant: p.plant}, nil
}

func (p plantFS) Mkdir(name string, perm fs.FileMode) error {
	if err := p.FS.Mkdir(name, perm); err != nil {
		return err
	}
	if strings.HasPrefix(name, fsx.TempPrefix) {
		p.plant(filepath.Join(p.dir, name))
	}
	return nil
}

func TestOSWriteSetStopsWhenAnotherActorPutSomethingInItsTemporaryFolder(t *testing.T) {
	for _, c := range []struct {
		name  string
		plant func(wd *world, inside string)
	}{
		{"a file", func(_ *world, in string) { _ = os.WriteFile(filepath.Join(in, "planted"), []byte("x"), 0o600) }},
		{"a folder", func(_ *world, in string) { _ = os.Mkdir(filepath.Join(in, "planted"), 0o700) }},
		{"a link to the outside", func(wd *world, in string) { _ = os.Symlink(wd.outside, filepath.Join(in, "planted")) }},
		{"a dangling link", func(wd *world, in string) {
			_ = os.Symlink(filepath.Join(wd.outside, "nothing"), filepath.Join(in, "planted"))
		}},
		{"a FIFO", func(_ *world, in string) { _ = syscall.Mkfifo(filepath.Join(in, "planted"), 0o600) }},
		{"a file called like the first file of the set", func(_ *world, in string) {
			_ = os.WriteFile(filepath.Join(in, "keys.json"), []byte("planted"), 0o600)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			wd := newWorld(t)
			beforeOut := snapshot(t, wd.outside)
			root, err := fsx.OpenFS(wd.root)
			if err != nil {
				t.Fatal(err)
			}
			w := &fsx.Writer{FS: plantFS{FS: root, dir: wd.root, plant: func(in string) { c.plant(wd, in) }}}
			t.Cleanup(func() { _ = w.Close() })
			err = w.WriteSet("0007-acme", []fsx.NewFile{
				{Name: "keys.json", Data: []byte("keys"), Perm: 0o600},
				{Name: "root.json", Data: []byte("root"), Perm: 0o600},
			})
			fe := requireFailed(t, err)
			if fe.Step != fsx.StepOpenDir || !errors.Is(err, fsx.ErrNotEmpty) || !strings.HasPrefix(fe.Path, fsx.TempPrefix) {
				t.Fatalf("got %v, want an open-dir error at the temporary folder that wraps ErrNotEmpty", err)
			}
			requireStoppedBy(t, w.Mkdir("other", 0o700), fe)
			if _, err := os.Lstat(filepath.Join(wd.root, "0007-acme")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the set stands at its final name: %v", err)
			}
			ents, err := os.ReadDir(filepath.Join(wd.root, fe.Path))
			if err != nil || len(ents) != 1 {
				t.Fatalf("the temporary folder holds %v (%v), want only what was planted", ents, err)
			}
			if c.name == "a file called like the first file of the set" {
				if got := readFile(t, filepath.Join(wd.root, fe.Path, "keys.json")); string(got) != "planted" {
					t.Fatalf("the planted file was written over: %q", got)
				}
			}
			wd.requireOutsideUntouched(beforeOut)
		})
	}
}
