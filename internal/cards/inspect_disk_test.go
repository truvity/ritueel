//go:build linux || darwin

package cards_test

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// The same checks against a real folder, through fsx.OpenFS: what only a real file system can hold (a
// link, a FIFO, a file of 8 MiB, a mode that refuses a read).

// diskBundle writes the files and opens the folder through fsx.
func diskBundle(t testing.TB, files map[string]string) (string, fsx.FS) {
	t.Helper()
	dir := t.TempDir()
	for p, text := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir, openDisk(t, dir)
}

func openDisk(t testing.TB, dir string) fsx.FS {
	t.Helper()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fsys.Close() })
	return fsys
}

// tree lists every path of a folder with its type and size, links not followed.
func tree(t testing.TB, dir string) []string {
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
		out = append(out, fmt.Sprintf("%s %s %d", rel, info.Mode(), info.Size()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheGoodSetOnTheDiskIsFiveCardsAndNothingIsChanged(t *testing.T) {
	dir, fsys := diskBundle(t, with(goodSet(), map[string]string{"ritueel.yaml": "x"}))
	before := tree(t, dir)
	rep := mustInspect(t, fsys)
	if got := names(rep); !slices.Equal(got, goodNames) || !rep.Clean() {
		t.Errorf("cards = %q, clean %v", got, rep.Clean())
	}
	if err := cards.Check(t.Context(), fsys); err != nil {
		t.Errorf("Check: %v", err)
	}
	if after := tree(t, dir); !slices.Equal(before, after) {
		t.Errorf("Inspect changed the folder:\n%q\n%q", before, after)
	}
}

func TestAFileOfEightMebibytesAndOneByteIsAFindingAndTheOtherCardsAreReturned(t *testing.T) {
	dir, fsys := diskBundle(t, goodSet())
	long := filepath.Join(dir, "want", "cards", "long.yaml")
	f, err := os.Create(long)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(cardRootB); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(fsx.MaxReadSize + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	rep := mustInspect(t, fsys)
	if len(rep.Findings) != 1 {
		t.Fatalf("findings = %+v", rep.Findings)
	}
	g := rep.Findings[0]
	if g.Code != cards.FileInvalid || g.Path != cardFile("long") || !strings.Contains(g.Detail, "too long") {
		t.Errorf("finding = %+v", g)
	}
	if got := names(rep); !slices.Equal(got, goodNames) {
		t.Errorf("cards = %q", got)
	}
	// The check names the file.
	var we *wanted.Error
	if err := cards.Check(t.Context(), fsys); !errors.As(err, &we) || we.Path != cardFile("long") {
		t.Errorf("Check = %v", err)
	}
	// The file of exactly 8 MiB is read, and refused by the reader of the card file as too long for a card.
	if err := os.Truncate(long, fsx.MaxReadSize); err != nil {
		t.Fatal(err)
	}
	rep = mustInspect(t, fsys)
	if len(rep.Findings) != 1 || !strings.Contains(rep.Findings[0].Detail, "longer than") {
		t.Errorf("a file of 8 MiB: findings = %+v", rep.Findings)
	}
}

func TestALinkAFifoAndAFolderInPlaceOfAFileAreErrorsAndNoFileIsFollowed(t *testing.T) {
	setups := map[string]func(t *testing.T, cards, outside string){
		"a link to a good file": func(t *testing.T, c, _ string) {
			if err := os.Symlink("root-a.yaml", filepath.Join(c, "zz.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"a link to a file outside the bundle": func(t *testing.T, c, outside string) {
			if err := os.Symlink(filepath.Join(outside, "x.yaml"), filepath.Join(c, "zz.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"a dangling link": func(t *testing.T, c, _ string) {
			if err := os.Symlink("nothing", filepath.Join(c, "zz.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"a link to a folder": func(t *testing.T, c, outside string) {
			if err := os.Symlink(outside, filepath.Join(c, "zz.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"a FIFO": func(t *testing.T, c, _ string) {
			if err := syscall.Mkfifo(filepath.Join(c, "zz.yaml"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func(t *testing.T, c, _ string) {
			if err := os.Mkdir(filepath.Join(c, "zz.yaml"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			dir, fsys := diskBundle(t, goodSet())
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "x.yaml"), []byte(cardRootB), 0o644); err != nil {
				t.Fatal(err)
			}
			setup(t, filepath.Join(dir, "want", "cards"), outside)
			before := tree(t, dir)
			rep, err := cards.Inspect(t.Context(), fsys)
			if err == nil || rep != nil {
				t.Fatalf("Inspect = %+v, %v", rep, err)
			}
			if !strings.Contains(err.Error(), "want/cards/zz.yaml") || !printable(err.Error()) {
				t.Errorf("the error %+q does not name the entry", err.Error())
			}
			if cerr := cards.Check(t.Context(), fsys); cerr == nil {
				t.Error("Check accepted it")
			}
			if after := tree(t, dir); !slices.Equal(before, after) {
				t.Error("the folder was changed")
			}
		})
	}
}

func TestAFolderThatIsALinkOrAFileInPlaceOfWantCardsIsAnErrorNotAnEmptySet(t *testing.T) {
	setups := map[string]func(t *testing.T, dir string){
		"want/cards is a file": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "want"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "want", "cards"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"want/cards is a link to a folder with a card": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "want"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "elsewhere"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "elsewhere", "a.yaml"), []byte(cardRootB), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../elsewhere", filepath.Join(dir, "want", "cards")); err != nil {
				t.Fatal(err)
			}
		},
		"want/cards is a dangling link": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "want"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("nothing", filepath.Join(dir, "want", "cards")); err != nil {
				t.Fatal(err)
			}
		},
		"want is a link": func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "elsewhere", "cards"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("elsewhere", filepath.Join(dir, "want")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(t, dir)
			fsys := openDisk(t, dir)
			rep, err := cards.Inspect(t.Context(), fsys)
			if err == nil || rep != nil || errors.Is(err, fs.ErrNotExist) {
				t.Errorf("Inspect = %+v, %v; want an error that is not a missing folder", rep, err)
			}
		})
	}
}

func TestAFileThatTheSystemRefusesToReadIsAnErrorAndNotAFinding(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("a file with no permission can be read by the superuser")
	}
	dir, fsys := diskBundle(t, goodSet())
	p := filepath.Join(dir, "want", "cards", "root-b.yaml")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	rep, err := cards.Inspect(t.Context(), fsys)
	if err == nil || rep != nil {
		t.Fatalf("Inspect = %+v, %v; want an error and no report", rep, err)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("the error %v does not say the system refused", err)
	}
	var we *wanted.Error
	if !errors.As(err, &we) || we.Path != cardFile("root-b") {
		t.Errorf("error = %v", err)
	}
}

func TestHostileNamesOnTheDiskAreRefusedWithPrintableText(t *testing.T) {
	for _, name := range []string{"a\x01b.yaml", "a\nb.yaml", "a\u202eb.yaml", "a\xffb.yaml", "A.yaml", "a b.yaml", strings.Repeat("a", 200) + ".yaml"} {
		t.Run(strings.ToValidUTF8(name, "?"), func(t *testing.T) {
			dir, fsys := diskBundle(t, goodSet())
			if err := os.WriteFile(filepath.Join(dir, "want", "cards", name), []byte(cardRootB), 0o644); err != nil {
				t.Skipf("the file system refuses the name: %v", err)
			}
			rep, err := cards.Inspect(t.Context(), fsys)
			if err == nil || rep != nil || !printable(err.Error()) {
				t.Errorf("Inspect = %+v, %+q", rep, err)
			}
		})
	}
}
