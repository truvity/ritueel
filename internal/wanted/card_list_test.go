//go:build linux || darwin

package wanted_test

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

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// ListCardNames lists want/cards once and reads no file; LoadCard reads one file by its name. The listing is the
// listing of want/roots (docs/reference/bundle.md, "The wanted files"): it judges names and entries, applies no
// limit on the count of cards (that is the caller's check) and returns no name with an error.

// cardFiles is the five good files of the set, by path.
func cardFiles() map[string]string {
	return map[string]string{
		"want/cards/root-a.yaml":       cardRootA,
		"want/cards/root-b.yaml":       cardRootB,
		"want/cards/day-one.yaml":      cardDayOne,
		"want/cards/server-one.yaml":   cardServerOne,
		"want/cards/practice-one.yaml": cardPracticeOne,
	}
}

// cardNumbered is the files of n cards with the names c0000, c0001, ...; each is a good card with its own serial.
func cardNumbered(n int) map[string]string {
	files := map[string]string{}
	for i := range n {
		files[fmt.Sprintf("want/cards/c%04d.yaml", i)] = fmt.Sprintf("version: 1\nserial: \"%d\"\nkind: server\napplications: [piv]\n", i)
	}
	return files
}

func TestListCardNamesGivesTheNamesInOrderAndReadsNoFile(t *testing.T) {
	files := cardFiles()
	files["want/cards/zz-broken.yaml"] = "this is not a card file, and nothing reads it"
	files["want/cards/empty.yaml"] = ""
	_, fsys, reads := nmOpen(t, files)
	names, err := wanted.ListCardNames(fsys)
	if err != nil {
		t.Fatalf("ListCardNames: %v", err)
	}
	want := []string{"day-one", "empty", "practice-one", "root-a", "root-b", "server-one", "zz-broken"}
	if !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
	if reads.count() != 0 {
		t.Errorf("ListCardNames read %d files: %q", reads.count(), reads.paths)
	}
}

func TestListCardNamesOrdersByTheNameAndNotByTheNameOfTheFile(t *testing.T) {
	// The file acme-tls.yaml sorts before acme.yaml (a hyphen comes before a dot), and the name acme before acme-tls.
	_, fsys := bundleDir(t, map[string]string{
		"want/cards/acme-tls.yaml": cardServerOne,
		"want/cards/acme.yaml":     cardServerOne,
		"want/cards/acme-a.yaml":   cardServerOne,
		"want/cards/0day.yaml":     cardServerOne,
	})
	names, err := wanted.ListCardNames(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"0day", "acme", "acme-a", "acme-tls"}; !slices.Equal(names, want) {
		t.Errorf("names = %q, want %q", names, want)
	}
}

func TestListCardNamesOfAMissingOrEmptyFolderIsNoNameAndNoError(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no want folder":    {"ritueel.yaml": goodSettings},
		"want but no cards": {"want/roots/a.yaml": goodRoot},
	} {
		t.Run(name, func(t *testing.T) {
			_, fsys := bundleDir(t, files)
			names, err := wanted.ListCardNames(fsys)
			if err != nil || len(names) != 0 {
				t.Errorf("ListCardNames = %q, %v", names, err)
			}
		})
	}
	t.Run("an empty cards folder", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"ritueel.yaml": goodSettings})
		if err := os.MkdirAll(filepath.Join(dir, "want", "cards"), 0o755); err != nil {
			t.Fatal(err)
		}
		names, err := wanted.ListCardNames(fsys)
		if err != nil || len(names) != 0 {
			t.Errorf("ListCardNames = %q, %v", names, err)
		}
	})
}

func TestListCardNamesListsOnlyTheCardsFolder(t *testing.T) {
	// The roots and the delegations are not cards, and the cards are not roots.
	_, fsys := bundleDir(t, map[string]string{
		"want/cards/root-a.yaml":       cardRootA,
		"want/roots/other.yaml":        goodRoot,
		"want/delegations/deleg.yaml":  goodX509Delegation,
		"want/cards-extra/other.yaml":  cardRootA,
		"cards/seen.yaml":              cardRootA,
		"want/cards/nested/inner.yaml": cardRootA,
	})
	_, err := wanted.ListCardNames(fsys)
	if err == nil || !strings.Contains(err.Error(), "want/cards/nested") {
		t.Fatalf("a folder in want/cards was not refused: %v", err)
	}
	_, fsys = bundleDir(t, map[string]string{
		"want/cards/root-a.yaml":      cardRootA,
		"want/roots/other.yaml":       goodRoot,
		"want/delegations/deleg.yaml": goodX509Delegation,
		"want/cards-extra/other.yaml": cardRootA,
		"cards/seen.yaml":             cardRootA,
	})
	names, err := wanted.ListCardNames(fsys)
	if err != nil || !slices.Equal(names, []string{"root-a"}) {
		t.Errorf("ListCardNames = %q, %v", names, err)
	}
	roots, err := wanted.ListRootNames(fsys)
	if err != nil || !slices.Equal(roots, []string{"other"}) {
		t.Errorf("ListRootNames = %q, %v", roots, err)
	}
}

func TestListCardNamesRefusesWhatIsNotACardFileAndReturnsNothing(t *testing.T) {
	type tc struct {
		name  string
		setup func(t *testing.T, cards string)
		path  string // the path the error names, escaped
		words string // a word of the fixed text
	}
	file := func(name, text string) func(*testing.T, string) {
		return func(t *testing.T, cards string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(cards, name), []byte(text), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []tc{
		{"upper-case name", file("X.yaml", cardServerOne), "want/cards/X.yaml", "lower-case"},
		{"another extension", file("a.txt", cardServerOne), "want/cards/a.txt", "NAME.yaml"},
		{"the yml spelling", file("a.yml", cardServerOne), "want/cards/a.yml", "NAME.yaml"},
		{"an upper-case extension", file("a.YAML", cardServerOne), "want/cards/a.YAML", "NAME.yaml"},
		{"no name", file(".yaml", cardServerOne), "want/cards/.yaml", "1 to 63"},
		{"two extensions", file("a.yaml.yaml", cardServerOne), "want/cards/a.yaml.yaml", "lower-case"},
		{"an editor backup", file("root-a.yaml~", cardServerOne), "want/cards/root-a.yaml~", "NAME.yaml"},
		{"an editor swap file", file(".root-a.yaml.swp", cardServerOne), "want/cards/.root-a.yaml.swp", "NAME.yaml"},
		{"a name with an underscore", file("root_a.yaml", cardServerOne), "want/cards/root_a.yaml", "lower-case"},
		// A name that starts with ".rt-" is not refused: it is skipped (list_temporary_test.go).
		{"a name that only looks like a leftover", file(".rtx.yaml", cardServerOne), "want/cards/.rtx.yaml", "lower-case"},
		{"a leftover name that is not at the start", file("a.rt-abc.yaml", cardServerOne), "want/cards/a.rt-abc.yaml", "lower-case"},
		{"a name of 64 characters", file(strings.Repeat("a", 64)+".yaml", cardServerOne), "want/cards/" + strings.Repeat("a", 64) + ".yaml", "1 to 63"},
		{"a space in the name", file("a b.yaml", cardServerOne), `want/cards/a\x20b.yaml`, "lower-case"},
		{"a hyphen first", file("-a.yaml", cardServerOne), "want/cards/-a.yaml", "lower-case"},
		{"a name that is a serial with a dot", file("1.5.yaml", cardServerOne), "want/cards/1.5.yaml", "lower-case"},
		{"a folder with a good name", func(t *testing.T, cards string) {
			if err := os.Mkdir(filepath.Join(cards, "a.yaml"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "want/cards/a.yaml", "not a regular file"},
		{"a folder with a bad name", func(t *testing.T, cards string) {
			if err := os.Mkdir(filepath.Join(cards, "sub"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "want/cards/sub", "NAME.yaml"},
		{"a link to a good file", func(t *testing.T, cards string) {
			file("real.yaml", cardServerOne)(t, cards)
			if err := os.Symlink("real.yaml", filepath.Join(cards, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/cards/a.yaml", "not a regular file"},
		{"a link to a file outside the bundle", func(t *testing.T, cards string) {
			outside := filepath.Join(t.TempDir(), "x.yaml")
			if err := os.WriteFile(outside, []byte(cardServerOne), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(cards, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/cards/a.yaml", "not a regular file"},
		{"a dangling link", func(t *testing.T, cards string) {
			if err := os.Symlink("nothing.yaml", filepath.Join(cards, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/cards/a.yaml", "not a regular file"},
		{"a link to a folder", func(t *testing.T, cards string) {
			if err := os.Symlink(".", filepath.Join(cards, "a.yaml")); err != nil {
				t.Fatal(err)
			}
		}, "want/cards/a.yaml", "not a regular file"},
		{"a FIFO", func(t *testing.T, cards string) {
			if err := syscall.Mkfifo(filepath.Join(cards, "a.yaml"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "want/cards/a.yaml", "not a regular file"},
		{"a name with a control character", file("a\x01b.yaml", cardServerOne), "want/cards/a\\u0001b.yaml", "lower-case"},
		{"a name with a line feed", file("a\nb.yaml", cardServerOne), "want/cards/a\\u000ab.yaml", "lower-case"},
		{"a name with a bidirectional control", file("a\u202eb.yaml", cardServerOne), "want/cards/a\\u202eb.yaml", "lower-case"},
		{"a name that is not UTF-8", file("a\xffb.yaml", cardServerOne), "want/cards/a", "lower-case"},
		{"a name of non-ASCII letters", file("caf\u00e9.yaml", cardServerOne), "want/cards/caf", "lower-case"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, fsys := bundleDir(t, map[string]string{"want/cards/good.yaml": cardServerOne})
			cards := filepath.Join(dir, "want", "cards")
			c.setup(t, cards)
			before := lstTree(t, dir)
			got, err := wanted.ListCardNames(fsys)
			if err == nil {
				t.Fatalf("ListCardNames accepted the folder and returned %q", got)
			}
			if got != nil {
				t.Errorf("ListCardNames returned %q with an error; an error returns nothing", got)
			}
			msg := err.Error()
			if !strings.Contains(msg, c.path) {
				t.Errorf("the error %q does not name the path %q", msg, c.path)
			}
			if !strings.Contains(msg, c.words) {
				t.Errorf("the error %q does not hold %q", msg, c.words)
			}
			if !printableASCII(msg) {
				t.Errorf("the error is not printable ASCII: %+q", msg)
			}
			var e *wanted.Error
			if !errors.As(err, &e) {
				t.Errorf("the error is %T, want *wanted.Error", err)
			}
			if after := lstTree(t, dir); !slices.Equal(before, after) {
				t.Errorf("ListCardNames changed the folder")
			}
		})
	}
}

func TestListCardNamesRefusesAFolderThatCannotBeListedAsAFolder(t *testing.T) {
	t.Run("want/cards is a file", func(t *testing.T) {
		_, fsys := bundleDir(t, map[string]string{"want/cards": "x"})
		names, err := wanted.ListCardNames(fsys)
		if err == nil || names != nil || !strings.Contains(err.Error(), "want/cards") {
			t.Errorf("ListCardNames = %v, %v", names, err)
		}
		if errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a file in place of the folder was told as a missing folder: %v", err)
		}
	})
	t.Run("want/cards is a link to a folder", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"elsewhere/a.yaml": cardServerOne})
		if err := os.MkdirAll(filepath.Join(dir, "want"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../elsewhere", filepath.Join(dir, "want", "cards")); err != nil {
			t.Fatal(err)
		}
		names, err := wanted.ListCardNames(fsys)
		if err == nil || names != nil {
			t.Fatalf("ListCardNames followed a link: %v, %v", names, err)
		}
		if !strings.Contains(err.Error(), "link") {
			t.Errorf("the error does not say a link: %v", err)
		}
	})
	t.Run("want is a link", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"elsewhere/cards/a.yaml": cardServerOne})
		if err := os.Symlink("elsewhere", filepath.Join(dir, "want")); err != nil {
			t.Fatal(err)
		}
		names, err := wanted.ListCardNames(fsys)
		if err == nil || names != nil {
			t.Errorf("ListCardNames followed a link in the path: %v, %v", names, err)
		}
	})
	t.Run("want/cards is a dangling link", func(t *testing.T) {
		dir, fsys := bundleDir(t, map[string]string{"want/other.yaml": "x"})
		if err := os.Symlink("nothing", filepath.Join(dir, "want", "cards")); err != nil {
			t.Fatal(err)
		}
		names, err := wanted.ListCardNames(fsys)
		if err == nil || names != nil {
			t.Errorf("a dangling link in place of the folder is no folder: %v, %v", names, err)
		}
	})
	t.Run("no folder", func(t *testing.T) {
		names, err := wanted.ListCardNames(nil)
		if err == nil || names != nil {
			t.Errorf("ListCardNames(nil) = %v, %v", names, err)
		}
		_ = wantFault(t, err, "want/cards", 0, "no folder")
	})
	t.Run("a closed folder", func(t *testing.T) {
		_, fsys := bundleDir(t, cardFiles())
		if err := fsys.Close(); err != nil {
			t.Fatal(err)
		}
		names, err := wanted.ListCardNames(fsys)
		if err == nil || names != nil {
			t.Errorf("ListCardNames of a closed folder = %v, %v", names, err)
		}
	})
}

func TestListCardNamesDoesNotApplyTheLimitOfCards(t *testing.T) {
	// The count of cards is the caller's check: MaxCards + 1 names are listed, with no error.
	_, fsys := bundleDir(t, cardNumbered(wanted.MaxCards+1))
	names, err := wanted.ListCardNames(fsys)
	if err != nil || len(names) != wanted.MaxCards+1 {
		t.Fatalf("ListCardNames of %d names = %d names, %v", wanted.MaxCards+1, len(names), err)
	}
	if !slices.IsSorted(names) {
		t.Error("the names are not in order")
	}
}

func TestListCardNamesStopsAtTheLimitOfFiles(t *testing.T) {
	_, fsys := bundleDir(t, cardNumbered(wanted.MaxFiles))
	names, err := wanted.ListCardNames(fsys)
	if err != nil || len(names) != wanted.MaxFiles {
		t.Fatalf("ListCardNames of exactly %d files = %d names, %v", wanted.MaxFiles, len(names), err)
	}
	_, fsys = bundleDir(t, cardNumbered(wanted.MaxFiles+1))
	names, err = wanted.ListCardNames(fsys)
	if err == nil || names != nil {
		t.Fatalf("ListCardNames of %d files = %d names, %v", wanted.MaxFiles+1, len(names), err)
	}
	if !strings.Contains(err.Error(), fmt.Sprint(wanted.MaxFiles)) || !strings.Contains(err.Error(), "want/cards") {
		t.Errorf("the error does not name the folder and the limit: %v", err)
	}
}

func TestListCardNamesRefusesAHostileFolderOfMoreNamesThanAnyFolderHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("makes 70,000 files")
	}
	dir, fsys := bundleDir(t, map[string]string{"want/cards/a.yaml": cardServerOne})
	cards := filepath.Join(dir, "want", "cards")
	for i := range fsx.MaxDirEntries + 10 {
		f, err := os.Create(filepath.Join(cards, fmt.Sprintf("c%06d.yaml", i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	names, err := wanted.ListCardNames(fsys)
	if err == nil || names != nil {
		t.Fatalf("ListCardNames of %d names = %d names, %v", fsx.MaxDirEntries+10, len(names), err)
	}
	if !printableASCII(err.Error()) || !strings.Contains(err.Error(), "want/cards") {
		t.Errorf("the error: %+q", err.Error())
	}
}

// What LoadCard returns for a name.

func TestLoadCardReadsTheFileOfTheName(t *testing.T) {
	_, fsys := bundleDir(t, cardFiles())
	for path, text := range cardFiles() {
		name := strings.TrimSuffix(strings.TrimPrefix(path, "want/cards/"), ".yaml")
		c, err := wanted.LoadCard(fsys, name)
		if err != nil {
			t.Fatalf("LoadCard(%s): %v", name, err)
		}
		if !c.Valid() || c.Name != name || c.File.Path != path || string(c.File.Data) != text || c.File.SHA256 != sha256hex([]byte(text)) {
			t.Errorf("LoadCard(%s) = %+v", name, c)
		}
		// The loader and the parser read one file in one way.
		p := mustCard(t, name, text)
		if p.Serial != c.Serial || p.Kind != c.Kind || !slices.Equal(p.Applications, c.Applications) || !slices.Equal(p.OtherRows, c.OtherRows) || p.File.SHA256 != c.File.SHA256 {
			t.Errorf("LoadCard(%s) and ParseCard differ: %+v / %+v", name, c, p)
		}
	}
}

func TestLoadCardOfAMissingFileSaysSo(t *testing.T) {
	_, fsys := bundleDir(t, cardFiles())
	c, err := wanted.LoadCard(fsys, "nobody")
	if c != nil || err == nil {
		t.Fatalf("LoadCard = %v, %v", c, err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the error does not wrap fs.ErrNotExist: %v", err)
	}
	_ = wantFault(t, err, "want/cards/nobody.yaml", 0, "does not exist")
	// A missing folder is a missing file.
	_, fsys = bundleDir(t, map[string]string{"ritueel.yaml": goodSettings})
	if c, err := wanted.LoadCard(fsys, "root-a"); c != nil || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("LoadCard without a folder = %v, %v", c, err)
	}
}

func TestLoadCardRefusesAFileThatFailsItsCheckWithItsPath(t *testing.T) {
	_, fsys := bundleDir(t, map[string]string{
		"want/cards/bad.yaml":   "version: 1\nserial: 10000001\nkind: root\napplications: [piv]\n",
		"want/cards/empty.yaml": "",
	})
	c, err := wanted.LoadCard(fsys, "bad")
	if c != nil {
		t.Errorf("a card beside the error")
	}
	e := wantFault(t, err, "want/cards/bad.yaml", 2, "serial", "quotes")
	if e.Unwrap() != nil {
		t.Errorf("the fault of a text has a cause: %v", e.Unwrap())
	}
	c, err = wanted.LoadCard(fsys, "empty")
	if c != nil || err == nil {
		t.Errorf("an empty file: %v, %v", c, err)
	}
	_ = wantFault(t, err, "want/cards/empty.yaml", 0, "no document")
}

func TestLoadCardRefusesANameThatIsNotTheNameOfAFileBeforeAnyRead(t *testing.T) {
	_, fsys, reads := nmOpen(t, cardFiles())
	for _, name := range []string{"", "../ritueel", "a/b", "A", ".rt-x", "root-a.yaml", "root_a", "-a", strings.Repeat("a", 64), "a\x00b", "a\xffb", "../want/cards/root-a"} {
		c, err := wanted.LoadCard(fsys, name)
		if c != nil || err == nil {
			t.Errorf("LoadCard(%q) = %v, %v", name, c, err)
			continue
		}
		var e *wanted.Error
		if !errors.As(err, &e) || !printableASCII(err.Error()) {
			t.Errorf("LoadCard(%q): %T %+q", name, err, err.Error())
		}
		if e != nil && e.Unwrap() != nil {
			t.Errorf("LoadCard(%q): the fault of a name has a cause", name)
		}
	}
	if reads.count() != 0 {
		t.Errorf("a file was read for a bad name: %q", reads.paths)
	}
}

func TestLoadCardReadsOnlyTheNamedFile(t *testing.T) {
	files := cardFiles()
	files["want/cards/bad.yaml"] = "not: [valid"
	files["want/cards/other.yml"] = "x"
	_, fsys, reads := nmOpen(t, files)
	if _, err := wanted.LoadCard(fsys, "root-a"); err != nil {
		t.Fatalf("a bad neighbour stopped the load: %v", err)
	}
	if got := reads.paths; len(got) != 1 || got[0] != "want/cards/root-a.yaml" {
		t.Errorf("the reads: %q", got)
	}
}

func TestLoadCardRefusesALinkAFolderAndAPipeInPlaceOfAFile(t *testing.T) {
	dir, fsys := bundleDir(t, cardFiles())
	cards := filepath.Join(dir, "want", "cards")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "real.yaml"), []byte(cardServerOne), 0o644); err != nil {
		t.Fatal(err)
	}
	// A link to a file outside the bundle.
	if err := os.Symlink(filepath.Join(outside, "real.yaml"), filepath.Join(cards, "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	c, err := wanted.LoadCard(fsys, "linked")
	if c != nil || !errors.Is(err, fsx.ErrLink) {
		t.Errorf("a link: %v, %v", c, err)
	}
	_ = wantFault(t, err, "want/cards/linked.yaml", 0, "a link is not followed")
	// A link to a file inside the bundle is a link as well.
	if err := os.Symlink(filepath.Join(cards, "root-a.yaml"), filepath.Join(cards, "inside.yaml")); err != nil {
		t.Fatal(err)
	}
	if c, err := wanted.LoadCard(fsys, "inside"); c != nil || !errors.Is(err, fsx.ErrLink) {
		t.Errorf("a link inside the bundle: %v, %v", c, err)
	}
	// A dangling link.
	if err := os.Symlink(filepath.Join(outside, "nothing"), filepath.Join(cards, "dangling.yaml")); err != nil {
		t.Fatal(err)
	}
	if c, err := wanted.LoadCard(fsys, "dangling"); c != nil || err == nil {
		t.Errorf("a dangling link: %v, %v", c, err)
	}
	// A folder named x.yaml.
	if err := os.Mkdir(filepath.Join(cards, "folder.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, err = wanted.LoadCard(fsys, "folder")
	if c != nil || !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("a folder: %v, %v", c, err)
	}
	_ = wantFault(t, err, "want/cards/folder.yaml", 0, "not a regular file")
	// A pipe: the read does not wait for a writer.
	if err := syscall.Mkfifo(filepath.Join(cards, "pipe.yaml"), 0o644); err != nil {
		t.Skipf("no pipe: %v", err)
	}
	c, err = wanted.LoadCard(fsys, "pipe")
	if c != nil || !errors.Is(err, fsx.ErrNotRegular) {
		t.Errorf("a pipe: %v, %v", c, err)
	}
	_ = wantFault(t, err, "want/cards/pipe.yaml", 0, "not a regular file")
}

func TestLoadCardRefusesALinkInThePathOfTheFolder(t *testing.T) {
	dir, fsys := bundleDir(t, map[string]string{})
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "cards"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "cards", "a.yaml"), []byte(cardServerOne), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "want")); err != nil {
		t.Fatal(err)
	}
	c, err := wanted.LoadCard(fsys, "a")
	if c != nil || err == nil {
		t.Errorf("a card under a linked want/: %v, %v", c, err)
	}
	// The folder cards itself as a link.
	dir2, fsys2 := bundleDir(t, map[string]string{"elsewhere/a.yaml": cardServerOne})
	if err := os.MkdirAll(filepath.Join(dir2, "want"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../elsewhere", filepath.Join(dir2, "want", "cards")); err != nil {
		t.Fatal(err)
	}
	if c, err := wanted.LoadCard(fsys2, "a"); c != nil || !errors.Is(err, fsx.ErrLink) {
		t.Errorf("a card under a linked want/cards: %v, %v", c, err)
	}
}

func TestLoadCardTellsAFileOverTheLimitOfTheTextFromAFileOverTheLimitOfARead(t *testing.T) {
	// A file over wanted.MaxBytes and under the limit of a read: a fault of the text, with no cause.
	pad := "#" + strings.Repeat("x", wanted.MaxBytes) + "\n"
	_, fsys := bundleDir(t, map[string]string{"want/cards/long.yaml": cardServerOne + pad})
	c, err := wanted.LoadCard(fsys, "long")
	if c != nil || err == nil {
		t.Fatalf("a long file: %v, %v", c, err)
	}
	e := wantFault(t, err, "want/cards/long.yaml", 0, "longer than")
	if e.Unwrap() != nil || errors.Is(err, fsx.ErrTooLarge) {
		t.Errorf("a file under the limit of a read has a cause: %v", e.Unwrap())
	}
	// A file over the limit of a read: the error wraps fsx.ErrTooLarge.
	_, fsys = bundleDir(t, map[string]string{"want/cards/huge.yaml": strings.Repeat("a", fsx.MaxReadSize+1)})
	c, err = wanted.LoadCard(fsys, "huge")
	if c != nil || !errors.Is(err, fsx.ErrTooLarge) {
		t.Fatalf("a huge file: %v, %v", c, err)
	}
	_ = wantFault(t, err, "want/cards/huge.yaml", 0, "too long")
	// A file of the limit of a read is the first kind.
	_, fsys = bundleDir(t, map[string]string{"want/cards/edge.yaml": strings.Repeat("a", fsx.MaxReadSize)})
	c, err = wanted.LoadCard(fsys, "edge")
	if c != nil || err == nil || errors.Is(err, fsx.ErrTooLarge) {
		t.Errorf("a file of exactly the limit of a read: %v, %v", c, err)
	}
	// A file of exactly wanted.MaxBytes is read.
	exact := cardServerOne + "#" + strings.Repeat("x", wanted.MaxBytes-len(cardServerOne)-2) + "\n"
	_, fsys = bundleDir(t, map[string]string{"want/cards/exact.yaml": exact})
	c, err = wanted.LoadCard(fsys, "exact")
	if err != nil || len(c.File.Data) != wanted.MaxBytes {
		t.Errorf("a file of the limit: %v", err)
	}
}

func TestLoadCardWithNoFolderIsAnError(t *testing.T) {
	c, err := wanted.LoadCard(nil, "root-a")
	if c != nil || err == nil {
		t.Fatalf("a nil folder: %v, %v", c, err)
	}
	_ = wantFault(t, err, "want/cards/root-a.yaml", 0, "no folder")
	_, fsys := bundleDir(t, cardFiles())
	if err := fsys.Close(); err != nil {
		t.Fatal(err)
	}
	if c, err := wanted.LoadCard(fsys, "root-a"); c != nil || err == nil {
		t.Errorf("a closed folder: %v, %v", c, err)
	}
}

func TestLoadCardGivesTheBytesOfTheFileOnDisk(t *testing.T) {
	dir, fsys := bundleDir(t, cardFiles())
	p := filepath.Join(dir, "want", "cards", "root-a.yaml")
	c, err := wanted.LoadCard(fsys, "root-a")
	if err != nil {
		t.Fatal(err)
	}
	// A change of the file on disk after the read changes nothing in the card.
	if err := os.WriteFile(p, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if string(c.File.Data) != cardRootA || c.File.SHA256 != sha256hex([]byte(cardRootA)) {
		t.Error("the card follows the file on disk")
	}
	c2, err := wanted.LoadCard(fsys, "root-a")
	if c2 != nil || err == nil {
		t.Errorf("a changed file is read again: %v, %v", c2, err)
	}
}

// The list and the load together: every listed name loads, in the order of the names.
func TestEveryListedCardNameLoads(t *testing.T) {
	_, fsys := bundleDir(t, cardFiles())
	names, err := wanted.ListCardNames(fsys)
	if err != nil || len(names) != 5 {
		t.Fatalf("ListCardNames = %q, %v", names, err)
	}
	seen := map[string]string{}
	for _, n := range names {
		c, err := wanted.LoadCard(fsys, n)
		if err != nil {
			t.Fatalf("LoadCard(%s): %v", n, err)
		}
		if other, ok := seen[wanted.SerialKey(c.Serial)]; ok {
			t.Errorf("%s and %s are one card", n, other)
		}
		seen[wanted.SerialKey(c.Serial)] = n
	}
}

// A file that the system refuses to read is a fault of the system and not of the text: the error has a cause, and
// the cause is not a missing file and not a file that is too long.
func TestLoadCardOfAFileThatCannotBeReadHasACause(t *testing.T) {
	dir, fsys := bundleDir(t, cardFiles())
	p := filepath.Join(dir, "want", "cards", "root-a.yaml")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	if f, err := os.Open(p); err == nil {
		_ = f.Close()
		t.Skip("this user can read a file of mode 000")
	}
	c, err := wanted.LoadCard(fsys, "root-a")
	if c != nil || err == nil {
		t.Fatalf("LoadCard = %v, %v", c, err)
	}
	e := wantFault(t, err, "want/cards/root-a.yaml", 0, "the file cannot be read")
	if e.Unwrap() == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, fsx.ErrTooLarge) {
		t.Errorf("the cause of a refused read: %v", e.Unwrap())
	}
}
