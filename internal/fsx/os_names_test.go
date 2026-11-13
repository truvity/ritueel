package fsx_test

// Names on the real file system of the test machine (t.TempDir()). The in-memory file system
// keeps whatever name it is given; a real one may refuse a name, change it or hold it under
// another one. A name the writer accepts must be created under exactly that name, so these
// tests read the folder back and compare the names byte for byte. They say something about the
// file system that t.TempDir() is on (on the machine that runs them), not about a stick.

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// osNames are names the writer accepts and a workstation's file system must hold as they are:
// not ASCII, composed and decomposed, and at the edge of 255 bytes with one, two, three and four
// bytes to a character.
var osNames = []nameRow{
	{"Latin with accents", "é-ü-ñ.json"},
	{"Cyrillic and Chinese and an emoji", "ключ-鍵-😀.json"},
	{"a decomposed accent", "e\u0301.json"},
	{"the Kelvin sign", "\u212a.json"},
	{"an emoji with the variation selector U+FE0F", "\u2764\ufe0f.json"},
	{"a plain space inside", "my file.json"},
	{"255 ASCII bytes", ascii255},
	{"127 times é and a, 255 bytes", eAcute127a},
	{"85 times €, 255 bytes", euro85},
	{"63 times U+1F600 and abc, 255 bytes", emoji63abc},
}

// readBack lists dir and requires exactly the names in want (sorted), byte for byte.
func readBack(t *testing.T, dir string, want ...string) {
	t.Helper()
	got := names(t, dir)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("the folder %s holds %q, want %q (the file system of %s)", dir, got, want, os.TempDir())
	}
}

func TestOSAcceptedNamesAreCreatedUnderExactlyThatName(t *testing.T) {
	for _, row := range osNames {
		t.Run(row.why+"/WriteFile", func(t *testing.T) {
			dir := t.TempDir()
			if err := (&fsx.Writer{}).WriteFile(filepath.Join(dir, row.name), []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			if got := readFile(t, filepath.Join(dir, row.name)); string(got) != "data" {
				t.Fatalf("the file holds %q", got)
			}
		})
		t.Run(row.why+"/Mkdir", func(t *testing.T) {
			dir := t.TempDir()
			if err := (&fsx.Writer{}).Mkdir(filepath.Join(dir, row.name), 0o700); err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			if st, err := os.Stat(filepath.Join(dir, row.name)); err != nil || !st.IsDir() {
				t.Fatalf("%v, %v: want a folder", st, err)
			}
		})
		t.Run(row.why+"/CreateJournal", func(t *testing.T) {
			dir := t.TempDir()
			j, err := (&fsx.Writer{}).CreateJournal(filepath.Join(dir, row.name))
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Append([]byte("one")); err != nil {
				t.Fatal(err)
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			if got := readFile(t, filepath.Join(dir, row.name)); string(got) != "one\n" {
				t.Fatalf("the journal holds %q", got)
			}
		})
		t.Run(row.why+"/WriteSet folder and file", func(t *testing.T) {
			dir := t.TempDir()
			set := filepath.Join(dir, row.name)
			err := (&fsx.Writer{}).WriteSet(set, []fsx.NewFile{{Name: row.name, Data: []byte("data"), Perm: 0o600}})
			if err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			readBack(t, set, row.name)
			if got := readFile(t, filepath.Join(set, row.name)); string(got) != "data" {
				t.Fatalf("the file holds %q", got)
			}
		})
		t.Run(row.why+"/a folder in the middle", func(t *testing.T) {
			dir := t.TempDir()
			mid := filepath.Join(dir, row.name)
			if err := os.Mkdir(mid, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := (&fsx.Writer{}).WriteFile(filepath.Join(mid, "f.json"), []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			readBack(t, mid, "f.json")
		})
	}
}

// TestOSSetWithTheKelvinSignAndKIsWrittenWhole: the Kelvin sign and "k" are
// two names that the writer lets into one set; a file system that cannot hold both would fail
// here and not on a stick.
func TestOSSetWithTheKelvinSignAndKIsWrittenWhole(t *testing.T) {
	dir := t.TempDir()
	set := filepath.Join(dir, "s")
	err := (&fsx.Writer{}).WriteSet(set, []fsx.NewFile{
		{Name: "\u212a.json", Data: []byte("kelvin"), Perm: 0o600},
		{Name: "k.json", Data: []byte("k"), Perm: 0o600},
	})
	if err != nil {
		t.Fatal(err)
	}
	readBack(t, set, "\u212a.json", "k.json")
	if got := readFile(t, filepath.Join(set, "\u212a.json")); string(got) != "kelvin" {
		t.Fatalf("the Kelvin file holds %q", got)
	}
}

// TestOSRelativePathsWithAndWithoutAFolder: the paths that have no folder ("x", whose folder is
// ".") or a relative one, relative to the working directory of the process.
func TestOSRelativePathsWithAndWithoutAFolder(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Mkdir("d", 0o700); err != nil {
		t.Fatal(err)
	}
	w := &fsx.Writer{}
	for _, p := range []string{"x.json", "d/y.json", "é.json"} {
		if err := w.WriteFile(p, []byte(p), 0o600); err != nil {
			t.Fatalf("WriteFile %q: %v", p, err)
		}
	}
	readBack(t, dir, "d", "x.json", "é.json")
	readBack(t, filepath.Join(dir, "d"), "y.json")
	if err := w.Mkdir("m", 0o700); err != nil {
		t.Fatal(err)
	}
	j, err := w.CreateJournal("j.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	if err := w.WriteSet("s", []fsx.NewFile{{Name: "a", Data: []byte("a"), Perm: 0o600}}); err != nil {
		t.Fatal(err)
	}
	readBack(t, dir, "d", "j.jsonl", "m", "s", "x.json", "é.json")
}

// TestOSRefusedNamesCreateNothing: a refused name does not reach the real file system, which
// would answer a name of 256 bytes with its own error, and the writer goes on.
func TestOSRefusedNamesCreateNothing(t *testing.T) {
	dir := t.TempDir()
	w := &fsx.Writer{}
	for _, name := range []string{ascii256, eAcute128, emoji127a, "a.", "a ", "a:b", `a\b`, "a\x01b", "a\xffb", "a|b"} {
		p := filepath.Join(dir, name)
		for what, err := range map[string]error{
			"WriteFile": w.WriteFile(p, []byte("x"), 0o600),
			"Mkdir":     w.Mkdir(p, 0o700),
			"WriteSet":  w.WriteSet(p, []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}}),
		} {
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s %q = %v, want ErrInvalid", what, name, err)
			}
		}
		if _, err := w.CreateJournal(p); !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("CreateJournal %q = %v, want ErrInvalid", name, err)
		}
		err := w.WriteSet(filepath.Join(dir, "s"), []fsx.NewFile{{Name: name, Data: []byte("x"), Perm: 0o600}})
		if !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("WriteSet with the file %q = %v, want ErrInvalid", name, err)
		}
	}
	readBack(t, dir)
	if err := w.WriteFile(filepath.Join(dir, "ok.json"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("the writer stopped after refusing names: %v", err)
	}
	readBack(t, dir, "ok.json")
}

// TestOSDeviceNameIsRefusedAndCreatesNothing: a device name of Windows (also with spaces before
// the extension), a name with a character that is not printable (a no-break space, a
// zero-width space, an emoji sequence joined with U+200D), and the temporary prefix in
// capitals, are refused for every method before the real file system is touched. Linux
// would have created "aux"; the writer refuses it because the stick goes to Windows machines.
func TestOSDeviceNameIsRefusedAndCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	w := &fsx.Writer{}
	for _, name := range []string{"aux", "Nul.txt", "COM1", "lpt\u00b2.tar.gz", ".RT-x", "nul .txt", "com1 ", "a\u00a0b", "a\u200bb", "\U0001f468\u200d\U0001f469"} {
		p := filepath.Join(dir, name)
		for what, err := range map[string]error{
			"WriteFile": w.WriteFile(p, []byte("x"), 0o600),
			"Mkdir":     w.Mkdir(p, 0o700),
			"WriteSet":  w.WriteSet(p, []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}}),
		} {
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s %q = %v, want ErrInvalid", what, name, err)
			}
		}
		if _, err := w.CreateJournal(p); !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("CreateJournal %q = %v, want ErrInvalid", name, err)
		}
		if err := w.WriteSet(filepath.Join(dir, "s"), []fsx.NewFile{{Name: name, Data: []byte("x"), Perm: 0o600}}); !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("WriteSet with the file %q = %v, want ErrInvalid", name, err)
		}
	}
	readBack(t, dir)
	// a name that only looks like a device name is created as it is
	for _, name := range []string{"auxiliary", "com10", ".con", "a.con", "COM\u00b2x", "com0", "lpt0", " nul", "nul x.txt"} {
		if err := w.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Errorf("WriteFile %q: %v", name, err)
		}
	}
	readBack(t, dir, "auxiliary", "com10", ".con", "a.con", "COM\u00b2x", "com0", "lpt0", " nul", "nul x.txt")
}
