//go:build linux || darwin

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
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

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

// TestOSAcceptedNamesAreCreatedUnderExactlyThatName: every accepted name of the table, with each
// method, in the last place, in the middle and as a file of a set.
func TestOSAcceptedNamesAreCreatedUnderExactlyThatName(t *testing.T) {
	for _, row := range acceptedNames {
		t.Run(row.why+"/WriteFile", func(t *testing.T) {
			w, dir := openIn(t)
			if err := w.WriteFile(row.name, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			if got := readFile(t, filepath.Join(dir, row.name)); string(got) != "data" {
				t.Fatalf("the file holds %q", got)
			}
		})
		t.Run(row.why+"/Mkdir", func(t *testing.T) {
			w, dir := openIn(t)
			if err := w.Mkdir(row.name, 0o700); err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			if st, err := os.Stat(filepath.Join(dir, row.name)); err != nil || !st.IsDir() {
				t.Fatalf("%v, %v: want a folder", st, err)
			}
		})
		t.Run(row.why+"/CreateJournal", func(t *testing.T) {
			w, dir := openIn(t)
			j, err := w.CreateJournal(row.name)
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
			w, dir := openIn(t)
			err := w.WriteSet(row.name, []fsx.NewFile{{Name: row.name, Data: []byte("data"), Perm: 0o600}})
			if err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			readBack(t, filepath.Join(dir, row.name), row.name)
			if got := readFile(t, filepath.Join(dir, row.name, row.name)); string(got) != "data" {
				t.Fatalf("the file holds %q", got)
			}
		})
		t.Run(row.why+"/a folder in the middle", func(t *testing.T) {
			w, dir := openIn(t)
			if err := os.Mkdir(filepath.Join(dir, row.name), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := w.WriteFile(row.name+"/f.json", []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			readBack(t, dir, row.name)
			readBack(t, filepath.Join(dir, row.name), "f.json")
		})
	}
}

// TestOSEveryAllowedCharacterIsCreatedUnderExactlyThatName: a real write of each of the 65, in the
// first, an inner and the last place, read back byte for byte.
func TestOSEveryAllowedCharacterIsCreatedUnderExactlyThatName(t *testing.T) {
	w, dir := openIn(t)
	var want []string
	seen := map[string]bool{}
	for _, c := range allowedChars() {
		ch := string(rune(c))
		for _, name := range []string{ch + "x1", "x" + ch + "1", "x1" + ch, ch} {
			if (c == '.' && (strings.HasSuffix(name, ".") || name == ".")) || seen[name] {
				continue
			}
			seen[name] = true
			if err := w.WriteFile(name, []byte("v"+name), 0o600); err != nil {
				t.Fatalf("WriteFile %q: %v", name, err)
			}
			want = append(want, name)
		}
	}
	slices.Sort(want)
	want = slices.Compact(want)
	readBack(t, dir, want...)
	for _, name := range want {
		if got := readFile(t, filepath.Join(dir, name)); string(got) != "v"+name {
			t.Fatalf("%q holds %q", name, got)
		}
	}
}

// TestOSRefusedNamesCreateNothing: a refused name does not reach the real file system, which
// would answer a name of 256 bytes with its own error, and the writer goes on.
func TestOSRefusedNamesCreateNothing(t *testing.T) {
	w, dir := openIn(t)
	for _, name := range []string{
		rep("a", 256), rep("é", 128), "a.", "a ", "a:b", `a\b`, "a\x01b", "a\xffb", "a|b", "é", "ключ", "a😀",
		"aux", "Nul.txt", "COM1", "lpt².tar.gz", ".RT-x", "nul .txt", "com1 ", "a\u00a0b", "a\u200bb",
		"\U0001f468\u200d\U0001f469", "a b", "a*b", "a?b", `a"b`, "a<b", "a>b", "a\tb", "a\nb", "a\x7fb", "..." + rep(".", 3) + "x.",
	} {
		for what, err := range map[string]error{
			"WriteFile": w.WriteFile(name, []byte("x"), 0o600),
			"Mkdir":     w.Mkdir(name, 0o700),
			"WriteSet":  w.WriteSet(name, []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: 0o600}}),
		} {
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s %q = %v, want ErrInvalid", what, name, err)
			}
		}
		if _, err := w.CreateJournal(name); !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("CreateJournal %q = %v, want ErrInvalid", name, err)
		}
		err := w.WriteSet("s", []fsx.NewFile{{Name: name, Data: []byte("x"), Perm: 0o600}})
		if !errors.Is(err, fsx.ErrInvalid) {
			t.Errorf("WriteSet with the file %q = %v, want ErrInvalid", name, err)
		}
	}
	readBack(t, dir)
	if err := w.WriteFile("ok.json", []byte("ok"), 0o600); err != nil {
		t.Fatalf("the writer stopped after refusing names: %v", err)
	}
	readBack(t, dir, "ok.json")
}

// TestOSNamesThatOnlyLookLikeADeviceNameAreCreatedAsTheyAre: a device name of Windows is refused,
// and a name that only looks like one is written.
func TestOSNamesThatOnlyLookLikeADeviceNameAreCreatedAsTheyAre(t *testing.T) {
	w, dir := openIn(t)
	var want []string
	for _, name := range []string{"auxiliary", "com10", ".con", "a.con", "com0", "lpt0", "con1", "nul-x.txt", "COM10"} {
		if err := w.WriteFile(name, []byte(name), 0o600); err != nil {
			t.Errorf("WriteFile %q: %v", name, err)
		}
		want = append(want, name)
	}
	readBack(t, dir, want...)
}

// TestOSLongestNameIsCreated: 255 bytes, the limit of the file system of a workstation, is
// written whole, and 256 is refused by the writer and not by the file system.
func TestOSLongestNameIsCreated(t *testing.T) {
	w, dir := openIn(t)
	long := rep("a", 255)
	if err := w.WriteFile(long, []byte("x"), 0o600); err != nil {
		t.Skipf("this file system does not hold a name of 255 bytes: %v", err)
	}
	if err := w.Mkdir(rep("b", 255), 0o700); err != nil {
		t.Fatal(err)
	}
	readBack(t, dir, long, rep("b", 255))
	err := w.WriteFile(rep("a", 256), []byte("x"), 0o600)
	if !errors.Is(err, fsx.ErrInvalid) || errors.Is(err, fsx.ErrStopped) {
		t.Fatalf("a name of 256 bytes: %v, want ErrInvalid from the writer", err)
	}
}

// TestOSTemporaryNameOfAFileIsShortEnoughToLeaveNothingLongerThanItself: the temporary name of a
// write that failed is left, and it is the 15 characters of the rule.
func TestOSTheTemporaryNameThatIsLeftHasTheRightShape(t *testing.T) {
	w, dir := openIn(t)
	if err := w.WriteFile("f", []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFile("f", []byte("b"), 0o600); err == nil {
		t.Fatal("a second write of one name succeeded")
	}
	left := tempNamed(names(t, dir))
	if len(left) != 1 || !tempShape.MatchString(left[0]) {
		t.Fatalf("temporary names: %v, want one of the shape .rt- and 11 of [a-z0-9]", left)
	}
}
