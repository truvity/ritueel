package fsx_test

// The mode of what the writer makes: a file needs the owner's read bit (0o400), a folder the owner's
// read, write and search bits (0o700); a bit beyond the nine permission bits is refused first.

import (
	"errors"
	"io/fs"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

func modeText(perm fs.FileMode, folder bool) string {
	if folder {
		return invalidPrefix + "mode " + perm.String() + ": a folder needs the owner's read, write and search bits"
	}
	return invalidPrefix + "mode " + perm.String() + ": a file needs the owner's read bit"
}

func TestEveryOneOfTheFiveHundredAndTwelveModesAgainstTheRule(t *testing.T) {
	for m := 0; m < 512; m++ {
		perm := fs.FileMode(m)
		fileOK, dirOK := m&0o400 == 0o400, m&0o700 == 0o700
		for _, c := range []struct {
			what   string
			do     func(w *fsx.Writer) error
			ok     bool
			folder bool
			kind   opKind
		}{
			{"WriteFile", func(w *fsx.Writer) error { return w.WriteFile("b/f", []byte("x"), perm) }, fileOK, false, kCreate},
			{"a file of a set", func(w *fsx.Writer) error {
				return w.WriteSet("b/s", []fsx.NewFile{{Name: "a", Data: []byte("x"), Perm: perm}})
			}, fileOK, false, kCreate},
			{"Mkdir", func(w *fsx.Writer) error { return w.Mkdir("b/m", perm) }, dirOK, true, kMkdir},
		} {
			f := newMemFS("b")
			w := newWriter(t, f, 1)
			err := c.do(w)
			if c.ok {
				if err != nil {
					t.Fatalf("%s with mode %v (%#o): %v, want it accepted", c.what, perm, m, err)
				}
				seen := false
				for _, o := range f.opList() {
					if o.Kind == c.kind && o.Mode == perm {
						seen = true
					}
				}
				if !seen {
					t.Fatalf("%s with mode %v: no call made with that mode: %v", c.what, perm, f.opList())
				}
				continue
			}
			if want := modeText(perm, c.folder); err == nil || err.Error() != want || !errors.Is(err, fsx.ErrInvalid) {
				t.Fatalf("%s with mode %v (%#o): %v, want\n  %s", c.what, perm, m, err, want)
			}
			if f.opCount() != 0 {
				t.Fatalf("%s with mode %v reached the file system: %v", c.what, perm, f.opList())
			}
			if err := w.WriteFile("b/ok", nil, 0o400); err != nil {
				t.Fatalf("the writer stopped after a refused mode: %v", err)
			}
		}
	}
}

func TestABitBeyondThePermissionBitsIsRefusedBeforeTheOwnersBits(t *testing.T) {
	for _, perm := range []fs.FileMode{fs.ModeDir, fs.ModeDir | 0o700, fs.ModeSetuid, fs.ModeSetuid | 0o400, fs.ModeSticky | 0o777, fs.ModeSymlink, fs.ModeNamedPipe | 0o400, 0o1000} {
		f := newMemFS("b")
		w := newWriter(t, f, 1)
		for what, err := range map[string]error{
			"WriteFile": w.WriteFile("b/f", nil, perm),
			"Mkdir":     w.Mkdir("b/m", perm),
			"WriteSet":  w.WriteSet("b/s", []fsx.NewFile{{Name: "a", Perm: perm}}),
		} {
			want := invalidPrefix + "mode " + perm.String() + " has bits beyond the permission bits"
			if err == nil || err.Error() != want {
				t.Errorf("%s with mode %v: %v, want\n  %s", what, perm, err, want)
			}
		}
	}
}

// The mode of a file of a set is checked as its name is: file by file, so a bad mode of an earlier
// file comes before a repeated name of a later one, and the repeated name of a file comes before its
// own mode (the order in checkFiles is the name, the repeat, then the mode).
func TestTheModeOfAFileOfASetAgainstTheRepeatedName(t *testing.T) {
	f := newMemFS("b")
	w := newWriter(t, f, 1)
	nf := func(n string, p fs.FileMode) fsx.NewFile { return fsx.NewFile{Name: n, Perm: p} }
	for _, c := range []struct {
		why   string
		files []fsx.NewFile
		want  string
	}{
		{"a bad mode, then the same name with a good one", []fsx.NewFile{nf("a", 0), nf("A", 0o600)}, modeText(0, false)},
		{"a good mode, then the same name with a bad one", []fsx.NewFile{nf("a", 0o600), nf("A", 0)}, fileText("A", "is given twice")},
		{"a bad mode, then a bad name", []fsx.NewFile{nf("a", 0), nf("b c", 0o600)}, modeText(0, false)},
		{"a bad name, then a bad mode", []fsx.NewFile{nf("b c", 0o600), nf("a", 0)}, fileText("b c", hasChar(' '))},
		{"the bad mode of the second file", []fsx.NewFile{nf("a", 0o600), nf("b", 0o200)}, modeText(0o200, false)},
	} {
		err := w.WriteSet("b/s", c.files)
		if err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want\n  %s", c.why, err, c.want)
		}
	}
	if f.opCount() != 0 {
		t.Fatal("a refused set reached the file system")
	}
}
