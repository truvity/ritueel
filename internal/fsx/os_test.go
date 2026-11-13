package fsx_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The writer on the real file system of the test machine (t.TempDir()).

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

func tempNamed(list []string) []string {
	var out []string
	for _, n := range list {
		if strings.HasPrefix(n, fsx.TempPrefix) {
			out = append(out, n)
		}
	}
	return out
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOSWriteFileWritesContentAndModeAndLeavesNoTemporaryName(t *testing.T) {
	dir := t.TempDir()
	w := &fsx.Writer{}
	for _, perm := range []fs.FileMode{0o600, 0o400} {
		p := filepath.Join(dir, fmt.Sprintf("f-%o.json", perm))
		data := bytes.Repeat([]byte("abc"), 500)
		if err := w.WriteFile(p, data, perm); err != nil {
			t.Fatal(err)
		}
		if got := readFile(t, p); !bytes.Equal(got, data) {
			t.Fatalf("content differs: %d bytes", len(got))
		}
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != perm {
			t.Fatalf("mode %v, want %v", st.Mode().Perm(), perm)
		}
	}
	if left := tempNamed(names(t, dir)); len(left) != 0 {
		t.Fatalf("temporary names left after success: %v", left)
	}
	if got := names(t, dir); len(got) != 2 {
		t.Fatalf("the folder holds %v, want two files", got)
	}
}

func TestOSWriteFileNeverReplacesAndKeepsTheFirstContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "attempt.json")
	w := &fsx.Writer{}
	if err := w.WriteFile(p, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := w.WriteFile(p, []byte("second"), 0o600)
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe.Step != fsx.StepRename || fe.Path != p || !errors.Is(err, fs.ErrExist) {
		if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
			t.Skipf("this file system has no rename that refuses to replace: %v", err)
		}
		t.Fatalf("second WriteFile = %v, want a rename error at the path wrapping fs.ErrExist", err)
	}
	if got := readFile(t, p); string(got) != "first" {
		t.Fatalf("the file holds %q after the second write", got)
	}
	// Nothing is deleted: the refused content stays under its temporary name.
	left := tempNamed(names(t, dir))
	if len(left) != 1 || string(readFile(t, filepath.Join(dir, left[0]))) != "second" {
		t.Fatalf("temporary names after the refused write: %v", left)
	}
	// The writer is stopped.
	if err2 := w.WriteFile(filepath.Join(dir, "other.json"), []byte("x"), 0o600); !sameError(err2, err) {
		t.Fatalf("a later write returned %v, want the same error", err2)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a later write wrote a file: %v", err)
	}
}

func TestOSWriteSetMakesTheFolderWholeAndASecondOneFails(t *testing.T) {
	root := t.TempDir()
	final := filepath.Join(root, "0007-acme")
	w := &fsx.Writer{}
	files := []fsx.NewFile{
		{Name: "keys.json", Data: []byte(`{"keys":[]}`), Perm: 0o600},
		{Name: "root.json", Data: bytes.Repeat([]byte("r"), 2000), Perm: 0o400},
		{Name: "empty", Data: nil, Perm: 0o600},
	}
	if err := w.WriteSet(final, files); err != nil {
		t.Fatal(err)
	}
	if got := names(t, root); !slices.Equal(got, []string{"0007-acme"}) {
		t.Fatalf("the parent holds %v, want only the set (no temporary folder after success)", got)
	}
	st, err := os.Stat(final)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("the set folder: %v, %v (want a folder of mode 0700)", st, err)
	}
	if got := names(t, final); !slices.Equal(got, []string{"empty", "keys.json", "root.json"}) {
		t.Fatalf("the set holds %v", got)
	}
	for _, f := range files {
		if got := readFile(t, filepath.Join(final, f.Name)); !bytes.Equal(got, f.Data) {
			t.Fatalf("%s holds %d bytes, want %d", f.Name, len(got), len(f.Data))
		}
		if st, _ := os.Stat(filepath.Join(final, f.Name)); st.Mode().Perm() != f.Perm {
			t.Fatalf("%s has mode %v, want %v", f.Name, st.Mode().Perm(), f.Perm)
		}
	}

	err = w.WriteSet(final, []fsx.NewFile{{Name: "other.json", Data: []byte("other"), Perm: 0o600}})
	if !errors.Is(err, fs.ErrExist) {
		if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
			t.Skipf("no rename that refuses to replace here: %v", err)
		}
		t.Fatalf("second WriteSet = %v, want fs.ErrExist", err)
	}
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe.Step != fsx.StepRename || fe.Path != final {
		t.Fatalf("second WriteSet = %v, want a rename error at %s", err, final)
	}
	if got := names(t, final); !slices.Equal(got, []string{"empty", "keys.json", "root.json"}) {
		t.Fatalf("the first set was changed: %v", got)
	}
	// The temporary folder of the refused set is left where it is.
	left := tempNamed(names(t, root))
	if len(left) != 1 || !slices.Equal(names(t, filepath.Join(root, left[0])), []string{"other.json"}) {
		t.Fatalf("temporary names after the refused set: %v", left)
	}
}

func TestOSMkdirTwiceFails(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "20261113-apply")
	w := &fsx.Writer{}
	if err := w.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("the folder: %v, %v", st, err)
	}
	err := w.Mkdir(p, 0o700)
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe.Step != fsx.StepMkdir || fe.Path != p || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second Mkdir = %v, want a mkdir error at the path wrapping fs.ErrExist", err)
	}
}

func TestOSJournalTenAppendsReadBackAsTenLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "signatures.jsonl")
	w := &fsx.Writer{}
	j, err := w.CreateJournal(p)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 || st.Size() != 0 {
		t.Fatalf("a new journal: %v, %v (want an empty file of mode 0600)", st, err)
	}
	var want []string
	for i := 0; i < 10; i++ {
		line := fmt.Sprintf(`{"n":%d}`, i)
		want = append(want, line)
		if err := j.Append([]byte(line)); err != nil {
			t.Fatal(err)
		}
		// each Append is on the disk before it returns: the file already holds it
		if got := readFile(t, p); string(got) != strings.Join(want, "\n")+"\n" {
			t.Fatalf("after Append %d the file holds %q", i, got)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	lines, partial, err := fsx.ReadJournal(fsx.OS, p)
	if err != nil || partial != nil || len(lines) != 10 {
		t.Fatalf("ReadJournal: %d lines, partial %q, %v", len(lines), partial, err)
	}
	for i, l := range lines {
		if string(l) != want[i] {
			t.Fatalf("line %d is %q, want %q", i, l, want[i])
		}
	}

	// A last line written by hand with no newline comes back apart.
	h, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteString(`{"n":10,"si`); err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	lines, partial, err = fsx.ReadJournal(fsx.OS, p)
	if err != nil || len(lines) != 10 || string(partial) != `{"n":10,"si` {
		t.Fatalf("ReadJournal with a torn line: %d lines, partial %q, %v", len(lines), partial, err)
	}
}

func TestOSSecondCreateJournalFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "births.jsonl")
	w := &fsx.Writer{}
	j, err := w.CreateJournal(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Append([]byte("one"))
	_ = j.Close()
	w2 := &fsx.Writer{}
	j2, err := w2.CreateJournal(p)
	var fe *fsx.Error
	if j2 != nil || !errors.As(err, &fe) || fe.Step != fsx.StepCreate || fe.Path != p || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second CreateJournal = %v, %v, want a create error wrapping fs.ErrExist", j2, err)
	}
	if got := readFile(t, p); string(got) != "one\n" {
		t.Fatalf("the journal holds %q", got)
	}
}

func TestOSWriteIntoAFolderThatDoesNotExistFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing", "f.json")
	err := (&fsx.Writer{}).WriteFile(p, []byte("x"), 0o600)
	var fe *fsx.Error
	if !errors.As(err, &fe) || fe.Step != fsx.StepCreate || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want a create error wrapping fs.ErrNotExist", err)
	}
}

func TestOSFilesystemPrimitives(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x")
	f, err := fsx.OS.CreateExcl(p, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err := fsx.OS.CreateExcl(p, 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second CreateExcl = %v, want ErrExist", err)
	}
	if err := fsx.OS.Mkdir(dir, 0o700); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Mkdir of an existing folder = %v, want ErrExist", err)
	}
	if err := fsx.OS.SyncDir(dir); err != nil {
		t.Fatalf("SyncDir of a folder: %v", err)
	}
	if err := fsx.OS.SyncDir(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("SyncDir of a missing folder = %v, want ErrNotExist", err)
	}
	if _, err := fsx.OS.ReadFile(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile of a missing file = %v", err)
	}
	if _, err := fsx.OS.Stat(p); err != nil {
		t.Fatal(err)
	}
	if ents, err := fsx.OS.ReadDir(dir); err != nil || len(ents) != 1 {
		t.Fatalf("ReadDir: %v, %v", ents, err)
	}
}

// TestOSTwoWritersRaceForOneNameAndExactlyOneWins: the rename that refuses to replace is
// what makes a name taken once, also across processes (here, across writers).
func TestOSTwoWritersRaceForOneNameAndExactlyOneWins(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "attempt.json")
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = (&fsx.Writer{}).WriteFile(p, []byte(fmt.Sprintf("writer-%02d", i)), 0o600)
		}()
	}
	wg.Wait()
	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("writers %d and %d both succeeded: a name was taken twice", winner, i)
			}
			winner = i
		case errors.Is(err, fsx.ErrNoReplaceUnsupported):
			t.Skipf("no rename that refuses to replace here: %v", err)
		case !errors.Is(err, fs.ErrExist):
			t.Fatalf("writer %d: %v, want fs.ErrExist", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no writer succeeded")
	}
	if got := readFile(t, p); string(got) != fmt.Sprintf("writer-%02d", winner) {
		t.Fatalf("the file holds %q, the winner is %d", got, winner)
	}
}

// TestOneWriterIsSafeForSeveralGoroutines: its calls run one at a time (run it under -race
// where the race detector is available).
func TestOneWriterIsSafeForSeveralGoroutines(t *testing.T) {
	f := newMemFS("/b", "/b/d")
	w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
	const workers, per = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := w.WriteFile(fmt.Sprintf("/b/d/f-%d-%d.json", g, i), []byte(fmt.Sprintf("%d/%d", g, i)), 0o600); err != nil {
					errs <- err
					return
				}
			}
			j, err := w.CreateJournal(fmt.Sprintf("/b/d/j-%d.jsonl", g))
			if err != nil {
				errs <- err
				return
			}
			for i := 0; i < per; i++ {
				if err := j.Append([]byte(fmt.Sprintf("line-%d-%d", g, i))); err != nil {
					errs <- err
					return
				}
			}
			errs <- j.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	live := f.Live()
	for g := 0; g < workers; g++ {
		for i := 0; i < per; i++ {
			if got := mustFile(t, live, fmt.Sprintf("/b/d/f-%d-%d.json", g, i)); string(got) != fmt.Sprintf("%d/%d", g, i) {
				t.Fatalf("file %d-%d holds %q", g, i, got)
			}
		}
		lines, partial, err := fsx.ReadJournal(live, fmt.Sprintf("/b/d/j-%d.jsonl", g))
		if err != nil || partial != nil || len(lines) != per {
			t.Fatalf("journal %d: %d lines, partial %q, %v", g, len(lines), partial, err)
		}
		for i, l := range lines {
			if string(l) != fmt.Sprintf("line-%d-%d", g, i) {
				t.Fatalf("journal %d line %d is %q", g, i, l)
			}
		}
	}
}

// TestOneWriterRacingForOnePathStopsTheLoser: two goroutines on one writer and one path: one
// wins, the other gets the refusal, and the content is the winner's.
func TestOneWriterRacingForOnePathStopsTheLoser(t *testing.T) {
	f := newMemFS("/b", "/b/d")
	w := &fsx.Writer{FS: f, Rand: newDetRand(1)}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = w.WriteFile("/b/d/f.json", []byte(fmt.Sprintf("writer %d", i)), 0o600)
		}()
	}
	wg.Wait()
	ok := 0
	for i, err := range errs {
		if err == nil {
			ok++
			if got := mustFile(t, f.Live(), "/b/d/f.json"); string(got) != fmt.Sprintf("writer %d", i) {
				t.Fatalf("the file holds %q, the winner is %d", got, i)
			}
		} else if !errors.Is(err, fs.ErrExist) {
			t.Fatalf("writer %d: %v", i, err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d writers succeeded, want exactly one", ok)
	}
}
