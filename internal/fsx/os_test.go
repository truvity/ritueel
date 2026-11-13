//go:build linux || darwin

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
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The writer on the real file system of the test machine (t.TempDir()), rooted at a folder of it.

// openIn opens a writer rooted at a new temporary folder, and closes it when the test ends.
func openIn(t testing.TB) (*fsx.Writer, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	t.Cleanup(func() {
		// a writer that stopped returns the stop from Close, and a test that made it stop knows
		if err := w.Close(); err != nil && !errors.Is(err, fsx.ErrStopped) {
			t.Errorf("Close: %v", err)
		}
	})
	return w, dir
}

// openFSIn opens the root folder of dir as an fsx.FS and closes it when the test ends.
func openFSIn(t testing.TB, dir string) fsx.FS {
	t.Helper()
	root, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatalf("OpenFS(%s): %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func names(t testing.TB, dir string) []string {
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

func readFile(t testing.TB, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOSWriteFileWritesContentAndModeAndLeavesNoTemporaryName(t *testing.T) {
	w, dir := openIn(t)
	for _, perm := range []fs.FileMode{0o600, 0o400} {
		name := fmt.Sprintf("f-%o.json", perm)
		data := bytes.Repeat([]byte("abc"), 500)
		if err := w.WriteFile(name, data, perm); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
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

func TestOSWriteFileInAFolderBelowTheRoot(t *testing.T) {
	w, dir := openIn(t)
	if err := os.MkdirAll(filepath.Join(dir, "b", "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteFile("b/d/f.json", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dir, "b", "d", "f.json")); string(got) != "x" {
		t.Fatalf("holds %q", got)
	}
	if got := names(t, filepath.Join(dir, "b", "d")); !slices.Equal(got, []string{"f.json"}) {
		t.Fatalf("the folder holds %v", got)
	}
}

func TestOSWriteFileNeverReplacesAndKeepsTheFirstContent(t *testing.T) {
	w, dir := openIn(t)
	p := filepath.Join(dir, "attempt.json")
	if err := w.WriteFile("attempt.json", []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := w.WriteFile("attempt.json", []byte("second"), 0o600)
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("this file system has no rename that refuses to replace: %v", err)
	}
	fe := requireFailed(t, err)
	if fe.Step != fsx.StepRename || fe.Path != "attempt.json" || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second WriteFile = %v, want a rename error at the path wrapping fs.ErrExist", err)
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) || errno != syscall.EEXIST {
		t.Fatalf("second WriteFile = %v, want the errno EEXIST inside", err)
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
	requireStoppedBy(t, w.WriteFile("other.json", []byte("x"), 0o600), fe)
	if _, err := os.Stat(filepath.Join(dir, "other.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a later write wrote a file: %v", err)
	}
}

func TestOSWriteSetMakesTheFolderWholeAndASecondOneFails(t *testing.T) {
	w, root := openIn(t)
	final := filepath.Join(root, "0007-acme")
	files := []fsx.NewFile{
		{Name: "keys.json", Data: []byte(`{"keys":[]}`), Perm: 0o600},
		{Name: "root.json", Data: bytes.Repeat([]byte("r"), 2000), Perm: 0o400},
		{Name: "empty", Data: nil, Perm: 0o600},
	}
	if err := w.WriteSet("0007-acme", files); err != nil {
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

	err = w.WriteSet("0007-acme", []fsx.NewFile{{Name: "other.json", Data: []byte("other"), Perm: 0o600}})
	if errors.Is(err, fsx.ErrNoReplaceUnsupported) {
		t.Skipf("no rename that refuses to replace here: %v", err)
	}
	fe := requireFailed(t, err)
	if !errors.Is(err, fs.ErrExist) || fe.Step != fsx.StepRename || fe.Path != "0007-acme" {
		t.Fatalf("second WriteSet = %v, want a rename error at 0007-acme wrapping fs.ErrExist", err)
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
	w, root := openIn(t)
	p := filepath.Join(root, "20261113-apply")
	if err := w.Mkdir("20261113-apply", 0o700); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatalf("the folder: %v, %v", st, err)
	}
	err := w.Mkdir("20261113-apply", 0o700)
	fe := requireFailed(t, err)
	if fe.Step != fsx.StepMkdir || fe.Path != "20261113-apply" || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second Mkdir = %v, want a mkdir error at the path wrapping fs.ErrExist", err)
	}
}

func TestOSJournalTenAppendsReadBackAsTenLines(t *testing.T) {
	w, dir := openIn(t)
	p := filepath.Join(dir, "signatures.jsonl")
	j, err := w.CreateJournal("signatures.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 || st.Size() != 0 {
		t.Fatalf("a new journal: %v, %v (want an empty file of mode 0600)", st, err)
	}
	root := openFSIn(t, dir)
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
	lines, partial, err := fsx.ReadJournal(root, "signatures.jsonl")
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
	lines, partial, err = fsx.ReadJournal(root, "signatures.jsonl")
	if err != nil || len(lines) != 10 || string(partial) != `{"n":10,"si` {
		t.Fatalf("ReadJournal with a torn line: %d lines, partial %q, %v", len(lines), partial, err)
	}
}

func TestOSSecondCreateJournalFails(t *testing.T) {
	w, dir := openIn(t)
	j, err := w.CreateJournal("births.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	_ = j.Append([]byte("one"))
	_ = j.Close()
	w2, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w2.Close() }()
	j2, err := w2.CreateJournal("births.jsonl")
	fe := asError(t, err)
	if j2 != nil || fe.Step != fsx.StepCreate || fe.Path != "births.jsonl" || !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second CreateJournal = %v, %v, want a create error wrapping fs.ErrExist", j2, err)
	}
	if got := readFile(t, filepath.Join(dir, "births.jsonl")); string(got) != "one\n" {
		t.Fatalf("the journal holds %q", got)
	}
}

func TestOSWriteIntoAFolderThatDoesNotExistFails(t *testing.T) {
	w, dir := openIn(t)
	err := w.WriteFile("missing/f.json", []byte("x"), 0o600)
	fe := requireFailed(t, err)
	if fe.Step != fsx.StepOpenDir || fe.Path != "missing" || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("got %v, want an open-dir error at missing wrapping fs.ErrNotExist", err)
	}
	if got := names(t, dir); len(got) != 0 {
		t.Fatalf("the folder holds %v", got)
	}
}

// TestOSFilesystemPrimitives: the folder handle of the real file system, call by call.
func TestOSFilesystemPrimitives(t *testing.T) {
	dir := t.TempDir()
	root := openFSIn(t, dir)
	f, err := root.CreateExcl("x", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := root.CreateExcl("x", 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second CreateExcl = %v, want ErrExist", err)
	}
	if err := root.Mkdir("d", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir("d", 0o700); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Mkdir of an existing folder = %v, want ErrExist", err)
	}
	if err := root.Mkdir("x", 0o700); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("Mkdir over a file = %v, want ErrExist", err)
	}
	if err := root.Sync(); err != nil {
		t.Fatalf("Sync of a folder: %v", err)
	}
	if got, err := root.ReadFile("x"); err != nil || string(got) != "hello" {
		t.Fatalf("ReadFile: %q, %v", got, err)
	}
	if _, err := root.ReadFile("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile of a missing file = %v", err)
	}
	if _, err := root.OpenDir("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("OpenDir of a missing folder = %v, want ErrNotExist", err)
	}
	if _, err := root.OpenDir("x"); err == nil || errors.Is(err, fs.ErrNotExist) || errors.Is(err, fsx.ErrLink) {
		t.Fatalf("OpenDir of a file = %v, want an error that is neither not-found nor a link", err)
	}
	ents, err := root.ReadDir()
	if err != nil || len(ents) != 2 || ents[0].Name() != "d" || ents[1].Name() != "x" {
		t.Fatalf("ReadDir: %v, %v", ents, err)
	}
	if !ents[0].IsDir() || ents[1].IsDir() || ents[0].Type() != fs.ModeDir || ents[1].Type() != 0 {
		t.Fatalf("the types: %v %v", ents[0].Type(), ents[1].Type())
	}
	info, err := ents[1].Info()
	if err != nil || info.Size() != 5 || info.Name() != "x" || info.Mode().Perm() != 0o600 || !info.ModTime().IsZero() {
		t.Fatalf("the info of x: %v, %v (size, name, mode; ModTime is the zero time)", info, err)
	}
	d, err := root.OpenDir("d")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Sync(); err != nil {
		t.Fatal(err)
	}
	if ents, err := d.ReadDir(); err != nil || len(ents) != 0 {
		t.Fatalf("ReadDir of an empty folder: %v, %v", ents, err)
	}
	if err := root.RenameNoReplace("x", "d/y"); err == nil {
		t.Fatal("a rename across folders was accepted: the names are one element each")
	}

	// the handles: a method after Close is fs.ErrClosed, a second Close is nil, and closing a
	// folder closes nothing that was opened from it
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("a second Close = %v", err)
	}
	if err := d.Sync(); err != nil {
		t.Fatalf("a folder opened from a closed one is still usable: %v", err)
	}
	for what, err := range map[string]error{
		"OpenDir":  func() error { _, err := root.OpenDir("d"); return err }(),
		"Mkdir":    root.Mkdir("q", 0o700),
		"Create":   func() error { _, err := root.CreateExcl("q", 0o600); return err }(),
		"Rename":   root.RenameNoReplace("x", "q"),
		"Sync":     root.Sync(),
		"ReadFile": func() error { _, err := root.ReadFile("x"); return err }(),
		"ReadDir":  func() error { _, err := root.ReadDir(); return err }(),
	} {
		if !errors.Is(err, fs.ErrClosed) {
			t.Errorf("%s after Close = %v, want fs.ErrClosed", what, err)
		}
	}
	_ = d.Close()
	if _, err := d.OpenDir("e"); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("OpenDir after Close = %v", err)
	}
}

// TestOSFilesystemRefusesWhatIsNotOnePlainElement: the package passes only plain elements, and a
// caller of the FS that skips the package must not be able to walk with one call.
func TestOSFilesystemRefusesWhatIsNotOnePlainElement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := openFSIn(t, dir)
	for _, name := range []string{"", ".", "..", "d/x", "/d", "d/", "../d", "a\x00b"} {
		calls := map[string]error{
			"OpenDir":  func() error { _, err := root.OpenDir(name); return err }(),
			"Mkdir":    root.Mkdir(name, 0o700),
			"Create":   func() error { _, err := root.CreateExcl(name, 0o600); return err }(),
			"Rename":   root.RenameNoReplace(name, "q"),
			"Rename 2": root.RenameNoReplace("d", name),
			"ReadFile": func() error { _, err := root.ReadFile(name); return err }(),
		}
		for what, err := range calls {
			if !errors.Is(err, fsx.ErrInvalid) {
				t.Errorf("%s(%q) = %v, want ErrInvalid", what, name, err)
			}
		}
	}
	if got := names(t, dir); !slices.Equal(got, []string{"d"}) {
		t.Fatalf("a refused element made something: %v", got)
	}
}

// TestOSTwoWritersRaceForOneNameAndExactlyOneWins: the rename that refuses to replace is
// what makes a name taken once, also across processes (here, across writers).
func TestOSTwoWritersRaceForOneNameAndExactlyOneWins(t *testing.T) {
	dir := t.TempDir()
	const n = 16
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		w, err := fsx.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = w.Close() }()
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = w.WriteFile("attempt.json", []byte(fmt.Sprintf("writer-%02d", i)), 0o600)
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
	if got := readFile(t, filepath.Join(dir, "attempt.json")); string(got) != fmt.Sprintf("writer-%02d", winner) {
		t.Fatalf("the file holds %q, the winner is %d", got, winner)
	}
}

// TestOneWriterIsSafeForSeveralGoroutines: its calls run one at a time (run it under -race
// where the race detector is available), on the model and on the real file system.
func TestOneWriterIsSafeForSeveralGoroutines(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	const workers, per = 8, 10
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := w.WriteFile(fmt.Sprintf("b/d/f-%d-%d.json", g, i), []byte(fmt.Sprintf("%d/%d", g, i)), 0o600); err != nil {
					errs <- err
					return
				}
			}
			j, err := w.CreateJournal(fmt.Sprintf("b/d/j-%d.jsonl", g))
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
			if got := mustFile(t, live, fmt.Sprintf("b/d/f-%d-%d.json", g, i)); string(got) != fmt.Sprintf("%d/%d", g, i) {
				t.Fatalf("file %d-%d holds %q", g, i, got)
			}
		}
		lines, partial, err := live.readJournal(fmt.Sprintf("b/d/j-%d.jsonl", g))
		if err != nil || partial != nil || len(lines) != per {
			t.Fatalf("journal %d: %d lines, partial %q, %v", g, len(lines), partial, err)
		}
		for i, l := range lines {
			if string(l) != fmt.Sprintf("line-%d-%d", g, i) {
				t.Fatalf("journal %d line %d is %q", g, i, l)
			}
		}
	}
	requireOpen(t, f, 0)
}

func TestOneWriterOnTheRealFileSystemIsSafeForSeveralGoroutines(t *testing.T) {
	w, dir := openIn(t)
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	const workers, per = 6, 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*2)
	for g := 0; g < workers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := w.WriteFile(fmt.Sprintf("d/f-%d-%d.json", g, i), []byte(fmt.Sprintf("%d/%d", g, i)), 0o600); err != nil {
					errs <- err
					return
				}
			}
			if err := w.WriteSet(fmt.Sprintf("d/s-%d", g), []fsx.NewFile{{Name: "a", Data: []byte("a"), Perm: 0o600}}); err != nil {
				errs <- err
				return
			}
			j, err := w.CreateJournal(fmt.Sprintf("d/j-%d.jsonl", g))
			if err != nil {
				errs <- err
				return
			}
			for i := 0; i < per; i++ {
				if err := j.Append([]byte("line")); err != nil {
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
	if got := len(names(t, filepath.Join(dir, "d"))); got != workers*(per+2) {
		t.Fatalf("the folder holds %d names, want %d", got, workers*(per+2))
	}
	for _, n := range names(t, filepath.Join(dir, "d")) {
		if strings.HasPrefix(n, fsx.TempPrefix) {
			t.Errorf("a temporary name is left: %s", n)
		}
	}
}

// TestOneWriterRacingForOnePathStopsTheLoser: two goroutines on one writer and one path: one
// wins, the other gets the refusal, and the content is the winner's.
func TestOneWriterRacingForOnePathStopsTheLoser(t *testing.T) {
	f := newMemFS("b", "b/d")
	w := newWriter(t, f, 1)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = w.WriteFile("b/d/f.json", []byte(fmt.Sprintf("writer %d", i)), 0o600)
		}()
	}
	wg.Wait()
	ok := 0
	for i, err := range errs {
		if err == nil {
			ok++
			if got := mustFile(t, f.Live(), "b/d/f.json"); string(got) != fmt.Sprintf("writer %d", i) {
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

// TestOSAFolderHandleClosedWhileOtherGoroutinesUseIt: Close takes the lock that every call takes,
// so a close never closes the descriptor under a call and a call after it never reaches a
// descriptor that another file has taken. Only the race run (go test -race) proves the lock.
func TestOSAFolderHandleClosedWhileOtherGoroutinesUseIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 40; round++ {
		root, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					_, e1 := root.ReadDir()
					_, e2 := root.ReadFile("f")
					e3 := root.Sync()
					for _, e := range []error{e1, e2, e3} {
						if errors.Is(e, fs.ErrClosed) {
							return
						}
						if e != nil {
							t.Errorf("a call on a handle that is being closed: %v", e)
							return
						}
					}
				}
			}()
		}
		if err := root.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		wg.Wait()
	}
}
