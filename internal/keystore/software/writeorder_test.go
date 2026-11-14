package software

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/fsx"
)

// A save looks at the folder first: the other-mode rule on the listing, then the name. A name that
// stands, of any kind, is refused before a byte of the new key is written, so no temporary file
// holds the key (record 0006, rule 33: nothing is deleted, so nothing may be left that need not be).

type entryKind struct {
	name string
	make func(t *testing.T, root, path string)
}

func entryKinds() []entryKind {
	return []entryKind{
		{"a regular file", func(t *testing.T, _, p string) {
			if err := os.WriteFile(p, []byte("old text\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"an empty file", func(t *testing.T, _, p string) {
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"an empty folder", func(t *testing.T, _, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"a folder with a file", func(t *testing.T, _, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, "inner"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a link to a file", func(t *testing.T, root, p string) {
			target := filepath.Join(root, "target-file")
			if err := os.WriteFile(target, []byte("target text"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"a link to a folder", func(t *testing.T, root, p string) {
			if err := os.Symlink(root, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"a dangling link", func(t *testing.T, root, p string) {
			if err := os.Symlink(filepath.Join(root, "nowhere"), p); err != nil {
				t.Fatal(err)
			}
		}},
		{"a pipe", func(t *testing.T, _, p string) {
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
}

func TestASaveOfANameThatStandsIsErrKeyExistsBeforeTheWriterIsCalledWhateverHoldsTheName(t *testing.T) {
	for _, kind := range saveKinds() {
		for _, entry := range entryKinds() {
			t.Run(kind.name+" over "+entry.name, func(t *testing.T) {
				s, bundle, keys := openStore(t)
				root := filepath.Dir(bundle)
				entry.make(t, root, filepath.Join(keys, kind.final))
				before, err := os.Lstat(filepath.Join(keys, kind.final))
				if err != nil {
					t.Fatal(err)
				}
				rec := record(s)
				k := mustGenerate(t)
				err = kind.save(t, s, k)
				if !errors.Is(err, ErrKeyExists) || !errors.Is(err, fs.ErrExist) || Code(err) != "key-exists" {
					t.Fatalf("the error is %v (code %q)", err, Code(err))
				}
				if !strings.Contains(err.Error(), kind.final) || strings.Contains(err.Error(), keys) {
					t.Errorf("the error names the file with no path or does not name it: %v", err)
				}
				if rec.calls() != 0 {
					t.Errorf("the writer was called %d times", rec.calls())
				}
				for _, n := range dirNames(t, keys) {
					if n != kind.final {
						t.Errorf("another name stands in the key folder: %s", n)
					}
				}
				after, statErr := os.Lstat(filepath.Join(keys, kind.final))
				if statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
					t.Errorf("the entry changed: %v", statErr)
				}
				if k.Saved() {
					t.Error("Saved is true")
				}
				// The writer stops: the next call returns the same error and does nothing.
				next := s.SaveX509("B", mustGenerate(t))
				if next != err { //nolint:errorlint // the same error value
					t.Errorf("the next save returns %v", next)
				}
				if rec.calls() != 0 {
					t.Error("the writer was called after the stop")
				}
			})
		}
	}
}

// The other-mode rule comes first, and a refusal for it is not a stop of the writer.
func TestAFileOfTheOtherModeIsRefusedBeforeTheNameIsLookedAtAndDoesNotStopTheWriter(t *testing.T) {
	s, _, keys := openStore(t)
	rec := record(s)
	writeKeyFile(t, keys, "A.x509.key.pem", []byte("old"))
	writeKeyFile(t, keys, "Z.x509.key.age", []byte("age-encryption.org/v1\n"))
	k := mustGenerate(t)
	err := s.SaveX509("A", k) // the name stands, and a file of the other mode stands too
	if !errors.Is(err, ErrWrongMode) || errors.Is(err, ErrKeyExists) || Code(err) != "key-file-mode" {
		t.Fatalf("the error is %v", err)
	}
	if rec.calls() != 0 || s.stop != nil {
		t.Errorf("the writer: %d calls, stopped=%v", rec.calls(), s.stop != nil)
	}
	if err := s.SaveX509("B", k); !errors.Is(err, ErrWrongMode) {
		t.Errorf("another label: %v", err)
	}
	if err := os.Remove(filepath.Join(keys, "Z.x509.key.age")); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveX509("B", k); err != nil {
		t.Fatalf("after the other-mode file went: %v", err)
	}
	if rec.calls() != 1 {
		t.Errorf("%d writer calls, want 1", rec.calls())
	}
}

// A folder that cannot be listed stops the save before the writer, with a key-directory error that
// does not stop the writer: the next call lists again.
func TestAFolderThatCannotBeListedRefusesTheSaveBeforeTheWriterAndDoesNotStopIt(t *testing.T) {
	s, _, keys := openStore(t)
	rec := record(s)
	real := s.fsys
	s.fsys = &failListing{FS: real, failFrom: 1}
	k := mustGenerate(t)
	err := s.SaveX509("A", k)
	if !errors.Is(err, ErrKeyDir) || errors.Is(err, ErrKeyExists) {
		t.Fatalf("the error is %v", err)
	}
	if rec.calls() != 0 || len(dirNames(t, keys)) != 0 || k.Saved() {
		t.Errorf("the writer: %d calls, names %v, saved %v", rec.calls(), dirNames(t, keys), k.Saved())
	}
	s.fsys = real
	if err := s.SaveX509("A", k); err != nil {
		t.Fatalf("the next save: %v", err)
	}
}

// failListing is a folder whose listing fails from the n-th call on.
type failListing struct {
	fsx.FS
	calls, failFrom int
}

func (f *failListing) ReadDir() ([]fs.DirEntry, error) {
	f.calls++
	if f.calls >= f.failFrom {
		return nil, errInjected
	}
	return f.FS.ReadDir()
}

// leaveWriter makes the files and folders it is told to, as a writer that was cut would, and then
// fails with its error. It stands in the folder of the real Store, so the listing sees them.
type leaveWriter struct {
	dir   string
	files []string
	dirs  []string
	data  []byte
	err   error
	calls int
}

func (w *leaveWriter) WriteFile(path string, _ []byte, _ fs.FileMode) error {
	w.calls++
	for _, n := range w.files {
		if err := os.WriteFile(filepath.Join(w.dir, n), w.data, 0o600); err != nil {
			return err
		}
	}
	for _, n := range w.dirs {
		if err := os.Mkdir(filepath.Join(w.dir, n), 0o700); err != nil {
			return err
		}
	}
	return w.err
}

func (w *leaveWriter) Close() error { return nil }

func raceExists(name string) error {
	return &fs.PathError{Op: "rename", Path: name, Err: fs.ErrExist}
}

func TestAFailedWriteNamesTheTemporaryFileOfAKeyFileAndSaysRemoveItAndNothingIsDeleted(t *testing.T) {
	for _, kind := range saveKinds() {
		for _, how := range []string{"a failure", "a name taken in a race"} {
			t.Run(kind.name+" after "+how, func(t *testing.T) {
				s, _, keys := openStore(t)
				w := &leaveWriter{dir: keys, files: []string{".rt-abcdefghijk"}, data: []byte("PLAIN KEY STAND-IN")}
				if how == "a failure" {
					w.err = errInjected
				} else {
					w.err = raceExists(kind.final)
				}
				s.w = w
				k := mustGenerate(t)
				err := kind.save(t, s, k)
				if err == nil {
					t.Fatal("no error")
				}
				if (how == "a failure") == errors.Is(err, ErrKeyExists) || (how != "a failure") != errors.Is(err, fs.ErrExist) {
					t.Errorf("the kind of the error: %v", err)
				}
				text := err.Error()
				keyKind := kind.name == "X509" || kind.name == "OpenPGP"
				has := strings.Contains(text, `the temporary file ".rt-abcdefghijk" may hold the key: remove it`)
				if has != keyKind {
					t.Errorf("a %s file: the error says the temporary file: %v (%q)", kind.name, has, text)
				}
				if !keyKind && strings.Contains(text, fsx.TempPrefix) {
					t.Errorf("a file that holds no key names a temporary file: %q", text)
				}
				if !strings.Contains(text, kind.final) || strings.Contains(text, keys) {
					t.Errorf("the text names no file or holds a path: %q", text)
				}
				if got := readKeyFile(t, keys, ".rt-abcdefghijk"); !bytes.Equal(got, w.data) {
					t.Error("the leftover was changed or deleted")
				}
				if k.Saved() {
					t.Error("Saved is true")
				}
				// The stop is this error, unchanged, and the writer is not called again.
				if next := s.SaveRemoval("B", jwsOf("a", "b", "c")); next != err { //nolint:errorlint // the same value
					t.Errorf("the next call returns %v", next)
				}
				if w.calls != 1 {
					t.Errorf("%d writer calls", w.calls)
				}
			})
		}
	}
}

func TestOnlyTheNewTemporaryNamesAreNamedAndEveryNameIsQuotedAsPlainText(t *testing.T) {
	s, _, keys := openStore(t)
	writeKeyFile(t, keys, ".rt-old00000000", []byte("an older stop"))
	writeKeyFile(t, keys, "notes.txt", []byte("not a key"))
	hostile := ".rt-new\nline\xff\u202e\u00e9"
	w := &leaveWriter{
		dir:   keys,
		files: []string{".rt-aaaaaaaaaaa", ".RT-BBBBBBBBBBB", ".Rt-cccccccccc", "plain-new-file", hostile},
		dirs:  []string{".rt-folderxxxxx"},
		data:  []byte("x"),
		err:   errInjected,
	}
	s.w = w
	err := s.SaveX509("A", mustGenerate(t))
	if err == nil {
		t.Fatal("no error")
	}
	text := err.Error()
	for _, n := range []string{".rt-aaaaaaaaaaa", ".RT-BBBBBBBBBBB", ".Rt-cccccccccc", ".rt-folderxxxxx"} {
		if !strings.Contains(text, `"`+n+`"`) {
			t.Errorf("%s is not named in %q", n, text)
		}
	}
	for _, n := range []string{".rt-old00000000", "notes.txt", "plain-new-file"} {
		if strings.Contains(text, n) {
			t.Errorf("%s is named though it is not a new temporary name: %q", n, text)
		}
	}
	if !strings.Contains(text, `".rt-new\nline\xff\u202e\u00e9"`) {
		t.Errorf("the hostile name is not shown quoted in ASCII: %q", text)
	}
	if !utf8.ValidString(text) || strings.ContainsAny(text, "\n\x00") {
		t.Errorf("the text holds a raw control byte or a byte that is not UTF-8: %q", text)
	}
	for _, r := range text {
		if r > 0x7e {
			t.Errorf("the text holds the non-ASCII %U", r)
			break
		}
	}
	if !strings.Contains(text, "remove it") {
		t.Errorf("the text does not say what to do: %q", text)
	}
}

func TestWhenTheFolderCannotBeListedAfterTheFailureTheErrorStillTellsToLookForATemporaryFile(t *testing.T) {
	for _, kind := range saveKinds() {
		t.Run(kind.name, func(t *testing.T) {
			s, _, keys := openStore(t)
			s.w = &leaveWriter{dir: keys, files: []string{".rt-abcdefghijk"}, data: []byte("x"), err: errInjected}
			s.fsys = &failListing{FS: s.fsys, failFrom: 2} // the listing before works, the one after fails
			err := kind.save(t, s, mustGenerate(t))
			if err == nil || !errors.Is(err, errInjected) {
				t.Fatalf("the error is %v", err)
			}
			has := strings.Contains(err.Error(), "a temporary file (a name that starts with .rt-) may hold the key: remove it")
			if want := kind.name == "X509" || kind.name == "OpenPGP"; has != want {
				t.Errorf("says to look: %v, want %v (%q)", has, want, err.Error())
			}
		})
	}
}

// With the real writer, at each step that can fail, the error names what the step left: nothing
// when nothing is left, and the temporary file when it stays.
func TestTheErrorOfARealStoppedWriteNamesExactlyTheTemporaryFilesThatStay(t *testing.T) {
	for _, kind := range saveKinds() {
		for _, step := range steps {
			t.Run(kind.name+" at "+string(step), func(t *testing.T) {
				s, _, keys := openStore(t)
				failAt(t, s, keys, step)
				err := kind.save(t, s, mustGenerate(t))
				if err == nil {
					t.Fatal("no error")
				}
				var temps []string
				for _, n := range dirNames(t, keys) {
					if strings.HasPrefix(n, fsx.TempPrefix) {
						temps = append(temps, n)
					}
				}
				keyKind := kind.name == "X509" || kind.name == "OpenPGP"
				text := err.Error()
				if len(temps) > 1 {
					t.Fatalf("%d temporary files", len(temps))
				}
				switch {
				case keyKind && len(temps) == 1:
					if !strings.Contains(text, `the temporary file "`+temps[0]+`" may hold the key: remove it`) {
						t.Errorf("a temporary file stays and the error does not name it: %q", text)
					}
				default:
					if strings.Contains(text, "temporary file") {
						t.Errorf("the error names a temporary file that is not there or holds no key: %q", text)
					}
				}
				// The file is never deleted by the store.
				for _, n := range temps {
					if _, err := os.Stat(filepath.Join(keys, n)); err != nil {
						t.Errorf("the temporary file is gone: %v", err)
					}
				}
			})
		}
	}
}
