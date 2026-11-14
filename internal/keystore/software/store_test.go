package software

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
)

// badLabels are labels that are not one upper-case ASCII letter.
var badLabels = []string{
	"a", "AA", "", "1", "A.", "A/B", "..", ".", "A\x00", "\x00", "A ", " A", "A\n", "\nA", "A\t",
	"Α",           // GREEK CAPITAL LETTER ALPHA, which looks like A
	"Ａ",           // FULLWIDTH LATIN CAPITAL LETTER A
	"\u200bA",     // a zero-width space before the letter
	"Ä",           // A with a diaeresis
	"Á",          // A and a combining accent
	"\xC1",        // a byte that is not UTF-8
	"A\xff",       // a letter and a byte that is not UTF-8
	"[", "@", "`", // the characters next to A, Z and a in ASCII
	"..\\A", "A\\", "A:", "A*", "~",
	strings.Repeat("A", 300),
}

func TestEveryOneLetterLabelFromAToZIsAcceptedAndNothingElseIs(t *testing.T) {
	for c := 'A'; c <= 'Z'; c++ {
		if !labelOK(string(c)) {
			t.Errorf("%c is refused", c)
		}
	}
	for c := 0; c < 256; c++ {
		if c >= 'A' && c <= 'Z' {
			continue
		}
		if labelOK(string([]byte{byte(c)})) {
			t.Errorf("byte %#x is accepted as a label", c)
		}
	}
	for _, l := range badLabels {
		if labelOK(l) {
			t.Errorf("%q is accepted", l)
		}
	}
	for _, l := range []string{"A", "B", "Z"} {
		s, _, keys := openStore(t)
		k := mustGenerate(t)
		if err := s.SaveX509(l, k); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		if got := dirNames(t, keys); len(got) != 1 || got[0] != l+".x509.key.pem" {
			t.Errorf("label %s gives %v", l, got)
		}
	}
}

func TestABadLabelIsErrParamsInEveryCallAndNothingIsMadeOrAsked(t *testing.T) {
	k := mustGenerate(t)
	cert := certFor(t, k)
	rev := revocationFor(t, k, openpgp.Compromised)
	jws := jwsOf("a", "b", "c")
	for _, label := range badLabels {
		s, _, keys := openStore(t)
		rec := record(s)
		fm := recordFormat(s)
		calls := map[string]error{
			"SaveX509":       s.SaveX509(label, k),
			"SaveOpenPGP":    s.SaveOpenPGP(label, k, cert),
			"SaveRevocation": s.SaveRevocation(label, "compromised", rev),
			"SaveRemoval":    s.SaveRemoval(label, jws),
		}
		_, calls["OpenX509"] = s.OpenX509(bg(), label)
		_, calls["OpenOpenPGP"] = s.OpenOpenPGP(bg(), label)
		_, calls["ReadRevocation"] = s.ReadRevocation(bg(), label, "compromised")
		_, calls["ReadRemoval"] = s.ReadRemoval(bg(), label)
		for name, err := range calls {
			if !errors.Is(err, ErrParams) {
				t.Errorf("%s with label %q: %v", name, label, err)
			}
			if err != nil && err.Error() != errLabel.Error() {
				t.Errorf("%s: the text depends on the label %q: %q", name, label, err)
			}
		}
		if rec.calls() != 0 || fm.wraps != 0 || fm.unwraps != 0 {
			t.Errorf("label %q: the writer was called %d times, the format %d/%d", label, rec.calls(), fm.wraps, fm.unwraps)
		}
		if names := dirNames(t, keys); len(names) != 0 {
			t.Errorf("label %q: files exist: %v", label, names)
		}
		if k.Saved() {
			t.Errorf("label %q: Saved", label)
		}
	}
}

func TestAFileOfTheSameNameIsErrKeyExistsAndTheWriterStopsAtTheFirstError(t *testing.T) {
	s, _, keys := openStore(t)
	rec := record(s)
	first, second := mustGenerate(t), mustGenerate(t)
	if err := s.SaveX509("A", first); err != nil {
		t.Fatal(err)
	}
	before := readKeyFile(t, keys, "A.x509.key.pem")
	err := s.SaveX509("A", second)
	if !errors.Is(err, ErrKeyExists) || Code(err) != "key-exists" {
		t.Fatalf("the error is %v (code %q)", err, Code(err))
	}
	if !bytes.Equal(before, readKeyFile(t, keys, "A.x509.key.pem")) {
		t.Error("the existing file changed")
	}
	if second.Saved() || !first.Saved() {
		t.Errorf("Saved: first %v second %v", first.Saved(), second.Saved())
	}
	// The name is looked at before a byte of the new key goes to the disk: the writer is not
	// called for the second save, and no temporary file holding the second key is made.
	if rec.calls() != 1 {
		t.Fatalf("%d calls to the writer, want 1 (the good one; the second save is refused before the writer)", rec.calls())
	}
	for _, n := range dirNames(t, keys) {
		if strings.HasPrefix(n, fsx.TempPrefix) {
			t.Errorf("a temporary file %s stands after a save that met an existing name", n)
		}
	}
	// The writer stopped: every call that writes returns the first error and calls the writer no more.
	third := mustGenerate(t)
	calls := map[string]func() error{
		"SaveX509 of another label": func() error { return s.SaveX509("B", third) },
		"SaveOpenPGP":               func() error { return s.SaveOpenPGP("C", third, certFor(t, third)) },
		"SaveRevocation":            func() error { return s.SaveRevocation("A", "retired", revocationFor(t, third, openpgp.Retired)) },
		"SaveRemoval":               func() error { return s.SaveRemoval("A", jwsOf("a", "b", "c")) },
		"SaveX509 of the same":      func() error { return s.SaveX509("A", third) },
	}
	for name, call := range calls {
		got := call()
		if got != err { //nolint:errorlint // the same error value, not one that wraps it
			t.Errorf("%s returns %v, want the first error itself", name, got)
		}
	}
	if rec.calls() != 1 {
		t.Errorf("the writer was called %d times after the stop", rec.calls()-1)
	}
	if third.Saved() {
		t.Error("Saved after a stop")
	}
	// Reads are not writes: the good file still opens.
	if got, err := s.OpenX509(bg(), "A"); err != nil || !samePublic(got, first) {
		t.Errorf("a read after a stop: %v", err)
	}
	if ok, err := s.HasKeyFiles(); err != nil || !ok {
		t.Errorf("HasKeyFiles after a stop: %v %v", ok, err)
	}
}

func keyFileNamesOfBothModes() []string {
	names := []string{"A.x509.key.pem", "A.openpgp.key.asc", "A.removal.jws", "A.x509.key.age", "A.openpgp.key.age", "A.removal.jws.age"}
	for _, r := range reasons {
		names = append(names, "A.revocation."+r.Text+".asc", "A.revocation."+r.Text+".pgp.age")
	}
	return names
}

func TestHasKeyFilesIsFalseForAnEmptyFolderAndTrueForEachNameOfAKeyFileOfEitherMode(t *testing.T) {
	s, _, keys := openStore(t)
	if ok, err := s.HasKeyFiles(); err != nil || ok {
		t.Fatalf("an empty folder: %v %v", ok, err)
	}
	names := keyFileNamesOfBothModes()
	if len(names) != 14 {
		t.Fatalf("%d names", len(names))
	}
	for _, n := range names {
		writeKeyFile(t, keys, n, []byte("x"))
		ok, err := s.HasKeyFiles()
		if err != nil || !ok {
			t.Errorf("%s: %v %v", n, ok, err)
		}
		if err := os.Remove(filepath.Join(keys, n)); err != nil {
			t.Fatal(err)
		}
	}
	for _, label := range []string{"A", "M", "Z"} {
		writeKeyFile(t, keys, label+".removal.jws", nil)
		if ok, _ := s.HasKeyFiles(); !ok {
			t.Errorf("label %s", label)
		}
		_ = os.Remove(filepath.Join(keys, label+".removal.jws"))
	}
}

func TestHasKeyFilesIsFalseForNamesThatAreNotKeyFilesAndForEntriesThatAreNotRegularFiles(t *testing.T) {
	s, _, keys := openStore(t)
	names := []string{
		".rt-abcdefghijk", ".RT-abcdefghijk", ".rt-A.x509.key.pem", "notes.txt", "A.x509.key.pem.bak", "A.x509.key", "x509.key.pem",
		"a.x509.key.pem", "AA.x509.key.pem", "1.x509.key.pem", ".x509.key.pem", "A.x509.key.PEM", "A.X509.key.pem",
		"A.revocation.stolen.asc", "A.revocation..asc", "A.revocation.compromised", "A.revocation.compromised.age",
		"A.revocation.compromised.pgp", "A.revocation.compromised.asc.age", "A.revocation.Compromised.asc",
		"A.removal.jws.pem", "A.removal", "A.openpgp.key.pem", "A.openpgp.key.asc.age", "B.x509.key.age.asc",
		"A.x509.key.pem\x01", "A.x509.key.pem\xff", "A.x509.key.pem\n", "A.x509.key.pem ", " A.x509.key.pem", "Α.x509.key.pem",
		"A.x509.key.pem.", "A.x509.key.pem\u202e",
	}
	for _, n := range names {
		writeKeyFile(t, keys, n, []byte("x"))
	}
	for _, n := range []string{"A.x509.key.pem", "B.openpgp.key.asc", "C.removal.jws", "D.x509.key.age"} {
		if err := os.Mkdir(filepath.Join(keys, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(keys, "notes.txt"), filepath.Join(keys, "E.x509.key.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(keys, "nowhere"), filepath.Join(keys, "F.x509.key.pem")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(keys, "G.x509.key.pem"), 0o600); err != nil {
		t.Logf("no named pipes here: %v", err)
	}
	ok, err := s.HasKeyFiles()
	if err != nil || ok {
		t.Errorf("HasKeyFiles is %v (%v) for a folder with no key file", ok, err)
	}
	// A folder of that name is not a key file, and a save of that name is refused, not made.
	err = s.SaveX509("A", mustGenerate(t))
	if !errors.Is(err, ErrKeyExists) {
		t.Errorf("a save over a folder of that name: %v", err)
	}
}

func TestOneKeyFileAmongManyOtherNamesIsFound(t *testing.T) {
	s, _, keys := openStore(t)
	for i := 0; i < 300; i++ {
		writeKeyFile(t, keys, fmt.Sprintf("note-%04d.txt", i), nil)
	}
	if ok, _ := s.HasKeyFiles(); ok {
		t.Fatal("found a key file among notes")
	}
	writeKeyFile(t, keys, "Q.removal.jws.age", nil)
	if ok, err := s.HasKeyFiles(); err != nil || !ok {
		t.Errorf("%v %v", ok, err)
	}
}

func TestAFolderWithMoreNamesThanTheLimitIsRefusedAndNothingIsWrittenInIt(t *testing.T) {
	if testing.Short() {
		t.Skip("makes 65,537 files")
	}
	s, _, keys := openStore(t)
	for i := 0; i <= fsx.MaxDirEntries; i++ {
		f, err := os.Create(filepath.Join(keys, fmt.Sprintf("n%06d", i)))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	rec := record(s)
	if ok, err := s.HasKeyFiles(); err == nil || ok || !errors.Is(err, ErrKeyDir) || !errors.Is(err, fsx.ErrTooMany) {
		t.Errorf("HasKeyFiles: %v %v", ok, err)
	}
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err == nil || !errors.Is(err, ErrKeyDir) {
		t.Errorf("a save into a folder that cannot be listed: %v", err)
	}
	if rec.calls() != 0 {
		t.Error("the writer was called")
	}
	if _, err := s.OpenX509(bg(), "A"); err == nil {
		t.Error("an open in a folder with no such file succeeded")
	}
}

func TestOpenRefusesAnythingThatIsNotAnOpenableConfigAndMakesNoStore(t *testing.T) {
	bundle, keys := newBundle(t)
	var typedNil *recordingSource
	cases := []struct {
		name string
		cfg  Config
		is   error
		code string
	}{
		{"the zero Config", Config{}, ErrParams, ""},
		{"a zero Mode", Config{KeyDir: keys, BundleDir: bundle}, ErrParams, ""},
		{"a negative Mode", Config{KeyDir: keys, BundleDir: bundle, Mode: -1}, ErrParams, ""},
		{"a Mode that does not exist", Config{KeyDir: keys, BundleDir: bundle, Mode: 3}, ErrParams, ""},
		{"a huge Mode", Config{KeyDir: keys, BundleDir: bundle, Mode: 1 << 30}, ErrParams, ""},
		{"an empty BundleDir", Config{KeyDir: keys, Mode: ModeTest}, ErrParams, ""},
		{"an empty BundleDir and no KeyDir", Config{Mode: ModeTest}, ErrParams, ""},
		{"a test root with a source", Config{KeyDir: keys, BundleDir: bundle, Mode: ModeTest, Passphrases: &recordingSource{}}, ErrParams, ""},
		{"a test root with a typed nil source", Config{KeyDir: keys, BundleDir: bundle, Mode: ModeTest, Passphrases: typedNil}, ErrParams, ""},
		{"a passphrase root with no source", Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase}, ErrParams, ""},
		{"a passphrase root with a source is not built", Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: &recordingSource{}}, ErrNotBuilt, "not-built"},
		{"a passphrase root with a typed nil source is not built", Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: typedNil}, ErrNotBuilt, "not-built"},
		{"an empty KeyDir", Config{BundleDir: bundle, Mode: ModeTest}, ErrKeyDir, "key-dir"},
		{"a missing KeyDir", Config{KeyDir: filepath.Join(keys, "nowhere"), BundleDir: bundle, Mode: ModeTest}, ErrKeyDir, "key-dir"},
		{"a missing BundleDir", Config{KeyDir: keys, BundleDir: filepath.Join(bundle, "nowhere"), Mode: ModeTest}, ErrKeyDir, "key-dir"},
		{"the bundle as the KeyDir", Config{KeyDir: bundle, BundleDir: bundle, Mode: ModeTest}, ErrKeyDir, "key-dir"},
		{"a KeyDir inside the bundle", Config{KeyDir: filepath.Join(bundle, "history"), BundleDir: bundle, Mode: ModeTest}, ErrKeyDir, "key-dir"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := Open(c.cfg)
			if err == nil {
				_ = s.Close()
				t.Fatal("opened")
			}
			if s != nil {
				t.Error("a refusal returned a Store")
			}
			if !errors.Is(err, c.is) || Code(err) != c.code {
				t.Errorf("the error is %v (code %q), want %v (code %q)", err, Code(err), c.is, c.code)
			}
			for _, p := range []string{keys, bundle} {
				if strings.Contains(err.Error(), p) {
					t.Errorf("the error holds the path %s", p)
				}
			}
			if names := dirNames(t, keys); len(names) != 0 {
				t.Errorf("files were made: %v", names)
			}
		})
	}
}

type recordingSource struct{ calls int }

func (r *recordingSource) Passphrase(context.Context, Purpose) ([]byte, error) {
	r.calls++
	return nil, errors.New("not to be asked")
}

func TestOpenAcceptsARelativePathAndTheStoreKeepsItsFolderWhenTheWorkingFolderChanges(t *testing.T) {
	bundle, keys := newBundle(t)
	root := filepath.Dir(bundle)
	t.Chdir(root)
	s, err := Open(Config{KeyDir: "keys", BundleDir: "bundle/", Mode: ModeTest})
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer func() { _ = s.Close() }()
	t.Chdir(t.TempDir())
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if got := readKeyFile(t, keys, "A.x509.key.pem"); len(got) == 0 {
		t.Error("the file is not in the key folder")
	}
}

func TestACallOnAStoreThatWasNotMadeByOpenOrIsClosedIsErrParamsAndNeverPanics(t *testing.T) {
	k := mustGenerate(t)
	cert := certFor(t, k)
	closed, _, _ := openStore(t)
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
	var nilStore *Store
	for name, s := range map[string]*Store{"nil": nilStore, "zero": {}, "closed": closed, "no format": {mode: ModeTest, fsys: staticFS{}, w: &recWriter{}}} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			calls := map[string]error{
				"SaveX509":       s.SaveX509("A", k),
				"SaveOpenPGP":    s.SaveOpenPGP("A", k, cert),
				"SaveRevocation": s.SaveRevocation("A", "compromised", revocationFor(t, k, openpgp.Compromised)),
				"SaveRemoval":    s.SaveRemoval("A", jwsOf("a", "b", "c")),
			}
			_, calls["OpenX509"] = s.OpenX509(bg(), "A")
			_, calls["OpenOpenPGP"] = s.OpenOpenPGP(bg(), "A")
			_, calls["ReadRevocation"] = s.ReadRevocation(bg(), "A", "compromised")
			_, calls["ReadRemoval"] = s.ReadRemoval(bg(), "A")
			_, calls["HasKeyFiles"] = s.HasKeyFiles()
			for call, err := range calls {
				if !errors.Is(err, ErrParams) {
					t.Errorf("%s: %v", call, err)
				}
			}
			if k.Saved() {
				t.Error("Saved")
			}
			if err := s.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

func TestACancelledContextIsReturnedAsItIsBeforeAnythingIsRead(t *testing.T) {
	s, _, _ := openStore(t)
	fm := recordFormat(s)
	ctx, cancel := context.WithCancel(bg())
	cancel()
	k := mustGenerate(t)
	cert := certFor(t, k)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOpenPGP("A", k, cert); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRevocation("A", "retired", revocationFor(t, k, openpgp.Retired)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRemoval("A", jwsOf("a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	fm.unwraps = 0
	_, e1 := s.OpenX509(ctx, "A")
	_, e2 := s.OpenOpenPGP(ctx, "A")
	_, e3 := s.ReadRevocation(ctx, "A", "retired")
	_, e4 := s.ReadRemoval(ctx, "A")
	for i, err := range []error{e1, e2, e3, e4} {
		if err != context.Canceled { //nolint:errorlint // the context's own error value, not a wrap of it
			t.Errorf("call %d: %v, want context.Canceled itself", i, err)
		}
	}
	if fm.unwraps != 0 {
		t.Error("a file was read for a cancelled context")
	}
	//nolint:staticcheck // a nil context is the case under test
	if _, err := s.ReadRemoval(nil, "A"); !errors.Is(err, ErrParams) {
		t.Errorf("a nil context: %v", err)
	}
	dctx, dcancel := context.WithTimeout(bg(), 0)
	defer dcancel()
	if _, err := s.ReadRemoval(dctx, "A"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("an expired context: %v", err)
	}
}

func TestAFileOfTheOtherModeIsErrWrongModeAndIsNeverParsed(t *testing.T) {
	k := mustGenerate(t)
	for _, name := range []string{"A.x509.key.age", "A.openpgp.key.age", "A.revocation.compromised.pgp.age", "A.removal.jws.age"} {
		t.Run(name, func(t *testing.T) {
			s, _, keys := openStore(t)
			fm := recordFormat(s)
			// What stands there is not a key file of a test root, and not parsed, whatever it holds.
			writeKeyFile(t, keys, name, append([]byte("age-encryption.org/v1\n"), scalarBytes(t, k)...))
			calls := map[string]error{}
			_, calls["OpenX509"] = s.OpenX509(bg(), "A")
			_, calls["OpenOpenPGP"] = s.OpenOpenPGP(bg(), "A")
			_, calls["ReadRevocation"] = s.ReadRevocation(bg(), "A", "compromised")
			_, calls["ReadRemoval"] = s.ReadRemoval(bg(), "A")
			want := map[string]string{
				"A.x509.key.age": "OpenX509", "A.openpgp.key.age": "OpenOpenPGP",
				"A.revocation.compromised.pgp.age": "ReadRevocation", "A.removal.jws.age": "ReadRemoval",
			}[name]
			for call, err := range calls {
				if call == want {
					if !errors.Is(err, ErrWrongMode) || Code(err) != "key-file-mode" {
						t.Errorf("%s: %v (code %q), want ErrWrongMode", call, err, Code(err))
					}
					continue
				}
				if !errors.Is(err, ErrKeyFile) {
					t.Errorf("%s: %v, want ErrKeyFile for a file that is not there", call, err)
				}
			}
			if fm.unwraps != 0 {
				t.Errorf("the parser was called %d times", fm.unwraps)
			}
			// A write into the folder is refused too, and writes nothing.
			rec := record(s)
			for call, err := range map[string]error{
				"SaveX509":       s.SaveX509("B", k),
				"SaveOpenPGP":    s.SaveOpenPGP("B", k, certFor(t, k)),
				"SaveRevocation": s.SaveRevocation("B", "retired", revocationFor(t, k, openpgp.Retired)),
				"SaveRemoval":    s.SaveRemoval("B", jwsOf("a", "b", "c")),
			} {
				if !errors.Is(err, ErrWrongMode) {
					t.Errorf("%s: %v", call, err)
				}
			}
			if rec.calls() != 0 || fm.wraps != 0 {
				t.Errorf("a file of the other mode did not stop a write: %d calls, %d wraps", rec.calls(), fm.wraps)
			}
			if k.Saved() {
				t.Error("Saved")
			}
		})
	}
}

// A passphrase Store cannot be made in this version; the half of the rule that this version can
// show is the one that does not depend on the cipher: the plain file of a test root where a
// passphrase root stands is not parsed and not written over.
func TestAPlainFileWhereAPassphraseRootStandsIsErrWrongModeWithoutAParse(t *testing.T) {
	s, _, keys := openStore(t)
	s.mode = ModePassphrase // as 11 b will make it; no write is made in this mode here
	fm := recordFormat(s)
	rec := record(s)
	k := mustGenerate(t)
	for name, file := range map[string]string{
		"A.x509.key.pem": "OpenX509", "A.openpgp.key.asc": "OpenOpenPGP", "A.revocation.superseded.asc": "ReadRevocation", "A.removal.jws": "ReadRemoval",
	} {
		writeKeyFile(t, keys, name, x509File(t, k))
		var err error
		switch file {
		case "OpenX509":
			_, err = s.OpenX509(bg(), "A")
		case "OpenOpenPGP":
			_, err = s.OpenOpenPGP(bg(), "A")
		case "ReadRevocation":
			_, err = s.ReadRevocation(bg(), "A", "superseded")
		case "ReadRemoval":
			_, err = s.ReadRemoval(bg(), "A")
		}
		if !errors.Is(err, ErrWrongMode) {
			t.Errorf("%s: %v", file, err)
		}
		if err := s.SaveX509("B", k); !errors.Is(err, ErrWrongMode) {
			t.Errorf("a save beside %s: %v", name, err)
		}
		_ = os.Remove(filepath.Join(keys, name))
	}
	if fm.unwraps != 0 || fm.wraps != 0 || rec.calls() != 0 {
		t.Errorf("unwraps %d wraps %d writes %d", fm.unwraps, fm.wraps, rec.calls())
	}
}

// Two goroutines save to one name: exactly one wins and the file is the key of the winner. The
// test asserts the pair, not who won.
func TestTwoGoroutinesSavingOneNameGiveOneWinnerAndOneErrKeyExists(t *testing.T) {
	for attempt := 0; attempt < 25; attempt++ {
		s, _, _ := openStore(t)
		keysOf2 := []*Key{mustGenerate(t), mustGenerate(t)}
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range keysOf2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = s.SaveX509("A", keysOf2[i])
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		var winner *Key
		for i, err := range errs {
			switch {
			case err == nil:
				wins++
				winner = keysOf2[i]
				if !keysOf2[i].Saved() {
					t.Error("the winner is not Saved")
				}
			case errors.Is(err, ErrKeyExists):
				if keysOf2[i].Saved() {
					t.Error("the loser is Saved")
				}
			default:
				t.Fatalf("attempt %d: %v", attempt, err)
			}
		}
		if wins != 1 {
			t.Fatalf("attempt %d: %d winners (%v)", attempt, wins, errs)
		}
		got, err := s.OpenX509(bg(), "A")
		if err != nil || !samePublic(got, winner) {
			t.Fatalf("attempt %d: the file is not the key of the winner (%v)", attempt, err)
		}
	}
}

func TestSavesOfDifferentLabelsAtOnceAllSucceedAndOpenAsTheirOwnKeys(t *testing.T) {
	s, _, _ := openStore(t)
	labels := []string{"A", "B", "C", "D", "E", "F"}
	ks := make([]*Key, len(labels))
	errs := make([]error, len(labels))
	for i := range ks {
		ks[i] = mustGenerate(t)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, l := range labels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = s.SaveX509(l, ks[i])
			if _, err := s.HasKeyFiles(); err != nil {
				errs[i] = err
			}
		}()
	}
	close(start)
	wg.Wait()
	for i, l := range labels {
		if errs[i] != nil {
			t.Fatalf("%s: %v", l, errs[i])
		}
		got, err := s.OpenX509(bg(), l)
		if err != nil || !samePublic(got, ks[i]) {
			t.Errorf("%s: %v", l, err)
		}
	}
}

func TestStoreCloseReleasesTheFolderAndAFollowingCallIsRefused(t *testing.T) {
	s, _, _ := openStore(t)
	rec := record(s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if rec.closes != 1 {
		t.Errorf("the writer was closed %d times", rec.closes)
	}
	_ = s.Close()
	if rec.closes != 1 {
		t.Errorf("the second Close closed the writer again (%d)", rec.closes)
	}
	if _, err := s.OpenX509(bg(), "A"); !errors.Is(err, ErrParams) {
		t.Errorf("%v", err)
	}
}

// countingFS counts the files that are read.
type countingFS struct {
	staticFS
	reads *int
}

func (c countingFS) ReadFile(name string) ([]byte, error) {
	*c.reads++
	return c.staticFS.ReadFile(name)
}

// The context is looked at before any file is read (and again before the parse), so a cancelled
// call costs no read.
func TestACancelledContextCostsNoRead(t *testing.T) {
	reads := 0
	s := staticStore(t, map[string][]byte{"A.removal.jws": jwsOf("a", "b", "c")})
	s.fsys = countingFS{staticFS: s.fsys.(staticFS), reads: &reads}
	ctx, cancel := context.WithCancel(bg())
	cancel()
	if _, err := s.ReadRemoval(ctx, "A"); err != context.Canceled { //nolint:errorlint // the context's own value
		t.Errorf("%v", err)
	}
	if reads != 0 {
		t.Errorf("%d files were read for a cancelled context", reads)
	}
	if _, err := s.ReadRemoval(bg(), "A"); err != nil || reads != 1 {
		t.Errorf("a live context: %v, %d reads", err, reads)
	}
}

// A context that is cancelled while the file is read is looked at again before the parse.
type cancelOnRead struct {
	staticFS
	cancel context.CancelFunc
}

func (c cancelOnRead) ReadFile(name string) ([]byte, error) {
	c.cancel()
	return c.staticFS.ReadFile(name)
}

func TestAContextCancelledDuringTheReadIsLookedAtBeforeTheParse(t *testing.T) {
	s := staticStore(t, map[string][]byte{"A.removal.jws": jwsOf("a", "b", "c")})
	fm := recordFormat(s)
	ctx, cancel := context.WithCancel(bg())
	s.fsys = cancelOnRead{staticFS: s.fsys.(staticFS), cancel: cancel}
	if _, err := s.ReadRemoval(ctx, "A"); err != context.Canceled { //nolint:errorlint // the context's own value
		t.Errorf("%v", err)
	}
	if fm.unwraps != 0 {
		t.Error("the file was parsed after the context was cancelled")
	}
}
