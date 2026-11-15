package software

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"filippo.io/age"
	"ritueel.id/ritueel/internal/openpgp"
)

// ---- Open ----

type nilFunc func(context.Context, Purpose) ([]byte, error)

func (f nilFunc) Passphrase(ctx context.Context, p Purpose) ([]byte, error) { return f(ctx, p) }

type nilMap map[string]string

func (nilMap) Passphrase(context.Context, Purpose) ([]byte, error) { return nil, errors.New("no") }

func TestOpenInPassphraseModeWithASourceBuildsAStoreAndItsFormatIsAge(t *testing.T) {
	bundle, keys := newBundle(t)
	s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: newPassSource(testPass)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, ok := s.format.(ageFormat); !ok {
		t.Errorf("the format is %T", s.format)
	}
	if s.mode != ModePassphrase || s.source == nil {
		t.Error("the mode or the source is not set")
	}
	if got, err := s.HasKeyFiles(); err != nil || got {
		t.Errorf("an empty folder: %v, %v", got, err)
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("Open made files: %v", names)
	}
}

func TestOpenInPassphraseModeRefusesEveryKindOfNilSourceAndMakesNoStore(t *testing.T) {
	bundle, keys := newBundle(t)
	var nilPtr *passSource
	var nilF nilFunc
	var nilM nilMap
	for name, src := range map[string]PassphraseSource{
		"a nil interface":    nil,
		"a typed nil":        nilPtr,
		"a nil function":     nilF,
		"a nil map":          nilM,
		"a nil ReaderSource": (*readerSource)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: src})
			if err == nil {
				_ = s.Close()
				t.Fatal("opened")
			}
			if s != nil {
				t.Error("a refusal gave a Store")
			}
			wantRefusal(t, err, ErrParams, "")
			if errors.Is(err, ErrNotBuilt) {
				t.Error("the refusal says not built")
			}
		})
	}
	// an empty map and a non-nil function are sources: they are not nil
	if s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: nilMap{}}); err != nil {
		t.Errorf("an empty map: %v", err)
	} else {
		_ = s.Close()
	}
}

func TestOpenInPassphraseModeChecksTheKeyDirectoryToo(t *testing.T) {
	bundle, keys := newBundle(t)
	src := newPassSource(testPass)
	for name, cfg := range map[string]Config{
		"the bundle as the key folder": {KeyDir: bundle, BundleDir: bundle},
		"a folder inside the bundle":   {KeyDir: filepath.Join(bundle, "history"), BundleDir: bundle},
		"a missing folder":             {KeyDir: filepath.Join(keys, "nowhere"), BundleDir: bundle},
		"an empty key folder name":     {BundleDir: bundle},
	} {
		cfg.Mode, cfg.Passphrases = ModePassphrase, src
		s, err := Open(cfg)
		if err == nil {
			_ = s.Close()
			t.Errorf("%s: opened", name)
			continue
		}
		wantRefusal(t, err, ErrKeyDir, "key-dir")
	}
	if s, err := Open(Config{KeyDir: keys, Mode: ModePassphrase, Passphrases: src}); err == nil {
		_ = s.Close()
		t.Error("an empty bundle folder: opened")
	} else {
		wantRefusal(t, err, ErrParams, "")
	}
	if src.calls() != 0 {
		t.Error("Open asked for a passphrase")
	}
}

// ---- the four files ----

// fourFiles holds the payloads of the four files of label A and what to call to save and read them.
type fourFiles struct {
	k       *Key
	cert    []byte
	x509    []byte
	pgp     []byte
	revoke  []byte
	removal []byte
}

func makeFourFiles(t testing.TB) fourFiles {
	t.Helper()
	k := mustGenerate(t)
	cert := certFor(t, k)
	return fourFiles{
		k: k, cert: cert,
		x509: pemOf(t, k), pgp: secretOf(t, k, cert),
		revoke: revocationFor(t, k, openpgp.Compromised), removal: jwsOf("aGVhZGVy", "cGF5bG9hZA", "c2ln"),
	}
}

func saveAll(t testing.TB, s *Store, f fourFiles) {
	t.Helper()
	for name, err := range map[string]error{
		"SaveX509": s.SaveX509("A", f.k), "SaveOpenPGP": s.SaveOpenPGP("A", f.k, f.cert),
		"SaveRevocation": s.SaveRevocation("A", "compromised", f.revoke), "SaveRemoval": s.SaveRemoval("A", f.removal),
	} {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestPassphraseFilesRoundTripAllFourKindsAtALoweredWorkFactor(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	f := makeFourFiles(t)
	saveAll(t, s, f)
	if !f.k.Saved() {
		t.Error("the key is not Saved after a save")
	}
	names := dirNames(t, keys)
	want := []string{"A.openpgp.key.age", "A.removal.jws.age", "A.revocation.compromised.pgp.age", "A.x509.key.age"}
	if strings.Join(sortedCopy(names), " ") != strings.Join(want, " ") {
		t.Fatalf("the key folder holds %v, want %v", names, want)
	}
	for _, n := range names {
		file := readKeyFile(t, keys, n)
		if !bytes.HasPrefix(file, []byte("age-encryption.org/v1\n-> scrypt ")) {
			t.Errorf("%s does not start as an age file with an scrypt stanza", n)
		}
		if wf := workFactorOfFile(t, file); wf != "10" {
			t.Errorf("%s says work factor %q at the lowered factor", n, wf)
		}
		if bytes.Contains(file[:headerLen(t, file)], []byte("TEST ONLY")) {
			t.Errorf("%s says TEST ONLY", n)
		}
		fi, err := os.Stat(filepath.Join(keys, n))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s has the mode %v", n, fi.Mode().Perm())
		}
		if len(file) > MaxKeyFileSize {
			t.Errorf("%s is %d bytes", n, len(file))
		}
	}
	// the reader that is not ours finds exactly the payloads of the page
	for name, want := range map[string][]byte{
		"A.x509.key.age": f.x509, "A.openpgp.key.age": f.pgp,
		"A.revocation.compromised.pgp.age": f.revoke, "A.removal.jws.age": f.removal,
	} {
		got, err := libraryOpen(t, testPass, readKeyFile(t, keys, name))
		if err != nil {
			t.Fatalf("the library cannot open %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: the payload is not the payload of the page", name)
		}
	}
	// and ours reads them back
	k2, err := s.OpenX509(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = k2.Close() }()
	if !samePublic(f.k, k2) {
		t.Error("another public key")
	}
	pg, err := s.OpenOpenPGP(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pg.Key.Close() }()
	if !samePublic(f.k, pg.Key) || !pg.Created.Equal(testCreated) || !bytes.Equal(pg.Cert, f.cert) {
		t.Error("the opened primary is not the saved one")
	}
	rev, err := s.ReadRevocation(bg(), "A", "compromised")
	if err != nil || !bytes.Equal(rev, f.revoke) {
		t.Errorf("revocation: %v", err)
	}
	rm, err := s.ReadRemoval(bg(), "A")
	if err != nil || !bytes.Equal(rm, f.removal) {
		t.Errorf("removal: %v", err)
	}
	if got, err := s.HasKeyFiles(); err != nil || !got {
		t.Errorf("HasKeyFiles: %v, %v", got, err)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// workFactorOfFile reads the second argument of the first stanza of an age file.
func workFactorOfFile(t testing.TB, file []byte) string {
	t.Helper()
	lines := strings.SplitN(string(file), "\n", 3)
	if len(lines) < 3 {
		t.Fatal("no stanza line")
	}
	f := strings.Fields(lines[1])
	if len(f) != 4 || f[0] != "->" || f[1] != "scrypt" {
		t.Fatalf("the stanza line is %q", lines[1])
	}
	return f[3]
}

func TestAFileThatTheLibraryWritesOpensWithTheStoreAndOtherPassphrasesDoNot(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	writeKeyFile(t, keys, "A.x509.key.age", libraryFile(t, testPass, 10, pemOf(t, k)))
	got, err := s.OpenX509(bg(), "A")
	if err != nil {
		t.Fatalf("a file of the library does not open: %v", err)
	}
	defer func() { _ = got.Close() }()
	if !samePublic(k, got) {
		t.Error("another key")
	}
	if p := src.purposes(); len(p) != 1 || p[0] != (Purpose{Label: "A", File: FileX509}) {
		t.Errorf("asked %v", p)
	}
}

func TestTheFileIsTheSameKindOfFileForEveryReasonAndEveryLabel(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	for i, r := range allReasons {
		sig := revocationFor(t, k, r)
		label := string(rune('B' + i))
		if err := s.SaveRevocation(label, r.Text, sig); err != nil {
			t.Fatalf("%s: %v", r.Text, err)
		}
		name := label + ".revocation." + r.Text + ".pgp.age"
		if _, err := os.Stat(filepath.Join(keys, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		got, err := s.ReadRevocation(bg(), label, r.Text)
		if err != nil || !bytes.Equal(got, sig) {
			t.Errorf("%s: %v", r.Text, err)
		}
		if _, err := s.ReadRevocation(bg(), label, "stolen"); !errors.Is(err, ErrParams) {
			t.Errorf("a reason that is not on the list: %v", err)
		}
	}
	if err := s.SaveX509("Z", k); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(keys, "Z.x509.key.age")); err != nil {
		t.Error(err)
	}
}

func TestEverySaveInPassphraseModeMakesAFreshSaltAndTwoSavesOfOneKeyDiffer(t *testing.T) {
	lowWork(t)
	s, _, keys := openPassStore(t, newPassSource(testPass))
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveX509("B", k); err != nil {
		t.Fatal(err)
	}
	a, b := readKeyFile(t, keys, "A.x509.key.age"), readKeyFile(t, keys, "B.x509.key.age")
	if bytes.Equal(a, b) {
		t.Fatal("two saves of one key with one passphrase are the same bytes")
	}
	if strings.Fields(strings.SplitN(string(a), "\n", 3)[1])[2] == strings.Fields(strings.SplitN(string(b), "\n", 3)[1])[2] {
		t.Error("the salt is the same")
	}
}

// ---- the production work factor: the real scrypt runs of the package ----

func TestPassphraseFileAtTheProductionWorkFactorRunsRealScrypt(t *testing.T) {
	if testing.Short() {
		t.Skip("real scrypt runs: about a second each and 256 MiB")
	}
	if workFactorWritten != 18 || workFactorLowest != 18 {
		t.Fatalf("the work factors are %d and %d, not the production 18", workFactorWritten, workFactorLowest)
	}
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	// one save: two scrypt runs (the encryption and the read back); one open: one run
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	file := readKeyFile(t, keys, "A.x509.key.age")
	if !bytes.HasPrefix(file, []byte("age-encryption.org/v1\n-> scrypt ")) {
		t.Fatal("not an age file with an scrypt stanza")
	}
	if wf := workFactorOfFile(t, file); wf != "18" {
		t.Fatalf("the work factor in the header is %q, want 18", wf)
	}
	got, err := s.OpenX509(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = got.Close() }()
	if !samePublic(k, got) {
		t.Error("another public key")
	}
	if p := src.purposes(); len(p) != 2 || p[0] != p[1] || p[0] != (Purpose{Label: "A", File: FileX509}) {
		t.Errorf("one ask for the save and one for the open, got %v", p)
	}

	t.Run("a wrong passphrase", func(t *testing.T) {
		bad := newPassSource(testPass2)
		s2, _, keys2 := openPassStore(t, bad)
		writeKeyFile(t, keys2, "A.x509.key.age", file)
		key, err := s2.OpenX509(bg(), "A")
		if key != nil {
			t.Error("a key came")
		}
		wantRefusal(t, err, ErrWrongPassphrase, "passphrase-wrong", testPass, testPass2)
	})
	t.Run("the right passphrase with one character changed", func(t *testing.T) {
		near := newPassSource(testPass[:len(testPass)-1] + "Y")
		s2, _, keys2 := openPassStore(t, near)
		writeKeyFile(t, keys2, "A.x509.key.age", file)
		key, err := s2.OpenX509(bg(), "A")
		if key != nil {
			t.Error("a key came")
		}
		wantRefusal(t, err, ErrWrongPassphrase, "passphrase-wrong")
		lower := strings.ToUpper(testPass[:1]) + testPass[1:]
		if err2 := openWith(t, lower, file); !errors.Is(err2, ErrWrongPassphrase) {
			t.Errorf("another case: %v", err2)
		}
	})
	t.Run("one changed byte in the payload", func(t *testing.T) {
		damaged := bytes.Clone(file)
		damaged[headerLen(t, file)+16+8] ^= 1
		wantRefusal(t, openWith(t, testPass, damaged), ErrKeyFile, "key-file")
	})
	t.Run("a file cut in its payload", func(t *testing.T) {
		wantRefusal(t, openWith(t, testPass, file[:len(file)-7]), ErrKeyFile, "key-file")
	})
	t.Run("a file with a byte after its last chunk", func(t *testing.T) {
		wantRefusal(t, openWith(t, testPass, append(bytes.Clone(file), 0)), ErrKeyFile, "key-file")
	})
}

// openWith opens a file of label A as the X.509 key with a passphrase, in a new store.
func openWith(t testing.TB, pass string, file []byte) error {
	t.Helper()
	s, _, keys := openPassStore(t, newPassSource(pass))
	writeKeyFile(t, keys, "A.x509.key.age", file)
	key, err := s.OpenX509(bg(), "A")
	if key != nil {
		_ = key.Close()
		if err != nil {
			t.Error("a key came with an error")
		}
	}
	return err
}

// ---- wrong passphrases (lowered) ----

func TestEveryWrongPassphraseIsErrWrongPassphraseWithOneSetOfWordsAndNoFileChange(t *testing.T) {
	lowWork(t)
	s, _, keys := openPassStore(t, newPassSource(testPass))
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	file := readKeyFile(t, keys, "A.x509.key.age")
	var texts []string
	for name, wrong := range map[string]string{
		"one character changed":       testPass[:len(testPass)-1] + "X",
		"the first character changed": "E" + testPass[1:],
		"one character added":         testPass + "x",
		"one character removed":       testPass[:len(testPass)-1],
		"another case":                strings.ToUpper(testPass),
		"a leading space":             " " + testPass,
		"a trailing space":            testPass + " ",
		"another passphrase":          testPass2,
		"the right words reversed":    reverse(testPass),
	} {
		other, _, keys2 := openPassStore(t, newPassSource(wrong))
		writeKeyFile(t, keys2, "A.x509.key.age", file)
		got, err := other.OpenX509(bg(), "A")
		if got != nil {
			t.Errorf("%s: a key came", name)
		}
		wantRefusal(t, err, ErrWrongPassphrase, "passphrase-wrong", wrong, testPass)
		text := strings.ToLower(err.Error())
		if strings.Contains(text, "close") || strings.Contains(text, "one character") || strings.Contains(text, "almost") {
			t.Errorf("%s: the words hint at how near the passphrase is: %v", name, err)
		}
		texts = append(texts, err.Error())
		if names := dirNames(t, keys2); len(names) != 1 {
			t.Errorf("%s: the folder holds %v", name, names)
		}
		if !bytes.Equal(readKeyFile(t, keys2, "A.x509.key.age"), file) {
			t.Errorf("%s: the file changed", name)
		}
	}
	for _, text := range texts {
		if text != texts[0] {
			t.Errorf("two wrong passphrases give different words: %q and %q", text, texts[0])
		}
	}
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func TestAPassphraseThatIsNotAcceptableIsErrPassphraseAndNeverReachesScryptOnOpenOrSave(t *testing.T) {
	lowWork(t)
	good := newPassSource(testPass)
	s0, _, keys0 := openPassStore(t, good)
	k := mustGenerate(t)
	if err := s0.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	file := readKeyFile(t, keys0, "A.x509.key.age")
	for name, raw := range map[string][]byte{
		"nil":                nil,
		"empty":              {},
		"14 characters":      []byte(strings.Repeat("a", 14)),
		"a control byte":     []byte(strings.Repeat("a", 20) + "\x00"),
		"a format character": []byte(strings.Repeat("a", 20) + "\u202e"),
		"invalid UTF-8":      []byte(strings.Repeat("a", 20) + "\xff"),
		"1025 bytes":         bytes.Repeat([]byte("a"), MaxPassphraseBytes+1),
	} {
		t.Run("open/"+name, func(t *testing.T) {
			src := &passSource{raw: func(Purpose) []byte { return bytes.Clone(raw) }}
			s, _, keys := openPassStore(t, src)
			writeKeyFile(t, keys, "A.x509.key.age", file)
			rf := recordAge(t, s)
			got, err := s.OpenX509(bg(), "A")
			if got != nil {
				t.Error("a key came")
			}
			wantRefusal(t, err, ErrPassphrase, "passphrase")
			if rf.unwraps != 0 {
				t.Error("scrypt ran")
			}
		})
		t.Run("save/"+name, func(t *testing.T) {
			src := &passSource{raw: func(Purpose) []byte { return bytes.Clone(raw) }}
			s, _, keys := openPassStore(t, src)
			rf := recordAge(t, s)
			kk := mustGenerate(t)
			err := s.SaveX509("A", kk)
			wantRefusal(t, err, ErrPassphrase, "passphrase")
			if kk.Saved() {
				t.Error("Saved")
			}
			if rf.wraps != 0 || len(dirNames(t, keys)) != 0 {
				t.Errorf("wraps %d, files %v", rf.wraps, dirNames(t, keys))
			}
			// a refused passphrase does not stop the writer: a good one saves
			src.raw = nil
			src.def = testPass
			if err := s.SaveX509("A", kk); err != nil {
				t.Errorf("a save after a refused passphrase: %v", err)
			}
		})
	}
}

// ---- damage (lowered) ----

func TestDamageToAPassphraseFileIsRefusedAndNeverGivesAKey(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	file := readKeyFile(t, keys, "A.x509.key.age")
	hl := headerLen(t, file)
	flip := func(i int) []byte { d := bytes.Clone(file); d[i] ^= 1; return d }
	lines := strings.SplitN(string(file), "\n", 4)
	saltAt := len(lines[0]) + 1 + len("-> scrypt ") + 3
	bodyAt := len(lines[0]) + 1 + len(lines[1]) + 1 + 2
	macAt := hl - 1 - 5
	cases := []struct {
		name string
		file []byte
		is   []error // the error is one of them
	}{
		{"a changed byte of the salt", flip(saltAt), []error{ErrWrongPassphrase, ErrKeyFile}},
		{"a changed byte of the stanza body", flip(bodyAt), []error{ErrWrongPassphrase, ErrKeyFile}},
		{"a changed byte of the MAC", flip(macAt), []error{ErrKeyFile}},
		{"a changed byte of the nonce", flip(hl + 3), []error{ErrKeyFile}},
		{"a changed byte at the start of the payload", flip(hl + 16), []error{ErrKeyFile}},
		{"a changed byte in the middle of the payload", flip(hl + 16 + (len(file)-hl-16)/2), []error{ErrKeyFile}},
		{"a changed byte of the tag of the last chunk", flip(len(file) - 1), []error{ErrKeyFile}},
		{"the file cut by one byte", file[:len(file)-1], []error{ErrKeyFile}},
		{"the file cut to its header", file[:hl], []error{ErrKeyFile}},
		{"the file cut to its header and the nonce", file[:hl+16], []error{ErrKeyFile}},
		{"the file cut inside the nonce", file[:hl+8], []error{ErrKeyFile}},
		{"the file cut to the nonce and ten bytes", file[:hl+16+10], []error{ErrKeyFile}},
		{"a byte after the last chunk", append(bytes.Clone(file), 0), []error{ErrKeyFile}},
		{"many bytes after the last chunk", append(bytes.Clone(file), bytes.Repeat([]byte{7}, 100)...), []error{ErrKeyFile}},
		{"a line feed after the file", append(bytes.Clone(file), '\n'), []error{ErrKeyFile}},
		{"the file twice", append(bytes.Clone(file), file...), []error{ErrKeyFile}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeKeyFile(t, keys, "B.x509.key.age", c.file)
			got, err := s.OpenX509(bg(), "B")
			if got != nil {
				t.Fatal("a key came out of a damaged file")
			}
			if err == nil {
				t.Fatal("a damaged file opened")
			}
			ok := false
			for _, want := range c.is {
				ok = ok || errors.Is(err, want)
			}
			if !ok {
				t.Errorf("the error is %v", err)
			}
			if Code(err) != "key-file" && Code(err) != "passphrase-wrong" {
				t.Errorf("the code is %q", Code(err))
			}
			if strings.Contains(err.Error(), testPass) {
				t.Error("the error holds the passphrase")
			}
		})
	}
}

func TestAnAgeFileOfTheWrongShapeIsErrKeyFileAndAsksForNoPassphrase(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	rf := recordAge(t, s)
	armoured := []byte(armourLine("BEGIN", "AGE ENCRYPTED FILE") + "\n" + b64(bytes.Repeat([]byte{1}, 60)) + "\n" + armourLine("END", "AGE ENCRYPTED FILE") + "\n")
	x25519 := headerOf(stanzaText("X25519", []string{b64(bytes.Repeat([]byte{3}, 32))}, bytes.Repeat([]byte{4}, 32)))
	for name, file := range map[string][]byte{
		"a plain PEM in an age name":       x509File(t, k),
		"an armoured age file":             armoured,
		"an empty file":                    {},
		"an X25519 file":                   x25519,
		"two scrypt stanzas":               headerOf(scryptStanza("18"), scryptStanza("18")),
		"a work factor of 17":              headerOf(scryptStanza("17")),
		"a work factor of 23":              headerOf(scryptStanza("23")),
		"a work factor of 30":              headerOf(scryptStanza("30")),
		"a work factor of 9999999999":      headerOf(scryptStanza("9999999999")),
		"a work factor of 018":             headerOf(scryptStanza("018")),
		"a work factor with a plus sign":   headerOf(scryptStanza("+18")),
		"junk of the size of a key file":   bytes.Repeat([]byte{0xA5}, MaxKeyFileSize),
		"junk over the size of a key file": bytes.Repeat([]byte{0xA5}, MaxKeyFileSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			// at the lowered factor 17 is outside the range because it is not 10..22, but 9 is the
			// first below it: the cases name the production range, so the lowest limit is put back
			workFactorLowest = MinWorkFactor
			defer func() { workFactorLowest = 10 }()
			writeKeyFile(t, keys, "B.x509.key.age", file)
			got, err := s.OpenX509(bg(), "B")
			if got != nil {
				t.Error("a key came")
			}
			wantRefusal(t, err, ErrKeyFile, "key-file")
		})
	}
	if src.calls() != 0 || rf.unwraps != 0 {
		t.Errorf("the passphrase was asked %d times and scrypt ran %d times", src.calls(), rf.unwraps)
	}
}

// ---- the size of a file ----

func TestAFileOfExactlyTheLimitIsReadAndOneByteMoreIsRefusedBeforeAnyPassphrase(t *testing.T) {
	lowWork(t)
	rcpLen := func(n int) []byte { return libraryFile(t, testPass, 10, bytes.Repeat([]byte{'x'}, n)) }
	overhead := len(rcpLen(1)) - 1
	atLimit := rcpLen(MaxKeyFileSize - overhead)
	if len(atLimit) != MaxKeyFileSize {
		t.Fatalf("the test file is %d bytes", len(atLimit))
	}
	over := rcpLen(MaxKeyFileSize - overhead + 1)
	if len(over) != MaxKeyFileSize+1 {
		t.Fatalf("the long file is %d bytes", len(over))
	}
	pass := []byte(testPass)
	got, err := ageFormat{}.unwrapWith(pass, FileRemoval, atLimit)
	if err != nil || len(got) != MaxKeyFileSize-overhead {
		t.Fatalf("a file at the limit: %d bytes, %v", len(got), err)
	}
	if _, err := (ageFormat{}).unwrapWith(pass, FileRemoval, over); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a file over the limit: %v", err)
	}
	// through the Store: no passphrase is asked for the long file
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	writeKeyFile(t, keys, "A.removal.jws.age", over)
	_, err = s.ReadRemoval(bg(), "A")
	wantRefusal(t, err, ErrKeyFile, "key-file")
	if src.calls() != 0 {
		t.Error("a passphrase was asked for a file over the limit")
	}
}

func TestAPayloadOverTheLimitIsRefusedBeforeThePassphraseIsAskedAndBeforeEncryption(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	rf := recordAge(t, s)
	s.mu.Lock()
	err := s.write(FileRemoval, "A", "", bytes.Repeat([]byte{'a'}, MaxKeyFileSize+1), func([]byte) error { return nil }, nil)
	s.mu.Unlock()
	wantRefusal(t, err, ErrKeyFile, "key-file")
	if src.calls() != 0 || rf.wraps != 0 {
		t.Errorf("asked %d, encrypted %d", src.calls(), rf.wraps)
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("files: %v", names)
	}
	// the format refuses too, and an empty payload, and a kind that is not one of the four
	for name, f := range map[string]func() error{
		"a payload over the limit": func() error {
			_, err := ageFormat{}.wrapWith([]byte(testPass), FileX509, bytes.Repeat([]byte{'a'}, MaxKeyFileSize+1))
			return err
		},
		"an empty payload": func() error { _, err := ageFormat{}.wrapWith([]byte(testPass), FileX509, nil); return err },
		"a kind that is not one of the four": func() error {
			_, err := ageFormat{}.wrapWith([]byte(testPass), FileKind("other"), []byte("x"))
			return err
		},
	} {
		if err := f(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (ageFormat{}).unwrapWith([]byte(testPass), FileKind("other"), []byte("x")); !errors.Is(err, ErrParams) {
		t.Errorf("a kind that is not one of the four, read: %v", err)
	}
	if _, err := (ageFormat{}).wrapWith(nil, FileX509, []byte("x")); !errors.Is(err, ErrPassphrase) {
		t.Errorf("an empty passphrase to wrapWith: %v", err)
	}
	if _, err := (ageFormat{}).unwrapWith(nil, FileX509, headerOf(scryptStanza("18"))); !errors.Is(err, ErrPassphrase) {
		t.Errorf("an empty passphrase to unwrapWith: %v", err)
	}
}

func TestTheWorkFactorThatIsWrittenIsHeldToItsBoundsAndAnOutOfRangeValueIsAParameterError(t *testing.T) {
	old := workFactorWritten
	defer func() { workFactorWritten = old }()
	for _, wf := range []int{-1, 0, MaxWorkFactor + 1, 30, 31, 1 << 20} {
		workFactorWritten = wf
		_, err := ageFormat{}.wrapWith([]byte(testPass), FileX509, []byte("x"))
		if !errors.Is(err, ErrParams) {
			t.Errorf("%d: %v", wf, err)
		}
	}
}

func TestThePlainMethodsOfTheAgeFormatRefuseBecauseTheyHaveNoPassphrase(t *testing.T) {
	if _, err := (ageFormat{}).wrap(FileX509, []byte("x")); !errors.Is(err, ErrParams) {
		t.Errorf("wrap: %v", err)
	}
	if _, err := (ageFormat{}).unwrap(FileX509, []byte("x")); !errors.Is(err, ErrParams) {
		t.Errorf("unwrap: %v", err)
	}
	// a Store whose format hides the secretFormat takes the plain path, and the file is not written
	s, _, keys := openPassStore(t, newPassSource(testPass))
	s.format = struct{ format }{ageFormat{}}
	if err := s.SaveX509("A", mustGenerate(t)); !errors.Is(err, ErrParams) {
		t.Errorf("%v", err)
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("files: %v", names)
	}
}

func TestReadPayloadStopsOnErrorsAndOnAReaderThatGivesNothing(t *testing.T) {
	buf := make([]byte, 100)
	// a clean end
	n, err := readPayload(bytes.NewReader([]byte("abc")), buf)
	if err != nil || n != 3 {
		t.Errorf("clean end: %d, %v", n, err)
	}
	// a full buffer is returned as it is and the caller sees the over-long payload
	n, err = readPayload(bytes.NewReader(bytes.Repeat([]byte{1}, 500)), buf)
	if err != nil || n != len(buf) {
		t.Errorf("over-long: %d, %v", n, err)
	}
	// a read error clears what was read and is a damaged file
	buf2 := make([]byte, 100)
	r := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte{9}, 10)), errReader{})
	if _, err := readPayload(r, buf2); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a read error: %v", err)
	}
	if !allZero(buf2[:10]) {
		t.Error("what was read is not cleared after an error")
	}
	// a reader that gives nothing for ever
	e := &emptyReader{}
	if _, err := readPayload(e, make([]byte, 10)); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a reader that gives nothing: %v", err)
	}
	if e.reads == 0 || e.reads > 1000 {
		t.Errorf("%d reads", e.reads)
	}
	// data together with the end
	if n, err := readPayload(dataEOF{[]byte("xyz")}, make([]byte, 10)); err != nil || n != 3 {
		t.Errorf("data with the end: %d, %v", n, err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("a read error with CANARY-TEXT") }

type dataEOF struct{ b []byte }

func (d dataEOF) Read(p []byte) (int, error) { return copy(p, d.b), io.EOF }

func TestClassifyDecryptKeepsOurErrorsAndNeverRepeatsTheTextOfTheLibrary(t *testing.T) {
	canary := "CANARY-LINE"
	if err := classifyDecrypt(refuse(ErrKeyFile, "a refusal of the gate")); !errors.Is(err, ErrKeyFile) {
		t.Errorf("the gate's refusal: %v", err)
	}
	if err := classifyDecrypt(refuse(ErrParams, "no identity")); !errors.Is(err, ErrParams) {
		t.Errorf("a parameter error: %v", err)
	}
	none := &age.NoIdentityMatchError{StanzaTypes: []string{canary}}
	err := classifyDecrypt(none)
	wantRefusal(t, err, ErrWrongPassphrase, "passphrase-wrong", canary)
	err = classifyDecrypt(errors.New("failed to read header: " + canary))
	wantRefusal(t, err, ErrKeyFile, "key-file", canary)
	err = classifyDecrypt(io.ErrUnexpectedEOF)
	wantRefusal(t, err, ErrKeyFile, "key-file")
}

// ---- who is asked, and how often ----

func TestEachKeyAsksTheSourceOnceWithItsPurposeAndTheWrittenFilesAskForTheRootTheyBelongTo(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, _ := openPassStore(t, src)
	f := makeFourFiles(t)
	if err := s.SaveX509("A", f.k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOpenPGP("A", f.k, f.cert); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRevocation("A", "compromised", f.revoke); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRemoval("A", f.removal); err != nil {
		t.Fatal(err)
	}
	want := []Purpose{{"A", FileX509}, {"A", FileOpenPGP}, {"A", FileRevocation}, {"A", FileRemoval}}
	if got := src.purposes(); !samePurposes(got, want) {
		t.Fatalf("saves asked %v, want %v", got, want)
	}
	if _, err := s.OpenX509(bg(), "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenOpenPGP(bg(), "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRevocation(bg(), "A", "compromised"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRemoval(bg(), "A"); err != nil {
		t.Fatal(err)
	}
	if got := src.purposes(); !samePurposes(got, append(append([]Purpose{}, want...), want...)) {
		t.Errorf("saves and opens asked %v", got)
	}
}

func samePurposes(a, b []Purpose) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestASourceThatAnswersPerKeyGivesEachFileItsOwnPassphrase(t *testing.T) {
	lowWork(t)
	src := &passSource{def: testPass, by: map[Purpose]string{{"A", FileOpenPGP}: testPass2}}
	s, _, keys := openPassStore(t, src)
	f := makeFourFiles(t)
	if err := s.SaveX509("A", f.k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOpenPGP("A", f.k, f.cert); err != nil {
		t.Fatal(err)
	}
	if _, err := libraryOpen(t, testPass, readKeyFile(t, keys, "A.x509.key.age")); err != nil {
		t.Errorf("the X.509 file does not open with its own passphrase: %v", err)
	}
	if _, err := libraryOpen(t, testPass2, readKeyFile(t, keys, "A.openpgp.key.age")); err != nil {
		t.Errorf("the OpenPGP file does not open with its own passphrase: %v", err)
	}
	if _, err := libraryOpen(t, testPass, readKeyFile(t, keys, "A.openpgp.key.age")); err == nil {
		t.Error("the OpenPGP file opens with the passphrase of the X.509 file")
	}
	if _, err := s.OpenOpenPGP(bg(), "A"); err != nil {
		t.Errorf("open: %v", err)
	}
	// swapped: the passphrase of one is not the passphrase of the other
	src.by = map[Purpose]string{{"A", FileX509}: testPass2}
	if _, err := s.OpenX509(bg(), "A"); !errors.Is(err, ErrWrongPassphrase) {
		t.Errorf("the other file's passphrase: %v", err)
	}
}

func TestASourceErrorIsReturnedWrappedAndNothingIsWrittenAndTheKeyIsNotSaved(t *testing.T) {
	lowWork(t)
	boom := errors.New("the source failed")
	src := &passSource{def: testPass, err: boom}
	s, _, keys := openPassStore(t, src)
	f := makeFourFiles(t)
	k := f.k
	rec := record(s)
	for name, err := range map[string]error{
		"SaveX509": s.SaveX509("A", k), "SaveOpenPGP": s.SaveOpenPGP("A", k, f.cert),
		"SaveRevocation": s.SaveRevocation("A", "compromised", f.revoke), "SaveRemoval": s.SaveRemoval("A", f.removal),
	} {
		if !errors.Is(err, boom) {
			t.Errorf("%s: the error of the source is not wrapped: %v", name, err)
		}
	}
	if k.Saved() {
		t.Error("Saved")
	}
	if rec.calls() != 0 || len(dirNames(t, keys)) != 0 {
		t.Errorf("writes %d, files %v", rec.calls(), dirNames(t, keys))
	}
	// the store is not stopped by a source error: with a good source the same calls work
	src.err = nil
	if err := s.SaveX509("A", k); err != nil {
		t.Errorf("a save after a source error: %v", err)
	}
	// and an open
	src.err = boom
	got, err := s.OpenX509(bg(), "A")
	if got != nil || !errors.Is(err, boom) {
		t.Errorf("open: %v, %v", got, err)
	}
	for _, f := range []func() error{
		func() error { _, err := s.OpenOpenPGP(bg(), "A"); return err },
		func() error { _, err := s.ReadRevocation(bg(), "A", "compromised"); return err },
		func() error { _, err := s.ReadRemoval(bg(), "A"); return err },
	} {
		// these files do not exist: the file is looked at first, so the source is not asked
		if err := f(); !errors.Is(err, ErrKeyFile) {
			t.Errorf("a missing file: %v", err)
		}
	}
}

func TestTheStoreWritesNothingAndAsksNothingWhenTheNameStandsAlreadyOrTheOtherModeIsThere(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	asked := src.calls()
	file := readKeyFile(t, keys, "A.x509.key.age")
	rec := record(s)
	err := s.SaveX509("A", mustGenerate(t))
	wantRefusal(t, err, ErrKeyExists, "key-exists")
	if src.calls() != asked || rec.calls() != 0 {
		t.Errorf("a name that stands: asked %d more times, wrote %d times", src.calls()-asked, rec.calls())
	}
	if !bytes.Equal(readKeyFile(t, keys, "A.x509.key.age"), file) {
		t.Error("the file changed")
	}
	// the writer is stopped: another name is refused with the same error
	if err2 := s.SaveX509("B", k); !errors.Is(err2, ErrKeyExists) {
		t.Errorf("after the stop: %v", err2)
	}
	if rec.calls() != 0 || src.calls() != asked {
		t.Error("a stopped writer wrote or asked")
	}
	// the other mode: a store with a plain file in its folder refuses to write
	s2, _, keys2 := openPassStore(t, src)
	writeKeyFile(t, keys2, "B.x509.key.pem", x509File(t, k))
	err = s2.SaveX509("A", k)
	wantRefusal(t, err, ErrWrongMode, "key-file-mode")
	if src.calls() != asked || len(dirNames(t, keys2)) != 1 {
		t.Error("asked or wrote")
	}
}

// ---- the other mode's files are not parsed ----

func TestAPassphraseStoreFindingAPlainFileIsErrWrongModeWithNoPassphraseAndNoParse(t *testing.T) {
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	rf := recordAge(t, s)
	k := mustGenerate(t)
	plain := x509File(t, k)
	calls := map[string]func() error{
		"A.x509.key.pem":           func() error { _, err := s.OpenX509(bg(), "A"); return err },
		"A.openpgp.key.asc":        func() error { _, err := s.OpenOpenPGP(bg(), "A"); return err },
		"A.revocation.retired.asc": func() error { _, err := s.ReadRevocation(bg(), "A", "retired"); return err },
		"A.removal.jws":            func() error { _, err := s.ReadRemoval(bg(), "A"); return err },
	}
	for name, call := range calls {
		writeKeyFile(t, keys, name, plain)
		err := call()
		wantRefusal(t, err, ErrWrongMode, "key-file-mode")
		_ = os.Remove(filepath.Join(keys, name))
	}
	if src.calls() != 0 || rf.inspects != 0 || rf.unwraps != 0 {
		t.Errorf("asked %d, inspected %d, scrypt %d", src.calls(), rf.inspects, rf.unwraps)
	}
	// a missing file with no file of the other mode is a missing file
	_, err := s.OpenX509(bg(), "A")
	wantRefusal(t, err, ErrKeyFile, "key-file")
}

func TestATestStoreFindingAnAgeFileIsErrWrongModeAndNoPassphraseIsNeeded(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	sp, _, keys := openPassStore(t, src)
	k := mustGenerate(t)
	if err := sp.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	_ = sp.Close()
	st, err := Open(Config{KeyDir: keys, BundleDir: filepath.Join(filepath.Dir(keys), "bundle"), Mode: ModeTest})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	_, err = st.OpenX509(bg(), "A")
	wantRefusal(t, err, ErrWrongMode, "key-file-mode")
	if err := st.SaveX509("B", k); !errors.Is(err, ErrWrongMode) {
		t.Errorf("a save beside an age file: %v", err)
	}
}

// ---- the passphrase slice is cleared on every path ----

func TestThePassphraseSliceIsClearedAfterEverySaveAndOpenAndOnEveryRefusal(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	f := makeFourFiles(t)
	saveAll(t, s, f)
	if _, err := s.OpenX509(bg(), "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenOpenPGP(bg(), "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRevocation(bg(), "A", "compromised"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadRemoval(bg(), "A"); err != nil {
		t.Fatal(err)
	}
	check := func(what string, src *passSource) {
		t.Helper()
		src.mu.Lock()
		defer src.mu.Unlock()
		if len(src.given) == 0 {
			t.Errorf("%s: the source gave no slice", what)
		}
		for i, b := range src.given {
			if len(b) > 0 && !allZero(b) {
				t.Errorf("%s: the slice %d still holds the passphrase", what, i)
			}
		}
	}
	check("saves and opens", src)

	// a wrong passphrase, a refused one, a source that fails and gives a slice with its error,
	// and a damaged file
	file := readKeyFile(t, keys, "A.x509.key.age")
	for name, p := range map[string]string{"a wrong passphrase": testPass2, "a short passphrase": "too short"} {
		bad := newPassSource(p)
		s2, _, keys2 := openPassStore(t, bad)
		writeKeyFile(t, keys2, "A.x509.key.age", file)
		_, _ = s2.OpenX509(bg(), "A")
		check(name, bad)
		kk := mustGenerate(t)
		_ = s2.SaveX509("B", kk)
		check(name+" on a save", bad)
	}
	failing := &passSource{def: testPass, err: errors.New("fails with a slice")}
	s3, _, keys3 := openPassStore(t, failing)
	writeKeyFile(t, keys3, "A.x509.key.age", file)
	_, _ = s3.OpenX509(bg(), "A")
	_ = s3.SaveX509("B", mustGenerate(t))
	check("a source that fails", failing)
	damaged := newPassSource(testPass)
	s4, _, keys4 := openPassStore(t, damaged)
	writeKeyFile(t, keys4, "A.x509.key.age", file[:len(file)-3])
	_, _ = s4.OpenX509(bg(), "A")
	check("a damaged file", damaged)
	// the passphrase that the format gets is the Store's copy of the slice of the source: cleared
	// too, through the same slice
	tracked := newPassSource(testPass)
	s5, _, _ := openPassStore(t, tracked)
	if err := s5.SaveX509("A", mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	check("a save", tracked)
}

// ---- a cancelled context ----

func TestACancelledContextStopsAnOpenBeforeThePassphraseAndBeforeScrypt(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, _ := openPassStore(t, src)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	asked := src.calls()
	rf := recordAge(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, call := range map[string]func() error{
		"OpenX509":       func() error { _, err := s.OpenX509(ctx, "A"); return err },
		"OpenOpenPGP":    func() error { _, err := s.OpenOpenPGP(ctx, "A"); return err },
		"ReadRevocation": func() error { _, err := s.ReadRevocation(ctx, "A", "retired"); return err },
		"ReadRemoval":    func() error { _, err := s.ReadRemoval(ctx, "A"); return err },
	} {
		if err := call(); !errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if src.calls() != asked || rf.inspects != 0 || rf.unwraps != 0 {
		t.Errorf("asked %d more times, inspected %d, scrypt %d", src.calls()-asked, rf.inspects, rf.unwraps)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 0)
	defer dcancel()
	if _, err := s.OpenX509(dctx, "A"); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("an expired deadline: %v", err)
	}
}

func TestAContextCancelledWhileThePassphraseIsAskedStopsBeforeScrypt(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, _ := openPassStore(t, src)
	if err := s.SaveX509("A", mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	rf := recordAge(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	src.hook = func(_ context.Context, _ Purpose) { cancel() }
	got, err := s.OpenX509(ctx, "A")
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("%v, %v", got, err)
	}
	if rf.unwraps != 0 {
		t.Error("scrypt ran after the context was cancelled")
	}
	src.mu.Lock()
	last := src.given[len(src.given)-1]
	src.mu.Unlock()
	if !allZero(last) {
		t.Error("the passphrase was not cleared on the path of a cancelled context")
	}
}

func TestACancelledContextAfterTheFileIsReadStopsBeforeThePassphrase(t *testing.T) {
	// the second look at the context, after the size is checked and before the header is read
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	if err := s.SaveX509("A", mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	// the format cancels when it is asked to look at the header
	s.format = cancelOnInspect{inner: ageFormat{}, cancel: cancel}
	asked := src.calls()
	_, err := s.OpenX509(ctx, "A")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("%v", err)
	}
	if src.calls() != asked {
		t.Error("the passphrase was asked after the context was cancelled")
	}
	_ = keys
}

type cancelOnInspect struct {
	inner  ageFormat
	cancel context.CancelFunc
}

func (c cancelOnInspect) wrap(k FileKind, p []byte) ([]byte, error)   { return c.inner.wrap(k, p) }
func (c cancelOnInspect) unwrap(k FileKind, f []byte) ([]byte, error) { return c.inner.unwrap(k, f) }
func (c cancelOnInspect) inspect(f []byte) error                      { c.cancel(); return c.inner.inspect(f) }
func (c cancelOnInspect) wrapWith(p []byte, k FileKind, b []byte) ([]byte, error) {
	return c.inner.wrapWith(p, k, b)
}
func (c cancelOnInspect) unwrapWith(p []byte, k FileKind, f []byte) ([]byte, error) {
	return c.inner.unwrapWith(p, k, f)
}

// ---- the store and ReaderSource together ----

func TestReaderSourceFeedsTheStoreOneLineForEachKeyInTheOrderOfTheAsks(t *testing.T) {
	lowWork(t)
	bundle, keys := newBundle(t)
	lines := testPass + "\n" + testPass2 + "\n"
	s, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: ReaderSource(strings.NewReader(lines))})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	k := mustGenerate(t)
	cert := certFor(t, k)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOpenPGP("A", k, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := libraryOpen(t, testPass, readKeyFile(t, keys, "A.x509.key.age")); err != nil {
		t.Errorf("the first line is not the passphrase of the first key: %v", err)
	}
	if _, err := libraryOpen(t, testPass2, readKeyFile(t, keys, "A.openpgp.key.age")); err != nil {
		t.Errorf("the second line is not the passphrase of the second key: %v", err)
	}
	// the descriptor is spent: a third key has no passphrase and nothing is written for it
	err = s.SaveX509("B", mustGenerate(t))
	wantRefusal(t, err, ErrPassphrase, "passphrase")
	if names := dirNames(t, keys); len(names) != 2 {
		t.Errorf("files: %v", names)
	}
	// opening with the lines in the order of the asks works, and in the other order it does not
	for _, c := range []struct {
		lines string
		ok    bool
	}{{testPass + "\n" + testPass2 + "\n", true}, {testPass2 + "\n" + testPass + "\n", false}} {
		s2, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModePassphrase, Passphrases: ReaderSource(strings.NewReader(c.lines))})
		if err != nil {
			t.Fatal(err)
		}
		_, e1 := s2.OpenX509(bg(), "A")
		_, e2 := s2.OpenOpenPGP(bg(), "A")
		if c.ok && (e1 != nil || e2 != nil) {
			t.Errorf("in order: %v, %v", e1, e2)
		}
		if !c.ok && (!errors.Is(e1, ErrWrongPassphrase) || !errors.Is(e2, ErrWrongPassphrase)) {
			t.Errorf("swapped: %v, %v", e1, e2)
		}
		_ = s2.Close()
	}
}

func TestTwoGoroutinesSavingTwoLabelsInPassphraseModeBothSucceed(t *testing.T) {
	lowWork(t)
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	ks := []*Key{mustGenerate(t), mustGenerate(t)}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, label := range []string{"A", "B"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.SaveX509(label, ks[i])
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
	if names := dirNames(t, keys); len(names) != 2 {
		t.Errorf("files: %v", names)
	}
	for i, label := range []string{"A", "B"} {
		got, err := s.OpenX509(bg(), label)
		if err != nil || !samePublic(ks[i], got) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

func TestTwoGoroutinesSavingOneNameInPassphraseModeGiveOneWinnerAndOneErrKeyExists(t *testing.T) {
	lowWork(t)
	for attempt := 0; attempt < 5; attempt++ {
		s, _, _ := openPassStore(t, newPassSource(testPass))
		ks := []*Key{mustGenerate(t), mustGenerate(t)}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i := range ks {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = s.SaveX509("A", ks[i])
			}()
		}
		wg.Wait()
		wins, exists, winner := 0, 0, -1
		for i, err := range errs {
			switch {
			case err == nil:
				wins, winner = wins+1, i
			case errors.Is(err, ErrKeyExists):
				exists++
			default:
				t.Fatalf("goroutine %d: %v", i, err)
			}
		}
		if wins != 1 || exists != 1 {
			t.Fatalf("%d winners, %d exists", wins, exists)
		}
		got, err := s.OpenX509(bg(), "A")
		if err != nil || !samePublic(ks[winner], got) {
			t.Fatalf("the file is not the key of the winner: %v", err)
		}
	}
}

func TestAStoreHandMadeWithNoSourceRefusesInsteadOfPanicking(t *testing.T) {
	s, _, keys := openPassStore(t, newPassSource(testPass))
	s.source = nil
	if err := s.SaveX509("A", mustGenerate(t)); !errors.Is(err, ErrParams) {
		t.Errorf("save: %v", err)
	}
	writeKeyFile(t, keys, "A.x509.key.age", headerOf(scryptStanza("18")))
	if _, err := s.OpenX509(bg(), "A"); !errors.Is(err, ErrParams) {
		t.Errorf("open: %v", err)
	}
}

func TestAnAgeFileThatIsAFifoOrALinkIsRefusedAndDoesNotWait(t *testing.T) {
	src := newPassSource(testPass)
	s, _, keys := openPassStore(t, src)
	if err := mkfifo(filepath.Join(keys, "A.x509.key.age")); err != nil {
		t.Skipf("no fifo: %v", err)
	}
	if err := os.Symlink(filepath.Join(keys, "A.x509.key.age"), filepath.Join(keys, "B.x509.key.age")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(keys, "nowhere"), filepath.Join(keys, "C.x509.key.age")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(keys, "D.x509.key.age"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"A", "B", "C", "D"} {
		got, err := s.OpenX509(bg(), label)
		if got != nil {
			t.Errorf("%s: a key came", label)
		}
		wantRefusal(t, err, ErrKeyFile, "key-file")
	}
	if src.calls() != 0 {
		t.Error("a passphrase was asked")
	}
	// the fifo, the links and the folder are not regular files: only a regular file is a key file
	if ok, err := s.HasKeyFiles(); err != nil || ok {
		t.Errorf("HasKeyFiles %v, %v", ok, err)
	}
	// a save of a name that stands as a folder or a link is refused with nothing asked
	if err := s.SaveX509("D", mustGenerate(t)); !errors.Is(err, ErrKeyExists) {
		t.Errorf("a save over a folder: %v", err)
	}
}

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
