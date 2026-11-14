package software

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
)

// saveKinds are the four saves, each with a label.
type saveKind struct {
	name  string
	final string // the name of the file it writes for label A
	save  func(t *testing.T, s *Store, k *Key) error
}

func saveKinds() []saveKind {
	return []saveKind{
		{"X509", "A.x509.key.pem", func(t *testing.T, s *Store, k *Key) error { return s.SaveX509("A", k) }},
		{"OpenPGP", "A.openpgp.key.asc", func(t *testing.T, s *Store, k *Key) error { return s.SaveOpenPGP("A", k, certFor(t, k)) }},
		{"Revocation", "A.revocation.compromised.asc", func(t *testing.T, s *Store, k *Key) error {
			return s.SaveRevocation("A", "compromised", revocationFor(t, k, openpgp.Compromised))
		}},
		{"Removal", "A.removal.jws", func(t *testing.T, s *Store, k *Key) error { return s.SaveRemoval("A", jwsOf("a", "b", "c")) }},
	}
}

var steps = []fsx.Step{fsx.StepCreate, fsx.StepWrite, fsx.StepSyncFile, fsx.StepRename, fsx.StepSyncDir}

func TestAWriteThatFailsAtAnyStepReturnsAnErrorAndLeavesTheStoreStopped(t *testing.T) {
	for _, kind := range saveKinds() {
		for _, step := range steps {
			t.Run(kind.name+" at "+string(step), func(t *testing.T) {
				s, _, keys := openStore(t)
				failAt(t, s, keys, step)
				rec := record(s)
				k := mustGenerate(t)
				err := kind.save(t, s, k)
				if err == nil {
					t.Fatal("the save succeeded")
				}
				if !errors.Is(err, errInjected) {
					t.Errorf("the error does not wrap the fault: %v", err)
				}
				if errors.Is(err, ErrKeyExists) {
					t.Errorf("the error says the file exists: %v", err)
				}
				if !strings.Contains(err.Error(), kind.final) {
					t.Errorf("the error does not name the file: %v", err)
				}
				if strings.Contains(err.Error(), keys) {
					t.Errorf("the error holds the key folder: %v", err)
				}
				if k.Saved() {
					t.Error("Saved is true")
				}
				names := dirNames(t, keys)
				final := false
				for _, n := range names {
					if n == kind.final {
						final = true
					} else if !strings.HasPrefix(n, fsx.TempPrefix) {
						t.Errorf("a stray name: %s", n)
					}
				}
				switch step {
				case fsx.StepSyncDir:
					// The rename was done: the whole file stands under its name, and the error says
					// that the folder was not flushed.
					if !final {
						t.Error("the folder flush failed after the rename, so the whole file should stand")
					}
				case fsx.StepCreate:
					if len(names) != 0 {
						t.Errorf("a create that failed left %v", names)
					}
				default:
					if final {
						t.Errorf("a stop before the rename left a file under its final name")
					}
					if len(names) != 1 {
						t.Errorf("a temporary file is expected to stay (nothing is deleted): %v", names)
					}
				}
				// No key comes out of the open that follows, unless the whole file stands.
				if !final {
					if _, err := s.OpenX509(bg(), "A"); err == nil && kind.name == "X509" {
						t.Error("a key came out of the open after a failed write")
					}
				}
				// The writer stopped: the next write returns the same first error and writes nothing.
				calls := rec.calls()
				other := mustGenerate(t)
				again := s.SaveX509("B", other)
				if again != err { //nolint:errorlint // the very same error value
					t.Errorf("the next save returns %v, want the first error itself", again)
				}
				if rec.calls() != calls {
					t.Errorf("the writer was called %d more times after the stop", rec.calls()-calls)
				}
				if other.Saved() {
					t.Error("a later key is Saved")
				}
			})
		}
	}
}

func TestAStoppedWriteInATestRootLeavesAPlainTemporaryFileAndTheKeyBytesAreNotInAnyOtherPlace(t *testing.T) {
	s, bundle, keys := openStore(t)
	tmp, work := t.TempDir(), t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Chdir(work)
	failAt(t, s, keys, fsx.StepSyncFile)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err == nil {
		t.Fatal("the save succeeded")
	}
	for _, dir := range []string{tmp, work, bundle} {
		for _, n := range dirNames(t, dir) {
			if dir == bundle && (n == "ritueel.yaml" || n == "history") {
				continue
			}
			t.Errorf("%s holds %s", filepath.Base(dir), n)
		}
	}
	var temps int
	for _, n := range dirNames(t, keys) {
		if strings.HasPrefix(n, fsx.TempPrefix) {
			temps++
			if got := readKeyFile(t, keys, n); !bytes.Equal(got, x509File(t, k)) {
				t.Error("the temporary file is not the whole file that was to be written")
			}
		}
	}
	if temps != 1 {
		t.Errorf("%d temporary files", temps)
	}
}

// A writer that says it wrote the file and left it other than it was written: the read back
// finds it, the Store says so, keeps the file and names it, and the key is not Saved (lesson 8).
func TestASaveThatDoesNotReadBackAsWrittenIsAnErrorThatNamesTheFileAndKeepsIt(t *testing.T) {
	type damage struct {
		name  string
		after func(t *testing.T, path string, data []byte)
	}
	damages := []damage{
		{"one byte of the file changed", func(t *testing.T, path string, data []byte) {
			d := bytes.Clone(data)
			d[len(d)/2] ^= 1
			if err := os.WriteFile(path, d, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"the file cut by one byte", func(t *testing.T, path string, data []byte) {
			if err := os.WriteFile(path, data[:len(data)-1], 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"a byte added to the file", func(t *testing.T, path string, data []byte) {
			if err := os.WriteFile(path, append(bytes.Clone(data), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"the file empty", func(t *testing.T, path string, _ []byte) {
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"the file gone", func(t *testing.T, path string, _ []byte) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}},
		{"the file turned into a folder", func(t *testing.T, path string, _ []byte) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, kind := range saveKinds() {
		for _, d := range damages {
			t.Run(kind.name+": "+d.name, func(t *testing.T) {
				s, _, keys := openStore(t)
				rec := record(s)
				k := mustGenerate(t)
				secrets := keysOf(t, k, certFor(t, k))
				s.w = damagingWriter{inner: rec, dir: keys, do: d.after, t: t}
				err := kind.save(t, s, k)
				if err == nil {
					t.Fatal("the save succeeded")
				}
				if !errors.Is(err, ErrKeyFile) && !errors.Is(err, ErrParams) {
					t.Errorf("the error is neither ErrKeyFile nor ErrParams: %v", err)
				}
				if !strings.Contains(err.Error(), kind.final) {
					t.Errorf("the error does not name the file: %v", err)
				}
				if k.Saved() {
					t.Error("Saved is true")
				}
				if f := secrets.findText(err.Error()); f != "" {
					t.Errorf("the error text holds a canary (%s)", f)
				}
				if d.name != "the file gone" && d.name != "the file turned into a folder" {
					if _, err := os.Stat(filepath.Join(keys, kind.final)); err != nil {
						t.Errorf("the file was deleted: %v", err)
					}
				}
			})
		}
	}
}

// damagingWriter writes through and then damages the file as the test says.
type damagingWriter struct {
	inner fileWriter
	dir   string
	do    func(t *testing.T, path string, data []byte)
	t     *testing.T
}

func (d damagingWriter) WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := d.inner.WriteFile(path, data, perm); err != nil {
		return err
	}
	d.do(d.t, filepath.Join(d.dir, path), data)
	return nil
}

func (d damagingWriter) Close() error { return d.inner.Close() }

// A writer that says it wrote and wrote nothing.
func TestAWriterThatWritesNothingIsFoundByTheReadBack(t *testing.T) {
	s, _, keys := openStore(t)
	s.w = &recWriter{}
	k := mustGenerate(t)
	err := s.SaveX509("A", k)
	if !errors.Is(err, ErrKeyFile) || !strings.Contains(err.Error(), "A.x509.key.pem") {
		t.Errorf("%v", err)
	}
	if k.Saved() || len(dirNames(t, keys)) != 0 {
		t.Error("Saved, or a file stands")
	}
}

func TestTheKeyThatIsReadBackMustBeTheKeyThatWasGiven(t *testing.T) {
	a, b := mustGenerate(t), mustGenerate(t)
	var privA, privB = a.s.priv, b.s.priv
	if err := sameKey(a.publicCopy(), privA); err != nil {
		t.Errorf("the same key is refused: %v", err)
	}
	if err := sameKey(a.publicCopy(), privB); !errors.Is(err, ErrKeyFile) {
		t.Errorf("another key is accepted: %v", err)
	}
	if err := sameKey(nil, privA); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a nil public key is accepted: %v", err)
	}
}

// What a failing save gives back is the same as what a refusal gives back: no key and no bytes.
func TestASaveWithAClosedKeyIsAnErrorAndMakesNoFile(t *testing.T) {
	for name, save := range map[string]func(s *Store, k *Key, cert []byte) error{
		"X509":    func(s *Store, k *Key, _ []byte) error { return s.SaveX509("A", k) },
		"OpenPGP": func(s *Store, k *Key, cert []byte) error { return s.SaveOpenPGP("A", k, cert) },
	} {
		s, _, keys := openStore(t)
		k := mustGenerate(t)
		cert := certFor(t, k)
		_ = k.Close()
		if err := save(s, k, cert); !errors.Is(err, ErrParams) {
			t.Errorf("%s: %v", name, err)
		}
		if len(dirNames(t, keys)) != 0 {
			t.Errorf("%s: a file was made", name)
		}
	}
	s, _, _ := openStore(t)
	var nilKey *Key
	if err := s.SaveX509("A", nilKey); !errors.Is(err, ErrParams) {
		t.Errorf("a nil key: %v", err)
	}
	if err := s.SaveX509("A", &Key{}); !errors.Is(err, ErrParams) {
		t.Errorf("a zero key: %v", err)
	}
	if err := s.SaveX509("A", &Key{s: &keyState{}}); !errors.Is(err, ErrParams) {
		t.Errorf("a key with no private half: %v", err)
	}
	if err := s.SaveX509("A", mustGenerate(t)); err != nil {
		t.Errorf("a good save after those refusals: %v", err)
	}
}

// A file larger than the limit is never written: the length is checked before the write.
func TestAFileThatWouldBeLongerThanTheLimitIsRefusedBeforeItIsWritten(t *testing.T) {
	s, _, keys := openStore(t)
	rec := record(s)
	// A payload over the limit reaches the write only through a format that grows it.
	s.format = growingFormat{inner: s.format, extra: MaxKeyFileSize}
	err := s.SaveRemoval("A", jwsOf("a", "b", "c"))
	if !errors.Is(err, ErrKeyFile) {
		t.Errorf("%v", err)
	}
	if rec.calls() != 0 || len(dirNames(t, keys)) != 0 {
		t.Error("a file over the limit was written")
	}
}

type growingFormat struct {
	inner format
	extra int
}

func (g growingFormat) wrap(kind FileKind, payload []byte) ([]byte, error) {
	b, err := g.inner.wrap(kind, payload)
	return append(b, bytes.Repeat([]byte("\n"), g.extra)...), err
}

func (g growingFormat) unwrap(kind FileKind, file []byte) ([]byte, error) {
	return g.inner.unwrap(kind, file)
}
