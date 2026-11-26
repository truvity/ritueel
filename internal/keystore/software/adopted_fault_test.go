package software

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/openpgp"
)

// The faults of SaveAdopted, with the seams that the other saves are tested with: a write that fails
// at each step, a disk that is full, a file that does not read back as written. In each: what the
// error names, what is left in the folder, and that the export of the caller is as it was.

const adFinal = "A.openpgp.key.age"

// adExportUntouched checks that the export still gives the packet that it gave.
func adExportUntouched(t testing.TB, fk *openpgp.ForeignKey, pass []byte, want []byte) {
	t.Helper()
	if fk.Wiped() {
		t.Errorf("the export was wiped")
	}
	got, err := fk.SecretPacket(pass)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("the export does not give the same packet any more: %v", err)
	}
	clear(got)
}

func TestASaveOfAnAdoptedKeyThatFailsAtAnyStepLeavesWhatTheOtherSavesLeave(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "p384")
	for _, protected := range []bool{false, true} {
		for _, step := range steps {
			t.Run(string(step)+map[bool]string{false: "", true: " with a protected export"}[protected], func(t *testing.T) {
				fk := b.foreign(t, importPassOf(protected))
				pkt, err := fk.SecretPacket(passOf(importPassOf(protected)))
				if err != nil {
					t.Fatal(err)
				}
				src := adoptedSource(importPassOf(protected))
				s, _, keys := openPassStore(t, src)
				failAt(t, s, keys, step)
				rec := record(s)
				err = s.SaveAdopted(bg(), "A", fk)
				if err == nil {
					t.Fatal("the save succeeded")
				}
				if !errors.Is(err, errInjected) || errors.Is(err, ErrKeyExists) {
					t.Errorf("the error does not wrap the fault, or says that the file exists: %v", err)
				}
				if !strings.Contains(err.Error(), adFinal) || strings.Contains(err.Error(), keys) {
					t.Errorf("the error does not name the file, or holds the folder: %v", err)
				}
				for _, w := range adSecretWords(pkt) {
					if strings.Contains(err.Error(), w) {
						t.Errorf("the error holds a secret or a passphrase: %v", err)
					}
				}
				names := dirNames(t, keys)
				final := false
				for _, n := range names {
					if n == adFinal {
						final = true
					} else if !strings.HasPrefix(n, fsx.TempPrefix) {
						t.Errorf("a stray name: %s", n)
					}
				}
				switch step {
				case fsx.StepSyncDir:
					if !final {
						t.Errorf("the rename was done and the whole file should stand")
					}
				case fsx.StepCreate:
					if len(names) != 0 || strings.Contains(err.Error(), "may hold the key") {
						t.Errorf("a create that failed left %v: %v", names, err)
					}
				default:
					if final || len(names) != 1 {
						t.Errorf("the folder holds %v, want one temporary file", names)
					}
					if !strings.Contains(err.Error(), "may hold the key: remove it") {
						t.Errorf("the error does not say that the temporary file may hold the key: %v", err)
					}
					// what stays is not the key in the clear
					if got := readKeyFile(t, keys, names[0]); bytes.Contains(got, pkt[len(pkt)-40:]) {
						t.Errorf("the temporary file holds the end of the packet in the clear")
					}
				}
				if step == fsx.StepSyncDir {
					// the file stands whole, and it opens as the key
					src2 := newPassSource(testPass)
					s.source = src2
					k, err := s.OpenAdopted(bg(), "A", expectOf(fk))
					if err != nil {
						t.Fatalf("the file that stands does not open: %v", err)
					}
					_ = k.Close()
				}
				// the writer stopped: the next save writes nothing and asks nothing
				asked, calls := src.calls(), rec.calls()
				again := s.SaveAdopted(bg(), "B", fk)
				if again != err { //nolint:errorlint // the very same error value
					t.Errorf("the next save returns %v, want the first error itself", again)
				}
				if src.calls() != asked || rec.calls() != calls {
					t.Errorf("a save after the stop asked or wrote")
				}
				adExportUntouched(t, fk, passOf(importPassOf(protected)), pkt)
			})
		}
	}
}

// fullFS is a folder whose files take half of a write and say that the disk is full.
type fullFS struct{ fsx.FS }

func (f fullFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	file, err := f.FS.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}
	return fullFile{File: file}, nil
}

type fullFile struct{ fsx.File }

func (f fullFile) Write(p []byte) (int, error) {
	n, _ := f.File.Write(p[:len(p)/2])
	return n, &fs.PathError{Op: "write", Path: "key", Err: syscall.ENOSPC}
}

func TestASaveOfAnAdoptedKeyOnAFullDiskNamesTheFileAndLeavesTheKeyAlone(t *testing.T) {
	lowWork(t)
	fk := adoptedNamed(t, "ed25519").foreign(t, exportPass)
	pkt, err := fk.SecretPacket([]byte(exportPass))
	if err != nil {
		t.Fatal(err)
	}
	src := adoptedSource(exportPass)
	s, _, keys := openPassStore(t, src)
	real, err := fsx.OpenFS(keys)
	if err != nil {
		t.Fatal(err)
	}
	w := &fsx.Writer{FS: fullFS{FS: real}}
	t.Cleanup(func() { _ = w.Close() })
	s.w = w
	first := s.SaveAdopted(bg(), "A", fk)
	err = first
	if !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("the error does not say that the disk is full: %v", err)
	}
	if !strings.Contains(err.Error(), "was not written whole") || !strings.Contains(err.Error(), adFinal) || !strings.Contains(err.Error(), "may hold the key: remove it") {
		t.Errorf("the error does not say what stands: %v", err)
	}
	names := dirNames(t, keys)
	if len(names) != 1 || !strings.HasPrefix(names[0], fsx.TempPrefix) {
		t.Fatalf("the folder holds %v, want the one temporary file", names)
	}
	part := readKeyFile(t, keys, names[0])
	whole, err := adAge.wrapWith([]byte(testPass), FileOpenPGP, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if len(part) == 0 || len(part) >= len(whole) {
		t.Errorf("the temporary file holds %d bytes, a whole file is about %d", len(part), len(whole))
	}
	// nothing opens from what is left, and a second save is stopped
	if _, err := os.Stat(filepath.Join(keys, adFinal)); err == nil {
		t.Errorf("a file stands under its name")
	}
	if again := s.SaveAdopted(bg(), "A", fk); again != first { //nolint:errorlint // the very same error value
		t.Errorf("the next save returns %v, want the first error itself", again)
	}
	adExportUntouched(t, fk, []byte(exportPass), pkt)
	adAllZero(t, "a full disk", src)
}

func TestASaveOfAnAdoptedKeyThatDoesNotReadBackAsWrittenSaysSoAndKeepsTheFile(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "p384")
	damages := []struct {
		name  string
		after func(t *testing.T, path string, data []byte)
		keeps bool
	}{
		{"one byte of the file changed", func(t *testing.T, path string, data []byte) {
			d := bytes.Clone(data)
			d[len(d)/2] ^= 1
			must(t, os.WriteFile(path, d, 0o600))
		}, true},
		{"the file cut by one byte", func(t *testing.T, path string, data []byte) {
			must(t, os.WriteFile(path, data[:len(data)-1], 0o600))
		}, true},
		{"a byte added", func(t *testing.T, path string, data []byte) {
			must(t, os.WriteFile(path, append(bytes.Clone(data), '\n'), 0o600))
		}, true},
		{"the file empty", func(t *testing.T, path string, _ []byte) { must(t, os.WriteFile(path, nil, 0o600)) }, true},
		{"the file gone", func(t *testing.T, path string, _ []byte) { must(t, os.Remove(path)) }, false},
		{"the file turned into a folder", func(t *testing.T, path string, _ []byte) {
			must(t, os.Remove(path))
			must(t, os.Mkdir(path, 0o700))
		}, false},
	}
	for _, d := range damages {
		t.Run(d.name, func(t *testing.T) {
			fk := b.foreign(t, exportPass)
			pkt, err := fk.SecretPacket([]byte(exportPass))
			if err != nil {
				t.Fatal(err)
			}
			src := adoptedSource(exportPass)
			s, _, keys := openPassStore(t, src)
			s.w = damagingWriter{inner: s.w, dir: keys, do: d.after, t: t}
			err = s.SaveAdopted(bg(), "A", fk)
			wantRefusal(t, err, ErrKeyFile, "key-file", adSecretWords(pkt)...)
			if !strings.Contains(err.Error(), adFinal) {
				t.Errorf("the error does not name the file: %v", err)
			}
			if d.keeps {
				if _, err := os.Stat(filepath.Join(keys, adFinal)); err != nil {
					t.Errorf("the file was deleted: %v", err)
				}
			}
			if got := src.purposes(); len(got) != 2 {
				t.Errorf("the source was asked %v", got)
			}
			adExportUntouched(t, fk, []byte(exportPass), pkt)
			adAllZero(t, d.name, src)
		})
	}
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestASaveOfAnAdoptedKeyWhoseFileReadsBackAsAnotherPayloadIsNotGood(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "ed25519")
	fk := b.foreign(t, "")
	pkt, err := fk.SecretPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	born := mustGenerate(t)
	var bornSecret []byte
	cert := certFor(t, born)
	if err := born.withPrivate(func(priv *ecdsa.PrivateKey) (err error) {
		bornSecret, err = openpgp.SecretKey(cert, priv)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"the packet and a byte":      append(bytes.Clone(pkt), 0),
		"the packet cut by one byte": pkt[:len(pkt)-1],
		"the packet twice":           append(bytes.Clone(pkt), pkt...),
		"the first byte changed":     append([]byte{pkt[0] ^ 1}, pkt[1:]...),
		"a checksum that is wrong":   append(bytes.Clone(pkt[:len(pkt)-1]), pkt[len(pkt)-1]^1),
		"a key that ritueel made":    bornSecret,
		"nothing but a byte":         {0},
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			s, _, keys := openPassStore(t, adoptedSource(""))
			s.format = swapPayload{inner: ageFormat{}, payload: payload}
			err := s.SaveAdopted(bg(), "A", fk)
			wantRefusal(t, err, ErrKeyFile, "key-file", adSecretWords(pkt)...)
			for _, w := range []string{adFinal, "was written", "failed its check"} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the text does not say %q: %v", w, err)
				}
			}
			if names := dirNames(t, keys); len(names) != 1 || names[0] != adFinal {
				t.Errorf("the file is not left where it is: %v", names)
			}
		})
	}
}
