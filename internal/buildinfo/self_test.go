//go:build linux || darwin

package buildinfo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// Self describes the program that runs: the member "ritueel" of a plan (docs/reference/
// ceremony-record.md, "The plan"). The digest is the SHA-256 of the program's own file, in 64
// lower-case hexadecimal digits, read as a stream.

var selfDigestForm = regexp.MustCompile(`^[0-9a-f]{64}$`)

// streamedDigest is the SHA-256 of a file, made here by reading it in pieces of 4 KiB, so that it
// is not made by the code under test and not by a read of the whole file.
func streamedDigest(t testing.TB, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		h.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestSelfIsTheDigestOfTheFileOfTheRunningProgram(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Self()
	if err != nil {
		t.Fatalf("Self: %v", err)
	}
	if !selfDigestForm.MatchString(p.SHA256) {
		t.Errorf("the digest %q is not 64 lower-case hexadecimal digits", p.SHA256)
	}
	if want := streamedDigest(t, exe); p.SHA256 != want {
		t.Errorf("the digest of the program = %s, want %s", p.SHA256, want)
	}
	if want := Read().Version; p.Version != want {
		t.Errorf("version = %q, want the version that Read gives, %q", p.Version, want)
	}
	if want := runtime.GOOS + "/" + runtime.GOARCH; p.OSArch != want {
		t.Errorf("os_arch = %q, want %q", p.OSArch, want)
	}
}

func TestSelfGivesTheSameProgramTwice(t *testing.T) {
	a, err := Self()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Self()
	if err != nil || a != b {
		t.Errorf("Self = %+v then %+v (%v)", a, b, err)
	}
}

func TestProgramIsWrittenWithTheMembersOfThePlan(t *testing.T) {
	p := Program{Version: "v1.2.3", OSArch: "linux/amd64", SHA256: strings.Repeat("ab", 32)}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"v1.2.3","os_arch":"linux/amd64","sha256":"` + strings.Repeat("ab", 32) + `"}`
	if string(b) != want {
		t.Errorf("Program = %s, want %s", b, want)
	}
	var back map[string]any
	if err := json.Unmarshal(b, &back); err != nil || len(back) != 3 {
		t.Errorf("Program has %d members: %v %v", len(back), back, err)
	}
}

func TestFileDigestOfAFileLargerThanTheReadersOfABundleAccept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	const size = 9 << 20
	if err := f.Truncate(size); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := fileDigest(path)
	if err != nil {
		t.Fatalf("fileDigest of 9 MiB: %v", err)
	}
	h := sha256.New()
	if _, err := io.CopyN(h, zeros{}, size); err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("fileDigest = %s, want %s", got, want)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestFileDigestOfEmptyAndOfKnownFiles(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"empty": "", "abc": "abc", "line": "a\n"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		got, err := fileDigest(path)
		if err != nil || got != hex.EncodeToString(sum[:]) {
			t.Errorf("fileDigest(%q) = %q, %v", name, got, err)
		}
	}
	// Two well-known values, so that the test does not stand on the same function twice.
	for content, want := range map[string]string{
		"":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	} {
		path := filepath.Join(dir, "k"+content)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := fileDigest(path); err != nil || got != want {
			t.Errorf("fileDigest of %q = %q, %v; want %s", content, got, err, want)
		}
	}
}

func TestFileDigestRefusesWhatIsNotAFileThatCanBeRead(t *testing.T) {
	dir := t.TempDir()
	t.Run("missing", func(t *testing.T) {
		got, err := fileDigest(filepath.Join(dir, "nothing"))
		if err == nil || got != "" {
			t.Errorf("fileDigest = %q, %v", got, err)
		}
	})
	t.Run("a folder", func(t *testing.T) {
		got, err := fileDigest(dir)
		if err == nil || got != "" || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("fileDigest = %q, %v", got, err)
		}
	})
	t.Run("a FIFO that is open at both ends", func(t *testing.T) {
		// The test opens the FIFO for reading and writing first, so that no open waits.
		path := filepath.Join(dir, "fifo")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		hold, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = hold.Close() }()
		got, err := fileDigest(path)
		if err == nil || got != "" || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("fileDigest = %q, %v", got, err)
		}
	})
	t.Run("a file that cannot be opened", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("the owner of the process reads any file")
		}
		path := filepath.Join(dir, "locked")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0); err != nil {
			t.Fatal(err)
		}
		got, err := fileDigest(path)
		if err == nil || got != "" {
			t.Errorf("fileDigest = %q, %v", got, err)
		}
	})
	t.Run("the error holds the cause", func(t *testing.T) {
		_, err := fileDigest(filepath.Join(dir, "nothing"))
		if err == nil || !bytes.Contains([]byte(err.Error()), []byte("buildinfo:")) {
			t.Errorf("the error does not say where it comes from: %v", err)
		}
	})
}
