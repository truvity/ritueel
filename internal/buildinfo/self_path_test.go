//go:build linux || darwin

package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The digest of the program looks at the path before it opens it: a path that is not a regular file
// is refused at once, by a look that opens nothing, because the open of a FIFO with no writer waits
// (the comment of fileDigest). The names of this file start with sp.

// spWatch is how long a call may take before a test says that it waits.
const spWatch = 2 * time.Second

type spResult struct {
	sum string
	err error
}

// spDigest runs fileDigest on path and fails the test when it does not return within spWatch. A call
// that waits is left behind; the cleanup of the test frees a FIFO that it waits on.
func spDigest(t *testing.T, path string, unblock func()) spResult {
	t.Helper()
	done := make(chan spResult, 1)
	go func() {
		sum, err := fileDigest(path)
		done <- spResult{sum, err}
	}()
	select {
	case r := <-done:
		return r
	case <-time.After(spWatch):
		if unblock != nil {
			unblock()
		}
		t.Fatalf("fileDigest(%q) did not return within %v: it waits to open a path that is not a regular file", path, spWatch)
		return spResult{}
	}
}

func spRefused(t *testing.T, r spResult, words string) {
	t.Helper()
	if r.err == nil || r.sum != "" {
		t.Fatalf("fileDigest = %q, %v; want an error and no digest", r.sum, r.err)
	}
	if !strings.HasPrefix(r.err.Error(), "buildinfo:") {
		t.Errorf("the error does not say where it comes from: %v", r.err)
	}
	if words != "" && !strings.Contains(r.err.Error(), words) {
		t.Errorf("the error %q does not say %q", r.err, words)
	}
}

// spFIFO makes a FIFO and returns its path and a function that opens it for reading and writing, which
// frees an open that waits for a writer.
func spFIFO(t *testing.T, dir, name string) (string, func()) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	free := func() {
		if f, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
			_ = f.Close()
		}
	}
	t.Cleanup(free)
	return path, free
}

func TestFileDigestRefusesAFIFOWithNoWriterAtOnce(t *testing.T) {
	path, free := spFIFO(t, t.TempDir(), "fifo")
	spRefused(t, spDigest(t, path, free), "not a regular file")
}

func TestFileDigestRefusesAFIFOThatAWriterHoldsOpenToo(t *testing.T) {
	path, _ := spFIFO(t, t.TempDir(), "fifo")
	hold, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Close() }()
	spRefused(t, spDigest(t, path, nil), "not a regular file")
}

func TestFileDigestRefusesAFolderAtOnce(t *testing.T) {
	dir := t.TempDir()
	spRefused(t, spDigest(t, dir, nil), "not a regular file")
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	spRefused(t, spDigest(t, sub, nil), "not a regular file")
}

func TestFileDigestRefusesADeviceAtOnce(t *testing.T) {
	// /dev/zero never ends and /dev/null is empty: a read that is not refused first would run for ever
	// or give the digest of nothing.
	for _, path := range []string{"/dev/zero", "/dev/null", "/dev/urandom"} {
		t.Run(path, func(t *testing.T) {
			if _, err := os.Stat(path); err != nil {
				t.Skipf("%s is not on this system", path)
			}
			spRefused(t, spDigest(t, path, nil), "not a regular file")
		})
	}
}

func TestFileDigestRefusesASocketAtOnce(t *testing.T) {
	// A path of a socket is short: a folder under /tmp holds it, whatever the temporary folder is.
	dir, err := os.MkdirTemp("", "sk") //nolint:usetesting // the path of a socket is at most about 100 bytes, and the folder of a test is longer
	if err != nil {
		t.Skip("no folder for a socket")
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("no socket here: %v", err)
	}
	defer func() { _ = l.Close() }()
	spRefused(t, spDigest(t, path, nil), "not a regular file")
}

func TestFileDigestFollowsALinkToARegularFileAndRefusesALinkToWhatIsNot(t *testing.T) {
	dir := t.TempDir()
	content := []byte("the program")
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	want := hex.EncodeToString(sum[:])

	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	r := spDigest(t, link, nil)
	if r.err != nil || r.sum != want {
		t.Errorf("fileDigest of a link to a regular file = %q, %v; want %s", r.sum, r.err, want)
	}
	// os.Executable can give a path through a link, so a link to the file is the file.
	chain := filepath.Join(dir, "chain")
	if err := os.Symlink(link, chain); err != nil {
		t.Fatal(err)
	}
	if r := spDigest(t, chain, nil); r.err != nil || r.sum != want {
		t.Errorf("fileDigest of a link to a link = %q, %v", r.sum, r.err)
	}

	fifo, free := spFIFO(t, dir, "fifo")
	toFIFO := filepath.Join(dir, "to-fifo")
	if err := os.Symlink(fifo, toFIFO); err != nil {
		t.Fatal(err)
	}
	spRefused(t, spDigest(t, toFIFO, free), "not a regular file")

	toDir := filepath.Join(dir, "to-dir")
	if err := os.Symlink(dir, toDir); err != nil {
		t.Fatal(err)
	}
	spRefused(t, spDigest(t, toDir, nil), "not a regular file")

	if _, err := os.Stat("/dev/zero"); err == nil {
		toDev := filepath.Join(dir, "to-dev")
		if err := os.Symlink("/dev/zero", toDev); err != nil {
			t.Fatal(err)
		}
		spRefused(t, spDigest(t, toDev, nil), "not a regular file")
	}

	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nothing"), dangling); err != nil {
		t.Fatal(err)
	}
	spRefused(t, spDigest(t, dangling, nil), "")
}

func TestFileDigestRefusesAPathThatIsNoPath(t *testing.T) {
	for name, path := range map[string]string{
		"empty":         "",
		"a NUL":         "a\x00b",
		"missing":       filepath.Join(t.TempDir(), "nothing"),
		"under a file":  "",
		"a long name":   filepath.Join(t.TempDir(), strings.Repeat("a", 5000)),
		"a missing dir": filepath.Join(t.TempDir(), "nothing", "file"),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "under a file" {
				f := filepath.Join(t.TempDir(), "f")
				if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(f, "g")
			}
			spRefused(t, spDigest(t, path, nil), "")
		})
	}
}

func TestFileDigestOfARegularFileIsNotChangedByTheLookBeforeTheOpen(t *testing.T) {
	// A regular file of any mode that can be read gives the digest, whether it is empty, small or
	// longer than a piece of the stream.
	dir := t.TempDir()
	for name, size := range map[string]int{"empty": 0, "one": 1, "a piece": 4096, "a piece and one": 4097, "a megabyte": 1 << 20} {
		path := filepath.Join(dir, name)
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i * 7)
		}
		if err := os.WriteFile(path, data, 0o400); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		r := spDigest(t, path, nil)
		if r.err != nil || r.sum != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: fileDigest = %q, %v", name, r.sum, r.err)
		}
	}
}

func TestSelfStillDescribesTheTestProgramAfterTheLook(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := Self()
	if err != nil {
		t.Fatalf("Self: %v", err)
	}
	if want := streamedDigest(t, exe); p.SHA256 != want {
		t.Errorf("the digest = %s, want %s", p.SHA256, want)
	}
}

// The comment of fileDigest and of Self says what the function does: the path is looked at before it
// is opened, a path that is not a regular file is refused, and why.
func TestTheCommentsSayThatThePathIsLookedAtBeforeItIsOpened(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "self.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	docs := map[string]string{}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			docs[fd.Name.Name] = strings.Join(strings.Fields(fd.Doc.Text()), " ")
		}
	}
	for name, words := range map[string][]string{
		"fileDigest": {"regular file", "FIFO", "before", "open"},
		"Self":       {"regular file", "before", "opened"},
	} {
		doc, ok := docs[name]
		if !ok || doc == "" {
			t.Errorf("%s has no doc", name)
			continue
		}
		for _, w := range words {
			if !strings.Contains(doc, w) {
				t.Errorf("the doc of %s does not say %q: %s", name, w, doc)
			}
		}
	}
}
