package handoff_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
)

// diskRoot writes the files (path to content) into a new folder and returns it opened as the root that
// LoadRequest takes, with the path of the folder. A path with a folder in it makes the folder.
func diskRoot(t testing.TB, files map[string][]byte) (fsx.FS, string) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return openRoot(t, dir), dir
}

// openRoot opens a folder as the root of a load.
func openRoot(t testing.TB, dir string) fsx.FS {
	t.Helper()
	root, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatalf("opening the root folder: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// strs makes the files of diskRoot from text.
func strs(files map[string]string) map[string][]byte {
	out := map[string][]byte{}
	for k, v := range files {
		out[k] = []byte(v)
	}
	return out
}

// loadWithin runs LoadRequest and fails the test when it does not return in time: a pipe in the place of
// a file must not make the call wait.
func loadWithin(t testing.TB, root fsx.FS, dir, stem string) (*handoff.Request, error) {
	t.Helper()
	type result struct {
		r   *handoff.Request
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := handoff.LoadRequest(root, dir, stem)
		done <- result{r, err}
	}()
	select {
	case res := <-done:
		return res.r, res.err
	case <-time.After(10 * time.Second):
		t.Fatal("LoadRequest did not return: it waits on a file that is not a regular file")
		return nil, nil
	}
}

func TestTheFilesOfARequestAreReadByTheirSuffix(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{
		"requests/a/a.proof.json": "P",
		"requests/a/a.csr.pem":    "C",
		"requests/a/a.subkey.pgp": "K",
		"requests/a/a.sshca.pub":  "S",
		"requests/a/a.sshca.sig":  "G",
	}))
	r, err := handoff.LoadRequest(root, "requests/a", "a")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		handoff.FileProof: "P", handoff.FileCSR: "C", handoff.FileSubkey: "K", handoff.FileSSHKey: "S", handoff.FileSSHSig: "G",
	}
	if r.Stem != "a" || len(r.Files) != len(want) {
		t.Fatalf("stem %q, files %d", r.Stem, len(r.Files))
	}
	for suffix, data := range want {
		if string(r.Files[suffix]) != data {
			t.Errorf("%s holds %q, want %q", suffix, r.Files[suffix], data)
		}
	}
}

func TestOnlyTheFilesThatThereAreAreInTheRequest(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"d/x.proof.json": "P", "d/x.csr.pem": "C"}))
	r, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 2 {
		t.Errorf("files %v", r.Files)
	}
	for _, absent := range []string{handoff.FileSubkey, handoff.FileSSHKey, handoff.FileSSHSig} {
		if _, ok := r.Files[absent]; ok {
			t.Errorf("%s is in the request but not in the folder", absent)
		}
	}
}

func TestAFolderOfTheRootIsAValidFolder(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"x.proof.json": "P"}))
	r, err := handoff.LoadRequest(root, ".", "x")
	if err != nil || string(r.Files[handoff.FileProof]) != "P" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestAMissingProofFileIsAnErrorOfTheCallerAndNotAVerdict(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"d/x.csr.pem": "C"}))
	r, err := handoff.LoadRequest(root, "d", "x")
	if !errors.Is(err, handoff.ErrNoProof) || r != nil {
		t.Fatalf("request %v, error %v, want ErrNoProof", r, err)
	}
	if errors.Is(err, handoff.ErrLoad) {
		t.Error("a missing proof file is its own error")
	}
	// A folder that is not there at all is the same: there is no proof.
	for _, dir := range []string{"nowhere", "d/nowhere", "nowhere/a/b"} {
		_, err = handoff.LoadRequest(root, dir, "x")
		if !errors.Is(err, handoff.ErrNoProof) {
			t.Errorf("the folder %q: error %v", dir, err)
		}
	}
}

func TestFilesOfOtherNamesAndTheFilesOfAnAnswerAreNeverRead(t *testing.T) {
	// Each of these is a folder where a file would be: reading one would be an error, so the test also
	// shows that no name outside the five is opened.
	files := map[string]string{"d/x.proof.json": "P"}
	for _, name := range []string{
		"d/x.result.json/f", "d/x.cert.pem/f", "d/x.bound.pgp/f", "d/y.proof.json/f", "d/x.csr.pem.bak/f",
		"d/x.proof.json.old/f", "d/x.kms-stub.json/f", "d/other/f", "d/X.csr.pem/f", "d/x.CSR.PEM/f",
	} {
		files[name] = "z"
	}
	root, _ := diskRoot(t, strs(files))
	r, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files) != 1 {
		t.Errorf("files %v", r.Files)
	}
}

func TestAFileLongerThanTheLimitComesBackCutOneByteOverAndIsNotAnError(t *testing.T) {
	big := strings.Repeat("a", handoff.MaxFileSize+100)
	root, _ := diskRoot(t, strs(map[string]string{"d/x.proof.json": "P", "d/x.csr.pem": big}))
	r, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Files[handoff.FileCSR]); got != handoff.MaxFileSize+1 {
		t.Errorf("%d bytes, want the limit and one more", got)
	}
	// The request is then a verdict of the checks, and not an acceptance.
	v, err := newChecker(t).Check(t.Context(), r)
	if err != nil || v.Accepted() {
		t.Errorf("code %q, error %v, accepted %v", v.Code, err, v.Accepted())
	}
}

func TestAFileOfFiveMebibytesComesBackCutAtTheLimitAndOneByte(t *testing.T) {
	root, _ := diskRoot(t, map[string][]byte{"d/x.proof.json": []byte("P"), "d/x.csr.pem": bytes.Repeat([]byte("a"), 5<<20)})
	r, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Files[handoff.FileCSR]); got != handoff.MaxFileSize+1 {
		t.Errorf("%d bytes, want %d", got, handoff.MaxFileSize+1)
	}
}

// The page, "The request": a file larger than 256 KiB "is refused before it is read". A file that the
// reader of folders will not read at all (over its own limit) is given the same answer: the request is
// refused as malformed, and the load is not an error.
func TestAFileOfNineMebibytesIsNeverAnAcceptedRequest(t *testing.T) {
	root, dir := diskRoot(t, strs(map[string]string{"d/x.proof.json": "P"}))
	f, err := os.Create(filepath.Join(dir, "d", "x.csr.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(9 << 20); err != nil { // a sparse file: it takes no room
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := loadWithin(t, root, "d", "x")
	if err != nil {
		t.Fatalf("a file of 9 MiB is an error of the load: %v", err)
	}
	v, err := newChecker(t).Check(t.Context(), r)
	if err != nil || v.Code != handoff.CodeMalformed || v.Accepted() {
		t.Errorf("a file of 9 MiB: code %q, error %v, want malformed", v.Code, err)
	}
	// The same answer as for a file of 300 KiB, which is over the limit of a request and under the reader's.
	root, _ = diskRoot(t, map[string][]byte{"d/x.proof.json": []byte("P"), "d/x.csr.pem": bytes.Repeat([]byte("a"), 300<<10)})
	r, err = handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	small, err := newChecker(t).Check(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if small.Code != v.Code || small.Detail != v.Detail || statuses(small) != statuses(v) {
		t.Errorf("9 MiB: %q %q %s; 300 KiB: %q %q %s", v.Code, v.Detail, statuses(v), small.Code, small.Detail, statuses(small))
	}
}

func TestAFileOfExactlyTheLimitComesBackWhole(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"d/x.proof.json": strings.Repeat("a", handoff.MaxFileSize)}))
	r, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Files[handoff.FileProof]); got != handoff.MaxFileSize {
		t.Errorf("%d bytes", got)
	}
}

func TestAnEmptyFileComesBackEmptyAndIsNotMissing(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"d/x.proof.json": "", "d/x.csr.pem": ""}))
	r, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := r.Files[handoff.FileCSR]; !ok || len(v) != 0 {
		t.Errorf("csr %v %v", v, ok)
	}
}

// Links, pipes and what is not a file, on a real folder. fsx walks the path one element at a time and opens
// each without following a link, and does not wait on a pipe.

var requestSuffixes = []string{handoff.FileProof, handoff.FileCSR, handoff.FileSubkey, handoff.FileSSHKey, handoff.FileSSHSig}

// requestLayout is a folder with a good request in requests/x, a folder "outside" with another, and a
// file "secret" that no load may return.
func requestLayout(t testing.TB) (root fsx.FS, dir string) {
	t.Helper()
	return diskRoot(t, strs(map[string]string{
		"requests/x/x.proof.json": "P",
		"requests/x/x.csr.pem":    "C",
		"outside/x.proof.json":    "OUTSIDE",
		"outside/x.csr.pem":       "OUTSIDE",
		"secret":                  "SECRET",
	}))
}

func link(t testing.TB, target, name string) {
	t.Helper()
	if err := os.Symlink(target, name); err != nil {
		t.Skipf("no links here: %v", err)
	}
}

func wantLoadError(t testing.TB, r *handoff.Request, err error) {
	t.Helper()
	if !errors.Is(err, handoff.ErrLoad) {
		t.Fatalf("error %v, want ErrLoad (request %v)", err, r)
	}
	if errors.Is(err, handoff.ErrNoProof) {
		t.Fatalf("a path that is there is not a missing proof: %v", err)
	}
	if r != nil {
		t.Fatalf("a request beside the error: %v", r.Files)
	}
}

func TestALinkInThePlaceOfAFileIsNotFollowed(t *testing.T) {
	for _, suffix := range requestSuffixes {
		t.Run(suffix, func(t *testing.T) {
			root, dir := requestLayout(t)
			name := filepath.Join(dir, "requests", "x", "x."+suffix)
			_ = os.Remove(name)
			link(t, filepath.Join(dir, "secret"), name)
			r, err := loadWithin(t, root, "requests/x", "x")
			wantLoadError(t, r, err)
		})
	}
}

func TestALinkThatPointsNowhereOrToItselfIsNotFollowedAndIsNotAMissingFile(t *testing.T) {
	for name, target := range map[string]string{"a dangling link": "nowhere", "a link to itself": "x.proof.json", "a link to a folder": "../../outside"} {
		t.Run(name, func(t *testing.T) {
			root, dir := requestLayout(t)
			p := filepath.Join(dir, "requests", "x", "x.proof.json")
			_ = os.Remove(p)
			link(t, target, p)
			r, err := loadWithin(t, root, "requests/x", "x")
			wantLoadError(t, r, err)
		})
	}
	// The same for an optional file: a link is an error, and not "the file is not there".
	root, dir := requestLayout(t)
	link(t, "nowhere", filepath.Join(dir, "requests", "x", "x.subkey.pgp"))
	r, err := loadWithin(t, root, "requests/x", "x")
	wantLoadError(t, r, err)
}

func TestALinkAtAnyElementOfTheFolderIsNotFollowed(t *testing.T) {
	for name, tc := range map[string]struct {
		dir   string // the folder asked for
		build func(t *testing.T, dir string)
	}{
		"the last folder": {"requests/x", func(t *testing.T, dir string) {
			mustRemoveAll(t, filepath.Join(dir, "requests", "x"))
			link(t, filepath.Join(dir, "outside"), filepath.Join(dir, "requests", "x"))
		}},
		"the first folder": {"requests/x", func(t *testing.T, dir string) {
			mustRename(t, filepath.Join(dir, "requests"), filepath.Join(dir, "real"))
			link(t, filepath.Join(dir, "real"), filepath.Join(dir, "requests"))
		}},
		"a folder in the middle": {"a/b/c", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "a"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "real", "c"), 0o700); err != nil {
				t.Fatal(err)
			}
			mustWrite(t, filepath.Join(dir, "real", "c", "x.proof.json"), "P")
			link(t, filepath.Join(dir, "real"), filepath.Join(dir, "a", "b"))
		}},
		"a link that points to the folder next to it": {"requests/y", func(t *testing.T, dir string) {
			link(t, "x", filepath.Join(dir, "requests", "y"))
		}},
		"a link to a folder that holds the same link": {"requests/x", func(t *testing.T, dir string) {
			mustRemoveAll(t, filepath.Join(dir, "requests", "x"))
			link(t, ".", filepath.Join(dir, "requests", "x"))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			root, dir := requestLayout(t)
			tc.build(t, dir)
			r, err := loadWithin(t, root, tc.dir, "x")
			if r != nil {
				t.Fatalf("the files of a path with a link on it were read: %v", r.Files)
			}
			if !errors.Is(err, handoff.ErrLoad) {
				t.Fatalf("error %v, want ErrLoad", err)
			}
		})
	}
}

func TestAFolderThatIsAFileIsAnErrorAndNotAMissingProof(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"requests": "a file", "d/x.proof.json": "P", "d/e": "a file"}))
	for _, dir := range []string{"requests", "requests/x", "d/e", "d/e/f"} {
		r, err := loadWithin(t, root, dir, "x")
		if r != nil || err == nil {
			t.Errorf("the folder %q: request %v, error %v", dir, r, err)
		}
		if errors.Is(err, handoff.ErrNoProof) && dir != "d/e/f" && dir != "requests/x" {
			t.Errorf("the folder %q is a file, which is not a missing proof: %v", dir, err)
		}
	}
}

func TestAPipeInThePlaceOfAFileDoesNotMakeTheCallWait(t *testing.T) {
	for _, suffix := range requestSuffixes {
		t.Run(suffix, func(t *testing.T) {
			root, dir := requestLayout(t)
			name := filepath.Join(dir, "requests", "x", "x."+suffix)
			_ = os.Remove(name)
			if err := syscall.Mkfifo(name, 0o600); err != nil {
				t.Skipf("no pipes here: %v", err)
			}
			r, err := loadWithin(t, root, "requests/x", "x")
			wantLoadError(t, r, err)
		})
	}
}

func TestASocketInThePlaceOfAFileIsAnError(t *testing.T) {
	for _, suffix := range requestSuffixes {
		t.Run(suffix, func(t *testing.T) {
			root, dir := requestLayout(t)
			name := filepath.Join(dir, "requests", "x", "x."+suffix)
			_ = os.Remove(name)
			if err := syscall.Mknod(name, syscall.S_IFSOCK|0o600, 0); err != nil {
				t.Skipf("no sockets here: %v", err)
			}
			r, err := loadWithin(t, root, "requests/x", "x")
			wantLoadError(t, r, err)
		})
	}
}

func TestAFolderWhereAFileBelongsIsAnError(t *testing.T) {
	for _, suffix := range requestSuffixes {
		t.Run(suffix, func(t *testing.T) {
			root, dir := requestLayout(t)
			name := filepath.Join(dir, "requests", "x", "x."+suffix)
			_ = os.Remove(name)
			if err := os.Mkdir(name, 0o700); err != nil {
				t.Fatal(err)
			}
			r, err := loadWithin(t, root, "requests/x", "x")
			wantLoadError(t, r, err)
		})
	}
}

func TestAFileThatCannotBeOpenedIsAnErrorThatIsNotAMissingFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a process of the superuser opens any file")
	}
	for _, suffix := range []string{handoff.FileProof, handoff.FileCSR} {
		t.Run(suffix, func(t *testing.T) {
			root, dir := requestLayout(t)
			name := filepath.Join(dir, "requests", "x", "x."+suffix)
			if err := os.Chmod(name, 0); err != nil {
				t.Fatal(err)
			}
			r, err := loadWithin(t, root, "requests/x", "x")
			wantLoadError(t, r, err)
			if !errors.Is(err, fs.ErrPermission) {
				t.Errorf("the error does not carry its cause: %v", err)
			}
		})
	}
}

func TestARealFileOnDiskIsRead(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"x.proof.json": "{}"}))
	r, err := handoff.LoadRequest(root, ".", "x")
	if err != nil || string(r.Files[handoff.FileProof]) != "{}" {
		t.Fatalf("%v %v", r, err)
	}
}

func mustRemoveAll(t testing.TB, p string) {
	t.Helper()
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
}

func mustRename(t testing.TB, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t testing.TB, p, data string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAStemThatIsNotAStemIsAnError(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"d/x.proof.json": "P"}))
	long := strings.Repeat("a", 64)
	for _, stem := range []string{
		"", "A", "aB", "a/b", "../x", "a\\b", "a_b", "a b", "-a", "--", "a.b", ".", "..", "a\x00", "a\n", "ä", "x.proof.json/..", long, "a b c",
	} {
		_, err := handoff.LoadRequest(root, "d", stem)
		if !errors.Is(err, handoff.ErrLoad) {
			t.Errorf("the stem %q: error %v, want ErrLoad", stem, err)
		}
		if errors.Is(err, handoff.ErrNoProof) {
			t.Errorf("the stem %q is a missing proof", stem)
		}
	}
}

func TestAStemOfThePageIsRead(t *testing.T) {
	for _, stem := range []string{"a", "0", "a-", "a-b", "9-9", "x", strings.Repeat("a", 63), strings.Repeat("0", 63), "a--b"} {
		root, _ := diskRoot(t, strs(map[string]string{"d/" + stem + ".proof.json": "P"}))
		r, err := handoff.LoadRequest(root, "d", stem)
		if err != nil || r.Stem != stem {
			t.Errorf("the stem %q: %v %v", stem, r, err)
		}
	}
}

func TestAFolderThatIsNotAPathInsideTheRootIsAnError(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"d/x.proof.json": "P", "x.proof.json": "P"}))
	for _, dir := range []string{"", "..", "/d", "d/", "d//e", "d/../d", "./d", "d/.", "../d", "d/..", "d\x00", "\\d"} {
		r, err := handoff.LoadRequest(root, dir, "x")
		if !errors.Is(err, handoff.ErrLoad) || r != nil {
			t.Errorf("the folder %q: request %v, error %v, want ErrLoad", dir, r, err)
		}
	}
}

func TestANilRootIsAnError(t *testing.T) {
	_, err := handoff.LoadRequest(nil, "d", "x")
	if !errors.Is(err, handoff.ErrLoad) {
		t.Errorf("error %v", err)
	}
}

func TestTheFilesOfALoadedRequestAreTheRequestsOwn(t *testing.T) {
	root, _ := diskRoot(t, strs(map[string]string{"d/x.proof.json": "PPP"}))
	a, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	a.Files[handoff.FileProof][0] = 'Z'
	b, err := handoff.LoadRequest(root, "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Files[handoff.FileProof], []byte("PPP")) {
		t.Errorf("a second load reads %q", b.Files[handoff.FileProof])
	}
}

// A folder that the test makes up: the read errors and the sizes that a real folder does not give on demand.

type fakeFile struct {
	data []byte
	err  error
}

type fakeDir struct {
	dirs  map[string]*fakeDir
	files map[string]fakeFile
}

func (d *fakeDir) OpenDir(name string) (fsx.FS, error) {
	if sub, ok := d.dirs[name]; ok {
		return sub, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (d *fakeDir) ReadFile(name string) ([]byte, error) {
	f, ok := d.files[name]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}

var errFakeUnused = errors.New("not used by a read")

func (*fakeDir) Mkdir(string, fs.FileMode) error                  { return errFakeUnused }
func (*fakeDir) CreateExcl(string, fs.FileMode) (fsx.File, error) { return nil, errFakeUnused }
func (*fakeDir) RenameNoReplace(string, string) error             { return errFakeUnused }
func (*fakeDir) Sync() error                                      { return errFakeUnused }
func (*fakeDir) ReadDir() ([]fs.DirEntry, error)                  { return nil, errFakeUnused }
func (*fakeDir) Close() error                                     { return nil }

func fakeRoot(files map[string]fakeFile) *fakeDir {
	return &fakeDir{dirs: map[string]*fakeDir{"d": {files: files}}}
}

func TestAFileThatCannotBeReadIsAnErrorThatCarriesItsCause(t *testing.T) {
	cause := errors.New("disk on fire")
	for _, suffix := range requestSuffixes {
		t.Run(suffix, func(t *testing.T) {
			files := map[string]fakeFile{"x.proof.json": {data: []byte("P")}, "x." + suffix: {err: cause}}
			r, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
			wantLoadError(t, r, err)
			if !errors.Is(err, cause) {
				t.Errorf("the error does not carry its cause: %v", err)
			}
		})
	}
	// A permission error on an optional file is not "the file is not there".
	files := map[string]fakeFile{"x.proof.json": {data: []byte("P")}, "x.subkey.pgp": {err: fs.ErrPermission}}
	r, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
	wantLoadError(t, r, err)
}

// A file that the reader of folders refuses for its size (over 8 MiB) is given the answer of a file that is
// only over 256 KiB: no error of the load, and a request that the checks refuse as malformed.
func TestAFileThatIsTooLongForTheReaderIsTheSameAnswerAsOneJustOverTheLimit(t *testing.T) {
	tooLarge := fakeFile{err: fmt.Errorf("%w: 9 bytes", fsx.ErrTooLarge)}
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	for _, suffix := range requestSuffixes {
		t.Run(suffix, func(t *testing.T) {
			whole := f.request()
			files := map[string]fakeFile{"x.proof.json": {data: whole.Files[handoff.FileProof]}, "x.csr.pem": {data: whole.Files[handoff.FileCSR]}}
			files["x."+suffix] = tooLarge
			over, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
			if err != nil {
				t.Fatalf("a file over the limit of the reader is an error of the load: %v", err)
			}
			if got := len(over.Files[suffix]); got != handoff.MaxFileSize+1 {
				t.Errorf("%d bytes, want %d", got, handoff.MaxFileSize+1)
			}
			if len(over.Files) < 2 {
				t.Errorf("the other files are missing: %d files", len(over.Files))
			}
			files["x."+suffix] = fakeFile{data: make([]byte, handoff.MaxFileSize+1)}
			just, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
			if err != nil {
				t.Fatal(err)
			}
			vOver, err := newChecker(t).Check(t.Context(), over)
			if err != nil {
				t.Fatalf("error %v", err)
			}
			vJust, err := newChecker(t).Check(t.Context(), just)
			if err != nil {
				t.Fatalf("error %v", err)
			}
			// The files of the other types are not read by a request of this type, whatever their size.
			if (suffix == handoff.FileProof || suffix == handoff.FileCSR) && vOver.Accepted() {
				t.Fatal("a file that is too large is accepted")
			}
			if vOver.Code != vJust.Code || vOver.Detail != vJust.Detail || statuses(vOver) != statuses(vJust) {
				t.Errorf("over the limit of the reader: %q %q %s; just over the limit: %q %q %s",
					vOver.Code, vOver.Detail, statuses(vOver), vJust.Code, vJust.Detail, statuses(vJust))
			}
		})
	}
}

func TestAProofOrARequestFileOverTheLimitOfTheReaderIsMalformedAtCheckTwo(t *testing.T) {
	tooLarge := fakeFile{err: fmt.Errorf("%w: 9 bytes", fsx.ErrTooLarge)}
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	whole := f.request()
	proof, csr := whole.Files[handoff.FileProof], whole.Files[handoff.FileCSR]
	for name, files := range map[string]map[string]fakeFile{
		"the proof": {"x.proof.json": tooLarge, "x.csr.pem": {data: csr}},
		"the csr":   {"x.proof.json": {data: proof}, "x.csr.pem": tooLarge},
		"both":      {"x.proof.json": tooLarge, "x.csr.pem": tooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
			if err != nil || r == nil {
				t.Fatalf("request %v, error %v", r, err)
			}
			v, err := newChecker(t).Check(t.Context(), r)
			if err != nil || v.Code != handoff.CodeMalformed || !v.Refused() || v.Accepted() {
				t.Errorf("code %q, error %v, accepted %v, want malformed", v.Code, err, v.Accepted())
			}
			if !plain(v.Detail) {
				t.Errorf("the detail is not plain text: %q", v.Detail)
			}
		})
	}
}

func TestOnlyTheSizeOfAFileIsTurnedIntoAVerdictAndAnyOtherErrorOfTheLoadIsKept(t *testing.T) {
	// Only the size is turned into a verdict. Another error of the same file, or of another file, is still
	// an error of the load, and so is an error that only says "too large" without being the one of fsx.
	cause := errors.New("disk on fire")
	tooLarge := fakeFile{err: fmt.Errorf("%w: 9 bytes", fsx.ErrTooLarge)}
	for name, files := range map[string]map[string]fakeFile{
		"another file cannot be read":              {"x.proof.json": tooLarge, "x.csr.pem": {err: cause}},
		"no proof beside a file that is too large": {"x.csr.pem": tooLarge},
		"a text that says too large":               {"x.proof.json": {data: []byte("P")}, "x.csr.pem": {err: errors.New("the file is longer than the limit of a read")}},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
			if err == nil {
				t.Fatalf("no error, request %v", r)
			}
			if r != nil {
				t.Errorf("a request beside the error %v", err)
			}
		})
	}
}

func TestAFileThatTheReaderGivesWholeIsCutAtTheLimitAndOneByteAndTheOriginalIsNotKept(t *testing.T) {
	big := bytes.Repeat([]byte("a"), fsx.MaxReadSize)
	files := map[string]fakeFile{"x.proof.json": {data: []byte("P")}, "x.csr.pem": {data: big}}
	r, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r.Files[handoff.FileCSR]); got != handoff.MaxFileSize+1 {
		t.Errorf("%d bytes, want %d", got, handoff.MaxFileSize+1)
	}
	if cap(r.Files[handoff.FileCSR]) > 2*(handoff.MaxFileSize+1) {
		t.Errorf("the request holds a buffer of %d bytes for a file that was cut to %d", cap(r.Files[handoff.FileCSR]), handoff.MaxFileSize+1)
	}
	// Exactly one byte over is kept as it is, and exactly the limit is whole.
	for n, want := range map[int]int{handoff.MaxFileSize: handoff.MaxFileSize, handoff.MaxFileSize + 1: handoff.MaxFileSize + 1, handoff.MaxFileSize + 2: handoff.MaxFileSize + 1} {
		files["x.csr.pem"] = fakeFile{data: make([]byte, n)}
		r, err := handoff.LoadRequest(fakeRoot(files), "d", "x")
		if err != nil || len(r.Files[handoff.FileCSR]) != want {
			t.Errorf("%d bytes read: %d bytes kept, error %v, want %d", n, len(r.Files[handoff.FileCSR]), err, want)
		}
	}
}

// What the loader gives to the checks: a hostile proof file, loaded through the folder, is a verdict.

// loadPair loads a proof file and a request file through a real folder.
func loadPair(t testing.TB, proof, csr []byte) (*handoff.Request, error) {
	t.Helper()
	root, _ := diskRoot(t, map[string][]byte{"requests/x/x.proof.json": proof, "requests/x/x.csr.pem": csr})
	return handoff.LoadRequest(root, "requests/x", "x")
}

// What the loader gives to the checks: a hostile proof file, loaded through the folder, is a verdict.

func TestHostileProofFilesFromAFolderAreMalformedAndNeverACrash(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	deepObj := func(n int) string { return strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n) }
	digest := f.proof["request_sha256"].(string)
	good := func(extra string) string {
		return `{"handoff":1,"type":"x509-intermediate","request_sha256":"` + digest + `","store":"software"` + extra + `}`
	}
	for name, proof := range map[string]string{
		"nesting of 10001 lists":               good(`,"x":` + deep(10001)),
		"nesting of 100000 lists":              good(`,"x":` + deep(100000)),
		"nesting of 10001 objects":             good(`,"x":` + deepObj(10001)),
		"nesting of 20000 objects at the top":  deepObj(20000),
		"a member twice, deep inside":          good(`,"evidence":{"a":{"b":1,"b":2}}`),
		"a member twice in the evidence":       `{"handoff":1,"type":"x509-intermediate","request_sha256":"` + digest + `","store":"piv","evidence":{"attestation":["YQ==","Yg=="],"attestation":["YQ==","Yg=="]}}`,
		"a byte that is not UTF-8 in a name":   "{\"handoff\":1,\"\xff\":1}",
		"a byte that is not UTF-8 in a value":  good(",\"x\":\"\xc3\x28\""),
		"an overlong UTF-8 sequence":           good(",\"x\":\"\xc0\xaf\""),
		"a surrogate in UTF-8":                 good(",\"x\":\"\xed\xa0\x80\""),
		"a lone surrogate escape":              good(`,"x":"\ud800"`),
		"a low surrogate escape":               good(`,"x":"\udc00"`),
		"a NUL byte":                           good(",\"x\":\"\x00\""),
		"a NUL byte at the end":                good("") + "\x00",
		"a control character in a string":      good(",\"x\":\"a\tb\""),
		"an escape that is not one":            good(`,"x":"\q"`),
		"a huge integer":                       good(`,"x":` + strings.Repeat("9", 5000)),
		"a huge negative integer":              good(`,"x":-` + strings.Repeat("9", 5000)),
		"a huge exponent":                      good(`,"x":1e999999999`),
		"a huge fraction":                      good(`,"x":0.` + strings.Repeat("0", 5000) + `1`),
		"the integer past the range":           good(`,"x":9007199254740992`),
		"the integer past the range, negative": good(`,"x":-9007199254740992`),
		"a long string":                        good(`,"x":"` + strings.Repeat("a", 200000) + `"`),
		"many members":                         good(strings.Repeat(`,"m":1`, 5000)),
		"many distinct unknown members":        manyMembers(5000),
		"the version as a long digit string":   `{"handoff":` + strings.Repeat("1", 3000) + `}`,
		"a document of a million spaces":       strings.Repeat(" ", 1<<20),
		"an array of the document":             `[` + good("") + `]`,
		"two documents":                        good("") + good(""),
		"the document in a string":             `"` + strings.ReplaceAll(good(""), `"`, `\"`) + `"`,
		"a type that is a list":                `{"handoff":1,"type":["x509-intermediate"],"request_sha256":"` + digest + `","store":"software"}`,
		"a store that is an object":            `{"handoff":1,"type":"x509-intermediate","request_sha256":"` + digest + `","store":{}}`,
		"a digest that is a list":              `{"handoff":1,"type":"x509-intermediate","request_sha256":[],"store":"software"}`,
		"every member null":                    `{"handoff":null,"type":null,"request_sha256":null,"store":null}`,
		"every member the wrong type":          `{"handoff":1,"type":1,"request_sha256":1,"store":1,"evidence":1,"primaries":1,"capabilities":1,"use":1}`,
		"every member a list":                  `{"handoff":1,"type":[],"request_sha256":[],"store":[],"evidence":[],"primaries":[],"capabilities":[],"use":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			r, err := loadPair(t, []byte(proof), f.csr)
			if err != nil {
				t.Fatalf("the loader refused a file that it should only read: %v", err)
			}
			v, err := newChecker(t).Check(t.Context(), r)
			if err != nil {
				t.Fatalf("error %v", err)
			}
			// A document that the page cannot read is refused for its form, or for its version when the
			// version is readable and not 1. Nothing is accepted, and nothing is called "policy".
			if v.Code != handoff.CodeMalformed && v.Code != handoff.CodeVersionUnsupported {
				t.Errorf("code %q (%s)", v.Code, v.Detail)
			}
			if v.Accepted() {
				t.Error("a hostile file is accepted")
			}
		})
	}
}

func manyMembers(n int) string {
	var b strings.Builder
	b.WriteString(`{"handoff":1`)
	for i := range n {
		b.WriteString(`,"m`)
		b.WriteString(strings.Repeat("a", i%7))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(string(rune('a' + (i/26)%26)))
		b.WriteString(string(rune('a' + (i/676)%26)))
		b.WriteString(`":1`)
	}
	b.WriteString(`}`)
	return b.String()
}

func TestAHostileRequestFileFromAFolderIsMalformedAndNeverACrash(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	proof := f.request().Files[handoff.FileProof]
	for name, csr := range map[string][]byte{
		"zero bytes":                           make([]byte, 1000),
		"0xff bytes":                           bytes.Repeat([]byte{0xff}, 1000),
		"a PEM block of a long line":           []byte("-----BEGIN CERTIFICATE REQUEST-----\n" + strings.Repeat("A", 100000) + "\n-----END CERTIFICATE REQUEST-----\n"),
		"a PEM block of many lines":            []byte("-----BEGIN CERTIFICATE REQUEST-----\n" + strings.Repeat("AAAA\n", 40000) + "-----END CERTIFICATE REQUEST-----\n"),
		"a PEM block of Base64 that is bad":    []byte("-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----\n"),
		"a DER length that is huge":            pemOf([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x01}),
		"a DER of deeply nested sequences":     pemOf(append(bytes.Repeat([]byte{0x30, 0x80}, 5000), 0x00, 0x00)),
		"a DER with an indefinite length":      pemOf([]byte{0x30, 0x80, 0x00, 0x00}),
		"a bare NUL":                           {0},
		"the file with its own bytes reversed": reversed(f.csr),
		"the DER of a certificate":             pemOf(mustMarshal(struct{ A int }{1})),
	} {
		t.Run(name, func(t *testing.T) {
			r, err := loadPair(t, proof, csr)
			if err != nil {
				t.Fatal(err)
			}
			v, err := newChecker(t).Check(t.Context(), r)
			if err != nil {
				t.Fatalf("error %v", err)
			}
			if v.Accepted() || !v.Refused() {
				t.Errorf("code %q: a hostile request file was not refused", v.Code)
			}
			// The digest of such a file is not the proof's, but the form is refused first.
			if v.Code != handoff.CodeMalformed {
				t.Errorf("code %q (%s), want malformed", v.Code, v.Detail)
			}
		})
	}
}

func reversed(b []byte) []byte {
	out := bytes.Clone(b)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// The comment of LoadRequest says that no element of the path is followed when it is a link. A link that is
// the folder of the request is a link on the way to the file.
func TestARealLinkThatIsTheFolderOfTheRequestIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "x.proof.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "requests"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "requests", "b")); err != nil {
		t.Skipf("no links here: %v", err)
	}
	r, err := handoff.LoadRequest(openRoot(t, dir), "requests/b", "x")
	if err == nil {
		t.Fatalf("the files of a folder that is a link were read: %v", r.Files)
	}
	if !errors.Is(err, handoff.ErrLoad) {
		t.Errorf("error %v, want ErrLoad", err)
	}
}
