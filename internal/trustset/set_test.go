package trustset_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/trustset"
)

// aSet signs a first list and a renewal and returns the renewal, a set of one signature.
func aSet(t *testing.T) (*chain, *trustset.Set) {
	t.Helper()
	c := newChain(t)
	c.add(next{labels: []string{"A", "B"}})
	return c, c.add(next{labels: []string{"A", "B", "C"}})
}

// setDir is a folder with a writer on it and a folder trust/ inside, which a bundle has.
func setDir(t *testing.T) (*fsx.Writer, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
		t.Fatal(err)
	}
	w, err := fsx.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return w, dir
}

func nameOf(t *testing.T, s *trustset.Set) string {
	t.Helper()
	name, err := trustset.SetName(s.Sequence(), hexOf(string(s.ListJSON())))
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestSetAccessors(t *testing.T) {
	c, s := aSet(t)
	if s.Sequence() != 2 || !slices.Equal(s.Signers(), []string{"A", "B", "C"}) {
		t.Errorf("sequence %d, signers %v", s.Sequence(), s.Signers())
	}
	if !bytes.Equal(s.ListJSON(), c.last().ListJSON()) {
		t.Error("ListJSON differs")
	}
	if len(s.ListJWS()) == 0 || len(s.CABundle()) == 0 {
		t.Error("a file is empty")
	}
	if bytes.HasSuffix(s.ListJWS(), []byte("\n")) {
		t.Error("root-list.jws has a trailing newline")
	}
}

// Files has the three names in the order of FileNames and then the keyring file, because the list
// of this set pins OpenPGP primaries; each has FileMode and the bytes of the set, and the data are
// copies.
func TestSetFiles(t *testing.T) {
	_, s := aSet(t)
	files := s.Files()
	names := trustset.FileNames()
	if len(files) != 4 || len(names) != 3 {
		t.Fatalf("%d files, %d names", len(files), len(names))
	}
	want := map[string][]byte{
		trustset.RootListFile:    s.ListJSON(),
		trustset.RootListJWSFile: s.ListJWS(),
		trustset.CABundleFile:    s.CABundle(),
		trustset.KeyringFile:     s.Keyring(),
	}
	for i, f := range files {
		wantName := trustset.KeyringFile
		if i < len(names) {
			wantName = names[i]
		}
		if f.Name != wantName {
			t.Errorf("file %d is %q, want %q", i, f.Name, wantName)
		}
		if f.Perm != 0o644 {
			t.Errorf("%s has mode %v", f.Name, f.Perm)
		}
		if !bytes.Equal(f.Data, want[f.Name]) {
			t.Errorf("%s holds other bytes than the set", f.Name)
		}
	}
	if !slices.Equal(names, []string{"root-list.json", "root-list.jws", "ca-bundle.pem"}) {
		t.Errorf("the names are %v", names)
	}
	// Changing what came out changes nothing in the set.
	for _, f := range files {
		for i := range f.Data {
			f.Data[i] = 'x'
		}
	}
	jsonBytes, jwsBytes, bundle := s.ListJSON(), s.ListJWS(), s.CABundle()
	jsonBytes[0], jwsBytes[0], bundle[0] = 'x', 'x', 'x'
	signers := s.Signers()
	signers[0] = "Z"
	if s.ListJSON()[0] != '{' || s.ListJWS()[0] != '{' || s.CABundle()[0] != '#' || s.Signers()[0] != "A" {
		t.Error("a result shares the set's own bytes")
	}
	if !bytes.Equal(s.Files()[0].Data, s.ListJSON()) {
		t.Error("Files changed after its result was changed")
	}
}

func TestZeroAndNilSet(t *testing.T) {
	w, dir := setDir(t)
	for name, s := range map[string]*trustset.Set{"nil": nil, "zero": {}} {
		if s.Sequence() != 0 || s.Signers() != nil || s.ListJSON() != nil || s.ListJWS() != nil || s.CABundle() != nil || s.Files() != nil {
			t.Errorf("%s set gives something", name)
		}
		err := s.Write(w, "trust/1-00000000")
		wantOnly(t, err, trustset.ErrParams)
		if !strings.Contains(err.Error(), "the set is empty") {
			t.Errorf("%s set: %v", name, err)
		}
		if ents, _ := os.ReadDir(filepath.Join(dir, "trust")); len(ents) != 0 {
			t.Errorf("%s set wrote something", name)
		}
	}
}

// Write writes the set into finalDir: the folder holds exactly the three files, the bytes are the
// set's, and a second Write to the same name fails with fs.ErrExist and changes nothing.
func TestSetWrite(t *testing.T) {
	_, s := aSet(t)
	w, dir := setDir(t)
	final := "trust/" + nameOf(t, s)
	if err := s.Write(w, final); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, filepath.FromSlash(final))
	ents, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
		data, err := os.ReadFile(filepath.Join(target, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var want []byte
		switch e.Name() {
		case "root-list.json":
			want = s.ListJSON()
		case "root-list.jws":
			want = s.ListJWS()
		case "ca-bundle.pem":
			want = s.CABundle()
		case "keyring.gpg":
			want = s.Keyring()
		}
		if !bytes.Equal(data, want) {
			t.Errorf("%s holds other bytes", e.Name())
		}
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o400 == 0 || info.Mode().Perm()&^0o644 != 0 {
			t.Errorf("%s has mode %v", e.Name(), info.Mode())
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"ca-bundle.pem", "keyring.gpg", "root-list.json", "root-list.jws"}) {
		t.Errorf("the folder holds %v", got)
	}
	// A second write to the name fails and changes nothing.
	before := snapshotOf(t, dir)
	err = s.Write(w, final)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("a second Write gave %v, want fs.ErrExist", err)
	}
	var fe *fsx.Error
	if !errors.As(err, &fe) {
		t.Errorf("the error is not the error of fsx as it is: %T", err)
	}
	for k, v := range snapshotOf(t, dir) {
		if k == "" {
			continue
		}
		if !bytes.Equal(before[k], v) {
			if _, was := before[k]; was {
				t.Errorf("%s changed", k)
			}
		}
	}
	for k := range before {
		if _, ok := snapshotOf(t, dir)[k]; !ok {
			t.Errorf("%s was lost", k)
		}
	}
}

// snapshotOf maps every path under dir to its bytes ("" for a folder).
func snapshotOf(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			out[rel+"/"] = nil
			return nil
		}
		data, err := os.ReadFile(p)
		out[rel] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A finalDir fsx refuses writes nothing: with .. in it, absolute, empty, a link on the way, a name
// that is not a plain name, a parent that does not exist.
func TestSetWriteRefusedByFsx(t *testing.T) {
	_, s := aSet(t)
	w, dir := setDir(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	for _, final := range []string{
		"trust/../x", "../x", "/abs", "", "trust/", "trust//x", "trust/./x", "trust/x/..", "nowhere/x", "linked/x",
		"trust/\x00x", "trust/a\\b", "trust/.", "trust/..", "trust/" + string(make([]byte, 300)),
	} {
		err := s.Write(w, final)
		if err == nil {
			t.Errorf("finalDir %q was taken", final)
			continue
		}
		if errors.Is(err, trustset.ErrParams) && final != "" {
			// fsx refuses these; this package adds no refusal of its own to the path.
			t.Errorf("finalDir %q: the error is ErrParams, not the error of fsx: %v", final, err)
		}
		// A stopped writer refuses the rest: use a new one for each path.
		fresh, err2 := fsx.Open(dir)
		if err2 != nil {
			t.Fatal(err2)
		}
		w = fresh
		t.Cleanup(func() { _ = fresh.Close() })
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Error("something was written through a link")
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "trust")); len(ents) != 0 {
		t.Errorf("trust/ holds %d entries", len(ents))
	}
}

// A nil writer is ErrParams; a closed writer gives the error of fsx and writes nothing.
func TestSetWriteWithNoWriterAndAClosedWriter(t *testing.T) {
	_, s := aSet(t)
	wantOnly(t, s.Write(nil, "trust/x"), trustset.ErrParams)
	w, dir := setDir(t)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	err := s.Write(w, "trust/"+nameOf(t, s))
	if err == nil || errors.Is(err, trustset.ErrParams) || !errors.Is(err, fsx.ErrWriterClosed) {
		t.Errorf("a closed writer: %v", err)
	}
	if ents, _ := os.ReadDir(filepath.Join(dir, "trust")); len(ents) != 0 {
		t.Error("a closed writer wrote")
	}
}

// failFS stands in for the root folder and fails the n-th call, so that a stop at each step of the
// write can be shown to leave no set at finalDir.
type failState struct {
	mu     sync.Mutex
	n      int
	failAt int
	calls  int
}

func (s *failState) hit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	if s.n == s.failAt {
		s.calls++
		return errors.New("the stick was pulled")
	}
	return nil
}

type failFS struct {
	inner fsx.FS
	st    *failState
}

func (f *failFS) OpenDir(name string) (fsx.FS, error) {
	if err := f.st.hit(); err != nil {
		return nil, err
	}
	in, err := f.inner.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &failFS{inner: in, st: f.st}, nil
}

func (f *failFS) Mkdir(name string, perm fs.FileMode) error {
	if err := f.st.hit(); err != nil {
		return err
	}
	return f.inner.Mkdir(name, perm)
}

func (f *failFS) CreateExcl(name string, perm fs.FileMode) (fsx.File, error) {
	if err := f.st.hit(); err != nil {
		return nil, err
	}
	file, err := f.inner.CreateExcl(name, perm)
	if err != nil {
		return nil, err
	}
	return &failFile{inner: file, st: f.st}, nil
}

func (f *failFS) RenameNoReplace(a, b string) error {
	if err := f.st.hit(); err != nil {
		return err
	}
	return f.inner.RenameNoReplace(a, b)
}

func (f *failFS) Sync() error {
	if err := f.st.hit(); err != nil {
		return err
	}
	return f.inner.Sync()
}

func (f *failFS) ReadFile(name string) ([]byte, error) { return f.inner.ReadFile(name) }
func (f *failFS) ReadDir() ([]fs.DirEntry, error)      { return f.inner.ReadDir() }
func (f *failFS) Close() error                         { return f.inner.Close() }

type failFile struct {
	inner fsx.File
	st    *failState
}

func (f *failFile) Write(p []byte) (int, error) {
	if err := f.st.hit(); err != nil {
		return 0, err
	}
	return f.inner.Write(p)
}

func (f *failFile) Sync() error {
	if err := f.st.hit(); err != nil {
		return err
	}
	return f.inner.Sync()
}

func (f *failFile) Close() error { return f.inner.Close() }

// A stop at each step leaves no set at finalDir: finalDir is there whole or not at all. When no
// step fails, the set is there. One call is made to fsx and nothing else.
func TestSetWriteCutAtEachStep(t *testing.T) {
	_, s := aSet(t)
	final := nameOf(t, s)
	ok := false
	steps := 0
	for at := 1; at < 200 && !ok; at++ {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "trust"), 0o755); err != nil {
			t.Fatal(err)
		}
		root, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		st := &failState{failAt: at}
		w := &fsx.Writer{FS: &failFS{inner: root, st: st}}
		err = s.Write(w, "trust/"+final)
		_ = w.Close()
		_, statErr := os.Stat(filepath.Join(dir, "trust", final))
		if st.calls == 0 {
			// No step failed: the write went through all its steps.
			if err != nil {
				t.Fatalf("no step failed and Write gave %v", err)
			}
			if statErr != nil {
				t.Fatalf("the set is not there: %v", statErr)
			}
			ok = true
			steps = at - 1
			break
		}
		if err == nil {
			t.Fatalf("step %d failed and Write gave no error", at)
		}
		if errors.Is(err, trustset.ErrParams) {
			t.Errorf("step %d: the error is ErrParams: %v", at, err)
		}
		if statErr == nil {
			// The rename or the flush after it failed: the folder is whole, with the four files.
			ents, _ := os.ReadDir(filepath.Join(dir, "trust", final))
			if len(ents) != 4 {
				t.Errorf("step %d: the folder at finalDir holds %d files", at, len(ents))
			}
		}
		// The writer is stopped for good: another Write does not write the set.
		if err2 := s.Write(w, "trust/"+final); err2 == nil && statErr != nil {
			t.Errorf("step %d: a stopped writer wrote", at)
		}
	}
	if !ok {
		t.Fatal("every step failed or the loop ended")
	}
	if steps < 10 {
		t.Errorf("only %d steps were counted, the write has more", steps)
	}
}
