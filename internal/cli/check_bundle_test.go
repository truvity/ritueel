//go:build linux || darwin

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The bundles of the tests of "check history" are made here, by hand: every file is spelled out and
// every digest is worked out with crypto/sha256, with no use of a helper of the library. A fault
// that the writer and the reader of the library share cannot hide in them. The bundle holds n
// ceremonies; each has a plan, an attempt, a wanted copy, a transcript, a trust set (keys.txt and
// root-list.json) and a record.

// hbSum is the SHA-256 of a text, in lower-case hexadecimal.
func hbSum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// hbCeremony is one ceremony of a hand-made bundle: the folder, the trust set, and the text of
// each file.
type hbCeremony struct {
	n          int
	folder     string
	set        string
	plan       string
	attempt    string
	wanted     string
	transcript string
	keys       string
	rootList   string
	record     string // "" for a ceremony that has no record yet
	digest     string // SHA-256 of record, "" when there is none
	prev       string // the predecessor the record names, "" for none
	noSet      bool   // the record lists no trust set, and none is written
}

func (c hbCeremony) base() string { return "history/" + c.folder + "/" }

// hbundle is a hand-made bundle in a folder of the test.
type hbundle struct {
	dir string
	cs  []hbCeremony
}

// hbFolder and hbSet are the names of the ceremony folder and the trust set of ceremony number n
// (from 1).
func hbFolder(n int) string { return fmt.Sprintf("2026%04dT100000Z-apply", n) }
func hbSet(n int) string    { return fmt.Sprintf("%d-3fa9c1d%x", n, n) }

// hbMake works out the files of ceremony number n whose predecessor has the record digest prev
// ("" for the first). withRecord says whether the record is written.
func hbMake(n int, prev string, withRecord bool) hbCeremony {
	c := hbCeremony{n: n, folder: hbFolder(n), set: hbSet(n), prev: prev}
	ns := fmt.Sprint(n)
	c.wanted = "name: bundle " + ns + "\n"
	c.transcript = "ceremony " + ns + "\n"
	c.keys = "keys of set " + ns + "\n"
	c.rootList = `{"version":1}`
	c.plan = `{"ceremony":"` + c.folder + `","command":"apply","trust_sequence":` + ns + `,"version":1,"wanted":[{"path":"ritueel.yaml","sha256":"` + hbSum(c.wanted) + `"}]}`
	if prev != "" {
		c.rootList = `{"last_record_sha256":"` + prev + `","version":1}`
		c.plan = `{"ceremony":"` + c.folder + `","command":"apply","last_record_sha256":"` + prev + `","trust_sequence":` + ns + `,"version":1,"wanted":[{"path":"ritueel.yaml","sha256":"` + hbSum(c.wanted) + `"}]}`
	}
	c.attempt = `{"ceremony":"` + c.folder + `","plan_sha256":"` + hbSum(c.plan) + `","version":1}`
	if withRecord {
		c.seal()
	}
	return c
}

// seal works out the record of c from its other files and the predecessor it names, and its digest.
func (c *hbCeremony) seal() {
	c.record = hbRecord(*c, c.prev)
	c.digest = hbSum(c.record)
}

// hbRecord is the text of the record of c, in canonical form: the members in order of name, no
// space.
func hbRecord(c hbCeremony, prev string) string {
	ns := fmt.Sprint(c.n)
	artifacts := `[` +
		`{"path":"trust/` + c.set + `/keys.txt","sha256":"` + hbSum(c.keys) + `"},` +
		`{"path":"trust/` + c.set + `/root-list.json","sha256":"` + hbSum(c.rootList) + `"}]`
	if c.noSet {
		artifacts = `[]`
	}
	r := `{"artifacts":` + artifacts + `,` +
		`"ceremony":"` + c.folder + `","command":"apply","outcome":"completed","plan_sha256":"` + hbSum(c.plan) + `",`
	if prev != "" {
		r += `"prev_record_sha256":"` + prev + `",`
	}
	r += `"transcript_sha256":"` + hbSum(c.transcript) + `","trust_sequence":` + ns + `,"version":1,` +
		`"wanted":[{"path":"ritueel.yaml","sha256":"` + hbSum(c.wanted) + `"}]}`
	return r
}

// hbWrite writes one file of a bundle, making its folders.
func hbWrite(t testing.TB, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// hbWriteCeremony writes the files of c.
func hbWriteCeremony(t testing.TB, dir string, c hbCeremony) {
	t.Helper()
	b := c.base()
	hbWrite(t, dir, b+"plan.json", c.plan)
	hbWrite(t, dir, b+"attempt.json", c.attempt)
	hbWrite(t, dir, b+"wanted/ritueel.yaml", c.wanted)
	hbWrite(t, dir, b+"transcript.txt", c.transcript)
	if !c.noSet {
		hbWrite(t, dir, "trust/"+c.set+"/keys.txt", c.keys)
		hbWrite(t, dir, "trust/"+c.set+"/root-list.json", c.rootList)
	}
	if c.record != "" {
		hbWrite(t, dir, b+"record.json", c.record)
	}
}

// newHB makes a bundle of n ceremonies in a new folder: ritueel.yaml, history/ and trust/.
func newHB(t testing.TB, n int) *hbundle {
	t.Helper()
	b := &hbundle{dir: t.TempDir()}
	hbWrite(t, b.dir, "ritueel.yaml", "name: test\n")
	if err := os.MkdirAll(filepath.Join(b.dir, "history"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		b.add(t, true)
	}
	return b
}

// end is the digest of the newest record, "" when there is none.
func (b *hbundle) end() string {
	for i := len(b.cs) - 1; i >= 0; i-- {
		if b.cs[i].digest != "" {
			return b.cs[i].digest
		}
	}
	return ""
}

// add writes the next ceremony. With withRecord false it is an unfinished one: a plan, an attempt
// and a trust set, and no record. The plan names the end of the history, as a plan does. Each
// change is applied to the files before the record is worked out from them, so a change to a file
// is a change that the record lists.
func (b *hbundle) add(t testing.TB, withRecord bool, changes ...func(*hbCeremony)) hbCeremony {
	t.Helper()
	c := hbMake(len(b.cs)+1, b.end(), false)
	for _, f := range changes {
		f(&c)
	}
	if withRecord {
		c.seal()
	}
	hbWriteCeremony(t, b.dir, c)
	b.cs = append(b.cs, c)
	return c
}

// path returns the path of a file of the bundle on disk, from the "/" separated name.
func (b *hbundle) path(rel string) string { return filepath.Join(b.dir, filepath.FromSlash(rel)) }

// recordPath and folderPath are the paths a finding of ceremony number n (from 1) names.
func (b *hbundle) recordPath(n int) string { return b.cs[n-1].base() + "record.json" }
func (b *hbundle) folderPath(n int) string { return "history/" + b.cs[n-1].folder }

// rewrite replaces the text of a file with f of it.
func (b *hbundle) rewrite(t testing.TB, rel string, f func(string) string) {
	t.Helper()
	data, err := os.ReadFile(b.path(rel))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.path(rel), []byte(f(string(data))), 0o644); err != nil {
		t.Fatal(err)
	}
}

// remove removes a file or a folder of the bundle.
func (b *hbundle) remove(t testing.TB, rel string) {
	t.Helper()
	if err := os.RemoveAll(b.path(rel)); err != nil {
		t.Fatal(err)
	}
}

// The environment variable that makes the next test write a bundle of three ceremonies into the
// folder it names, so that a person can run the real program on it. It checks nothing.
const hbOutVar = "RITUEEL_CHECK_BUNDLE_OUT"

func TestWriteHandMadeBundleForAPerson(t *testing.T) {
	out := os.Getenv(hbOutVar)
	if out == "" {
		t.Skipf("%s is not set: this test only writes a bundle for a person to look at", hbOutVar)
	}
	b := newHB(t, 3)
	if err := os.CopyFS(out, os.DirFS(b.dir)); err != nil {
		t.Fatal(err)
	}
}

// The helper itself is checked: a bundle that is built wrong would make every test below test
// nothing.
func TestHandMadeBundleHoldsWhatItSays(t *testing.T) {
	for _, n := range []int{1, 3} {
		b := newHB(t, n)
		if len(b.cs) != n {
			t.Fatalf("the bundle holds %d ceremonies, want %d", len(b.cs), n)
		}
		for i, c := range b.cs {
			if c.digest == "" || len(c.digest) != 64 {
				t.Errorf("ceremony %d has no record digest: %q", i+1, c.digest)
			}
			got, err := os.ReadFile(b.path(b.recordPath(i + 1)))
			if err != nil {
				t.Fatal(err)
			}
			if hbSum(string(got)) != c.digest {
				t.Errorf("the digest of ceremony %d is not the digest of its record file", i+1)
			}
			if i > 0 && !strings.Contains(c.record, `"prev_record_sha256":"`+b.cs[i-1].digest+`"`) {
				t.Errorf("record %d does not name record %d", i+1, i)
			}
			if i == 0 && strings.Contains(c.record, "prev_record_sha256") {
				t.Error("the first record names a predecessor")
			}
		}
	}
	// Different ceremonies have different digests: the end is not the same for one and for three.
	if newHB(t, 1).end() == newHB(t, 3).end() {
		t.Error("a bundle of one ceremony and one of three have the same end")
	}
}

// hbTree is every entry of a folder, for the proof that a run changed nothing: a file as its
// SHA-256, a folder as "dir", a link as its target, anything else as its type; each with its mode.
func hbTree(t testing.TB, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		switch {
		case d.Type().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			out[rel] = fmt.Sprintf("file %s %v", hbSum(string(data)), mode)
		case d.IsDir():
			out[rel] = fmt.Sprintf("dir %v", mode)
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			out[rel] = "link " + target
		default:
			out[rel] = fmt.Sprintf("other %v", d.Type())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// hbSameTree fails the test when the two trees differ, and names the first difference.
func hbSameTree(t testing.TB, before, after map[string]string) {
	t.Helper()
	var names []string
	for k := range before {
		names = append(names, k)
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	for _, k := range slices.Compact(names) {
		if before[k] != after[k] {
			t.Errorf("the folder changed at %q: before %q, after %q", k, before[k], after[k])
			return
		}
	}
	if len(before) == 0 {
		t.Error("the tree is empty: nothing was compared")
	}
}

// failingFS is a folder whose OpenDir of one name fails with err, or every OpenDir when name is "".
// Everything else is the real folder.
type failingFS struct {
	fsx.FS
	name string
	err  error
}

func (f *failingFS) OpenDir(name string) (fsx.FS, error) {
	if f.name == "" || f.name == name {
		return nil, f.err
	}
	d, err := f.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &failingFS{FS: d, name: f.name, err: f.err}, nil
}

// failingRead is a folder whose ReadFile fails with err for the name, and whose handles do the
// same.
type failingRead struct {
	fsx.FS
	name string
	err  error
}

func (f *failingRead) OpenDir(name string) (fsx.FS, error) {
	d, err := f.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &failingRead{FS: d, name: f.name, err: f.err}, nil
}

func (f *failingRead) ReadFile(name string) ([]byte, error) {
	if name == f.name {
		return nil, f.err
	}
	return f.FS.ReadFile(name)
}

// guardFS wraps a folder and counts every call. A call that would write (Mkdir, CreateExcl,
// RenameNoReplace, Sync) is refused with errGuard and counted as a write. The handles that
// OpenDir returns are wrapped with the same counters, so no handle escapes the guard.
type guardFS struct {
	fsx.FS
	c *guardCount
}

type guardCount struct {
	mu     sync.Mutex
	writes []string
	reads  int
	opens  int
}

var errGuard = errors.New("guard: the call writes")

func newGuard(inner fsx.FS) (*guardFS, *guardCount) {
	c := &guardCount{}
	return &guardFS{FS: inner, c: c}, c
}

func (g *guardFS) note(call string) {
	g.c.mu.Lock()
	defer g.c.mu.Unlock()
	g.c.writes = append(g.c.writes, call)
}

func (g *guardFS) OpenDir(name string) (fsx.FS, error) {
	g.c.mu.Lock()
	g.c.opens++
	g.c.mu.Unlock()
	d, err := g.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &guardFS{FS: d, c: g.c}, nil
}

func (g *guardFS) Mkdir(name string, _ fs.FileMode) error {
	g.note("Mkdir " + name)
	return errGuard
}

func (g *guardFS) CreateExcl(name string, _ fs.FileMode) (fsx.File, error) {
	g.note("CreateExcl " + name)
	return nil, errGuard
}

func (g *guardFS) RenameNoReplace(oldName, newName string) error {
	g.note("RenameNoReplace " + oldName + " " + newName)
	return errGuard
}

func (g *guardFS) Sync() error {
	g.note("Sync")
	return errGuard
}

func (g *guardFS) ReadFile(name string) ([]byte, error) {
	g.c.mu.Lock()
	g.c.reads++
	g.c.mu.Unlock()
	return g.FS.ReadFile(name)
}

// openGuarded opens dir with fsx.OpenFS and wraps it with a guard; the folder is closed when the
// test ends.
func openGuarded(t testing.TB, dir string) (*guardFS, *guardCount) {
	t.Helper()
	inner, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	return newGuard(inner)
}
