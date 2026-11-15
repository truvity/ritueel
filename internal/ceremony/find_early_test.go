//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/wanted"
)

// Find lists the names of the root files and judges their number before it reads a byte of any of
// them: a bundle of many root files is refused without reading a thousand files, and no bundle that
// was valid gives another plan (record 0005, rules 4 and 5; docs/reference/bundle.md, "The wanted
// files"). The names of this file start with ef.

// efReads records the path of every file read through a counting folder.
type efReads struct {
	mu    sync.Mutex
	paths []string
}

func (r *efReads) add(p string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths = append(r.paths, p)
}

// under is the number of reads of files below the folder dir.
func (r *efReads) under(dir string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, p := range r.paths {
		if strings.HasPrefix(p, dir+"/") {
			n++
		}
	}
	return n
}

func (r *efReads) of(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Count("\n"+strings.Join(r.paths, "\n")+"\n", "\n"+path+"\n")
}

func (r *efReads) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

// efFS is a folder that counts the files read through it and through every folder opened from it.
type efFS struct {
	fsx.FS
	dir   string
	reads *efReads
}

func (f efFS) OpenDir(name string) (fsx.FS, error) {
	sub, err := f.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return efFS{FS: sub, dir: f.dir + name + "/", reads: f.reads}, nil
}

func (f efFS) ReadFile(name string) ([]byte, error) {
	f.reads.add(f.dir + name)
	return f.FS.ReadFile(name)
}

// efFind runs Find on a counting folder over inner.
func efFind(t testing.TB, inner fsx.FS) (*ceremony.Found, *efReads, error) {
	t.Helper()
	reads := &efReads{}
	f, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: efFS{FS: inner, reads: reads}})
	return f, reads, err
}

// efLargest is a root file of the largest size that is accepted (wanted.MaxBytes), that passes its
// check: its three parts and comment lines to the size.
func efLargest() []byte {
	head := pfX509Test
	line := "# " + strings.Repeat("x", 62) + "\n"
	b := []byte(head)
	for len(b)+len(line) <= wanted.MaxBytes {
		b = append(b, line...)
	}
	b = append(b, ("#" + strings.Repeat("y", wanted.MaxBytes-len(b)-2) + "\n")...)
	return b
}

// efRootName is the name of the i-th root file: r0000, r0001, ...
func efRootName(i int) string { return fmt.Sprintf("r%04d", i) }

// efMemBundle is a bundle in memory with n root files that all hold the same bytes.
func efMemBundle(n int, data []byte) *pfNode {
	m := pfMem(map[string]string{"ritueel.yaml": pfSettings})
	for i := range n {
		m.put("want/roots/"+efRootName(i)+".yaml", &pfNode{kind: "file", data: data})
	}
	return m
}

// efDiskBundle writes a bundle on the disk with n root files: the three parts of a root file and
// then a hole up to the largest size, so that the folder costs nothing and a read of it would fail.
func efDiskBundle(t testing.TB, n int) string {
	t.Helper()
	dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings})
	roots := filepath.Join(dir, "want", "roots")
	if err := os.MkdirAll(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range n {
		f, err := os.Create(filepath.Join(roots, efRootName(i)+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(pfX509Test); err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(wanted.MaxBytes); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestALargestRootFileIsAcceptedAndMakesAPlan(t *testing.T) {
	data := efLargest()
	if len(data) != wanted.MaxBytes {
		t.Fatalf("the test file is %d bytes, want %d", len(data), wanted.MaxBytes)
	}
	m := efMemBundle(1, data)
	f, reads, err := efFind(t, pfFS{m})
	if err != nil || f.Nothing() {
		t.Fatalf("Find = %+v, %v", f, err)
	}
	if reads.of("want/roots/r0000.yaml") != 1 {
		t.Errorf("the one root file was read %d times", reads.of("want/roots/r0000.yaml"))
	}
}

func TestAThousandRootFilesOfTheLargestSizeAreRefusedWithoutReadingThem(t *testing.T) {
	data := efLargest()
	m := efMemBundle(wanted.MaxFiles, data)
	start := time.Now()
	f, reads, err := efFind(t, pfFS{m})
	elapsed := time.Since(start)
	if f != nil || err == nil {
		t.Fatalf("Find = %+v, %v", f, err)
	}
	if k := pfKind(err); k != "not-built" || !errors.Is(err, ceremony.ErrNotBuilt) {
		t.Errorf("kind = %s (%v), want not-built (exit code 1)", k, err)
	}
	for _, w := range []string{"1000 root files", "want/roots/r0000.yaml", "want/roots/r0001.yaml", "nothing was written"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("the text %q does not hold %q", err, w)
		}
	}
	if !pfPrintable(err.Error()) {
		t.Errorf("the text is not printable ASCII: %+q", err.Error())
	}
	if n := reads.under("want/roots"); n != 0 {
		t.Errorf("%d root files were read; none is needed to refuse a bundle of 1,000", n)
	}
	// Only ritueel.yaml and nothing else of the bundle was read.
	if reads.total() != 1 || reads.of("ritueel.yaml") != 1 {
		t.Errorf("the files read are %q, want ritueel.yaml alone", reads.paths)
	}
	if elapsed > 5*time.Second {
		t.Errorf("the refusal took %v", elapsed)
	}
}

func TestAThousandRootFilesOnTheDiskAreRefusedWithoutReadingThem(t *testing.T) {
	dir := efDiskBundle(t, wanted.MaxFiles)
	before := tree(t, dir)
	fsys := pfOpen(t, dir)
	start := time.Now()
	f, reads, err := efFind(t, fsys)
	elapsed := time.Since(start)
	if f != nil || err == nil || pfKind(err) != "not-built" {
		t.Fatalf("Find = %+v, %v (%s)", f, err, pfKind(err))
	}
	if n := reads.under("want/roots"); n != 0 {
		t.Errorf("%d root files were read", n)
	}
	if elapsed > 10*time.Second {
		t.Errorf("the refusal took %v", elapsed)
	}
	sameTree(t, "Find", before, tree(t, dir))
}

func TestMoreRootFilesThanTheLimitAreRefusedAsTooMany(t *testing.T) {
	m := efMemBundle(wanted.MaxFiles+1, efLargest())
	f, reads, err := efFind(t, pfFS{m})
	if f != nil || err == nil || pfKind(err) != "failure" {
		t.Fatalf("Find = %+v, %v (%s)", f, err, pfKind(err))
	}
	if !strings.Contains(err.Error(), "want/roots") || !strings.Contains(err.Error(), fmt.Sprint(wanted.MaxFiles)) {
		t.Errorf("the text %q does not name the folder and the limit", err)
	}
	if reads.under("want/roots") != 0 {
		t.Errorf("%d root files were read", reads.under("want/roots"))
	}
}

// The number of root files that Find reads is bounded: it is as many as there are, up to a few, and
// none above that. The bound is one number in the source (maxRootsRead).
func TestFindReadsFewRootFilesAndNoneOfAFolderOfMany(t *testing.T) {
	const bound = 8
	for _, n := range []int{2, 3, 7, 8, 9, 10, 64, 999, 1000} {
		t.Run(fmt.Sprintf("%d root files", n), func(t *testing.T) {
			m := efMemBundle(n, []byte(pfX509Test))
			f, reads, err := efFind(t, pfFS{m})
			if f != nil || err == nil || pfKind(err) != "not-built" {
				t.Fatalf("Find = %+v, %v (%s)", f, err, pfKind(err))
			}
			read := reads.under("want/roots")
			if read > bound {
				t.Errorf("%d root files were read, more than the %d that a refusal needs", read, bound)
			}
			if n > bound && read != 0 {
				t.Errorf("%d root files were read of a folder of %d", read, n)
			}
			if n <= bound && read != n {
				t.Errorf("%d root files were read of a folder of %d", read, n)
			}
			if want := fmt.Sprintf("%d root files", n); !strings.Contains(err.Error(), want) {
				t.Errorf("the text %q does not say %q", err, want)
			}
			first, second := strings.Index(err.Error(), "want/roots/r0000.yaml"), strings.Index(err.Error(), "want/roots/r0001.yaml")
			if first < 0 || second < 0 {
				t.Errorf("the text %q does not name the first two files", err)
			} else if first > second {
				t.Errorf("the text %q names the files in another order than their names", err)
			}
		})
	}
}

func TestTheRefusalOfManyRootFilesWritesNothingAndIsTheSameTwice(t *testing.T) {
	dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings})
	for i := range 20 {
		p := filepath.Join(dir, "want", "roots", efRootName(i)+".yaml")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(pfX509Test), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := tree(t, dir)
	_, err1 := pfFind(t, dir)
	_, err2 := pfFind(t, dir)
	if err1 == nil || err2 == nil || err1.Error() != err2.Error() {
		t.Errorf("Find = %v and %v", err1, err2)
	}
	sameTree(t, "Find", before, tree(t, dir))
}

// What a root file holds does not change the refusal of a bundle of many: no byte is read.
func TestTheRootFilesOfABundleOfManyAreNeverReadWhateverTheyHold(t *testing.T) {
	m := efMemBundle(12, []byte(pfX509Test))
	for i, text := range []string{
		"", "not yaml {", pfOpenPGPTest, pfSSHTest, pfX509Real, "version: 1\nkind: nonsense\n", "\xff\xfe\x00",
	} {
		m.put("want/roots/"+efRootName(i)+".yaml", &pfNode{kind: "file", data: []byte(text)})
	}
	m.put("want/roots/"+efRootName(11)+".yaml", &pfNode{kind: "file", long: true})
	m.put("want/roots/"+efRootName(10)+".yaml", &pfNode{kind: "file", readErr: errors.New("this file cannot be read")})
	f, reads, err := efFind(t, pfFS{m})
	if f != nil || err == nil || pfKind(err) != "not-built" || !strings.Contains(err.Error(), "12 root files") {
		t.Fatalf("Find = %+v, %v (%s)", f, err, pfKind(err))
	}
	if reads.under("want/roots") != 0 {
		t.Errorf("%d root files were read", reads.under("want/roots"))
	}
}

// A bundle of many root files is refused at the place of the "not built" refusal, so what comes
// before it in the order still comes first: wanted files, failing findings of the history, an open
// attempt, a bundle that is not first.
func TestABundleOfManyRootFilesKeepsTheOrderOfTheRefusals(t *testing.T) {
	manyRoots := func(t *testing.T, dir string) {
		t.Helper()
		for i := 1; i < 12; i++ {
			p := filepath.Join(dir, "want", "roots", efRootName(i)+".yaml")
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(pfX509Test), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("nothing else is wrong: not built", func(t *testing.T) {
		dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings, "want/roots/r0000.yaml": pfX509Test})
		manyRoots(t, dir)
		if _, err := pfFind(t, dir); pfKind(err) != "not-built" || !strings.Contains(err.Error(), "12 root files") {
			t.Errorf("Find = %v (%s)", err, pfKind(err))
		}
	})
	t.Run("a settings file that fails comes first", func(t *testing.T) {
		dir := pfWrite(t, map[string]string{"ritueel.yaml": "version: 1\nname: Example\nnonsense: 1\n", "want/roots/r0000.yaml": pfX509Test})
		manyRoots(t, dir)
		_, err := pfFind(t, dir)
		if pfKind(err) != "failure" || !strings.Contains(err.Error(), "ritueel.yaml") {
			t.Errorf("Find = %v (%s), want a failure that names ritueel.yaml", err, pfKind(err))
		}
	})
	t.Run("a name of another form comes first, and is named", func(t *testing.T) {
		dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings, "want/roots/r0000.yaml": pfX509Test, "want/roots/BAD.yaml": pfX509Test})
		manyRoots(t, dir)
		_, err := pfFind(t, dir)
		if pfKind(err) != "failure" || !strings.Contains(err.Error(), "want/roots/BAD.yaml") {
			t.Errorf("Find = %v (%s), want a failure that names want/roots/BAD.yaml", err, pfKind(err))
		}
	})
	t.Run("a delegation that fails comes first, though the roots are not read", func(t *testing.T) {
		dir := pfWrite(t, map[string]string{
			"ritueel.yaml":                   pfSettings,
			"want/roots/r0000.yaml":          pfX509Test,
			"want/delegations/acme-tls.yaml": "version: 1\ntype: nonsense\n",
		})
		manyRoots(t, dir)
		_, err := pfFind(t, dir)
		if pfKind(err) != "failure" || !strings.Contains(err.Error(), "want/delegations/acme-tls.yaml") {
			t.Errorf("Find = %v (%s), want a failure that names the delegation", err, pfKind(err))
		}
	})
	t.Run("a failing history comes before not built", func(t *testing.T) {
		dir := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings, "want/roots/r0000.yaml": pfX509Test})
		manyRoots(t, dir)
		if err := os.MkdirAll(filepath.Join(dir, "history"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/", filepath.Join(dir, "history", name1)); err != nil {
			t.Fatal(err)
		}
		want := pfHistoryReasons(t, dir)
		_, err := pfFind(t, dir)
		var refused *ceremony.RefusedError
		if !errors.As(err, &refused) || !slices.Equal(refused.Reasons, want) {
			t.Errorf("Find = %v (%s), want the refusal with the reasons %q", err, pfKind(err), want)
		}
	})
	t.Run("an open attempt comes before not built", func(t *testing.T) {
		b := pfRecorded(t)
		for i := 1; i < 12; i++ {
			if err := os.WriteFile(b.path("want", "roots", efRootName(i)+".yaml"), []byte(pfX509Test), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		newFlow(t, b, newSpec(name1, 1, "")).must("start")
		_, err := pfFind(t, b.dir)
		var refused *ceremony.RefusedError
		if !errors.As(err, &refused) || !slices.Equal(refused.Reasons, []string{"unfinished-ceremony"}) {
			t.Errorf("Find = %v (%s), want the refusal of an open attempt", err, pfKind(err))
		}
	})
	t.Run("a bundle that is not first comes before not built", func(t *testing.T) {
		b := pfRecorded(t)
		for i := 1; i < 12; i++ {
			if err := os.WriteFile(b.path("want", "roots", efRootName(i)+".yaml"), []byte(pfX509Test), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		newFlow(t, b, newSpec(name1, 1, "")).must("")
		_, err := pfFind(t, b.dir)
		if pfKind(err) != "not-first" {
			t.Errorf("Find = %v (%s), want not-first", err, pfKind(err))
		}
	})
}

// A root file that fails its own check is a failure when the bundle has few root files, and, because
// none is read, is not looked at when the bundle has many: both end in an exit code 1 and no plan.
func TestARootFileThatFailsItsCheckIsNamedOnlyWhenTheFilesAreFew(t *testing.T) {
	few := pfWrite(t, map[string]string{"ritueel.yaml": pfSettings, "want/roots/a.yaml": "version: 1\nkind: nonsense\n"})
	if _, err := pfFind(t, few); pfKind(err) != "failure" || !strings.Contains(err.Error(), "want/roots/a.yaml") {
		t.Errorf("Find = %v (%s), want a failure that names the file", err, pfKind(err))
	}
	m := efMemBundle(30, []byte(pfX509Test))
	m.put("want/roots/"+efRootName(0)+".yaml", &pfNode{kind: "file", data: []byte("version: 1\nkind: nonsense\n")})
	f, _, err := efFind(t, pfFS{m})
	if f != nil || err == nil || pfKind(err) != "not-built" {
		t.Errorf("Find = %+v, %v (%s)", f, err, pfKind(err))
	}
}

// No bundle that was valid gives another result: the Found and the plan bytes are those of a bundle
// that has no other files, and the golden plan is unchanged.
func TestABundleThatWasValidGivesTheSamePlanBytesAsBefore(t *testing.T) {
	plain := pfPlan(t, pfFiles())
	if string(plain.JSON) != pfGolden || plain.SHA256 != pfGoldenDigest {
		t.Fatalf("the plan of the first-apply bundle is not the golden plan:\n%s", plain.JSON)
	}
	withMore := pfFiles()
	withMore["want/delegations/acme-tls.yaml"] = "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_dns_names: [example.org]\npermitted_uri_hosts: [example.org]\n"
	withMore["want/delegations/acme-web.yaml"] = "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_dns_names: [example.org]\npermitted_uri_hosts: [example.org]\n"
	withMore["README"] = "x"
	withMore["want/other/thing.yaml"] = "not yaml {"
	got := pfPlan(t, withMore)
	if string(got.JSON) != pfGolden || got.SHA256 != pfGoldenDigest || got.Prefix != pfGoldenDigest[:8] {
		t.Errorf("a bundle with delegation files and other files gives another plan:\n%s", got.JSON)
	}
	// The same bundle in memory and on the disk gives the same Found.
	a := pfMustFind(t, pfFiles())
	m := pfMem(pfFiles())
	b, err := ceremony.Find(context.Background(), ceremony.FindInput{FS: pfFS{m}})
	if err != nil || len(a.Wanted) != len(b.Wanted) {
		t.Fatalf("Find in memory = %+v, %v", b, err)
	}
	for i := range a.Wanted {
		if a.Wanted[i].Path != b.Wanted[i].Path || a.Wanted[i].SHA256 != b.Wanted[i].SHA256 {
			t.Errorf("Wanted[%d] differs between the disk and the memory", i)
		}
	}
	// A bundle of up to the few root files still names the root it refuses (the text before the fix).
	two := pfFiles()
	two["want/roots/other.yaml"] = pfX509Test
	_, err = pfFind(t, pfWrite(t, two))
	for _, w := range []string{"2 root files", "want/roots/other.yaml", "want/roots/x509.yaml", "nothing was written"} {
		if err == nil || !strings.Contains(err.Error(), w) {
			t.Errorf("Find of two root files = %v, want it to hold %q", err, w)
		}
	}
}

// Delegation files are checked one at a time and none is kept: a thousand valid ones pass, each is
// read once, and a thousand and one are refused by their number before any is read.
func TestAThousandDelegationFilesAreEachReadOnceAndNoneIsUsed(t *testing.T) {
	const deleg = "version: 1\ntype: x509-intermediate\nroot: x509\npermitted_dns_names: [example.org]\npermitted_uri_hosts: [example.org]\n"
	m := pfMem(pfFiles())
	for i := range wanted.MaxFiles {
		m.put(fmt.Sprintf("want/delegations/d%04d.yaml", i), &pfNode{kind: "file", data: []byte(deleg)})
	}
	f, reads, err := efFind(t, pfFS{m})
	if err != nil || f.Nothing() || len(f.Wanted) != 2 {
		t.Fatalf("Find = %+v, %v", f, err)
	}
	for i := range wanted.MaxFiles {
		if n := reads.of(fmt.Sprintf("want/delegations/d%04d.yaml", i)); n != 1 {
			t.Fatalf("delegation %d was read %d times", i, n)
		}
	}
	m.put("want/delegations/d1000.yaml", &pfNode{kind: "file", data: []byte(deleg)})
	f, reads, err = efFind(t, pfFS{m})
	if f != nil || err == nil || !strings.Contains(err.Error(), "want/delegations") {
		t.Fatalf("Find of %d delegations = %+v, %v", wanted.MaxFiles+1, f, err)
	}
	if reads.under("want/delegations") != 0 {
		t.Errorf("%d delegation files were read of a folder that is refused by its number", reads.under("want/delegations"))
	}
}

func TestADelegationThatFailsIsNamedWhenTheRootFilesAreFewAndWhenManyAlike(t *testing.T) {
	for _, n := range []int{1, 20} {
		t.Run(fmt.Sprintf("%d root files", n), func(t *testing.T) {
			m := efMemBundle(n, []byte(pfX509Test))
			m.put("want/delegations/acme-tls.yaml", &pfNode{kind: "file", data: []byte("version: 1\ntype: nonsense\n")})
			f, _, err := efFind(t, pfFS{m})
			if f != nil || err == nil || !strings.Contains(err.Error(), "want/delegations/acme-tls.yaml") || pfKind(err) != "failure" {
				t.Errorf("Find = %+v, %v (%s)", f, err, pfKind(err))
			}
		})
	}
}
