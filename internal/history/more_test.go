//go:build linux || darwin

package history

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// Tests that came from breaking the code on purpose: each holds a rule that no other test held.

// A folder that is not a bundle and cannot be read is a read error, not "not a bundle".
func TestRootFolderThatCannotBeListedIsAReadErrorAndNotAFolderThatIsNoBundle(t *testing.T) {
	m := newMem()
	m.readErr = fs.ErrPermission
	rep, err := runMem(t, m)
	if err == nil || rep != nil {
		t.Fatalf("Check = %v, %v", rep, err)
	}
	if !errors.Is(err, fs.ErrPermission) || errors.Is(err, ErrNotBundle) {
		t.Errorf("err = %v, want a refused permission and not ErrNotBundle", err)
	}
}

func TestOtherFileThanTheManifestDoesNotMakeABundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/README.md", []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/ritueel.yaml.bak", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runDirErr(t, dir); !errors.Is(err, ErrNotBundle) {
		t.Errorf("err = %v, want ErrNotBundle", err)
	}
}

// The run looks at its context before each folder and each read.
func TestContextEndedBeforeTheRunStopsAnEmptyBundleToo(t *testing.T) {
	b := newBundle(t)
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rep, err := Check(ctx, root); !errors.Is(err, context.Canceled) || rep != nil {
		t.Errorf("Check = %v, %v; want context.Canceled", rep, err)
	}
}

// cancelAfterList ends the context when the folder trust/ has been listed, which is after the
// run listed history/ and before it walks the ceremony folders.
type cancelAfterList struct {
	fsx.FS
	here   string
	cancel context.CancelFunc
}

func (c cancelAfterList) OpenDir(name string) (fsx.FS, error) {
	d, err := c.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return cancelAfterList{d, name, c.cancel}, nil
}

func (c cancelAfterList) ReadDir() ([]fs.DirEntry, error) {
	ents, err := c.FS.ReadDir()
	if c.here == "trust" {
		c.cancel()
	}
	return ents, err
}

func TestContextEndedWhileTheCeremonyFoldersAreWalkedStopsTheRun(t *testing.T) {
	// Ceremony folders with no file to read: only the check of the context between folders sees it.
	b := newBundle(t)
	for i := 0; i < 3; i++ {
		b.mkdir(fmt.Sprintf("history/2026%04dT100000Z-apply", i+1))
	}
	b.mkdir("trust")
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rep, err := Check(ctx, cancelAfterList{root, "", cancel})
	if !errors.Is(err, context.Canceled) || rep != nil {
		t.Errorf("Check = %v, %v; want context.Canceled", rep, err)
	}
}

// A name that begins like the prefix of a temporary name, and is not one, is a name like any other:
// a ceremony folder with it is read.
func TestNamesThatOnlyLookLikeTheTemporaryPrefixAreReadAsCeremonyFolders(t *testing.T) {
	for _, name := range []string{"xrt-1", ".xt-1", ".rx-1", ".rt_1", "rt-1", ".r-t-1", "-rt-1", "art-x"} {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			b.apply(noSet, folderName(name))
			rep := b.run()
			wantFindings(t, rep, nil)
			if rep.Records != 1 {
				t.Errorf("Records = %d, want 1: %s is a name like any other", rep.Records, name)
			}
		})
	}
}

// Names shorter than the prefix of a temporary name that are the start of it: no read beyond the name.
func TestShortNamesThatStartLikeTheTemporaryPrefixAreNotTemporary(t *testing.T) {
	for _, name := range []string{".r", ".rt", ".R", ".RT", "x"} {
		for _, place := range []string{"history", "trust", "ceremony"} {
			t.Run(place+" "+name, func(t *testing.T) {
				b := newBundle(t)
				r := b.apply(noSet)
				dir := map[string]string{"history": "history", "trust": "trust", "ceremony": "history/" + r.folder}[place]
				b.put(dir+"/"+name, []byte("x"))
				rep := b.run()
				wantFindings(t, rep, []wf{{UnexpectedFile, dir + "/" + name}})
				if d := detail(rep, UnexpectedFile, dir+"/"+name); strings.Contains(d, "temporary") {
					t.Errorf("%s is called a temporary name: %s", name, d)
				}
			})
		}
	}
}

// A record of a version that is not known: nothing else about it is said, not even that its bytes
// are not canonical (the check does not know the canonical form of a version it cannot read).
func TestRecordOfAnUnknownVersionIsNotAlsoCalledNotCanonical(t *testing.T) {
	b := newBundle(t)
	r := b.apply(noSet, recordAs(func([]byte) []byte { return []byte("{ \"version\": 2,\n  \"b\": 1, \"a\": 2 }\n") }))
	rep := b.run()
	wantFindings(t, rep, []wf{{RecordVersionUnknown, recordPath(r)}}, RecordOffChain)
}

// Many copies of one record in a chain: the walk of the chain visits each record once, so a
// bundle that holds a record three times in each of 25 places is not 3^25 steps.
func TestChainOfRecordsThatAreCopiedManyTimesIsWalkedInLinearTime(t *testing.T) {
	b := newBundle(t)
	var all []*rec
	for i := 0; i < 25; i++ {
		all = append(all, b.apply(noSet))
	}
	// The first record has no predecessor and must stay the only one without: its copies would
	// be more of them, and the chain is not walked then.
	for _, r := range all[1:] {
		data := b.get("history/" + r.folder + "/record.json")
		for c := 0; c < 2; c++ {
			b.put(fmt.Sprintf("history/%s-copy%d/record.json", r.folder, c), data)
		}
	}
	start := time.Now()
	rep := b.run()
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("the run took %v", d)
	}
	if want := 25 + 2*24; rep.Records != want {
		t.Errorf("Records = %d, want %d", rep.Records, want)
	}
	// The copies of a record name the same predecessor, so each record that has copies is a fork.
	if rep.Clean() {
		t.Error("clean")
	}
	has(t, rep, Fork, folderPath(all[0]))
	// Every record is on the chain: no record is called off it.
	lacks(t, rep, RecordOffChain)
	lacks(t, rep, ChainBroken)
}

// The number a trust set's name begins with links a set to an open ceremony by the plan's
// trust_sequence.
func TestTrustSetIsLinkedToAnOpenCeremonyByTheNumberItsNameBeginsWith(t *testing.T) {
	linked := map[string]int64{
		"5-3fa9c1d2":    5,
		"10-3fa9c1d2":   10,
		"123-3fa9c1d2":  123,
		"1-a-b":         1, // the number is what stands before the first hyphen
		"99-3fa9c1d2":   99,
		"7-":            7,
		"1000-aaaa":     1000,
		"12345678-aaaa": 12345678,
	}
	for name, seq := range linked {
		t.Run("linked "+name, func(t *testing.T) {
			b := newBundle(t)
			u := b.unfinished(setName(name), func(r *rec) {
				r.plan.TrustSequence = ptr(seq)
				r.refresh()
			})
			rep := b.run()
			wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
		})
	}
	// A name that does not begin with a number is linked to no ceremony, even to one that says 0.
	for _, name := range []string{"x", "abc-def", "-0-x", "1a-x", "a1-x", "x-1", "12"} {
		t.Run("not linked "+name, func(t *testing.T) {
			b := newBundle(t)
			u := b.unfinished(setName(name), func(r *rec) {
				r.plan.TrustSequence = ptr(int64(0))
				r.refresh()
			})
			rep := b.run()
			has(t, rep, TrustSetUnlisted, setPath(u))
			lacks(t, rep, UnfinishedCeremony)
		})
	}
	// The sequence of the plan must be the number of the name.
	b := newBundle(t)
	u := b.unfinished(setName("5-3fa9c1d2"), func(r *rec) {
		r.plan.TrustSequence = ptr(int64(6))
		r.refresh()
	})
	has(t, b.run(), TrustSetUnlisted, setPath(u))
}

// The attempt or the plan of an open ceremony that cannot be read stops the check; so does the root
// list of a set that no record lists.
func TestUnreadableFilesOfAnOpenCeremonyAndOfAnUnlistedSetStopTheCheck(t *testing.T) {
	build := func(t *testing.T) (*mnode, *rec) {
		b := newBundle(t)
		b.apply()
		u := b.unfinished()
		return loadMem(t, b.dir), u
	}
	for _, f := range []string{"attempt.json", "plan.json"} {
		t.Run(f, func(t *testing.T) {
			m, u := build(t)
			m.get("history/" + u.folder + "/" + f).readErr = fs.ErrPermission
			rep, err := runMem(t, m)
			if !errors.Is(err, fs.ErrPermission) || rep != nil {
				t.Errorf("Check = %v, %v; want a refused permission", rep, err)
			}
		})
	}
	t.Run("root list of an unlisted set", func(t *testing.T) {
		m, u := build(t)
		m.get("trust/" + u.set + "/root-list.json").readErr = fs.ErrPermission
		rep, err := runMem(t, m)
		if !errors.Is(err, fs.ErrPermission) || rep != nil {
			t.Errorf("Check = %v, %v; want a refused permission", rep, err)
		}
	})
}

// A detail is kept whole up to 240 bytes and cut beyond.
func TestDetailOfAFindingIsKeptUpTo240BytesAndCutBeyond(t *testing.T) {
	c := newCollector(10)
	exact := strings.Repeat("d", 240)
	c.add(FileMissing, "a", exact)
	c.add(FileMissing, "b", exact+"d")
	c.add(FileMissing, "c", strings.Repeat("d", 1000))
	got := c.sorted()
	if got[0].Detail != exact {
		t.Errorf("a detail of 240 bytes is changed: %d bytes", len(got[0].Detail))
	}
	for _, f := range got[1:] {
		if len(f.Detail) >= 1000 || f.Detail == exact+"d" {
			t.Errorf("the detail of %s is not cut: %d bytes", f.Path, len(f.Detail))
		}
		if !strings.HasPrefix(f.Detail, exact) {
			t.Errorf("the cut detail of %s does not begin with the first 240 bytes", f.Path)
		}
	}
}

// More findings of one code than a report keeps: the report keeps the most it may of each code,
// says how many it left out, and its reasons are whole.
func TestMoreFindingsOfOneCodeThanAReportKeepsAreCounted(t *testing.T) {
	const want = MaxFindingsPerCode + 50
	b := newBundle(t)
	made := 0
	for made < want {
		n := min(400, want-made)
		from := made
		b.apply(noSet, func(r *rec) {
			for i := 0; i < n; i++ {
				// Listed with a digest and never written: each is a file that is missing.
				r.record.Artifacts = append(r.record.Artifacts, fileRef(fmt.Sprintf("gone/f%05d", from+i)))
			}
		})
		made += n
	}
	rep := b.run()
	missing := 0
	for _, f := range rep.Findings {
		if f.Code == FileMissing {
			missing++
		}
	}
	if missing != MaxFindingsPerCode {
		t.Errorf("%d findings of file-missing are kept, want MaxFindingsPerCode = %d", missing, MaxFindingsPerCode)
	}
	if rep.Omitted != want-MaxFindingsPerCode {
		t.Errorf("Omitted = %d, want %d", rep.Omitted, want-MaxFindingsPerCode)
	}
	wantReasons(t, rep, []Code{FileMissing}, nil)
	if rep.Clean() {
		t.Error("clean")
	}
	checkForm(t, rep)
}

func fileRef(path string) files.FileRef { return files.FileRef{Path: path, SHA256: digestA} }
