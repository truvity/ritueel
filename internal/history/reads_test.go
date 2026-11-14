//go:build linux || darwin

package history

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// What the check reads, what it never reads, and that it changes nothing.

// everyKindOfFault builds a bundle with a finding of most of the codes.
func everyKindOfFault(t *testing.T) *bundle {
	t.Helper()
	b := newBundle(t)
	a := b.apply()
	b2 := b.apply()
	b.apply(prev(a.digest))                                                    // a fork
	b.apply(noSet, recordAs(func(c []byte) []byte { return append(c, '\n') })) // not canonical
	b.apply(noSet, recordAs(func([]byte) []byte { return []byte(`{"version":2}`) }))
	b.apply(noSet, recordAs(func([]byte) []byte { return []byte(`{"version":1}`) }))
	b.put("history/"+b2.folder+"/transcript.txt", []byte("changed"))
	b.remove("trust/" + a.set + "/keys.txt")
	b.put("trust/"+b2.set+"/keys.txt", []byte("changed"))
	b.unfinished()
	b.mkdir("trust/99-aaaaaaaa")
	b.mkdir("history/a b")
	b.put("history/stray.txt", []byte("x"))
	b.mkdir("history/.rt-abcdefghijk")
	return b
}

func TestCheckMakesNoCallThatChangesAnything(t *testing.T) {
	for name, build := range map[string]func(*testing.T) *bundle{
		"a clean bundle":                      func(t *testing.T) *bundle { b, _ := threeRecords(t); return b },
		"a bundle with a fault of most codes": everyKindOfFault,
		"an empty bundle":                     func(t *testing.T) *bundle { return newBundle(t) },
	} {
		t.Run(name, func(t *testing.T) {
			b := build(t)
			before := tree(t, b.dir)
			rep, log := b.runSpied()
			if len(log.changes) != 0 {
				t.Errorf("calls that change the bundle: %v", log.changes)
			}
			if len(log.reads) == 0 && name != "an empty bundle" {
				t.Error("the spy saw no read: a check that reads nothing proves nothing")
			}
			after := tree(t, b.dir)
			if len(before) != len(after) {
				t.Errorf("the bundle holds %d files before and %d after", len(before), len(after))
			}
			for p, w := range before {
				if after[p] != w {
					t.Errorf("%s changed", p)
				}
			}
			checkForm(t, rep)
		})
	}
}

func TestCheckOfAFaultyBundleSeesTheFaults(t *testing.T) {
	// The bundle of the test above is not clean: a check that finds nothing is a failed check.
	rep := everyKindOfFault(t).run()
	// No ceremony of everyKindOfFault is an unfinished one: the history has two ends, so no plan
	// names the end it was made against.
	for _, c := range []Code{Fork, RecordNotCanonical, RecordVersionUnknown, RecordInvalid, TranscriptDigest, FileDigest, FileMissing, TrustSetUnlisted, UnexpectedName, UnexpectedFile} {
		found := false
		for _, f := range rep.Findings {
			found = found || f.Code == c
		}
		if !found {
			t.Errorf("no finding of code %s", c)
		}
	}
}

// The check reads the files of a clean bundle and nothing else: no file outside the lists of a
// record, no journal, no file of the person, and nothing of the trace area.
func TestCheckReadsOnlyTheFilesOfTheBundleThatItChecks(t *testing.T) {
	b, r := threeRecords(t)
	// Files that are there and must not be read.
	b.put("want/ritueel.yaml", []byte("wanted\n"))
	b.put("want/cards/root-a.yaml", []byte("wanted\n"))
	b.put("trace/area.bin", []byte("trace"))
	b.put("trace/records/000001", []byte("trace"))
	b.put("requests/alice/alice.csr", []byte("csr"))
	b.put("README.md", []byte("hello"))
	for _, c := range r {
		b.put("history/"+c.folder+"/births.jsonl", []byte("this is not a journal\n"))
		b.put("history/"+c.folder+"/signatures.jsonl", []byte("nor is this\n"))
	}
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	allowed := map[string]bool{}
	for _, c := range r {
		for _, f := range []string{"record.json", "transcript.txt", "plan.json", "wanted/ritueel.yaml"} {
			allowed["history/"+c.folder+"/"+f] = true
		}
		allowed["trust/"+c.set+"/keys.txt"] = true
		allowed["trust/"+c.set+"/root-list.json"] = true
	}
	for p := range log.reads {
		if !allowed[p] {
			t.Errorf("the check read %s", p)
		}
	}
	for p := range allowed {
		if log.reads[p] == 0 {
			t.Errorf("the check did not read %s", p)
		}
	}
	// The folders it lists are the history, its ceremony folders and the trust folder; no other.
	// It also lists the folder of each listed trust set and of the copies of each record, to see
	// what no record lists; it reads none of what it lists there.
	okList := map[string]bool{".": true, "history": true, "trust": true}
	for _, c := range r {
		okList["history/"+c.folder] = true
		okList["history/"+c.folder+"/wanted"] = true
		okList["trust/"+c.set] = true
	}
	for p := range log.lists {
		if !okList[p] {
			t.Errorf("the check listed %s", p)
		}
	}
}

func TestCheckReadsTheAttemptAndThePlanOfAnUnfinishedCeremonyAndNothingMore(t *testing.T) {
	b := newBundle(t)
	b.apply()
	u := b.unfinished()
	b.put("history/"+u.folder+"/births.jsonl", []byte("x"))
	b.put("history/"+u.folder+"/signatures.jsonl", []byte("x"))
	_, log := b.runSpied()
	for _, f := range []string{"attempt.json", "plan.json"} {
		if log.reads["history/"+u.folder+"/"+f] == 0 {
			t.Errorf("%s of the unfinished ceremony was not read", f)
		}
	}
	for _, f := range []string{"births.jsonl", "signatures.jsonl", "transcript.txt", "wanted/ritueel.yaml"} {
		if log.reads["history/"+u.folder+"/"+f] != 0 {
			t.Errorf("%s of the unfinished ceremony was read", f)
		}
	}
}

func TestPathListedManyTimesIsReadOnce(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		r.artifacts["a.txt"] = []byte("one file")
		r.refresh()
		entry := r.record.Artifacts[0]
		r.record.Artifacts = nil
		for i := 0; i < 2000; i++ {
			r.record.Artifacts = append(r.record.Artifacts, entry)
		}
	})
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	if n := log.reads["a.txt"]; n != 1 {
		t.Errorf("a.txt, listed 2000 times, was read %d times, want once", n)
	}
	// Listed with a wrong digest 2000 times: still one read, and the findings stay few.
	b2 := newBundle(t)
	b2.apply(noSet, func(r *rec) {
		r.artifacts["a.txt"] = []byte("one file")
		r.refresh()
		entry := r.record.Artifacts[0]
		entry.SHA256 = digestA
		r.record.Artifacts = nil
		for i := 0; i < 2000; i++ {
			r.record.Artifacts = append(r.record.Artifacts, entry)
		}
	})
	rep2, log2 := b2.runSpied()
	if n := log2.reads["a.txt"]; n != 1 {
		t.Errorf("a.txt with a wrong digest, listed 2000 times, was read %d times, want once", n)
	}
	if n := len(rep2.Findings); n < 1 || n > MaxFindingsPerCode {
		t.Errorf("%d findings for a path that is listed 2000 times", n)
	}
	has(t, rep2, FileDigest, "a.txt")
}

func TestPathListedByManyRecordsIsReadOnce(t *testing.T) {
	b := newBundle(t)
	for i := 0; i < 20; i++ {
		b.apply(noSet, func(r *rec) {
			r.artifacts["common.txt"] = []byte("one file")
			r.refresh()
		})
	}
	rep, log := b.runSpied()
	wantFindings(t, rep, nil)
	if n := log.reads["common.txt"]; n != 1 {
		t.Errorf("common.txt, listed by 20 records, was read %d times, want once", n)
	}
}

// A record lists a path with a digest. A path outside the bundle is never read, and a file outside
// the bundle that would give the digest is never taken for it.
func TestNoPathOutsideTheBundleIsReadNorUsed(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(base+"/canary.txt", []byte("the canary\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := &bundle{t: t, dir: base + "/bundle"}
	if err := os.Mkdir(b.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b.put("ritueel.yaml", []byte("name: test\n"))
	b.mkdir("history")
	canary := sha256Hex("the canary\n")
	hostile := []string{"../canary.txt", "/" + strings.TrimPrefix(base, "/") + "/canary.txt", "a/../../canary.txt", "x/../../canary.txt", "./../canary.txt", "..", "a/..", "%2e%2e/canary.txt", "..\\canary.txt"}
	for _, p := range hostile {
		b.apply(noSet, func(r *rec) { r.record.Artifacts = []files.FileRef{{Path: p, SHA256: canary}} })
	}
	rep, log := b.runSpied()
	for _, r := range b.recs {
		has(t, rep, RecordInvalid, recordPath(r))
	}
	for p := range log.reads {
		if strings.Contains(p, "canary") || strings.Contains(p, "..") || strings.HasPrefix(p, "/") {
			t.Errorf("the check read %q", p)
		}
	}
	for p := range log.opens {
		if strings.Contains(p, "canary") || strings.Contains(p, "..") || strings.HasPrefix(p, "/") || strings.Contains(p, "%") {
			t.Errorf("the check opened %q", p)
		}
	}
	if len(log.changes) != 0 {
		t.Errorf("changes: %v", log.changes)
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// A link in the bundle that points at a file outside it is not followed: the file outside has the
// right digest and is still not taken for the listed file.
func TestLinkToAFileOutsideTheBundleIsNotFollowed(t *testing.T) {
	base := t.TempDir()
	b := &bundle{t: t, dir: base + "/bundle"}
	if err := os.Mkdir(b.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b.put("ritueel.yaml", []byte("name: test\n"))
	b.mkdir("history")
	r := b.apply(noSet, func(r *rec) {
		r.artifacts["a.txt"] = []byte("outside\n")
		r.refresh()
	})
	b.remove("a.txt")
	if err := os.WriteFile(base+"/outside.txt", []byte("outside\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b.symlink("../outside.txt", "a.txt")
	rep := b.run()
	wantFindings(t, rep, []wf{{FileDigest, "a.txt"}})
	_ = r
	// The same for the transcript.
	b.remove("a.txt")
	b.put("a.txt", []byte("outside\n"))
	b.remove("history/" + r.folder + "/transcript.txt")
	if err := os.WriteFile(base+"/transcript.txt", r.transcript, 0o644); err != nil {
		t.Fatal(err)
	}
	b.symlink("../../../transcript.txt", "history/"+r.folder+"/transcript.txt")
	rep = b.run()
	// A name that the folder expects, as a link: the page does not say whether it is also noticed.
	wantFindings(t, rep, []wf{{FileDigest, "history/" + r.folder + "/transcript.txt"}}, UnexpectedFile)
}

// The limits that a test can lower. The values of the three constants are not tested; that the run
// stops at the limit, to the byte, and says so, is.

// readTotal is the number of bytes the check reads from the bundle, counted by a spy.
type countingFS struct {
	fsx.FS
	n *int64
}

func (c countingFS) OpenDir(name string) (fsx.FS, error) {
	d, err := c.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return countingFS{d, c.n}, nil
}

func (c countingFS) ReadFile(name string) ([]byte, error) {
	data, err := c.FS.ReadFile(name)
	*c.n += int64(len(data))
	return data, err
}

func readTotal(t *testing.T, b *bundle) int64 {
	t.Helper()
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	var n int64
	if _, err := runFS(t, countingFS{root, &n}, nil); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRunStopsWhenItWouldReadMoreBytesThanTheLimit(t *testing.T) {
	b, _ := threeRecords(t)
	total := readTotal(t, b)
	if total == 0 {
		t.Fatal("the check read nothing")
	}
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	base := limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode}
	// Exactly the bytes it reads is enough; one byte less is too little.
	l := base
	l.readBytes = total
	rep, err := runFS(t, root, &l)
	if err != nil {
		t.Fatalf("a limit of %d bytes, which is what the run reads: %v", total, err)
	}
	wantFindings(t, rep, nil)
	l.readBytes = total - 1
	rep, err = runFS(t, root, &l)
	if !errors.Is(err, ErrTooMuch) {
		t.Fatalf("a limit of %d bytes: err = %v, want ErrTooMuch", total-1, err)
	}
	if rep != nil {
		t.Errorf("a report comes with the error: %+v", rep)
	}
	for _, n := range []int64{0, 1} {
		l.readBytes = n
		if _, err := runFS(t, root, &l); !errors.Is(err, ErrTooMuch) {
			t.Errorf("a limit of %d bytes: err = %v, want ErrTooMuch", n, err)
		}
	}
}

func TestRunStopsWhenItWouldListMoreFilesThanTheLimit(t *testing.T) {
	b, _ := threeRecords(t)
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	// Each of the three records lists its transcript, its plan, one wanted copy and two artifacts.
	const distinct = 3 * 5
	l := limits{readBytes: MaxReadBytes, fileReads: distinct, perCode: MaxFindingsPerCode}
	rep, err := runFS(t, root, &l)
	if err != nil {
		t.Fatalf("a limit of %d files, which is what the bundle lists: %v", distinct, err)
	}
	wantFindings(t, rep, nil)
	l.fileReads = distinct - 1
	rep, err = runFS(t, root, &l)
	if !errors.Is(err, ErrTooMuch) {
		t.Fatalf("a limit of %d files: err = %v, want ErrTooMuch", distinct-1, err)
	}
	if rep != nil {
		t.Errorf("a report comes with the error: %+v", rep)
	}
	l.fileReads = 0
	if _, err := runFS(t, root, &l); !errors.Is(err, ErrTooMuch) {
		t.Errorf("a limit of 0 files: err = %v, want ErrTooMuch", err)
	}
}

func TestRunKeepsAtMostTheLimitOfFindingsOfEachCodeAndCountsTheRest(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		for i := 0; i < 7; i++ {
			r.artifacts[fmt.Sprintf("m/f%d", i)] = []byte{byte(i)}
		}
		r.refresh()
	})
	b.mkdir("history/a b")
	b.mkdir("history/c d")
	for i := 0; i < 7; i++ {
		b.remove(fmt.Sprintf("m/f%d", i))
	}
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	l := limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: 3}
	rep, err := runFS(t, root, &l)
	if err != nil {
		t.Fatal(err)
	}
	n := map[Code]int{}
	for _, f := range rep.Findings {
		n[f.Code]++
	}
	if n[FileMissing] != 3 || n[UnexpectedName] != 2 {
		t.Errorf("kept %v, want 3 file-missing and 2 unexpected-name", n)
	}
	if rep.Omitted != 4 {
		t.Errorf("Omitted = %d, want 4", rep.Omitted)
	}
	// A code that has findings left out is still in the reasons.
	wantReasons(t, rep, []Code{FileMissing, UnexpectedName}, nil)
	if rep.Clean() {
		t.Error("Clean() = true for a report that left findings out")
	}
}

func TestFindingsOfAFolderOfStrayFilesAreBoundedAndTheRestIsCounted(t *testing.T) {
	if testing.Short() {
		t.Skip("makes 65,536 files")
	}
	b := newBundle(t)
	b.apply(noSet)
	const strays = fsx.MaxDirEntries - 1 // the ceremony folder is the other entry of history/
	for i := 0; i < strays; i++ {
		f, err := os.Create(fmt.Sprintf("%s/history/f%05d", b.dir, i))
		if err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	rep := b.run()
	if len(rep.Findings) > MaxFindingsPerCode {
		t.Errorf("%d findings of one code are kept, more than MaxFindingsPerCode = %d", len(rep.Findings), MaxFindingsPerCode)
	}
	if got := len(rep.Findings) + rep.Omitted; got != strays {
		t.Errorf("kept and omitted findings add up to %d, want %d", got, strays)
	}
	wantReasons(t, rep, nil, []Code{UnexpectedFile})
	if !rep.Clean() {
		t.Error("stray files are notices: the history is clean")
	}
}

func TestFolderOf65537EntriesIsNotChecked(t *testing.T) {
	if testing.Short() {
		t.Skip("makes 65,537 files")
	}
	for _, place := range []string{"history", "trust", "ceremony"} {
		t.Run(place, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet)
			dir := map[string]string{"history": "history", "trust": "trust", "ceremony": "history/" + r.folder}[place]
			b.mkdir(dir)
			existing, err := os.ReadDir(b.abs(dir))
			if err != nil {
				t.Fatal(err)
			}
			for i := len(existing); i < fsx.MaxDirEntries+1; i++ {
				f, err := os.Create(fmt.Sprintf("%s/f%05d", b.abs(dir), i))
				if err != nil {
					t.Fatal(err)
				}
				_ = f.Close()
			}
			rep, err := runDirErr(t, b.dir)
			if !errors.Is(err, fsx.ErrTooMany) {
				t.Fatalf("err = %v, want one that wraps fsx.ErrTooMany", err)
			}
			if rep != nil {
				t.Error("a report comes with the error")
			}
			if !printable(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII: %q", err)
			}
		})
	}
}

func TestContextThatEndedStopsTheRun(t *testing.T) {
	b, _ := threeRecords(t)
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rep, err := Check(ctx, root)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if rep != nil {
		t.Error("a report comes with the error")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel2()
	time.Sleep(time.Millisecond)
	if _, err := Check(ctx2, root); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

func TestCheckOfNothingIsAnErrorAndNotAPanic(t *testing.T) {
	rep, err := Check(context.Background(), nil)
	if err == nil || rep != nil {
		t.Errorf("Check(nil) = %v, %v", rep, err)
	}
}

// A chain of 2,000 records is checked in a time that grows about linearly with the number of
// records. No absolute time is asserted, which would flake: 4 times the records must take under
// 8 times as long, with the best of three runs for each size and a little slack for the timer.
func TestTimeGrowsAboutLinearlyWithTheLengthOfTheChain(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 2,500 records")
	}
	timeOf := func(n int) time.Duration {
		b := newBundle(t)
		for i := 0; i < n; i++ {
			b.apply(noSet)
		}
		best := time.Hour
		for i := 0; i < 3; i++ {
			start := time.Now()
			rep := b.run()
			if d := time.Since(start); d < best {
				best = d
			}
			if rep.Records != n || !rep.Clean() {
				t.Fatalf("n = %d: Records = %d, clean = %v", n, rep.Records, rep.Clean())
			}
		}
		return best
	}
	small, large := timeOf(500), timeOf(2000)
	t.Logf("500 records: %v, 2000 records: %v", small, large)
	if large > 8*small+20*time.Millisecond {
		t.Errorf("2000 records took %v, more than 8 times the %v of 500", large, small)
	}
}

// Reading is through fsx only: a file that is too long, a link and a FIFO are never read.
func TestReadsOfLongFilesLinksAndFIFOsAreRefusedByTheLayerBelow(t *testing.T) {
	b := newBundle(t)
	b.apply(noSet, func(r *rec) {
		r.artifacts["big.bin"] = nil
		r.artifacts["link.txt"] = nil
		r.artifacts["fifo"] = nil
		r.artifacts["dir"] = nil
		r.refresh()
	})
	for _, p := range []string{"big.bin", "link.txt", "fifo", "dir"} {
		b.remove(p)
	}
	b.sparse("big.bin", fsx.MaxReadSize+1)
	b.symlink("ritueel.yaml", "link.txt")
	b.fifo("fifo")
	b.mkdir("dir")
	rep := b.run()
	wantFindings(t, rep, []wf{{FileDigest, "big.bin"}, {FileDigest, "link.txt"}, {FileDigest, "fifo"}, {FileDigest, "dir"}})
}

// The same limit on folders as on the disk, in memory, so that it runs under -short too.
func TestFolderOf65537NamesInMemoryIsNotChecked(t *testing.T) {
	for _, place := range []string{"history", "trust", "ceremony"} {
		t.Run(place, func(t *testing.T) {
			b := newBundle(t)
			r := b.apply(noSet)
			m := loadMem(t, b.dir)
			dir := map[string]string{"history": "history", "trust": "trust", "ceremony": "history/" + r.folder}[place]
			if m.get(dir) == nil {
				m.put(dir, newMem())
			}
			for i := len(m.get(dir).kids); i < fsx.MaxDirEntries+1; i++ {
				m.file(fmt.Sprintf("%s/f%05d", dir, i), "")
			}
			rep, err := runMem(t, m)
			if !errors.Is(err, fsx.ErrTooMany) {
				t.Fatalf("err = %v, want one that wraps fsx.ErrTooMany", err)
			}
			if rep != nil {
				t.Error("a report comes with the error")
			}
		})
	}
	// 65,536 is the longest folder that is listed.
	b := newBundle(t)
	r := b.apply(noSet)
	m := loadMem(t, b.dir)
	dir := "history/" + r.folder
	for i := len(m.get(dir).kids); i < fsx.MaxDirEntries; i++ {
		m.file(fmt.Sprintf("%s/f%05d", dir, i), "")
	}
	rep, err := runMem(t, m)
	if err != nil {
		t.Fatalf("a folder of %d names: %v", fsx.MaxDirEntries, err)
	}
	if rep.Records != 1 || len(rep.Findings)+rep.Omitted == 0 {
		t.Errorf("Records = %d, findings %d, omitted %d", rep.Records, len(rep.Findings), rep.Omitted)
	}
}

// The same bundle gives the same report on every run: the order of a listing, of a map and of the
// goroutines of the run does not show.
func TestReportIsTheSameOnEveryRun(t *testing.T) {
	b := everyKindOfFault(t)
	first := b.run()
	for i := 0; i < 5; i++ {
		again := b.run()
		if fmt.Sprint(again.Findings, again.Ends, again.Records, again.Omitted) != fmt.Sprint(first.Findings, first.Ends, first.Records, first.Omitted) {
			t.Fatalf("run %d differs:\n%v\n%v", i+2, again.Findings, first.Findings)
		}
	}
}
