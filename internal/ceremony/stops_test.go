package ceremony_test

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// newBundleFailing makes a bundle whose writer fails its nth changing call.
func newBundleFailing(t *testing.T, n int) *bundle {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ritueel.yaml"), []byte(manifestText), 0o644); err != nil {
		t.Fatal(err)
	}
	return openBundle(t, dir, n)
}

// leftover reports whether a name that a cut leaves (a temporary name) is in the folder dir
// itself; a folder inside it is not looked into.
func leftover(t testing.TB, dir string) bool {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".rt-") {
			return true
		}
	}
	return false
}

// prefixOf fails when the folder that a cut left holds something that the whole run does not: a
// file that the whole run lacks or has with other bytes. A journal may be a prefix of the whole
// one, and a temporary name is a leftover of the cut.
func prefixOf(t testing.TB, cut, whole string) {
	t.Helper()
	err := filepath.WalkDir(cut, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(cut, p)
		if rel == "." {
			return nil
		}
		for _, e := range strings.Split(rel, string(filepath.Separator)) {
			if strings.HasPrefix(e, ".rt-") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		other := filepath.Join(whole, rel)
		st, err := os.Lstat(other)
		if err != nil {
			t.Errorf("the cut left %s, which the whole run does not have", rel)
			return nil
		}
		if d.IsDir() != st.IsDir() {
			t.Errorf("%s is a folder in one run and a file in the other", rel)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		a, _ := os.ReadFile(p)
		b, _ := os.ReadFile(other)
		if strings.HasSuffix(rel, ".jsonl") {
			if !bytes.HasPrefix(b, a) {
				t.Errorf("%s of the cut is not a prefix of the whole journal", rel)
			}
			return nil
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s of the cut is not the whole file", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// the first ceremony of a bundle, or the second after a whole first.
func prepare(t *testing.T, second bool, failAt int) (*bundle, *flow) {
	t.Helper()
	if !second {
		b := newBundleFailing(t, failAt)
		return b, newFlow(t, b, newSpec(name1, 1, ""))
	}
	b1 := newBundle(t)
	f1 := newFlow(t, b1, newSpec(name1, 1, ""))
	f1.must("")
	b := openBundle(t, b1.dir, failAt)
	return b, newFlow(t, b, newSpec(name2, 2, sum(f1.out)))
}

// A cut at every changing call of a whole ceremony: the first one and the one that follows it.
func TestACutAtEveryWriteLeavesWhatTheOrderLeaves(t *testing.T) {
	for _, second := range []bool{false, true} {
		name := "first ceremony"
		if second {
			name = "second ceremony"
		}
		t.Run(name, func(t *testing.T) {
			// The whole run counts the calls and gives the tree that every cut is a part of.
			wb, wfl := prepare(t, second, 0)
			wfl.must("")
			total := wb.r.count
			if total < 40 {
				t.Fatalf("a whole ceremony made only %d changing calls", total)
			}
			t.Logf("a whole ceremony makes %d changing calls", total)
			prior := 0
			if second {
				prior = 1
			}
			for k := 1; k <= total; k++ {
				t.Run(fmt.Sprintf("cut at call %d of %d", k, total), func(t *testing.T) {
					t.Parallel()
					b, fl := prepare(t, second, k)
					err := fl.run("")
					if err == nil {
						t.Fatalf("the cut at call %d did not stop the ceremony", k)
					}
					if !errors.Is(err, errCut) {
						t.Errorf("the error does not hold the failed write: %v", err)
					}
					failed := stageOf(err)
					// A write that the folder itself made and that failed stops the folder, at each of
					// its stages: the first Mkdir of history/ and of the ceremony folder included.
					if slices.Contains([]string{"plan", "start", "end", "transcript", "record"}, failed) && !errors.Is(err, ceremony.ErrFolderStopped) {
						t.Errorf("a write of stage %s was cut and the folder is not stopped: %v", failed, err)
					}
					if failed == "births" || failed == "signatures" {
						// A line that was cut: the journal says that the folder is stopped.
						if !errors.Is(err, ceremony.ErrFolderStopped) {
							t.Errorf("a journal line cut: %v, want an error that says the folder is stopped", err)
						}
					}
					// The writer is stopped for good.
					if err := b.w.Mkdir("elsewhere", 0o755); !errors.Is(err, fsx.ErrStopped) {
						t.Errorf("a write after the cut: %v, want fsx.ErrStopped", err)
					}
					after, events := tree(t, b.dir), b.r.mark()
					// Every later call of the folder is an error and reaches no file. When a write of the
					// folder itself failed, each of them says that the folder is stopped.
					broken := errors.Is(err, ceremony.ErrFolderStopped) && !slices.Contains([]string{"births", "signatures", "artifacts"}, failed)
					plan := fl.s.plan(t)
					for call, fn := range calls(t, fl.s, plan) {
						e := fn(fl.f)
						if e == nil {
							t.Errorf("%s succeeded after the cut", call)
							continue
						}
						if broken && (!errors.Is(e, ceremony.ErrFolderStopped) || !errors.Is(e, fsx.ErrStopped)) {
							t.Errorf("%s after the cut: %v, want an error that says the folder and the writer are stopped", call, e)
						}
					}
					if fl.tr != nil {
						for _, e := range []error{
							fl.tr.Births().Append(birthBytes(t, "Z", rep('d'))),
							fl.tr.Signatures().Append(sigBytes(t, 9, "root-list", rep('a'))),
						} {
							if e == nil {
								t.Error("a journal line was written after the cut")
							}
						}
					}
					if b.r.mark() != events {
						t.Errorf("calls after the cut reached the file system: %v", b.r.since(events))
					}
					sameTree(t, "the calls after the cut", after, tree(t, b.dir))
					// Nothing is deleted and nothing is half done but a temporary name.
					prefixOf(t, b.dir, wb.dir)

					// What the check of the history says of the state.
					rep := b.check()
					if f := rep.Failing(); len(f) != 0 {
						t.Errorf("history.Check finds %+v", f)
					}
					_, recordErr := os.Lstat(b.path("history", fl.s.name, "record.json"))
					haveRecord := recordErr == nil
					_, setErr := os.Lstat(b.path(filepath.FromSlash(fl.s.setName())))
					haveSet := setErr == nil
					wantRecords := prior
					if haveRecord {
						wantRecords++
					}
					if rep.Records != wantRecords {
						t.Errorf("the check counts %d records, want %d", rep.Records, wantRecords)
					}
					warns := codes(rep.Warnings())
					if want := haveSet && !haveRecord; slices.Contains(warns, "unfinished-ceremony") != want {
						t.Errorf("the notices are %v; unfinished-ceremony expected: %v (a set: %v, a record: %v)", warns, want, haveSet, haveRecord)
					}
					if leftover(t, b.path("history")) || leftover(t, b.path("trust")) || leftover(t, b.path("history", fl.s.name)) {
						if !slices.Contains(warns, "unexpected-file") {
							t.Errorf("a leftover name, and the notices are %v", warns)
						}
					}
					for _, w := range warns {
						if w != "unfinished-ceremony" && w != "unexpected-file" {
							t.Errorf("an unexpected notice %s", w)
						}
					}
				})
			}
		})
	}
}

// stageOf takes the name of the stage out of the error that flow.run made.
func stageOf(err error) string {
	s := err.Error()
	s = strings.TrimPrefix(s, "stage ")
	name, _, _ := strings.Cut(s, ":")
	return name
}

// With every write done, the check says what the page says.
func TestAWholeCeremonyIsRecordedAndClean(t *testing.T) {
	b, fl := prepare(t, false, 0)
	fl.must("")
	rep := b.check()
	if !rep.Clean() || len(rep.Findings) != 0 || rep.Records != 1 {
		t.Errorf("%+v", rep)
	}
}

// Two folders of two ceremonies on one writer, from two goroutines that start behind a closed
// channel: every call is whole and both ceremonies are written.
func TestTwoFoldersOnOneWriterFromTwoGoroutines(t *testing.T) {
	b := newBundle(t)
	mustMkdir(t, b.path("history"))
	mustMkdir(t, b.path("roots"))
	mustMkdir(t, b.path("trust"))
	flows := []*flow{newFlow(t, b, newSpec(name1, 1, "")), newFlow(t, b, newSpec(name2, 2, ""))}
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, len(flows))
	for i, fl := range flows {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fl.run("")
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("ceremony %d: %v", i+1, err)
		}
	}
	for _, fl := range flows {
		raw := fl.file("record.json")
		if !bytes.Equal(raw, fl.out) {
			t.Errorf("%s: record.json is not what Record returned", fl.s.name)
		}
		if _, err := os.Stat(fl.b.path("history", fl.s.name, "births.jsonl")); err != nil {
			t.Error(err)
		}
	}
}

// A ceremony name that is taken is refused with fs.ErrExist, and the first folder is untouched.
func TestASecondFolderOfTheSameNameIsRefusedAndTheFirstIsUntouched(t *testing.T) {
	b := newBundle(t)
	fl := newFlow(t, b, newSpec(name1, 1, ""))
	fl.must("plan")
	before := tree(t, b.dir)
	f2, err := ceremony.NewFolder(b.w, name1)
	if err != nil {
		t.Fatal(err)
	}
	s := newSpec(name1, 1, "")
	err = f2.WritePlan(s.plan(t), s.copies)
	wantKind(t, err, fs.ErrExist)
	sameTree(t, "the second WritePlan", before, tree(t, b.dir))
	// The first folder goes on, and the writer is not stopped.
	for _, st := range stages[1:] {
		if err := fl.step(st); err != nil {
			t.Fatalf("stage %s: %v", st, err)
		}
	}
	if rep := b.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("%+v", rep.Findings)
	}
}

// Two folders of one name from two goroutines: one at most writes the plan. The other is refused
// because the name is taken, or because the writer stopped on the name that was taken between its
// read and its write (record 0006, rule 44); it is never a second plan in the folder.
func TestTwoFoldersOfOneNameFromTwoGoroutinesWriteOnePlanAtMost(t *testing.T) {
	for attempt := 0; attempt < 20; attempt++ {
		b := newBundle(t)
		mustMkdir(t, b.path("history"))
		s := newSpec(name1, 1, "")
		plan := s.plan(t)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range errs {
			f, err := ceremony.NewFolder(b.w, name1)
			if err != nil {
				t.Fatal(err)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = f.WritePlan(plan, s.copies)
			}()
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case errors.Is(err, fs.ErrExist), errors.Is(err, fsx.ErrStopped):
			default:
				t.Errorf("a refusal that is neither a taken name nor a stopped writer: %v", err)
			}
		}
		if won > 1 {
			t.Fatalf("both goroutines wrote the plan")
		}
		ents, err := os.ReadDir(b.path("history"))
		if err != nil || len(ents) != 1 || ents[0].Name() != name1 {
			t.Fatalf("history/ holds %v, %v", ents, err)
		}
		if won == 1 {
			if got := b.read("history", name1, "plan.json"); !bytes.Equal(got, plan) {
				t.Error("plan.json is not the plan")
			}
		}
	}
}

// One Folder used from eight goroutines that start behind a closed channel: each call of the
// ceremony is made by one of them, and the others are out of order, whatever the schedule is.
func TestOneFolderFromManyGoroutinesTakesEachCallOnce(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	fl := newFlow(t, b, s)
	plan := s.plan(t)
	run := func(name string, call func() error) {
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 8)
		for i := range errs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = call()
			}()
		}
		close(start)
		wg.Wait()
		won := 0
		for _, err := range errs {
			if err == nil {
				won++
			} else {
				wantKind(t, err, ceremony.ErrOutOfOrder)
			}
		}
		if won != 1 {
			t.Errorf("%s: %d of 8 calls succeeded, want 1", name, won)
		}
	}
	run("WritePlan", func() error { return fl.f.WritePlan(plan, s.copies) })
	run("Start", func() error {
		tr, err := fl.f.Start(s.attempt(t, plan))
		if err == nil {
			fl.tr = tr
		}
		return err
	})
	if err := fl.step("births"); err != nil {
		t.Fatal(err)
	}
	if err := fl.step("signatures"); err != nil {
		t.Fatal(err)
	}
	run("End", func() error { return fl.f.End() })
	fl.con.Out("done")
	text, err := fl.con.Transcript()
	if err != nil {
		t.Fatal(err)
	}
	run("WriteTranscript", func() error { return fl.f.WriteTranscript(text) })
	if err := fl.step("artifacts"); err != nil {
		t.Fatal(err)
	}
	run("Record", func() error {
		out, err := fl.f.Record(fl.recordIn())
		if err == nil {
			fl.out = out
		}
		return err
	})
	if rep := b.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("%+v", rep.Findings)
	}
}

// Two Folders of two ceremonies on one writer, in a bundle that has no history/ yet, from two
// goroutines: every call is whole, so both plans are written. The folder history/ is made by one of
// them and read by the other; neither stops the writer for the other.
func TestTwoFoldersOfTwoNamesOnABundleWithNoHistoryAreBothWritten(t *testing.T) {
	for attempt := 0; attempt < 30; attempt++ {
		b := newBundle(t)
		flows := []*flow{newFlow(t, b, newSpec(name1, 1, "")), newFlow(t, b, newSpec(name2, 2, ""))}
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, len(flows))
		for i, fl := range flows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = fl.step("plan")
			}()
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("attempt %d, ceremony %d: %v", attempt, i+1, err)
			}
		}
	}
}

// Two Folders of one name on one writer, from two goroutines: one writes the plan, and the other is
// refused with fs.ErrExist and does not touch the first folder, so the first goes on to a record.
func TestTwoFoldersOfOneNameOneWinsAndTheOtherIsRefusedWithErrExist(t *testing.T) {
	for attempt := 0; attempt < 30; attempt++ {
		b := newBundle(t)
		mustMkdir(t, b.path("history"))
		flows := []*flow{newFlow(t, b, newSpec(name1, 1, "")), newFlow(t, b, newSpec(name1, 1, ""))}
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, len(flows))
		for i, fl := range flows {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = fl.step("plan")
			}()
		}
		close(start)
		wg.Wait()
		var winner *flow
		for i, err := range errs {
			if err == nil {
				if winner != nil {
					t.Fatal("both Folders wrote the plan")
				}
				winner = flows[i]
			} else if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("attempt %d: the loser is refused with %v, want fs.ErrExist", attempt, err)
			}
		}
		if winner == nil {
			t.Fatalf("attempt %d: neither Folder wrote the plan: %v", attempt, errs)
		}
		winner.skipTo("start")
		if err := winner.run(""); err != nil {
			t.Fatalf("attempt %d: the winner does not go on: %v", attempt, err)
		}
		if rep := b.check(); !rep.Clean() || rep.Records != 1 {
			t.Fatalf("attempt %d: %+v", attempt, rep.Findings)
		}
	}
}

// count is how many events of the file system are exactly e.
func count(events []string, e string) int {
	n := 0
	for _, x := range events {
		if x == e {
			n++
		}
	}
	return n
}

// startAll runs one function for each flow on its own goroutine, all of them released together,
// and returns the errors in the order of the flows.
func startAll(flows []*flow, do func(fl *flow) error) []error {
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, len(flows))
	for i, fl := range flows {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = do(fl)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// Many Folders of many names on a bundle that has no history/: all of them write, history/ is made
// once and before every ceremony folder, and each ceremony folder is made once.
func TestManyFoldersOfManyNamesMakeHistoryOnce(t *testing.T) {
	const n = 12
	for attempt := 0; attempt < 10; attempt++ {
		b := newBundle(t)
		var flows []*flow
		var names []string
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("2026111410%02d00Z-apply", i)
			names = append(names, name)
			flows = append(flows, newFlow(t, b, newSpec(name, 1, "")))
		}
		for i, err := range startAll(flows, func(fl *flow) error { return fl.step("plan") }) {
			if err != nil {
				t.Fatalf("attempt %d, folder %d: %v", attempt, i, err)
			}
		}
		ev := b.r.snapshot()
		if got := count(ev, "mkdir history"); got != 1 {
			t.Errorf("attempt %d: history/ was made %d times", attempt, got)
		}
		first := -1
		for i, e := range ev {
			if e == "mkdir history" {
				first = i
			}
		}
		for _, name := range names {
			if got := count(ev, "mkdir history/"+name); got != 1 {
				t.Errorf("attempt %d: %s was made %d times", attempt, name, got)
			}
			for i, e := range ev {
				if e == "mkdir history/"+name && i < first {
					t.Errorf("attempt %d: %s was made before history/", attempt, name)
				}
			}
		}
		if t.Failed() {
			return
		}
	}
}

// Many Folders of one name on one writer: one writes the plan, every other is refused with
// fs.ErrExist and no Mkdir call of its own, and the writer is not stopped. With and without a
// history/ that exists before.
func TestManyFoldersOfOneNameOneWinsAndTheOthersMakeNothing(t *testing.T) {
	const n = 10
	for _, haveHistory := range []bool{false, true} {
		for attempt := 0; attempt < 10; attempt++ {
			b := newBundle(t)
			if haveHistory {
				mustMkdir(t, b.path("history"))
			}
			var flows []*flow
			for i := 0; i < n; i++ {
				flows = append(flows, newFlow(t, b, newSpec(name1, 1, "")))
			}
			wins := 0
			for _, err := range startAll(flows, func(fl *flow) error { return fl.step("plan") }) {
				switch {
				case err == nil:
					wins++
				case !errors.Is(err, fs.ErrExist):
					t.Fatalf("a loser is refused with %v, want fs.ErrExist", err)
				case errors.Is(err, ceremony.ErrFolderStopped) || errors.Is(err, fsx.ErrStopped):
					t.Fatalf("a loser stopped: %v", err)
				}
			}
			if wins != 1 {
				t.Fatalf("%d Folders wrote the plan", wins)
			}
			ev := b.r.snapshot()
			if got := count(ev, "mkdir history/"+name1); got != 1 {
				t.Errorf("the ceremony folder was made %d times", got)
			}
			want := 1
			if haveHistory {
				want = 0
			}
			if got := count(ev, "mkdir history"); got != want {
				t.Errorf("history/ was made %d times, want %d", got, want)
			}
			if err := b.w.Mkdir("history/"+name2, 0o755); err != nil {
				t.Errorf("the writer is stopped: %v", err)
			}
			if t.Failed() {
				return
			}
		}
	}
}

// Two names that differ only in case are one name for the lock as for the disk: one wins and the
// other is refused with fs.ErrExist.
func TestTwoFoldersOfNamesThatDifferOnlyInCaseOneWins(t *testing.T) {
	up := strings.ToUpper(name1)
	for attempt := 0; attempt < 20; attempt++ {
		b := newBundle(t)
		flows := []*flow{newFlow(t, b, newSpec(name1, 1, "")), newFlow(t, b, newSpec(up, 1, ""))}
		errs := startAll(flows, func(fl *flow) error { return fl.step("plan") })
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else if !errors.Is(err, fs.ErrExist) {
				t.Fatalf("attempt %d: %v", attempt, err)
			}
		}
		if wins != 1 {
			t.Fatalf("attempt %d: %d Folders wrote a plan: %v", attempt, wins, errs)
		}
	}
}

// panicFS panics at the read of history/ while it is armed.
type panicFS struct {
	fsx.FS
	armed *bool
}

func (p *panicFS) OpenDir(name string) (fsx.FS, error) {
	if *p.armed && name == "history" {
		*p.armed = false
		panic("test: the file system panicked")
	}
	return p.FS.OpenDir(name)
}

// A call that panics under the lock of the make releases it: a Folder of another bundle, and the
// same Folder again, are not stopped by a lock that stays held.
func TestAPanicUnderTheLockOfTheMakeReleasesIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ritueel.yaml"), []byte(manifestText), 0o644); err != nil {
		t.Fatal(err)
	}
	inner, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	armed := true
	w := &fsx.Writer{FS: &panicFS{FS: inner, armed: &armed}}
	t.Cleanup(func() { _ = w.Close() })
	s := newSpec(name1, 1, "")
	f, _ := ceremony.NewFolder(w, name1)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the file system did not panic")
			}
		}()
		_ = f.WritePlan(s.plan(t), s.copies)
	}()
	done := make(chan error, 2)
	other := newFlow(t, newBundle(t), newSpec(name1, 1, ""))
	go func() { done <- other.step("plan") }()
	go func() { done <- f.WritePlan(s.plan(t), s.copies) }()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("a call after the panic: %v", err)
			}
		case <-time.After(30 * time.Second): // only a deadlock lets this run out
			t.Fatal("a call after the panic waits for a lock that is not released")
		}
	}
}

// While one Folder is between its read of history/ and its Mkdir of the ceremony folder, a second
// Folder does not read history/. The check is made from inside the first Folder's Mkdir: the second
// is started there, and must not reach its read of history/ while the first is still in the Mkdir.
// A lock that works never lets the second read; a missing lock lets it read at once, and the wait
// of 300 ms that follows would see it. A slow machine can only make this test pass wrongly, never
// fail.
func TestASecondFolderDoesNotReadHistoryWhileTheFirstMakesItsFolder(t *testing.T) {
	b := newBundle(t)
	mustMkdir(t, b.path("history"))
	first := newFlow(t, b, newSpec(name1, 1, ""))
	second := newFlow(t, b, newSpec(name2, 2, ""))
	var started sync.Once
	read := make(chan struct{}, 4)
	secondDone := make(chan error, 1)
	var inFirst atomic.Bool
	b.r.openHook = func(path string) {
		if path == "history" && inFirst.Load() {
			read <- struct{}{}
		}
	}
	b.r.hook = func(_ int, desc string) {
		if desc != "mkdir history/"+name1 {
			return
		}
		started.Do(func() {
			inFirst.Store(true)
			go func() { secondDone <- second.step("plan") }()
			select {
			case <-read:
				t.Error("the second Folder read history/ while the first was making its folder")
			case <-time.After(300 * time.Millisecond):
			}
			inFirst.Store(false)
		})
	}
	if err := first.step("plan"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondDone:
		if err != nil {
			t.Errorf("the second Folder: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the second Folder never finished")
	}
}

// Record can return an error while record.json is on disk: the file is renamed into place, and a
// cut at the flush of the folder after the rename is an error of the call although the file is
// there. The doc of Record says that a caller looks at the folder before it says that there is no
// record; the folder holds a whole record that the check of the history reads.
func TestARecordCutAtTheFlushAfterTheRenameIsAnErrorWithTheRecordOnDisk(t *testing.T) {
	wb, wfl := prepare(t, false, 0)
	wfl.must("")
	ev := wb.r.snapshot()
	total := len(ev)
	if last := ev[total-1]; last != "sync-dir history/"+name1 {
		t.Fatalf("the last changing call of a ceremony is %q, want the flush of the ceremony folder", last)
	}
	if prev := ev[total-2]; prev != "rename history/"+name1+"/record.json" {
		t.Fatalf("the call before it is %q, want the rename of record.json", prev)
	}
	b, fl := prepare(t, false, total)
	err := fl.run("")
	if err == nil {
		t.Fatal("a cut at the flush after the rename gave no error")
	}
	if stageOf(err) != "record" || !errors.Is(err, errCut) || !errors.Is(err, ceremony.ErrFolderStopped) {
		t.Errorf("the error is %v", err)
	}
	if fl.out != nil {
		t.Error("Record returned bytes with its error")
	}
	disk := fl.file("record.json")
	if _, err := files.ReadRecord(disk); err != nil {
		t.Errorf("the record on the disk is not a record: %v", err)
	}
	if rep := b.check(); !rep.Clean() || rep.Records != 1 {
		t.Errorf("findings %+v", rep.Findings)
	}
}
