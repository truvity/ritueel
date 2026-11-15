//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/history"
)

// A stop: the first fault after the first write. The ceremony is left as it is, nothing is retried and
// nothing is deleted (record 0006, rules 33 and 45), and the line says what is on disk.

// rtEvents are the changing calls of one whole run, in order.
func rtEvents(t *testing.T) []string {
	t.Helper()
	r := rtNew(t)
	r.mustDirect()
	return r.b.r.snapshot()
}

// rtFirst is the number (from 1) of the first event at or after from that starts with prefix.
func rtFirst(t *testing.T, ev []string, prefix string, from int) int {
	t.Helper()
	for i := max(from, 1); i <= len(ev); i++ {
		if strings.HasPrefix(ev[i-1], prefix) {
			return i
		}
	}
	t.Fatalf("no event %q after %d", prefix, from)
	return 0
}

// rtLayout is where each step of the run ends, as event numbers of a whole run.
type rtLayout struct {
	planEnd, attemptEnd, makeEnd, transcriptEnd, artifactsEnd, total int
}

func rtLayoutOf(t *testing.T, name string) rtLayout {
	t.Helper()
	ev := rtEvents(t)
	h := "history/" + name + "/"
	var l rtLayout
	l.total = len(ev)
	l.planEnd = rtFirst(t, ev, "rename "+h+"wanted/want/roots/x509.yaml", 1) + 1 // its sync of the folder
	l.attemptEnd = rtFirst(t, ev, "create "+h+"signatures.jsonl", 1) + 2         // create, sync-file, sync-dir
	first := rtFirst(t, ev, "write "+h+"signatures.jsonl", 1)
	l.makeEnd = first + 4*2 + 1 // five signature lines, each a write and a sync
	l.transcriptEnd = rtFirst(t, ev, "rename "+h+"transcript.txt", 1) + 1
	l.artifactsEnd = rtFirst(t, ev, "rename trust/1-", l.transcriptEnd) + 1 // its sync of trust/
	return l
}

func TestTheLayoutOfAWholeRunIsWhatTheStopsAreSortedBy(t *testing.T) {
	l := rtLayoutOf(t, pfName)
	if l.total < 30 {
		t.Fatalf("a whole run makes %d changing calls, the stops need more than 30", l.total)
	}
	if l.planEnd <= 0 || l.planEnd >= l.attemptEnd || l.attemptEnd >= l.makeEnd || l.makeEnd >= l.transcriptEnd || l.transcriptEnd >= l.artifactsEnd || l.artifactsEnd >= l.total {
		t.Errorf("the steps are out of order: %+v", l)
	}
}

// rtDiskState is what a stop left, read from the disk.
type rtDiskState struct {
	attempt, record, transcript        bool
	rootJSON                           int
	trustSets                          []string
	keyFiles, removals                 int
	birthLines, sigLines               int
	birthPartial, sigPartial           bool
	removalLines, certLines, listLines int
}

func rtReadState(t *testing.T, r *rt, name string) rtDiskState {
	t.Helper()
	var s rtDiskState
	exists := func(p ...string) bool {
		_, err := os.Lstat(filepath.Join(append([]string{r.bundleDir}, p...)...))
		return err == nil
	}
	s.attempt = exists("history", name, "attempt.json")
	s.record = exists("history", name, "record.json")
	s.transcript = exists("history", name, "transcript.txt")
	for _, l := range []string{"A", "B"} {
		if exists("roots", l, "root.json") {
			s.rootJSON++
		}
	}
	if ents, err := os.ReadDir(filepath.Join(r.bundleDir, "trust")); err == nil {
		for _, e := range ents {
			if !strings.HasPrefix(e.Name(), ".rt-") {
				s.trustSets = append(s.trustSets, e.Name())
			}
		}
	}
	ents, _ := os.ReadDir(r.keyDir)
	for _, e := range ents {
		switch {
		case strings.HasSuffix(e.Name(), ".x509.key.pem"):
			s.keyFiles++
		case strings.HasSuffix(e.Name(), ".removal.jws"):
			s.removals++
		}
	}
	lines := func(file string) (whole [][]byte, partial bool) {
		b, err := os.ReadFile(filepath.Join(r.bundleDir, "history", name, file))
		if err != nil {
			return nil, false
		}
		for len(b) > 0 {
			i := bytes.IndexByte(b, '\n')
			if i < 0 {
				return whole, true
			}
			whole = append(whole, b[:i])
			b = b[i+1:]
		}
		return whole, false
	}
	var bl, sl [][]byte
	bl, s.birthPartial = lines("births.jsonl")
	sl, s.sigPartial = lines("signatures.jsonl")
	s.birthLines, s.sigLines = len(bl), len(sl)
	for _, l := range bl {
		if _, err := files.ReadBirthLine(l); err != nil {
			t.Errorf("a whole line of births.jsonl is refused by its reader: %v", err)
		}
	}
	for _, l := range sl {
		sig, err := files.ReadSignatureLine(l)
		if err != nil {
			t.Errorf("a whole line of signatures.jsonl is refused by its reader: %v", err)
			continue
		}
		switch sig.Kind {
		case "root-removal":
			s.removalLines++
		case "root-certificate":
			s.certLines++
		case "root-list":
			s.listLines++
		}
	}
	return s
}

// rtWantInvariants fails the test when the state breaks an order of the writes.
func rtWantInvariants(t *testing.T, s rtDiskState, n int) {
	t.Helper()
	if s.rootJSON > 0 && (!s.attempt || !s.transcript) {
		t.Errorf("cut %d: a root.json exists but the attempt (%v) or the transcript (%v) does not", n, s.attempt, s.transcript)
	}
	if len(s.trustSets) > 0 && (s.keyFiles != 2 || s.removals != 2 || s.rootJSON != 2 || s.birthLines != 2 || s.sigLines != 5 || !s.transcript) {
		t.Errorf("cut %d: a trust set exists and not all that it stands on: %+v", n, s)
	}
	if s.record && len(s.trustSets) == 0 {
		t.Errorf("cut %d: the record exists and the trust set does not", n)
	}
	if s.transcript && (s.birthLines != 2 || s.sigLines != 5 || s.birthPartial || s.sigPartial) {
		t.Errorf("cut %d: the transcript exists and the journals are not whole: %+v", n, s)
	}
	if s.birthLines > s.keyFiles && !s.birthPartial || s.birthLines > s.keyFiles {
		t.Errorf("cut %d: %d birth lines for %d key files: a line may only follow its key file", n, s.birthLines, s.keyFiles)
	}
	if s.keyFiles > s.birthLines+1 && !s.birthPartial {
		t.Errorf("cut %d: %d key files for %d birth lines: at most one key file may have no line", n, s.keyFiles, s.birthLines)
	}
	if s.removalLines > s.removals {
		t.Errorf("cut %d: %d removal lines for %d removal files: a line may only follow its file", n, s.removalLines, s.removals)
	}
	if (s.sigLines > 0 || s.birthLines > 0 || s.keyFiles > 0) && !s.attempt {
		t.Errorf("cut %d: a journal line or a key exists and the attempt does not", n)
	}
}

func TestACutAtEveryWriteOfARunIsAStopThatSaysWhatIsOnDisk(t *testing.T) {
	l := rtLayoutOf(t, pfName)
	for n := 1; n <= l.total; n++ {
		t.Run("cut at "+rtItoa(n), func(t *testing.T) {
			t.Parallel()
			r := rtNew(t, rtFailAt(n))
			p, f := r.plan()
			done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
			if done != nil {
				t.Fatalf("Run ended well with a write that failed: %+v", done)
			}
			s, ok := rtStopped(err)
			if !ok {
				t.Fatalf("the error is %T %v, want a *StoppedError", err, err)
			}
			if rtKind(err) != "stopped" {
				t.Errorf("a stop is exit code 1: kind %s", rtKind(err))
			}
			if got := len(r.b.r.snapshot()); got != n {
				t.Errorf("%d changing calls reached the disk, want %d: nothing is retried after a fault", got, n)
			}
			wantStep, wantAttempt := "", true
			switch {
			case n <= l.planEnd:
				wantStep, wantAttempt = "write-plan", false
			case n <= l.attemptEnd:
				wantStep = "attempt"
			case n <= l.makeEnd:
				wantStep = "make"
			case n <= l.transcriptEnd:
				wantStep = "transcript"
			case n <= l.artifactsEnd:
				wantStep = "artifacts"
			default:
				wantStep = "record"
			}
			if s.Step != wantStep || s.Attempt != wantAttempt || s.Ceremony != p.Name {
				t.Errorf("stop = step %q, attempt %v, ceremony %q; want %q, %v, %q", s.Step, s.Attempt, s.Ceremony, wantStep, wantAttempt, p.Name)
			}
			msg := err.Error()
			for _, w := range []string{"history/" + p.Name, "stopped at " + wantStep, "nothing was retried and nothing was deleted"} {
				if !strings.Contains(msg, w) {
					t.Errorf("the line does not say %q: %s", w, msg)
				}
			}
			if !pfPrintable(msg) {
				t.Errorf("the line %+q is not printable ASCII on one line", msg)
			}
			if wantStep == "write-plan" && (!strings.Contains(msg, "no attempt was written") || strings.Contains(msg, "close")) {
				t.Errorf("the line of a stop before the attempt: %s", msg)
			}
			if wantAttempt && !strings.Contains(msg, "the key directory may hold A.x509.key.pem, B.x509.key.pem and the removal authorisations") {
				t.Errorf("the line of a stop with an open attempt does not name the key files: %s", msg)
			}
			if wantStep == "record" && !strings.Contains(msg, "look at the folder") {
				t.Errorf("the line of a stop at the record does not say that record.json may be in place: %s", msg)
			}
			switch {
			case wantAttempt && n > l.attemptEnd:
				if !strings.Contains(msg, "an attempt is open") || !strings.Contains(msg, "A.x509.key.pem, B.x509.key.pem") || !strings.Contains(msg, "close, which closes an open attempt, is not built") {
					t.Errorf("the line of a stop with an open attempt: %s", msg)
				}
			case wantAttempt:
				if !strings.Contains(msg, "may or may not") {
					t.Errorf("the line of a stop at the write of the attempt: %s", msg)
				}
			}
			state := rtReadState(t, r, p.Name)
			rtWantInvariants(t, state, n)
			// The check of the history: no failing finding, and the notice that a trust set has no
			// record exactly when it is so.
			rep, err := history.Check(context.Background(), r.b.raw)
			if err != nil {
				t.Fatal(err)
			}
			if !rep.Clean() {
				t.Errorf("the history fails after a cut: %+v", rep.Failing())
			}
			var unfinished bool
			for _, nt := range rep.Notices() {
				if nt.Code == history.UnfinishedCeremony {
					unfinished = true
				}
			}
			if want := len(state.trustSets) > 0 && !state.record; unfinished != want {
				t.Errorf("notice unfinished-ceremony = %v, want %v (trust sets %v, record %v)", unfinished, want, state.trustSets, state.record)
			}
			rtSecondRun(t, r, p, f, state)
		})
	}
}

// rtSecondRun runs the same plan on the bundle that a stop left, with a writer that does not fail, and
// checks that the next run is refused as the page says, and that a refusal writes nothing.
func rtSecondRun(t *testing.T, r *rt, p *ceremony.PlanOut, f *ceremony.Found, s rtDiskState) {
	t.Helper()
	again := openBundle(t, r.bundleDir, 0)
	r2 := &rt{t: t, root: r.root, bundleDir: r.bundleDir, keyDir: rtMkdir(t), b: again, stderr: &rtBuf{}, stdout: &rtBuf{}, clockAt: pfClock.Add(time.Minute)}
	r2.console = ceremony.NewConsole(r2.stderr, r2.stdout)
	switch {
	case s.record:
		err := rtRefused(t, r2, r2.in(p, f, rtFlag(p)), "not-first")
		if !errors.Is(err, ceremony.ErrNotFirst) {
			t.Errorf("a bundle with a record: %v", err)
		}
	case s.attempt:
		err := rtRefused(t, r2, r2.in(p, f, rtFlag(p)), "refused")
		if got := rtReasons(t, err); !slices.Equal(got, []string{"unfinished-ceremony"}) {
			t.Errorf("a bundle with an open attempt: reasons %q", got)
		}
	default:
		// A plan folder that a cut left, whole or not: a second run makes the plan again in the same
		// second or finds its folder in the way, and writes nothing in that case.
		before := r2.tree()
		done, err := ceremony.Run(context.Background(), r2.in(p, f, rtFlag(p)))
		if err == nil {
			if done == nil {
				t.Error("a second run ended with no result")
			}
			return
		}
		if _, stopped := rtStopped(err); stopped || !strings.Contains(err.Error(), "same second") {
			t.Errorf("the second run: %v", err)
		}
		sameTree(t, "a second run into the plan folder of a cut", before, r2.tree())
	}
}

func TestTheCauseOfAStopStaysReachableWhereThePackageThatFailedKeepsItsCause(t *testing.T) {
	// The comment of StoppedError says that the cause of a stop stays reachable with errors.Is and
	// errors.As where the package that failed keeps its cause, and that a fault of the trust set writer
	// keeps its text only. The trust set writer signs the root list and appends its line to the journal:
	// a cut at the write of that last signature line, and at its flush, is the one place where the cause
	// is text only. Everywhere else the cut is found with errors.Is, and the stop is found with errors.As.
	l := rtLayoutOf(t, pfName)
	ev := rtEvents(t)
	lastSig := 0
	for i, e := range ev {
		if e == "write history/"+pfName+"/signatures.jsonl" {
			lastSig = i + 1
		}
	}
	if lastSig == 0 || ev[lastSig] != "sync-file history/"+pfName+"/signatures.jsonl" {
		t.Fatalf("the last write of a signature line is call %d of %v", lastSig, ev)
	}
	textOnly := map[int]bool{lastSig: true, lastSig + 1: true}
	for n := 1; n <= l.total; n++ {
		r := rtNew(t, rtFailAt(n))
		p, f := r.plan()
		_, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
		s, ok := rtStopped(err)
		if !ok {
			t.Fatalf("cut %d: %v", n, err)
		}
		if got := errors.Is(err, errCut); got == textOnly[n] {
			t.Errorf("cut %d: errors.Is finds the cut = %v, want %v", n, got, !textOnly[n])
		}
		if textOnly[n] {
			// The line is cut at a fixed length, so the cause itself may not be in it; it names what failed.
			if s.Step != "make" || !strings.Contains(err.Error(), "the first trust set was not made") || !strings.Contains(err.Error(), "the line of the signature 5 was not written") {
				t.Errorf("cut %d: the line of a fault of the trust set writer must name what failed (step %q): %s", n, s.Step, err.Error())
			}
		}
		var again *ceremony.StoppedError
		if !errors.As(err, &again) || again != s {
			t.Errorf("cut %d: errors.As does not find the stop", n)
		}
	}
}

func TestTheLineOfAStopWhilePlanningDoesNotSayThePlanIsWrittenWhenItIsNot(t *testing.T) {
	// The line says what is on disk. A cut at the first folder or at a copy leaves no plan or a part of
	// the copies, and the line must not say that the plan and the copies are written.
	l := rtLayoutOf(t, pfName)
	var wrong []int
	for n := 1; n <= l.planEnd; n++ {
		r := rtNew(t, rtFailAt(n))
		p, f := r.plan()
		_, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
		s, ok := rtStopped(err)
		if !ok || s.Step != "write-plan" {
			t.Fatalf("cut %d: %v", n, err)
		}
		whole := true
		for _, rel := range []string{"plan.json", "wanted/ritueel.yaml", "wanted/want/roots/x509.yaml"} {
			if _, err := os.Lstat(filepath.Join(r.bundleDir, "history", p.Name, filepath.FromSlash(rel))); err != nil {
				whole = false
			}
		}
		if !whole && strings.Contains(err.Error(), "the plan and the copies are written") {
			wrong = append(wrong, n)
		}
	}
	if len(wrong) > 0 {
		t.Errorf("the line says that the plan and the copies are written, and they are not, for the cuts at the writes %v", wrong)
	}
}
