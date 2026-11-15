//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/history"
)

// The name of the attempt is taken: another run of the same plan was first. The run that is second is
// refused with plan-used (exit code 3) and says that it made no key. The attempt of the first run is a
// file that is never replaced.

const fxUsedText = "holds an attempt.json already, so another run of this plan was first; this run wrote no attempt and made no key, and the attempt of the other run was not changed"

func fxWantPlanUsed(t *testing.T, err error, name string) {
	t.Helper()
	if _, stopped := rtStopped(err); stopped || rtKind(err) != "refused" {
		t.Fatalf("the error is %v (%s), want a refusal that is not a stop", err, rtKind(err))
	}
	if got := rtReasons(t, err); !slices.Equal(got, []string{"plan-used"}) {
		t.Errorf("reasons %q, want plan-used", got)
	}
	if !strings.Contains(err.Error(), "history/"+name+" "+fxUsedText) {
		t.Errorf("the text does not say what happened: %v", err)
	}
	if !pfPrintable(err.Error()) || strings.Contains(err.Error(), "\n") {
		t.Errorf("the text %q is not one line of printable ASCII", err.Error())
	}
}

func TestTheLoserOfTwoRunsOfOneSavedPlanIsRefusedWithPlanUsedAndMadeNoKey(t *testing.T) {
	r := rtNew(t)
	saved := r.savePlan()
	birth := fxCount(r)
	var doneB *ceremony.Done
	var errB error
	var snapshot map[string]string
	var keysB map[string]string
	ran := false
	r2 := fxSecond(t, r)
	r.b.r.hook = func(n int, desc string) {
		// The first changing call of this run is the temporary file of its attempt; the other run makes
		// its whole ceremony before it.
		if ran || !strings.HasPrefix(desc, "create-tmp history/"+saved.Name+"/") {
			return
		}
		ran = true
		doneB, errB = ceremony.Run(context.Background(), r2.savedIn(saved, rtFlag(saved)))
		snapshot, keysB = r.tree(), r2.keyTree()
	}
	done, err := ceremony.Run(context.Background(), r.savedIn(saved, rtFlag(saved)))
	if !ran || errB != nil || doneB == nil {
		t.Fatalf("the other run: %v, %v", doneB, errB)
	}
	if done != nil {
		t.Fatalf("the second run ended well: %+v", done)
	}
	fxWantPlanUsed(t, err, saved.Name)
	fxNoKeys(t, r)
	if b, s := birth.counts(); b != 0 || s != 0 {
		t.Errorf("the loser made %d keys and %d removals", b, s)
	}
	if len(keysB) != 4 {
		t.Errorf("the winner has %d files in its key directory, want 4", len(keysB))
	}
	// The attempt of the winner is the one on disk, and the files of the winner are what they were.
	after := r.tree()
	for p, d := range snapshot {
		if after[p] != d {
			t.Errorf("%s changed after the winner finished: %q to %q", p, d, after[p])
		}
	}
	for p := range after {
		if _, had := snapshot[p]; !had && !strings.HasPrefix(filepath.Base(p), ".rt-") {
			t.Errorf("the loser wrote %s", p)
		}
	}
	rep, cerr := history.Check(context.Background(), r.b.raw)
	if cerr != nil {
		t.Fatal(cerr)
	}
	if !rep.Clean() || rep.Records != 1 {
		t.Errorf("the history after the two runs: clean %v, records %d", rep.Clean(), rep.Records)
	}
}

func TestAnAttemptThatAppearsAtTheMomentOfTheWriteIsPlanUsedAndIsNotChanged(t *testing.T) {
	for _, saved := range []bool{false, true} {
		name := "direct"
		if saved {
			name = "saved"
		}
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			var in ceremony.RunIn
			var p *ceremony.PlanOut
			if saved {
				p = r.savePlan()
				in = r.savedIn(p, rtFlag(p))
			} else {
				pp, f := r.plan()
				p, in = pp, r.in(pp, f, rtFlag(pp))
			}
			birth := fxCount(r)
			other := []byte("{\"another\":\"run\"}\n")
			target := filepath.Join(r.bundleDir, "history", p.Name, "attempt.json")
			r.b.r.hook = func(n int, desc string) {
				if desc == "rename history/"+p.Name+"/attempt.json" {
					if err := os.WriteFile(target, other, 0o644); err != nil {
						t.Error(err)
					}
				}
			}
			done, err := ceremony.Run(context.Background(), in)
			if done != nil {
				t.Fatalf("Run ended well: %+v", done)
			}
			fxWantPlanUsed(t, err, p.Name)
			if got, _ := os.ReadFile(target); !bytes.Equal(got, other) {
				t.Errorf("the attempt of the other run was changed: %q", got)
			}
			for _, j := range []string{"births.jsonl", "signatures.jsonl", "transcript.txt", "record.json"} {
				if fxExists(r, "history", p.Name, j) {
					t.Errorf("this run wrote %s", j)
				}
			}
			fxNoKeys(t, r)
			if b, s := birth.counts(); b != 0 || s != 0 {
				t.Errorf("the store made %d keys and %d removals", b, s)
			}
			if fxExists(r, "roots") || fxExists(r, "trust") {
				t.Error("an artifact was written")
			}
			if r.stdout.String() != "" {
				t.Errorf("standard output holds %q", r.stdout.String())
			}
		})
	}
}

func TestAJournalThatExistsAlreadyIsAStopAndNotPlanUsed(t *testing.T) {
	// The attempt of this run is written; the journal that follows it cannot be made. That is after the
	// attempt of this run: an open attempt, a stop, and no key.
	for _, journal := range []string{"births.jsonl", "signatures.jsonl"} {
		t.Run(journal, func(t *testing.T) {
			r := rtNew(t)
			birth := fxCount(r)
			p, f := r.plan()
			target := filepath.Join(r.bundleDir, "history", p.Name, journal)
			r.b.r.hook = func(n int, desc string) {
				if desc == "create history/"+p.Name+"/"+journal {
					if err := os.WriteFile(target, nil, 0o644); err != nil {
						t.Error(err)
					}
				}
			}
			done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
			s, ok := rtStopped(err)
			if done != nil || !ok || s.Step != "attempt" || !s.Attempt {
				t.Fatalf("Run = %v, %v; want a stop at attempt with an open attempt", done, err)
			}
			if errors.Is(err, ceremony.ErrAttemptExists) || slices.Contains(refusedReasons(err), "plan-used") {
				t.Errorf("a journal that exists is taken for an attempt that exists: %v", err)
			}
			if !errors.Is(err, fs.ErrExist) {
				t.Errorf("the cause is not fs.ErrExist: %v", err)
			}
			if !fxExists(r, "history", p.Name, "attempt.json") {
				t.Error("the attempt of this run is not on disk")
			}
			fxNoKeys(t, r)
			if b, _ := birth.counts(); b != 0 {
				t.Errorf("%d keys were made", b)
			}
		})
	}
}

func refusedReasons(err error) []string {
	var ref *ceremony.RefusedError
	if errors.As(err, &ref) {
		return ref.Reasons
	}
	return nil
}

func TestAFolderThatMeetsAnAttemptThatExistsReturnsErrAttemptExistsAndChangesNothing(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	fl := newFlow(t, b, s)
	fl.must("plan")
	target := b.path("history", name1, "attempt.json")
	other := []byte("not ours\n")
	if err := os.WriteFile(target, other, 0o644); err != nil {
		t.Fatal(err)
	}
	before := tree(t, b.dir)
	tr, err := fl.f.Start(s.attempt(t, s.plan(t)))
	if tr != nil {
		t.Error("a Trace was returned")
	}
	for _, want := range []error{ceremony.ErrAttemptExists, fs.ErrExist, ceremony.ErrFolderStopped} {
		if !errors.Is(err, want) {
			t.Errorf("Start = %v, want %v reachable", err, want)
		}
	}
	var fe *ceremony.FolderError
	if !errors.As(err, &fe) || fe.Op != "start" {
		t.Errorf("no FolderError of the step start in %v", err)
	}
	if got, _ := os.ReadFile(target); !bytes.Equal(got, other) {
		t.Errorf("the attempt that existed was changed: %q", got)
	}
	// No journal was made, and the only change is none: the temporary file of the failed write stays, as
	// nothing is deleted.
	after := tree(t, b.dir)
	for p := range after {
		if _, had := before[p]; !had && !strings.HasPrefix(filepath.Base(p), ".rt-") {
			t.Errorf("Start wrote %s", p)
		}
	}
	for _, j := range []string{"births.jsonl", "signatures.jsonl"} {
		if _, ok := after["history/"+name1+"/"+j]; ok {
			t.Errorf("%s was made", j)
		}
	}
	// The folder is stopped: nothing more is written through it.
	if _, err := fl.f.Start(s.attempt(t, s.plan(t))); !errors.Is(err, ceremony.ErrFolderStopped) {
		t.Errorf("a second Start = %v, want ErrFolderStopped", err)
	}
}

func TestAFolderThatCannotMakeAJournalDoesNotReturnErrAttemptExists(t *testing.T) {
	b := newBundle(t)
	s := newSpec(name1, 1, "")
	fl := newFlow(t, b, s)
	fl.must("plan")
	if err := os.WriteFile(b.path("history", name1, "births.jsonl"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := fl.f.Start(s.attempt(t, s.plan(t)))
	if err == nil || errors.Is(err, ceremony.ErrAttemptExists) {
		t.Fatalf("Start = %v, want a fault that is not ErrAttemptExists", err)
	}
	if !errors.Is(err, fs.ErrExist) || !errors.Is(err, ceremony.ErrFolderStopped) {
		t.Errorf("Start = %v, want fs.ErrExist and ErrFolderStopped reachable", err)
	}
}
