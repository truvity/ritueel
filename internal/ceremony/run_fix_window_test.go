//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/history"
)

// The state of the bundle is judged a second time, just before the attempt (record 0005, rules 9 to 13):
// a bundle that changed while the person was reading the plan, or while the plan folder was written,
// stops this run with the refusal that the first judgement would give, before the attempt and before any
// key. The second judgement narrows the window of two runs at once; it does not close it, because no lock
// exists. The tests make the change at the one moment between the two judgements, with no scheduling.

// fxKinds are the changes that another run can make to the bundle in that window.
var fxKinds = []string{"an open attempt", "a record", "an attempt and a trust set", "a trust set alone", "an entry under roots", "a history that fails its check"}

// fxPlant makes the change in the bundle folder of r, as another copy of the program would have made it.
func fxPlant(t *testing.T, r *rt, kind string) {
	t.Helper()
	other := func(stage string) {
		b2 := openBundle(t, r.bundleDir, 0)
		newFlow(t, b2, newSpec(name1, 1, "")).must(stage)
	}
	switch kind {
	case "an open attempt":
		other("start")
	case "a record":
		other("")
	case "an attempt and a trust set":
		other("artifacts")
	case "a trust set alone":
		scratch := newBundle(t)
		newFlow(t, scratch, newSpec(name1, 1, "")).must("artifacts")
		fxCopyTree(t, filepath.Join(scratch.dir, "trust"), filepath.Join(r.bundleDir, "trust"))
	case "an entry under roots":
		if err := os.MkdirAll(filepath.Join(r.bundleDir, "roots", "Q"), 0o755); err != nil {
			t.Fatal(err)
		}
	case "a history that fails its check":
		other("")
		if err := os.WriteFile(filepath.Join(r.bundleDir, "history", name1, "transcript.txt"), []byte("changed\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("no change %q", kind)
	}
}

// fxSecond is a second run on the bundle that the first left: a new writer, a new key directory and a
// later clock, as a person who starts the command again.
func fxSecond(t *testing.T, r *rt) *rt {
	t.Helper()
	again := openBundle(t, r.bundleDir, 0)
	r2 := &rt{t: t, root: r.root, bundleDir: r.bundleDir, keyDir: rtMkdir(t), b: again, stderr: &rtBuf{}, stdout: &rtBuf{}, clockAt: pfClock.Add(time.Minute)}
	r2.console = ceremony.NewConsole(r2.stderr, r2.stdout)
	return r2
}

func TestABundleThatChangesBetweenThePreflightAndTheAttemptIsRefusedAsThePreflightWouldRefuseIt(t *testing.T) {
	l := rtLayoutOf(t, pfName)
	for _, saved := range []bool{false, true} {
		for _, kind := range fxKinds {
			name := "direct, " + kind
			if saved {
				name = "saved, " + kind
			}
			t.Run(name, func(t *testing.T) {
				r := rtNew(t)
				birth := fxCount(r)
				var plan *ceremony.PlanOut
				var found *ceremony.Found
				var in ceremony.RunIn
				planted := false
				var after map[string]string
				plant := func() {
					if planted {
						return
					}
					planted = true
					fxPlant(t, r, kind)
					after = r.tree()
				}
				if saved {
					plan = r.savePlan()
					in = r.savedIn(plan, rtFlag(plan))
					// The clock is read for the preflight and then for the time of the confirmation, after
					// which the second judgement is made.
					calls := 0
					now := in.Env.Now
					in.Env.Now = func() time.Time {
						calls++
						if calls == 2 {
							plant()
						}
						return now()
					}
				} else {
					p, f := r.plan()
					plan, found, in = p, f, r.in(p, f, rtFlag(p))
					r.b.r.hook = func(n int, desc string) {
						if n == l.planEnd {
							plant()
						}
					}
				}
				done, err := ceremony.Run(context.Background(), in)
				if !planted {
					t.Fatal("the bundle was not changed: the moment of the test is not reached")
				}
				if done != nil || err == nil {
					t.Fatalf("Run = %v, %v; want a refusal", done, err)
				}
				// The refusal that the first judgement gives for the same bundle.
				r2 := fxSecond(t, r)
				var in2 ceremony.RunIn
				if saved {
					in2 = r2.savedIn(plan, rtFlag(plan))
				} else {
					// The plan is the one that was made before the change: a new plan is refused by Find.
					in2 = r2.in(plan, found, rtFlag(plan))
				}
				_, err2 := ceremony.Run(context.Background(), in2)
				if err2 == nil {
					t.Fatal("the first judgement of the changed bundle passes: the test changes nothing that is judged")
				}
				if _, stopped := rtStopped(err2); stopped {
					t.Fatalf("the first judgement is a stop: %v", err2)
				}
				if saved {
					// Nothing was written by this run, and the refusal is the one of the preflight, word for word.
					if _, stopped := rtStopped(err); stopped {
						t.Fatalf("a saved plan: a stop %v", err)
					}
					if err.Error() != err2.Error() || rtKind(err) != rtKind(err2) {
						t.Errorf("the refusal is\n  %v (%s)\nthe preflight gives\n  %v (%s)", err, rtKind(err), err2, rtKind(err2))
					}
					sameTree(t, "a saved plan that is refused at the second judgement", after, r.tree())
				} else {
					fxWantDirectRefusal(t, r, plan.Name, err, err2)
					// What was there stays, and what this run added is its plan folder.
					now := r.tree()
					for p, d := range after {
						if now[p] != d {
							t.Errorf("%s changed from %q to %q", p, d, now[p])
						}
					}
					for p := range now {
						if _, had := after[p]; !had && !strings.HasPrefix(p, "history/"+plan.Name) {
							t.Errorf("the run wrote %s", p)
						}
					}
				}
				// In both: no attempt of this run, no key, no birth, nothing printed after the plan.
				if fxExists(r, "history", plan.Name, "attempt.json") {
					t.Error("this run wrote an attempt")
				}
				for _, j := range []string{"births.jsonl", "signatures.jsonl", "transcript.txt", "record.json"} {
					if fxExists(r, "history", plan.Name, j) {
						t.Errorf("this run wrote %s", j)
					}
				}
				fxNoKeys(t, r)
				if b, s := birth.counts(); b != 0 || s != 0 {
					t.Errorf("the store made %d keys and %d removals", b, s)
				}
				if r.stdout.String() != "" {
					t.Errorf("standard output holds %q", r.stdout.String())
				}
			})
		}
	}
}

// fxWantDirectRefusal checks what a direct apply says when the second judgement finds what the first
// would have found, after the plan folder was written.
func fxWantDirectRefusal(t *testing.T, r *rt, name string, err, first error) {
	t.Helper()
	switch rtKind(first) {
	case "refused":
		// A refusal keeps its reasons and its exit code, and says what this run wrote.
		if rtKind(err) != "refused" {
			t.Fatalf("the first judgement refuses (%v), the second gives %s: %v", first, rtKind(err), err)
		}
		if got, want := rtReasons(t, err), rtReasons(t, first); !slices.Equal(got, want) {
			t.Errorf("reasons %q, the first judgement gives %q", got, want)
		}
		if _, stopped := rtStopped(err); stopped {
			t.Errorf("a refusal is not a stop: %v", err)
		}
		for _, w := range []string{"history/" + name, "this run wrote the plan folder", "wrote no attempt and made no key"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("the text does not say %q: %v", w, err)
			}
		}
		if strings.Contains(err.Error(), "nothing was written") {
			t.Errorf("the text says that nothing was written, and the plan folder was: %v", err)
		}
		if !pfPrintable(err.Error()) || strings.Contains(err.Error(), "\n") {
			t.Errorf("the text %q is not one line of printable ASCII", err.Error())
		}
	case "not-first":
		// A bundle that is not in the first state is a failure, and the line says what is on disk.
		s, ok := rtStopped(err)
		if !ok || s.Step != "attempt" || s.Attempt {
			t.Fatalf("the error is %v, want a stop at attempt with no open attempt", err)
		}
		if !errors.Is(err, ceremony.ErrNotFirst) {
			t.Errorf("the cause is not ErrNotFirst: %v", err)
		}
		if !strings.Contains(err.Error(), "the plan folder may hold some of its files, no attempt was written, and no key was made") {
			t.Errorf("the line does not say what is on disk: %v", err)
		}
	default:
		t.Fatalf("the first judgement is %s: %v", rtKind(first), first)
	}
}

func TestTheRefusalOfTheSecondJudgementHasTheReasonOfEachChangeOfTheBundle(t *testing.T) {
	// The reasons of the page, in its order: a history that fails its check, an open attempt, a plan that is
	// stale, a bundle that is not first.
	want := map[string]map[bool]string{
		"an open attempt":                {false: "unfinished-ceremony", true: "unfinished-ceremony"},
		"an attempt and a trust set":     {false: "unfinished-ceremony", true: "unfinished-ceremony"},
		"a record":                       {false: "not-first", true: "plan-stale"},
		"a trust set alone":              {false: "", true: ""},
		"an entry under roots":           {false: "not-first", true: "not-first"},
		"a history that fails its check": {false: "", true: ""},
	}
	l := rtLayoutOf(t, pfName)
	for _, saved := range []bool{false, true} {
		for kind, byMode := range want {
			if byMode[saved] == "" {
				continue
			}
			t.Run(kind+", saved "+rtItoa(map[bool]int{false: 0, true: 1}[saved]), func(t *testing.T) {
				r := rtNew(t)
				var in ceremony.RunIn
				if saved {
					plan := r.savePlan()
					in = r.savedIn(plan, rtFlag(plan))
					calls := 0
					now := in.Env.Now
					in.Env.Now = func() time.Time {
						calls++
						if calls == 2 {
							fxPlant(t, r, kind)
						}
						return now()
					}
				} else {
					p, f := r.plan()
					in = r.in(p, f, rtFlag(p))
					planted := false
					r.b.r.hook = func(n int, desc string) {
						if n == l.planEnd && !planted {
							planted = true
							fxPlant(t, r, kind)
						}
					}
				}
				_, err := ceremony.Run(context.Background(), in)
				switch w := byMode[saved]; w {
				case "not-first":
					if !errors.Is(err, ceremony.ErrNotFirst) {
						t.Errorf("the error is %v, want ErrNotFirst", err)
					}
				default:
					if got := rtReasons(t, err); !slices.Equal(got, []string{w}) {
						t.Errorf("reasons %q, want %q", got, w)
					}
				}
			})
		}
	}
}

func TestAHistoryThatFailsItsCheckInTheWindowIsRefusedWithTheFindingsOfTheCheck(t *testing.T) {
	l := rtLayoutOf(t, pfName)
	for _, saved := range []bool{false, true} {
		t.Run("saved "+rtItoa(map[bool]int{false: 0, true: 1}[saved]), func(t *testing.T) {
			r := rtNew(t)
			var in ceremony.RunIn
			plant := func() { fxPlant(t, r, "a history that fails its check") }
			if saved {
				plan := r.savePlan()
				in = r.savedIn(plan, rtFlag(plan))
				calls := 0
				now := in.Env.Now
				in.Env.Now = func() time.Time {
					calls++
					if calls == 2 {
						plant()
					}
					return now()
				}
			} else {
				p, f := r.plan()
				in = r.in(p, f, rtFlag(p))
				r.b.r.hook = func(n int, desc string) {
					if n == l.planEnd {
						plant()
					}
				}
			}
			_, err := ceremony.Run(context.Background(), in)
			rep, cerr := history.Check(context.Background(), r.b.raw)
			if cerr != nil || rep.Clean() {
				t.Fatalf("the history is clean after the change: %v", cerr)
			}
			if !slices.Equal(rtReasons(t, err), codes(rep.Reasons())) || !slices.Contains(rtReasons(t, err), "transcript-digest") {
				t.Errorf("reasons %q, the check gives %q", rtReasons(t, err), codes(rep.Reasons()))
			}
		})
	}
}

func TestACancelledContextBetweenTheConfirmationAndTheAttemptWritesNoAttempt(t *testing.T) {
	l := rtLayoutOf(t, pfName)
	t.Run("a direct apply is a stop at the attempt, with the plan folder on disk", func(t *testing.T) {
		r := rtNew(t)
		birth := fxCount(r)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r.b.r.hook = func(n int, desc string) {
			if n == l.planEnd {
				cancel()
			}
		}
		p, f := r.plan()
		done, err := ceremony.Run(ctx, r.in(p, f, rtFlag(p)))
		s, ok := rtStopped(err)
		if done != nil || !ok || s.Step != "attempt" || s.Attempt {
			t.Fatalf("Run = %v, %v; want a stop at attempt with no open attempt", done, err)
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the cause is not the cancelled context: %v", err)
		}
		if !strings.Contains(err.Error(), "no attempt was written, and no key was made") {
			t.Errorf("the line: %v", err)
		}
		if !fxExists(r, "history", pfName, "plan.json") || fxExists(r, "history", pfName, "attempt.json") {
			t.Error("the plan folder must hold the plan and no attempt")
		}
		fxNoKeys(t, r)
		if b, _ := birth.counts(); b != 0 {
			t.Errorf("%d keys were made", b)
		}
	})
	t.Run("a saved plan is the error of the context and nothing is written", func(t *testing.T) {
		r := rtNew(t)
		birth := fxCount(r)
		plan := r.savePlan()
		before := r.tree()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		in := r.savedIn(plan, rtFlag(plan))
		calls := 0
		now := in.Env.Now
		in.Env.Now = func() time.Time {
			calls++
			if calls == 2 {
				cancel()
			}
			return now()
		}
		done, err := ceremony.Run(ctx, in)
		if done != nil || !errors.Is(err, context.Canceled) || err.Error() != context.Canceled.Error() {
			t.Fatalf("Run = %v, %v; want the error of the context as it is", done, err)
		}
		if _, stopped := rtStopped(err); stopped {
			t.Errorf("a stop for a run that wrote nothing: %v", err)
		}
		sameTree(t, "a saved plan with a cancelled context", before, r.tree())
		fxNoKeys(t, r)
		if b, _ := birth.counts(); b != 0 {
			t.Errorf("%d keys were made", b)
		}
	})
}

func TestAWholeCeremonyThatAnotherRunMakesInTheWindowStopsThisRunBeforeItsAttempt(t *testing.T) {
	// The other run is a real run: it makes its plan, its attempt, its keys and its record, in another key
	// directory, between the writes of the plan of this run and its attempt.
	l := rtLayoutOf(t, pfName)
	r := rtNew(t)
	birth := fxCount(r)
	p, f := r.plan()
	var doneB *ceremony.Done
	var errB error
	var nameB string
	ran := false
	r.b.r.hook = func(n int, desc string) {
		if n != l.planEnd || ran {
			return
		}
		ran = true
		r2 := fxSecond(t, r)
		f2 := r2.find()
		env := pfEnv()
		env.Now = func() time.Time { return pfClock.Add(10 * time.Second) }
		p2, perr := ceremony.MakePlan(f2, env)
		if perr != nil {
			t.Error(perr)
			return
		}
		doneB, errB = ceremony.Run(context.Background(), r2.in(p2, f2, rtFlag(p2)))
		if doneB != nil {
			nameB = doneB.Ceremony
		}
	}
	done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
	if !ran || errB != nil || doneB == nil {
		t.Fatalf("the other run: %v, %v", doneB, errB)
	}
	if nameB == p.Name {
		t.Fatal("the other run made the same ceremony: the test needs two names")
	}
	s, ok := rtStopped(err)
	if done != nil || !ok || s.Step != "attempt" || s.Attempt || !errors.Is(err, ceremony.ErrNotFirst) {
		t.Fatalf("Run = %v, %v; want a stop at attempt, no open attempt, ErrNotFirst", done, err)
	}
	// Exactly one ceremony has an attempt and a record; this run has only its plan folder and no key.
	if fxExists(r, "history", p.Name, "attempt.json") || !fxExists(r, "history", nameB, "attempt.json") || !fxExists(r, "history", nameB, "record.json") {
		t.Error("the attempts of the two runs are not as the page says")
	}
	fxNoKeys(t, r)
	if b, _ := birth.counts(); b != 0 {
		t.Errorf("%d keys were made by the run that was stopped", b)
	}
	rep, cerr := history.Check(context.Background(), r.b.raw)
	if cerr != nil {
		t.Fatal(cerr)
	}
	if !rep.Clean() || rep.Records != 1 {
		t.Errorf("the history after the two runs: clean %v, records %d", rep.Clean(), rep.Records)
	}
}

func TestTwoDirectRunsAtOnceFromTwoGoroutinesBehindAClosedChannelLeaveOneCeremonyWithAnAttempt(t *testing.T) {
	for try := 0; try < 5; try++ {
		r := rtNew(t)
		p, f := r.plan()
		r2 := fxSecond(t, r)
		r2.clockAt = r.clockAt // the same second: one ceremony name for both
		p2, f2 := r2.plan()
		if p.Name != p2.Name {
			t.Fatalf("the plans have two names %s and %s", p.Name, p2.Name)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make([]error, 2)
		dones := make([]*ceremony.Done, 2)
		runs := []ceremony.RunIn{r.in(p, f, rtFlag(p)), r2.in(p2, f2, rtFlag(p2))}
		for i := range runs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				dones[i], results[i] = ceremony.Run(context.Background(), runs[i])
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		for i := range dones {
			if dones[i] != nil {
				wins++
				if results[i] != nil {
					t.Errorf("run %d: a result and an error: %v", i, results[i])
				}
			}
		}
		if wins != 1 {
			t.Fatalf("%d of two runs ended well, want exactly one: %v, %v", wins, results[0], results[1])
		}
		attempts := 0
		ents, _ := os.ReadDir(filepath.Join(r.bundleDir, "history"))
		for _, e := range ents {
			if fxExists(r, "history", e.Name(), "attempt.json") {
				attempts++
			}
		}
		if attempts != 1 {
			t.Errorf("%d ceremonies have an attempt, want one", attempts)
		}
		keys := 0
		for _, d := range []string{r.keyDir, r2.keyDir} {
			if ents, _ := os.ReadDir(d); len(ents) > 0 {
				keys++
			}
		}
		if keys != 1 {
			t.Errorf("%d key directories hold keys, want one", keys)
		}
		rep, err := history.Check(context.Background(), r.b.raw)
		if err != nil {
			t.Fatal(err)
		}
		if !rep.Clean() || rep.Records != 1 {
			t.Errorf("history after the two runs: clean %v, records %d", rep.Clean(), rep.Records)
		}
	}
}
