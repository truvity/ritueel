//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

// A console that breaks after the plan was shown and the plan was confirmed is found before anything is
// written: the run ends as an ordinary failure (exit code 1), not as a refused confirmation, and the bundle
// and the key directory are as they were.

// rtBreakAt is a standard error that takes every line until one holds marker, and refuses that line and
// every later one, as a pipe whose reader has gone does. It counts what it was given and what it refused.
type rtBreakAt struct {
	mu      sync.Mutex
	w       *rtBuf
	marker  string
	broken  bool
	refused int
}

func (s *rtBreakAt) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.broken && strings.Contains(string(p), s.marker) {
		s.broken = true
	}
	if s.broken {
		s.refused++
		return 0, errors.New("test: the stream is closed")
	}
	return s.w.Write(p)
}

func (s *rtBreakAt) refusals() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

const (
	rtLineFlag  = "confirmed with --confirm"
	rtLineTyped = "confirmed by typing"
)

// rtConsoleCases are the four forms of a run: a direct apply and a saved plan, each confirmed by the flag
// and by typing.
type rtConsoleCase struct {
	name   string
	saved  bool
	typed  bool
	marker string
}

var rtConsoleCases = []rtConsoleCase{
	{"direct, flag", false, false, rtLineFlag},
	{"direct, typed", false, true, rtLineTyped},
	{"saved plan, flag", true, false, rtLineFlag},
	{"saved plan, typed", true, true, rtLineTyped},
}

// rtBrokenAfterConfirm prepares the case: the bundle, the plan (made or saved), the store that counts its
// acts and the console that breaks at the line of the confirmation. It returns the input of the run.
func rtBrokenAfterConfirm(t *testing.T, c rtConsoleCase) (r *rt, in ceremony.RunIn, p *ceremony.PlanOut, log *mkLog, stream *rtBreakAt) {
	t.Helper()
	r = rtNew(t)
	log = &mkLog{}
	rtUseStore(r, log, nil)
	var f *ceremony.Found
	if c.saved {
		p = r.savePlan()
	} else {
		p, f = r.plan()
	}
	stream = &rtBreakAt{w: r.stderr, marker: c.marker}
	r.console = ceremony.NewConsole(stream, r.stdout)
	conf := rtFlag(p)
	if c.typed {
		r.typed(p.SHA256[:ceremonyTyped] + "\n")
		conf = ceremony.Confirm{}
	}
	if c.saved {
		in = r.savedIn(p, conf)
	} else {
		in = r.in(p, f, conf)
	}
	return r, in, p, log, stream
}

// ceremonyTyped is the number of characters that a person types.
const ceremonyTyped = 8

func TestAConsoleThatBreaksAtTheConfirmationEndsTheRunAsAFailureAndWritesNothing(t *testing.T) {
	for _, c := range rtConsoleCases {
		t.Run(c.name, func(t *testing.T) {
			r, in, p, log, stream := rtBrokenAfterConfirm(t, c)
			treeBefore, keysBefore := r.tree(), r.keyTree()
			mark := r.b.r.mark()
			done, err := ceremony.Run(context.Background(), in)
			if done != nil || err == nil {
				t.Fatalf("Run = %v, %v; want a failure", done, err)
			}
			if stream.refusals() == 0 {
				t.Fatal("the stream was never broken: the case does not reach the line of the confirmation")
			}
			// The kind: an ordinary failure, exit code 1. Not a refused confirmation (exit code 5), not a
			// stop of a ceremony, not a refusal.
			if got := rtKind(err); got != "failure" {
				t.Errorf("the error is %s (%v), want a plain failure", got, err)
			}
			if errors.Is(err, ceremony.ErrNotConfirmed) {
				t.Errorf("a person who confirmed is not refused: %v", err)
			}
			if _, stopped := rtStopped(err); stopped {
				t.Errorf("no ceremony folder was written, so there is no stop: %v", err)
			}
			if !errors.Is(err, ceremony.ErrPrintFailed) {
				t.Errorf("the cause is not reachable: %v", err)
			}
			msg := err.Error()
			for _, w := range []string{"a line could not be shown", "nothing was written"} {
				if !strings.Contains(msg, w) {
					t.Errorf("the text does not say %q: %s", w, msg)
				}
			}
			if !pfPrintable(msg) || strings.Contains(msg, "\n") {
				t.Errorf("the text %+q is not one line of printable ASCII", msg)
			}
			// Nothing was written: the bundle and the key directory are as they were, and no call that
			// changes the bundle reached the file system.
			sameTree(t, "a console that broke at the confirmation", treeBefore, r.tree())
			sameTree(t, "a console that broke at the confirmation (key directory)", keysBefore, r.keyTree())
			if got := r.b.r.since(mark); len(got) != 0 {
				t.Errorf("changing calls reached the bundle: %q", got)
			}
			if !c.saved {
				if _, ok := r.tree()["history"]; ok {
					t.Error("history/ exists: a direct apply wrote its plan folder before the console was judged")
				}
			} else if _, ok := r.tree()["history/"+p.Name+"/attempt.json"]; ok {
				t.Error("an attempt was written")
			}
			if n := log.count("birth"); n != 0 {
				t.Errorf("the store was asked for %d births", n)
			}
			if n := log.count("sign") + log.count("save-removal"); n != 0 {
				t.Errorf("the store was asked for %d signatures or removals", n)
			}
			if n := log.count("store-close"); n != 1 {
				t.Errorf("the store was closed %d times, want once", n)
			}
			if r.stdout.String() != "" {
				t.Errorf("standard output holds %q", r.stdout.String())
			}
			if c.typed && r.stdin.count() == 0 {
				t.Error("the typed line was not read")
			}
		})
	}
}

func TestAPlanThatWasNotRunBecauseTheConsoleBrokeCanBeRunAfterwards(t *testing.T) {
	for _, c := range rtConsoleCases {
		t.Run(c.name, func(t *testing.T) {
			r, in, p, _, _ := rtBrokenAfterConfirm(t, c)
			if _, err := ceremony.Run(context.Background(), in); !errors.Is(err, ceremony.ErrPrintFailed) {
				t.Fatalf("Run = %v, want the fault of the console", err)
			}
			// The same plan with a console that works: nothing of the first run stands in its way.
			r.console = ceremony.NewConsole(r.stderr, r.stdout)
			var again ceremony.RunIn
			if c.saved {
				again = r.savedIn(p, rtFlag(p))
			} else {
				_, f := r.plan()
				again = r.in(p, f, rtFlag(p))
			}
			done, err := ceremony.Run(context.Background(), again)
			if err != nil || done == nil {
				t.Fatalf("the second run: %v, %v", done, err)
			}
			if rep := r.b.check(); !rep.Clean() || rep.Records != 1 {
				t.Errorf("the history after the second run: %+v", rep)
			}
		})
	}
}

func TestAConsoleThatBreaksAtTheRefusalOfAConfirmationIsStillNotConfirmed(t *testing.T) {
	// The confirmation is judged first. A person or a script that did not confirm gets exit code 5 and
	// not the fault of the console, even when the line that says so cannot be shown.
	for _, c := range []struct {
		name   string
		typed  string
		flag   string
		marker string
	}{
		{"a wrong digest by flag", "", strings.Repeat("0", 64), "not confirmed"},
		{"a wrong line typed", "ffffffff\n", "", "not confirmed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			stream := &rtBreakAt{w: r.stderr, marker: c.marker}
			r.console = ceremony.NewConsole(stream, r.stdout)
			conf := ceremony.Confirm{Flag: true, Digest: c.flag}
			if c.typed != "" {
				r.typed(c.typed)
				conf = ceremony.Confirm{}
			}
			treeBefore, keysBefore := r.tree(), r.keyTree()
			done, err := ceremony.Run(context.Background(), r.in(p, f, conf))
			if done != nil || !errors.Is(err, ceremony.ErrNotConfirmed) || rtKind(err) != "not-confirmed" {
				t.Fatalf("Run = %v, %v; want ErrNotConfirmed", done, err)
			}
			if stream.refusals() == 0 {
				t.Fatal("the stream was never broken")
			}
			sameTree(t, "a refused confirmation", treeBefore, r.tree())
			sameTree(t, "a refused confirmation (key directory)", keysBefore, r.keyTree())
		})
	}
}

func TestAConsoleThatBreaksAfterTheBirthsIsStillAStopOfTheMakerAndNotTheNewFailure(t *testing.T) {
	// The check after the confirmation does not replace the check of the maker: a stream that works up to
	// and including the confirmation, and breaks at the first line after the keys are born, is a stop at the
	// step make, with an open attempt, as it was.
	for _, saved := range []bool{false, true} {
		name := "direct"
		if saved {
			name = "saved plan"
		}
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			log := &mkLog{}
			rtUseStore(r, log, nil)
			stream := &rtBreakAt{w: r.stderr, marker: "x509 pin"}
			r.console = ceremony.NewConsole(stream, r.stdout)
			var in ceremony.RunIn
			var p *ceremony.PlanOut
			if saved {
				p = r.savePlan()
				in = r.savedIn(p, rtFlag(p))
			} else {
				var f *ceremony.Found
				p, f = r.plan()
				in = r.in(p, f, rtFlag(p))
			}
			done, err := ceremony.Run(context.Background(), in)
			s, ok := rtStopped(err)
			if done != nil || !ok {
				t.Fatalf("Run = %v, %v; want a stop", done, err)
			}
			if s.Step != "make" || !s.Attempt {
				t.Errorf("stop at %q with attempt %v, want make and an open attempt", s.Step, s.Attempt)
			}
			if !errors.Is(err, ceremony.ErrPrintFailed) {
				t.Errorf("the cause is not reachable: %v", err)
			}
			if strings.Contains(err.Error(), "a line could not be shown, so the run stopped") {
				t.Errorf("the words of the check before the attempt in the stop of the maker: %s", err.Error())
			}
			for _, w := range []string{stopKeyClause, stopTempClause} {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("the line does not say %q: %s", w, err.Error())
				}
			}
			if n := log.count("birth"); n != 2 {
				t.Errorf("%d births, want 2: the keys are made before the console is asked", n)
			}
		})
	}
}

func TestAConsoleThatWorksUntilTheEndIsNotCheckedAnyEarlier(t *testing.T) {
	// A console that does not break is asked once more and is not changed by it: the whole run still ends
	// well and the transcript holds every line once.
	r := rtNew(t)
	done, _ := r.mustDirect()
	if done == nil {
		t.Fatal("no result")
	}
	if got := strings.Count(r.transcript(done.Ceremony), rtLineFlag); got != 1 {
		t.Errorf("the line of the confirmation is in the transcript %d times, want once", got)
	}
}

// rtBreakNth is a standard error that takes the lines before the nth and refuses the nth and every later one.
// It keeps the lines it was given, the refused ones too.
type rtBreakNth struct {
	mu    sync.Mutex
	w     *rtBuf
	n     int
	lines []string
}

func (s *rtBreakNth) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, strings.TrimSuffix(string(p), "\n"))
	if s.n > 0 && len(s.lines) >= s.n {
		return 0, errors.New("test: the stream is closed")
	}
	return s.w.Write(p)
}

func (s *rtBreakNth) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func TestAStandardErrorThatBreaksAtAnyLineOfARunIsFoundAtTheStepThatTheLineBelongsTo(t *testing.T) {
	// The lines of a whole run, in order: the plan in words, the confirmation, the pins of the keys, the
	// checks, the writes, the summary. A stream that breaks at the kth line ends the run where the step of
	// that line puts it: before the confirmation line the plan is not asked for, at the confirmation
	// line the run stops before it writes, at the pins and the checks it is a stop of the maker and the
	// transcript, and in the summary after the record it is no fault of the run.
	base := rtNew(t)
	baseline := &rtBreakNth{w: base.stderr}
	base.console = ceremony.NewConsole(baseline, base.stdout)
	if _, err := base.direct(); err != nil {
		t.Fatal(err)
	}
	lines := baseline.all()
	confirm := -1
	for i, l := range lines {
		if strings.HasPrefix(l, rtLineFlag) {
			confirm = i + 1
		}
	}
	if confirm < 5 || len(lines) < confirm+6 {
		t.Fatalf("a whole run prints %d lines and its confirmation is line %d: %q", len(lines), confirm, lines)
	}
	for k := 1; k <= len(lines)+1; k++ {
		var what string
		switch {
		case k <= confirm-1:
			what = "plan"
		case k == confirm:
			what = "confirmation"
		case k <= len(lines) && strings.HasPrefix(lines[k-1], "root key ") && !strings.Contains(lines[k-1], "certificate ends"):
			what = "pins"
		case k <= len(lines) && (strings.HasPrefix(lines[k-1], "checked: ") || strings.HasPrefix(lines[k-1], "writes: ")):
			what = "checks"
		default:
			what = "summary"
		}
		t.Run(rtItoa(k)+" "+what, func(t *testing.T) {
			r := rtNew(t)
			stream := &rtBreakNth{w: r.stderr, n: k}
			r.console = ceremony.NewConsole(stream, r.stdout)
			p, f := r.plan()
			before, keys := r.tree(), r.keyTree()
			mark := r.b.r.mark()
			done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
			switch what {
			case "plan", "confirmation":
				want := "the plan could not be shown, so it is not asked for, and nothing was written"
				if what == "confirmation" {
					want = "a line could not be shown, so the run stopped, and nothing was written"
				}
				if done != nil || err == nil || !strings.Contains(err.Error(), want) || !errors.Is(err, ceremony.ErrPrintFailed) {
					t.Fatalf("Run = %v, %v; want a failure that says %q", done, err, want)
				}
				if got := rtKind(err); got != "failure" {
					t.Errorf("the kind is %s, want failure", got)
				}
				sameTree(t, "a console that broke before anything was written", before, r.tree())
				sameTree(t, "a console that broke before anything was written (key directory)", keys, r.keyTree())
				if got := r.b.r.since(mark); len(got) != 0 {
					t.Errorf("changing calls reached the bundle: %q", got)
				}
			case "pins", "checks":
				s, ok := rtStopped(err)
				want := map[string]string{"pins": "make", "checks": "transcript"}[what]
				if done != nil || !ok || s.Step != want || !s.Attempt {
					t.Fatalf("Run = %v, %v; want a stop at %s with an open attempt", done, err, want)
				}
				if !errors.Is(err, ceremony.ErrPrintFailed) {
					t.Errorf("the cause is not reachable: %v", err)
				}
				rtWantMakeLine(t, err.Error())
			default:
				// The lines after the record: the record is written, the run ends well, and the fault of the
				// console is the business of the command, which reads it from the console after the run.
				if err != nil || done == nil {
					t.Fatalf("Run = %v, %v; want the run to end well", done, err)
				}
				if _, terr := r.console.Transcript(); !errors.Is(terr, ceremony.ErrPrintFailed) && k <= len(lines) {
					t.Errorf("the console does not report its fault after the run: %v", terr)
				}
			}
		})
	}
}

// rtOddStream is a standard error that misbehaves from its nth write on: it fails, writes less than it was
// given, or panics.
type rtOddStream struct {
	mu    sync.Mutex
	w     *rtBuf
	from  int
	mode  byte
	count int
}

func (s *rtOddStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	s.count++
	odd := s.count >= s.from
	s.mu.Unlock()
	if !odd {
		return s.w.Write(p)
	}
	switch s.mode % 3 {
	case 0:
		return 0, errors.New("test: the stream is closed")
	case 1:
		return len(p) / 2, nil
	}
	panic("test: the stream panics")
}

// FuzzAConsoleThatMisbehavesFromAnyLineOn runs a saved plan with a standard error that fails, writes short
// or panics from the line that the input names, and with either confirmation. Whatever the line: the run
// never panics, ends with a result or an error and never with both, a refusal of the console before the first
// write leaves the bundle and the key directory as they were, no confirmation that was given is turned into a
// refused one, and the history that a stop leaves passes its own check. The sequence of lines of a whole run
// is under thirty lines, so the line is taken modulo forty.
func FuzzAConsoleThatMisbehavesFromAnyLineOn(f *testing.F) {
	for _, s := range []struct {
		from, mode byte
		typed      bool
	}{{1, 0, false}, {11, 0, false}, {12, 0, false}, {12, 1, true}, {12, 2, false}, {13, 2, true}, {15, 1, false}, {17, 0, true}, {30, 0, false}, {39, 2, true}} {
		f.Add(s.from, s.mode, s.typed)
	}
	f.Fuzz(func(t *testing.T, from, mode byte, typed bool) {
		r := rtNew(t)
		p := r.savePlan()
		stream := &rtOddStream{w: r.stderr, from: int(from)%40 + 1, mode: mode}
		r.console = ceremony.NewConsole(stream, r.stdout)
		conf := rtFlag(p)
		if typed {
			r.typed(p.SHA256[:ceremonyTyped] + "\n")
			conf = ceremony.Confirm{}
		}
		before, keys := r.tree(), r.keyTree()
		mark := r.b.r.mark()
		done, err := ceremony.Run(context.Background(), r.savedIn(p, conf))
		if (done == nil) == (err == nil) {
			t.Fatalf("Run = %v, %v: one of the two", done, err)
		}
		if err == nil {
			return
		}
		if !pfPrintable(err.Error()) {
			t.Fatalf("the text %+q is not printable ASCII on one line", err.Error())
		}
		if errors.Is(err, ceremony.ErrNotConfirmed) {
			t.Fatalf("a confirmation that was given is refused: %v", err)
		}
		if _, stopped := rtStopped(err); !stopped {
			sameTree(t, "a failure before the first write", before, r.tree())
			sameTree(t, "a failure before the first write (key directory)", keys, r.keyTree())
			if got := r.b.r.since(mark); len(got) != 0 {
				t.Fatalf("changing calls reached the bundle: %q", got)
			}
			return
		}
		if rep := r.b.check(); !rep.Clean() {
			t.Fatalf("the history of a stop fails its check: %+v", rep.Failing())
		}
	})
}

func TestAConsoleThatIsFullAfterTheConfirmationLineIsFoundBeforeAnythingIsWritten(t *testing.T) {
	// The fault is not only a stream that refused a line: a console that cannot keep the line of the
	// confirmation (the transcript holds no more lines) could not make the transcript of the ceremony. The
	// plan words fit, the line of the confirmation is the first one that does not, and nothing is written.
	r := rtNew(t)
	p, f := r.plan()
	for i := 0; i < ceremony.MaxTranscriptLines-len(p.Words()); i++ {
		r.console.Err("a line that was printed before the run: %d", i)
	}
	if _, err := r.console.Transcript(); err != nil {
		t.Fatalf("the console is full and not yet over: %v", err)
	}
	in := r.in(p, f, rtFlag(p))
	before, keys := r.tree(), r.keyTree()
	mark := r.b.r.mark()
	done, err := ceremony.Run(context.Background(), in)
	if done != nil || !errors.Is(err, ceremony.ErrTranscriptLimit) || !strings.Contains(err.Error(), "nothing was written") {
		t.Fatalf("Run = %v, %v; want a failure with the cause ErrTranscriptLimit that says nothing was written", done, err)
	}
	if rtKind(err) != "failure" {
		t.Errorf("the kind is %s, want failure", rtKind(err))
	}
	sameTree(t, "a console that is full", before, r.tree())
	sameTree(t, "a console that is full (key directory)", keys, r.keyTree())
	if got := r.b.r.since(mark); len(got) != 0 {
		t.Errorf("changing calls reached the bundle: %q", got)
	}
}
