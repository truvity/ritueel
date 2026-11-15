//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
)

// A run whose key store, journals, console or context fail after the attempt, and the order of the
// acts of a whole run.

// rtRefuseHook is a store that calls after when Refuse returned nil.
type rtRefuseHook struct {
	*mkStore
	after func()
}

func (s rtRefuseHook) Refuse(ctx context.Context) error {
	err := s.mkStore.Refuse(ctx)
	if err == nil && s.after != nil {
		s.after()
	}
	return err
}

// rtUseStore makes the run open the software store wrapped in a mkStore, and returns the wrapper.
func rtUseStore(r *rt, log *mkLog, edit func(*mkStore)) *mkStore {
	w := &mkStore{log: log}
	r.open = func(keyDir, bundleDir string) (ceremony.RootStore, error) {
		inner, err := ceremony.NewSoftwareStore(keyDir, bundleDir)
		if err != nil {
			return nil, err
		}
		w.inner = inner
		if edit != nil {
			edit(w)
		}
		return w, nil
	}
	return w
}

// rtStopOf runs a direct apply that must stop, and returns the stop and what was left on disk.
func rtStopOf(t *testing.T, r *rt) (*ceremony.StoppedError, rtDiskState, error) {
	t.Helper()
	p, f := r.plan()
	done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
	if done != nil {
		t.Fatalf("Run ended well: %+v", done)
	}
	s, ok := rtStopped(err)
	if !ok {
		t.Fatalf("the error is %T %v, want a *StoppedError", err, err)
	}
	if rtKind(err) != "stopped" {
		t.Errorf("a stop is exit code 1, the kind is %s", rtKind(err))
	}
	st := rtReadState(t, r, p.Name)
	rtWantInvariants(t, st, 0)
	return s, st, err
}

func TestAKeyStoreThatFailsAfterTheAttemptStopsTheRunWithTheCauseAndExitCode1(t *testing.T) {
	boom := errors.New("test: the store failed")
	cases := []struct {
		name         string
		edit         func(*mkStore)
		keys, births int
		removals     int
	}{
		{"the birth of A", func(s *mkStore) { s.failBirth = map[string]error{"A": boom} }, 0, 0, 0},
		{"the birth of B", func(s *mkStore) { s.failBirth = map[string]error{"B": boom} }, 1, 1, 0},
		{"a key and an error", func(s *mkStore) { s.keyAndErr = map[string]error{"A": boom} }, 1, 0, 0},
		{"the removal of A", func(s *mkStore) { s.failRemoval = map[string]error{"A": boom} }, 2, 2, 0},
		{"a refusal of the key store in the form of the key directory", func(s *mkStore) {
			s.failBirth = map[string]error{"B": &ceremony.BackendError{Reasons: []string{"key-exists"}, Msg: "a key file exists"}}
		}, 1, 1, 0},
		{"a store that panics at the birth", func(s *mkStore) { s.panicOn = "birth" }, 0, 0, 0},
		{"a store that panics at the removal", func(s *mkStore) { s.panicOn = "saveremoval" }, 2, 2, 0},
		{"a read back that fails", func(s *mkStore) { s.readErr = boom }, 2, 2, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rtNew(t)
			rtUseStore(r, &mkLog{}, c.edit)
			s, st, err := rtStopOf(t, r)
			if s.Step != "make" || !s.Attempt {
				t.Errorf("stop = %q, attempt %v, want make with an open attempt", s.Step, s.Attempt)
			}
			if st.keyFiles != c.keys || st.birthLines != c.births || !st.attempt || st.transcript || st.rootJSON != 0 || len(st.trustSets) != 0 || st.record {
				t.Errorf("on disk: %+v, want %d key files, %d birth lines, the attempt, no transcript, no artifact, no record", st, c.keys, c.births)
			}
			if strings.Contains(c.name, "refusal of the key store") {
				var be *ceremony.BackendError
				if !errors.As(err, &be) || !slices.Equal(be.Reasons, []string{"key-exists"}) {
					t.Errorf("the refusal of the store is not reachable inside the stop: %v", err)
				}
			}
			if strings.Contains(c.name, "the birth of") && !errors.Is(err, boom) {
				t.Errorf("the cause is not reachable inside the stop: %v", err)
			}
		})
	}
}

func TestAKeyFileThatAppearsAfterTheRefusalIsNotReplacedAndStopsTheRun(t *testing.T) {
	r := rtNew(t)
	planted := []byte("not a key, planted after the refusal")
	log := &mkLog{}
	w := &mkStore{log: log}
	r.open = func(keyDir, bundleDir string) (ceremony.RootStore, error) {
		inner, err := ceremony.NewSoftwareStore(keyDir, bundleDir)
		if err != nil {
			return nil, err
		}
		w.inner = inner
		calls := 0
		return rtRefuseHook{mkStore: w, after: func() {
			// The first refusal judges the key directory before the confirmation; the second is the
			// one that the maker asks for before the first key is born.
			if calls++; calls != 2 {
				return
			}
			if err := os.WriteFile(filepath.Join(keyDir, "B.x509.key.pem"), planted, 0o600); err != nil {
				t.Error(err)
			}
		}}, nil
	}
	s, st, _ := rtStopOf(t, r)
	if s.Step != "make" || st.keyFiles != 2 || st.birthLines != 1 {
		t.Errorf("stop %q, on disk %+v: want A born and journaled, B refused", s.Step, st)
	}
	got, err := os.ReadFile(filepath.Join(r.keyDir, "B.x509.key.pem"))
	if err != nil || !bytes.Equal(got, planted) {
		t.Errorf("the file that stood in the place of B was replaced: %q, %v", got, err)
	}
}

func TestTheKeyStoreIsClosedOnEveryWayOutOfARun(t *testing.T) {
	cases := map[string]func(t *testing.T, r *rt, p *ceremony.PlanOut, f *ceremony.Found) ceremony.Confirm{
		"a run that ends well": func(t *testing.T, r *rt, p *ceremony.PlanOut, f *ceremony.Found) ceremony.Confirm { return rtFlag(p) },
		"a confirmation that is refused": func(t *testing.T, r *rt, p *ceremony.PlanOut, f *ceremony.Found) ceremony.Confirm {
			return ceremony.Confirm{Flag: true, Digest: "no"}
		},
		"a store that is stopped": func(t *testing.T, r *rt, p *ceremony.PlanOut, f *ceremony.Found) ceremony.Confirm {
			rtUseStoreFail(r)
			return rtFlag(p)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			log := &mkLog{}
			rtUseStore(r, log, nil)
			p, f := r.plan()
			c := mk(t, r, p, f)
			if r.open == nil {
				t.Fatal("no store")
			}
			_, _ = ceremony.Run(context.Background(), r.in(p, f, c))
			if n := log.count("store-close"); n != 1 {
				t.Errorf("the store was closed %d times, want once", n)
			}
		})
	}
}

// rtUseStoreFail is a marker that the case sets a failing store itself: it is replaced below.
func rtUseStoreFail(r *rt) {
	log := &mkLog{}
	_ = log
	old := r.open
	r.open = func(k, b string) (ceremony.RootStore, error) {
		st, err := old(k, b)
		if err != nil {
			return nil, err
		}
		st.(*mkStore).failBirth = map[string]error{"A": errors.New("test: no birth")}
		return st, nil
	}
}

func TestARefusalOfTheKeyStoreBeforeTheAttemptMakesNoKeyAndWritesNothing(t *testing.T) {
	r := rtNew(t)
	log := &mkLog{}
	rtUseStore(r, log, func(s *mkStore) {
		s.refuseErr = &ceremony.BackendError{Reasons: []string{"key-dir"}, Msg: "the key directory is refused"}
	})
	p, f := r.plan()
	_ = rtRefused(t, r, r.in(p, f, rtFlag(p)), "backend")
	if log.index("refuse") != 0 || log.count("birth") != 0 || log.count("sign") != 0 || len(r.b.r.snapshot()) != 0 {
		t.Errorf("events %q, disk calls %q: Birth must not be called when Refuse fails", log.all(), r.b.r.snapshot())
	}
}

func TestAKeyStoreThatPanicsInRefuseIsAFailureAndNothingIsWritten(t *testing.T) {
	r := rtNew(t)
	rtUseStore(r, &mkLog{}, func(s *mkStore) { s.panicOn = "refuse" })
	p, f := r.plan()
	_ = rtRefused(t, r, r.in(p, f, rtFlag(p)), "failure")
}

func TestARunThatWasCancelledStopsAtTheNextStepAndSaysSo(t *testing.T) {
	cases := []struct {
		name, desc string
		nth        int
		step       string
		keys       int
	}{
		{"before the first signature line", "write HIST/signatures.jsonl", 1, "make", 2},
		{"between the births", "write HIST/births.jsonl", 1, "make", 1},
		{"after the last signature", "sync-file HIST/signatures.jsonl", 6, "make", 2},
		{"after the transcript", "rename HIST/transcript.txt", 1, "artifacts", 2},
		{"after the trust set", "rename trust/1-", 1, "record", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := strings.ReplaceAll(c.desc, "HIST", "history/"+p.Name)
			seen := 0
			r.b.r.hook = func(n int, desc string) {
				if strings.HasPrefix(desc, want) {
					seen++
					if seen == c.nth {
						cancel()
					}
				}
			}
			done, err := ceremony.Run(ctx, r.in(p, f, rtFlag(p)))
			s, ok := rtStopped(err)
			if done != nil || !ok || s.Step != c.step || !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v, %v; want a stop at %s that holds context.Canceled", done, err, c.step)
			}
			st := rtReadState(t, r, p.Name)
			rtWantInvariants(t, st, 0)
			if st.keyFiles < c.keys-1 || (c.step == "artifacts" && st.rootJSON != 0) || (c.step == "journals" && st.transcript) || (c.step == "record" && (st.record || len(st.trustSets) != 1)) {
				t.Errorf("on disk: %+v", st)
			}
		})
	}
}

// rtTamper changes the file of a journal at the moment the run is about to sync its last line, after
// the lines are written and before the journals are read back.
func rtTamper(t *testing.T, r *rt, p *ceremony.PlanOut, journal string, nth int, edit func(path string, whole []byte)) {
	t.Helper()
	path := filepath.Join(r.bundleDir, "history", p.Name, journal)
	want := "sync-file history/" + p.Name + "/" + journal
	seen := 0
	r.b.r.hook = func(n int, desc string) {
		if desc != want {
			return
		}
		seen++
		if seen != nth {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		edit(path, b)
	}
}

func TestAJournalThatIsNotWhatWasMadeStopsTheRunBeforeTheTranscriptAndTheArtifacts(t *testing.T) {
	lines := func(b []byte) [][]byte { return bytes.SplitAfter(bytes.TrimSuffix(b, nil), []byte("\n")) }
	write := func(t *testing.T, path string, b []byte) {
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Error(err)
		}
	}
	cases := []struct {
		name    string
		journal string
		nth     int
		edit    func(t *testing.T, path string, whole []byte)
	}{
		{"a signature line is dropped", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			l := lines(b)
			write(t, p, bytes.Join(l[:len(l)-2], nil))
		}},
		{"a signature digest is changed", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			i := bytes.LastIndex(b, []byte(`"signature_sha256":"`)) + len(`"signature_sha256":"`)
			c := slices.Clone(b)
			if c[i] == '0' {
				c[i] = '1'
			} else {
				c[i] = '0'
			}
			write(t, p, c)
		}},
		{"a signature line is added", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			l := lines(b)
			write(t, p, append(slices.Clone(b), l[0]...))
		}},
		{"two signature lines change places", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			l := lines(b)
			l[0], l[1] = l[1], l[0]
			write(t, p, bytes.Join(l, nil))
		}},
		{"the last signature line has no line feed", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			write(t, p, bytes.TrimSuffix(b, []byte("\n")))
		}},
		{"a signature line is not JSON", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			write(t, p, append(b[:len(b)-1:len(b)-1], "\xff\xfe\n"...))
		}},
		{"a half line follows the last signature line", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			write(t, p, append(slices.Clone(b), '{'))
		}},
		{"a half line follows the last birth line", "births.jsonl", 3, func(t *testing.T, p string, b []byte) {
			write(t, p, append(slices.Clone(b), '{'))
		}},
		{"the signature journal is empty", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) { write(t, p, nil) }},
		{"a birth line is dropped", "births.jsonl", 3, func(t *testing.T, p string, b []byte) {
			l := lines(b)
			write(t, p, bytes.Join(l[:len(l)-2], nil))
		}},
		{"a birth line is added", "births.jsonl", 3, func(t *testing.T, p string, b []byte) {
			l := lines(b)
			write(t, p, append(slices.Clone(b), l[0]...))
		}},
		{"two birth lines change places", "births.jsonl", 3, func(t *testing.T, p string, b []byte) {
			l := lines(b)
			l[0], l[1] = l[1], l[0]
			write(t, p, bytes.Join(l, nil))
		}},
		{"a pin of a birth line is changed", "births.jsonl", 3, func(t *testing.T, p string, b []byte) {
			i := bytes.LastIndex(b, []byte(`"public_key_sha256":"`)) + len(`"public_key_sha256":"`)
			c := slices.Clone(b)
			if c[i] == '0' {
				c[i] = '1'
			} else {
				c[i] = '0'
			}
			write(t, p, c)
		}},
		{"the birth journal holds a line of a huge size", "births.jsonl", 3, func(t *testing.T, p string, b []byte) {
			write(t, p, append(slices.Clone(b), append(bytes.Repeat([]byte("a"), 1<<20), '\n')...))
		}},
		{"the birth journal is a folder", "births.jsonl", 3, func(t *testing.T, p string, b []byte) {
			if err := os.Remove(p); err != nil {
				t.Error(err)
			}
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Error(err)
			}
		}},
		{"the signature journal is a link", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			if err := os.Remove(p); err != nil {
				t.Error(err)
			}
			if err := os.Symlink("births.jsonl", p); err != nil {
				t.Error(err)
			}
		}},
		{"the signature journal is a pipe", "signatures.jsonl", 6, func(t *testing.T, p string, b []byte) {
			if err := os.Remove(p); err != nil {
				t.Error(err)
			}
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Error(err)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			rtTamper(t, r, p, c.journal, c.nth, func(path string, whole []byte) { c.edit(t, path, whole) })
			type out struct {
				done *ceremony.Done
				err  error
			}
			ch := make(chan out, 1)
			go func() {
				d, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
				ch <- out{d, err}
			}()
			var o out
			select {
			case o = <-ch:
			case <-time.After(30 * time.Second):
				t.Fatal("the run waits on a journal that is not a file")
			}
			s, ok := rtStopped(o.err)
			if o.done != nil || !ok || s.Step != "journals" || !s.Attempt {
				t.Fatalf("Run = %v, %v; want a stop at journals with an open attempt", o.done, o.err)
			}
			if !pfPrintable(o.err.Error()) {
				t.Errorf("the line %+q is not printable ASCII", o.err.Error())
			}
			st := rtReadStateLoose(t, r, p.Name)
			if st.transcript || st.rootJSON != 0 || len(st.trustSets) != 0 || st.record || st.keyFiles != 2 {
				t.Errorf("a stop at journals left %+v: no transcript, no artifact, no record, two keys", st)
			}
		})
	}
}

// rtReadStateLoose reads the files that a run leaves outside the journals; it does not judge a
// journal, which a test of this kind has changed on purpose.
func rtReadStateLoose(t *testing.T, r *rt, name string) rtDiskState {
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
			s.trustSets = append(s.trustSets, e.Name())
		}
	}
	ents, _ := os.ReadDir(r.keyDir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".x509.key.pem") {
			s.keyFiles++
		}
	}
	return s
}

func TestARemovalFileThatChangesBetweenTheMakerAndTheReadBackStopsTheRunAtTheJournals(t *testing.T) {
	r := rtNew(t)
	var reads atomic.Int32
	rtUseStore(r, &mkLog{}, func(s *mkStore) {
		s.readRemoval = func(label string, real []byte) []byte {
			if label == "A" && reads.Add(1) == 2 {
				return append(slices.Clone(real), 'x')
			}
			return real
		}
	})
	s, st, _ := rtStopOf(t, r)
	if s.Step != "journals" || st.transcript || st.rootJSON != 0 || len(st.trustSets) != 0 || reads.Load() != 2 {
		t.Errorf("stop %q, on disk %+v, reads of A %d: want a stop at journals after the second read", s.Step, st, reads.Load())
	}
}

func TestAConsoleWhoseStreamFailsAfterTheKeysAreBornWritesNoTranscriptAndNoArtifact(t *testing.T) {
	r := rtNew(t)
	var broken atomic.Bool
	r.console = ceremony.NewConsole(&rtSwitch{w: r.stderr, broken: &broken}, r.stdout)
	rtUseStore(r, &mkLog{}, func(s *mkStore) {
		s.afterBirth = func(label string) {
			if label == "A" {
				broken.Store(true)
			}
		}
	})
	s, st, _ := rtStopOf(t, r)
	if (s.Step != "make" && s.Step != "transcript") || st.transcript || st.rootJSON != 0 || len(st.trustSets) != 0 || st.record {
		t.Errorf("stop %q, on disk %+v: a transcript that is not what was printed must not be written", s.Step, st)
	}
}

type rtSwitch struct {
	w      *rtBuf
	broken *atomic.Bool
}

func (s *rtSwitch) Write(p []byte) (int, error) {
	if s.broken.Load() {
		return 0, errors.New("test: the terminal is gone")
	}
	return s.w.Write(p)
}

func TestTheOrderOfTheActsOfAWholeRun(t *testing.T) {
	r := rtNew(t)
	log := &mkLog{}
	rtUseStore(r, log, nil)
	errW := &mkLineWriter{log: log, prefix: "console: "}
	outW := &mkLineWriter{log: log, prefix: "console-out: "}
	r.console = ceremony.NewConsole(errW, outW)
	r.b.r.hook = func(n int, desc string) { log.add("fs: %s", desc) }
	p, f := r.plan()
	if _, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p))); err != nil {
		t.Fatal(err)
	}
	ev := log.all()
	at := func(prefix string, nth int) int {
		t.Helper()
		seen := 0
		for i, e := range ev {
			if strings.HasPrefix(e, prefix) {
				seen++
				if seen == nth {
					return i
				}
			}
		}
		t.Fatalf("no event %q (%d) in\n%s", prefix, nth, strings.Join(ev, "\n"))
		return -1
	}
	h := "fs: %s history/" + p.Name + "/"
	rename := func(file string) string { return strings.Replace(h, "%s", "rename", 1) + file }
	order := []struct {
		name string
		idx  int
	}{
		{"the key directory is judged", at("refuse", 1)},
		{"the plan is shown with its digest", at("console: plan digest ", 1)},
		{"the confirmation", at("console: confirmed with --confirm", 1)},
		{"the first write", at("fs: mkdir history", 1)},
		{"the plan", at(rename("plan.json"), 1)},
		{"the attempt", at(rename("attempt.json"), 1)},
		{"the first birth", at("birth A", 1)},
		{"the line of the first birth", at(strings.Replace(h, "%s", "write", 1)+"births.jsonl", 1)},
		{"the second birth", at("birth B", 1)},
		{"the line of the second birth", at(strings.Replace(h, "%s", "write", 1)+"births.jsonl", 2)},
		{"the pin lines", at("console: root key A: x509 pin ", 1)},
		{"the first signature", at("sign A", 1)},
		{"the first signature line", at(strings.Replace(h, "%s", "write", 1)+"signatures.jsonl", 1)},
		{"the last signature line", at(strings.Replace(h, "%s", "write", 1)+"signatures.jsonl", 5)},
		{"the transcript", at(rename("transcript.txt"), 1)},
		{"the first artifact", at("fs: mkdir roots", 1)},
		{"the trust set", at("fs: rename trust/1-", 1)},
		{"the record", at(rename("record.json"), 1)},
		{"the summary", at("console: ceremony "+p.Name+" is recorded", 1)},
	}
	for i := 1; i < len(order); i++ {
		if order[i].idx <= order[i-1].idx {
			t.Errorf("%s (%d) is not after %s (%d)", order[i].name, order[i].idx, order[i-1].name, order[i-1].idx)
		}
	}
	// Both pin lines come before the first signature.
	if at("console: root key B: x509 pin ", 1) > at("sign A", 1) {
		t.Error("a key signed before every new key was shown")
	}
	// The transcript is written before every artifact; the record is the last file that is created.
	for _, art := range []string{"fs: mkdir roots", "fs: mkdir trust", "fs: rename trust/1-", "fs: rename roots/A/root.json", "fs: rename roots/B/root.json"} {
		if at(art, 1) < at(rename("transcript.txt"), 1) {
			t.Errorf("%s comes before the transcript", art)
		}
	}
	last := -1
	for i, e := range ev {
		if strings.HasPrefix(e, "fs: rename ") || strings.HasPrefix(e, "fs: create ") || strings.HasPrefix(e, "fs: mkdir ") {
			last = i
		}
	}
	if last != at(rename("record.json"), 1) {
		t.Errorf("the last file that was created is %q, want record.json", ev[last])
	}
	// No line is printed between the transcript and the record.
	for i := at(rename("transcript.txt"), 1); i < at(rename("record.json"), 1); i++ {
		if strings.HasPrefix(ev[i], "console") {
			t.Errorf("a line was printed between the transcript and the record: %q", ev[i])
		}
	}
	// Each journal line follows the act that it names: the birth, and each signature.
	if at("birth A", 1) > at(strings.Replace(h, "%s", "write", 1)+"births.jsonl", 1) || at("birth B", 1) > at(strings.Replace(h, "%s", "write", 1)+"births.jsonl", 2) {
		t.Error("a birth line was written before its key was made")
	}
	// The key directory is judged before the first write, and again before the first key is born.
	if log.count("refuse") != 2 || at("refuse", 2) > at("birth A", 1) || at("refuse", 2) < at("fs: rename history/"+p.Name+"/attempt.json", 1) {
		t.Errorf("the key directory was judged %d times, want before the first write and after the attempt", log.count("refuse"))
	}
}

// The secret scan: the private scalar of each key is in its key file and nowhere in the bundle, in
// the output or in the transcript.
func TestNoPrivateKeyIsInTheBundleTheOutputOrTheTranscript(t *testing.T) {
	r := rtNew(t)
	r.mustDirect()
	for _, label := range []string{"A", "B"} {
		scalar := mkScalar(t, r.keyDir, label)
		if len(scalar) == 0 {
			t.Fatal("no scalar")
		}
		needles := map[string][]byte{
			"raw":          scalar,
			"hex":          []byte(hex.EncodeToString(scalar)),
			"hex upper":    []byte(strings.ToUpper(hex.EncodeToString(scalar))),
			"base64":       []byte(base64.StdEncoding.EncodeToString(scalar)),
			"base64 url":   []byte(base64.URLEncoding.EncodeToString(scalar)),
			"base64 raw":   []byte(base64.RawStdEncoding.EncodeToString(scalar)),
			"base64 rawur": []byte(base64.RawURLEncoding.EncodeToString(scalar)),
		}
		// The key file is the one place that holds it.
		keyFile, err := os.ReadFile(filepath.Join(r.keyDir, label+".x509.key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(keyFile, needles["raw"]) && !bytes.Contains(keyFile, needles["base64"]) {
			t.Logf("the key file of %s holds the scalar inside its encoded form", label)
		}
		hay := map[string][]byte{"standard error": []byte(r.stderr.String()), "standard output": []byte(r.stdout.String())}
		for path := range r.tree() {
			full := filepath.Join(r.bundleDir, path)
			if st, err := os.Lstat(full); err == nil && st.Mode().IsRegular() {
				b, _ := os.ReadFile(full)
				hay[path] = b
			}
		}
		for where, b := range hay {
			if bytes.Contains(b, []byte("PRIVATE KEY")) {
				t.Errorf("%s holds PRIVATE KEY text", where)
			}
			for form, n := range needles {
				if len(n) >= 16 && bytes.Contains(b, n) {
					t.Errorf("%s holds the private scalar of %s (%s)", where, label, form)
				}
			}
		}
	}
	// The key directory holds the key files and the removal authorisations and nothing else.
	if got := rtNames(r.keyTree()); !slices.Equal(got, []string{"A.removal.jws", "A.x509.key.pem", "B.removal.jws", "B.x509.key.pem"}) {
		t.Errorf("the key directory holds %q", got)
	}
}

var _ = sync.Mutex{}
