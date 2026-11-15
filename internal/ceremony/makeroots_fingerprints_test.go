//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/wanted"
)

// record 0005, rule 11: each fingerprint is shown before any root key signs for it. A line that could
// not be printed was not shown, so the run stops after the births and before the first signature, and
// says what is on disk.

// mkFailAfter is a stream that passes the first n writes to inner and refuses every write after them.
type mkFailAfter struct {
	inner io.Writer
	n     int

	mu   sync.Mutex
	seen int
}

func (w *mkFailAfter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.seen++
	fail := w.seen > w.n
	w.mu.Unlock()
	if fail {
		return 0, errors.New("test: the stream is closed")
	}
	return w.inner.Write(p)
}

// mkPanicWriter is a stream that panics.
type mkPanicWriter struct{}

func (mkPanicWriter) Write([]byte) (int, error) { panic("test: the stream panics") }

// mkWantStoppedAfterTheBirths holds what every run that stops at the fingerprints must show.
func mkWantStoppedAfterTheBirths(t *testing.T, r *mkRun, m *ceremony.Made, err error) {
	t.Helper()
	if m != nil || err == nil {
		t.Fatalf("MakeRoots made a result (%v) and returned %v although the fingerprints were not shown", m != nil, err)
	}
	me, ok := mkAs[*ceremony.MakeError](err)
	if !ok {
		t.Fatalf("the error is %T (%v), want a *MakeError", err, err)
	}
	if me.Step != "fingerprints" {
		t.Errorf("the step is %q, want fingerprints", me.Step)
	}
	text := err.Error()
	for _, want := range []string{"nothing is signed", "A.x509.key.pem", "B.x509.key.pem", "2 lines"} {
		if !strings.Contains(text, want) {
			t.Errorf("the error does not say %q: %s", want, text)
		}
	}
	if !pfPrintable(text) {
		t.Errorf("the text %+q is not printable ASCII", text)
	}
	if n := r.log.count("sign "); n != 0 {
		t.Errorf("%d signatures were made", n)
	}
	if n := r.log.count("signatures-line"); n != 0 {
		t.Errorf("%d signature lines were written", n)
	}
	if n := r.log.count("save-removal"); n != 0 {
		t.Errorf("%d removal authorisations were stored", n)
	}
	if n := r.log.count("births-line"); n != 2 {
		t.Errorf("%d birth lines were written, want 2", n)
	}
	// The keys are born and are kept: nothing is deleted by any path.
	if got := strings.Join(r.keyFiles(), " "); got != "A.x509.key.pem B.x509.key.pem" {
		t.Errorf("the key folder holds %q", got)
	}
	for _, label := range []string{"A", "B"} {
		if len(mkScalar(t, r.keyDir, label)) == 0 {
			t.Errorf("the key file of %s is empty", label)
		}
	}
	// Every key that the store made was closed once.
	if len(r.store.keys) != 2 {
		t.Fatalf("the store made %d keys, want 2", len(r.store.keys))
	}
	for _, k := range r.store.keys {
		if k.closed() != 1 {
			t.Errorf("the key %s was closed %d times, want 1", k.label, k.closed())
		}
	}
}

func TestAConsoleThatFailsAfterTheFirstFingerprintStopsTheRunBeforeTheFirstSignature(t *testing.T) {
	r := newMkRun(t)
	r.env.Out = ceremony.NewConsole(&mkFailAfter{inner: r.stderr, n: 1}, r.stdout)
	m, err := r.make()
	mkWantStoppedAfterTheBirths(t, r, m, err)
	if !errors.Is(err, ceremony.ErrPrintFailed) {
		t.Errorf("the cause is not ErrPrintFailed: %v", err)
	}
	if n := r.log.count("console: root key A"); n != 1 {
		t.Errorf("the first fingerprint was printed %d times, want 1", n)
	}
	if n := r.log.count("console: root key B"); n != 0 {
		t.Errorf("the second fingerprint was printed although the stream was closed")
	}
}

func TestAConsoleThatFailsAtTheFirstFingerprintStopsTheRunBeforeTheFirstSignature(t *testing.T) {
	r := newMkRun(t)
	r.env.Out = ceremony.NewConsole(&mkFailAfter{inner: r.stderr, n: 0}, r.stdout)
	m, err := r.make()
	mkWantStoppedAfterTheBirths(t, r, m, err)
	if !errors.Is(err, ceremony.ErrPrintFailed) {
		t.Errorf("the cause is not ErrPrintFailed: %v", err)
	}
}

func TestAConsoleWhoseStreamPanicsStopsTheRunBeforeTheFirstSignature(t *testing.T) {
	r := newMkRun(t)
	r.env.Out = ceremony.NewConsole(mkPanicWriter{}, r.stdout)
	m, err := r.make()
	mkWantStoppedAfterTheBirths(t, r, m, err)
	if !errors.Is(err, ceremony.ErrPrintFailed) {
		t.Errorf("the cause is not ErrPrintFailed: %v", err)
	}
}

func TestAConsoleWithNoStreamForTheLinesStopsTheRunBeforeTheFirstSignature(t *testing.T) {
	// The fingerprints go to standard error. A console that was given no stream for it keeps the lines
	// and prints none, and the transcript would say what no person read.
	r := newMkRun(t)
	r.env.Out = ceremony.NewConsole(nil, r.stdout)
	m, err := r.make()
	mkWantStoppedAfterTheBirths(t, r, m, err)
	if !errors.Is(err, ceremony.ErrPrintFailed) {
		t.Errorf("the cause is not ErrPrintFailed: %v", err)
	}
}

func TestAConsoleThatHoldsMoreThanATranscriptTakesStopsTheRunBeforeTheFirstSignature(t *testing.T) {
	// The lines were printed, and the transcript cannot hold them: the console has a fault and the
	// run stops, because the record of the ceremony could not be written from it.
	r := newMkRun(t)
	for i := 0; i < ceremony.MaxTranscriptLines; i++ {
		r.console.Err("a line that was printed before the run: %d", i)
	}
	if _, err := r.console.Transcript(); err != nil {
		t.Fatalf("the console is full and not yet over: %v", err)
	}
	m, err := r.make()
	mkWantStoppedAfterTheBirths(t, r, m, err)
	if !errors.Is(err, ceremony.ErrTranscriptLimit) {
		t.Errorf("the cause is not ErrTranscriptLimit: %v", err)
	}
}

func TestAConsoleThatCannotPrintTheStandardOutputOnlyDoesNotStopTheFingerprints(t *testing.T) {
	// The fingerprints are lines of standard error. The other stream is not part of what a person
	// must see before a key signs, and a fault of it that no line met is no fault of the run.
	r := newMkRun(t)
	r.env.Out = ceremony.NewConsole(r.stderr, mkBrokenWriter{})
	m, err := r.make()
	if err != nil || m == nil {
		t.Fatalf("MakeRoots: %v", err)
	}
	if n := r.log.count("sign "); n != 5 {
		t.Errorf("%d signatures were made, want 5", n)
	}
}

func TestTheFingerprintsAreShownOnceAndBeforeEachSignatureOfAGoodRun(t *testing.T) {
	r, _ := mkGood(t)
	lastFingerprint := -1
	for i, e := range r.log.all() {
		if strings.HasPrefix(e, "console: root key ") {
			lastFingerprint = i
		}
	}
	firstSign := r.log.index("sign ")
	if lastFingerprint < 0 || firstSign < 0 || lastFingerprint > firstSign {
		t.Fatalf("the last fingerprint stands at %d and the first signature at %d:\n%s", lastFingerprint, firstSign, strings.Join(r.log.all(), "\n"))
	}
	if n := r.log.count("console: root key "); n != 2 {
		t.Errorf("%d fingerprint lines, want 2", n)
	}
}

// ---- the settings and the root file are the files of the confirmed plan ----

func TestASettingsOrRootFileThatIsNotTheFileOfThePlanByPathOrDigestIsRefusedBeforeTheStoreIsAsked(t *testing.T) {
	for name, edit := range map[string]func(r *mkRun, in *ceremony.MakeIn){
		"ritueel.yaml with the bytes of the plan and another path": func(r *mkRun, in *ceremony.MakeIn) {
			s, err := wanted.ParseSettings("other/ritueel.yaml", []byte(pfSettings))
			if err != nil {
				t.Fatal(err)
			}
			in.Settings = s
		},
		"ritueel.yaml with another digest and the path of the plan": func(r *mkRun, in *ceremony.MakeIn) {
			s := *r.found.Settings
			s.File.SHA256 = strings.Repeat("ab", 32)
			in.Settings = &s
		},
		"ritueel.yaml with an empty digest": func(r *mkRun, in *ceremony.MakeIn) {
			s := *r.found.Settings
			s.File.SHA256 = ""
			in.Settings = &s
		},
		"ritueel.yaml with an empty path": func(r *mkRun, in *ceremony.MakeIn) {
			s := *r.found.Settings
			s.File.Path = ""
			in.Settings = &s
		},
		"the root file with another path": func(r *mkRun, in *ceremony.MakeIn) {
			x := *r.found.Root
			x.File.Path = "want/roots/other.yaml"
			in.Root = &x
		},
		"the root file with another digest": func(r *mkRun, in *ceremony.MakeIn) {
			x := *r.found.Root
			x.File.SHA256 = strings.Repeat("cd", 32)
			in.Root = &x
		},
		"the root file with an empty digest": func(r *mkRun, in *ceremony.MakeIn) {
			x := *r.found.Root
			x.File.SHA256 = ""
			in.Root = &x
		},
		"the two digests exchanged": func(r *mkRun, in *ceremony.MakeIn) {
			s, x := *r.found.Settings, *r.found.Root
			s.File.SHA256, x.File.SHA256 = x.File.SHA256, s.File.SHA256
			in.Settings, in.Root = &s, &x
		},
		"the two paths exchanged": func(r *mkRun, in *ceremony.MakeIn) {
			s, x := *r.found.Settings, *r.found.Root
			s.File.Path, x.File.Path = x.File.Path, s.File.Path
			in.Settings, in.Root = &s, &x
		},
		"the path of the plan with a dot segment": func(r *mkRun, in *ceremony.MakeIn) {
			s := *r.found.Settings
			s.File.Path = "./" + s.File.Path
			in.Settings = &s
		},
		"the digest of the plan in upper case": func(r *mkRun, in *ceremony.MakeIn) {
			s := *r.found.Settings
			s.File.SHA256 = strings.ToUpper(s.File.SHA256)
			in.Settings = &s
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newMkRun(t)
			in := r.in()
			edit(r, &in)
			m, err := ceremony.MakeRoots(context.Background(), in)
			if m != nil || err == nil {
				t.Fatalf("MakeRoots made a result (%v) from a file that is not the file of the plan: %v", m != nil, err)
			}
			me, ok := mkAs[*ceremony.MakeError](err)
			if !ok || me.Step != "input" {
				t.Fatalf("the error is %T (%v), want a *MakeError of the step input", err, err)
			}
			if !strings.Contains(err.Error(), "confirmed plan") && !strings.Contains(err.Error(), "ritueel.yaml") {
				t.Errorf("the error does not say what is wrong: %v", err)
			}
			if ev := r.log.all(); len(ev) != 0 {
				t.Errorf("the store, a journal or the console was used before the refusal:\n%s", strings.Join(ev, "\n"))
			}
			if len(r.keyFiles()) != 0 {
				t.Errorf("a key was made: %v", r.keyFiles())
			}
			if _, err := os.Stat(filepath.Join(r.keyDir, "A.x509.key.pem")); err == nil {
				t.Error("the key file of A exists")
			}
		})
	}
}

func TestTheFilesOfThePlanAreAcceptedWhateverTheOrderThatTheyAreGivenIn(t *testing.T) {
	// The check sorts by path: the input names the two files by field, and that is its only order.
	r := newMkRun(t)
	in := r.in()
	if len(r.plan.Wanted) != 2 {
		t.Fatalf("the plan lists %d wanted files, want 2", len(r.plan.Wanted))
	}
	if in.Settings.File.Path != r.plan.Wanted[1].Path && in.Settings.File.Path != r.plan.Wanted[0].Path {
		t.Fatalf("the path of ritueel.yaml is not in the plan: %q", in.Settings.File.Path)
	}
	if m, err := ceremony.MakeRoots(context.Background(), in); err != nil || m == nil {
		t.Fatalf("MakeRoots: %v", err)
	}
}

func TestTheFilesOfThePlanAreJudgedBeforeTheStoreIsAskedAnything(t *testing.T) {
	// A store that panics in any call that the engine makes before the first key would turn the
	// refusal into another error, if the files were judged after it was asked. The refusal that is
	// returned is the one about the files.
	for _, call := range []string{"kind", "place", "refuse", "birth"} {
		t.Run("a store that panics in "+call, func(t *testing.T) {
			r := newMkRun(t)
			r.store.panicOn = call
			s, err := wanted.ParseSettings("other/ritueel.yaml", []byte(pfSettings))
			if err != nil {
				t.Fatal(err)
			}
			in := r.in()
			in.Settings = s
			m, err := ceremony.MakeRoots(context.Background(), in)
			if m != nil || err == nil || !strings.Contains(err.Error(), "confirmed plan") {
				t.Fatalf("MakeRoots: %v, %v; want the refusal about the files of the plan", m != nil, err)
			}
		})
	}
}
