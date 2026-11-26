//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
)

// The words of the line of a stop that say what the key directory may hold: none at the write of the
// attempt, the key files from the first call of the maker on, and the temporary file from the step make on.

// stopClosing are the last words of the line of a stop with an open attempt, and stopEnd the last words
// of every line of a stop.
const (
	stopClosing = "; close, which closes an open attempt, is not built yet"
	stopEnd     = "; nothing was retried, and ritueel deleted nothing"
)

// rtWantMakeLine fails the test when the line of a stop in the phase of an open attempt does not hold the
// two clauses once each, in order, and then the words of the end.
func rtWantMakeLine(t *testing.T, msg string) {
	t.Helper()
	if !pfPrintable(msg) {
		t.Errorf("the line %+q is not printable ASCII on one line", msg)
	}
	if !strings.Contains(msg, "an attempt is open") {
		t.Errorf("the line does not say that an attempt is open: %s", msg)
	}
	if !strings.HasSuffix(msg, stopKeyClause+stopTempClause+stopClosing+stopEnd) {
		t.Errorf("the line does not end with the clause of the key files, the clause of the temporary file, close and the end words: %s", msg)
	}
	if n := strings.Count(msg, stopKeyClause); n != 1 {
		t.Errorf("the clause of the key files is in the line %d times: %s", n, msg)
	}
	if n := strings.Count(msg, stopTempClause); n != 1 {
		t.Errorf("the clause of the temporary file is in the line %d times: %s", n, msg)
	}
}

func TestTheLineOfAStopAtMakeHoldsTheClauseOfTheTemporaryFileAfterTheKeyFiles(t *testing.T) {
	boom := errors.New("test: the store failed")
	cases := []struct {
		name string
		edit func(*mkStore)
	}{
		{"the birth of A", func(s *mkStore) { s.failBirth = map[string]error{"A": boom} }},
		{"the birth of B", func(s *mkStore) { s.failBirth = map[string]error{"B": boom} }},
		{"a key and an error", func(s *mkStore) { s.keyAndErr = map[string]error{"A": boom} }},
		{"the removal of A", func(s *mkStore) { s.failRemoval = map[string]error{"A": boom} }},
		{"a key file that exists", func(s *mkStore) {
			s.failBirth = map[string]error{"B": &ceremony.BackendError{Reasons: []string{"key-exists"}, Msg: "a key file exists"}}
		}},
		{"a store that panics at the birth", func(s *mkStore) { s.panicOn = "birth" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rtNew(t)
			rtUseStore(r, &mkLog{}, c.edit)
			s, _, err := rtStopOf(t, r)
			if s.Step != "make" {
				t.Fatalf("stop at %q, want make", s.Step)
			}
			rtWantMakeLine(t, err.Error())
		})
	}
}

func TestTheLineOfAStopAtEachLaterStepHoldsTheClauseOfTheTemporaryFile(t *testing.T) {
	// The steps after make, by the one fault that reaches each of them without a cut of the disk: a read back
	// of a removal that fails (journals), and a context that ends after a write of the step before (the
	// transcript, the artifacts, the record).
	t.Run("journals: a removal that is not what was made", func(t *testing.T) {
		r := rtNew(t)
		reads := 0
		rtUseStore(r, &mkLog{}, func(s *mkStore) {
			s.readRemoval = func(label string, real []byte) []byte {
				if label == "A" {
					if reads++; reads == 2 {
						return append(append([]byte(nil), real...), 'x')
					}
				}
				return real
			}
		})
		s, _, err := rtStopOf(t, r)
		if s.Step != "journals" {
			t.Fatalf("stop at %q, want journals", s.Step)
		}
		rtWantMakeLine(t, err.Error())
	})
	cases := []struct {
		name, desc, step string
		nth              int
	}{
		{"make: after the last signature", "sync-file HIST/signatures.jsonl", "make", 6},
		{"artifacts: after the transcript", "rename HIST/transcript.txt", "artifacts", 1},
		{"record: after the trust set", "rename trust/1-", "record", 1},
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
					if seen++; seen == c.nth {
						cancel()
					}
				}
			}
			done, err := ceremony.Run(ctx, r.in(p, f, rtFlag(p)))
			s, ok := rtStopped(err)
			if done != nil || !ok || s.Step != c.step || !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v, %v; want a stop at %s that holds context.Canceled", done, err, c.step)
			}
			rtWantMakeLine(t, err.Error())
		})
	}
}

func TestTheLineOfAStopAfterTheRecordIsWrittenHoldsTheClauseOfTheTemporaryFileAndNoOther(t *testing.T) {
	// A stop in the phase of a written record: no attempt is open, so no key files are named and close is not
	// named; the temporary file is, as at every step from make on.
	check := func(t *testing.T, step string, err error, done *ceremony.Done) {
		t.Helper()
		s, ok := rtStopped(err)
		if done != nil || !ok || s.Step != step || s.Attempt {
			t.Fatalf("Run = %v, %v; want a stop at %s with no open attempt", done, err, step)
		}
		msg := err.Error()
		if !pfPrintable(msg) {
			t.Errorf("the line %+q is not printable ASCII on one line", msg)
		}
		if !strings.HasSuffix(msg, "; the ceremony record is written"+stopTempClause+stopEnd) {
			t.Errorf("the line does not end with the record, the clause of the temporary file and the end words: %s", msg)
		}
		for _, not := range []string{stopKeyClause, "key directory may hold", "x509-root-a", "an attempt is open", "close, which closes"} {
			if strings.Contains(msg, not) {
				t.Errorf("the line says %q after the record is written: %s", not, msg)
			}
		}
		if n := strings.Count(msg, stopTempClause); n != 1 {
			t.Errorf("the clause of the temporary file is in the line %d times: %s", n, msg)
		}
	}
	t.Run("the check refuses the bundle", func(t *testing.T) {
		_, done, err := rtAtRecord(t, func(r *rt, name string) {
			if e := os.WriteFile(filepath.Join(r.bundleDir, "history", name, "transcript.txt"), []byte("changed\n"), 0o644); e != nil {
				t.Error(e)
			}
		})
		check(t, "check", err, done)
	})
	t.Run("the check cannot run", func(t *testing.T) {
		r := rtNew(t)
		p, f := r.plan()
		total := len(rtEvents(t))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r.b.r.hook = func(n int, desc string) {
			if n == total {
				cancel()
			}
		}
		done, err := ceremony.Run(ctx, r.in(p, f, rtFlag(p)))
		check(t, "check", err, done)
	})
}

func TestTheLineOfAStopAtTheWriteOfTheAttemptNamesNoKeyFileAtAnyChangingCallOfThatWrite(t *testing.T) {
	l := rtLayoutOf(t, pfName)
	calls := l.attemptEnd - l.planEnd
	if calls < 5 {
		t.Fatalf("the write of the attempt makes %d changing calls, want the attempt, the two journals and their syncs", calls)
	}
	const state = "; attempt.json may or may not have been written, so treat an attempt as open; nothing was signed"
	for n := l.planEnd + 1; n <= l.attemptEnd; n++ {
		t.Run("cut at "+rtItoa(n), func(t *testing.T) {
			t.Parallel()
			r := rtNew(t, rtFailAt(n))
			log := &mkLog{}
			rtUseStore(r, log, nil)
			p, f := r.plan()
			done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
			s, ok := rtStopped(err)
			if done != nil || !ok || s.Step != "attempt" || !s.Attempt {
				t.Fatalf("Run = %v, %v; want a stop at attempt with an attempt that may be open", done, err)
			}
			msg := err.Error()
			if !strings.HasSuffix(msg, state+stopEmptyClause+stopClosing+stopEnd) {
				t.Errorf("the line does not end with the words of the attempt that may be open: %s", msg)
			}
			for _, not := range []string{"key file", ".p8", "x509-root-a", "removal authorisation", "a temporary file whose name starts with", "remove one by hand"} {
				if strings.Contains(msg, not) {
					t.Errorf("the line of a stop at the write of the attempt says %q: %s", not, msg)
				}
			}
			if got := log.count("birth"); got != 0 {
				t.Errorf("%d keys were born although the attempt was not written", got)
			}
		})
	}
}

func TestTheLineOfAStopBeforeTheMakerRanHoldsNoClauseOfTheKeyDirectory(t *testing.T) {
	check := func(t *testing.T, err error, step string, attempt bool) {
		t.Helper()
		s, ok := rtStopped(err)
		if !ok || s.Step != step || s.Attempt != attempt {
			t.Fatalf("the error is %v, want a stop at %s (attempt %v)", err, step, attempt)
		}
		for _, not := range []string{"key directory", "x509-root-a", "a temporary file whose name starts with", "removal authorisation"} {
			if strings.Contains(err.Error(), not) {
				t.Errorf("the line says %q: %s", not, err.Error())
			}
		}
	}
	t.Run("a context that ended before the attempt", func(t *testing.T) {
		// The second judgement of the state before the attempt: the stop is at the step attempt and no attempt
		// was written (the folder of the plan stands).
		r := rtNew(t)
		p, f := r.plan()
		l := rtLayoutOf(t, pfName)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		r.b.r.hook = func(n int, desc string) {
			if n == l.planEnd {
				cancel()
			}
		}
		done, err := ceremony.Run(ctx, r.in(p, f, rtFlag(p)))
		if done != nil {
			t.Fatalf("Run ended well: %+v", done)
		}
		check(t, err, "attempt", false)
		if !strings.Contains(err.Error(), "no attempt was written") {
			t.Errorf("the line does not say that no attempt was written: %s", err.Error())
		}
		if !errors.Is(err, context.Canceled) {
			t.Errorf("the cause is not reachable: %v", err)
		}
	})
	t.Run("a cut at the write of the plan", func(t *testing.T) {
		r := rtNew(t, rtFailAt(1))
		p, f := r.plan()
		_, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
		check(t, err, "write-plan", false)
	})
}

func TestTheLineOfAStopNamesNoFileOfTheKeyDirectoryAndIsTheSameWhateverItHolds(t *testing.T) {
	// The clause is fixed words: no folder is read and no file is listed. A key directory that holds a
	// leftover temporary file gives the same line as one that holds none.
	line := func(t *testing.T, leftover string) (msg, keyDir string) {
		t.Helper()
		r := rtNew(t)
		w := &mkStore{log: &mkLog{}}
		r.open = func(keyDir, bundleDir string) (ceremony.RootStore, error) {
			inner, err := ceremony.NewSoftwareStore(keyDir, bundleDir)
			if err != nil {
				return nil, err
			}
			w.inner = inner
			calls := 0
			return rtRefuseHook{mkStore: w, after: func() {
				// The second refusal is the one that the maker asks for before the first key is born: a key
				// file stands in the place of B after it, and a leftover temporary file beside it.
				if calls++; calls != 2 {
					return
				}
				if err := os.WriteFile(filepath.Join(keyDir, mkKeyFile("B")), []byte("planted"), 0o600); err != nil {
					t.Error(err)
				}
				if leftover != "" {
					if err := os.WriteFile(filepath.Join(keyDir, leftover), []byte("a leftover"), 0o600); err != nil {
						t.Error(err)
					}
				}
			}}, nil
		}
		s, _, err := rtStopOf(t, r)
		if s.Step != "make" {
			t.Fatalf("stop at %q, want make", s.Step)
		}
		return err.Error(), r.keyDir
	}
	plain, k1 := line(t, "")
	with, k2 := line(t, ".rt-leftover0000")
	rtWantMakeLine(t, plain)
	rtWantMakeLine(t, with)
	if strings.Contains(with, "leftover0000") {
		t.Errorf("the line lists the file that stands in the key directory: %s", with)
	}
	if a, b := strings.ReplaceAll(plain, k1, "KEYS"), strings.ReplaceAll(with, k2, "KEYS"); a != b {
		t.Errorf("a key directory that holds a leftover gives another line:\n%s\n%s", a, b)
	}
}
