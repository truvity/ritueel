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
	"ritueel.id/ritueel/internal/fsx"
)

// A write that reaches the disk with another content than was written is found by reading the file back:
// each copy of a wanted file after the plan (record 0006, rule 33, as plan.json is), and transcript.txt
// before any artifact. Each file below is changed on its way to the disk in five ways, and the writer is
// told that the whole write was made, so that only the read back can tell.

// fxIndex is the number (from 1) of the write of file data of a whole run that fills the file path.
func fxIndex(t *testing.T, path string) int {
	t.Helper()
	for i, name := range fxTargets(rtEvents(t)) {
		if name == path {
			return i + 1
		}
	}
	t.Fatalf("no write fills %s", path)
	return 0
}

// fxNoKeys fails the test when the key directory holds a key or a removal authorisation. A run that
// stopped after the key store was started, and before the first key, leaves the folder test-only-keys,
// empty; that is no key. A stop before the key store starts uses fxNoKeyDirEntries.
func fxNoKeys(t *testing.T, r *rt) {
	t.Helper()
	ents, err := os.ReadDir(r.keyDir)
	if err != nil {
		t.Errorf("the key directory cannot be read: %v", err)
		return
	}
	for _, e := range ents {
		if inner, ierr := os.ReadDir(filepath.Join(r.keyDir, e.Name())); e.Name() == "test-only-keys" && e.IsDir() && ierr == nil && len(inner) == 0 {
			continue
		}
		t.Errorf("the key directory holds %q, want no key and no removal authorisation", e.Name())
	}
}

// fxNoKeyDirEntries fails the test when the key directory holds any entry at all, the empty folder
// test-only-keys too: a run that stopped before the key store was started has made nothing in it.
func fxNoKeyDirEntries(t *testing.T, r *rt) {
	t.Helper()
	ents, err := os.ReadDir(r.keyDir)
	if err != nil {
		t.Fatalf("the key directory cannot be read: %v", err)
	}
	for _, e := range ents {
		t.Errorf("the key directory holds %q although the key store was not started", e.Name())
	}
}

func fxExists(r *rt, parts ...string) bool {
	_, err := os.Lstat(filepath.Join(append([]string{r.bundleDir}, parts...)...))
	return err == nil
}

func TestACopyOfAWantedFileThatReachesTheDiskChangedStopsTheRunBeforeTheAttemptAndBeforeAnyKey(t *testing.T) {
	for _, file := range []string{"plan.json", "wanted/ritueel.yaml", "wanted/want/roots/x509.yaml"} {
		for _, mode := range fxModes {
			t.Run(file+", "+string(mode), func(t *testing.T) {
				t.Parallel()
				idx := fxIndex(t, "history/"+pfName+"/"+file)
				r := rtNew(t)
				birth := fxCount(r)
				st := fxLie(t, r, idx, mode)
				p, f := r.plan()
				done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
				if !st.hit {
					t.Fatal("the write was not met")
				}
				s, ok := rtStopped(err)
				if done != nil || !ok {
					t.Fatalf("Run = %v, %v; want a stop", done, err)
				}
				if s.Step != "write-plan" || s.Attempt {
					t.Errorf("stop at %q with attempt %v, want write-plan and no attempt", s.Step, s.Attempt)
				}
				if !errors.Is(err, ceremony.ErrDiskMismatch) || !errors.Is(err, ceremony.ErrFolderStopped) {
					t.Errorf("the cause is not ErrDiskMismatch and ErrFolderStopped: %v", err)
				}
				var fe *ceremony.FolderError
				if !errors.As(err, &fe) || fe.Op != "write-plan" {
					t.Errorf("no FolderError of the write of the plan in %v", err)
				}
				if fxExists(r, "history", pfName, "attempt.json") || fxExists(r, "history", pfName, "births.jsonl") || fxExists(r, "history", pfName, "signatures.jsonl") {
					t.Error("an attempt or a journal exists: the run went on after a copy that is not what was written")
				}
				if fxExists(r, "roots") || fxExists(r, "trust") || fxExists(r, "history", pfName, "record.json") {
					t.Error("an artifact or a record exists")
				}
				fxNoKeys(t, r)
				fxNoKeyDirEntries(t, r)
				if b, sv := birth.counts(); b != 0 || sv != 0 {
					t.Errorf("the store made %d keys and %d removals", b, sv)
				}
				msg := err.Error()
				for _, w := range []string{"stopped at write-plan", "the plan folder may hold some of its files, no attempt was written, and no key was made", "nothing was retried, and ritueel deleted nothing"} {
					if !strings.Contains(msg, w) {
						t.Errorf("the line does not say %q: %s", w, msg)
					}
				}
				if strings.Contains(msg, "the plan and the copies are written") || strings.Contains(msg, "an attempt is open") {
					t.Errorf("the line says what is not true: %s", msg)
				}
				if r.stdout.String() != "" {
					t.Errorf("standard output holds %q", r.stdout.String())
				}
			})
		}
	}
}

func TestAFolderThatWritesACopyThatReachesTheDiskChangedIsStoppedAndMakesNoAttempt(t *testing.T) {
	// The folder alone, without Run: the call that wrote the files returns the fault, and a later call
	// is refused.
	ev := rtEvents(t)
	targets := fxTargets(ev)
	for _, file := range []string{"plan.json", "wanted/ritueel.yaml", "wanted/want/roots/x509.yaml"} {
		for _, mode := range fxModes {
			t.Run(file+", "+string(mode), func(t *testing.T) {
				idx := 0
				for i, n := range targets {
					if n == "history/"+pfName+"/"+file {
						idx = i + 1
					}
				}
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "ritueel.yaml"), []byte(manifestText), 0o644); err != nil {
					t.Fatal(err)
				}
				inner, err := fsx.OpenFS(dir)
				if err != nil {
					t.Fatal(err)
				}
				st := &fxState{target: idx, mode: mode}
				w := &fsx.Writer{FS: &fxFS{in: inner, st: st}}
				t.Cleanup(func() { _ = w.Close() })
				f, err := ceremony.NewFolder(w, pfName)
				if err != nil {
					t.Fatal(err)
				}
				r := rtNew(t)
				p, found := r.plan()
				err = f.WritePlan(p.JSON, found.Wanted)
				if !st.hit {
					t.Fatal("the write was not met")
				}
				if !errors.Is(err, ceremony.ErrDiskMismatch) || !errors.Is(err, ceremony.ErrFolderStopped) {
					t.Fatalf("WritePlan = %v, want ErrDiskMismatch and ErrFolderStopped", err)
				}
				var fe *ceremony.FolderError
				if !errors.As(err, &fe) || fe.Op != "write-plan" {
					t.Errorf("the error is %v", err)
				}
				if _, err := os.Lstat(filepath.Join(dir, "history", pfName, "attempt.json")); err == nil {
					t.Error("attempt.json exists")
				}
				// A stopped folder does nothing more.
				if _, serr := f.Start(attemptOf(p)); !errors.Is(serr, ceremony.ErrFolderStopped) {
					t.Errorf("Start after the fault = %v, want ErrFolderStopped", serr)
				}
				if _, err := os.Lstat(filepath.Join(dir, "history", pfName, "attempt.json")); err == nil {
					t.Error("attempt.json exists after Start of a stopped folder")
				}
			})
		}
	}
}

func TestATranscriptThatReachesTheDiskChangedStopsTheRunBeforeAnyArtifact(t *testing.T) {
	for _, mode := range fxModes {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			idx := fxIndex(t, "history/"+pfName+"/transcript.txt")
			r := rtNew(t)
			st := fxLie(t, r, idx, mode)
			p, f := r.plan()
			done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
			if !st.hit {
				t.Fatal("the write was not met")
			}
			s, ok := rtStopped(err)
			if done != nil || !ok {
				t.Fatalf("Run = %v, %v; want a stop", done, err)
			}
			if s.Step != "transcript" || !s.Attempt {
				t.Errorf("stop at %q with attempt %v, want transcript and an open attempt", s.Step, s.Attempt)
			}
			if !errors.Is(err, ceremony.ErrDiskMismatch) {
				t.Errorf("the cause is not ErrDiskMismatch: %v", err)
			}
			if fxExists(r, "roots") || fxExists(r, "trust") || fxExists(r, "history", pfName, "record.json") {
				t.Error("an artifact or a record was written after a transcript that is not what was printed")
			}
			if !strings.Contains(err.Error(), "an attempt is open") {
				t.Errorf("the line: %s", err.Error())
			}
			if r.stdout.String() != "" {
				t.Errorf("the end line was printed: %q", r.stdout.String())
			}
		})
	}
}

func TestEveryWriteOfARunThatReachesTheDiskChangedStopsTheRunAtTheStepOfThatFile(t *testing.T) {
	// Every write of file data of a whole run, each changed in each way: none ends well, and the stop is at
	// the step of the file that was changed.
	targets := fxTargets(rtEvents(t))
	if len(targets) < 18 {
		t.Fatalf("a whole run writes %d files of data, want at least 18", len(targets))
	}
	step := func(path string) string {
		switch {
		case strings.HasSuffix(path, "/plan.json"), strings.Contains(path, "/wanted/"):
			return "write-plan"
		case strings.HasSuffix(path, "/attempt.json"):
			return "attempt"
		case strings.HasSuffix(path, "/births.jsonl"), strings.HasSuffix(path, "/signatures.jsonl"):
			return "journals"
		case strings.HasSuffix(path, "/transcript.txt"):
			return "transcript"
		case strings.HasSuffix(path, "/record.json"):
			return "record"
		}
		return "artifacts"
	}
	for k, path := range targets {
		for _, mode := range fxModes {
			t.Run(rtItoa(k+1)+" "+path+", "+string(mode), func(t *testing.T) {
				t.Parallel()
				r := rtNew(t)
				st := fxLie(t, r, k+1, mode)
				p, f := r.plan()
				done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
				if !st.hit {
					t.Fatal("the write was not met")
				}
				if done != nil {
					t.Fatalf("Run ended well although the write of %s reached the disk changed (%s)", path, mode)
				}
				s, ok := rtStopped(err)
				if !ok {
					t.Fatalf("the error is %T %v, want a stop", err, err)
				}
				if want := step(path); s.Step != want {
					t.Errorf("stop at %q, want %q: %v", s.Step, want, err)
				}
			})
		}
	}
}

func TestTheLineOfAStopWhilePlanningSaysOnlyWhatIsTrueAtEachOfTheFirstWrites(t *testing.T) {
	l := rtLayoutOf(t, pfName)
	if l.planEnd != 25 {
		t.Fatalf("the plan is written by %d changing calls, the test is built for 25", l.planEnd)
	}
	const want = "the plan folder may hold some of its files, no attempt was written, and no key was made"
	for n := 1; n <= l.planEnd; n++ {
		t.Run("cut at "+rtItoa(n), func(t *testing.T) {
			t.Parallel()
			r := rtNew(t, rtFailAt(n))
			birth := fxCount(r)
			p, f := r.plan()
			_, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
			s, ok := rtStopped(err)
			if !ok || s.Step != "write-plan" || s.Attempt {
				t.Fatalf("Run = %v, want a stop at write-plan with no attempt", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, "; "+want+"; nothing was retried, and ritueel deleted nothing") {
				t.Errorf("the line does not say %q before the closing words: %s", want, msg)
			}
			for _, not := range []string{"the plan and the copies are written", "an attempt is open", "close", "nothing was signed", "no attempt exists"} {
				if strings.Contains(msg, not) {
					t.Errorf("the line says %q: %s", not, msg)
				}
			}
			if strings.Contains(msg, "key directory may hold") {
				t.Errorf("the line names key files before any key could exist: %s", msg)
			}
			// What the line says is what is on disk.
			if fxExists(r, "history", pfName, "attempt.json") {
				t.Error("attempt.json exists")
			}
			fxNoKeys(t, r)
			fxNoKeyDirEntries(t, r)
			if b, _ := birth.counts(); b != 0 {
				t.Errorf("%d keys were made", b)
			}
			if r.stdout.String() != "" {
				t.Errorf("standard output holds %q", r.stdout.String())
			}
		})
	}
}
