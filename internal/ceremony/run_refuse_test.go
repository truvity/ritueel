//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// The refusals of a run, in the order of the page: what is judged before the confirmation is asked,
// the exit code of each, and that nothing is written (the key directory included).

// rtRefused runs a direct apply that must be refused before the first write, and checks the kind of
// the error, that nothing changed, that no line was asked of the person, and that the text is plain.
func rtRefused(t *testing.T, r *rt, in ceremony.RunIn, kind string) error {
	t.Helper()
	before, keys := r.tree(), r.keyTree()
	outBefore := r.stdout.String()
	done, err := ceremony.Run(context.Background(), in)
	if done != nil || err == nil {
		t.Fatalf("Run = %v, %v; want a refusal of kind %s", done, err, kind)
	}
	if got := rtKind(err); got != kind {
		t.Fatalf("the error is %s (%v), want %s", got, err, kind)
	}
	if _, stopped := rtStopped(err); stopped {
		t.Errorf("a refusal before the first write is a stop of a ceremony: %v", err)
	}
	sameTree(t, "a refusal", before, r.tree())
	sameTree(t, "a refusal (key directory)", keys, r.keyTree())
	if r.stdin != nil && r.stdin.count() != 0 {
		t.Errorf("standard input was read %d times before the refusal", r.stdin.count())
	}
	if !pfPrintable(err.Error()) || strings.Contains(err.Error(), "\n") {
		t.Errorf("the text %q is not one line of printable ASCII", err.Error())
	}
	if r.stdout.String() != outBefore {
		t.Errorf("a refusal printed on standard output: %q", strings.TrimPrefix(r.stdout.String(), outBefore))
	}
	return err
}

func rtReasons(t *testing.T, err error) []string {
	t.Helper()
	var ref *ceremony.RefusedError
	var back *ceremony.BackendError
	switch {
	case errors.As(err, &ref):
		return ref.Reasons
	case errors.As(err, &back):
		return back.Reasons
	}
	t.Fatalf("%v has no reasons", err)
	return nil
}

func TestAHistoryThatFailsItsCheckIsRefusedWithTheFindingsAndNothingIsAsked(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	// A completed ceremony whose transcript is changed afterwards: the check of the history fails.
	r.mustDirect()
	tp := filepath.Join(r.bundleDir, "history", p.Name, "transcript.txt")
	if err := os.WriteFile(tp, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := history.Check(context.Background(), r.b.raw)
	if err != nil || rep.Clean() {
		t.Fatalf("the check of the changed history: %v, clean %v", err, rep.Clean())
	}
	want := codes(rep.Reasons())
	for _, saved := range []bool{false, true} {
		in := r.in(p, f, rtFlag(p))
		in.Saved = saved
		if saved {
			in.Wanted = nil
		}
		err := rtRefused(t, r.typed(p.SHA256[:8]+"\n"), in, "refused")
		got := rtReasons(t, err)
		if !slices.Equal(got, want) || !slices.Contains(got, "transcript-digest") {
			t.Errorf("saved=%v: reasons %q, want the findings of the check %q", saved, got, want)
		}
	}
}

func TestAnOpenAttemptIsRefusedWithUnfinishedCeremonyForAPlanAndForARun(t *testing.T) {
	// The run stops after the attempt (the first write of a journal fails): the folder holds an
	// attempt and no record.
	r := rtNew(t, rtFailAt(37))
	p, f := r.plan()
	_, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
	if s, ok := rtStopped(err); !ok || !s.Attempt {
		t.Fatalf("Run = %v, want a stop with an open attempt", err)
	}
	again := openBundle(t, r.bundleDir, 0)
	for _, saved := range []bool{false, true} {
		r2 := &rt{t: t, root: r.root, bundleDir: r.bundleDir, keyDir: rtMkdir(t), b: again, stderr: &rtBuf{}, stdout: &rtBuf{}, clockAt: pfClock.Add(time.Minute)}
		r2.console = ceremony.NewConsole(r2.stderr, r2.stdout)
		in := r2.in(p, f, rtFlag(p))
		in.Saved = saved
		err := rtRefused(t, r2, in, "refused")
		if got := rtReasons(t, err); !slices.Equal(got, []string{"unfinished-ceremony"}) {
			t.Errorf("saved=%v: reasons %q, want unfinished-ceremony", saved, got)
		}
		if !strings.Contains(err.Error(), "history/"+p.Name) || !strings.Contains(err.Error(), "close is not built") {
			t.Errorf("the text does not name the folder and say that close is not built: %v", err)
		}
	}
}

func rtMkdir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestABundleThatHoldsARecordIsNotFirstForARunAndStaleForASavedPlan(t *testing.T) {
	r := rtNew(t)
	saved := r.savePlan()
	p, f := r.plan()
	if done, err := ceremony.Run(context.Background(), r.savedIn(saved, rtFlag(saved))); err != nil || done == nil {
		t.Fatalf("Run = %v, %v", done, err)
	}
	// Direct: this version makes the first apply only.
	in := r.in(p, f, rtFlag(p))
	err := rtRefused(t, r, in, "not-first")
	if !errors.Is(err, ceremony.ErrNotFirst) || !strings.Contains(err.Error(), "ceremony record") {
		t.Errorf("direct: %v", err)
	}
	// Saved: the plan was made against a bundle with no ceremony record.
	rs := r
	in = rs.savedIn(saved, rtFlag(saved))
	err = rtRefused(t, r, in, "refused")
	if got := rtReasons(t, err); !slices.Equal(got, []string{"plan-stale"}) {
		t.Errorf("saved: reasons %q, want plan-stale", got)
	}
}

func TestABundleThatHoldsATrustSetAndNoRecordMakesASavedPlanStale(t *testing.T) {
	r := rtNew(t)
	saved := r.savePlan()
	// A trust set that a synthetic ceremony of another name wrote.
	fl := newFlow(t, r.b, newSpec(name1, 1, ""))
	fl.must("")
	in := r.savedIn(saved, rtFlag(saved))
	err := rtRefused(t, r, in, "refused")
	if got := rtReasons(t, err); !slices.Equal(got, []string{"plan-stale"}) {
		t.Errorf("reasons %q, want plan-stale", got)
	}
}

func TestAnEntryUnderRootsMakesTheBundleNotFirst(t *testing.T) {
	for _, mk := range []string{"dir", "file"} {
		t.Run(mk, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			if err := os.Mkdir(filepath.Join(r.bundleDir, "roots"), 0o755); err != nil {
				t.Fatal(err)
			}
			if mk == "dir" {
				if err := os.Mkdir(filepath.Join(r.bundleDir, "roots", "Q"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(r.bundleDir, "roots", "note"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			err := rtRefused(t, r, r.in(p, f, rtFlag(p)), "not-first")
			if !strings.Contains(err.Error(), "roots/") {
				t.Errorf("the text does not name roots/: %v", err)
			}
		})
	}
	t.Run("an empty roots folder is the first state", func(t *testing.T) {
		r := rtNew(t)
		if err := os.Mkdir(filepath.Join(r.bundleDir, "roots"), 0o755); err != nil {
			t.Fatal(err)
		}
		if done, err := r.direct(); err != nil || done == nil {
			t.Fatalf("Run = %v, %v", done, err)
		}
	})
}

func TestTheKeyDirectoryIsJudgedBeforeTheConfirmationAndBeforeAnythingIsWritten(t *testing.T) {
	type tc struct {
		name   string
		keyDir func(r *rt) string
		reason string
	}
	cases := []tc{
		{"a folder that does not exist", func(r *rt) string { return filepath.Join(r.root, "nowhere") }, "key-dir"},
		{"a file", func(r *rt) string {
			p := filepath.Join(r.root, "file")
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, "key-dir"},
		{"the bundle itself", func(r *rt) string { return r.bundleDir }, "key-dir"},
		{"a folder inside the bundle", func(r *rt) string {
			p := filepath.Join(r.bundleDir, "keys")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		}, "key-dir"},
		{"a folder that holds a key file", func(r *rt) string {
			if err := os.WriteFile(filepath.Join(r.keyDir, "A.x509.key.pem"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return r.keyDir
		}, "key-exists"},
		{"a folder that holds a removal file", func(r *rt) string {
			if err := os.WriteFile(filepath.Join(r.keyDir, "A.removal.jws"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return r.keyDir
		}, "key-exists"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			in := r.in(p, f, ceremony.Confirm{})
			in.KeyDir = c.keyDir(r)
			r.stdin = &rtReader{r: strings.NewReader(p.SHA256[:8] + "\n")}
			r.term = true
			in.Env = r.env()
			err := rtRefused(t, r, in, "backend")
			if got := rtReasons(t, err); !slices.Equal(got, []string{c.reason}) {
				t.Errorf("reasons %q, want %s", got, c.reason)
			}
			if strings.Contains(r.stderr.String(), "plan digest") {
				t.Error("the plan was shown to a person who cannot run it")
			}
		})
	}
}

func TestAKeyDirectoryThatIsALinkToTheBundleIsRefused(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	link := filepath.Join(r.root, "link")
	if err := os.Symlink(r.bundleDir, link); err != nil {
		t.Fatal(err)
	}
	in := r.in(p, f, rtFlag(p))
	in.KeyDir = link
	_ = rtRefused(t, r, in, "backend")
}

func TestAnInputThatIsNotCompleteIsAnErrorAndWritesNothing(t *testing.T) {
	type edit func(r *rt, in *ceremony.RunIn)
	cases := map[string]edit{
		"no key directory":  func(r *rt, in *ceremony.RunIn) { in.KeyDir = "" },
		"no bundle path":    func(r *rt, in *ceremony.RunIn) { in.BundleDir = "" },
		"no plan":           func(r *rt, in *ceremony.RunIn) { in.Plan = nil },
		"an empty plan":     func(r *rt, in *ceremony.RunIn) { in.Plan = &ceremony.PlanOut{} },
		"no writer":         func(r *rt, in *ceremony.RunIn) { in.Writer = nil },
		"a writer of no FS": func(r *rt, in *ceremony.RunIn) { in.Writer = &fsx.Writer{} },
		"no console":        func(r *rt, in *ceremony.RunIn) { in.Env.Out = nil },
		"a zero console":    func(r *rt, in *ceremony.RunIn) { in.Env.Out = &ceremony.Console{} },
		"no clock":          func(r *rt, in *ceremony.RunIn) { in.Env.Now = nil },
		"a clock that panics": func(r *rt, in *ceremony.RunIn) {
			in.Env.Now = func() time.Time { panic("test: the clock is broken") }
		},
		"a clock outside the years": func(r *rt, in *ceremony.RunIn) {
			in.Env.Now = func() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }
		},
		"a plan with another digest": func(r *rt, in *ceremony.RunIn) {
			q := *in.Plan
			q.SHA256 = strings.Repeat("0", 64)
			in.Plan = &q
		},
		"a plan that its reader refuses": func(r *rt, in *ceremony.RunIn) {
			q := *in.Plan
			q.JSON = []byte(`{"version":1}`)
			in.Plan = &q
		},
		"a plan of bytes that are not JSON": func(r *rt, in *ceremony.RunIn) {
			q := *in.Plan
			q.JSON = []byte("\xff\xfe not json")
			in.Plan = &q
		},
		"no copies": func(r *rt, in *ceremony.RunIn) { in.Wanted = nil },
		"one copy":  func(r *rt, in *ceremony.RunIn) { in.Wanted = in.Wanted[:1] },
		"a copy with other bytes": func(r *rt, in *ceremony.RunIn) {
			w := slices.Clone(in.Wanted)
			w[0].Data = append(slices.Clone(w[0].Data), '#')
			in.Wanted = w
		},
		"a copy listed twice": func(r *rt, in *ceremony.RunIn) { in.Wanted = append(slices.Clone(in.Wanted), in.Wanted[0]) },
		"a key store that is nil": func(r *rt, in *ceremony.RunIn) {
			in.OpenStore = func(string, string) (ceremony.RootStore, error) { return nil, nil }
		},
		"a key store that fails to open": func(r *rt, in *ceremony.RunIn) {
			in.OpenStore = func(string, string) (ceremony.RootStore, error) { return nil, errors.New("test: no store") }
		},
		"a key store that panics": func(r *rt, in *ceremony.RunIn) {
			in.OpenStore = func(string, string) (ceremony.RootStore, error) { panic("test: the store panics") }
		},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			in := r.in(p, f, rtFlag(p))
			e(r, &in)
			before, keys := r.tree(), r.keyTree()
			done, err := ceremony.Run(context.Background(), in)
			if done != nil || err == nil {
				t.Fatalf("Run = %v, %v; want an error", done, err)
			}
			if _, stopped := rtStopped(err); stopped {
				t.Errorf("a fault before the first write is not a stop: %v", err)
			}
			if name == "no key directory" && rtKind(err) != "usage" {
				t.Errorf("a missing key directory is %s, want usage", rtKind(err))
			}
			if !pfPrintable(err.Error()) {
				t.Errorf("the text %+q is not printable ASCII", err.Error())
			}
			if want := map[string]string{
				"no key directory": "--key-dir", "no bundle path": "path of the bundle folder", "no plan": "no plan to run",
				"an empty plan": "no plan to run", "no writer": "no bundle folder", "a writer of no FS": "no bundle folder",
				"no console": "there is no console", "a zero console": "there is no console", "no clock": "no clock",
			}[name]; want != "" && !strings.Contains(err.Error(), want) {
				t.Errorf("the text %q does not say %q", err.Error(), want)
			}
			sameTree(t, "an incomplete input", before, r.tree())
			sameTree(t, "an incomplete input (key directory)", keys, r.keyTree())
		})
	}
}

func TestAContextThatIsCancelledOrMissingStopsTheRunBeforeAnyWrite(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	before := r.tree()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done, err := ceremony.Run(ctx, r.in(p, f, rtFlag(p)))
	if done != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, %v; want context.Canceled", done, err)
	}
	//lint:ignore SA1012 a nil context is the case under test
	done, err = ceremony.Run(nil, r.in(p, f, rtFlag(p))) //nolint:staticcheck
	if done != nil || err == nil {
		t.Fatalf("Run with no context = %v, %v", done, err)
	}
	sameTree(t, "a cancelled context", before, r.tree())
}

func TestAClockBehindTheCeremonyTimeIsRefusedAndTheCeremonyTimeItselfIsNot(t *testing.T) {
	for _, saved := range []bool{false, true} {
		name := "direct"
		if saved {
			name = "saved"
		}
		t.Run(name+" behind", func(t *testing.T) {
			r := rtNew(t)
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
			in.Env.Now = func() time.Time { return pfClock.Add(-time.Second) }
			err := rtRefused(t, r, in, "refused")
			if got := rtReasons(t, err); !slices.Equal(got, []string{"clock-behind"}) {
				t.Errorf("reasons %q, want clock-behind", got)
			}
			if !strings.Contains(err.Error(), "2026-11-20T09:59:59Z") || !strings.Contains(err.Error(), "2026-11-20T10:00:00Z") {
				t.Errorf("the text does not show the two times: %v", err)
			}
		})
		t.Run(name+" at the time", func(t *testing.T) {
			r := rtNew(t)
			r.clockAt = pfClock.Add(-time.Second) // the first call of the clock is the ceremony time
			var in ceremony.RunIn
			if saved {
				p := r.savePlan()
				in = r.savedIn(p, rtFlag(p))
			} else {
				p, f := r.plan()
				in = r.in(p, f, rtFlag(p))
			}
			if done, err := ceremony.Run(context.Background(), in); err != nil || done == nil {
				t.Fatalf("Run = %v, %v; the ceremony time itself is not behind", done, err)
			}
		})
	}
}

func TestASavedPlanOfAnotherProgramIsRefusedWithPlanVersion(t *testing.T) {
	cases := map[string]func(p *ceremony.PlanOut) (v, os, sum string){
		"another version": func(p *ceremony.PlanOut) (string, string, string) {
			return "v9.9.9", "linux/amd64", strings.Repeat("ab", 32)
		},
		"another system": func(p *ceremony.PlanOut) (string, string, string) {
			return "v0.0.0-test", "darwin/arm64", strings.Repeat("ab", 32)
		},
		"another digest": func(p *ceremony.PlanOut) (string, string, string) {
			return "v0.0.0-test", "linux/amd64", strings.Repeat("cd", 32)
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			p := r.savePlan()
			v, o, s := mk(p)
			in := r.savedIn(p, rtFlag(p))
			in.Env.Self = rtSelf(v, o, s)
			err := rtRefused(t, r, in, "refused")
			if got := rtReasons(t, err); !slices.Equal(got, []string{"plan-version"}) {
				t.Errorf("reasons %q, want plan-version", got)
			}
		})
	}
	t.Run("the same program passes", func(t *testing.T) {
		r := rtNew(t)
		p := r.savePlan()
		if done, err := ceremony.Run(context.Background(), r.savedIn(p, rtFlag(p))); err != nil || done == nil {
			t.Fatalf("Run = %v, %v", done, err)
		}
	})
	t.Run("a program that cannot be described is a failure and not a pass", func(t *testing.T) {
		r := rtNew(t)
		p := r.savePlan()
		for _, self := range []func() (buildinfoProgram, error){
			func() (buildinfoProgram, error) { return buildinfoProgram{}, errors.New("test: no description") },
			func() (buildinfoProgram, error) { panic("test: the description panics") },
		} {
			in := r.savedIn(p, rtFlag(p))
			in.Env.Self = self
			_ = rtRefused(t, r, in, "failure")
		}
	})
	t.Run("a direct apply does not ask which program made the plan", func(t *testing.T) {
		r := rtNew(t)
		p, f := r.plan()
		in := r.in(p, f, rtFlag(p))
		in.Env.Self = rtSelf("v9.9.9", "linux/amd64", strings.Repeat("ab", 32))
		if done, err := ceremony.Run(context.Background(), in); err != nil || done == nil {
			t.Fatalf("Run = %v, %v", done, err)
		}
	})
}

func TestAPlanFolderThatIsNotTheFolderThePlanDescribesIsRefusedAndNothingIsWritten(t *testing.T) {
	edits := map[string]func(t *testing.T, dir string){
		"a changed copy": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "wanted", "ritueel.yaml")
			if err := os.WriteFile(p, []byte("version: 1\nname: Other\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a missing copy": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "wanted", "want", "roots", "x509.yaml")); err != nil {
				t.Fatal(err)
			}
		},
		"an extra file": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "wanted", "extra.yaml"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"an extra entry in the folder": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a copy that is a link": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "wanted", "ritueel.yaml")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../../../ritueel.yaml", p); err != nil {
				t.Fatal(err)
			}
		},
		"a copy that is a pipe": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "wanted", "ritueel.yaml")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a plan that is a folder": func(t *testing.T, dir string) {
			p := filepath.Join(dir, "plan.json")
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
			_ = b
		},
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			p := r.savePlan()
			edit(t, filepath.Join(r.bundleDir, "history", p.Name))
			in := r.savedIn(p, rtFlag(p))
			err := rtRefusedWithin(t, r, in)
			if err == nil {
				t.Fatal("no error")
			}
		})
	}
}

// rtRefusedWithin runs a saved plan whose folder was damaged, within a time limit, because a pipe in
// place of a file must be refused and not waited for.
func rtRefusedWithin(t *testing.T, r *rt, in ceremony.RunIn) error {
	t.Helper()
	type out struct {
		done *ceremony.Done
		err  error
	}
	before, keys := r.tree(), r.keyTree()
	ch := make(chan out, 1)
	go func() {
		d, err := ceremony.Run(context.Background(), in)
		ch <- out{d, err}
	}()
	select {
	case o := <-ch:
		if o.done != nil || o.err == nil {
			t.Fatalf("Run = %v, %v; want a refusal", o.done, o.err)
		}
		if _, stopped := rtStopped(o.err); stopped {
			t.Errorf("a refusal before the first write is a stop: %v", o.err)
		}
		if rtKind(o.err) != "failure" {
			t.Errorf("the error is %s (%v), want a plain failure", rtKind(o.err), o.err)
		}
		if !pfPrintable(o.err.Error()) {
			t.Errorf("the text %+q is not printable ASCII", o.err.Error())
		}
		sameTree(t, "a damaged plan folder", before, r.tree())
		sameTree(t, "a damaged plan folder (key directory)", keys, r.keyTree())
		return o.err
	case <-time.After(20 * time.Second):
		t.Fatal("Run waits on a file that is not a regular file")
		return nil
	}
}
