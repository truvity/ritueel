//go:build linux || darwin

package ceremony_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// apply PLAN: the path of a saved plan, the plan read once from its folder, and a run of it.

func TestCheckPlanPathAcceptsTheFormThatPlanOnlyPrintsAndNothingElse(t *testing.T) {
	good := map[string]string{
		"history/20261120T100000Z-apply/plan.json": "20261120T100000Z-apply",
		"history/a/plan.json":                      "a",
		"history/x-1.y/plan.json":                  "x-1.y",
	}
	for path, name := range good {
		got, err := ceremony.CheckPlanPath(path)
		if err != nil || got != name {
			t.Errorf("CheckPlanPath(%q) = %q, %v; want %q", path, got, err, name)
		}
	}
	bad := []string{
		"", "plan.json", "/history/x/plan.json", "./history/x/plan.json", "history/x/plan.json/", "history//plan.json",
		"history/../plan.json", "history/x/../plan.json", "history/./plan.json", "history/x/other.json", "history/x/plan.json.bak",
		"history/x/PLAN.json", "History/x/plan.json", "histories/x/plan.json", "history/plan.json", "history/x/y/plan.json",
		"history/x/wanted/plan.json", "x/plan.json", "history\\x\\plan.json", "history/x\\y/plan.json",
		"history/x /plan.json", "history/ x/plan.json", "history/x\x00/plan.json", "history/\xff/plan.json", "history/x\n/plan.json",
		"history/а/plan.json", "history/.rt-abc/plan.json", "history/" + strings.Repeat("a", 300) + "/plan.json",
		"history/..", "history", "history/x", "//history/x/plan.json", "history/x/plan.json\x00",
		strings.Repeat("history/", 13) + "plan.json", "history/x/plan.json?x=1", "history/x:y/plan.json", "~/history/x/plan.json",
		"history/x/plan.json ", " history/x/plan.json", "history/x/plan.json/y", "history/x/plan.json/..", "history/x/plan.json/plan.json",
	}
	for _, path := range bad {
		got, err := ceremony.CheckPlanPath(path)
		var u *ceremony.UsageError
		if !errors.As(err, &u) || got != "" {
			t.Errorf("CheckPlanPath(%+q) = %q, %v; want a usage error", path, got, err)
			continue
		}
		if !pfPrintable(err.Error()) || strings.Contains(err.Error(), "\n") {
			t.Errorf("the text %+q is not printable ASCII on one line", err.Error())
		}
	}
}

func TestReadSavedPlanReadsThePlanFolderOnceAndGivesThePlanThatWasMade(t *testing.T) {
	r := rtNew(t)
	made, _ := r.plan()
	saved := r.savePlan()
	if saved.SHA256 != made.SHA256 || !bytes.Equal(saved.JSON, made.JSON) || saved.Name != made.Name || saved.Prefix != made.Prefix {
		t.Errorf("the saved plan is not the plan that was made: %s and %s", saved.SHA256, made.SHA256)
	}
	if got := strings.Join(saved.Words(), "\n"); got != strings.Join(made.Words(), "\n") {
		t.Error("the words of the saved plan are not the words of the plan that was made: a person must confirm the plan that runs")
	}
}

func TestReadSavedPlanRefusesWhatIsNotAPlanOfThatFolder(t *testing.T) {
	r := rtNew(t)
	made, f := r.plan()
	canon := func(edit func(m map[string]any)) []byte { return rtEditPlan(t, made.JSON, edit) }
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	cases := map[string][]byte{
		"a plan of another ceremony": canon(func(m map[string]any) { m["ceremony"] = "20261120T100001Z-apply" }),
		"a plan of another ceremony that is whole": canon(func(m map[string]any) {
			// Every time of the plan moves a second: it is a plan of the next second, and in the folder of
			// this one.
			const later, end = "2026-11-20T10:00:01Z", "2029-11-20T10:00:01Z"
			m["ceremony"], m["ceremony_time"], m["made_at"] = "20261120T100001Z-apply", later, later
			for _, s := range m["signatures"].([]any) {
				sig := s.(map[string]any)
				if sig["kind"] == "root-certificate" {
					sig["not_before"], sig["not_after"] = later, end
				}
			}
		}),
		"another version":   canon(func(m map[string]any) { m["version"] = 2 }),
		"a version as text": canon(func(m map[string]any) { m["version"] = "1" }),
		"an unknown member": canon(func(m map[string]any) { m["extra"] = true }),
		"a third root": canon(func(m map[string]any) {
			m["births"] = append(m["births"].([]any), map[string]any{"label": "C", "purpose": "x509-root", "store": "software", "place": "C.x509.key.pem"})
		}),
		"a null member":        bytes.Replace(made.JSON, []byte(`"command":"apply"`), []byte(`"command":null`), 1),
		"an empty file":        {},
		"one byte":             []byte("{"),
		"a byte order mark":    append([]byte("\xef\xbb\xbf"), made.JSON...),
		"a trailing line feed": append(slices.Clone(made.JSON), '\n'),
		"a trailing byte":      append(slices.Clone(made.JSON), ' '),
		"not UTF-8":            bytes.Replace(made.JSON, []byte("software"), []byte("soft\xff\xfe"), 1),
		"a deep nesting":       []byte(deep),
		"an array":             []byte("[]"),
		"a string":             []byte(`"plan"`),
		"a number":             []byte("1"),
		"a zero byte":          append(slices.Clone(made.JSON[:len(made.JSON)-1]), 0, '}'),
		"the plan twice":       append(slices.Clone(made.JSON), made.JSON...),
		"a member twice":       bytes.Replace(made.JSON, []byte(`"command":"apply"`), []byte(`"command":"apply","command":"apply"`), 1),
		"a huge list of changes": canon(func(m map[string]any) {
			m["applies"] = slices.Repeat([]any{map[string]any{"change": "create", "object": "x509/A"}}, 3000)
		}),
		"a file over the limit":     bytes.Repeat([]byte(" "), 300<<10),
		"a file far over the limit": bytes.Repeat([]byte("a"), 9<<20),
	}
	_ = f
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(r.bundleDir, "history", made.Name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "plan.json"), b, 0o644); err != nil {
				t.Fatal(err)
			}
			p, err := ceremony.ReadSavedPlan(r.b.w.FS, "history/"+made.Name+"/plan.json")
			if p != nil || err == nil {
				t.Fatalf("ReadSavedPlan = %v, %v; want a refusal", p, err)
			}
			if rtKind(err) != "failure" {
				t.Errorf("the error is %s (%v), want a plain failure", rtKind(err), err)
			}
			if !pfPrintable(err.Error()) || len(err.Error()) > 2000 {
				t.Errorf("the text is not one short printable line: %d bytes", len(err.Error()))
			}
		})
	}
}

func TestReadSavedPlanRefusesAPlanThatIsNotARegularFileOrIsNotThere(t *testing.T) {
	r := rtNew(t)
	made, _ := r.plan()
	hist := filepath.Join(r.bundleDir, "history", made.Name)
	if err := os.MkdirAll(hist, 0o755); err != nil {
		t.Fatal(err)
	}
	plan := filepath.Join(hist, "plan.json")
	path := "history/" + made.Name + "/plan.json"
	type step func(t *testing.T)
	cases := map[string]step{
		"no file": func(t *testing.T) {},
		"a folder": func(t *testing.T) {
			if err := os.Mkdir(plan, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"a link to a plan": func(t *testing.T) {
			other := filepath.Join(r.root, "other.json")
			if err := os.WriteFile(other, made.JSON, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, plan); err != nil {
				t.Fatal(err)
			}
		},
		"a link that points nowhere": func(t *testing.T) {
			if err := os.Symlink(filepath.Join(r.root, "nowhere"), plan); err != nil {
				t.Fatal(err)
			}
		},
		"a pipe": func(t *testing.T) {
			if err := syscall.Mkfifo(plan, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a sparse file of a huge size": func(t *testing.T) {
			f, err := os.Create(plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(1 << 40); err != nil {
				t.Skip("the file system has no sparse files of that size")
			}
			_ = f.Close()
		},
		"a file with no read bit": func(t *testing.T) {
			if err := os.WriteFile(plan, made.JSON, 0o000); err != nil {
				t.Fatal(err)
			}
			if os.Geteuid() == 0 {
				t.Skip("root reads any file")
			}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(plan)
			mk(t)
			done := make(chan error, 1)
			go func() {
				p, err := ceremony.ReadSavedPlan(r.b.w.FS, path)
				if p != nil && err == nil {
					err = errors.New("a plan was read")
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !pfPrintable(err.Error()) {
					t.Errorf("ReadSavedPlan = %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Fatal("ReadSavedPlan waits on a file that is not a regular file")
			}
		})
	}
	t.Run("a history folder that is a link", func(t *testing.T) {
		_ = os.Remove(plan)
		other := t.TempDir()
		if err := os.WriteFile(filepath.Join(other, "plan.json"), made.JSON, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(r.bundleDir, "history")); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(other, made.Name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(other, made.Name, "plan.json"), made.JSON, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, filepath.Join(r.bundleDir, "history")); err != nil {
			t.Fatal(err)
		}
		if p, err := ceremony.ReadSavedPlan(r.b.w.FS, path); p != nil || err == nil {
			t.Errorf("ReadSavedPlan through a link = %v, %v", p, err)
		}
	})
	t.Run("no bundle", func(t *testing.T) {
		if p, err := ceremony.ReadSavedPlan(nil, path); p != nil || err == nil {
			t.Errorf("= %v, %v", p, err)
		}
	})
	t.Run("a path of a wrong form is a usage error and reads nothing", func(t *testing.T) {
		_, err := ceremony.ReadSavedPlan(r.b.w.FS, "plan.json")
		var u *ceremony.UsageError
		if !errors.As(err, &u) {
			t.Errorf("= %v", err)
		}
	})
}

func TestARunOfASavedPlanDoesTheSameCeremonyAsADirectRun(t *testing.T) {
	direct := rtNew(t)
	dd, dp := direct.mustDirect()
	saved := rtNew(t)
	p := saved.savePlan()
	sd, err := ceremony.Run(context.Background(), saved.savedIn(p, rtFlag(p)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The names of the trust set and the pins differ (the keys are new); the shape does not.
	norm := func(names []string, set string) []string {
		out := make([]string, len(names))
		for i, n := range names {
			out[i] = strings.ReplaceAll(n, set, "SET")
		}
		slices.Sort(out)
		return out
	}
	a, b := norm(rtNames(direct.tree()), dd.TrustSet), norm(rtNames(saved.tree()), sd.TrustSet)
	if !slices.Equal(a, b) {
		t.Errorf("a direct run writes\n%q\na saved plan writes\n%q", a, b)
	}
	if dp.SHA256 != p.SHA256 {
		t.Fatal("the two plans differ")
	}
	rec, _ := saved.record(p.Name)
	if rec.Confirmation == nil || rec.Confirmation.By != "flag" || rec.PlanSHA256 != p.SHA256 {
		t.Errorf("record = %+v", rec)
	}
	rep, err := history.Check(context.Background(), saved.b.raw)
	if err != nil || !rep.Clean() || rep.Records != 1 {
		t.Errorf("history.Check: %+v, %v", rep, err)
	}
	// What the plan folder held before is untouched: plan.json and the copies keep their digests.
	if got := rtHexSum(saved.b.read("history", p.Name, "plan.json")); got != p.SHA256 {
		t.Errorf("plan.json changed: %s", got)
	}
}

func TestASavedPlanIsConfirmedByTheFirstEightCharactersToo(t *testing.T) {
	r := rtNew(t)
	p := r.savePlan()
	r.typed(strings.ToUpper(p.SHA256[:8]) + "\n")
	if _, err := ceremony.Run(context.Background(), r.savedIn(p, ceremony.Confirm{})); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec, _ := r.record(p.Name); rec.Confirmation == nil || rec.Confirmation.By != "typed" {
		t.Errorf("confirmation = %+v", rec.Confirmation)
	}
}

func TestAWrongConfirmationOfASavedPlanLeavesTheFolderAsTheGlobalPlanOnlyLeftIt(t *testing.T) {
	r := rtNew(t)
	p := r.savePlan()
	for _, c := range []ceremony.Confirm{{}, {Flag: true}, {Flag: true, Digest: strings.Repeat("0", 64)}, {Flag: true, Digest: strings.ToUpper(p.SHA256)}} {
		before, keys := r.tree(), r.keyTree()
		done, err := ceremony.Run(context.Background(), r.savedIn(p, c))
		if done != nil || !errors.Is(err, ceremony.ErrNotConfirmed) {
			t.Fatalf("Run = %v, %v", done, err)
		}
		sameTree(t, "a refused confirmation of a saved plan", before, r.tree())
		sameTree(t, "a refused confirmation of a saved plan (keys)", keys, r.keyTree())
	}
	// The plan can still be run afterwards.
	if _, err := ceremony.Run(context.Background(), r.savedIn(p, rtFlag(p))); err != nil {
		t.Fatalf("the plan cannot be run after a refused confirmation: %v", err)
	}
}

func TestAPlanThatWasEditedByAByteHasAnotherDigestAndTheOldDigestDoesNotConfirmIt(t *testing.T) {
	r := rtNew(t)
	old := r.savePlan()
	// The same plan with another serial, in the canonical form: a valid plan with another digest.
	b := rtEditPlan(t, old.JSON, func(m map[string]any) {
		sig := m["signatures"].([]any)[0].(map[string]any)
		serial := sig["serial"].(string)
		last := serial[len(serial)-1]
		sig["serial"] = serial[:len(serial)-1] + map[bool]string{true: "6", false: "5"}[last == '5']
	})
	if err := os.WriteFile(filepath.Join(r.bundleDir, "history", old.Name, "plan.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	edited, err := ceremony.ReadSavedPlan(r.b.w.FS, "history/"+old.Name+"/plan.json")
	if err != nil {
		t.Fatalf("the edited plan is refused by its reader: %v", err)
	}
	if edited.SHA256 == old.SHA256 {
		t.Fatal("the digest did not change")
	}
	before := r.tree()
	done, err := ceremony.Run(context.Background(), r.savedIn(edited, ceremony.Confirm{Flag: true, Digest: old.SHA256}))
	if done != nil || !errors.Is(err, ceremony.ErrNotConfirmed) {
		t.Fatalf("Run = %v, %v; the old digest confirms the edited plan", done, err)
	}
	sameTree(t, "a plan that was edited", before, r.tree())
	// The edited plan that the person confirms by its own digest is the plan that runs: the digest
	// in the record is the digest of the file.
	if _, err := ceremony.Run(context.Background(), r.savedIn(edited, rtFlag(edited))); err != nil {
		t.Fatal(err)
	}
	if rec, _ := r.record(old.Name); rec.PlanSHA256 != edited.SHA256 {
		t.Errorf("plan_sha256 = %s, want the digest of the file that ran, %s", rec.PlanSHA256, edited.SHA256)
	}
}

func TestAPlanThatIsNotTheOneInTheFolderIsRefusedByTheFolder(t *testing.T) {
	r := rtNew(t)
	p := r.savePlan()
	other, err := ceremony.MakePlan(r.find(), rtOtherEnv())
	if err != nil {
		t.Fatal(err)
	}
	if other.Name != p.Name || other.SHA256 == p.SHA256 {
		t.Fatal("the other plan is not a plan of the same name with other serials")
	}
	in := r.savedIn(other, rtFlag(other))
	before := r.tree()
	done, err := ceremony.Run(context.Background(), in)
	if done != nil || err == nil || rtKind(err) != "failure" {
		t.Fatalf("Run = %v, %v", done, err)
	}
	sameTree(t, "a plan that is not the one in the folder", before, r.tree())
}

func TestTheRunReadsTheCopiesOfThePlanAndNotTheWantedFilesThatChangedAfterwards(t *testing.T) {
	r := rtNew(t)
	p := r.savePlan()
	// The settings are edited after the plan was made: the name of the bundle changes.
	if err := os.WriteFile(filepath.Join(r.bundleDir, "ritueel.yaml"), []byte(strings.Replace(pfSettings, "name: Example", "name: Changed", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	done, err := ceremony.Run(context.Background(), r.savedIn(p, rtFlag(p)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var names []string
	for _, c := range rtBundleCerts(t, r.b.read(filepath.FromSlash(done.TrustSet), "ca-bundle.pem")) {
		names = append(names, c.Subject.CommonName)
	}
	if want := []string{"Example Root A (TEST ONLY)", "Example Root B (TEST ONLY)"}; !slices.Equal(names, want) {
		t.Errorf("the certificates are %q, want %q: the name of the copy in the plan folder", names, want)
	}
}

func TestTwoRunsOfOneSavedPlanFromTwoGoroutinesLetExactlyOneWin(t *testing.T) {
	for try := 0; try < 4; try++ {
		r := rtNew(t)
		p := r.savePlan()
		keys := [2]string{rtMkdir(t), rtMkdir(t)}
		writers := [2]*fsx.Writer{}
		for i := range writers {
			w, err := fsx.Open(r.bundleDir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			writers[i] = w
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		type out struct {
			done *ceremony.Done
			err  error
		}
		res := [2]out{}
		for i := range res {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rr := &rt{t: t, bundleDir: r.bundleDir, keyDir: keys[i], b: r.b, stderr: &rtBuf{}, stdout: &rtBuf{}, clockAt: pfClock.Add(time.Second)}
				rr.console = ceremony.NewConsole(rr.stderr, rr.stdout)
				in := rr.savedIn(p, rtFlag(p))
				in.Writer = writers[i]
				<-start
				d, err := ceremony.Run(context.Background(), in)
				res[i] = out{d, err}
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		for i, o := range res {
			if o.done != nil {
				wins++
				if o.err != nil {
					t.Errorf("try %d, run %d: a result and an error", try, i)
				}
				continue
			}
			var ref *ceremony.RefusedError
			if _, stopped := rtStopped(o.err); !stopped && !errors.As(o.err, &ref) && rtKind(o.err) != "failure" {
				t.Errorf("try %d, run %d: %v is neither a refusal nor a failure", try, i, o.err)
			}
			// A loser that reached the key store made keys only if it also wrote its attempt, which the
			// exclusive create gives to one run. The store is started before the attempt, so a loser may
			// have made the empty folder test-only-keys, and nothing else.
			for _, e := range func() []os.DirEntry { ents, _ := os.ReadDir(keys[i]); return ents }() {
				inner, ierr := os.ReadDir(filepath.Join(keys[i], e.Name()))
				if e.Name() == "test-only-keys" && e.IsDir() && ierr == nil && len(inner) == 0 {
					continue
				}
				t.Errorf("try %d, run %d lost and left %q in its key directory", try, i, e.Name())
			}
		}
		if wins != 1 {
			t.Fatalf("try %d: %d runs won, want exactly 1 (%v, %v)", try, wins, res[0].err, res[1].err)
		}
		rep, err := history.Check(context.Background(), r.b.raw)
		if err != nil || !rep.Clean() || rep.Records != 1 {
			t.Errorf("try %d: history.Check = %+v, %v", try, rep, err)
		}
	}
}

// rtEditPlan edits the members of a plan and writes it again in the canonical form.
func rtEditPlan(t *testing.T, plan []byte, edit func(m map[string]any)) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(plan))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		m[k] = rtInts(v)
	}
	edit(m)
	b, err := canonjson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// rtInts turns the numbers of a decoded document into integers.
func rtInts(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			panic(err)
		}
		return n
	case []any:
		for i := range x {
			x[i] = rtInts(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = rtInts(x[k])
		}
	}
	return v
}

func TestTwoDirectRunsOfOnePlanFromTwoGoroutinesLetExactlyOneWin(t *testing.T) {
	for try := 0; try < 4; try++ {
		r := rtNew(t)
		p, f := r.plan()
		keys := [2]string{rtMkdir(t), rtMkdir(t)}
		var writers [2]*fsx.Writer
		for i := range writers {
			w, err := fsx.Open(r.bundleDir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			writers[i] = w
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		var dones [2]*ceremony.Done
		var errs [2]error
		for i := range dones {
			wg.Add(1)
			go func() {
				defer wg.Done()
				rr := &rt{t: t, bundleDir: r.bundleDir, keyDir: keys[i], b: r.b, stderr: &rtBuf{}, stdout: &rtBuf{}, clockAt: pfClock.Add(time.Second)}
				rr.console = ceremony.NewConsole(rr.stderr, rr.stdout)
				in := rr.in(p, f, rtFlag(p))
				in.Writer = writers[i]
				<-start
				dones[i], errs[i] = ceremony.Run(context.Background(), in)
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		for i := range dones {
			if dones[i] != nil {
				wins++
				continue
			}
			if ents, _ := os.ReadDir(keys[i]); len(ents) != 0 {
				t.Errorf("try %d: the run %d lost and left %d files in its key directory", try, i, len(ents))
			}
		}
		if wins != 1 {
			t.Fatalf("try %d: %d runs won, want exactly 1 (%v, %v)", try, wins, errs[0], errs[1])
		}
		rep, err := history.Check(context.Background(), r.b.raw)
		if err != nil || !rep.Clean() || rep.Records != 1 {
			t.Errorf("try %d: history.Check = %+v, %v", try, rep, err)
		}
	}
}
