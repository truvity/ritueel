//go:build linux || darwin

package ceremony_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/wanted"
)

func TestAWriteThatReachesTheDiskChangedIsNeverTakenForAGoodWrite(t *testing.T) {
	events := rtEvents(t)
	var writes []string
	for _, e := range events {
		if strings.HasPrefix(e, "write ") {
			writes = append(writes, e)
		}
	}
	if len(writes) < 15 {
		t.Fatalf("a whole run makes %d writes of file data", len(writes))
	}
	for k := 1; k <= len(writes); k++ {
		t.Run(rtItoa(k), func(t *testing.T) {
			t.Parallel()
			r := rtNew(t)
			r.b.r.corruptAt = k
			p, f := r.plan()
			done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
			if done != nil || err == nil {
				t.Fatalf("Run ended well although the write %d (%s) reached the disk with a byte changed", k, writes[k-1])
			}
			if _, ok := rtStopped(err); !ok {
				t.Errorf("the error is %v, want a stop: the first write was made", err)
			}
		})
	}
}

// rtAtRecord runs a whole run and calls edit at the moment the run is about to flush the folder of the
// record, after the record is in place.
func rtAtRecord(t *testing.T, edit func(r *rt, name string)) (*rt, *ceremony.Done, error) {
	t.Helper()
	r := rtNew(t)
	p, f := r.plan()
	last := "sync-dir history/" + p.Name
	count := 0
	total := len(rtEvents(t))
	r.b.r.hook = func(n int, desc string) {
		count++
		if n == total && desc == last {
			edit(r, p.Name)
		}
	}
	done, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
	return r, done, err
}

func TestABundleThatItsOwnCheckRefusesAfterTheRecordIsAStopAtTheCheckThatSaysTheRecordIsWritten(t *testing.T) {
	r, done, err := rtAtRecord(t, func(r *rt, name string) {
		if e := os.WriteFile(filepath.Join(r.bundleDir, "history", name, "transcript.txt"), []byte("changed\n"), 0o644); e != nil {
			t.Error(e)
		}
	})
	s, ok := rtStopped(err)
	if done != nil || !ok || s.Step != "check" || s.Attempt {
		t.Fatalf("Run = %v, %v; want a stop at check with no open attempt", done, err)
	}
	if !strings.Contains(err.Error(), "the ceremony record is written") || !strings.Contains(err.Error(), "its own check refuses") || !strings.Contains(err.Error(), "transcript-digest") {
		t.Errorf("the line: %s", err.Error())
	}
	if strings.Contains(err.Error(), "an attempt is open") {
		t.Error("the line says an attempt is open after the record is written")
	}
	if r.stdout.String() != "" {
		t.Errorf("the end line was printed although the check failed: %q", r.stdout.String())
	}
}

func TestANoticeOfTheCheckAfterTheRecordIsPrintedAndIsNotAFault(t *testing.T) {
	r, done, err := rtAtRecord(t, func(r *rt, name string) {
		if e := os.WriteFile(filepath.Join(r.bundleDir, "history", name, ".rt-left-over"), []byte("x"), 0o644); e != nil {
			t.Error(e)
		}
	})
	if err != nil || done == nil {
		t.Fatalf("Run = %v, %v: a notice is not a fault", done, err)
	}
	rep, cerr := history.Check(context.Background(), r.b.raw)
	if cerr != nil || len(rep.Notices()) == 0 {
		t.Fatalf("the check has no notice: %v", cerr)
	}
	if !strings.Contains(r.stderr.String(), "check history notice: ") {
		t.Errorf("the notice is not printed: %q", r.stderr.String())
	}
	if r.stdout.String() != done.EndLine+"\n" {
		t.Errorf("standard output = %q", r.stdout.String())
	}
}

func TestTheSummaryLinesAreThoseOfTheRecordedCeremony(t *testing.T) {
	r := rtNew(t)
	done, p := r.mustDirect()
	errText := r.stderr.String()
	for _, want := range []string{
		"ceremony " + p.Name + " is recorded: " + done.RecordPath + ", digest " + done.RecordSHA256 + "\n",
		"trust set " + done.TrustSet + ", sequence 1\n",
		"root key A: x509 pin " + done.Roots[0].X509SPKISHA256 + ", certificate ends 2029-11-20T10:00:00Z\n",
		"root key B: x509 pin " + done.Roots[1].X509SPKISHA256 + ", certificate ends 2029-11-20T10:00:00Z\n",
		"the key files A.x509.key.pem, B.x509.key.pem and the removal authorisations beside them are in the key directory: copy them to a safe place; this is a TEST ONLY root\n",
	} {
		if !strings.Contains(errText, want) {
			t.Errorf("standard error does not hold the line %q", want)
		}
	}
}

func TestTheTranscriptIsWhatWasPrintedBeforeTheRecordOnEitherStreamInOrder(t *testing.T) {
	r := rtNew(t)
	log := &mkLog{}
	r.console = ceremony.NewConsole(&mkLineWriter{log: log, prefix: "e|"}, &mkLineWriter{log: log, prefix: "o|"})
	p, f := r.plan()
	r.b.r.hook = func(n int, desc string) { log.add("fs|%s", desc) }
	if _, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p))); err != nil {
		t.Fatal(err)
	}
	var printed []string
	for _, e := range log.all() {
		if strings.HasPrefix(e, "fs|rename history/"+p.Name+"/record.json") {
			break
		}
		if strings.HasPrefix(e, "e|") || strings.HasPrefix(e, "o|") {
			printed = append(printed, e[2:])
		}
	}
	got := strings.Split(strings.TrimSuffix(r.transcript(p.Name), "\n"), "\n")
	if strings.Join(got, "\n") != strings.Join(printed, "\n") {
		t.Errorf("the transcript is not the lines printed before the record:\n%q\n%q", got, printed)
	}
}

func TestAPlanThatIsForAnotherKindOfRootThanTheFirstApplyBuildsIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	// The copies of the plan folder are read again by the readers of the wanted files, and the plan is
	// held to them by digest. A plan whose copies are of a root that is not a test root, of the kind
	// openpgp, or of a personal bundle is not what this version builds, even when its digests agree.
	cases := map[string]struct{ settings, root string }{
		"a root that is not a test root": {pfSettings, pfX509Real},
		"a root of the kind openpgp":     {pfSettings, pfOpenPGPTest},
		"a root of the kind ssh":         {pfSettings, pfSSHTest},
		"a personal bundle":              {pfPersonal, pfX509Test},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			r := rtNew(t)
			p, f := r.plan()
			_ = f
			in := r.in(p, f, rtFlag(p))
			in.Plan = rtPlanWithCopies(t, p, c.settings, c.root)
			in.Wanted = rtCopies(c.settings, c.root)
			in.Confirm = rtFlag(in.Plan)
			before, keys := r.tree(), r.keyTree()
			done, err := ceremony.Run(context.Background(), in)
			if done != nil || err == nil || (rtKind(err) != "not-built" && rtKind(err) != "failure") {
				t.Fatalf("Run = %v, %v; want a failure that writes nothing", done, err)
			}
			if !strings.Contains(err.Error(), "nothing was written") || !pfPrintable(err.Error()) {
				t.Errorf("the line: %v", err)
			}
			sameTree(t, "a plan of another kind of root", before, r.tree())
			sameTree(t, "a plan of another kind of root (keys)", keys, r.keyTree())
		})
	}
}

// rtCopies are the two wanted files of a run, as copies.
func rtCopies(settings, root string) []wanted.File {
	return []wanted.File{wantedFile("ritueel.yaml", settings), wantedFile("want/roots/x509.yaml", root)}
}

// rtPlanWithCopies is the plan p with the digests of its two wanted files changed to those of the
// given texts, read again by ReadPlanOut.
func rtPlanWithCopies(t *testing.T, p *ceremony.PlanOut, settings, root string) *ceremony.PlanOut {
	t.Helper()
	b := rtEditPlan(t, p.JSON, func(m map[string]any) {
		w := m["wanted"].([]any)
		w[0].(map[string]any)["sha256"] = sum([]byte(settings))
		w[1].(map[string]any)["sha256"] = sum([]byte(root))
	})
	out, err := ceremony.ReadPlanOut(b)
	if err != nil {
		t.Fatalf("ReadPlanOut: %v", err)
	}
	return out
}

func TestABundleWhoseHistoryIsNotOneRecordThatEndsAtTheNewRecordIsAStopAtTheCheck(t *testing.T) {
	// A second ceremony record that chains to the new one is written at the moment of the flush of the
	// folder, as another copy of ritueel on the same bundle would: the history is whole and has two
	// records, and this run's record is not its end.
	r := rtNew(t)
	p, f := r.plan()
	total := len(rtEvents(t))
	var other *flow
	r.b.r.hook = func(n int, desc string) {
		if n != total {
			return
		}
		raw, e := os.ReadFile(filepath.Join(r.bundleDir, "history", p.Name, "record.json"))
		if e != nil {
			t.Error(e)
			return
		}
		b2 := openBundle(t, r.bundleDir, 0)
		s := newSpec(name1, 2, rtHexSum(raw))
		s.label, s.pin = "C", rep('c')
		other = newFlow(t, b2, s)
		if e := other.run(""); e != nil {
			t.Error(e)
		}
	}
	got, err := ceremony.Run(context.Background(), r.in(p, f, rtFlag(p)))
	if other == nil {
		t.Fatal("the hook did not run")
	}
	s, ok := rtStopped(err)
	if got != nil || !ok || s.Step != "check" || !strings.Contains(err.Error(), "not one record that ends at the new record") {
		t.Fatalf("Run = %v, %v; want a stop at check that says the history is not one record that ends at the new record", got, err)
	}
}

func TestAPlanThatListsAThirdWantedFileIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	third := wantedFile("want/delegations/web.yaml", "version: 1\ntype: x509-intermediate\nroot: x509\n")
	edited := rtEditPlan(t, p.JSON, func(m map[string]any) {
		w := m["wanted"].([]any)
		m["wanted"] = append(w, map[string]any{"path": third.Path, "sha256": third.SHA256})
	})
	q, err := ceremony.ReadPlanOut(edited)
	if err != nil {
		// The reader of the plan does not let a run meet a third wanted file.
		if !strings.Contains(err.Error(), "wanted lists ritueel.yaml and the root file") {
			t.Errorf("the reader refuses a third wanted file with another line: %v", err)
		}
		return
	}
	in := r.in(q, f, rtFlag(q))
	in.Wanted = append(slices.Clone(f.Wanted), third)
	before, keys := r.tree(), r.keyTree()
	done, err := ceremony.Run(context.Background(), in)
	if done != nil || err == nil {
		t.Fatalf("Run = %v, %v", done, err)
	}
	sameTree(t, "a plan of a third wanted file", before, r.tree())
	sameTree(t, "a plan of a third wanted file (keys)", keys, r.keyTree())
}

func TestATrustSetThatNoRecordListsIsRefusedWithTheFindingForARunAndForASavedPlan(t *testing.T) {
	// The trust set of a whole run is copied into a bundle that has no history: a trust set that no
	// record lists. The check of the history fails it, so it is refused as a history that fails, before
	// the bundle is judged to be first or not.
	done := rtNew(t)
	d, _ := done.mustDirect()
	r := rtNew(t)
	f := r.find()
	saved := r.savePlan()
	set := filepath.Join(r.bundleDir, filepath.FromSlash(d.TrustSet))
	if err := os.MkdirAll(set, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root-list.json", "root-list.jws", "ca-bundle.pem"} {
		if err := os.WriteFile(filepath.Join(set, name), done.b.read(filepath.FromSlash(d.TrustSet), name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	other, err := ceremony.MakePlan(f, rtOtherEnv())
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]ceremony.RunIn{
		"direct": r.in(other, f, rtFlag(other)),
		"saved":  r.savedIn(saved, rtFlag(saved)),
	} {
		err := rtRefusedNamed(t, r, in)
		var ref *ceremony.RefusedError
		if !errors.As(err, &ref) || !slices.Contains(ref.Reasons, "trust-set-unlisted") {
			t.Errorf("%s: %v; want a refusal with the finding trust-set-unlisted", name, err)
		}
	}
}

// rtRefusedNamed runs a run that must be refused before the first write and returns the error.
func rtRefusedNamed(t *testing.T, r *rt, in ceremony.RunIn) error {
	t.Helper()
	before, keys := r.tree(), r.keyTree()
	done, err := ceremony.Run(context.Background(), in)
	if done != nil || err == nil {
		t.Fatalf("Run = %v, %v; want a refusal", done, err)
	}
	sameTree(t, "a refusal", before, r.tree())
	sameTree(t, "a refusal (keys)", keys, r.keyTree())
	return err
}

func TestAKeyStoreThatIsNilIsNamedAndNothingIsWritten(t *testing.T) {
	r := rtNew(t)
	p, f := r.plan()
	in := r.in(p, f, rtFlag(p))
	in.OpenStore = func(string, string) (ceremony.RootStore, error) { return nil, nil }
	before := r.tree()
	_, err := ceremony.Run(context.Background(), in)
	if err == nil || !strings.Contains(err.Error(), "key store was not opened") {
		t.Errorf("the line: %v", err)
	}
	sameTree(t, "a store that is nil", before, r.tree())
}
