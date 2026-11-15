package ceremonytest

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/bundle"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
)

// Step is where a ceremony of a software test root is left.
type Step int

// The steps, in the order of the ceremony (record 0005, rules 10 to 12).
const (
	// AtPlan is history/<c>/ with plan.json and wanted/: a planned folder.
	AtPlan Step = iota + 1
	// AtAttempt is AtPlan and attempt.json and the two empty journals.
	AtAttempt
	// AtFirstBirth is AtAttempt and the first key born (its key file is in the key directory) and
	// its line written.
	AtFirstBirth
	// AtBirths is AtFirstBirth and both keys and both lines.
	AtBirths
	// AtSignatures is AtBirths and every signature line; the removal files exist in the key
	// directory. The journals are not closed and no transcript is written.
	AtSignatures
	// AtTranscript is AtSignatures and the journals closed and transcript.txt: the transcript is
	// written before the artifacts (record 0005, rule 12).
	AtTranscript
	// AtSet is AtTranscript and roots/A/root.json, roots/B/root.json and the trust set.
	AtSet
	// Recorded is AtSet and record.json: a finished ceremony.
	Recorded
)

// String is the name of the step, as the constants are written; "" for a value that is none.
func (s Step) String() string {
	switch s {
	case AtPlan:
		return "AtPlan"
	case AtAttempt:
		return "AtAttempt"
	case AtFirstBirth:
		return "AtFirstBirth"
	case AtBirths:
		return "AtBirths"
	case AtSignatures:
		return "AtSignatures"
	case AtTranscript:
		return "AtTranscript"
	case AtSet:
		return "AtSet"
	case Recorded:
		return "Recorded"
	}
	return ""
}

// Options say what bundle to make.
type Options struct {
	// Step is where the ceremony is left. [Bundle] needs one of the steps; [AfterWrites] and
	// [Writes] take the zero value as Recorded.
	Step Step
	// Now is the clock of the ceremony. It is read once, and the ceremony then runs on a clock
	// that gives that time and one second more at each later call: the plan, the name of the
	// ceremony folder and the lines of the journals follow it. Nil means 2026-11-20T10:00:00Z.
	Now func() time.Time
	// Dir is the bundle folder. It must not exist, and its parent must: it is made by
	// bundle.Create, which never writes into a folder that exists. "" means the folder "ca" in a
	// folder made by t.TempDir().
	Dir string
	// KeyDir is the key directory of the software store. It is made (with mode 0700) when it does
	// not exist. "" means the folder "keys" in a folder made by t.TempDir(), outside the bundle.
	KeyDir string
}

// Made is what a call of [Bundle] or [AfterWrites] left, as far as the run got.
type Made struct {
	// Dir and KeyDir are the bundle folder and the key directory.
	Dir, KeyDir string
	// Ceremony is the name of the ceremony folder, for example 20261120T100000Z-apply. After [More]
	// it is the name of the newest ceremony.
	Ceremony string
	// PlanSHA256 is the digest of plan.json of Ceremony; AttemptSHA256 is the digest of its
	// attempt.json, "" while no attempt was written.
	PlanSHA256, AttemptSHA256 string
	// Pins are the X.509 pins of the keys that were born, in the order of their labels.
	Pins []string
	// Set is the folder name of the trust set (without "trust/"), "" while it is not written.
	Set string

	at time.Time // the time of the first ceremony
}

// defaultNow is the clock of a ceremony that the Options leave open.
var defaultNow = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

// program is the description of the program in every plan that this package makes: a fixed one, so
// that two plans of equal Options have equal bytes.
var program = buildinfo.Program{Version: "v0.0.0-test", OSArch: "linux/amd64", SHA256: "abababababababababababababababababababababababababababababababab"}

// counterRand is a source of random bytes that counts: byte i of the stream is i plus 1, modulo 251,
// plus 1. Two readers give the same bytes in the same order, so the serials of two plans are equal.
type counterRand struct{ n int }

func (c *counterRand) Read(p []byte) (int, error) {
	for i := range p {
		c.n++
		p[i] = byte(c.n%251) + 1
	}
	return len(p), nil
}

// Bundle makes a bundle with bundle.Create (a test root, the OpenPGP root file removed as a person
// would), runs the ceremony with the exported pieces of internal/ceremony and internal/trustset up
// to o.Step, and leaves it there. It does not call apply. It fails the test on any error. Two calls
// with equal Options write the same bytes into history/<c>/plan.json and into wanted/ (the clock, the
// source of the serials and the description of the program are fixed): a workstation copy at AtPlan
// and a stick copy at Recorded can be made by two calls. The keys, and so the pins, the journals, the
// root list and the record, differ between two calls.
func Bundle(t testing.TB, o Options) *Made {
	t.Helper()
	if o.Step.String() == "" {
		t.Fatalf("ceremonytest: Options.Step is %d, which is no step", o.Step)
	}
	m, _ := run(t, o, 0)
	return m
}

// AfterWrites makes the same bundle but ends it at the Nth write of the ceremony: the Nth changing
// call that the ceremony makes on the bundle (a folder made, a file created, a rename, a flush of a
// folder or a file, a write of data) fails, and so does every call after it, as a stopped writer
// does. A failed write of data leaves the first half of the data, as a cut does. So a test can stop
// after a write that no Step names, for example after a key file and before its line. The key
// files are written by the key store into the key directory and are not counted. The bundle is
// made with bundle.Create first, and that is not counted. o.Step is the last step the run would
// reach; zero means Recorded. A number past the writes of the run leaves the whole bundle. It fails
// the test on any error that is not the cut.
func AfterWrites(t testing.TB, o Options, n int) *Made {
	t.Helper()
	if n < 1 {
		t.Fatalf("ceremonytest: AfterWrites needs a number of writes of at least 1, got %d", n)
	}
	m, _ := run(t, o, n)
	return m
}

// Writes is the number of writes that the ceremony of o makes, as [AfterWrites] counts them: for each
// n from 1 to Writes, AfterWrites fails the Nth. The last write is the flush of the folder after the
// rename of the last file, so the cut at Writes leaves every file in place, as a cut at that flush
// does. It makes a whole bundle to count.
func Writes(t testing.TB, o Options) int {
	t.Helper()
	_, n := run(t, o, 0)
	return n
}

// ceremonyRun is one run of the ceremony.
type ceremonyRun struct {
	t       testing.TB
	step    Step
	m       *Made
	w       *fsx.Writer
	folder  *ceremony.Folder
	store   *stopStore
	trace   *stopTrace
	found   *ceremony.Found
	plan    *ceremony.PlanOut
	console *ceremony.Console
	clock   *clock
	cut     *counter
	started bool
	ended   bool
}

// clock gives a time and one second more at each later call.
type clock struct {
	mu   sync.Mutex
	base time.Time
	n    int
}

func newClock(base time.Time) *clock { return &clock{base: base} }

// now is the clock of the journals. The first call gives the time after the base, so the lines
// of the journals follow the plan.
func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return c.base.Add(time.Duration(c.n) * time.Second)
}

// run makes the bundle and returns what it holds and the number of the changing calls the ceremony
// made. cutAt is the call that fails; 0 fails none.
func run(t testing.TB, o Options, cutAt int) (*Made, int) {
	t.Helper()
	step := o.Step
	if step == 0 {
		step = Recorded
	}
	if step.String() == "" {
		t.Fatalf("ceremonytest: Options.Step is %d, which is no step", o.Step)
	}
	base := defaultNow
	if o.Now != nil {
		base = o.Now().UTC().Truncate(time.Second)
		if y := base.Year(); y < 1 || y > 9999 {
			t.Fatalf("ceremonytest: the clock gives a time outside the years 1 to 9999")
		}
	}
	dir, keyDir := folders(t, o)
	prepare(t, dir)
	r := &ceremonyRun{t: t, step: step, cut: &counter{failAt: cutAt}, clock: newClock(base)}
	r.m = &Made{Dir: dir, KeyDir: keyDir, at: base}
	r.find(base)
	r.m.Ceremony, r.m.PlanSHA256 = r.plan.Name, r.plan.SHA256

	inner, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be opened: %v", err)
	}
	r.w = &fsx.Writer{FS: &cutFS{in: inner, c: r.cut}}
	t.Cleanup(func() { _ = r.w.Close() })

	err = r.ceremony()
	r.finish(err)
	return r.m, r.cut.count()
}

// folders returns the bundle folder and the key directory of the Options, and makes the key
// directory.
func folders(t testing.TB, o Options) (dir, keyDir string) {
	t.Helper()
	dir, keyDir = o.Dir, o.KeyDir
	if dir == "" {
		dir = filepath.Join(t.TempDir(), "ca")
	}
	if keyDir == "" {
		keyDir = filepath.Join(t.TempDir(), "keys")
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatalf("ceremonytest: the key directory cannot be made: %v", err)
	}
	return dir, keyDir
}

// prepare makes the new bundle as a person does: bundle.Create with a test root, and the file of the
// OpenPGP root removed, because this version applies one root.
func prepare(t testing.TB, dir string) {
	t.Helper()
	if _, err := bundle.Create(dir, bundle.StarterOptions{TestRoot: true}); err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be made: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "want", "roots", "openpgp.yaml")); err != nil {
		t.Fatalf("ceremonytest: the OpenPGP root file cannot be removed: %v", err)
	}
}

// find reads what is to be applied and makes the plan.
func (r *ceremonyRun) find(base time.Time) {
	t := r.t
	t.Helper()
	fsys, err := fsx.OpenFS(r.m.Dir)
	if err != nil {
		t.Fatalf("ceremonytest: the bundle cannot be opened: %v", err)
	}
	defer func() { _ = fsys.Close() }()
	r.found, err = ceremony.Find(context.Background(), ceremony.FindInput{FS: fsys})
	if err != nil {
		t.Fatalf("ceremonytest: the new bundle is not the first state: %v", err)
	}
	env := ceremony.Env{
		Now:  func() time.Time { return base },
		Rand: &counterRand{},
		Self: func() (buildinfo.Program, error) { return program, nil },
	}
	r.plan, err = ceremony.MakePlan(r.found, env)
	if err != nil {
		t.Fatalf("ceremonytest: the plan cannot be made: %v", err)
	}
}

// ceremony runs the ceremony up to the step. An error that is the stop of the run is returned as it
// is; the caller tells it from a fault.
func (r *ceremonyRun) ceremony() error {
	t := r.t
	var err error
	r.folder, err = ceremony.NewFolder(r.w, r.plan.Name)
	if err != nil {
		return err
	}
	if err := r.folder.WritePlan(r.plan.JSON, r.found.Wanted); err != nil {
		return err
	}
	if r.step == AtPlan {
		return nil
	}
	attempt := files.Attempt{Version: files.FormatVersion, Ceremony: r.plan.Name, PlanSHA256: r.plan.SHA256, Root: r.plan.Plan.Root.Label, StartedAt: r.m.at.Format(time.RFC3339)}
	raw, err := attempt.Canonical()
	if err != nil {
		t.Fatalf("ceremonytest: the attempt cannot be written: %v", err)
	}
	tr, err := r.folder.Start(attempt)
	if err != nil {
		return err
	}
	r.started = true
	r.m.AttemptSHA256 = files.Digest(raw)
	if r.step == AtAttempt {
		return nil
	}
	return r.keys(tr)
}

// keys runs the births and the signatures with the wrapped store and trace, and what comes after.
func (r *ceremonyRun) keys(tr ceremony.Trace) error {
	t := r.t
	store, err := ceremony.NewSoftwareStore(r.m.KeyDir, r.m.Dir)
	if err != nil {
		t.Fatalf("ceremonytest: the key store cannot be opened: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	r.store = &stopStore{RootStore: store}
	sigsAt := 0
	switch r.step {
	case AtFirstBirth:
		r.store.birthAt = 2
	case AtBirths:
		sigsAt = 1
	}
	r.trace = newStopTrace(sigsAt)
	r.trace.use(tr)
	r.console = ceremony.NewConsole(io.Discard, io.Discard)
	r.console.Out("plan %s", r.plan.Prefix)
	env := ceremony.Env{Now: r.clock.now, Out: r.console}
	made, err := ceremony.MakeRoots(context.Background(), ceremony.MakeIn{
		Env: env, Store: r.store, Plan: r.plan, Settings: r.found.Settings, Root: r.found.Root, Trace: r.trace,
	})
	r.notePins()
	if err != nil {
		if r.step == AtFirstBirth && r.store.hit() || r.step == AtBirths && r.trace.sigs.hit() {
			return nil // the stop that the step asks for
		}
		return err
	}
	if r.step == AtFirstBirth || r.step == AtBirths {
		t.Fatalf("ceremonytest: the ceremony did not stop at %s", r.step)
	}
	if r.step == AtSignatures {
		return nil
	}
	if err := r.folder.End(); err != nil {
		return err
	}
	r.ended = true
	r.console.Out("done %s", r.plan.Prefix)
	text, err := r.console.Transcript()
	if err != nil {
		t.Fatalf("ceremonytest: the transcript cannot be made: %v", err)
	}
	if err := r.folder.WriteTranscript(text); err != nil {
		return err
	}
	if r.step == AtTranscript {
		return nil
	}
	return r.artifacts(made)
}

// notePins keeps the pins of the keys whose birth line the journal accepted.
func (r *ceremonyRun) notePins() {
	r.m.Pins = nil
	for _, line := range r.trace.births.accepted() {
		b, err := files.ReadBirthLine(line)
		if err != nil {
			r.t.Fatalf("ceremonytest: a birth line that the journal took is refused by its reader: %v", err)
		}
		r.m.Pins = append(r.m.Pins, b.PublicKeySHA256)
	}
}

// artifacts writes what the ceremony writes between the transcript and the record (record 0005,
// rule 12): roots/, the root.json of each key, trust/ and the trust set last; then the record.
func (r *ceremonyRun) artifacts(made *ceremony.Made) error {
	for _, d := range []string{"roots", "trust"} {
		if err := r.w.Mkdir(d, 0o755); err != nil {
			return err
		}
	}
	for _, root := range made.Roots {
		if err := r.w.Mkdir("roots/"+root.Label, 0o755); err != nil {
			return err
		}
		if err := r.w.WriteFile(root.RootJSONPath, root.RootJSON, 0o644); err != nil {
			return err
		}
	}
	if err := made.Set.Write(r.w, made.TrustSetDir()); err != nil {
		return err
	}
	r.m.Set = made.Set.Name()
	if r.step == AtSet {
		return nil
	}
	root := made.Record
	_, err := r.folder.Record(ceremony.RecordIn{
		Command: files.CommandApply, Outcome: files.OutcomeCompleted,
		StartedAt: r.m.at.Format(time.RFC3339), FinishedAt: r.m.at.Add(5 * time.Minute).Format(time.RFC3339),
		Root: &root, Confirmation: &files.Confirmation{By: "flag", At: r.m.at.Format(time.RFC3339)},
		RanOn: ceremony.RanOnWorkstation, LimitShown: true, Artifacts: made.Artifacts(),
	})
	return err
}

// finish judges the end of the run: an error that is the cut of the run is the end that was asked
// for, and any other is a fault of the test. The journals that a stop left open are closed, so that
// no file stays open; that changes no file.
func (r *ceremonyRun) finish(err error) {
	t := r.t
	t.Helper()
	if r.started && !r.ended {
		_ = r.folder.End()
	}
	if err == nil {
		return
	}
	if r.cut.hit() || errors.Is(err, errStop) {
		return
	}
	t.Fatalf("ceremonytest: the ceremony stopped at an error that was not asked for: %v", err)
}
