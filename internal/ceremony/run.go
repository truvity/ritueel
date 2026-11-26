package ceremony

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/keydir"
	"ritueel.id/ritueel/internal/wanted"
)

// RunIn is what [Run] needs. Every member that a run cannot do without is checked first, and a zero
// RunIn runs nothing and writes nothing.
type RunIn struct {
	// Writer is the bundle folder, opened once. Run reads and writes through it only, so what it
	// judges and what it writes are one folder. The caller closes it after Run returns.
	Writer *fsx.Writer
	// Env is the clock, the standard input and the console. Out is required: a run prints the plan
	// before the person confirms it, and the transcript is what was printed.
	Env Env
	// Plan is the plan that the person confirms: made now by [MakePlan] for a direct apply, or taken
	// from its folder by [ReadSavedPlan] for apply PLAN. Run reads its bytes again with [ReadPlanOut].
	Plan *PlanOut
	// Saved is true for apply PLAN: the plan folder exists already, and its plan and copies are read
	// back and compared, and the plan is judged against the state of the bundle ([ReasonPlanStale],
	// [ReasonPlanVersion], [ReasonPlanUsed], [ReasonClockBehind]).
	Saved bool
	// Wanted are the wanted files that the plan used, as Find read them, for a direct apply: Run writes
	// them as the copies of the plan folder and reads the settings and the root file from these same
	// bytes. It is not used when Saved is true: the copies are those that the plan folder holds.
	Wanted []wanted.File
	// KeyDir is the key directory, outside the bundle. It must exist and not have been used: it holds no
	// folder test-only-keys, no removal authorisation and no key file of the older naming.
	KeyDir string
	// BundleDir is the path text of the bundle folder, which the key directory is judged against (it is
	// not held to the opened folder by identity: a later change).
	BundleDir string
	// Confirm is how the plan is confirmed. The zero value is the typed confirmation.
	Confirm Confirm
	// OpenStore opens the key store of the run; nil means [NewSoftwareStore]. It only opens the key
	// directory: the store is started later, after the confirmation ([RootStore.Start]). It is the place
	// where a test puts a store of its own.
	OpenStore func(keyDir, bundleDir string) (RootStore, error)
}

// RootInfo is one root key of the ceremony, as the result of a run lists it (docs/reference/cli.md,
// "Machine-readable output", the member roots).
type RootInfo struct {
	// Label is the label of the key.
	Label string
	// Store is the key store: "software".
	Store string
	// Test is true for a test root.
	Test bool
	// X509SPKISHA256 is the pin of the key.
	X509SPKISHA256 string
	// NotAfter is when the root certificate of the key ends.
	NotAfter string
}

// Done is what a run that ended well returns. Everything in it was read back from the disk.
type Done struct {
	// Ceremony is the name of the ceremony, the folder history/<Ceremony>.
	Ceremony string
	// RecordPath is the path of the ceremony record in the bundle.
	RecordPath string
	// RecordSHA256 is the digest of the record file, which is the end of the history.
	RecordSHA256 string
	// End is the full digest of the one end of the history that the self-check found.
	End string
	// EndLine is the end line of the history, "history: 1 ceremony records, end XXXXXXXX".
	EndLine string
	// Records is the number of ceremony records that the self-check counted: 1.
	Records int
	// Artifacts are the files that the record lists, in the order of the record.
	Artifacts []files.FileRef
	// TrustSequence is the sequence of the trust set that was written: 1.
	TrustSequence int64
	// TrustSet is the path of the trust set in the bundle, trust/<number>-<8 characters>.
	TrustSet string
	// Roots are the keys, in label order.
	Roots []RootInfo
}

// StoppedError is a fault after the first write of a run: a ceremony folder exists and the ceremony did
// not end. It says which step stopped, which ceremony folder stands, whether an attempt is open, and
// which keys may stand in the folder test-only-keys of the key directory (none for a stop at the write
// of the attempt, before any key is made) and that the folder may also hold a temporary file of the key
// driver, and the key directory a temporary file of ritueel's own that starts with .rt- and holds a
// removal authorisation (from the step make on), in one line, and that close, which closes an open
// attempt, is not built. Nothing was retried, and ritueel deleted nothing (record 0006, rules 33 and 45;
// the key driver removes only its own temporary files in its own folder, when it opens that folder). It
// is a failure (exit code 1) whatever its cause is, and a command maps this type before it maps the
// cause. The cause stays reachable with errors.Is and errors.As where the package that failed keeps
// its cause. The trust set writer is the one that does not: a fault of it keeps its text only, so
// errors.Is and errors.As find nothing behind it, and the text of the line still names what failed.
type StoppedError struct {
	// Ceremony is the name of the ceremony folder.
	Ceremony string
	// Step is the step that stopped: "write-plan", "key-store", "attempt", "make", "journals", "transcript",
	// "artifacts", "record" or "check".
	Step string
	// Attempt is true when attempt.json was or may have been written and no record was written: the
	// ceremony is "started" and no record closes it.
	Attempt bool
	// Msg is the line for a person, made once, in printable ASCII.
	Msg string
	err error
}

// Error returns the line.
func (e *StoppedError) Error() string {
	if e == nil {
		return "no stop"
	}
	return e.Msg
}

// Unwrap returns the cause.
func (e *StoppedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// run is one run of [Run]: what it reads once and what it holds between the steps.
type run struct {
	ctx     context.Context
	in      RunIn
	console *Console
	plan    *PlanOut

	folder   *Folder
	copies   []wanted.File
	settings *wanted.Settings
	root     *wanted.Root
	store    RootStore

	limitShown bool
	confirmed  string // the time of the confirmation
	started    string // the time of the attempt
	phase      phase
}

// phase is what a stop leaves on disk, in the order of the writes.
type phase uint8

const (
	// phaseNone is a run that wrote nothing yet.
	phaseNone phase = iota
	// phasePlanned is a ceremony folder that a write of the plan may have left with some of its files, or
	// with all of them; it holds no attempt and no key was made.
	phasePlanned
	// phaseAttemptMaybe is a failed write of the attempt: the file may or may not exist.
	phaseAttemptMaybe
	// phaseAttempt is an open attempt: attempt.json was written and no record closes it.
	phaseAttempt
	// phaseRecorded is a ceremony whose record was written.
	phaseRecorded
)

// Run is the whole of one ceremony after the refusals of the command line, for the first apply of a
// software test root, in the order of docs/reference/ceremony-record.md, "The order of writes"
// (record 0005, rules 9 to 13):
//
//  1. Preflight, no write: the history of the bundle is read ([history.Inspect]); an open attempt is
//     refused with [ReasonUnfinishedCeremony]; for a saved plan the plan folder is read back and compared
//     and the plan is judged ([ReasonPlanStale], [ReasonPlanUsed], [ReasonPlanVersion]); the clock must not
//     be before the ceremony time ([ReasonClockBehind]); the settings and the root file are read from the
//     copies.
//  2. The key directory is judged by the key store ([RootStore.Refuse]); a refusal is a [*BackendError].
//  3. The plan in words and its digest are printed, and the plan is confirmed ([Confirm]); anything but
//     the digest, or the first eight characters of it typed at a terminal, is [ErrNotConfirmed] and
//     nothing is written. Then the console is asked for its fault once more, so that a console that broke
//     after the plan was shown is found before anything is written: that is an ordinary failure, and
//     the person did confirm.
//  4. The ceremony folder with plan.json and the copies (a direct apply); then the state of the bundle is
//     judged a second time, immediately before the attempt (this narrows the window of two runs at once
//     and does not close it: no lock exists yet); then the key store is started ([RootStore.Start]: the
//     folder test-only-keys is made and the driver is linked in the process, so that nothing of the
//     store exists before the person confirmed); then the attempt and the two journals, before the first
//     key is born.
//  5. [MakeRoots]: the births, the fingerprints, the signatures, and the seven checks of the artifacts.
//  6. The journals are closed, read back from their files and checked again by [CheckJournals] and
//     [CheckSignatureDigests]; the transcript is written, with no line printed after it; the artifacts
//     (the root.json of each key, then the trust set last); and the ceremony record last.
//  7. The self-check: [history.Check] on the bundle must find a whole history of one record that ends
//     at this record.
//
// Every fault after the first write is a [*StoppedError] (exit code 1). A fault before it is the error
// of the step: [*RefusedError], [*BackendError], [ErrNotConfirmed], [*UsageError], or an ordinary error.
// Nothing is retried and ritueel deletes nothing. The key store is closed before Run returns.
func Run(ctx context.Context, in RunIn) (*Done, error) {
	r := &run{ctx: ctx, in: in}
	defer func() {
		if r.store != nil {
			// The store is closed whatever happened; the keys it made were closed by the maker.
			_ = r.store.Close()
		}
	}()
	if err := r.begin(); err != nil {
		return nil, err
	}
	if err := r.preflight(); err != nil {
		return nil, err
	}
	if err := r.openStore(); err != nil {
		return nil, err
	}
	if err := r.show(); err != nil {
		return nil, err
	}
	if err := r.confirm(); err != nil {
		return nil, err
	}
	if err := r.checkConsole(); err != nil {
		return nil, err
	}
	if err := r.writeFolder(); err != nil {
		return nil, err
	}
	return r.ceremony()
}

// begin judges the input that needs no file.
func (r *run) begin() error {
	in := r.in
	if r.ctx == nil {
		return errors.New("ceremony: there is no context")
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if in.Writer == nil || in.Writer.FS == nil {
		return errors.New("ceremony: there is no bundle folder to run in")
	}
	if in.Env.Out == nil || !consoleMade(in.Env.Out) {
		return errors.New("ceremony: there is no console, and a person must read the plan before it is confirmed")
	}
	r.console = in.Env.Out
	if in.KeyDir == "" {
		return &UsageError{Msg: "apply needs --key-dir DIR, the folder for the key files, which must exist outside the bundle"}
	}
	if in.BundleDir == "" {
		return errors.New("ceremony: the path of the bundle folder is needed to judge the key directory")
	}
	if in.Plan == nil || len(in.Plan.JSON) == 0 {
		return errors.New("ceremony: there is no plan to run")
	}
	own, err := ReadPlanOut(in.Plan.JSON)
	if err != nil {
		return fmt.Errorf("the plan is refused by its reader, and nothing was written: %w", err)
	}
	if own.SHA256 != in.Plan.SHA256 {
		return errors.New("ceremony: the digest of the plan is not the digest of its bytes, and nothing was written")
	}
	r.plan = own
	return nil
}

// preflight is the first step: it reads and writes nothing it keeps, and refuses in the order of the page of
// the refusals: a history that fails its check (exit code 3), an open attempt (exit code 3), the state of
// a saved plan (plan-stale), a bundle that is not in the first state (exit code 1), a saved plan that
// was used or made by another program, a clock that is behind. Then the wanted files are read from the
// copies.
func (r *run) preflight() error {
	if err := r.judgeState(); err != nil {
		return err
	}
	if r.in.Saved {
		if err := checkVersion(r.in.Env, r.plan); err != nil {
			return err
		}
	}
	if err := checkClock(r.in.Env, r.plan); err != nil {
		return err
	}
	folder, err := NewFolder(r.in.Writer, r.plan.Name)
	if err != nil {
		return err
	}
	r.folder = folder
	if r.in.Saved {
		if r.copies, err = folder.Adopt(r.plan.JSON); err != nil {
			return fmt.Errorf("the plan folder is not the folder that the plan describes, and nothing was written: %w", err)
		}
	} else {
		r.copies = slices.Clone(r.in.Wanted)
	}
	return r.readWanted()
}

// judgeState is the judgement of the state of the bundle, in the one order of the refusals: the
// history is read and must pass its own check, an open attempt is refused, a saved plan is judged against the
// state ([ReasonPlanStale]), a bundle that is not in the first state is refused, and a saved plan whose
// ceremony folder holds an attempt or a record is refused ([ReasonPlanUsed]). It writes nothing. The
// preflight runs it, and the run runs it again just before the attempt.
func (r *run) judgeState() error {
	fsys := r.in.Writer.FS
	st, err := inspect(r.ctx, fsys)
	if err != nil {
		return err
	}
	if err := refuseWhileOpen(st); err != nil {
		return err
	}
	if r.in.Saved {
		if err := checkStale(st); err != nil {
			return err
		}
	}
	if err := refuseNotFirst(fsys, st); err != nil {
		return err
	}
	if r.in.Saved {
		if err := refuseUsedPlan(fsys, r.plan.Name); err != nil {
			return err
		}
	}
	return nil
}

// recheck is the second judgement of the state, immediately before the attempt is written. A bundle
// that changed since the preflight (another run wrote an attempt, a record or a trust set while this
// person was reading the plan) stops this run with the refusal that the preflight would give, before the
// attempt and before any key. It narrows the window of two runs at once and does not close it: no lock
// exists yet, so a run that starts between this judgement and the write of its attempt is not seen, and
// the attempt that is created second is the one refused (reason plan-used, see [run.ceremony]).
//
// For a saved plan nothing was written by this run, so the refusal is the one that the preflight gives.
// For a direct apply the plan folder was written: a refusal then says so and keeps its reasons and its
// exit code (3), and any other fault is a stop, so that the line says what is on disk.
func (r *run) recheck() error {
	if err := r.ctx.Err(); err != nil {
		if r.in.Saved {
			return err
		}
		return r.stop("attempt", err)
	}
	err := r.judgeState()
	if err == nil || r.in.Saved {
		return err
	}
	var refused *RefusedError
	if errors.As(err, &refused) {
		msg := strings.TrimSuffix(refused.Msg, "; nothing was written")
		msg += fmt.Sprintf("; this run wrote the plan folder history/%s before it found this, and wrote no attempt and made no key", jsonset.EscapeExact(r.plan.Name))
		return &RefusedError{Reasons: slices.Clone(refused.Reasons), Msg: msg}
	}
	return r.stop("attempt", err)
}

// startStore starts the key store for the labels of the plan, after the confirmation and the second
// judgement of the state and before the attempt is written: the folder of the keys is made and the
// driver is linked here, and nowhere before. A refusal of the store keeps its reasons and its exit code
// (4); for a direct apply its text says that the plan folder was written and no attempt and no key. Any
// other fault is a stop at the step key-store.
func (r *run) startStore() error {
	labels := make([]string, len(r.plan.Births))
	for i, b := range r.plan.Births {
		labels[i] = b.Label
	}
	err := guard("key store", func() error { return r.store.Start(r.ctx, labels) })
	if err == nil {
		return nil
	}
	var refused *BackendError
	if errors.As(err, &refused) && !r.in.Saved {
		msg := strings.TrimSuffix(refused.Msg, "; nothing was written")
		msg = strings.TrimSuffix(msg, "; no key was made")
		msg += fmt.Sprintf("; this run wrote the plan folder history/%s before it found this, and wrote no attempt and made no key", jsonset.EscapeExact(r.plan.Name))
		return &BackendError{Reasons: slices.Clone(refused.Reasons), Msg: msg}
	}
	if errors.As(err, &refused) {
		return err
	}
	return r.stop("key-store", err)
}

// readWanted reads the settings and the root file from the copies, with the readers of the wanted files,
// and holds them to the plan: each of the two files of the plan has a copy of the same path and the same
// digest, and the root is the X.509 test root that the plan names in a company bundle. A direct apply and
// a saved plan are judged by this one code.
func (r *run) readWanted() error {
	p := r.plan
	byPath := make(map[string]wanted.File, len(r.copies))
	for _, c := range r.copies {
		if _, dup := byPath[c.Path]; dup {
			return fmt.Errorf("the copies hold %s twice, and nothing was written", jsonset.EscapeExact(c.Path))
		}
		byPath[c.Path] = c
	}
	data := make([][]byte, 0, len(p.Wanted))
	for _, w := range p.Wanted {
		c, ok := byPath[w.Path]
		if !ok || files.Digest(c.Data) != w.SHA256 {
			return fmt.Errorf("the plan lists %s and the copy of it is missing or has another digest, and nothing was written", jsonset.EscapeExact(w.Path))
		}
		data = append(data, c.Data)
	}
	if len(data) != 2 {
		return errors.New("the plan lists other wanted files than ritueel.yaml and one root file, and nothing was written")
	}
	settings, err := wanted.ParseSettings(p.Wanted[0].Path, data[0])
	if err != nil {
		return fmt.Errorf("a wanted file is refused, and nothing was written: %w", err)
	}
	root, err := wanted.ParseRoot(p.RootName, data[1])
	if err != nil {
		return fmt.Errorf("a wanted file is refused, and nothing was written: %w", err)
	}
	if _, ok := rootKinds[root.Kind]; !ok || !root.Test || settings.Personal || settings.Name == "" {
		return fmt.Errorf("%w: the plan is for one X.509 test root of a company bundle, and nothing was written", ErrNotBuilt)
	}
	r.settings, r.root = settings, root
	return nil
}

// openStore is the second step: the key store is opened and refuses what needs no key, before the person confirms,
// so that nobody confirms a plan that cannot run.
func (r *run) openStore() error {
	open := r.in.OpenStore
	if open == nil {
		open = NewSoftwareStore
	}
	var st RootStore
	if err := guard("key store", func() (e error) { st, e = open(r.in.KeyDir, r.in.BundleDir); return e }); err != nil {
		return err
	}
	if isNilValue(st) {
		return errors.New("ceremony: the key store was not opened, and nothing was written")
	}
	r.store = st
	return guard("key store", func() error { return st.Refuse(r.ctx) })
}

// show is the first half of the third step: the plan in words and its digest are printed, and the accepted limit with
// them. The record says the limit was shown only when the lines were printed.
func (r *run) show() error {
	for _, line := range r.plan.Words() {
		r.console.Err("%s", line)
	}
	if _, err := r.console.Transcript(); err != nil {
		return fmt.Errorf("the plan could not be shown, so it is not asked for, and nothing was written: %w", err)
	}
	r.limitShown = true
	return nil
}

// checkConsole asks the console for its fault after the confirmation and before anything is written (before the plan
// folder of a direct apply and before the attempt in every form). A console whose stream refused a line, for
// example standard error closed by the reader of a pipe, would be found by [MakeRoots] only after the keys
// are born; here it is found while nothing exists. The person did confirm, so this is an ordinary failure
// and not [ErrNotConfirmed]. The check of [MakeRoots] after the births stays.
func (r *run) checkConsole() error {
	if _, err := r.console.Transcript(); err != nil {
		return fmt.Errorf("a line could not be shown, so the run stopped, and nothing was written: %w", err)
	}
	return nil
}

// writeFolder is the fourth step for a direct apply: the confirmation was given, and now the ceremony folder is made
// with plan.json and the copies. A saved plan has its folder already, adopted in the preflight.
func (r *run) writeFolder() error {
	now, err := r.in.Env.now()
	if err != nil {
		return err
	}
	r.confirmed = timeText(now)
	if r.in.Saved {
		r.phase = phasePlanned
		return nil
	}
	if err := r.folder.WritePlan(r.plan.JSON, r.copies); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("a plan was made in the same second, and the folder history/%s exists already; run apply again a second later; nothing was written: %w", jsonset.EscapeExact(r.plan.Name), err)
		}
		// A failed write may have left the folder with some of its files.
		r.phase = phasePlanned
		return r.stop("write-plan", err)
	}
	r.phase = phasePlanned
	return nil
}

// stop makes the error of a fault after the first write: a [*StoppedError] that says what is on disk.
func (r *run) stop(step string, err error) error {
	var already *StoppedError
	if errors.As(err, &already) {
		return err
	}
	places := make([]string, 0, len(r.plan.Births))
	for _, b := range r.plan.Births {
		places = append(places, jsonset.EscapeExact(b.Place))
	}
	var state string
	switch r.phase {
	case phasePlanned:
		state = "the plan folder may hold some of its files, no attempt was written, and no key was made"
	case phaseAttemptMaybe:
		state = "attempt.json may or may not have been written, so treat an attempt as open; nothing was signed"
	case phaseAttempt:
		state = "an attempt is open, which means keys or signatures may exist from this plan, and no ceremony record closes it"
	case phaseRecorded:
		state = "the ceremony record is written"
	default:
		state = "nothing was written"
	}
	// A key can exist only from the first call of MakeRoots on, which is the phase of an open attempt. A
	// stop at the write of the attempt itself (phaseAttemptMaybe) names no key file: none was made.
	keys := ""
	if r.phase == phaseAttempt && len(places) > 0 {
		keys = "; the folder " + keydir.TestOnlyFolder + " of the key directory may hold the keys " + strings.Join(places, ", ") + ", and the removal authorisations may stand beside that folder, which stay"
	}
	// From the step "make" on (the phases of an open attempt and of a written record) two temporary files may
	// be left. The key driver writes a key under a temporary name in its folder and links it to its name: a run
	// that was cut leaves that file, which holds a whole key, and the driver removes its own temporary files, and
	// no other, when it opens its folder the next time. ritueel writes a removal authorisation under a name that
	// starts with .rt- in the key directory and renames it: a file left there holds no key. The words are
	// fixed; no file is listed and no folder is read.
	if r.phase == phaseAttempt || r.phase == phaseRecorded {
		keys += "; the folder " + keydir.TestOnlyFolder + " may also hold a temporary file whose name starts with .tmp-, which can hold a key; the key driver removes its own temporary files there when it opens the folder, and a person may remove one by hand; the key directory may also hold a temporary file whose name starts with .rt-, which holds a removal authorisation and no key"
	}
	if step == "record" && r.phase != phaseRecorded {
		state += " (a cut at the flush of the folder may leave record.json in place: look at the folder)"
	}
	closing := "; close, which closes an open attempt, is not built yet"
	if r.phase == phaseRecorded || r.phase == phasePlanned || r.phase == phaseNone {
		closing = ""
	}
	msg := fmt.Sprintf("the ceremony history/%s stopped at %s: %s; %s%s%s; nothing was retried, and ritueel deleted nothing",
		jsonset.EscapeExact(r.plan.Name), step, causeText(err), state, keys, closing)
	return &StoppedError{Ceremony: r.plan.Name, Step: step, Attempt: r.phase == phaseAttempt || r.phase == phaseAttemptMaybe, Msg: jsonset.Escape(msg), err: err}
}

// ceremony is the rest of the run: the attempt, the keys, the checks, the transcript, the artifacts, the record and
// the self-check. Every fault in it is a stop.
func (r *run) ceremony() (*Done, error) {
	if err := r.recheck(); err != nil {
		return nil, err
	}
	if err := r.startStore(); err != nil {
		return nil, err
	}
	now, err := r.in.Env.now()
	if err != nil {
		return nil, r.stop("attempt", err)
	}
	r.started = timeText(now)
	trace, err := r.folder.Start(files.Attempt{Version: files.FormatVersion, Ceremony: r.plan.Name, PlanSHA256: r.plan.SHA256, Root: r.plan.Plan.Root.Label, StartedAt: r.started})
	if err != nil {
		if errors.Is(err, ErrAttemptExists) {
			// The name of the attempt is taken: another run of this plan was first, and its attempt is
			// untouched (a file is never replaced). This run made no key.
			return nil, &RefusedError{
				Reasons: []string{ReasonPlanUsed},
				Msg: fmt.Sprintf("history/%s holds an attempt.json already, so another run of this plan was first; this run wrote no attempt and made no key, and the attempt of the other run was not changed; look at the folder and at ritueel check history",
					jsonset.EscapeExact(r.plan.Name)),
			}
		}
		// A failed write of the attempt may leave attempt.json: the folder is stopped, and the text says
		// that an attempt may be open.
		r.phase = phaseAttemptMaybe
		return nil, r.stop("attempt", err)
	}
	r.phase = phaseAttempt
	made, err := MakeRoots(r.ctx, MakeIn{Env: r.in.Env, Store: r.store, Plan: r.plan, Settings: r.settings, Root: r.root, Trace: trace})
	if err != nil {
		return nil, r.stop("make", err)
	}
	if err := r.closeJournals(made); err != nil {
		return nil, err
	}
	r.console.Err("checked: %s", strings.Join(made.Checked, ", "))
	r.console.Err("writes: %s", strings.Join(made.Artifacts(), ", "))
	tb, err := r.console.Transcript()
	if err != nil {
		return nil, r.stop("transcript", err)
	}
	if err := r.folder.WriteTranscript(tb); err != nil {
		return nil, r.stop("transcript", err)
	}
	// No line is printed from here to the write of the record: the transcript ends with the last line
	// printed before the record is written.
	if err := r.writeArtifacts(made); err != nil {
		return nil, r.stop("artifacts", err)
	}
	return r.record(made)
}

// closeJournals is the end of the journals: they are closed, read back from their files,
// and judged again by the checks that judged the lines the journals accepted; a fault stops the run
// before the transcript and before any artifact is written.
func (r *run) closeJournals(made *Made) error {
	if err := r.ctx.Err(); err != nil {
		return r.stop("journals", err)
	}
	if err := r.folder.End(); err != nil {
		return r.stop("journals", err)
	}
	fsys := r.in.Writer.FS
	dir := historyDir + "/" + r.plan.Name + "/"
	var read [2]JournalRead
	for i, name := range []string{files.BirthsFile, files.SignaturesFile} {
		lines, partial, err := fsx.ReadJournal(fsys, dir+name)
		if err != nil {
			return r.stop("journals", fmt.Errorf("%s cannot be read back: %w", name, err))
		}
		read[i] = JournalRead{Lines: lines, Partial: partial}
	}
	pins := make(map[string]string, len(made.Roots))
	certs := make(map[string][]byte, len(made.Roots))
	removals := make(map[string]string, len(made.Roots))
	for _, root := range made.Roots {
		pins[root.Label], certs[root.Label] = root.Pin, root.Certificate
		var stored []byte
		if err := guard("key store", func() (e error) { stored, e = r.store.ReadRemoval(r.ctx, root.Label); return e }); err != nil {
			return r.stop("journals", fmt.Errorf("the removal authorisation of %s cannot be read back from the key store: %w", root.Label, err))
		}
		removals[root.Label] = string(stored)
	}
	if err := CheckJournals(r.plan, pins, read[0], read[1]); err != nil {
		return r.stop("journals", err)
	}
	if err := CheckSignatureDigests(r.plan, certs, removals, made.Set, read[1]); err != nil {
		return r.stop("journals", err)
	}
	return nil
}

// writeArtifacts writes the artifacts: roots/ and roots/<label>/ are made, the root.json of each label is written, then
// trust/ is made and the trust set is written, last, as one folder. A folder that may exist already is
// read first and made only when it is absent. Each file is read back and compared with what was written.
// The names of the files of the trust set are those that the set gives.
func (r *run) writeArtifacts(made *Made) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	w := r.in.Writer
	if err := r.ensureDir(rootsDir); err != nil {
		return err
	}
	for _, root := range made.Roots {
		if err := w.Mkdir(rootsDir+"/"+root.Label, dirMode); err != nil {
			return fmt.Errorf("%s/%s could not be made: %w", rootsDir, root.Label, err)
		}
		if err := w.WriteFile(root.RootJSONPath, root.RootJSON, fileMode); err != nil {
			return fmt.Errorf("%s could not be written: %w", root.RootJSONPath, err)
		}
		if err := r.verify(root.RootJSONPath, root.RootJSON); err != nil {
			return err
		}
	}
	if err := r.ensureDir(trustDir); err != nil {
		return err
	}
	dir := trustSetFolder(made)
	if dir == "" {
		return errors.New("the trust set has no name")
	}
	if err := made.Set.Write(w, dir); err != nil {
		return fmt.Errorf("the trust set %s could not be written: %w", dir, err)
	}
	for _, f := range made.Set.Files() {
		if err := r.verify(dir+"/"+f.Name, f.Data); err != nil {
			return err
		}
	}
	return nil
}

// trustSetFolder is the folder of the first trust set in the bundle, trust/<number>-<8 characters of the
// digest of root-list.json> (docs/reference/bundle.md, "The layout"; the name is Proposed there). It is ""
// for a Made with no set. It is the one place of the name in this file.
func trustSetFolder(m *Made) string { return m.TrustSetDir() }

// ensureDir makes the folder path when it is absent. It reads first: a folder that exists is not made
// again, because a Mkdir of a name that exists stops the writer (record 0006, rule 44).
func (r *run) ensureDir(path string) error {
	_, err := fsx.ReadDir(r.in.Writer.FS, path)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		if err := r.in.Writer.Mkdir(path, dirMode); err != nil {
			return fmt.Errorf("%s/ could not be made: %w", path, err)
		}
		return nil
	}
	return fmt.Errorf("%s/ cannot be listed: %w", path, err)
}

// verify reads the file at path back and compares it with what was written.
func (r *run) verify(path string, want []byte) error {
	got, err := fsx.ReadFile(r.in.Writer.FS, path)
	if err != nil {
		return fmt.Errorf("%s could not be read back: %w", path, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%s is not what was written", path)
	}
	return nil
}

// record writes the ceremony record, last, and the self-check of the bundle.
func (r *run) record(made *Made) (*Done, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, r.stop("record", err)
	}
	now, err := r.in.Env.now()
	if err != nil {
		return nil, r.stop("record", err)
	}
	root := made.Record
	rb, err := r.folder.Record(RecordIn{
		Command:      files.CommandApply,
		Outcome:      files.OutcomeCompleted,
		StartedAt:    r.started,
		FinishedAt:   timeText(now),
		Root:         &root,
		Confirmation: &files.Confirmation{By: r.in.Confirm.by(), At: r.confirmed},
		RanOn:        RanOnWorkstation,
		LimitShown:   r.limitShown,
		Artifacts:    made.Artifacts(),
	})
	if err != nil {
		return nil, r.stop("record", err)
	}
	r.phase = phaseRecorded
	rec, err := files.ReadRecord(rb)
	if err != nil {
		return nil, r.stop("record", fmt.Errorf("the record that was written is refused by its reader: %w", err))
	}
	done := &Done{
		Ceremony:      r.plan.Name,
		RecordPath:    historyDir + "/" + r.plan.Name + "/" + files.RecordFile,
		RecordSHA256:  files.Digest(rb),
		Artifacts:     slices.Clone(rec.Artifacts),
		TrustSequence: rec.TrustSequence,
		TrustSet:      trustSetFolder(made),
	}
	for i, m := range made.Roots {
		done.Roots = append(done.Roots, RootInfo{Label: m.Label, Store: storeSoftware, Test: true, X509SPKISHA256: m.Pin, NotAfter: r.plan.Signatures[2*i].NotAfter})
	}
	if err := r.selfCheck(done); err != nil {
		return nil, err
	}
	r.summary(done, made)
	return done, nil
}

// selfCheck is the last step: the check of the history on the bundle that was just written must be clean, count one
// record, and have that record as its one end. A bundle that its own check refuses is a fault of the
// program, found at once. A notice is not a fault, and is printed.
func (r *run) selfCheck(done *Done) error {
	rep, err := history.Check(r.ctx, r.in.Writer.FS)
	if err != nil {
		return r.stop("check", fmt.Errorf("the history check could not run on the bundle that was written: %w", err))
	}
	if !rep.Clean() {
		codes := make([]string, 0, len(rep.Reasons()))
		for _, c := range rep.Reasons() {
			codes = append(codes, string(c))
		}
		return r.stop("check", fmt.Errorf("the ceremony wrote a bundle that its own check refuses (findings: %s); run ritueel check history", strings.Join(codes, ", ")))
	}
	if rep.Records != 1 || len(rep.Ends) != 1 || rep.Ends[0] != done.RecordSHA256 {
		return r.stop("check", errors.New("the ceremony wrote a bundle whose history is not one record that ends at the new record; run ritueel check history"))
	}
	for _, f := range rep.Notices() {
		r.console.Err("check history notice: %s", f.Line())
	}
	done.End, done.Records, done.EndLine = rep.Ends[0], rep.Records, rep.EndLine()
	return nil
}

// summary prints what the run did. These lines come after the record and are not in the transcript. The
// last line, on standard output, is the end line of the history.
func (r *run) summary(done *Done, made *Made) {
	r.console.Err("ceremony %s is recorded: %s, digest %s", done.Ceremony, done.RecordPath, done.RecordSHA256)
	r.console.Err("trust set %s, sequence %d", done.TrustSet, done.TrustSequence)
	for _, root := range done.Roots {
		r.console.Err("root key %s: x509 pin %s, certificate ends %s", root.Label, root.X509SPKISHA256, root.NotAfter)
	}
	places := make([]string, 0, len(made.Roots))
	for _, root := range made.Roots {
		places = append(places, root.Place)
	}
	r.console.Err("the keys %s are in the folder %s of the key directory, and the removal authorisations are beside that folder: copy them to a safe place; this is a TEST ONLY root", strings.Join(places, ", "), keydir.TestOnlyFolder)
	r.console.Out("%s", done.EndLine)
}
