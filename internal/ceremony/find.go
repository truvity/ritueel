package ceremony

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/cards"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/wanted"
)

// defaultKeys is the number of keys that the first apply makes for a root: two (record 0005, rule 20,
// "two keys of each root by default"). The labels are the next free letters, A then B (record 0006,
// rule 2).
const defaultKeys = 2

// changeCreate is the one change of the first apply: a key is made (record 0007, rule 1).
const changeCreate = "create"

// Reason codes of a refusal that Find makes.
const (
	// ReasonUnfinishedCeremony is the reason code of an apply that is refused because an attempt is
	// open: a ceremony folder holds attempt.json and no ceremony record.
	ReasonUnfinishedCeremony = "unfinished-ceremony"
)

// leftOutReason is the reason that a request gives in leaves_out: the first apply answers no
// request (record 0007, rule 9: a change of the root keys runs alone).
const leftOutReason = "a change of the root keys runs alone (record 0007, rule 9)"

// maxRequestNames is the most names under requests/ that Find keeps.
const maxRequestNames = wanted.MaxFiles

// maxRootsRead is the most root files whose bytes Find reads. This version builds one root, so a
// bundle of two or more root files is refused whatever they hold; the first few are read only so
// that the refusal can name what is wrong with them (a kind that is not built, a root that is not a
// test root). A bundle of more root files is refused from their names, and none is read.
const maxRootsRead = 8

// rootFiles are the root files of a bundle as Find reads them: all the names, in order, and the
// roots of those names when there are no more than maxRootsRead of them.
type rootFiles struct {
	// names are the names of every root file, without ".yaml", in the order of the names.
	names []string
	// roots are the roots of the names, in the same order; nil when the names are more than
	// maxRootsRead and none was read.
	roots []*wanted.Root
}

// unread reports whether the files were too many to be read.
func (r rootFiles) unread() bool { return len(r.names) > len(r.roots) }

// FindInput is what Find reads: the bundle, from its root folder. Find reads and writes nothing
// else.
type FindInput struct {
	// FS is the root folder of the bundle. Find only reads it.
	FS fsx.FS
	// Now is the clock of the command's environment. Find reads it once, and only for a personal bundle,
	// whose keys are judged against the day they expire. A nil clock is an error for a personal bundle and
	// is not read for another.
	Now func() time.Time
}

// Change is one change that a plan applies: the word and the object it applies to, for example
// {"create", "x509/A"} (docs/reference/ceremony-record.md, "The plan": the names of the members are
// Proposed). The object is the name of the wanted root file, a slash and the label of the key.
type Change struct {
	Change string `json:"change"`
	Object string `json:"object"`
}

// LeftOut is one change that a plan leaves out, with the reason: for a request,
// {"requests/acme-ca-2027", "..."}.
type LeftOut struct {
	Object string `json:"object"`
	Reason string `json:"reason"`
}

// Found is what Find returns: what a plan would apply and what it would leave out, and what the plan
// is made from.
type Found struct {
	// Applies are the changes, in the order the plan lists them. Empty when there is nothing to
	// apply.
	Applies []Change
	// LeavesOut are the changes that are left out, with the reason, in the order of the names.
	LeavesOut []LeftOut
	// Root is the one wanted root file of this version; nil when there is nothing to apply.
	Root *wanted.Root
	// Settings is ritueel.yaml.
	Settings *wanted.Settings
	// Wanted are the wanted files that the plan uses, in path order: ritueel.yaml and the root
	// file. They are the bytes that were read, and the plan lists their digests.
	Wanted []wanted.File
	// State is the state of the bundle that Find judged: no ceremony record and no trust set.
	State *history.State
}

// Nothing reports whether Find found nothing to apply. A Found of this kind has no plan.
func (f *Found) Nothing() bool { return f == nil || len(f.Applies) == 0 }

// Find is the function of record 0005, rules 4 and 5: it reads the wanted files and the state of
// the bundle and says what is not applied yet. Nothing is stored (rule 4) and nothing is written. In
// this version it knows one case: the first apply of a bundle that has one wanted test root of the
// kind x509 and no history. It returns an error, and no Found, for a bundle that is in another state
// and for a wanted file that it cannot use. The order of the refusals is: a wanted file that fails its
// check (exit code 1); a history that fails its own check (exit code 3); a history whose order cannot
// be settled (exit code 1); an open attempt (exit code 3, [ReasonUnfinishedCeremony]); a bundle that
// is not in the first state (exit code 1, [ErrNotFirst]); a root that is not built (exit code 1,
// [ErrNotBuilt]); a request name that is not a plain name (exit code 1). The names of the root files
// are listed and counted before any is read, and when there are more than maxRootsRead of them none
// is read: that bundle is refused as not built, at the place of that refusal, whatever the files hold. A
// personal bundle is judged with the clock of [FindInput.Now]: when its wanted files fail their check it is
// the first refusal, and when they pass it is refused as not built, with the personal case first.
func Find(ctx context.Context, in FindInput) (*Found, error) {
	if ctx == nil {
		return nil, errors.New("ceremony: there is no context")
	}
	if in.FS == nil {
		return nil, errors.New("ceremony: there is no bundle to read")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	settings, rf, err := readWanted(ctx, in.FS, in.Now)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st, err := inspect(ctx, in.FS)
	if err != nil {
		return nil, err
	}
	if err := refuseWhileOpen(st); err != nil {
		return nil, err
	}
	if err := refuseNotFirst(in.FS, st); err != nil {
		return nil, err
	}
	if err := notBuilt(settings, rf); err != nil {
		return nil, err
	}
	requests, err := requestNames(in.FS)
	if err != nil {
		return nil, err
	}
	found := &Found{Settings: settings, State: st}
	for _, name := range requests {
		found.LeavesOut = append(found.LeavesOut, LeftOut{Object: "requests/" + name, Reason: leftOutReason})
	}
	if len(rf.roots) == 0 {
		return found, nil
	}
	root := rf.roots[0]
	for i := range defaultKeys {
		found.Applies = append(found.Applies, Change{Change: changeCreate, Object: root.Name + "/" + labelOf(i)})
	}
	found.Root = root
	found.Wanted = []wanted.File{settings.File, root.File}
	return found, nil
}

// labelOf is the label of the i-th key of a root: the next free letters from A (record 0006, rule 2).
func labelOf(i int) string { return string(rune('A' + i)) }

// readWanted reads ritueel.yaml, the root files and every delegation file, and refuses the first one
// that fails its own check, with an error that names the path (escaped by the error itself). The
// names of the root files are listed and counted before any is read; the bytes of the root files are
// read only when there are no more than maxRootsRead of them. The delegation files are read and
// checked one at a time, and not used or kept. The card files are checked last, as a whole, and not kept
// either. A canceled context is returned as it is: it is not a refused file.
//
// For a personal bundle the delegations and the cards are kept until the last step, which reads
// want/openpgp.yaml when it exists and judges every file against the others ([wanted.CheckPersonal]) with the
// time of now; a bundle that is not personal is judged by [wanted.CheckCompanyRoots] instead.
func readWanted(ctx context.Context, fsys fsx.FS, now func() time.Time) (*wanted.Settings, rootFiles, error) {
	refused := func(err error) error {
		return fmt.Errorf("a wanted file is refused, and nothing was written: %w", err)
	}
	settings, err := wanted.LoadSettings(fsys)
	if err != nil {
		return nil, rootFiles{}, refused(err)
	}
	names, err := wanted.ListRootNames(fsys)
	if err != nil {
		return nil, rootFiles{}, refused(err)
	}
	rf := rootFiles{names: names}
	if len(names) <= maxRootsRead {
		if rf.roots, err = wanted.LoadRoots(fsys, names); err != nil {
			return nil, rootFiles{}, refused(err)
		}
	}
	var delegations []*wanted.Delegation
	if settings.Personal {
		delegations, err = wanted.ListDelegations(fsys, settings)
	} else {
		err = wanted.CheckDelegations(fsys, settings)
	}
	if err != nil {
		return nil, rootFiles{}, refused(err)
	}
	cardFiles, err := cards.Load(ctx, fsys)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, rootFiles{}, err
		}
		return nil, rootFiles{}, refused(err)
	}
	if err := checkAcross(fsys, settings, rf, delegations, cardFiles, now); err != nil {
		return nil, rootFiles{}, refused(err)
	}
	return settings, rf, nil
}

// checkAcross judges the wanted files against each other once each has passed its own reader: for a personal
// bundle the check of [wanted.CheckPersonal], with want/openpgp.yaml when it exists and the time of now, and for
// a bundle that is not personal the refusal of the members that only a person's OpenPGP root has.
func checkAcross(fsys fsx.FS, s *wanted.Settings, rf rootFiles, delegations []*wanted.Delegation, cardFiles []*wanted.Card, now func() time.Time) error {
	if !s.Personal {
		return wanted.CheckCompanyRoots(rf.roots)
	}
	if rf.unread() {
		return &wanted.Error{Path: wanted.RootsDir, Msg: "a personal bundle has one root file, and this folder holds more than one"}
	}
	userIDs, err := wanted.LoadUserIDs(fsys)
	if errors.Is(err, fs.ErrNotExist) {
		userIDs, err = nil, nil
	}
	if err != nil {
		return err
	}
	at, err := Env{Now: now}.now()
	if err == nil && at.IsZero() {
		err = errNoClock // a clock that gives the zero time is no clock
	}
	if err != nil {
		return err
	}
	return wanted.CheckPersonal(s, rf.roots, delegations, cardFiles, userIDs, at)
}

// inspect reads the history of the bundle once and returns its state, or the reason there is none: a
// finding that fails is a refusal (exit code 3) with the codes of the findings, and a clean history
// whose order of root lists cannot be settled is a failure (exit code 1), because a check that cannot
// run is not a pass.
func inspect(ctx context.Context, fsys fsx.FS) (*history.State, error) {
	insp, err := history.Inspect(ctx, fsys)
	if err != nil {
		return nil, fmt.Errorf("the history of the bundle could not be read, and nothing was written: %w", err)
	}
	if insp == nil || insp.Report == nil {
		return nil, errors.New("the history check gave no report, and nothing was written")
	}
	if !insp.Report.Clean() {
		reasons := make([]string, 0, len(insp.Report.Reasons()))
		for _, c := range insp.Report.Reasons() {
			reasons = append(reasons, string(c))
		}
		if len(reasons) == 0 {
			return nil, errors.New("the history check says the history fails and names no reason, and nothing was written")
		}
		return nil, &RefusedError{
			Reasons: reasons,
			Msg:     fmt.Sprintf("the history of the bundle fails its own check (findings: %d): run ritueel check history; nothing was written", len(insp.Report.Failing())),
		}
	}
	if insp.State == nil {
		if insp.OrderErr != nil {
			return nil, fmt.Errorf("the history of the bundle cannot be used, and nothing was written: %w", insp.OrderErr)
		}
		return nil, errors.New("the history check gave no state, and nothing was written")
	}
	return insp.State, nil
}

// refuseWhileOpen is the one place of the rule that an apply makes no plan and runs no plan while an
// attempt is open (issue 140, the stricter of the two readings): a ceremony folder that holds an
// attempt and no ceremony record is refused with the reason [ReasonUnfinishedCeremony] (exit code 3),
// and the text names the folder, escaped. Until a command that closes an attempt is built, a bundle
// with an open attempt cannot be applied to again.
func refuseWhileOpen(st *history.State) error {
	if st == nil || len(st.Unfinished) == 0 {
		return nil
	}
	const shown = 3
	var names []string
	for i, n := range st.Unfinished {
		if i == shown {
			break
		}
		names = append(names, "history/"+jsonset.EscapeExact(n))
	}
	text := strings.Join(names, ", ")
	if more := len(st.Unfinished) - shown; more > 0 {
		text += " and " + strconv.Itoa(more) + " more"
	}
	return &RefusedError{
		Reasons: []string{ReasonUnfinishedCeremony},
		Msg:     "an attempt is open in " + text + ": the folder holds an attempt and no ceremony record, so apply makes no plan and runs none until it is closed (close is not built yet); nothing was written",
	}
}

// refuseNotFirst refuses a bundle that is not in the first state: it has a ceremony record, a trust
// set or an entry under roots/. This version makes the first apply only. (A folder of history/ that
// holds an attempt is [refuseWhileOpen]'s.)
func refuseNotFirst(fsys fsx.FS, st *history.State) error {
	if st == nil {
		return errors.New("the history gave no state, and nothing was written")
	}
	notFirst := func(what string) error {
		return fmt.Errorf("%w: the bundle has %s; the later applies are not built yet, and nothing was written", ErrNotFirst, what)
	}
	if st.Records > 0 {
		return notFirst("a ceremony record")
	}
	if len(st.Lists) > 0 || st.Newest != nil {
		return notFirst("a trust set")
	}
	ents, err := fsx.ReadDir(fsys, "roots")
	switch {
	case err == nil:
		if len(ents) > 0 {
			return notFirst("an entry under roots/")
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return fmt.Errorf("the folder roots/ cannot be listed, and nothing was written: %w", err)
	}
	return nil
}

// notBuilt refuses what the first apply of this version does not make, with a text that names the
// file and what to do (exit code 1, [ErrNotBuilt]). The order is: a personal bundle, whose wanted files
// passed their check (it is refused with a text of its own: adoption and the subkeys are built by later
// parts); a root of the kind openpgp or ssh; a root that is not a test root; two roots of one kind. A
// root of a kind that is not built is never left out silently: a label that was made without an OpenPGP
// primary could never get one, because a label names a key and is not reused. A bundle of more root
// files than Find reads (maxRootsRead) is refused first, from the names alone, because none of those
// files was read.
func notBuilt(s *wanted.Settings, rf rootFiles) error {
	if s.Personal {
		return fmt.Errorf("%w: a personal bundle (kind: personal in ritueel.yaml) passed the check of its wanted files; adoption and subkeys are built by later parts, so apply makes no plan and makes no key; nothing was written", ErrNotBuilt)
	}
	if rf.unread() {
		path := func(name string) string { return jsonset.EscapeExact(wanted.RootsDir + "/" + name + ".yaml") }
		return fmt.Errorf("%w: the bundle has %d root files, more than this version reads, and a bundle has one root of each kind; keep one of %s and %s; nothing was written", ErrNotBuilt, len(rf.names), path(rf.names[0]), path(rf.names[1]))
	}
	roots := rf.roots
	for _, r := range roots {
		switch r.Kind {
		case wanted.RootX509:
		case wanted.RootOpenPGP:
			return fmt.Errorf("%w: the root file %s is of the kind openpgp, and the OpenPGP root is not built; delete that file to apply the X.509 root, or wait for the version that builds the OpenPGP root; nothing was written", ErrNotBuilt, jsonset.EscapeExact(r.File.Path))
		default:
			return fmt.Errorf("%w: the root file %s is of the kind %s, which is not built; delete that file to apply the other roots; nothing was written", ErrNotBuilt, jsonset.EscapeExact(r.File.Path), jsonset.EscapeExact(string(r.Kind)))
		}
	}
	for _, r := range roots {
		if !r.Test {
			return fmt.Errorf("%w: the root file %s is not a test root (it has no \"test: true\"); a root that is not a test root keeps its keys under a passphrase, a card or in the cloud, which is not built; nothing was written", ErrNotBuilt, jsonset.EscapeExact(r.File.Path))
		}
	}
	if len(roots) > 1 {
		return fmt.Errorf("%w: the bundle has %d root files of the kind x509, and a bundle has one root of each kind; keep one of %s and %s; nothing was written", ErrNotBuilt, len(roots), jsonset.EscapeExact(roots[0].File.Path), jsonset.EscapeExact(roots[1].File.Path))
	}
	return nil
}

// requestNames lists the names under requests/, once, in the order of the names. A folder that does
// not exist has none. A name that is not a plain name (fsx.CheckName) is an error that names it,
// escaped, and more than maxRequestNames names is an error: a check that cannot run is not a pass.
// The names are not read.
func requestNames(fsys fsx.FS) ([]string, error) {
	ents, err := fsx.ReadDir(fsys, "requests")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("the folder requests/ cannot be listed, and nothing was written: %w", err)
	}
	if len(ents) > maxRequestNames {
		return nil, fmt.Errorf("the folder requests/ holds more than %d names, and nothing was written", maxRequestNames)
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if err := fsx.CheckName(e.Name()); err != nil {
			return nil, fmt.Errorf("the name %s under requests/ is not a plain name, and nothing was written: %w", jsonset.EscapeExact(e.Name()), err)
		}
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names, nil
}
