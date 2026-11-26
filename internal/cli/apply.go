package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"

	ucli "github.com/urfave/cli/v3"

	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
)

// The flags of apply.
const (
	flagPlanOnly = "plan-only"
	flagKeyDir   = "key-dir"
	flagConfirm  = "confirm"
)

// historyDir is the folder of the ceremony folders in the bundle.
const historyDir = "history"

// nothingToApply is the text of an apply that found no wanted root file: it writes no file and makes
// no plan (Proposed: no page says what apply does with nothing to apply).
const nothingToApply = "nothing to apply\n"

// applySpec is the word apply. This version makes the first apply of a software test root: apply
// --plan-only finds what is wanted and not applied, writes the plan folder (plan.json and the exact
// copies of the wanted files it used) and stops; apply runs the whole ceremony after the confirmation of
// the person (the first eight characters of the plan digest, typed at a terminal) or of a script
// (--confirm and the whole digest); apply PLAN runs a plan that --plan-only made.
var applySpec = spec{
	name:      "apply",
	usage:     "make the plan of the first apply of a test root and stop, or run it (PLAN is a saved plan)",
	argsUsage: "--plan-only [--key-dir DIR] | --key-dir DIR [--confirm DIGEST] [PLAN]",
	flags:     applyFlags,
	run:       runApply,
}

func applyFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.BoolFlag{Name: flagPlanOnly, Usage: "write the plan (history/CEREMONY/plan.json) and stop"},
		&ucli.StringFlag{Name: flagKeyDir, Usage: "the folder `DIR` for the key files, outside the bundle and its work tree; it must exist and not have been used: no folder test-only-keys, no removal authorisation and no key file; a run needs it"},
		&ucli.StringFlag{Name: flagConfirm, Usage: "confirm the plan from a script: the whole plan `DIGEST`, 64 lower-case hexadecimal digits; without it the person types the first eight characters at a terminal"},
	}
}

// runApply is apply. With --plan-only it finds what is wanted, shows the plan in words on standard
// error, writes the plan folder through ceremony.Folder and ends with the name of the ceremony and the
// plan's path and digest. Without it the command runs the ceremony: it makes the plan (or reads PLAN,
// the path of a saved plan inside the bundle), shows it, asks for the confirmation and calls
// ceremony.Run. The usage errors come first, in the order of the page: a flag given twice, more than one argument, --plan-only
// with a PLAN, --confirm with --plan-only, a PLAN that is not history/CEREMONY/plan.json, and a run with
// no --key-dir. Every line a person reads goes through one ceremony.Console.
func runApply(ctx context.Context, c *Call) (*Result, error) {
	// A flag that is given twice is a usage error and nothing is read: the library keeps the last value,
	// so the first would be dropped without a word (check request does the same for --delegation).
	for _, name := range []string{flagConfirm, flagKeyDir, flagPlanOnly} {
		if c.FlagCount(name) > 1 {
			return nil, UsageError{Msg: "--" + name + " is given once"}
		}
	}
	if len(c.Args) > 1 {
		return nil, UsageError{Msg: "apply takes at most one argument, the path of a saved plan"}
	}
	planOnly := c.FlagBool(flagPlanOnly)
	saved := len(c.Args) == 1
	if planOnly && saved {
		return nil, UsageError{Msg: "--plan-only makes a plan; it does not take a saved plan as an argument"}
	}
	if planOnly && c.FlagSet(flagConfirm) {
		return nil, UsageError{Msg: "--plan-only makes a plan and asks for nothing; it does not take --confirm"}
	}
	if saved {
		if _, err := ceremony.CheckPlanPath(c.Args[0]); err != nil {
			return nil, applyError(err)
		}
	}
	if !planOnly && c.FlagString(flagKeyDir) == "" {
		return nil, UsageError{Msg: "apply needs --key-dir DIR, the folder for the key files; make it first, outside the bundle and its work tree"}
	}
	dir, err := bundleDir(c)
	if err != nil {
		return nil, err
	}
	if planOnly {
		return planOnlyIn(ctx, c, dir)
	}
	return runIn(ctx, c, dir, saved)
}

// runIn is apply and apply PLAN on the bundle folder dir. The folder is opened once, with one writer:
// its FS is what Find and the saved plan are read from, and the writer writes the ceremony into it, so
// that what was judged and what is written are one folder. The key directory is judged against the path
// text of the bundle, not the opened folder; holding it to the folder by identity is a later change. The
// writer is released after the run, and on every path out.
func runIn(ctx context.Context, c *Call, dir string, saved bool) (*Result, error) {
	w, err := fsx.Open(dir)
	if err != nil {
		return nil, err
	}
	released := false
	defer func() {
		if !released {
			// The error path: the run's own error is the one to report, and a stopped writer says the same.
			_ = w.Close()
		}
	}()
	stdout := c.Env.Stdout
	if c.Global.Output == OutputJSON {
		// With --output json standard output holds the object only.
		stdout = io.Discard
	}
	console := ceremony.NewConsole(c.Env.Stderr, stdout)
	env := ceremony.Env{Now: c.Env.Now, In: c.Env.Stdin, InIsTerminal: c.Env.StdinIsTerminal, Out: console}
	in := ceremony.RunIn{Writer: w, Env: env, Saved: saved, KeyDir: c.FlagString(flagKeyDir), BundleDir: dir}
	if c.FlagSet(flagConfirm) {
		in.Confirm = ceremony.Confirm{Flag: true, Digest: c.FlagString(flagConfirm)}
	}
	if saved {
		if in.Plan, err = ceremony.ReadSavedPlan(w.FS, c.Args[0]); err != nil {
			return nil, applyError(err)
		}
	} else {
		found, err := ceremony.Find(ctx, ceremony.FindInput{FS: w.FS})
		if err != nil {
			return nil, applyError(err)
		}
		if found.Nothing() {
			return &Result{ExitCode: ExitOK, Text: nothingToApply}, nil
		}
		if in.Plan, err = ceremony.MakePlan(found, env); err != nil {
			return nil, applyError(err)
		}
		in.Wanted = found.Wanted
	}
	done, err := ceremony.Run(ctx, in)
	released = true
	if cerr := w.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("the bundle folder could not be released: %w", cerr)
		if done != nil {
			err = fmt.Errorf("the ceremony %s is recorded, but the bundle folder could not be released: %w", jsonset.EscapeExact(done.Ceremony), cerr)
		}
	}
	if err != nil {
		return nil, applyError(err)
	}
	if _, err := console.Transcript(); errors.Is(err, ceremony.ErrPrintFailed) {
		return nil, fmt.Errorf("the ceremony %s is recorded, but a line of it could not be shown: %w", jsonset.EscapeExact(done.Ceremony), err)
	}
	return resultOf(in.Plan, done), nil
}

// resultOf is the Result of a ceremony that ended well: the members ceremony, plan, record, artifacts,
// trust_sequence and roots of docs/reference/cli.md, "Machine-readable output". The text of the end line was
// printed by the run, on standard output.
func resultOf(plan *ceremony.PlanOut, done *ceremony.Done) *Result {
	res := &Result{
		ExitCode:      ExitOK,
		Ceremony:      done.Ceremony,
		Plan:          &PlanRef{Path: historyDir + "/" + plan.Name + "/" + files.PlanFile, SHA256: plan.SHA256, Prefix: plan.Prefix},
		Record:        &RecordRef{Path: done.RecordPath, SHA256: done.RecordSHA256},
		TrustSequence: done.TrustSequence,
	}
	for _, a := range done.Artifacts {
		res.Artifacts = append(res.Artifacts, ArtifactRef{Path: a.Path, SHA256: a.SHA256})
	}
	for _, r := range done.Roots {
		res.Roots = append(res.Roots, RootRef{Label: r.Label, Store: r.Store, Test: r.Test, X509SPKISHA256: r.X509SPKISHA256, NotAfter: r.NotAfter})
	}
	return res
}

// planOnlyIn is apply --plan-only on the bundle folder dir. The folder is opened once, with one
// writer: its FS is what Find reads, and the writer writes the plan folder into it, so that what was
// judged and what is written are one folder even when a parent of dir is swapped between two opens.
// The key directory is checked against the same path of the folder that this open used. The writer is
// released before the plan is shown, and on every path out.
func planOnlyIn(ctx context.Context, c *Call, dir string) (*Result, error) {
	w, err := fsx.Open(dir)
	if err != nil {
		return nil, err
	}
	released := false
	defer func() {
		if !released {
			// Nothing was written on a path that gets here, so a failed close loses nothing.
			_ = w.Close()
		}
	}()
	found, err := ceremony.Find(ctx, ceremony.FindInput{FS: w.FS})
	if err != nil {
		return nil, applyError(err)
	}
	if found.Nothing() {
		return &Result{ExitCode: ExitOK, Text: nothingToApply}, nil
	}
	if c.FlagSet(flagKeyDir) {
		// The key directory is judged against the path text of the bundle, not the opened folder; holding it to the folder by identity comes with the part that makes keys.
		if err := ceremony.CheckKeyDir(c.FlagString(flagKeyDir), dir); err != nil {
			return nil, applyError(err)
		}
	}
	stdout := c.Env.Stdout
	if c.Global.Output == OutputJSON {
		// With --output json standard output holds the object only.
		stdout = io.Discard
	}
	console := ceremony.NewConsole(c.Env.Stderr, stdout)
	plan, err := ceremony.MakePlan(found, ceremony.Env{Now: c.Env.Now, In: c.Env.Stdin, Out: console})
	if err != nil {
		return nil, applyError(err)
	}
	err = writePlan(w, plan, found)
	released = true
	if cerr := w.Close(); cerr != nil && err == nil {
		err = fmt.Errorf("the bundle folder could not be released: %w", cerr)
	}
	if err != nil {
		return nil, err
	}
	path := historyDir + "/" + plan.Name + "/" + files.PlanFile
	for _, line := range plan.Words() {
		console.Err("%s", line)
	}
	console.Out("plan %s", path)
	console.Out("digest %s", plan.SHA256)
	if _, err := console.Transcript(); err != nil {
		return nil, fmt.Errorf("the plan was written as %s (digest %s), but it could not be shown: %w", jsonset.EscapeExact(path), plan.SHA256, err)
	}
	return &Result{
		ExitCode: ExitOK,
		Ceremony: plan.Name,
		Plan:     &PlanRef{Path: path, SHA256: plan.SHA256, Prefix: plan.Prefix},
	}, nil
}

// writePlan writes the plan folder with ceremony.Folder.WritePlan, the only writer of this command,
// into the folder that w holds; the caller releases w. A name that is taken, which is a plan made in
// the same second, is a failure that says so, and the folder that exists is untouched.
func writePlan(w *fsx.Writer, plan *ceremony.PlanOut, found *ceremony.Found) error {
	folder, err := ceremony.NewFolder(w, plan.Name)
	if err != nil {
		return err
	}
	if err := folder.WritePlan(plan.JSON, found.Wanted); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("a plan was made in the same second, and the folder history/%s exists already; run apply --plan-only again a second later; nothing was written: %w", jsonset.EscapeExact(plan.Name), err)
		}
		return err
	}
	return nil
}

// applyError is the one place that turns the errors of package ceremony into the errors of this
// package that carry an exit code. It returns exactly one of them, or the error itself for a failure.
func applyError(err error) error {
	var usage *ceremony.UsageError
	var refused *ceremony.RefusedError
	var backend *ceremony.BackendError
	var stopped *ceremony.StoppedError
	switch {
	case errors.As(err, &stopped):
		// A fault after the first write is a failure (exit code 1) whatever its cause is: the cause may
		// be a refusal of the key store, and the line says what is on disk. The cause stays reachable.
		return err
	case errors.As(err, &usage):
		return UsageError{Msg: usage.Msg}
	case errors.As(err, &refused):
		return Refusal{Reasons: refused.Reasons, Msg: refused.Msg}
	case errors.As(err, &backend):
		return BackendRefusal{Reasons: backend.Reasons, Msg: backend.Msg}
	case errors.Is(err, ceremony.ErrNotConfirmed):
		return NotConfirmed{}
	}
	return err
}
