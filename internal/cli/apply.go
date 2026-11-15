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
)

// nothingToApply is the text of an apply that found no wanted root file: it writes no file and makes
// no plan (Proposed: no page says what apply does with nothing to apply).
const nothingToApply = "nothing to apply\n"

// applySpec is the word apply. This version builds the plan only: apply --plan-only finds what is
// wanted and not applied, writes the plan folder (plan.json and the exact copies of the wanted files
// it used) and stops. It makes no key and writes no attempt. The run of a plan, with or without a PLAN
// argument, is not built yet.
var applySpec = spec{
	name:      "apply",
	usage:     "make the plan of the first apply of a test root, and stop (the run of a plan is not built yet)",
	argsUsage: "--plan-only [--key-dir DIR]",
	flags:     applyFlags,
	run:       runApply,
}

func applyFlags() []ucli.Flag {
	return []ucli.Flag{
		&ucli.BoolFlag{Name: flagPlanOnly, Usage: "write the plan (history/CEREMONY/plan.json) and stop"},
		&ucli.StringFlag{Name: flagKeyDir, Usage: "the folder `DIR` for the key files, outside the bundle and its work tree; it must exist and hold no key file"},
	}
}

// runApply is apply. With --plan-only it finds what is wanted, shows the plan in words on standard
// error, writes the plan folder through ceremony.Folder and ends with the name of the ceremony and the
// plan's path and digest. Every line a person reads goes through one ceremony.Console. Without
// --plan-only, or with a PLAN argument, it says in one line that it is not built yet and writes nothing
// (exit code 1).
func runApply(ctx context.Context, c *Call) (*Result, error) {
	if len(c.Args) > 1 {
		return nil, UsageError{Msg: "apply takes at most one argument, the path of a saved plan"}
	}
	planOnly := c.FlagBool(flagPlanOnly)
	if planOnly && len(c.Args) == 1 {
		return nil, UsageError{Msg: "--plan-only makes a plan; it does not take a saved plan as an argument"}
	}
	if !planOnly {
		if len(c.Args) == 1 {
			return nil, errors.New("apply of a saved plan is not built yet; apply --plan-only makes a plan; nothing was written")
		}
		return nil, errors.New("apply without --plan-only is not built yet; apply --plan-only makes a plan; nothing was written")
	}
	dir, err := bundleDir(c)
	if err != nil {
		return nil, err
	}
	return planOnlyIn(ctx, c, dir)
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
	path := "history/" + plan.Name + "/" + files.PlanFile
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
	switch {
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
