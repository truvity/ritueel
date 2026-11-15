package ceremony

import (
	"errors"
	"fmt"
	"io/fs"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/jsonset"
)

// The reason codes of a saved plan that is refused before anything is written (exit code 3). Only
// plan-stale is a code of the pages; the other three are Proposed (docs/reference/ceremony-record.md,
// "The plan digest and the confirmation").
const (
	// ReasonPlanStale is a plan whose state of the bundle has changed since it was made: the newest
	// trust sequence is no longer its base_sequence, or the end of the history is no longer its
	// last_record_sha256.
	ReasonPlanStale = "plan-stale"
	// ReasonPlanVersion is a plan that another copy of ritueel made: its version, system or digest
	// is not that of the program that runs (Proposed).
	ReasonPlanVersion = "plan-version"
	// ReasonPlanUsed is a plan whose folder holds an attempt or a record already: the plan has been
	// run, or started (Proposed).
	ReasonPlanUsed = "plan-used"
	// ReasonClockBehind is a clock that shows a time before the ceremony time of the plan (Proposed):
	// a list signed in the future is refused by every host.
	ReasonClockBehind = "clock-behind"
)

// refused makes the refusal of a saved plan: one reason code and one line for a person.
func refused(reason, format string, args ...any) error {
	return &RefusedError{Reasons: []string{reason}, Msg: fmt.Sprintf(format, args...) + "; nothing was written"}
}

// checkStale is the first of the checks that a saved plan is bound to the state it was made against
// (docs/reference/ceremony-record.md, "A plan is bound to the state it was made against"). The plan
// of this version is made against a bundle with no trust set and no ceremony record, so its base
// sequence is none and its last record is none: it is stale as soon as the bundle holds a trust set
// or a ceremony record. The files of inputs are not compared, because this plan lists none. The
// refusal is plan-stale (exit code 3). There is no age limit and the live wanted files are not
// compared (issue 142 is open).
func checkStale(st *history.State) error {
	if st == nil {
		return errors.New("the history gave no state, so the plan cannot be judged, and nothing was written")
	}
	if st.Newest != nil || len(st.Lists) > 0 {
		return refused(ReasonPlanStale, "the plan was made against a bundle with no trust set, and the bundle holds one now")
	}
	if st.Records > 0 || st.End != "" {
		return refused(ReasonPlanStale, "the plan was made against a bundle with no ceremony record, and the bundle holds one now")
	}
	return nil
}

// checkVersion refuses a plan that another copy of ritueel made: the version, the system and the
// architecture, and the digest of the program must be those of the program that runs (record 0005,
// rule 32; Proposed code plan-version). A description of this program that cannot be made is a
// failure and not a pass.
func checkVersion(env Env, p *PlanOut) error {
	self, err := env.program()
	if err != nil {
		return fmt.Errorf("the description of this program cannot be made, so the plan cannot be judged, and nothing was written: %w", err)
	}
	if self != p.Program {
		return refused(ReasonPlanVersion, "the plan was made by ritueel %s (%s) and this is ritueel %s (%s), or another copy of it; run the plan with the copy that made it",
			jsonset.EscapeExact(p.Program.Version), jsonset.EscapeExact(p.Program.OSArch), jsonset.EscapeExact(self.Version), jsonset.EscapeExact(self.OSArch))
	}
	return nil
}

// checkClock refuses a clock that shows a time before the ceremony time of the plan: every signature
// of the ceremony would carry a time that has not come, and a host refuses a list signed in its
// future (Proposed code clock-behind). A clock that cannot be read is a failure.
func checkClock(env Env, p *PlanOut) error {
	now, err := env.now()
	if err != nil {
		return err
	}
	if now.Before(p.Time) {
		return refused(ReasonClockBehind, "the clock shows %s, which is before the ceremony time of the plan, %s", timeText(now), timeText(p.Time))
	}
	return nil
}

// refuseUsedPlan refuses a plan whose folder already holds an attempt or a ceremony record: the plan
// has been started, and ritueel refuses to run it again (docs/reference/ceremony-record.md, "The
// attempt": "An existing attempt for a plan means its serials may be used: ritueel refuses to run
// that plan again"; the code plan-used is Proposed). While issue 140 stays on option B, an open attempt is
// refused earlier, by [refuseWhileOpen], and a plan whose ceremony has a record is refused earlier
// as stale; this function stays behind them and is reached for a folder that a closing record
// resolved, and when the earlier refusals change. A folder that cannot be listed is a failure.
func refuseUsedPlan(fsys fsx.FS, name string) error {
	ents, err := fsx.ReadDir(fsys, historyDir+"/"+name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("the folder history/%s of the plan does not exist, and nothing was written", jsonset.EscapeExact(name))
		}
		return fmt.Errorf("the folder history/%s of the plan cannot be listed, and nothing was written: %w", jsonset.EscapeExact(name), err)
	}
	for _, e := range ents {
		switch e.Name() {
		case files.AttemptFile:
			return refused(ReasonPlanUsed, "the folder history/%s holds an attempt, so the plan was started; ritueel does not run a plan again", jsonset.EscapeExact(name))
		case files.RecordFile:
			return refused(ReasonPlanUsed, "the folder history/%s holds a ceremony record, so the plan was run; ritueel does not run a plan again", jsonset.EscapeExact(name))
		}
	}
	return nil
}
