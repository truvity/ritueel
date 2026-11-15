package ceremony

import (
	"errors"
	"fmt"
	"strings"

	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/jsonset"
)

// CheckPlanPath judges the argument PLAN of apply and returns the name of the ceremony in it. PLAN is a
// path inside the bundle of the form history/<ceremony>/plan.json, the path that apply --plan-only
// prints as plan.path: a plan is written by the process inside the bundle (record 0006, rule 9). A path
// of another form (an absolute path, another file name, a path outside history/, a name that is not a
// plain name) is a [*UsageError] (exit code 2; Proposed: the cli page gives no form for PLAN). It
// reads nothing.
func CheckPlanPath(path string) (string, error) {
	bad := func() error {
		return &UsageError{Msg: "PLAN is the path that apply --plan-only printed, history/CEREMONY/plan.json, inside the bundle; got " + jsonset.Quote(path)}
	}
	if files.CheckPath(path) != nil {
		return "", bad()
	}
	elems := strings.Split(path, "/")
	if len(elems) != 3 || elems[0] != historyDir || elems[2] != files.PlanFile || fsx.CheckName(elems[1]) != nil {
		return "", bad()
	}
	return elems[1], nil
}

// ReadSavedPlan takes the plan of apply PLAN: it checks the form of path ([CheckPlanPath]), reads the
// file once with fsx.ReadFile, bounds it before it is parsed, and reads it with [ReadPlanOut], the one
// typed reading of a plan, so that the words that a person confirms and the values that the run
// executes come from one reading. The member ceremony of the plan must be the name of the folder in
// path. A file that cannot be read, a plan that its reader refuses and a plan of another folder are
// failures (exit code 1) and nothing is written. The plan is not read a second time.
func ReadSavedPlan(fsys fsx.FS, path string) (*PlanOut, error) {
	name, err := CheckPlanPath(path)
	if err != nil {
		return nil, err
	}
	if fsys == nil {
		return nil, errors.New("ceremony: there is no bundle to read")
	}
	b, err := fsx.ReadFile(fsys, path)
	if err != nil {
		return nil, fmt.Errorf("the saved plan %s cannot be read, and nothing was written: %w", jsonset.EscapeExact(path), err)
	}
	p, err := ReadPlanOut(b)
	if err != nil {
		return nil, fmt.Errorf("the saved plan %s is refused, and nothing was written: %w", jsonset.EscapeExact(path), err)
	}
	if p.Name != name {
		return nil, fmt.Errorf("the saved plan %s is the plan of the ceremony %s, not of the folder it stands in, and nothing was written", jsonset.EscapeExact(path), jsonset.EscapeExact(p.Name))
	}
	return p, nil
}
