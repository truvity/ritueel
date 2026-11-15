//go:build linux || darwin

package history_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// The additions to Inspect and State, on the bundles of a real ceremony that was stopped at each
// step (package ceremonytest). This is an external test package: ceremonytest imports ceremony,
// which imports history.

func inspectDir(t testing.TB, dir string) (*history.Report, *history.Inspection) {
	t.Helper()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	rep, err := history.Check(context.Background(), fsys)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	in, err := history.Inspect(context.Background(), fsys)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !reflect.DeepEqual(rep, in.Report) {
		t.Fatalf("Check and Inspect give different reports:\n%+v\n%+v", rep, in.Report)
	}
	return rep, in
}

var allSteps = []ceremonytest.Step{
	ceremonytest.AtPlan, ceremonytest.AtAttempt, ceremonytest.AtFirstBirth, ceremonytest.AtBirths,
	ceremonytest.AtSignatures, ceremonytest.AtTranscript, ceremonytest.AtSet, ceremonytest.Recorded,
}

// For every bundle at every step: Inspect gives the report of Check; Inspection.Unfinished names the
// ceremony from the attempt up to the trust set and no other; State.Unfinished equals it; a set that
// no record lists is in Unlisted with its bytes; NewestListed is never that set.
func TestEveryStepGivesTheReportOfCheckAndTheAdditions(t *testing.T) {
	for _, step := range allSteps {
		t.Run(step.String(), func(t *testing.T) {
			m := ceremonytest.Bundle(t, ceremonytest.Options{Step: step})
			rep, in := inspectDir(t, m.Dir)
			if in.State == nil {
				t.Fatalf("no State: %v", in.OrderErr)
			}
			st := in.State
			open := step >= ceremonytest.AtAttempt && step <= ceremonytest.AtSet
			if open {
				if !slices.Equal(in.Unfinished, []string{m.Ceremony}) {
					t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, m.Ceremony)
				}
			} else if len(in.Unfinished) != 0 {
				t.Errorf("Unfinished = %v, want none", in.Unfinished)
			}
			if !slices.Equal(st.Unfinished, in.Unfinished) {
				t.Errorf("State.Unfinished %v, Inspection.Unfinished %v", st.Unfinished, in.Unfinished)
			}
			switch step {
			case ceremonytest.AtSet:
				list, err := os.ReadFile(filepath.Join(m.Dir, "trust", m.Set, "root-list.json"))
				if err != nil {
					t.Fatal(err)
				}
				if len(st.Unlisted) != 1 || st.Unlisted[0].Name != m.Set || st.Unlisted[0].Number != 1 || !bytes.Equal(st.Unlisted[0].ListJSON, list) {
					t.Errorf("Unlisted = %+v, want the set %s with its list", st.Unlisted, m.Set)
				}
				if st.NewestListed != nil || len(st.Chain) != 0 || st.Newest == nil || st.Newest.Name != m.Set {
					t.Errorf("NewestListed %+v, Chain %+v, Newest %+v", st.NewestListed, st.Chain, st.Newest)
				}
				if len(rep.Findings) != 1 || rep.Findings[0].Code != history.UnfinishedCeremony {
					t.Errorf("findings %v", rep.Findings)
				}
			case ceremonytest.Recorded:
				if len(st.Unlisted) != 0 || len(st.Chain) != 1 || st.NewestListed == nil || st.NewestListed.Name != m.Set {
					t.Errorf("Unlisted %+v, Chain %+v, NewestListed %+v", st.Unlisted, st.Chain, st.NewestListed)
				}
				if !bytes.Equal(st.NewestListed.ListJSON, st.Newest.ListJSON) || st.NewestListed.Number != st.Newest.Number {
					t.Errorf("NewestListed %+v differs from Newest %+v", st.NewestListed, st.Newest)
				}
				if st.Chain[0].SHA256 != st.End || st.Chain[0].Folder != m.Ceremony {
					t.Errorf("Chain %+v, End %s", st.Chain, st.End)
				}
			default:
				if len(st.Unlisted) != 0 || len(st.Chain) != 0 || st.NewestListed != nil || st.Newest != nil {
					t.Errorf("Unlisted %+v, Chain %+v, NewestListed %+v, Newest %+v", st.Unlisted, st.Chain, st.NewestListed, st.Newest)
				}
			}
		})
	}
}

// A real bundle with three records: the chain is in order, the newest listed set is the newest set,
// and what is returned is a copy.
func TestChainOfRealRecords(t *testing.T) {
	m := ceremonytest.More(t, ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded}), 2)
	_, in := inspectDir(t, m.Dir)
	st := in.State
	if st == nil || len(st.Chain) != 3 || st.Records != 3 {
		t.Fatalf("State %+v", st)
	}
	for i, c := range st.Chain {
		sum := digestFile(t, filepath.Join(m.Dir, "history", c.Folder, "record.json"))
		if c.SHA256 != sum || c.Command != "apply" || c.Outcome != "completed" {
			t.Errorf("Chain[%d] = %+v, the file has %s", i, c, sum)
		}
	}
	if st.Chain[2].Folder != m.Ceremony || st.Chain[2].SHA256 != st.End {
		t.Errorf("the last of Chain is %+v, want %s ending the history at %s", st.Chain[2], m.Ceremony, st.End)
	}
	if st.NewestListed == nil || st.NewestListed.Name != m.Set || st.Newest.Name != m.Set || len(st.Unlisted) != 0 {
		t.Errorf("NewestListed %+v, Newest %+v, Unlisted %+v", st.NewestListed, st.Newest, st.Unlisted)
	}
	want := fmt.Sprintf("history: 3 ceremony records, end %s", st.End[:8])
	if in.Report.EndLine() != want {
		t.Errorf("EndLine = %q, want %q", in.Report.EndLine(), want)
	}
	// Changing what was given changes nothing in the next call.
	chain := slices.Clone(st.Chain)
	st.Chain[0].Folder = "mutated"
	st.NewestListed.ListJSON[0] = 'X'
	_, again := inspectDir(t, m.Dir)
	if !slices.Equal(again.State.Chain, chain) || again.State.NewestListed.ListJSON[0] != '{' {
		t.Errorf("a second call after a change: Chain %+v, ListJSON %.10s", again.State.Chain, again.State.NewestListed.ListJSON)
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func digestFile(t testing.TB, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return sha256Hex(data)
}

// The bundle cut at each write of a whole run: Inspect gives the report of Check, the report holds no
// fault that fails (only the notices), there is a State, the attempt that is open is named once, a set
// that no record lists is in Unlisted when it stands, and the number of records in Chain is the number
// of record files.
func TestEveryCutHasAStateWithTheAdditions(t *testing.T) {
	o := ceremonytest.Options{}
	total := ceremonytest.Writes(t, o)
	type seen struct {
		ok bool
		m  *ceremonytest.Made
		in *history.Inspection
		fs map[string]bool
	}
	got := make([]seen, total+1)
	t.Run("runs", func(t *testing.T) {
		for n := 1; n <= total; n++ {
			t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
				t.Parallel()
				m := ceremonytest.AfterWrites(t, o, n)
				_, in := inspectDir(t, m.Dir)
				names := map[string]bool{}
				_ = filepath.WalkDir(m.Dir, func(p string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() {
						rel, _ := filepath.Rel(m.Dir, p)
						names[filepath.ToSlash(rel)] = true
					}
					return nil
				})
				got[n] = seen{true, m, in, names}
			})
		}
	})
	if t.Failed() {
		return
	}
	for n := 1; n <= total; n++ {
		s := got[n]
		in, names := s.in, s.fs
		if !in.Report.Clean() {
			t.Errorf("n=%d: the report fails: %v", n, in.Report.Failing())
			continue
		}
		hasAttempt := names["history/"+s.m.Ceremony+"/attempt.json"]
		hasRecord := names["history/"+s.m.Ceremony+"/record.json"]
		var wantOpen []string
		if hasAttempt && !hasRecord {
			wantOpen = []string{s.m.Ceremony}
		}
		if !slices.Equal(in.Unfinished, wantOpen) && (len(in.Unfinished) != 0 || len(wantOpen) != 0) {
			t.Errorf("n=%d: Unfinished = %v, the files say %v", n, in.Unfinished, wantOpen)
		}
		if in.State == nil {
			t.Errorf("n=%d: no State (%v) for a clean report of a stopped ceremony", n, in.OrderErr)
			continue
		}
		st := in.State
		if !slices.Equal(st.Unfinished, in.Unfinished) && (len(st.Unfinished) != 0 || len(in.Unfinished) != 0) {
			t.Errorf("n=%d: State.Unfinished = %v, Unfinished = %v", n, st.Unfinished, in.Unfinished)
		}
		if hasRecord != (len(st.Chain) == 1) {
			t.Errorf("n=%d: record %v, Chain %+v", n, hasRecord, st.Chain)
		}
		setStands := false
		for p := range names {
			if strings.HasPrefix(p, "trust/") && strings.HasSuffix(p, "/root-list.json") && !strings.Contains(p, ".rt-") {
				setStands = true
			}
		}
		if setStands != (st.Newest != nil) {
			t.Errorf("n=%d: a set stands %v, Newest %+v", n, setStands, st.Newest)
		}
		switch {
		case setStands && !hasRecord:
			if len(st.Unlisted) != 1 || st.NewestListed != nil || len(in.Unfinished) != 1 {
				t.Errorf("n=%d: Unlisted %+v NewestListed %+v Unfinished %v for a set with no record", n, st.Unlisted, st.NewestListed, in.Unfinished)
			}
		case setStands && hasRecord:
			if len(st.Unlisted) != 0 || st.NewestListed == nil || st.NewestListed.Name != st.Newest.Name {
				t.Errorf("n=%d: Unlisted %+v NewestListed %+v for a set with a record", n, st.Unlisted, st.NewestListed)
			}
		default:
			if len(st.Unlisted) != 0 || st.NewestListed != nil {
				t.Errorf("n=%d: Unlisted %+v NewestListed %+v with no set", n, st.Unlisted, st.NewestListed)
			}
		}
	}
}
