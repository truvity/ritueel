package ceremony

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// The small functions of a run that the whole run reaches only by one road: the typed line, the
// judgement of a saved plan against the state of the bundle, and the name of the trust set.

func TestReadTypedLineTakesOneLineOfAtMostSixtyFourBytesWithItsLineFeed(t *testing.T) {
	cases := []struct {
		name, in, want string
		ok             bool
	}{
		{"a line", "12345678\n", "12345678", true},
		{"a line with CRLF", "12345678\r\n", "12345678", true},
		{"an empty line", "\n", "", true},
		{"a carriage return only", "\r\n", "", true},
		{"two lines", "12345678\nabcdefgh\n", "12345678", true},
		{"no line feed", "12345678", "", false},
		{"nothing", "", "", false},
		{"a line of exactly 64 bytes", strings.Repeat("a", 63) + "\n", strings.Repeat("a", 63), true},
		{"a line of 65 bytes", strings.Repeat("a", 64) + "\n", "", false},
		{"a line feed past 64 bytes", strings.Repeat("a", 100) + "\n", "", false},
		{"two carriage returns keep one", "ab\r\r\n", "ab\r", true},
		{"a carriage return alone ends nothing", "ab\r", "", false},
		{"a zero byte stays in the line", "a\x00b\n", "a\x00b", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := readTypedLine(strings.NewReader(c.in))
			if (err == nil) != c.ok || got != c.want {
				t.Errorf("readTypedLine(%q) = %q, %v; want %q, ok %v", c.in, got, err, c.want, c.ok)
			}
		})
	}
	t.Run("a reader that fails", func(t *testing.T) {
		if got, err := readTypedLine(iotest.ErrReader(errors.New("test: gone"))); err == nil || got != "" {
			t.Errorf("= %q, %v", got, err)
		}
	})
	t.Run("a reader that gives one byte at a time", func(t *testing.T) {
		got, err := readTypedLine(iotest.OneByteReader(strings.NewReader("12345678\n")))
		if err != nil || got != "12345678" {
			t.Errorf("= %q, %v", got, err)
		}
	})
	t.Run("a reader that fails after the line", func(t *testing.T) {
		r := io.MultiReader(strings.NewReader("12345678\n"), iotest.ErrReader(errors.New("test: gone")))
		if got, err := readTypedLine(r); err != nil || got != "12345678" {
			t.Errorf("= %q, %v", got, err)
		}
	})
	t.Run("no more than 64 bytes are taken", func(t *testing.T) {
		n := 0
		_, err := readTypedLine(readerFunc(func(p []byte) (int, error) {
			for i := range p {
				p[i] = 'a'
			}
			n += len(p)
			return len(p), nil
		}))
		if err == nil || n > maxTypedLine {
			t.Errorf("err %v, %d bytes taken", err, n)
		}
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestTypedMatchesIsTheFirstEightHexDigitsOfTheDigestInEitherCase(t *testing.T) {
	digest := "0123abcdEF" + strings.Repeat("0", 54)
	digest = strings.ToLower(digest)
	cases := []struct {
		line string
		want bool
	}{
		{"0123abcd", true},
		{"0123ABCD", true},
		{"0123AbCd", true},
		{"0123abc", false},
		{"0123abcde", false},
		{"", false},
		{"0123abce", false},
		{"0123abc ", false},
		{" 0123abc", false},
		{"0123abcg", false},
		{"0123abc\x00", false},
		{"0123abc٠", false},
		{"０123abc", false},
		{"0123abcd\r", false},
		{"0123abcd\n", false},
	}
	for _, c := range cases {
		if got := typedMatches(c.line, digest); got != c.want {
			t.Errorf("typedMatches(%q) = %v, want %v", c.line, got, c.want)
		}
	}
	if typedMatches("0123abcd", "0123abc") || typedMatches("0123abcd", "") {
		t.Error("a digest shorter than eight characters is confirmed by a line")
	}
	// A line that is not hexadecimal is not a match even for a digest that is not hexadecimal.
	if typedMatches("zzzzzzzz", "zzzzzzzz"+strings.Repeat("0", 56)) {
		t.Error("a line of letters that are not digits is confirmed")
	}
}

func TestConfirmByIsTheWordOfTheRecord(t *testing.T) {
	if (Confirm{}).by() != ConfirmedTyped || ConfirmedTyped != "typed" {
		t.Error("the zero value is the typed confirmation")
	}
	if (Confirm{Flag: true}).by() != ConfirmedFlag || ConfirmedFlag != "flag" {
		t.Error("a flag is the word flag")
	}
	// A digest without the flag is not a flag confirmation.
	if (Confirm{Digest: strings.Repeat("a", 64)}).by() != ConfirmedTyped {
		t.Error("a digest with no Flag is not a script")
	}
}

func TestCheckStaleIsStaleAsSoonAsTheBundleHoldsATrustSetOrARecord(t *testing.T) {
	cases := map[string]struct {
		st    *history.State
		stale bool
	}{
		"an empty history":   {&history.State{}, false},
		"a trust set":        {&history.State{Newest: &history.SetInfo{Name: "1-aaaaaaaa", Number: 1}}, true},
		"a list":             {&history.State{Lists: []history.RootList{{}}}, true},
		"a record":           {&history.State{Records: 1}, true},
		"an end":             {&history.State{End: strings.Repeat("a", 64)}, true},
		"an open attempt":    {&history.State{Unfinished: []string{"x"}}, false},
		"a record and a set": {&history.State{Records: 2, Newest: &history.SetInfo{Number: 2}}, true},
	}
	for name, c := range cases {
		err := checkStale(c.st)
		if c.stale {
			var ref *RefusedError
			if !errors.As(err, &ref) || len(ref.Reasons) != 1 || ref.Reasons[0] != ReasonPlanStale || ReasonPlanStale != "plan-stale" {
				t.Errorf("%s: %v, want a refusal with the reason plan-stale", name, err)
			}
		} else if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkStale(nil); err == nil {
		t.Error("no state is not a pass")
	}
}

func TestCheckVersionComparesTheWholeDescriptionOfTheProgram(t *testing.T) {
	self := buildinfo.Program{Version: "v1", OSArch: "linux/amd64", SHA256: strings.Repeat("a", 64)}
	env := Env{Self: func() (buildinfo.Program, error) { return self, nil }}
	plan := &PlanOut{Program: self}
	if err := checkVersion(env, plan); err != nil {
		t.Fatalf("the same program: %v", err)
	}
	for name, p := range map[string]buildinfo.Program{
		"version": {Version: "v2", OSArch: self.OSArch, SHA256: self.SHA256},
		"system":  {Version: self.Version, OSArch: "linux/arm64", SHA256: self.SHA256},
		"digest":  {Version: self.Version, OSArch: self.OSArch, SHA256: strings.Repeat("b", 64)},
		"empty":   {},
	} {
		err := checkVersion(env, &PlanOut{Program: p})
		var ref *RefusedError
		if !errors.As(err, &ref) || len(ref.Reasons) != 1 || ref.Reasons[0] != ReasonPlanVersion || ReasonPlanVersion != "plan-version" {
			t.Errorf("another %s: %v", name, err)
		}
	}
	if err := checkVersion(Env{Self: func() (buildinfo.Program, error) { return buildinfo.Program{}, errors.New("no") }}, plan); err == nil {
		t.Error("a program that cannot be described passes")
	} else if errors.As(err, new(*RefusedError)) {
		t.Errorf("a program that cannot be described is a refusal, want a failure: %v", err)
	}
}

func TestCheckClockRefusesOnlyATimeBeforeTheCeremonyTime(t *testing.T) {
	at := time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)
	plan := &PlanOut{Time: at}
	for name, c := range map[string]struct {
		now    time.Time
		behind bool
	}{
		"one second before": {at.Add(-time.Second), true},
		"a year before":     {at.AddDate(-1, 0, 0), true},
		"the same second":   {at, false},
		"a part of a second before the same second": {at.Add(500 * time.Millisecond), false},
		"one second after":                          {at.Add(time.Second), false},
		"a year after":                              {at.AddDate(1, 0, 0), false},
	} {
		err := checkClock(Env{Now: func() time.Time { return c.now }}, plan)
		var ref *RefusedError
		if c.behind {
			if !errors.As(err, &ref) || len(ref.Reasons) != 1 || ref.Reasons[0] != ReasonClockBehind || ReasonClockBehind != "clock-behind" {
				t.Errorf("%s: %v", name, err)
			}
		} else if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkClock(Env{}, plan); err == nil {
		t.Error("no clock is not a pass")
	}
}

func TestRefuseUsedPlanLooksAtTheAttemptAndTheRecordOfTheFolderOfThePlan(t *testing.T) {
	const name = "20261120T100000Z-apply"
	mk := func(t *testing.T, entries ...string) fsx.FS {
		t.Helper()
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "history", name), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.WriteFile(filepath.Join(dir, "history", name, e), []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		fsys, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = fsys.Close() })
		return fsys
	}
	for _, c := range []struct {
		name    string
		entries []string
		used    bool
	}{
		{"an attempt", []string{files.AttemptFile}, true},
		{"a record", []string{files.RecordFile}, true},
		{"an attempt and a record", []string{files.AttemptFile, files.RecordFile}, true},
		{"the plan only", []string{files.PlanFile}, false},
		{"nothing", nil, false},
		{"the journals but no attempt", []string{files.BirthsFile, files.SignaturesFile}, false},
	} {
		err := refuseUsedPlan(mk(t, c.entries...), name)
		var ref *RefusedError
		if c.used {
			if !errors.As(err, &ref) || len(ref.Reasons) != 1 || ref.Reasons[0] != ReasonPlanUsed || ReasonPlanUsed != "plan-used" {
				t.Errorf("%s: %v, want plan-used", c.name, err)
			}
		} else if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// A folder that is not there is a failure that says so, and not a pass.
	dir := t.TempDir()
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fsys.Close() }()
	if err := refuseUsedPlan(fsys, name); err == nil || errors.As(err, new(*RefusedError)) {
		t.Errorf("a folder that does not exist: %v", err)
	}
}

func TestRefusedMakesOneReasonAndSaysNothingWasWritten(t *testing.T) {
	err := refused("plan-stale", "the plan is %s", "old")
	var ref *RefusedError
	if !errors.As(err, &ref) || len(ref.Reasons) != 1 || ref.Reasons[0] != "plan-stale" || ref.Msg != "the plan is old; nothing was written" {
		t.Errorf("refused = %#v", err)
	}
}

func TestTrustSetFolderIsEmptyForAMadeThatHasNoSet(t *testing.T) {
	if got := trustSetFolder(&Made{}); got != "" {
		t.Errorf("trustSetFolder(&Made{}) = %q", got)
	}
	if got := trustSetFolder(nil); got != "" {
		t.Errorf("trustSetFolder(nil) = %q", got)
	}
}
