package cli

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/history"
)

// historyOutcome is the one place that decides what a report means. These tests give it reports
// made in memory, as if the library had a fault or a bundle were hostile, and ask what the command
// would do. A report that is not whole fails closed: the exit code 1 and nothing written, never
// the end line.

const goodEnd = "5056dc22aa5056dc22aa5056dc22aa5056dc22aa5056dc22aa5056dc22aa5056"

func finding(code history.Code, path, detail string) history.Finding {
	return history.Finding{Code: code, Path: path, Detail: detail}
}

// outcome runs historyOutcome with a buffer for standard error.
func outcome(rep *history.Report) (res *Result, stderr string, err error) {
	var b strings.Builder
	res, err = historyOutcome(rep, &b)
	return res, b.String(), err
}

func TestNilReportIsExitOneAndWritesNothing(t *testing.T) {
	res, stderr, err := outcome(nil)
	if res != nil || err == nil || stderr != "" {
		t.Fatalf("%v, %v, %q; want an error, no result and nothing written", res, err, stderr)
	}
	if code, _ := ExitFor(err); code != ExitFailure {
		t.Errorf("exit %d, want 1", code)
	}
	// And with no writer at all.
	res, err = historyOutcome(nil, nil)
	if res != nil || err == nil {
		t.Errorf("a nil report and a nil writer: %v, %v", res, err)
	}
	if got := findingLines(nil); got != "" {
		t.Errorf("findingLines(nil) = %q", got)
	}
}

func TestNilWriterIsTheSameAsAWriterThatKeepsNothing(t *testing.T) {
	reports := map[string]*history.Report{
		"clean": {Records: 1, Ends: []string{goodEnd}},
		"notice": {Records: 1, Ends: []string{goodEnd}, Findings: []history.Finding{
			finding(history.UnexpectedFile, "history/x", "d"),
		}},
		"failing": {Records: 1, Ends: []string{goodEnd}, Findings: []history.Finding{
			finding(history.FileDigest, "p", "d"),
		}, Omitted: 3},
		"inconsistent": {Records: 4},
	}
	for name, rep := range reports {
		wres, _, werr := outcome(rep)
		nres, nerr := historyOutcome(rep, nil)
		if (werr == nil) != (nerr == nil) {
			t.Errorf("%s: errors differ: %v and %v", name, werr, nerr)
		}
		if werr != nil {
			wc, _ := ExitFor(werr)
			nc, _ := ExitFor(nerr)
			if wc != nc || werr.Error() != nerr.Error() {
				t.Errorf("%s: %v (%d) and %v (%d)", name, werr, wc, nerr, nc)
			}
		}
		if (wres == nil) != (nres == nil) || (wres != nil && wres.Text != nres.Text) {
			t.Errorf("%s: results differ: %v and %v", name, wres, nres)
		}
	}
}

func TestCleanReportIsTheEndLineAndExitZero(t *testing.T) {
	rep := &history.Report{Records: 3, Ends: []string{goodEnd}}
	res, stderr, err := outcome(rep)
	if err != nil || res == nil {
		t.Fatalf("%v, %v", res, err)
	}
	if res.ExitCode != ExitOK || res.Text != "history: 3 ceremony records, end 5056dc22\n" || stderr != "" {
		t.Errorf("exit %d, text %q, stderr %q", res.ExitCode, res.Text, stderr)
	}
	if len(res.Reasons) != 0 || len(res.Warnings) != 0 || res.Error != "" {
		t.Errorf("a clean result holds reasons %v, warnings %v, error %q", res.Reasons, res.Warnings, res.Error)
	}
	// One record is "records" too, and zero has no end.
	if res, _, _ := outcome(&history.Report{Records: 1, Ends: []string{goodEnd}}); res.Text != "history: 1 ceremony records, end 5056dc22\n" {
		t.Errorf("one record: %q", res.Text)
	}
	if res, _, _ := outcome(&history.Report{}); res == nil || res.Text != "history: 0 ceremony records\n" || res.ExitCode != ExitOK {
		t.Errorf("no record: %+v", res)
	}
}

// The number and the end come from the report and from nothing else: a report with 12 records, and
// an end of another digest, prints those.
func TestEndLineComesFromTheReport(t *testing.T) {
	res, _, _ := outcome(&history.Report{Records: 12, Ends: []string{"0123456789abcdef" + strings.Repeat("0", 48)}})
	if res == nil || res.Text != "history: 12 ceremony records, end 01234567\n" {
		t.Errorf("%+v", res)
	}
}

func TestReportThatDisagreesWithItselfIsNeverClean(t *testing.T) {
	cases := map[string]*history.Report{
		"records and no end":                 {Records: 3},
		"records and an empty end list":      {Records: 3, Ends: []string{}},
		"records and two ends":               {Records: 3, Ends: []string{goodEnd, strings.Repeat("a", 64)}},
		"records and three ends":             {Records: 3, Ends: []string{goodEnd, goodEnd, goodEnd}},
		"no record and an end":               {Records: 0, Ends: []string{goodEnd}},
		"a negative count":                   {Records: -1, Ends: []string{goodEnd}},
		"a negative count and no end":        {Records: -1},
		"an end of 3 characters":             {Records: 1, Ends: []string{"abc"}},
		"an end of 7 characters":             {Records: 1, Ends: []string{"5056dc2"}},
		"an empty end":                       {Records: 1, Ends: []string{""}},
		"an end in upper case":               {Records: 1, Ends: []string{strings.ToUpper(goodEnd)}},
		"an end with a letter beyond f":      {Records: 1, Ends: []string{"5056dc2g" + goodEnd[8:]}},
		"an end that starts with a space":    {Records: 1, Ends: []string{" 056dc22" + goodEnd[8:]}},
		"an end with a line break":           {Records: 1, Ends: []string{"5056dc2\n" + goodEnd[8:]}},
		"an end with an escape":              {Records: 1, Ends: []string{"5056dc2\x1b" + goodEnd[8:]}},
		"an end with a character of 2 bytes": {Records: 1, Ends: []string{"5056dc2\u00e9" + goodEnd[8:]}},
		"an end that is a sign":              {Records: 1, Ends: []string{"-056dc22" + goodEnd[8:]}},
		"two ends and no record":             {Records: 0, Ends: []string{goodEnd, goodEnd}},
		"a very large count and no end":      {Records: 1 << 40},
	}
	for name, rep := range cases {
		t.Run(name, func(t *testing.T) {
			res, stderr, err := outcome(rep)
			if res != nil || err == nil || stderr != "" {
				t.Fatalf("%+v, %v, %q; want an error, no result and nothing written", res, err, stderr)
			}
			if code, outcome := ExitFor(err); code != ExitFailure || outcome != OutcomeFailed {
				t.Errorf("exit %d (%s), want 1 (failed)", code, outcome)
			}
			if !strings.Contains(err.Error(), "the history report is not consistent") {
				t.Errorf("the text is %q", err.Error())
			}
			if strings.Contains(err.Error(), "history:") {
				t.Errorf("the error holds an end line: %q", err.Error())
			}
		})
	}
	// An end of exactly eight good characters is enough for the line: the library gives 64, and
	// the line needs eight.
	if res, _, err := outcome(&history.Report{Records: 2, Ends: []string{"0123abcd"}}); err != nil || res.Text != "history: 2 ceremony records, end 0123abcd\n" {
		t.Errorf("an end of eight good characters: %+v, %v", res, err)
	}
	// Every character of a digest is a digit or a lower-case letter a to f, each in the first
	// eight places.
	for i := 0; i < 8; i++ {
		for _, bad := range []byte{'/', ':', '@', 'G', 'F', '`', 'g', 0, '\n'} {
			end := []byte(goodEnd)
			end[i] = bad
			if res, _, err := outcome(&history.Report{Records: 1, Ends: []string{string(end)}}); res != nil || err == nil {
				t.Errorf("the byte %q at place %d was accepted", bad, i)
			}
		}
		for _, good := range []byte{'0', '9', 'a', 'f'} {
			end := []byte(goodEnd)
			end[i] = good
			if res, _, err := outcome(&history.Report{Records: 1, Ends: []string{string(end)}}); res == nil || err != nil {
				t.Errorf("the byte %q at place %d was refused: %v", good, i, err)
			}
		}
	}
}

// The consistency test is for a report that says the history is whole. A report that holds a
// failing finding is refused whatever the numbers say.
func TestFailingFindingIsExitThreeWhateverTheNumbersSay(t *testing.T) {
	fail := []history.Finding{finding(history.FileDigest, "trust/1/keys.txt", "d")}
	for name, rep := range map[string]*history.Report{
		"a good count":      {Records: 3, Ends: []string{goodEnd}, Findings: fail},
		"no end":            {Records: 3, Findings: fail},
		"no record":         {Findings: fail},
		"a negative count":  {Records: -5, Findings: fail},
		"two ends":          {Records: 3, Ends: []string{goodEnd, goodEnd}, Findings: fail},
		"a short end":       {Records: 3, Ends: []string{"a"}, Findings: fail},
		"left out findings": {Records: 3, Ends: []string{goodEnd}, Findings: fail, Omitted: 7},
	} {
		t.Run(name, func(t *testing.T) {
			res, stderr, err := outcome(rep)
			if res != nil || err == nil {
				t.Fatalf("%+v, %v; want a refusal", res, err)
			}
			code, out := ExitFor(err)
			if code != ExitRefused || out != OutcomeRefused {
				t.Errorf("exit %d (%s), want 3 (refused)", code, out)
			}
			if got := reasonsOf(err); !slices.Equal(got, []string{"file-digest"}) {
				t.Errorf("reasons %v", got)
			}
			if !strings.HasPrefix(stderr, "file-digest trust/1/keys.txt: d\n") {
				t.Errorf("standard error = %q", stderr)
			}
			if strings.Contains(stderr, "history:") || strings.Contains(err.Error(), "history:") {
				t.Errorf("an end line in a refusal: %q, %q", stderr, err.Error())
			}
			if err.Error() != "refused: file-digest" {
				t.Errorf("the text of the refusal is %q: the program writes the codes when the message is empty", err.Error())
			}
		})
	}
}

func TestRefusalListsEachFailingCodeOnceAndNoNotice(t *testing.T) {
	rep := &history.Report{Records: 2, Ends: []string{goodEnd}, Findings: []history.Finding{
		finding(history.ChainBroken, "a", "1"),
		finding(history.ChainBroken, "b", "2"),
		finding(history.FileDigest, "c", "3"),
		finding(history.UnfinishedCeremony, "d", "4"),
		finding(history.UnexpectedFile, "e", "5"),
		finding(history.UnexpectedFile, "f", "6"),
		finding(history.UnexpectedName, "g", "7"),
	}}
	res, stderr, err := outcome(rep)
	if res != nil || err == nil {
		t.Fatal("not a refusal")
	}
	if got := reasonsOf(err); !slices.Equal(got, []string{"chain-broken", "file-digest", "unexpected-name"}) {
		t.Errorf("reasons %v", got)
	}
	if got := warningsOf(err); !slices.Equal(got, []string{"unfinished-ceremony", "unexpected-file"}) {
		t.Errorf("warnings %v", got)
	}
	want := "chain-broken a: 1\nchain-broken b: 2\nfile-digest c: 3\nunfinished-ceremony d: 4\nunexpected-file e: 5\nunexpected-file f: 6\nunexpected-name g: 7\n"
	if stderr != want {
		t.Errorf("standard error:\n got %q\nwant %q", stderr, want)
	}
}

func TestNoticesOnlyAreExitZeroWithTheEndLineAndTheWarnings(t *testing.T) {
	rep := &history.Report{Records: 2, Ends: []string{goodEnd}, Findings: []history.Finding{
		finding(history.UnfinishedCeremony, "trust/3", "open"),
		finding(history.UnexpectedFile, "history/a", "x"),
		finding(history.UnexpectedFile, "history/b", "y"),
	}}
	res, stderr, err := outcome(rep)
	if err != nil || res == nil {
		t.Fatalf("%v, %v", res, err)
	}
	if res.ExitCode != ExitOK || res.Text != "history: 2 ceremony records, end 5056dc22\n" {
		t.Errorf("exit %d, text %q", res.ExitCode, res.Text)
	}
	if !slices.Equal(res.Warnings, []string{"unfinished-ceremony", "unexpected-file"}) || len(res.Reasons) != 0 {
		t.Errorf("warnings %v, reasons %v", res.Warnings, res.Reasons)
	}
	if want := "unfinished-ceremony trust/3: open\nunexpected-file history/a: x\nunexpected-file history/b: y\n"; stderr != want {
		t.Errorf("standard error = %q, want %q", stderr, want)
	}
}

func TestOmittedLineHasOneFormForEveryNumber(t *testing.T) {
	for _, n := range []int{1, 2, 5, 17, 1000, 1 << 20} {
		rep := &history.Report{Records: 1, Ends: []string{goodEnd}, Findings: []history.Finding{
			finding(history.UnexpectedFile, "x", "y"),
		}, Omitted: n}
		res, stderr, err := outcome(rep)
		if err != nil || res == nil {
			t.Fatalf("%d: %v", n, err)
		}
		want := "unexpected-file x: y\n" + itoa(n) + " more findings not shown\n"
		if stderr != want {
			t.Errorf("Omitted %d: standard error %q, want %q", n, stderr, want)
		}
	}
	for _, n := range []int{0, -1, -1000} {
		_, stderr, _ := outcome(&history.Report{Records: 1, Ends: []string{goodEnd}, Omitted: n})
		if stderr != "" {
			t.Errorf("Omitted %d: standard error %q, want nothing", n, stderr)
		}
	}
	// Findings of a failing code are followed by the line too, then the refusal is the program's.
	res, stderr, err := outcome(&history.Report{Findings: []history.Finding{finding(history.Fork, "p", "d")}, Omitted: 5})
	if res != nil || err == nil || stderr != "fork p: d\n5 more findings not shown\n" {
		t.Errorf("%v, %v, %q", res, err, stderr)
	}
	// Findings left out and none shown, and nothing else: the line is written, the exit is 0.
	res, stderr, err = outcome(&history.Report{Omitted: 4})
	if err != nil || res == nil || res.ExitCode != ExitOK || stderr != "4 more findings not shown\n" {
		t.Errorf("%+v, %v, %q", res, err, stderr)
	}
}

func TestLineOfAFindingHasTheFormCodePathColonDetail(t *testing.T) {
	cases := []struct {
		f    history.Finding
		want string
	}{
		{finding(history.FileDigest, "trust/3-example/keys.txt", "detail"), "file-digest trust/3-example/keys.txt: detail"},
		{finding(history.FileDigest, "", ""), "file-digest"},
		{finding(history.FileDigest, "", "detail"), "file-digest: detail"},
		{finding(history.FileDigest, "path", ""), "file-digest path"},
		{finding(history.FileDigest, "a b", "c d"), "file-digest a b: c d"},
	}
	for _, tc := range cases {
		rep := &history.Report{Findings: []history.Finding{tc.f}}
		_, stderr, _ := outcome(rep)
		if stderr != tc.want+"\n" {
			t.Errorf("%+v: %q, want %q", tc.f, stderr, tc.want+"\n")
		}
	}
}

// A finding that holds a raw byte in its path, its detail or its code, as if the library had a
// fault, writes no raw byte and no line break inside a line.
func TestRawBytesNeverReachStandardError(t *testing.T) {
	raw := "a\x1b[31m\nb\r\tc\x00d\x7fe\xff\u202ef\u0430"
	cases := []history.Finding{
		finding(history.FileDigest, raw, "detail"),
		finding(history.FileDigest, "path", raw),
		finding(history.Code("x"+raw), "path", "detail"),
		finding(history.Code(raw), raw, raw),
		finding(history.Code(""), "", ""),
		finding(history.FileDigest, strings.Repeat("a\x1b", 5000), strings.Repeat("\n", 5000)),
	}
	for _, f := range cases {
		for _, rep := range []*history.Report{
			{Findings: []history.Finding{f}},
			{Records: 1, Ends: []string{goodEnd}, Findings: []history.Finding{{Code: history.UnexpectedFile, Path: f.Path, Detail: f.Detail}}},
		} {
			_, stderr, _ := outcome(rep)
			if !onlyPrintable(stderr) {
				t.Errorf("a raw byte on standard error: %q", stderr)
			}
			if lines := chLines(stderr); len(lines) != 1 {
				t.Errorf("one finding made %d lines: %q", len(lines), lines)
			}
			if strings.Contains(stderr, "\n\n") {
				t.Errorf("an empty line: %q", stderr)
			}
		}
	}
	if got := findingLines(&history.Report{Findings: []history.Finding{finding(history.Code("a\nb"), "", "")}}); got != "a\\u000ab\n" {
		t.Errorf("the code a\\nb is written %q", got)
	}
}

// A code that the library does not know fails, as Code.Fails says, and its name reaches reasons
// with the program's escape.
func TestUnknownCodeFailsAndIsEscapedInReasons(t *testing.T) {
	for _, name := range []string{"new-code", "x\x1b[0my", "\u0430bc", "a\nb", "", strings.Repeat("z", 400)} {
		rep := &history.Report{Records: 1, Ends: []string{goodEnd}, Findings: []history.Finding{finding(history.Code(name), "p", "d")}}
		res, stderr, err := outcome(rep)
		if res != nil || err == nil {
			t.Fatalf("%q: not a refusal: %v", name, res)
		}
		if code, _ := ExitFor(err); code != ExitRefused {
			t.Errorf("%q: exit %d, want 3", name, code)
		}
		if got := reasonsOf(err); !slices.Equal(got, []string{name}) {
			t.Errorf("%q: reasons %q", name, got)
		}
		if !onlyPrintable(stderr) {
			t.Errorf("%q: a raw byte in %q", name, stderr)
		}
		// The whole way through the program.
		r := runSynthetic(t, rep, "--output", "json", "check", "history")
		if r.code != ExitRefused || r.stdout == "" {
			t.Fatalf("%q: exit %d, stdout %q", name, r.code, r.stdout)
		}
		if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Errorf("%q: a raw byte: stdout %q, stderr %q", name, r.stdout, r.stderr)
		}
		obj := jsonObject(t, r)
		reasons, ok := stringList(obj["reasons"])
		if !ok || len(reasons) != 1 {
			t.Fatalf("%q: reasons %v", name, obj["reasons"])
		}
		for _, c := range reasons[0] {
			if c < 0x20 || c >= 0x7f {
				t.Errorf("%q: a raw character in reasons: %q", name, reasons[0])
			}
		}
		if _, has := obj["error"]; has {
			t.Errorf("%q: a refusal with an error member: %v", name, obj)
		}
	}
}

// runSynthetic runs the program with a table in which "check history" gives the report to
// historyOutcome, as the command does, so that the whole path from a report to the output is run.
func runSynthetic(t *testing.T, rep *history.Report, args ...string) result {
	t.Helper()
	withSpecs(t, spec{
		name: "check",
		subs: []spec{{name: "history", run: func(_ context.Context, c *Call) (*Result, error) {
			return historyOutcome(rep, c.Env.Stderr)
		}}},
	})
	return run(t, args...)
}

func TestSyntheticReportsThroughTheProgram(t *testing.T) {
	t.Run("clean", func(t *testing.T) {
		r := runSynthetic(t, &history.Report{Records: 3, Ends: []string{goodEnd}}, "check", "history")
		if r.code != ExitOK || r.stdout != "history: 3 ceremony records, end 5056dc22\n" || r.stderr != "" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("clean in JSON", func(t *testing.T) {
		r := runSynthetic(t, &history.Report{Records: 3, Ends: []string{goodEnd}}, "check", "history", "--output", "json")
		wantObject(t, jsonObject(t, r), map[string]any{"output": 1, "command": "check", "exit_code": 0, "outcome": "done"})
	})
	t.Run("a notice", func(t *testing.T) {
		rep := &history.Report{Records: 3, Ends: []string{goodEnd}, Findings: []history.Finding{finding(history.UnfinishedCeremony, "trust/4", "open")}}
		r := runSynthetic(t, rep, "check", "history")
		if r.code != ExitOK || r.stdout != "history: 3 ceremony records, end 5056dc22\n" {
			t.Errorf("%+v", r)
		}
		if r.stderr != "unfinished-ceremony trust/4: open\nritueel: warning: unfinished-ceremony\n" {
			t.Errorf("standard error %q", r.stderr)
		}
	})
	t.Run("a notice and a refusal", func(t *testing.T) {
		rep := &history.Report{Findings: []history.Finding{
			finding(history.Fork, "a", "b"), finding(history.UnfinishedCeremony, "c", "d"), finding(history.UnexpectedName, "e", "f"),
		}}
		r := runSynthetic(t, rep, "check", "history")
		want := "fork a: b\nunfinished-ceremony c: d\nunexpected-name e: f\nritueel: warning: unfinished-ceremony\nritueel: refused: fork, unexpected-name\n"
		if r.code != ExitRefused || r.stdout != "" || r.stderr != want {
			t.Errorf("%+v, want standard error %q", r, want)
		}
		j := runSynthetic(t, rep, "check", "history", "--output", "json")
		wantObject(t, jsonObject(t, j), map[string]any{
			"output": 1, "command": "check", "exit_code": 3, "outcome": "refused",
			"reasons": []string{"fork", "unexpected-name"}, "warnings": []string{"unfinished-ceremony"},
		})
	})
	t.Run("a report that disagrees", func(t *testing.T) {
		r := runSynthetic(t, &history.Report{Records: 3}, "check", "history")
		if r.code != ExitFailure || r.stdout != "" || r.stderr != "ritueel: the history report is not consistent\n" {
			t.Errorf("%+v", r)
		}
		j := runSynthetic(t, &history.Report{Records: 3}, "check", "history", "--output", "json")
		obj := jsonObject(t, j)
		wantObject(t, obj, map[string]any{
			"output": 1, "command": "check", "exit_code": 1, "outcome": "failed", "error": "the history report is not consistent",
		})
	})
	t.Run("no report", func(t *testing.T) {
		r := runSynthetic(t, nil, "check", "history")
		if r.code != ExitFailure || r.stdout != "" || strings.Count(r.stderr, "\n") != 1 {
			t.Errorf("%+v", r)
		}
	})
}

// The errors that the command returns are errors of one code each: it never joins two coded
// errors, which the program would refuse with a panic.
func TestRefusalIsOneCodedError(t *testing.T) {
	rep := &history.Report{Findings: []history.Finding{finding(history.Fork, "a", "b"), finding(history.UnexpectedFile, "c", "d")}}
	_, _, err := outcome(rep)
	var refusal Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("%T is not a Refusal", err)
	}
	if refusal.Msg != "" || !slices.Equal(refusal.Reasons, []string{"fork"}) {
		t.Errorf("%+v: the message is left empty so that the program writes the codes", refusal)
	}
	if coded := codedIn(err); len(coded) != 1 {
		t.Errorf("the error holds %d coded errors", len(coded))
	}
}

// findingLines writes the lines in the order of the report, and the line of what was left out last.
func TestFindingLinesKeepTheOrderOfTheReport(t *testing.T) {
	rep := &history.Report{Findings: []history.Finding{
		finding(history.UnexpectedFile, "z", "1"),
		finding(history.ChainBroken, "a", "2"),
		finding(history.UnexpectedFile, "m", "3"),
	}, Omitted: 2}
	want := "unexpected-file z: 1\nchain-broken a: 2\nunexpected-file m: 3\n2 more findings not shown\n"
	if got := findingLines(rep); got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if got := findingLines(&history.Report{}); got != "" {
		t.Errorf("a report with no finding: %q", got)
	}
	if got := codeStrings(nil); got != nil {
		t.Errorf("codeStrings(nil) = %v", got)
	}
	if got := codeStrings([]history.Code{"a", "b"}); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("codeStrings = %v", got)
	}
}

// A write that fails is not an error of the check: the result of the run does not depend on it.
func TestFailingWriterDoesNotChangeTheResult(t *testing.T) {
	w := &failingWriter{err: errors.New("disk full")}
	rep := &history.Report{Records: 1, Ends: []string{goodEnd}, Findings: []history.Finding{finding(history.UnexpectedFile, "x", "y")}}
	res, err := historyOutcome(rep, w)
	if err != nil || res == nil || res.ExitCode != ExitOK {
		t.Errorf("%v, %v", res, err)
	}
	rep.Findings = []history.Finding{finding(history.Fork, "x", "y")}
	if res, err := historyOutcome(rep, w); res != nil || err == nil {
		t.Errorf("%v, %v", res, err)
	} else if code, _ := ExitFor(err); code != ExitRefused {
		t.Errorf("exit %d, want 3", code)
	}
}
