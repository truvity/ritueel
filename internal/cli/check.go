package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
	"ritueel.id/ritueel/internal/jsonset"
)

// checkSpec is the word check. Its second words are the read-only checks of a bundle; each is one
// entry on its own line, so that a part that adds a second word adds one line.
var checkSpec = spec{
	name:  "check",
	usage: "check what a bundle holds, and change nothing",
	subs: []spec{
		checkHistorySpec,
	},
}

// checkHistorySpec is the second word history: it takes no flag of its own and no argument.
var checkHistorySpec = spec{
	name:  "history",
	usage: "walk the hash chain of the ceremony records of a bundle and check the files they list",
	run:   runCheckHistory,
}

// omittedFormat is the line that follows the findings when the report left some out, with the
// number of them. It has this form for every number, also for 1, as the end line says "records" for
// every count. It is the one place of the wording.
const omittedFormat = "%d more findings not shown"

// errInconsistentReport is the fault of the program that a report breaks: a report that says the
// history is whole and whose count and ends do not agree. It is exit code 1 and never the end line.
var errInconsistentReport = errors.New("the history report is not consistent")

// runCheckHistory finds the folder of the bundle, opens it, and runs checkHistory on it. It takes no
// argument. It reads files only and writes nothing, anywhere.
func runCheckHistory(ctx context.Context, c *Call) (*Result, error) {
	if len(c.Args) > 0 {
		return nil, UsageError{Msg: "check history takes no argument; the bundle folder is given with --dir"}
	}
	dir, err := bundleDir(c)
	if err != nil {
		return nil, err
	}
	fsys, err := fsx.OpenFS(dir)
	if err != nil {
		return nil, err
	}
	defer func() {
		// The folder was opened to read it only; nothing was written, so a failed close loses nothing.
		_ = fsys.Close()
	}()
	return checkHistory(ctx, fsys, c.Env.Stderr)
}

// checkHistory runs history.Check on the folder and turns the report into the result. It is the seam
// for a test: the file system is given. An error from the check, or a context that has ended, is the
// error and nothing else: no line is written, so a run that did not check is never mistaken for
// one that did.
func checkHistory(ctx context.Context, fsys fsx.FS, stderr io.Writer) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rep, err := history.Check(ctx, fsys)
	if err != nil {
		return nil, err
	}
	return historyOutcome(rep, stderr)
}

// historyOutcome is the one place that decides what a report means: the exit code and the lines come
// from here, and it asks Report.Clean once. A nil report, and a report that says the history is whole
// and whose count and ends disagree, are exit code 1 with nothing written; a report with a failing
// finding is exit code 3 (docs/reference/cli.md, "check history"), whatever else it holds.
//
// A clean report is the Result with the end line on standard output and one line for each notice
// written on stderr. A refusal writes one line for each finding and each notice on stderr, and ends
// with one Refusal that lists the failing codes in the order of the library, with the notice codes as
// its warnings; the program writes the last line. The lines are composed first and written once, on
// the two paths that return a Result or a Refusal.
func historyOutcome(rep *history.Report, stderr io.Writer) (*Result, error) {
	if rep == nil {
		return nil, errors.New("the history check gave no report")
	}
	if stderr == nil {
		stderr = io.Discard
	}
	warnings := codeStrings(rep.Warnings())
	clean := rep.Clean()
	if !clean {
		reasons := codeStrings(rep.Reasons())
		if len(reasons) == 0 {
			return nil, errInconsistentReport
		}
		writeLines(stderr, findingLines(rep))
		return nil, WithWarnings(Refusal{Reasons: reasons}, warnings...)
	}
	if !reportAgrees(rep) {
		return nil, errInconsistentReport
	}
	writeLines(stderr, findingLines(rep))
	return &Result{ExitCode: ExitOK, Warnings: warnings, Text: rep.EndLine() + "\n"}, nil
}

// reportAgrees says whether the count and the ends of a clean report fit: with no record there is no
// end, with records there is exactly one, and its first eight characters are lower-case
// hexadecimal digits, so that the end line can be written.
func reportAgrees(rep *history.Report) bool {
	switch {
	case rep.Records < 0:
		return false
	case rep.Records == 0:
		return len(rep.Ends) == 0
	case len(rep.Ends) != 1:
		return false
	}
	end := rep.Ends[0]
	if len(end) < 8 {
		return false
	}
	for i := 0; i < 8; i++ {
		if c := end[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// findingLines returns every finding and every notice as Finding.Line() and a line break, in the
// order of the report, and then the line of the findings that were left out when there are some.
// The code of a finding is written as the library gives it, except that a character outside printable
// ASCII is escaped, as a guard: Finding.Line escapes the path and the detail and not the code. It
// returns "" for a nil report.
func findingLines(rep *history.Report) string {
	if rep == nil {
		return ""
	}
	var b strings.Builder
	for _, f := range rep.Findings {
		f.Code = history.Code(jsonset.Escape(string(f.Code)))
		b.WriteString(f.Line())
		b.WriteByte('\n')
	}
	if rep.Omitted > 0 {
		fmt.Fprintf(&b, omittedFormat+"\n", rep.Omitted)
	}
	return b.String()
}

// writeLines writes the composed lines once. A write that fails is not an error of the check: the
// result of the run does not depend on it, and the program has no other place to say it.
func writeLines(w io.Writer, lines string) {
	if lines == "" {
		return
	}
	_, _ = io.WriteString(w, lines)
}

// codeStrings returns the codes as strings, in the order given; nil for no code.
func codeStrings(codes []history.Code) []string {
	if len(codes) == 0 {
		return nil
	}
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i] = string(c)
	}
	return out
}
