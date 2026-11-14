//go:build linux || darwin

package history

import (
	"slices"
	"strings"
	"testing"
)

// The report as a value: what it says about reasons, warnings, the end and the line of a finding.

func report(records int, ends []string, fs ...Finding) *Report {
	return &Report{Records: records, Ends: ends, Findings: fs}
}

func TestReasonsAndWarningsAreDistinctAndInTheOrderOfTheCodes(t *testing.T) {
	// Findings as a check returns them: sorted by code.
	rep := report(3, nil,
		Finding{ChainBroken, "history/a", "x"},
		Finding{ChainBroken, "history/b", "x"},
		Finding{RecordInvalid, "history/a/record.json", "x"},
		Finding{FileMissing, "x", "x"},
		Finding{FileMissing, "y", "x"},
		Finding{UnfinishedCeremony, "trust/1-a", "x"},
		Finding{AnchorUnknown, "trust/2-a/root-list.json", "x"},
		Finding{UnexpectedFile, "history/z", "x"},
		Finding{UnexpectedFile, "history/zz", "x"},
	)
	wantReasons(t, rep, []Code{ChainBroken, RecordInvalid, FileMissing, AnchorUnknown}, []Code{UnfinishedCeremony, UnexpectedFile})
	if rep.Clean() {
		t.Error("Clean() = true with failing findings")
	}
	if got := len(rep.Failing()); got != 6 {
		t.Errorf("Failing() holds %d findings, want 6", got)
	}
	if got := len(rep.Notices()); got != 3 {
		t.Errorf("Notices() holds %d findings, want 3", got)
	}
	// The two lists keep the order of the findings.
	f := rep.Failing()
	if f[0].Path != "history/a" || f[1].Path != "history/b" || f[5].Path != "trust/2-a/root-list.json" {
		t.Errorf("Failing() = %v", f)
	}
}

func TestReportOfNoticesOnlyIsClean(t *testing.T) {
	rep := report(1, []string{digestA}, Finding{UnexpectedFile, "history/z", "x"}, Finding{UnfinishedCeremony, "trust/1-a", "x"})
	if !rep.Clean() {
		t.Error("Clean() = false with notices only")
	}
	if len(rep.Reasons()) != 0 {
		t.Errorf("Reasons() = %v, want none", rep.Reasons())
	}
	// A report with no finding at all.
	empty := report(0, nil)
	if !empty.Clean() || len(empty.Reasons()) != 0 || len(empty.Warnings()) != 0 || len(empty.Failing()) != 0 || len(empty.Notices()) != 0 {
		t.Error("an empty report is not whole")
	}
}

func TestEndAndEndLine(t *testing.T) {
	cases := []struct {
		name    string
		rep     *Report
		eight   string
		count   int
		ok      bool
		endLine string
	}{
		{"no record", report(0, nil), "", 0, false, "history: 0 ceremony records"},
		{"one end", report(1, []string{"0123456789abcdef" + digestA[16:]}), "01234567", 1, true, "history: 1 ceremony records, end 01234567"},
		{"seven records", report(7, []string{"fedcba98" + digestA[8:]}), "fedcba98", 7, true, "history: 7 ceremony records, end fedcba98"},
		{"two ends", report(5, []string{digestA, digestB}), "", 5, false, "history: 5 ceremony records"},
		{"records and no end", report(2, nil), "", 2, false, "history: 2 ceremony records"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eight, count, ok := c.rep.End()
			if eight != c.eight || count != c.count || ok != c.ok {
				t.Errorf("End() = %q, %d, %v; want %q, %d, %v", eight, count, ok, c.eight, c.count, c.ok)
			}
			if got := c.rep.EndLine(); got != c.endLine {
				t.Errorf("EndLine() = %q, want %q", got, c.endLine)
			}
		})
	}
}

func TestFindingLineIsCodePathColonDetail(t *testing.T) {
	f := Finding{Code: FileMissing, Path: "trust/1-3fa9c1d2/keys.txt", Detail: "listed by x"}
	if got, want := f.Line(), "file-missing trust/1-3fa9c1d2/keys.txt: listed by x"; got != want {
		t.Errorf("Line() = %q, want %q", got, want)
	}
}

// The line is escaped once more as a last guard: whatever is in a finding, no raw byte of it
// reaches a terminal.
func TestFindingLineEscapesWhateverItHolds(t *testing.T) {
	hostile := "a\x1b[31m" + string(rune(0x430)) + string(rune(0x202e)) + "\xff\n\r\t\x00" + string(rune(0x1f600))
	f := Finding{Code: UnexpectedName, Path: "history/" + hostile, Detail: "detail " + hostile}
	line := f.Line()
	if !printable(line) {
		t.Fatalf("the line holds a byte beyond printable ASCII: %q", line)
	}
	for _, want := range []string{uesc(0x1b), uesc(0x430), uesc(0x202e), uesc(0xfffd), uesc(0xa), uesc(0xd), uesc(0x9), uesc(0), uesc(0xd83d) + uesc(0xde00)} {
		if !strings.Contains(line, want) {
			t.Errorf("the line %q lacks the escape %s", line, want)
		}
	}
	if !strings.HasPrefix(line, "unexpected-name history/a") || !strings.Contains(line, ": detail a") {
		t.Errorf("the form is lost: %q", line)
	}
}

// uesc is the escape of a code unit: a backslash, a "u" and four lower-case hexadecimal digits.
// It is built here, so that no escape is written in this file.
func uesc(u rune) string {
	const hex = "0123456789abcdef"
	return string([]rune{'\\', 'u', rune(hex[u>>12&15]), rune(hex[u>>8&15]), rune(hex[u>>4&15]), rune(hex[u&15])})
}

func TestCollectorKeepsTheOrderOfTheCodesThenThePathThenTheDetail(t *testing.T) {
	c := newCollector(1000)
	in := []Finding{
		{UnexpectedFile, "b", "1"},
		{ChainBroken, "z", "1"},
		{FileMissing, "b", "2"},
		{FileMissing, "b", "1"},
		{FileMissing, "a", "9"},
		{AnchorUnknown, "a", "1"},
		{Fork, "a", "1"},
		{ChainBroken, "a", "1"},
		{TrustSetUnlisted, "a", "1"},
		{UnfinishedCeremony, "a", "1"},
		{UnexpectedName, "a", "1"},
		{RecordOffChain, "a", "1"},
		{RecordNotCanonical, "a", "1"},
		{RecordVersionUnknown, "a", "1"},
		{RecordInvalid, "a", "1"},
		{TranscriptDigest, "a", "1"},
		{FileDigest, "a", "1"},
	}
	for _, f := range in {
		c.add(f.Code, f.Path, f.Detail)
	}
	got := c.sorted()
	want := []Finding{
		{ChainBroken, "a", "1"}, {ChainBroken, "z", "1"},
		{Fork, "a", "1"},
		{RecordOffChain, "a", "1"}, {RecordNotCanonical, "a", "1"}, {RecordVersionUnknown, "a", "1"}, {RecordInvalid, "a", "1"},
		{TranscriptDigest, "a", "1"}, {FileDigest, "a", "1"},
		{FileMissing, "a", "9"}, {FileMissing, "b", "1"}, {FileMissing, "b", "2"},
		{TrustSetUnlisted, "a", "1"}, {UnfinishedCeremony, "a", "1"}, {AnchorUnknown, "a", "1"},
		{UnexpectedName, "a", "1"}, {UnexpectedFile, "b", "1"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("order:\n got %v\nwant %v", got, want)
	}
}

func TestCollectorKeepsAtMostTheLimitOfEachCodeAndCountsTheRest(t *testing.T) {
	c := newCollector(3)
	for i := 0; i < 5; i++ {
		c.add(FileMissing, strings.Repeat("a", i+1), "x")
	}
	c.add(FileDigest, "p", "x") // another code has its own count
	c.add(FileDigest, "q", "x")
	c.add(Fork, "r", "x")
	for i := 0; i < 2; i++ {
		c.add(FileDigest, "s", "x")
	}
	n := map[Code]int{}
	for _, f := range c.sorted() {
		n[f.Code]++
	}
	if n[FileMissing] != 3 || n[FileDigest] != 3 || n[Fork] != 1 {
		t.Errorf("kept %v, want 3 file-missing, 3 file-digest, 1 fork", n)
	}
	if c.omitted != 2+1 {
		t.Errorf("omitted = %d, want 3", c.omitted)
	}
	// Exactly at the limit nothing is left out.
	d := newCollector(2)
	d.add(Fork, "a", "x")
	d.add(Fork, "b", "x")
	if d.omitted != 0 || len(d.sorted()) != 2 {
		t.Errorf("at the limit: omitted %d, kept %d", d.omitted, len(d.sorted()))
	}
	d.add(Fork, "c", "x")
	if d.omitted != 1 || len(d.sorted()) != 2 {
		t.Errorf("over the limit: omitted %d, kept %d", d.omitted, len(d.sorted()))
	}
}

func TestCutShortensAtACharacterBoundary(t *testing.T) {
	if got := cut("short", 240); got != "short" {
		t.Errorf("cut of a short text = %q", got)
	}
	exact := strings.Repeat("a", 240)
	if got := cut(exact, 240); got != exact {
		t.Errorf("a text of exactly 240 bytes is changed: %d bytes", len(got))
	}
	long := strings.Repeat("a", 241)
	got := cut(long, 240)
	if !strings.HasPrefix(got, exact) || !strings.HasSuffix(got, "...") || len(got) >= len(long)+3 {
		t.Errorf("cut of 241 bytes = %d bytes: %.30q", len(got), got)
	}
	// Not inside a character: two-byte letters, cut at an odd byte.
	two := strings.Repeat(string(rune(0xe9)), 200)
	got = cut(two, 241)
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("not cut: %d bytes", len(got))
	}
	for _, r := range strings.TrimSuffix(got, "...") {
		if r != 0xe9 {
			t.Fatalf("a character was cut in two: %q", r)
		}
	}
}
