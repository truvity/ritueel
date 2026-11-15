//go:build linux || darwin

package cli

import (
	"slices"
	"testing"
)

// The command "check history" and the finding trust-sequence (record 0006, rules 14 and 21): exit
// code 3, the name in reasons, one line "trust-sequence PATH: DETAIL" on standard error, the same in
// both output modes; the two ranges of a number: a sequence below 1 is anchor-unknown, a folder
// number of 0 is no trust number. The bundles are made by hand like the others of check_bundle_test.go.

const seqRule = "(record 0006, rules 14 and 21)"

// refusedAs runs the command in both modes on the bundle and checks the lines of standard error, the
// exit code 3, the reasons of the JSON object, and that the two modes say the same.
func refusedAs(t *testing.T, b *hbundle, lines []string, reasons []string) {
	t.Helper()
	want := append(slices.Clone(lines), "ritueel: refused: "+joinReasons(reasons))
	text := chHist(t, b.dir)
	if text.code != ExitRefused || text.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 and nothing on standard output", text.code, text.stdout, text.stderr)
	}
	if got := chLines(text.stderr); !slices.Equal(got, want) {
		t.Errorf("standard error:\n got %q\nwant %q", got, want)
	}
	js := chJSON(t, b.dir)
	if js.code != ExitRefused || js.stderr != text.stderr {
		t.Errorf("JSON: exit %d; standard error differs from the text mode: %q and %q", js.code, js.stderr, text.stderr)
	}
	chWantRefused(t, js, reasons, []string{})
}

func joinReasons(r []string) string {
	out := ""
	for i, s := range r {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func TestCheckHistoryReportsATrustNumberThatDoesNotGrow(t *testing.T) {
	b := newHB(t, 2)
	b.add(t, true, func(c *hbCeremony) { c.set = "2-3fa9c1df" })
	rep := chReport(t, b.dir)
	if got := chCodes(rep.Reasons()); !slices.Equal(got, []string{"trust-sequence"}) {
		t.Fatalf("the bundle of the test gives the reasons %v", got)
	}
	refusedAs(t, b, []string{
		"trust-sequence trust/2-3fa9c1df: the number in its name, 2, is not higher than 2, the number of the set before it in the chain, trust/" + b.cs[1].set + " " + seqRule,
	}, []string{"trust-sequence"})
}

func TestCheckHistoryReportsATrustNumberThatFalls(t *testing.T) {
	b := newHB(t, 2)
	b.add(t, true, func(c *hbCeremony) { c.set = "1-3fa9c1df" })
	b.add(t, true, func(c *hbCeremony) { c.set = "9-3fa9c1df" })
	refusedAs(t, b, []string{
		"trust-sequence trust/1-3fa9c1df: the number in its name, 1, is not higher than 2, the number of the set before it in the chain, trust/" + b.cs[1].set + " " + seqRule,
	}, []string{"trust-sequence"})
}

func TestCheckHistoryAcceptsATrustNumberThatSkips(t *testing.T) {
	b := newHB(t, 2)
	b.add(t, true, func(c *hbCeremony) { c.set = "9-3fa9c1df" })
	for _, r := range []result{chHist(t, b.dir), chJSON(t, b.dir)} {
		if r.code != ExitOK || r.stderr != "" {
			t.Errorf("exit %d, stderr %q; a skip is no finding", r.code, r.stderr)
		}
	}
	if r := chHist(t, b.dir); r.stdout != chEnd(3, b.cs[2].digest) {
		t.Errorf("stdout %q", r.stdout)
	}
	chWantDone(t, chJSON(t, b.dir), []string{})
}

func TestCheckHistoryReportsANumberThatIsNotTheSequenceOfItsList(t *testing.T) {
	b := newHB(t, 1)
	b.add(t, true, func(c *hbCeremony) {
		c.rootList = `{"last_record_sha256":"` + c.prev + `","sequence":3,"version":1}`
	})
	refusedAs(t, b, []string{
		"trust-sequence trust/" + b.cs[1].set + ": the number in its name, 2, is not the sequence of its root list, 3 " + seqRule,
	}, []string{"trust-sequence"})
}

func TestCheckHistoryReportsASequenceBelowOneAsAnAnchor(t *testing.T) {
	for _, seq := range []string{"0", "-1"} {
		t.Run(seq, func(t *testing.T) {
			b := newHB(t, 0)
			b.add(t, true, func(c *hbCeremony) { c.rootList = `{"sequence":` + seq + `,"version":1}` })
			path := "trust/" + b.cs[0].set
			refusedAs(t, b, []string{
				"anchor-unknown " + path + "/root-list.json: the root list has a sequence of " + seq + ", and a sequence is an integer of at least 1; its keys are still read",
				"trust-sequence " + path + ": the number in its name, 1, is not the sequence of its root list, " + seq + " " + seqRule,
			}, []string{"anchor-unknown", "trust-sequence"})
		})
	}
}

func TestCheckHistoryReportsASetOfTheNumberZeroAsNoTrustNumber(t *testing.T) {
	b := newHB(t, 2)
	hbWrite(t, b.dir, "trust/0-3fa9c1d2/keys.txt", "x")
	refusedAs(t, b, []string{
		"trust-set-unlisted trust/0-3fa9c1d2: no record lists it, and its name has no trust number",
	}, []string{"trust-set-unlisted"})
}

func TestCheckHistoryReportsASetWithNoTrustNumberThatARecordLists(t *testing.T) {
	b := newHB(t, 1)
	b.add(t, true, func(c *hbCeremony) { c.set = "01-3fa9c1df" })
	refusedAs(t, b, []string{
		"trust-sequence trust/01-3fa9c1df: its name has no trust number, so the number and the sequence of its root list cannot be compared (record 0006, rule 14)",
	}, []string{"trust-sequence"})
}
