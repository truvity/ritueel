//go:build linux || darwin

package cli

import (
	"slices"
	"strings"
	"testing"
)

// The command "check history" and a root list with no sequence member (the row anchor-unknown of
// "The hash chain" in docs/reference/ceremony-record.md): exit code 3, the name in reasons, one line
// "anchor-unknown PATH: DETAIL" on standard error for each list, the same in both output modes.
// The bundles are made by hand like the others of check_bundle_test.go.

// noSequenceWords is the detail of the finding for a list with no sequence.
const noSequenceWords = "the root list has no sequence, and a sequence is an integer of at least 1; its keys are still read"

// hbNoSequence makes the root list of a ceremony a list with the version and the anchor, and no
// sequence.
func hbNoSequence(c *hbCeremony) {
	c.rootList = `{"version":1}`
	if c.prev != "" {
		c.rootList = `{"last_record_sha256":"` + c.prev + `","version":1}`
	}
}

// noSequenceLine is the line of standard error for the list of the set.
func noSequenceLine(set string) string {
	return "anchor-unknown trust/" + set + "/root-list.json: " + noSequenceWords
}

// A bundle of two sets whose lists have no sequence member (the example of the rule): before, the
// command said nothing about them and exited 0.
func TestCheckHistoryReportsTwoListsWithNoSequence(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbNoSequence)
	b.add(t, true, hbNoSequence)
	refusedAs(t, b, []string{noSequenceLine(b.cs[0].set), noSequenceLine(b.cs[1].set)}, []string{"anchor-unknown"})
}

func TestCheckHistoryReportsOneListWithNoSequence(t *testing.T) {
	for name, which := range map[string]int{"the first": 0, "the middle": 1, "the last": 2} {
		t.Run(name, func(t *testing.T) {
			b := newHB(t, 0)
			for i := 0; i < 3; i++ {
				if i == which {
					b.add(t, true, hbNoSequence)
				} else {
					b.add(t, true)
				}
			}
			refusedAs(t, b, []string{noSequenceLine(b.cs[which].set)}, []string{"anchor-unknown"})
		})
	}
}

// The exit code, the streams and the object are those of every other finding: nothing on standard
// output, exit 3, the outcome refused with the one reason.
func TestCheckHistoryRefusesAListWithNoSequenceInBothModes(t *testing.T) {
	b := newHB(t, 2)
	b.add(t, true, hbNoSequence)
	text := chHist(t, b.dir)
	if text.code != ExitRefused || text.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 and nothing on standard output", text.code, text.stdout, text.stderr)
	}
	want := []string{noSequenceLine(b.cs[2].set), "ritueel: refused: anchor-unknown"}
	if got := chLines(text.stderr); !slices.Equal(got, want) {
		t.Errorf("standard error:\n got %q\nwant %q", got, want)
	}
	js := chJSON(t, b.dir)
	if js.code != ExitRefused || js.stderr != text.stderr || js.stdout == "" {
		t.Errorf("JSON: exit %d, stdout %q; standard error %q, in text mode %q", js.code, js.stdout, js.stderr, text.stderr)
	}
	chWantRefused(t, js, []string{"anchor-unknown"}, []string{})
	if rep := chReport(t, b.dir); !slices.Equal(chWantLines(rep), want) {
		t.Errorf("the library says %q", chWantLines(rep))
	}
}

// The end line is not printed for a refused bundle, and nothing else changes: the same bundle with
// a sequence in each list ends with exit 0 and the end line.
func TestCheckHistoryIsCleanWhenEveryListHasASequence(t *testing.T) {
	b := newHB(t, 3)
	r := chHist(t, b.dir)
	if want := chEnd(3, b.cs[2].digest); r.code != ExitOK || r.stdout != want || r.stderr != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q and nothing", r.code, r.stdout, r.stderr, want)
	}
	for _, c := range b.cs {
		if !strings.Contains(c.rootList, `"sequence":`) {
			t.Errorf("the root list of %s has no sequence: %s", c.set, c.rootList)
		}
	}
	chWantDone(t, chJSON(t, b.dir), []string{})
}

// A list with a sequence below 1 keeps its line, and a list with no sequence has another one.
func TestCheckHistoryTellsNoSequenceAndSequenceZeroApart(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbNoSequence)
	b.add(t, true, func(c *hbCeremony) { c.rootList = `{"last_record_sha256":"` + c.prev + `","sequence":0,"version":1}` })
	refusedAs(t, b, []string{
		noSequenceLine(b.cs[0].set),
		"anchor-unknown trust/" + b.cs[1].set + "/root-list.json: the root list has a sequence of 0, and a sequence is an integer of at least 1; its keys are still read",
		"trust-sequence trust/" + b.cs[1].set + ": the number in its name, 2, is not the sequence of its root list, 0 " + seqRule,
	}, []string{"anchor-unknown", "trust-sequence"})
}

// A list with no sequence is read for its keys all the same: a key that is on it, leaves and comes
// back is found, with the path of the later list. The two findings are told, and the reasons are in
// the order of the page.
func TestCheckHistoryFindsAReturnThroughAListWithNoSequence(t *testing.T) {
	noSeqRoots := func(entries ...string) func(*hbCeremony) {
		return func(c *hbCeremony) {
			hbRoots(entries...)(c)
			c.rootList = strings.Replace(c.rootList, `"sequence":`+itoa(c.n)+`,`, "", 1)
		}
	}
	b := newHB(t, 0)
	b.add(t, true, noSeqRoots(hbRoot("A", 1), hbRoot("B", 2)))
	b.add(t, true, hbRoots(hbRoot("B", 2)))
	b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	refusedAs(t, b, []string{
		noSequenceLine(b.cs[0].set),
		"root-returns trust/" + b.cs[2].set + "/root-list.json: root key \"A\" returns: its pin " + hbPin(1)[:16] + "... was on an earlier list and is not on the list before this one (record 0006, rule 54); pin held on trust/" + b.cs[0].set + "; list before trust/" + b.cs[1].set,
	}, []string{"anchor-unknown", "root-returns"})
}

// The same, with the list that has no sequence in the middle and the key missing from it.
func TestCheckHistoryFindsAReturnAfterAListWithNoSequenceThatLacksTheKey(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	b.add(t, true, hbRoots(hbRoot("B", 2)), func(c *hbCeremony) {
		c.rootList = strings.Replace(c.rootList, `"sequence":`+itoa(c.n)+`,`, "", 1)
	})
	b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	refusedAs(t, b, []string{
		noSequenceLine(b.cs[1].set),
		"root-returns trust/" + b.cs[2].set + "/root-list.json: root key \"A\" returns: its pin " + hbPin(1)[:16] + "... was on an earlier list and is not on the list before this one (record 0006, rule 54); pin held on trust/" + b.cs[0].set + "; list before trust/" + b.cs[1].set,
	}, []string{"anchor-unknown", "root-returns"})
}

// A set of a ceremony that stopped, with a list that has no sequence, is both a notice and a
// refusal; and a closing record that lists it does not hide the finding.
func TestCheckHistoryReportsAListWithNoSequenceInAnUnfinishedSet(t *testing.T) {
	b := newHB(t, 2)
	open := b.add(t, false, hbNoSequence)
	text := chHist(t, b.dir)
	if text.code != ExitRefused || text.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", text.code, text.stdout, text.stderr)
	}
	lines := chLines(text.stderr)
	if !slices.Contains(lines, noSequenceLine(open.set)) || !slices.Contains(lines, "ritueel: warning: unfinished-ceremony") || lines[len(lines)-1] != "ritueel: refused: anchor-unknown" {
		t.Errorf("standard error: %q", lines)
	}
	chWantRefused(t, chJSON(t, b.dir), []string{"anchor-unknown"}, []string{"unfinished-ceremony"})

	hbClosing(t, b, open)
	closed := chHist(t, b.dir)
	if closed.code != ExitRefused || !slices.Contains(chLines(closed.stderr), noSequenceLine(open.set)) {
		t.Errorf("after the closing record: exit %d, stderr %q", closed.code, closed.stderr)
	}
}

// A list with no sequence among many is bounded like every finding: at most 1,000 lines of one code
// and the count of the rest.
func TestCheckHistoryBoundsTheLinesOfListsWithNoSequence(t *testing.T) {
	b := newHB(t, 0)
	for i := 0; i < 1005; i++ {
		b.add(t, true, hbNoSequence)
	}
	text := chHist(t, b.dir)
	if text.code != ExitRefused || text.stdout != "" {
		t.Fatalf("exit %d, stdout %q", text.code, text.stdout)
	}
	lines := chLines(text.stderr)
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "anchor-unknown ") {
			n++
		}
	}
	if n != 1000 || !slices.Contains(lines, "5 more findings not shown") || lines[len(lines)-1] != "ritueel: refused: anchor-unknown" {
		t.Errorf("%d lines of anchor-unknown; the last lines are %q", n, lines[max(0, len(lines)-3):])
	}
}
