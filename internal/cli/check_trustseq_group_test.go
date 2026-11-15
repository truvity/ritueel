//go:build linux || darwin

package cli

import (
	"fmt"
	"strings"
	"testing"
)

// The command "check history" and the trust sets that one record lists together, and the sets that
// the finding trust-sequence leaves out on purpose (record 0006, rules 14 and 21).

// hbOpenFor makes the plan of an unfinished ceremony say that the number of its set is num, and the
// attempt follow the plan. The set is named with that number.
func hbOpenFor(num int, name string) func(*hbCeremony) {
	return func(c *hbCeremony) {
		c.nameSet(name)
		c.plan = strings.Replace(c.plan, fmt.Sprintf(`"trust_sequence":%d,`, c.n), fmt.Sprintf(`"trust_sequence":%d,`, num), 1)
		c.attempt = `{"ceremony":"` + c.folder + `","plan_sha256":"` + hbSum(c.plan) + `","version":1}`
	}
}

// doneAs runs the command in both modes on a bundle that is whole: exit 0, nothing but the lines of
// the notices on standard error, and the warnings of the library in the JSON object.
func doneAs(t *testing.T, b *hbundle, warnings []string) {
	t.Helper()
	rep := chReport(t, b.dir)
	if !rep.Clean() {
		t.Fatalf("the bundle of the test is not clean: %v", chCodes(rep.Reasons()))
	}
	if got := chCodes(rep.Warnings()); strings.Join(got, ",") != strings.Join(warnings, ",") {
		t.Fatalf("the bundle of the test gives the warnings %v, want %v", got, warnings)
	}
	text := chHist(t, b.dir)
	if text.code != ExitOK {
		t.Errorf("exit %d, stderr %q; want exit 0", text.code, text.stderr)
	}
	if got, want := chLines(text.stderr), chWantLines(rep); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("standard error:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(text.stderr, "trust-sequence") {
		t.Errorf("standard error names trust-sequence: %q", text.stderr)
	}
	js := chJSON(t, b.dir)
	if js.code != ExitOK || js.stderr != text.stderr {
		t.Errorf("JSON: exit %d; standard error %q, in text mode %q", js.code, js.stderr, text.stderr)
	}
	if warnings == nil {
		warnings = []string{}
	}
	chWantDone(t, js, warnings)
}

// One record lists two sets of the number 2: the second in the order of the place is not higher
// than the first, exit 3, one line, the same in both modes.
func TestCheckHistoryReportsTwoSetsOfOneRecordWithOneNumber(t *testing.T) {
	b := newHB(t, 1)
	b.add(t, true, func(c *hbCeremony) { c.nameSet("2-3fa9c1d1"); c.nameExtra("2-3fa9c1d2") })
	refusedAs(t, b, []string{
		"trust-sequence trust/2-3fa9c1d2: the number in its name, 2, is not higher than 2, the number of the set before it in the chain, trust/2-3fa9c1d1 " + seqRule,
	}, []string{"trust-sequence"})
}

// The same record with numbers that grow is whole, and the set after it is held to the last of the
// two.
func TestCheckHistoryAcceptsTwoSetsOfOneRecordWithGrowingNumbers(t *testing.T) {
	b := newHB(t, 1)
	b.add(t, true, func(c *hbCeremony) { c.nameSet("2-3fa9c1d1"); c.nameExtra("3-3fa9c1d2") })
	doneAs(t, b, nil)
}

func TestCheckHistoryHoldsTheSetAfterAGroupToTheLastSetOfTheGroup(t *testing.T) {
	b := newHB(t, 1)
	b.add(t, true, func(c *hbCeremony) { c.nameSet("2-3fa9c1d1"); c.nameExtra("4-3fa9c1d2") })
	b.add(t, true, func(c *hbCeremony) { c.nameSet("3-3fa9c1d3") })
	refusedAs(t, b, []string{
		"trust-sequence trust/3-3fa9c1d3: the number in its name, 3, is not higher than 4, the number of the set before it in the chain, trust/4-3fa9c1d2 " + seqRule,
	}, []string{"trust-sequence"})
}

// The cases that the finding leaves out on purpose end with exit code 0.

// A closing record lists a set whose number repeats one of the chain, or is lower than the one
// before it: the set is left out, and so the number does not count.
func TestCheckHistoryAcceptsAClosingRecordThatListsARepeatedOrLoweredNumber(t *testing.T) {
	for _, tc := range []struct{ name, set string }{
		{"a repeated number", "2-3fa9c1ff"},
		{"a lowered number", "1-3fa9c1ff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := newHB(t, 2)
			stopped := b.add(t, false, hbOpenFor(2, tc.set))
			hbClosing(t, b, stopped)
			doneAs(t, b, nil)
		})
	}
}

// A set that a stopped ceremony left, with an open attempt and a number that repeats: it is the
// notice unfinished-ceremony, and not trust-sequence.
func TestCheckHistoryAcceptsAnUnfinishedSetWithARepeatedNumber(t *testing.T) {
	b := newHB(t, 2)
	b.add(t, false, hbOpenFor(2, "2-3fa9c1ff"))
	doneAs(t, b, []string{"unfinished-ceremony"})
	b2 := newHB(t, 2)
	b2.add(t, false, hbOpenFor(1, "1-3fa9c1ff"))
	doneAs(t, b2, []string{"unfinished-ceremony"})
}

// A leftover that a closing record lists is no set before: the ordinary set after it has the same
// number and is held to the set before the leftover.
func TestCheckHistoryAcceptsAnOrdinarySetWithTheNumberOfAClosedLeftover(t *testing.T) {
	b := newHB(t, 1)
	stopped := b.add(t, false, hbOpenFor(2, "2-3fa9c1ee"))
	hbClosing(t, b, stopped)
	b.add(t, true, func(c *hbCeremony) { c.nameSet("2-3fa9c1ff") })
	doneAs(t, b, nil)
}
