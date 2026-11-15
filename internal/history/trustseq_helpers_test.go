//go:build linux || darwin

package history

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The helpers of the tests about the numbers of the trust sets (record 0006, rules 14 and 21).

// maxIJSON is the highest whole number that a JSON text may hold in the I-JSON range.
const maxIJSON = 1<<53 - 1

// listSeqRE finds the member sequence of a root list written by these tests: a whole number.
var listSeqRE = regexp.MustCompile(`"sequence":(-?[0-9]+)`)

// seqOfList is the member sequence of a root list of a test, and whether it has one.
func seqOfList(list []byte) (int64, bool) {
	m := listSeqRE.FindSubmatch(list)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(string(m[1]), 10, 64)
	return n, err == nil
}

// modelNumber is the number a folder name begins with, worked out a second way: the digits before
// the first hyphen, at most fifteen of them, with no leading zero unless the number is 0 itself.
func modelNumber(name string) (int64, bool) {
	i := strings.IndexByte(name, '-')
	if i <= 0 || i > 15 {
		return 0, false
	}
	digits := name[:i]
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	return n, err == nil
}

// modelTrustSeq is what record 0006, rules 14 and 21, give for a chain of ordinary ceremonies that list one set each, with
// no fork and no closing record: for each set in the order of the chain, a finding anchor-unknown
// when the sequence of its list is below 1, and a finding trust-sequence when the number of its
// name is not the sequence of its list, is not higher than the number of the set before it, or is
// no trust number at all. A list with no sequence is not compared with its name.
func modelTrustSeq(sets []cset) []wf {
	var out []wf
	var before int64
	have := false
	for i, s := range sets {
		name := s.name
		if name == "" {
			name = setN(i + 1)
		}
		seq, hasSeq := seqOfList(s.list)
		if hasSeq && (seq > maxIJSON || seq < -maxIJSON) {
			// a number that RFC 8785 cannot hold: the list cannot be read, so it has no sequence to compare
			out = append(out, wf{AnchorUnknown, listPathOf(name)})
			hasSeq = false
		} else if hasSeq && seq < 1 {
			out = append(out, wf{AnchorUnknown, listPathOf(name)})
		}
		n, ok := modelNumber(name)
		if !ok {
			out = append(out, wf{TrustSequence, "trust/" + name})
			continue
		}
		if (hasSeq && seq != n) || (have && n <= before) {
			out = append(out, wf{TrustSequence, "trust/" + name})
		}
		before, have = n, true
	}
	return out
}

// wantFailed fails the test unless the inspection is a failing report with exactly the findings
// want, and has neither a State nor an OrderErr: the findings are the reason.
func wantFailed(t testing.TB, in *Inspection, want []wf) {
	t.Helper()
	if in.State != nil {
		t.Errorf("a State with the lists %v, want none", namesOfLists(in.State))
	}
	if in.OrderErr != nil {
		t.Errorf("an OrderErr %v with a failing report", in.OrderErr)
	}
	if in.Report.Clean() {
		t.Error("the report is clean, want a failing one")
	}
	got, want := sortWF(findingsOf(in.Report)), sortWF(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings:\n got %v\nwant %v", got, want)
	}
}

// wantModel is wantFailed with the findings that the rules give for these sets, and it fails when
// the sets are meant to be a failing case and the model finds nothing.
func wantModel(t testing.TB, in *Inspection, sets []cset) {
	t.Helper()
	want := modelTrustSeq(sets)
	if len(want) == 0 {
		t.Fatal("the case is meant to fail, and the model finds nothing")
	}
	wantFailed(t, in, want)
}

// csetsOf is the sets of a chain table: the names are "<num>-" and eight letters that differ from
// one ceremony to the next, the sequences are those of the specs (see chainOf).
func csetsOf(specs []seqSet) []cset {
	sets := make([]cset, len(specs))
	for i, s := range specs {
		name := strings.Join([]string{strconv.Itoa(s.num), strings.Repeat(string(rune('a'+i)), 8)}, "-")
		if s.none {
			sets[i] = cset{name, rootsJSON(0, kA)}
		} else {
			sets[i] = cset{name, keyList(s.seq, kA)}
		}
	}
	return sets
}

// wantRefusedBy is for a chain whose inspection has no State: when the model finds a number that
// breaks the rules, the report fails with exactly those findings; when it finds none, the report is
// clean and the order has no one reading (an OrderErr).
func wantRefusedBy(t testing.TB, in *Inspection, sets []cset) {
	t.Helper()
	if len(modelTrustSeq(sets)) > 0 {
		wantModel(t, in, sets)
		return
	}
	wantOrderErr(t, in)
}

// leftoverLast builds a chain whose last record is a closing record that lists the leftover set of
// a stopped ceremony: the set is not judged by trust-sequence, so a report with nothing else wrong
// is clean, and the State refuses it for the way its number and its list stand.
func leftoverLast(t testing.TB, first cset, name string, list []byte) *bundle {
	t.Helper()
	b := chainBundle(t, false, first)
	stopped := b.unfinished(withSet(name, list))
	b.closing(stopped, listsLeftover(stopped, nil))
	return b
}
