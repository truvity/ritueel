//go:build linux || darwin

package history

import (
	"slices"
	"strings"
	"testing"
)

// When the bundle has ceremony records and none of them is on the chain (two records that have no
// prev_record_sha256, or one whose predecessor is no record), no trust set has a place, and every
// root list is judged as a list whose place cannot be told: an entry of it is a return when any
// other list that could be read held the key. The bundle fails with chain-broken in any case, and
// the name root-returns must be there when a key came back. A bundle with no ceremony record keeps
// the places that its root lists claim.

// firstRecords makes a bundle in memory whose records each list one set and none of them has a
// predecessor: every record is a first record.
func firstRecords(t testing.TB, lists ...[]byte) *bundle {
	t.Helper()
	b := chainBundle(t, true)
	for i, l := range lists {
		b.apply(prev(""), withSet(setN(i+1), l))
	}
	return b
}

func TestRootReturnsTwoFirstRecordsStillNameAKeyThatCameBack(t *testing.T) {
	b := firstRecords(t, seqList("1", kA), seqList("2", kA))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	hasCode := false
	for _, f := range rep.Findings {
		hasCode = hasCode || f.Code == ChainBroken
	}
	if !hasCode {
		t.Errorf("no chain-broken in %v", findingsOf(rep))
	}
	wantReturnsAt(t, rep, setN(1)+" A", setN(2)+" A")
	if !slices.Contains(rep.Reasons(), RootReturns) || !slices.Contains(rep.Reasons(), ChainBroken) {
		t.Errorf("the reasons are %v", rep.Reasons())
	}
	// Each list is judged as a list whose place cannot be told, and names the other as the holder.
	for _, f := range returnsOf(rep) {
		other := setN(1)
		if f.Path == listPathOf(setN(1)) {
			other = setN(2)
		}
		want := `root key "A" returns: ` + wPinFloating(pa) + wRule + "; " + wHeldPin(other)
		if f.Detail != want {
			t.Errorf("%s: the detail is\n%q\nwant\n%q", f.Path, f.Detail, want)
		}
	}
}

// The OpenPGP fingerprint is judged in the same way.
func TestRootReturnsTwoFirstRecordsNameAFingerprintThatCameBack(t *testing.T) {
	kf := ent{"F", "", f1}
	b := firstRecords(t, seqList("1", kf), seqList("2", kf))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	wantReturnsAt(t, rep, setN(1)+" F", setN(2)+" F")
	for _, f := range returnsOf(rep) {
		if !strings.Contains(f.Detail, wFPFloating(f1)) || !strings.Contains(f.Detail, "; fingerprint held on trust/") {
			t.Errorf("the detail is %q", f.Detail)
		}
	}
}

// No key came back: the bundle fails with chain-broken, and there is no finding of root-returns.
func TestRootReturnsTwoFirstRecordsWithNoKeyThatCameBackHaveNoFinding(t *testing.T) {
	b := firstRecords(t, seqList("1", kA), seqList("2", kB))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	wantReturnsAt(t, rep)
	found := false
	for _, f := range rep.Findings {
		found = found || f.Code == ChainBroken
	}
	if !found {
		t.Errorf("no chain-broken in %v", findingsOf(rep))
	}
}

// Three first records: a key on the first and the third list and not on the second. With no place,
// the rule for a list whose place cannot be told is the one that holds: an entry is a return when
// any other list held the key. The second list holds a key that nobody else held.
func TestRootReturnsThreeFirstRecordsAreJudgedByTheRuleOfAListWhosePlaceCannotBeTold(t *testing.T) {
	b := firstRecords(t, seqList("1", kA, kB), seqList("2", kB, kK), seqList("3", kA))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	// A is on lists 1 and 3, B on 1 and 2, K on 2 only.
	wantReturnsAt(t, rep, setN(1)+" A", setN(1)+" B", setN(2)+" B", setN(3)+" A")
	for _, f := range returnsOf(rep) {
		if !strings.Contains(f.Detail, "the place of this trust set in the chain cannot be told") {
			t.Errorf("the place is not said to be unknown: %q", f.Detail)
		}
		if strings.Contains(f.Detail, "list before trust/") {
			t.Errorf("a list with no place names a list before: %q", f.Detail)
		}
	}
}

// The order of the names and the numbers does not give a place to a list when no record is on the
// chain: sets numbered in the order that would hide the return are judged all the same.
func TestRootReturnsFirstRecordsAreNotPlacedByTheNumbersOfTheirSets(t *testing.T) {
	b := chainBundle(t, true)
	// The key leaves at set 2 and does not come back by the numbers: 1 {A}, 2 {B}; with places,
	// nothing returns. Without places, A is on another list and B is not, so only one list names it.
	b.apply(prev(""), withSet(setN(1), seqList("1", kA, kB)))
	b.apply(prev(""), withSet(setN(2), seqList("2", kB)))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	// B is on both lists: a return at each. A is on list 1 only: not a return.
	wantReturnsAt(t, rep, setN(1)+" B", setN(2)+" B")
}

// A record whose predecessor is no record is not on the chain, and when it is the only record, no
// set has a place: a set that no record lists is judged by the same rule.
func TestRootReturnsARecordWithAPredecessorThatIsNoRecordGivesNoPlace(t *testing.T) {
	b := chainBundle(t, true)
	b.apply(prev(digestA), withSet(setN(1), seqList("1", kA)))
	addList(b.mem, setN(2), seqList("2", kA))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		found = found || f.Code == ChainBroken
	}
	if !found {
		t.Errorf("no chain-broken in %v", findingsOf(rep))
	}
	wantReturnsAt(t, rep, setN(1)+" A", setN(2)+" A")
}

// A bundle with no ceremony record at all keeps the places that its root lists claim: a list that
// names no record is after no record, and sets are ordered by their sequence and their number.
func TestRootReturnsABundleWithNoRecordKeepsTheOrderThatItsListsClaim(t *testing.T) {
	m := memBundle(map[string][]byte{
		setN(1): seqList("1", kA, kB),
		setN(2): seqList("2", kB),
		setN(3): seqList("3", kA),
	})
	rep, err := runMem(t, m)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	// Only the list that brings the key back is a finding, and its place is known.
	wantReturnsAt(t, rep, setN(3)+" A")
	f := firstReturn(t, rep)
	if strings.Contains(f.Detail, "cannot be told") {
		t.Errorf("a set with a place is judged as a set with none: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "; "+wHeldPin(setN(1))) || !strings.Contains(f.Detail, wBefore(setN(2))) {
		t.Errorf("the detail is %q", f.Detail)
	}
	// And no key that stays or leaves is a finding.
	m = memBundle(map[string][]byte{setN(1): seqList("1", kA, kB), setN(2): seqList("2", kB), setN(3): seqList("3", kB)})
	rep, err = runMem(t, m)
	if err != nil {
		t.Fatal(err)
	}
	wantReturnsAt(t, rep)
}

// A bundle whose chain is walked is unchanged: when one record is on the chain, a record beside it
// whose predecessor is no record does not float the sets of the chain.
func TestRootReturnsARecordOffTheChainBesideAChainDoesNotFloatTheChain(t *testing.T) {
	b := chainBundle(t, true,
		cset{setN(1), seqList("1", kA, kB)},
		cset{setN(2), seqList("2", kB)},
		cset{setN(3), seqList("3", kA)},
	)
	// A record that follows no record is chain-broken; it lists a set of its own.
	b.apply(prev(digestA), withSet(setN(4), seqList("4", kK)))
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	has(t, rep, ChainBroken, "history/"+b.recs[3].folder)
	var at []string
	for _, f := range returnsOf(rep) {
		if f.Path == listPathOf(setN(3)) {
			at = append(at, f.Detail)
		}
	}
	if len(at) != 1 {
		t.Fatalf("%d findings at the third set: %v", len(at), lines(returnsOf(rep)))
	}
	if strings.Contains(at[0], "cannot be told") || !strings.Contains(at[0], wBefore(setN(2))) {
		t.Errorf("the third set has a place and the detail is %q", at[0])
	}
}
