//go:build linux || darwin

package history

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The most places at which the trust sets of a bundle stand, all sets together (MaxSetPlaces). A
// set that records list stands at one place for each different record before a record that lists
// it, and is judged at each place, so the work and the memory of the finding root-returns grow
// with the number of places. A run that meets more stops with ErrTooMuch and a sentence that names
// the limit. Below the limit nothing floats and nothing is dropped.

// placesBundle is a bundle in memory of records records in a chain, each listing the same sets
// sets, with the same bytes: every set stands at one place for each record, records places for
// each set.
func placesBundle(t testing.TB, sets, records int) *bundle {
	t.Helper()
	b := chainBundle(t, true)
	var cs []cset
	for i := 0; i < sets; i++ {
		cs = append(cs, cset{setN(i + 1), seqList(strconv.Itoa(i+1), kA)})
	}
	for r := 0; r < records; r++ {
		b.apply(withBytes(cs))
	}
	return b
}

// runPlaces runs the check with the limit of the places lowered to n.
func runPlaces(t testing.TB, b *bundle, n int) (*Report, error) {
	t.Helper()
	lim := limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode, setPlaces: n}
	return runFS(t, memFS{b.mem}, &lim)
}

// wantTooMuchPlaces fails unless the run ended with ErrTooMuch, no report and a sentence that names
// the limit that was set.
func wantTooMuchPlaces(t testing.TB, rep *Report, err error, limit int) {
	t.Helper()
	if !errors.Is(err, ErrTooMuch) || rep != nil {
		t.Errorf("limit %d: Check = %v, %v; want ErrTooMuch and no report", limit, rep, err)
		return
	}
	if !strings.Contains(err.Error(), "MaxSetPlaces") || !strings.Contains(err.Error(), strconv.Itoa(limit)) {
		t.Errorf("limit %d: the sentence %q does not name the limit", limit, err)
	}
}

func TestMaxSetPlacesIsTheDocumentedNumber(t *testing.T) {
	if MaxSetPlaces != 131072 {
		t.Errorf("MaxSetPlaces = %d, want 131072 (1 << 17)", MaxSetPlaces)
	}
	src, err := os.ReadFile("check.go")
	if err != nil {
		t.Fatal(err)
	}
	// The comment of the constant gives the number as the page of limits does.
	i := strings.Index(string(src), "// MaxSetPlaces is")
	if i < 0 {
		t.Fatal("check.go has no comment of MaxSetPlaces")
	}
	end := strings.Index(string(src)[i:], "MaxSetPlaces =")
	if end < 0 || !strings.Contains(string(src)[i:i+end], "131,072") {
		t.Errorf("the comment of MaxSetPlaces does not say 131,072")
	}
	doc, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatal(err)
	}
	_, listOfLimits, found := strings.Cut(string(doc), "# Limits")
	if !found || !strings.Contains(listOfLimits, "[MaxSetPlaces]") {
		t.Error("the list of limits of doc.go does not name MaxSetPlaces")
	}
	if !strings.Contains(string(doc), "[MaxSetPlaces] places") {
		t.Error("the paragraph of root-returns of doc.go does not name MaxSetPlaces")
	}
}

// A run that follows the limit exactly is accepted, and one place more is not.
func TestSetPlacesLimitBelowAtAndAboveTheLimit(t *testing.T) {
	for _, c := range []struct{ sets, records int }{
		{1, 1}, {1, 5}, {2, 1}, {3, 4}, {7, 3},
	} {
		places := c.sets * c.records
		t.Run(fmt.Sprintf("%d sets in %d records", c.sets, c.records), func(t *testing.T) {
			b := placesBundle(t, c.sets, c.records)
			for _, n := range []int{places + 1, places} {
				if rep, err := runPlaces(t, b, n); err != nil || rep == nil {
					t.Errorf("limit %d (%d places): Check = %v, %v", n, places, rep, err)
				}
			}
			for _, n := range []int{places - 1, 1} {
				if n < 1 || n >= places {
					continue
				}
				rep, err := runPlaces(t, b, n)
				wantTooMuchPlaces(t, rep, err, n)
			}
		})
	}
}

// A limit of 0 is the constant: the bundles of the tests above are far below it.
func TestSetPlacesLimitOfZeroIsTheConstant(t *testing.T) {
	b := placesBundle(t, 3, 4)
	if rep, err := runPlaces(t, b, 0); err != nil || rep == nil {
		t.Errorf("Check = %v, %v", rep, err)
	}
}

// A bundle that follows the rules has one place for each set, so a bundle of many sets is
// accepted at a limit of exactly its number of sets, and not at one less.
func TestSetPlacesABundleThatFollowsTheRulesStandsAtOnePlaceForEachSet(t *testing.T) {
	const n = 300
	var cs []cset
	for i := 0; i < n; i++ {
		cs = append(cs, cset{setN(i + 1), seqList(strconv.Itoa(i+1), kA)})
	}
	b := chainBundle(t, true, cs...)
	if rep, err := runPlaces(t, b, n); err != nil || rep == nil {
		t.Errorf("limit %d: Check = %v, %v", n, rep, err)
	}
	rep, err := runPlaces(t, b, n-1)
	wantTooMuchPlaces(t, rep, err, n-1)
	// The real limit is far away.
	if n*100 > MaxSetPlaces {
		t.Errorf("the test is no longer far below the limit")
	}
}

// The two files of a set that one record lists are one place, not two.
func TestSetPlacesTheFilesOfOneSetThatOneRecordListsAreOnePlace(t *testing.T) {
	b := chainBundle(t, true)
	b.apply(withSet(setN(1), seqList("1", kA)))
	if len(b.recs[0].artifacts) != 2 {
		t.Fatalf("the record lists %d files, the test wants two", len(b.recs[0].artifacts))
	}
	if rep, err := runPlaces(t, b, 1); err != nil || rep == nil {
		t.Errorf("limit 1: Check = %v, %v", rep, err)
	}
}

// A set that no record lists is not a place that a record notes: it is bounded by the names that
// one folder may hold, so it does not count against the limit.
func TestSetPlacesSetsThatNoRecordListsAreNotCounted(t *testing.T) {
	b := chainBundle(t, true, cset{setN(1), seqList("1", kA)}, cset{setN(2), seqList("2", kA)})
	for i := 3; i < 60; i++ {
		addList(b.mem, setN(i), seqList(strconv.Itoa(i), kA))
	}
	if rep, err := runPlaces(t, b, 2); err != nil || rep == nil {
		t.Errorf("limit 2 with 57 unlisted sets: Check = %v, %v", rep, err)
	}
}

// Two records of a fork that follow the same record and list a set are one place of it; two
// records that follow different records are two.
func TestSetPlacesTheRecordsOfAForkThatFollowOneRecordAreOnePlace(t *testing.T) {
	b := chainBundle(t, true, cset{setN(1), seqList("1", kA)})
	first := b.recs[0].digest
	b.apply(prev(first), withSet(setN(2), seqList("2", kA)))
	b.apply(prev(first), withSet(setN(2), seqList("2", kA)))
	// Places: set 1 after no record, set 2 after the first record, once.
	rep, err := runPlaces(t, b, 2)
	if err != nil || rep == nil {
		t.Fatalf("limit 2: Check = %v, %v", rep, err)
	}
	has(t, rep, Fork, "history/"+b.recs[0].folder)
	rep, err = runPlaces(t, b, 1)
	wantTooMuchPlaces(t, rep, err, 1)

	// The same set listed after two different records is two places.
	c := chainBundle(t, true, cset{setN(1), seqList("1", kA)}, cset{setN(2), seqList("2", kA)})
	c.apply(withSet(setN(1), seqList("1", kA)))
	if rep, err := runPlaces(t, c, 3); err != nil || rep == nil {
		t.Errorf("limit 3: Check = %v, %v", rep, err)
	}
	rep, err = runPlaces(t, c, 2)
	wantTooMuchPlaces(t, rep, err, 2)
}

// A closing record that lists a set notes a place of it like any other record.
func TestSetPlacesAClosingRecordThatListsASetIsOnePlace(t *testing.T) {
	m := chainBundle(t, true)
	m.apply(withSet(setN(1), seqList("1", kA)))
	stopped := m.unfinished(withSet(setN(2), seqList("2", kA)))
	m.closing(stopped, listsLeftover(stopped, nil))
	if rep, err := runPlaces(t, m, 2); err != nil || rep == nil {
		t.Fatalf("limit 2: Check = %v, %v", rep, err)
	}
	rep, err := runPlaces(t, m, 1)
	wantTooMuchPlaces(t, rep, err, 1)
}

// Below the limit nothing floats and nothing is dropped: the findings at the exact limit are the
// findings of the default limit, and a set at two places is judged at both.
func TestSetPlacesAtTheLimitTheFindingsAreTheOnesOfTheDefaultLimit(t *testing.T) {
	b := chainBundle(t, true,
		cset{setN(1), seqList("1", kA, kB)},
		cset{setN(2), seqList("2", kB)},
	)
	b.apply(withSet(setN(1), seqList("1", kA, kB)))
	b.apply(withSet(setN(2), seqList("2", kB)))
	want, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	// 2 sets at 2 places each; the record before the first is none, so the places are by the
	// records before the records that list a set: four records, four places for two sets.
	got, err := runPlaces(t, b, 4)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.Findings) != fmt.Sprint(want.Findings) {
		t.Errorf("findings at the limit:\n%v\nfindings at the default limit:\n%v", got.Findings, want.Findings)
	}
	wantReturnsAt(t, got, "1-aaaaaaaa A")
	for _, f := range returnsOf(got) {
		if strings.Contains(f.Detail, "cannot be told") {
			t.Errorf("a set at its places floats: %q", f.Detail)
		}
	}
	if rep, err := runPlaces(t, b, 3); !errors.Is(err, ErrTooMuch) || rep != nil {
		t.Errorf("limit 3: %v, %v", rep, err)
	}
}

// The bundle that the limit was made for: records that each list the same many sets. The most that
// the limit allows is accepted in a bounded time, and one place more stops the run.
func TestSetPlacesManyRecordsThatListManySetsAreBoundedAtTheRealLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 130,000 places")
	}
	const records, sets = 512, 256
	if records*sets != MaxSetPlaces {
		t.Fatalf("the test wants %d places, the limit is %d", records*sets, MaxSetPlaces)
	}
	b := placesBundle(t, sets, records)
	start := time.Now()
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("took %v", d)
	}
	checkReport(t, rep)
}

func TestSetPlacesOnePlaceMoreThanTheRealLimitStopsTheRun(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 130,000 places")
	}
	b := placesBundle(t, 257, 512)
	start := time.Now()
	rep, err := runMem(t, b.mem)
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("took %v", d)
	}
	wantTooMuchPlaces(t, rep, err, MaxSetPlaces)
}

// 200 records that each list 1,000 sets are 200,000 places; the old version of this case had no
// limit and took 577 MB. The run ends with the sentence and no report.
func TestSetPlacesTheCaseOfManyRecordsOfManySetsEndsWithTheLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 200,000 places")
	}
	b := placesBundle(t, 1000, 200)
	start := time.Now()
	rep, err := runMem(t, b.mem)
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("took %v", d)
	}
	wantTooMuchPlaces(t, rep, err, MaxSetPlaces)
}

// A record that lists a file of a set whose folder is not in trust/ notes no place: the folder is gone (the file is
// file-missing), so there is no root list to place, and the notes of the places are only for the sets that the check reads.
func TestSetPlacesAFileOfASetWhoseFolderIsGoneNotesNoPlace(t *testing.T) {
	b := placesBundle(t, 1, 5)
	b.mem.remove("trust/" + setN(1))
	rep, err := runPlaces(t, b, 1)
	if err != nil || rep == nil {
		t.Fatalf("limit 1: Check = %v, %v", rep, err)
	}
	has(t, rep, FileMissing, "trust/"+setN(1)+"/keys.txt")
	// The same bundle with the folder is five places.
	c := placesBundle(t, 1, 5)
	rep, err = runPlaces(t, c, 1)
	wantTooMuchPlaces(t, rep, err, 1)
}
