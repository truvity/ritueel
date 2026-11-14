//go:build linux || darwin

package history

import (
	"slices"
	"strconv"
	"testing"
)

func TestCleanHistoriesOfEveryLength(t *testing.T) {
	for _, n := range []int{1, 2, 3, 10, 50} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			b := newBundle(t)
			for i := 0; i < n; i++ {
				b.apply()
			}
			rep := b.run()
			wantFindings(t, rep, nil)
			if rep.Records != n {
				t.Errorf("Records = %d, want %d", rep.Records, n)
			}
			last := b.recs[n-1].digest
			if !slices.Equal(rep.Ends, []string{last}) {
				t.Errorf("Ends = %v, want %v", rep.Ends, []string{last})
			}
			if want := "history: " + strconv.Itoa(n) + " ceremony records, end " + last[:8]; rep.EndLine() != want {
				t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
			}
			if !rep.Clean() {
				t.Error("Clean() = false")
			}
		})
	}
}

func TestFirstRecordHasNoPredecessorAndNoAnchor(t *testing.T) {
	b := newBundle(t)
	first := b.apply()
	if first.record.PrevRecordSHA256 != "" {
		t.Fatal("the builder gave the first record a predecessor")
	}
	if string(b.get("trust/"+first.set+"/root-list.json")) != `{"version":1}` {
		t.Fatalf("the first root list has an anchor: %s", b.get("trust/"+first.set+"/root-list.json"))
	}
	wantFindings(t, b.run(), nil)
}

func TestEmptyHistoryIsAReportOfNothing(t *testing.T) {
	b := newBundle(t)
	rep := b.run()
	wantFindings(t, rep, nil)
	if rep.Records != 0 || len(rep.Ends) != 0 {
		t.Errorf("Records %d, Ends %v; want 0 and none", rep.Records, rep.Ends)
	}
	if _, count, ok := rep.End(); ok || count != 0 {
		t.Errorf("End() = _, %d, %v; want 0, false", count, ok)
	}
	if want := "history: 0 ceremony records"; rep.EndLine() != want {
		t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
	}
	if !rep.Clean() {
		t.Error("Clean() = false")
	}
}

// A closing record is a member of the chain. The ceremony that stopped has no record, and the
// closing record lists the files of the trust set that the stopped ceremony left.
func TestClosingRecordIsPartOfAChain(t *testing.T) {
	b := newBundle(t)
	a := b.apply()
	stopped := b.unfinished()
	closing := b.closing(stopped, func(r *rec) {
		for p, data := range stopped.artifacts {
			r.artifacts[p] = data
		}
		r.refresh()
	})
	last := b.apply()
	rep := b.run()
	wantFindings(t, rep, nil)
	if rep.Records != 3 {
		t.Errorf("Records = %d, want 3 (the stopped ceremony has no record)", rep.Records)
	}
	if closing.record.PrevRecordSHA256 != a.digest || last.record.PrevRecordSHA256 != closing.digest {
		t.Fatal("the builder did not chain the records")
	}
	if !slices.Equal(rep.Ends, []string{last.digest}) {
		t.Errorf("Ends = %v, want %v", rep.Ends, []string{last.digest})
	}
}

// A bundle whose ceremony folders have no record.json has no record. The count says so, and a
// check that finds nothing does not pass for a check that found a whole history.
func TestCeremonyFoldersWithoutRecordsAreNotRecords(t *testing.T) {
	b := newBundle(t)
	b.apply(func(r *rec) { r.noRecord = true })
	b.apply(func(r *rec) { r.noRecord = true })
	b.mkdir("history/20269999T000000Z-apply")
	rep := b.run()
	if rep.Records != 0 {
		t.Errorf("Records = %d, want 0: no folder holds a record.json", rep.Records)
	}
	if len(rep.Ends) != 0 {
		t.Errorf("Ends = %v, want none", rep.Ends)
	}
	if want := "history: 0 ceremony records"; rep.EndLine() != want {
		t.Errorf("EndLine() = %q, want %q", rep.EndLine(), want)
	}
}
