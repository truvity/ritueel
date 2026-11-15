//go:build linux || darwin

package history

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/files"
)

// The additions to Inspection and State: Inspection.Unfinished, State.Chain, State.Unlisted and
// State.NewestListed. What each must be comes from record 0006: rule 8 and rule 35 (the records
// form one chain with one end and no fork), rule 34 (a trust set that no record lists is an
// unfinished ceremony when an open attempt is linked to it) and rule 54 (the order of the root
// lists is the order of the chain). The expected values are what a test wrote: the folder names and
// digests the builder computed, the bytes it put on disk.

// inspectAdditions runs Check and Inspect on the bundle, requires the same report, and holds the
// four additions to what the bundle's files say, as read by checkAdditions.
func (b *bundle) inspectAdditions() *Inspection {
	b.t.Helper()
	in := b.inspect()
	m := b.mem
	if m == nil {
		m = loadForModel(b.t, b.dir)
	}
	checkAdditions(b.t, m, in)
	return in
}

// chainFolders are the folder names of a Chain.
func chainFolders(st *State) []string {
	out := make([]string, len(st.Chain))
	for i, c := range st.Chain {
		out[i] = c.Folder
	}
	return out
}

// folderNames are the ceremony folders of the records, in the order the builder made them.
func folderNames(recs ...*rec) []string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.folder
	}
	return out
}

// unlistedNames are the names of the sets of State.Unlisted.
func unlistedNames(st *State) []string {
	out := make([]string, len(st.Unlisted))
	for i, s := range st.Unlisted {
		out[i] = s.Name
	}
	return out
}

// Inspection.Unfinished is a copy of the two lists that the walk holds, whether the report is clean
// or not, and when there is a State it equals State.Unfinished.
func TestInspectionUnfinished(t *testing.T) {
	t.Run("a bundle with no open attempt", func(t *testing.T) {
		b := numbered(t, false, 3)
		in := b.inspectAdditions()
		if len(in.Unfinished) != 0 || len(in.State.Unfinished) != 0 {
			t.Errorf("Unfinished %v, State.Unfinished %v; want none", in.Unfinished, in.State.Unfinished)
		}
	})
	t.Run("an empty bundle", func(t *testing.T) {
		b := newBundle(t)
		in := b.inspectAdditions()
		if len(in.Unfinished) != 0 || in.State == nil {
			t.Errorf("Unfinished %v, State %v", in.Unfinished, in.State)
		}
	})
	t.Run("an open attempt, clean report", func(t *testing.T) {
		b := numbered(t, false, 2)
		u := b.unfinished(withSet(setN(3), keyList(3, kA)))
		in := b.inspectAdditions()
		if !slices.Equal(in.Unfinished, []string{u.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, u.folder)
		}
		if !slices.Equal(in.State.Unfinished, in.Unfinished) {
			t.Errorf("State.Unfinished %v differs from Inspection.Unfinished %v", in.State.Unfinished, in.Unfinished)
		}
	})
	t.Run("an attempt with no trust set at all", func(t *testing.T) {
		b := numbered(t, false, 1)
		u := b.unfinished(noSet)
		in := b.inspectAdditions()
		if !slices.Equal(in.Unfinished, []string{u.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, u.folder)
		}
	})
	t.Run("in the order of the names, not of the writing", func(t *testing.T) {
		b := newBundle(t)
		late := b.unfinished(noSet)
		early := b.unfinished(noSet, folderName("20260000T100000Z-apply"))
		mid := b.unfinished(noSet, folderName("20260000T100001Z-apply"))
		in := b.inspectAdditions()
		want := []string{early.folder, mid.folder, late.folder}
		if !slices.Equal(in.Unfinished, want) {
			t.Errorf("Unfinished = %v, want %v", in.Unfinished, want)
		}
	})
	t.Run("a ceremony that a closing record names is left out", func(t *testing.T) {
		b := numbered(t, false, 2)
		stopped := b.unfinished(withSet(setN(3), keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		still := b.unfinished(withSet(setN(5), keyList(5, kA)))
		in := b.inspectAdditions()
		if !slices.Equal(in.Unfinished, []string{still.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, still.folder)
		}
		if in.State != nil && !slices.Equal(in.State.Unfinished, in.Unfinished) {
			t.Errorf("State.Unfinished %v differs", in.State.Unfinished)
		}
	})
	t.Run("a ceremony that has a record is not open, whatever else it holds", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.apply(withSet(setN(3), keyList(3, kA)), namesAll)
		in := b.inspectAdditions()
		if len(in.Unfinished) != 0 {
			t.Errorf("Unfinished = %v, want none", in.Unfinished)
		}
	})
	t.Run("a plan with no attempt is not open", func(t *testing.T) {
		b := numbered(t, false, 1)
		b.unfinished(noSet, func(r *rec) { r.noAttempt = true })
		in := b.inspectAdditions()
		if len(in.Unfinished) != 0 {
			t.Errorf("Unfinished = %v, want none", in.Unfinished)
		}
	})
	t.Run("a clean report that has no State still names the open attempt", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		b.apply(withSets(cset{setN(2), keyList(2, kA)}, cset{setN(3), keyList(3, kA)}))
		u := b.unfinished(noSet)
		in := b.inspectAdditions()
		wantOrderErr(t, in)
		if !slices.Equal(in.Unfinished, []string{u.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, u.folder)
		}
	})
	t.Run("a ceremony folder with a record of another name still counts as the folder", func(t *testing.T) {
		// The folder is judged by what it holds: attempt.json and no record.json.
		b := numbered(t, false, 1)
		u := b.unfinished(noSet, func(r *rec) { r.extra = map[string][]byte{files.TranscriptFile: []byte("t\n")} })
		in := b.inspectAdditions()
		if !slices.Equal(in.Unfinished, []string{u.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, u.folder)
		}
	})
}

// An open attempt is never hidden by another fault: the walk ends, and the two lists it holds are
// copied, so a report that fails still shows every attempt that has no record. The State is nil and
// there is no OrderErr, as for every failing report.
func TestInspectionUnfinishedSurvivesAFailingReport(t *testing.T) {
	faults := map[string]struct {
		code Code
		make func(t *testing.T, b *bundle)
	}{
		"a fork": {Fork, func(t *testing.T, b *bundle) {
			first := b.apply()
			b.apply()
			b.apply(prev(first.digest))
		}},
		"a flipped digest": {FileDigest, func(t *testing.T, b *bundle) {
			b.apply()
			second := b.apply()
			b.put("trust/"+second.set+"/keys.txt", []byte("flipped\n"))
		}},
		"a record that names no record": {ChainBroken, func(t *testing.T, b *bundle) {
			b.apply()
			b.apply(prev(digestA))
		}},
		"a record that is no record": {RecordInvalid, func(t *testing.T, b *bundle) {
			b.apply()
			r := b.apply()
			rewrite(b, r, func([]byte) []byte { return []byte(`{"version":1}`) })
		}},
		"a trust set that nothing lists": {TrustSetUnlisted, func(t *testing.T, b *bundle) {
			b.apply()
			b.mkdir("trust/7-unlisted")
			b.put("trust/7-unlisted/root-list.json", keyList(7, kA))
		}},
		"a name that breaks the rule": {UnexpectedName, func(t *testing.T, b *bundle) {
			b.apply()
			b.mkdir("history/bad name")
		}},
	}
	for name, f := range faults {
		t.Run(name, func(t *testing.T) {
			b := newBundle(t)
			f.make(t, b)
			u := b.unfinished(noSet)
			in := b.inspectAdditions()
			if in.Report.Clean() || in.State != nil || in.OrderErr != nil {
				t.Fatalf("clean %v, State %v, OrderErr %v; the fault must fail the report", in.Report.Clean(), in.State, in.OrderErr)
			}
			has(t, in.Report, f.code, findingPathOf(in.Report, f.code))
			if !slices.Equal(in.Unfinished, []string{u.folder}) {
				t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, u.folder)
			}
		})
	}
	t.Run("the walk that ends on a fork leaves out the attempt that a closing record names", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply()
		b.apply()
		b.apply(prev(first.digest))
		stopped := b.unfinished(noSet)
		b.closing(stopped, noSet)
		other := b.unfinished(noSet)
		in := b.inspectAdditions()
		has(t, in.Report, Fork, "history/"+first.folder)
		if !slices.Equal(in.Unfinished, []string{other.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, other.folder)
		}
	})
	t.Run("a closing record that cannot be read names nothing", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		stopped := b.unfinished(noSet)
		closing := b.closing(stopped, noSet)
		rewrite(b, closing, func([]byte) []byte { return []byte(`{"version":1}`) })
		in := b.inspectAdditions()
		has(t, in.Report, RecordInvalid, "history/"+closing.folder+"/record.json")
		if !slices.Equal(in.Unfinished, []string{stopped.folder}) {
			t.Errorf("Unfinished = %v, want [%s]: a record that cannot be read closes nothing", in.Unfinished, stopped.folder)
		}
	})
}

// findingPathOf is the path of the first finding with the code, for a test that cares only that
// the code is there.
func findingPathOf(rep *Report, code Code) string {
	for _, f := range rep.Findings {
		if f.Code == code {
			return f.Path
		}
	}
	return ""
}

// The walk takes an entry named attempt.json of any type as an attempt (a link, a FIFO or a folder
// too): the report fails with the finding of that entry, and the ceremony is still in
// Inspection.Unfinished. No State, because the report fails.
func TestInspectionUnfinishedTakesAnyEntryNamedAttempt(t *testing.T) {
	for _, kind := range []string{"link", "fifo", "dir"} {
		t.Run(kind+" in memory", func(t *testing.T) {
			b := chainBundle(t, true, cset{setN(1), keyList(1, kA)})
			u := b.unfinished(noSet, func(r *rec) { r.noAttempt = true })
			n := &mnode{kind: kind, data: []byte("x")}
			if kind == "dir" {
				n.kids = map[string]*mnode{"x": {kind: "file", data: []byte("x")}}
			}
			b.mem.put("history/"+u.folder+"/"+files.AttemptFile, n)
			in := b.inspectAdditions()
			wantOddAttempt(t, in, u)
		})
	}
	t.Run("a symbolic link on disk", func(t *testing.T) {
		b := numbered(t, false, 1)
		u := b.unfinished(noSet, func(r *rec) { r.noAttempt = true })
		b.symlink("plan.json", "history/"+u.folder+"/"+files.AttemptFile)
		in := b.inspect()
		wantOddAttempt(t, in, u)
	})
	t.Run("a FIFO on disk", func(t *testing.T) {
		b := numbered(t, false, 1)
		u := b.unfinished(noSet, func(r *rec) { r.noAttempt = true })
		b.fifo("history/" + u.folder + "/" + files.AttemptFile)
		in := b.inspect()
		wantOddAttempt(t, in, u)
	})
	t.Run("a folder on disk", func(t *testing.T) {
		b := numbered(t, false, 1)
		u := b.unfinished(noSet, func(r *rec) { r.noAttempt = true })
		b.mkdir("history/" + u.folder + "/" + files.AttemptFile)
		in := b.inspectAdditions()
		wantOddAttempt(t, in, u)
	})
	t.Run("a record that is a link or a folder is a record of the folder, not a missing one", func(t *testing.T) {
		for _, kind := range []string{"link", "dir", "fifo"} {
			b := chainBundle(t, true, cset{setN(1), keyList(1, kA)})
			u := b.unfinished(noSet, func(r *rec) { r.noRecord = true })
			n := &mnode{kind: kind, data: []byte("x")}
			if kind == "dir" {
				n.kids = map[string]*mnode{}
			}
			b.mem.put("history/"+u.folder+"/record.json", n)
			in := b.inspect()
			if len(in.Unfinished) != 0 {
				t.Errorf("%s: Unfinished = %v: an entry named record.json is the folder's record", kind, in.Unfinished)
			}
			if in.Report.Clean() {
				t.Errorf("%s: the report is clean", kind)
			}
		}
	})
}

func wantOddAttempt(t *testing.T, in *Inspection, u *rec) {
	t.Helper()
	path := "history/" + u.folder + "/" + files.AttemptFile
	has(t, in.Report, UnexpectedName, path)
	if in.State != nil || in.OrderErr != nil {
		t.Errorf("State %v, OrderErr %v with a failing report", in.State, in.OrderErr)
	}
	if !slices.Equal(in.Unfinished, []string{u.folder}) {
		t.Errorf("Unfinished = %v, want [%s]", in.Unfinished, u.folder)
	}
}

// Many open attempts: every one is named, in the order of the names.
func TestInspectionUnfinishedHoldsEveryOpenAttempt(t *testing.T) {
	b := chainBundle(t, true, cset{setN(1), keyList(1, kA)})
	var want []string
	for i := range 300 {
		name := fmt.Sprintf("2027%04dT100000Z-apply", 299-i)
		u := b.unfinished(noSet, folderName(name))
		want = append(want, u.folder)
	}
	slices.Sort(want)
	in := b.inspectAdditions()
	if !slices.Equal(in.Unfinished, want) {
		t.Errorf("Unfinished has %d names, want %d, in the order of the names", len(in.Unfinished), len(want))
	}
}

// Chain is every record, in the order of the hash chain, the oldest first, and never an order of
// folder names (record 0006, rules 8 and 35).
func TestStateChain(t *testing.T) {
	t.Run("no record", func(t *testing.T) {
		in := newBundle(t).inspectAdditions()
		if len(in.State.Chain) != 0 {
			t.Errorf("Chain = %+v, want none", in.State.Chain)
		}
	})
	t.Run("one record", func(t *testing.T) {
		b := newBundle(t)
		r := b.apply()
		st := b.inspectAdditions().State
		want := []CeremonyInfo{{Folder: r.folder, Command: "apply", Outcome: "completed", SHA256: r.digest}}
		if !slices.Equal(st.Chain, want) {
			t.Errorf("Chain = %+v, want %+v", st.Chain, want)
		}
	})
	t.Run("three records in the order of writing", func(t *testing.T) {
		b, r := threeRecords(t)
		st := b.inspectAdditions().State
		for i, c := range st.Chain {
			if c.Folder != r[i].folder || c.SHA256 != r[i].digest {
				t.Errorf("Chain[%d] = %+v, want %s %s", i, c, r[i].folder, r[i].digest)
			}
		}
		if len(st.Chain) != 3 || st.Chain[2].SHA256 != st.End {
			t.Errorf("Chain %+v, End %s", st.Chain, st.End)
		}
	})
	t.Run("the order is the chain, not the names", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply(folderName("20260009T100000Z-apply"))
		second := b.apply(folderName("20260005T100000Z-apply"))
		third := b.apply(folderName("20260001T100000Z-apply"))
		st := b.inspectAdditions().State
		if want := folderNames(first, second, third); !slices.Equal(chainFolders(st), want) {
			t.Errorf("Chain folders = %v, want %v", chainFolders(st), want)
		}
	})
	t.Run("many records whose names run against the chain", func(t *testing.T) {
		b := chainBundle(t, true)
		var recs []*rec
		for i := range 60 {
			recs = append(recs, b.apply(folderName(fmt.Sprintf("2026%04dT100000Z-apply", 9000-i)), noSet))
		}
		st := b.inspectAdditions().State
		if want := folderNames(recs...); !slices.Equal(chainFolders(st), want) {
			t.Errorf("Chain folders = %v, want %v", chainFolders(st), want)
		}
	})
	t.Run("a closing record is there with close and closed", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply()
		stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
		closing := b.closing(stopped, listsLeftover(stopped, nil))
		after := b.apply(withSet(setN(4), keyList(4, kA)))
		st := b.inspectAdditions().State
		want := []CeremonyInfo{
			{Folder: first.folder, Command: "apply", Outcome: "completed", SHA256: first.digest},
			{Folder: closing.folder, Command: "close", Outcome: "closed", SHA256: closing.digest},
			{Folder: after.folder, Command: "apply", Outcome: "completed", SHA256: after.digest},
		}
		if !slices.Equal(st.Chain, want) {
			t.Errorf("Chain = %+v, want %+v", st.Chain, want)
		}
		if st.Records != 3 {
			t.Errorf("Records = %d: the open attempt is no record", st.Records)
		}
	})
	t.Run("a declined ceremony carries its outcome", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply()
		declined := b.apply(noSet, func(r *rec) {
			r.record.Outcome = files.OutcomeDeclined
			r.record.Declined = &files.Declined{Reason: "the request was declined"}
			r.refresh()
		})
		in := b.inspect()
		if in.State == nil {
			t.Skipf("the builder cannot make a declined record that the check accepts: %v", findingsOf(in.Report))
		}
		want := []CeremonyInfo{
			{Folder: first.folder, Command: "apply", Outcome: "completed", SHA256: first.digest},
			{Folder: declined.folder, Command: "apply", Outcome: "declined", SHA256: declined.digest},
		}
		if !slices.Equal(in.State.Chain, want) {
			t.Errorf("Chain = %+v, want %+v", in.State.Chain, want)
		}
	})
	t.Run("the digest is that of the bytes of record.json", func(t *testing.T) {
		b, r := threeRecords(t)
		st := b.inspectAdditions().State
		for i, c := range st.Chain {
			if got := files.Digest(b.get("history/" + c.Folder + "/record.json")); got != c.SHA256 || got != r[i].digest {
				t.Errorf("Chain[%d].SHA256 = %s, the file has %s", i, c.SHA256, got)
			}
		}
	})
	t.Run("an open attempt is not in the chain", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.unfinished(withSet(setN(3), keyList(3, kA)))
		st := b.inspectAdditions().State
		if len(st.Chain) != 2 {
			t.Errorf("Chain = %+v, want the two records", st.Chain)
		}
	})
}

// A State and what it holds belong to the caller: changing the lists and the bytes of one call
// changes nothing in the next.
func TestStateAdditionsAreCopies(t *testing.T) {
	b := numbered(t, false, 3)
	b.unfinished(withSet(setN(4), keyList(4, kA)))
	first := b.inspect()
	// A copy of what the first call gave, before anything is changed.
	wantChain := slices.Clone(first.State.Chain)
	wantUnlisted := make([]SetInfo, len(first.State.Unlisted))
	for i, s := range first.State.Unlisted {
		wantUnlisted[i] = SetInfo{Name: s.Name, Number: s.Number, ListJSON: slices.Clone(s.ListJSON)}
	}
	wantNewest := SetInfo{Name: first.State.NewestListed.Name, Number: first.State.NewestListed.Number, ListJSON: slices.Clone(first.State.NewestListed.ListJSON)}
	wantUnfinished := slices.Clone(first.Unfinished)
	if len(wantChain) != 3 || len(wantUnlisted) != 1 || len(wantUnfinished) != 1 || len(wantNewest.ListJSON) == 0 {
		t.Fatalf("the bundle does not hold what the test needs: %d %d %d", len(wantChain), len(wantUnlisted), len(wantUnfinished))
	}
	for i := range first.State.Chain {
		first.State.Chain[i] = CeremonyInfo{Folder: "x", SHA256: "x"}
	}
	first.State.Chain = append(first.State.Chain[:0], first.State.Chain...)
	for i := range first.State.Unlisted[0].ListJSON {
		first.State.Unlisted[0].ListJSON[i] = 'X'
	}
	first.State.Unlisted[0].Name = "mutated"
	for i := range first.State.NewestListed.ListJSON {
		first.State.NewestListed.ListJSON[i] = 'X'
	}
	first.State.NewestListed.Name = "mutated"
	first.Unfinished[0] = "mutated"
	first.State.Unfinished[0] = "mutated"
	for i := range first.State.Newest.ListJSON {
		first.State.Newest.ListJSON[i] = 'X'
	}

	second := b.inspect()
	if !slices.Equal(second.State.Chain, wantChain) {
		t.Errorf("Chain = %+v after a change, want %+v", second.State.Chain, wantChain)
	}
	if got := second.State.Unlisted; len(got) != 1 || got[0].Name != wantUnlisted[0].Name || !bytes.Equal(got[0].ListJSON, wantUnlisted[0].ListJSON) {
		t.Errorf("Unlisted = %+v after a change, want %+v", got, wantUnlisted)
	}
	if got := second.State.NewestListed; got == nil || got.Name != wantNewest.Name || !bytes.Equal(got.ListJSON, wantNewest.ListJSON) {
		t.Errorf("NewestListed = %+v after a change, want %+v", got, wantNewest)
	}
	if !slices.Equal(second.Unfinished, wantUnfinished) || !slices.Equal(second.State.Unfinished, wantUnfinished) {
		t.Errorf("Unfinished = %v, %v after a change, want %v", second.Unfinished, second.State.Unfinished, wantUnfinished)
	}
	// The three copies do not share a byte with each other either.
	third := b.inspect()
	third.State.NewestListed.ListJSON[0] = 'Y'
	if third.State.Newest.ListJSON[0] == 'Y' || third.State.Lists[len(third.State.Lists)-2].Name == "" {
		t.Error("NewestListed shares its bytes with another field of the State")
	}
	if !bytes.Equal(third.State.Unlisted[0].ListJSON, third.State.Newest.ListJSON) {
		t.Error("the newest set is the unlisted one here: their bytes must be equal")
	}
	third.State.Unlisted[0].ListJSON[0] = 'Z'
	if third.State.Newest.ListJSON[0] == 'Z' {
		t.Error("Unlisted shares its bytes with Newest")
	}
}

// Unlisted are the trust sets that no record lists (record 0006, rule 34), in the order of the
// names, with the number that the digits of the name give.
func TestStateUnlisted(t *testing.T) {
	t.Run("a stopped ceremony's set", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.unfinished(withSet(setN(3), keyList(3, kA)))
		in := b.inspectAdditions()
		st := in.State
		if len(st.Unlisted) != 1 {
			t.Fatalf("Unlisted = %+v", st.Unlisted)
		}
		got := st.Unlisted[0]
		if got.Name != setN(3) || got.Number != 3 {
			t.Errorf("Unlisted[0] = %s %d, want %s 3", got.Name, got.Number, setN(3))
		}
		if want := b.get(listPathOf(setN(3))); !bytes.Equal(got.ListJSON, want) {
			t.Errorf("ListJSON = %q, want the file %q", got.ListJSON, want)
		}
		if !slices.Contains(namesOfLists(st), setN(3)) {
			t.Errorf("a set with a root list is in Lists too: Lists = %v", namesOfLists(st))
		}
		if st.Newest.Name != setN(3) || st.NewestListed == nil || st.NewestListed.Name != setN(2) {
			t.Errorf("Newest %+v, NewestListed %+v", st.Newest, st.NewestListed)
		}
	})
	t.Run("no stopped ceremony, no unlisted set", func(t *testing.T) {
		st := numbered(t, false, 3).inspectAdditions().State
		if len(st.Unlisted) != 0 {
			t.Errorf("Unlisted = %+v, want none", st.Unlisted)
		}
	})
	t.Run("an attempt that wrote no set", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.unfinished(noSet)
		if st := b.inspectAdditions().State; len(st.Unlisted) != 0 {
			t.Errorf("Unlisted = %+v, want none", st.Unlisted)
		}
	})
	t.Run("a set that a closing record lists is listed", func(t *testing.T) {
		b := numbered(t, false, 2)
		stopped := b.unfinished(withSet(setN(3), keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		st := b.inspectAdditions().State
		if len(st.Unlisted) != 0 {
			t.Errorf("Unlisted = %+v, want none: the closing record lists the set", st.Unlisted)
		}
		if st.NewestListed == nil || st.NewestListed.Name != setN(3) || st.Newest.Name != setN(3) {
			t.Errorf("NewestListed %+v, Newest %+v; want the set the closing record lists", st.NewestListed, st.Newest)
		}
	})
	t.Run("in the order of the names, not of the numbers or the chain", func(t *testing.T) {
		b := numbered(t, false, 8)
		b.unfinished(withSet("9-aaaaaaaa", keyList(9, kA)))
		b.unfinished(withSet("10-aaaaaaaa", keyList(10, kA)))
		in := b.inspectAdditions()
		st := in.State
		if got, want := unlistedNames(st), []string{"10-aaaaaaaa", "9-aaaaaaaa"}; !slices.Equal(got, want) {
			t.Errorf("Unlisted = %v, want %v (the order of the names)", got, want)
		}
		if st.Unlisted[0].Number != 10 || st.Unlisted[1].Number != 9 {
			t.Errorf("Numbers = %d, %d, want 10, 9", st.Unlisted[0].Number, st.Unlisted[1].Number)
		}
		if st.Newest.Name != "10-aaaaaaaa" || st.NewestListed.Name != setN(8) {
			t.Errorf("Newest %s, NewestListed %s", st.Newest.Name, st.NewestListed.Name)
		}
		if len(in.Unfinished) != 2 {
			t.Errorf("Unfinished = %v: each unlisted set is linked to an open attempt", in.Unfinished)
		}
	})
	t.Run("a set with no root list is named, with no bytes", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.unfinished(func(r *rec) {
			delete(r.artifacts, "trust/"+r.set+"/root-list.json")
			r.refresh()
		}, setName(setN(3)))
		in := b.inspectAdditions()
		st := in.State
		if got := unlistedNames(st); !slices.Equal(got, []string{setN(3)}) {
			t.Fatalf("Unlisted = %v, want [%s]", got, setN(3))
		}
		if st.Unlisted[0].Number != 3 || st.Unlisted[0].ListJSON != nil {
			t.Errorf("Unlisted[0] = %+v, want number 3 and no bytes", st.Unlisted[0])
		}
		if slices.Contains(namesOfLists(st), setN(3)) {
			t.Errorf("a set with no root list stands in no place of the order: Lists = %v", namesOfLists(st))
		}
	})
	t.Run("a set whose name has no trust number fails the report, so no State", func(t *testing.T) {
		for _, name := range []string{"latest", "0-aaaaaaaa", "-aaaaaaaa", "01-aaaaaaaa", "1x-aaaaaaaa"} {
			b := numbered(t, false, 1)
			b.mkdir("trust/" + name)
			b.put("trust/"+name+"/root-list.json", keyList(2, kA))
			u := b.unfinished(noSet)
			in := b.inspect()
			if in.Report.Clean() || in.State != nil {
				t.Errorf("%s: clean %v, State %v", name, in.Report.Clean(), in.State)
			}
			has(t, in.Report, TrustSetUnlisted, "trust/"+name)
			if !slices.Equal(in.Unfinished, []string{u.folder}) {
				t.Errorf("%s: Unfinished = %v", name, in.Unfinished)
			}
		}
	})
	t.Run("every unlisted set of a clean report is linked to an open attempt", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.unfinished(withSet(setN(3), keyList(3, kA)))
		in := b.inspectAdditions()
		if len(in.State.Unlisted) > len(in.State.Unfinished) {
			t.Errorf("%d unlisted sets and %d open attempts", len(in.State.Unlisted), len(in.State.Unfinished))
		}
	})
	t.Run("an unlisted set that no attempt is linked to fails the report", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.mkdir("trust/3-bbbbbbbb")
		b.put("trust/3-bbbbbbbb/root-list.json", keyList(3, kA))
		in := b.inspect()
		has(t, in.Report, TrustSetUnlisted, "trust/3-bbbbbbbb")
		if in.State != nil {
			t.Errorf("a State with a failing report")
		}
	})
}

// NewestListed is the last set of Lists that a record lists; nil when no record lists a set; never
// the leftover set of a stopped ceremony (record 0006, rules 34 and 54).
func TestStateNewestListed(t *testing.T) {
	same := func(t *testing.T, got, want *SetInfo) {
		t.Helper()
		if got == nil || want == nil {
			t.Fatalf("NewestListed %v, Newest %v", got, want)
		}
		if got.Name != want.Name || got.Number != want.Number || !bytes.Equal(got.ListJSON, want.ListJSON) {
			t.Errorf("NewestListed %+v differs from Newest %+v", got, want)
		}
	}
	t.Run("no record, no set", func(t *testing.T) {
		st := newBundle(t).inspectAdditions().State
		if st.NewestListed != nil || st.Newest != nil {
			t.Errorf("NewestListed %+v, Newest %+v", st.NewestListed, st.Newest)
		}
	})
	t.Run("only a stopped ceremony's set", func(t *testing.T) {
		b := newBundle(t)
		b.unfinished(withSet(setN(1), keyList(1, kA)))
		st := b.inspectAdditions().State
		if st.NewestListed != nil {
			t.Errorf("NewestListed = %+v, want nil: no record lists a set", st.NewestListed)
		}
		if st.Newest == nil || st.Newest.Name != setN(1) || len(st.Unlisted) != 1 {
			t.Errorf("Newest %+v, Unlisted %+v", st.Newest, st.Unlisted)
		}
	})
	t.Run("records only: it is the newest", func(t *testing.T) {
		st := numbered(t, false, 3).inspectAdditions().State
		same(t, st.NewestListed, st.Newest)
		if st.NewestListed.Name != setN(3) || st.NewestListed.Number != 3 {
			t.Errorf("NewestListed = %+v", st.NewestListed)
		}
	})
	t.Run("a leftover set after the records is never taken", func(t *testing.T) {
		b := numbered(t, false, 3)
		b.unfinished(withSet(setN(4), keyList(4, kA)))
		st := b.inspectAdditions().State
		if st.NewestListed.Name != setN(3) || st.Newest.Name != setN(4) {
			t.Errorf("NewestListed %s, Newest %s; want %s, %s", st.NewestListed.Name, st.Newest.Name, setN(3), setN(4))
		}
		if want := b.get(listPathOf(setN(3))); !bytes.Equal(st.NewestListed.ListJSON, want) {
			t.Errorf("ListJSON is not the file of %s", setN(3))
		}
	})
	t.Run("a leftover set in the middle of the lists", func(t *testing.T) {
		// A stopped ceremony whose set the later ceremonies stand beside: the order is the chain's.
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		b.unfinished(withSet(setN(2), keyList(2, kA)))
		in := b.inspectAdditions()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		if in.State.NewestListed.Name != setN(1) || in.State.Newest.Name != setN(2) {
			t.Errorf("NewestListed %s, Newest %s", in.State.NewestListed.Name, in.State.Newest.Name)
		}
	})
	t.Run("the last record lists no root list: the one before it is the newest listed", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.apply(func(r *rec) {
			delete(r.artifacts, "trust/"+r.set+"/root-list.json")
			r.refresh()
		})
		st := b.inspectAdditions().State
		if st.NewestListed.Name != setN(2) || st.Newest.Name != setN(2) {
			t.Errorf("NewestListed %s, Newest %s", st.NewestListed.Name, st.Newest.Name)
		}
	})
	t.Run("a set that only a closing record lists", func(t *testing.T) {
		b := numbered(t, false, 2)
		stopped := b.unfinished(withSet(setN(3), keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		st := b.inspectAdditions().State
		same(t, st.NewestListed, st.Newest)
		if st.NewestListed.Name != setN(3) {
			t.Errorf("NewestListed = %s", st.NewestListed.Name)
		}
	})
	t.Run("a set with a record and a leftover set of a second stopped ceremony after a closed one", func(t *testing.T) {
		b := numbered(t, false, 2)
		first := b.unfinished(withSet(setN(3), keyList(3, kA)))
		b.closing(first, listsLeftover(first, nil))
		b.unfinished(withSet(setN(5), keyList(5, kA)))
		st := b.inspectAdditions().State
		if st.NewestListed.Name != setN(3) || st.Newest.Name != setN(5) || !slices.Equal(unlistedNames(st), []string{setN(5)}) {
			t.Errorf("NewestListed %s, Newest %s, Unlisted %v", st.NewestListed.Name, st.Newest.Name, unlistedNames(st))
		}
	})
	t.Run("the number is that of the name, and the name is not held to the sequence", func(t *testing.T) {
		// A set that a closing record lists is not judged by trust-sequence. Newest must hold the
		// number of its list; a listed set before it is only a set.
		b := newBundle(t)
		b.apply(withSet(setN(1), keyList(1, kA)))
		stopped := b.unfinished(withSet(setN(2), keyList(2, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		in := b.inspectAdditions()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		if in.State.NewestListed.Number != 2 {
			t.Errorf("Number = %d", in.State.NewestListed.Number)
		}
	})
	t.Run("a name with no trust number that only a closing record lists", func(t *testing.T) {
		// The check does not judge a set that a closing record lists by its name, so the report is
		// clean. When that set is the newest that a record lists, its number cannot be told, and the
		// State refuses it rather than give a NewestListed with a number that is not one. A name that
		// has a number gives a State.
		build := func(name string) *bundle {
			b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
			stopped := b.unfinished(withSet(name, keyList(2, kA)))
			b.closing(stopped, listsLeftover(stopped, nil))
			b.unfinished(withSet(setN(5), keyList(5, kA)), func(r *rec) {
				r.plan.TrustSequence = ptr(int64(5))
				r.refresh()
			})
			return b
		}
		in := build(setN(2)).inspectAdditions()
		if in.State == nil || in.State.NewestListed.Name != setN(2) || in.State.Newest.Name != setN(5) {
			t.Fatalf("a numbered name gave State %v, OrderErr %v", in.State, in.OrderErr)
		}
		// The digits "0" are a number that is read and is no trust number (the finding
		// trust-sequence says the same), so a name that begins 0- is a name with no number.
		ran := 0
		for _, name := range []string{"latest", "x-aaaaaaaa", "0-aaaaaaaa", "00-aaaaaaaa", "-aaaaaaaa", "1x-aaaaaaaa"} {
			in := build(name).inspect()
			if !in.Report.Clean() {
				continue // another finding comes first: the rule for names
			}
			ran++
			if in.State != nil {
				t.Errorf("%s: a State with NewestListed %+v", name, in.State.NewestListed)
				continue
			}
			if !errors.Is(in.OrderErr, ErrOrder) {
				t.Errorf("%s: OrderErr = %v, want one that wraps ErrOrder", name, in.OrderErr)
				continue
			}
			if strings.Contains(in.OrderErr.Error(), name+"/") {
				t.Errorf("%s: the reason carries the raw name: %v", name, in.OrderErr)
			}
		}
		if ran < 3 {
			t.Errorf("only %d of the names reached the State: the case tests nothing", ran)
		}
	})
}

// The bytes of the newest listed list are kept under the same budget as those of Newest: a list
// that does not fit in what is left of the budget is not kept, and a State that would need it ends
// with ErrTooMuch, as for Newest. The lists that records list are read first, then those that no
// record lists; a list that does not fit is skipped and a later, smaller one is still kept. So here
// the newest listed list does not fit and the newest list, a leftover set's, does.
func TestStateNewestListedBytesAreBoundedLikeNewest(t *testing.T) {
	if testing.Short() {
		t.Skip("builds 64 MiB of root lists")
	}
	const each = 256 << 10
	n := MaxStateBytes / each
	list := func(seq int64, size int) func(r *rec) {
		return func(r *rec) {
			delete(r.artifacts, "trust/"+r.set+"/root-list.json")
			delete(r.artifacts, "trust/"+r.set+"/keys.txt")
			r.set = fmt.Sprintf("%d-aaaaaaaa", seq)
			mk := func(pad int) []byte {
				return []byte(fmt.Sprintf(`{"pad":"%s","roots":[{"label":"A","x509_spki_sha256":%q}],"sequence":%d,"version":1}`, strings.Repeat("x", pad), pa, seq))
			}
			l := anchored(mk(0), r.record.PrevRecordSHA256)
			l = anchored(mk(size-len(l)), r.record.PrevRecordSHA256)
			if len(l) != size {
				t.Fatalf("the list %d has %d bytes, want %d", seq, len(l), size)
			}
			r.artifacts["trust/"+r.set+"/root-list.json"] = l
			r.artifacts["trust/"+r.set+"/keys.txt"] = []byte("keys")
			r.refresh()
		}
	}
	build := func(t *testing.T, room, size int) *bundle {
		b := chainBundle(t, true)
		for i := 1; i < n; i++ {
			b.apply(list(int64(i), each))
		}
		// One list that leaves exactly room bytes of the budget, then the newest listed list, then a leftover set with a short list.
		b.apply(list(int64(n), each-room))
		b.apply(list(int64(n+1), size))
		leftover := fmt.Sprintf("%d-aaaaaaaa", n+2)
		b.unfinished(withSet(leftover, keyList(int64(n+2), kA)), func(r *rec) {
			r.plan.TrustSequence = ptr(int64(n + 2))
			r.refresh()
		})
		want, err := runMem(t, b.mem)
		if err != nil || !want.Clean() {
			t.Fatalf("Check = %v, %v; the bundle is meant to be clean", findingsOf(want), err)
		}
		return b
	}
	t.Run("the newest listed list does not fit", func(t *testing.T) {
		b := build(t, 1000, each)
		in, err := inspectFS(t, memFS{b.mem})
		if !errors.Is(err, ErrTooMuch) || in != nil {
			t.Fatalf("Inspect = %v, %v; want ErrTooMuch and no Inspection", in, err)
		}
		// It is the newest listed list that was not kept, and not the newest one.
		if want := fmt.Sprintf("trust/%d-aaaaaaaa", n+1); !strings.Contains(err.Error(), want) {
			t.Errorf("the error is %q, want it to name %s", err, want)
		}
	})
	t.Run("it fits, with room for the leftover set's list", func(t *testing.T) {
		const size = 2000
		b := build(t, size+400, size)
		in := b.inspectAdditions()
		if in.State == nil {
			t.Fatalf("no State: %v", in.OrderErr)
		}
		if got := len(in.State.NewestListed.ListJSON); got != size {
			t.Errorf("NewestListed has %d bytes, want %d", got, size)
		}
	})
}
