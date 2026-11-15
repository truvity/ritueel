package ceremonytest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/ceremony/ceremonytest"
	"ritueel.id/ritueel/internal/history"
)

// cutState is what a bundle cut at one write holds.
type cutState struct {
	bundle, keys map[string]entry
	made         *ceremonytest.Made
	codes        []history.Code
	records      int
	unfinished   []string
}

func cutAt(t *testing.T, o ceremonytest.Options, n int) cutState {
	t.Helper()
	m := ceremonytest.AfterWrites(t, o, n)
	rep, in := check(t, m.Dir)
	return cutState{bundle: treeOf(t, m.Dir), keys: treeOf(t, m.KeyDir), made: m, codes: codes(rep), records: rep.Records, unfinished: in.Unfinished}
}

// What a cut leaves behind (record 0005, rules 10 to 12; record 0006, rules 33 and 45): nothing is
// deleted, the writer is stopped, and the check of the history finds nothing worse than the notice
// that a ceremony is unfinished and the notice of a leftover temporary name. For each n from 1 to the
// number of writes of the whole run, the bundle cut at the nth write:
//   - holds every file that the bundle cut at the write before held, with the same name and a size
//     that did not fall, except a temporary name that was renamed;
//   - has a finding for exactly what is on disk: unfinished-ceremony when a trust set stands and no
//     record does, unexpected-file when a temporary name does;
//   - is a whole bundle at the last write, and so for a number past it.
func TestAfterWritesLeavesWhatACutLeaves(t *testing.T) {
	o := ceremonytest.Options{}
	total := ceremonytest.Writes(t, o)
	if total < 60 || total > 200 {
		t.Fatalf("Writes = %d: the ceremony makes about 91 changing calls", total)
	}
	states := make([]cutState, total+1)
	t.Run("runs", func(t *testing.T) {
		for n := 1; n <= total; n++ {
			t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
				t.Parallel()
				states[n] = cutAt(t, o, n)
			})
		}
	})
	if t.Failed() {
		return
	}
	for n := 1; n <= total; n++ {
		s := states[n]
		var set, record bool
		var seen []string // leftover names in a place that the check walks
		for p := range s.bundle {
			parts := strings.Split(p, "/")
			if strings.HasSuffix(p, "/root-list.json") && strings.HasPrefix(p, "trust/") && !isLeftover(p) {
				set = true
			}
			if strings.HasSuffix(p, "/record.json") && !isLeftover(p) {
				record = true
			}
			if !isLeftover(p) {
				continue
			}
			// The first temporary name of the path decides where it stands.
			idx := slices.IndexFunc(parts, func(x string) bool { return strings.HasPrefix(strings.ToLower(x), ".rt-") })
			switch {
			case parts[0] == "history" && idx <= 2, parts[0] == "trust" && idx == 1:
				seen = append(seen, p)
			case parts[0] == "history" && idx == 3 && parts[2] == "wanted":
				seen = append(seen, p) // looked at only when the record of the folder was read
			}
		}
		var want []history.Code
		for _, p := range seen {
			if strings.Split(p, "/")[0] == "history" && len(strings.Split(p, "/")) > 3 && !record {
				continue // the copies of a ceremony with no record are not looked at
			}
			if !slices.Contains(want, history.UnexpectedFile) {
				want = append(want, history.UnexpectedFile)
			}
		}
		if set && !record {
			want = append(want, history.UnfinishedCeremony)
		}
		got := slices.Clone(s.codes)
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) && (len(got) != 0 || len(want) != 0) {
			t.Errorf("n=%d: the check finds %v, the files say %v (temporary names %v)", n, got, want, seen)
		}
		if record && s.records != 1 {
			t.Errorf("n=%d: a record and %d records counted", n, s.records)
		}
		if s.made.Set != "" {
			if _, ok := s.bundle["trust/"+s.made.Set+"/root-list.json"]; !ok {
				t.Errorf("n=%d: Set %s names no set", n, s.made.Set)
			}
		}
		if s.made.AttemptSHA256 != "" {
			if e, ok := s.bundle["history/"+s.made.Ceremony+"/attempt.json"]; !ok || e.sum != s.made.AttemptSHA256 {
				t.Errorf("n=%d: AttemptSHA256 names no attempt", n)
			}
		}
		if e, ok := s.bundle["history/"+s.made.Ceremony+"/plan.json"]; ok && e.sum != s.made.PlanSHA256 {
			t.Errorf("n=%d: PlanSHA256 is not the digest of plan.json", n)
		}
		if n == 1 {
			continue
		}
		// Every name that was there is there, under the name of the trust set that its digest makes
		// (the keys, and so the digest, differ from one run to the next), except a temporary name that
		// was renamed.
		prev := states[n-1]
		for _, pair := range [][2]map[string]entry{{prev.bundle, s.bundle}, {prev.keys, s.keys}} {
			have := map[string]entry{}
			for p, e := range pair[1] {
				have[setFolder.ReplaceAllString(p, "trust/N-*")] = e
			}
			// A temporary name is renamed into place by the next cut: the folder that held it holds
			// as many entries as before, whether the name still stands or its final name does.
			for _, why := range shrunk(pair[0], pair[1]) {
				t.Errorf("n=%d: %s", n, why)
			}
			for p, e := range pair[0] {
				if isLeftover(p) {
					continue
				}
				g, ok := have[setFolder.ReplaceAllString(p, "trust/N-*")]
				switch {
				case !ok:
					t.Errorf("n=%d: %s was there at n=%d and is gone", n, p, n-1)
				case g.dir != e.dir:
					t.Errorf("n=%d: %s changed between a file and a folder", n, p)
				}
			}
		}
	}
	// The first write makes the folder of the ceremony; the last leaves everything.
	whole := ceremonytest.Bundle(t, ceremonytest.Options{Step: ceremonytest.Recorded})
	wholeShape := shape(treeOf(t, whole.Dir))
	for _, n := range []int{total, total + 1, total + 40} {
		m := ceremonytest.AfterWrites(t, o, n)
		if got := shape(treeOf(t, m.Dir)); !slices.Equal(got, wholeShape) {
			t.Errorf("n=%d (writes %d): the bundle holds\n%v\nwant the whole\n%v", n, total, got, wholeShape)
		}
		if rep, _ := check(t, m.Dir); len(rep.Findings) != 0 || rep.Records != 1 {
			t.Errorf("n=%d: findings %v, %d records; want a clean history of one record", n, rep.Findings, rep.Records)
		}
		if m.Set == "" {
			t.Errorf("n=%d: Set is empty for a whole bundle", n)
		}
	}
	// The last cut that leaves anything out leaves out the flush of the folder only.
	if last := states[total-1]; len(last.bundle) < len(treeOf(t, whole.Dir))-1 {
		t.Errorf("the cut before the last write leaves %d entries, the whole has %d", len(last.bundle), len(treeOf(t, whole.Dir)))
	}
	// The first write is the making of the folder of the ceremony.
	if first := states[1]; len(first.bundle) < 1 || first.made.AttemptSHA256 != "" || first.records != 0 {
		t.Errorf("the first write leaves %v", first.bundle)
	}
}

// folderKey is the path of the folder that holds an entry, with a temporary name and the name of a
// trust set each written "*": the cuts are runs of their own, so the random temporary name of one
// is not that of the next, and a set that is made in a temporary folder is renamed to its number.
func folderKey(p string) string {
	parts := strings.Split(p, "/")
	parts = parts[:len(parts)-1]
	out := make([]string, len(parts))
	for i, x := range parts {
		switch {
		case strings.HasPrefix(strings.ToLower(x), ".rt-"):
			out[i] = "*"
		case i == 1 && parts[0] == "trust":
			out[i] = "*"
		default:
			out[i] = x
		}
	}
	return strings.Join(out, "/")
}

// shrunk says which folders hold fewer entries in cur (the cut after n writes) than in prev (the cut
// before it). A leftover temporary name is a name that the next cut renames: it is there, or the
// name that it becomes is, and no folder falls in the number of its entries.
func shrunk(prev, cur map[string]entry) []string {
	count := func(tree map[string]entry) map[string]int {
		out := map[string]int{}
		for p := range tree {
			out[folderKey(p)]++
		}
		return out
	}
	before, after := count(prev), count(cur)
	var out []string
	for k, n := range before {
		if after[k] < n {
			out = append(out, fmt.Sprintf("the folder %q held %d entries and now holds %d", k, n, after[k]))
		}
	}
	slices.Sort(out)
	return out
}

// shrunk takes a leftover temporary name as renamed by the next cut, and only a name that is gone
// with no name in its place as a loss.
func TestShrunkTreatsALeftoverAsRenamedByTheNextCut(t *testing.T) {
	file := entry{size: 5}
	dir := entry{dir: true}
	tree := func(paths ...string) map[string]entry {
		out := map[string]entry{}
		for _, p := range paths {
			if strings.HasSuffix(p, "/") {
				out[strings.TrimSuffix(p, "/")] = dir
			} else {
				out[p] = file
			}
		}
		return out
	}
	for _, tc := range []struct {
		name      string
		prev, cur map[string]entry
		lost      int
	}{
		{"a temporary file that stands again", tree("roots/A/", "roots/A/.rt-aaa"), tree("roots/A/", "roots/A/.rt-bbb"), 0},
		{"a temporary file renamed into place", tree("roots/A/", "roots/A/.rt-aaa"), tree("roots/A/", "roots/A/root.json"), 0},
		{"a temporary file renamed, and the next one begun", tree("roots/A/", "roots/A/.rt-aaa"), tree("roots/A/", "roots/A/root.json", "roots/A/.rt-ccc"), 0},
		{"a temporary file that is gone and no name is in its place", tree("roots/A/", "roots/A/.rt-aaa"), tree("roots/A/"), 1},
		{"a file that is gone", tree("roots/A/", "roots/A/root.json"), tree("roots/A/"), 1},
		{"a file replaced by another", tree("roots/A/", "roots/A/root.json"), tree("roots/A/", "roots/A/other.json"), 0},
		{"a temporary folder of a set renamed to the set", tree("trust/", "trust/.rt-aaa/", "trust/.rt-aaa/root-list.json"), tree("trust/", "trust/1-aaaaaaaa/", "trust/1-aaaaaaaa/root-list.json"), 0},
		{"a temporary folder of a set that lost its file", tree("trust/", "trust/.rt-aaa/", "trust/.rt-aaa/root-list.json"), tree("trust/", "trust/.rt-bbb/"), 1},
		{"a temporary folder of a set that is gone", tree("trust/", "trust/.rt-aaa/", "trust/.rt-aaa/root-list.json"), tree("trust/"), 2},
		{"a temporary name in capitals", tree("a/", "a/.RT-aaa"), tree("a/"), 1},
		{"nothing before", tree(), tree("a/"), 0},
	} {
		if got := shrunk(tc.prev, tc.cur); len(got) != tc.lost {
			t.Errorf("%s: %v, want %d folders that lost entries", tc.name, got, tc.lost)
		}
	}
}

// A cut in the middle of the write of a file leaves a temporary name beside the place of the file,
// holding the first half of the data: some n leave a temporary file, and they are only half written.
func TestAfterWritesLeavesAHalfWrittenTemporaryFile(t *testing.T) {
	o := ceremonytest.Options{}
	total := ceremonytest.Writes(t, o)
	found := 0
	for n := 1; n <= total; n++ {
		m := ceremonytest.AfterWrites(t, o, n)
		for p, e := range treeOf(t, m.Dir) {
			if isLeftover(p) && !e.dir {
				found++
				if e.size == 0 {
					continue // cut before the data
				}
				// The data is the first half of the file that is renamed into place later: it never
				// is a whole file of a record.
				if strings.HasSuffix(p, "record.json") {
					t.Errorf("n=%d: a half record at %s", n, p)
				}
			}
		}
		if found > 0 && n > 20 {
			break
		}
	}
	if found == 0 {
		t.Error("no cut left a temporary file: the cut in the middle of a write is not made")
	}
}

// A cut leaves no folder other than the bundle and the key directory: the key store writes only into
// the key directory, and a stopped run leaves no open handle that a removal of the folder would meet.
func TestAfterWritesCanBeRemoved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	m := ceremonytest.AfterWrites(t, ceremonytest.Options{Dir: dir}, 30)
	if err := os.RemoveAll(m.Dir); err != nil {
		t.Fatal(err)
	}
}

// AfterWrites with a number below 1 fails the test and writes nothing.
func TestAfterWritesRefusesNoWrites(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		dir := filepath.Join(t.TempDir(), "ca")
		msg := failsWith(t, func(tb testing.TB) { ceremonytest.AfterWrites(tb, ceremonytest.Options{Dir: dir}, n) })
		if !strings.Contains(msg, "at least 1") {
			t.Errorf("n=%d: message %q", n, msg)
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("n=%d: the bundle was made", n)
		}
	}
}

// Options.Step is the last step the cut run would reach: the writes of a run that ends at AtAttempt
// are fewer than those of a whole run, and a number past them leaves the bundle of that step.
func TestWritesAndAfterWritesFollowTheStep(t *testing.T) {
	prev := 0
	for _, step := range []ceremonytest.Step{ceremonytest.AtPlan, ceremonytest.AtAttempt, ceremonytest.AtFirstBirth, ceremonytest.AtBirths, ceremonytest.AtSignatures, ceremonytest.AtTranscript, ceremonytest.AtSet, ceremonytest.Recorded} {
		t.Run(step.String(), func(t *testing.T) {
			o := ceremonytest.Options{Step: step}
			n := ceremonytest.Writes(t, o)
			if n <= prev {
				t.Errorf("Writes = %d at %s, %d at the step before", n, step, prev)
			}
			prev = n
			plain := ceremonytest.Bundle(t, o)
			cut := ceremonytest.AfterWrites(t, o, n+5)
			if got, want := shape(treeOf(t, cut.Dir)), shape(treeOf(t, plain.Dir)); !slices.Equal(got, want) {
				t.Errorf("a cut past the writes holds\n%v\nthe bundle at the step holds\n%v", got, want)
			}
			if got, want := shape(treeOf(t, cut.KeyDir)), shape(treeOf(t, plain.KeyDir)); !slices.Equal(got, want) {
				t.Errorf("a cut past the writes: key directory %v, want %v", got, want)
			}
		})
	}
	// The zero step is the whole run.
	if a, b := ceremonytest.Writes(t, ceremonytest.Options{}), ceremonytest.Writes(t, ceremonytest.Options{Step: ceremonytest.Recorded}); a != b {
		t.Errorf("Writes of the zero step = %d, of Recorded = %d", a, b)
	}
}

// A cut after a key file and before its line: the key directory holds the key and the journal does
// not name it yet. Some n of a run leave a key file that no birth line names.
func TestSomeCutLeavesAKeyFileNoLineNames(t *testing.T) {
	o := ceremonytest.Options{Step: ceremonytest.AtBirths}
	total := ceremonytest.Writes(t, o)
	hit := false
	for n := 1; n <= total && !hit; n++ {
		m := ceremonytest.AfterWrites(t, o, n)
		keys := treeOf(t, m.KeyDir)
		c := filepath.Join(m.Dir, "history", m.Ceremony, "births.jsonl")
		if _, err := os.Stat(c); err != nil {
			continue
		}
		if lines(t, c) < len(keys) {
			hit = true
		}
	}
	if !hit {
		t.Error("no cut leaves a key file with no birth line: the cut of the journal is never between the key and its line")
	}
}

// The cut is at the call that is named: the first call of the run makes history/ and the cut at it
// leaves none; the second leaves it; the folder of the ceremony, the plan and the folder of the copies
// follow, one call at a time. The numbers are those of the changing calls of the writer of the
// bundle, in the order of record 0005, rule 10 (the plan and the copies come first).
func TestAfterWritesStopsAtTheCallThatIsNamed(t *testing.T) {
	c := "history/" + ceremonyName
	base := []string{"ritueel.yaml", "want", "want/roots", "want/roots/x509.yaml"}
	cases := []struct {
		n    int
		want []string
	}{
		{1, base},
		{2, append(slices.Clone(base), "history")},
		{3, append(slices.Clone(base), "history")},
		{4, append(slices.Clone(base), "history", c)},
		{5, append(slices.Clone(base), "history", c)},
		{9, append(slices.Clone(base), "history", c, c+"/plan.json")},
		{10, append(slices.Clone(base), "history", c, c+"/plan.json")},
		{11, append(slices.Clone(base), "history", c, c+"/plan.json", c+"/wanted")},
	}
	for _, tc := range cases {
		m := ceremonytest.AfterWrites(t, ceremonytest.Options{}, tc.n)
		var got []string
		for p := range treeOf(t, m.Dir) {
			got = append(got, p)
		}
		slices.Sort(got)
		want := slices.Clone(tc.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("n=%d: the bundle holds\n%v\nwant\n%v", tc.n, got, want)
		}
	}
	// n=6 to 8 are cuts in the writing of plan.json: a temporary name is there and the plan is not.
	for n := 6; n <= 8; n++ {
		m := ceremonytest.AfterWrites(t, ceremonytest.Options{}, n)
		tree := treeOf(t, m.Dir)
		if _, ok := tree[c+"/plan.json"]; ok {
			t.Errorf("n=%d: plan.json is there", n)
		}
		temp := 0
		for p := range tree {
			if isLeftover(p) {
				temp++
			}
		}
		if temp != 1 {
			t.Errorf("n=%d: %d temporary names, want 1", n, temp)
		}
	}
}
