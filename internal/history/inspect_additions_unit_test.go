//go:build linux || darwin

package history

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The two helpers that build the additions of a State work from what the walk collected. A walk of
// a bundle that is clean cannot reach their refusals (a record that is not on the chain, or two
// records at one depth, is a finding), so a checker is made by hand here and the helpers are
// called on it: each refusal is one sentence, and an error is a fault of the run.

// handChecker is a checker with the maps of a walk, and no file system.
func handChecker() *checker {
	return &checker{
		onChain: map[string]bool{},
		depth:   map[string]int{},
		listed:  map[string]*anchorWant{},
		sets:    map[string]bool{},
	}
}

// addRec puts a record on the chain at a depth.
func (ck *checker) addRec(folder, digest, command, outcome string, depth int) {
	ck.recs = append(ck.recs, recInfo{folder: folder, digest: digest, parsed: true, command: command, outcome: outcome})
	ck.onChain[digest] = true
	ck.depth[digest] = depth
}

func TestChainAndUnlistedOrdersByDepth(t *testing.T) {
	ck := handChecker()
	// The names run against the chain, and the records are in the order of the names.
	ck.addRec("a-apply", "dc", "apply", "completed", 2)
	ck.addRec("b-close", "db", "close", "closed", 1)
	ck.addRec("c-apply", "da", "apply", "declined", 0)
	st := &State{Records: 3}
	if why := ck.chainAndUnlisted(st); why != "" {
		t.Fatalf("why = %q", why)
	}
	want := []CeremonyInfo{
		{"c-apply", "apply", "declined", "da"},
		{"b-close", "close", "closed", "db"},
		{"a-apply", "apply", "completed", "dc"},
	}
	if !slices.Equal(st.Chain, want) {
		t.Errorf("Chain = %+v, want %+v", st.Chain, want)
	}
}

func TestChainAndUnlistedRefusesWhatIsNotOneLine(t *testing.T) {
	t.Run("a record that is not on the chain", func(t *testing.T) {
		ck := handChecker()
		ck.addRec("a", "da", "apply", "completed", 0)
		ck.recs = append(ck.recs, recInfo{folder: "b", digest: "db", parsed: true})
		why := ck.chainAndUnlisted(&State{Records: 2})
		if !strings.Contains(why, "does not hold every record") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("a record that could not be read", func(t *testing.T) {
		ck := handChecker()
		ck.addRec("a", "da", "apply", "completed", 0)
		ck.recs = append(ck.recs, recInfo{folder: "b", digest: "db"})
		ck.onChain["db"] = true
		ck.depth["db"] = 1
		if why := ck.chainAndUnlisted(&State{Records: 2}); !strings.Contains(why, "does not hold every record") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("more on the chain than the report counted", func(t *testing.T) {
		ck := handChecker()
		ck.addRec("a", "da", "apply", "completed", 0)
		ck.addRec("b", "db", "apply", "completed", 1)
		if why := ck.chainAndUnlisted(&State{Records: 1}); !strings.Contains(why, "does not hold every record") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("two records at one depth", func(t *testing.T) {
		ck := handChecker()
		ck.addRec("a", "da", "apply", "completed", 0)
		ck.addRec("b", "db", "apply", "completed", 1)
		ck.addRec("c", "dc", "apply", "completed", 1)
		why := ck.chainAndUnlisted(&State{Records: 3})
		if !strings.Contains(why, "one line") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("a depth that does not start at 0", func(t *testing.T) {
		ck := handChecker()
		ck.addRec("a", "da", "apply", "completed", 1)
		if why := ck.chainAndUnlisted(&State{Records: 1}); !strings.Contains(why, "one line") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("a gap in the depths", func(t *testing.T) {
		ck := handChecker()
		ck.addRec("a", "da", "apply", "completed", 0)
		ck.addRec("b", "db", "apply", "completed", 2)
		if why := ck.chainAndUnlisted(&State{Records: 2}); !strings.Contains(why, "one line") {
			t.Errorf("why = %q", why)
		}
	})
	t.Run("no record at all", func(t *testing.T) {
		st := &State{}
		if why := handChecker().chainAndUnlisted(st); why != "" || len(st.Chain) != 0 {
			t.Errorf("why %q, Chain %+v", why, st.Chain)
		}
	})
}

func TestChainAndUnlistedUnlistedSets(t *testing.T) {
	ck := handChecker()
	ck.setNames = []string{"9-b", "10-a", "2-c", "1-listed"}
	ck.listed["1-listed"] = &anchorWant{}
	ck.rootLists = []setList{
		{set: "10-a", read: &anchorOf{raw: []byte("ten")}},
		{set: "9-b", read: &anchorOf{}}, // read, but the bytes were not kept
		{set: "1-listed", read: &anchorOf{raw: []byte("one")}},
	}
	st := &State{}
	if why := ck.chainAndUnlisted(st); why != "" {
		t.Fatalf("why = %q", why)
	}
	want := []SetInfo{
		{Name: "10-a", Number: 10, ListJSON: []byte("ten")},
		{Name: "2-c", Number: 2},
		{Name: "9-b", Number: 9},
	}
	if len(st.Unlisted) != len(want) {
		t.Fatalf("Unlisted = %+v, want %+v", st.Unlisted, want)
	}
	for i, w := range want {
		g := st.Unlisted[i]
		if g.Name != w.Name || g.Number != w.Number || string(g.ListJSON) != string(w.ListJSON) || (w.ListJSON == nil) != (g.ListJSON == nil) {
			t.Errorf("Unlisted[%d] = %+v, want %+v", i, g, w)
		}
	}
	// The bytes are a copy of what the walk holds.
	st.Unlisted[0].ListJSON[0] = 'X'
	if string(ck.rootLists[0].read.raw) != "ten" {
		t.Error("ListJSON shares its bytes with the walk")
	}
	t.Run("a name with no trust number", func(t *testing.T) {
		ck := handChecker()
		ck.setNames = []string{"1-a", "latest"}
		why := ck.chainAndUnlisted(&State{})
		if !strings.Contains(why, "no trust number") {
			t.Errorf("why = %q", why)
		}
		if strings.Contains(why, "trust/latest/") || strings.Contains(why, "\n") {
			t.Errorf("the reason carries a raw name: %q", why)
		}
	})
	t.Run("a set that has no root list", func(t *testing.T) {
		ck := handChecker()
		ck.setNames = []string{"1-a"}
		st := &State{}
		if why := ck.chainAndUnlisted(st); why != "" || len(st.Unlisted) != 1 || st.Unlisted[0].ListJSON != nil {
			t.Errorf("why %q, Unlisted %+v", why, st.Unlisted)
		}
	})
	t.Run("a root list that could not be read", func(t *testing.T) {
		ck := handChecker()
		ck.setNames = []string{"1-a"}
		ck.rootLists = []setList{{set: "1-a"}}
		st := &State{}
		if why := ck.chainAndUnlisted(st); why != "" || len(st.Unlisted) != 1 || st.Unlisted[0].ListJSON != nil {
			t.Errorf("why %q, Unlisted %+v", why, st.Unlisted)
		}
	})
}

func TestNewestListedFromTheLists(t *testing.T) {
	lists := func(names ...string) []RootList {
		out := make([]RootList, len(names))
		for i, n := range names {
			out[i] = RootList{Name: n}
		}
		return out
	}
	mk := func(listed ...string) *checker {
		ck := handChecker()
		for _, n := range []string{"1-a", "2-b", "3-c"} {
			ck.rootLists = append(ck.rootLists, setList{set: n, read: &anchorOf{raw: []byte("list " + n)}})
		}
		for _, n := range listed {
			ck.listed[n] = &anchorWant{}
		}
		return ck
	}
	t.Run("the last listed list", func(t *testing.T) {
		st := &State{Lists: lists("1-a", "2-b", "3-c")}
		if why, err := mk("1-a", "2-b").newestListed(st); why != "" || err != nil {
			t.Fatalf("why %q, err %v", why, err)
		}
		if st.NewestListed == nil || st.NewestListed.Name != "2-b" || st.NewestListed.Number != 2 || string(st.NewestListed.ListJSON) != "list 2-b" {
			t.Errorf("NewestListed = %+v", st.NewestListed)
		}
	})
	t.Run("the order of Lists is the order, not the order of the reads", func(t *testing.T) {
		st := &State{Lists: lists("3-c", "1-a", "2-b")}
		if why, err := mk("1-a", "3-c").newestListed(st); why != "" || err != nil {
			t.Fatalf("why %q, err %v", why, err)
		}
		if st.NewestListed.Name != "1-a" {
			t.Errorf("NewestListed = %+v, want 1-a: the last of Lists that is listed", st.NewestListed)
		}
	})
	t.Run("none listed", func(t *testing.T) {
		st := &State{Lists: lists("1-a", "2-b")}
		if why, err := mk().newestListed(st); why != "" || err != nil || st.NewestListed != nil {
			t.Errorf("why %q, err %v, NewestListed %+v", why, err, st.NewestListed)
		}
	})
	t.Run("a name with no trust number", func(t *testing.T) {
		ck := mk("2-b")
		ck.rootLists = append(ck.rootLists, setList{set: "latest", read: &anchorOf{raw: []byte("x")}})
		ck.listed["latest"] = &anchorWant{}
		st := &State{Lists: lists("1-a", "latest")}
		why, err := ck.newestListed(st)
		if err != nil || !strings.Contains(why, "no trust number") || st.NewestListed != nil {
			t.Errorf("why %q, err %v, NewestListed %+v", why, err, st.NewestListed)
		}
	})
	t.Run("the bytes were not kept", func(t *testing.T) {
		ck := mk("1-a", "2-b")
		ck.rootLists[1].read.raw = nil
		st := &State{Lists: lists("1-a", "2-b")}
		_, err := ck.newestListed(st)
		if !errors.Is(err, ErrTooMuch) || st.NewestListed != nil {
			t.Errorf("err %v, NewestListed %+v", err, st.NewestListed)
		}
		ck.rootLists[1].read = nil
		if _, err := ck.newestListed(&State{Lists: lists("1-a", "2-b")}); !errors.Is(err, ErrTooMuch) {
			t.Errorf("a list that was not read: err %v", err)
		}
	})
	t.Run("a copy of the bytes", func(t *testing.T) {
		ck := mk("1-a")
		st := &State{Lists: lists("1-a")}
		if _, err := ck.newestListed(st); err != nil {
			t.Fatal(err)
		}
		st.NewestListed.ListJSON[0] = 'X'
		if string(ck.rootLists[0].read.raw) != "list 1-a" {
			t.Error("ListJSON shares its bytes with the walk")
		}
	})
}

// unfinishedFolders is the two lists of the walk: a candidate that no closing record names, in the
// order of the names, and a copy.
func TestUnfinishedFoldersIsTheCandidatesThatNoClosingRecordNames(t *testing.T) {
	ck := handChecker()
	ck.candidates = []string{"d", "a", "c", "b"}
	ck.closed = map[string]struct{}{"c": {}, "zz": {}}
	got := ck.unfinishedFolders()
	if want := []string{"a", "b", "d"}; !slices.Equal(got, want) {
		t.Errorf("unfinishedFolders = %v, want %v", got, want)
	}
	if !slices.Equal(ck.candidates, []string{"d", "a", "c", "b"}) {
		t.Errorf("the candidates of the walk were reordered: %v", ck.candidates)
	}
	if got := handChecker().unfinishedFolders(); len(got) != 0 {
		t.Errorf("unfinishedFolders = %v with no candidate", got)
	}
}
