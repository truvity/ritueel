//go:build linux || darwin

package history

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// cloneMem copies a bundle in memory, so that a fuzz run changes its own copy.
func cloneMem(n *mnode) *mnode {
	c := *n
	c.data = slices.Clone(n.data)
	if n.kids != nil {
		c.kids = make(map[string]*mnode, len(n.kids))
		for name, k := range n.kids {
			c.kids[name] = cloneMem(k)
		}
	}
	return &c
}

// FuzzCheckClosing takes the bytes of a closing record, of the plan and the attempt of the
// ceremony it closes, and of the two root lists around it, in a bundle that has an ordinary
// ceremony, a ceremony that stopped, a closing record that lists its set, and one ceremony after
// it. Whatever the bytes are: no error, no panic, every text is printable ASCII, and a finding of
// root-returns is the root list of a set of the bundle, in the form of the page.
func FuzzCheckClosing(f *testing.F) {
	b := newBundle(f)
	first := b.apply(withSet("1-aaaaaaaa", seqList("1", kA, kB)))
	stopped := b.unfinished(withSet("2-aaaaaaaa", seqList("2", kA, kB)), planNames(first.digest))
	b.apply(withSet("3-aaaaaaaa", seqList("3", kB)))
	closing := b.closing(stopped, listsLeftover(stopped, nil))
	last := b.apply(withSet("5-aaaaaaaa", seqList("5", kA)))
	root := loadMem(f, b.dir)
	paths := struct{ closing, plan, attempt, left, first, last string }{
		closing: "history/" + closing.folder + "/record.json",
		plan:    "history/" + stopped.folder + "/plan.json",
		attempt: "history/" + stopped.folder + "/attempt.json",
		left:    "trust/2-aaaaaaaa/root-list.json",
		first:   "trust/1-aaaaaaaa/root-list.json",
		last:    "trust/5-aaaaaaaa/root-list.json",
	}
	get := func(p string) []byte { return root.get(p).data }
	f.Add(get(paths.closing), get(paths.plan), get(paths.attempt), get(paths.left), get(paths.first), get(paths.last))
	f.Add([]byte(`{`), get(paths.plan), get(paths.attempt), get(paths.left), get(paths.first), get(paths.last))
	f.Add(get(paths.closing), []byte(`{}`), []byte(`{`), seqList("0", kA), get(paths.first), get(paths.last))
	f.Add(get(paths.closing), get(paths.plan), get(paths.attempt), []byte(`{`), seqList("1", kA, kB), seqList("5", kA, kB))
	_ = last
	f.Fuzz(func(t *testing.T, closingRec, plan, attempt, left, firstList, lastList []byte) {
		m := cloneMem(root)
		for p, data := range map[string][]byte{paths.closing: closingRec, paths.plan: plan, paths.attempt: attempt, paths.left: left, paths.first: firstList, paths.last: lastList} {
			m.put(p, &mnode{kind: "file", data: data})
		}
		spy, log := newSpy(memFS{m})
		rep, err := runFS(t, spy, nil)
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if len(log.changes) != 0 {
			t.Fatalf("calls that change the bundle: %v", log.changes)
		}
		checkReport(t, rep)
		for _, f := range returnsOf(rep) {
			if !strings.HasPrefix(f.Detail, `root key "`) || !strings.Contains(f.Detail, `" returns: its `) || !strings.Contains(f.Detail, wRule) && !strings.HasSuffix(f.Detail, "...") {
				t.Fatalf("the detail of %q has not the form of the page", f.Line())
			}
			if len(f.Detail) > maxDetail+len("...") {
				t.Fatalf("a detail of %d bytes", len(f.Detail))
			}
		}
		if slices.Contains(rep.Reasons(), RootReturns) != (len(returnsOf(rep)) > 0) {
			t.Fatalf("Reasons() = %v and %d findings", rep.Reasons(), len(returnsOf(rep)))
		}
	})
}

// Many records that list many sets: every set stands at the place of every record that lists it, and
// the run still ends in bounded time with the findings that the walk makes.
func TestRootReturnsManyRecordsThatListManySetsAreBounded(t *testing.T) {
	const records, sets = 200, 1000
	var names []string
	for i := 0; i < sets; i++ {
		names = append(names, fmt.Sprintf("%d-aaaaaaaa", i+1))
	}
	b := chainBundle(t, true)
	for r := 0; r < records; r++ {
		var cs []cset
		for i, name := range names {
			// The first half hold the key A, the others the key B; the sets of a record are listed in
			// the same bytes by every record, so that no record contradicts another.
			key := kA
			if i%2 == 1 {
				key = kB
			}
			cs = append(cs, cset{name, seqList(fmt.Sprint(i+1), key)})
		}
		b.apply(withBytes(cs))
	}
	start := time.Now()
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Errorf("took %v", d)
	}
	checkReport(t, rep)
	// Every set stands at every place, so the lists before it are the other sets: the keys of the
	// sets come back at each place. The run keeps 1,000 findings and counts the rest.
	if got := len(returnsOf(rep)); got == 0 || got > MaxFindingsPerCode {
		t.Errorf("%d findings kept, %d not shown", got, rep.Omitted)
	}
}

// withBytes makes a record list these sets with exactly these bytes (no anchor is added).
func withBytes(sets []cset) func(*rec) {
	return func(r *rec) {
		r.artifacts = map[string][]byte{}
		for _, s := range sets {
			r.artifacts["trust/"+s.name+"/root-list.json"] = s.list
			r.artifacts["trust/"+s.name+"/keys.txt"] = []byte("keys of " + s.name + "\n")
		}
		r.refresh()
	}
}
