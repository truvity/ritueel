//go:build linux || darwin

package history

import (
	"fmt"
	"testing"
)

// FuzzInspectAdditions puts bytes into the root list and the name of a trust set that a stopped
// ceremony left, the attempt of a second stopped ceremony, and a record, in a bundle of clean
// ceremonies; a shape byte adds a closing record, a fork, a record that lists nothing, an entry of
// another type in place of attempt.json, and a set of any name. Whatever the bytes are: no
// panic, the run ends, and the four additions agree with what a second reader makes of the files
// (checkAdditions, run by checkInspectInvariants): Unfinished never hides an attempt with no
// record, Chain is the chain, Unlisted holds the sets that no record lists, and NewestListed is
// the last list that a record lists.
func FuzzInspectAdditions(f *testing.F) {
	ok := keyList
	f.Add(ok(3, kA), []byte(`{"version":1}`), []byte(`{`), "3-aaaaaaaa", uint8(0))
	f.Add(ok(3, kA), []byte(`{}`), []byte(``), "3-aaaaaaaa", uint8(1))
	f.Add(ok(3, kA), []byte(`{}`), []byte(``), "3-aaaaaaaa", uint8(2))
	f.Add(ok(3, kA), []byte(`{}`), []byte(``), "3-aaaaaaaa", uint8(4))
	f.Add(ok(3, kA), []byte(`{}`), []byte(``), "3-aaaaaaaa", uint8(8))
	f.Add(ok(3, kA), []byte(`{}`), []byte(``), "3-aaaaaaaa", uint8(16))
	f.Add(ok(3, kA), []byte(`{}`), []byte(``), "latest", uint8(37))
	f.Add(ok(3, kA), []byte(`{}`), []byte(``), "10-aaaaaaaa", uint8(31))
	f.Add([]byte(`{`), []byte(`null`), []byte(`[]`), "0-a", uint8(255))
	f.Add(rootsJSON(0, kA), []byte(`{}`), []byte(`{}`), "", uint8(7))
	f.Fuzz(func(t *testing.T, list, attempt, record []byte, set string, shape uint8) {
		if len(list)+len(attempt)+len(record)+len(set) > 1<<14 || len(set) > 64 {
			t.Skip("large")
		}
		b := chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kA)})
		first := b.recs[0]
		open := b.unfinished(withSet("3-aaaaaaaa", list), func(r *rec) {
			r.plan.TrustSequence = ptr(int64(3))
			r.refresh()
		})
		if shape&32 != 0 && set != "" {
			// A set of any name, as the bytes give it, that nothing lists.
			b.mem.put("trust/"+set+"/root-list.json", &mnode{kind: "file", data: list})
		}
		if shape&1 != 0 {
			b.closing(open, listsLeftover(open, nil))
		}
		if shape&2 != 0 {
			b.apply(prev(first.digest), noSet)
		}
		if shape&4 != 0 {
			b.unfinished(noSet)
		}
		if shape&8 != 0 {
			kind := []string{"link", "fifo", "dir", "file"}[int(shape>>6)%4]
			n := &mnode{kind: kind, data: attempt}
			if kind == "dir" {
				n.kids = map[string]*mnode{}
			}
			b.mem.put("history/"+open.folder+"/attempt.json", n)
		} else {
			b.mem.put("history/"+open.folder+"/attempt.json", &mnode{kind: "file", data: attempt})
		}
		if shape&16 != 0 && len(record) > 0 {
			b.mem.put(fmt.Sprintf("history/%s/record.json", b.recs[len(b.recs)-1].folder), &mnode{kind: "file", data: record})
		}
		checkInspectInvariants(t, b.mem)
	})
}
