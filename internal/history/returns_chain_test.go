//go:build linux || darwin

package history

import (
	"bytes"
	"testing"
)

// Bundles whose trust sets are listed by ceremony records, for the finding root-returns. The order
// of the root lists is the order of the hash chain of the records (record 0006, rules 8, 14 and
// 54), so a test that wants a known order of lists builds a chain: one ceremony for each list, in
// the order the test gives them, each ceremony writing one trust set.

// cset is one ceremony of a chain: the name of the trust set it writes (setN(position) when
// empty) and the bytes of its root list. The member last_record_sha256 is put in front of the
// list when the ceremony has a record before it, so that a test writes a list as it writes any
// other and the anchor of the list agrees with the record.
type cset struct {
	name string
	list []byte
}

// anchored puts the member last_record_sha256 at the front of the root list list. It leaves the
// bytes as they are when they have no object to put it in, or have the member already.
func anchored(list []byte, last string) []byte {
	if last == "" || !bytes.HasPrefix(list, []byte("{")) || bytes.Contains(list, []byte(`"last_record_sha256"`)) {
		return list
	}
	rest := list[1:]
	member := `"last_record_sha256":"` + last + `"`
	if bytes.HasPrefix(bytes.TrimLeft(rest, " \t\r\n"), []byte("}")) {
		return append([]byte("{"+member), rest...)
	}
	return append([]byte("{"+member+","), rest...)
}

// chainBundle builds a bundle of one apply ceremony for each set, on disk or, with mem, in memory.
func chainBundle(t testing.TB, mem bool, sets ...cset) *bundle {
	t.Helper()
	b := newBundle(t)
	if mem {
		b = &bundle{t: t, mem: newMem()}
		b.put("ritueel.yaml", []byte("name: test\n"))
		b.mkdir("history")
	}
	for i, s := range sets {
		name := s.name
		if name == "" {
			name = setN(i + 1)
		}
		b.apply(withSet(name, s.list))
	}
	return b
}

// withSet makes the ceremony write the trust set name with this root list, anchored to the record
// before the ceremony.
func withSet(name string, list []byte) func(*rec) {
	return func(r *rec) {
		delete(r.artifacts, "trust/"+r.set+"/root-list.json")
		delete(r.artifacts, "trust/"+r.set+"/keys.txt")
		r.set = name
		r.artifacts["trust/"+name+"/root-list.json"] = anchored(list, r.record.PrevRecordSHA256)
		r.artifacts["trust/"+name+"/keys.txt"] = []byte("keys of " + name + "\n")
		r.refresh()
	}
}

// chainMem is a chain of ceremonies in memory.
func chainMem(t testing.TB, sets ...cset) *mnode { return chainBundle(t, true, sets...).mem }

// inOrder gives each list the name setN(position), the names the older tests use.
func inOrder(lists ...[]byte) []cset {
	out := make([]cset, len(lists))
	for i, l := range lists {
		out[i] = cset{list: l}
	}
	return out
}

// runChain runs the check on a chain of ceremonies in memory.
func runChain(t *testing.T, sets ...cset) *Report {
	t.Helper()
	rep, err := runMem(t, chainMem(t, sets...))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	checkReport(t, rep)
	return rep
}

// addList puts a root list in memory, as a trust set that nothing may list.
func addList(m *mnode, set string, list []byte) {
	m.put(listPathOf(set), &mnode{kind: "file", data: list})
}

// digests are the digests of the records of the ceremonies of a bundle, in order.
func (b *bundle) digests() []string {
	out := make([]string, len(b.recs))
	for i, r := range b.recs {
		out[i] = r.digest
	}
	return out
}

// claims is a root list of an unlisted set that says it follows the record with this digest.
func claims(list []byte, digest string) []byte { return anchored(list, digest) }
