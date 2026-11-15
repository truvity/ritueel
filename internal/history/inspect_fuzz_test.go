//go:build linux || darwin

package history

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// checkInspectInvariants holds what is true of every Inspection of every bundle: the report is the
// report of Check, a State only for a clean report, an OrderErr only without a State, no list
// Unreadable, the newest is the last list, holds the highest sequence and agrees with its name and its file, and a second run
// says the same.
func checkInspectInvariants(t *testing.T, m *mnode) *Inspection {
	t.Helper()
	fsys := memFS{m}
	want, cerr := runFS(t, fsys, nil)
	in, err := inspectFS(t, fsys)
	if (cerr != nil) != (err != nil) {
		t.Fatalf("Check error %v, Inspect error %v", cerr, err)
	}
	if err != nil {
		if in != nil {
			t.Fatalf("an Inspection with an error %v", err)
		}
		return nil
	}
	sameReport(t, in.Report, want)
	checkReport(t, in.Report)
	checkInspection(t, in)
	again, err := inspectFS(t, fsys)
	if err != nil || !reflect.DeepEqual(in, again) {
		t.Fatalf("a second run differs: %v", err)
	}
	if in.State == nil {
		return in
	}
	st := in.State
	if st.Records != in.Report.Records {
		t.Fatalf("Records %d, report %d", st.Records, in.Report.Records)
	}
	if st.Records == 0 && st.End != "" {
		t.Fatalf("End %q with no record", st.End)
	}
	if st.Records > 0 && (len(in.Report.Ends) != 1 || st.End != in.Report.Ends[0]) {
		t.Fatalf("End %q, report ends %v", st.End, in.Report.Ends)
	}
	if !slices.IsSorted(st.Unfinished) {
		t.Fatalf("Unfinished %v is not in order", st.Unfinished)
	}
	seen := map[string]bool{}
	for _, l := range st.Lists {
		if seen[l.Name] {
			t.Fatalf("the list %q is twice in the State", l.Name)
		}
		seen[l.Name] = true
		for _, k := range l.Keys {
			if k.Pin == "" && k.Fingerprint == "" {
				t.Fatalf("a key with neither pin nor fingerprint in %s", l.Name)
			}
			if k.Pin != "" && (len(k.Pin) != 64 || k.Pin != strings.ToLower(k.Pin)) {
				t.Fatalf("pin %q is not 64 lower-case digits", k.Pin)
			}
			if k.Fingerprint != "" && (len(k.Fingerprint) != 40 || k.Fingerprint != strings.ToLower(k.Fingerprint)) {
				t.Fatalf("fingerprint %q is not 40 lower-case digits", k.Fingerprint)
			}
		}
	}
	if st.Newest != nil {
		// The bytes are the file, the number is the sequence of the list, read by another reader.
		file := m.get("trust/" + st.Newest.Name + "/root-list.json")
		if file == nil || !bytes.Equal(file.data, st.Newest.ListJSON) {
			t.Fatalf("ListJSON is not the file of %s", st.Newest.Name)
		}
		var v struct {
			Sequence json.Number `json:"sequence"`
		}
		if err := json.Unmarshal(st.Newest.ListJSON, &v); err != nil {
			t.Fatalf("ListJSON does not parse: %v", err)
		}
		if n, err := v.Sequence.Int64(); err != nil || n != st.Newest.Number {
			t.Fatalf("Number %d, sequence %q", st.Newest.Number, v.Sequence)
		}
		if len(st.Lists) == 0 || st.Lists[len(st.Lists)-1].Name != st.Newest.Name {
			t.Fatalf("Newest %s is not the last list", st.Newest.Name)
		}
	}
	// The newest list holds the highest sequence: every list has a sequence that an independent
	// reader finds, and the last one is above all that stand before it.
	var top int64
	for i, l := range st.Lists {
		file := m.get("trust/" + l.Name + "/root-list.json")
		if file == nil {
			t.Fatalf("the list %s is no file of the bundle", l.Name)
		}
		var v struct {
			Sequence *json.Number `json:"sequence"`
		}
		if err := json.Unmarshal(file.data, &v); err != nil || v.Sequence == nil {
			t.Fatalf("the list %s of a State has no sequence that can be read: %v", l.Name, err)
		}
		n, err := v.Sequence.Int64()
		if err != nil {
			t.Fatalf("the sequence %q of %s is no integer", *v.Sequence, l.Name)
		}
		if i == len(st.Lists)-1 && i > 0 && n <= top {
			t.Fatalf("the last list %s has the sequence %d, a list before it has %d", l.Name, n, top)
		}
		if i == 0 || n > top {
			top = n
		}
	}
	// Every list in the State is a trust set of the bundle, with a root list, as a regular file.
	for _, l := range st.Lists {
		n := m.get("trust/" + l.Name + "/root-list.json")
		if n == nil || n.kind != "file" {
			t.Fatalf("the list %s is no file of the bundle", l.Name)
		}
	}
	// The place of each list in the State follows the chain: the lists listed by a record are in
	// the order of the records that list them.
	return in
}

// FuzzInspectLists puts any bytes in the root lists of a chain of ceremonies. The record lists the
// digest of the bytes, so a list that can be read is judged as it is. A shape byte adds a stopped
// ceremony, a closing record and a name that runs against the chain. Whatever the bytes are: no
// panic, the run ends, and every invariant of an Inspection holds. In a State, the lists are in the
// order of the ceremonies that wrote them.
func FuzzInspectLists(f *testing.F) {
	ok := keyList
	f.Add(ok(1, kA), ok(2, kA, kB), ok(3, kB), uint8(0))
	f.Add(ok(1, kA), ok(2, kB), ok(3, kA), uint8(1))
	f.Add(ok(1, kA), ok(2, kA), ok(3, kA), uint8(2))
	f.Add(ok(1, kA), ok(2, kA), ok(3, kA), uint8(7))
	f.Add(ok(1, kA), ok(2, kA), ok(2, kA), uint8(4))
	f.Add(ok(1, kA), ok(1, kA), ok(3, kA), uint8(0))
	f.Add(ok(5, kA), ok(1, kA), ok(3, kA), uint8(0))
	f.Add(ok(1, kA), ok(3, kA), ok(2, kA), uint8(6))
	f.Add(rootsJSON(0, kA), ok(2, kA), ok(3, kA), uint8(0))
	f.Add(ok(1, kA), ok(9, kA), ok(3, ent{"C", "", f1}), uint8(3))
	f.Add([]byte(`{`), []byte(``), []byte(`null`), uint8(5))
	f.Add(rootsJSON(0, kA), rootsJSON(0, kA), rootsJSON(0, kA), uint8(6))
	f.Add(seqList("-1", kA), seqList("9007199254740993", kA), seqList("0", kA), uint8(0))
	f.Fuzz(func(t *testing.T, l1, l2, l3 []byte, shape uint8) {
		if len(l1)+len(l2)+len(l3) > 1<<16 {
			t.Skip("large")
		}
		descending := shape&1 != 0
		stopped := shape&2 != 0
		closed := shape&4 != 0
		name := func(i int) string {
			if descending {
				return setN(100 - i)
			}
			return setN(i)
		}
		b := chainBundle(t, true)
		order := []string{}
		for i, l := range [][]byte{l1, l2} {
			b.apply(withSet(name(i+1), l))
			order = append(order, name(i+1))
		}
		if stopped {
			u := b.unfinished(withSet(name(3), l3))
			if closed {
				b.closing(u, listsLeftover(u, nil))
			}
		} else {
			b.apply(withSet(name(3), l3))
		}
		order = append(order, name(3))
		in := checkInspectInvariants(t, b.mem)
		if in == nil || in.State == nil {
			return
		}
		// The lists that the State has are in the order of the ceremonies: a subsequence of order, and,
		// as a State needs a root list for a place, all of them but the sets that have none.
		if got := namesOfLists(in.State); !slices.Equal(got, order) {
			t.Fatalf("the lists are %v, the ceremonies wrote %v", got, order)
		}
		if stopped && !closed && len(in.State.Unfinished) != 1 {
			t.Fatalf("Unfinished = %v", in.State.Unfinished)
		}
	})
}

// FuzzInspectBundle takes any bytes as the files of one ceremony and one entry with a hostile name
// in one place, in a bundle of two clean ceremonies. Whatever the bytes are: no panic, the run ends,
// nothing is changed, and every invariant of an Inspection holds.
func FuzzInspectBundle(f *testing.F) {
	b := newBundle(f)
	b.apply()
	last := b.apply()
	base := "history/" + last.folder + "/"
	seed := func(pick uint8) {
		f.Add(b.get(base+"record.json"), b.get(base+"attempt.json"), b.get(base+"plan.json"), b.get("trust/"+last.set+"/root-list.json"), pick)
	}
	seed(0)
	for pick := 1; pick < 80; pick += 9 {
		seed(uint8(pick))
	}
	f.Add([]byte{}, []byte("{}"), []byte("{}"), []byte("{}"), uint8(3))
	f.Add([]byte(`{`), []byte{}, []byte{}, []byte{}, uint8(200))
	pool := hostileNames()
	master := loadMem(f, b.dir)
	f.Fuzz(func(t *testing.T, record, attempt, plan, rootList []byte, pick uint8) {
		if len(record)+len(attempt)+len(plan)+len(rootList) > 1<<16 {
			t.Skip("large")
		}
		m := cloneMem(master)
		const c = "history/20261114T100000Z-apply"
		m.put(c+"/attempt.json", &mnode{kind: "file", data: attempt})
		m.put(c+"/plan.json", &mnode{kind: "file", data: plan})
		if len(record) > 0 {
			m.put(c+"/record.json", &mnode{kind: "file", data: record})
		}
		m.put("trust/1-3fa9c1d3/root-list.json", &mnode{kind: "file", data: rootList})
		if i := int(pick) % (len(pool) + 1); i > 0 {
			where := []string{"history", "trust", base, "trust/" + last.set}[int(pick/uint8(len(pool)+1))%4]
			kind := []string{"file", "dir", "link", "fifo"}[int(pick/7)%4]
			n := &mnode{kind: kind, data: []byte("x")}
			if kind == "dir" {
				n.kids = map[string]*mnode{"record.json": {kind: "file", data: []byte("not a record")}}
			}
			m.put(where+"/"+pool[i-1].name, n)
		}
		spy, log := newSpy(memFS{m})
		in, err := inspectFS(t, spy)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if len(log.changes) != 0 {
			t.Fatalf("calls that change the bundle: %v", log.changes)
		}
		checkInspectInvariants(t, m)
		_ = in
	})
}
