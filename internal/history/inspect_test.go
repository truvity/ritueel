//go:build linux || darwin

package history

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
)

// The tests of Inspect. A bundle is built by the helpers of the other tests of this package (the
// builder of bundle_test.go, the chains of returns_chain_test.go). The expected values come from
// what a test wrote: the names of the sets in the order of the ceremonies that wrote them, the
// digest of the last record that the builder computed with crypto/sha256, the bytes it put on disk.

// inspectFS runs Inspect on fsys and fails the test when it does not return in time.
func inspectFS(t testing.TB, fsys fsx.FS) (*Inspection, error) {
	t.Helper()
	type result struct {
		in  *Inspection
		err error
	}
	ch := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), runLimit)
	defer cancel()
	go func() {
		var r result
		r.in, r.err = Inspect(ctx, fsys)
		ch <- r
	}()
	select {
	case r := <-ch:
		return r.in, r.err
	case <-time.After(runLimit + 10*time.Second):
		t.Fatalf("Inspect did not return within %v", runLimit)
		return nil, nil
	}
}

// fsOf opens the bundle for a run: the memory file system when the bundle is kept in memory.
func (b *bundle) fsOf() (fsx.FS, func()) {
	b.t.Helper()
	if b.mem != nil {
		return memFS{b.mem}, func() {}
	}
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		b.t.Fatalf("OpenFS: %v", err)
	}
	return root, func() { _ = root.Close() }
}

// sameReport fails the test unless the two reports are equal in every field.
func sameReport(t testing.TB, got, want *Report) {
	t.Helper()
	if got == nil || want == nil {
		t.Fatalf("a report is nil: %v, %v", got, want)
	}
	if got.Records != want.Records || !slices.Equal(got.Ends, want.Ends) || got.Omitted != want.Omitted ||
		!reflect.DeepEqual(got.Findings, want.Findings) {
		t.Errorf("the reports differ:\n inspect %+v\n check   %+v", *got, *want)
	}
}

// inspect runs Check and Inspect on the same bundle, requires the same report, and returns the
// Inspection.
func (b *bundle) inspect() *Inspection {
	b.t.Helper()
	fsys, closeFS := b.fsOf()
	defer closeFS()
	want, err := runFS(b.t, fsys, nil)
	if err != nil {
		b.t.Fatalf("Check: %v", err)
	}
	in, err := inspectFS(b.t, fsys)
	if err != nil {
		b.t.Fatalf("Inspect: %v", err)
	}
	if in == nil {
		b.t.Fatal("Inspect returned no Inspection and no error")
	}
	sameReport(b.t, in.Report, want)
	checkInspection(b.t, in)
	return in
}

// checkInspection checks what holds for every Inspection: a State only for a clean report, an
// OrderErr only without a State, and only for a clean report; no list of a State is Unreadable.
func checkInspection(t testing.TB, in *Inspection) {
	t.Helper()
	switch {
	case in.State != nil && !in.Report.Clean():
		t.Error("a State with a failing finding")
	case in.State != nil && in.OrderErr != nil:
		t.Errorf("a State and an OrderErr: %v", in.OrderErr)
	case in.State == nil && in.Report.Clean() && in.OrderErr == nil:
		t.Error("a clean report with no State and no OrderErr")
	case !in.Report.Clean() && in.OrderErr != nil:
		t.Errorf("a failing report with an OrderErr: %v", in.OrderErr)
	case in.OrderErr != nil && !errors.Is(in.OrderErr, ErrOrder):
		t.Errorf("OrderErr %v does not wrap ErrOrder", in.OrderErr)
	}
	if in.State == nil {
		return
	}
	for _, l := range in.State.Lists {
		if l.Unreadable {
			t.Errorf("the list %q of the State is Unreadable", l.Name)
		}
	}
	if n := len(in.State.Lists); n == 0 {
		if in.State.Newest != nil {
			t.Error("Newest with no list")
		}
	} else if in.State.Newest == nil || in.State.Newest.Name != in.State.Lists[n-1].Name {
		t.Errorf("Newest %v is not the last list %q", in.State.Newest, in.State.Lists[n-1].Name)
	}
}

// namesOfLists are the names of the lists of a State, in order.
func namesOfLists(st *State) []string {
	out := make([]string, len(st.Lists))
	for i, l := range st.Lists {
		out[i] = l.Name
	}
	return out
}

// wantState fails the test unless the Inspection has a State whose lists have these names in this
// order.
func wantState(t testing.TB, in *Inspection, names ...string) *State {
	t.Helper()
	if in.State == nil {
		t.Fatalf("no State; OrderErr %v; findings %v", in.OrderErr, findingsOf(in.Report))
	}
	if in.OrderErr != nil {
		t.Errorf("a State and an OrderErr %v", in.OrderErr)
	}
	if got := namesOfLists(in.State); !slices.Equal(got, names) && (len(got) != 0 || len(names) != 0) {
		t.Errorf("the lists are %v, want %v", got, names)
	}
	return in.State
}

// wantNoState fails the test unless there is no State, and the report is clean with an OrderErr
// that wraps ErrOrder.
func wantOrderErr(t testing.TB, in *Inspection) {
	t.Helper()
	if in.State != nil {
		t.Fatalf("a State with the lists %v, want none", namesOfLists(in.State))
	}
	if !in.Report.Clean() {
		t.Fatalf("the report is not clean: %v", findingsOf(in.Report))
	}
	if !errors.Is(in.OrderErr, ErrOrder) {
		t.Fatalf("OrderErr is %v, want one that wraps ErrOrder", in.OrderErr)
	}
}

// numbered is a chain of n ceremonies. Ceremony i writes the set setN(i) with the sequence i and
// the key A on every list.
func numbered(t testing.TB, mem bool, n int) *bundle {
	t.Helper()
	sets := make([]cset, n)
	for i := range sets {
		sets[i] = cset{setN(i + 1), keyList(int64(i+1), kA)}
	}
	return chainBundle(t, mem, sets...)
}

// An empty bundle: a folder with ritueel.yaml and no history. Inspect says the same as Check and
// has a State with nothing in it.
func TestInspectABundleWithNothingHasAnEmptyState(t *testing.T) {
	for _, mem := range []bool{false, true} {
		b := newBundle(t)
		if mem {
			b = &bundle{t: t, mem: newMem()}
			b.put("ritueel.yaml", []byte("name: test\n"))
			b.mkdir("history")
		}
		in := b.inspect()
		st := wantState(t, in)
		if st.Records != 0 || st.End != "" || st.Newest != nil || len(st.Lists) != 0 || len(st.Unfinished) != 0 {
			t.Errorf("mem %v: State %+v, want an empty one", mem, *st)
		}
		if !in.Report.Clean() || in.Report.Records != 0 {
			t.Errorf("mem %v: the report is %+v", mem, *in.Report)
		}
	}
}

// A folder that is no bundle: Check says ErrNotBundle, and so does Inspect, with no Inspection.
func TestInspectAFolderThatIsNoBundleIsAnError(t *testing.T) {
	m := newMem()
	m.file("readme.txt", "hello")
	in, err := inspectFS(t, memFS{m})
	if !errors.Is(err, ErrNotBundle) || in != nil {
		t.Errorf("Inspect = %v, %v; want ErrNotBundle and no Inspection", in, err)
	}
	if _, cerr := runFS(t, memFS{m}, nil); !errors.Is(cerr, ErrNotBundle) {
		t.Errorf("Check = %v", cerr)
	}
}

// Check and Inspect say the same of every bundle of this table: each field of the report is equal.
// The table holds clean bundles of every shape and bundles that fail for every kind of reason, and
// for the failing ones there is no State and no OrderErr.
func TestInspectGivesTheReportOfCheck(t *testing.T) {
	tamper := func(b *bundle, rel string) {
		b.put(rel, append(b.get(rel), '!'))
	}
	cases := []struct {
		name  string
		build func(t *testing.T) *bundle
		state bool // a State is expected
	}{
		{"three records", func(t *testing.T) *bundle { b, _ := threeRecords(t); return b }, false},
		{"a chain of numbered sets", func(t *testing.T) *bundle { return numbered(t, false, 4) }, true},
		{"a chain in memory", func(t *testing.T) *bundle { return numbered(t, true, 4) }, true},
		{"a stopped ceremony", func(t *testing.T) *bundle {
			b := numbered(t, false, 2)
			b.unfinished(withSet(setN(3), keyList(3, kA)))
			return b
		}, true},
		{"a file that changed", func(t *testing.T) *bundle {
			b := numbered(t, false, 3)
			tamper(b, "trust/"+setN(2)+"/keys.txt")
			return b
		}, false},
		{"a root list that changed", func(t *testing.T) *bundle {
			b := numbered(t, false, 3)
			tamper(b, listPathOf(setN(3)))
			return b
		}, false},
		{"a record that changed", func(t *testing.T) *bundle {
			b := numbered(t, false, 3)
			rewrite(b, b.recs[1], func(d []byte) []byte { return append(d, ' ') })
			return b
		}, false},
		{"a key that returns", func(t *testing.T) *bundle {
			return chainBundle(t, false,
				cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kB)}, cset{setN(3), keyList(3, kA)})
		}, false},
		{"a set that no record lists", func(t *testing.T) *bundle {
			b := numbered(t, true, 2)
			addList(b.mem, "9-aaaaaaaa", claims(keyList(9, kA), b.digests()[1]))
			return b
		}, false},
		{"a fork", func(t *testing.T) *bundle {
			b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
			first := b.recs[0].digest
			b.apply(prev(first), withSet(setN(2), keyList(2, kA)))
			b.apply(prev(first), withSet(setN(3), keyList(3, kA)))
			return b
		}, false},
		{"a root list that cannot be read", func(t *testing.T) *bundle {
			return chainBundle(t, true, cset{setN(1), keyList(1, kA)}, cset{setN(2), []byte(`{`)})
		}, false},
		{"a name that breaks the rule", func(t *testing.T) *bundle {
			b := numbered(t, false, 2)
			b.put("history/bad name/plan.json", []byte("{}"))
			return b
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c.build(t)
			in := b.inspect()
			if got := in.State != nil; got != c.state {
				t.Errorf("State present %v, want %v (OrderErr %v, findings %v)", got, c.state, in.OrderErr, findingsOf(in.Report))
			}
			if !in.Report.Clean() && (in.State != nil || in.OrderErr != nil) {
				t.Errorf("a failing report with a State or an OrderErr")
			}
		})
	}
}

// A chain of 1, 2, 5 and 26 ceremonies, each with its set: the lists are in the order of the
// ceremonies, the newest is the last, the end is the digest of the last record, the count is the
// count of records. The names are those of the plain run of numbers, and then names that run
// against the order of the chain: the order is the chain and not the names, so a number that does
// not grow is the finding trust-sequence at the set where the chain puts it.
func TestInspectPutsTheListsInTheOrderOfTheChain(t *testing.T) {
	for _, n := range []int{1, 2, 5, 26} {
		for _, style := range []string{"ascending", "descending", "shuffled"} {
			t.Run(style+" "+itoa(n), func(t *testing.T) {
				names := make([]string, n)
				sets := make([]cset, n)
				for i := range sets {
					num := i + 1
					switch style {
					case "descending":
						num = 200 - i
					case "shuffled":
						num = 1 + (i*7+3)%n + 100*(i%2) // not monotone along the chain
					}
					if i == n-1 && style != "ascending" {
						// The last set holds the highest sequence of the chain: only the sets
						// before it run against the order.
						num = 5000
					}
					names[i] = setN(num)
					sets[i] = cset{names[i], keyList(int64(num), kA)}
				}
				// A shuffled style can repeat a number: keep every name once.
				seen := map[string]bool{}
				for i := range names {
					for seen[names[i]] {
						num := 1000 + i
						names[i] = setN(num)
						sets[i] = cset{names[i], keyList(int64(num), kA)}
					}
					seen[names[i]] = true
				}
				b := chainBundle(t, false, sets...)
				in := b.inspect()
				if style != "ascending" {
					// A number that does not grow along the chain is the finding trust-sequence: the
					// order is the chain, never the numbers, so these sets are found where the chain
					// puts them, and there is no State.
					if len(modelTrustSeq(sets)) == 0 {
						wantState(t, in, names...) // one set, or two that grow
						return
					}
					wantModel(t, in, sets)
					return
				}
				st := wantState(t, in, names...)
				if st.Records != n {
					t.Errorf("Records = %d, want %d", st.Records, n)
				}
				if want := b.recs[n-1].digest; st.End != want {
					t.Errorf("End = %q, want the digest of the last record %q", st.End, want)
				}
				if st.Newest == nil || st.Newest.Name != names[n-1] {
					t.Errorf("Newest = %+v, want %s", st.Newest, names[n-1])
				}
				if len(st.Unfinished) != 0 {
					t.Errorf("Unfinished = %v", st.Unfinished)
				}
				eight, count, ok := in.Report.End()
				if !ok || count != n || eight != st.End[:8] {
					t.Errorf("the report ends at %q (%d, %v), the State at %q", eight, count, ok, st.End)
				}
			})
		}
	}
}

// itoa is strconv.Itoa for a name of a test.
func itoa(n int) string {
	var sb strings.Builder
	if n == 0 {
		return "0"
	}
	var digits []byte
	for ; n > 0; n /= 10 {
		digits = append(digits, byte('0'+n%10))
	}
	slices.Reverse(digits)
	sb.Write(digits)
	return sb.String()
}

// The keys of a list come out as the lists of FindReturns take them: the label as written, the pin
// and the fingerprint as lower-case hexadecimal digits, whatever form the file had.
func TestInspectKeysAreInTheFormOfFindReturns(t *testing.T) {
	upper := strings.ToUpper(pa)
	colons := func(s string) string {
		var parts []string
		for i := 0; i < len(s); i += 2 {
			parts = append(parts, s[i:i+2])
		}
		return strings.Join(parts, ":")
	}
	list := []byte(`{"roots":[` +
		rawEntry("A", upper, "") + `,` +
		rawEntry("B", "0x"+pb, "") + `,` +
		rawEntry("C", "", strings.ToUpper(f1)) + `,` +
		rawEntry("D", pc, colons(f2)) +
		`],"sequence":1,"version":1}`)
	b := chainBundle(t, false, cset{setN(1), list})
	in := b.inspect()
	st := wantState(t, in, setN(1))
	want := []RootKey{
		{Label: "A", Pin: pa},
		{Label: "B", Pin: pb},
		{Label: "C", Fingerprint: f1},
		{Label: "D", Pin: pc, Fingerprint: f2},
	}
	if !reflect.DeepEqual(st.Lists[0].Keys, want) {
		t.Errorf("Keys = %+v\n want %+v", st.Lists[0].Keys, want)
	}
	if st.Lists[0].Name != setN(1) {
		t.Errorf("Name = %q", st.Lists[0].Name)
	}
}

// A list with no entries is a list: the State has it with no keys.
func TestInspectAListWithNoKeys(t *testing.T) {
	b := chainBundle(t, false, cset{setN(1), keyList(1)}, cset{setN(2), keyList(2)})
	st := wantState(t, b.inspect(), setN(1), setN(2))
	for _, l := range st.Lists {
		if len(l.Keys) != 0 {
			t.Errorf("%s has keys %v", l.Name, l.Keys)
		}
	}
}

// A bundle in memory and the same bundle on disk give the same State.
func TestInspectMemoryAndDiskAgree(t *testing.T) {
	disk := numbered(t, false, 5).inspect()
	mem := numbered(t, true, 5).inspect()
	if disk.State == nil || mem.State == nil {
		t.Fatal("no State")
	}
	// The digests of the records differ between two builds only when a clock is used: none is.
	if !reflect.DeepEqual(disk.State, mem.State) {
		t.Errorf("disk %+v\n mem %+v", *disk.State, *mem.State)
	}
}

// The State holds the bytes that are on disk, not another reading and not a rebuilt form.
func TestInspectNewestHoldsTheBytesOfTheFile(t *testing.T) {
	// A list in a form that no writer of ritueel makes: spaces, a line break, an unknown member.
	odd := []byte("{ \"version\": 1,\n  \"sequence\": 3 ,\"roots\":[{\"label\":\"A\",\"x509_spki_sha256\":\"" + strings.ToUpper(pa) + "\"}],\"zz\":5 }\n")
	b := chainBundle(t, false,
		cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kA)},
		cset{setN(3), odd})
	in := b.inspect()
	if in.State == nil {
		t.Fatalf("no State: %v %v", findingsOf(in.Report), in.OrderErr)
	}
	disk := b.get(listPathOf(setN(3)))
	if !bytes.Equal(in.State.Newest.ListJSON, disk) {
		t.Errorf("ListJSON %q\n disk %q", in.State.Newest.ListJSON, disk)
	}
}

// Newest: the number is the number of the name and equals the sequence of the list, the bytes are
// those of the file, and the digest of the bytes is the one a record lists for the file.
func TestInspectNewest(t *testing.T) {
	b := numbered(t, false, 3)
	in := b.inspect()
	st := wantState(t, in, setN(1), setN(2), setN(3))
	nw := st.Newest
	if nw.Name != setN(3) || nw.Number != 3 {
		t.Errorf("Newest = %s, %d", nw.Name, nw.Number)
	}
	disk := b.get(listPathOf(setN(3)))
	if !bytes.Equal(nw.ListJSON, disk) {
		t.Errorf("ListJSON %q is not the file %q", nw.ListJSON, disk)
	}
	if got, want := sum(string(nw.ListJSON)), sum(string(disk)); got != want {
		t.Errorf("digests %s %s", got, want)
	}
	// The record of the third ceremony lists the file with the digest of exactly these bytes.
	if want := sum(string(disk)); !strings.Contains(string(b.get("history/"+b.recs[2].folder+"/record.json")), want) {
		t.Errorf("the record does not list the digest %s of the bytes", want)
	}
}

// A State is a copy: changing what a call returned changes nothing of the next call, and nothing of
// the first when the second is changed.
func TestInspectStateIsACopy(t *testing.T) {
	b := numbered(t, false, 3)
	b.unfinished(withSet(setN(4), keyList(4, kA)))
	first := b.inspect()
	st := wantState(t, first, setN(1), setN(2), setN(3), setN(4))
	if len(st.Unfinished) != 1 {
		t.Fatalf("Unfinished = %v", st.Unfinished)
	}
	listBefore := string(st.Newest.ListJSON)
	for i := range st.Newest.ListJSON {
		st.Newest.ListJSON[i] = 'x'
	}
	st.Lists[0].Name = "changed"
	st.Lists[0].Keys[0].Label = "Z"
	st.Lists[0].Keys = append(st.Lists[0].Keys, RootKey{Label: "Y"})
	st.Lists = append(st.Lists[:1], st.Lists[2:]...)
	st.Unfinished[0] = "changed"
	st.End = "changed"

	second := b.inspect()
	st2 := wantState(t, second, setN(1), setN(2), setN(3), setN(4))
	if string(st2.Newest.ListJSON) != listBefore || !bytes.Equal(st2.Newest.ListJSON, b.get(listPathOf(setN(4)))) {
		t.Errorf("the second call holds %q", st2.Newest.ListJSON)
	}
	if st2.Lists[0].Keys[0].Label != "A" || len(st2.Lists[0].Keys) != 1 || st2.End == "changed" || st2.Unfinished[0] == "changed" {
		t.Errorf("the second call changed with the first: %+v", *st2)
	}
	// Two Inspections that are alive together share no memory.
	a1, a2 := b.inspect(), b.inspect()
	a1.State.Newest.ListJSON[0] = 'x'
	a1.State.Lists[0].Keys[0].Label = "Q"
	if a2.State.Newest.ListJSON[0] != '{' || a2.State.Lists[0].Keys[0].Label != "A" {
		t.Error("two Inspections share memory")
	}
}

// The newest set is the last of the chain: the one a ceremony writes last, whatever the names of
// the earlier sets say. A name that is lower than the one before it is the finding trust-sequence,
// at that set and at no other, so there is no State.
func TestInspectNewestIsTheLastOfTheChainNotTheHighestName(t *testing.T) {
	sets := []cset{{"9-aaaaaaaa", keyList(9, kA)}, {"8-aaaaaaaa", keyList(8, kA)}, {"12-aaaaaaaa", keyList(12, kA)}}
	wantFailed(t, chainBundle(t, false, sets...).inspect(), []wf{{TrustSequence, "trust/8-aaaaaaaa"}})
	// The same names with the last one lowest: both falls are found.
	low := []cset{{"9-aaaaaaaa", keyList(9, kA)}, {"8-aaaaaaaa", keyList(8, kA)}, {"7-aaaaaaaa", keyList(7, kA)}}
	wantFailed(t, chainBundle(t, false, low...).inspect(), []wf{{TrustSequence, "trust/8-aaaaaaaa"}, {TrustSequence, "trust/7-aaaaaaaa"}})
}

// A set that has no root list (a personal bundle's set, record 0006, rule 12) is no list of the
// State: it stands in no place of the order and holds no key.
func TestInspectASetWithNoRootListIsNotAList(t *testing.T) {
	b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
	noList := func(r *rec) {
		delete(r.artifacts, "trust/"+r.set+"/root-list.json")
		r.refresh()
	}
	b.apply(noList)
	b.apply(withSet(setN(3), keyList(3, kA)))
	st := wantState(t, b.inspect(), setN(1), setN(3))
	if st.Records != 3 || st.Newest.Name != setN(3) {
		t.Errorf("State %+v", *st)
	}
}

// Unfinished: a ceremony folder with attempt.json and no record is in it; a folder with a plan and
// no attempt is not; one that a closing record names is not; one with a record is not. The names
// are in the order of the names.
func TestInspectUnfinished(t *testing.T) {
	t.Run("an attempt with no record", func(t *testing.T) {
		b := numbered(t, false, 2)
		u := b.unfinished(withSet(setN(3), keyList(3, kA)))
		st := wantState(t, b.inspect(), setN(1), setN(2), setN(3))
		if !slices.Equal(st.Unfinished, []string{u.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", st.Unfinished, u.folder)
		}
		if st.Records != 2 {
			t.Errorf("Records = %d: a folder with no record is not a record", st.Records)
		}
	})
	t.Run("a plan with no attempt", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.unfinished(noSet, func(r *rec) { r.noAttempt = true })
		in := b.inspect()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		if len(in.State.Unfinished) != 0 {
			t.Errorf("Unfinished = %v, want none: no attempt was made", in.State.Unfinished)
		}
	})
	t.Run("a closed attempt is not unfinished", func(t *testing.T) {
		b := numbered(t, false, 2)
		stopped := b.unfinished(withSet(setN(3), keyList(3, kA)))
		b.closing(stopped, listsLeftover(stopped, nil))
		in := b.inspect()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		if len(in.State.Unfinished) != 0 {
			t.Errorf("Unfinished = %v, want none: a closing record names it", in.State.Unfinished)
		}
	})
	t.Run("a record with an attempt is not unfinished", func(t *testing.T) {
		b := numbered(t, false, 2)
		b.apply(withSet(setN(3), keyList(3, kA)), namesAttempt)
		if st := wantState(t, b.inspect(), setN(1), setN(2), setN(3)); len(st.Unfinished) != 0 {
			t.Errorf("Unfinished = %v", st.Unfinished)
		}
	})
	t.Run("two attempts, one closed, in the order of the names", func(t *testing.T) {
		b := numbered(t, false, 1)
		first := b.unfinished(withSet(setN(2), keyList(2, kA)))
		b.closing(first, listsLeftover(first, nil))
		second := b.unfinished(withSet(setN(4), keyList(4, kA)))
		in := b.inspect()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		if !slices.Equal(in.State.Unfinished, []string{second.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.State.Unfinished, second.folder)
		}
	})
	t.Run("an attempt that has no trust set", func(t *testing.T) {
		// The check does not see an attempt that has no trust set (a run that stopped after the
		// births): the report is clean, and the State says that the attempt is open.
		b := numbered(t, false, 2)
		u := b.unfinished(noSet)
		in := b.inspect()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		if !slices.Equal(in.State.Unfinished, []string{u.folder}) {
			t.Errorf("Unfinished = %v, want [%s]", in.State.Unfinished, u.folder)
		}
		if got := namesOfLists(in.State); !slices.Equal(got, []string{setN(1), setN(2)}) {
			t.Errorf("lists %v", got)
		}
	})
	t.Run("a bundle that has only an attempt", func(t *testing.T) {
		b := newBundle(t)
		u := b.unfinished(noSet)
		in := b.inspect()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		if st := in.State; !slices.Equal(st.Unfinished, []string{u.folder}) || st.Records != 0 || st.End != "" || st.Newest != nil {
			t.Errorf("State %+v", *st)
		}
	})
	t.Run("sorted by name, not by the order of writing", func(t *testing.T) {
		b := newBundle(t)
		// Ceremony folders are named by the builder in the order of writing; make the second one
		// sort first.
		late := b.unfinished(noSet)
		early := b.unfinished(noSet, folderName("20260000T100000Z-apply"))
		in := b.inspect()
		if in.State == nil {
			t.Fatalf("no State: %v %v", in.OrderErr, findingsOf(in.Report))
		}
		want := []string{early.folder, late.folder}
		if !slices.Equal(in.State.Unfinished, want) {
			t.Errorf("Unfinished = %v, want %v", in.State.Unfinished, want)
		}
	})
}

// A stopped ceremony that left a trust set is a notice, not a failing finding: the State has its
// list as the last one, and says that the attempt is open.
func TestInspectAnUnfinishedTrustSetIsTheLastList(t *testing.T) {
	b := numbered(t, false, 2)
	u := b.unfinished(withSet(setN(3), keyList(3, kA, kB)))
	in := b.inspect()
	st := wantState(t, in, setN(1), setN(2), setN(3))
	has(t, in.Report, UnfinishedCeremony, "trust/"+setN(3))
	if !slices.Equal(st.Unfinished, []string{u.folder}) {
		t.Errorf("Unfinished = %v", st.Unfinished)
	}
	if st.End != b.recs[1].digest {
		t.Errorf("End = %s, want the digest of the last record %s", st.End, b.recs[1].digest)
	}
	if st.Newest.Name != setN(3) || st.Newest.Number != 3 {
		t.Errorf("Newest = %+v", *st.Newest)
	}
	if got := st.Lists[2].Keys; len(got) != 2 || got[1].Label != "B" {
		t.Errorf("keys of the list left by the attempt: %+v", got)
	}
}

// Inspect reads and writes nothing it should not: the spy sees no call that changes the bundle, and
// the tree of files is byte for byte the same after the run.
func TestInspectChangesNothing(t *testing.T) {
	b := numbered(t, false, 4)
	b.unfinished(withSet(setN(5), keyList(5, kA)))
	before := tree(t, b.dir)
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	spy, log := newSpy(root)
	in, err := inspectFS(t, spy)
	if err != nil || in == nil || in.State == nil {
		t.Fatalf("Inspect: %v, %v", in, err)
	}
	if len(log.changes) != 0 {
		t.Errorf("Inspect changed the bundle: %v", log.changes)
	}
	if after := tree(t, b.dir); !reflect.DeepEqual(before, after) {
		t.Error("the files of the bundle changed")
	}
}

// The walk is made once: a path that Check reads once is read once by Inspect, and no root list is
// read a second time to give the State its bytes.
func TestInspectReadsNoFileTwiceForTheState(t *testing.T) {
	b := numbered(t, false, 4)
	checkSpy, checkLog := func() (*spyFS, *spyLog) {
		root, err := fsx.OpenFS(b.dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = root.Close() })
		return newSpy(root)
	}()
	if _, err := runFS(t, checkSpy, nil); err != nil {
		t.Fatal(err)
	}
	root, err := fsx.OpenFS(b.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	spy, log := newSpy(root)
	if in, err := inspectFS(t, spy); err != nil || in.State == nil {
		t.Fatalf("Inspect: %v %v", in, err)
	}
	if !reflect.DeepEqual(checkLog.reads, log.reads) {
		t.Errorf("reads differ:\n check   %v\n inspect %v", checkLog.reads, log.reads)
	}
	if !reflect.DeepEqual(checkLog.lists, log.lists) {
		t.Errorf("listings differ:\n check   %v\n inspect %v", checkLog.lists, log.lists)
	}
	if !reflect.DeepEqual(checkLog.opens, log.opens) {
		t.Errorf("opens differ:\n check   %v\n inspect %v", checkLog.opens, log.opens)
	}
	for p, n := range log.reads {
		if n > 1 && strings.HasPrefix(p, "trust/") {
			t.Errorf("%s was read %d times", p, n)
		}
	}
}

// The State holds the bytes that were judged: the file changes after the walk read it, and the
// State still holds what the walk read. A file system that hands out other bytes at the second
// read of a root list shows a second read: the State must hold the first.
func TestInspectNewestIsWhatTheWalkReadNotASecondRead(t *testing.T) {
	b := numbered(t, true, 3)
	path := listPathOf(setN(3))
	first := append([]byte(nil), b.mem.get(path).data...)
	flip := &flipFS{FS: memFS{b.mem}, path: path}
	in, err := inspectFS(t, flip)
	if err != nil || in == nil || in.State == nil {
		t.Fatalf("Inspect: %v, %v", in, err)
	}
	if !bytes.Equal(in.State.Newest.ListJSON, first) {
		t.Errorf("ListJSON %q is not the bytes of the first read %q", in.State.Newest.ListJSON, first)
	}
	if flip.reads != 1 {
		t.Errorf("the root list was read %d times, want once", flip.reads)
	}
}

// flipFS answers a read of path with the file the first time and with another content every time
// after; it counts the reads.
type flipFS struct {
	fsx.FS
	path   string
	here   string
	reads  int
	shared *int
}

func (f *flipFS) at(name string) string {
	if f.here == "" {
		return name
	}
	return f.here + "/" + name
}

func (f *flipFS) OpenDir(name string) (fsx.FS, error) {
	d, err := f.FS.OpenDir(name)
	if err != nil {
		return nil, err
	}
	return &flipFS{FS: d, path: f.path, here: f.at(name), shared: f.counter()}, nil
}

func (f *flipFS) counter() *int {
	if f.shared == nil {
		f.shared = &f.reads
	}
	return f.shared
}

func (f *flipFS) ReadFile(name string) ([]byte, error) {
	data, err := f.FS.ReadFile(name)
	if err != nil || f.at(name) != f.path {
		return data, err
	}
	n := f.counter()
	*n++
	if *n > 1 {
		return []byte(`{"version":1,"sequence":3,"roots":[{"label":"Z","x509_spki_sha256":"` + pd + `"}]}`), nil
	}
	return data, nil
}

// A trust set that no ceremony record lists, in a bundle with no record at all, is the finding
// trust-set-unlisted (the page: "A trust set in trust/ is not an artifact of a ceremony record, and
// no attempt of that ceremony is open"). The report fails, so there is no State and no OrderErr.
func TestInspectASetWithNoRecordAndNoAttemptHasNoState(t *testing.T) {
	for _, mem := range []bool{false, true} {
		b := chainBundle(t, mem)
		if mem {
			b.mem.put(listPathOf(setN(1)), &mnode{kind: "file", data: keyList(1, kA)})
		} else {
			b.put(listPathOf(setN(1)), keyList(1, kA))
		}
		in := b.inspect()
		if in.State != nil || in.OrderErr != nil || in.Report.Clean() {
			t.Errorf("mem %v: State %v, OrderErr %v, clean %v", mem, in.State, in.OrderErr, in.Report.Clean())
		}
		has(t, in.Report, TrustSetUnlisted, "trust/"+setN(1))
	}
}

// The first ceremony stopped: an attempt, a trust set and no record. The set is the one list, there
// is no end and no record, and the attempt is open.
func TestInspectTheFirstCeremonyThatStopped(t *testing.T) {
	b := newBundle(t)
	u := b.unfinished(withSet(setN(1), keyList(1, kA, kB)))
	in := b.inspect()
	st := wantState(t, in, setN(1))
	if st.Records != 0 || st.End != "" || !slices.Equal(st.Unfinished, []string{u.folder}) {
		t.Errorf("State %+v", *st)
	}
	if st.Newest == nil || st.Newest.Number != 1 || len(st.Lists[0].Keys) != 2 {
		t.Errorf("Newest %+v, keys %+v", st.Newest, st.Lists[0].Keys)
	}
	has(t, in.Report, UnfinishedCeremony, "trust/"+setN(1))
}
