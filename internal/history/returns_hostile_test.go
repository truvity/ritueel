//go:build linux || darwin

package history

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
)

// The order of the lists, the lists that cannot be read, and hostile input for the finding
// root-returns.

// wantReturnsAt fails unless the findings of root-returns are at exactly these sets, with these
// labels ("set label").
func wantReturnsAt(t *testing.T, rep *Report, want ...string) {
	t.Helper()
	var got []string
	for _, f := range returnsOf(rep) {
		label := strings.TrimPrefix(f.Detail, `root key "`)
		if i := strings.Index(label, `"`); i >= 0 {
			label = label[:i]
		}
		set := strings.TrimSuffix(strings.TrimPrefix(f.Path, "trust/"), "/root-list.json")
		got = append(got, set+" "+label)
	}
	slices.Sort(got)
	want = slices.Clone(want)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings of root-returns:\n got %q\nwant %q", got, want)
	}
}

const notSure = "the order of the trust sets is not sure"

// A root list that cannot be read is another finding (anchor-unknown), is not reported again, and
// is a list whose keys are not known: the list after it has no known list before it, so a key of
// the lists before is a return there. It does not stop the walk.
func damagedLists() map[string]func(m *mnode, path string) {
	file := func(s string) func(*mnode, string) {
		return func(m *mnode, path string) { m.put(path, &mnode{kind: "file", data: []byte(s)}) }
	}
	kind := func(k string) func(*mnode, string) {
		return func(m *mnode, path string) {
			m.put(path, &mnode{kind: k, data: []byte("x"), kids: map[string]*mnode{}})
		}
	}
	deep := strings.Repeat("[", 10001) + strings.Repeat("]", 10001)
	var many strings.Builder
	many.WriteString(`{"roots":[`)
	for i := 0; i < 27; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		fmt.Fprintf(&many, `{"label":"A","x509_spki_sha256":"%s"}`, pinOf(100+i))
	}
	many.WriteString(`],"version":1}`)
	return map[string]func(*mnode, string){
		"not JSON":                        file(`{`),
		"empty":                           file(``),
		"an array":                        file(`[]`),
		"a number":                        file(`7`),
		"text after the object":           file(`{"roots":[],"version":1} x`),
		"a byte order mark":               file("\xef\xbb\xbf" + `{"roots":[],"version":1}`),
		"bytes that are not UTF-8":        file("{\"roots\":[],\"note\":\"\xff\xfe\",\"version\":1}"),
		"a lone surrogate":                file(`{"roots":[],"note":"\ud800","version":1}`),
		"a member twice":                  file(`{"roots":[],"roots":[],"version":1}`),
		"a member twice, deeper":          file(`{"roots":[{"label":"A","label":"B"}],"version":1}`),
		"a null":                          file(`{"roots":null,"version":1}`),
		"a null entry":                    file(`{"roots":[null],"version":1}`),
		"roots a text":                    file(`{"roots":"x","version":1}`),
		"roots an object":                 file(`{"roots":{"a":1},"version":1}`),
		"an entry a number":               file(`{"roots":[7],"version":1}`),
		"an entry an array":               file(`{"roots":[[]],"version":1}`),
		"a pin a number":                  file(`{"roots":[{"x509_spki_sha256":7}],"version":1}`),
		"a pin a list":                    file(`{"roots":[{"x509_spki_sha256":[]}],"version":1}`),
		"a label a number":                file(`{"roots":[{"label":5}],"version":1}`),
		"a fingerprint a number":          file(`{"roots":[{"openpgp_fingerprint":5}],"version":1}`),
		"a sequence a text":               file(`{"roots":[],"sequence":"7","version":1}`),
		"a sequence a fraction":           file(`{"roots":[],"sequence":1.5,"version":1}`),
		"a sequence a bool":               file(`{"roots":[],"sequence":true,"version":1}`),
		"a sequence beyond 2^53":          file(`{"roots":[],"sequence":9007199254740993,"version":1}`),
		"nested 10001 deep":               file(deep),
		"27 entries of roots":             file(many.String()),
		"a pin that is not hexadecimal":   file(`{"roots":[{"label":"A","x509_spki_sha256":"` + strings.Repeat("g", 64) + `"}],"version":1}`),
		"a pin of 63 digits":              file(`{"roots":[{"label":"A","x509_spki_sha256":"` + pa[:63] + `"}],"version":1}`),
		"a fingerprint of 39 digits":      file(`{"roots":[{"label":"A","openpgp_fingerprint":"` + f1[:39] + `"}],"version":1}`),
		"a good entry and then a bad pin": file(`{"roots":[{"label":"A","x509_spki_sha256":"` + pa + `"},{"label":"B","x509_spki_sha256":"zz"}],"version":1}`),
		"an empty text for a pin":         file(`{"roots":[{"label":"A","x509_spki_sha256":""}],"version":1}`),
		"an empty text for a fingerprint": file(`{"roots":[{"label":"A","openpgp_fingerprint":""}],"version":1}`),
		"more than 256 KiB":               file(`{"roots":[],"note":"` + strings.Repeat("a", 300<<10) + `","version":1}`),
		"longer than 8 MiB":               func(m *mnode, path string) { m.put(path, &mnode{kind: "file", long: true}) },
		"a symbolic link":                 kind("link"),
		"a pipe":                          kind("fifo"),
		"a folder":                        kind("dir"),
	}
}

func TestRootReturnsAListThatCannotBeReadIsNotReportedTwiceAndHidesNothing(t *testing.T) {
	for name, damage := range damagedLists() {
		t.Run(name, func(t *testing.T) {
			m := chainMem(t, inOrder(
				rootsJSON(0, ent{"A", pa, ""}, ent{"B", pb, ""}),
				rootsJSON(0),
				rootsJSON(0, ent{"A", pa, ""}, ent{"C", pc, ""}),
			)...)
			damage(m, listPathOf(setN(2)))
			rep, err := runMem(t, m)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			checkReport(t, rep)
			has(t, rep, AnchorUnknown, listPathOf(setN(2)))
			got := returnsOf(rep)
			if len(got) != 1 {
				t.Fatalf("%d findings of root-returns: %v", len(got), lines(got))
			}
			f := got[0]
			if want := `root key "A" returns: ` + wPinUnread(pa) + wRule + "; " + wHeldPin(setN(1)) + "; " + wBefore(setN(2)); f.Path != listPathOf(setN(3)) || !strings.HasPrefix(f.Detail, want) {
				t.Errorf("the finding is %q, want the detail %q", f.Line(), want)
			}
		})
	}
}

func TestRootReturnsWalkGoesOnAfterAListThatCannotBeRead(t *testing.T) {
	bad := []byte(`{`)
	t.Run("a return after the damaged list is found as usual", func(t *testing.T) {
		rep := runLists(t,
			rootsJSON(0, ent{"A", pa, ""}, ent{"B", pb, ""}),
			bad,
			rootsJSON(0),
			rootsJSON(0, ent{"A", pa, ""}),
			rootsJSON(0, ent{"A", pa, ""}),
		)
		got := returnsOf(rep)
		if len(got) != 1 || got[0].Path != listPathOf(setN(4)) || strings.Contains(got[0].Detail, "cannot be read") {
			t.Errorf("findings %v", lines(got))
		}
	})
	t.Run("two lists in a row that cannot be read", func(t *testing.T) {
		rep := runLists(t,
			rootsJSON(0, ent{"A", pa, ""}),
			bad,
			bad,
			rootsJSON(0, ent{"A", pa, ""}),
		)
		got := returnsOf(rep)
		if len(got) != 1 || !strings.Contains(got[0].Detail, "the list before this one cannot be read"+wRule+"; "+wHeldPin(setN(1))+"; "+wBefore(setN(3))) {
			t.Errorf("findings %v", lines(got))
		}
	})
	t.Run("a list that cannot be read first, last, or alone", func(t *testing.T) {
		rep := runLists(t, bad, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0), bad)
		wantReturns(t, rep)
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
		has(t, rep, AnchorUnknown, listPathOf(setN(4)))
		rep = runLists(t, bad)
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
		wantReturns(t, rep)
	})
	t.Run("a key that never was before the list that cannot be read is no return", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), bad, rootsJSON(0, ent{"B", pb, ""}))
		wantReturns(t, rep)
	})
	t.Run("the list after the one that cannot be read has no known list before it, the list after that has", func(t *testing.T) {
		rep := runLists(t,
			rootsJSON(0, ent{"A", pa, ""}),
			bad,
			rootsJSON(0, ent{"A", pa, ""}),
			rootsJSON(0, ent{"A", pa, ""}),
		)
		got := returnsOf(rep)
		if len(got) != 1 || got[0].Path != listPathOf(setN(3)) {
			t.Errorf("findings %v", lines(got))
		}
	})
	t.Run("a fingerprint that was held under another pin, after a list that cannot be read", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, f1}), bad, rootsJSON(0, ent{"C", pc, f1}))
		got := returnsOf(rep)
		if len(got) != 1 || !strings.Contains(got[0].Detail, "OpenPGP fingerprint") || !strings.Contains(got[0].Detail, "cannot be read") {
			t.Errorf("findings %v", lines(got))
		}
	})
}

// A list of exactly 26 entries is read; 27 cannot be read.
func TestRootReturnsAListMayHaveTwentySixEntries(t *testing.T) {
	var all []ent
	for i := 0; i < 26; i++ {
		all = append(all, ent{string(rune('A' + i)), pinOf(200 + i), ""})
	}
	rep := runLists(t, rootsJSON(0, all...), rootsJSON(0), rootsJSON(0, all...))
	if got := returnsOf(rep); len(got) != 26 {
		t.Fatalf("%d findings, want 26", len(got))
	}
	for _, f := range rep.Findings {
		if f.Code == AnchorUnknown && strings.Contains(f.Detail, "cannot be read") {
			t.Errorf("a list of 26 entries cannot be read: %s", f.Line())
		}
	}
	all = append(all, ent{"A", pinOf(300), ""})
	rep = runLists(t, rootsJSON(0, all[:26]...), rootsJSON(0), rootsJSON(0, all...))
	has(t, rep, AnchorUnknown, listPathOf(setN(3)))
	if got := returnsOf(rep); len(got) != 0 {
		t.Errorf("a list of 27 entries was read: %v", lines(got))
	}
	if MaxRootsPerList != 26 {
		t.Errorf("MaxRootsPerList = %d", MaxRootsPerList)
	}
}

// Entries that name no key are not counted against the list's 26: the number is of entries of
// roots as the file has them, so a list of 26 entries and 1 with no pin cannot be read either.
func TestRootReturnsTheLimitOfTheListCountsEveryEntryOfRoots(t *testing.T) {
	var all []ent
	for i := 0; i < 26; i++ {
		all = append(all, ent{"A", pinOf(200 + i), ""})
	}
	all = append(all, ent{"Z", "", ""})
	rep := runLists(t, rootsJSON(0, all...))
	has(t, rep, AnchorUnknown, listPathOf(setN(1)))
}

// The detail is bounded, and shows a label of the file only with escapes.
func TestRootReturnsLabelsOfTheFileAreEscapedAndCut(t *testing.T) {
	cases := []struct {
		name, label, shown string
	}{
		{"plain", "A", `A`},
		{"a letter beyond ASCII", rn(0xe9), bs + "u00e9"},
		{"a line break", "A\nB", `A\u000aB`},
		{"a carriage return", "A\rB", `A\u000dB`},
		{"a tab", "A\tB", `A\u0009B`},
		{"an escape", "A\x1b[31m", `A\u001b[31m`},
		{"a right to left override", "A" + rn(0x202e) + "B", "A" + bs + "u202eB"},
		{"a zero width space", "A" + rn(0x200b) + "B", "A" + bs + "u200bB"},
		{"a backslash", `A\B`, `A\\B`},
		{"a backslash and the text of an escape", bs + "u0041", bs + bs + "u0041"},
		{"a space", "A B", `A\x20B`},
		{"a character beyond the first plane", rn(0x1f600), bs + "ud83d" + bs + "ude00"},
		// The reader keeps 16 bytes of a label (cut at a character, with three dots); the detail
		// shows what it keeps with at most 48 bytes of escapes.
		{"16 bytes are kept whole", strings.Repeat("A", 16), strings.Repeat("A", 16)},
		{"17 bytes are cut", strings.Repeat("A", 17), strings.Repeat("A", 16) + "..."},
		{"a long label is cut", strings.Repeat("A", 1000), strings.Repeat("A", 16) + "..."},
		{"escapes that make 48 bytes are kept whole", strings.Repeat("\x01", 8), strings.Repeat(`\u0001`, 8)},
		{"escapes that make 54 bytes are cut", strings.Repeat("\x01", 9), strings.Repeat(`\u0001`, 8) + "..."},
		{"a long label of characters is cut inside no character", "A" + strings.Repeat(rn(0xe9), 9), "A" + strings.Repeat(bs+"u00e9", 7) + "..."},
		{"a long label of four byte characters", strings.Repeat(rn(0x1f600), 5), strings.Repeat(bs+"ud83d"+bs+"ude00", 4) + "..."},
		{"a long label of backslashes", strings.Repeat(`\`, 40), strings.Repeat(`\\`, 16) + "..."},
		{"a long label of controls", strings.Repeat("\x01", 20), strings.Repeat(`\u0001`, 8) + "..."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rep := runLists(t, rootsJSON(0, ent{c.label, pa, ""}), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{c.label, pa, ""}))
			got := returnsOf(rep)
			if len(got) != 1 {
				t.Fatalf("%d findings", len(got))
			}
			if want := `root key "` + c.shown + `" returns: `; !strings.HasPrefix(got[0].Detail, want) {
				t.Errorf("the detail is %q, want it to start with %q", got[0].Detail, want)
			}
			if !printable(got[0].Line()) || strings.ContainsAny(got[0].Line(), "\r\n") {
				t.Errorf("the line is not one line of printable ASCII: %q", got[0].Line())
			}
		})
	}
}

// A label cannot make a second line or a second finding: the code and the path stay in front of the
// line, and the label stays one quoted word of the detail.
func TestRootReturnsALabelCannotForgeALine(t *testing.T) {
	forged := "A\nroot-returns x: y"
	rep := runLists(t, rootsJSON(0, ent{forged, pa, ""}), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{forged, pa, ""}))
	got := returnsOf(rep)
	if len(got) != 1 {
		t.Fatalf("%d findings", len(got))
	}
	if strings.ContainsAny(got[0].Line(), "\r\n") || strings.Count(got[0].Line(), "root-returns ") != 1 {
		t.Errorf("the line %q", got[0].Line())
	}
	if !strings.HasPrefix(got[0].Line(), "root-returns "+listPathOf(setN(3))+": root key \"A") {
		t.Errorf("the line %q", got[0].Line())
	}
}

// A long name of a set is escaped and the detail is cut to its bound.
func TestRootReturnsDetailWithLongNamesOfSetsIsCutAndStaysOneLine(t *testing.T) {
	long := func(n int, c string) string { return fmt.Sprintf("%d-", n) + strings.Repeat(c, 200) }
	rep := runChain(t,
		cset{long(1, "a"), rootsJSON(0, ent{"A", pa, f1})},
		cset{long(2, "b"), rootsJSON(0, ent{"B", pb, ""})},
		cset{long(3, "c"), rootsJSON(0, ent{"A", pa, f1})},
	)
	got := returnsOf(rep)
	if len(got) != 1 {
		t.Fatalf("%d findings: %v", len(got), lines(got))
	}
	if len(got[0].Detail) > maxDetail+len("...") || !strings.HasSuffix(got[0].Detail, "...") {
		t.Errorf("the detail has %d bytes and ends %q", len(got[0].Detail), got[0].Detail[len(got[0].Detail)-10:])
	}
	if !strings.HasPrefix(got[0].Detail, `root key "A" returns: its pin `) {
		t.Errorf("the detail %q", got[0].Detail)
	}
}

// A folder of trust/ whose name breaks the rule for names is not a trust set: it is unexpected-name,
// its list is not read, and what it holds neither returns nor hides a return in the others.
func TestRootReturnsFolderWithAHostileNameIsNotATrustSet(t *testing.T) {
	names := []string{"1-a b", "1-a" + bs + "b", "1-caf" + rn(0xe9), "1-a:b", "1-a*b"}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			m := chainMem(t, inOrder(rootsJSON(0), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{"A", pa, ""}))...)
			// The folder holds a key that left; its name breaks the rule, so it is not a trust set.
			addList(m, n, rootsJSON(0, ent{"A", pa, ""}))
			rep, err := runMem(t, m)
			if err != nil {
				t.Fatal(err)
			}
			checkReport(t, rep)
			wantReturns(t, rep)
			found := false
			for _, f := range rep.Findings {
				found = found || f.Code == UnexpectedName
			}
			if !found {
				t.Errorf("no unexpected-name for the folder: %v", findingsOf(rep))
			}
		})
	}
}

// At most 1,000 findings of one code are kept, and the rest are counted.
func TestRootReturnsKeepsAThousandFindingsAndCountsTheRest(t *testing.T) {
	var all []ent
	for i := 0; i < 26; i++ {
		all = append(all, ent{string(rune('A' + i)), pinOf(400 + i), ""})
	}
	var lists [][]byte
	n := 80
	for i := 1; i <= n; i++ {
		if i%2 == 1 {
			lists = append(lists, rootsJSON(0, all...))
		} else {
			lists = append(lists, rootsJSON(0))
		}
	}
	rep := runLists(t, lists...)
	// The lists 3, 5, ..., 79 return: 39 lists of 26 findings.
	const total = 39 * 26
	if got := len(returnsOf(rep)); got != MaxFindingsPerCode {
		t.Errorf("%d findings kept, want %d", got, MaxFindingsPerCode)
	}
	if rep.Omitted != total-MaxFindingsPerCode {
		t.Errorf("Omitted = %d, want %d", rep.Omitted, total-MaxFindingsPerCode)
	}
	if !slices.Contains(rep.Reasons(), RootReturns) {
		t.Errorf("Reasons() = %v", rep.Reasons())
	}
}

// The same entry twice in a list that returns is a finding for each entry.
func TestRootReturnsTheSameKeyTwiceInOneListIsTwoFindings(t *testing.T) {
	rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0), rootsJSON(0, ent{"A", pa, ""}, ent{"B", pa, ""}))
	if got := returnsOf(rep); len(got) != 2 {
		t.Errorf("%d findings: %v", len(got), lines(got))
	}
}

// The fields that the list has beyond those the check reads are not looked into.
func TestRootReturnsReadsListsWithOtherMembers(t *testing.T) {
	extra := []byte(`{"expires_at":"2027-01-01T00:00:00Z","roots":[{"future":{"a":[1,2]},"label":"A","x509_spki_sha256":"` + pa + `"}],"sequence":4,"signed_at":"2026-11-15T12:00:00Z","unknown":[{"x":true}],"version":1}`)
	rep := runLists(t, extra, rootsJSON(0, ent{"B", pb, ""}), extra)
	wantReturns(t, rep, ret{list: 3, label: "A"})
}

// Many sets that no record lists, which all follow no record and so tie: bounded work, and every
// list that holds a key that another list may precede is a finding (the order is not sure).
func TestRootReturnsManySetsThatTieFinishInBoundedTime(t *testing.T) {
	const sets = 60000
	lists := make(map[string][]byte, sets)
	for i := 1; i <= sets; i++ {
		// Every list holds a new key; every 500th list holds the first key again.
		pin := pinOf(1000 + i)
		if i%500 == 0 {
			pin = pinOf(1001)
		}
		lists[setN(i)] = rootsJSON(0, ent{"A", pin, ""})
	}
	rep, err := runMem(t, memBundle(lists))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	// The first list holds the first key too: 120 lists that hold it again and the first.
	if got, want := len(returnsOf(rep)), sets/500+1; got != want {
		t.Errorf("%d findings, want %d", got, want)
	}
	for _, f := range returnsOf(rep) {
		if !strings.Contains(f.Detail, notSure) {
			t.Fatalf("the detail does not say that the order is not sure: %q", f.Detail)
		}
	}
}

// Many ceremonies in a chain: the order is sure and the work is bounded.
func TestRootReturnsManyCeremoniesInAChainFinishInBoundedTime(t *testing.T) {
	const sets = 3000
	cs := make([]cset, sets)
	for i := 1; i <= sets; i++ {
		pin := pinOf(1000 + i)
		if i%100 == 0 {
			pin = pinOf(1001)
		}
		cs[i-1] = cset{list: rootsJSON(0, ent{"A", pin, ""})}
	}
	rep := runChain(t, cs...)
	if got, want := len(returnsOf(rep)), sets/100; got != want {
		t.Errorf("%d findings, want %d", got, want)
	}
	for _, f := range returnsOf(rep) {
		if strings.Contains(f.Detail, notSure) {
			t.Fatalf("the order is sure: %q", f.Detail)
		}
	}
}

// The largest number of entries that a run keeps (MaxRootEntries) is read; one more stops the run
// with ErrTooMuch and no report.
func TestRootReturnsLargestNumberOfEntriesIsReadAndOneMoreIsRefused(t *testing.T) {
	build := func(total int) *mnode {
		lists := map[string][]byte{}
		var pins []ent
		for i := 0; i < 26; i++ {
			pins = append(pins, ent{string(rune('A' + i)), pinOf(5000 + i), ""})
		}
		left, i := total, 1
		for left > 0 {
			k := min(26, left)
			if i%2 == 1 {
				lists[setN(i)] = rootsJSON(0, pins[:k]...)
			} else {
				// A list of other keys: each pin of its own, so that the lists have no key in common.
				var es []ent
				for j := 0; j < k; j++ {
					es = append(es, ent{"A", pinOf(100000 + i*26 + j), ""})
				}
				lists[setN(i)] = rootsJSON(0, es...)
			}
			left -= k
			i++
		}
		return memBundle(lists)
	}
	t.Run("exactly MaxRootEntries", func(t *testing.T) {
		rep, err := runMem(t, build(MaxRootEntries))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if got := len(returnsOf(rep)); got != MaxFindingsPerCode {
			t.Errorf("%d findings kept, want %d", got, MaxFindingsPerCode)
		}
		if rep.Omitted == 0 {
			t.Error("no finding was counted as not shown")
		}
	})
	t.Run("one more", func(t *testing.T) {
		rep, err := runMem(t, build(MaxRootEntries+1))
		if !errors.Is(err, ErrTooMuch) || rep != nil {
			t.Errorf("Check = %v, %v; want ErrTooMuch and no report", rep, err)
		}
	})
}

func TestRootReturnsLimitOnEntriesCanBeLoweredAndCountsKeptEntriesOnly(t *testing.T) {
	lim := func(n int) *limits {
		return &limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode, rootEntries: n}
	}
	three := func(base int) []byte {
		return rootsJSON(0, ent{"A", pinOf(base), ""}, ent{"B", pinOf(base + 1), ""}, ent{"C", pinOf(base + 2), ""})
	}
	run := func(t *testing.T, n int, lists map[string][]byte) (*Report, error) {
		t.Helper()
		return runFS(t, memFS{memBundle(lists)}, lim(n))
	}
	t.Run("at the limit", func(t *testing.T) {
		if _, err := run(t, 6, map[string][]byte{setN(1): three(10), setN(2): three(20)}); err != nil {
			t.Errorf("Check: %v", err)
		}
	})
	t.Run("one over", func(t *testing.T) {
		rep, err := run(t, 5, map[string][]byte{setN(1): three(10), setN(2): three(20)})
		if !errors.Is(err, ErrTooMuch) || rep != nil {
			t.Errorf("Check = %v, %v", rep, err)
		}
		if err != nil && !strings.Contains(err.Error(), "5") {
			t.Errorf("the error does not name the limit: %v", err)
		}
	})
	t.Run("a list with an entry that names no key cannot be read and counts nothing", func(t *testing.T) {
		l := rootsJSON(0, ent{"A", pinOf(1), ""}, ent{"B", "", ""}, ent{"E", pinOf(2), ""})
		rep, err := run(t, 0, map[string][]byte{setN(1): l})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
	})
	t.Run("an entry with a fingerprint and no pin is a key and counts", func(t *testing.T) {
		l := rootsJSON(0, ent{"A", pinOf(1), ""}, ent{"C", "", f1})
		if _, err := run(t, 2, map[string][]byte{setN(1): l}); err != nil {
			t.Errorf("Check: %v", err)
		}
		if rep, err := run(t, 1, map[string][]byte{setN(1): l}); !errors.Is(err, ErrTooMuch) || rep != nil {
			t.Errorf("two keys at a limit of one: %v, %v", rep, err)
		}
	})
	t.Run("a list with a pin that cannot be read does not count", func(t *testing.T) {
		l := rootsJSON(0, ent{"E", pa[:10], ""})
		rep, err := run(t, 0, map[string][]byte{setN(1): l})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
	})
	t.Run("a list that cannot be read does not count", func(t *testing.T) {
		if _, err := run(t, 3, map[string][]byte{setN(1): three(10), setN(2): []byte(`{`), setN(3): []byte(`{"roots":"x"}`)}); err != nil {
			t.Errorf("Check: %v", err)
		}
	})
	t.Run("a list of 27 entries does not count", func(t *testing.T) {
		var es []ent
		for i := 0; i < 27; i++ {
			es = append(es, ent{"A", pinOf(300 + i), ""})
		}
		rep, err := run(t, 1, map[string][]byte{setN(1): rootsJSON(0, es...)})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		has(t, rep, AnchorUnknown, listPathOf(setN(1)))
	})
	t.Run("a list that a record lists counts once", func(t *testing.T) {
		// The list is read for the digest of the record that lists it, and again for its anchor: the
		// entries of one file are counted when the file is read, once.
		b := newBundle(t)
		b.apply(withRoots(ent{"A", pinOf(1), ""}, ent{"B", pinOf(2), ""}))
		b.apply(withRoots(ent{"A", pinOf(1), ""}, ent{"B", pinOf(2), ""}))
		root, err := fsx.OpenFS(b.dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		if _, err := runFS(t, root, lim(4)); err != nil {
			t.Errorf("four entries at a limit of four: %v", err)
		}
		if rep, err := runFS(t, root, lim(3)); !errors.Is(err, ErrTooMuch) || rep != nil {
			t.Errorf("four entries at a limit of three: %v, %v", rep, err)
		}
	})
}

// The reader of the bytes of a root list.
func TestParseAnchorReadsWhatTheCheckNeeds(t *testing.T) {
	newR := func(n int) *reader { return &reader{entriesLeft: n, entryLimit: n} }
	t.Run("the members", func(t *testing.T) {
		data := []byte(`{"last_record_sha256":"` + digestA + `","roots":[{"label":"A","openpgp_fingerprint":"` + f1 + `","x509_spki_sha256":"` + pa + `"},{"label":"B","x509_spki_sha256":"` + pb + `"}],"sequence":12,"version":1}`)
		a, err := newR(10).parseAnchor(data)
		if err != nil {
			t.Fatal(err)
		}
		if !a.present || a.value != digestA || a.problem != "" || !a.hasSequence || a.sequence != 12 || len(a.keys) != 2 {
			t.Fatalf("anchor %+v", a)
		}
		k := a.keys[0]
		if k.label != "A" || !k.hasFP || hexOf(k.pin[:]) != pa || hexOf(k.fp[:]) != f1 {
			t.Errorf("key 0 = %+v", k)
		}
		if k := a.keys[1]; k.label != "B" || k.hasFP || hexOf(k.pin[:]) != pb {
			t.Errorf("key 1 = %+v", k)
		}
	})
	t.Run("no anchor and no sequence", func(t *testing.T) {
		a, err := newR(10).parseAnchor([]byte(`{"roots":[],"version":1}`))
		if err != nil || a.present || a.hasSequence || a.problem != "" || len(a.keys) != 0 {
			t.Errorf("anchor %+v, error %v", a, err)
		}
	})
	t.Run("a list with no roots member", func(t *testing.T) {
		a, err := newR(10).parseAnchor([]byte(`{"version":1}`))
		if err != nil || a.problem != "" || len(a.keys) != 0 {
			t.Errorf("anchor %+v, error %v", a, err)
		}
	})
	t.Run("a sequence of zero is a sequence", func(t *testing.T) {
		a, err := newR(10).parseAnchor([]byte(`{"sequence":0,"version":1}`))
		if err != nil || !a.hasSequence || a.sequence != 0 {
			t.Errorf("anchor %+v, error %v", a, err)
		}
	})
	t.Run("a problem is a text that says the list cannot be read", func(t *testing.T) {
		for _, bad := range []string{`{`, `{"roots":"x"}`, `[]`, ``, "{\"a\":\"\xff\"}"} {
			a, err := newR(10).parseAnchor([]byte(bad))
			if err != nil || !strings.HasPrefix(a.problem, "the root list cannot be read: ") || len(a.keys) != 0 {
				t.Errorf("%q: anchor %+v, error %v", bad, a, err)
			}
		}
	})
	t.Run("27 entries", func(t *testing.T) {
		var b bytes.Buffer
		b.WriteString(`{"roots":[`)
		for i := 0; i < 27; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{}`)
		}
		b.WriteString(`]}`)
		r := newR(1000)
		a, err := r.parseAnchor(b.Bytes())
		if err != nil || !strings.Contains(a.problem, "more than 26 entries") {
			t.Errorf("anchor %+v, error %v", a, err)
		}
		if r.entriesLeft != 1000 {
			t.Errorf("entries were counted for a list that cannot be read: %d left", r.entriesLeft)
		}
	})
	t.Run("26 entries that name no key make a list that cannot be read, and count nothing", func(t *testing.T) {
		var b bytes.Buffer
		b.WriteString(`{"roots":[`)
		for i := 0; i < 26; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`{}`)
		}
		b.WriteString(`]}`)
		r := newR(0)
		a, err := r.parseAnchor(b.Bytes())
		if err != nil || !strings.Contains(a.problem, "entry 0 of roots has neither a pin nor an OpenPGP fingerprint") || len(a.keys) != 0 || r.entriesLeft != 0 {
			t.Errorf("anchor %+v, error %v", a, err)
		}
	})
	t.Run("the count", func(t *testing.T) {
		r := newR(3)
		two := []byte(`{"roots":[{"x509_spki_sha256":"` + pa + `"},{"label":"B","openpgp_fingerprint":"` + f1 + `"}]}`)
		if _, err := r.parseAnchor(two); err != nil {
			t.Fatal(err)
		}
		if r.entriesLeft != 1 {
			t.Errorf("%d left, want 1", r.entriesLeft)
		}
		a, err := r.parseAnchor(two)
		if !errors.Is(err, ErrTooMuch) || a != nil {
			t.Errorf("anchor %v, error %v", a, err)
		}
	})
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }

// rn is the character with the code c.
func rn(c rune) string { return string(c) }
