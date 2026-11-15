//go:build linux || darwin

package history

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
)

// A root list with no sequence member is refused by a host as malformed (root-list page), so the
// check reports it as the finding anchor-unknown, with the case in the detail. The keys of such a
// list are still read, so that it hides no key from the later lists.

// noSequenceDetail is the detail of the finding for a list that has no sequence member.
const noSequenceDetail = "the root list has no sequence, and a sequence is an integer of at least 1; its keys are still read"

// noSequenceList is a root list with a version, the anchor when there is one, and no sequence.
func noSequenceList(last string) []byte {
	m := map[string]any{"version": 1}
	if last != "" {
		m["last_record_sha256"] = last
	}
	return must(canonjson.Marshal(m))
}

// wantNoSequence fails the test unless the finding anchor-unknown at path says that the list has no
// sequence, with exactly the words of the page.
func wantNoSequence(t testing.TB, rep *Report, path string) {
	t.Helper()
	if d := detail(rep, AnchorUnknown, path); d != noSequenceDetail {
		t.Errorf("the detail of %s is %q, want %q", path, d, noSequenceDetail)
	}
}

func TestRootListWithNoSequenceIsAnchorUnknown(t *testing.T) {
	t.Run("a set that a record lists, in the middle", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		two := b.apply(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList(r.record.PrevRecordSHA256)
			r.refresh()
		})
		b.apply()
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, rootListPath(two)}})
		wantNoSequence(t, rep, rootListPath(two))
		wantReasons(t, rep, []Code{AnchorUnknown}, nil)
		if rep.Clean() {
			t.Error("Clean() = true")
		}
	})
	t.Run("the first set", func(t *testing.T) {
		b := newBundle(t)
		first := b.apply(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList("")
			r.refresh()
		})
		b.apply()
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, rootListPath(first)}})
		wantNoSequence(t, rep, rootListPath(first))
	})
	t.Run("the only set", func(t *testing.T) {
		b := newBundle(t)
		only := b.apply(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList("")
			r.refresh()
		})
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, rootListPath(only)}})
		if _, _, ok := rep.End(); !ok {
			t.Error("the end of the history is not told: the walk of the records was not touched")
		}
	})
	t.Run("a set that no record lists", func(t *testing.T) {
		b := newBundle(t)
		b.apply(noSet)
		b.put("trust/1-aaaaaaaa/root-list.json", noSequenceList(""))
		rep := b.run()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/1-aaaaaaaa"}, {AnchorUnknown, "trust/1-aaaaaaaa/root-list.json"}})
		wantNoSequence(t, rep, "trust/1-aaaaaaaa/root-list.json")
	})
	t.Run("a set that no record lists and that is not the first", func(t *testing.T) {
		// The list has no anchor either: both facts are told.
		b, _ := threeRecords(t)
		b.put("trust/4-3fa9c1d6/root-list.json", noSequenceList(""))
		rep := b.run()
		wantFindings(t, rep, []wf{{TrustSetUnlisted, "trust/4-3fa9c1d6"}, {AnchorUnknown, "trust/4-3fa9c1d6/root-list.json"}, {AnchorUnknown, "trust/4-3fa9c1d6/root-list.json"}})
		var details []string
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown {
				details = append(details, f.Detail)
			}
		}
		slices.Sort(details)
		if len(details) != 2 || details[0] != "the root list has no last_record_sha256, and the set is not the first one" || details[1] != noSequenceDetail {
			t.Errorf("the details are %q; want both the anchor and the sequence", details)
		}
	})
	t.Run("a set of an unfinished ceremony", func(t *testing.T) {
		b := newBundle(t)
		b.apply()
		open := b.unfinished(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList(b.end)
			r.refresh()
		})
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, "trust/" + open.set}, {AnchorUnknown, rootListPath(open)}})
		wantNoSequence(t, rep, rootListPath(open))
	})
	t.Run("the first set of an unfinished ceremony", func(t *testing.T) {
		b := newBundle(t)
		open := b.unfinished(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList("")
			r.refresh()
		})
		rep := b.run()
		wantFindings(t, rep, []wf{{UnfinishedCeremony, "trust/" + open.set}, {AnchorUnknown, rootListPath(open)}})
	})
	t.Run("a leftover set that a closing record lists", func(t *testing.T) {
		b := newBundle(t)
		stopped := b.unfinished(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList("")
			r.refresh()
		})
		b.closing(stopped, listsLeftover(stopped, nil))
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, rootListPath(stopped)}})
		wantNoSequence(t, rep, rootListPath(stopped))
	})
	t.Run("every set of a bundle", func(t *testing.T) {
		// The example of the page: two sets, 1-aaaaaaaa and 2-bbbbbbbb, no sequence in either list.
		b := chainBundle(t, false,
			cset{"1-aaaaaaaa", noSequenceList("")}, cset{"2-bbbbbbbb", noSequenceList("")})
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf("1-aaaaaaaa")}, {AnchorUnknown, listPathOf("2-bbbbbbbb")}})
		wantNoSequence(t, rep, listPathOf("1-aaaaaaaa"))
		wantNoSequence(t, rep, listPathOf("2-bbbbbbbb"))
		if got := rep.Reasons(); !slices.Equal(got, []Code{AnchorUnknown}) {
			t.Errorf("Reasons() = %v", got)
		}
	})
	t.Run("a list that has a sequence is not touched", func(t *testing.T) {
		b := chainBundle(t, false, cset{"1-aaaaaaaa", keyList(1, kA)}, cset{"2-bbbbbbbb", keyList(2, kA)})
		wantFindings(t, b.run(), nil)
	})
}

// Whatever else a list holds, when it has no sequence member it is this finding.
func TestRootListWithNoSequenceMemberIsTheSameFindingWhateverElseItHolds(t *testing.T) {
	for name, list := range map[string]string{
		"roots and no member":  `{"roots":[{"label":"A","x509_spki_sha256":"` + pa + `"}],"version":1}`,
		"no member":            `{"version":1}`,
		"an empty object":      `{}`,
		"only a version":       `{"version":2}`,
		"unknown members only": `{"comment":"x","roots":[],"version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			b := chainBundle(t, false, cset{"1-aaaaaaaa", []byte(list)})
			rep := b.run()
			wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf("1-aaaaaaaa")}})
			wantNoSequence(t, rep, listPathOf("1-aaaaaaaa"))
		})
	}
}

// A list with no sequence and a list with the sequence 0 are two findings with two details.
func TestNoSequenceAndSequenceZeroAreTwoFindingsWithTwoDetails(t *testing.T) {
	b := chainBundle(t, false,
		cset{"1-aaaaaaaa", noSequenceList("")}, cset{"2-bbbbbbbb", seqList("0", kA)})
	rep := b.run()
	wantFindings(t, rep, []wf{
		{AnchorUnknown, listPathOf("1-aaaaaaaa")}, {AnchorUnknown, listPathOf("2-bbbbbbbb")}, {TrustSequence, "trust/2-bbbbbbbb"},
	})
	d1, d2 := detail(rep, AnchorUnknown, listPathOf("1-aaaaaaaa")), detail(rep, AnchorUnknown, listPathOf("2-bbbbbbbb"))
	if d1 == d2 {
		t.Errorf("one detail for two cases: %q", d1)
	}
	if !strings.Contains(d1, "no sequence") || strings.Contains(d1, "sequence of 0") {
		t.Errorf("the detail for no sequence is %q", d1)
	}
	if !strings.Contains(d2, "sequence of 0") || strings.Contains(d2, "no sequence") {
		t.Errorf("the detail for the sequence 0 is %q", d2)
	}
}

// The keys of a list with no sequence are read, as for a sequence below 1: a key that is on it and
// leaves, or is missing from it and comes back, is found.
func TestKeysOfAListWithNoSequenceAreStillRead(t *testing.T) {
	t.Run("a key is on the list with no sequence, leaves, and returns", func(t *testing.T) {
		b := chainBundle(t, false,
			cset{setN(1), rootsJSON(0, kA, kB)}, cset{setN(2), keyList(2, kB)}, cset{setN(3), keyList(3, kA, kB)})
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf(setN(1))}, {RootReturns, listPathOf(setN(3))}})
		wantReturns(t, rep, ret{list: 3, label: "A"})
	})
	t.Run("a key is missing from the list with no sequence and comes back", func(t *testing.T) {
		b := chainBundle(t, false,
			cset{setN(1), keyList(1, kA, kB)}, cset{setN(2), rootsJSON(0, kB)}, cset{setN(3), keyList(3, kA, kB)})
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf(setN(2))}, {RootReturns, listPathOf(setN(3))}})
		wantReturns(t, rep, ret{list: 3, label: "A"})
	})
	t.Run("the list with no sequence is the last one, and a key has gone", func(t *testing.T) {
		b := chainBundle(t, false,
			cset{setN(1), keyList(1, kA, kB)}, cset{setN(2), keyList(2, kB)}, cset{setN(3), rootsJSON(0, kA, kB)})
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf(setN(3))}, {RootReturns, listPathOf(setN(3))}})
		wantReturns(t, rep, ret{list: 3, label: "A"})
	})
	t.Run("a key that never left is not found", func(t *testing.T) {
		b := chainBundle(t, false,
			cset{setN(1), keyList(1, kA, kB)}, cset{setN(2), rootsJSON(0, kA, kB)}, cset{setN(3), keyList(3, kA, kB)})
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf(setN(2))}})
	})
	t.Run("in memory the same", func(t *testing.T) {
		m := chainMem(t, cset{setN(1), rootsJSON(0, kA, kB)}, cset{setN(2), keyList(2, kB)}, cset{setN(3), keyList(3, kA, kB)})
		rep, err := runMem(t, m)
		if err != nil {
			t.Fatal(err)
		}
		wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf(setN(1))}, {RootReturns, listPathOf(setN(3))}})
	})
}

// The finding for a missing sequence does not change what trust-sequence says: a list with no
// sequence is not compared with the number of its folder, and its folder number still takes its
// place in the order of the numbers.
func TestNoSequenceIsNotComparedWithTheFolderNumber(t *testing.T) {
	t.Run("a number that skips", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(5), rootsJSON(0, kA)}, cset{setN(6), keyList(6, kA)})
		wantFindings(t, b.run(), []wf{{AnchorUnknown, listPathOf(setN(5))}})
	})
	t.Run("a number that does not grow is still trust-sequence", func(t *testing.T) {
		b := chainBundle(t, false, cset{"2-aaaaaaaa", keyList(2, kA)}, cset{"2-bbbbbbbb", rootsJSON(0, kA)})
		rep := b.run()
		wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf("2-bbbbbbbb")}, {TrustSequence, "trust/2-bbbbbbbb"}})
		if d := detail(rep, TrustSequence, "trust/2-bbbbbbbb"); strings.Contains(d, "is not the sequence of its root list") {
			t.Errorf("the detail compares the number with a sequence that is not there: %q", d)
		}
	})
	t.Run("a name with no number is still trust-sequence", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{"02-aaaaaaaa", rootsJSON(0, kA)})
		wantFindings(t, b.run(), []wf{{AnchorUnknown, listPathOf("02-aaaaaaaa")}, {TrustSequence, "trust/02-aaaaaaaa"}})
	})
}

// A report with the finding has neither a State nor an OrderErr: the finding is the reason.
func TestInspectGivesNoStateForAListWithNoSequence(t *testing.T) {
	for _, mem := range []bool{false, true} {
		t.Run(fmt.Sprint("in memory ", mem), func(t *testing.T) {
			b := chainBundle(t, mem, cset{setN(1), keyList(1, kA)}, cset{setN(2), noSequenceList("")})
			if mem {
				in, err := inspectFS(t, memFS{b.mem})
				if err != nil || in == nil {
					t.Fatalf("Inspect = %v, %v", in, err)
				}
				wantFailed(t, in, []wf{{AnchorUnknown, listPathOf(setN(2))}})
				return
			}
			in := b.inspect()
			wantFailed(t, in, []wf{{AnchorUnknown, listPathOf(setN(2))}})
			if in.Report.Clean() {
				t.Error("the report is clean")
			}
		})
	}
	t.Run("a bundle whose lists all have a sequence has a State", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)}, cset{setN(2), keyList(2, kA)})
		wantState(t, b.inspect(), setN(1), setN(2))
	})
}

// A list that cannot be read has its own finding only: it has no sequence to speak of, and the
// second finding is not told.
func TestAListThatCannotBeReadIsNotAlsoAListWithNoSequence(t *testing.T) {
	cases := map[string][]byte{
		"cut short":              []byte(`{"version":1`),
		"an array":               []byte(`[]`),
		"not JSON":               []byte("garbage"),
		"an empty file":          nil,
		"null for the number":    []byte(`{"sequence":null,"version":1}`),
		"null and roots":         []byte(`{"roots":[{"label":"A","x509_spki_sha256":"` + pa + `"}],"sequence":null,"version":1}`),
		"a text for the number":  []byte(`{"sequence":"1","version":1}`),
		"a fraction":             []byte(`{"sequence":1.5,"version":1}`),
		"an exponent":            []byte(`{"sequence":1e0,"version":1}`),
		"a boolean":              []byte(`{"sequence":true,"version":1}`),
		"an array for a number":  []byte(`{"sequence":[1],"version":1}`),
		"an object for a number": []byte(`{"sequence":{},"version":1}`),
		"beyond 2^53":            []byte(`{"sequence":9007199254740993,"version":1}`),
		"forty digits":           []byte(`{"sequence":` + strings.Repeat("9", 40) + `,"version":1}`),
		"the member twice":       []byte(`{"sequence":1,"sequence":1,"version":1}`),
		"a byte order mark":      []byte("\xef\xbb\xbf" + `{"sequence":1,"version":1}`),
		"text after the object":  []byte(`{"sequence":1,"version":1} x`),
		"a lone surrogate":       []byte(`{"note":"\ud800","sequence":1,"version":1}`),
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			b := chainBundle(t, false, cset{"1-aaaaaaaa", list})
			rep := b.run()
			wantFindings(t, rep, []wf{{AnchorUnknown, listPathOf("1-aaaaaaaa")}})
			d := detail(rep, AnchorUnknown, listPathOf("1-aaaaaaaa"))
			if !strings.HasPrefix(d, "the root list cannot be read: ") || strings.Contains(d, "no sequence") {
				t.Errorf("the detail is %q", d)
			}
		})
	}
}

// A list with no sequence and a bad anchor is two findings at one path: each fact is told, and the
// report keeps them in its fixed order (by detail, for one code and one path).
func TestFindingsOfOneListWithNoSequenceAreInOrder(t *testing.T) {
	t.Run("an anchor that is no record", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		second := b.apply(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList(digestB)
			r.refresh()
		})
		rep := b.run()
		var details []string
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown && f.Path == rootListPath(second) {
				details = append(details, f.Detail)
			}
		}
		if len(details) != 2 || !slices.Contains(details, noSequenceDetail) || !strings.Contains(strings.Join(details, "|"), "is not the record before the ceremony") {
			t.Fatalf("the details are %q", details)
		}
		if !slices.IsSorted(details) {
			t.Errorf("the findings of one path are not in the fixed order: %q", details)
		}
		wantFindings(t, rep, []wf{{AnchorUnknown, rootListPath(second)}, {AnchorUnknown, rootListPath(second)}})
	})
	t.Run("a list that is not the first and has no anchor", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		second := b.apply(func(r *rec) {
			r.artifacts[rootListPath(r)] = noSequenceList("")
			r.refresh()
		})
		rep := b.run()
		var details []string
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown && f.Path == rootListPath(second) {
				details = append(details, f.Detail)
			}
		}
		if len(details) != 2 || !slices.Contains(details, noSequenceDetail) || !strings.Contains(strings.Join(details, "|"), "has no last_record_sha256") {
			t.Fatalf("the details are %q", details)
		}
	})
	t.Run("a digest that is not a digest", func(t *testing.T) {
		b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
		second := b.apply(func(r *rec) {
			r.artifacts[rootListPath(r)] = []byte(`{"last_record_sha256":"zz","version":1}`)
			r.refresh()
		})
		rep := b.run()
		var details []string
		for _, f := range rep.Findings {
			if f.Code == AnchorUnknown && f.Path == rootListPath(second) {
				details = append(details, f.Detail)
			}
		}
		if len(details) != 2 || !slices.Contains(details, noSequenceDetail) || !slices.Contains(details, "last_record_sha256 is not a SHA-256 digest") {
			t.Fatalf("the details are %q", details)
		}
	})
}

// A history of many sets with no sequence is bounded as every finding is: the first thousand are
// kept and the count of the rest is said.
func TestFindingsOfListsWithNoSequenceAreBounded(t *testing.T) {
	const sets = MaxFindingsPerCode + 101
	list := make([]cset, sets)
	for i := range list {
		list[i] = cset{fmt.Sprintf("%d-%08x", i+1, i), rootsJSON(0, kA)}
	}
	rep, err := runMem(t, chainMem(t, list...))
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	if n := countCode(rep, AnchorUnknown); n != MaxFindingsPerCode {
		t.Errorf("%d findings of anchor-unknown are kept, want %d", n, MaxFindingsPerCode)
	}
	if rep.Omitted != sets-MaxFindingsPerCode {
		t.Errorf("Omitted = %d, want %d", rep.Omitted, sets-MaxFindingsPerCode)
	}
	if rep.Clean() {
		t.Error("clean")
	}
}

// A list with no sequence that is hostile in another way is one finding and no crash: the run
// ends with a report, reads each file once, and changes nothing.
func TestHostileListWithNoSequenceIsOneFinding(t *testing.T) {
	deep := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	cases := map[string][]byte{
		"nested arrays 20,000 deep":  []byte(`{"pad":` + deep + `,"version":1}`),
		"more than 256 KiB":          []byte(`{"note":"` + strings.Repeat("a", 300<<10) + `","version":1}`),
		"bytes that are not UTF-8":   []byte("{\"note\":\"\xff\xfe\xc3\",\"version\":1}"),
		"a NUL in a text":            []byte("{\"note\":\"a\x00b\",\"version\":1}"),
		"27 entries of roots":        []byte(`{"roots":[` + strings.TrimSuffix(strings.Repeat(`{"label":"A","x509_spki_sha256":"`+pa+`"},`, 27), ",") + `],"version":1}`),
		"roots a text":               []byte(`{"roots":"A","version":1}`),
		"roots null":                 []byte(`{"roots":null,"version":1}`),
		"an entry that is a number":  []byte(`{"roots":[7],"version":1}`),
		"a pin that is a number":     []byte(`{"roots":[{"label":"A","x509_spki_sha256":5}],"version":1}`),
		"the sequence in a capital":  []byte(`{"Sequence":1,"version":1}`),
		"the sequence in an entry":   []byte(`{"roots":[{"label":"A","sequence":1,"x509_spki_sha256":"` + pa + `"}],"version":1}`),
		"the sequence in a sub-list": []byte(`{"extra":{"sequence":1},"version":1}`),
	}
	for name, list := range cases {
		t.Run(name, func(t *testing.T) {
			b := chainBundle(t, true, cset{"1-aaaaaaaa", list})
			rep, err := runMem(t, b.mem)
			if err != nil {
				t.Fatal(err)
			}
			checkReport(t, rep)
			if n := countCode(rep, AnchorUnknown); n != 1 {
				t.Errorf("%d findings of anchor-unknown: %v", n, findingsOf(rep))
			}
			if rep.Clean() {
				t.Error("clean")
			}
		})
	}
}

// A link or a FIFO in place of the list is a list that cannot be read: one finding, and not the
// finding for no sequence; the check does not wait on the pipe.
func TestRootListThatIsALinkOrAPipeIsNotAListWithNoSequence(t *testing.T) {
	t.Run("a link to a list", func(t *testing.T) {
		b := newBundle(t)
		one := b.apply(noSet)
		b.put("elsewhere.json", keyList(1, kA))
		b.symlink("../../elsewhere.json", "trust/1-3fa9c1d3/root-list.json")
		_ = one
		rep := b.run()
		d := detail(rep, AnchorUnknown, listPathOf("1-3fa9c1d3"))
		if !strings.HasPrefix(d, "the root list cannot be read: ") {
			t.Errorf("the detail is %q; findings %v", d, findingsOf(rep))
		}
	})
	t.Run("a FIFO", func(t *testing.T) {
		b := newBundle(t)
		b.apply(noSet)
		b.fifo("trust/1-3fa9c1d3/root-list.json")
		rep := b.run()
		d := detail(rep, AnchorUnknown, listPathOf("1-3fa9c1d3"))
		if !strings.HasPrefix(d, "the root list cannot be read: ") {
			t.Errorf("the detail is %q; findings %v", d, findingsOf(rep))
		}
	})
}

// The reader says "no sequence" exactly when the standard decoder finds no member or a null.
func FuzzRootListSequenceFinding(f *testing.F) {
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"sequence":null,"version":1}`))
	f.Add([]byte(`{"sequence":1,"version":1}`))
	f.Add([]byte(`{"sequence":0,"version":1}`))
	f.Add([]byte(`{"sequence":-3,"version":1}`))
	f.Add([]byte(`{"sequence":"1","version":1}`))
	f.Add([]byte(`{"sequence":9007199254740993,"version":1}`))
	f.Add([]byte(`{"roots":[{"label":"A","x509_spki_sha256":"` + pa + `"}],"version":1}`))
	f.Add([]byte(`{"extra":{"sequence":1},"version":1}`))
	f.Add([]byte(`{`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip("large")
		}
		b := chainBundle(t, true, cset{"1-aaaaaaaa", data})
		rep, err := runMem(t, b.mem)
		if err != nil || rep == nil {
			t.Fatalf("Check = %v, %v", rep, err)
		}
		checkReport(t, rep)
		path := listPathOf("1-aaaaaaaa")
		d := detail(rep, AnchorUnknown, path)
		var loose map[string]json.RawMessage // member names are matched exactly
		wellFormed := json.Unmarshal(data, &loose) == nil && loose != nil
		seq, present := loose["sequence"]
		noMember := wellFormed && (!present || string(seq) == "null")
		if noMember && d == "" {
			// A well-formed object with no member, or a null: never clean, and never silent.
			t.Fatalf("no finding for a list with no sequence: %q", data)
		}
		if d == noSequenceDetail && !noMember {
			t.Fatalf("the finding says no sequence, and the list has the member: %q", data)
		}
		if rep.Clean() && d != "" {
			t.Fatalf("clean with a finding: %q", data)
		}
	})
}
