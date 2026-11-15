//go:build linux || darwin

package history

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
)

// The finding root-returns (record 0006, rule 54; docs/reference/ceremony-record.md, "The hash
// chain", the row root-returns): a root list holds a root key whose pin, or whose OpenPGP
// fingerprint under another pin, an earlier root list of the bundle held and the root list before
// it did not. The check reads every trust set, also a set that no ceremony record lists. The tests
// of this file build the lists in memory, as trust sets that no record lists, and look at the
// findings of this one code only: the other findings of such a bundle are not what is tested here.

// ent is one entry of the member roots, as a test writes it. An empty text leaves its member out.
type ent struct{ label, pin, fp string }

func (e ent) member() map[string]any {
	m := map[string]any{}
	if e.label != "" {
		m["label"] = e.label
	}
	if e.pin != "" {
		m["x509_spki_sha256"] = e.pin
	}
	if e.fp != "" {
		m["openpgp_fingerprint"] = e.fp
	}
	return m
}

// rootsJSON is a root list with the entries given and, when seq is not 0, the member sequence.
func rootsJSON(seq int64, ents ...ent) []byte {
	roots := make([]any, 0, len(ents))
	for _, e := range ents {
		roots = append(roots, e.member())
	}
	m := map[string]any{"version": 1, "roots": roots}
	if seq != 0 {
		m["sequence"] = seq
	}
	return must(canonjson.Marshal(m))
}

// pinOf and fpOf are the nth pin (64 lower-case digits) and the nth OpenPGP fingerprint (40).
func pinOf(n int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("pin %d", n)))
	return hex.EncodeToString(h[:])
}

func fpOf(n int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("fingerprint %d", n)))
	return hex.EncodeToString(h[:20])
}

// setN is the name of the nth trust set; listPathOf the path of its root list.
func setN(n int) string { return fmt.Sprintf("%d-aaaaaaaa", n) }

func listPathOf(set string) string { return "trust/" + set + "/root-list.json" }

// memBundle is a bundle in memory with no ceremony record and the root lists given, by set.
func memBundle(lists map[string][]byte) *mnode {
	m := newMem()
	m.file("ritueel.yaml", "name: x\n")
	m.put("history", &mnode{kind: "dir", kids: map[string]*mnode{}})
	m.put("trust", &mnode{kind: "dir", kids: map[string]*mnode{}})
	for set, data := range lists {
		m.put(listPathOf(set), &mnode{kind: "file", data: data})
	}
	return m
}

// returnsOf returns the findings of the code root-returns.
func returnsOf(rep *Report) []Finding {
	var out []Finding
	for _, f := range rep.Findings {
		if f.Code == RootReturns {
			out = append(out, f)
		}
	}
	return out
}

// runLists runs the check on a chain of ceremonies, one for each list, in the order given: the
// list at position i is in the set setN(i+1), written by the ceremony i+1.
func runLists(t *testing.T, lists ...[]byte) *Report {
	t.Helper()
	return runChain(t, inOrder(lists...)...)
}

// ret is what a test expects of one finding: the list (counted from 1, in the order the test gives
// them), the label named in the detail, and texts that the detail has and has not.
type ret struct {
	list  int
	label string
	has   []string
	not   []string
}

// wantReturns fails unless the findings of root-returns are exactly want, in any order.
func wantReturns(t testing.TB, rep *Report, want ...ret) {
	t.Helper()
	got := returnsOf(rep)
	if len(got) != len(want) {
		t.Errorf("%d findings of root-returns, want %d:", len(got), len(want))
		for _, f := range got {
			t.Errorf("  %s", f.Line())
		}
		return
	}
	used := make([]bool, len(got))
	for _, w := range want {
		path := listPathOf(setN(w.list))
		prefix := `root key "` + w.label + `" returns`
		found := false
		for i, f := range got {
			if used[i] || f.Path != path || !strings.HasPrefix(f.Detail, prefix) {
				continue
			}
			ok := true
			for _, h := range w.has {
				if !strings.Contains(f.Detail, h) {
					t.Errorf("the finding %q lacks %q", f.Line(), h)
					ok = false
				}
			}
			for _, n := range w.not {
				if strings.Contains(f.Detail, n) {
					t.Errorf("the finding %q has %q", f.Line(), n)
					ok = false
				}
			}
			_ = ok
			used[i], found = true, true
			break
		}
		if !found {
			t.Errorf("no finding of root-returns at %s for the label %q; the findings are %v", path, w.label, lines(got))
		}
	}
}

func lines(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Line())
	}
	return out
}

var (
	pa, pb, pc, pd = pinOf(1), pinOf(2), pinOf(3), pinOf(4)
	f1, f2         = fpOf(1), fpOf(2)
)

func short16(pin string) string { return pin[:16] + "..." }

// The row of the page, case by case. Each case gives the lists in the order of the bundle.
func TestRootReturnsWalk(t *testing.T) {
	cases := []struct {
		name  string
		lists [][]ent
		want  []ret
	}{
		{"a key that stays in two lists", [][]ent{{{"A", pa, ""}}, {{"A", pa, ""}}}, nil},
		{"a key that stays in four lists", [][]ent{{{"A", pa, ""}}, {{"A", pa, ""}}, {{"A", pa, ""}}, {{"A", pa, ""}}}, nil},
		{"a key that leaves and never returns", [][]ent{{{"A", pa, ""}, {"B", pb, ""}}, {{"B", pb, ""}}, {{"B", pb, ""}}}, nil},
		{"the first list holds keys and has no list before it", [][]ent{{{"A", pa, ""}, {"B", pb, ""}}}, nil},
		{"two lists with different keys", [][]ent{{{"A", pa, ""}}, {{"B", pb, ""}}}, nil},
		{"a key that leaves and returns with the same label",
			[][]ent{{{"A", pa, ""}}, {{"B", pb, ""}}, {{"A", pa, ""}, {"B", pb, ""}}},
			[]ret{{list: 3, label: "A", has: []string{
				wPin(pa) + wRule,
				wHeldPin(setN(1)),
				wBefore(setN(2)),
			}, not: []string{"OpenPGP"}}}},
		{"a key that leaves and returns with a new label",
			[][]ent{{{"A", pa, ""}}, {{"B", pb, ""}}, {{"C", pa, ""}}},
			[]ret{{list: 3, label: "C", has: []string{wPin(pa), wHeldPin(setN(1))}}}},
		{"a key that returns after two lists without it",
			[][]ent{{{"A", pa, ""}}, {{"B", pb, ""}}, {{"B", pb, ""}}, {{"A", pa, ""}, {"B", pb, ""}}},
			[]ret{{list: 4, label: "A", has: []string{wHeldPin(setN(1)), wBefore(setN(3))}}}},
		{"a key that returns and then stays is a finding in the list it returns in only",
			[][]ent{{{"A", pa, ""}}, {{"B", pb, ""}}, {{"A", pa, ""}}, {{"A", pa, ""}}, {{"A", pa, ""}}},
			[]ret{{list: 3, label: "A"}}},
		{"a key that returns twice has a finding each time",
			[][]ent{{{"A", pa, ""}}, {{"B", pb, ""}}, {{"A", pa, ""}}, {{"B", pb, ""}}, {{"A", pa, ""}}},
			[]ret{{list: 3, label: "A"}, {list: 5, label: "A"}, {list: 4, label: "B"}}},
		{"the finding names the first list that held the pin",
			[][]ent{{{"A", pa, ""}}, {{"A", pa, ""}}, {{"B", pb, ""}}, {{"A", pa, ""}}},
			[]ret{{list: 4, label: "A", has: []string{wHeldPin(setN(1)) + "; "}}}},
		{"two returns in one list",
			[][]ent{{{"A", pa, ""}, {"B", pb, ""}}, {{"C", pc, ""}}, {{"A", pa, ""}, {"B", pb, ""}, {"C", pc, ""}}},
			[]ret{{list: 3, label: "A"}, {list: 3, label: "B"}}},
		{"a key that is added for the first time in a later list is no return",
			[][]ent{{{"A", pa, ""}}, {{"A", pa, ""}, {"B", pb, ""}}, {{"A", pa, ""}, {"B", pb, ""}, {"C", pc, ""}}}, nil},
		{"an empty list between two lists that hold the key",
			[][]ent{{{"A", pa, ""}}, {}, {{"A", pa, ""}}},
			[]ret{{list: 3, label: "A"}}},
		{"a list that holds a key twice does not return to itself",
			[][]ent{{{"A", pa, ""}, {"B", pa, ""}}, {{"A", pa, ""}, {"B", pa, ""}}}, nil},

		// The OpenPGP fingerprint.
		{"a fingerprint that returns under another pin",
			[][]ent{{{"A", pa, f1}}, {{"B", pb, ""}}, {{"C", pc, f1}}},
			[]ret{{list: 3, label: "C", has: []string{
				wFP(f1) + wRule,
				wHeldFP(setN(1)),
				wBefore(setN(2)),
			}, not: []string{"its pin"}}}},
		{"a fingerprint that stays under its pin",
			[][]ent{{{"A", pa, f1}}, {{"A", pa, f1}}, {{"A", pa, f1}}}, nil},
		{"a fingerprint that returns with the pin that held it is both cases, in one finding",
			[][]ent{{{"A", pa, f1}}, {{"B", pb, ""}}, {{"A", pa, f1}}},
			[]ret{{list: 3, label: "A", has: []string{"its pin " + short16(pa), "its OpenPGP fingerprint " + f1[:16]}}}},
		{"a key and a fingerprint that both return are one finding",
			[][]ent{{{"A", pa, ""}}, {{"C", pc, f1}}, {{"B", pb, ""}}, {{"X", pa, f1}}},
			[]ret{{list: 4, label: "X", has: []string{"its pin", "OpenPGP fingerprint"}}}},
		{"a pin that changes under its fingerprint in one step is a finding at the list that changes it",
			[][]ent{{{"A", pa, f1}}, {{"A", pb, f1}}},
			[]ret{{list: 2, label: "A", has: []string{
				wFP(f1) + wRule,
				wHeldFP(setN(1)),
				wBefore(setN(1)),
			}, not: []string{"its pin"}}}},
		{"a pin that changes in each list and keeps its fingerprint is a finding at each change",
			[][]ent{{{"A", pa, f1}}, {{"A", pb, f1}}, {{"A", pc, f1}}, {{"A", pd, f1}}},
			[]ret{{list: 2, label: "A"}, {list: 3, label: "A"}, {list: 4, label: "A"}}},
		{"a fingerprint under a new pin after a list that did not hold it",
			[][]ent{{{"A", pa, f1}}, {{"B", pb, ""}}, {{"A", pc, f1}}},
			[]ret{{list: 3, label: "A", has: []string{"OpenPGP fingerprint"}}}},
		{"a fingerprint that was held under two pins and returns under a third",
			[][]ent{{{"A", pa, f1}}, {{"A", pb, f1}}, {{"B", pd, ""}}, {{"C", pc, f1}}},
			[]ret{{list: 2, label: "A", has: []string{"OpenPGP fingerprint"}}, {list: 4, label: "C", has: []string{"OpenPGP fingerprint"}}}},
		{"a fingerprint that a pin gains after the pin was held without it",
			[][]ent{{{"A", pa, ""}}, {{"A", pa, f1}}, {{"A", pa, f1}}}, nil},
		{"a fingerprint added to a pin that held it before, under another pin",
			[][]ent{{{"A", pa, f1}}, {{"B", pb, f1}}, {{"A", pa, ""}}, {{"A", pa, f1}}},
			[]ret{{list: 2, label: "B", has: []string{"OpenPGP fingerprint"}, not: []string{"its pin"}},
				{list: 3, label: "A", has: []string{"its pin"}},
				{list: 4, label: "A", has: []string{"OpenPGP fingerprint"}, not: []string{"its pin"}}}},
		{"a fingerprint dropped from its pin and put back is a return of the fingerprint (rule 54: under any pin)",
			[][]ent{{{"A", pa, f1}}, {{"A", pa, ""}}, {{"A", pa, f1}}},
			[]ret{{list: 3, label: "A", has: []string{"its OpenPGP fingerprint " + f1[:16]}, not: []string{"its pin"}}}},
		{"a fingerprint changed under a pin that stays and put back",
			[][]ent{{{"A", pa, f1}}, {{"A", pa, f2}}, {{"A", pa, f1}}},
			[]ret{{list: 3, label: "A", has: []string{"its OpenPGP fingerprint " + f1[:16]}, not: []string{"its pin"}}}},
		{"a fingerprint that returns under the same pin after a gap",
			[][]ent{{{"A", pa, f1}}, {{"B", pb, ""}}, {{"C", pc, ""}}, {{"A", pa, f1}}},
			[]ret{{list: 4, label: "A", has: []string{"its pin " + short16(pa), "its OpenPGP fingerprint " + f1[:16]}}}},
		{"a fingerprint that returns under another pin after a gap",
			[][]ent{{{"A", pa, f1}}, {{"B", pb, ""}}, {{"C", pc, ""}}, {{"D", pd, f1}}},
			[]ret{{list: 4, label: "D", has: []string{"its OpenPGP fingerprint " + f1[:16]}, not: []string{"its pin"}}}},
		{"a fingerprint with no pin that leaves and returns",
			[][]ent{{{"A", "", f1}}, {{"B", pb, ""}}, {{"A", "", f1}}},
			[]ret{{list: 3, label: "A", has: []string{"its OpenPGP fingerprint " + f1[:16]}, not: []string{"its pin"}}}},
		{"a fingerprint with no pin that stays",
			[][]ent{{{"A", "", f1}}, {{"A", "", f1}}, {{"A", "", f1}}}, nil},
		{"a fingerprint with no pin that moves to a pin in one step",
			[][]ent{{{"A", "", f1}}, {{"A", pa, f1}}},
			[]ret{{list: 2, label: "A", has: []string{"its OpenPGP fingerprint " + f1[:16]}}}},
		{"a fingerprint that is new in a later list is no return",
			[][]ent{{{"A", pa, f1}}, {{"A", pa, f1}, {"B", pb, f2}}}, nil},
		{"a key that stays is not reported again by its fingerprint in a later list",
			[][]ent{{{"A", pa, f1}}, {{"A", pb, f1}}, {{"A", pb, f1}}, {{"A", pb, f1}}},
			[]ret{{list: 2, label: "A"}}},
		{"another fingerprint under a pin that was held is no return",
			[][]ent{{{"A", pa, f1}}, {{"A", pa, f2}}}, nil},
		{"a fingerprint with no pin is a key held by its fingerprint",
			[][]ent{{{"A", pa, f1}}, {{"B", pb, ""}}, {{"C", "", f1}}},
			[]ret{{list: 3, label: "C", has: []string{wFP(f1), wHeldFP(setN(1)), wBefore(setN(2))}, not: []string{"its pin"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var lists [][]byte
			for _, l := range c.lists {
				lists = append(lists, rootsJSON(0, l...))
			}
			wantReturns(t, runLists(t, lists...), c.want...)
		})
	}
}

// A finding that has both reasons says both, once.
func TestRootReturnsFindingWithBothReasonsIsOneFindingThatSaysBoth(t *testing.T) {
	rep := runLists(t,
		rootsJSON(0, ent{"A", pa, ""}),
		rootsJSON(0, ent{"C", pc, f1}),
		rootsJSON(0, ent{"B", pb, ""}),
		rootsJSON(0, ent{"X", pa, f1}),
	)
	got := returnsOf(rep)
	if len(got) != 1 {
		t.Fatalf("%d findings: %v", len(got), lines(got))
	}
	d := got[0].Detail
	for _, s := range []string{
		`root key "X" returns: ` + wBoth(pa, f1) + wRule,
		"; " + wHeldPin(setN(1)) + "; fingerprint held",
	} {
		if !strings.Contains(d, s) {
			t.Errorf("the detail %q lacks %q", d, s)
		}
	}
	if got[0].Path != listPathOf(setN(4)) {
		t.Errorf("path %q", got[0].Path)
	}
	// The detail is kept to 240 bytes, so that with both reasons the names that come last are cut
	// off (the finding still says which two reasons it has, and the reasons come first).
	if len(d) > maxDetail+len("...") {
		t.Errorf("a detail of %d bytes", len(d))
	}
}

// A swap of the pin under one fingerprint, in one step (a revoked OpenPGP primary that takes a new
// X.509 key): record 0006, rule 54 says the fingerprint of an entry that left is on no later list
// under any pin, so the list that makes the swap has the finding, and the lists after it that keep
// the new pin have none. The row of the page ("and the root list before it did not") is read the
// same way: the list before does not hold this key.
func TestRootReturnsASwapOfThePinThatKeepsTheFingerprintIsAFindingAtTheListThatMakesIt(t *testing.T) {
	t.Run("the swap is the newest list", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, f1}), rootsJSON(0, ent{"A", pb, f1}))
		wantReturns(t, rep, ret{list: 2, label: "A", has: []string{"OpenPGP fingerprint"}})
	})
	t.Run("the lists after the swap that keep the new pin have no finding", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, f1}), rootsJSON(0, ent{"A", pb, f1}), rootsJSON(0, ent{"A", pb, f1}),
			rootsJSON(0, ent{"A", pb, f1}), rootsJSON(0, ent{"A", pb, f1}))
		wantReturns(t, rep, ret{list: 2, label: "A"})
	})
	t.Run("a gap between the swap and the older list", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, f1}), rootsJSON(0), rootsJSON(0, ent{"C", pc, f1}), rootsJSON(0, ent{"C", pc, f1}),
			rootsJSON(0, ent{"C", pc, f1}))
		wantReturns(t, rep, ret{list: 3, label: "C"})
	})
	t.Run("a key that merely stays is never a finding by its fingerprint", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, f1}), rootsJSON(0, ent{"A", pa, f1}), rootsJSON(0, ent{"A", pa, f1}))
		wantReturns(t, rep)
	})
}

// The rule "the key is the pin": the label plays no part in either direction.
func TestRootReturnsTheLabelIsNotTheKey(t *testing.T) {
	t.Run("the label of a key that stays may change", func(t *testing.T) {
		wantReturns(t, runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0, ent{"B", pa, ""}), rootsJSON(0, ent{"C", pa, ""})))
	})
	t.Run("a label that was held by another pin is a new key", func(t *testing.T) {
		wantReturns(t, runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0, ent{"A", pb, ""}), rootsJSON(0, ent{"A", pc, ""})))
	})
	t.Run("an entry with no label is judged by its pin", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"", pa, ""}), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{"", pa, ""}))
		got := returnsOf(rep)
		if len(got) != 1 || !strings.HasPrefix(got[0].Detail, `root key "" returns`) {
			t.Errorf("findings %v", lines(got))
		}
	})
}

// The form in which keys are compared is the bytes the digits stand for: the case of a digit is
// not a difference. (The reader of `verify root-list` would refuse such a list; this check reads
// it, so that a list that was changed by hand cannot hide a key behind the case of a digit.)
func TestRootReturnsPinsAndFingerprintsAreComparedAsBytes(t *testing.T) {
	up := strings.ToUpper
	t.Run("a pin in capitals returns", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{"A", up(pa), ""}))
		wantReturns(t, rep, ret{list: 3, label: "A", has: []string{"its pin " + short16(pa)}})
	})
	t.Run("a pin in capitals that was held in capitals returns in lower case", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", up(pa), ""}), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{"A", pa, ""}))
		wantReturns(t, rep, ret{list: 3, label: "A"})
	})
	t.Run("a pin of mixed case that stays", func(t *testing.T) {
		mixed := strings.ToUpper(pa[:20]) + pa[20:]
		rep := runLists(t, rootsJSON(0, ent{"A", pa, ""}), rootsJSON(0, ent{"A", mixed, ""}), rootsJSON(0, ent{"A", up(pa), ""}))
		wantReturns(t, rep)
	})
	t.Run("a fingerprint in capitals returns under another pin", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, f1}), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{"C", pc, up(f1)}))
		wantReturns(t, rep, ret{list: 3, label: "C", has: []string{"OpenPGP fingerprint " + f1[:16]}})
	})
	t.Run("a fingerprint in capitals that stays under its pin", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", pa, f1}), rootsJSON(0, ent{"A", pa, up(f1)}), rootsJSON(0, ent{"A", pa, f1}))
		wantReturns(t, rep)
	})
	t.Run("the digits that are shown are lower case", func(t *testing.T) {
		rep := runLists(t, rootsJSON(0, ent{"A", up(pa), up(f1)}), rootsJSON(0, ent{"B", pb, ""}), rootsJSON(0, ent{"A", up(pa), up(f1)}))
		for _, f := range returnsOf(rep) {
			if f.Detail != strings.ToLower(f.Detail) && strings.Contains(f.Detail, strings.ToUpper(pa[:16])) {
				t.Errorf("a pin in capitals in %q", f.Detail)
			}
		}
		wantReturns(t, rep, ret{list: 3, label: "A", has: []string{short16(pa)}})
	})
}

// A trust set with no root list is not in the sequence (a personal bundle's set has none); a set
// that no ceremony record lists is read all the same.
func TestRootReturnsSetsWithNoRootListAndSetsThatNoRecordLists(t *testing.T) {
	t.Run("a set with no root list in the middle is skipped", func(t *testing.T) {
		m := memBundle(map[string][]byte{
			setN(1): rootsJSON(0, ent{"A", pa, ""}),
			setN(3): rootsJSON(0, ent{"A", pa, ""}),
		})
		m.file("trust/"+setN(2)+"/root.pem", "x")
		rep, err := runMem(t, m)
		if err != nil {
			t.Fatal(err)
		}
		// The set with no list is not in the sequence, so the list before the third is the first,
		// and it holds the key.
		wantReturns(t, rep)
	})
	t.Run("a bundle with no root list at all", func(t *testing.T) {
		m := memBundle(nil)
		m.file("trust/"+setN(1)+"/root.pem", "x")
		m.file("trust/"+setN(2)+"/root.pem", "x")
		rep, err := runMem(t, m)
		if err != nil {
			t.Fatal(err)
		}
		wantReturns(t, rep)
	})
	t.Run("a bundle with no trust folder", func(t *testing.T) {
		m := newMem()
		m.file("ritueel.yaml", "name: x\n")
		m.put("history", &mnode{kind: "dir", kids: map[string]*mnode{}})
		rep, err := runMem(t, m)
		if err != nil {
			t.Fatal(err)
		}
		wantReturns(t, rep)
	})
	t.Run("a bundle with one root list", func(t *testing.T) {
		wantReturns(t, runLists(t, rootsJSON(0, ent{"A", pa, f1}, ent{"B", pb, ""})))
	})
	t.Run("a set that no record lists has its list read, and the record's set does too", func(t *testing.T) {
		b := newBundle(t)
		a := b.apply(withRoots(ent{"A", pa, ""}))
		b.apply(withRoots(ent{"B", pb, ""}))
		b.apply(withRoots(ent{"B", pb, ""}))
		// A set that nothing lists: it holds the key that left, and it follows the end of the chain.
		b.put(listPathOf("9-aaaaaaaa"), claims(rootsJSON(0, ent{"A", pa, ""}), b.end))
		rep := b.run()
		has(t, rep, TrustSetUnlisted, "trust/9-aaaaaaaa")
		got := returnsOf(rep)
		if len(got) != 1 || got[0].Path != listPathOf("9-aaaaaaaa") || !strings.Contains(got[0].Detail, wPin(pa)+wRule+"; "+wHeldPin(a.set)+"; list before") {
			t.Errorf("findings %v", lines(got))
		}
	})
}

// withRoots writes the root list of the trust set of a ceremony with these entries, anchored to the
// record before it as the other root lists of these bundles are.
func withRoots(ents ...ent) func(*rec) {
	return func(r *rec) {
		m := map[string]any{"version": 1, "sequence": int64(r.n)}
		roots := make([]any, 0, len(ents))
		for _, e := range ents {
			roots = append(roots, e.member())
		}
		m["roots"] = roots
		if r.record.PrevRecordSHA256 != "" {
			m["last_record_sha256"] = r.record.PrevRecordSHA256
		}
		r.artifacts["trust/"+r.set+"/root-list.json"] = must(canonjson.Marshal(m))
		r.refresh()
	}
}

// A whole bundle whose ceremonies are all in order: a key that stays gives a clean report, and the
// same bundle with one key that came back fails, with the name of the code in the reasons.
func TestRootReturnsInABundleOfCeremonies(t *testing.T) {
	t.Run("a key that stays and a key that leaves for good: clean", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withRoots(ent{"A", pa, f1}, ent{"B", pb, ""}))
		b.apply(withRoots(ent{"A", pa, f1}))
		b.apply(withRoots(ent{"A", pa, f1}, ent{"C", pc, ""}))
		rep := b.run()
		wantFindings(t, rep, nil)
		if !rep.Clean() {
			t.Errorf("not clean: %v", rep.Reasons())
		}
	})
	t.Run("a key that came back fails with exit meaning and a reason", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withRoots(ent{"A", pa, ""}, ent{"B", pb, ""}))
		b.apply(withRoots(ent{"A", pa, ""}))
		third := b.apply(withRoots(ent{"A", pa, ""}, ent{"B", pb, ""}))
		rep := b.run()
		wantFindings(t, rep, []wf{{RootReturns, listPathOf(third.set)}})
		wantReasons(t, rep, []Code{RootReturns}, nil)
		if rep.Clean() {
			t.Error("Clean() with a root key that came back")
		}
		if !RootReturns.Fails() || RootReturns.Notice() {
			t.Error("root-returns must be a failing finding, not a notice")
		}
		f := returnsOf(rep)[0]
		if want := "root-returns " + listPathOf(third.set) + ": root key"; !strings.HasPrefix(f.Line(), want) {
			t.Errorf("the line is %q", f.Line())
		}
	})
	t.Run("the end of the history is still printed for a refusal", func(t *testing.T) {
		b := newBundle(t)
		b.apply(withRoots(ent{"A", pa, ""}))
		b.apply(withRoots(ent{"B", pb, ""}))
		last := b.apply(withRoots(ent{"A", pa, ""}))
		rep := b.run()
		if eight, count, ok := rep.End(); count != 3 || !ok || eight != last.digest[:8] {
			t.Errorf("End() = %q, %d, %v", eight, count, ok)
		}
	})
}

// codes: root-returns is a name of the page, after anchor-unknown and before trust-sequence.
func TestRootReturnsIsAFailingCodeInThePlaceOfThePage(t *testing.T) {
	codes := Codes()
	i := slices.Index(codes, RootReturns)
	if i < 0 {
		t.Fatal("no code root-returns")
	}
	if codes[i-1] != AnchorUnknown || codes[i+1] != TrustSequence {
		t.Errorf("root-returns stands between %s and %s", codes[i-1], codes[i+1])
	}
	if string(RootReturns) != "root-returns" {
		t.Errorf("the name is %q", RootReturns)
	}
	if !RootReturns.Fails() || RootReturns.Notice() {
		t.Errorf("Fails() = %v, Notice() = %v", RootReturns.Fails(), RootReturns.Notice())
	}
}

// The bounds are the numbers the documentation of the package gives.
func TestRootReturnsBoundsAreTheDocumentedNumbers(t *testing.T) {
	if MaxRootEntries != 262144 || MaxRootsPerList != 26 {
		t.Errorf("MaxRootEntries = %d, MaxRootsPerList = %d; want 262144 and 26", MaxRootEntries, MaxRootsPerList)
	}
}
