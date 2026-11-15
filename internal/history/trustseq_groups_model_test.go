//go:build linux || darwin

package history

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// A second way to work out the finding trust-sequence for chains in which a record may list more
// than one set: the sets of one record are ordered by the sequence of their lists (a list with none
// last), then by the number in the folder name (a name with no trust number last), then by the
// name; each set is judged against the set directly before it that has a trust number, across the
// places of the chain.

// gset is one set of a record in a model chain: the digits of its name, the sequence of its list
// (none for a list with no sequence member), and the tag that makes its name unique.
type gset struct {
	digits string
	seq    int64
	none   bool
	tag    string
}

func (g gset) name() string { return g.digits + "-" + g.tag }

func (g gset) cset() cset {
	if g.none {
		return cset{g.name(), rootsJSON(0, kA)}
	}
	return cset{g.name(), seqList(strconv.FormatInt(g.seq, 10), kA)}
}

// modelGroups gives the findings trust-sequence and anchor-unknown for a chain of places, each a
// list of sets, with no fork and no closing record.
func modelGroups(places [][]gset) []wf {
	var out []wf
	var before int64
	have := false
	for _, place := range places {
		ordered := slices.Clone(place)
		slices.SortStableFunc(ordered, func(a, b gset) int {
			an, aok := modelNumber(a.name())
			bn, bok := modelNumber(b.name())
			return cmp.Or(
				cmp.Compare(boolInt(a.none), boolInt(b.none)),
				cmp.Compare(seqKey(a), seqKey(b)),
				cmp.Compare(boolInt(!aok), boolInt(!bok)),
				cmp.Compare(an, bn),
				strings.Compare(a.name(), b.name()),
			)
		})
		for _, g := range ordered {
			if !g.none && g.seq < 1 {
				out = append(out, wf{AnchorUnknown, listPathOf(g.name())})
			}
			n, ok := modelNumber(g.name())
			if !ok {
				out = append(out, wf{TrustSequence, "trust/" + g.name()})
				continue
			}
			if (!g.none && g.seq != n) || (have && n <= before) {
				out = append(out, wf{TrustSequence, "trust/" + g.name()})
			}
			before, have = n, true
		}
	}
	return out
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func seqKey(g gset) int64 {
	if g.none {
		return 0
	}
	return g.seq
}

// runGroups builds the chain in memory: one ceremony for each place, which lists the sets of the
// place in the order given.
func runGroups(t *testing.T, places [][]gset) (*bundle, *Report) {
	t.Helper()
	b := chainBundle(t, true)
	for _, place := range places {
		sets := make([]cset, len(place))
		for i, g := range place {
			sets[i] = g.cset()
		}
		b.apply(withSets(sets...))
	}
	rep, err := runMem(t, b.mem)
	if err != nil {
		t.Fatal(err)
	}
	checkReport(t, rep)
	return b, rep
}

func wantGroups(t *testing.T, places [][]gset) {
	t.Helper()
	b, rep := runGroups(t, places)
	var got []wf
	for _, f := range rep.Findings {
		if f.Code == TrustSequence || f.Code == AnchorUnknown {
			got = append(got, wf{f.Code, f.Path})
		}
	}
	want := modelGroups(places)
	if g, w := sortWF(got), sortWF(want); fmt.Sprint(g) != fmt.Sprint(w) {
		t.Fatalf("places %v\n got %v\nwant %v", places, g, w)
	}
	in, err := inspectFS(t, memFS{b.mem})
	if err != nil || in == nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !in.Report.Clean() && (in.State != nil || in.OrderErr != nil) {
		t.Fatalf("State %v, OrderErr %v with a failing report", in.State, in.OrderErr)
	}
	sameReport(t, in.Report, rep)
}

// Every record of two sets after one set, over the numbers 0 to 3 (0 is no trust number) and the
// sequences none and 0 to 3: the findings are those of the model.
func TestTrustSequenceTwoSetsOfOneRecordOverSmallNumbers(t *testing.T) {
	nums := []string{"0", "1", "2", "3", "02"}
	seqs := []int64{-1, 0, 1, 2, 3} // -1 stands for a list with no sequence member
	var sets []gset
	for _, d := range nums {
		for _, s := range seqs {
			sets = append(sets, gset{digits: d, seq: s, none: s < 0})
		}
	}
	first := gset{digits: "1", seq: 1, tag: "aaaaaaaa"}
	for _, x := range sets {
		x.tag = "bbbbbbbb"
		for _, y := range sets {
			y.tag = "cccccccc"
			wantGroups(t, [][]gset{{first}, {x, y}})
			// the order the record spells the sets in makes no difference
			wantGroups(t, [][]gset{{first}, {y, x}})
		}
	}
}

// Three places of up to three sets, from bytes.
func groupsFromBytes(data []byte) [][]gset {
	var places [][]gset
	letter := 0
	i := 0
	for len(places) < 3 && i < len(data) {
		size := int(data[i]%3) + 1
		i++
		var place []gset
		for k := 0; k < size && i+1 < len(data); k++ {
			num, seq := data[i], data[i+1]
			i += 2
			g := gset{digits: strconv.Itoa(int(num % 6)), tag: strings.Repeat(string(rune('a'+letter)), 8)}
			if num%6 == 5 {
				g.digits = "0" + g.digits // a name with a leading zero has no trust number
			}
			letter++
			if s := int64(seq % 7); s == 6 {
				g.none = true
			} else {
				g.seq = s
			}
			place = append(place, g)
		}
		if len(place) > 0 {
			places = append(places, place)
		}
	}
	return places
}

func FuzzTrustNumbersInGroups(f *testing.F) {
	f.Add([]byte{0, 1, 1, 1, 2, 2})
	f.Add([]byte{1, 2, 2, 2, 2, 0, 3, 3})
	f.Add([]byte{2, 5, 5, 1, 1, 6, 6, 0, 2, 3, 3})
	f.Add([]byte{1, 1, 1, 1, 4, 4, 1, 3, 3, 3, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		places := groupsFromBytes(data)
		if len(places) == 0 {
			return
		}
		wantGroups(t, places)
	})
}
