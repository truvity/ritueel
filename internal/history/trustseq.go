package history

import (
	"cmp"
	"slices"
	"strconv"
)

// trustSequence is the finding trust-sequence (record 0006, rules 14 and 21). Each trust set has a
// number in its folder name and a sequence in its root list, and a host refuses a list whose
// sequence is not higher than the one it holds. The finding takes the trust sets that ordinary
// ceremony records list, in the order of the chain of records, and says of each:
//
//   - the number in its folder name is not the sequence of its root list; or
//   - the number in its folder name is not higher than the number of the set before it; or
//   - its folder name has no trust number (see [trustNumber]), so neither can be said.
//
// A skip is allowed: a number higher than the one before it is right, however much higher. The
// order is the order of the chain and never the order of the numbers: the place of a set is the
// place of the record that lists it, as for [checker.rootReturns], so a number that goes down is
// found and not sorted away. The sets that are left out are those that stand at no sure place: the
// sets that a closing record lists, a set that two records list with different records before them,
// a set whose record is not on the chain, and the sets of a fork (records that name one record). A
// record that lists more than one set gives them one place: they are judged one after the other in
// the order that the package gives sets at one place (the sequence of their lists, then the number
// in the folder name, see [setKeys]), by the same rule as every other set, and the last of them is
// the set before for the next place. A set that no record lists is left out too: an unfinished
// ceremony is not judged here. A list that cannot be read, has no sequence, or is not there is a
// list with no sequence to compare; the number of its folder still takes its place in the order,
// and the lists that cannot be read have their own finding.
//
// It reads nothing: it works from what the one walk collected, so there is no second walk.
func (ck *checker) trustSequence() {
	if len(ck.listed) == 0 || (len(ck.recs) > 0 && len(ck.onChain) == 0) {
		return // no set is listed, or no record is on the chain: no set has a place
	}
	type judged struct {
		name  string
		place int
	}
	var sets []judged
	for name, w := range ck.listed {
		if w.conflict || w.closes != "" || ck.forked[w.prev] {
			continue
		}
		place, ok := ck.afterRecord(w.prev)
		if !ok {
			continue
		}
		sets = append(sets, judged{name, place})
	}
	seqOf := make(map[string]*anchorOf, len(ck.rootLists))
	for _, l := range ck.rootLists {
		seqOf[l.set] = l.read
	}
	// The places in the order of the chain. Inside one place (one record that lists more than one
	// set) the order is the one that the package gives sets at one place: the sequence of their
	// lists, a set with none after all that have one, then the number in the folder name (a name with
	// no trust number after all that have one), then the name. Every set of the place is judged by the
	// same rule as any other set, and the last of them is the set before for the next place.
	keys := make(map[string]setOrder, len(sets))
	for _, s := range sets {
		var k setOrder
		if n, ok := trustNumber(s.name); ok {
			k.numbered, k.number = true, n
		}
		if a := seqOf[s.name]; a != nil && a.hasSequence {
			k.hasSeq, k.sequence = true, a.sequence
		}
		keys[s.name] = k
	}
	slices.SortFunc(sets, func(a, b judged) int {
		ka, kb := keys[a.name], keys[b.name]
		return cmp.Or(
			cmp.Compare(a.place, b.place),
			cmpBool(!ka.hasSeq, !kb.hasSeq),
			cmp.Compare(ka.sequence, kb.sequence),
			cmpBool(!ka.numbered, !kb.numbered),
			cmp.Compare(ka.number, kb.number),
			cmp.Compare(a.name, b.name),
		)
	})
	var before string
	var beforeNumber int64
	haveBefore := false
	for _, s := range sets {
		n, ok := trustNumber(s.name)
		path := "trust/" + s.name
		if !ok {
			ck.col.add(TrustSequence, path, "its name has no trust number, so the number and the sequence of its root list cannot be compared (record 0006, rule 14)")
			continue
		}
		var why []string
		if a := seqOf[s.name]; a != nil && a.hasSequence && a.sequence != n {
			why = append(why, "the number in its name, "+strconv.FormatInt(n, 10)+", is not the sequence of its root list, "+strconv.FormatInt(a.sequence, 10))
		}
		if haveBefore && n <= beforeNumber {
			why = append(why, "the number in its name, "+strconv.FormatInt(n, 10)+", is not higher than "+strconv.FormatInt(beforeNumber, 10)+", the number of the set before it in the chain, "+setShown(before))
		}
		if len(why) > 0 {
			d := why[0]
			for _, w := range why[1:] {
				d += "; " + w
			}
			ck.col.add(TrustSequence, path, d+" (record 0006, rules 14 and 21)")
		}
		before, beforeNumber, haveBefore = s.name, n, true
	}
}

// cmpBool orders false before true.
func cmpBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	}
	return 1
}
