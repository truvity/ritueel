//go:build linux || darwin

package history

import (
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A model of the finding root-returns, written from the page and the record with none of the
// code's structure: no maps, no counts, no groups kept between sets. A bundle is a chain of
// ceremonies, each writing one trust set, and trust sets that no record lists, each saying which
// record it follows. The model puts the sets in every order that the rules allow and, for each
// order, looks at every entry against every earlier list and against the list directly before. The
// model and the check are run on the same random bundles; they must give the same findings, with
// the same reasons.
//
// The rules the model follows (record 0006, rules 8, 14 and 54):
//
//   - a set that a ceremony record lists follows the record before that ceremony, whatever its folder
//     number and its sequence say; the first ceremony follows none;
//   - a set that no record lists follows the record its list names, and none when it names none;
//   - when a record is not on the chain (its predecessor is not a record, or an earlier record is
//     not on the chain), the sets it lists and the sets that name it have no place that can be told;
//     so has a set that no record lists and whose list cannot be read, because it names nothing;
//   - the sets that follow one record are put in the order of the sequence of their lists, then of
//     the number of their folders; the order is sure when every set has both and they agree, and
//     then there is one order. When it is not sure two readings are judged, one by sequence and
//     one by number, and in a reading the sets that share a value, or have none, tie and may follow
//     one another in any order. A set that has none comes after the sets that have one;
//   - an entry is a return when an earlier list held its pin and the list directly before did not,
//     or when an earlier list held its OpenPGP fingerprint, under any pin, and the list directly
//     before does not hold it under the same pin (an entry with no pin has the pin none);
//   - a list that cannot be read holds no key; a list that follows it has an unknown list before it;
//   - the entry of a set whose place cannot be told is a return when any other list that can be
//     read held the pin, or the fingerprint under any pin; such lists are not part of the order.

type mEnt struct {
	label string
	pin   int // 0 for no pin, else 1..mPins
	fp    int // 0 for none, else 1..mFPs
	form  int // how the digits are written: 0 lower case, 1 upper case, 2 with 0x, 3 with colons
}

// mList is the content of one root list. damaged is 0 for a list that can be read, 1 for text that
// is not JSON, 2 for an entry that names neither a pin nor a fingerprint, 3 for a pin of 63 digits.
type mList struct {
	ents    []mEnt
	damaged int
	num     int // the number in the name of the set; -1 when the name has none
	seq     int // the member sequence; -1 when the list has none
}

const (
	mPins = 6
	mFPs  = 4
)

func writeForm(h string, form int) string {
	switch form {
	case 1:
		return strings.ToUpper(h)
	case 2:
		return "0x" + h
	case 3:
		return pairs(h, ":")
	}
	return h
}

func (e mEnt) json() string {
	p, f := "", ""
	if e.pin != 0 {
		p = writeForm(pinOf(e.pin), e.form)
	}
	if e.fp != 0 {
		f = writeForm(fpOf(e.fp), e.form)
	}
	return rawEntry(e.label, p, f)
}

func (l mList) bytes() []byte {
	var es []string
	for _, e := range l.ents {
		es = append(es, e.json())
	}
	switch l.damaged {
	case 1:
		return []byte(`{`)
	case 2:
		es = append(es, `{"label":"N"}`)
	case 3:
		es = append(es, rawEntry("P", pa[:63], ""))
	}
	seq := ""
	if l.seq >= 0 {
		seq = fmt.Sprintf(`,"sequence":%d`, l.seq)
	}
	return []byte(`{"roots":[` + strings.Join(es, ",") + `]` + seq + `,"version":1}`)
}

func (l mList) readable() bool { return l.damaged == 0 }

// Claims of a set (the field claim of mSet).
const (
	listedByCeremony        = -2 // a record lists the set (the field recs of the bundle says which)
	namesNoRecordOfTheChain = -1 // no record lists it, and its list names a digest that is no record
	namesNoRecord           = 0  // no record lists it, and its list names none
	// k > 0: no record lists it, and its list names the kth record of the chain
)

// mSet is one trust set of a model bundle.
type mSet struct {
	mList
	claim int
}

// mRec is one record of the chain, in order, and the sets it lists. closing says how the bundle
// is built (a record that closes a stopped ceremony and lists the files it left); the model treats
// it as any other record, because that is what the record says (rule 8: the chain is the order).
type mRec struct {
	lists   []int
	closing bool
}

// mBundle is the records in order, the sets, and the sets that no record lists. From the record
// brokenAt on (counted from 1; 0 for none), the records are not on the chain: that record names a
// predecessor that is no record. With no recs, the sets of claim listedByCeremony are written one
// by each ordinary record, in order.
type mBundle struct {
	sets     []mSet
	recs     []mRec
	brokenAt int
}

func (b mBundle) name(i int) string { return setNameOf(b.sets[i].mList, i) }

func setNameOf(l mList, i int) string {
	if l.num < 0 {
		return fmt.Sprintf("x-aaaaaaa%c", 'a'+i)
	}
	return fmt.Sprintf("%d-aaaaaaa%c", l.num, 'a'+i)
}

// records is the chain of the bundle.
func (b mBundle) records() []mRec {
	if b.recs != nil {
		return b.recs
	}
	var out []mRec
	for i, s := range b.sets {
		if s.claim == listedByCeremony {
			out = append(out, mRec{lists: []int{i}})
		}
	}
	return out
}

// placing is a set at a place of the chain; listed when a record that stands there lists it.
type mPlacing struct {
	set, place int
	listed     bool
}

// placings says where the set stands: at the place of every record that lists it and is on the
// chain (the place of a record is its number in the chain, from 0), and once for each place; a set
// that no record lists stands after the record that its list names, or at 0 when it names none.
// None means that the place cannot be told.
func (b mBundle) placings(i int) []mPlacing {
	s := b.sets[i]
	offChain := func(k int) bool { return b.brokenAt > 0 && k >= b.brokenAt }
	if s.claim == listedByCeremony {
		var out []mPlacing
		for ri, r := range b.records() {
			if !slices.Contains(r.lists, i) || offChain(ri+1) {
				continue
			}
			if !slices.ContainsFunc(out, func(p mPlacing) bool { return p.place == ri }) {
				out = append(out, mPlacing{set: i, place: ri, listed: true})
			}
		}
		return out
	}
	switch {
	case !s.readable():
		return nil // no record lists it, and what it names cannot be read
	case s.claim == namesNoRecordOfTheChain:
		return nil
	case s.claim == namesNoRecord:
		return []mPlacing{{set: i, place: 0}}
	case offChain(s.claim):
		return nil
	}
	return []mPlacing{{set: i, place: s.claim}}
}

// modelFinding is a finding as the model says it: the set, the label, and the two reasons.
type modelFinding struct {
	set      int
	label    string
	pin, fpr bool
	floating bool
	doubt    bool // the order of the sets around it is not sure
	prevGone bool // the list directly before it cannot be read
	multi    bool // the set stands at more than one place: its reasons are those of the first visit
}

func (m modelFinding) String() string {
	return fmt.Sprintf("set %d label %s pin=%v fingerprint=%v", m.set, m.label, m.pin, m.fpr)
}

func holdsPin(l mList, pin int) bool {
	if !l.readable() {
		return false
	}
	for _, o := range l.ents {
		if o.pin != 0 && o.pin == pin {
			return true
		}
	}
	return false
}

func holdsFPAny(l mList, fp int) bool {
	if !l.readable() {
		return false
	}
	for _, o := range l.ents {
		if o.fp == fp {
			return true
		}
	}
	return false
}

func holdsFPUnder(l mList, fp, pin int) bool {
	if !l.readable() {
		return false
	}
	for _, o := range l.ents {
		if o.fp == fp && o.pin == pin {
			return true
		}
	}
	return false
}

// judge says, for the lists in this order, which entries return and why: the pin case and the
// fingerprint case. A list that stands at two places is in the order twice.
func judge(sets []mSet, order []int) map[[2]int][2]bool {
	out := map[[2]int][2]bool{}
	for pos, li := range order {
		l := sets[li].mList
		if !l.readable() {
			continue
		}
		before := -1
		if pos > 0 {
			before = order[pos-1]
		}
		for ei, e := range l.ents {
			var pinCase, fpCase bool
			if e.pin != 0 {
				held := false
				for _, j := range order[:pos] {
					held = held || holdsPin(sets[j].mList, e.pin)
				}
				pinCase = held && (before < 0 || !holdsPin(sets[before].mList, e.pin))
			}
			if e.fp != 0 {
				held := false
				for _, j := range order[:pos] {
					held = held || holdsFPAny(sets[j].mList, e.fp)
				}
				fpCase = held && (before < 0 || !holdsFPUnder(sets[before].mList, e.fp, e.pin))
			}
			if pinCase || fpCase {
				prev := out[[2]int{li, ei}]
				out[[2]int{li, ei}] = [2]bool{prev[0] || pinCase, prev[1] || fpCase}
			}
		}
	}
	return out
}

func permutations(in []int) [][]int {
	if len(in) <= 1 {
		return [][]int{slices.Clone(in)}
	}
	var out [][]int
	for i := range in {
		rest := slices.Concat(in[:i:i], in[i+1:])
		for _, p := range permutations(rest) {
			out = append(out, append([]int{in[i]}, p...))
		}
	}
	return out
}

// orderIsSure says whether the sets of one place have one order: each has a number and a sequence,
// no two share either, and the sequences and the numbers put them in the same order.
func orderIsSure(sets []mSet, place []int) bool {
	for _, i := range place {
		if sets[i].num < 0 || sets[i].seq < 0 || !sets[i].readable() {
			return false
		}
	}
	for _, i := range place {
		for _, j := range place {
			if i == j {
				continue
			}
			a, b := sets[i], sets[j]
			if a.num == b.num || a.seq == b.seq || (a.num < b.num) != (a.seq < b.seq) {
				return false
			}
		}
	}
	return true
}

// mPlace is what stands at one place: the sets, and how many of them a record lists.
type mPlace struct {
	place  int
	sets   []int
	listed int
}

// readingGroups cuts the sets of each place, in the order of the places, into groups that tie in a
// reading: by sequence, or by number. In a group the sets share the value, or all have none; the
// groups of a place are in the order of the value, those with none last. A place where more than
// one listed set stands is one group.
func readingGroups(sets []mSet, places []mPlace, byNumber bool) [][]int {
	var groups [][]int
	val := func(i int) (int, bool) {
		if byNumber {
			return sets[i].num, sets[i].num >= 0
		}
		return sets[i].seq, sets[i].seq >= 0 && sets[i].readable()
	}
	for _, pl := range places {
		inPlace := pl.sets
		if pl.listed > 1 {
			groups = append(groups, slices.Clone(inPlace))
			continue
		}
		var values []int
		for _, i := range inPlace {
			if v, ok := val(i); ok && !slices.Contains(values, v) {
				values = append(values, v)
			}
		}
		slices.Sort(values)
		for _, v := range values {
			var g []int
			for _, i := range inPlace {
				if w, ok := val(i); ok && w == v {
					g = append(g, i)
				}
			}
			groups = append(groups, g)
		}
		var none []int
		for _, i := range inPlace {
			if _, ok := val(i); !ok {
				none = append(none, i)
			}
		}
		if len(none) > 0 {
			groups = append(groups, none)
		}
	}
	return groups
}

// ordersOf returns every order of the groups: the groups in sequence, the sets of a group in any
// order.
func ordersOf(groups [][]int) [][]int {
	orders := [][]int{nil}
	for _, g := range groups {
		var next [][]int
		for _, p := range permutations(g) {
			for _, o := range orders {
				next = append(next, append(slices.Clone(o), p...))
			}
		}
		orders = next
	}
	return orders
}

// seen is what one reading says of an entry that it shows as a return.
type seen struct {
	pin, fp  bool
	tie      bool // a group of sets that tie is around the entry
	prev     int  // the one list directly before it when no group ties; -1 for none
	prevGone bool
}

// model returns the findings of the bundle.
func model(b mBundle) []modelFinding {
	sets := slices.Clone(b.sets)
	var floating []int
	byPlace := map[int]*mPlace{}
	var placeNos []int
	count := make([]int, len(sets))
	for i := range sets {
		ps := b.placings(i)
		count[i] = len(ps)
		if len(ps) == 0 {
			floating = append(floating, i)
			continue
		}
		for _, p := range ps {
			pl := byPlace[p.place]
			if pl == nil {
				pl = &mPlace{place: p.place}
				byPlace[p.place] = pl
				placeNos = append(placeNos, p.place)
			}
			pl.sets = append(pl.sets, i)
			if p.listed {
				pl.listed++
			}
		}
	}
	slices.Sort(placeNos)
	var places []mPlace
	unsure := false
	for _, n := range placeNos {
		pl := *byPlace[n]
		if len(pl.sets) > 1 && pl.listed <= 1 && !orderIsSure(sets, pl.sets) {
			unsure = true
		}
		places = append(places, pl)
	}
	readings := [][][]int{readingGroups(sets, places, false)}
	if unsure {
		readings = append(readings, readingGroups(sets, places, true))
	}
	// What each reading shows: every entry that returns in some order of the groups.
	shown := make([]map[[2]int]seen, len(readings))
	for ri, groups := range readings {
		shown[ri] = map[[2]int]seen{}
		reading := map[[2]int][2]bool{}
		for _, o := range ordersOf(groups) {
			for k, r := range judge(sets, o) {
				prev := reading[k]
				reading[k] = [2]bool{prev[0] || r[0], prev[1] || r[1]}
			}
		}
		for k, r := range reading {
			sn := seen{pin: r[0], fp: r[1], prev: -1}
			for gi, g := range groups {
				if !slices.Contains(g, k[0]) {
					continue
				}
				// A set at more than one place is in more than one group: the first group that
				// has it shows it, as the first visit does.
				sn.tie = len(g) > 1 || (gi > 0 && len(groups[gi-1]) > 1)
				if gi > 0 && len(groups[gi-1]) == 1 {
					sn.prevGone = !sets[groups[gi-1][0]].readable()
					if !sn.tie {
						sn.prev = groups[gi-1][0]
					}
				}
				break
			}
			shown[ri][k] = sn
		}
	}
	var out []modelFinding
	keys := map[[2]int]bool{}
	var order [][2]int
	for _, m := range shown {
		for k := range m {
			if !keys[k] {
				keys[k] = true
				order = append(order, k)
			}
		}
	}
	for _, k := range order {
		first, inFirst := shown[0][k]
		sn := first
		if !inFirst {
			sn = shown[1][k]
		}
		f := modelFinding{set: k[0], label: sets[k[0]].ents[k[1]].label, pin: sn.pin, fpr: sn.fp, prevGone: sn.prevGone, multi: count[k[0]] > 1}
		f.doubt = sn.tie
		if len(shown) == 2 {
			second, inSecond := shown[1][k]
			switch {
			case !inFirst || !inSecond:
				f.doubt = true
			default:
				f.doubt = first.tie || second.tie || first.prev != second.prev
			}
		}
		out = append(out, f)
	}
	// The sets whose place cannot be told: against every other list that can be read.
	for _, i := range floating {
		if !sets[i].readable() {
			continue
		}
		for _, e := range sets[i].ents {
			var pinCase, fpCase bool
			for j := range sets {
				if j == i || !sets[j].readable() {
					continue
				}
				pinCase = pinCase || (e.pin != 0 && holdsPin(sets[j].mList, e.pin))
				fpCase = fpCase || (e.fp != 0 && holdsFPAny(sets[j].mList, e.fp))
			}
			if pinCase || fpCase {
				out = append(out, modelFinding{set: i, label: e.label, pin: pinCase, fpr: fpCase, floating: true})
			}
		}
	}
	return out
}

// holderRE finds the set that the detail says held the pin or the fingerprint.
var holderRE = regexp.MustCompile(`(?:pin|fingerprint) held on trust/([^/ ,;)]+)`)

// notItself fails when the list that a finding names as the one that held the key is the list of
// the finding: an earlier list is another list.
func notItself(t testing.TB, f Finding) {
	t.Helper()
	ms := holderRE.FindAllStringSubmatch(f.Detail, -1)
	for _, m := range ms {
		if f.Path == listPathOf(m[1]) {
			t.Errorf("the finding %q names its own list as the list that held the key", f.Line())
		}
	}
}

// build makes the bundle in memory: the chain of records, and then the sets that no record lists.
func (b mBundle) build(t testing.TB) *mnode {
	t.Helper()
	bb := chainBundle(t, true)
	content := map[int][]byte{}
	var digests []string
	for ri, rc := range b.records() {
		var opts []func(*rec)
		if b.brokenAt == ri+1 {
			opts = append(opts, prev(digestB))
		}
		lists := rc.lists
		opts = append(opts, func(r *rec) {
			r.artifacts = map[string][]byte{}
			for _, i := range lists {
				if content[i] == nil {
					content[i] = anchored(b.sets[i].bytes(), r.record.PrevRecordSHA256)
				}
				name := b.name(i)
				r.artifacts["trust/"+name+"/root-list.json"] = content[i]
				r.artifacts["trust/"+name+"/keys.txt"] = []byte("keys of " + name + "\n")
			}
			r.refresh()
		})
		var r *rec
		if rc.closing {
			r = bb.closing(bb.unfinished(noSet), opts...)
		} else {
			r = bb.apply(opts...)
		}
		digests = append(digests, r.digest)
	}
	for i, s := range b.sets {
		if s.claim == listedByCeremony {
			continue
		}
		list := s.bytes()
		switch {
		case s.claim > 0:
			list = claims(list, digests[s.claim-1])
		case s.claim < 0:
			list = claims(list, digestB)
		}
		addList(bb.mem, b.name(i), list)
	}
	return bb.mem
}

// compareModel runs the check on the bundle and compares it with the model.
func compareModel(t *testing.T, b mBundle) {
	t.Helper()
	rep, err := runMem(t, b.build(t))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	checkReport(t, rep)
	want := model(b)
	got := returnsOf(rep)
	if len(want) > MaxFindingsPerCode {
		t.Skip("more findings than a report keeps")
	}
	byPath := map[string]int{}
	for i := range b.sets {
		byPath[listPathOf(b.name(i))] = i
	}
	byKey := map[string]modelFinding{}
	for _, w := range want {
		byKey[fmt.Sprintf("%d %s", w.set, w.label)] = w
	}
	var gotS, wantS []string
	for _, f := range got {
		label := strings.TrimPrefix(f.Detail, `root key "`)
		if i := strings.Index(label, `"`); i >= 0 {
			label = label[:i]
		}
		set := byPath[f.Path]
		w, known := byKey[fmt.Sprintf("%d %s", set, label)]
		mf := modelFinding{
			set:   set,
			label: label,
			pin:   strings.Contains(f.Detail, "its pin "),
			fpr:   strings.Contains(f.Detail, "OpenPGP fingerprint"),
		}
		if known && w.multi {
			// A set that stands at more than one place is judged at each, and the reasons are
			// those of the first place that shows it: only that it returns is compared.
			mf.pin, mf.fpr = w.pin, w.fpr
		}
		gotS = append(gotS, mf.String())
		if !known || !w.multi {
			// A set that stands at two places is its own earlier list at the later one, and the
			// detail may name it.
			notItself(t, f)
		}
		if !known || w.multi {
			continue
		}
		switch {
		case w.floating:
			if !strings.Contains(f.Detail, "the place of this trust set in the chain cannot be told") {
				t.Errorf("%s: the place cannot be told and the detail is %q", mf, f.Detail)
			}
		default:
			if says := strings.Contains(f.Detail, "the order of the trust sets is not sure"); says != w.doubt {
				t.Errorf("%s: the model says doubt=%v and the detail is %q", mf, w.doubt, f.Detail)
			}
			// The reason is complete in every detail: the bound cuts what comes after it.
			if gone := strings.Contains(f.Detail, "the list before this one cannot be read"); gone != w.prevGone {
				t.Errorf("%s: the list before cannot be read: %v, and the detail is %q", mf, w.prevGone, f.Detail)
			}
			if w.doubt {
				// The names of the sets come directly after the words that say the order is not sure;
				// the bound of a detail may cut them, and then it ends with three dots.
				if cut := strings.HasSuffix(f.Detail, "..."); !cut && !strings.Contains(f.Detail, "is not sure, among trust/") {
					t.Errorf("%s: the order is not sure and the detail names no set: %q", mf, f.Detail)
				}
			} else if strings.Contains(f.Detail, "among") {
				t.Errorf("%s: the order is sure and the detail names sets: %q", mf, f.Detail)
			}
		}
	}
	for _, w := range want {
		wantS = append(wantS, w.String())
	}
	slices.Sort(gotS)
	slices.Sort(wantS)
	if !slices.Equal(gotS, wantS) {
		t.Errorf("the check and the model differ\n bundle: %v\n  check: %v\n  model: %v", describe(b), gotS, wantS)
	}
}

func describe(b mBundle) []string {
	out := []string{fmt.Sprintf("brokenAt=%d", b.brokenAt)}
	for ri, r := range b.records() {
		kind := "record"
		if r.closing {
			kind = "closing record"
		}
		out = append(out, fmt.Sprintf("%s %d lists %v", kind, ri+1, r.lists))
	}
	for i, s := range b.sets {
		head := fmt.Sprintf("%d: %s claim=%d seq=%d", i, b.name(i), s.claim, s.seq)
		if !s.readable() {
			out = append(out, head+fmt.Sprintf(": damaged %d", s.damaged))
			continue
		}
		var es []string
		for _, e := range s.ents {
			es = append(es, fmt.Sprintf("%s=p%d/f%d", e.label, e.pin, e.fp))
		}
		out = append(out, head+": "+strings.Join(es, " "))
	}
	return out
}

// randomSet makes the content of one set. honest numbers and sequences follow the chain.
func randomSet(rng *rand.Rand, i int, fpOnly bool, s mSet) mSet {
	s.seq = -1
	s.num = 1 + rng.IntN(4)
	if rng.IntN(8) == 0 {
		s.num = -1
	}
	if rng.IntN(3) != 0 {
		s.seq = rng.IntN(5)
	}
	if rng.IntN(10) == 0 {
		s.damaged = 1 + rng.IntN(3)
		return s
	}
	for k, c := 0, rng.IntN(5); k < c; k++ {
		e := mEnt{label: fmt.Sprintf("L%dE%d", i, k), pin: 1 + rng.IntN(mPins), form: rng.IntN(4) * (rng.IntN(5) / 4)}
		if rng.IntN(2) == 0 {
			e.fp = 1 + rng.IntN(mFPs)
		}
		if fpOnly && e.fp != 0 && rng.IntN(3) == 0 {
			e.pin = 0
		}
		s.ents = append(s.ents, e)
	}
	return s
}

// randomBundle makes a bundle the way a bundle may be: records in order, ordinary and closing,
// each listing a set, or none, or two, and sometimes a set that another record lists; numbers and
// sequences that follow the rules or do not; sets that no record lists and name a record or none;
// a record that is off the chain; and lists that cannot be read. With fpOnly some entries have a
// fingerprint and no pin.
func randomBundle(rng *rand.Rand, fpOnly bool) mBundle {
	n := 1 + rng.IntN(4)
	var b mBundle
	honest := rng.IntN(3) == 0
	num := 7 + rng.IntN(3)
	for ri := 0; ri < n; ri++ {
		rc := mRec{closing: ri > 0 && rng.IntN(3) == 0}
		count := 1
		switch rng.IntN(8) {
		case 0:
			count = 2
		case 1:
			if rc.closing {
				count = 0
			}
		}
		for c := 0; c < count; c++ {
			if len(b.sets) > 0 && rng.IntN(6) == 0 {
				// a set that another record lists too
				i := rng.IntN(len(b.sets))
				if b.sets[i].claim == listedByCeremony && !slices.Contains(rc.lists, i) {
					rc.lists = append(rc.lists, i)
					continue
				}
			}
			i := len(b.sets)
			s := randomSet(rng, i, fpOnly, mSet{claim: listedByCeremony})
			if honest {
				s.num = num
				num += 1 + rng.IntN(3)
				s.seq = -1
				if rng.IntN(3) != 0 {
					s.seq = s.num
				}
			}
			b.sets = append(b.sets, s)
			rc.lists = append(rc.lists, i)
		}
		b.recs = append(b.recs, rc)
	}
	for extra := rng.IntN(3); extra > 0; extra-- {
		i := len(b.sets)
		b.sets = append(b.sets, randomSet(rng, i, fpOnly, mSet{claim: rng.IntN(n+2) - 1}))
	}
	if n >= 2 && rng.IntN(6) == 0 {
		b.brokenAt = 2 + rng.IntN(n-1)
	}
	return b
}

func TestRootReturnsMatchesTheModelOnRandomBundles(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261115, 7))
	for iter := 0; iter < 3000; iter++ {
		compareModel(t, randomBundle(rng, false))
		if t.Failed() {
			return
		}
	}
}

// The same with entries that have a fingerprint and no pin. Record 0006, rule 54 says the
// fingerprint of an entry that left is on no later list under any pin.
func TestRootReturnsMatchesTheModelWithEntriesThatHaveNoPin(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261116, 9))
	for iter := 0; iter < 3000; iter++ {
		compareModel(t, randomBundle(rng, true))
		if t.Failed() {
			return
		}
	}
}

// decodeModel makes a bundle from fuzz bytes: the same shapes as the random test, in a form that a
// fuzzer can mutate one byte at a time.
func decodeModel(data []byte, fpOnly bool) mBundle {
	pos := 0
	next := func() int {
		if pos >= len(data) {
			return 0
		}
		pos++
		return int(data[pos-1])
	}
	set := func(i int) mSet {
		s := mSet{claim: listedByCeremony}
		a, c := next(), next()
		s.num = a%5 - 1 // -1 (no number), 0 .. 3
		if a%7 == 0 {
			s.num = 7 + i
		}
		s.seq = c%6 - 1 // -1 (none), 0 .. 4
		head := next()
		if head%11 == 0 {
			s.damaged = 1 + head/11%3
			return s
		}
		for k, cnt := 0, head%5; k < cnt; k++ {
			x := next()
			e := mEnt{label: fmt.Sprintf("L%dE%d", i, k), pin: 1 + x%mPins, form: (x / 7) % 4}
			if f := (x / mPins) % (mFPs + 1); f != 0 {
				e.fp = f
				if fpOnly && x%13 == 0 {
					e.pin = 0
				}
			}
			s.ents = append(s.ents, e)
		}
		return s
	}
	n := 1 + next()%4
	var b mBundle
	for ri := 0; ri < n; ri++ {
		kind := next()
		rc := mRec{closing: ri > 0 && kind%3 == 0}
		count := 1
		switch kind / 3 % 8 {
		case 0:
			count = 2
		case 1:
			if rc.closing {
				count = 0
			}
		}
		for c := 0; c < count; c++ {
			if kind/24%5 == 0 && len(b.sets) > 0 {
				if i := next() % len(b.sets); b.sets[i].claim == listedByCeremony && !slices.Contains(rc.lists, i) {
					rc.lists = append(rc.lists, i)
					continue
				}
			}
			b.sets = append(b.sets, set(len(b.sets)))
			rc.lists = append(rc.lists, len(b.sets)-1)
		}
		b.recs = append(b.recs, rc)
	}
	for extra := next() % 3; extra > 0; extra-- {
		s := set(len(b.sets))
		s.claim = next()%(n+2) - 1
		b.sets = append(b.sets, s)
	}
	if n >= 2 {
		if k := next() % (n + 3); k >= 2 && k <= n {
			b.brokenAt = k
		}
	}
	return b
}

func FuzzRootReturnsModel(f *testing.F) {
	f.Add([]byte{3, 0, 8, 1, 3, 1, 0, 2, 9, 2, 4, 1, 0, 3, 10, 3, 5, 1, 0})
	f.Add([]byte{5, 1, 2, 9, 20, 2, 21, 30, 1, 40, 2, 9, 20, 3, 21, 30, 40, 1, 2, 3})
	f.Add([]byte{4, 2, 1, 7, 11, 1, 7, 1, 7, 0, 0, 0})
	f.Add([]byte{5, 2, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 4, 1, 2, 3, 4, 0, 0, 0, 0, 4, 1, 2, 3, 4})
	f.Add([]byte{3, 1, 1, 1, 7, 1, 2, 2, 8, 2, 2, 3, 1, 8, 7, 9, 3, 3, 4, 6, 1})                // numbers that tie
	f.Add([]byte{3, 2, 1, 4, 8, 5, 6, 2, 1, 4, 9, 6, 7, 1, 2, 3, 1, 2, 4, 1, 2, 5, 3, 3, 4, 9}) // a record off the chain
	f.Fuzz(func(t *testing.T, data []byte) {
		compareModel(t, decodeModel(data, false))
	})
}

// The random bundles of the model reach every shape that the check has a rule for: a closing
// record, a record that lists two sets, a set that two records list, a record off the chain, sets
// that no record lists, lists that cannot be read, and findings of each kind. A generator that
// stopped producing one of them would leave the model test comparing nothing.
func TestRootReturnsTheRandomBundlesReachEveryShape(t *testing.T) {
	seen := map[string]int{}
	for _, fpOnly := range []bool{false, true} {
		rng := rand.New(rand.NewPCG(20261115, 7))
		if fpOnly {
			rng = rand.New(rand.NewPCG(20261116, 9))
		}
		for iter := 0; iter < 3000; iter++ {
			b := randomBundle(rng, fpOnly)
			for _, r := range b.records() {
				if r.closing {
					seen["a closing record"]++
					if len(r.lists) == 0 {
						seen["a closing record that lists nothing"]++
					}
				}
				if len(r.lists) > 1 {
					seen["a record that lists two sets"]++
				}
			}
			listed := map[int]int{}
			for _, r := range b.records() {
				for _, i := range r.lists {
					listed[i]++
				}
			}
			for _, n := range listed {
				if n > 1 {
					seen["a set that two records list"]++
				}
			}
			if b.brokenAt > 0 {
				seen["a record off the chain"]++
			}
			for _, s := range b.sets {
				if s.claim != listedByCeremony {
					seen["a set that no record lists"]++
				}
				if !s.readable() {
					seen["a list that cannot be read"]++
				}
			}
			for _, f := range model(b) {
				seen["a finding"]++
				switch {
				case f.floating:
					seen["a finding of a set whose place cannot be told"]++
				case f.doubt:
					seen["a finding whose order is not sure"]++
				}
				if f.multi {
					seen["a finding of a set at more than one place"]++
				}
				if f.prevGone {
					seen["a finding after a list that cannot be read"]++
				}
				if f.pin && f.fpr {
					seen["a finding with both reasons"]++
				}
				if !f.pin && f.fpr {
					seen["a finding by the fingerprint alone"]++
				}
			}
		}
	}
	for _, shape := range []string{
		"a closing record", "a closing record that lists nothing", "a record that lists two sets", "a set that two records list",
		"a record off the chain", "a set that no record lists", "a list that cannot be read", "a finding",
		"a finding of a set whose place cannot be told", "a finding whose order is not sure", "a finding of a set at more than one place",
		"a finding after a list that cannot be read", "a finding with both reasons", "a finding by the fingerprint alone",
	} {
		if seen[shape] < 20 {
			t.Errorf("%q came %d times in 6,000 bundles", shape, seen[shape])
		}
	}
}

// A bundle that follows the rules, with closing records in it, has no finding of root-returns: each
// record lists one set, and each list holds keys of the list before it and new keys, never one that
// left. Whatever the numbers and the sequences say, there is one order, and no detail says the
// order is not sure.
func TestRootReturnsAnHonestBundleWithClosingRecordsHasNoFinding(t *testing.T) {
	rng := rand.New(rand.NewPCG(20261117, 3))
	for iter := 0; iter < 400; iter++ {
		n := 2 + rng.IntN(5)
		var b mBundle
		fresh := 0
		var before []mEnt
		for i := 0; i < n; i++ {
			s := mSet{claim: listedByCeremony}
			s.num, s.seq = 1+rng.IntN(9), rng.IntN(9)-1 // statements that say anything
			var ents []mEnt
			for _, e := range before {
				if rng.IntN(3) != 0 {
					ents = append(ents, e)
				}
			}
			for k, c := 0, rng.IntN(3); k < c; k++ {
				fresh++
				e := mEnt{label: fmt.Sprintf("N%d", fresh), pin: 100 + fresh, form: rng.IntN(4)}
				if rng.IntN(2) == 0 {
					e.fp = 100 + fresh
				}
				ents = append(ents, e)
			}
			s.ents = ents
			before = ents
			b.sets = append(b.sets, s)
			b.recs = append(b.recs, mRec{lists: []int{i}, closing: i > 0 && rng.IntN(3) == 0})
		}
		compareModel(t, b)
		rep, err := runMem(t, b.build(t))
		if err != nil {
			t.Fatal(err)
		}
		if got := returnsOf(rep); len(got) != 0 {
			t.Fatalf("a bundle that follows the rules has findings: %v\n%v", lines(got), describe(b))
		}
		if t.Failed() {
			return
		}
	}
}
