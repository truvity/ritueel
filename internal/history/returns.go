package history

import (
	"cmp"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/jsonset"
)

// setList is the root list of one trust set, as the anchor check read it. read is nil when the
// file is there and cannot be read (a link, a folder, a FIFO, a file that is too long, JSON that
// breaks the rules, more than [MaxRootsPerList] entries, an entry whose pin or fingerprint cannot
// be read): the anchor check says so under its own name, and this check takes the list as one
// whose keys are not known. A trust set with no root-list.json has no setList: it has no root list.
type setList struct {
	set  string
	read *anchorOf
}

// pinID is the pin an entry holds a fingerprint under. An entry with a fingerprint and no pin
// holds it under none, and none is a pin of its own for this check (record 0006, rule 54).
type pinID struct {
	b    [32]byte
	none bool
}

func idOf(k rootKey) pinID {
	if k.hasPin {
		return pinID{b: k.pin}
	}
	return pinID{none: true}
}

// fpKey is a fingerprint held under one pin.
type fpKey struct {
	fp  [20]byte
	pin pinID
}

// tally counts, for a group of lists, how many of them hold each key. A list counts once for a
// key, however many entries of it name the key. size is the number of lists of the group, those
// that cannot be read included: such a list holds no key. Only the tallies that [view] reads as
// prev and cur have a size; the running tally cum holds counts only, and merge does not add sizes.
type tally struct {
	size  int
	pin   map[[32]byte]int // lists that hold the pin
	fp    map[[20]byte]int // lists that hold the fingerprint under some pin
	fpPin map[fpKey]int    // lists that hold the fingerprint under this pin
}

func bump[K comparable](m *map[K]int, k K, by int) {
	if *m == nil {
		*m = map[K]int{}
	}
	(*m)[k] += by
}

// addList counts the keys of one readable list.
func (t *tally) addList(keys []rootKey) {
	var pins [][32]byte
	var fps [][20]byte
	var pairs []fpKey
	for _, k := range keys {
		if k.hasPin && !slices.Contains(pins, k.pin) {
			pins = append(pins, k.pin)
			bump(&t.pin, k.pin, 1)
		}
		if k.hasFP {
			if !slices.Contains(fps, k.fp) {
				fps = append(fps, k.fp)
				bump(&t.fp, k.fp, 1)
			}
			if fk := (fpKey{k.fp, idOf(k)}); !slices.Contains(pairs, fk) {
				pairs = append(pairs, fk)
				bump(&t.fpPin, fk, 1)
			}
		}
	}
}

// merge adds the counts of o to t.
func (t *tally) merge(o *tally) {
	for k, n := range o.pin {
		bump(&t.pin, k, n)
	}
	for k, n := range o.fp {
		bump(&t.fp, k, n)
	}
	for k, n := range o.fpPin {
		bump(&t.fpPin, k, n)
	}
}

// view is the lists before one list, as counts: cum is every group of lists before the group of
// the list, prev is the group directly before it (nil for none), and cur is the group of the list,
// the list itself included. A group is a set of lists whose order among themselves is not known:
// any of them may be directly before another, or first. A group of one list is a list whose place
// is known, and then the rule below is the plain rule of record 0006, rule 54.
type view struct {
	cum, prev, cur *tally
}

// pinReturns is the one place of the rule for a pin (record 0006, rule 54): an earlier list held
// the pin, and the list directly before this one did not. With groups it asks whether some order
// of the lists that tie makes this so: (a) this list is first of its group and a list of the group
// before, which may be the last, lacks the pin; (b) another list of its own group lacks the pin and
// may be directly before it. In both an earlier list holds the pin, other than the one that lacks
// it. The list is one that holds the pin.
func (v view) pinReturns(k rootKey) bool {
	if !k.hasPin {
		return false
	}
	before, here := v.cum.pin[k.pin], v.cur.pin[k.pin]
	a := v.prev != nil && v.prev.size-v.prev.pin[k.pin] > 0 && before > 0
	b := v.cur.size-here > 0 && before+here-1 > 0
	return a || b
}

// fpReturns is the rule for an OpenPGP fingerprint (record 0006, rule 54: it "is on no later list
// either, under any pin or label"): an earlier list held the fingerprint, under any pin, and the
// list directly before this one does not hold it under this same pin. An entry with no pin has the
// pin none. The list before may itself be the earlier list that held the fingerprint: that is a
// change of the pin, in one step. The groups are read as in [view.pinReturns], with "holds" meaning
// the fingerprint under any pin for the earlier list, and "lacks" meaning not under this pin for
// the list before.
func (v view) fpReturns(k rootKey) bool {
	if !k.hasFP {
		return false
	}
	fk := fpKey{k.fp, idOf(k)}
	before, here := v.cum.fp[k.fp], v.cur.fp[k.fp]
	a := v.prev != nil && v.prev.size-v.prev.fpPin[fk] > 0 && before > 0
	b := v.cur.size-v.cur.fpPin[fk] > 0 && before+here-1 > 0
	return a || b
}

// holders keeps the first two sets that held a key, to name one that is not the set judged.
type holders struct {
	a, b string
	n    int
}

func (h *holders) add(set string) {
	switch {
	case h.n == 0:
		h.a, h.n = set, 1
	case h.n == 1 && h.a != set:
		h.b, h.n = set, 2
	}
}

// other returns a set that held the key and is not set. A holder is always there when the rule
// found a return; the set itself is the fallback so that a detail never names nothing.
func (h *holders) other(set string) string {
	if h == nil {
		return set
	}
	switch {
	case h.a != set:
		return h.a
	case h.b != "":
		return h.b
	}
	return set
}

// holder is [holders.other], and says whether the set itself is the only one that held the key: a
// set that more than one record lists is judged at its later place against its own earlier place.
func (h *holders) holder(set string) (name string, self bool) {
	name = h.other(set)
	return name, name == set
}

func addHolders(pinHold map[[32]byte]*holders, fpHold map[[20]byte]*holders, set string, keys []rootKey) {
	for _, k := range keys {
		if k.hasPin {
			h := pinHold[k.pin]
			if h == nil {
				h = &holders{}
				pinHold[k.pin] = h
			}
			h.add(set)
		}
		if k.hasFP {
			h := fpHold[k.fp]
			if h == nil {
				h = &holders{}
				fpHold[k.fp] = h
			}
			h.add(set)
		}
	}
}

// RootKey is one entry of the roots of a root list, as the text of the file has it. Pin is the
// x509_spki_sha256 member and Fingerprint the openpgp_fingerprint member; an empty text is a member
// that is not there. Both are read in the one form of this check: hexadecimal digits of either
// case, with white space around, a 0x prefix and the separators space, colon and hyphen dropped.
type RootKey struct {
	Label       string
	Pin         string
	Fingerprint string
}

// RootList is one root list of a bundle, in the form [FindReturns] reads. Name is what the
// result calls the list. Unreadable is a list whose keys are not known; it holds none, and the list
// after it has no known list before it.
type RootList struct {
	Name       string
	Unreadable bool
	Keys       []RootKey
}

// Return is one entry of a list that adds a root key that left (record 0006, rule 54).
type Return struct {
	// Entry is the index of the entry in [RootList.Keys].
	Entry int
	// ByPin is set when an earlier list held the pin and the list before did not.
	ByPin bool
	// ByFingerprint is set when an earlier list held the fingerprint and the list before does
	// not hold it under this pin.
	ByFingerprint bool
	// PinHeldOn and FingerprintHeldOn name an earlier list that held the pin or the fingerprint.
	PinHeldOn, FingerprintHeldOn string
	// PreviousUnreadable is set when the list before cannot be read.
	PreviousUnreadable bool
}

// ErrRootKey is returned by [FindReturns] when an entry of the list to judge has a pin or a
// fingerprint that cannot be read, or has neither: a list with such an entry cannot be read.
var ErrRootKey = errors.New("an entry of roots has no pin and no fingerprint, or one that is not hexadecimal digits of the right length")

// FindReturns says which entries of list add a root key that left, when earlier are the root lists
// of the bundle before it, in the order of the ceremonies that wrote them (record 0006, rule 54):
// one Return for each such entry. It is the rule that `check history` applies to every list of a
// bundle, so a writer that is about to write a list asks the same question before it writes. An
// earlier list with an entry that cannot be read is taken as one that cannot be read. The work is
// linear in the number of entries.
func FindReturns(earlier []RootList, list RootList) ([]Return, error) {
	if list.Unreadable {
		return nil, nil // its keys are not known
	}
	own, err := keysOf(list.Keys)
	if err != nil {
		return nil, fmt.Errorf("%w (%q)", ErrRootKey, list.Name)
	}
	cum, prev := &tally{}, (*tally)(nil)
	pinHold := map[[32]byte]*holders{}
	fpHold := map[[20]byte]*holders{}
	prevUnreadable := false
	for _, e := range earlier {
		t := &tally{size: 1}
		keys, err := keysOf(e.Keys)
		prevUnreadable = e.Unreadable || err != nil
		if !prevUnreadable {
			t.addList(keys)
			addHolders(pinHold, fpHold, e.Name, keys)
		}
		cum.merge(t)
		prev = t
	}
	cur := &tally{size: 1}
	cur.addList(own)
	v := view{cum: cum, prev: prev, cur: cur}
	var out []Return
	for i, k := range own {
		r := Return{Entry: i, ByPin: v.pinReturns(k), ByFingerprint: v.fpReturns(k), PreviousUnreadable: prevUnreadable}
		if !r.ByPin && !r.ByFingerprint {
			continue
		}
		if r.ByPin {
			r.PinHeldOn = pinHold[k.pin].other(list.Name)
		}
		if r.ByFingerprint {
			r.FingerprintHeldOn = fpHold[k.fp].other(list.Name)
		}
		out = append(out, r)
	}
	return out, nil
}

// keysOf reads entries as the check reads them. An entry with a pin or a fingerprint that cannot
// be read, and an entry with neither, is an error.
func keysOf(in []RootKey) ([]rootKey, error) {
	out := make([]rootKey, 0, len(in))
	for _, e := range in {
		ent := rootEntry{Label: &e.Label}
		if e.Pin != "" {
			ent.Pin = &e.Pin
		}
		if e.Fingerprint != "" {
			ent.Fingerprint = &e.Fingerprint
		}
		k, ok := keyOf(ent)
		if !ok || (!k.hasPin && !k.hasFP) {
			return nil, ErrRootKey
		}
		out = append(out, k)
	}
	return out, nil
}

// rootReturns is the finding root-returns (record 0006, rule 54; docs/reference/ceremony-record.md,
// "The hash chain"). It takes the root list of every trust set of the bundle, also a set that no
// ceremony record lists, puts them in the order of the ceremonies that wrote them and applies the
// rule of [view] to each entry of each list. One finding is given for each entry that is a return
// by its pin, by its OpenPGP fingerprint, or by both. The key is the pin, so a new label makes no
// key new, and an entry with a fingerprint and no pin is a key held by its fingerprint. Pins and
// fingerprints are compared as the bytes that the hexadecimal digits stand for.
//
// The order comes from the hash chain of the ceremony records, which cannot be reordered without
// another finding, and not from the names that the writer of the newest ceremony chooses. A list
// stands at a place of the chain, the number of records before the record that stands there:
//
//   - a set that a record lists stands at the place of that record, whatever kind of record it is:
//     a closing record is a record of the chain like any other, so the set that it lists stands at
//     the place of the closing record itself, and not at the end that the plan of the closed
//     ceremony names (a plan is a file that the writer of the closing record can make). The folder
//     number of the set and the sequence of its list do not move it. A set that more than one
//     record lists stands at the place of each of them and is judged at each;
//   - a set that no record lists stands at the place its root list claims: it follows the record
//     that last_record_sha256 names, and a list that names none follows no record;
//   - sets that stand at one place are ordered among themselves by the member sequence of the
//     list, then by the number in the folder name. Where these two statements tie, are missing,
//     or do not give the same order, any of the readings may be true: each is judged, an entry
//     that any of them shows as a return is a finding. Where more than one set that a record
//     lists stands at one place (records that fork, or one record that lists two sets) the names
//     and sequences are not believed at all, because they are chosen by the writer of the newest
//     record: every order of the sets of that place is judged. The detail of a finding says that
//     the order is not sure when a group of sets that tie is around the entry, or when the
//     readings differ for it (the other reading does not show it, or has another list before
//     it), and it names the sets of the places whose order is not sure. In a bundle that follows
//     the rules one record stands at each place and one set follows it, so there is one reading;
//   - a set whose place cannot be told at all (its last_record_sha256 names no record of the chain,
//     the records that list it are off the chain, or its list cannot be read) is judged as a list
//     after one that cannot be read: an entry of it is a return when any other list that could be
//     read held the key. Such a list is already anchor-unknown or chain-broken, so the bundle fails
//     with or without this finding; the lists with a place are judged without it. When the bundle
//     has ceremony records and none of them is on the chain (two records that have no
//     prev_record_sha256, for one), no set has a place, and every root list is judged so. A bundle
//     with no ceremony record keeps the places that its root lists claim.
//
// A list that cannot be read adds nothing to what was held. The list after it, when it has a
// place, has no known list before it: an entry of that list is a return when an earlier list that
// could be read held it, so that a list that cannot be read in the middle hides nothing. An honest
// bundle has no list that cannot be read, and the anchor check already reports one.
//
// The work is one sort by place and name, at most three passes over the lists (the third only when
// the first reading shows an entry that the second does not), and one pass over the floating
// lists. Each list has at most [MaxRootsPerList] entries, all lists together at most
// [MaxRootEntries], and all the sets together stand at most at [MaxSetPlaces] places. The maps of
// the tallies and of the holders hold at most one item for each entry, and the notes of the places
// and the placings hold at most one item for each place, so the memory is bounded by the entries
// and the places, and not by the number of records.
func (ck *checker) rootReturns() error {
	if len(ck.rootLists) == 0 {
		return nil
	}
	var all []placing
	var placed, floating []setList
	multi := false
	// Records that are all off the chain (two records with no predecessor, for one) give no set a
	// place: every root list is judged as a list whose place cannot be told. A bundle with no
	// ceremony record keeps the places that its root lists claim.
	noChain := len(ck.recs) > 0 && len(ck.onChain) == 0
	for _, l := range ck.rootLists {
		var ps []placing
		if !noChain {
			ps = ck.placingsOf(l)
		}
		if len(ps) == 0 {
			floating = append(floating, l)
			continue
		}
		multi = multi || len(ps) > 1
		placed = append(placed, l)
		all = append(all, ps...)
	}
	order := inPlaces(all, setKeys(placed))
	w := &retWalk{ck: ck, places: order.places, doubts: map[[2]int][]string{}}
	if multi {
		w.emitted = map[findKey]struct{}{}
	}
	if !order.unsure {
		if err := w.run(order.bySeq, w.emit(nil)); err != nil {
			return err
		}
		return ck.floatingReturns(placed, floating)
	}
	// The two readings are walked. The first only notes which entries it shows, and which list is
	// before each; the second reports what it shows and says so when the first differs; a third
	// walk, run only when there is something left, reports what only the first showed.
	first := map[findKey]shown{}
	if err := w.run(order.bySeq, func(l setList, at int, r returned, s shown) {
		if _, ok := first[findKey{l.set, at}]; !ok {
			s.r = r
			first[findKey{l.set, at}] = s
		}
	}); err != nil {
		return err
	}
	if err := w.run(order.byNum, w.emit(first)); err != nil {
		return err
	}
	if len(first) > 0 {
		left := first
		if err := w.run(order.bySeq, func(l setList, at int, r returned, s shown) {
			if _, ok := left[findKey{l.set, at}]; ok {
				w.report(l, at, r, true)
			}
		}); err != nil {
			return err
		}
	}
	return ck.floatingReturns(placed, floating)
}

// placing is one place at which a list stands. listed is set when a record that stands at the
// place lists the set, and not set for a set that no record lists and that only claims the place.
type placing struct {
	l      setList
	place  int
	listed bool
}

// placingsOf says where a list stands in the chain: one placing for each place of the records that
// list its set, or the one place that its own last_record_sha256 claims when no record lists it.
// None means that the place cannot be told. The place of a record is the number of records before
// it (0 for the first), so a set that a record lists stands at the place of that record, the same
// for an ordinary record and for a closing record.
func (ck *checker) placingsOf(l setList) []placing {
	if w := ck.listed[l.set]; w != nil {
		var out []placing
		at := map[int]struct{}{}
		for prev := range w.by {
			place, ok := ck.afterRecord(prev)
			if !ok {
				continue // the record is not on the chain: chain-broken says so
			}
			if _, seen := at[place]; !seen { // two records at one place (a fork) place the set once
				at[place] = struct{}{}
				out = append(out, placing{l: l, place: place, listed: true})
			}
		}
		return out
	}
	if l.read == nil {
		return nil
	}
	if !l.read.present {
		return []placing{{l: l}} // names no record: it follows none
	}
	place, ok := ck.afterRecord(l.read.value)
	if !ok {
		return nil
	}
	return []placing{{l: l, place: place}}
}

// afterRecord is the place of a list that follows the record with this digest ("" for none): the
// place of the record that stands next. ok is false when the record is not on the chain.
func (ck *checker) afterRecord(digest string) (int, bool) {
	if digest == "" {
		return 0, true
	}
	d, ok := ck.depth[digest]
	return d + 1, ok
}

// findKey names one entry of one list.
type findKey struct {
	set string
	at  int
}

// group is a set of lists at one place whose order among themselves is not known: any of them may
// be directly before another, or first. A group of one list is a list whose place in the order is
// known.
type group struct {
	place int
	lists []setList
}

// retWalk walks the groups of lists. A group of one list is the order of a bundle that follows the
// rules.
type retWalk struct {
	ck      *checker
	places  map[int][]string     // the places whose order is not sure -> the names of their sets
	emitted map[findKey]struct{} // entries already reported; nil when no entry is visited twice
	doubts  map[[2]int][]string  // the sets of two places whose order is not sure, worked out once
}

// shown is what one reading knows of an entry that it shows as a return: whether a group of lists
// that tie is around it, which list is directly before it (one list, or none), and the return.
type shown struct {
	tie  bool
	prev string
	r    returned
}

// emit is the visit that reports each entry once. With the entries that the first reading showed,
// an entry is reported as the first reading shows it, and with the words about the order when the
// other reading did not show it or shows it with another list before it; the entries it finds
// there are taken out of first.
func (w *retWalk) emit(first map[findKey]shown) func(setList, int, returned, shown) {
	return func(l setList, at int, r returned, s shown) {
		unsure := s.tie
		if first != nil {
			fk := findKey{l.set, at}
			f, ok := first[fk]
			delete(first, fk)
			if ok {
				r = f.r
			}
			unsure = unsure || !ok || f.tie || f.prev != s.prev
		}
		w.report(l, at, r, unsure)
	}
}

// report makes the finding of one entry. unsure says that the order is not sure for it.
func (w *retWalk) report(l setList, at int, r returned, unsure bool) {
	if w.emitted != nil {
		fk := findKey{l.set, at}
		if _, ok := w.emitted[fk]; ok {
			return
		}
		w.emitted[fk] = struct{}{}
	}
	if !unsure {
		r.doubt = nil
	}
	w.ck.col.add(RootReturns, listPath(l.set), returnDetail(r))
}

// mergeNames joins two lists of names, each in order and with no name twice, into one.
func mergeNames(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	out := make([]string, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		switch c := cmp.Compare(a[0], b[0]); {
		case c < 0:
			out, a = append(out, a[0]), a[1:]
		case c > 0:
			out, b = append(out, b[0]), b[1:]
		default:
			out, a, b = append(out, a[0]), a[1:], b[1:]
		}
	}
	out = append(out, a...)
	return append(out, b...)
}

// run walks the groups in order and calls visit for every entry that returns. The entry carries
// the sets whose order is not sure around it, whether or not the walk says so.
func (w *retWalk) run(groups []group, visit func(l setList, at int, r returned, s shown)) error {
	cum := &tally{}
	var prev *tally
	var prevGroup *group
	pinHold := map[[32]byte]*holders{}
	fpHold := map[[20]byte]*holders{}
	for gi := range groups {
		g := &groups[gi]
		if err := w.ck.ctx.Err(); err != nil {
			return err
		}
		cur := &tally{size: len(g.lists)}
		for _, l := range g.lists {
			if l.read == nil {
				continue
			}
			cur.addList(l.read.keys)
			addHolders(pinHold, fpHold, l.set, l.read.keys)
		}
		v := view{cum: cum, prev: prev, cur: cur}
		var doubt []string // worked out once for the group, and only when a finding needs it
		doubtDone := false
		s := shown{tie: len(g.lists) > 1}
		r0 := returned{known: true}
		if prevGroup != nil {
			s.tie = s.tie || len(prevGroup.lists) > 1
			if len(prevGroup.lists) == 1 {
				s.prev = prevGroup.lists[0].set
				r0.prevSet, r0.known = s.prev, prevGroup.lists[0].read != nil
			}
		}
		for _, l := range g.lists {
			if l.read == nil {
				continue
			}
			for at, k := range l.read.keys {
				r := r0
				r.k = k
				if v.pinReturns(k) {
					r.pinCase = true
					r.holder, r.pinSelf = pinHold[k.pin].holder(l.set)
				}
				if v.fpReturns(k) {
					r.fpCase = true
					r.fpHolder, r.fpSelf = fpHold[k.fp].holder(l.set)
				}
				if !r.pinCase && !r.fpCase {
					continue
				}
				if !doubtDone {
					doubt, doubtDone = w.doubtFor(g, prevGroup), true
				}
				r.doubt = doubt
				visit(l, at, r, s)
			}
		}
		cum.merge(cur)
		prev, prevGroup = cur, g
	}
	return nil
}

// doubtFor is the sets whose order is not sure for a finding in the group g, with prev the group
// before it: the sets of the place of g and of the place of prev when the order of that place is
// not sure.
func (w *retWalk) doubtFor(g, prev *group) []string {
	q := -1
	if prev != nil {
		q = prev.place
	}
	key := [2]int{g.place, q}
	if names, ok := w.doubts[key]; ok {
		return names
	}
	names := mergeNames(w.places[g.place], w.places[q])
	w.doubts[key] = names
	return names
}

// floatingReturns judges the lists whose place cannot be told. The place of such a list is any
// place, so the list before it is any list: an entry of it is a return when another list that
// could be read, of any place, held the key. The lists with a place are not judged against them.
func (ck *checker) floatingReturns(placed, floating []setList) error {
	if len(floating) == 0 {
		return nil
	}
	all := &tally{}
	pinHold := map[[32]byte]*holders{}
	fpHold := map[[20]byte]*holders{}
	for _, group := range [][]setList{placed, floating} {
		for _, l := range group {
			if l.read == nil {
				continue
			}
			all.addList(l.read.keys)
			addHolders(pinHold, fpHold, l.set, l.read.keys)
		}
	}
	for _, l := range floating {
		if err := ck.ctx.Err(); err != nil {
			return err
		}
		if l.read == nil {
			continue
		}
		for _, k := range l.read.keys {
			r := returned{k: k, floating: true}
			if k.hasPin && all.pin[k.pin] > 1 {
				r.pinCase = true
				r.holder, r.pinSelf = pinHold[k.pin].holder(l.set)
			}
			if k.hasFP && all.fp[k.fp] > 1 {
				r.fpCase = true
				r.fpHolder, r.fpSelf = fpHold[k.fp].holder(l.set)
			}
			if r.pinCase || r.fpCase {
				ck.col.add(RootReturns, listPath(l.set), returnDetail(r))
			}
		}
	}
	return nil
}

// setOrder is what a set states about its place among the sets that stand at the same place: the
// member sequence of its root list, and the number in its folder name.
type setOrder struct {
	numbered bool
	number   int64
	hasSeq   bool
	sequence int64
}

func setKeys(lists []setList) map[string]setOrder {
	keys := make(map[string]setOrder, len(lists))
	for _, l := range lists {
		var k setOrder
		if n, ok := trustNumber(l.set); ok {
			k.numbered, k.number = true, n
		}
		if l.read != nil && l.read.hasSequence {
			k.hasSeq, k.sequence = true, l.read.sequence
		}
		keys[l.set] = k
	}
	return keys
}

// placeOrder is the lists with a place, in the order of the chain.
type placeOrder struct {
	// bySeq and byNum are the groups in the order of the places and, inside one place, in the
	// order of the sequences (bySeq) or of the folder numbers (byNum). Where more than one listed
	// set stands, both are the same: one group of every set of the place.
	bySeq, byNum []group
	// unsure is set when some place holds more than one set, at most one of them is listed by a
	// record, and the two statements do not give one order: then the two readings differ, and both
	// are walked.
	unsure bool
	// places that hold more than one set whose order is not sure (more than one listed set, or
	// statements that tie, are missing or disagree) -> the names of their sets, in order.
	places map[int][]string
}

// inPlaces puts the lists with a place in order and cuts them into groups of lists that tie: the
// places in the order of the chain, and inside one place the sets in the order of their sequence
// or of their folder number, a set that has none after all that have one, and sets that share a
// value together in one group. A place at which more than one listed set stands (records that
// fork, or one record that lists two sets) is one group, in either reading: every order of its
// sets is judged. The names of the sets of every place whose
// order is not sure are kept for the words of a finding.
func inPlaces(all []placing, keys map[string]setOrder) placeOrder {
	sorted := slices.Clone(all)
	slices.SortFunc(sorted, func(a, b placing) int {
		return cmp.Or(cmp.Compare(a.place, b.place), cmp.Compare(a.l.set, b.l.set))
	})
	var o placeOrder
	for i := 0; i < len(sorted); {
		j := i + 1
		for j < len(sorted) && sorted[j].place == sorted[i].place {
			j++
		}
		lists := make([]setList, 0, j-i)
		listed := 0
		for _, p := range sorted[i:j] {
			lists = append(lists, p.l)
			if p.listed {
				listed++
			}
		}
		place := sorted[i].place
		switch {
		case len(lists) == 1:
			g := group{place, lists}
			o.bySeq, o.byNum = append(o.bySeq, g), append(o.byNum, g)
		case listed > 1:
			g := group{place, lists}
			o.bySeq, o.byNum = append(o.bySeq, g), append(o.byNum, g)
			o.markUnsure(place, lists)
		default:
			if !orderSure(lists, keys) {
				o.unsure = true
				o.markUnsure(place, lists)
			}
			o.bySeq = append(o.bySeq, tieGroups(place, lists, keys, false)...)
			o.byNum = append(o.byNum, tieGroups(place, lists, keys, true)...)
		}
		i = j
	}
	return o
}

func (o *placeOrder) markUnsure(place int, lists []setList) {
	if o.places == nil {
		o.places = map[int][]string{}
	}
	names := make([]string, len(lists))
	for i, l := range lists {
		names[i] = l.set
	}
	o.places[place] = names
}

// orderSure reports whether the sets that stand at one place have one order: each has a sequence
// and a folder number, no two share either, and the sequences and the numbers put them in the same
// order. A set whose list cannot be read has no sequence.
func orderSure(place []setList, keys map[string]setOrder) bool {
	sorted := slices.Clone(place)
	slices.SortFunc(sorted, func(a, b setList) int {
		return cmp.Compare(keys[a.set].sequence, keys[b.set].sequence)
	})
	for i, l := range sorted {
		k := keys[l.set]
		if !k.hasSeq || !k.numbered {
			return false
		}
		if i > 0 {
			p := keys[sorted[i-1].set]
			if k.sequence <= p.sequence || k.number <= p.number {
				return false
			}
		}
	}
	return true
}

// tieGroups puts the sets of one place in the order of their sequence, or of their folder number,
// and cuts the result into groups of sets that tie: sets that share the value, and the sets that
// have none, which come last.
func tieGroups(place int, lists []setList, keys map[string]setOrder, byNumber bool) []group {
	has := func(k setOrder) bool { return k.hasSeq }
	val := func(k setOrder) int64 { return k.sequence }
	if byNumber {
		has = func(k setOrder) bool { return k.numbered }
		val = func(k setOrder) int64 { return k.number }
	}
	sorted := slices.Clone(lists)
	slices.SortFunc(sorted, func(a, b setList) int {
		ka, kb := keys[a.set], keys[b.set]
		switch {
		case has(ka) && !has(kb):
			return -1
		case !has(ka) && has(kb):
			return 1
		}
		return cmp.Or(cmp.Compare(val(ka), val(kb)), cmp.Compare(a.set, b.set))
	})
	var groups []group
	for i, l := range sorted {
		if i > 0 {
			a, b := keys[sorted[i-1].set], keys[l.set]
			if has(a) == has(b) && val(a) == val(b) {
				g := &groups[len(groups)-1]
				g.lists = append(g.lists, l)
				continue
			}
		}
		groups = append(groups, group{place, []setList{l}})
	}
	return groups
}

// The most sets that the words of a finding name when the order is not sure; the rest is counted.
// A name of a set is cut to maxDoubtName bytes. The label of a key is shown with at most
// maxLabelDetail bytes of escapes.
const (
	maxDoubtShown  = 2
	maxDoubtName   = 40
	maxLabelDetail = 48
)

// returned is what is known of one entry that came back.
type returned struct {
	k        rootKey
	pinCase  bool
	holder   string // a set that held the pin
	pinSelf  bool   // the only set that held the pin is the set itself, at an earlier place
	fpCase   bool
	fpHolder string   // a set that held the fingerprint
	fpSelf   bool     // the only set that held the fingerprint is the set itself, at an earlier place
	doubt    []string // the sets whose order is not sure; empty when the order is sure
	floating bool     // the place of the list cannot be told
	known    bool     // the list before can be read (false only when one list is before and cannot be read)
	prevSet  string   // the list before, when one list is before
}

// returnDetail says what returned, in printable ASCII, in this order: the label (written with
// escapes, because it is a text of the file, and cut), the reason (which key returned, by which of
// the two cases, and what the list before it held), what is not sure, the rule, and last the
// names of the sets (each cut). When the order is not sure, the names of the sets whose order is
// not sure come directly after the words that say so, before the rule and before the holders. The
// bound of a detail cuts from the end, so it cuts a name or the words about what is not sure and
// never the reason: the label takes at most 51 bytes, the reason at most 150, and the bound is 240.
func returnDetail(r returned) string {
	d := `root key "` + labelShown(r.k.label) + `" returns: ` + reasonOf(r)
	switch {
	case r.floating:
		d += "; the place of this trust set in the chain cannot be told"
	case len(r.doubt) > 0:
		d += "; the order of the trust sets is not sure, among " + doubtNames(r.doubt)
	}
	d += " (record 0006, rule 54)"
	var where []string
	if r.pinCase {
		where = append(where, "pin held on "+heldOn(r.holder, r.pinSelf))
	}
	if r.fpCase {
		where = append(where, "fingerprint held on "+heldOn(r.fpHolder, r.fpSelf))
	}
	if len(r.doubt) == 0 && !r.floating && r.prevSet != "" {
		where = append(where, "list before "+setShown(r.prevSet))
	}
	for _, w := range where {
		d += "; " + w
	}
	return d
}

// heldOn names the set that held a key. When the only set that held it is the set judged (a set
// that more than one record lists, judged at its later place against its own earlier place), it
// says so in plain words and does not print the name as if it were another set.
func heldOn(holder string, self bool) string {
	if self {
		return "the same set at an earlier place"
	}
	return setShown(holder)
}

// reasonOf is the words that say which key returned and why, with no name of a set in them.
func reasonOf(r returned) string {
	var d string
	switch {
	case r.pinCase && r.fpCase:
		d = "its pin " + short(r.k.pin[:]) + " and its OpenPGP fingerprint " + short(r.k.fp[:]) + " were on "
	case r.pinCase:
		d = "its pin " + short(r.k.pin[:]) + " was on "
	default:
		d = "its OpenPGP fingerprint " + short(r.k.fp[:]) + " was on "
	}
	if r.floating {
		return d + "another list"
	}
	d += "an earlier list and "
	switch {
	case !r.known:
		return d + "the list before this one cannot be read"
	case r.pinCase && r.fpCase:
		return d + "the list before this one did not hold them"
	case r.pinCase:
		return d + "is not on the list before this one"
	}
	return d + "the list before this one did not hold it under this pin"
}

// labelShown is the label as the detail shows it: escaped, and cut at a character, with "...", so
// that the escapes take at most maxLabelDetail bytes.
func labelShown(label string) string {
	if all := jsonset.EscapeExact(label); len(all) <= maxLabelDetail {
		return all
	}
	out := ""
	for i := 0; i < len(label); {
		_, size := utf8.DecodeRuneInString(label[i:])
		piece := jsonset.EscapeExact(label[i : i+size])
		if len(out)+len(piece) > maxLabelDetail {
			break
		}
		out += piece
		i += size
	}
	return out + "..."
}

// setShown is the name of a set, cut to maxDoubtName bytes, as "trust/<name>".
func setShown(s string) string { return "trust/" + jsonset.EscapeExact(cutName(s)) }

func cutName(s string) string {
	if len(s) <= maxDoubtName {
		return s
	}
	return s[:maxDoubtName] + "..."
}

// doubtNames names at most [maxDoubtShown] sets and says how many more there are.
func doubtNames(names []string) string {
	text := ""
	for i, n := range names {
		if i == maxDoubtShown {
			text += " and " + strconv.Itoa(len(names)-maxDoubtShown) + " more"
			break
		}
		if i > 0 {
			text += ", "
		}
		text += setShown(n)
	}
	return text
}

// short is the first sixteen hexadecimal digits of b, with "...".
func short(b []byte) string { return hex.EncodeToString(b)[:16] + "..." }

func listPath(set string) string { return "trust/" + jsonset.EscapeExact(set) + "/root-list.json" }
