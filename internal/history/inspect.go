package history

import (
	"bytes"
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"ritueel.id/ritueel/internal/fsx"
)

// ErrOrder is the reason a clean report has no [State]: the order of the root lists cannot be
// settled by one reading. Two or more trust sets stand at one place and their sequences and
// numbers do not put them in one order, or a set stands at more than one place, or a set that no
// record lists cannot be placed (its place is not on the chain), or the newest set does not carry
// the number that its folder name says, or the last set of the chain does not hold the highest
// sequence (a ceremony that stopped, and a later one that wrote a set with a higher number: a list
// built on the last set would take a number that is in use), or the sequence of a list of the
// chain cannot be read. It never leads to a guessed order, and never to an order taken from a
// folder name alone. [Inspection.OrderErr] wraps it.
var ErrOrder = errors.New("the order of the root lists cannot be settled")

// Inspection is what [Inspect] returns.
type Inspection struct {
	// Report is exactly what [Check] returns for the same bundle.
	Report *Report
	// State is nil unless the report has no failing finding ([Report.Clean]) and the order of the
	// root lists has one reading.
	State *State
	// OrderErr says why a clean report has no State. It wraps [ErrOrder]. It is nil when State is
	// not nil, and nil when the report has a failing finding (the findings are the reason then).
	OrderErr error
	// Unfinished are the ceremony folders that hold an entry named attempt.json and no record.json,
	// and that no closing record names in closes.ceremony, in the order of the names. It is set
	// whenever the walk ended, whether the report is clean or not and whether the order of the root
	// lists is sure or not: an open attempt is never hidden by another fault (a fork, a flipped
	// digest). It is a copy of two lists that the walk holds, so it takes any entry of that name as
	// an attempt, a link or a folder too; the report says what is wrong with such an entry, and
	// the caller reads the attempt before it takes the ceremony as open. When State is not nil it
	// equals State.Unfinished.
	Unfinished []string
}

// State is what a writer of the next ceremony needs to know of a bundle whose history is whole.
// Every value in it was read by the one walk that made the report, and a caller may change what it
// holds: each call of [Inspect] builds a new one.
type State struct {
	// Records is the count of ceremony records.
	Records int
	// End is the digest of the one end of the hash chain, "" when there is no record.
	End string
	// Lists is every root list of the bundle, in the order of the hash chain, the newest last, in
	// the form that [FindReturns] takes. Name is the folder name of the set (without "trust/"). A
	// list in it is never Unreadable. A label is as the walk kept it: it may be cut short, and it
	// may hold control characters or an escape sequence, so a caller shows it only through the
	// escape of internal/jsonset. The next list is built from Newest.ListJSON and never from these
	// labels.
	Lists []RootList
	// Newest is the last of Lists, the newest set: it is the last of the chain and it holds the
	// highest sequence of all lists (a bundle where it does not has no State). It is nil when there
	// is no trust set with a root list.
	Newest *SetInfo
	// Unfinished are the names of the ceremony folders that hold a file named attempt.json and no
	// record.json, and that no closing record names in closes.ceremony, in the order of the names.
	// The check does not say whether the attempt belongs to this history, or whether the ceremony
	// is still open: the caller reads the attempt before it takes the ceremony as open.
	Unfinished []string
	// Chain is every ceremony record, in the order of the hash chain, the oldest first: the order
	// that a writer cannot choose, and never an order of folder names. Each of Records is in it
	// once. It is nil when there is no record.
	Chain []CeremonyInfo
	// Unlisted are the trust sets that no record lists (the set that an unfinished ceremony left),
	// in the order of the names, with the number that the digits of the name give: the one rule of
	// this package for a number, so that a caller does not write it a second time. A set in it
	// that has a root list is in Lists too, and its ListJSON is a copy of the bytes that the walk
	// read; ListJSON is nil for a set that has no root list, or whose bytes were not kept (see
	// [MaxStateBytes]), and the caller reads the file. In a clean report each of them is linked to
	// an open attempt, because a set that is not linked is the failing finding trust-set-unlisted.
	Unlisted []SetInfo
	// NewestListed is the last set of Lists that a record lists, never a set that no record lists.
	// It is nil when no record lists a set. Its ListJSON is a copy of the bytes that the walk read
	// and judged; a bundle where those bytes were not kept has no State ([ErrTooMuch]), as for
	// Newest.
	NewestListed *SetInfo
}

// CeremonyInfo is one record of the chain.
type CeremonyInfo struct {
	// Folder is the name of the ceremony folder that holds the record, without "history/".
	Folder string
	// Command and Outcome are the members command and outcome of the record: apply or close, and
	// completed, declined or closed.
	Command, Outcome string
	// SHA256 is the digest of record.json as it is stored, lower-case hexadecimal.
	SHA256 string
}

// SetInfo is a trust set that [State] describes: the newest one, the newest that a record lists,
// or one that no record lists. The newest set is the last set of the chain, and the one that holds
// the highest sequence of all root lists.
type SetInfo struct {
	// Name is the folder name of the set, "13-3fa9c1d2".
	Name string
	// Number is the trust number in the name: the decimal digits before the first hyphen, at least
	// 1 (a name that begins 0- has no trust number, as for the finding trust-sequence). A set
	// whose name has none is not described by a SetInfo: the bundle has no State. For the newest set
	// it equals the member sequence of the list; a newest set for which the two differ is not
	// placed, and the bundle has no State. For the other sets it is the number that the digits of
	// the name give, and nothing more.
	Number int64
	// ListJSON is a copy of the bytes of root-list.json that the walk read and judged. It is nil
	// only for a set of [State.Unlisted] that has no root list or whose bytes were not kept.
	ListJSON []byte
}

// Inspect runs the walk of [Check] once and returns its report together with the [State] that a
// writer of the next ceremony needs. It reads files only and writes nothing, and it makes no
// second walk of the bundle: the State is worked out from what the one walk collected. An error
// means "the bundle was not inspected" (a read failed, a limit was met, the context ended), as for
// [Check]; it is also returned, with [ErrTooMuch], when the report is clean and the bytes of the
// newest root list were not kept (see [MaxStateBytes]).
//
// A State is returned only when the report has no failing finding and there is exactly one reading
// of the order of the root lists (record 0006, rule 54). Where [Check] judges every order, or says
// that the order is not sure, there is no State, and [Inspection.OrderErr] wraps [ErrOrder].
//
// A set that [State] describes with a [SetInfo] (the newest listed set, and each set of
// [State.Unlisted]) must have a trust number in its folder name. One bundle that gave a State
// before this rule gives none now, and it fails closed: a closing record lists a set whose name has
// no trust number (the check leaves such a set out of trust-sequence), and a newer ceremony
// stopped and left a set. The report is the same as for [Check]; only State is nil, and
// [Inspection.OrderErr] says why.
func Inspect(ctx context.Context, fsys fsx.FS) (*Inspection, error) {
	ck, err := runCheck(ctx, fsys, limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode}, true)
	if err != nil {
		return nil, err
	}
	in := &Inspection{Report: ck.report(), Unfinished: ck.unfinishedFolders()}
	if !in.Report.Clean() {
		return in, nil
	}
	st, why, err := ck.state(in.Report)
	if err != nil {
		return nil, err
	}
	if why != "" {
		in.OrderErr = fmt.Errorf("%w: %s", ErrOrder, why)
		return in, nil
	}
	in.State = st
	return in, nil
}

// state works out the State of a clean walk. why is the reason, in one sentence, when the order of
// the root lists has no one reading; an error is a fault of the run.
func (ck *checker) state(rep *Report) (st *State, why string, err error) {
	if rep.Records > 0 && len(rep.Ends) != 1 {
		return nil, "the history does not have exactly one end", nil
	}
	all, placed, floating, multi := ck.placeLists()
	switch {
	case len(floating) > 0:
		return nil, "the place of " + namesOf(floating) + " in the chain cannot be told", nil
	case multi:
		return nil, "a trust set stands at more than one place in the chain", nil
	}
	order := inPlaces(all, setKeys(placed))
	if order.unsure || len(order.places) > 0 {
		return nil, "trust sets stand at one place and their sequences and numbers do not put them in one order", nil
	}
	if len(order.bySeq) != len(placed) {
		return nil, "a trust set is not at one place of its own", nil
	}
	st = &State{Records: rep.Records}
	if rep.Records > 0 {
		st.End = rep.Ends[0]
	}
	var newest setList
	// before is the highest sequence of the lists before the last one; seqOK is false when the
	// sequence of one list of the chain cannot be read.
	var before int64
	haveBefore, seqOK := false, true
	for i, g := range order.bySeq {
		if len(g.lists) != 1 || g.lists[0].read == nil {
			return nil, "a trust set is not at one place of its own, or its root list cannot be read", nil
		}
		l := g.lists[0]
		st.Lists = append(st.Lists, rootListOf(l))
		newest = l
		switch {
		case !l.read.hasSequence:
			seqOK = false
		case i < len(order.bySeq)-1 && (!haveBefore || l.read.sequence > before):
			before, haveBefore = l.read.sequence, true
		}
	}
	if len(st.Lists) > 0 {
		n, ok := trustNumber(newest.set)
		if !ok || !newest.read.hasSequence || newest.read.sequence != n {
			return nil, "the number in the name of " + setShown(newest.set) + " is not the sequence of its root list", nil
		}
		if !seqOK {
			return nil, "the sequence of a root list of the chain cannot be read", nil
		}
		if haveBefore && newest.read.sequence <= before {
			return nil, "the last set of the chain, " + setShown(newest.set) + ", does not hold the highest sequence of the root lists", nil
		}
		if newest.read.raw == nil {
			return nil, "", fmt.Errorf("%w: the root list of %s is not among the %d bytes of root lists that an inspection keeps", ErrTooMuch, setShown(newest.set), MaxStateBytes)
		}
		st.Newest = &SetInfo{Name: newest.set, Number: n, ListJSON: bytes.Clone(newest.read.raw)}
		if why, err := ck.newestListed(st); why != "" || err != nil {
			return nil, why, err
		}
	}
	if why := ck.chainAndUnlisted(st); why != "" {
		return nil, why, nil
	}
	st.Unfinished = ck.unfinishedFolders()
	return st, "", nil
}

// unfinishedFolders are the ceremony folders that hold an entry named attempt.json and no
// record.json, and that no closing record names, in the order of the names. The walk holds both
// lists when it ends, whether its report is clean or not.
func (ck *checker) unfinishedFolders() []string {
	var out []string
	for _, f := range ck.candidates {
		if _, closed := ck.closed[f]; !closed {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

// newestListed sets State.NewestListed: the last list of the chain whose set a record lists. why is
// the reason, in one sentence, when the order has no one reading; an error is a fault of the run.
func (ck *checker) newestListed(st *State) (why string, err error) {
	byName := make(map[string]setList, len(ck.rootLists))
	for _, l := range ck.rootLists {
		byName[l.set] = l
	}
	for i := len(st.Lists) - 1; i >= 0; i-- {
		name := st.Lists[i].Name
		if ck.listed[name] == nil {
			continue
		}
		l := byName[name]
		n, ok := trustNumberFrom1(name)
		if !ok {
			return "the name of " + setShown(name) + " has no trust number", nil
		}
		if l.read == nil || l.read.raw == nil {
			return "", fmt.Errorf("%w: the root list of %s is not among the %d bytes of root lists that an inspection keeps", ErrTooMuch, setShown(name), MaxStateBytes)
		}
		st.NewestListed = &SetInfo{Name: name, Number: n, ListJSON: bytes.Clone(l.read.raw)}
		return "", nil
	}
	return "", nil
}

// chainAndUnlisted sets State.Chain and State.Unlisted from what the walk collected. why is the
// reason, in one sentence, when the order has no one reading.
func (ck *checker) chainAndUnlisted(st *State) (why string) {
	var chain []recInfo
	for _, r := range ck.recs {
		if r.parsed && ck.onChain[r.digest] {
			chain = append(chain, r)
		}
	}
	// A clean report has every record on the chain, in one line: the depths are all different.
	slices.SortFunc(chain, func(a, b recInfo) int {
		return cmp.Or(cmp.Compare(ck.depth[a.digest], ck.depth[b.digest]), cmp.Compare(a.folder, b.folder))
	})
	if len(chain) != st.Records {
		return "the chain of records does not hold every record"
	}
	for i, r := range chain {
		if ck.depth[r.digest] != i {
			return "the records do not stand in one line in the chain"
		}
		st.Chain = append(st.Chain, CeremonyInfo{Folder: r.folder, Command: r.command, Outcome: r.outcome, SHA256: r.digest})
	}
	byName := make(map[string]setList, len(ck.rootLists))
	for _, l := range ck.rootLists {
		byName[l.set] = l
	}
	for _, name := range slices.Sorted(slices.Values(ck.setNames)) {
		if ck.listed[name] != nil {
			continue
		}
		n, ok := trustNumberFrom1(name)
		if !ok {
			return "the name of " + setShown(name) + " has no trust number"
		}
		info := SetInfo{Name: name, Number: n}
		if l, ok := byName[name]; ok && l.read != nil && l.read.raw != nil {
			info.ListJSON = bytes.Clone(l.read.raw)
		}
		st.Unlisted = append(st.Unlisted, info)
	}
	return ""
}

// rootListOf turns a list that was read into the form of [FindReturns]: each pin and fingerprint as
// lower-case hexadecimal digits, each label as the walk kept it.
func rootListOf(l setList) RootList {
	out := RootList{Name: l.set, Keys: make([]RootKey, 0, len(l.read.keys))}
	for _, k := range l.read.keys {
		rk := RootKey{Label: k.label}
		if k.hasPin {
			rk.Pin = hex.EncodeToString(k.pin[:])
		}
		if k.hasFP {
			rk.Fingerprint = hex.EncodeToString(k.fp[:])
		}
		out.Keys = append(out.Keys, rk)
	}
	return out
}

// namesOf names the first of some trust sets for a reason, and how many more there are.
func namesOf(lists []setList) string {
	text := setShown(lists[0].set)
	if len(lists) > 1 {
		text += " and " + strconv.Itoa(len(lists)-1) + " more"
	}
	return text
}
