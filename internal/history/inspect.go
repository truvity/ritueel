package history

import (
	"bytes"
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
// the number that its folder name says. It never leads to a guessed order, and never to an order
// taken from a folder name alone. [Inspection.OrderErr] wraps it.
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
	// list in it is never Unreadable.
	Lists []RootList
	// Newest is the last of Lists; nil when there is no trust set with a root list.
	Newest *SetInfo
	// Unfinished are the names of the ceremony folders that hold attempt.json and no record.json,
	// and that no closing record names in closes.ceremony, in the order of the names. The check
	// does not say whether the attempt belongs to this history: a person or a later part reads it.
	Unfinished []string
}

// SetInfo is the newest trust set.
type SetInfo struct {
	// Name is the folder name of the set, "13-3fa9c1d2".
	Name string
	// Number is the number in the name. It equals the member sequence of the list; a set for which
	// the two differ is not placed, and the bundle has no State.
	Number int64
	// ListJSON is a copy of the bytes of root-list.json that the walk read and judged.
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
func Inspect(ctx context.Context, fsys fsx.FS) (*Inspection, error) {
	ck, err := runCheck(ctx, fsys, limits{readBytes: MaxReadBytes, fileReads: MaxFileReads, perCode: MaxFindingsPerCode}, true)
	if err != nil {
		return nil, err
	}
	in := &Inspection{Report: ck.report()}
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
	for _, g := range order.bySeq {
		if len(g.lists) != 1 || g.lists[0].read == nil {
			return nil, "a trust set is not at one place of its own, or its root list cannot be read", nil
		}
		l := g.lists[0]
		st.Lists = append(st.Lists, rootListOf(l))
		newest = l
	}
	if len(st.Lists) > 0 {
		n, ok := trustNumber(newest.set)
		if !ok || !newest.read.hasSequence || newest.read.sequence != n {
			return nil, "the number in the name of " + setShown(newest.set) + " is not the sequence of its root list", nil
		}
		if newest.read.raw == nil {
			return nil, "", fmt.Errorf("%w: the root list of %s is not among the %d bytes of root lists that an inspection keeps", ErrTooMuch, setShown(newest.set), MaxStateBytes)
		}
		st.Newest = &SetInfo{Name: newest.set, Number: n, ListJSON: bytes.Clone(newest.read.raw)}
	}
	for _, f := range ck.candidates {
		if _, closed := ck.closed[f]; !closed {
			st.Unfinished = append(st.Unfinished, f)
		}
	}
	slices.Sort(st.Unfinished)
	return st, "", nil
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
