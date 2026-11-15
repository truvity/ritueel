//go:build linux || darwin

package history

import (
	"errors"
	"strings"
	"testing"
)

// A set whose folder name has the number 0 is a name with no trust number (the finding
// trust-sequence says a folder number of 0 is no trust number). No SetInfo carries it, so no caller
// can take 0 for a number: the bundle has no State and OrderErr says why.

// zeroNamed is a clean bundle where a closing record lists the set name, and a newer stopped
// ceremony left the set with the number 5 (so the set of the name is the newest that a record
// lists).
func zeroNamed(t *testing.T, name string, leftover bool) *bundle {
	t.Helper()
	b := chainBundle(t, false, cset{setN(1), keyList(1, kA)})
	stopped := b.unfinished(withSet(name, keyList(2, kA)))
	b.closing(stopped, listsLeftover(stopped, nil))
	if leftover {
		b.unfinished(withSet(setN(5), keyList(5, kA)), func(r *rec) {
			r.plan.TrustSequence = ptr(int64(5))
			r.refresh()
		})
	}
	return b
}

func TestAZeroNumberIsNoTrustNumberForTheNewestListedSet(t *testing.T) {
	for _, leftover := range []bool{true, false} {
		for _, name := range []string{"0-aaaaaaaa", "0-0", "0-"} {
			b := zeroNamed(t, name, leftover)
			in := b.inspect() // the report equals that of Check
			if !in.Report.Clean() {
				t.Logf("%q (leftover %v): another finding comes first", name, leftover)
				if in.State != nil {
					t.Errorf("%q: a State with a failing report", name)
				}
				continue
			}
			if in.State != nil {
				t.Errorf("%q (leftover %v): a State with NewestListed %+v and Newest %+v", name, leftover, in.State.NewestListed, in.State.Newest)
				continue
			}
			if !errors.Is(in.OrderErr, ErrOrder) {
				t.Errorf("%q (leftover %v): OrderErr = %v, want one that wraps ErrOrder", name, leftover, in.OrderErr)
				continue
			}
			// With a newer set, the name is judged as the newest listed set. With none, the set is also
			// the newest, and its number is held to the sequence of its list first.
			if leftover && !strings.Contains(in.OrderErr.Error(), "no trust number") {
				t.Errorf("%q: the reason does not say there is no trust number: %v", name, in.OrderErr)
			}
		}
	}
}

// A name that begins with a number of 1 and up is the neighbour: the same bundles give a State.
func TestANumberOfOneAndUpIsATrustNumberForTheNewestListedSet(t *testing.T) {
	for _, leftover := range []bool{true, false} {
		in := zeroNamed(t, setN(2), leftover).inspectAdditions()
		if in.State == nil {
			t.Fatalf("leftover %v: no State: %v", leftover, in.OrderErr)
		}
		if in.State.NewestListed == nil || in.State.NewestListed.Number != 2 {
			t.Errorf("leftover %v: NewestListed = %+v", leftover, in.State.NewestListed)
		}
	}
}

// With no record that lists the set, a set named 0- is an unlisted set that no attempt can be
// linked to: the report fails, so there is no State and no OrderErr.
func TestAZeroNumberedSetThatNoRecordListsFailsTheReport(t *testing.T) {
	b := numbered(t, false, 1)
	b.mkdir("trust/0-aaaaaaaa")
	b.put("trust/0-aaaaaaaa/root-list.json", keyList(1, kA))
	b.unfinished(noSet)
	in := b.inspect()
	if in.Report.Clean() || in.State != nil || in.OrderErr != nil {
		t.Errorf("clean %v, State %v, OrderErr %v", in.Report.Clean(), in.State, in.OrderErr)
	}
	has(t, in.Report, TrustSetUnlisted, "trust/0-aaaaaaaa")
}

// The two helpers, called on a hand-made checker, for the names that have the number 0.
func TestTheHelpersTakeANameWithTheNumberZeroAsOneWithNoNumber(t *testing.T) {
	t.Run("an unlisted set", func(t *testing.T) {
		for _, name := range []string{"0-a", "0-", "0-0-0"} {
			ck := handChecker()
			ck.setNames = []string{"1-a", name}
			st := &State{}
			why := ck.chainAndUnlisted(st)
			if !strings.Contains(why, "no trust number") {
				t.Errorf("%q: why = %q", name, why)
			}
		}
	})
	t.Run("an unlisted set whose name has the number 1", func(t *testing.T) {
		ck := handChecker()
		ck.setNames = []string{"1-a"}
		st := &State{}
		if why := ck.chainAndUnlisted(st); why != "" || len(st.Unlisted) != 1 || st.Unlisted[0].Number != 1 {
			t.Errorf("why %q, Unlisted %+v", why, st.Unlisted)
		}
	})
	t.Run("the newest listed set", func(t *testing.T) {
		for _, name := range []string{"0-a", "0-", "0-0-0"} {
			ck := handChecker()
			ck.rootLists = []setList{{set: name, read: &anchorOf{raw: []byte("x")}}}
			ck.listed[name] = &anchorWant{}
			st := &State{Lists: []RootList{{Name: name}}}
			why, err := ck.newestListed(st)
			if err != nil || !strings.Contains(why, "no trust number") || st.NewestListed != nil {
				t.Errorf("%q: why %q, err %v, NewestListed %+v", name, why, err, st.NewestListed)
			}
		}
	})
	t.Run("the newest listed set whose name has the number 1", func(t *testing.T) {
		ck := handChecker()
		ck.rootLists = []setList{{set: "1-a", read: &anchorOf{raw: []byte("x")}}}
		ck.listed["1-a"] = &anchorWant{}
		st := &State{Lists: []RootList{{Name: "1-a"}}}
		if why, err := ck.newestListed(st); why != "" || err != nil || st.NewestListed == nil || st.NewestListed.Number != 1 {
			t.Errorf("why %q, err %v, NewestListed %+v", why, err, st.NewestListed)
		}
	})
}
