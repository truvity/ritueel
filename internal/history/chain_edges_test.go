//go:build linux || darwin

package history

import (
	"fmt"
	"strings"
	"testing"
)

// With two records that have no predecessor the first one cannot be told, so no record is on the
// chain: a record after either of them is off the chain too. (The page says that a record that is not
// on the chain is record-off-chain; it does not say which of two roots counts. The check does not pick.)
func TestRecordAfterOneOfTwoRootsIsOffTheChain(t *testing.T) {
	b := newBundle(t)
	a := b.apply(noSet)
	x := b.apply(noSet, prev(""))
	y := b.apply(noSet)
	rep := b.run()
	wantFindings(t, rep, []wf{
		{ChainBroken, folderPath(a)},
		{ChainBroken, folderPath(x)},
		{RecordOffChain, folderPath(y)},
	})
}

// The detail of an unfinished ceremony names at most three of the open attempts of the trust sequence,
// then three dots.
func TestUnfinishedCeremonyNamesAtMostThreeOpenAttempts(t *testing.T) {
	for _, n := range []int{1, 3, 4, 6} {
		t.Run(fmt.Sprintf("%d attempts", n), func(t *testing.T) {
			b := newBundle(t)
			u := b.unfinished()
			for i := 1; i < n; i++ {
				b.unfinished(noSet, func(r *rec) {
					r.plan.TrustSequence = ptr(int64(1))
					r.refresh()
				})
			}
			rep := b.run()
			wantFindings(t, rep, []wf{{UnfinishedCeremony, setPath(u)}})
			d := detail(rep, UnfinishedCeremony, setPath(u))
			names := strings.Count(d, "T100000Z-apply")
			if want := min(n, 3); names != want {
				t.Errorf("the detail names %d attempts, want %d: %s", names, want, d)
			}
			if got := strings.Contains(d, "..."); got != (n > 3) {
				t.Errorf("three dots = %v for %d attempts: %s", got, n, d)
			}
		})
	}
}

// The number that a trust set's name begins with has at most 15 digits, no leading zero, and the
// number 0 is a number. (The page leaves the length open; the check bounds it.)
func TestTrustNumberIsAtMostFifteenDigitsWithNoLeadingZero(t *testing.T) {
	for _, c := range []struct {
		name   string
		number int64
		code   Code
	}{
		{"999999999999999-3fa9c1d3", 999999999999999, UnfinishedCeremony},
		{"1000000000000000-3fa9c1d3", 1000000000000000, TrustSetUnlisted},
		{"0-3fa9c1d3", 0, TrustSetUnlisted}, // 0 is no trust number: the trust numbers are 1 and up
		{"00-3fa9c1d3", 0, TrustSetUnlisted},
		{"01-3fa9c1d3", 1, TrustSetUnlisted},
		{"1-3fa9c1d3", 1, UnfinishedCeremony},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newBundle(t)
			u := b.unfinished(setName(c.name), func(r *rec) {
				r.plan.TrustSequence = ptr(c.number)
				r.refresh()
			})
			rep := b.run()
			has(t, rep, c.code, setPath(u))
		})
	}
}

// A code that is not one of the known ones sorts after every known code, whatever the paths say.
func TestFindingOfAnUnknownCodeSortsAfterEveryKnownCode(t *testing.T) {
	unknown := Finding{Code: "zzz-not-a-code", Path: "a", Detail: "d"}
	for _, c := range Codes() {
		known := Finding{Code: c, Path: "z", Detail: "d"}
		if compare(known, unknown) >= 0 || compare(unknown, known) <= 0 {
			t.Errorf("%s does not sort before an unknown code", c)
		}
	}
}
