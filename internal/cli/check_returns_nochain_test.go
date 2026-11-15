//go:build linux || darwin

package cli

import (
	"slices"
	"strings"
	"testing"
)

// When the bundle has ceremony records and none of them is on the chain (two records that have no
// prev_record_sha256), no trust set has a place, and every root list is judged as a list whose place
// cannot be told. The bundle fails with chain-broken, and the name root-returns is there when a key
// came back: exit code 3, the name in reasons, one line on standard error for each finding, in both
// output modes.

// hbFirst makes a ceremony a first record: its record names no predecessor, and its root list names none.
func hbFirst(c *hbCeremony) { c.prev = "" }

func TestCheckHistoryNamesRootReturnsForTwoFirstRecordsThatShareAKey(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbFirst, hbRoots(hbRoot("A", 1)))
	b.add(t, true, hbFirst, hbRoots(hbRoot("A", 1)))
	rep := chReport(t, b.dir)
	got := chCodes(rep.Reasons())
	if !slices.Contains(got, "chain-broken") || !slices.Contains(got, "root-returns") {
		t.Fatalf("the library gives the reasons %v", got)
	}

	text := chHist(t, b.dir)
	if text.code != ExitRefused || text.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 and nothing on standard output", text.code, text.stdout, text.stderr)
	}
	for i, other := range []int{2, 1} {
		path := "trust/" + b.cs[i].set + "/root-list.json"
		want := "root-returns " + path + ": root key \"A\" returns: its pin " + hbPin(1)[:16] + "... was on another list; the place of this trust set in the chain cannot be told (record 0006, rule 54); pin held on trust/" + b.cs[other-1].set
		if !slices.Contains(chLines(text.stderr), want) {
			t.Errorf("standard error lacks the line\n%q\nstandard error: %q", want, text.stderr)
		}
	}
	if got := chLines(text.stderr); !slices.Equal(got, chWantLines(rep)) {
		t.Errorf("standard error:\n got %q\nwant %q", got, chWantLines(rep))
	}
	last := chLines(text.stderr)
	if want := "ritueel: refused: " + strings.Join(got, ", "); last[len(last)-1] != want {
		t.Errorf("the last line is %q, want %q", last[len(last)-1], want)
	}

	js := chJSON(t, b.dir)
	if js.code != ExitRefused || js.stderr != text.stderr {
		t.Errorf("JSON: exit %d; standard error %q, in text mode %q", js.code, js.stderr, text.stderr)
	}
	chWantRefused(t, js, got, []string{})
}

// The same through the fingerprint of an OpenPGP key.
func TestCheckHistoryNamesRootReturnsForTwoFirstRecordsThatShareAFingerprint(t *testing.T) {
	fp := strings.Repeat("ab", 20)
	entry := `{"label":"F","openpgp_fingerprint":"` + fp + `"}`
	b := newHB(t, 0)
	b.add(t, true, hbFirst, hbRoots(entry))
	b.add(t, true, hbFirst, hbRoots(entry))
	r := chHist(t, b.dir)
	if r.code != ExitRefused {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	n := 0
	for _, l := range chLines(r.stderr) {
		if strings.HasPrefix(l, "root-returns ") && strings.Contains(l, "its OpenPGP fingerprint "+fp[:16]+"... was on another list; the place of this trust set in the chain cannot be told") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d lines of root-returns for the fingerprint, want 2: %q", n, r.stderr)
	}
	chWantRefused(t, chJSON(t, b.dir), chCodes(chReport(t, b.dir).Reasons()), []string{})
}

// No key came back: the bundle fails with chain-broken and has no finding of root-returns.
func TestCheckHistoryHasNoRootReturnsForTwoFirstRecordsThatShareNoKey(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbFirst, hbRoots(hbRoot("A", 1)))
	b.add(t, true, hbFirst, hbRoots(hbRoot("B", 2)))
	r := chHist(t, b.dir)
	if r.code != ExitRefused {
		t.Fatalf("exit %d, stderr %q", r.code, r.stderr)
	}
	if strings.Contains(r.stderr, "root-returns") {
		t.Errorf("a finding of root-returns where no key came back: %q", r.stderr)
	}
	if !strings.Contains(r.stderr, "chain-broken") {
		t.Errorf("no chain-broken: %q", r.stderr)
	}
	chWantRefused(t, chJSON(t, b.dir), []string{"chain-broken"}, []string{})
}

// A bundle whose chain is walked is unchanged: the same keys give a place, and the finding says the list before.
func TestCheckHistoryGivesAPlaceToAChainThatIsWalked(t *testing.T) {
	b := hbReturned(t, "A")
	r := chHist(t, b.dir)
	if r.code != ExitRefused || strings.Contains(r.stderr, "cannot be told") || !strings.Contains(r.stderr, "; list before trust/"+b.cs[1].set) {
		t.Errorf("exit %d, stderr %q", r.code, r.stderr)
	}
}
