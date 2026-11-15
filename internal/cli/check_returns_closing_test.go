//go:build linux || darwin

package cli

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// A closing record that lists the files of a stopped ceremony places the set where the closing
// record stands, and not at the end that the plan of the closed ceremony names (record 0006, rule
// 8): a plan is a file that the writer of the closing record can make. The command reports the
// return, with exit code 3, in both output modes.

// hbClosing writes a closing record, after the newest record of b, for the attempt of the stopped
// ceremony, and lists the trust set that the stopped ceremony left.
func hbClosing(t testing.TB, b *hbundle, stopped hbCeremony) hbCeremony {
	t.Helper()
	n := len(b.cs) + 1
	c := hbCeremony{n: n, folder: fmt.Sprintf("2026%04dT100000Z-close", n), prev: b.end()}
	c.transcript = fmt.Sprintf("closing %d\n", n)
	rec := `{"artifacts":[` +
		`{"path":"trust/` + stopped.set + `/keys.txt","sha256":"` + hbSum(stopped.keys) + `"},` +
		`{"path":"trust/` + stopped.set + `/root-list.json","sha256":"` + hbSum(stopped.rootList) + `"}],` +
		`"ceremony":"` + c.folder + `",` +
		`"closes":{"attempt_sha256":"` + hbSum(stopped.attempt) + `","ceremony":"` + stopped.folder + `","reason":"the run stopped"},` +
		`"command":"close","outcome":"closed","prev_record_sha256":"` + c.prev + `",` +
		`"transcript_sha256":"` + hbSum(c.transcript) + `","version":1}`
	c.record, c.digest = rec, hbSum(rec)
	hbWrite(t, b.dir, c.base()+"transcript.txt", c.transcript)
	hbWrite(t, b.dir, c.base()+"record.json", c.record)
	b.cs = append(b.cs, c)
	return c
}

// hbPlanNames makes the plan of a ceremony name the record with this digest as the end of the
// history, and the attempt and the root list of its set follow it.
func hbPlanNames(digest string) func(*hbCeremony) {
	return func(c *hbCeremony) {
		c.prev = digest
		ns := fmt.Sprint(c.n)
		c.plan = `{"ceremony":"` + c.folder + `","command":"apply","last_record_sha256":"` + digest + `","trust_sequence":` + ns + `,"version":1,"wanted":[{"path":"ritueel.yaml","sha256":"` + hbSum(c.wanted) + `"}]}`
		c.attempt = `{"ceremony":"` + c.folder + `","plan_sha256":"` + hbSum(c.plan) + `","version":1}`
	}
}

func TestCheckHistoryReportsAReturnThatAClosingRecordHidesInThePlan(t *testing.T) {
	b := newHB(t, 0)
	first := b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	b.add(t, true, hbRoots(hbRoot("B", 2)))
	// The ceremony that stopped left the list {A, B} and a plan that names the first record, so
	// that the set would stand next to the second one. The closing record lists it, as the newest.
	// Its folder number and the sequence of its list say that it is older than the second set.
	older := func(c *hbCeremony) {
		c.set = "1-ffffffff"
		c.rootList = strings.Replace(c.rootList, `"sequence":3`, `"sequence":1`, 1)
	}
	stopped := b.add(t, false, hbPlanNames(first.digest), hbRoots(hbRoot("A", 1), hbRoot("B", 2)), older)
	hbClosing(t, b, stopped)

	rep := chReport(t, b.dir)
	if got := chCodes(rep.Reasons()); !slices.Equal(got, []string{"root-returns"}) {
		t.Fatalf("the bundle of the test gives the reasons %v", got)
	}
	path := "trust/" + stopped.set + "/root-list.json"
	want := "root-returns " + path + ": root key \"A\" returns: its pin " + hbPin(1)[:16] + "... was on an earlier list and is not on the list before this one (record 0006, rule 54); pin held on trust/" + b.cs[0].set + "; list before trust/" + b.cs[1].set

	text := chHist(t, b.dir)
	if text.code != ExitRefused || text.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 and nothing on standard output", text.code, text.stdout, text.stderr)
	}
	if got := chLines(text.stderr); !slices.Equal(got, []string{want, "ritueel: refused: root-returns"}) {
		t.Errorf("standard error:\n got %q\nwant %q", got, []string{want, "ritueel: refused: root-returns"})
	}
	js := chJSON(t, b.dir)
	if js.code != ExitRefused || js.stderr != text.stderr {
		t.Errorf("JSON: exit %d; standard error %q, in text mode %q", js.code, js.stderr, text.stderr)
	}
	chWantRefused(t, js, []string{"root-returns"}, []string{})
}

// The honest closing, made at once, is clean and exits 0.
func TestCheckHistoryIsCleanForAnHonestClosing(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	stopped := b.add(t, false, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	hbClosing(t, b, stopped)
	b.add(t, true, hbRoots(hbRoot("A", 1)))
	r := chHist(t, b.dir)
	// Three records: the first ceremony, the closing record and the last ceremony.
	if want := chEnd(3, b.end()); r.code != ExitOK || r.stdout != want || r.stderr != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 0, %q and nothing on standard error", r.code, r.stdout, r.stderr, want)
	}
}
