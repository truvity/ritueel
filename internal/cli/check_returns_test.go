//go:build linux || darwin

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// The command "check history" and the finding root-returns (record 0006, rule 54; the row
// root-returns of "The hash chain" in docs/reference/ceremony-record.md): exit code 3, the name in
// reasons, one line "root-returns PATH: DETAIL" on standard error, the same in both output modes.
// The bundles are made by hand like the others of check_bundle_test.go.

// bsl is a backslash.
const bsl = string(rune(0x5c))

// hbPin is the nth pin: 64 lower-case hexadecimal digits.
func hbPin(n int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("pin %d", n)))
	return hex.EncodeToString(h[:])
}

// hbRoot is one entry of roots in canonical form: the members in order of name.
func hbRoot(label string, n int) string {
	return `{"label":` + jsonText(label) + `,"x509_spki_sha256":"` + hbPin(n) + `"}`
}

// jsonText writes a text as a JSON string; the tests give it ASCII and escapes it themselves.
func jsonText(s string) string { return `"` + s + `"` }

// hbRoots makes the root list of a ceremony hold the entries, anchored to the record before it.
func hbRoots(entries ...string) func(*hbCeremony) {
	return func(c *hbCeremony) {
		l := `{`
		if c.prev != "" {
			l += `"last_record_sha256":"` + c.prev + `",`
		}
		c.rootList = l + `"roots":[` + strings.Join(entries, ",") + `],"sequence":` + fmt.Sprint(c.n) + `,"version":1}`
	}
}

// hbReturned is a bundle of three ceremonies whose third root list holds the key A that the second
// one left out.
func hbReturned(t testing.TB, label string) *hbundle {
	t.Helper()
	b := newHB(t, 0)
	b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	b.add(t, true, hbRoots(hbRoot("B", 2)))
	b.add(t, true, hbRoots(hbRoot(label, 1), hbRoot("B", 2)))
	return b
}

func TestCheckHistoryReportsARootKeyThatCameBack(t *testing.T) {
	b := hbReturned(t, "A")
	rep := chReport(t, b.dir)
	if got := chCodes(rep.Reasons()); !slices.Equal(got, []string{"root-returns"}) {
		t.Fatalf("the bundle of the test gives the reasons %v", got)
	}
	path := "trust/" + b.cs[2].set + "/root-list.json"
	wantLine := "root-returns " + path + ": root key \"A\" returns: its pin " + hbPin(1)[:16] + "... was on an earlier list and is not on the list before this one (record 0006, rule 54); pin held on trust/" + b.cs[0].set + "; list before trust/" + b.cs[1].set

	text := chHist(t, b.dir)
	if text.code != ExitRefused || text.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 3 and nothing on standard output", text.code, text.stdout, text.stderr)
	}
	want := []string{wantLine, "ritueel: refused: root-returns"}
	if got := chLines(text.stderr); !slices.Equal(got, want) {
		t.Errorf("standard error:\n got %q\nwant %q", got, want)
	}

	js := chJSON(t, b.dir)
	if js.code != ExitRefused || js.stderr != text.stderr {
		t.Errorf("JSON: exit %d; standard error %q, in text mode %q", js.code, js.stderr, text.stderr)
	}
	chWantRefused(t, js, []string{"root-returns"}, []string{})
}

func TestCheckHistoryIsCleanWhenNoRootKeyCameBack(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("B", 2)))
	b.add(t, true, hbRoots(hbRoot("A", 1)))
	b.add(t, true, hbRoots(hbRoot("A", 1), hbRoot("C", 3)))
	r := chHist(t, b.dir)
	if want := chEnd(3, b.cs[2].digest); r.code != ExitOK || r.stdout != want || r.stderr != "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want 0, %q and nothing", r.code, r.stdout, r.stderr, want)
	}
	chWantDone(t, chJSON(t, b.dir), []string{})
}

// A label with characters beyond printable ASCII, escaped in the file, reaches the terminal as
// escapes only, and cannot start a second line.
func TestCheckHistoryShowsALabelOfTheFileOnlyWithEscapes(t *testing.T) {
	labels := map[string]string{
		"a line break":      `A\nroot-returns trust/x: forged`,
		"a carriage":        `A\rB`,
		"an escape":         `A\u001b[31mred`,
		"a right to left":   "A" + bsl + "u202eB",
		"a letter beyond":   bsl + "u00e9" + bsl + "u0430",
		"a backslash":       `A\\B`,
		"a space":           `A B`,
		"a long label":      strings.Repeat("A", 200),
		"a character plane": bsl + "ud83d" + bsl + "ude00",
	}
	for name, l := range labels {
		t.Run(name, func(t *testing.T) {
			b := hbReturned(t, l)
			rep := chReport(t, b.dir)
			if !slices.Equal(chCodes(rep.Reasons()), []string{"root-returns"}) {
				t.Fatalf("reasons %v", chCodes(rep.Reasons()))
			}
			r := chHist(t, b.dir)
			if r.code != ExitRefused {
				t.Fatalf("exit %d", r.code)
			}
			ls := chLines(r.stderr)
			if len(ls) != 2 {
				t.Fatalf("%d lines: %q", len(ls), ls)
			}
			if !strings.HasPrefix(ls[0], "root-returns trust/"+b.cs[2].set+"/root-list.json: root key \"") {
				t.Errorf("the line is %q", ls[0])
			}
			if ls[1] != "ritueel: refused: root-returns" {
				t.Errorf("the last line is %q", ls[1])
			}
			if !slices.Equal(ls[:1], chWantLines(rep)[:1]) {
				t.Errorf("the line differs from the library's: %q", ls[0])
			}
		})
	}
}

// The code takes its place in reasons by the order of the page: after anchor-unknown, before
// unexpected-name.
func TestCheckHistoryPutsRootReturnsBetweenAnchorUnknownAndUnexpectedName(t *testing.T) {
	b := hbReturned(t, "A")
	// A root list that cannot be read (anchor-unknown), a name with a space (unexpected-name).
	b.add(t, true, func(c *hbCeremony) { c.rootList = `{"last_record_sha256":"` + c.prev + `","roots":"x","version":1}` })
	if err := os.Mkdir(b.path("history/a b"), 0o755); err != nil {
		t.Fatal(err)
	}
	want := []string{"anchor-unknown", "root-returns", "unexpected-name"}
	rep := chReport(t, b.dir)
	if got := chCodes(rep.Reasons()); !slices.Equal(got, want) {
		t.Fatalf("the bundle of the test gives %v", got)
	}
	r := chHist(t, b.dir)
	if r.code != ExitRefused || r.stdout != "" {
		t.Fatalf("exit %d, stdout %q", r.code, r.stdout)
	}
	ls := chLines(r.stderr)
	if got := ls[len(ls)-1]; got != "ritueel: refused: anchor-unknown, root-returns, unexpected-name" {
		t.Errorf("the last line is %q", got)
	}
	if !slices.Equal(ls, chWantLines(rep)) {
		t.Errorf("standard error:\n got %q\nwant %q", ls, chWantLines(rep))
	}
	chWantRefused(t, chJSON(t, b.dir), want, []string{})
}

// A root list of a trust set that no record lists is read all the same.
func TestCheckHistoryReadsATrustSetThatNoRecordLists(t *testing.T) {
	b := newHB(t, 0)
	b.add(t, true, hbRoots(hbRoot("A", 1)))
	b.add(t, true, hbRoots(hbRoot("B", 2)))
	// The set that no record lists follows the end of the chain, so it is the newest list.
	hbWrite(t, b.dir, "trust/9-3fa9c1d9/root-list.json", `{"last_record_sha256":"`+b.end()+`","roots":[`+hbRoot("A", 1)+`],"version":1}`)
	rep := chReport(t, b.dir)
	if got := chCodes(rep.Reasons()); !slices.Contains(got, "root-returns") {
		t.Fatalf("reasons %v", got)
	}
	r := chHist(t, b.dir)
	if r.code != ExitRefused {
		t.Fatalf("exit %d", r.code)
	}
	if !strings.Contains(r.stderr, "root-returns trust/9-3fa9c1d9/root-list.json: root key \"A\" returns") {
		t.Errorf("standard error %q", r.stderr)
	}
}

// A writer who chooses the name of a trust folder cannot hide a return from the command. A set that
// no record lists and that names no record follows the first ceremony's set, and states its number
// and its sequence: the order of the two is not sure, and the key that left in the second set
// returns in the third in one of the orders. The finding is exit code 3, in both output modes, and
// says that the order is not sure.
func TestCheckHistoryFindsAReturnThatTheNamesOfTheFoldersWouldHide(t *testing.T) {
	build := func(t *testing.T) *hbundle {
		b := newHB(t, 0)
		b.add(t, true, hbRoots(hbRoot("A", 1)))
		b.add(t, true, hbRoots(hbRoot("B", 2)))
		b.add(t, true, hbRoots(hbRoot("B", 2)))
		// A set with the number and the sequence of the first set, which holds the key B: before
		// the first set it is a list that holds B, then the first set lacks it, then B comes back.
		hbWrite(t, b.dir, "trust/1-ffffffff/root-list.json", `{"roots":[`+hbRoot("B", 2)+`],"sequence":1,"version":1}`)
		return b
	}
	b := build(t)
	rep := chReport(t, b.dir)
	if got := chCodes(rep.Reasons()); !slices.Contains(got, "root-returns") {
		t.Fatalf("reasons %v", got)
	}
	r := chHist(t, b.dir)
	if r.code != ExitRefused || r.stdout != "" {
		t.Fatalf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "root-returns trust/"+hbSet(2)+"/root-list.json: root key \"B\" returns: its pin "+hbPin(2)[:16]+"... was on an earlier list and is not on the list before this one; the order of the trust sets is not sure, among trust/"+hbSet(1)+", trust/1-ffffffff (record 0006, rule 54); pin held on ") {
		t.Errorf("standard error %q", r.stderr)
	}
	if got := chLines(r.stderr); !slices.Equal(got, chWantLines(rep)) {
		t.Errorf("standard error:\n got %q\nwant %q", got, chWantLines(rep))
	}
	js := chJSON(t, b.dir)
	if js.code != ExitRefused || js.stderr != r.stderr {
		t.Errorf("JSON: exit %d, standard error %q", js.code, js.stderr)
	}
	// The same set that names the end of the chain follows every ceremony: the order is sure, and
	// the finding says nothing of doubt.
	c := newHB(t, 0)
	c.add(t, true, hbRoots(hbRoot("A", 1)))
	c.add(t, true, hbRoots(hbRoot("B", 2)))
	c.add(t, true, hbRoots(hbRoot("B", 2)))
	hbWrite(t, c.dir, "trust/4-ffffffff/root-list.json", `{"last_record_sha256":"`+c.end()+`","roots":[`+hbRoot("A", 1)+`],"sequence":4,"version":1}`)
	r = chHist(t, c.dir)
	if r.code != ExitRefused || !strings.Contains(r.stderr, "root-returns trust/4-ffffffff/root-list.json: root key \"A\" returns") || strings.Contains(r.stderr, "not sure") {
		t.Errorf("exit %d, standard error %q", r.code, r.stderr)
	}
}
