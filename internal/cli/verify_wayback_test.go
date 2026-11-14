package cli

import (
	"strconv"
	"strings"
	"testing"
)

// The member wayback (docs/reference/cli.md, "Machine-readable output", and record 0006, rule 53):
// true only when the list was accepted although check 6 or check 7 would have refused it, because its
// sequence is lower than the held list's or equal to it with other content; absent otherwise. The text
// output has the line "wayback: the held list had sequence N; this list replaces it at sequence M"
// directly after the line accepted.

func hasWaybackLine(stdout string) bool {
	for _, l := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(l, "wayback:") {
			return true
		}
	}
	return false
}

func TestTheMemberWaybackIsThereForAWayBackAndNowhereElse(t *testing.T) {
	m := vloadManifest(t)
	sawWayback, sawNew, sawAgain, sawPins := false, false, false, false
	for _, c := range m.Cases {
		if c.Expect != "accept" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			s := vstage(t, m, c)
			js := vrunAt(t, s.clock, s.args("json")...)
			txt := vrunAt(t, s.clock, s.args("text")...)
			obj := jsonObject(t, js)
			v, has := obj["wayback"]
			if has != c.Wayback || (has && v != true) {
				t.Errorf("the member wayback is %v (value %v); the case is a way back: %v", has, v, c.Wayback)
			}
			if hasWaybackLine(txt.stdout) != c.Wayback {
				t.Errorf("the line wayback is there: %v; want %v\n%s", hasWaybackLine(txt.stdout), c.Wayback, txt.stdout)
			}
			_, hasAgain := obj["again"]
			if hasAgain && has {
				t.Errorf("both again and wayback: %q", js.stdout)
			}
			lines := strings.Split(txt.stdout, "\n")
			if c.Wayback {
				sawWayback = true
				want := wantTextWayback(vheldSequence(s), s.candList.Sequence)
				if len(lines) < 4 || !strings.HasPrefix(lines[0], "accepted: ") || lines[1] != want {
					t.Errorf("the line is not %q directly after accepted: %q", want, lines)
				}
				if strings.Count(txt.stdout, "\n") != 2+len(vfiles(s)) {
					t.Errorf("the text output has other lines than accepted, wayback and the sums: %q", txt.stdout)
				}
				if js.stdout != doneObjectFlags(vheldWarnings(t, m, c, s.clock), false, true, vfiles(s)...) {
					t.Errorf("json: %q", js.stdout)
				}
			} else {
				if strings.Contains(js.stdout, "wayback") || strings.Contains(txt.stdout, "wayback") {
					t.Errorf("wayback in the output of a list that is no way back: %q %q", js.stdout, txt.stdout)
				}
				if vagain(s) {
					sawAgain = true
				} else {
					sawNew = true
				}
			}
			if s.held == "" {
				sawPins = true
				if has || hasWaybackLine(txt.stdout) {
					t.Errorf("wayback with initial pins")
				}
			}
		})
	}
	if !sawWayback || !sawNew || !sawAgain || !sawPins {
		t.Errorf("the manifest has an accepted way back: %v, a new list: %v, the held list again: %v, a list against pins: %v", sawWayback, sawNew, sawAgain, sawPins)
	}
}

// The three output cases of the vector set: the way back says so in text and in JSON, a list that
// names a removed key at a higher sequence does not, and the held list again after a revoke is
// again and not a way back.

func TestOutputWaybackTextAndJSON(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.caseByID(t, "way-back-from-the-highest-sequence"))
	js := vrunAt(t, s.clock, s.args("json")...)
	if js.code != ExitOK || js.stdout != doneObjectFlags(nil, false, true, vfiles(s)...) || js.stderr != "" {
		t.Fatalf("json: %d\nstdout %q\nstderr %q", js.code, js.stdout, js.stderr)
	}
	obj := jsonObject(t, js)
	if obj["wayback"] != true {
		t.Errorf("the member wayback is %v, want true", obj["wayback"])
	}
	if _, has := obj["again"]; has {
		t.Errorf("the member again is there")
	}
	txt := vrunAt(t, s.clock, s.args("text")...)
	// The held list has the highest sequence the page allows, and the list has sequence 8.
	wantLine := "wayback: the held list had sequence 9007199254740991; this list replaces it at sequence 8"
	lines := strings.Split(txt.stdout, "\n")
	if txt.code != ExitOK || len(lines) < 2 || !strings.HasPrefix(lines[0], "accepted: sequence 8, ") || lines[1] != wantLine {
		t.Fatalf("text: %d %q, want the second line %q", txt.code, txt.stdout, wantLine)
	}
	if txt.stdout != vacceptedTextFlags(s, false, true) || strings.Contains(txt.stdout, "again") {
		t.Errorf("the text output is %q", txt.stdout)
	}
}

func TestOutputNoWaybackAtAHigherSequence(t *testing.T) {
	m := vloadManifest(t)
	// The same takeover, with one stolen key and one stored authorisation, at the next sequence: the
	// list names a removed key and is accepted as always, without the member.
	s := vstage(t, m, m.caseByID(t, "the-same-takeover-at-the-next-sequence"))
	js := vrunAt(t, s.clock, s.args("json")...)
	if js.code != ExitOK || js.stdout != doneObject(nil, vfiles(s)...) || strings.Contains(js.stdout, "wayback") {
		t.Fatalf("json: %d %q", js.code, js.stdout)
	}
	if _, has := jsonObject(t, js)["wayback"]; has {
		t.Errorf("the member wayback is there")
	}
	txt := vrunAt(t, s.clock, s.args("text")...)
	if txt.code != ExitOK || txt.stdout != vacceptedText(s, false) || hasWaybackLine(txt.stdout) {
		t.Fatalf("text: %d %q", txt.code, txt.stdout)
	}
	// A revoke of main at a higher sequence is the same.
	r := vstage(t, m, m.caseByID(t, "revoke-a-root"))
	if o := vrunAt(t, r.clock, r.args("json")...); strings.Contains(o.stdout, "wayback") {
		t.Errorf("a revoke at a higher sequence says wayback: %q", o.stdout)
	}
}

func TestOutputAgainAfterAWayBack(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.caseByID(t, "same-list-again-after-a-revoke"))
	js := vrunAt(t, s.clock, s.args("json")...)
	if js.code != ExitOK || js.stdout != doneObjectFlags(nil, true, false, vfiles(s)...) {
		t.Fatalf("json: %d %q", js.code, js.stdout)
	}
	obj := jsonObject(t, js)
	if obj["again"] != true {
		t.Errorf("the member again is %v", obj["again"])
	}
	if _, has := obj["wayback"]; has {
		t.Errorf("the member wayback is there")
	}
	txt := vrunAt(t, s.clock, s.args("text")...)
	if txt.code != ExitOK || txt.stdout != vacceptedTextFlags(s, true, false) || hasWaybackLine(txt.stdout) {
		t.Fatalf("text: %d %q", txt.code, txt.stdout)
	}
}

func (m *vmanifest) caseByID(t testing.TB, id string) vcase {
	t.Helper()
	for _, c := range m.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no case %q in the manifest", id)
	return vcase{}
}

// TestTheWayBackThroughTheCommandForEachSentenceOfTheRule runs the cases that belong to a sentence of
// rule 53 through the command, in both output modes, and holds the output to the page: the member and
// the line for a list taken by the way back, neither for a list refused for any reason, and the
// reason the rule gives.
func TestTheWayBackThroughTheCommandForEachSentenceOfTheRule(t *testing.T) {
	m := vloadManifest(t)
	for _, c := range []struct {
		id string
		// way is the line the text output gives: "" for none; held and list are the sequences in it.
		way        bool
		held, list int64
		reason     string // the reason of a refusal; "" for an acceptance
		warning    bool
	}{
		{id: "way-back-at-the-sequence-of-the-thief", way: true, held: 8, list: 8},
		{id: "way-back-from-the-highest-sequence", way: true, held: 9007199254740991, list: 8},
		{id: "two-removed-both-named", way: true, held: 9007199254740991, list: 8},
		{id: "two-removed-one-named", reason: "rollback"},
		{id: "extra-entry-for-a-key-not-held", reason: "removal-invalid"},
		{id: "way-back-with-another-keys-authorisation", reason: "removal-invalid"},
		{id: "entry-for-a-key-that-stays", reason: "removal-invalid"},
		{id: "no-entry-is-not-the-way-back", reason: "rollback"},
		{id: "the-same-takeover-at-the-next-sequence"},
		{id: "revoke-a-root"},
		{id: "same-list-again-after-a-revoke"},
		{id: "pins-keep-their-lowest-sequence-for-a-named-removal", reason: "rollback"},
		{id: "way-back-that-also-adds-a-key", way: true, held: 9007199254740991, list: 8},
		{id: "way-back-removing-every-held-key", way: true, held: 9007199254740991, list: 8},
		{id: "way-back-over-an-expired-held-list", way: true, held: 9007199254740991, list: 8, warning: true},
		{id: "way-back-with-a-new-label", way: true, held: 9007199254740991, list: 8},
		{id: "way-back-entry-with-another-label", way: true, held: 9007199254740991, list: 8},
		{id: "way-back-with-a-new-fingerprint", way: true, held: 9007199254740991, list: 8},
		{id: "retire-with-the-authorisation", way: true, held: 9007199254740991, list: 8},
		{id: "revoke-signed-by-the-key-with-its-entry", way: true, held: 9007199254740991, list: 8},
		{id: "pin-twice-in-removals", reason: "malformed"},
		{id: "way-back-with-a-signature-missing", reason: "insufficient-signers"},
		{id: "way-back-after-its-expiry", reason: "expired", warning: true},
	} {
		t.Run(c.id, func(t *testing.T) {
			mc := m.caseByID(t, c.id)
			if mc.Wayback != c.way {
				t.Fatalf("the manifest says wayback %v, the test expects %v", mc.Wayback, c.way)
			}
			s := vstage(t, m, mc)
			warn := vheldWarnings(t, m, mc, s.clock)
			if (len(warn) == 1) != c.warning {
				t.Fatalf("the warning of the case is %v, the test expects %v", warn, c.warning)
			}
			js := vrunAt(t, s.clock, s.args("json")...)
			txt := vrunAt(t, s.clock, s.args("text")...)
			if c.reason != "" {
				if js.code != ExitRefused || js.stdout != refusedObject(c.reason, warn...) || txt.code != ExitRefused || txt.stdout != "" {
					t.Fatalf("json %d %q; text %d %q", js.code, js.stdout, txt.code, txt.stdout)
				}
				if strings.Contains(js.stdout+js.stderr+txt.stdout+txt.stderr, "wayback") {
					t.Errorf("a refusal says wayback: %q %q", js.stderr, txt.stderr)
				}
				return
			}
			again := vagain(s)
			if js.code != ExitOK || js.stdout != doneObjectFlags(warn, again, c.way, vfiles(s)...) || js.stderr != warnLines(warn...) {
				t.Fatalf("json: %d\nstdout %q\nstderr %q", js.code, js.stdout, js.stderr)
			}
			if txt.code != ExitOK || txt.stdout != vacceptedTextFlags(s, again, c.way) || txt.stderr != warnLines(warn...) {
				t.Fatalf("text: %d\nstdout %q\nstderr %q", txt.code, txt.stdout, txt.stderr)
			}
			if c.way {
				// The page's line, written out here: the held sequence first, then the list's.
				wantLine := "wayback: the held list had sequence " + strconv.FormatInt(c.held, 10) + "; this list replaces it at sequence " + strconv.FormatInt(c.list, 10)
				if lines := strings.Split(txt.stdout, "\n"); lines[1] != wantLine {
					t.Errorf("the second line is %q, want %q", lines[1], wantLine)
				}
			}
		})
	}
}

// TestAHostWithOnlyPinsNeverSaysWayback: a host that holds no list does not use the way back, with or
// without a lowest sequence. The same list that a held list takes by the way back is refused as a
// rollback when it is below the lowest sequence of pins, and accepted as a plain list when it is not.
func TestAHostWithOnlyPinsNeverSaysWayback(t *testing.T) {
	m := vloadManifest(t)
	const list = "seq8-b-without-a" // a list that removes A and names it, at sequence 8
	id := list
	stage := func(t *testing.T, min *int64) *vscene {
		return vstage(t, m, vcase{ID: "pins-" + list, Candidate: &id, Clock: "2026-12-01T12:00:00Z", Expect: "accept", MinSequence: min})
	}
	seq := func(n int64) *int64 { return &n }
	t.Run("without a lowest sequence", func(t *testing.T) {
		s := stage(t, nil)
		js := vrunAt(t, s.clock, s.args("json")...)
		txt := vrunAt(t, s.clock, s.args("text")...)
		if js.code != ExitOK || js.stdout != doneObject(nil, vfiles(s)...) || txt.code != ExitOK || txt.stdout != vacceptedText(s, false) {
			t.Fatalf("json %d %q; text %d %q", js.code, js.stdout, txt.code, txt.stdout)
		}
	})
	t.Run("at the lowest sequence", func(t *testing.T) {
		s := stage(t, seq(8))
		js := vrunAt(t, s.clock, s.args("json")...)
		txt := vrunAt(t, s.clock, s.args("text")...)
		if js.code != ExitOK || js.stdout != doneObject(nil, vfiles(s)...) || txt.code != ExitOK || txt.stdout != vacceptedText(s, false) {
			t.Fatalf("json %d %q; text %d %q", js.code, js.stdout, txt.code, txt.stdout)
		}
	})
	t.Run("below the lowest sequence", func(t *testing.T) {
		s := stage(t, seq(9))
		js := vrunAt(t, s.clock, s.args("json")...)
		txt := vrunAt(t, s.clock, s.args("text")...)
		if js.code != ExitRefused || js.stdout != refusedObject("rollback") || txt.code != ExitRefused || txt.stdout != "" {
			t.Fatalf("json %d %q; text %d %q", js.code, js.stdout, txt.code, txt.stdout)
		}
		if !strings.HasPrefix(js.stderr, "ritueel: refused: rollback (check 6: ") || strings.Contains(js.stderr, "wayback") {
			t.Errorf("the refusal line is %q", js.stderr)
		}
	})
}

// TestAWayBackWithTheCABundleOfTheList: the bundle is checked against the list that was accepted, and
// it is the third file after the two of the list; the line of the way back stays directly after
// accepted.
func TestAWayBackWithTheCABundleOfTheList(t *testing.T) {
	m := vloadManifest(t)
	bundleCase := m.caseByID(t, "ca-bundle-after-a-revoke") // a bundle that goes with seq8-b-without-a
	if bundleCase.Bundle == "" || bundleCase.Candidate == nil {
		t.Fatalf("the case %s has no bundle", bundleCase.ID)
	}
	way := m.caseByID(t, "way-back-from-the-highest-sequence")
	if *way.Candidate != *bundleCase.Candidate {
		t.Fatalf("the two cases do not share a candidate: %s, %s", *way.Candidate, *bundleCase.Candidate)
	}
	way.Bundle = bundleCase.Bundle
	s := vstage(t, m, way)
	js := vrunAt(t, s.clock, s.args("json")...)
	if js.code != ExitOK || js.stdout != doneObjectFlags(nil, false, true, vfiles(s)...) || len(vfiles(s)) != 3 {
		t.Fatalf("json: %d %q", js.code, js.stdout)
	}
	txt := vrunAt(t, s.clock, s.args("text")...)
	if txt.code != ExitOK || txt.stdout != vacceptedTextFlags(s, false, true) || strings.Count(txt.stdout, "\n") != 5 {
		t.Fatalf("text: %d %q", txt.code, txt.stdout)
	}
}

func TestTheMemberWaybackIsNotInARefusalAFailureOrAUsageError(t *testing.T) {
	m := vloadManifest(t)
	for _, c := range m.Cases {
		if c.Expect != "refuse" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			s := vstage(t, m, c)
			for _, mode := range []string{"json", "text"} {
				r := vrunAt(t, s.clock, s.args(mode)...)
				if r.code != ExitRefused || strings.Contains(r.stdout, "wayback") || strings.Contains(r.stderr, "wayback") {
					t.Fatalf("%s: exit %d stdout %q stderr %q", mode, r.code, r.stdout, r.stderr)
				}
			}
		})
	}
	s := vstage(t, m, m.wayBackCase(t))
	for name, r := range map[string]result{
		"a failure (the .jws is missing)": vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.dir+"/nosuch.json", "--held", s.held),
		"a usage error":                   vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand),
	} {
		if strings.Contains(r.stdout, "wayback") || strings.Contains(r.stderr, "wayback") {
			t.Errorf("%s: stdout %q stderr %q", name, r.stdout, r.stderr)
		}
	}
}

// TestTheTextLineOfTheWayBackIsAfterTheLineAcceptedAndBeforeTheSums: the order of the lines, and the
// line of a list that is no way back is not written.
func TestTheTextLineOfTheWayBackIsAfterTheLineAcceptedAndBeforeTheSums(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.wayBackCase(t))
	txt := vrunAt(t, s.clock, s.args("text")...)
	lines := strings.Split(strings.TrimSuffix(txt.stdout, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("%d lines, want 4: %q", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "accepted: ") || !strings.HasPrefix(lines[1], "wayback: ") || strings.HasPrefix(lines[2], "wayback") || strings.HasPrefix(lines[3], "wayback") {
		t.Errorf("the order of the lines is %q", lines)
	}
}
