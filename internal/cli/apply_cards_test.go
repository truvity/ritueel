//go:build linux || darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// "apply --plan-only" stops at a card file that fails its check, before anything is written (record 0005,
// rule 19), and gives what it always gave for a good set of card files: the card files are not wanted
// files that a plan uses. The names of this file start with ac.

const (
	acRootA = `version: 1
serial: "10000001"
kind: root
applications: [piv, fido2]
other_rows: [3]
`
	acRootB = `version: 1
serial: "10000002"
kind: root
applications: [piv, fido2]
`
	acDayOne = `version: 1
serial: "10000003"
kind: day-to-day
applications: [openpgp, fido2]
`
	acBad = "version: 2\nserial: \"10000009\"\nkind: server\napplications: [piv]\n"
)

func acCards() map[string]string {
	return map[string]string{
		"want/cards/root-a.yaml":  acRootA,
		"want/cards/root-b.yaml":  acRootB,
		"want/cards/day-one.yaml": acDayOne,
	}
}

func acBundle(t testing.TB, more ...map[string]string) string {
	t.Helper()
	files := apFiles()
	for _, m := range more {
		for k, v := range m {
			files[k] = v
		}
	}
	return apBundle(t, files)
}

// acAdded is the entries that a run added to the folder.
func acAdded(before, after map[string]os.FileMode) []string {
	var added []string
	for name := range after {
		if _, ok := before[name]; !ok {
			added = append(added, name)
		}
	}
	slices.Sort(added)
	return added
}

// The plan holds the serial numbers of certificates that are made at random, so two plans of one bundle are
// not equal byte for byte. acMasked writes a text with every digest and every serial as a mark.
var acRandom = regexp.MustCompile(`[0-9a-f]{64}|"serial":"[0-9a-f]+"|"prefix":"[0-9a-f]{8}"`)

func acMasked(s string) string { return acRandom.ReplaceAllString(s, "#") }

// acPrintableLines reports whether every line of s is printable ASCII.
func acPrintableLines(s string) bool {
	for _, l := range strings.Split(s, "\n") {
		if !apPrintable(l) {
			return false
		}
	}
	return true
}

func TestApplyPlanOnlyOfAGoodSetOfCardFilesWritesWhatItWroteBeforeAndNoCardFile(t *testing.T) {
	plainDir, cardDir := acBundle(t), acBundle(t, acCards())
	plainBefore, cardBefore := entriesOf(t, plainDir), entriesOf(t, cardDir)
	plain := apPlanOnly(t, apClock, plainDir, "--key-dir", apKeys(t), "--output", "json")
	cards := apPlanOnly(t, apClock, cardDir, "--key-dir", apKeys(t), "--output", "json")
	if plain.code != ExitOK || cards.code != ExitOK {
		t.Fatalf("exit codes %d and %d; stderr %q", plain.code, cards.code, cards.stderr)
	}
	if got, want := acAdded(cardBefore, entriesOf(t, cardDir)), acAdded(plainBefore, entriesOf(t, plainDir)); !slices.Equal(got, want) {
		t.Errorf("the command added\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, a := range acAdded(cardBefore, entriesOf(t, cardDir)) {
		if strings.Contains(a, "cards") {
			t.Errorf("the plan folder holds a card file: %s", a)
		}
	}
	if acMasked(plain.stdout) != acMasked(cards.stdout) || acMasked(plain.stderr) != acMasked(cards.stderr) {
		t.Errorf("the output differs:\n%q %q\n%q %q", plain.stdout, plain.stderr, cards.stdout, cards.stderr)
	}
	pa, err := os.ReadFile(filepath.Join(plainDir, "history", apName, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := os.ReadFile(filepath.Join(cardDir, "history", apName, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if acMasked(string(pa)) != acMasked(string(pb)) || strings.Contains(string(pb), "cards") {
		t.Errorf("the plan differs or names a card file:\n%s\n%s", pa, pb)
	}
	// The card files are untouched.
	for p, text := range acCards() {
		got, err := os.ReadFile(filepath.Join(cardDir, filepath.FromSlash(p)))
		if err != nil || string(got) != text {
			t.Errorf("%s changed: %v", p, err)
		}
	}
}

func TestApplyPlanOnlyOfAnEmptyCardFolderIsTheSameAsOfNoCardFolder(t *testing.T) {
	plainDir := acBundle(t)
	emptyDir := acBundle(t)
	if err := os.MkdirAll(filepath.Join(emptyDir, "want", "cards"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := apPlanOnly(t, apClock, plainDir, "--key-dir", apKeys(t))
	b := apPlanOnly(t, apClock, emptyDir, "--key-dir", apKeys(t))
	if a.code != ExitOK || b.code != a.code || acMasked(a.stdout) != acMasked(b.stdout) || acMasked(a.stderr) != acMasked(b.stderr) {
		t.Errorf("results differ: %+v / %+v", a, b)
	}
}

func TestApplyPlanOnlyRefusesACardFileThatFailsWithExitCode1AndWritesNothing(t *testing.T) {
	cases := map[string]struct {
		extra map[string]string
		path  string
	}{
		"a version that is not 1":         {map[string]string{"want/cards/bad.yaml": acBad}, "want/cards/bad.yaml"},
		"an empty file":                   {map[string]string{"want/cards/bad.yaml": ""}, "want/cards/bad.yaml"},
		"a holder key":                    {map[string]string{"want/cards/bad.yaml": acRootB + "holder: Example Person\n"}, "want/cards/bad.yaml"},
		"a card named twice":              {map[string]string{"want/cards/twin.yaml": acRootB}, "want/cards/twin.yaml"},
		"a card named twice with zeros":   {map[string]string{"want/cards/twin.yaml": strings.Replace(acRootB, "10000002", "0010000002", 1)}, "want/cards/twin.yaml"},
		"a name that is not lower case":   {map[string]string{"want/cards/Bad.yaml": acRootB}, "want/cards/Bad.yaml"},
		"a file with another extension":   {map[string]string{"want/cards/bad.yml": acRootB}, "want/cards/bad.yml"},
		"a folder in the card folder":     {map[string]string{"want/cards/sub/a.yaml": acRootA}, "want/cards/sub"},
		"a name with a control character": {map[string]string{"want/cards/a\x01b.yaml": acRootB}, `want/cards/a\u0001b.yaml`},
		"a name with a line break":        {map[string]string{"want/cards/a\nb.yaml": acRootB}, `want/cards/a\u000ab.yaml`},
		"a card text with a bidi control": {map[string]string{"want/cards/bad.yaml": "version: 1\nserial: \"1\"\nkind: \"a\u202eb\"\napplications: [piv]\n"}, "want/cards/bad.yaml"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := acBundle(t, acCards(), c.extra)
			keys := apKeys(t)
			before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
			r := apPlanOnly(t, apClock, dir, "--key-dir", keys)
			if r.code != ExitFailure || r.stdout != "" {
				t.Fatalf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stderr, c.path) || !strings.Contains(r.stderr, "nothing was written") {
				t.Errorf("standard error %q does not name %q and say that nothing was written", r.stderr, c.path)
			}
			if !acPrintableLines(r.stderr) {
				t.Errorf("standard error is not printable ASCII: %+q", r.stderr)
			}
			crqSame(t, "apply", before, apSnapshot(t, dir))
			crqSame(t, "the key directory", keysBefore, apSnapshot(t, keys))
			if _, err := os.Stat(filepath.Join(dir, "history")); err == nil {
				t.Errorf("a history folder was made")
			}
			// JSON mode: the object has an error and no reasons.
			j := apPlanOnly(t, apClock, dir, "--key-dir", keys, "--output", "json")
			obj := apObject(t, j.stdout)
			msg, _ := obj["error"].(string)
			if j.code != ExitFailure || !strings.Contains(msg, c.path) || !strings.Contains(msg, "nothing was written") {
				t.Errorf("JSON: %d %v", j.code, obj)
			}
			if _, has := obj["reasons"]; has {
				t.Errorf("a refusal of a wanted file has reasons: %v", obj["reasons"])
			}
			if obj["plan"] != nil || obj["ceremony"] != nil {
				t.Errorf("JSON names a plan: %v", obj)
			}
		})
	}
}

func TestApplyPlanOnlyRefusesMoreCardFilesThanTheLimitAndNamesTheFolder(t *testing.T) {
	over := map[string]string{}
	for i := range wanted.MaxCards + 1 {
		over[fmt.Sprintf("want/cards/c%04d.yaml", i)] = fmt.Sprintf("version: 1\nserial: \"%d\"\nkind: server\napplications: [piv]\n", i+1)
	}
	dir := acBundle(t, over)
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
	if r.code != ExitFailure || r.stdout != "" || !strings.Contains(r.stderr, "want/cards") || !strings.Contains(r.stderr, "64") {
		t.Errorf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	crqSame(t, "apply", before, apSnapshot(t, dir))
	// The limit itself is accepted.
	delete(over, fmt.Sprintf("want/cards/c%04d.yaml", wanted.MaxCards))
	if r := apPlanOnly(t, apClock, acBundle(t, over), "--key-dir", apKeys(t)); r.code != ExitOK {
		t.Errorf("exactly %d card files: exit code %d, %q", wanted.MaxCards, r.code, r.stderr)
	}
}

func TestApplyPlanOnlyNamesTheFirstOfTwoBadCardFilesAndCountsTheOther(t *testing.T) {
	dir := acBundle(t, acCards(), map[string]string{"want/cards/zz-bad.yaml": acBad, "want/cards/aa-bad.yaml": acBad})
	r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
	if r.code != ExitFailure || !strings.Contains(r.stderr, "want/cards/aa-bad.yaml") || strings.Contains(r.stderr, "zz-bad") || !strings.Contains(r.stderr, "and 1 more") {
		t.Errorf("exit code %d, stderr %q", r.code, r.stderr)
	}
}

// A card file that fails comes before the refusals that follow it, and after the files that are read before it.
func TestApplyPlanOnlyRefusesACardFileBeforeAnOpenAttemptAndAfterABadRootFile(t *testing.T) {
	bad := map[string]string{"want/cards/bad.yaml": acBad}
	r := apPlanOnly(t, apClock, acBundle(t, bad, map[string]string{"want/roots/openpgp.yaml": newOpenPGPTestText}), "--key-dir", apKeys(t))
	if r.code != ExitFailure || !strings.Contains(r.stderr, "want/cards/bad.yaml") || strings.Contains(r.stderr, "openpgp.yaml") {
		t.Errorf("a root that is not built: exit code %d, stderr %q", r.code, r.stderr)
	}
	r = apPlanOnly(t, apClock, acBundle(t, bad, map[string]string{"want/roots/x509.yaml": "kind: nonsense\n"}), "--key-dir", apKeys(t))
	if r.code != ExitFailure || !strings.Contains(r.stderr, "want/roots/x509.yaml") || strings.Contains(r.stderr, "want/cards") {
		t.Errorf("a bad root file: exit code %d, stderr %q", r.code, r.stderr)
	}
	// A bundle with an open attempt (exit code 3 without a bad card file) is exit code 1 with one.
	dir := acBundle(t, acCards())
	keys := apKeys(t)
	if r := apPlanOnly(t, apClock, dir, "--key-dir", keys); r.code != ExitOK {
		t.Fatalf("first plan: %d %q", r.code, r.stderr)
	}
	if err := os.WriteFile(filepath.Join(dir, "want", "cards", "bad.yaml"), []byte(acBad), 0o644); err != nil {
		t.Fatal(err)
	}
	r = apPlanOnly(t, apClock.Add(2e9), dir, "--key-dir", keys)
	if r.code != ExitFailure || !strings.Contains(r.stderr, "want/cards/bad.yaml") {
		t.Errorf("a second plan with a bad card file: exit code %d, stderr %q", r.code, r.stderr)
	}
}

func TestACardFileThatFailsIsNotLookedAtByCheckHistoryCheckRequestAndNew(t *testing.T) {
	// check history: a bundle with a plan folder, with and without a bad card file.
	dir := acBundle(t, acCards())
	if r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t)); r.code != ExitOK {
		t.Fatalf("plan: %d %q", r.code, r.stderr)
	}
	good := apRun(t, apClock, "--dir", dir, "check", "history")
	if err := os.WriteFile(filepath.Join(dir, "want", "cards", "bad.yaml"), []byte(acBad), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "want", "cards", "Bad Name.yaml"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	withBad := apRun(t, apClock, "--dir", dir, "check", "history")
	if good.code != ExitOK || withBad != good {
		t.Errorf("check history differs with a bad card file: %+v / %+v", good, withBad)
	}
	// check request: an accepted request is still accepted.
	rdir, stem := crqBundleOf(t, "x509-software-valid")
	now := crqClock(t)
	plain := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", rdir)
	if plain.code != ExitOK {
		t.Fatalf("check request: %d %q", plain.code, plain.stderr)
	}
	if err := os.MkdirAll(filepath.Join(rdir, "want", "cards"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rdir, "want", "cards", "bad.yaml"), []byte(acBad), 0o644); err != nil {
		t.Fatal(err)
	}
	withBad = crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", rdir)
	if withBad != plain {
		t.Errorf("check request differs with a bad card file:\n%+v\n%+v", plain, withBad)
	}
	// new: it writes no card file and no card folder.
	ca := filepath.Join(t.TempDir(), "ca")
	if r := apRun(t, apClock, "new", "--test-root", ca); r.code != ExitOK {
		t.Fatalf("new: %d %q", r.code, r.stderr)
	}
	if _, err := os.Lstat(filepath.Join(ca, "want", "cards")); err == nil {
		t.Error("new made want/cards")
	}
}
