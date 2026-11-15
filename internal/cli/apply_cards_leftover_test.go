//go:build linux || darwin

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/wanted"
)

// A name that starts with ".rt-" in want/cards is the leftover of a stopped write: "apply --plan-only"
// does not read it, does not count it toward the limit of card files and gives no refusal for it, and it
// writes what it writes without it (record 0006, rule 45). A name from the folder is shown in a refusal
// with the exact escape (record 0006, rule 46). The names of this file start with al.

// alLeftovers are leftover files of the card folder: bad content, a copy of a good card, no bytes.
func alLeftovers() map[string]string {
	return map[string]string{
		"want/cards/.rt-a.yaml":      acBad,
		"want/cards/.RT-b.yaml":      acRootB,
		"want/cards/.Rt-c.yaml":      "",
		"want/cards/.rt-d.yaml":      "\xff\xfe\x00 not: [yaml",
		"want/cards/.rt-root-a.yaml": acRootA,
	}
}

func TestApplyPlanOnlyDoesNotReadOrCountALeftoverInTheCardFolder(t *testing.T) {
	cleanDir, leftDir := acBundle(t, acCards()), acBundle(t, acCards(), alLeftovers())
	leftBefore, leftModes, cleanModes := apSnapshot(t, leftDir), entriesOf(t, leftDir), entriesOf(t, cleanDir)
	clean := apPlanOnly(t, apClock, cleanDir, "--key-dir", apKeys(t), "--output", "json")
	left := apPlanOnly(t, apClock, leftDir, "--key-dir", apKeys(t), "--output", "json")
	if clean.code != ExitOK || left.code != ExitOK {
		t.Fatalf("exit codes %d and %d; stderr %q", clean.code, left.code, left.stderr)
	}
	if acMasked(clean.stdout) != acMasked(left.stdout) || acMasked(clean.stderr) != acMasked(left.stderr) {
		t.Errorf("the output differs:\n%q %q\n%q %q", clean.stdout, clean.stderr, left.stdout, left.stderr)
	}
	// What the run added is what it adds without a leftover.
	if got, want := acAdded(leftModes, entriesOf(t, leftDir)), acAdded(cleanModes, entriesOf(t, cleanDir)); !slices.Equal(got, want) {
		t.Errorf("the command added\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, line := range apSnapshot(t, leftDir) {
		if strings.HasPrefix(line, "history/") && strings.Contains(strings.ToLower(line), ".rt-") {
			t.Errorf("the run wrote a leftover: %s", line)
		}
	}
	for _, f := range []string{left.stdout, left.stderr} {
		if strings.Contains(strings.ToLower(f), ".rt-") {
			t.Errorf("the output names a leftover: %q", f)
		}
	}
	pa, err := os.ReadFile(filepath.Join(cleanDir, "history", apName, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := os.ReadFile(filepath.Join(leftDir, "history", apName, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if acMasked(string(pa)) != acMasked(string(pb)) {
		t.Errorf("the plans differ:\n%s\n%s", pa, pb)
	}
	// The leftovers are untouched, with the rest of the folder: every line of the first snapshot is still there.
	after := apSnapshot(t, leftDir)
	for _, line := range leftBefore {
		if !slices.Contains(after, line) {
			t.Errorf("the run changed or removed: %s", line)
		}
	}
}

func TestApplyPlanOnlyDoesNotCountLeftoversTowardTheLimitOfCardFiles(t *testing.T) {
	files := map[string]string{}
	for i := range wanted.MaxCards {
		files[fmt.Sprintf("want/cards/c%04d.yaml", i)] = fmt.Sprintf("version: 1\nserial: \"%d\"\nkind: server\napplications: [piv]\n", i+1)
	}
	for i := range 3 * wanted.MaxCards {
		files[fmt.Sprintf("want/cards/.rt-%04d.yaml", i)] = acBad
	}
	r := apPlanOnly(t, apClock, acBundle(t, files), "--key-dir", apKeys(t))
	if r.code != ExitOK {
		t.Errorf("%d card files and leftovers: exit code %d, stderr %q", wanted.MaxCards, r.code, r.stderr)
	}
	// One card file more is the refusal that names the limit, whatever the leftovers.
	files["want/cards/c9999.yaml"] = "version: 1\nserial: \"9999\"\nkind: server\napplications: [piv]\n"
	dir := acBundle(t, files)
	before := apSnapshot(t, dir)
	r = apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
	if r.code != ExitFailure || !strings.Contains(r.stderr, "want/cards") || !strings.Contains(r.stderr, "64") {
		t.Errorf("exit code %d, stderr %q", r.code, r.stderr)
	}
	crqSame(t, "apply", before, apSnapshot(t, dir))
}

// A leftover of any kind of entry is skipped: a folder, a link, a FIFO.
func TestApplyPlanOnlySkipsALeftoverThatIsAFolderALinkOrAFifo(t *testing.T) {
	dir := acBundle(t, acCards(), map[string]string{"want/cards/.rt-folder/inner.yaml": acRootB})
	cards := filepath.Join(dir, "want", "cards")
	if err := os.Symlink("root-a.yaml", filepath.Join(cards, ".rt-link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(cards, ".RT-out")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(cards, ".rt-fifo.yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
	if r.code != ExitOK {
		t.Errorf("exit code %d, stderr %q", r.code, r.stderr)
	}
}

// A leftover beside a card file that fails does not hide the refusal, and the refusal does not name it.
func TestApplyPlanOnlyStillRefusesACardFileBesideALeftover(t *testing.T) {
	dir := acBundle(t, acCards(), alLeftovers(), map[string]string{"want/cards/zz-bad.yaml": acBad})
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
	if r.code != ExitFailure || !strings.Contains(r.stderr, "want/cards/zz-bad.yaml") || strings.Contains(strings.ToLower(r.stderr), ".rt-") || strings.Contains(r.stderr, "and 1 more") {
		t.Errorf("exit code %d, stderr %q", r.code, r.stderr)
	}
	crqSame(t, "apply", before, apSnapshot(t, dir))
}

// A name from the folder is shown with the exact escape, so two different names never give one refusal.
func TestApplyPlanOnlyShowsAHostileCardFileNameWithTheExactEscape(t *testing.T) {
	names := []struct{ name, shown string }{
		{"a b.yaml", `a\x20b.yaml`},
		{`a\b.yaml`, `a\\b.yaml`},
		{`a\x20b.yaml`, `a\\x20b.yaml`},
		{"a\xffb.yaml", `a\xffb.yaml`},
		{"a\xfeb.yaml", `a\xfeb.yaml`},
		{"a\xef\xbf\xbdb.yaml", `a\` + "u" + `fffdb.yaml`},
	}
	seen := map[string]string{}
	for _, n := range names {
		t.Run(n.shown, func(t *testing.T) {
			dir := acBundle(t, acCards(), map[string]string{"want/cards/" + n.name: acRootB})
			before := apSnapshot(t, dir)
			r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
			if r.code != ExitFailure || !strings.Contains(r.stderr, "want/cards/"+n.shown+":") || !acPrintableLines(r.stderr) {
				t.Fatalf("exit code %d, stderr %q", r.code, r.stderr)
			}
			if other, ok := seen[r.stderr]; ok {
				t.Errorf("the names %+q and %+q give the same refusal %q", other, n.name, r.stderr)
			}
			seen[r.stderr] = n.name
			crqSame(t, "apply", before, apSnapshot(t, dir))
			j := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t), "--output", "json")
			msg, _ := apObject(t, j.stdout)["error"].(string)
			if j.code != ExitFailure || !strings.Contains(msg, "want/cards/"+n.shown+":") {
				t.Errorf("JSON: %d %q", j.code, msg)
			}
		})
	}
}
