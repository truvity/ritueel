//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/wanted"
)

// "new --template personal DIR" and what apply says about the bundle it made: the placeholder fingerprint is
// refused by name, and a bundle whose wanted files pass is refused as not built, with nothing written.

const (
	personalFingerprint = "0123456789abcdef0123456789abcdef01234567"
	personalRefusal     = "a personal bundle (kind: personal in ritueel.yaml) passed the check of its wanted files; adoption and subkeys are built by later parts, so apply makes no plan and makes no key; nothing was written"
)

func TestNewMakesTheStarterBundleOfAPerson(t *testing.T) {
	folderMode, fileMode := umaskModes(t)
	dir := filepath.Join(t.TempDir(), "ada")
	r := apRun(t, apClock, "new", "--template", "personal", dir)
	if r.code != ExitOK || r.stderr != "" || !strings.HasPrefix(r.stdout, "made the bundle ") ||
		!strings.Contains(r.stdout, "write the fingerprint of your key and the day it expires in want/roots/openpgp.yaml") ||
		strings.Contains(r.stdout, "TEST ONLY") {
		t.Fatalf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	got := entriesOf(t, dir)
	for _, d := range []string{"want/", "want/roots/"} {
		if m, ok := got[d]; !ok || !m.IsDir() || m.Perm() != folderMode {
			t.Errorf("%s: %v (present %v)", d, m, ok)
		}
	}
	files := []string{"want/roots/openpgp.yaml", "want/openpgp.yaml", wanted.SettingsPath}
	if len(got) != 2+len(files) {
		t.Errorf("the folder holds %d entries: %v", len(got), got)
	}
	for _, p := range files {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
		if err != nil || got[p].Perm() != fileMode || !strings.Contains(r.stdout, sha256Of(string(data))+"  "+p) {
			t.Errorf("%s: %v %v", p, err, got[p])
		}
	}
	root, _ := os.ReadFile(filepath.Join(dir, "want", "roots", "openpgp.yaml"))
	if !strings.Contains(string(root), `valid_until: "2028-11-20"`) || !strings.Contains(string(root), wanted.PlaceholderFingerprint) {
		t.Errorf("the root file, made with the clock of 2026-11-20:\n%s", root)
	}
}

func TestTheTemplatesThatAreNotBuiltAreAUsageErrorAndNothingIsWritten(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "ada")
	for name, args := range map[string][]string{
		"two-cards":              {"new", "--template", "two-cards", dir},
		"cloud":                  {"new", "--template", "cloud", dir},
		"file":                   {"new", "--template", "file", dir},
		"a name that is unknown": {"new", "--template", "company", dir},
		"an empty name":          {"new", "--template", "", dir},
		"personal in upper case": {"new", "--template", "Personal", dir},
		"the test-root flag":     {"new", "--template", "personal", "--test-root", dir},
	} {
		t.Run(name, func(t *testing.T) {
			before := crqSnapshot(t, root)
			r := apRun(t, apClock, args...)
			if r.code != ExitUsage || r.stdout != "" || !strings.HasPrefix(r.stderr, "ritueel: ") {
				t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
			}
			crqSame(t, "new", before, crqSnapshot(t, root))
		})
	}
}

// personalBundle makes a bundle with new and writes a fingerprint in the place of the placeholder.
func personalBundle(t *testing.T, fingerprint string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ada")
	if r := apRun(t, apClock, "new", "--template", "personal", dir); r.code != ExitOK {
		t.Fatalf("new: %q", r.stderr)
	}
	path := filepath.Join(dir, "want", "roots", "openpgp.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), wanted.PlaceholderFingerprint, fingerprint, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestApplyRefusesAPersonalBundleAsNotBuiltAndWritesNothing(t *testing.T) {
	for _, args := range [][]string{{"--plan-only"}, {"--plan-only", "--output", "json"}, {"--key-dir", "KEYS"}} {
		dir := personalBundle(t, personalFingerprint)
		before := apSnapshot(t, dir)
		keys := apKeys(t)
		for i := range args {
			if args[i] == "KEYS" {
				args[i] = keys
			}
		}
		r := apRun(t, apClock, append([]string{"--dir", dir, "apply"}, args...)...)
		json := slices.Contains(args, "json")
		if r.code != ExitFailure || (r.stdout != "") != json || !strings.Contains(r.stderr+r.stdout, personalRefusal) || (!json && !strings.HasPrefix(r.stderr, "ritueel: this version does not build that yet: ")) {
			t.Errorf("%v: (%d, %q, %q)", args, int(r.code), r.stdout, r.stderr)
		}
		crqSame(t, "apply", before, apSnapshot(t, dir))
	}
}

func TestApplyRefusesTheStarterWhileThePlaceholderStands(t *testing.T) {
	dir := personalBundle(t, wanted.PlaceholderFingerprint)
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, dir)
	if r.code != ExitFailure || r.stdout != "" || !strings.Contains(r.stderr, "want/roots/openpgp.yaml:") ||
		!strings.Contains(r.stderr, "replace the placeholder with the fingerprint of your key") || !strings.Contains(r.stderr, "nothing was written") {
		t.Errorf("(%d, %q, %q)", int(r.code), r.stdout, r.stderr)
	}
	crqSame(t, "apply", before, apSnapshot(t, dir))
}

func TestApplyJudgesTheKeyOfAPersonAgainstTheClockOfTheCommand(t *testing.T) {
	dir := personalBundle(t, personalFingerprint) // the key expires on 2028-11-20
	for name, tc := range map[string]struct {
		now   time.Time
		words string
	}{
		"the day the key expires": {time.Date(2028, 11, 20, 0, 0, 0, 0, time.UTC), "not after now"},
		"after it":                {time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC), "not after now"},
		"the day before":          {time.Date(2028, 11, 19, 23, 59, 0, 0, time.UTC), personalRefusal},
	} {
		t.Run(name, func(t *testing.T) {
			r := apPlanOnly(t, tc.now, dir)
			if r.code != ExitFailure || !strings.Contains(r.stderr, tc.words) {
				t.Errorf("(%d, %q)", int(r.code), r.stderr)
			}
		})
	}
}
