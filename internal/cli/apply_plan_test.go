//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/history"
)

// "apply --plan-only [--key-dir DIR]" through Run: it finds what is wanted, writes the plan folder
// history/<ceremony>/ (plan.json and exact copies of the wanted files it used) and stops. It makes
// no key and writes no attempt. The words of the plan go to standard error; with --output json
// standard output holds the one object (docs/reference/cli.md, "Machine-readable output"). The
// names of this file start with ap.

var apClock = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

const apName = "20261120T100000Z-apply"

// apFiles is the file set of a first-apply bundle with one X.509 test root: the settings and the
// root file that `new --test-root` writes, without the OpenPGP root file.
func apFiles() map[string]string {
	return map[string]string{"ritueel.yaml": newSettingsTestText, "want/roots/x509.yaml": newX509TestText}
}

// apBundle makes a bundle folder with the files given.
func apBundle(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, text := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// apKeys makes a key directory outside every bundle.
func apKeys(t testing.TB) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// apRun runs the command line with a fixed clock; the clock is read from *now at every call.
func apRun(t testing.TB, now time.Time, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, Env{
		Stdin:  strings.NewReader(""),
		Stdout: &stdout,
		Stderr: &stderr,
		Build:  testBuild,
		Now:    func() time.Time { return now },
	})
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// apPlanOnly runs apply --plan-only on dir.
func apPlanOnly(t testing.TB, now time.Time, dir string, extra ...string) result {
	t.Helper()
	args := append([]string{"--dir", dir, "apply", "--plan-only"}, extra...)
	return apRun(t, now, args...)
}

// apSnapshot is every entry of a folder as "path mode digest", links not followed.
func apSnapshot(t testing.TB, dir string) []string { return crqSnapshot(t, dir) }

func apObject(t testing.TB, stdout string) map[string]any {
	t.Helper()
	tt, ok := t.(*testing.T)
	if !ok {
		t.Fatal("apObject needs a *testing.T")
	}
	return object(tt, stdout)
}

func TestApplyPlanOnlyWritesThePlanFolderAndNothingElse(t *testing.T) {
	dir := apBundle(t, apFiles())
	keys := apKeys(t)
	before := entriesOf(t, dir)
	r := apPlanOnly(t, apClock, dir, "--key-dir", keys, "--output", "json")
	if r.code != ExitOK {
		t.Fatalf("exit code %d; stderr %q", r.code, r.stderr)
	}
	after := entriesOf(t, dir)
	var added []string
	for name := range after {
		if _, ok := before[name]; !ok {
			added = append(added, name)
		}
	}
	slices.Sort(added)
	want := []string{
		"history/",
		"history/" + apName + "/",
		"history/" + apName + "/plan.json",
		"history/" + apName + "/wanted/",
		"history/" + apName + "/wanted/ritueel.yaml",
		"history/" + apName + "/wanted/want/",
		"history/" + apName + "/wanted/want/roots/",
		"history/" + apName + "/wanted/want/roots/x509.yaml",
	}
	if !slices.Equal(added, want) {
		t.Errorf("the command added\n%s\nwant\n%s", strings.Join(added, "\n"), strings.Join(want, "\n"))
	}
	for name, mode := range after {
		if mode.Perm()&0o022 != 0 {
			t.Errorf("%s is writable by others: %v", name, mode)
		}
	}
	// No key, no trust set, no roots folder: the folder of the keys is untouched.
	for _, n := range []string{"roots", "trust", "history/" + apName + "/attempt.json", "history/" + apName + "/record.json"} {
		if _, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(n))); err == nil {
			t.Errorf("%s was written", n)
		}
	}
	if ents, err := os.ReadDir(keys); err != nil || len(ents) != 0 {
		t.Errorf("the key directory holds %d entries: %v", len(ents), err)
	}
}

func TestTheCopiesAreTheWantedFilesAndTheirDigestsAreThoseOfThePlan(t *testing.T) {
	dir := apBundle(t, apFiles())
	r := apPlanOnly(t, apClock, dir)
	if r.code != ExitOK {
		t.Fatalf("exit code %d; stderr %q", r.code, r.stderr)
	}
	planPath := filepath.Join(dir, "history", apName, "plan.json")
	planBytes, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := ceremony.ReadPlanOut(planBytes)
	if err != nil {
		t.Fatalf("the plan on the disk is not read by the reader of the run: %v", err)
	}
	if ok, err := canonjson.IsCanonical(planBytes); err != nil || !ok {
		t.Errorf("the plan is not canonical: %v %v", ok, err)
	}
	for _, c := range []struct{ path, text string }{{"ritueel.yaml", newSettingsTestText}, {"want/roots/x509.yaml", newX509TestText}} {
		copyOf, err := os.ReadFile(filepath.Join(dir, "history", apName, "wanted", filepath.FromSlash(c.path)))
		if err != nil || string(copyOf) != c.text {
			t.Errorf("the copy of %s is %q (%v)", c.path, copyOf, err)
		}
		live, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(c.path)))
		if err != nil || !bytes.Equal(live, copyOf) {
			t.Errorf("the wanted file %s changed", c.path)
		}
		i := slices.IndexFunc(plan.Wanted, func(f files.FileRef) bool { return f.Path == c.path })
		if i < 0 || plan.Wanted[i].SHA256 != sha256Of(c.text) {
			t.Errorf("the plan has no digest of %s that is the digest of the file", c.path)
		}
	}
	// The program in the plan is this program.
	self, err := buildinfo.Self()
	if err != nil {
		t.Fatal(err)
	}
	if plan.Program.SHA256 != self.SHA256 || plan.Program.OSArch != self.OSArch || plan.Program.Version != self.Version {
		t.Errorf("the program of the plan is %+v, this program is %+v", plan.Program, self)
	}
	if !plan.Time.Equal(apClock) || plan.Name != apName {
		t.Errorf("name %s time %v", plan.Name, plan.Time)
	}
}

func TestApplyPlanOnlyJSONHasTheCeremonyAndThePlanAndTheWordsGoToStandardError(t *testing.T) {
	dir := apBundle(t, apFiles())
	keys := apKeys(t)
	r := apPlanOnly(t, apClock, dir, "--key-dir", keys, "--output", "json")
	if r.code != ExitOK {
		t.Fatalf("exit code %d; stderr %q", r.code, r.stderr)
	}
	obj := apObject(t, r.stdout)
	planBytes, err := os.ReadFile(filepath.Join(dir, "history", apName, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Of(string(planBytes))
	wantObject(t, obj, map[string]any{
		"output":    json.Number("1"),
		"command":   "apply",
		"exit_code": json.Number("0"),
		"outcome":   "done",
		"ceremony":  apName,
		"plan": map[string]any{
			"path":   "history/" + apName + "/plan.json",
			"sha256": digest,
			"prefix": digest[:8],
		},
	})
	// The words are on standard error, in order, and the digest is the last line.
	lines := strings.Split(strings.TrimSuffix(r.stderr, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "ceremony "+apName+", made at 2026-11-20T10:00:00Z") {
		t.Errorf("the first line of the words is %q", lines[0])
	}
	if last := lines[len(lines)-1]; last != "plan digest "+digest {
		t.Errorf("the last line of the words is %q", last)
	}
	if !strings.Contains(r.stderr, ceremony.AcceptedLimit) {
		t.Error("the accepted limit is not in the words")
	}
	if strings.Contains(r.stdout, "plan digest") || strings.Contains(r.stdout, "TEST ONLY") {
		t.Errorf("the words are on standard output: %q", r.stdout)
	}
	// The two lines of the text mode are not printed in the JSON mode.
	if strings.Contains(r.stderr, "\nplan history/") || strings.HasPrefix(r.stderr, "plan history/") {
		t.Errorf("the lines of the text mode were printed: %q", r.stderr)
	}
}

func TestApplyPlanOnlyTextPrintsTheWordsOnStandardErrorAndTwoLinesOnStandardOutput(t *testing.T) {
	dir := apBundle(t, apFiles())
	r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
	if r.code != ExitOK {
		t.Fatalf("exit code %d; stderr %q", r.code, r.stderr)
	}
	planBytes, err := os.ReadFile(filepath.Join(dir, "history", apName, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256Of(string(planBytes))
	if want := "plan history/" + apName + "/plan.json\ndigest " + digest + "\n"; r.stdout != want {
		t.Errorf("standard output = %q, want %q", r.stdout, want)
	}
	plan, err := ceremony.ReadPlanOut(planBytes)
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join(plan.Words(), "\n") + "\n"; r.stderr != want {
		t.Errorf("standard error = %q\nwant %q", r.stderr, want)
	}
	for _, l := range strings.Split(strings.TrimSuffix(r.stderr, "\n"), "\n") {
		if !apPrintable(l) {
			t.Errorf("the line %+q is not printable ASCII", l)
		}
	}
}

func apPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func TestApplyPlanOnlyDoesNotNeedAKeyDirectory(t *testing.T) {
	dir := apBundle(t, apFiles())
	r := apPlanOnly(t, apClock, dir)
	if r.code != ExitOK || !strings.Contains(r.stdout, "plan history/"+apName+"/plan.json") {
		t.Errorf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
}

func TestApplyPlanOnlyLeavesAHistoryThatTheCheckAcceptsAndTheCommandFinds(t *testing.T) {
	dir := apBundle(t, apFiles())
	keys := apKeys(t)
	if r := apPlanOnly(t, apClock, dir, "--key-dir", keys); r.code != ExitOK {
		t.Fatalf("first plan: %d %q", r.code, r.stderr)
	}
	check := func(want string) {
		t.Helper()
		fsys, err := fsx.OpenFS(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fsys.Close() }()
		rep, err := history.Check(context.Background(), fsys)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Findings) != 0 || !rep.Clean() || rep.Records != 0 {
			t.Errorf("the check finds %+v after %s", rep.Findings, want)
		}
		r := apRun(t, apClock, "--dir", dir, "check", "history")
		if r.code != ExitOK || r.stdout != "history: 0 ceremony records\n" || r.stderr != "" {
			t.Errorf("check history after %s: %d %q %q", want, r.code, r.stdout, r.stderr)
		}
	}
	check("the first plan")
	later := apClock.Add(time.Second)
	if r := apPlanOnly(t, later, dir, "--key-dir", keys); r.code != ExitOK {
		t.Fatalf("second plan: %d %q", r.code, r.stderr)
	}
	for _, name := range []string{apName, "20261120T100001Z-apply"} {
		if _, err := os.Stat(filepath.Join(dir, "history", name, "plan.json")); err != nil {
			t.Errorf("no plan in %s: %v", name, err)
		}
	}
	check("two plans")
}

func TestTwoPlansInOneSecondTheSecondIsRefusedAndTheFirstIsUntouched(t *testing.T) {
	dir := apBundle(t, apFiles())
	if r := apPlanOnly(t, apClock, dir); r.code != ExitOK {
		t.Fatalf("first plan: %d %q", r.code, r.stderr)
	}
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, dir)
	if r.code != ExitFailure || r.stdout != "" {
		t.Fatalf("second plan in the same second: exit code %d, stdout %q", r.code, r.stdout)
	}
	if !strings.Contains(r.stderr, "history/"+apName) || !strings.Contains(r.stderr, "nothing was written") || !apPrintable(strings.TrimSuffix(r.stderr, "\n")) {
		t.Errorf("standard error = %q", r.stderr)
	}
	crqSame(t, "the second plan", before, apSnapshot(t, dir))
	// And in JSON mode: an error and no ceremony and no plan.
	rj := apPlanOnly(t, apClock, dir, "--output", "json")
	obj := apObject(t, rj.stdout)
	if rj.code != ExitFailure || obj["outcome"] != "failed" || obj["error"] == nil || obj["plan"] != nil || obj["ceremony"] != nil {
		t.Errorf("JSON of the second plan: %d %v", rj.code, obj)
	}
	crqSame(t, "the second plan in JSON mode", before, apSnapshot(t, dir))
}

func TestApplyWithoutPlanOnlyIsNotBuiltAndWritesNothing(t *testing.T) {
	for _, c := range []struct {
		args  []string
		words string
	}{
		{[]string{"apply"}, "without --plan-only"},
		{[]string{"apply", "history/" + apName + "/plan.json"}, "saved plan"},
		{[]string{"apply", "--key-dir", "x"}, "without --plan-only"},
		{[]string{"apply", "somewhere", "--key-dir", "x"}, "saved plan"},
	} {
		args := c.args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			dir := apBundle(t, apFiles())
			before := apSnapshot(t, dir)
			r := apRun(t, apClock, append([]string{"--dir", dir}, args...)...)
			if r.code != ExitFailure || r.stdout != "" {
				t.Fatalf("exit code %d, stdout %q", r.code, r.stdout)
			}
			if n := strings.Count(r.stderr, "\n"); n != 1 || !strings.Contains(r.stderr, "not built yet") || !strings.Contains(r.stderr, c.words) || !strings.Contains(r.stderr, "nothing was written") {
				t.Errorf("standard error is not one plain line that says it is not built yet: %q", r.stderr)
			}
			crqSame(t, "apply", before, apSnapshot(t, dir))
		})
	}
	t.Run("in JSON mode", func(t *testing.T) {
		dir := apBundle(t, apFiles())
		r := apRun(t, apClock, "--dir", dir, "--output", "json", "apply")
		obj := apObject(t, r.stdout)
		if r.code != ExitFailure || obj["outcome"] != "failed" || obj["command"] != "apply" {
			t.Errorf("%d %v", r.code, obj)
		}
		if msg, _ := obj["error"].(string); !strings.Contains(msg, "not built yet") {
			t.Errorf("error = %v", obj["error"])
		}
	})
}

func TestApplyDoesNotLookAtTheBundleBeforeItSaysItIsNotBuilt(t *testing.T) {
	// Not built is a fact about the command and not about the folder: a folder that is not a
	// bundle gets the same line, and no file.
	dir := t.TempDir()
	r := apRun(t, apClock, "--dir", dir, "apply")
	if r.code != ExitFailure || !strings.Contains(r.stderr, "not built yet") {
		t.Errorf("exit code %d, stderr %q", r.code, r.stderr)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("the command wrote %d entries", len(ents))
	}
}

func TestApplyPlanOnlyUsageErrorsAreExitCode2AndWriteNothing(t *testing.T) {
	cases := map[string][]string{
		"a plan argument":            {"apply", "--plan-only", "history/x/plan.json"},
		"two arguments":              {"apply", "--plan-only", "a", "b"},
		"two arguments, no flag":     {"apply", "a", "b"},
		"a flag that is not there":   {"apply", "--plan-only", "--confirm", "abc"},
		"another flag not there":     {"apply", "--plan-only", "--only"},
		"the flag of another word":   {"apply", "--plan-only", "--with", "card"},
		"a flag with no value":       {"apply", "--plan-only", "--key-dir"},
		"a value of the output flag": {"apply", "--plan-only", "--output", "xml"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			dir := apBundle(t, apFiles())
			before := apSnapshot(t, dir)
			r := apRun(t, apClock, append([]string{"--dir", dir}, args...)...)
			if r.code != ExitUsage || r.stdout != "" {
				t.Errorf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			crqSame(t, "apply", before, apSnapshot(t, dir))
		})
	}
}

func TestApplyPlanOnlyUsageErrorIsAnObjectInJSONMode(t *testing.T) {
	dir := apBundle(t, apFiles())
	r := apRun(t, apClock, "--dir", dir, "--output", "json", "apply", "--plan-only", "plan.json")
	obj := apObject(t, r.stdout)
	if r.code != ExitUsage || obj["outcome"] != "usage" || obj["command"] != "apply" || obj["error"] == nil {
		t.Errorf("%d %v", r.code, obj)
	}
}

func TestTheKeyDirectoryIsCheckedAndARefusalIsExitCode4WithTheReason(t *testing.T) {
	cases := map[string]struct {
		keyDir func(t *testing.T, dir string) string
		reason string
	}{
		"missing": {func(t *testing.T, dir string) string { return filepath.Join(t.TempDir(), "gone") }, "key-dir"},
		"inside the bundle": {func(t *testing.T, dir string) string {
			p := filepath.Join(dir, "keys")
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
			return p
		}, "key-dir"},
		"the bundle": {func(t *testing.T, dir string) string { return dir }, "key-dir"},
		"a file": {func(t *testing.T, dir string) string {
			p := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}, "key-dir"},
		"one that holds a key file": {func(t *testing.T, dir string) string {
			k := apKeys(t)
			if err := os.WriteFile(filepath.Join(k, "A.x509.key.pem"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return k
		}, "key-exists"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := apBundle(t, apFiles())
			keyDir := c.keyDir(t, dir)
			before := apSnapshot(t, dir)
			var beforeKeys []string
			_, statErr := os.Lstat(keyDir)
			inspectKeys := keyDir != dir && statErr == nil
			if inspectKeys {
				beforeKeys = apSnapshot(t, keyDir)
			}
			r := apPlanOnly(t, apClock, dir, "--key-dir", keyDir)
			if r.code != ExitBackend || r.stdout != "" {
				t.Fatalf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stderr, "nothing was written") {
				t.Errorf("standard error = %q", r.stderr)
			}
			crqSame(t, "apply", before, apSnapshot(t, dir))
			if inspectKeys {
				crqSame(t, "apply in the key directory", beforeKeys, apSnapshot(t, keyDir))
			}
			rj := apPlanOnly(t, apClock, dir, "--key-dir", keyDir, "--output", "json")
			obj := apObject(t, rj.stdout)
			reasons, _ := stringList(obj["reasons"])
			if rj.code != ExitBackend || obj["outcome"] != "refused" || !slices.Equal(reasons, []string{c.reason}) || obj["error"] != nil {
				t.Errorf("JSON: %d %v, want the reason %s", rj.code, obj, c.reason)
			}
		})
	}
}

func TestNothingToApplyIsExitCode0WithOneLineAndNoFile(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"no want folder": {"ritueel.yaml": newSettingsTestText},
		"only a request": {"ritueel.yaml": newSettingsTestText, "requests/acme-ca/request.json": "{}"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := apBundle(t, files)
			before := apSnapshot(t, dir)
			for _, extra := range [][]string{{"--key-dir", apKeys(t)}, {}} {
				r := apPlanOnly(t, apClock, dir, extra...)
				if r.code != ExitOK || r.stdout != "nothing to apply\n" || r.stderr != "" {
					t.Errorf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
				}
			}
			crqSame(t, "apply", before, apSnapshot(t, dir))
			rj := apPlanOnly(t, apClock, dir, "--output", "json")
			obj := apObject(t, rj.stdout)
			if rj.code != ExitOK || obj["outcome"] != "done" || obj["plan"] != nil || obj["ceremony"] != nil || rj.stderr != "" {
				t.Errorf("JSON: %d %v %q", rj.code, obj, rj.stderr)
			}
		})
	}
}

func TestApplyPlanOnlyRefusesWhatThisVersionDoesNotBuildWithExitCode1(t *testing.T) {
	with := func(extra map[string]string) map[string]string {
		m := apFiles()
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := map[string]struct {
		files map[string]string
		words string
	}{
		"the OpenPGP root file that new writes": {with(map[string]string{"want/roots/openpgp.yaml": newOpenPGPTestText}), "want/roots/openpgp.yaml"},
		"a root that is not a test root":        {map[string]string{"ritueel.yaml": newSettingsTestText, "want/roots/x509.yaml": newX509Text}, "not a test root"},
		"a personal bundle": {map[string]string{"ritueel.yaml": "version: 1\nkind: personal\nperson:\n  name: Example Person\n  address: person@example.org\npolicy:\n  stores: [piv]\n  min_firmware: 5.7.0\n  pin_policy: [once]\n  require_name_constraints: true\n  validity_months: 13\n",
			"want/roots/x509.yaml": newX509TestText}, "personal"},
		"a wanted file that fails its check": {map[string]string{"ritueel.yaml": newSettingsTestText, "want/roots/x509.yaml": "kind: nonsense\n"}, "want/roots/x509.yaml"},
		"a request name that is not plain":   {with(map[string]string{"requests/a b/x": "x"}), "requests/"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := apBundle(t, c.files)
			before := apSnapshot(t, dir)
			r := apPlanOnly(t, apClock, dir, "--key-dir", apKeys(t))
			if r.code != ExitFailure || r.stdout != "" || !strings.Contains(r.stderr, c.words) || !strings.Contains(r.stderr, "nothing was written") {
				t.Errorf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
			}
			crqSame(t, "apply", before, apSnapshot(t, dir))
		})
	}
}

func TestApplyPlanOnlyRefusesAnOpenAttemptWithExitCode3AndTheReason(t *testing.T) {
	dir := apBundle(t, apFiles())
	if r := apPlanOnly(t, apClock, dir); r.code != ExitOK {
		t.Fatalf("plan: %d %q", r.code, r.stderr)
	}
	// An attempt that the later parts write: the plan's digest, the ceremony and the root.
	planBytes, err := os.ReadFile(filepath.Join(dir, "history", apName, "plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := (&files.Attempt{Version: 1, Ceremony: apName, PlanSHA256: sha256Of(string(planBytes)), Root: "A", StartedAt: "2026-11-20T10:00:05Z"}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "history", apName, "attempt.json"), attempt, 0o644); err != nil {
		t.Fatal(err)
	}
	before := apSnapshot(t, dir)
	later := apClock.Add(time.Hour)
	r := apPlanOnly(t, later, dir, "--key-dir", apKeys(t))
	if r.code != ExitRefused || r.stdout != "" || !strings.Contains(r.stderr, "history/"+apName) || !strings.Contains(r.stderr, "nothing was written") {
		t.Fatalf("exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	crqSame(t, "apply with an open attempt", before, apSnapshot(t, dir))
	rj := apPlanOnly(t, later, dir, "--output", "json")
	obj := apObject(t, rj.stdout)
	reasons, _ := stringList(obj["reasons"])
	if rj.code != ExitRefused || obj["outcome"] != "refused" || !slices.Equal(reasons, []string{"unfinished-ceremony"}) || obj["error"] != nil {
		t.Errorf("JSON: %d %v", rj.code, obj)
	}
	// The same refusal with no flag at all: an open attempt does not make a plan, and it is
	// told before the key directory is looked at.
	if r2 := apPlanOnly(t, later, dir, "--key-dir", filepath.Join(t.TempDir(), "gone")); r2.code != ExitRefused {
		t.Errorf("with a key directory that is missing: exit code %d", r2.code)
	}
}

func TestApplyPlanOnlyRefusesAHistoryThatFailsItsCheckWithExitCode3(t *testing.T) {
	dir := apBundle(t, apFiles())
	if err := os.MkdirAll(filepath.Join(dir, "history"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(dir, "history", apName)); err != nil {
		t.Fatal(err)
	}
	want := apRun(t, apClock, "--dir", dir, "--output", "json", "check", "history")
	wantObj := apObject(t, want.stdout)
	if want.code != ExitRefused {
		t.Fatalf("check history of the bundle: exit code %d", want.code)
	}
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, dir, "--output", "json")
	obj := apObject(t, r.stdout)
	if r.code != ExitRefused || !slices.Equal(mustStrings(t, obj["reasons"]), mustStrings(t, wantObj["reasons"])) {
		t.Errorf("apply: %d %v; check history: %v", r.code, obj, wantObj)
	}
	crqSame(t, "apply", before, apSnapshot(t, dir))
}

func mustStrings(t testing.TB, v any) []string {
	t.Helper()
	s, ok := stringList(v)
	if !ok {
		t.Fatalf("%#v is not a list of strings", v)
	}
	return s
}

func TestApplyPlanOnlyOfABundleThatIsNotInTheFirstStateIsExitCode1(t *testing.T) {
	dir := apBundle(t, apFiles())
	if err := os.MkdirAll(filepath.Join(dir, "roots", "A"), 0o755); err != nil {
		t.Fatal(err)
	}
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, dir)
	if r.code != ExitFailure || !strings.Contains(r.stderr, "first apply only") || !strings.Contains(r.stderr, "nothing was written") {
		t.Errorf("exit code %d, stderr %q", r.code, r.stderr)
	}
	crqSame(t, "apply", before, apSnapshot(t, dir))
}

func TestApplyNeedsABundleFolder(t *testing.T) {
	r := apRun(t, apClock, "apply", "--plan-only")
	// The test runs in the folder of the package, which has no ritueel.yaml.
	if r.code != ExitUsage || !strings.Contains(r.stderr, "--dir") {
		t.Errorf("no --dir: exit code %d, stderr %q", r.code, r.stderr)
	}
	missing := filepath.Join(t.TempDir(), "gone")
	r = apRun(t, apClock, "--dir", missing, "apply", "--plan-only")
	if r.code != ExitFailure || r.stdout != "" {
		t.Errorf("a folder that is not there: exit code %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r = apRun(t, apClock, "--dir", file, "apply", "--plan-only"); r.code != ExitFailure {
		t.Errorf("a file as the folder: exit code %d, stderr %q", r.code, r.stderr)
	}
}

func TestApplyPlanOnlyThroughALinkAsTheBundleFolderWritesNothingThroughTheLink(t *testing.T) {
	dir := apBundle(t, apFiles())
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	before := apSnapshot(t, dir)
	r := apPlanOnly(t, apClock, link)
	if r.code == ExitOK {
		// A link as the root of --dir is the person's own choice; if it is followed, the plan is
		// in the folder it points to and nowhere else.
		if _, err := os.Stat(filepath.Join(dir, "history", apName, "plan.json")); err != nil {
			t.Errorf("exit code 0 and no plan: %v", err)
		}
		return
	}
	crqSame(t, "apply through a link", before, apSnapshot(t, dir))
}

func TestHelpListsApplyAndTheWordHasItsFlags(t *testing.T) {
	r := apRun(t, apClock, "--help")
	if r.code != ExitOK || !regexp.MustCompile(`(?m)^\s+apply\s`).MatchString(r.stdout) {
		t.Errorf("--help: %d %q", r.code, r.stdout)
	}
	r = apRun(t, apClock, "apply", "--help")
	for _, w := range []string{"--plan-only", "--key-dir"} {
		if r.code != ExitOK || !strings.Contains(r.stdout, w) {
			t.Errorf("apply --help does not list %s: %d %q", w, r.code, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "--confirm") {
		t.Errorf("apply --help lists a flag that is not built: %q", r.stdout)
	}
}

func TestTheResultMembersOfApplyAreTheOnesOfThePage(t *testing.T) {
	b, err := json.Marshal(&Result{Ceremony: "c", Plan: &PlanRef{Path: "p", SHA256: "s", Prefix: "x"}})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	plan, _ := m["plan"].(map[string]any)
	if m["ceremony"] != "c" || len(plan) != 3 || plan["path"] != "p" || plan["sha256"] != "s" || plan["prefix"] != "x" {
		t.Errorf("Result = %s", b)
	}
	// A Result with neither has neither.
	b, _ = json.Marshal(&Result{})
	if strings.Contains(string(b), "ceremony") || strings.Contains(string(b), "plan") {
		t.Errorf("an empty Result holds %s", b)
	}
}

func TestApplyErrorMapsEachTypeOfTheEngineToOneCodedError(t *testing.T) {
	cases := []struct {
		err  error
		code ExitCode
	}{
		{&ceremony.UsageError{Msg: "bad"}, ExitUsage},
		{&ceremony.RefusedError{Reasons: []string{"a"}, Msg: "m"}, ExitRefused},
		{&ceremony.BackendError{Reasons: []string{"key-dir"}, Msg: "m"}, ExitBackend},
		{ceremony.ErrNotConfirmed, ExitNotConfirmed},
		{ceremony.ErrNotBuilt, ExitFailure},
		{ceremony.ErrNotFirst, ExitFailure},
		{os.ErrNotExist, ExitFailure},
		{&fs.PathError{Op: "x", Path: "y", Err: os.ErrPermission}, ExitFailure},
	}
	for _, c := range cases {
		got := applyError(c.err)
		code := ExitFailure
		var coded Coded
		if errors.As(got, &coded) {
			code = coded.ExitCode()
		}
		if code != c.code {
			t.Errorf("applyError(%v) has the exit code %d, want %d", c.err, code, c.code)
		}
	}
	// A type of the engine inside a wrapper is mapped too.
	wrapped := applyError(joinErr{&ceremony.RefusedError{Reasons: []string{"unfinished-ceremony"}, Msg: "m"}})
	var r Refusal
	if !errors.As(wrapped, &r) || !slices.Equal(r.Reasons, []string{"unfinished-ceremony"}) {
		t.Errorf("a wrapped refusal = %#v", wrapped)
	}
	// An error that is nothing of the engine is returned as it is.
	plain := os.ErrClosed
	if !errors.Is(applyError(plain), plain) {
		t.Error("a plain error was changed")
	}
}

type joinErr struct{ err error }

func (e joinErr) Error() string { return "wrapped: " + e.err.Error() }
func (e joinErr) Unwrap() error { return e.err }

func TestApplyPlanOnlyIsTheSameWithAnyOrderOfTheGlobalFlags(t *testing.T) {
	dir := apBundle(t, apFiles())
	for _, args := range [][]string{
		{"--dir", dir, "--output", "json", "apply", "--plan-only"},
		{"apply", "--plan-only", "--dir", dir, "--output", "json"},
		{"--output", "json", "apply", "--dir", dir, "--plan-only"},
	} {
		d := apBundle(t, apFiles())
		args = slices.Clone(args)
		for i, a := range args {
			if a == dir {
				args[i] = d
			}
		}
		r := apRun(t, apClock, args...)
		if r.code != ExitOK || apObject(t, r.stdout)["ceremony"] != apName {
			t.Errorf("%v: %d %q", args, r.code, r.stdout)
		}
	}
}

func TestNothingOnTheRealStreamsIsWrittenByApply(t *testing.T) {
	// A run with nil streams writes nothing to the process's own streams and does not panic.
	dir := apBundle(t, apFiles())
	code := Run(context.Background(), []string{"--dir", dir, "apply", "--plan-only"}, Env{Build: testBuild, Now: func() time.Time { return apClock }})
	if code != ExitOK {
		t.Errorf("exit code %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "history", apName, "plan.json")); err != nil {
		t.Errorf("no plan: %v", err)
	}
}

// apFailingWriter is a stream that refuses every write.
type apFailingWriter struct{}

func (apFailingWriter) Write([]byte) (int, error) { return 0, errors.New("the stream is closed") }

func TestAStreamThatRefusesTheWordsIsAFailureThatSaysWhereThePlanIs(t *testing.T) {
	for name, env := range map[string]func(*bytes.Buffer) Env{
		"standard error": func(out *bytes.Buffer) Env {
			return Env{Stdin: strings.NewReader(""), Stdout: out, Stderr: apFailingWriter{}, Build: testBuild, Now: func() time.Time { return apClock }}
		},
		"standard output": func(out *bytes.Buffer) Env {
			return Env{Stdin: strings.NewReader(""), Stdout: apFailingWriter{}, Stderr: out, Build: testBuild, Now: func() time.Time { return apClock }}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := apBundle(t, apFiles())
			var other bytes.Buffer
			code := Run(context.Background(), []string{"--dir", dir, "apply", "--plan-only"}, env(&other))
			if code != ExitFailure {
				t.Errorf("exit code %d, want 1: a plan that nobody could read is not a success", code)
			}
			planBytes, err := os.ReadFile(filepath.Join(dir, "history", apName, "plan.json"))
			if err != nil {
				t.Fatalf("the plan is not on the disk: %v", err)
			}
			// The line that the stream that works holds names the plan and its digest.
			text := other.String()
			if name == "standard output" && !strings.Contains(text, "history/"+apName+"/plan.json") {
				t.Errorf("the line for the person does not name the plan: %q", text)
			}
			if !strings.Contains(text, sha256Of(string(planBytes))) && name == "standard output" {
				t.Errorf("the line for the person does not give the digest: %q", text)
			}
		})
	}
}
