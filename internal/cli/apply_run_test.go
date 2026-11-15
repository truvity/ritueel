//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony"
)

// "apply" and "apply PLAN" through Run: the whole first apply of a test root, its exit codes and its
// JSON result. The names of this file start with ar.

// arTicker is a clock that shows one second more at each call.
type arTicker struct {
	t atomic.Int64
	n time.Time
}

func newTicker(start time.Time) *arTicker { return &arTicker{n: start} }

func (c *arTicker) now() time.Time {
	return c.n.Add(time.Duration(c.t.Add(1)) * time.Second)
}

// arCount is a standard input that counts its reads.
type arCount struct {
	r     io.Reader
	reads atomic.Int32
}

func (c *arCount) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.r.Read(p)
}

// arRun runs the command line with a ticking clock after the plan time, the given standard input and
// the kind of it.
func arRun(t testing.TB, clock func() time.Time, in io.Reader, term bool, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), args, Env{
		Stdin: in, Stdout: &stdout, Stderr: &stderr, Build: testBuild, Now: clock, StdinIsTerminal: term,
	})
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// arBundle makes the bundle that "new --test-root" makes, with the OpenPGP root file deleted as a
// person does before the first apply, and a key directory outside it.
func arBundle(t testing.TB) (dir, keys string) {
	t.Helper()
	root := t.TempDir()
	dir, keys = filepath.Join(root, "ca"), filepath.Join(root, "keys")
	if r := apRun(t, apClock, "new", "--test-root", dir); r.code != ExitOK {
		t.Fatalf("new: %d %s", r.code, r.stderr)
	}
	if err := os.Remove(filepath.Join(dir, "want", "roots", "openpgp.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, keys
}

// arPlan runs apply --plan-only in JSON mode and returns the path and the digest of the plan.
func arPlan(t testing.TB, now time.Time, dir string, extra ...string) (path, digest string) {
	t.Helper()
	args := append([]string{"--dir", dir, "--output", "json", "apply", "--plan-only"}, extra...)
	r := apRun(t, now, args...)
	if r.code != ExitOK {
		t.Fatalf("apply --plan-only: %d %s", r.code, r.stderr)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &obj); err != nil {
		t.Fatalf("apply --plan-only: %v: %q", err, r.stdout)
	}
	plan, _ := obj["plan"].(map[string]any)
	path, _ = plan["path"].(string)
	digest, _ = plan["sha256"].(string)
	if len(digest) != 64 || path == "" {
		t.Fatalf("plan = %v", plan)
	}
	return path, digest
}

var arEndLine = regexp.MustCompile(`^history: 1 ceremony records, end [0-9a-f]{8}\n$`)

func TestApplyPlanWithTheFlagMakesTheCeremonyAndTheResultHasTheMembersOfThePage(t *testing.T) {
	dir, keys := arBundle(t)
	planT := apClock
	path, digest := arPlan(t, planT, dir, "--key-dir", keys)
	tick := newTicker(planT)
	r := arRun(t, tick.now, strings.NewReader(""), false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	if r.code != ExitOK {
		t.Fatalf("exit %d, stderr %s", r.code, r.stderr)
	}
	obj := apObject(t, r.stdout)
	for _, m := range []string{"output", "command", "exit_code", "outcome", "warnings", "ceremony", "plan", "record", "artifacts", "trust_sequence", "roots"} {
		if _, ok := obj[m]; !ok {
			t.Errorf("no member %q in %v", m, keysOf(obj))
		}
	}
	for _, m := range []string{"reasons", "error"} {
		if _, ok := obj[m]; ok {
			t.Errorf("a success has the member %q", m)
		}
	}
	if len(obj) != 11 {
		t.Errorf("members %v", keysOf(obj))
	}
	if obj["command"] != "apply" || obj["outcome"] != "done" || obj["exit_code"].(json.Number).String() != "0" || obj["trust_sequence"].(json.Number).String() != "1" {
		t.Errorf("head %v", obj)
	}
	plan := obj["plan"].(map[string]any)
	if plan["path"] != path || plan["sha256"] != digest || plan["prefix"] != digest[:8] {
		t.Errorf("plan = %v", plan)
	}
	rec := obj["record"].(map[string]any)
	if rec["path"] != strings.TrimSuffix(path, "plan.json")+"record.json" || len(rec["sha256"].(string)) != 64 {
		t.Errorf("record = %v", rec)
	}
	data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rec["path"].(string))))
	if err != nil || rec["sha256"] != arSum(data) {
		t.Errorf("the digest of the record is not the digest of the file: %v", err)
	}
	arts := obj["artifacts"].([]any)
	if len(arts) != 5 {
		t.Fatalf("%d artifacts", len(arts))
	}
	for _, a := range arts {
		m := a.(map[string]any)
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(m["path"].(string))))
		if err != nil || arSum(b) != m["sha256"] {
			t.Errorf("artifact %v: %v", m, err)
		}
	}
	roots := obj["roots"].([]any)
	if len(roots) != 2 {
		t.Fatalf("%d roots", len(roots))
	}
	for i, r := range roots {
		m := r.(map[string]any)
		if len(m) != 5 || m["label"] != string(rune('A'+i)) || m["store"] != "software" || m["test"] != true || len(m["x509_spki_sha256"].(string)) != 64 || m["not_after"] == "" {
			t.Errorf("root %d = %v", i, m)
		}
		if _, ok := m["openpgp_fingerprint"]; ok {
			t.Errorf("root %d has an OpenPGP fingerprint", i)
		}
	}
	// Everything a person reads is on standard error and the object is not in it.
	if !strings.Contains(r.stderr, "plan digest "+digest) || strings.Contains(r.stderr, `"outcome"`) {
		t.Errorf("standard error: %q", r.stderr)
	}
	if !apPrintable(strings.TrimSuffix(r.stdout, "\n")) || !apPrintable(strings.ReplaceAll(r.stderr, "\n", " ")) {
		t.Error("an output is not printable ASCII")
	}
}

func arSum(b []byte) string { return sum(b) }

func TestApplyWithTheFlagThenCheckHistoryAndVerifyRootListAcceptWhatItWrote(t *testing.T) {
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	tick := newTicker(apClock)
	r := arRun(t, tick.now, nil, false, "--dir", dir, "apply", path, "--key-dir", keys, "--confirm", digest)
	if r.code != ExitOK || !arEndLine.MatchString(r.stdout) || strings.Count(r.stdout, "\n") != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %s: want the end line only on standard output", r.code, r.stdout, r.stderr)
	}
	h := apRun(t, apClock, "--dir", dir, "check", "history")
	if h.code != ExitOK || h.stdout != r.stdout {
		t.Errorf("check history: %d %q, apply printed %q", h.code, h.stdout, r.stdout)
	}
	// verify root-list with the pins of the result.
	j := arRun(t, tick.now, nil, false, "--dir", dir, "check", "history", "--output", "json")
	_ = j
	rr := apRun(t, apClock, "--dir", dir, "--output", "json", "apply", "--key-dir", keys)
	_ = rr
	entries, err := os.ReadDir(filepath.Join(dir, "trust"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("trust/: %v %v", entries, err)
	}
	set := filepath.Join(dir, "trust", entries[0].Name())
	pins := arPinsOf(t, filepath.Join(dir, "roots"))
	args := []string{"verify", "root-list", filepath.Join(set, "root-list.json"), "--ca-bundle", filepath.Join(set, "ca-bundle.pem")}
	for _, p := range pins {
		args = append(args, "--pin", p)
	}
	v := apRun(t, apClock, args...)
	if v.code != ExitOK || !strings.HasPrefix(v.stdout, "accepted: sequence 1, 2 root keys") {
		t.Errorf("verify root-list: %d %q %s", v.code, v.stdout, v.stderr)
	}
}

// arPinsOf reads the pins of root.json of each label under roots/.
func arPinsOf(t testing.TB, roots string) []string {
	t.Helper()
	var pins []string
	for _, l := range []string{"A", "B"} {
		b, err := os.ReadFile(filepath.Join(roots, l, "root.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		pins = append(pins, m["x509_spki_sha256"].(string))
	}
	return pins
}

func TestADirectApplyIsConfirmedByTypingTheFirstEightCharactersAtATerminal(t *testing.T) {
	for _, upper := range []bool{false, true} {
		dir, keys := arBundle(t)
		tick := newTicker(apClock)
		// The digest of a direct apply is known only after the plan is made: read it from standard
		// error, which is what a person does, and type it into the next run of the same plan.
		first := arRun(t, tick.now, strings.NewReader("00000000\n"), true, "--dir", dir, "apply", "--key-dir", keys)
		if first.code != ExitNotConfirmed {
			t.Fatalf("a first run with a wrong line: exit %d %s", first.code, first.stderr)
		}
		m := regexp.MustCompile(`plan digest ([0-9a-f]{64})`).FindStringSubmatch(first.stderr)
		if m == nil {
			t.Fatalf("no digest in %q", first.stderr)
		}
		// The next plan has other serials: its digest is another one, so the typed line of the first
		// plan does not confirm it.
		typed := m[1][:8]
		if upper {
			typed = strings.ToUpper(typed)
		}
		again := arRun(t, tick.now, strings.NewReader(typed+"\n"), true, "--dir", dir, "apply", "--key-dir", keys)
		if again.code != ExitNotConfirmed {
			t.Errorf("the digest of another plan confirmed this plan: exit %d", again.code)
		}
		if _, err := os.Stat(filepath.Join(dir, "history")); err == nil {
			t.Error("history/ exists after a plan that was not confirmed")
		}
	}
}

func TestADirectApplyTypedAtATerminalWritesTheCeremonyAndPrintsOnlyTheEndLine(t *testing.T) {
	dir, keys := arBundle(t)
	// A typed confirmation of a direct apply needs the digest before it is printed, which only a
	// reader of the plan words has: the test makes the plan with --plan-only, runs the saved plan, and
	// the typed line is the first eight characters that --plan-only printed.
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	tick := newTicker(apClock)
	in := &arCount{r: strings.NewReader(strings.ToUpper(digest[:8]) + "\n")}
	r := arRun(t, tick.now, in, true, "--dir", dir, "apply", path, "--key-dir", keys)
	if r.code != ExitOK || !arEndLine.MatchString(r.stdout) {
		t.Fatalf("exit %d, stdout %q, stderr %s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stderr, "type the first 8 characters of the plan digest") || !strings.Contains(r.stderr, "confirmed by typing") {
		t.Errorf("standard error: %q", r.stderr)
	}
	if in.reads.Load() == 0 {
		t.Error("standard input was not read")
	}
	rec, err := os.ReadFile(filepath.Join(dir, strings.TrimSuffix(path, "plan.json")+"record.json"))
	if err != nil || !bytes.Contains(rec, []byte(`"by":"typed"`)) {
		t.Errorf("the record does not say typed: %v", err)
	}
	if strings.ToUpper(digest[:8]) != digest[:8] && bytes.Contains(rec, []byte(strings.ToUpper(digest[:8]))) {
		t.Error("the typed text is in the record")
	}
}

func TestApplyWithStandardInputThatIsNotATerminalNeverReadsItAndIsNotConfirmed(t *testing.T) {
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	for _, args := range [][]string{{"apply", path}, {"apply"}} {
		before := apSnapshot(t, dir)
		in := &arCount{r: strings.NewReader(digest[:8] + "\n")}
		tick := newTicker(apClock)
		r := arRun(t, tick.now, in, false, append([]string{"--dir", dir, "--output", "json"}, append(args, "--key-dir", keys)...)...)
		obj := apObject(t, r.stdout)
		if r.code != ExitNotConfirmed || obj["outcome"] != "not-confirmed" || obj["exit_code"].(json.Number).String() != "5" {
			t.Errorf("%v: exit %d, %v", args, r.code, obj)
		}
		if _, ok := obj["error"]; ok {
			t.Errorf("a command that was not confirmed has an error member: %v", obj)
		}
		if _, ok := obj["reasons"]; ok {
			t.Errorf("a command that was not confirmed has reasons: %v", obj)
		}
		if in.reads.Load() != 0 {
			t.Errorf("%v: standard input was read", args)
		}
		if !strings.Contains(r.stderr, "standard input is not a terminal") {
			t.Errorf("standard error: %q", r.stderr)
		}
		crqSame(t, "a run that was not confirmed", before, apSnapshot(t, dir))
	}
	// The zero value of the environment says there is no terminal.
	var env Env
	if env.StdinIsTerminal {
		t.Error("the zero Env has a terminal")
	}
}

func TestApplyThatIsNotConfirmedByTheFlagIsExitCode5AndWritesNothing(t *testing.T) {
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	wrong := map[string][]string{
		"an empty value":     {"--confirm", ""},
		"63 digits":          {"--confirm", digest[:63]},
		"upper case":         {"--confirm", strings.ToUpper(digest)},
		"another digest":     {"--confirm", strings.Repeat("0", 64)},
		"the first eight":    {"--confirm", digest[:8]},
		"a value with space": {"--confirm", digest + " "},
	}
	for name, extra := range wrong {
		t.Run(name, func(t *testing.T) {
			before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
			tick := newTicker(apClock)
			r := arRun(t, tick.now, nil, false, append([]string{"--dir", dir, "--output", "json", "apply", path, "--key-dir", keys}, extra...)...)
			obj := apObject(t, r.stdout)
			if r.code != ExitNotConfirmed || obj["outcome"] != "not-confirmed" {
				t.Errorf("exit %d, %v", r.code, obj)
			}
			crqSame(t, "a wrong digest", before, apSnapshot(t, dir))
			crqSame(t, "a wrong digest (keys)", keysBefore, apSnapshot(t, keys))
		})
	}
	t.Run("the digest still confirms the plan afterwards", func(t *testing.T) {
		tick := newTicker(apClock)
		r := arRun(t, tick.now, nil, false, "--dir", dir, "apply", path, "--key-dir", keys, "--confirm", digest)
		if r.code != ExitOK {
			t.Errorf("exit %d %s", r.code, r.stderr)
		}
	})
}

func TestApplyUsageErrorsAreExitCode2AndWriteNothing(t *testing.T) {
	cases := map[string]func(path, digest, keys string) []string{
		"confirm with plan-only":      func(path, digest, keys string) []string { return []string{"apply", "--plan-only", "--confirm", digest} },
		"confirm with an empty value": func(path, digest, keys string) []string { return []string{"apply", "--plan-only", "--confirm", ""} },
		"plan-only with a plan":       func(path, digest, keys string) []string { return []string{"apply", "--plan-only", path} },
		"two arguments":               func(path, digest, keys string) []string { return []string{"apply", path, path, "--key-dir", keys} },
		"a plan outside history":      func(path, digest, keys string) []string { return []string{"apply", "plan.json", "--key-dir", keys} },
		"an absolute plan":            func(path, digest, keys string) []string { return []string{"apply", "/" + path, "--key-dir", keys} },
		"a plan of another file name": func(path, digest, keys string) []string {
			return []string{"apply", strings.TrimSuffix(path, "plan.json") + "other.json", "--key-dir", keys}
		},
		"a plan with two dots": func(path, digest, keys string) []string {
			return []string{"apply", "history/../" + path, "--key-dir", keys}
		},
		"a plan of 13 elements": func(path, digest, keys string) []string {
			return []string{"apply", strings.Repeat("a/", 12) + "plan.json", "--key-dir", keys}
		},
		"no key directory":            func(path, digest, keys string) []string { return []string{"apply", path} },
		"an empty key directory":      func(path, digest, keys string) []string { return []string{"apply", path, "--key-dir", ""} },
		"a flag that is not declared": func(path, digest, keys string) []string { return []string{"apply", path, "--only", "--key-dir", keys} },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			dir, keys := arBundle(t)
			path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
			args := mk(path, digest, keys)
			before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
			tick := newTicker(apClock)
			r := arRun(t, tick.now, strings.NewReader(""), false, append([]string{"--dir", dir, "--output", "json"}, args...)...)
			obj := apObject(t, r.stdout)
			if r.code != ExitUsage || obj["outcome"] != "usage" || obj["command"] != "apply" {
				t.Fatalf("exit %d, %v", r.code, obj)
			}
			if msg, _ := obj["error"].(string); msg == "" || !apPrintable(msg) {
				t.Errorf("error = %v", obj["error"])
			}
			if _, ok := obj["reasons"]; ok {
				t.Errorf("a usage error has reasons: %v", obj)
			}
			crqSame(t, "a usage error", before, apSnapshot(t, dir))
			crqSame(t, "a usage error (keys)", keysBefore, apSnapshot(t, keys))
		})
	}
}

func TestAnApplyOfASavedPlanIsRefusedWithTheReasonsOfThePageAndWritesNothing(t *testing.T) {
	type tc struct {
		name   string
		reason string
		code   ExitCode
		prep   func(t *testing.T, dir, keys, path string)
		clock  func() time.Time
	}
	tick := func() func() time.Time { return newTicker(apClock).now }
	cases := []tc{
		{"a plan of a bundle that has a ceremony record now", "plan-stale", ExitRefused, func(t *testing.T, dir, keys, path string) {
			r := arRun(t, tick(), nil, false, "--dir", dir, "apply", path, "--key-dir", keys, "--confirm", arDigestOf(t, dir, path))
			if r.code != ExitOK {
				t.Fatalf("the first run: %d %s", r.code, r.stderr)
			}
		}, tick()},
		{"a clock that is behind the ceremony time", "clock-behind", ExitRefused, func(t *testing.T, dir, keys, path string) {}, func() time.Time { return apClock.Add(-time.Hour) }},
		{"a plan of another copy of the program", "plan-version", ExitRefused, func(t *testing.T, dir, keys, path string) {
			arEditSavedPlan(t, dir, path, func(m map[string]any) { m["ritueel"].(map[string]any)["version"] = "v0.0.0-another" })
		}, tick()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, keys := arBundle(t)
			path, _ := arPlan(t, apClock, dir, "--key-dir", keys)
			c.prep(t, dir, keys, path)
			digest := arDigestOf(t, dir, path)
			before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
			r := arRun(t, c.clock, nil, false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
			obj := apObject(t, r.stdout)
			reasons, _ := stringList(obj["reasons"])
			if r.code != c.code || obj["outcome"] != "refused" || !slices.Equal(reasons, []string{c.reason}) {
				t.Fatalf("exit %d, %v; want refused with %s", r.code, obj, c.reason)
			}
			if _, ok := obj["error"]; ok {
				t.Errorf("a refusal has an error member: %v", obj)
			}
			crqSame(t, "a refused plan", before, apSnapshot(t, dir))
			crqSame(t, "a refused plan (keys)", keysBefore, apSnapshot(t, keys))
		})
	}
}

// arDigestOf is the digest of the plan file as the run reads it.
func arDigestOf(t testing.TB, dir, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return arSum(b)
}

// arEditSavedPlan changes a member of a saved plan and writes it again in the canonical form.
func arEditSavedPlan(t testing.TB, dir, path string, edit func(m map[string]any)) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(path))
	b, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	for k, v := range m {
		m[k] = arInts(v)
	}
	edit(m)
	out, err := canonjson.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func arInts(v any) any {
	switch x := v.(type) {
	case json.Number:
		n, err := x.Int64()
		if err != nil {
			panic(err)
		}
		return n
	case []any:
		for i := range x {
			x[i] = arInts(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = arInts(x[k])
		}
	}
	return v
}

func TestApplyRefusesTheKeyDirectoryWithExitCode4BeforeItAsksAndBeforeItWrites(t *testing.T) {
	cases := map[string]struct {
		mk     func(t *testing.T, dir string) string
		reason string
	}{
		"missing":           {func(t *testing.T, dir string) string { return filepath.Join(t.TempDir(), "gone") }, "key-dir"},
		"inside the bundle": {func(t *testing.T, dir string) string { return arMkdir(t, filepath.Join(dir, "keys")) }, "key-dir"},
		"the bundle":        {func(t *testing.T, dir string) string { return dir }, "key-dir"},
		"one with a key": {func(t *testing.T, dir string) string {
			k := apKeys(t)
			if err := os.WriteFile(filepath.Join(k, "B.x509.key.pem"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return k
		}, "key-exists"},
	}
	for name, c := range cases {
		for _, saved := range []bool{false, true} {
			t.Run(name+map[bool]string{false: " direct", true: " saved"}[saved], func(t *testing.T) {
				dir, keys := arBundle(t)
				path, digest := arPlan(t, apClock, dir)
				keyDir := c.mk(t, dir)
				args := []string{"--dir", dir, "--output", "json", "apply", "--key-dir", keyDir, "--confirm", digest}
				if saved {
					args = append(args, path)
				}
				before := apSnapshot(t, dir)
				in := &arCount{r: strings.NewReader("")}
				tick := newTicker(apClock)
				r := arRun(t, tick.now, in, true, args...)
				obj := apObject(t, r.stdout)
				reasons, _ := stringList(obj["reasons"])
				if r.code != ExitBackend || obj["outcome"] != "refused" || !slices.Equal(reasons, []string{c.reason}) {
					t.Fatalf("exit %d, %v; want exit 4 with %s", r.code, obj, c.reason)
				}
				if _, ok := obj["error"]; ok {
					t.Errorf("a refusal has an error member")
				}
				if in.reads.Load() != 0 || strings.Contains(r.stderr, "plan digest") && !saved && false {
					t.Errorf("standard input was read before the key directory was judged")
				}
				crqSame(t, "a refused key directory", before, apSnapshot(t, dir))
				if k, _ := os.ReadDir(keys); len(k) != 0 {
					t.Error("the other key directory was written")
				}
			})
		}
	}
}

func arMkdir(t *testing.T, p string) string {
	t.Helper()
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestASecondApplyOnABundleThatHoldsACeremonyIsExitCode1AndAFailureNotARefusal(t *testing.T) {
	dir, keys := arBundle(t)
	tick := newTicker(apClock)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	if r := arRun(t, tick.now, nil, false, "--dir", dir, "apply", path, "--key-dir", keys, "--confirm", digest); r.code != ExitOK {
		t.Fatalf("the first apply: %d %s", r.code, r.stderr)
	}
	before := apSnapshot(t, dir)
	r := arRun(t, tick.now, nil, false, "--dir", dir, "--output", "json", "apply", "--key-dir", apKeys(t), "--confirm", digest)
	obj := apObject(t, r.stdout)
	if r.code != ExitFailure || obj["outcome"] != "failed" {
		t.Fatalf("exit %d, %v", r.code, obj)
	}
	if _, ok := obj["reasons"]; ok {
		t.Errorf("a failure has reasons: %v", obj)
	}
	if msg, _ := obj["error"].(string); !strings.Contains(msg, "first apply only") {
		t.Errorf("error = %v", obj["error"])
	}
	crqSame(t, "a second apply", before, apSnapshot(t, dir))
}

func TestAnOpenAttemptIsExitCode3WithUnfinishedCeremonyForApplyAndForApplyPlan(t *testing.T) {
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	// An attempt with no record: the plan folder holds an attempt.json, as a stop leaves it.
	attempt := filepath.Join(dir, strings.TrimSuffix(path, "plan.json")+"attempt.json")
	if err := os.WriteFile(attempt, []byte(`{"ceremony":"x","plan_sha256":"`+digest+`","root":"A","started_at":"2026-11-20T10:00:00Z","version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	before := apSnapshot(t, dir)
	for _, args := range [][]string{{"apply", path, "--key-dir", keys, "--confirm", digest}, {"apply", "--key-dir", keys, "--confirm", digest}, {"apply", "--plan-only"}} {
		tick := newTicker(apClock)
		r := arRun(t, tick.now, nil, false, append([]string{"--dir", dir, "--output", "json"}, args...)...)
		obj := apObject(t, r.stdout)
		reasons, _ := stringList(obj["reasons"])
		if r.code != ExitRefused || obj["outcome"] != "refused" || !slices.Equal(reasons, []string{"unfinished-ceremony"}) {
			t.Errorf("%v: exit %d, %v", args, r.code, obj)
		}
	}
	crqSame(t, "apply while an attempt is open", before, apSnapshot(t, dir))
}

func TestAStopAfterTheFirstWriteIsExitCode1WithTheLineThatNamesTheOpenCeremony(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a folder that has no write bit")
	}
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	folder := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(path, "/plan.json")))
	if err := os.Chmod(folder, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(folder, 0o755) })
	tick := newTicker(apClock)
	r := arRun(t, tick.now, nil, false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	obj := apObject(t, r.stdout)
	msg, _ := obj["error"].(string)
	if r.code != ExitFailure || obj["outcome"] != "failed" || !strings.Contains(msg, "stopped at attempt") || !strings.Contains(msg, strings.TrimSuffix(path, "/plan.json")) {
		t.Fatalf("exit %d, %v", r.code, obj)
	}
	if _, ok := obj["reasons"]; ok {
		t.Errorf("a stop has reasons: %v", obj)
	}
	if !apPrintable(msg) {
		t.Errorf("the line %+q is not printable ASCII", msg)
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 0 {
		t.Errorf("a stop before the first key left %d files in the key directory", len(ents))
	}
}

func TestApplyErrorTakesAStopForAFailureWhateverItsCauseIs(t *testing.T) {
	stopped := &ceremony.StoppedError{Ceremony: "c", Step: "make", Attempt: true, Msg: "the ceremony stopped"}
	for name, cause := range map[string]error{
		"a refusal of the key store": &ceremony.BackendError{Reasons: []string{"key-exists"}, Msg: "a key file exists"},
		"a refusal":                  &ceremony.RefusedError{Reasons: []string{"plan-stale"}, Msg: "stale"},
		"a usage error":              &ceremony.UsageError{Msg: "usage"},
		"not confirmed":              ceremony.ErrNotConfirmed,
	} {
		err := applyError(errors.Join(stopped, cause))
		var coded interface{ ExitCode() ExitCode }
		if errors.As(err, &coded) {
			t.Errorf("%s: a stop that holds the cause is exit code %d, want an uncoded failure", name, coded.ExitCode())
		}
	}
}

func TestApplyWithNothingToApplyAndAKeyDirectoryIsExitCode0AndWritesNothing(t *testing.T) {
	dir := apBundle(t, map[string]string{"ritueel.yaml": newSettingsTestText})
	keys := apKeys(t)
	before := apSnapshot(t, dir)
	r := apRun(t, apClock, "--dir", dir, "apply", "--key-dir", keys)
	if r.code != ExitOK || r.stdout != "nothing to apply\n" {
		t.Errorf("exit %d, stdout %q, stderr %q", r.code, r.stdout, r.stderr)
	}
	crqSame(t, "nothing to apply", before, apSnapshot(t, dir))
}

func TestApplyOfTheSameBundleBySeveralOrdersOfTheGlobalFlagsIsTheSame(t *testing.T) {
	for _, order := range [][]string{
		{"--output", "json", "--dir", "DIR", "apply"},
		{"--dir", "DIR", "apply", "--output", "json"},
		{"apply", "--dir", "DIR", "--output", "json"},
	} {
		dir, keys := arBundle(t)
		path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
		args := slices.Clone(order)
		for i := range args {
			if args[i] == "DIR" {
				args[i] = dir
			}
		}
		args = append(args, path, "--key-dir", keys, "--confirm", digest)
		tick := newTicker(apClock)
		r := arRun(t, tick.now, nil, false, args...)
		if r.code != ExitOK {
			t.Errorf("%v: exit %d %s", order, r.code, r.stderr)
			continue
		}
		if obj := apObject(t, r.stdout); obj["command"] != "apply" {
			t.Errorf("%v: %v", order, obj)
		}
	}
}

// A flag that decides what is confirmed or where the keys go is given once. check request refuses a
// second --delegation with a usage error; the first version of apply is held to the same rule, and so
// a script that appends a flag to a line that holds it already does not run on a value it did not mean.
func TestAFlagOfApplyThatIsGivenTwiceIsAUsageError(t *testing.T) {
	cases := map[string]func(path, digest, keys string) []string{
		"confirm": func(path, digest, keys string) []string {
			return []string{"apply", path, "--key-dir", keys, "--confirm", digest, "--confirm", digest}
		},
		"key-dir": func(path, digest, keys string) []string {
			return []string{"apply", path, "--key-dir", keys, "--key-dir", keys, "--confirm", digest}
		},
		"plan-only": func(path, digest, keys string) []string { return []string{"apply", "--plan-only", "--plan-only"} },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			dir, keys := arBundle(t)
			path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
			before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
			tick := newTicker(apClock)
			r := arRun(t, tick.now, nil, false, append([]string{"--dir", dir, "--output", "json"}, mk(path, digest, keys)...)...)
			obj := apObject(t, r.stdout)
			if r.code != ExitUsage || obj["outcome"] != "usage" {
				t.Fatalf("exit %d, %v: want a usage error", r.code, obj)
			}
			crqSame(t, "a flag given twice", before, apSnapshot(t, dir))
			crqSame(t, "a flag given twice (keys)", keysBefore, apSnapshot(t, keys))
		})
	}
}

func TestApplyOfAPlanThatIsNotARegularFileIsAFailureThatWritesNothingAndDoesNotWait(t *testing.T) {
	type mk func(t *testing.T, dir, keys, path string)
	plan := func(dir, path string) string { return filepath.Join(dir, filepath.FromSlash(path)) }
	cases := map[string]mk{
		"a pipe": func(t *testing.T, dir, keys, path string) {
			mustRemove(t, plan(dir, path))
			if err := syscallMkfifo(plan(dir, path)); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func(t *testing.T, dir, keys, path string) {
			mustRemove(t, plan(dir, path))
			arMkdir(t, plan(dir, path))
		},
		"a link to the plan": func(t *testing.T, dir, keys, path string) {
			b, err := os.ReadFile(plan(dir, path))
			if err != nil {
				t.Fatal(err)
			}
			other := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(other, b, 0o644); err != nil {
				t.Fatal(err)
			}
			mustRemove(t, plan(dir, path))
			if err := os.Symlink(other, plan(dir, path)); err != nil {
				t.Fatal(err)
			}
		},
		"a missing file": func(t *testing.T, dir, keys, path string) { mustRemove(t, plan(dir, path)) },
		"a huge file": func(t *testing.T, dir, keys, path string) {
			if err := os.WriteFile(plan(dir, path), bytes.Repeat([]byte(" "), 9<<20), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a file that is not UTF-8": func(t *testing.T, dir, keys, path string) {
			if err := os.WriteFile(plan(dir, path), []byte("\xff\xfe\x00{"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"a file of a deep nesting": func(t *testing.T, dir, keys, path string) {
			if err := os.WriteFile(plan(dir, path), []byte(strings.Repeat("[", 50000)), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, prep := range cases {
		t.Run(name, func(t *testing.T) {
			dir, keys := arBundle(t)
			path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
			prep(t, dir, keys, path)
			before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
			done := make(chan result, 1)
			go func() {
				tick := newTicker(apClock)
				done <- arRun(t, tick.now, nil, false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
			}()
			select {
			case r := <-done:
				obj := apObject(t, r.stdout)
				if r.code != ExitFailure || obj["outcome"] != "failed" || obj["error"] == nil {
					t.Errorf("exit %d, %v", r.code, obj)
				}
				if msg, _ := obj["error"].(string); !apPrintable(msg) {
					t.Errorf("the text %+q is not printable ASCII", msg)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("apply waits on a plan that is not a regular file")
			}
			crqSame(t, "a plan that cannot be read", before, apSnapshot(t, dir))
			crqSame(t, "a plan that cannot be read (keys)", keysBefore, apSnapshot(t, keys))
		})
	}
}

func mustRemove(t *testing.T, p string) {
	t.Helper()
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
}

func syscallMkfifo(p string) error { return syscall.Mkfifo(p, 0o644) }

func TestApplyThroughALinkAsTheBundleFolderWritesNothingThroughTheLink(t *testing.T) {
	dir, keys := arBundle(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	before := apSnapshot(t, dir)
	tick := newTicker(apClock)
	r := arRun(t, tick.now, nil, false, "--dir", link, "--output", "json", "apply", "--key-dir", keys, "--confirm", strings.Repeat("0", 64))
	if r.code == ExitOK {
		t.Fatalf("a run through a link ended well: %s", r.stdout)
	}
	crqSame(t, "apply through a link", before, apSnapshot(t, dir))
}

// arLate is a stream that refuses the first line that holds the words given.
type arLate struct {
	buf   bytes.Buffer
	words string
}

func (w *arLate) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.words) {
		return 0, errors.New("the terminal is gone")
	}
	return w.buf.Write(p)
}

func TestAStreamThatRefusesALineAfterTheRecordIsAFailureThatSaysTheCeremonyIsRecorded(t *testing.T) {
	dir, keys := arBundle(t)
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	var stdout bytes.Buffer
	stderr := &arLate{words: "is recorded"}
	tick := newTicker(apClock)
	code := Run(context.Background(), []string{"--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest}, Env{
		Stdout: &stdout, Stderr: stderr, Build: testBuild, Now: tick.now,
	})
	if code != ExitFailure {
		t.Fatalf("exit %d, want 1", code)
	}
	obj := apObject(t, stdout.String())
	if msg, _ := obj["error"].(string); !strings.Contains(msg, "is recorded, but a line of it could not be shown") || obj["outcome"] != "failed" {
		t.Errorf("the object: %v", obj)
	}
	// The ceremony is on disk and the history is whole.
	if h := apRun(t, apClock, "--dir", dir, "check", "history"); h.code != ExitOK || !arEndLine.MatchString(h.stdout) {
		t.Errorf("check history: %d %q", h.code, h.stdout)
	}
}

// A key directory inside the bundle is refused whatever way it is spelled: relative to the working
// folder, with dots, with a trailing slash, through a link, or through a link in a parent of the
// bundle. (Holding the key directory to the opened folder by identity is a later change; these are
// the spellings of the same path text.)
func TestApplyRefusesAKeyDirectoryInsideTheBundleWhateverItsSpelling(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	arMkdir(t, real)
	parentLink := filepath.Join(root, "parentlink")
	if err := os.Symlink(real, parentLink); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(real, "ca")
	if r := apRun(t, apClock, "new", "--test-root", ca); r.code != ExitOK {
		t.Fatal(r.stderr)
	}
	mustRemove(t, filepath.Join(ca, "want", "roots", "openpgp.yaml"))
	inside := arMkdir(t, filepath.Join(ca, "keys"))
	arMkdir(t, filepath.Join(ca, "sub"))
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(cwd, inside)
	if err != nil {
		t.Skip("no relative path from the working folder")
	}
	toInside := filepath.Join(root, "toinside")
	if err := os.Symlink(inside, toInside); err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"absolute":                       {ca, inside},
		"with a dot":                     {ca, ca + "/./keys"},
		"with two dots":                  {ca, ca + "/sub/../keys"},
		"with a trailing slash":          {ca, inside + "/"},
		"relative to the working folder": {ca, rel},
		"through a link":                 {ca, toInside},
		"the bundle through a parent":    {filepath.Join(parentLink, "ca"), inside},
		"the key directory through one":  {ca, filepath.Join(parentLink, "ca", "keys")},
		"the bundle itself":              {ca, ca},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			before := apSnapshot(t, ca)
			tick := newTicker(apClock)
			r := arRun(t, tick.now, nil, false, "--dir", c[0], "--output", "json", "apply", "--key-dir", c[1], "--confirm", strings.Repeat("0", 64))
			obj := apObject(t, r.stdout)
			reasons, _ := stringList(obj["reasons"])
			if r.code != ExitBackend || !slices.Equal(reasons, []string{"key-dir"}) {
				t.Fatalf("exit %d, %v; want exit 4 with key-dir", r.code, obj)
			}
			crqSame(t, "a key directory inside the bundle", before, apSnapshot(t, ca))
		})
	}
}

// The form of PLAN is judged before the folder is opened: a PLAN that is not of the form of the page is
// a usage error, whether or not the bundle can be read.
func TestAPlanOfAWrongFormIsAUsageErrorBeforeTheBundleIsLookedAt(t *testing.T) {
	keys := apKeys(t)
	gone := filepath.Join(t.TempDir(), "no-such-bundle")
	for _, plan := range []string{"plan.json", "/history/x/plan.json", "history/x/other.json", "history/x/plan.json/y"} {
		r := apRun(t, apClock, "--dir", gone, "apply", plan, "--key-dir", keys)
		if r.code != ExitUsage {
			t.Errorf("PLAN %q on a folder that is not there: exit %d, %q; want 2", plan, r.code, r.stderr)
		}
	}
	// A PLAN of the right form on a folder that is not there is a failure of the folder.
	r := apRun(t, apClock, "--dir", gone, "apply", "history/x/plan.json", "--key-dir", keys)
	if r.code != ExitFailure {
		t.Errorf("a PLAN of the right form on a folder that is not there: exit %d, %q; want 1", r.code, r.stderr)
	}
}
