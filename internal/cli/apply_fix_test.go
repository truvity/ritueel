//go:build linux || darwin

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The flags of apply that are given twice, and a plan that two runs start. The names of this file start
// with af.

func TestAFlagOfApplyThatIsGivenTwiceIsExitCode2InEverySpellingAndNothingIsRead(t *testing.T) {
	type spelling struct {
		flag string
		args func(d, k string) []string
	}
	cases := []spelling{
		{"confirm", func(d, k string) []string { return []string{"--confirm", d, "--confirm", d} }},
		{"confirm", func(d, k string) []string { return []string{"--confirm=" + d, "--confirm", d} }},
		{"confirm", func(d, k string) []string { return []string{"--confirm", d, "--confirm=" + strings.Repeat("0", 64)} }},
		{"confirm", func(d, k string) []string { return []string{"--confirm=" + d, "--confirm=" + d} }},
		{"key-dir", func(d, k string) []string { return []string{"--key-dir", k, "--key-dir", k, "--confirm", d} }},
		{"key-dir", func(d, k string) []string {
			return []string{"--key-dir=" + k, "--key-dir", k + "-other", "--confirm", d}
		}},
		{"key-dir", func(d, k string) []string { return []string{"--confirm", d, "--key-dir", k, "--key-dir=" + k} }},
		{"plan-only", func(d, k string) []string { return []string{"--plan-only", "--plan-only"} }},
		{"plan-only", func(d, k string) []string { return []string{"--plan-only=true", "--plan-only"} }},
		{"plan-only", func(d, k string) []string { return []string{"--plan-only", "--plan-only=false"} }},
	}
	for i, c := range cases {
		for _, mode := range []string{"direct", "saved", "no bundle"} {
			t.Run(c.flag+" "+rtN(i)+" "+mode, func(t *testing.T) {
				dir, keys := arBundle(t)
				path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
				before, keysBefore := apSnapshot(t, dir), apSnapshot(t, keys)
				args := []string{"--dir", dir, "--output", "json", "apply"}
				switch mode {
				case "saved":
					args = append(args, path)
				case "no bundle":
					// Nothing is read: a bundle that does not exist is not looked at.
					args[1] = filepath.Join(t.TempDir(), "nowhere")
				}
				args = append(args, c.args(digest, keys)...)
				in := &arCount{r: strings.NewReader(digest[:8] + "\n")}
				tick := newTicker(apClock)
				r := arRun(t, tick.now, in, true, args...)
				obj := apObject(t, r.stdout)
				msg, _ := obj["error"].(string)
				if r.code != ExitUsage || obj["outcome"] != "usage" || msg != "--"+c.flag+" is given once" {
					t.Fatalf("exit %d, %v; want a usage error that says --%s is given once", r.code, obj, c.flag)
				}
				if in.reads.Load() != 0 {
					t.Errorf("standard input was read %d times", in.reads.Load())
				}
				if _, ok := obj["reasons"]; ok {
					t.Errorf("a usage error has reasons: %v", obj)
				}
				if tick.t.Load() != 0 {
					t.Errorf("the clock was read %d times", tick.t.Load())
				}
				crqSame(t, "a flag given twice", before, apSnapshot(t, dir))
				crqSame(t, "a flag given twice (keys)", keysBefore, apSnapshot(t, keys))
			})
		}
	}
}

func rtN(i int) string { return string(rune('a' + i)) }

func TestEachFlagOfApplyGivenOnceWorksInAnyOrderAndSpelling(t *testing.T) {
	for i, order := range [][]string{
		{"--confirm", "{D}", "--key-dir", "{K}"},
		{"--key-dir", "{K}", "--confirm", "{D}"},
		{"--confirm={D}", "--key-dir={K}"},
		{"--key-dir={K}", "--confirm", "{D}"},
	} {
		for _, planFirst := range []bool{true, false} {
			t.Run(rtN(i)+map[bool]string{true: " plan first", false: " plan last"}[planFirst], func(t *testing.T) {
				dir, keys := arBundle(t)
				path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
				var args []string
				for _, a := range order {
					args = append(args, strings.NewReplacer("{D}", digest, "{K}", keys).Replace(a))
				}
				if planFirst {
					args = append([]string{path}, args...)
				} else {
					args = append(args, path)
				}
				r := arRun(t, newTicker(apClock).now, nil, false, append([]string{"--dir", dir, "apply"}, args...)...)
				if r.code != ExitOK {
					t.Fatalf("exit %d: %s", r.code, r.stderr)
				}
			})
		}
	}
	t.Run("--plan-only once", func(t *testing.T) {
		dir, keys := arBundle(t)
		r := arRun(t, newTicker(apClock).now, nil, false, "--dir", dir, "apply", "--plan-only", "--key-dir", keys)
		if r.code != ExitOK {
			t.Fatalf("exit %d: %s", r.code, r.stderr)
		}
	})
}

func TestTheLoserOfTwoRunsOfOneSavedPlanIsExitCode3WithPlanUsedAndMakesNoKey(t *testing.T) {
	dir, keys := arBundle(t)
	keysB := filepath.Join(filepath.Dir(keys), "keys-b")
	if err := os.Mkdir(keysB, 0o700); err != nil {
		t.Fatal(err)
	}
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	var bRan atomic.Bool
	var b result
	// The clock of the first run is read for the preflight, for the time of the confirmation and then
	// for the time of the attempt. At the third reading the other run makes its whole ceremony, so that
	// the attempt of the first run finds the name taken.
	var calls atomic.Int32
	tick := newTicker(apClock)
	clock := func() time.Time {
		if calls.Add(1) == 3 {
			bRan.Store(true)
			b = arRun(t, newTicker(apClock).now, nil, false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keysB, "--confirm", digest)
		}
		return tick.now()
	}
	a := arRun(t, clock, nil, false, "--dir", dir, "--output", "json", "apply", path, "--key-dir", keys, "--confirm", digest)
	if !bRan.Load() || b.code != ExitOK {
		t.Fatalf("the other run: ran %v, exit %d, %s", bRan.Load(), b.code, b.stderr)
	}
	obj := apObject(t, a.stdout)
	reasons, _ := stringList(obj["reasons"])
	if a.code != ExitRefused || obj["outcome"] != "refused" || obj["exit_code"].(json.Number).String() != "3" || !slices.Equal(reasons, []string{"plan-used"}) {
		t.Fatalf("exit %d, %v; want refused with plan-used", a.code, obj)
	}
	if _, ok := obj["error"]; ok {
		t.Errorf("a refusal has an error member: %v", obj)
	}
	if !strings.Contains(a.stderr, "wrote no attempt and made no key") {
		t.Errorf("standard error does not say that this run made no key: %q", a.stderr)
	}
	if ents, _ := os.ReadDir(keys); len(ents) != 0 {
		t.Errorf("the key directory of the loser holds %d entries", len(ents))
	}
	if ents, _ := os.ReadDir(keysB); len(ents) != 4 {
		t.Errorf("the key directory of the winner holds %d entries, want 4", len(ents))
	}
	h := apRun(t, apClock, "--dir", dir, "check", "history")
	if h.code != ExitOK {
		t.Errorf("check history after the two runs: exit %d %s", h.code, h.stderr)
	}
}

func TestTheRefusalWithPlanUsedIsTheLastLineOfTheTextForm(t *testing.T) {
	dir, keys := arBundle(t)
	keysB := filepath.Join(filepath.Dir(keys), "keys-b")
	if err := os.Mkdir(keysB, 0o700); err != nil {
		t.Fatal(err)
	}
	path, digest := arPlan(t, apClock, dir, "--key-dir", keys)
	var calls atomic.Int32
	tick := newTicker(apClock)
	clock := func() time.Time {
		if calls.Add(1) == 3 {
			arRun(t, newTicker(apClock).now, nil, false, "--dir", dir, "apply", path, "--key-dir", keysB, "--confirm", digest)
		}
		return tick.now()
	}
	a := arRun(t, clock, nil, false, "--dir", dir, "apply", path, "--key-dir", keys, "--confirm", digest)
	if a.code != ExitRefused || !strings.HasSuffix(a.stderr, "ritueel: history/20261120T100000Z-apply holds an attempt.json already, so another run of this plan was first; this run wrote no attempt and made no key, and the attempt of the other run was not changed; look at the folder and at ritueel check history\n") || a.stdout != "" {
		t.Errorf("exit %d, stdout %q, stderr tail %q", a.code, a.stdout, a.stderr[max(0, len(a.stderr)-500):])
	}
}

// FuzzApplyRepeatedFlags builds the flags of apply from the bytes of the input: each byte is one flag
// with a value, in one of the two spellings. When the same flag of the three is there twice or more, the
// run is exit code 2 and says which flag, in the order confirm, key-dir, plan-only, and nothing changes
// and nothing is read, whatever the values are. A list with no repeated flag is not run: it can write.
func FuzzApplyRepeatedFlags(f *testing.F) {
	dir, keys := arBundle(f)
	path, digest := arPlan(f, apClock, dir, "--key-dir", keys)
	for _, s := range [][]byte{{0, 0}, {1, 1}, {2, 2}, {0, 3}, {4, 5, 2}, {2, 8}, {6, 7, 6}, {9, 9, 9}} {
		f.Add(s, path)
	}
	before, keysBefore := apSnapshot(f, dir), apSnapshot(f, keys)
	units := func(b byte) (name string, args []string) {
		values := []string{digest, "x", "", keys, strings.Repeat("0", 64)}
		v := values[int(b/6)%len(values)]
		switch b % 6 {
		case 0:
			return "confirm", []string{"--confirm", v}
		case 1:
			return "confirm", []string{"--confirm=" + v}
		case 2:
			return "key-dir", []string{"--key-dir", v}
		case 3:
			return "key-dir", []string{"--key-dir=" + v}
		case 4:
			return "plan-only", []string{"--plan-only"}
		}
		return "plan-only", []string{"--plan-only=" + []string{"true", "false"}[int(b/6)%2]}
	}
	f.Fuzz(func(t *testing.T, sel []byte, plan string) {
		if len(sel) > 12 {
			t.Skip()
		}
		count := map[string]int{}
		args := []string{"--dir", dir, "--output", "json", "apply"}
		for _, b := range sel {
			name, a := units(b)
			count[name]++
			args = append(args, a...)
		}
		want := ""
		for _, name := range []string{"confirm", "key-dir", "plan-only"} {
			if count[name] > 1 {
				want = "--" + name + " is given once"
				break
			}
		}
		if want == "" {
			t.Skip()
		}
		if plan != "" {
			// After "--" the argument is never read as a flag, whatever its first characters are.
			args = append(args, "--", plan)
		}
		in := &arCount{r: strings.NewReader(digest[:8] + "\n")}
		tick := newTicker(apClock)
		r := arRun(t, tick.now, in, true, args...)
		obj := apObject(t, r.stdout)
		if msg, _ := obj["error"].(string); r.code != ExitUsage || msg != want {
			t.Fatalf("%q: exit %d, %v; want a usage error %q", args, r.code, obj, want)
		}
		if in.reads.Load() != 0 || tick.t.Load() != 0 {
			t.Fatalf("%q: input read %d times, clock read %d times", args, in.reads.Load(), tick.t.Load())
		}
		if strings.Join(apSnapshot(t, dir), "\n") != strings.Join(before, "\n") || strings.Join(apSnapshot(t, keys), "\n") != strings.Join(keysBefore, "\n") {
			t.Fatalf("%q: a run that is a usage error changed a folder", args)
		}
	})
}
