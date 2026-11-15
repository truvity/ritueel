//go:build linux || darwin

package cli

import (
	"strings"
	"testing"
)

// FuzzApplyArguments runs apply with a plan path, a key directory and a confirmation that come from
// the input, on a bundle that is not changed by a run that is not confirmed: no panic, one of the exit
// codes of the page, plain ASCII text, and the same tree afterwards. The digest of a plan is not in
// the input, so a run that gets as far as the confirmation is not confirmed.
func FuzzApplyArguments(f *testing.F) {
	dir, keys := arBundle(f)
	path, right := arPlan(f, apClock, dir, "--key-dir", keys)
	// The seeds hold a digest that is wrong in its last digit: an input that is the right digest of
	// the plan would run it, and this target never confirms.
	digest := right[:63] + map[bool]string{true: "1", false: "0"}[right[63] == '0']
	for _, s := range [][3]string{
		{path, keys, digest[:8]}, {path, keys, "x"}, {"", keys, ""}, {"plan.json", keys, digest},
		{path, "", digest}, {path, dir, digest}, {path + "/", keys, digest}, {"history/../" + path, keys, digest},
		{path, keys + "/..", digest}, {"\xff", "\x00", "\n"}, {strings.Repeat("a/", 40) + "plan.json", keys, digest},
		{path, strings.Repeat("k", 5000), digest}, {"-" + path, keys, digest},
	} {
		f.Add(s[0], s[1], s[2], false)
	}
	before, keysBefore := apSnapshot(f, dir), apSnapshot(f, keys)
	f.Fuzz(func(t *testing.T, plan, key, confirm string, withPlan bool) {
		args := []string{"--dir", dir, "--output", "json", "apply", "--key-dir=" + key, "--confirm=" + confirm}
		if withPlan || plan != "" {
			args = append(args, "--", plan)
		}
		tick := newTicker(apClock)
		r := arRun(t, tick.now, strings.NewReader(""), false, args...)
		switch r.code {
		case ExitUsage, ExitFailure, ExitRefused, ExitBackend, ExitNotConfirmed:
		case ExitOK:
			// Only a run that was confirmed, which needs the digest of a plan that the input does not hold,
			// or one with nothing to apply.
			t.Fatalf("exit 0 for %q: %s", args, r.stdout)
		default:
			t.Fatalf("exit %d", r.code)
		}
		if !apPrintable(strings.TrimSuffix(r.stdout, "\n")) {
			t.Fatalf("standard output is not printable ASCII: %+q", r.stdout)
		}
		if got := apSnapshot(t, dir); strings.Join(got, "\n") != strings.Join(before, "\n") {
			t.Fatalf("a run that was not confirmed changed the bundle")
		}
		if got := apSnapshot(t, keys); strings.Join(got, "\n") != strings.Join(keysBefore, "\n") {
			t.Fatalf("a run that was not confirmed changed the key directory")
		}
	})
}
