package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// The member again (docs/reference/cli.md, "Machine-readable output"): true when the list is the
// list the host holds, byte for byte, coming again; absent otherwise. The text output has one line
// for it, directly after the line accepted. With initial pins nothing is held, so it can never be
// there.

func hasAgainLine(stdout string) bool {
	for _, l := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(l, "again:") {
			return true
		}
	}
	return false
}

func TestTheMemberAgainIsThereForTheHeldListAgainAndNowhereElse(t *testing.T) {
	m := vloadManifest(t)
	sawAgain, sawNew, sawPins := false, false, false
	for _, c := range m.Cases {
		if c.Expect != "accept" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			s := vstage(t, m, c)
			again := vagain(s)
			js := vrunAt(t, s.clock, s.args("json")...)
			txt := vrunAt(t, s.clock, s.args("text")...)
			obj := jsonObject(t, js)
			_, has := obj["again"]
			if has != again || (has && obj["again"] != true) {
				t.Errorf("the member again is %v (value %v); the list is the held one again: %v", has, obj["again"], again)
			}
			if hasAgainLine(txt.stdout) != again {
				t.Errorf("the line again is there: %v; want %v\n%s", hasAgainLine(txt.stdout), again, txt.stdout)
			}
			if again {
				lines := strings.Split(txt.stdout, "\n")
				if len(lines) < 3 || !strings.HasPrefix(lines[0], "accepted: ") || lines[1] != wantTextAgain {
					t.Errorf("the line is not directly after accepted: %q", lines)
				}
				sawAgain = true
			} else {
				sawNew = true
			}
			if s.held == "" {
				sawPins = true
				if has || hasAgainLine(txt.stdout) {
					t.Errorf("again with initial pins")
				}
			}
		})
	}
	if !sawAgain || !sawNew || !sawPins {
		t.Errorf("the manifest has an accepted list that is the held list again: %v, a new list: %v, a list against pins: %v", sawAgain, sawNew, sawPins)
	}
}

func TestTheMemberAgainIsNotInARefusalAFailureOrAUsageError(t *testing.T) {
	m := vloadManifest(t)
	for _, c := range m.Cases {
		if c.Expect != "refuse" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			s := vstage(t, m, c)
			for _, mode := range []string{"json", "text"} {
				r := vrunAt(t, s.clock, s.args(mode)...)
				if r.code != ExitRefused || strings.Contains(r.stdout, "again") || strings.Contains(r.stderr, "again") {
					t.Fatalf("%s: exit %d stdout %q stderr %q", mode, r.code, r.stdout, r.stderr)
				}
			}
		})
	}
	s := vstage(t, m, m.againCase(t))
	for name, r := range map[string]result{
		"a failure (the .jws is missing)": vrunAt(t, s.clock, "--output", "json", "verify", "root-list", filepath.Join(s.dir, "nosuch.json"), "--held", s.held),
		"a usage error":                   vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand),
	} {
		if strings.Contains(r.stdout, "again") || strings.Contains(r.stderr, "again") {
			t.Errorf("%s: stdout %q stderr %q", name, r.stdout, r.stderr)
		}
	}
}

func TestTheHeldListAgainInEveryFormTheManifestHas(t *testing.T) {
	m := vloadManifest(t)
	s := vstage(t, m, m.againCase(t))
	t.Run("after its expiry it is refused, the warning is given, and it is not again", func(t *testing.T) {
		clock := s.candList.ExpiresAt
		r := vrunAt(t, clock, s.args("json")...)
		warn := "ritueel: warning: held-expired\n"
		if r.code != ExitRefused || r.stdout != refusedObject("expired", "held-expired") || !strings.HasPrefix(r.stderr, warn+"ritueel: refused: expired (check 11: ") {
			t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
		x := vrunAt(t, clock, s.args("text")...)
		if x.code != ExitRefused || x.stdout != "" || x.stderr != r.stderr {
			t.Errorf("text: exit %d stdout %q stderr %q", x.code, x.stdout, x.stderr)
		}
	})
	t.Run("a changed byte of the held list is a conflict, and not again", func(t *testing.T) {
		held := vwrite(t, s.dir, "held-space.json", append(append([]byte{}, s.heldBytes...), ' '))
		r := vrunAt(t, s.clock, "--output", "json", "verify", "root-list", s.cand, "--held", held)
		if r.code != ExitRefused || r.stdout != refusedObject("sequence-conflict") || strings.Contains(r.stdout, "again") {
			t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("with the CA bundle of its list, it is again, and the bundle is the third entry", func(t *testing.T) {
		_, bundle, _ := m.bundleScene(t)
		// The scene of the held list again with a bundle that goes with its list (by sequence and roots).
		var data []byte
		for _, b := range m.Bundles {
			if b.Flaw == "" && b.Sequence == s.candList.Sequence {
				var want []string
				for _, l := range b.Roots {
					want = append(want, m.pin(t, l))
				}
				if strings.Join(want, ",") == strings.Join(s.candList.Pins(), ",") {
					data = m.bundleBytes(t, b.ID)
				}
			}
		}
		if data == nil {
			t.Fatalf("no bundle of the manifest goes with the list of %s (a bundle was found for another: %d bytes)", m.againCase(t).ID, len(bundle))
		}
		bs := *s
		bs.bundle, bs.bundleData = vwrite(t, s.dir, "bundle.pem", data), data
		r := vrunAt(t, s.clock, bs.args("json")...)
		if r.code != ExitOK || r.stdout != doneObjectAgain(nil, true, vfiles(&bs)...) {
			t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
		}
		x := vrunAt(t, s.clock, bs.args("text")...)
		if x.stdout != vacceptedText(&bs, true) || strings.Count(x.stdout, "\n") != 5 {
			t.Errorf("text %q", x.stdout)
		}
	})
}
