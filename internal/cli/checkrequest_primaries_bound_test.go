//go:build linux || darwin

package cli

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// A root list holds up to 26 entries (one for each label A to Z) and each may pin one OpenPGP primary. "check request"
// takes every list that the trust set writer and the reader of lists accept: a bundle whose newest list pins 16, 17,
// 20 or 26 primaries is judged the same way. The requests of the vectors name two primaries and are signed for them
// only, so beside a list of more the request is refused at check 3 with unknown-primary, and the sentence of the
// refusal says how many active primaries the list has: the checker was made for all of them.

// theMostRoots are the roots of a full list, made once for the tests of this file and of the tests that need them: a key
// of P-384 is made for each of the 26 and the keys are not changed afterwards.
var (
	theMostRootsOnce sync.Once
	theMostRootsList []memRoot
)

// theMostRoots gives a copy of the list of roots, so a test may change its own copy.
func theMostRoots(t testing.TB) []memRoot {
	t.Helper()
	theMostRootsOnce.Do(func() { theMostRootsList = memRoots(t, handoff.MaxPrimaries) })
	if len(theMostRootsList) != handoff.MaxPrimaries {
		t.Fatalf("the roots of a full list were not made")
	}
	return slices.Clone(theMostRootsList)
}

func TestARootListThatPinsManyPrimariesIsJudgedAsOneThatPinsSixteenWas(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "pgp-software-valid")
	type outcome struct {
		code    ExitCode
		stdout  string // the text, with the count of the list taken out
		reasons []string
		checks  [][2]string
	}
	judge := func(t *testing.T, n int, delegation bool) (text, js result, dir string) {
		t.Helper()
		dir = t.TempDir()
		crqWrite(t, dir, crqWithTrust(crqBundleTree(t, m, c), memTrustOf(theMostRoots(t)[:n])))
		args := []string{"check", "request", c.stem(t), "--dir", dir}
		if delegation {
			args = append(args, "--delegation", crqDelegation)
		}
		return crqRun(t, now, args...), crqRun(t, now, append(slices.Clone(args), "--output", "json")...), dir
	}
	reference := map[bool]outcome{}
	for _, n := range []int{16, 17, 20, handoff.MaxPrimaries} {
		for _, delegation := range []bool{true, false} {
			t.Run(fmt.Sprintf("%d/delegation=%v", n, delegation), func(t *testing.T) {
				text, js, dir := judge(t, n, delegation)
				before := crqSnapshot(t, dir)
				if text.code != ExitRefused || js.code != ExitRefused {
					t.Fatalf("exit codes %d and %d, want %d\n%s%s", int(text.code), int(js.code), int(ExitRefused), text.stderr, js.stderr)
				}
				wantReason := fmt.Sprintf("ritueel: refused: unknown-primary (check 3: primaries lists 2 fingerprints and the root list has %d active primaries)\n", n)
				for _, r := range []result{text, js} {
					if !strings.HasSuffix(r.stderr, wantReason) || !onlyPrintable(r.stderr) {
						t.Errorf("standard error = %q, want it to end with %q", r.stderr, wantReason)
					}
					for _, bad := range []string{"checks take", "not accepted and not refused", "keyring.gpg"} {
						if strings.Contains(r.stderr, bad) {
							t.Errorf("standard error %q holds %q", r.stderr, bad)
						}
					}
				}
				lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n")
				if len(lines) != 11 || lines[10] != "request "+c.stem(t)+": refused: unknown-primary" {
					t.Fatalf("standard output = %q", text.stdout)
				}
				obj := object(t, js.stdout)
				got := outcome{code: text.code, stdout: text.stdout, reasons: stringsOf(obj["reasons"]), checks: crqChecks(t, obj)}
				if !slices.Equal(got.reasons, []string{"unknown-primary"}) || len(got.checks) != 9 {
					t.Fatalf("object = %s", js.stdout)
				}
				for i, want := range []string{"passed", "passed", "failed", "not-run", "not-run", "not-run", "not-run", "not-run", "not-run"} {
					if got.checks[i][1] != want {
						t.Errorf("check %d is %s, want %s: %s", i+1, got.checks[i][1], want, js.stdout)
					}
				}
				// What the verdict says does not depend on the count: it is what it was for 16.
				if n == 16 {
					reference[delegation] = got
				} else if ref, ok := reference[delegation]; ok && (ref.stdout != got.stdout || !slices.Equal(ref.checks, got.checks) || ref.code != got.code) {
					t.Errorf("%d primaries: the verdict is %q, for 16 it was %q", n, got.stdout, ref.stdout)
				}
				crqSame(t, "check request", before, crqSnapshot(t, dir))
			})
		}
	}
}

// A request that the list fits is accepted whatever else the trust set pins: the two primaries of the vectors with no
// other entry are the control of the tests above.
func TestTheControlOfTheRootListThatPinsTwoPrimariesIsAccepted(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	dir := crqBundle(t, m, c)
	r := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir)
	if r.code != ExitOK {
		t.Errorf("(%d, %q, %q), want exit code 0", int(r.code), r.stdout, r.stderr)
	}
}
