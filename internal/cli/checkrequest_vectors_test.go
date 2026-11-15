package cli

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// The command and the library must agree on every request case of the hand-off vectors. For each case a bundle
// is made on disk (the policy and the delegation of the case's configuration, a trust set of the vectors, the
// files of the request), the command runs on it through Run, and the library runs on the same case with the
// configuration the command builds for itself: no verifier and no primaries. The same exit code, the same
// reason code and the same nine results must come out. The cases that the library decides are then also
// compared with what the manifest says.

// listedConfig is the configuration whose lists name badly formed names on purpose. A delegation file is
// read by the loader of package wanted, which refuses such a name, so no bundle can hold these cases.
const listedConfig = "development-listed-names"

// listedCases is how many request cases use [listedConfig] (the manifest holds the same number).
const listedCases = 17

func TestEveryRequestCaseGivesThroughTheCommandWhatTheLibraryGives(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	ran, skipped, decided, undecided := 0, 0, 0, 0
	exits := map[ExitCode]int{}
	pgpExits := map[ExitCode]int{}
	for _, c := range m.Requests {
		if c.Config == listedConfig {
			skipped++
			continue
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			dir := crqBundle(t, m, c)
			before := crqSnapshot(t, dir)
			v, libErr := crqLibrary(t, m, c)

			r := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
			crqSame(t, "check request", before, crqSnapshot(t, dir))
			exits[r.code]++
			if c.Type == "openpgp-subkey" && r.code != ExitFailure {
				pgpExits[r.code]++
			}
			obj := object(t, r.stdout)
			if got, want := obj["command"], "check"; got != want {
				t.Errorf("command = %v, want %v", got, want)
			}

			// What the library says, as an exit code.
			var wantCode ExitCode
			switch {
			case libErr != nil:
				wantCode = ExitFailure
			case v.Accepted():
				wantCode = ExitOK
			case v.Refused():
				wantCode = ExitRefused
			default:
				t.Fatalf("the library gave neither an error, an acceptance nor a refusal for a request with a delegation: %+v", v)
			}
			if r.code != wantCode {
				t.Fatalf("exit code %d, the library says %d (error %v, code %q)\nstdout %s\nstderr %s", int(r.code), int(wantCode), libErr, v.Code, r.stdout, r.stderr)
			}

			switch wantCode {
			case ExitFailure:
				undecided++
				if _, ok := obj["checks"]; ok {
					t.Errorf("an exit code 1 has the member checks: %s", r.stdout)
				}
				if _, ok := obj["reasons"]; ok {
					t.Errorf("an exit code 1 has the member reasons: %s", r.stdout)
				}
				// The command stopped before it had nine results: no warning about the trust set, and none
				// of another kind.
				if w := stringsOf(obj["warnings"]); len(w) != 0 || r.stderr == "" || strings.Contains(r.stderr, "trust-set-unchecked") {
					t.Errorf("a request that stopped before nine results has the warnings %q and standard error %q", w, r.stderr)
				}
				if !errors.Is(libErr, handoff.ErrNoVerifier) && !errors.Is(libErr, handoff.ErrTypeNotBuilt) {
					t.Errorf("the library gave an error that is neither no verifier nor a type that is not built: %v", libErr)
				}
				if c.Type == "openpgp-subkey" {
					pgpExits[ExitFailure]++
					// An OpenPGP request that no check refused and that needs a card or a cloud key: the store has
					// no verifier, and the sentence says so; it is not the sentence about the primaries.
					if s, _ := obj["error"].(string); !errors.Is(libErr, handoff.ErrNoVerifier) || !strings.Contains(s, "no evidence verifier") || strings.Contains(s, "pins no OpenPGP primary") {
						t.Errorf("error = %q (library: %v), want no evidence verifier", s, libErr)
					}
				}
				if s, _ := obj["error"].(string); !strings.Contains(s, "request "+c.stem(t)+" is not accepted and not refused") {
					t.Errorf("error = %q, want the words that the request is not accepted and not refused", s)
				}
			case ExitOK, ExitRefused:
				got := crqChecks(t, obj)
				if len(got) != 9 {
					t.Fatalf("checks has %d entries, want 9: %v", len(got), got)
				}
				for i, ch := range v.Checks {
					if got[i][0] != strconv.Itoa(i+1) || got[i][1] != string(ch.Status) {
						t.Errorf("checks[%d] = %v, the library says check %d is %s", i, got[i], ch.N, ch.Status)
					}
				}
				// Every run with nine results, accepted or refused, has the one warning about the trust set.
				if w := stringsOf(obj["warnings"]); len(w) != 1 || w[0] != trustSetWarningText {
					t.Errorf("warnings = %q, want the one warning about the trust set", w)
				}
				if wantCode == ExitRefused {
					reasons, ok := stringList(obj["reasons"])
					if !ok || len(reasons) != 1 || reasons[0] != string(v.Code) {
						t.Errorf("reasons = %v, want [%s]", obj["reasons"], v.Code)
					}
					if !strings.HasPrefix(r.stderr, trustSetStderrLine+"ritueel: refused: "+string(v.Code)+" (check ") {
						t.Errorf("standard error = %q, want the warning about the trust set and then the refusal line of the code %s", r.stderr, v.Code)
					}
				} else if _, ok := obj["reasons"]; ok {
					t.Errorf("an accepted request has reasons: %s", r.stdout)
				}
				decided++
				// The manifest, for what the library decides.
				switch {
				case c.Confirmation == "declined":
					// Checks 1 to 9 accept; the person at the ceremony declines, which this command does not run.
					if c.Expect != "refuse" || c.Reason != "declined" || wantCode != ExitOK {
						t.Errorf("a declined case: manifest %s %s, exit code %d", c.Expect, c.Reason, int(r.code))
					}
				case c.Expect == "accept":
					if wantCode != ExitOK {
						t.Errorf("the manifest accepts the case, and the exit code is %d with the code %q", int(r.code), v.Code)
					}
				case c.Expect == "refuse":
					if wantCode != ExitRefused || string(v.Code) != c.Reason {
						t.Errorf("the manifest refuses the case with %q, and the exit code is %d with the code %q", c.Reason, int(r.code), v.Code)
					}
				default:
					t.Errorf("the manifest holds the expectation %q", c.Expect)
				}
			}
		})
	}

	if skipped != listedCases {
		t.Errorf("%d cases use the configuration %s, want %d", skipped, listedConfig, listedCases)
	}
	if ran+skipped != len(m.Requests) {
		t.Errorf("ran %d and skipped %d cases, the manifest holds %d", ran, skipped, len(m.Requests))
	}
	if decided+undecided != ran {
		t.Errorf("decided %d and undecided %d cases, ran %d", decided, undecided, ran)
	}
	for _, code := range []ExitCode{ExitOK, ExitFailure, ExitRefused} {
		if exits[code] == 0 {
			t.Errorf("no case ended with the exit code %d: the test would not see a fault of that kind", int(code))
		}
	}
	// The OpenPGP cases, counted by what is true: 14 are decided (2 accepted, 12 refused) and 6 are not, because
	// the command registers no verifier of a card or of a cloud key.
	if pgpExits[ExitOK] != 2 || pgpExits[ExitRefused] != 12 || pgpExits[ExitFailure] != 6 {
		t.Errorf("the OpenPGP cases ended as %v, want 2 accepted, 12 refused and 6 not judged", pgpExits)
	}
	t.Logf("%d request cases: %d run (%d decided, %d undecided by the library and the command alike), %d skipped; exit codes %v", len(m.Requests), ran, decided, undecided, skipped, exits)
}

// The cases that list badly formed names cannot be made into a bundle: the loader of the delegation file refuses
// each one, so the command stops with exit code 1 and names the list, and never runs a check.
func TestACaseThatListsABadNameIsStoppedByTheDelegationFile(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	n := 0
	for _, c := range m.Requests {
		if c.Config != listedConfig {
			continue
		}
		n++
		t.Run(c.ID, func(t *testing.T) {
			dir := crqBundle(t, m, c)
			r := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
			if r.code != ExitFailure {
				t.Fatalf("exit code %d, want 1\nstdout %s\nstderr %s", int(r.code), r.stdout, r.stderr)
			}
			obj := object(t, r.stdout)
			msg, _ := obj["error"].(string)
			if !strings.Contains(msg, "want/delegations/"+crqDelegation+".yaml") || !strings.Contains(msg, "permitted_") {
				t.Errorf("error = %q, want the delegation file and the list that holds the bad entry", msg)
			}
			if _, ok := obj["checks"]; ok {
				t.Errorf("a check ran: %s", r.stdout)
			}
		})
	}
	if n != listedCases {
		t.Errorf("%d cases list bad names, want %d", n, listedCases)
	}
}

// Without --delegation the rules of one delegation are not run: the request is neither accepted nor refused, so
// the command does not judge it and exits 1, whatever the library would say with a delegation. Check 9 says
// which rules were left out and the last line says what to give.
func TestWithNoDelegationAnAcceptedCaseIsNotJudgedAndARefusalOfAnEarlierRuleStays(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	const reason = "check 9 needs a delegation; give --delegation NAME"

	t.Run("x509-software-valid", func(t *testing.T) {
		dir, stem := crqBundleOf(t, "x509-software-valid")
		before := crqSnapshot(t, dir)
		js := crqRun(t, now, "check", "request", stem, "--dir", dir, "--output", "json")
		if js.code != ExitFailure {
			t.Fatalf("exit code %d, want 1\nstdout %s\nstderr %s", int(js.code), js.stdout, js.stderr)
		}
		obj := object(t, js.stdout)
		const wantWarning = "check 9: rules not run: delegation-type, name-constraints; give --delegation NAME"
		wantObject(t, withoutChecks(obj), map[string]any{
			"output": 1, "command": "check", "exit_code": 1, "outcome": "failed",
			"error":    "request " + stem + " is not accepted and not refused: " + reason,
			"warnings": []string{wantWarning, trustSetWarningText},
		})
		checks := crqChecks(t, obj)
		if len(checks) != 9 {
			t.Fatalf("checks = %v, want nine", checks)
		}
		for i, ch := range checks {
			want := "passed"
			if i == 8 {
				want = "not-run"
			}
			if ch[0] != strconv.Itoa(i+1) || ch[1] != want {
				t.Errorf("checks = %v, want 1 to 8 passed and 9 not-run", checks)
				break
			}
		}
		if _, ok := obj["reasons"]; ok {
			t.Errorf("a request that is not judged has reasons: %s", js.stdout)
		}
		if want := "ritueel: warning: " + wantWarning + "\n" + trustSetStderrLine + "ritueel: request " + stem + " is not accepted and not refused: " + reason + "\n"; js.stderr != want {
			t.Errorf("standard error = %q, want %q", js.stderr, want)
		}

		text := crqRun(t, now, "check", "request", stem, "--dir", dir)
		if text.code != ExitFailure {
			t.Fatalf("text: exit code %d", int(text.code))
		}
		if strings.Contains(text.stdout, "accepted") || strings.Contains(strings.TrimSuffix(text.stderr, "is not accepted and not refused: "+reason+"\n"), "accepted") {
			t.Errorf("a request with no delegation is called accepted:\n%s\n%s", text.stdout, text.stderr)
		}
		lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n")
		if len(lines) != 11 {
			t.Fatalf("standard output has %d lines, want 11: %q", len(lines), text.stdout)
		}
		contract := contractChecks(t)
		for i := 0; i < 8; i++ {
			if want := "check " + strconv.Itoa(i+1) + ": passed: " + contract[i].name; lines[i] != want {
				t.Errorf("line %d = %q, want %q", i+1, lines[i], want)
			}
		}
		if want := "check 9: not-run: " + contract[8].name + " (rules not run: delegation-type, name-constraints)"; lines[8] != want {
			t.Errorf("line 9 = %q, want %q", lines[8], want)
		}
		if lines[9] != "check 10: not made here; the person at the ceremony confirms" {
			t.Errorf("line 10 = %q", lines[9])
		}
		if want := "request " + stem + ": not complete: " + reason; lines[10] != want {
			t.Errorf("the last line = %q, want %q", lines[10], want)
		}
		crqSame(t, "check request", before, crqSnapshot(t, dir))
	})

	t.Run("a delegation whose lists do not hold the names of the request", func(t *testing.T) {
		// The software case with the lists of the delegation changed to other names: the delegation refuses
		// it with the code policy; with no delegation named that rule is not run, so the request is neither
		// refused nor accepted, and the command does not judge it: it never exits 0 for it.
		c := m.byID(t, "x509-software-valid")
		tree := crqBundleTree(t, m, c)
		tree["want/delegations/"+crqDelegation+".yaml"] = []byte("version: 1\ntype: x509-intermediate\nroot: " + crqRoot + "\npermitted_uri_hosts: [other.example.org]\npermitted_dns_names: [other.example.org]\n")
		dir := t.TempDir()
		crqWrite(t, dir, tree)
		with := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
		if with.code != ExitRefused {
			t.Fatalf("with the delegation: exit code %d, want 3\n%s%s", int(with.code), with.stdout, with.stderr)
		}
		if got := crqChecks(t, object(t, with.stdout)); got[8][1] != "failed" {
			t.Errorf("with the delegation, check 9 = %v, want failed", got[8])
		}
		without := crqRun(t, now, "check", "request", c.stem(t), "--dir", dir, "--output", "json")
		if without.code != ExitFailure {
			t.Fatalf("without the delegation: exit code %d, want 1\n%s%s", int(without.code), without.stdout, without.stderr)
		}
		obj := object(t, without.stdout)
		if _, ok := obj["reasons"]; ok {
			t.Errorf("reasons without a delegation: %s", without.stdout)
		}
		if got := crqChecks(t, obj); got[8][1] != "not-run" {
			t.Errorf("check 9 = %v, want not-run", got[8])
		}
		if obj["outcome"] != "failed" {
			t.Errorf("outcome = %v, want failed", obj["outcome"])
		}
	})

	t.Run("a request of a store with no verifier is exit 1 with or without a delegation", func(t *testing.T) {
		// x509-name-constraint-outside is a piv case: it never reaches check 9 in a command that registers no
		// verifier of a card.
		c := m.byID(t, "x509-name-constraint-outside")
		dir := crqBundle(t, m, c)
		for _, args := range [][]string{{"--delegation", crqDelegation}, {}} {
			r := crqRun(t, now, append([]string{"check", "request", c.stem(t), "--dir", dir}, args...)...)
			if r.code != ExitFailure {
				t.Errorf("%v: exit code %d, want 1\n%s%s", args, int(r.code), r.stdout, r.stderr)
			}
		}
	})

	t.Run("a refusal of a rule that needs no delegation stays a refusal", func(t *testing.T) {
		for _, id := range []string{"x509-csr-bad-signature", "x509-eku-missing", "x509-request-root-key"} {
			c := m.byID(t, id)
			dir := crqBundle(t, m, c)
			r := crqRun(t, now, "check", "request", c.stem(t), "--dir", dir, "--output", "json")
			if r.code != ExitRefused {
				t.Errorf("%s: exit code %d, want 3\n%s%s", id, int(r.code), r.stdout, r.stderr)
			}
		}
	})
}

// A check is never reported by a count that the test holds: it is the manifest that says how many cases there
// are, and the formula is the same for every later part that decides more cases.
func TestTheCountsOfTheCasesAddUp(t *testing.T) {
	m := crqManifestOf(t)
	byConfig := map[string]int{}
	for _, c := range m.Requests {
		byConfig[c.Config]++
	}
	if byConfig[listedConfig] != listedCases {
		t.Errorf("the manifest has %d cases of %s, want %d", byConfig[listedConfig], listedConfig, listedCases)
	}
	total := 0
	for _, n := range byConfig {
		total += n
	}
	if total != len(m.Requests) {
		t.Errorf("%d cases in the configurations, %d in the manifest", total, len(m.Requests))
	}
}

// With no --delegation the command and the library, built the same way with no delegation, agree on every request
// case: a refusal by a rule that needs no delegation is the same exit code 3, the same code and the same nine
// results; an error of the library is exit code 1 with no results; and a request that nothing refused is exit
// code 1 with the nine results, check 9 not run, and the words that a delegation is needed. Never exit code 0.
func TestEveryRequestCaseWithNoDelegationGivesThroughTheCommandWhatTheLibraryGives(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	kinds := map[string]int{}
	for _, c := range m.Requests {
		if c.Config == listedConfig {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			dir := crqBundle(t, m, c)
			before := crqSnapshot(t, dir)
			v, libErr := crqLibraryWith(t, m, c, false)
			r := crqRun(t, now, "check", "request", c.stem(t), "--dir", dir, "--output", "json")
			crqSame(t, "check request", before, crqSnapshot(t, dir))
			obj := object(t, r.stdout)
			if r.code == ExitOK {
				t.Fatalf("exit code 0 for a request with no delegation\n%s%s", r.stdout, r.stderr)
			}
			switch {
			case libErr != nil:
				kinds["error"]++
				if r.code != ExitFailure {
					t.Fatalf("the library gave %v and the exit code is %d\n%s%s", libErr, int(r.code), r.stdout, r.stderr)
				}
				if _, ok := obj["checks"]; ok {
					t.Errorf("an error of the library has checks: %s", r.stdout)
				}
				if w := stringsOf(obj["warnings"]); len(w) != 0 || strings.Contains(r.stderr, "trust-set-unchecked") {
					t.Errorf("a run that stopped before nine results has the warnings %q and standard error %q", w, r.stderr)
				}
				if msg, _ := obj["error"].(string); !strings.Contains(msg, "request "+c.stem(t)+" is not accepted and not refused") {
					t.Errorf("error = %q", msg)
				}
				if msg, _ := obj["error"].(string); !errors.Is(libErr, handoff.ErrNoVerifier) && !errors.Is(libErr, handoff.ErrTypeNotBuilt) || strings.Contains(msg, "pins no OpenPGP primary") {
					t.Errorf("the library gave %v and the error is %q: a trust set that pins primaries never gives the sentence about none", libErr, msg)
				}
			case v.Refused():
				kinds["refused"]++
				if r.code != ExitRefused {
					t.Fatalf("the library refuses with %q and the exit code is %d\n%s%s", v.Code, int(r.code), r.stdout, r.stderr)
				}
				if reasons, _ := stringList(obj["reasons"]); len(reasons) != 1 || reasons[0] != string(v.Code) {
					t.Errorf("reasons = %v, want [%s]", obj["reasons"], v.Code)
				}
				if w := stringsOf(obj["warnings"]); len(w) != 1 || w[0] != trustSetWarningText {
					t.Errorf("warnings = %q, want the one warning about the trust set", w)
				}
				got := crqChecks(t, obj)
				for i, ch := range v.Checks {
					if got[i][1] != string(ch.Status) {
						t.Errorf("check %d is %s, the library says %s", i+1, got[i][1], ch.Status)
					}
				}
			default:
				kinds["not complete"]++
				if v.Accepted() {
					t.Fatal("the library accepts a request with no delegation")
				}
				if r.code != ExitFailure {
					t.Fatalf("the library does not judge the case and the exit code is %d\n%s%s", int(r.code), r.stdout, r.stderr)
				}
				got := crqChecks(t, obj)
				if len(got) != 9 || got[8][1] != "not-run" {
					t.Fatalf("checks = %v, want nine with check 9 not run", got)
				}
				for i, ch := range v.Checks {
					if got[i][1] != string(ch.Status) {
						t.Errorf("check %d is %s, the library says %s", i+1, got[i][1], ch.Status)
					}
				}
				if msg, _ := obj["error"].(string); !strings.HasSuffix(msg, "check 9 needs a delegation; give --delegation NAME") {
					t.Errorf("error = %q", msg)
				}
				if w := stringsOf(obj["warnings"]); len(w) < 2 || w[len(w)-1] != trustSetWarningText || strings.Contains(strings.Join(w[:len(w)-1], "\n"), "trust-set-unchecked") {
					t.Errorf("warnings = %q, want the ones of the rules and then, last and once, the one about the trust set", w)
				}
			}
		})
	}
	for _, k := range []string{"error", "refused", "not complete"} {
		if kinds[k] == 0 {
			t.Errorf("no case ended as %q: the test would not see a fault of that kind (%v)", k, kinds)
		}
	}
	t.Logf("with no delegation: %v", kinds)
}
