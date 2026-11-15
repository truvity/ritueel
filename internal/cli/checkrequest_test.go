//go:build linux || darwin

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"ritueel.id/ritueel/internal/testrepo"
)

// "check request STEM [--delegation NAME]" through Run, on bundles made on disk from the hand-off vectors. The
// meaning of each result is the one of docs/reference/cli.md ("The first version's commands" and "Machine-readable
// output") and of the contract ("What the certifier checks"): checks 1 to 9, the code of the first check that
// refuses, and a request that a delegation rule was not run for is never reported as accepted.

// contractCheck is a row of the table of the nine checks of the contract.
type contractCheck struct {
	n    int
	name string
	code string
}

// contractChecks reads the table "What the certifier checks" of the contract page: the number, the name and the
// code of each of the nine checks. The names that the command prints are these, so a rename of a check on the
// page or in the library shows up here.
func contractChecks(t testing.TB) []contractCheck {
	t.Helper()
	page := string(testrepo.Read(t, "docs", "reference", "hand-off-contract.md"))
	_, rest, ok := strings.Cut(page, "### What the certifier checks\n")
	if !ok {
		t.Fatal("the contract page has no section \"What the certifier checks\"")
	}
	row := regexp.MustCompile("(?m)^\\| ([1-9]) \\| (.+?)\\.? \\| `([a-z-]+)` \\|$")
	var out []contractCheck
	for _, m := range row.FindAllStringSubmatch(rest, -1) {
		n, _ := strconv.Atoi(m[1])
		if n != len(out)+1 {
			break
		}
		// The cell says "The evidence is valid, as below": the words after the comma point at a paragraph.
		name, _, _ := strings.Cut(strings.ReplaceAll(m[2], "`", ""), ", as below")
		out = append(out, contractCheck{n: n, name: name, code: m[3]})
	}
	if len(out) != 9 {
		t.Fatalf("read %d checks from the contract page, want 9", len(out))
	}
	return out
}

// withoutChecks is the object with the member checks taken out: its entries are read by crqChecks.
func withoutChecks(obj map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range obj {
		if k != "checks" {
			out[k] = v
		}
	}
	return out
}

// contractCodeOfCheck maps each reason code of the contract table to the number of its check.
func contractCodeOfCheck(t testing.TB) map[string]int {
	out := map[string]int{}
	for _, c := range contractChecks(t) {
		out[c.code] = c.n
	}
	return out
}

func TestTheContractTableIsReadAsTheNineChecks(t *testing.T) {
	cs := contractChecks(t)
	if cs[0].name != "The contract version is known" || cs[0].code != "version-unsupported" || cs[8].code != "policy" {
		t.Errorf("the table was read as %+v", cs)
	}
}

// ---- accepted -----------------------------------------------------------------------------------

// acceptedWarning is the one warning of an accepted run: the roots were read from the newest trust set, and the
// command does not check that set's signature file or its expiry. A run that is not accepted has none.
const acceptedWarning = "trust-set-unchecked: this command did not check the signature and the expiry of the trust set that the roots were read from"

const acceptedStderr = "ritueel: warning: " + acceptedWarning + "\n"

func TestAnAcceptedRequestIsExitZeroWithNinePassedChecksAndTheLastLine(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	dir, stem := crqBundleOf(t, "x509-software-valid")
	before := crqSnapshot(t, dir)
	checks := contractChecks(t)

	text := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir)
	if text.code != ExitOK || text.stderr != acceptedStderr {
		t.Fatalf("text: (%d, %q), want only the one warning of an accepted run", int(text.code), text.stderr)
	}
	var want strings.Builder
	for _, c := range checks {
		want.WriteString("check " + strconv.Itoa(c.n) + ": passed: " + c.name + "\n")
	}
	want.WriteString("check 10: not made here; the person at the ceremony confirms\n")
	want.WriteString("request " + stem + ": accepted\n")
	if text.stdout != want.String() {
		t.Errorf("standard output =\n%s\nwant\n%s", text.stdout, want.String())
	}

	js := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir, "--output", "json")
	if js.code != ExitOK || js.stderr != acceptedStderr {
		t.Fatalf("json: (%d, %q), want only the one warning of an accepted run", int(js.code), js.stderr)
	}
	obj := object(t, js.stdout)
	got := crqChecks(t, obj)
	wantObject(t, withoutChecks(obj), map[string]any{"output": 1, "command": "check", "exit_code": 0, "outcome": "done", "warnings": []string{acceptedWarning}})
	if len(got) != 9 {
		t.Fatalf("checks = %v", got)
	}
	for i, c := range got {
		if c[0] != strconv.Itoa(i+1) || c[1] != "passed" {
			t.Errorf("checks[%d] = %v, want passed", i, c)
		}
	}
	crqSame(t, "check request", before, crqSnapshot(t, dir))
}

// An answer file beside the request is not read and does not stop the check: that refusal belongs to apply.
func TestAnAnswerFileBesideTheRequestDoesNotStopTheCheck(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "x509-software-valid")
	for _, name := range []string{"result.json", "bound.pem", "cert.pem"} {
		t.Run(name, func(t *testing.T) {
			tree := crqBundleTree(t, m, c)
			tree["requests/"+c.stem(t)+"/"+c.stem(t)+"."+name] = []byte("not an answer, not json, not read")
			dir := t.TempDir()
			crqWrite(t, dir, tree)
			r := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
			if r.code != ExitOK {
				t.Errorf("exit code %d\n%s%s", int(r.code), r.stdout, r.stderr)
			}
		})
	}
}

// ---- refused: each code the library reaches with no verifier -------------------------------------

func TestEachRefusalCodeIsExitThreeWithTheCheckThatRefused(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	numberOf := contractCodeOfCheck(t)
	checks := contractChecks(t)
	// proof-invalid and key-mismatch need the evidence of a store: this command registers no verifier of a
	// card or of a cloud key, so no request reaches them here.
	for _, tc := range []struct{ id, code string }{
		{"x509-version-2", "version-unsupported"},
		{"x509-unknown-member", "malformed"},
		{"x509-request-mismatch", "request-mismatch"},
		{"x509-p256", "algorithm-unsupported"},
		{"x509-csr-bad-signature", "possession-invalid"},
		{"x509-software-in-production", "store-not-allowed"},
		{"x509-eku-missing", "policy"},
		{"x509-request-root-key", "policy"},
	} {
		t.Run(tc.code+" "+tc.id, func(t *testing.T) {
			c := m.byID(t, tc.id)
			if c.Reason != tc.code {
				t.Fatalf("the manifest says the case %s is refused with %q, the test names %q", tc.id, c.Reason, tc.code)
			}
			dir := crqBundle(t, m, c)
			before := crqSnapshot(t, dir)
			n := numberOf[tc.code]
			stem := c.stem(t)

			text := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir)
			if text.code != ExitRefused {
				t.Fatalf("exit code %d\n%s%s", int(text.code), text.stdout, text.stderr)
			}
			lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n")
			if len(lines) != 11 {
				t.Fatalf("standard output has %d lines, want 9 checks, check 10 and the last line:\n%s", len(lines), text.stdout)
			}
			for i, c := range checks {
				status := "not-run"
				switch {
				case c.n < n:
					status = "passed"
				case c.n == n:
					status = "failed"
				}
				if want := "check " + strconv.Itoa(c.n) + ": " + status + ": " + c.name; lines[i] != want {
					t.Errorf("line %d = %q, want %q", i+1, lines[i], want)
				}
			}
			if lines[9] != "check 10: not made here; the person at the ceremony confirms" {
				t.Errorf("line 10 = %q", lines[9])
			}
			if want := "request " + stem + ": refused: " + tc.code; lines[10] != want {
				t.Errorf("last line = %q, want %q", lines[10], want)
			}
			// Standard error: the refusal, with the check and its detail.
			prefix := "ritueel: refused: " + tc.code + " (check " + strconv.Itoa(n) + ": "
			if !strings.HasPrefix(text.stderr, prefix) || !strings.HasSuffix(text.stderr, ")\n") || strings.Count(text.stderr, "\n") != 1 {
				t.Errorf("standard error = %q, want one line that starts %q and ends with the detail and a closing parenthesis", text.stderr, prefix)
			}
			if detail := strings.TrimSuffix(strings.TrimPrefix(text.stderr, prefix), ")\n"); strings.TrimSpace(detail) == "" {
				t.Errorf("the refusal line has no detail: %q", text.stderr)
			}
			if !onlyPrintable(text.stdout) || !onlyPrintable(text.stderr) {
				t.Errorf("a byte that is not printable ASCII: %q %q", text.stdout, text.stderr)
			}

			js := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir, "--output", "json")
			if js.code != ExitRefused || js.stderr != text.stderr {
				t.Errorf("json: (%d, %q), want (3, %q): the line of standard error is the same in both modes", int(js.code), js.stderr, text.stderr)
			}
			obj := object(t, js.stdout)
			got := crqChecks(t, obj)
			wantObject(t, withoutChecks(obj), map[string]any{"output": 1, "command": "check", "exit_code": 3, "outcome": "refused", "reasons": []string{tc.code}})
			if len(got) != 9 {
				t.Fatalf("checks = %v", got)
			}
			for i, g := range got {
				want := "not-run"
				switch {
				case i+1 < n:
					want = "passed"
				case i+1 == n:
					want = "failed"
				}
				if g[0] != strconv.Itoa(i+1) || g[1] != want {
					t.Errorf("checks[%d] = %v, want result %s", i, g, want)
				}
			}
			for _, leak := range []string{"refused:", "(check"} {
				if strings.Contains(js.stdout, leak) {
					t.Errorf("the refusal line is in the object: %q", js.stdout)
				}
			}
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

// The first check that refuses gives the code; the checks before it passed and the ones after it did not run.
func TestEveryRefusalLeavesTheChecksAfterItNotRun(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	numberOf := contractCodeOfCheck(t)
	seen := 0
	for _, c := range m.Requests {
		if c.Config == listedConfig || c.Type != "x509-intermediate" || c.Expect != "refuse" || c.Confirmation == "declined" {
			continue
		}
		dir := crqBundle(t, m, c)
		r := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
		if r.code != ExitRefused {
			continue // an undecided case: a store with no verifier
		}
		seen++
		if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
			t.Errorf("%s: a byte that is not printable ASCII: %q %q", c.ID, r.stdout, r.stderr)
		}
		if text := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir); !onlyPrintable(text.stdout) || !onlyPrintable(text.stderr) || text.code != ExitRefused {
			t.Errorf("%s: text mode (%d, %q, %q)", c.ID, int(text.code), text.stdout, text.stderr)
		}
		obj := object(t, r.stdout)
		reasons, _ := stringList(obj["reasons"])
		if len(reasons) != 1 {
			t.Errorf("%s: reasons = %v", c.ID, reasons)
			continue
		}
		n, ok := numberOf[reasons[0]]
		if !ok {
			t.Errorf("%s: the code %q is not one of the codes of the contract's checks", c.ID, reasons[0])
			continue
		}
		for i, g := range crqChecks(t, obj) {
			want := "not-run"
			switch {
			case i+1 < n:
				want = "passed"
			case i+1 == n:
				want = "failed"
			}
			if g[1] != want {
				t.Errorf("%s: check %d is %s, want %s (code %s)", c.ID, i+1, g[1], want, reasons[0])
			}
		}
	}
	if seen < 20 {
		t.Errorf("only %d refused cases were seen: a check that finds almost nothing to check is not a check", seen)
	}
}

// ---- exit code 1: what stops the command from judging -----------------------------------------------

func TestWhatStopsTheCommandIsExitOneWithTheTextOfTheFault(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	good := m.byID(t, "x509-software-valid")
	stem := good.stem(t)

	// A change to the good bundle, and a word that the error text must hold.
	type change func(tree crqTree)
	drop := func(prefix string) change {
		return func(tree crqTree) {
			for p := range tree {
				if strings.HasPrefix(p, prefix) {
					delete(tree, p)
				}
			}
		}
	}
	set := func(p, content string) change { return func(tree crqTree) { tree[p] = []byte(content) } }

	for _, tc := range []struct {
		name   string
		change change
		args   []string // after "check request STEM"; the default names the delegation
		want   []string // every word the error text holds
	}{
		{"no ritueel.yaml", drop("ritueel.yaml"), nil, []string{"ritueel.yaml"}},
		{"ritueel.yaml that fails its reader", set("ritueel.yaml", strings.Replace(crqSettings(m.Configs["development"]), "require_name_constraints: true", "require_name_constraints: false", 1)), nil, []string{"ritueel.yaml", "require_name_constraints"}},
		{"ritueel.yaml with a second document", set("ritueel.yaml", crqSettings(m.Configs["development"])+"---\nversion: 1\n"), nil, []string{"ritueel.yaml"}},
		{"ritueel.yaml with an unknown member", set("ritueel.yaml", crqSettings(m.Configs["development"])+"colour: red\n"), nil, []string{"ritueel.yaml", "colour"}},
		{"the delegation named has no file", drop("want/delegations/"), nil, []string{"want/delegations/" + crqDelegation + ".yaml"}},
		{"a delegation that is not named in the files", nil, []string{"--delegation", "nosuch"}, []string{"want/delegations/nosuch.yaml"}},
		{"a delegation that fails its reader", set("want/delegations/"+crqDelegation+".yaml", "version: 1\ntype: x509-intermediate\nroot: "+crqRoot+"\n"), nil, []string{"want/delegations/" + crqDelegation + ".yaml"}},
		{"a delegation with a bad name in its list", set("want/delegations/"+crqDelegation+".yaml", "version: 1\ntype: x509-intermediate\nroot: "+crqRoot+"\npermitted_dns_names: [\"*.example.org\"]\n"), nil, []string{"permitted_dns_names"}},
		{"the root of the delegation has no file", drop("want/roots/"), nil, []string{"want/roots/" + crqRoot + ".yaml"}},
		{"the root of the delegation is of another kind", set("want/roots/"+crqRoot+".yaml", "version: 1\nkind: openpgp\n"), nil, []string{"want/delegations/" + crqDelegation + ".yaml", "kind openpgp", "kind x509"}},
		{"a root file that fails its reader", set("want/roots/"+crqRoot+".yaml", "version: 1\nkind: x509\nkeys: []\n"), nil, []string{"want/roots/" + crqRoot + ".yaml"}},
		{"no trust set", drop("trust/"), nil, []string{"no trust set"}},
		{"an empty trust folder", func(tree crqTree) {
			drop("trust/")(tree)
			tree["trust/.keep"] = []byte("x")
		}, nil, []string{"no trust set"}},
		{"the newest trust set has no CA bundle", drop("trust/" + crqTrustSet + "/ca-bundle.pem"), nil, []string{"ca-bundle.pem"}},
		{"the newest trust set has no list", drop("trust/" + crqTrustSet + "/root-list.json"), nil, []string{"root-list.json"}},
		{"the list of the newest trust set is not json", set("trust/"+crqTrustSet+"/root-list.json", "not json"), nil, []string{"root-list.json"}},
		{"the list says another sequence than the folder", func(tree crqTree) {
			tree["trust/8-3fa9c1d2/root-list.json"] = tree["trust/"+crqTrustSet+"/root-list.json"]
			tree["trust/8-3fa9c1d2/ca-bundle.pem"] = tree["trust/"+crqTrustSet+"/ca-bundle.pem"]
		}, nil, []string{"sequence"}},
		{"the CA bundle is not the bundle of the list", set("trust/"+crqTrustSet+"/ca-bundle.pem", "# trust-sequence: 7\n"), nil, []string{"ca-bundle.pem"}},
		{"no proof file", drop("requests/" + stem + "/" + stem + ".proof.json"), nil, []string{"proof"}},
		{"no request folder", drop("requests/"), nil, []string{"no proof file", stem}},
		{"a delegation of the SSH list", nil, []string{"--delegation", "break-glass-a"}, []string{"want/delegations/break-glass-a.yaml"}},
		{"a proof file that is not json", set("requests/"+stem+"/"+stem+".proof.json", "{"), nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := crqBundleTree(t, m, good)
			if tc.change != nil {
				tc.change(tree)
			}
			dir := t.TempDir()
			crqWrite(t, dir, tree)
			before := crqSnapshot(t, dir)
			args := tc.args
			if args == nil {
				args = []string{"--delegation", crqDelegation}
			}
			run1 := append([]string{"check", "request", stem, "--dir", dir}, args...)
			text := crqRun(t, now, run1...)
			js := crqRun(t, now, append(run1, "--output", "json")...)
			if text.code != ExitFailure && (tc.name != "a proof file that is not json" || text.code != ExitRefused) {
				t.Fatalf("exit code %d, want 1\n%s%s", int(text.code), text.stdout, text.stderr)
			}
			if js.code != text.code {
				t.Errorf("the exit code of the JSON mode is %d, of the text mode %d", int(js.code), int(text.code))
			}
			if text.code == ExitFailure {
				if text.stdout != "" {
					t.Errorf("standard output = %q, want nothing for exit code 1", text.stdout)
				}
				for _, w := range tc.want {
					if !strings.Contains(text.stderr, w) {
						t.Errorf("standard error = %q, want it to hold %q", text.stderr, w)
					}
				}
				obj := object(t, js.stdout)
				wantObject(t, obj, map[string]any{"output": 1, "command": "check", "exit_code": 1, "outcome": "failed", "error": "<any>"})
				if strings.Contains(js.stdout, `"checks"`) {
					t.Errorf("an exit code 1 has the member checks: %s", js.stdout)
				}
				if !onlyPrintable(text.stderr) {
					t.Errorf("a byte that is not printable ASCII: %q", text.stderr)
				}
			}
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

// A store whose verifier no command registers: the request is not accepted and not refused, and the text says
// that only a software key can be accepted.
func TestARequestOfAStoreWithNoVerifierIsExitOneAndSaysOnlyASoftwareKeyIsAccepted(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, id := range []string{"x509-piv-valid", "x509-kms-valid", "pgp-openpgp-card-valid"} {
		c := m.byID(t, id)
		if c.Type != "x509-intermediate" {
			continue
		}
		t.Run(id, func(t *testing.T) {
			dir := crqBundle(t, m, c)
			for _, d := range [][]string{{"--delegation", crqDelegation}, nil} {
				r := crqRun(t, now, append([]string{"check", "request", c.stem(t), "--dir", dir}, d...)...)
				if r.code != ExitFailure {
					t.Fatalf("%v: exit code %d\n%s%s", d, int(r.code), r.stdout, r.stderr)
				}
				for _, w := range []string{"request " + c.stem(t) + " is not accepted and not refused", "no evidence verifier", "software key", "check 7"} {
					if !strings.Contains(r.stderr, w) {
						t.Errorf("%v: standard error %q does not hold %q", d, r.stderr, w)
					}
				}
				if r.stdout != "" {
					t.Errorf("%v: standard output = %q", d, r.stdout)
				}
				if strings.Contains(r.stderr, "accepted:") {
					t.Errorf("the request is called accepted: %q", r.stderr)
				}
			}
		})
	}
}

// An OpenPGP request and an SSH request cannot be judged by this command. The text says so plainly, and for an
// OpenPGP request it names the primaries that the bundle cannot give.
func TestARequestOfATypeThatIsNotBuiltIsExitOneAndSaysSo(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, tc := range []struct {
		id      string
		want    []string
		wantNot []string
	}{
		{"pgp-software-valid", []string{"openpgp-subkey", "primaries", "cannot judge"}, []string{"ssh"}},
		{"pgp-piv-valid", []string{"openpgp-subkey", "primaries", "cannot judge"}, []string{"ssh"}},
		{"ssh-software-valid", []string{"cannot judge a request of this type yet", "check 4"}, []string{"openpgp"}},
		{"ssh-piv-valid", []string{"cannot judge a request of this type yet"}, []string{"openpgp"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c := m.byID(t, tc.id)
			dir := crqBundle(t, m, c)
			for _, d := range [][]string{{"--delegation", crqDelegation}, nil} {
				before := crqSnapshot(t, dir)
				r := crqRun(t, now, append([]string{"check", "request", c.stem(t), "--dir", dir}, d...)...)
				if r.code != ExitFailure {
					t.Fatalf("%v: exit code %d\n%s%s", d, int(r.code), r.stdout, r.stderr)
				}
				for _, w := range append([]string{"request " + c.stem(t) + " is not accepted and not refused"}, tc.want...) {
					if !strings.Contains(r.stderr, w) {
						t.Errorf("%v: standard error %q does not hold %q", d, r.stderr, w)
					}
				}
				for _, w := range tc.wantNot {
					if strings.Contains(r.stderr, w) {
						t.Errorf("%v: standard error %q holds %q", d, r.stderr, w)
					}
				}
				crqSame(t, "check request", before, crqSnapshot(t, dir))
			}
		})
	}
}

// ---- exit code 2 --------------------------------------------------------------------------------------

func TestAWrongCommandLineIsExitTwoBeforeAnyFileIsRead(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	dir, stem := crqBundleOf(t, "x509-software-valid")
	long := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no STEM", []string{"check", "request", "--dir", dir}, "STEM"},
		{"two STEMs", []string{"check", "request", stem, stem, "--dir", dir}, "STEM"},
		{"a STEM in upper case", []string{"check", "request", "Stem", "--dir", dir}, "STEM"},
		{"a STEM that is a path", []string{"check", "request", "a/b", "--dir", dir}, "STEM"},
		{"a STEM that climbs", []string{"check", "request", "..", "--dir", dir}, "STEM"},
		{"a STEM that is the current folder", []string{"check", "request", ".", "--dir", dir}, "STEM"},
		{"an empty STEM", []string{"check", "request", "", "--dir", dir}, "STEM"},
		{"a STEM that starts with a hyphen", []string{"check", "request", "--dir", dir, "--", "-a"}, "STEM"},
		{"a STEM of 64 characters", []string{"check", "request", long, "--dir", dir}, "1 to 63"},
		{"a STEM with a space", []string{"check", "request", "a b", "--dir", dir}, "STEM"},
		{"a STEM with a letter of another script", []string{"check", "request", "aе", "--dir", dir}, "STEM"},
		{"a STEM with an underscore", []string{"check", "request", "a_b", "--dir", dir}, "STEM"},
		{"a name of a delegation in upper case", []string{"check", "request", stem, "--delegation", "Acme", "--dir", dir}, "--delegation"},
		{"a name of a delegation with an underscore", []string{"check", "request", stem, "--delegation", "a_b", "--dir", dir}, "--delegation"},
		{"a name of a delegation that is a path", []string{"check", "request", stem, "--delegation", "a/b", "--dir", dir}, "--delegation"},
		{"a name of a delegation of 64 characters", []string{"check", "request", stem, "--delegation", long, "--dir", dir}, "--delegation"},
		{"a name of a delegation that starts with a hyphen", []string{"check", "request", stem, "--delegation=-a", "--dir", dir}, "--delegation"},
		{"an empty name of a delegation", []string{"check", "request", stem, "--delegation", "", "--dir", dir}, "--delegation"},
		{"an empty name of a delegation, with an equals sign", []string{"check", "request", stem, "--delegation=", "--dir", dir}, "--delegation"},
		{"an unknown flag", []string{"check", "request", stem, "--nosuch", "--dir", dir}, ""},
		{"a usage error before a folder that is not there", []string{"check", "request", "Stem", "--dir", filepath.Join(dir, "nosuch")}, "STEM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := crqSnapshot(t, dir)
			text := crqRun(t, now, tc.args...)
			if text.code != ExitUsage || text.stdout != "" {
				t.Fatalf("(%d, %q, %q), want exit code 2 and nothing on standard output", int(text.code), text.stdout, text.stderr)
			}
			if !strings.Contains(text.stderr, tc.want) || !strings.HasPrefix(text.stderr, "ritueel: ") {
				t.Errorf("standard error = %q, want a line that holds %q", text.stderr, tc.want)
			}
			js := crqRun(t, now, append([]string{"--output", "json"}, tc.args...)...)
			if js.code != ExitUsage {
				t.Errorf("json: exit code %d", int(js.code))
			}
			wantObject(t, object(t, js.stdout), map[string]any{"output": 1, "command": "check", "exit_code": 2, "outcome": "usage", "error": "<any>"})
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

// With no --dir the folder is the current one when it holds ritueel.yaml; the folder of these tests holds none, so
// the command is a usage error that names --dir, and reads nothing.
func TestWithNoDirAndNoManifestHereTheCommandIsAUsageErrorThatNamesTheFlag(t *testing.T) {
	r := crqRun(t, crqClock(t), "check", "request", "x509-software-valid")
	if r.code != ExitUsage || !strings.Contains(r.stderr, "--dir") {
		t.Errorf("(%d, %q), want exit code 2 and a line that names --dir", int(r.code), r.stderr)
	}
}

// --dir is a flag of the program: it is read before the words and after them.
func TestTheFolderFlagIsAcceptedBeforeAndAfterTheWords(t *testing.T) {
	now := crqClock(t)
	dir, stem := crqBundleOf(t, "x509-software-valid")
	for _, args := range [][]string{
		{"--dir", dir, "check", "request", stem, "--delegation", crqDelegation},
		{"check", "--dir", dir, "request", stem, "--delegation", crqDelegation},
		{"check", "request", "--dir", dir, stem, "--delegation", crqDelegation},
		{"check", "request", stem, "--delegation", crqDelegation, "--dir", dir},
		{"check", "request", "--delegation", crqDelegation, stem, "--dir=" + dir},
	} {
		if r := crqRun(t, now, args...); r.code != ExitOK || r.stderr != acceptedStderr {
			t.Errorf("%v: (%d, %q)", args[:3], int(r.code), r.stderr)
		}
	}
}

// ---- a request folder that is not what it should be --------------------------------------------------

func TestLinksAndPipesInPlaceOfTheFilesOfARequestAreRefusedAndNeverFollowed(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	c := m.byID(t, "x509-software-valid")
	stem := c.stem(t)
	for _, tc := range []struct {
		name string
		make func(t *testing.T, dir string)
	}{
		{"the request folder is a link to a folder", func(t *testing.T, dir string) {
			real := filepath.Join(dir, "requests", stem)
			moved := filepath.Join(dir, "elsewhere")
			if err := os.Rename(real, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, real); err != nil {
				t.Fatal(err)
			}
		}},
		{"the requests folder is a link", func(t *testing.T, dir string) {
			real := filepath.Join(dir, "requests")
			moved := filepath.Join(dir, "elsewhere")
			if err := os.Rename(real, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, real); err != nil {
				t.Fatal(err)
			}
		}},
		{"the proof file is a link", replaceWithLink(stem, stem+".proof.json")},
		{"the signed request is a link", replaceWithLink(stem, stem+".csr.pem")},
		{"the proof file is a pipe", replaceWithPipe(stem, stem+".proof.json")},
		{"the signed request is a pipe", replaceWithPipe(stem, stem+".csr.pem")},
		{"the proof file is a folder", replaceWithFolder(stem, stem+".proof.json")},
		{"the signed request is a folder", replaceWithFolder(stem, stem+".csr.pem")},
		{"the proof file is empty", func(t *testing.T, dir string) {
			writeEmpty(t, filepath.Join(dir, "requests", stem, stem+".proof.json"))
		}},
		{"the signed request is empty", func(t *testing.T, dir string) { writeEmpty(t, filepath.Join(dir, "requests", stem, stem+".csr.pem")) }},
		{"the signed request is very large", func(t *testing.T, dir string) {
			f, err := os.OpenFile(filepath.Join(dir, "requests", stem, stem+".csr.pem"), os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			if err := f.Truncate(64 << 20); err != nil {
				t.Skipf("cannot make a sparse file: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := crqBundle(t, m, c)
			tc.make(t, dir)
			before := crqSnapshot(t, dir)
			r := crqRun(t, now, "check", "request", stem, "--delegation", crqDelegation, "--dir", dir, "--output", "json")
			if r.code == ExitOK {
				t.Fatalf("a request that is not a folder of plain files is accepted: %s%s", r.stdout, r.stderr)
			}
			// A file that cannot be read as a plain file is a failure of the command; a plain file with the
			// wrong content is a refusal of the request, with the code malformed.
			wantCode, wantText := ExitFailure, "cannot be read"
			if strings.Contains(tc.name, "is empty") || strings.Contains(tc.name, "very large") {
				wantCode, wantText = ExitRefused, "refused: malformed"
			}
			if r.code != wantCode || !strings.Contains(r.stderr, wantText) {
				t.Errorf("(%d, %q), want exit code %d and a line that holds %q", int(r.code), r.stderr, int(wantCode), wantText)
			}
			if !onlyPrintable(r.stdout) || !onlyPrintable(r.stderr) {
				t.Errorf("a byte that is not printable ASCII: %q %q", r.stdout, r.stderr)
			}
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

func replaceWithLink(stem, name string) func(t *testing.T, dir string) {
	return func(t *testing.T, dir string) {
		p := filepath.Join(dir, "requests", stem, name)
		moved := filepath.Join(dir, "elsewhere-"+name)
		if err := os.Rename(p, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, p); err != nil {
			t.Fatal(err)
		}
	}
}

func writeEmpty(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func replaceWithPipe(stem, name string) func(t *testing.T, dir string) {
	return func(t *testing.T, dir string) {
		p := filepath.Join(dir, "requests", stem, name)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(p, 0o644); err != nil {
			t.Skipf("cannot make a pipe: %v", err)
		}
	}
}

func replaceWithFolder(stem, name string) func(t *testing.T, dir string) {
	return func(t *testing.T, dir string) {
		p := filepath.Join(dir, "requests", stem, name)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// A STEM of 63 characters has the form of the contract (1 to 63 lower-case letters, digits and hyphens): the command
// goes on to look for its folder and, finding none, stops with exit code 1, not with a usage error.
func TestAStemOfTheLongestFormIsNotAUsageError(t *testing.T) {
	dir, _ := crqBundleOf(t, "x509-software-valid")
	for _, stem := range []string{strings.Repeat("a", 63), "0", "a-", "9" + strings.Repeat("-", 62)} {
		r := crqRun(t, crqClock(t), "check", "request", stem, "--delegation", crqDelegation, "--dir", dir)
		if r.code != ExitFailure || !strings.Contains(r.stderr, "no proof file") {
			t.Errorf("%q: (%d, %q), want exit code 1 and the words no proof file", stem, int(r.code), r.stderr)
		}
	}
}
