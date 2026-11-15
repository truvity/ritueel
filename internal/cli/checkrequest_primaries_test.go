package cli

import (
	"strconv"
	"strings"
	"testing"
)

// A trust set whose root list pins no OpenPGP primary gives the checker none. So the command cannot judge a request
// of the type openpgp-subkey: the request is neither accepted nor refused, and the person is told so in one plain
// sentence, with a delegation named and without one. The sentence is exit code 1 and holds no result.

// otherTypeSentence is the sentence for an openpgp-subkey request under a delegation of another type: the checker holds
// no primaries beside such a delegation, whatever the root list pins, so the sentence says only that the checks take
// the primaries for a delegation of the type openpgp-subkey: it never says what the list pins.
func otherTypeSentence(name, typ string) string {
	return "this command cannot judge an openpgp-subkey request under the delegation " + name + ", which is of the type " + typ +
		": the checks take the OpenPGP primaries only for a delegation of the type openpgp-subkey"
}

const primariesText = "this command cannot judge an openpgp-subkey request: the newest root list pins no OpenPGP primary"

// delegationPrimariesText is the sentence for a delegation of the type openpgp-subkey: it is the delegation that the
// command cannot give primaries for, so the sentence names it, and the request may be of any type.
const delegationPrimariesText = "this command cannot judge a request under the delegation " + crqDelegation + ", which is of the type openpgp-subkey: the newest root list pins no OpenPGP primary"

// noPrimaryBundle is the bundle of a case whose trust set has a root list that pins no OpenPGP primary.
func noPrimaryBundle(t testing.TB, m crqManifest, c crqCase) string {
	t.Helper()
	dir := t.TempDir()
	crqWrite(t, dir, crqWithTrust(crqBundleTree(t, m, c), crqTrustWithoutPrimaries(t)))
	return dir
}

func TestAnOpenPGPRequestOfAListThatPinsNoPrimaryIsNotJudgedAndTheSentenceIsPlainInBothModesWithAndWithoutADelegation(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, id := range []string{"pgp-software-valid", "pgp-piv-valid", "pgp-openpgp-card-valid", "pgp-kms-valid", "pgp-ed25519", "pgp-backsig-missing"} {
		c := m.byID(t, id)
		t.Run(id, func(t *testing.T) {
			dir := noPrimaryBundle(t, m, c)
			before := crqSnapshot(t, dir)
			for _, withDelegation := range []bool{true, false} {
				args := []string{"check", "request", c.stem(t), "--dir", dir}
				if withDelegation {
					args = append(args, "--delegation", crqDelegation)
				}
				text := crqRun(t, now, args...)
				js := crqRun(t, now, append(args, "--output", "json")...)
				for _, r := range []result{text, js} {
					if r.code != ExitFailure {
						t.Fatalf("delegation %v: exit code %d\n%s%s", withDelegation, int(r.code), r.stdout, r.stderr)
					}
					line := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + primariesText
					delegationLine := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + delegationPrimariesText
					if withDelegation && r.stderr != delegationLine+"\n" {
						t.Errorf("standard error = %q, want %q", r.stderr, delegationLine+"\n")
					}
					if !withDelegation && (!strings.HasPrefix(r.stderr, line+" (the first check that did not run is check ") || strings.Count(r.stderr, "\n") != 1) {
						t.Errorf("standard error = %q, want the sentence and the first check that did not run", r.stderr)
					}
					for _, bad := range []string{"accepted:", "holds no primaries", "ErrConfig", "ritueel: refused", "keyring.gpg", "where they are read from"} {
						if strings.Contains(r.stderr, bad) {
							t.Errorf("standard error %q holds %q", r.stderr, bad)
						}
					}
				}
				if text.stdout != "" {
					t.Errorf("text mode: standard output = %q, want nothing", text.stdout)
				}
				obj := object(t, js.stdout)
				for _, k := range []string{"checks", "reasons"} {
					if _, ok := obj[k]; ok {
						t.Errorf("the object has %s: %s", k, js.stdout)
					}
				}
				want := primariesText
				if withDelegation {
					want = delegationPrimariesText
				}
				if msg, _ := obj["error"].(string); !strings.Contains(msg, want) || obj["outcome"] != "failed" || obj["exit_code"] != jsonNumber("1") {
					t.Errorf("object = %s", js.stdout)
				}
			}
			crqSame(t, "check request", before, crqSnapshot(t, dir))
		})
	}
}

// A delegation of another type, named for an OpenPGP request, makes a checker with no primaries (the checker refuses
// primaries beside it, so the keyring file is not read); the request then stops at the primaries after checks 1 and
// 2 passed, and the first check that did not run is check 3. The sentence is the same whether the list pins primaries
// or not, and it never says that the list pins none when it pins some.
func TestAnOpenPGPRequestOnADelegationOfAnotherTypeStopsAtTheFirstCheckThatNeedsThePrimaries(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	for _, pinned := range []bool{true, false} {
		tree := crqBundleTree(t, m, c)
		if !pinned {
			tree = crqWithTrust(tree, crqTrustWithoutPrimaries(t))
		} else {
			// A keyring file that the reader would refuse: it is not read beside this delegation.
			tree["trust/"+crqTrustSet+"/"+crqKeyringFile] = []byte("not a keyring")
		}
		tree["want/roots/"+crqRoot+".yaml"] = []byte("version: 1\nkind: x509\ntest: true\n")
		tree["want/delegations/"+crqDelegation+".yaml"] = []byte("version: 1\ntype: x509-intermediate\nroot: " + crqRoot + "\npermitted_uri_hosts: [example.org]\n")
		dir := t.TempDir()
		crqWrite(t, dir, tree)
		r := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir)
		want := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + otherTypeSentence(crqDelegation, "x509-intermediate") + " (the first check that did not run is check 3)\n"
		if r.code != ExitFailure || r.stdout != "" || r.stderr != want {
			t.Errorf("pinned %v: (%d, %q, %q), want exit code 1 and %q", pinned, int(r.code), r.stdout, r.stderr, want)
		}
	}
}

// With a keyring file the command judges an OpenPGP request: the software request is accepted under a delegation, and
// is not complete without one; a request that check 5 refuses is exit code 3 with the code, with and without a
// delegation, because the primaries come from the trust set whatever the delegation is.
func TestAnOpenPGPRequestOfAListThatPinsPrimariesIsJudgedWithAndWithoutADelegation(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	t.Run("accepted under a delegation", func(t *testing.T) {
		c := m.byID(t, "pgp-software-valid")
		dir := crqBundle(t, m, c)
		before := crqSnapshot(t, dir)
		text := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir)
		js := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
		if text.code != ExitOK || js.code != ExitOK || text.stderr != trustSetStderrLine || js.stderr != trustSetStderrLine {
			t.Fatalf("(%d, %q) and (%d, %q), want exit code 0 and only the warning about the trust set", int(text.code), text.stderr, int(js.code), js.stderr)
		}
		lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n")
		if len(lines) != 11 || lines[10] != "request "+c.stem(t)+": accepted" {
			t.Fatalf("standard output = %q", text.stdout)
		}
		for i := 0; i < 9; i++ {
			if !strings.HasPrefix(lines[i], "check "+strconv.Itoa(i+1)+": passed: ") {
				t.Errorf("line %d = %q, want a passed check", i+1, lines[i])
			}
		}
		wantObject(t, withoutChecks(object(t, js.stdout)), map[string]any{"output": 1, "command": "check", "exit_code": 0, "outcome": "done", "warnings": []string{trustSetWarningText}})
		crqSame(t, "check request", before, crqSnapshot(t, dir))
	})
	t.Run("not complete with no delegation", func(t *testing.T) {
		c := m.byID(t, "pgp-software-valid")
		dir := crqBundle(t, m, c)
		const wantWarning = "check 9: rules not run: delegation-type, capability; give --delegation NAME"
		want := "ritueel: warning: " + wantWarning + "\n" + trustSetStderrLine +
			"ritueel: request " + c.stem(t) + " is not accepted and not refused: check 9 needs a delegation; give --delegation NAME\n"
		r := crqRun(t, now, "check", "request", c.stem(t), "--dir", dir)
		if r.code != ExitFailure || r.stderr != want {
			t.Fatalf("(%d, %q), want exit code 1 and %q", int(r.code), r.stderr, want)
		}
		lines := strings.Split(strings.TrimSuffix(r.stdout, "\n"), "\n")
		if len(lines) != 11 || !strings.HasPrefix(lines[8], "check 9: not-run: ") || strings.Contains(r.stdout, "accepted") {
			t.Errorf("standard output = %q", r.stdout)
		}
	})
	t.Run("refused with the code", func(t *testing.T) {
		c := m.byID(t, "pgp-backsig-missing")
		dir := crqBundle(t, m, c)
		for _, args := range [][]string{{"--delegation", crqDelegation}, nil} {
			r := crqRun(t, now, append([]string{"check", "request", c.stem(t), "--dir", dir, "--output", "json"}, args...)...)
			if r.code != ExitRefused {
				t.Fatalf("%v: exit code %d\n%s%s", args, int(r.code), r.stdout, r.stderr)
			}
			obj := object(t, r.stdout)
			if reasons, _ := stringList(obj["reasons"]); len(reasons) != 1 || reasons[0] != "possession-invalid" {
				t.Errorf("%v: reasons = %v, want [possession-invalid]", args, obj["reasons"])
			}
			if got := crqChecks(t, obj); len(got) != 9 || got[4][1] != "failed" {
				t.Errorf("%v: checks = %v, want check 5 failed", args, got)
			}
		}
	})
}

// The warning about the trust set belongs to every run that prints the nine results: an accepted request, a refusal
// and a request that is not complete. A command that stopped before it had nine results carries none. It is on
// standard error and in the object, in both modes, once.
func TestEveryRunThatHasTheNineResultsCarriesTheWarningAboutTheTrustSetAndNoOtherRunDoes(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, tc := range []struct {
		id       string
		withDele bool
		code     ExitCode
		nine     bool // the run has the nine results
	}{
		{"x509-software-valid", true, ExitOK, true},
		{"x509-csr-bad-signature", true, ExitRefused, true},
		{"x509-csr-bad-signature", false, ExitRefused, true},
		{"x509-software-valid", false, ExitFailure, true}, // not complete: check 9 needs a delegation
		{"x509-piv-valid", true, ExitFailure, false},
		{"ssh-software-valid", true, ExitFailure, false},
		{"pgp-software-valid", true, ExitOK, true},
		{"pgp-software-valid", false, ExitFailure, true}, // not complete: check 9 needs a delegation
		{"pgp-backsig-missing", true, ExitRefused, true},
		{"pgp-piv-valid", true, ExitFailure, false},
	} {
		t.Run(tc.id, func(t *testing.T) {
			c := m.byID(t, tc.id)
			dir := crqBundle(t, m, c)
			args := []string{"check", "request", c.stem(t), "--dir", dir}
			if tc.withDele {
				args = append(args, "--delegation", crqDelegation)
			}
			for _, mode := range [][]string{nil, {"--output", "json"}} {
				r := crqRun(t, now, append(args, mode...)...)
				if r.code != tc.code {
					t.Fatalf("%v: exit code %d, want %d\n%s%s", mode, int(r.code), int(tc.code), r.stdout, r.stderr)
				}
				has := strings.Contains(r.stderr, "trust-set-unchecked")
				if has != tc.nine {
					t.Errorf("%v: the trust set warning is there: %v\n%s%s", mode, has, r.stdout, r.stderr)
				}
				if got := strings.Count(r.stderr, "trust-set-unchecked"); got > 1 {
					t.Errorf("%v: the trust set warning is given %d times: %q", mode, got, r.stderr)
				}
				// The warning is a line of standard error, and never of standard output.
				if strings.Contains(r.stdout, "trust-set-unchecked") && mode == nil {
					t.Errorf("%v: the trust set warning is on standard output: %q", mode, r.stdout)
				}
				if tc.nine && !strings.Contains(r.stderr, trustSetStderrLine) {
					t.Errorf("%v: standard error = %q, want the line %q", mode, r.stderr, trustSetStderrLine)
				}
				if mode != nil {
					if w := stringsOf(object(t, r.stdout)["warnings"]); (len(w) > 0 && w[len(w)-1] == trustSetWarningText) != tc.nine {
						t.Errorf("%v: warnings = %q, want the one about the trust set last: %v", mode, w, tc.nine)
					}
				}
			}
		})
	}
}

// The text of the warning names the roots and the OpenPGP primaries, and says what is not checked.
func TestTheWarningAboutTheTrustSetNamesTheRootsAndTheOpenPGPPrimaries(t *testing.T) {
	const want = "trust-set-unchecked: this command did not check the signature and the expiry of the trust set that the roots and the OpenPGP primaries were read from"
	if trustSetWarning != want {
		t.Errorf("trustSetWarning = %q, want %q", trustSetWarning, want)
	}
	for _, w := range []string{"roots", "OpenPGP primaries", "signature", "expiry"} {
		if !strings.Contains(trustSetWarning, w) {
			t.Errorf("the warning does not hold %q", w)
		}
	}
}

// A delegation of the type openpgp-subkey, with a root list that pins no primary, cannot make a checker, whatever
// the type of the request is: an x509 request named under it is not judged either (exit code 1, never accepted). The
// command stops before it reads the request. With a list that pins primaries the checker is made, the request is
// read, and check 9 refuses an x509 request under a delegation of another type.
func TestAnOpenPGPDelegationStopsTheCommandWhateverTheTypeOfTheRequestIs(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "x509-software-valid")
	for _, pinned := range []bool{false, true} {
		tree := crqBundleTree(t, m, c)
		if !pinned {
			tree = crqWithTrust(tree, crqTrustWithoutPrimaries(t))
		}
		tree["want/roots/"+crqRoot+".yaml"] = []byte("version: 1\nkind: openpgp\ntest: true\n")
		tree["want/delegations/"+crqDelegation+".yaml"] = []byte("version: 1\ntype: openpgp-subkey\nroot: " + crqRoot + "\ncapability: sign\n")
		dir := t.TempDir()
		crqWrite(t, dir, tree)
		before := crqSnapshot(t, dir)
		for _, mode := range [][]string{nil, {"--output", "json"}} {
			r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir}, mode...)...)
			if strings.Contains(r.stdout+r.stderr, "accepted:") {
				t.Errorf("pinned %v %v: the request is called accepted: %q %q", pinned, mode, r.stdout, r.stderr)
			}
			if !pinned {
				if r.code != ExitFailure || !strings.Contains(r.stderr, "openpgp-subkey") || !strings.Contains(r.stderr, "pins no OpenPGP primary") {
					t.Errorf("%v: (%d, %q, %q), want exit code 1 and the words openpgp-subkey and pins no OpenPGP primary", mode, int(r.code), r.stdout, r.stderr)
				}
				continue
			}
			if r.code != ExitRefused || !strings.Contains(r.stderr, "refused: policy (check 9: the type of the request is not the type of the delegation)") {
				t.Errorf("pinned: %v: (%d, %q, %q), want exit code 3 and the refusal of check 9", mode, int(r.code), r.stdout, r.stderr)
			}
		}
		crqSame(t, "check request", before, crqSnapshot(t, dir))
	}
}
