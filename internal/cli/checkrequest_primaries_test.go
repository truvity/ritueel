package cli

import (
	"strings"
	"testing"
)

// The command gives the checker no OpenPGP primaries, because where they are read from is not decided. So it cannot
// judge a request of the type openpgp-subkey: the request is neither accepted nor refused, and the person is told so
// in one plain sentence, with a delegation named and without one. The sentence is exit code 1 and holds no result.

const primariesText = "this command cannot judge an openpgp-subkey request: it cannot give the checker the OpenPGP primaries, because where they are read from is not decided"

// delegationPrimariesText is the sentence for a delegation of the type openpgp-subkey: it is the delegation that the
// command cannot give primaries for, so the sentence names it, and the request may be of any type.
const delegationPrimariesText = "this command cannot judge a request under the delegation " + crqDelegation + ", which is of the type openpgp-subkey: it cannot give the checker the OpenPGP primaries, because where they are read from is not decided"

func TestAnOpenPGPRequestIsNotJudgedAndTheSentenceIsPlainInBothModesWithAndWithoutADelegation(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, id := range []string{"pgp-software-valid", "pgp-piv-valid", "pgp-openpgp-card-valid", "pgp-kms-valid", "pgp-ed25519", "pgp-backsig-missing"} {
		c := m.byID(t, id)
		t.Run(id, func(t *testing.T) {
			dir := crqBundle(t, m, c)
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
					for _, bad := range []string{"accepted:", "holds no primaries", "ErrConfig", "ritueel: refused"} {
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

// A delegation of another type, named for an OpenPGP request, makes a checker; the request then stops at the
// primaries after checks 1 and 2 passed, and the first check that did not run is check 3.
func TestAnOpenPGPRequestOnADelegationOfAnotherTypeStopsAtTheFirstCheckThatNeedsThePrimaries(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "pgp-software-valid")
	tree := crqBundleTree(t, m, c)
	tree["want/roots/"+crqRoot+".yaml"] = []byte("version: 1\nkind: x509\ntest: true\n")
	tree["want/delegations/"+crqDelegation+".yaml"] = []byte("version: 1\ntype: x509-intermediate\nroot: " + crqRoot + "\npermitted_uri_hosts: [example.org]\n")
	dir := t.TempDir()
	crqWrite(t, dir, tree)
	r := crqRun(t, m.clock(t), "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir)
	want := "ritueel: request " + c.stem(t) + " is not accepted and not refused: " + primariesText + " (the first check that did not run is check 3)\n"
	if r.code != ExitFailure || r.stdout != "" || r.stderr != want {
		t.Errorf("(%d, %q, %q), want exit code 1 and %q", int(r.code), r.stdout, r.stderr, want)
	}
}

// With no delegation a form fault of the subkey file is a refusal of check 2 as before, and only a file that passes
// checks 1 and 2 reaches the sentence. With an openpgp-subkey delegation the command cannot make the checker, so
// every OpenPGP request is exit code 1: a request is never refused for want of a check that the command cannot run.
func TestAnOpenPGPRequestThatChecksOneAndTwoRefuseIsARefusalWithNoDelegationAndTheSentenceWithOne(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	refused, sentence := 0, 0
	for _, c := range m.Requests {
		if c.Type != "openpgp-subkey" || c.Config == listedConfig {
			continue
		}
		dir := crqBundle(t, m, c)
		with := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir)
		if with.code != ExitFailure || !strings.Contains(with.stderr, delegationPrimariesText) || strings.Contains(with.stderr, "openpgp-subkey request") {
			t.Errorf("%s with a delegation: (%d, %q), want exit code 1 and the sentence", c.ID, int(with.code), with.stderr)
		}
		without := crqRun(t, now, "check", "request", c.stem(t), "--dir", dir)
		switch without.code {
		case ExitRefused:
			refused++
			if !strings.Contains(without.stderr, "ritueel: refused: ") || strings.Contains(without.stderr, "primaries") {
				t.Errorf("%s: refusal line = %q", c.ID, without.stderr)
			}
		case ExitFailure:
			sentence++
			if !strings.Contains(without.stderr, primariesText) {
				t.Errorf("%s: standard error = %q, want the sentence", c.ID, without.stderr)
			}
		default:
			t.Errorf("%s: exit code %d with no delegation", c.ID, int(without.code))
		}
	}
	if refused == 0 || sentence == 0 {
		t.Errorf("%d refusals and %d sentences: the test would not see a fault of either kind", refused, sentence)
	}
}

// The warning of an accepted run belongs to an accepted run alone: a refusal, a request that was not judged and a
// command that failed carry none, on standard error and in the object, in both modes.
func TestOnlyAnAcceptedRequestCarriesTheWarningAboutTheTrustSet(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, tc := range []struct {
		id       string
		withDele bool
		code     ExitCode
	}{
		{"x509-software-valid", true, ExitOK},
		{"x509-csr-bad-signature", true, ExitRefused},
		{"x509-csr-bad-signature", false, ExitRefused},
		{"x509-software-valid", false, ExitFailure},
		{"x509-piv-valid", true, ExitFailure},
		{"ssh-software-valid", true, ExitFailure},
		{"pgp-software-valid", true, ExitFailure},
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
				has := strings.Contains(r.stderr, "trust-set-unchecked") || strings.Contains(r.stdout, "trust-set-unchecked")
				if has != (tc.code == ExitOK) {
					t.Errorf("%v: the trust set warning is there: %v\n%s%s", mode, has, r.stdout, r.stderr)
				}
				if tc.code == ExitOK && strings.Count(r.stderr, "warning:") != 1 {
					t.Errorf("%v: standard error = %q, want one warning", mode, r.stderr)
				}
			}
		})
	}
}

// A delegation of the type openpgp-subkey cannot make a checker here, whatever the request is: an x509 request
// named under it is not judged either (exit code 1, never accepted), where the library given a delegation of that type
// and primaries would refuse it at check 9. The command stops before it reads the request.
func TestAnOpenPGPDelegationStopsTheCommandWhateverTheTypeOfTheRequestIs(t *testing.T) {
	m := crqManifestOf(t)
	c := m.byID(t, "x509-software-valid")
	tree := crqBundleTree(t, m, c)
	tree["want/roots/"+crqRoot+".yaml"] = []byte("version: 1\nkind: openpgp\ntest: true\n")
	tree["want/delegations/"+crqDelegation+".yaml"] = []byte("version: 1\ntype: openpgp-subkey\nroot: " + crqRoot + "\ncapability: sign\n")
	dir := t.TempDir()
	crqWrite(t, dir, tree)
	before := crqSnapshot(t, dir)
	for _, mode := range [][]string{nil, {"--output", "json"}} {
		r := crqRun(t, m.clock(t), append([]string{"check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir}, mode...)...)
		if r.code != ExitFailure || strings.Contains(r.stdout+r.stderr, "accepted:") || !strings.Contains(r.stderr, "openpgp-subkey") || !strings.Contains(r.stderr, "primaries") {
			t.Errorf("%v: (%d, %q, %q), want exit code 1 and the words openpgp-subkey and primaries", mode, int(r.code), r.stdout, r.stderr)
		}
	}
	crqSame(t, "check request", before, crqSnapshot(t, dir))
}
