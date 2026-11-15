//go:build linux || darwin

package cli

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// A key on an OpenPGP card is not taken for an X.509 intermediate: "check request" refuses an x509-intermediate
// request whose store is openpgp-card with the code store-not-allowed (exit code 3, check 6), also when the
// policy of the bundle lists that store. The request of the test is made from the vector case of a PIV key, with
// the store of its proof file changed; the vectors are not changed.

const cardRefusalLine = "ritueel: refused: store-not-allowed (check 6: the store openpgp-card is not allowed for an x509-intermediate: its attestation shows no PIN or touch rule)\n"

// crqCardBundle is the bundle of the case with the store of its proof file set to openpgp-card.
func crqCardBundle(t testing.TB, m crqManifest, c crqCase) (dir, stem string) {
	t.Helper()
	tree := crqBundleTree(t, m, c)
	stem = c.stem(t)
	name := "requests/" + stem + "/" + stem + ".proof.json"
	var proof map[string]any
	if err := json.Unmarshal(tree[name], &proof); err != nil {
		t.Fatal(err)
	}
	if proof["store"] == "openpgp-card" {
		t.Fatalf("test setup: the case %s already has the store openpgp-card", c.ID)
	}
	proof["store"] = "openpgp-card"
	b, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	tree[name] = b
	dir = t.TempDir()
	crqWrite(t, dir, tree)
	return dir, stem
}

func TestAnX509RequestWithTheStoreOpenPGPCardIsExitThreeWithStoreNotAllowedAtCheckSix(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	checks := contractChecks(t)
	// Both configurations list the store openpgp-card for subkeys, and the first one is the production one.
	// The evidence of a PIV key has the shape that the page gives a card (a list of certificates), so the
	// request passes check 2 with the store changed; the evidence of a cloud key does not.
	for _, id := range []string{"x509-piv-valid"} {
		for _, listed := range []string{"production", "development"} {
			t.Run(id+"/"+listed, func(t *testing.T) {
				c := m.byID(t, id)
				c.Config = listed
				cfg := m.Configs[listed]
				found := false
				for _, s := range cfg.Stores {
					found = found || s == "openpgp-card"
				}
				if !found {
					t.Fatalf("test setup: the configuration %s does not list the store openpgp-card", listed)
				}
				dir, stem := crqCardBundle(t, m, c)
				before := crqSnapshot(t, dir)
				for _, withDelegation := range []bool{true, false} {
					args := []string{"check", "request", stem, "--dir", dir}
					if withDelegation {
						args = append(args, "--delegation", crqDelegation)
					}
					text := crqRun(t, now, args...)
					if text.code != ExitRefused {
						t.Fatalf("delegation %v: exit code %d\n%s%s", withDelegation, int(text.code), text.stdout, text.stderr)
					}
					if text.stderr != cardRefusalLine {
						t.Errorf("standard error = %q, want %q", text.stderr, cardRefusalLine)
					}
					lines := strings.Split(strings.TrimSuffix(text.stdout, "\n"), "\n")
					if len(lines) != 11 {
						t.Fatalf("standard output has %d lines:\n%s", len(lines), text.stdout)
					}
					for i, ck := range checks {
						status := "not-run"
						switch {
						case ck.n < 6:
							status = "passed"
						case ck.n == 6:
							status = "failed"
						}
						if want := "check " + strconv.Itoa(ck.n) + ": " + status + ": " + ck.name; lines[i] != want {
							t.Errorf("line %d = %q, want %q", i+1, lines[i], want)
						}
					}
					if want := "request " + stem + ": refused: store-not-allowed"; lines[10] != want {
						t.Errorf("last line = %q, want %q", lines[10], want)
					}
					if !onlyPrintable(text.stdout) || !onlyPrintable(text.stderr) || strings.Contains(text.stdout, "accepted") {
						t.Errorf("standard output %q, standard error %q", text.stdout, text.stderr)
					}

					js := crqRun(t, now, append(args, "--output", "json")...)
					if js.code != ExitRefused || js.stderr != cardRefusalLine {
						t.Fatalf("json: (%d, %q)", int(js.code), js.stderr)
					}
					obj := object(t, js.stdout)
					got := crqChecks(t, obj)
					wantObject(t, withoutChecks(obj), map[string]any{"output": 1, "command": "check", "exit_code": 3, "outcome": "refused", "reasons": []string{"store-not-allowed"}})
					for i, g := range got {
						want := map[bool]string{true: "passed", false: "not-run"}[i+1 < 6]
						if i+1 == 6 {
							want = "failed"
						}
						if g[0] != strconv.Itoa(i+1) || g[1] != want {
							t.Errorf("checks[%d] = %v, want result %s", i, g, want)
						}
					}
					if len(got) != 9 {
						t.Errorf("checks = %v", got)
					}
				}
				crqSame(t, "check request", before, crqSnapshot(t, dir))
			})
		}
	}
}

// The same bundle with the store of the proof left as the vector has it is not refused for its store: the
// refusal is the card store's and no other store's.
func TestTheStoreOfAnX509RequestIsNotRefusedWhenItIsNotTheCard(t *testing.T) {
	m := crqManifestOf(t)
	now := m.clock(t)
	for _, id := range []string{"x509-piv-valid", "x509-kms-valid"} {
		c := m.byID(t, id)
		dir := crqBundle(t, m, c)
		r := crqRun(t, now, "check", "request", c.stem(t), "--delegation", crqDelegation, "--dir", dir, "--output", "json")
		if strings.Contains(r.stdout+r.stderr, "store-not-allowed") || r.code == ExitRefused {
			t.Errorf("%s: (%d, %q, %q)", id, int(r.code), r.stdout, r.stderr)
		}
	}
}
