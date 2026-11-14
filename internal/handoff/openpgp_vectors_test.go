package handoff_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	goecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/testrepo"
)

// The OpenPGP cases of the vector set are decided by the nine checks, with the verifiers of the card and KMS
// stores that the vector tests register. The expected statuses are written from the page: the check that a code
// belongs to ("What the certifier checks"), the checks before it passed and the checks after it not run.

// checkOfCode is the number of the check that gives a code.
var checkOfCode = map[handoff.Code]int{
	handoff.CodeVersionUnsupported:   1,
	handoff.CodeMalformed:            2,
	handoff.CodeRequestMismatch:      3,
	handoff.CodeUnknownPrimary:       3,
	handoff.CodeAlgorithmUnsupported: 4,
	handoff.CodePossessionInvalid:    5,
	handoff.CodeStoreNotAllowed:      6,
	handoff.CodeProofInvalid:         7,
	handoff.CodeKeyMismatch:          8,
	handoff.CodePolicy:               9,
}

// statusesOfCase are the nine results that the page gives for a case: all passed for an acceptance, and for a
// refusal passed before the check of its code, failed at it, and not run after it.
func statusesOfCase(c vectorCase) string {
	if c.Expect == "accept" {
		return "ppppppppp"
	}
	n := checkOfCode[handoff.Code(c.Reason)]
	out := make([]byte, 9)
	for i := range out {
		switch {
		case i+1 < n:
			out[i] = 'p'
		case i+1 == n:
			out[i] = 'f'
		default:
			out[i] = 'n'
		}
	}
	return string(out)
}

// changedCheckerOfCase is the checker of a case with the registered verifiers, after a change of the
// configuration that is made once the verifiers are built from the configuration with its delegation.
func changedCheckerOfCase(t testing.TB, m vectorManifest, c vectorCase, roots []handoff.RootRef, change func(cfg *handoff.Config)) *handoff.Checker {
	t.Helper()
	cfg := configOfCase(t, m, c, roots, testNow)
	merged := map[handoff.Store]handoff.EvidenceVerifier{}
	for _, register := range vectorVerifiers {
		maps.Copy(merged, register(t, m, c, cfg))
	}
	change(&cfg)
	if len(merged) > 0 {
		cfg.Evidence = merged
	}
	return mustNew(t, cfg)
}

func openpgpCases(t testing.TB) (vectorManifest, []vectorCase) {
	t.Helper()
	m := readManifest(t)
	var out []vectorCase
	for _, c := range m.Cases {
		if c.Type == string(handoff.TypeOpenPGP) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("the manifest holds no OpenPGP case: a check that finds nothing to check fails")
	}
	return m, out
}

func TestEveryOpenPGPVectorIsDecidedAndNoneIsPending(t *testing.T) {
	m, cases := openpgpCases(t)
	roots := rootsOfManifest(t, m)
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			if _, ok := pending[c.ID]; ok {
				t.Fatal("the case is in the pending map")
			}
			v, err := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), loadCase(t, c))
			if err != nil {
				t.Fatalf("error %v: the case is not decided", err)
			}
			if !matches(c, v, err) {
				t.Fatalf("the manifest says %s %s, and the verdict is %q (%s)", c.Expect, c.Reason, v.Code, v.Detail)
			}
			if got, want := statuses(v), statusesOfCase(c); got != want {
				t.Errorf("statuses %s, want %s", got, want)
			}
			if c.Expect == "refuse" && (v.Subkey != nil || v.Key != nil || v.Evidence != nil) {
				t.Errorf("a refused verdict holds a subkey, key or evidence")
			}
		})
	}
	t.Logf("%d OpenPGP cases, all decided", len(cases))
}

// An accepted vector gives the subkey that go-crypto reads from the file, with the capability of the case.
func TestTheAcceptedOpenPGPVectorsGiveTheSubkeyThatAnotherReaderReads(t *testing.T) {
	m, cases := openpgpCases(t)
	roots := rootsOfManifest(t, m)
	seen := 0
	for _, c := range cases {
		if c.Expect != "accept" {
			continue
		}
		seen++
		t.Run(c.ID, func(t *testing.T) {
			r := loadCase(t, c)
			v, err := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), r)
			wantAccepted(t, v, err)
			pk := firstPacketOf(t, r.Files[handoff.FileSubkey])
			if !pk.IsSubkey {
				t.Fatal("the first packet is not a subkey")
			}
			if got := hex.EncodeToString(pk.Fingerprint); v.Subkey.Fingerprint != got {
				t.Errorf("fingerprint %s, go-crypto reads %s", v.Subkey.Fingerprint, got)
			}
			if !v.Subkey.Created.Equal(pk.CreationTime) {
				t.Errorf("created %v, go-crypto reads %v", v.Subkey.Created, pk.CreationTime)
			}
			if want := capabilityOfCase(c); v.Subkey.Capability != want {
				t.Errorf("capability %q, want %q", v.Subkey.Capability, want)
			}
			raw, ok := pk.PublicKey.(*goecdsa.PublicKey)
			if !ok {
				t.Fatalf("the key is %T", pk.PublicKey)
			}
			want, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw.MarshalPoint())
			if err != nil {
				t.Fatal(err)
			}
			if !v.Key.Equal(want) {
				t.Error("the key of the verdict is not the point of the subkey")
			}
		})
	}
	if seen == 0 {
		t.Fatal("no accepted OpenPGP case: a check that finds nothing to check fails")
	}
}

// The primaries of the pinned root list are the ones the proofs of the vectors list, in the order of the list,
// and the primary that is not listed is the one that the unknown-primary case names.
func TestThePinnedPrimariesAreTheOnesTheVectorProofsList(t *testing.T) {
	m := readManifest(t)
	primaries := primariesOfManifest(t, m)
	var listed []string
	for _, p := range primaries {
		listed = append(listed, p.Fingerprint)
	}
	proofOf := func(id string) (p struct {
		Primaries []string `json:"primaries"`
	}) {
		if err := json.Unmarshal(testrepo.Read(t, vectorsDir, "requests", id+".proof.json"), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := proofOf("pgp-software-valid").Primaries; !slices.Equal(got, listed) {
		t.Errorf("the valid case lists %v, the pinned list is %v", got, listed)
	}
	if len(m.Pinned.NotListed.OpenPGP) == 0 {
		t.Fatal("the manifest names no primary that is not listed")
	}
	z := primaryOfFile(t, testrepo.Read(t, vectorsDir, m.Pinned.NotListed.OpenPGP[0]))
	if z.Fingerprint == listed[0] || z.Fingerprint == listed[1] {
		t.Error("the primary that is not listed is a listed one")
	}
	if got := proofOf("pgp-unknown-primary").Primaries; !slices.Contains(got, z.Fingerprint) {
		t.Errorf("the unknown-primary case lists %v and not %s", got, z.Fingerprint)
	}
	if got := proofOf("pgp-primaries-incomplete").Primaries; len(got) != 1 || got[0] != listed[0] && got[0] != listed[1] {
		t.Errorf("the incomplete case lists %v", got)
	}
}

// The same vector with the list of the checker in another order, or a capability of another kind, or no
// delegation: what the page says for each.
func TestTheValidOpenPGPVectorWithAChangedCheckerIsRefusedWhereThePageSays(t *testing.T) {
	m, cases := openpgpCases(t)
	roots := rootsOfManifest(t, m)
	var c vectorCase
	for _, k := range cases {
		if k.ID == "pgp-software-valid" {
			c = k
		}
	}
	if c.ID == "" {
		t.Fatal("the manifest holds no pgp-software-valid")
	}
	run := func(change func(cfg *handoff.Config)) (handoff.Verdict, error) {
		return changedCheckerOfCase(t, m, c, roots, change).Check(t.Context(), loadCase(t, c))
	}
	v, err := run(func(cfg *handoff.Config) { slices.Reverse(cfg.Primaries) })
	wantRefusal(t, v, err, handoff.CodeUnknownPrimary, 3)
	v, err = run(func(cfg *handoff.Config) { cfg.Primaries = cfg.Primaries[:1] })
	wantRefusal(t, v, err, handoff.CodeUnknownPrimary, 3)
	v, err = run(func(cfg *handoff.Config) { cfg.Delegation.Capability = "authenticate" })
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
	// The clock before the back-signatures of the vectors: possession-invalid.
	v, err = run(func(cfg *handoff.Config) {
		cfg.Now = func() time.Time { return time.Date(2026, 10, 20, 0, 0, 30, 0, time.UTC) }
	})
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	// No delegation: every rule that can run passes, the two that need one are named, and nothing is accepted.
	v, err = run(func(cfg *handoff.Config) { cfg.Delegation = nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := statuses(v); got != "ppppppppn" || v.Accepted() || v.Refused() || v.Complete() || v.Subkey != nil || v.Key != nil {
		t.Errorf("statuses %s, accepted %v, refused %v", got, v.Accepted(), v.Refused())
	}
	if !slices.Equal(v.Checks[8].NotRun, []string{"delegation-type", "capability"}) {
		t.Errorf("check 9 names %v as not run", v.Checks[8].NotRun)
	}
}

// With no delegation the decided OpenPGP vectors keep their codes.
func TestTheOpenPGPVectorsWithNoDelegationKeepTheirCodesAndNeverAreAccepted(t *testing.T) {
	m, cases := openpgpCases(t)
	roots := rootsOfManifest(t, m)
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			chk := changedCheckerOfCase(t, m, c, roots, func(cfg *handoff.Config) { cfg.Delegation = nil })
			v, err := chk.Check(t.Context(), loadCase(t, c))
			if err != nil {
				t.Fatal(err)
			}
			if v.Accepted() {
				t.Fatal("a request is accepted with no delegation")
			}
			if c.Expect == "accept" {
				if got := statuses(v); got != "ppppppppn" {
					t.Errorf("statuses %s", got)
				}
				return
			}
			if string(v.Code) != c.Reason || statuses(v) != statusesOfCase(c) {
				t.Errorf("code %q, statuses %s; the page gives %s and %s", v.Code, statuses(v), c.Reason, statusesOfCase(c))
			}
		})
	}
}

// TestOpenPGPVectorDetails only logs: for each OpenPGP case of the vectors it prints the statuses, the code and
// the detail of the verdict, so that a person can read that the code and the place of each fault are the ones
// the contract names. Run it with -v.
func TestOpenPGPVectorDetails(t *testing.T) {
	m, cases := openpgpCases(t)
	roots := rootsOfManifest(t, m)
	for _, c := range cases {
		v, err := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), loadCase(t, c))
		t.Logf("%-34s %s  %-22s %v %s", c.ID, statuses(v), v.Code, err, v.Detail)
	}
}

// TestOpenPGPOneByte checks one request that a person has changed by hand. It reads the proof file and the subkey
// file named in the folder of the environment variable RITUEEL_TRY_DIR (try.proof.json and try.subkey.pgp), runs the
// checks of the vectors' configuration on them with the clock of the vectors, and logs the verdict. It skips when the
// variable is not set, and it writes nothing.
func TestOpenPGPOneByte(t *testing.T) {
	dir := os.Getenv("RITUEEL_TRY_DIR")
	if dir == "" {
		t.Skip("RITUEEL_TRY_DIR is not set")
	}
	m := readManifest(t)
	proof, err := os.ReadFile(filepath.Join(dir, "try.proof.json"))
	if err != nil {
		t.Fatal(err)
	}
	subkey, err := os.ReadFile(filepath.Join(dir, "try.subkey.pgp"))
	if err != nil {
		t.Fatal(err)
	}
	c := vectorCase{ID: "try", Type: string(handoff.TypeOpenPGP), Config: "development"}
	r := &handoff.Request{Stem: "try", Files: map[string][]byte{handoff.FileProof: proof, handoff.FileSubkey: subkey}}
	v, err := checkerOfCase(t, m, c, rootsOfManifest(t, m), testNow).Check(t.Context(), r)
	t.Logf("%s  %s  %v  %s", statuses(v), v.Code, err, v.Detail)
}
