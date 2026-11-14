package handoff_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/testrepo"
)

// The vectors of the hand-off contract, read through their manifest. A request case is decided by the
// code when its verdict is a verdict. A case that needs the evidence of a key store, or the checks of a
// type that are not built, is named in pending with the work that will decide it; the test fails when a
// pending case is decided (so the map shrinks) and when a case that is not in the map is not decided
// as the manifest says.

const vectorsDir = "testdata/hand-off/v1"

type vectorConfig struct {
	Stores                 []string          `json:"stores"`
	MinFirmware            string            `json:"min_firmware"`
	PINPolicy              []string          `json:"pin_policy"`
	RequireNameConstraints bool              `json:"require_name_constraints"`
	PermittedURIHosts      []string          `json:"permitted_uri_hosts"`
	PermittedDNSNames      []string          `json:"permitted_dns_names"`
	ValidityMonths         int               `json:"validity_months"`
	KMSReadRoles           map[string]string `json:"kms_read_roles"`
}

type vectorCase struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	Config       string   `json:"config"`
	Files        []string `json:"files"`
	Expect       string   `json:"expect"`
	Reason       string   `json:"reason"`
	Confirmation string   `json:"confirmation"`
}

type vectorManifest struct {
	Clock  string `json:"clock"`
	Pinned struct {
		RootList                 struct{ X509 []string } `json:"root_list"`
		AttestationRoots         []string                `json:"attestation_roots"`
		AttestationIntermediates []string                `json:"attestation_intermediates"`
	}
	Configs map[string]vectorConfig `json:"configs"`
	Cases   []vectorCase            `json:"requests"`
}

func readManifest(t testing.TB) vectorManifest {
	t.Helper()
	var m vectorManifest
	if err := json.Unmarshal(testrepo.Read(t, vectorsDir, "manifest.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) == 0 {
		t.Fatal("the manifest holds no request case: a check that finds nothing to check fails")
	}
	return m
}

// rootsOfManifest are the roots on the pinned root list of the manifest.
func rootsOfManifest(t testing.TB, m vectorManifest) []handoff.RootRef {
	t.Helper()
	if len(m.Pinned.RootList.X509) < 2 {
		t.Fatalf("the pinned root list holds %d X.509 roots, want at least 2", len(m.Pinned.RootList.X509))
	}
	var roots []handoff.RootRef
	for _, f := range m.Pinned.RootList.X509 {
		block, _ := pem.Decode(testrepo.Read(t, vectorsDir, f))
		if block == nil {
			t.Fatalf("%s holds no PEM block", f)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("%s: the key is not ECDSA", f)
		}
		roots = append(roots, handoff.RootRef{Subject: cert.RawSubject, Key: key})
	}
	return roots
}

// configOfCase is the configuration of a checker for a case: the policy and the delegation that the case's
// named configuration holds, the roots of the pinned root list and the clock of the manifest.
func configOfCase(t testing.TB, m vectorManifest, c vectorCase, roots []handoff.RootRef, clock time.Time) handoff.Config {
	t.Helper()
	cfg, ok := m.Configs[c.Config]
	if !ok {
		t.Fatalf("case %s names the configuration %q, which the manifest does not hold", c.ID, c.Config)
	}
	if !cfg.RequireNameConstraints {
		t.Fatalf("case %s: the configuration %q does not require name constraints, and no configuration may switch the rule off", c.ID, c.Config)
	}
	p := handoff.Policy{MinFirmware: cfg.MinFirmware, ValidityMonths: cfg.ValidityMonths}
	for _, s := range cfg.Stores {
		p.Stores = append(p.Stores, handoff.Store(s))
	}
	for _, s := range cfg.PINPolicy {
		p.PINPolicies = append(p.PINPolicies, handoff.PINPolicy(s))
	}
	d := &handoff.Delegation{
		Name:              "example-intermediate",
		Type:              handoff.Type(c.Type),
		Root:              "example-root",
		PermittedURIHosts: cfg.PermittedURIHosts,
		PermittedDNSNames: cfg.PermittedDNSNames,
		KMSReadRoles:      cfg.KMSReadRoles,
	}
	return handoff.Config{Policy: p, Delegation: d, Roots: roots, Now: func() time.Time { return clock }}
}

// vectorVerifiers are the evidence verifiers that the vector test registers for every case, one function
// for each store family. A file of this package that tests a verifier appends its own in init, so that no
// file edits a line of another's. A function returns the verifiers it has for the case, by store.
var vectorVerifiers []func(t testing.TB, m vectorManifest, c vectorCase, cfg handoff.Config) map[handoff.Store]handoff.EvidenceVerifier

// checkerOfCase is the checker of a case, with the verifiers that the test gives and the registered ones.
func checkerOfCase(t testing.TB, m vectorManifest, c vectorCase, roots []handoff.RootRef, clock time.Time, evidence ...map[handoff.Store]handoff.EvidenceVerifier) *handoff.Checker {
	t.Helper()
	cfg := configOfCase(t, m, c, roots, clock)
	all := map[handoff.Store]handoff.EvidenceVerifier{}
	for _, mk := range vectorVerifiers {
		maps.Copy(all, mk(t, m, c, cfg))
	}
	for _, e := range evidence {
		maps.Copy(all, e)
	}
	if len(all) > 0 {
		cfg.Evidence = all
	}
	return mustNew(t, cfg)
}

// loadCase reads the files of a case through LoadRequest. The stem is the one of the proof file named
// in the case: a case may share the files of another.
func loadCase(t testing.TB, c vectorCase) *handoff.Request {
	t.Helper()
	var stem string
	for _, f := range c.Files {
		if s, ok := strings.CutSuffix(path.Base(f), "."+handoff.FileProof); ok {
			stem = s
		}
	}
	if stem == "" {
		t.Fatalf("case %s names no proof file: %v", c.ID, c.Files)
	}
	for _, f := range c.Files {
		if path.Dir(f) != "requests" || !strings.HasPrefix(path.Base(f), stem+".") {
			t.Fatalf("case %s: the file %s is not of the stem %s in requests/", c.ID, f, stem)
		}
	}
	root, err := fsx.OpenFS(testrepo.Path(t, vectorsDir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	r, err := handoff.LoadRequest(root, "requests", stem)
	if err != nil {
		t.Fatalf("case %s: %v", c.ID, err)
	}
	// The files that the case names are the files that were read, and no others of its own.
	for _, f := range c.Files {
		suffix := strings.TrimPrefix(path.Base(f), stem+".")
		if _, ok := r.Files[suffix]; !ok {
			t.Fatalf("case %s: LoadRequest did not return %s", c.ID, f)
		}
	}
	return r
}

// accepted reports whether the verdict is an acceptance of checks 1 to 9: the one call that says so.
func accepted(v handoff.Verdict, err error) bool {
	return err == nil && v.Accepted()
}

// matches reports whether the verdict is what the manifest says for a case. A case with a confirmation
// that is declined is accepted by checks 1 to 9 and then declined by the ceremony, which is not a
// check of this package.
func matches(c vectorCase, v handoff.Verdict, err error) bool {
	if err != nil {
		return false
	}
	switch {
	case c.Confirmation == "declined":
		return c.Expect == "refuse" && c.Reason == "declined" && accepted(v, nil)
	case c.Expect == "accept":
		return accepted(v, nil)
	case c.Expect == "refuse":
		return v.Refused() && string(v.Code) == c.Reason
	}
	return false
}

// pending names, for each case that this package cannot decide yet, the work that will decide it.
const (
	laterKMS     = "the evidence verifier of AWS KMS keys"
	laterOpenPGP = "the checks 3 to 9 of an OpenPGP subkey request"
	laterSSH     = "the checks 4 to 9 of an SSH CA key request"
)

var pending = map[string]string{
	// X.509: the store's verifier is check 7 and is not built.
	"x509-kms-valid":                 laterKMS,
	"x509-kms-cross-account":         laterKMS,
	"x509-kms-cross-account-no-role": laterKMS,
	"x509-kms-key-mismatch":          laterKMS,
	"x509-kms-two-actors":            laterKMS,

	// OpenPGP: the back-signatures, the root list and the evidence.
	"pgp-backsig-missing":              laterOpenPGP,
	"pgp-backsig-missing-one":          laterOpenPGP,
	"pgp-backsig-wrong-primary":        laterOpenPGP,
	"pgp-backsig-wrong-type":           laterOpenPGP,
	"pgp-backsig-tampered":             laterOpenPGP,
	"pgp-backsig-no-key-id":            laterOpenPGP,
	"pgp-ed25519":                      laterOpenPGP,
	"pgp-unknown-primary":              laterOpenPGP,
	"pgp-primaries-incomplete":         laterOpenPGP,
	"pgp-piv-valid":                    laterOpenPGP,
	"pgp-kms-valid":                    laterOpenPGP,
	"pgp-openpgp-card-valid":           laterOpenPGP,
	"pgp-software-valid":               laterOpenPGP,
	"pgp-response-request":             laterOpenPGP,
	"pgp-openpgp-card-authenticate":    laterOpenPGP,
	"pgp-piv-key-mismatch":             laterOpenPGP,
	"pgp-openpgp-card-untrusted-chain": laterOpenPGP,

	// SSH CA key: the key, the signature, the store and the evidence.
	"ssh-bad-signature":          laterSSH,
	"ssh-wrong-namespace":        laterSSH,
	"ssh-ed25519":                laterSSH,
	"ssh-software-in-production": laterSSH,
	"ssh-openpgp-card":           laterSSH,
	"ssh-piv-key-mismatch":       laterSSH,
	"ssh-kms-key-mismatch":       laterSSH,
	"ssh-piv-untrusted-chain":    laterSSH,
	"ssh-piv-pin-never":          laterSSH,
	"ssh-kms-two-actors":         laterSSH,
	"ssh-piv-valid":              laterSSH,
	"ssh-kms-valid":              laterSSH,
	"ssh-software-valid":         laterSSH,
	"ssh-response-request":       laterSSH,
}

func TestVectorsAreDecidedOrPending(t *testing.T) {
	m := readManifest(t)
	roots := rootsOfManifest(t, m)
	clock, err := time.Parse(time.RFC3339, m.Clock)
	if err != nil {
		t.Fatal(err)
	}
	if !clock.Equal(testNow) {
		t.Fatalf("the manifest's clock is %s, and these tests were written for %s", clock, testNow)
	}

	known := map[string]bool{}
	for _, c := range m.Cases {
		if known[c.ID] {
			t.Fatalf("the manifest holds the case %s twice", c.ID)
		}
		known[c.ID] = true
	}
	for id := range pending {
		if !known[id] {
			t.Errorf("the pending map names %s, which the manifest does not hold", id)
		}
	}

	ran, decided := 0, 0
	var stillPending []string
	for _, c := range m.Cases {
		t.Run(c.ID, func(t *testing.T) {
			ran++
			chk := checkerOfCase(t, m, c, roots, clock)
			v, err := chk.Check(t.Context(), loadCase(t, c))
			later, isPending := pending[c.ID]
			undecided := errors.Is(err, handoff.ErrNoVerifier) || errors.Is(err, handoff.ErrTypeNotBuilt)
			switch {
			case isPending && undecided:
				stillPending = append(stillPending, c.ID)
				if v.Refused() && c.Expect == "accept" {
					t.Errorf("an undecided case that the manifest accepts is refused with %q", v.Code)
				}
				if v.Complete() {
					t.Errorf("an undecided case reads as complete (%s)", later)
				}
			case isPending:
				t.Errorf("the case is pending (%s) and is now decided: verdict %q, error %v. Take it out of the pending map", later, v.Code, err)
			case undecided:
				t.Errorf("an unlisted case is not decided: %v. Name the later work in the pending map", err)
			case err != nil:
				t.Errorf("an unlisted case gives the error %v", err)
			case !matches(c, v, err):
				t.Errorf("the manifest says %s %s %s, and the verdict is code %q (%s), statuses %s",
					c.Expect, c.Reason, c.Confirmation, v.Code, v.Detail, statuses(v))
			default:
				decided++
			}
		})
	}

	if ran != len(m.Cases) {
		t.Errorf("ran %d cases, the manifest holds %d", ran, len(m.Cases))
	}
	if decided+len(stillPending) != len(m.Cases) {
		t.Errorf("%d decided and %d pending are not the %d cases of the manifest", decided, len(stillPending), len(m.Cases))
	}
	if len(stillPending) != len(pending) {
		sort.Strings(stillPending)
		t.Errorf("the pending map has %d entries and %d cases are still undecided: %v", len(pending), len(stillPending), stillPending)
	}
	if decided == 0 {
		t.Error("no case is decided")
	}
	t.Logf("%d request cases: %d decided, %d pending", len(m.Cases), decided, len(stillPending))
}

// A case that the code cannot decide alone has a verdict up to the check that needs the missing part,
// and the checks before it passed: the refusal of an undecided case is never a code of a later check.
func TestAnUndecidedVectorStopsWhereTheMissingPartIs(t *testing.T) {
	m := readManifest(t)
	roots := rootsOfManifest(t, m)
	for _, c := range m.Cases {
		later, ok := pending[c.ID]
		if !ok {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			v, err := checkerOfCase(t, m, c, roots, testNow).Check(t.Context(), loadCase(t, c))
			switch later {
			case laterKMS:
				if !errors.Is(err, handoff.ErrNoVerifier) {
					t.Fatalf("error %v, want ErrNoVerifier", err)
				}
				if got := statuses(v); got != "ppppppnnn" {
					t.Errorf("statuses %s, want checks 1 to 6 passed and 7 to 9 not run", got)
				}
			default:
				if !errors.Is(err, handoff.ErrTypeNotBuilt) {
					t.Fatalf("error %v, want ErrTypeNotBuilt", err)
				}
				if v.Refused() {
					t.Errorf("the code %q was given for a type whose later checks are not built", v.Code)
				}
				if v.Checks[8].Status != handoff.StatusNotRun || v.Checks[3].Status != handoff.StatusNotRun {
					t.Errorf("a check after 3 ran: %s", statuses(v))
				}
			}
		})
	}
}

// A stub verifier reads what the case says about its evidence, and the code decides the cases that wait for
// a verifier of the store aws-kms. The stub knows nothing of the proof: it gives the key of the request
// unless the case is about the key, one role unless the case is about two, and a refusal for a chain or a
// role that is not there. The number of cases is the number of the pending entries that wait for a verifier;
// no number is written here.
func TestVectorsThatNeedAVerifierAreDecidedWithAStubbedOne(t *testing.T) {
	m := readManifest(t)
	roots := rootsOfManifest(t, m)
	other := newP384(t)
	var seen []string
	want := 0
	for _, later := range pending {
		if later == laterKMS {
			want++
		}
	}
	if want == 0 {
		t.Fatal("no pending case waits for a verifier: take this test out")
	}
	for _, c := range m.Cases {
		later, ok := pending[c.ID]
		if !ok || later != laterKMS {
			continue
		}
		seen = append(seen, c.ID)
		t.Run(c.ID, func(t *testing.T) {
			req := loadCase(t, c)
			key, err := pki.RequestKeyFile(req.Files[handoff.FileCSR])
			if err != nil {
				t.Fatal(err)
			}
			role := handoff.Principal{ARN: "arn:aws:iam::123456789012:role/example-holder", Kind: handoff.PrincipalRole}
			ev := &handoff.Evidence{Key: key, SignPrincipals: []handoff.Principal{role}}
			var verifyErr error
			switch {
			case strings.HasSuffix(c.ID, "key-mismatch"):
				ev.Key = &other.PublicKey
			case strings.HasSuffix(c.ID, "two-actors"):
				ev.SignPrincipals = append(ev.SignPrincipals, handoff.Principal{ARN: "arn:aws:iam::123456789012:role/example-other", Kind: handoff.PrincipalRole})
			case strings.HasSuffix(c.ID, "no-role"):
				verifyErr = &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "the role is not there"}
			}
			var sv *stub
			if verifyErr != nil {
				sv = failing(verifyErr)
			} else {
				sv = returning(ev)
			}
			chk := checkerOfCase(t, m, c, roots, testNow, map[handoff.Store]handoff.EvidenceVerifier{handoff.StoreKMS: sv})
			v, err := chk.Check(t.Context(), req)
			if !matches(c, v, err) {
				t.Errorf("the manifest says %s %s, and the verdict is code %q (%s), error %v", c.Expect, c.Reason, v.Code, v.Detail, err)
			}
			if sv.calls.Load() != 1 {
				t.Errorf("the verifier was called %d times, want once", sv.calls.Load())
			}
		})
	}
	if len(seen) != want {
		t.Errorf("%d cases were run, and the pending map names %d that wait for a verifier: %v", len(seen), want, seen)
	}
}

// Every case of the manifest has an outcome, a reason when it refuses, and one of the three types.
func TestEveryVectorCaseIsWellFormed(t *testing.T) {
	m := readManifest(t)
	byType := map[string]int{}
	for _, c := range m.Cases {
		byType[c.Type]++
		if c.Expect != "accept" && c.Expect != "refuse" {
			t.Errorf("case %s has the outcome %q", c.ID, c.Expect)
		}
		if c.Expect == "refuse" && c.Reason == "" {
			t.Errorf("case %s refuses with no reason", c.ID)
		}
		if !slices.Contains([]string{"x509-intermediate", "openpgp-subkey", "ssh-ca-key"}, c.Type) {
			t.Errorf("case %s has the type %q", c.ID, c.Type)
		}
	}
	if len(byType) != 3 {
		t.Errorf("the manifest holds the types %v, want the three of the contract", byType)
	}
}
