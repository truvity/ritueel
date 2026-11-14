package handoff_test

import (
	"crypto/x509/pkix"
	"errors"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/handoff"
)

// A checker with no delegation runs every rule of check 9 that does not need one, does not run the two that
// do (a request is of the delegation's type, and its name constraints are inside the delegation's lists), says
// so, and never accepts. These tests state that; the page of the command says the rules of one delegation are
// "reported as not run, never as passed".

// wantedNotRun is the list that a verdict of an X.509 request with no delegation names, in this order.
var wantedNotRun = []string{"delegation-type", "name-constraints"}

// noDelegation is the change that takes the delegation out of the default configuration.
func noDelegation(c *handoff.Config) { c.Delegation = nil }

// wantNotComplete checks the verdict of a request that every rule that could run has passed, and that the
// checker with no delegation could not accept: checks 1 to 8 passed, check 9 not run with the two rules named.
func wantNotComplete(t testing.TB, v handoff.Verdict, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if got := statuses(v); got != "pppppppp"+"n" {
		t.Fatalf("statuses %s, want checks 1 to 8 passed and check 9 not run", got)
	}
	if got := v.Checks[8].NotRun; !slices.Equal(got, wantedNotRun) {
		t.Fatalf("check 9 names %q as not run, want %q", got, wantedNotRun)
	}
	for i, c := range v.Checks[:8] {
		if len(c.NotRun) != 0 {
			t.Errorf("check %d, which passed, names %q as not run", i+1, c.NotRun)
		}
	}
	if v.Accepted() {
		t.Error("Accepted() is true with no delegation")
	}
	if v.Complete() {
		t.Error("Complete() is true although check 9 did not run")
	}
	if v.Refused() || v.Code != "" {
		t.Errorf("Refused() is %v and the code is %q: nothing was refused", v.Refused(), v.Code)
	}
	if v.Key != nil || v.Evidence != nil {
		t.Errorf("a verdict that is not accepted holds a key or evidence: %+v %+v", v.Key, v.Evidence)
	}
}

func TestACheckerWithNoDelegationIsMade(t *testing.T) {
	cfg := defaultConfig(t)
	cfg.Delegation = nil
	c, err := handoff.New(cfg)
	if err != nil || c == nil {
		t.Fatalf("checker %v, error %v", c, err)
	}
}

func TestEveryOtherPartIsStillRequiredWhenThereIsNoDelegation(t *testing.T) {
	for name, change := range map[string]func(c *handoff.Config){
		"the policy":                  func(c *handoff.Config) { c.Policy = handoff.Policy{} },
		"the stores of the policy":    func(c *handoff.Config) { c.Policy.Stores = nil },
		"the minimum firmware":        func(c *handoff.Config) { c.Policy.MinFirmware = "" },
		"the PIN policies":            func(c *handoff.Config) { c.Policy.PINPolicies = nil },
		"the roots":                   func(c *handoff.Config) { c.Roots = nil },
		"the roots, as an empty list": func(c *handoff.Config) { c.Roots = []handoff.RootRef{} },
		"the clock":                   func(c *handoff.Config) { c.Now = nil },
		"a verifier that is nil": func(c *handoff.Config) {
			c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: nil}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := defaultConfig(t)
			cfg.Delegation = nil
			change(&cfg)
			wantConfigError(t, cfg)
		})
	}
	// Nothing at all, and a nil delegation with no roots, as the page of the library says.
	wantConfigError(t, handoff.Config{})
}

func TestADelegationOfAnUnknownTypeIsStillRefusedAndANilOneIsNotAnUnknownType(t *testing.T) {
	for _, typ := range []handoff.Type{"", "x509", "X509-INTERMEDIATE", "x509-intermediate "} {
		cfg := defaultConfig(t)
		cfg.Delegation.Type = typ
		wantConfigError(t, cfg)
	}
}

func TestASoftwareRequestWithNoDelegationRunsEveryCheckBeforeNineAndIsNotAccepted(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v, err := newCheckerWith(t, noDelegation).Check(t.Context(), f.request())
	wantNotComplete(t, v, err)
}

func TestTheSameRequestIsAcceptedWithADelegationAndNotWithout(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	with, err := newChecker(t).Check(t.Context(), f.request())
	wantAccepted(t, with, err)
	without, err := newCheckerWith(t, noDelegation).Check(t.Context(), f.request())
	wantNotComplete(t, without, err)
	for i := range 8 {
		if with.Checks[i].Status != without.Checks[i].Status || with.Checks[i].Name != without.Checks[i].Name {
			t.Errorf("check %d differs: %+v and %+v", i+1, with.Checks[i], without.Checks[i])
		}
	}
}

func TestTheNotRunListIsAFreshCopyForEachVerdict(t *testing.T) {
	chk := newCheckerWith(t, noDelegation)
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	first, err := chk.Check(t.Context(), f.request())
	wantNotComplete(t, first, err)
	first.Checks[8].NotRun[0] = "changed by the caller"
	second, err := chk.Check(t.Context(), f.request())
	wantNotComplete(t, second, err)
}

// Every rule that can run without a delegation still refuses, with the code policy at check 9, as with one.
func TestARuleThatRunsWithNoDelegationStillRefusesWithPolicy(t *testing.T) {
	noDel := func(c *handoff.Config) { noDelegation(c) }
	t.Run("firmware older than the minimum", func(t *testing.T) {
		v, err := pivVerdictCfg(t, noDel, func(ev *handoff.Evidence) { ev.Firmware = "5.6.9" })
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
	t.Run("a firmware that is not three numbers", func(t *testing.T) {
		v, err := pivVerdictCfg(t, noDel, func(ev *handoff.Evidence) { ev.Firmware = "5.7" })
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
	t.Run("the PIN policy never", func(t *testing.T) {
		v, err := pivVerdictCfg(t, noDel, func(ev *handoff.Evidence) { ev.PINPolicy = handoff.PINNever })
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
	t.Run("no firmware in the evidence of a PIV key", func(t *testing.T) {
		v, err := pivVerdictCfg(t, noDel, func(ev *handoff.Evidence) { ev.Firmware = "" })
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
	t.Run("a PIV key that is as the policy wants is not accepted either", func(t *testing.T) {
		v, err := pivVerdictCfg(t, noDel, nil)
		wantNotComplete(t, v, err)
	})
	t.Run("a KMS key whose policy allows two principals", func(t *testing.T) {
		f := newFixture(t, handoff.StoreKMS, csrSpec{})
		ev := f.goodEvidence(handoff.StoreKMS)
		ev.SignPrincipals = append(ev.SignPrincipals, handoff.Principal{ARN: "arn:aws:iam::123456789012:role/example-other", Kind: handoff.PrincipalRole})
		v, err := checkerWithCfg(t, handoff.StoreKMS, returning(ev), noDel).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
	t.Run("a KMS key whose policy allows nobody", func(t *testing.T) {
		f := newFixture(t, handoff.StoreKMS, csrSpec{})
		ev := f.goodEvidence(handoff.StoreKMS)
		ev.SignPrincipals = nil
		v, err := checkerWithCfg(t, handoff.StoreKMS, returning(ev), noDel).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
	t.Run("a KMS key with one principal is not accepted", func(t *testing.T) {
		f := newFixture(t, handoff.StoreKMS, csrSpec{})
		v, err := checkerWithCfg(t, handoff.StoreKMS, returning(f.goodEvidence(handoff.StoreKMS)), noDel).Check(t.Context(), f.request())
		wantNotComplete(t, v, err)
	})
	t.Run("the key of the request is the key of a root", func(t *testing.T) {
		f := newFixture(t, handoff.StoreSoftware, csrSpec{})
		chk := newCheckerWith(t, func(c *handoff.Config) {
			noDelegation(c)
			c.Roots = append(c.Roots, handoff.RootRef{Subject: newRoot(t, "Example Test Other Root").subject, Key: f.publicKey()})
		})
		v, err := chk.Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
	t.Run("the subject of the request is the name of a root", func(t *testing.T) {
		f := newFixture(t, handoff.StoreSoftware, csrSpec{})
		same := newRoot(t, defaultSubject().CommonName)
		chk := newCheckerWith(t, func(c *handoff.Config) {
			noDelegation(c)
			c.Roots = append(c.Roots, same.ref())
		})
		v, err := chk.Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
}

// The rules about the request itself and the extensions need no delegation, and the refusal is the same
// with and without one.
func TestARequestThatThePageRefusesForItsContentIsRefusedWithNoDelegationToo(t *testing.T) {
	host := uriName("example.org")
	good := goodExtensions(host)
	san := pkix.Extension{Id: oidSubjectAltName, Value: tlv(0x30, tlv(0x82, []byte("example.org")))}
	for name, exts := range map[string][]pkix.Extension{
		"a fifth extension":                        append(slices.Clone(good), san),
		"no extended key usage":                    dropExt(good, oidEKU),
		"an extended key usage that is critical":   replaceExt(good, extEKU(true, oidServerAuth)),
		"a basic constraints that is not critical": replaceExt(good, extBasic(false, 0)),
		"a path length of one":                     replaceExt(good, extBasic(true, 1)),
		"a key usage without keyCertSign":          replaceExt(good, extKeyUsage(false, keyCertSign)),
		"an extension twice":                       append(slices.Clone(good), good[0]),
		"no key usage":                             dropExt(good, oidKeyUsage),
		"no basic constraints":                     dropExt(good, oidBasicConstraints),
		"name constraints that are not critical":   replaceExt(good, extNameConstraints(false, []generalName{host}, allIPs())),
		"an excluded subtree that is not an IP":    replaceExt(good, extNameConstraints(true, []generalName{host}, []generalName{dnsName("example.net")})),
		"a permitted name that is not a host name": replaceExt(good, extNameConstraints(true, []generalName{uriName("Example.ORG")}, allIPs())),
		"a permitted e-mail name":                  replaceExt(good, extNameConstraints(true, []generalName{emailName("example.org")}, allIPs())),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ncVerdict(t, newCheckerWith(t, noDelegation), exts)
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

// The page says name constraints are "Present", with at least one permitted subtree, in every request; that
// part of the rule needs no delegation, so a request that has none is refused with no delegation too, and is
// not reported as a request whose only open question is the delegation's lists. The page of the contract
// ("Policy (check 9)", row "Name constraints") states "Present" apart from "inside the entries the policy
// lists".
func TestARequestWithNoPermittedNameIsRefusedWithNoDelegationToo(t *testing.T) {
	for name, exts := range map[string][]pkix.Extension{
		"no name constraints":  dropExt(goodExtensions(uriName("example.org")), oidNameConstraints),
		"no permitted subtree": replaceExt(goodExtensions(), extNameConstraints(true, nil, allIPs())),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ncVerdict(t, newCheckerWith(t, noDelegation), exts)
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

// With no delegation the two rules are not run, so a name outside every list, and a request of another type
// than the delegation's, do not refuse: that is the whole difference, and it is named.
func TestARequestOutsideTheListsOfADelegationIsNotRefusedWhereThereIsNoDelegation(t *testing.T) {
	outside := goodExtensions(uriName("example.net"), dnsName("example.net"))
	v, err := ncVerdict(t, newChecker(t), outside)
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
	v, err = ncVerdict(t, newCheckerWith(t, noDelegation), outside)
	wantNotComplete(t, v, err)
}

func TestEveryRefusalBeforeCheckNineIsTheSameWithNoDelegation(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	other := newFixture(t, handoff.StoreSoftware, csrSpec{})
	badProof := func(change func(p map[string]any)) *handoff.Request {
		g := newFixture(t, handoff.StoreSoftware, csrSpec{})
		change(g.proof)
		return g.request()
	}
	for name, req := range map[string]*handoff.Request{
		"version 2":                badProof(func(p map[string]any) { p["handoff"] = 2 }),
		"a proof for another csr":  func() *handoff.Request { r := f.request(); r.Files[handoff.FileCSR] = other.csr; return r }(),
		"a store the policy lacks": badProof(func(p map[string]any) { p["store"] = "tpm" }),
		"an unknown member":        badProof(func(p map[string]any) { p["extra"] = 1 }),
		"a bad csr":                func() *handoff.Request { r := f.request(); r.Files[handoff.FileCSR] = []byte("not pem"); return r }(),
	} {
		t.Run(name, func(t *testing.T) {
			with, werr := newChecker(t).Check(t.Context(), req)
			without, nerr := newCheckerWith(t, noDelegation).Check(t.Context(), req)
			if (werr == nil) != (nerr == nil) || (werr != nil && werr.Error() != nerr.Error()) {
				t.Fatalf("errors differ: %v and %v", werr, nerr)
			}
			if with.Code != without.Code || with.Detail != without.Detail || statuses(with) != statuses(without) {
				t.Errorf("with a delegation %q %q %s, without %q %q %s", with.Code, with.Detail, statuses(with), without.Code, without.Detail, statuses(without))
			}
			if !without.Refused() {
				t.Errorf("the request is not refused: %s", statuses(without))
			}
		})
	}
}

func TestARequestOfAnotherTypeStopsWhereItDidWithNoDelegation(t *testing.T) {
	for name, req := range map[string]*handoff.Request{"openpgp-subkey": pgpRequest(nil), "ssh-ca-key": sshRequest(nil)} {
		t.Run(name, func(t *testing.T) {
			with, werr := newChecker(t).Check(t.Context(), req)
			without, nerr := newCheckerWith(t, noDelegation).Check(t.Context(), req)
			if !errors.Is(werr, handoff.ErrTypeNotBuilt) || !errors.Is(nerr, handoff.ErrTypeNotBuilt) {
				t.Fatalf("errors %v and %v, want ErrTypeNotBuilt", werr, nerr)
			}
			if statuses(with) != statuses(without) || without.Refused() || without.Complete() || without.Accepted() {
				t.Errorf("statuses %s and %s; refused %v complete %v accepted %v", statuses(with), statuses(without), without.Refused(), without.Complete(), without.Accepted())
			}
		})
	}
}

func TestAPivRequestWithNoVerifierStopsAtCheckSevenWithNoDelegationToo(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	v, err := newCheckerWith(t, noDelegation).Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrNoVerifier, "ppppppnnn")
}

// A verdict with check 9 not run is not an acceptance whatever the rest says: the one way to ask is Accepted().
func TestAVerdictThatHoldsANotRunCheckNineIsNeverAccepted(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v, err := newCheckerWith(t, noDelegation).Check(t.Context(), f.request())
	wantNotComplete(t, v, err)
	// Pretend the check passed and left its not-run list: still not accepted.
	v.Checks[8].Status = handoff.StatusPassed
	if v.Accepted() {
		t.Error("a passed check that names rules as not run is accepted")
	}
}

// The vectors: every X.509 case, run twice with the same verifiers, with and without the delegation.
func TestEveryVectorCaseWithNoDelegationIsTheCaseWithOneUpToTheTwoRules(t *testing.T) {
	m := readManifest(t)
	roots := rootsOfManifest(t, m)
	v := fuzzVerifier{}
	evidence := map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: v, handoff.StoreKMS: v, handoff.StoreOpenPGPCard: v}
	delegationRules := []string{
		"the type of the request is not the type of the delegation",
		"the name constraints have no permitted subtree",
		"a permitted URI constraint is not an entry of the delegation",
		"a permitted DNS name is not an entry of the delegation",
	}
	var compared, accepted, partial, refusedAt9, refusedEarlier int
	for _, c := range m.Cases {
		if c.Type != "x509-intermediate" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			req := loadCase(t, c)
			cfg := configOfCase(t, m, c, roots, testNow)
			cfg.Evidence = evidence
			with, werr := mustNew(t, cfg).Check(t.Context(), req)
			cfg = configOfCase(t, m, c, roots, testNow)
			cfg.Evidence = evidence
			cfg.Delegation = nil
			without, nerr := mustNew(t, cfg).Check(t.Context(), req)
			if werr != nil || nerr != nil {
				t.Fatalf("errors %v and %v", werr, nerr)
			}
			compared++
			if without.Accepted() {
				t.Fatalf("the case is accepted with no delegation: %s", statuses(without))
			}
			switch {
			case with.Accepted():
				accepted++
				wantNotComplete(t, without, nil)
				partial++
			case with.Refused() && with.Checks[8].Status == handoff.StatusNotRun:
				refusedEarlier++
				if with.Code != without.Code || with.Detail != without.Detail || statuses(with) != statuses(without) {
					t.Errorf("a refusal before check 9 differs: %q %q %s and %q %q %s", with.Code, with.Detail, statuses(with), without.Code, without.Detail, statuses(without))
				}
			case with.Refused():
				refusedAt9++
				byDelegation := slices.ContainsFunc(delegationRules, func(p string) bool { return strings.HasPrefix(with.Detail, p) })
				if byDelegation {
					// The two rules are not run; the rules that ran passed. The one exception is the presence of
					// name constraints, which needs no delegation (the test above).
					if strings.HasPrefix(with.Detail, "the name constraints have no permitted subtree") {
						if !without.Refused() || without.Code != handoff.CodePolicy {
							t.Errorf("a request with no permitted name is not refused with no delegation: %s %q", statuses(without), without.Detail)
						}
						return
					}
					wantNotComplete(t, without, nil)
					return
				}
				if with.Code != without.Code || with.Detail != without.Detail || statuses(with) != statuses(without) {
					t.Errorf("a refusal of a rule that needs no delegation differs: %q %q and %q %q", with.Code, with.Detail, without.Code, without.Detail)
				}
			default:
				t.Fatalf("a verdict that is neither accepted nor refused: %s", statuses(with))
			}
		})
	}
	if compared < 100 || accepted == 0 || refusedAt9 == 0 || refusedEarlier == 0 {
		t.Errorf("compared %d X.509 cases: %d accepted, %d refused at check 9, %d refused earlier; each kind must occur", compared, accepted, refusedAt9, refusedEarlier)
	}
	t.Logf("%d X.509 cases: %d accepted with a delegation, %d refused at check 9, %d refused before it; %d not complete with none", compared, accepted, refusedAt9, refusedEarlier, partial)
}

// ValidStem is the form of the stem that LoadRequest holds to.
func TestValidStemIsTheStemOfTheContract(t *testing.T) {
	for _, tc := range []struct {
		stem string
		ok   bool
	}{
		{"a", true}, {"0", true}, {"example-request", true}, {"a-b-c", true}, {"9lives", true}, {"a--b", true}, {"a-", true},
		{strings.Repeat("a", 63), true}, {strings.Repeat("a", 64), false}, {"", false},
		{"-a", false}, {"-", false}, {"A", false}, {"aB", false}, {"a_b", false}, {"a.b", false}, {"a b", false}, {" a", false}, {"a ", false},
		{"a/b", false}, {"../a", false}, {"..", false}, {".", false}, {"a\x00", false}, {"a\n", false}, {"\u00e4", false}, {"a\u00e4", false},
		{"\u0430", false}, {"a\u200b", false}, {"a:b", false}, {"a%2fb", false}, {"a,b", false},
	} {
		if got := handoff.ValidStem(tc.stem); got != tc.ok {
			t.Errorf("ValidStem(%q) = %v, want %v", tc.stem, got, tc.ok)
		}
	}
}

// A stem that ValidStem refuses is refused by LoadRequest, and one it accepts is not refused for its form.
func TestLoadRequestAndValidStemAgree(t *testing.T) {
	root := openEmptyFS(t)
	for _, stem := range []string{"a", "example-request", strings.Repeat("a", 63), "", "-a", "A", "a.b", "a/b", strings.Repeat("a", 64), "..", "a b"} {
		_, err := handoff.LoadRequest(root, "requests", stem)
		formRefused := err != nil && strings.Contains(err.Error(), "the stem is not")
		if formRefused == handoff.ValidStem(stem) {
			t.Errorf("stem %q: ValidStem %v, LoadRequest refuses its form %v (error %v)", stem, handoff.ValidStem(stem), formRefused, err)
		}
	}
}

// openEmptyFS opens an empty folder through package fsx.
func openEmptyFS(t testing.TB) fsx.FS {
	t.Helper()
	root, err := fsx.OpenFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}
