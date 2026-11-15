package handoff_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

var (
	oidCN     = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOU     = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidAnyEKU = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
)

// pivVerdict runs a PIV request with the evidence given and returns the verdict.
func pivVerdict(t *testing.T, change func(ev *handoff.Evidence)) (handoff.Verdict, error) {
	t.Helper()
	return pivVerdictCfg(t, nil, change)
}

// pivVerdictCfg is pivVerdict with a change to the configuration of the checker.
func pivVerdictCfg(t *testing.T, cfg func(c *handoff.Config), change func(ev *handoff.Evidence)) (handoff.Verdict, error) {
	t.Helper()
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	ev := f.goodEvidence(handoff.StorePIV)
	if change != nil {
		change(ev)
	}
	return checkerWithCfg(t, handoff.StorePIV, returning(ev), cfg).Check(t.Context(), f.request())
}

func TestTheFirmwareOfAYubiKeyIsComparedAsThreeNumbers(t *testing.T) {
	for _, tc := range []struct {
		firmware string
		ok       bool
	}{
		{"5.6.9", false}, {"5.6.0", false}, {"5.6.10", false}, {"4.9.9", false}, {"4.10.10", false}, {"0.0.0", false},
		{"5.7.0", true}, {"5.7.4", true}, {"5.7.10", true}, {"5.8.0", true}, {"5.10.0", true}, {"5.100.0", true}, {"6.0.0", true}, {"10.0.0", true}, {"5.7.1", true},
	} {
		t.Run(tc.firmware, func(t *testing.T) {
			v, err := pivVerdict(t, func(ev *handoff.Evidence) { ev.Firmware = tc.firmware })
			if tc.ok {
				wantAccepted(t, v, err)
			} else {
				wantRefusal(t, v, err, handoff.CodePolicy, 9)
			}
		})
	}
}

func TestAFirmwareThatIsNotThreeNumbersIsRefusedByThePolicy(t *testing.T) {
	for _, fw := range []string{"5.7", "5", "5.7.0.1", "five", "5.7.x", "-5.7.0", "5.-7.0", " 5.8.0", "5.8.0 ", "5..0", ".5.7", "5.7.", "5,8,0", "5.8.0-beta", "+5.8.0", "5.8.0\n", "5.8.99999999999"} {
		t.Run(fw, func(t *testing.T) {
			v, err := pivVerdict(t, func(ev *handoff.Evidence) { ev.Firmware = fw })
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestAMinimumFirmwareThatIsNotThreeNumbersIsAConfigurationFault(t *testing.T) {
	for _, bad := range []string{"", "5.7", "5", "5.7.0.1", "x.y.z", "5.7.-1", " 5.7.0", "5.7.0 ", "5..0", "5.7.99999999999", "+5.7.0", "5.7.0\x00"} {
		t.Run(bad, func(t *testing.T) {
			cfg := defaultConfig(t)
			cfg.Policy.MinFirmware = bad
			wantConfigError(t, cfg)
		})
	}
}

func TestThePINPolicyNeverIsRefusedAndOnceAndAlwaysAreAccepted(t *testing.T) {
	for _, tc := range []struct {
		pin handoff.PINPolicy
		ok  bool
	}{
		{handoff.PINNever, false}, {handoff.PINOnce, true}, {handoff.PINAlways, true}, {"sometimes", false}, {"ONCE", false}, {"Once ", false},
	} {
		t.Run(string(tc.pin), func(t *testing.T) {
			v, err := pivVerdict(t, func(ev *handoff.Evidence) { ev.PINPolicy = tc.pin })
			if tc.ok {
				wantAccepted(t, v, err)
			} else {
				wantRefusal(t, v, err, handoff.CodePolicy, 9)
			}
		})
	}
}

func TestThePINPoliciesThatAreAllowedAreTheOnesOfThePolicy(t *testing.T) {
	only := func(p handoff.PINPolicy) func(c *handoff.Config) {
		return func(c *handoff.Config) { c.Policy.PINPolicies = []handoff.PINPolicy{p} }
	}
	v, err := pivVerdictCfg(t, only(handoff.PINAlways), func(ev *handoff.Evidence) { ev.PINPolicy = handoff.PINOnce })
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
	v, err = pivVerdictCfg(t, only(handoff.PINNever), func(ev *handoff.Evidence) { ev.PINPolicy = handoff.PINNever })
	wantAccepted(t, v, err)
}

func TestAPolicyThatAllowsNoPINPolicyIsAConfigurationFaultAndNotARefusalOfEverything(t *testing.T) {
	for name, list := range map[string][]handoff.PINPolicy{"nil": nil, "empty": {}, "an unknown policy": {handoff.PINOnce, "sometimes"}} {
		t.Run(name, func(t *testing.T) {
			cfg := defaultConfig(t)
			cfg.Policy.PINPolicies = list
			wantConfigError(t, cfg)
		})
	}
}

func TestTheTouchPolicyIsRecordedAndNeverEnforced(t *testing.T) {
	for _, touch := range []string{"never", "always", "cached", "", "something else"} {
		v, err := pivVerdict(t, func(ev *handoff.Evidence) { ev.TouchPolicy = touch })
		wantAccepted(t, v, err)
		if v.Evidence.TouchPolicy != touch {
			t.Errorf("the touch policy %q was not recorded: %q", touch, v.Evidence.TouchPolicy)
		}
	}
}

func TestTheDetailsOfEvidenceAreKeptAsTheVerifierGaveThem(t *testing.T) {
	v, err := pivVerdict(t, func(ev *handoff.Evidence) { ev.Details = map[string]string{"serial": "1", "form_factor": "usb-a"} })
	wantAccepted(t, v, err)
	if v.Evidence.Details["serial"] != "1" || v.Evidence.Details["form_factor"] != "usb-a" {
		t.Errorf("details %v", v.Evidence.Details)
	}
}

func TestAPIVKeyWhoseEvidenceHoldsNoFirmwareOrNoPINPolicyIsNotAccepted(t *testing.T) {
	// The page makes both extensions of the attestation required (check 7), so evidence without them is a
	// fault of the verifier, and a request on it is not accepted.
	for name, change := range map[string]func(ev *handoff.Evidence){
		"no firmware":   func(ev *handoff.Evidence) { ev.Firmware = "" },
		"no PIN policy": func(ev *handoff.Evidence) { ev.PINPolicy = "" },
	} {
		t.Run(name, func(t *testing.T) {
			v, err := pivVerdict(t, change)
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

// The key of a card is a key of an openpgp-subkey request: an x509-intermediate request with this store
// does not reach the evidence (cardstore_test.go).

func TestAnOpenPGPCardKeyNeedsNoFirmwareAndNoPINPolicy(t *testing.T) {
	// The page: the extensions of the card's certificate are not specified yet, and a certifier that
	// cannot read them records the key as attested and enforces no PIN or touch policy.
	f := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	ev := &handoff.Evidence{Key: f.sub.pub()}
	v, err := f.checker(withVerifier(handoff.StoreOpenPGPCard, returning(ev))).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
}

func TestAnOpenPGPCardKeyWithAFirmwareThatIsOldIsRefused(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreOpenPGPCard)
	ev := &handoff.Evidence{Key: f.sub.pub(), Firmware: "5.6.9"}
	v, err := f.checker(withVerifier(handoff.StoreOpenPGPCard, returning(ev))).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
}

func kmsVerdict(t *testing.T, principals []handoff.Principal) (handoff.Verdict, error) {
	t.Helper()
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	ev := &handoff.Evidence{Key: f.publicKey(), SignPrincipals: principals}
	return checkerWith(t, handoff.StoreKMS, returning(ev)).Check(t.Context(), f.request())
}

func TestAKMSKeyMustNameOneSinglePrincipalThatIsARoleOrAUser(t *testing.T) {
	role := func(n string) handoff.Principal {
		return handoff.Principal{ARN: "arn:aws:iam::123456789012:role/" + n, Kind: handoff.PrincipalRole}
	}
	user := handoff.Principal{ARN: "arn:aws:iam::123456789012:user/example", Kind: handoff.PrincipalUser}
	root := handoff.Principal{ARN: "arn:aws:iam::123456789012:root", Kind: handoff.PrincipalRoot}
	wild := handoff.Principal{ARN: "*", Kind: handoff.PrincipalWildcard}
	other := handoff.Principal{ARN: "ec2.amazonaws.com", Kind: handoff.PrincipalOther}
	for _, tc := range []struct {
		name string
		list []handoff.Principal
		ok   bool
	}{
		{"none", nil, false},
		{"an empty list", []handoff.Principal{}, false},
		{"one role", []handoff.Principal{role("a")}, true},
		{"one user", []handoff.Principal{user}, true},
		{"the account root", []handoff.Principal{root}, false},
		{"a wildcard", []handoff.Principal{wild}, false},
		{"another kind of principal", []handoff.Principal{other}, false},
		{"two roles", []handoff.Principal{role("a"), role("b")}, false},
		{"a role and a user", []handoff.Principal{role("a"), user}, false},
		{"the same role twice", []handoff.Principal{role("a"), role("a")}, true},
		{"the same role three times", []handoff.Principal{role("a"), role("a"), role("a")}, true},
		{"the same user twice", []handoff.Principal{user, user}, true},
		{"a role and the wildcard", []handoff.Principal{role("a"), wild}, false},
		{"the wildcard and a role", []handoff.Principal{wild, role("a")}, false},
		{"a role and the root", []handoff.Principal{role("a"), root}, false},
		{"the root twice", []handoff.Principal{root, root}, false},
		{"one ARN with two kinds", []handoff.Principal{{ARN: role("a").ARN, Kind: handoff.PrincipalRole}, {ARN: role("a").ARN, Kind: handoff.PrincipalUser}}, false},
		{"two ARNs of one kind with one different letter", []handoff.Principal{role("a"), role("A")}, false},
		{"a kind that is empty", []handoff.Principal{{ARN: role("a").ARN}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := kmsVerdict(t, tc.list)
			if tc.ok {
				wantAccepted(t, v, err)
			} else {
				wantRefusal(t, v, err, handoff.CodePolicy, 9)
			}
		})
	}
}

func TestTheRulesOfAYubiKeyDoNotApplyToAKMSKey(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	ev := &handoff.Evidence{
		Key: f.publicKey(), Firmware: "", PINPolicy: "",
		SignPrincipals: []handoff.Principal{{ARN: "arn:aws:iam::1:role/r", Kind: handoff.PrincipalRole}},
	}
	v, err := checkerWith(t, handoff.StoreKMS, returning(ev)).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
}

func TestTheKMSRuleDoesNotApplyToAPIVKey(t *testing.T) {
	// A PIV key has no key policy: principals on its evidence are not read.
	v, err := pivVerdict(t, func(ev *handoff.Evidence) {
		ev.SignPrincipals = []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}, {ARN: "x", Kind: handoff.PrincipalRoot}}
	})
	wantAccepted(t, v, err)
}

// Name constraints

// ncVerdict runs a software request whose extensions are given, against the checker.
func ncVerdict(t *testing.T, chk *handoff.Checker, exts []pkix.Extension) (handoff.Verdict, error) {
	t.Helper()
	f := newFixture(t, handoff.StoreSoftware, csrSpec{exts: exts})
	return chk.Check(t.Context(), f.request())
}

func TestEveryPermittedNameMustEqualAnEntryTheDelegationLists(t *testing.T) {
	for _, tc := range []struct {
		name      string
		permitted []generalName
		uri, dns  []string
		ok        bool
	}{
		{"a host equal to the entry", []generalName{uriName("example.org")}, []string{"example.org"}, nil, true},
		{"another host", []generalName{uriName("example.net")}, []string{"example.org"}, nil, false},
		{"a host that is listed with another letter case in the list", []generalName{uriName("example.org")}, []string{"EXAMPLE.ORG"}, nil, false},
		{"a subdomain of the entry", []generalName{uriName("a.example.org")}, []string{"example.org"}, nil, false},
		{"the parent of the entry", []generalName{uriName("example.org")}, []string{"a.example.org"}, nil, false},
		{"a host with a leading period when only the host is listed", []generalName{uriName(".example.org")}, []string{"example.org"}, nil, false},
		{"a host with no period when only the period form is listed", []generalName{uriName("example.org")}, []string{".example.org"}, nil, false},
		{"a host with a leading period that is listed", []generalName{uriName(".example.org")}, []string{".example.org"}, nil, true},
		{"two hosts, both listed", []generalName{uriName("example.org"), uriName(".example.org")}, []string{"example.org", ".example.org"}, nil, true},
		{"two hosts, the second outside", []generalName{uriName("example.org"), uriName("example.net")}, []string{"example.org"}, nil, false},
		{"two hosts, the first outside", []generalName{uriName("example.net"), uriName("example.org")}, []string{"example.org"}, nil, false},
		{"a host and the list is empty", []generalName{uriName("example.org")}, nil, nil, false},
		{"a DNS name equal to the entry", []generalName{dnsName("example.org")}, nil, []string{"example.org"}, true},
		{"a DNS name that is another", []generalName{dnsName("example.net")}, nil, []string{"example.org"}, false},
		{"a DNS name below the entry", []generalName{dnsName("www.example.org")}, nil, []string{"example.org"}, false},
		{"a DNS name that is listed with capitals", []generalName{dnsName("example.org")}, nil, []string{"EXAMPLE.ORG"}, false},
		{"a DNS name when the list is empty", []generalName{dnsName("example.org")}, nil, nil, false},
		{"a DNS name that is only listed as a URI host", []generalName{dnsName("example.org")}, []string{"example.org"}, nil, false},
		{"a URI host that is only listed as a DNS name", []generalName{uriName("example.org")}, nil, []string{"example.org"}, false},
		{"a DNS name and a URI host, both listed", []generalName{dnsName("example.org"), uriName("example.org")}, []string{"example.org"}, []string{"example.org"}, true},
		{"a DNS name that is listed and a URI host that is not", []generalName{dnsName("example.org"), uriName("example.net")}, []string{"example.org"}, []string{"example.org"}, false},
		{"a DNS name that is not listed and a URI host that is", []generalName{dnsName("example.net"), uriName("example.org")}, []string{"example.org"}, []string{"example.org"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chk := newCheckerWith(t, func(c *handoff.Config) {
				c.Delegation.PermittedURIHosts, c.Delegation.PermittedDNSNames = tc.uri, tc.dns
			})
			v, err := ncVerdict(t, chk, goodExtensions(tc.permitted...))
			if tc.ok {
				wantAccepted(t, v, err)
			} else {
				wantRefusal(t, v, err, handoff.CodePolicy, 9)
			}
		})
	}
}

func TestANameConstraintThatIsNotWhatThePageAllowsIsRefusedWithPolicy(t *testing.T) {
	host := uriName("example.org")
	ip4 := ipRange(make([]byte, 4), make([]byte, 4))
	ip6 := ipRange(make([]byte, 16), make([]byte, 16))
	for name, nc := range map[string]pkix.Extension{
		"not critical":                                          extNameConstraints(false, []generalName{host}, allIPs()),
		"no permitted subtree":                                  extNameConstraints(true, nil, allIPs()),
		"an empty permitted list":                               extNameConstraints(true, []generalName{}, allIPs()),
		"an e-mail name as a permitted subtree":                 extNameConstraints(true, []generalName{host, emailName("example.org")}, allIPs()),
		"an IP range as a permitted subtree":                    extNameConstraints(true, []generalName{host, ip4}, allIPs()),
		"only one of the two excluded ranges":                   extNameConstraints(true, []generalName{host}, []generalName{ip4}),
		"only the IPv6 excluded range":                          extNameConstraints(true, []generalName{host}, []generalName{ip6}),
		"an excluded DNS subtree":                               extNameConstraints(true, []generalName{host}, append(allIPs(), dnsName("bad.example.org"))),
		"an excluded subtree that is a range of one address":    extNameConstraints(true, []generalName{host}, []generalName{ipRange([]byte{10, 0, 0, 0}, []byte{255, 0, 0, 0}), ip6}),
		"an excluded subtree with another range beside the two": extNameConstraints(true, []generalName{host}, append(allIPs(), ipRange([]byte{10, 0, 0, 0}, []byte{255, 0, 0, 0}))),
		"an excluded e-mail":                                    extNameConstraints(true, []generalName{host}, append(allIPs(), emailName("example.org"))),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ncVerdict(t, newChecker(t), replaceExt(goodExtensions(host), nc))
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestAnExcludedListOfNoneOrOfTheTwoRangesInEitherOrderIsAccepted(t *testing.T) {
	host := uriName("example.org")
	ip4 := ipRange(make([]byte, 4), make([]byte, 4))
	ip6 := ipRange(make([]byte, 16), make([]byte, 16))
	for name, excluded := range map[string][]generalName{
		"none":   nil,
		"v4, v6": {ip4, ip6},
		"v6, v4": {ip6, ip4},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ncVerdict(t, newChecker(t), replaceExt(goodExtensions(host), extNameConstraints(true, []generalName{host}, excluded)))
			wantAccepted(t, v, err)
		})
	}
}

func TestARequestWithNoNameConstraintsIsRefusedWithPolicy(t *testing.T) {
	v, err := ncVerdict(t, newChecker(t), dropExt(goodExtensions(uriName("example.org")), oidNameConstraints))
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
}

func TestADelegationWithNoListsOfNamesRefusesEveryRequestAndSwitchesNoRuleOff(t *testing.T) {
	// An empty list does not mean that the names are not held to the list: it means that no name is inside
	// it, so every request, which must have at least one permitted subtree, is refused.
	for name, uri := range map[string]generalName{"a host": uriName("example.org"), "another host": uriName("example.net"), "a DNS name": dnsName("example.org")} {
		t.Run(name, func(t *testing.T) {
			chk := newCheckerWith(t, func(c *handoff.Config) {
				c.Delegation.PermittedURIHosts, c.Delegation.PermittedDNSNames = nil, nil
			})
			v, err := ncVerdict(t, chk, goodExtensions(uri))
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestTheNameConstraintsThatThePageRequiresOfARequestAreAlwaysRequired(t *testing.T) {
	// The profile of the request has name constraints with at least one permitted subtree. Nothing in the
	// configuration, whatever the delegation lists, makes the request go without them.
	for name, exts := range map[string][]pkix.Extension{
		"none":                 dropExt(goodExtensions(uriName("example.org")), oidNameConstraints),
		"no permitted subtree": replaceExt(goodExtensions(), extNameConstraints(true, nil, allIPs())),
		"not critical":         replaceExt(goodExtensions(), extNameConstraints(false, []generalName{uriName("example.org")}, allIPs())),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ncVerdict(t, newChecker(t), exts)
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestARequestWhoseExtensionsAreNotTheOnesOfThePageIsRefusedWithPolicy(t *testing.T) {
	host := uriName("example.org")
	good := goodExtensions(host)
	san := pkix.Extension{Id: oidSubjectAltName, Value: tlv(0x30, tlv(0x82, []byte("example.org")))}
	for name, exts := range map[string][]pkix.Extension{
		"a fifth extension":                         append(slices.Clone(good), san),
		"a fifth extension that is critical":        append(slices.Clone(good), pkix.Extension{Id: oidSubjectAltName, Critical: true, Value: san.Value}),
		"no extended key usage":                     dropExt(good, oidEKU),
		"an extended key usage that is critical":    replaceExt(good, extEKU(true, oidServerAuth)),
		"an extended key usage of any purpose":      replaceExt(good, extEKU(false, oidAnyEKU)),
		"an extended key usage of serverAuth twice": replaceExt(good, extEKU(false, oidServerAuth, oidServerAuth)),
		"an empty extended key usage":               replaceExt(good, extEKU(false)),
		"a basic constraints that is not critical":  replaceExt(good, extBasic(false, 0)),
		"a path length of one":                      replaceExt(good, extBasic(true, 1)),
		"a key usage without keyCertSign":           replaceExt(good, extKeyUsage(true, 0x80)),
		"a key usage that is not critical":          replaceExt(good, extKeyUsage(false, keyCertSign)),
		"an extension twice":                        append(slices.Clone(good), good[0]),
		"no key usage":                              dropExt(good, oidKeyUsage),
		"no basic constraints":                      dropExt(good, oidBasicConstraints),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ncVerdict(t, newChecker(t), exts)
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestEachPurposeOfTheExtendedKeyUsageThatThePageAllowsIsAccepted(t *testing.T) {
	for name, eku := range map[string]pkix.Extension{
		"server and client": extEKU(false, oidServerAuth, oidClientAuth),
		"client and server": extEKU(false, oidClientAuth, oidServerAuth),
		"server":            extEKU(false, oidServerAuth),
		"client":            extEKU(false, oidClientAuth),
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ncVerdict(t, newChecker(t), replaceExt(goodExtensions(uriName("example.org")), eku))
			wantAccepted(t, v, err)
		})
	}
}

func TestARequestWithNoExtensionsAtAllIsMalformed(t *testing.T) {
	// The page lists a request with no extensions among the faults of its form: it has not exactly the one
	// extensionRequest attribute.
	f := newFixture(t, handoff.StoreSoftware, csrSpec{noExts: true})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

// The subject

func TestASubjectThatThePageRefusesIsRefusedWithPolicy(t *testing.T) {
	for name, subj := range map[string]pkix.Name{
		"a value with two spaces in a row":              {CommonName: "Example  Test"},
		"a value with a space at its end":               {CommonName: "Example Test "},
		"a value of 65 characters":                      {CommonName: strings.Repeat("a", 65)},
		"a value that is not ASCII":                     {CommonName: "Ex\u00e4mple"},
		"a country of three characters":                 {Country: []string{"NLD"}, CommonName: "Example Test"},
		"a common name twice":                           {ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidCN, Value: "A"}, {Type: oidCN, Value: "B"}}},
		"two organisational units in one relative name": {OrganizationalUnit: []string{"One", "Two"}, CommonName: "Example Test"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreSoftware, csrSpec{subject: &subj})
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestASubjectThatThePageAllowsIsAccepted(t *testing.T) {
	for name, subj := range map[string]pkix.Name{
		"a common name of 64 characters":         {CommonName: strings.Repeat("a", 64)},
		"two organisational units":               {CommonName: "Example Test", ExtraNames: []pkix.AttributeTypeAndValue{{Type: oidOU, Value: "One"}, {Type: oidOU, Value: "Two"}}},
		"an underscore, written as a UTF8String": {CommonName: "example_test"},
		"a country of two characters":            {Country: []string{"NL"}, CommonName: "Example Test"},
		"a value with a slash and equals":        {CommonName: "a/b=c, d"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreSoftware, csrSpec{subject: &subj})
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantAccepted(t, v, err)
		})
	}
}

// The delegation and the roots

func TestARequestOfAnotherTypeThanTheDelegationsIsRefusedWithPolicy(t *testing.T) {
	// A delegation of another type has no capability, and only an openpgp-subkey delegation has primaries and
	// a capability, so each is made as New asks for it.
	pgp := newPGPFixture(t, 1, handoff.StoreSoftware)
	for _, other := range []handoff.Type{handoff.TypeOpenPGP, handoff.TypeSSH} {
		t.Run(string(other), func(t *testing.T) {
			chk := newCheckerWith(t, func(c *handoff.Config) {
				c.Delegation.Type = other
				if other == handoff.TypeOpenPGP {
					c.Delegation.Capability = "sign"
					c.Primaries = pgp.refs()
				}
			})
			v, err := chk.Check(t.Context(), newFixture(t, handoff.StoreSoftware, csrSpec{}).request())
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestADelegationOfNoKnownTypeIsAConfigurationFault(t *testing.T) {
	for _, typ := range []handoff.Type{"", "something", "X509-INTERMEDIATE"} {
		t.Run(string(typ), func(t *testing.T) {
			cfg := defaultConfig(t)
			cfg.Delegation.Type = typ
			wantConfigError(t, cfg)
		})
	}
}

func TestTheKeyOfARootIsNotAKeyForARequest(t *testing.T) {
	root := newRoot(t, "Example Test Root")
	chk := newCheckerWith(t, func(c *handoff.Config) {
		c.Roots = []handoff.RootRef{newRoot(t, "Another Root").ref(), root.ref()}
	})
	f := newFixture(t, handoff.StoreSoftware, csrSpec{key: root.key})
	v, err := chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
}

func TestTheNameOfARootIsNotASubjectForARequest(t *testing.T) {
	root := newRoot(t, "Example Test Root")
	for name, subj := range map[string]pkix.Name{
		"the same name":               {CommonName: "Example Test Root", Organization: []string{"acme"}},
		"the same name in capitals":   {CommonName: "EXAMPLE TEST ROOT", Organization: []string{"ACME"}},
		"the same name in lower case": {CommonName: "example test root", Organization: []string{"acme"}},
	} {
		t.Run(name, func(t *testing.T) {
			chk := newCheckerWith(t, func(c *handoff.Config) {
				c.Roots = []handoff.RootRef{newRoot(t, "Another Root").ref(), root.ref()}
			})
			f := newFixture(t, handoff.StoreSoftware, csrSpec{subject: &subj})
			v, err := chk.Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestASubjectThatIsNotTheNameOfARootIsAccepted(t *testing.T) {
	chk := newCheckerWith(t, func(c *handoff.Config) {
		c.Roots = []handoff.RootRef{newRoot(t, "Example Test Root").ref(), newRoot(t, "Another Root").ref()}
	})
	subj := pkix.Name{CommonName: "Example Test Roots", Organization: []string{"acme"}}
	v, err := chk.Check(t.Context(), newFixture(t, handoff.StoreSoftware, csrSpec{subject: &subj}).request())
	wantAccepted(t, v, err)
}

func TestARootListThatCannotBeReadIsAConfigurationFault(t *testing.T) {
	good := newRoot(t, "Example Test Root")
	other := otherKeys(t)
	badName := handoff.RootRef{Subject: []byte{0x01, 0x02}, Key: &good.key.PublicKey}
	offCurve := handoff.RootRef{Subject: good.subject, Key: &ecdsa.PublicKey{Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(1)}} //nolint:staticcheck // a point off the curve is the case under test
	emptyName := handoff.RootRef{Subject: nil, Key: &good.key.PublicKey}
	for name, root := range map[string]handoff.RootRef{
		"a key that is not ECDSA":        {Subject: good.subject, Key: other["RSA-2048"].Public()},
		"a key that is on P-256":         {Subject: good.subject, Key: other["P-256"].Public()},
		"a key that is on P-521":         {Subject: good.subject, Key: other["P-521"].Public()},
		"no key":                         {Subject: good.subject},
		"a key that is not on the curve": offCurve,
		"a subject that is not a name":   badName,
		"no subject":                     emptyName,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := defaultConfig(t)
			cfg.Roots = []handoff.RootRef{good.ref(), root}
			wantConfigError(t, cfg)
		})
	}
}

func TestAStoreThatThePolicyDoesNotListIsNotAllowed(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS, handoff.StoreSoftware} {
		t.Run(string(store), func(t *testing.T) {
			f := newStoreCase(t, store)
			sv := returning(f.good())
			without := f.checker(sv, func(c *handoff.Config) {
				c.Policy.Stores = slices.DeleteFunc(slices.Clone(c.Policy.Stores), func(s handoff.Store) bool { return s == store })
			})
			v, err := without.Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
			if sv.calls.Load() != 0 {
				t.Error("the evidence of a store that is not allowed was read")
			}
			// Listed, it is accepted: it is the list that decides.
			v, err = f.checker(sv, nil).Check(t.Context(), f.request())
			wantAccepted(t, v, err)
		})
	}
}

func TestAPolicyThatListsNoStoreOrAStoreThatIsNotOneIsAConfigurationFault(t *testing.T) {
	for name, stores := range map[string][]handoff.Store{"nil": nil, "empty": {}, "an unknown store": {handoff.StorePIV, "tpm"}, "a store in capitals": {"PIV"}} {
		t.Run(name, func(t *testing.T) {
			cfg := defaultConfig(t)
			cfg.Policy.Stores = stores
			wantConfigError(t, cfg)
		})
	}
}

func TestTheValidityOfThePolicyIsNotCheckedOnARequestAndIsNotNegative(t *testing.T) {
	for _, months := range []int{0, 1, 13, 120} {
		chk := newCheckerWith(t, func(c *handoff.Config) { c.Policy.ValidityMonths = months })
		v, err := chk.Check(t.Context(), newFixture(t, handoff.StoreSoftware, csrSpec{}).request())
		wantAccepted(t, v, err)
	}
	for _, months := range []int{-1, -5} {
		cfg := defaultConfig(t)
		cfg.Policy.ValidityMonths = months
		wantConfigError(t, cfg)
	}
}

func TestNothingIsAcceptedFromANilCheckerARequestOrAContext(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	var nilChecker *handoff.Checker
	for name, run := range map[string]func() (handoff.Verdict, error){
		"a nil checker": func() (handoff.Verdict, error) { return nilChecker.Check(t.Context(), f.request()) },
		"a nil request": func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), nil) },
		"a nil context": func() (handoff.Verdict, error) { return newChecker(t).Check(nil, f.request()) }, //nolint:staticcheck // a nil context is the case under test
	} {
		t.Run(name, func(t *testing.T) {
			v, err := run()
			if !errors.Is(err, handoff.ErrConfig) {
				t.Fatalf("error %v, want ErrConfig", err)
			}
			if v.Refused() || v.Complete() || v.Accepted() || len(v.Checks) != 9 || statuses(v) != "nnnnnnnnn" {
				t.Errorf("verdict %+v", v)
			}
		})
	}
}
