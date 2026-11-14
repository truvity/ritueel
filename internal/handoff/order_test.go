package handoff_test

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
)

// A request that fails two checks is refused with the code of the earlier one, and nothing after the
// earlier one ran. Each case below has a fault for the earlier check and another for a later one.

func TestWhenTwoChecksWouldRefuseTheEarlierOneGivesTheCode(t *testing.T) {
	pivNotAllowed := func(c *handoff.Config) {
		c.Policy.Stores = slices.DeleteFunc(slices.Clone(c.Policy.Stores), func(s handoff.Store) bool { return s == handoff.StorePIV })
	}
	for _, tc := range []struct {
		name    string
		store   handoff.Store
		spec    csrSpec
		prepare func(t *testing.T, f *fixture, c *handoff.Config, sv **stub) *handoff.Request
		code    handoff.Code
		n       int
	}{
		{
			name: "version 2 and a wrong digest", store: handoff.StoreSoftware,
			prepare: func(t *testing.T, f *fixture, _ *handoff.Config, _ **stub) *handoff.Request {
				f.proof["handoff"] = 2
				f.proof["request_sha256"] = digestHex(nil)
				return f.request()
			},
			code: handoff.CodeVersionUnsupported, n: 1,
		},
		{
			name: "version 2 and an unknown member", store: handoff.StoreSoftware,
			prepare: func(t *testing.T, f *fixture, _ *handoff.Config, _ **stub) *handoff.Request {
				f.proof["handoff"] = 2
				f.proof["unknown"] = 1
				return f.request()
			},
			code: handoff.CodeVersionUnsupported, n: 1,
		},
		{
			name: "an unknown member and a wrong digest", store: handoff.StoreSoftware,
			prepare: func(t *testing.T, f *fixture, _ *handoff.Config, _ **stub) *handoff.Request {
				f.proof["unknown"] = 1
				f.proof["request_sha256"] = digestHex(nil)
				return f.request()
			},
			code: handoff.CodeMalformed, n: 2,
		},
		{
			name: "a request file that is not a request and a wrong digest", store: handoff.StoreSoftware,
			prepare: func(t *testing.T, f *fixture, _ *handoff.Config, _ **stub) *handoff.Request {
				r := f.request()
				r.Files[handoff.FileCSR] = []byte("not a request")
				return r
			},
			code: handoff.CodeMalformed, n: 2,
		},
		{
			name: "a wrong digest and a key on P-256", store: handoff.StoreSoftware,
			spec: csrSpec{key: nil},
			prepare: func(t *testing.T, _ *fixture, _ *handoff.Config, _ **stub) *handoff.Request {
				f := newFixture(t, handoff.StoreSoftware, csrSpec{key: otherKeys(t)["P-256"], sigAlg: x509.ECDSAWithSHA256})
				f.proof["request_sha256"] = digestHex(nil)
				return f.request()
			},
			code: handoff.CodeRequestMismatch, n: 3,
		},
		{
			name: "a wrong digest and a signature of another kind", store: handoff.StoreSoftware,
			prepare: func(t *testing.T, _ *fixture, _ *handoff.Config, _ **stub) *handoff.Request {
				f := newFixture(t, handoff.StoreSoftware, csrSpec{sigAlg: x509.ECDSAWithSHA256})
				f.proof["request_sha256"] = digestHex(nil)
				return f.request()
			},
			code: handoff.CodeRequestMismatch, n: 3,
		},
		{
			name: "a key on P-256 and a signature that does not verify", store: handoff.StoreSoftware,
			prepare: func(t *testing.T, _ *fixture, _ *handoff.Config, _ **stub) *handoff.Request {
				// Signed with SHA-256 by a P-256 key: the key is what is wrong first.
				return newFixture(t, handoff.StoreSoftware, csrSpec{key: otherKeys(t)["P-256"], sigAlg: x509.ECDSAWithSHA512}).request()
			},
			code: handoff.CodeAlgorithmUnsupported, n: 4,
		},
		{
			name: "a signature of another kind and a store that is not allowed", store: handoff.StorePIV,
			prepare: func(t *testing.T, _ *fixture, c *handoff.Config, _ **stub) *handoff.Request {
				pivNotAllowed(c)
				return newFixture(t, handoff.StorePIV, csrSpec{sigAlg: x509.ECDSAWithSHA256}).request()
			},
			code: handoff.CodePossessionInvalid, n: 5,
		},
		{
			name: "a store that is not allowed and evidence that is invalid", store: handoff.StorePIV,
			prepare: func(t *testing.T, f *fixture, c *handoff.Config, sv **stub) *handoff.Request {
				pivNotAllowed(c)
				*sv = failing(&handoff.CodeError{Code: handoff.CodeProofInvalid})
				return f.request()
			},
			code: handoff.CodeStoreNotAllowed, n: 6,
		},
		{
			name: "a store that is not allowed and a policy fault", store: handoff.StorePIV,
			prepare: func(t *testing.T, _ *fixture, c *handoff.Config, _ **stub) *handoff.Request {
				pivNotAllowed(c)
				f := newFixture(t, handoff.StorePIV, csrSpec{exts: goodExtensions(uriName("example.net"))})
				return f.request()
			},
			code: handoff.CodeStoreNotAllowed, n: 6,
		},
		{
			name: "evidence that is invalid and a key that does not match", store: handoff.StorePIV,
			prepare: func(t *testing.T, f *fixture, _ *handoff.Config, sv **stub) *handoff.Request {
				*sv = failing(&handoff.CodeError{Code: handoff.CodeProofInvalid})
				return f.request()
			},
			code: handoff.CodeProofInvalid, n: 7,
		},
		{
			name: "evidence that is invalid and a policy fault", store: handoff.StorePIV,
			prepare: func(t *testing.T, _ *fixture, _ *handoff.Config, sv **stub) *handoff.Request {
				*sv = failing(&handoff.CodeError{Code: handoff.CodeProofInvalid})
				return newFixture(t, handoff.StorePIV, csrSpec{exts: goodExtensions(uriName("example.net"))}).request()
			},
			code: handoff.CodeProofInvalid, n: 7,
		},
		{
			name: "a key that does not match and a policy fault", store: handoff.StorePIV,
			prepare: func(t *testing.T, _ *fixture, _ *handoff.Config, sv **stub) *handoff.Request {
				f := newFixture(t, handoff.StorePIV, csrSpec{exts: goodExtensions(uriName("example.net"))})
				ev := f.goodEvidence(handoff.StorePIV)
				ev.Key = &newP384(t).PublicKey
				ev.Firmware = "5.0.0"
				*sv = returning(ev)
				return f.request()
			},
			code: handoff.CodeKeyMismatch, n: 8,
		},
		{
			name: "a policy fault in the evidence and a policy fault in the request", store: handoff.StorePIV,
			prepare: func(t *testing.T, _ *fixture, _ *handoff.Config, sv **stub) *handoff.Request {
				f := newFixture(t, handoff.StorePIV, csrSpec{exts: goodExtensions(uriName("example.net"))})
				ev := f.goodEvidence(handoff.StorePIV)
				ev.PINPolicy = handoff.PINNever
				*sv = returning(ev)
				return f.request()
			},
			code: handoff.CodePolicy, n: 9,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.store, tc.spec)
			cfg := defaultConfig(t)
			var sv *stub
			req := tc.prepare(t, f, &cfg, &sv)
			if sv == nil {
				sv = returning(f.goodEvidence(tc.store))
			}
			cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: sv, handoff.StoreKMS: sv, handoff.StoreOpenPGPCard: sv}
			v, err := mustNew(t, cfg).Check(t.Context(), req)
			wantRefusal(t, v, err, tc.code, tc.n)
			if tc.n < 7 && sv.calls.Load() != 0 {
				t.Error("a verifier was called for a request that a check before check 7 refused")
			}
		})
	}
}

func TestAFaultOfFormInTheSubjectIsMalformedBeforeAFaultOfContentThatStandsEarlierInIt(t *testing.T) {
	// A value that is not a string is policy, and a name that has a relative name that is empty is
	// malformed: the form is judged first wherever in the subject each stands.
	// The request is made by hand: a subject of two relative names, the first with a bad value and the
	// second empty.
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	badValue := tlv(0x31, tlv(0x30, mustMarshal(oidCN), tlv(0x02, []byte{0x01})))
	emptyRDN := tlv(0x31)
	subject := tlv(0x30, badValue, emptyRDN)
	der := replaceSubject(t, f.der, subject)
	f.csr, f.der = pemOf(der), der
	f.proof["request_sha256"] = digestHex(der)
	// The signature no longer covers the new subject; check 5 is not reached when the form is refused.
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeMalformed, 2)
}

// replaceSubject swaps the DER of the subject in a request for another and fixes the lengths above it.
func replaceSubject(t *testing.T, der, subject []byte) []byte {
	t.Helper()
	// CertificationRequest ::= SEQUENCE { info SEQUENCE { version, subject, spki, attributes }, alg, sig }
	read := func(b []byte) (tag byte, hdr, n int) {
		tag = b[0]
		if b[1] < 0x80 {
			return tag, 2, int(b[1])
		}
		l := int(b[1] & 0x7f)
		for i := 0; i < l; i++ {
			n = n<<8 | int(b[2+i])
		}
		return tag, 2 + l, n
	}
	_, outerHdr, _ := read(der)
	rest := der[outerHdr:]
	_, infoHdr, infoLen := read(rest)
	info := rest[infoHdr : infoHdr+infoLen]
	tail := rest[infoHdr+infoLen:]
	_, verHdr, verLen := read(info)
	version := info[:verHdr+verLen]
	afterVer := info[verHdr+verLen:]
	_, subjHdr, subjLen := read(afterVer)
	afterSubj := afterVer[subjHdr+subjLen:]
	newInfo := tlv(0x30, version, subject, afterSubj)
	return tlv(0x30, newInfo, tail)
}

func TestARequestWhoseSignatureIsBadAndWhoseSubjectIsNotOfThePageIsPossessionInvalidFirst(t *testing.T) {
	// Check 5 comes before check 9: a request signed by another kind of signature and asking for an
	// extension that the page does not allow is refused for its signature.
	f := newFixture(t, handoff.StoreSoftware, csrSpec{sigAlg: x509.ECDSAWithSHA256, exts: dropExt(goodExtensions(uriName("example.org")), oidEKU)})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
}

func TestAKeyThatIsNotP384AndAPolicyFaultIsAlgorithmUnsupportedFirst(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{
		key: otherKeys(t)["P-256"], sigAlg: x509.ECDSAWithSHA256,
		exts: dropExt(goodExtensions(uriName("example.org")), oidEKU),
	})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeAlgorithmUnsupported, 4)
}

func TestARequestThatFailsTheFirstCheckLeavesEveryOtherCheckNotRun(t *testing.T) {
	v, err := newChecker(t).Check(t.Context(), &handoff.Request{Stem: testStem, Files: map[string][]byte{handoff.FileProof: []byte(`{"handoff":2}`)}})
	wantRefusal(t, v, err, handoff.CodeVersionUnsupported, 1)
	for i, c := range v.Checks {
		if c.N != i+1 {
			t.Errorf("check %d is numbered %d", i+1, c.N)
		}
		if i > 0 && (c.Status != handoff.StatusNotRun || len(c.NotRun) != 0) {
			t.Errorf("check %d after the failed one: %+v", i+1, c)
		}
	}
	if v.Key != nil || v.Evidence != nil {
		t.Error("a verdict of the first check carries a key or evidence")
	}
}

func TestTheKeyAndTheEvidenceAreInAVerdictOnlyWhenItIsAccepted(t *testing.T) {
	// A refusal at each check, and a call that could not decide at each of the places that it can stop,
	// holds neither the key of the request nor the evidence, whatever the checks that ran have read.
	f := newFixture(t, handoff.StorePIV, csrSpec{sigAlg: x509.ECDSAWithSHA256})
	v, err := newChecker(t).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)

	g := newFixture(t, handoff.StorePIV, csrSpec{})
	notAllowed := newCheckerWith(t, func(c *handoff.Config) { c.Policy.Stores = []handoff.Store{handoff.StoreKMS} })
	v, err = notAllowed.Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)

	// Checks 1 to 6 passed and the key is known to the checker: it is not offered.
	v, err = newChecker(t).Check(t.Context(), g.request())
	wantUndecided(t, v, err, handoff.ErrNoVerifier, "ppppppnnn")

	// Evidence read, key matched, and check 9 refuses: neither is offered.
	h := newFixture(t, handoff.StorePIV, csrSpec{exts: goodExtensions(uriName("example.net"))})
	v, err = checkerWith(t, handoff.StorePIV, returning(h.goodEvidence(handoff.StorePIV))).Check(t.Context(), h.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)

	// The request of a type that is not built, checks 1 to 3 passed.
	v, err = newChecker(t).Check(t.Context(), sshRequest(nil))
	wantUndecided(t, v, err, handoff.ErrTypeNotBuilt, "pppnnnnnn")

	// Accepted: both are there.
	v, err = checkerWith(t, handoff.StorePIV, returning(g.goodEvidence(handoff.StorePIV))).Check(t.Context(), g.request())
	wantAccepted(t, v, err)
	if !v.Key.Equal(g.publicKey()) {
		t.Error("the key of an accepted verdict is not the key of the request")
	}
}

func TestEveryVerdictHasNineCheckResultsInOrder(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	good := f.request()
	bad := f.request()
	bad.Files[handoff.FileCSR] = []byte("x")
	for name, r := range map[string]*handoff.Request{
		"good": good, "bad": bad,
		"empty":     {Stem: testStem},
		"nil files": {Stem: testStem, Files: nil},
	} {
		v, err := newChecker(t).Check(t.Context(), r)
		if errors.Is(err, handoff.ErrConfig) {
			t.Fatalf("%s: %v", name, err)
		}
		if len(v.Checks) != 9 {
			t.Fatalf("%s: %d results", name, len(v.Checks))
		}
		for i, c := range v.Checks {
			if c.N != i+1 || c.Name == "" || c.Status == "" {
				t.Errorf("%s: check %d reads %+v", name, i+1, c)
			}
		}
	}
}

// Passed, failed and not-run follow one rule: the checks before the one that failed passed, the failed
// one failed, the others did not run. No check is passed after one failed, and no verdict is accepted
// unless every check passed and no error came with it.
func TestNoVerdictIsAnAcceptanceUnlessEveryCheckPassed(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	good := f.goodEvidence(handoff.StorePIV)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for name, run := range map[string]func() (handoff.Verdict, error){
		"no verifier": func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), f.request()) },
		"a verifier that could not decide": func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, failing(errors.New("down"))).Check(t.Context(), f.request())
		},
		"a verifier that broke its contract": func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, returning(nil)).Check(t.Context(), f.request())
		},
		"a stopped context": func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, returning(good)).Check(cancelled, f.request())
		},
		"a request of a type that is not built": func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), pgpRequest(nil)) },
		"a checker that was not made by New":    func() (handoff.Verdict, error) { return (&handoff.Checker{}).Check(t.Context(), f.request()) },
	} {
		t.Run(name, func(t *testing.T) {
			v, err := run()
			if err == nil {
				t.Fatal("a call that could not decide returned no error")
			}
			if v.Accepted() || v.Complete() || v.Refused() {
				t.Fatalf("accepted %v, complete %v, refused %v beside the error %v", v.Accepted(), v.Complete(), v.Refused(), err)
			}
			for _, r := range v.Checks {
				if r.Status == handoff.StatusPassed && len(r.NotRun) != 0 {
					t.Errorf("check %d is passed and names rules that did not run: %v", r.N, r.NotRun)
				}
				if r.Status != handoff.StatusNotRun && len(r.NotRun) != 0 {
					t.Errorf("check %d (%s) names rules that did not run", r.N, r.Status)
				}
			}
		})
	}
}

func TestAnEmptyVerdictIsNotComplete(t *testing.T) {
	if (handoff.Verdict{}).Complete() {
		t.Error("a verdict with no checks reads as complete")
	}
	if (handoff.Verdict{}).Refused() {
		t.Error("a verdict with no code reads as refused")
	}
	short := handoff.Verdict{Checks: make([]handoff.CheckResult, 8)}
	for i := range short.Checks {
		short.Checks[i].Status = handoff.StatusPassed
	}
	if short.Complete() {
		t.Error("a verdict with eight passed checks reads as complete")
	}
	nine := handoff.Verdict{Checks: make([]handoff.CheckResult, 9)}
	for i := range nine.Checks {
		nine.Checks[i].Status = handoff.StatusPassed
	}
	if !nine.Complete() {
		t.Error("nine passed checks do not read as complete")
	}
	ten := handoff.Verdict{Checks: make([]handoff.CheckResult, 10)}
	for i := range ten.Checks {
		ten.Checks[i].Status = handoff.StatusPassed
	}
	if ten.Complete() {
		t.Error("a verdict with ten results reads as complete")
	}
	nine.Checks[4].Status = handoff.StatusNotRun
	if nine.Complete() {
		t.Error("a verdict with one check not run reads as complete")
	}
	nine.Checks[4].Status = handoff.StatusFailed
	if !nine.Complete() {
		t.Error("a verdict whose checks all ran reads as incomplete")
	}
	if !(handoff.Verdict{Code: handoff.CodePolicy}).Refused() {
		t.Error("a verdict with a code does not read as refused")
	}
}

// The content of the request is read right after check 5, from the same bytes, and a refusal of the content
// is told by check 9. So a fault of content stands behind every check that comes first, however that check
// ends: a refusal, a call that could not decide, or a stop.

func TestAFaultOfContentNeverTakesThePlaceOfACheckThatComesFirst(t *testing.T) {
	faults := map[string]csrSpec{
		"a name outside the delegation": {exts: goodExtensions(uriName("example.net"))},
		"an extension that is not one":  {exts: dropExt(goodExtensions(uriName("example.org")), oidEKU)},
		"a subject of 65 characters":    {subject: &pkixName65},
	}
	cause := errors.New("the service did not answer")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for name, spec := range faults {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StorePIV, spec)
			good := f.goodEvidence(handoff.StorePIV)
			wrong := f.goodEvidence(handoff.StorePIV)
			wrong.Key = &newP384(t).PublicKey

			// Check 9 itself, as the control.
			v, err := checkerWith(t, handoff.StorePIV, returning(good)).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodePolicy, 9)

			// Each earlier stop.
			v, err = newChecker(t).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrNoVerifier, "ppppppnnn")
			v, err = checkerWith(t, handoff.StorePIV, failing(cause)).Check(t.Context(), f.request())
			wantUndecided(t, v, err, cause, "ppppppnnn")
			v, err = checkerWith(t, handoff.StorePIV, returning(good)).Check(cancelled, f.request())
			wantUndecided(t, v, err, context.Canceled, "ppppppnnn")
			v, err = checkerWith(t, handoff.StorePIV, panicWith{"x"}).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
			v, err = checkerWith(t, handoff.StorePIV, failing(&handoff.CodeError{Code: handoff.CodeProofInvalid})).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
			v, err = checkerWith(t, handoff.StorePIV, returning(wrong)).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
			v, err = checkerWithCfg(t, handoff.StorePIV, returning(good), func(c *handoff.Config) {
				c.Policy.Stores = []handoff.Store{handoff.StoreKMS}
			}).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
		})
	}
}

func TestAKMSProofWithAWrongPublicKeyAndAFaultOfContentIsKeyMismatch(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{exts: goodExtensions(uriName("example.net"))})
	f.proof["evidence"] = kmsEvidence(&newP384(t).PublicKey)
	v, err := checkerWith(t, handoff.StoreKMS, returning(f.goodEvidence(handoff.StoreKMS))).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
}
