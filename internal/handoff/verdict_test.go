package handoff_test

import (
	"crypto/ecdsa"
	"errors"
	"slices"
	"testing"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/jsonset"
)

// Verdict.Accepted is the one reading of an acceptance. It is true when Check returned no error, no check
// refused and every check ran and passed. A verdict is read in three shapes: accepted, refused by check 9
// with every check run (Complete() is true and the request is not accepted), and an error beside a verdict
// that is not refused (neither Refused() nor Complete()).

func TestAcceptedIsTrueForARequestThatEveryCheckAccepted(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StoreSoftware, handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS} {
		t.Run(string(store), func(t *testing.T) {
			f := newFixture(t, store, csrSpec{})
			chk := newChecker(t)
			if store != handoff.StoreSoftware {
				chk = checkerWith(t, store, returning(f.goodEvidence(store)))
			}
			v, err := chk.Check(t.Context(), f.request())
			wantAccepted(t, v, err)
			if v.Refused() || !v.Complete() || v.Code != "" || v.Detail != "" {
				t.Errorf("refused %v, complete %v, code %q, detail %q", v.Refused(), v.Complete(), v.Code, v.Detail)
			}
		})
	}
}

func TestAcceptedIsFalseForARequestThatCheckNineRefusedAfterEveryCheckRan(t *testing.T) {
	// The trap that Accepted() closes: Complete() is true here, and the request is refused.
	for name, spec := range map[string]csrSpec{
		"a name outside the delegation": {exts: goodExtensions(uriName("example.net"))},
		"a subject of 65 characters":    {subject: &pkixName65},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, handoff.StoreSoftware, spec)
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
			if !v.Complete() {
				t.Fatal("test setup: a refusal by check 9 leaves no check unrun")
			}
			if v.Accepted() {
				t.Error("a verdict that check 9 refused is accepted")
			}
		})
	}
	// With every check run and a refusal from the evidence rules of check 9 too.
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	ev := f.goodEvidence(handoff.StorePIV)
	ev.PINPolicy = handoff.PINNever
	v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
	if !v.Complete() || v.Accepted() {
		t.Errorf("complete %v, accepted %v", v.Complete(), v.Accepted())
	}
}

func TestAcceptedIsFalseForEveryCallThatReturnedAnErrorWithAVerdictThatIsNotRefused(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	for name, tc := range map[string]struct {
		run  func() (handoff.Verdict, error)
		want error
	}{
		"a request of a type that is not built": {func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), pgpRequest(nil)) }, handoff.ErrTypeNotBuilt},
		"an ssh request":                        {func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), sshRequest(nil)) }, handoff.ErrTypeNotBuilt},
		"a store with no verifier":              {func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), f.request()) }, handoff.ErrNoVerifier},
		"a verifier that could not decide": {func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, failing(errCannotDecide)).Check(t.Context(), f.request())
		}, errCannotDecide},
		"a verifier that returned nothing": {func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, returning(nil)).Check(t.Context(), f.request())
		}, handoff.ErrInternal},
		"a checker that was not made by New": {func() (handoff.Verdict, error) { return new(handoff.Checker).Check(t.Context(), f.request()) }, handoff.ErrConfig},
		"a nil request":                      {func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), nil) }, handoff.ErrConfig},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := tc.run()
			wantUndecided(t, v, err, tc.want, "")
			if v.Accepted() {
				t.Error("Accepted() is true beside an error")
			}
		})
	}
}

var errCannotDecide = errors.New("the service did not answer")

func TestAcceptedIsFalseForAVerdictThatCheckDidNotReturn(t *testing.T) {
	nine := func(status handoff.CheckStatus) []handoff.CheckResult {
		out := make([]handoff.CheckResult, 9)
		for i := range out {
			out[i] = handoff.CheckResult{N: i + 1, Status: status}
		}
		return out
	}
	for name, v := range map[string]handoff.Verdict{
		"the zero verdict":                   {},
		"nine passed checks made by hand":    {Checks: nine(handoff.StatusPassed)},
		"nine passed checks and a key":       {Checks: nine(handoff.StatusPassed), Key: &newP384(t).PublicKey, Evidence: &handoff.Evidence{Unprotected: true}},
		"nine failed checks":                 {Checks: nine(handoff.StatusFailed)},
		"nine checks that did not run":       {Checks: nine(handoff.StatusNotRun)},
		"a refusal and nine passed checks":   {Code: handoff.CodePolicy, Checks: nine(handoff.StatusPassed)},
		"eight passed checks":                {Checks: nine(handoff.StatusPassed)[:8]},
		"ten passed checks":                  {Checks: append(nine(handoff.StatusPassed), handoff.CheckResult{N: 10, Status: handoff.StatusPassed})},
		"a verdict with no check results":    {Key: &newP384(t).PublicKey},
		"a refused verdict with its details": {Code: handoff.CodeMalformed, Detail: "x", Checks: nine(handoff.StatusNotRun)},
	} {
		if v.Accepted() {
			t.Errorf("%s: Accepted() is true", name)
		}
	}
}

func TestAnAcceptedVerdictThatIsChangedByHandIsNotAccepted(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	good := mustCheck(t, newChecker(t), f.request())
	if !good.Accepted() {
		t.Fatal("test setup")
	}
	clone := func() handoff.Verdict {
		v := good
		v.Checks = slices.Clone(good.Checks)
		return v
	}
	for name, change := range map[string]func(v *handoff.Verdict){
		"a code is set":                 func(v *handoff.Verdict) { v.Code = handoff.CodePolicy },
		"a check is not run":            func(v *handoff.Verdict) { v.Checks[4].Status = handoff.StatusNotRun },
		"a check is failed":             func(v *handoff.Verdict) { v.Checks[8].Status = handoff.StatusFailed },
		"a check has an unknown status": func(v *handoff.Verdict) { v.Checks[0].Status = "ok" },
		"a check has an empty status":   func(v *handoff.Verdict) { v.Checks[3].Status = "" },
		"a rule is named as not run":    func(v *handoff.Verdict) { v.Checks[2].NotRun = []string{"primaries"} },
		"a check is dropped":            func(v *handoff.Verdict) { v.Checks = v.Checks[:8] },
		"a check is added": func(v *handoff.Verdict) {
			v.Checks = append(v.Checks, handoff.CheckResult{N: 10, Status: handoff.StatusPassed})
		},
		"the checks are taken away":          func(v *handoff.Verdict) { v.Checks = nil },
		"the last check is replaced by none": func(v *handoff.Verdict) { v.Checks = v.Checks[:0] },
	} {
		v := clone()
		change(&v)
		if v.Accepted() {
			t.Errorf("%s: Accepted() is true", name)
		}
	}
	if !good.Accepted() {
		t.Error("the changes to the copies changed the verdict that Check returned")
	}
}

func TestACompleteVerdictThatIsRefusedIsNotAnAcceptanceAndSaysSo(t *testing.T) {
	// The three calls say different things, and a request is accepted only when Accepted() says so.
	f := newFixture(t, handoff.StoreSoftware, csrSpec{exts: goodExtensions(uriName("example.net"))})
	v, err := newChecker(t).Check(t.Context(), f.request())
	if err != nil || !v.Complete() || !v.Refused() || v.Accepted() {
		t.Fatalf("complete %v, refused %v, accepted %v, error %v", v.Complete(), v.Refused(), v.Accepted(), err)
	}
}

// The key and the evidence of the verdict.

func TestTheKeyAndTheEvidenceOfAnAcceptedVerdictAreCopies(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	ev := f.goodEvidence(handoff.StoreKMS)
	ev.Key = copyOfKey(t, f.publicKey()) // the verifier's own key: the test writes to it below
	ev.Details = map[string]string{"arn": "arn:aws:kms:eu-west-1:123456789012:key/x"}
	ev.TouchPolicy = "never"
	req := f.request()
	v, err := checkerWith(t, handoff.StoreKMS, returning(ev)).Check(t.Context(), req)
	wantAccepted(t, v, err)

	// What the verdict holds is not what the verifier gave, or what the request holds.
	if v.Evidence == ev {
		t.Fatal("Verdict.Evidence is the pointer the verifier returned")
	}
	if v.Evidence.Key == ev.Key || v.Evidence.Key == f.publicKey() || v.Key == f.publicKey() || v.Key == v.Evidence.Key {
		t.Error("a key of the verdict is a pointer that something else holds")
	}
	if !v.Key.Equal(f.publicKey()) || !v.Evidence.Key.Equal(f.publicKey()) {
		t.Error("a copy of the key is not the key")
	}
	if &v.Evidence.SignPrincipals[0] == &ev.SignPrincipals[0] {
		t.Error("the principals of the verdict are the verifier's slice")
	}
	snapshot := *v.Evidence
	snapshot.Details = map[string]string{"arn": "arn:aws:kms:eu-west-1:123456789012:key/x"}
	snapshot.SignPrincipals = slices.Clone(v.Evidence.SignPrincipals)

	// The verifier writes to its own pointer after the call, in every field.
	ev.Firmware, ev.PINPolicy, ev.TouchPolicy, ev.Unprotected = "1.0.0", handoff.PINNever, "changed", true
	ev.SignPrincipals[0] = handoff.Principal{ARN: "*", Kind: handoff.PrincipalWildcard}
	ev.Details["arn"] = "changed"
	ev.Details["new"] = "added"
	*ev.Key = newP384(t).PublicKey
	if v.Evidence.Firmware != snapshot.Firmware || v.Evidence.PINPolicy != snapshot.PINPolicy || v.Evidence.TouchPolicy != "never" || v.Evidence.Unprotected {
		t.Errorf("a write by the verifier changed the verdict: %+v", v.Evidence)
	}
	if !slices.Equal(v.Evidence.SignPrincipals, snapshot.SignPrincipals) || v.Evidence.SignPrincipals[0].Kind != handoff.PrincipalRole {
		t.Errorf("the principals of the verdict changed: %v", v.Evidence.SignPrincipals)
	}
	if len(v.Evidence.Details) != 1 || v.Evidence.Details["arn"] != "arn:aws:kms:eu-west-1:123456789012:key/x" {
		t.Errorf("the details of the verdict changed: %v", v.Evidence.Details)
	}
	if !v.Evidence.Key.Equal(f.publicKey()) {
		t.Error("the key of the verdict changed with the verifier's key")
	}

	// And the other way: what the caller does to the verdict does not reach the request's key, or a later call.
	*v.Key = newP384(t).PublicKey
	v.Evidence.Details["arn"] = "caller"
	v.Evidence.SignPrincipals[0].ARN = "caller"
	w, err := checkerWith(t, handoff.StoreKMS, returning(f.goodEvidence(handoff.StoreKMS))).Check(t.Context(), req)
	wantAccepted(t, w, err)
	if !w.Key.Equal(f.publicKey()) {
		t.Error("a later call returned a key that the caller had changed")
	}
}

func TestTheEvidenceOfASoftwareKeyIsUnprotectedAndHasNoKey(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v := mustCheck(t, newChecker(t), f.request())
	wantAccepted(t, v, nil)
	if !v.Evidence.Unprotected || v.Evidence.Key != nil || v.Evidence.Firmware != "" || len(v.Evidence.SignPrincipals) != 0 {
		t.Errorf("evidence of a software key: %+v", v.Evidence)
	}
	if !v.Key.Equal(f.publicKey()) {
		t.Error("the key of the verdict is not the key of the request")
	}
}

func TestNoVerdictThatIsNotAcceptedHoldsAKeyOrEvidenceWhateverCheckStoppedIt(t *testing.T) {
	// The key is known after check 5, and evidence after check 7: a verdict that stopped later than that and
	// was not accepted holds neither. Stops at 6 to 9, and an error after 7, are the cases.
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	notAllowed := newCheckerWith(t, func(c *handoff.Config) { c.Policy.Stores = []handoff.Store{handoff.StoreSoftware} })
	g := newFixture(t, handoff.StorePIV, csrSpec{exts: goodExtensions(uriName("example.net"))})
	wrongKey := f.goodEvidence(handoff.StorePIV)
	wrongKey.Key = &newP384(t).PublicKey
	for name, run := range map[string]func() (handoff.Verdict, error){
		"check 6 refused": func() (handoff.Verdict, error) { return notAllowed.Check(t.Context(), f.request()) },
		"check 7 refused": func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "x"})).Check(t.Context(), f.request())
		},
		"check 8 refused": func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, returning(wrongKey)).Check(t.Context(), f.request())
		},
		"check 9 refused": func() (handoff.Verdict, error) {
			return checkerWith(t, handoff.StorePIV, returning(g.goodEvidence(handoff.StorePIV))).Check(t.Context(), g.request())
		},
		"no verifier": func() (handoff.Verdict, error) { return newChecker(t).Check(t.Context(), f.request()) },
	} {
		t.Run(name, func(t *testing.T) {
			v, _ := run()
			if v.Accepted() || v.Key != nil || v.Evidence != nil {
				t.Errorf("accepted %v, key %v, evidence %v", v.Accepted(), v.Key, v.Evidence)
			}
		})
	}
}

// The detail of a refusal that a verifier gives is escaped as CodeError.Error() escapes it.

func TestADetailThatAVerifierGivesIsEscapedInTheVerdict(t *testing.T) {
	hostile := "chain \x1b[2J\nsecond line \u202e rtl \x00 nul \xff bad \u2028 sep"
	for _, code := range []handoff.Code{handoff.CodeProofInvalid, handoff.CodeMalformed} {
		t.Run(string(code), func(t *testing.T) {
			f := newFixture(t, handoff.StorePIV, csrSpec{})
			sv := failing(&handoff.CodeError{Code: code, Detail: hostile})
			v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
			wantRefusal(t, v, err, code, 7)
			if !plain(v.Detail) {
				t.Fatalf("the detail is not plain text: %q", v.Detail)
			}
			if want := jsonset.Escape(hostile); v.Detail != want {
				t.Errorf("the detail is %q, the escape of the verifier's text is %q", v.Detail, want)
			}
			// The same escape as the error of the code: the text of the error ends with the detail.
			ce := &handoff.CodeError{Code: code, Detail: hostile}
			if want := "handoff: " + string(code) + ": " + v.Detail; ce.Error() != want {
				t.Errorf("the error reads %q, the verdict's detail would make %q", ce.Error(), want)
			}
		})
	}
}

func TestAPlainDetailOfAVerifierIsNotChanged(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "the chain does not lead to a pinned root: 9a (2026-11-15)"})
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
	if v.Detail != "the chain does not lead to a pinned root: 9a (2026-11-15)" {
		t.Errorf("detail %q", v.Detail)
	}
}

func TestTheCodeOfAVerifierThatIsNotACodeOfCheckSevenIsEscapedInTheError(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := failing(&handoff.CodeError{Code: "bad \x1b[31m\ncode", Detail: "x"})
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
	if !plain(err.Error()) {
		t.Errorf("the error is not plain text: %q", err.Error())
	}
}

// What a verifier is given and what it does to it.

func TestAnEvidenceKeyThatIsAPointerOfTheVerifierIsNotKeptByTheVerdict(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	ev := f.goodEvidence(handoff.StorePIV)
	v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	var zero *ecdsa.PublicKey
	if v.Evidence.Key == zero || v.Evidence.Key == ev.Key {
		t.Error("the verdict keeps the verifier's key pointer")
	}
}

// copyOfKey is a key with numbers of its own.
func copyOfKey(t testing.TB, k *ecdsa.PublicKey) *ecdsa.PublicKey {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	c, err := ecdsa.ParseUncompressedPublicKey(k.Curve, b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
