package handoff_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// checkerWith is a checker with one verifier for the store.
func checkerWith(t testing.TB, store handoff.Store, v handoff.EvidenceVerifier) *handoff.Checker {
	t.Helper()
	return checkerWithCfg(t, store, v, nil)
}

// checkerWithCfg is checkerWith with a change to the configuration before the checker is made.
func checkerWithCfg(t testing.TB, store handoff.Store, v handoff.EvidenceVerifier, change func(c *handoff.Config)) *handoff.Checker {
	t.Helper()
	return newCheckerWith(t, func(c *handoff.Config) {
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{store: v}
		if change != nil {
			change(c)
		}
	})
}

func TestASoftwareKeyIsAcceptedWithNoVerifierAndRecordedAsUnprotected(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	v := mustCheck(t, newChecker(t), f.request())
	if v.Evidence == nil || !v.Evidence.Unprotected || v.Evidence.Key != nil {
		t.Errorf("evidence of a software key: %+v", v.Evidence)
	}
	if statuses(v) != "ppppppppp" {
		t.Errorf("statuses %s", statuses(v))
	}
}

func TestAVerifierRegisteredForSoftwareIsNeverCalled(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	sv := failing(&handoff.CodeError{Code: handoff.CodeProofInvalid})
	v, err := checkerWith(t, handoff.StoreSoftware, sv).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if sv.calls.Load() != 0 {
		t.Error("a software key has no evidence, and the verifier was asked for it")
	}
}

func TestAStoreWithNoVerifierGivesNoVerifierAndCheckSevenIsNotRun(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS} {
		t.Run(string(store), func(t *testing.T) {
			f := newFixture(t, store, csrSpec{})
			v, err := newChecker(t).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrNoVerifier, "ppppppnnn")
		})
	}
}

func TestAVerifierOfAnotherStoreDoesNotServe(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := returning(f.goodEvidence(handoff.StoreKMS))
	_, err := checkerWith(t, handoff.StoreKMS, sv).Check(t.Context(), f.request())
	if !errors.Is(err, handoff.ErrNoVerifier) || sv.calls.Load() != 0 {
		t.Errorf("error %v, calls %d", err, sv.calls.Load())
	}
}

func TestANilVerifierInTheMapIsAConfigurationFault(t *testing.T) {
	cfg := defaultConfig(t)
	cfg.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: nil}
	wantConfigError(t, cfg)
}

func TestARefusalOfTheEvidenceStopsBeforeCheckEightAndNine(t *testing.T) {
	for _, code := range []handoff.Code{handoff.CodeProofInvalid, handoff.CodeMalformed} {
		t.Run(string(code), func(t *testing.T) {
			f := newFixture(t, handoff.StorePIV, csrSpec{})
			sv := failing(&handoff.CodeError{Code: code, Detail: "the chain does not lead to a pinned root"})
			v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
			wantRefusal(t, v, err, code, 7)
			if v.Detail != "the chain does not lead to a pinned root" {
				t.Errorf("detail %q", v.Detail)
			}
			if v.Evidence != nil {
				t.Error("a refused verdict carries evidence")
			}
		})
	}
}

func TestARefusalOfTheEvidenceThatIsWrappedIsStillARefusal(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	inner := &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "no role"}
	sv := failing(fmt.Errorf("reading the key: %w", inner))
	v, err := checkerWith(t, handoff.StoreKMS, sv).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
}

func TestAVerifierThatRefusesWithACodeOfAnotherCheckIsAFaultAndNotAVerdict(t *testing.T) {
	for _, code := range []handoff.Code{
		handoff.CodePolicy, handoff.CodeKeyMismatch, handoff.CodeDeclined, handoff.CodeVersionUnsupported,
		handoff.CodeRequestMismatch, handoff.CodeUnknownPrimary, handoff.CodeAlgorithmUnsupported,
		handoff.CodePossessionInvalid, handoff.CodeStoreNotAllowed, "",
	} {
		t.Run(string(code), func(t *testing.T) {
			f := newFixture(t, handoff.StorePIV, csrSpec{})
			sv := failing(&handoff.CodeError{Code: code})
			v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
		})
	}
}

func TestAVerifierThatCouldNotDecideIsNotARefusal(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	cause := errors.New("the service did not answer")
	v, err := checkerWith(t, handoff.StoreKMS, failing(cause)).Check(t.Context(), f.request())
	wantUndecided(t, v, err, cause, "ppppppnnn")
	if errors.Is(err, handoff.ErrInternal) || errors.Is(err, handoff.ErrNoVerifier) {
		t.Errorf("a failure of the service is not a fault of the verifier: %v", err)
	}
}

func TestAVerifierThatReturnsANilCodeErrorCouldNotDecide(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	var none *handoff.CodeError
	sv := &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		return nil, none
	}}
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
	if err == nil {
		t.Fatal("no error for a verifier that returned an error")
	}
	wantUndecided(t, v, err, err, "ppppppnnn")
}

func TestAVerifierThatBreaksItsContractIsAFault(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	for name, ev := range map[string]*handoff.Evidence{
		"returns neither evidence nor an error": nil,
		"returns evidence with no key":          {Firmware: "5.8.0", PINPolicy: handoff.PINOnce},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
		})
	}
}

func TestEvidenceForAnotherKeyIsKeyMismatch(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	ev := f.goodEvidence(handoff.StorePIV)
	ev.Key = &newP384(t).PublicKey
	v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
}

// pointOf returns the two coordinates of a P-384 key as numbers.
func pointOf(t testing.TB, k *ecdsa.PublicKey) (x, y *big.Int) {
	t.Helper()
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return new(big.Int).SetBytes(b[1:49]), new(big.Int).SetBytes(b[49:])
}

func TestEvidenceThatDiffersInOneCoordinateIsKeyMismatch(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	x, y := pointOf(t, f.publicKey())
	one := big.NewInt(1)
	for name, key := range map[string]*ecdsa.PublicKey{
		"x": {Curve: elliptic.P384(), X: new(big.Int).Add(x, one), Y: y},
		"y": {Curve: elliptic.P384(), X: x, Y: new(big.Int).Add(y, one)},
	} {
		t.Run(name, func(t *testing.T) {
			ev := f.goodEvidence(handoff.StorePIV)
			ev.Key = key
			v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
		})
	}
}

func TestEvidenceForAKeyOfAnotherCurveOrNotAPointIsKeyMismatch(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := pointOf(t, f.publicKey())
	for name, key := range map[string]*ecdsa.PublicKey{
		"a P-256 key":                   &p256.PublicKey,
		"a point that is not on P-384":  {Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(1)},
		"the same coordinates on P-256": {Curve: elliptic.P256(), X: x, Y: y},
	} {
		t.Run(name, func(t *testing.T) {
			ev := f.goodEvidence(handoff.StorePIV)
			ev.Key = key
			v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
		})
	}
}

func TestEvidenceForTheKeyOfTheRequestPassesCheckEightAndIsKept(t *testing.T) {
	for _, store := range []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS} {
		t.Run(string(store), func(t *testing.T) {
			f := newFixture(t, store, csrSpec{})
			ev := f.goodEvidence(store)
			// A copy of the key with its own numbers: equality is by the point, not by the pointer.
			raw, err := ev.Key.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if ev.Key, err = ecdsa.ParseUncompressedPublicKey(elliptic.P384(), raw); err != nil {
				t.Fatal(err)
			}
			v, err := checkerWith(t, store, returning(ev)).Check(t.Context(), f.request())
			wantAccepted(t, v, err)
			if v.Evidence == nil || v.Evidence.Key == nil || !v.Evidence.Key.Equal(f.publicKey()) {
				t.Errorf("the verdict does not carry what the verifier read: %+v", v.Evidence)
			}
			if v.Evidence.Unprotected {
				t.Error("a key in a store is recorded as unprotected")
			}
		})
	}
}

func TestTheVerifierIsGivenTheContextTheClockAndTheProofAsItWas(t *testing.T) {
	f := newFixture(t, handoff.StoreKMS, csrSpec{})
	type ctxKey struct{}
	ctx := context.WithValue(t.Context(), ctxKey{}, "marker")
	var gotCtx context.Context
	var gotNow time.Time
	var gotReq *handoff.Request
	var gotProof *handoff.Proof
	sv := &stub{fn: func(c context.Context, r *handoff.Request, p *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
		gotCtx, gotNow, gotReq, gotProof = c, now, r, p
		return f.goodEvidence(handoff.StoreKMS), nil
	}}
	// A clock in another zone is given as UTC.
	chk := checkerWithCfg(t, handoff.StoreKMS, sv, func(c *handoff.Config) {
		c.Now = func() time.Time { return testNow.In(time.FixedZone("far", 5*3600)) }
	})
	req := f.request()
	v, err := chk.Check(ctx, req)
	wantAccepted(t, v, err)
	if gotCtx.Value(ctxKey{}) != "marker" {
		t.Error("the verifier did not get the context of the call")
	}
	if !gotNow.Equal(testNow) || gotNow.Location() != time.UTC {
		t.Errorf("the verifier got the time %v", gotNow)
	}
	if gotProof.Handoff != 1 || gotProof.Type != handoff.TypeX509 || gotProof.Store != handoff.StoreKMS ||
		gotProof.RequestSHA256 != digestHex(f.der) || gotProof.Primaries != nil || gotProof.Capabilities != nil || gotProof.Use != "" {
		t.Errorf("the proof as the verifier got it: %+v", gotProof)
	}
	want := mustJSON(t, f.proof["evidence"])
	if !bytes.Equal(gotProof.Evidence, want) {
		t.Errorf("the evidence as the verifier got it is %s, the file has %s", gotProof.Evidence, want)
	}
	if gotReq.Stem != testStem || !bytes.Equal(gotReq.Files[handoff.FileCSR], f.csr) {
		t.Error("the verifier did not get the files of the request")
	}
}

func TestWhatAVerifierDoesToItsCopiesDoesNotChangeTheChecksThatFollow(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := &stub{fn: func(_ context.Context, r *handoff.Request, p *handoff.Proof, _ time.Time) (*handoff.Evidence, error) {
		// A verifier that spoils everything it was given.
		clear(r.Files[handoff.FileCSR])
		r.Files[handoff.FileProof] = []byte("{}")
		delete(r.Files, handoff.FileCSR)
		r.Stem = "other"
		for i := range p.Evidence {
			p.Evidence[i] = 'x'
		}
		p.Store = handoff.StoreSoftware
		p.Type = handoff.TypeSSH
		p.RequestSHA256 = "x"
		return f.goodEvidence(handoff.StorePIV), nil
	}}
	req := f.request()
	proofBefore := bytes.Clone(req.Files[handoff.FileProof])
	csrBefore := bytes.Clone(req.Files[handoff.FileCSR])
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), req)
	wantAccepted(t, v, err)
	if !bytes.Equal(req.Files[handoff.FileProof], proofBefore) || !bytes.Equal(req.Files[handoff.FileCSR], csrBefore) || req.Stem != testStem {
		t.Error("the request of the caller was changed")
	}
}

func TestWhatTheCallerDoesToItsRequestAfterTheCallDoesNotChangeTheVerdict(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	req := f.request()
	chk := newChecker(t)
	v := mustCheck(t, chk, req)
	req.Files[handoff.FileCSR][10] ^= 0xff
	if v.Key == nil || !v.Key.Equal(f.publicKey()) {
		t.Error("the key of the verdict changed")
	}
}

func TestAStoppedContextStopsTheCallBeforeTheVerifierRuns(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	sv := returning(f.goodEvidence(handoff.StorePIV))
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(ctx, f.request())
	wantUndecided(t, v, err, context.Canceled, "ppppppnnn")
	if sv.calls.Load() != 0 {
		t.Error("the verifier was called with a stopped context")
	}
}

func TestACheckerIsSafeToUseFromSeveralGoroutines(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := returning(f.goodEvidence(handoff.StorePIV))
	chk := checkerWith(t, handoff.StorePIV, sv)
	req := f.request()
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				v, err := chk.Check(t.Context(), req)
				if err != nil || !v.Accepted() {
					errs <- fmt.Sprintf("code %q, error %v", v.Code, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if sv.calls.Load() != 80 {
		t.Errorf("the verifier was called %d times, want 80", sv.calls.Load())
	}
}

// A context whose Err is a place where the caller's goroutine can do something to its request files: the
// checker calls Err after it has read every file once and before it calls the verifier.
type hookContext struct {
	context.Context
	hook func()
}

func (h hookContext) Err() error {
	h.hook()
	return h.Context.Err()
}

func TestWhatTheCallerDoesToItsFilesBeforeTheVerifierIsCalledHasNoEffect(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	req := f.request()
	proofBefore, csrBefore := bytes.Clone(req.Files[handoff.FileProof]), bytes.Clone(req.Files[handoff.FileCSR])
	var got *handoff.Request
	sv := &stub{fn: func(_ context.Context, r *handoff.Request, _ *handoff.Proof, _ time.Time) (*handoff.Evidence, error) {
		got = r
		return f.goodEvidence(handoff.StorePIV), nil
	}}
	ctx := hookContext{t.Context(), func() {
		clear(req.Files[handoff.FileCSR])
		clear(req.Files[handoff.FileProof])
		req.Stem = "changed"
	}}
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(ctx, req)
	wantAccepted(t, v, err)
	if got == nil || !bytes.Equal(got.Files[handoff.FileCSR], csrBefore) || !bytes.Equal(got.Files[handoff.FileProof], proofBefore) || got.Stem != testStem {
		t.Error("the verifier was given what the caller wrote after the call began")
	}
}

func TestAVerifierErrorThatIsAnInternalFaultAndARefusalIsAFaultAndNotARefusal(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	sv := failing(errors.Join(handoff.ErrInternal, &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "x"}))
	v, err := checkerWith(t, handoff.StorePIV, sv).Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
}

// A key that a verifier returns is data from outside: one that is not a point of P-384 is never a key of the
// request, and it must not stop the call with a panic.

func brokenKeys() map[string]*ecdsa.PublicKey {
	return map[string]*ecdsa.PublicKey{
		"a zero key":                    {},
		"a curve and no point":          {Curve: elliptic.P384()},                                       //nolint:staticcheck // a key with no point is the case under test
		"a curve and only X":            {Curve: elliptic.P384(), X: big.NewInt(1)},                     //nolint:staticcheck // as above
		"a curve and only Y":            {Curve: elliptic.P384(), Y: big.NewInt(1)},                     //nolint:staticcheck // as above
		"a negative point":              {Curve: elliptic.P384(), X: big.NewInt(-1), Y: big.NewInt(-1)}, //nolint:staticcheck // as above
		"no curve and a point":          {X: big.NewInt(1), Y: big.NewInt(1)},                           //nolint:staticcheck // as above
		"a point that is off the curve": {Curve: elliptic.P384(), X: big.NewInt(1), Y: big.NewInt(1)},   //nolint:staticcheck // as above
	}
}

func TestAKeyOfAVerifierThatIsNotAPointIsKeyMismatchAndNeverAPanic(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	for name, key := range brokenKeys() {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Check panicked on a key that a verifier returned: %v", r)
				}
			}()
			ev := f.goodEvidence(handoff.StorePIV)
			ev.Key = key
			v, err := checkerWith(t, handoff.StorePIV, returning(ev)).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
		})
	}
}

func TestARootWhoseKeyIsNotAPointIsAConfigurationFaultAndNeverAPanic(t *testing.T) {
	good := newRoot(t, "Example Test Root")
	for name, key := range brokenKeys() {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("New panicked on a root key that is not a point: %v", r)
				}
			}()
			cfg := defaultConfig(t)
			cfg.Roots = []handoff.RootRef{good.ref(), {Subject: good.subject, Key: key}}
			wantConfigError(t, cfg)
		})
	}
}
