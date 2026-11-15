package handoff_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// The clock of an openpgp-subkey request: read once for a call, after check 4, and cut to whole seconds; a
// back-signature may not be made after it.

func TestTheClockDecidesWhichBackSignaturesAreInTheFuture(t *testing.T) {
	sigAt := pgpSubCreated.Add(time.Minute) // the writer's default
	for name, tc := range map[string]struct {
		now    time.Time
		accept bool
	}{
		"half a minute after the subkey":      {pgpSubCreated.Add(30 * time.Second), false},
		"a second before the signatures":      {sigAt.Add(-time.Second), false},
		"exactly at the signatures":           {sigAt, true},
		"half a second after the signatures":  {sigAt.Add(500 * time.Millisecond), true},
		"half a second before the signatures": {sigAt.Add(-500 * time.Millisecond), false},
		"a day after":                         {sigAt.Add(24 * time.Hour), true},
		"the last second that a field holds":  {time.Unix(1<<32-1, 0), true},
		"the same time in another zone":       {sigAt.In(time.FixedZone("example", 5*3600)), true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware)
			chk := f.checker(func(c *handoff.Config) { c.Now = func() time.Time { return tc.now } })
			v, err := chk.Check(t.Context(), f.request())
			if tc.accept {
				wantAccepted(t, v, err)
				return
			}
			wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
		})
	}
}

// A clock that can be read by New and not by the call (it gives a time outside the years 1970 to 2106, or panics) is an
// error of the checker, never a refusal or an acceptance. With primaries New already refuses such a clock, so the clock
// of these tests is good for its first read and bad for the next.
func TestAClockOutsideTheYears1970To2106IsAFaultOfTheCheckerAndNeverARefusalOrAnAcceptance(t *testing.T) {
	afterNew := func(bad func() time.Time) func() time.Time {
		n := 0
		return func() time.Time {
			n++
			if n == 1 {
				return testNow
			}
			return bad()
		}
	}
	for name, at := range map[string]time.Time{
		"before 1970":              time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC),
		"one second before 1970":   time.Unix(-1, 0),
		"the epoch":                time.Unix(0, 0),
		"the first second of 2106": time.Unix(1<<32, 0),
		"the year 2200":            time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC),
		"the zero time":            {},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware)
			chk := f.checker(func(c *handoff.Config) { c.Now = afterNew(func() time.Time { return at }) })
			v, err := chk.Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppnnnnn")
			if v.Refused() {
				t.Errorf("the request was refused with %q for a fault of the clock", v.Code)
			}
		})
	}
	// A panicking clock is an error too, and no acceptance.
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	chk := f.checker(func(c *handoff.Config) { c.Now = afterNew(func() time.Time { panic("the clock broke") }) })
	v, err := chk.Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppnnnnn")
}

func TestTheClockIsReadOnceAndOnlyWhenCheckFiveIsReached(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(f *pgpFixture)
		reads  int
	}{
		"an accepted request":          {func(f *pgpFixture) {}, 1},
		"a refusal at check 5":         {func(f *pgpFixture) { f.sigs = f.sigs[:1] }, 1},
		"a refusal at check 4":         {func(f *pgpFixture) { f.subPacket = oddSubkey(pgpSubCreated, []byte{22}, []byte{1, 2, 3}) }, 0},
		"a refusal at check 3":         {func(f *pgpFixture) { f.listed = fingerprints(2) }, 0},
		"a digest that is wrong":       {func(f *pgpFixture) { f.digest = digestHex(nil) }, 0},
		"a file that is not packets":   {func(f *pgpFixture) { f.file = []byte{1} }, 0},
		"a proof that is not the form": {func(f *pgpFixture) { f.edit(func(m map[string]any) { delete(m, "capabilities") }) }, 0},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware)
			tc.change(f)
			var reads int
			chk := f.checker(func(c *handoff.Config) { c.Now = func() time.Time { reads++; return testNow } })
			reads = 0 // the one read of New (a primary is not after the clock) is not a read of a call
			_, _ = chk.Check(t.Context(), f.request())
			if reads != tc.reads {
				t.Errorf("the clock was read %d times, want %d", reads, tc.reads)
			}
		})
	}
	// With a verifier the clock is still read once: the verifier gets the reading that check 5 used.
	f := newPGPFixture(t, 2, handoff.StorePIV)
	rv := &recordingVerifier{fixture: f, store: handoff.StorePIV}
	var reads int
	clock := testNow.Add(500 * time.Millisecond).In(time.FixedZone("example", 5*3600))
	chk := f.checker(func(c *handoff.Config) {
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: rv}
		c.Now = func() time.Time { reads++; return clock }
	})
	reads = 0 // the one read of New is not a read of a call
	v, err := chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if reads != 1 {
		t.Errorf("the clock was read %d times for a request with a verifier", reads)
	}
	if rv.now.Before(clock.Add(-time.Second)) || rv.now.After(clock) {
		t.Errorf("the verifier was given %v for the clock %v", rv.now, clock)
	}
	if rv.now.Location() != time.UTC {
		t.Errorf("the verifier was given a time in the zone %v, not in UTC", rv.now.Location())
	}
}

// Checks 6 to 8 with the verifiers of the three stores that need one.

var verifiedStores = []handoff.Store{handoff.StorePIV, handoff.StoreOpenPGPCard, handoff.StoreKMS}

func TestTheVerifierOfAStoreIsCalledOnceWithTheFilesOfTheRequestAndACopyOfTheProof(t *testing.T) {
	for _, store := range verifiedStores {
		t.Run(string(store), func(t *testing.T) {
			f := newPGPFixture(t, 2, store)
			rv := &recordingVerifier{fixture: f, store: store}
			chk := f.checker(withVerifier(store, rv))
			req := f.request()
			before := copyOfRequest(req)
			v, err := chk.Check(t.Context(), req)
			wantAccepted(t, v, err)
			if rv.calls != 1 {
				t.Fatalf("the verifier was called %d times", rv.calls)
			}
			if _, ok := rv.req.Files[handoff.FileSubkey]; !ok {
				t.Error("the verifier was not given the subkey file")
			}
			if _, ok := rv.req.Files[handoff.FileCSR]; ok {
				t.Error("the verifier was given a csr.pem for an OpenPGP request")
			}
			if !bytes.Equal(rv.req.Files[handoff.FileSubkey], req.Files[handoff.FileSubkey]) || rv.req.Stem != testStem {
				t.Error("the request that the verifier saw is not the caller's")
			}
			if rv.proof.Store != store || rv.proof.Type != handoff.TypeOpenPGP || rv.proof.RequestSHA256 != digestHex(req.Files[handoff.FileSubkey]) {
				t.Errorf("the proof that the verifier saw: %+v", rv.proof)
			}
			if !slices.Equal(rv.proof.Primaries, f.fingerprints()) || !slices.Equal(rv.proof.Capabilities, []string{"sign"}) {
				t.Errorf("the proof lists primaries %v and capabilities %v", rv.proof.Primaries, rv.proof.Capabilities)
			}
			if !sameRequest(before, req) {
				t.Error("the caller's request was changed")
			}
			// What the verifier is given is a copy: a write to it changes nothing the checker holds.
			rv.req.Files[handoff.FileSubkey][0] ^= 0xFF
			rv.proof.Primaries[0] = "changed"
			if !sameRequest(before, req) {
				t.Error("a write by the verifier changed the caller's request")
			}
			again, err := chk.Check(t.Context(), req)
			wantAccepted(t, again, err)
			if again.Subkey.Fingerprint != v.Subkey.Fingerprint {
				t.Error("the second call differs from the first")
			}
		})
	}
}

func TestAVerifierThatWritesToWhatItWasGivenChangesNothingTheCheckerUses(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StorePIV)
	sv := &stub{fn: func(_ context.Context, r *handoff.Request, p *handoff.Proof, _ time.Time) (*handoff.Evidence, error) {
		clear(r.Files[handoff.FileSubkey])
		p.Capabilities[0] = "authenticate"
		ev := f.goodEvidence(handoff.StorePIV)
		return ev, nil
	}}
	v, err := f.checker(withVerifier(handoff.StorePIV, sv)).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if v.Subkey.Capability != "sign" {
		t.Errorf("the capability of the verdict is %q", v.Subkey.Capability)
	}
}

func TestAVerifierThatGivesAnotherKeyIsKeyMismatchAndOneThatGivesNoneIsAFault(t *testing.T) {
	for _, store := range verifiedStores {
		t.Run(string(store), func(t *testing.T) {
			f := newPGPFixture(t, 2, store)
			wrong := f.goodEvidence(store)
			wrong.Key = &newP384(t).PublicKey
			v, err := f.checker(withVerifier(store, returning(wrong))).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)

			// The key of a primary is not the key of the subkey either.
			prim := f.goodEvidence(store)
			prim.Key = f.primaries[0].pub()
			v, err = f.checker(withVerifier(store, returning(prim))).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)

			none := f.goodEvidence(store)
			none.Key = nil
			v, err = f.checker(withVerifier(store, returning(none))).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")

			v, err = f.checker(withVerifier(store, returning(nil))).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
		})
	}
}

func TestAVerifierThatRefusesFailsOrPanicsIsHeardAtCheckSeven(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StorePIV)
	for _, code := range []handoff.Code{handoff.CodeProofInvalid, handoff.CodeMalformed} {
		v, err := f.checker(withVerifier(handoff.StorePIV, failing(&handoff.CodeError{Code: code, Detail: "the chain is broken"}))).Check(t.Context(), f.request())
		wantRefusal(t, v, err, code, 7)
		if got := statuses(v); got != "ppppppfnn" {
			t.Errorf("code %s: statuses %s", code, got)
		}
	}
	// A code that is not a code of check 7 is a fault of the verifier.
	v, err := f.checker(withVerifier(handoff.StorePIV, failing(&handoff.CodeError{Code: handoff.CodePolicy, Detail: "x"}))).Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
	// A plain failure is not a refusal.
	v, err = f.checker(withVerifier(handoff.StorePIV, failing(errCannotDecide))).Check(t.Context(), f.request())
	wantUndecided(t, v, err, errCannotDecide, "ppppppnnn")
	if errors.Is(err, handoff.ErrInternal) {
		t.Error("a verifier that could not decide is not an internal fault")
	}
	// A panic.
	boom := &stub{fn: func(context.Context, *handoff.Request, *handoff.Proof, time.Time) (*handoff.Evidence, error) {
		panic("the verifier broke")
	}}
	v, err = f.checker(withVerifier(handoff.StorePIV, boom)).Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
	// A stopped context stops before the verifier is called.
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	sv := returning(f.goodEvidence(handoff.StorePIV))
	v, err = f.checker(withVerifier(handoff.StorePIV, sv)).Check(cancelled, f.request())
	wantUndecided(t, v, err, context.Canceled, "ppppppnnn")
	if sv.calls.Load() != 0 {
		t.Error("the verifier was called with a stopped context")
	}
}

func TestAStoreWithNoVerifierStopsAtCheckSevenAndASoftwareKeyNeedsNone(t *testing.T) {
	for _, store := range verifiedStores {
		f := newPGPFixture(t, 2, store)
		v, err := f.checker(nil).Check(t.Context(), f.request())
		wantUndecided(t, v, err, handoff.ErrNoVerifier, "ppppppnnn")
	}
	// A verifier that is registered for software is never called.
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	sv := returning(f.goodEvidence(handoff.StorePIV))
	v, err := f.checker(withVerifier(handoff.StoreSoftware, sv)).Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if sv.calls.Load() != 0 {
		t.Error("the verifier of the software store was called")
	}
	// A store that the policy does not allow is refused at check 6 and its verifier is never called.
	g := newPGPFixture(t, 2, handoff.StorePIV)
	pv := returning(g.goodEvidence(handoff.StorePIV))
	chk := g.checker(func(c *handoff.Config) {
		c.Policy.Stores = []handoff.Store{handoff.StoreSoftware}
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: pv}
	})
	v, err = chk.Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
	if pv.calls.Load() != 0 {
		t.Error("the verifier of a store that is not allowed was called")
	}
}

func TestTheKMSPublicKeyOfTheProofIsHeldToTheKeyOfTheSubkey(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreKMS)
	// The proof names the key of another request; the verifier gives the right key.
	other := newP384(t)
	f.proof["evidence"] = kmsEvidence(&other.PublicKey)
	v, err := f.checker(withVerifier(handoff.StoreKMS, returning(f.goodEvidence(handoff.StoreKMS)))).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
	// A public_key that is Base64 and no key at all.
	f.proof["evidence"] = evidenceFor(handoff.StoreKMS)
	v, err = f.checker(withVerifier(handoff.StoreKMS, returning(f.goodEvidence(handoff.StoreKMS)))).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
	// The key of the subkey, as the proof writes it, is accepted.
	f.proof["evidence"] = kmsEvidence(f.sub.pub())
	f.mustAccept(f.checker(withVerifier(handoff.StoreKMS, returning(f.goodEvidence(handoff.StoreKMS)))))
	if !bytes.Equal(f.subPublicKeyDER(), f.subPublicKeyDER()) {
		t.Fatal("test setup")
	}
}

// Check 9.

func TestTheCapabilityOfTheProofIsTheCapabilityOfTheDelegation(t *testing.T) {
	for name, tc := range map[string]struct{ proof, delegation string }{
		"sign asked, authenticate held": {"sign", "authenticate"},
		"authenticate asked, sign held": {"authenticate", "sign"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware).edit(func(m map[string]any) { m["capabilities"] = []string{tc.proof} })
			v, err := f.checker(func(c *handoff.Config) { c.Delegation.Capability = tc.delegation }).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
			if !v.Complete() {
				t.Error("a refusal at check 9 leaves every check run")
			}
		})
	}
}

func TestTheEvidenceRulesOfX509HoldForAnOpenPGPKey(t *testing.T) {
	type change func(ev *handoff.Evidence)
	for name, tc := range map[string]struct {
		store  handoff.Store
		change change
		accept bool
	}{
		"firmware 5.6.9":                  {handoff.StorePIV, func(ev *handoff.Evidence) { ev.Firmware = "5.6.9" }, false},
		"firmware 5.7.0":                  {handoff.StorePIV, func(ev *handoff.Evidence) { ev.Firmware = "5.7.0" }, true},
		"firmware 5.10.0, newer than 5.7": {handoff.StorePIV, func(ev *handoff.Evidence) { ev.Firmware = "5.10.0" }, true},
		"firmware 4.99.99":                {handoff.StorePIV, func(ev *handoff.Evidence) { ev.Firmware = "4.99.99" }, false},
		"firmware that is not numbers":    {handoff.StorePIV, func(ev *handoff.Evidence) { ev.Firmware = "latest" }, false},
		"no firmware for a PIV key":       {handoff.StorePIV, func(ev *handoff.Evidence) { ev.Firmware = "" }, false},
		"PIN never":                       {handoff.StorePIV, func(ev *handoff.Evidence) { ev.PINPolicy = handoff.PINNever }, false},
		"PIN always":                      {handoff.StorePIV, func(ev *handoff.Evidence) { ev.PINPolicy = handoff.PINAlways }, true},
		"no PIN policy for a PIV key":     {handoff.StorePIV, func(ev *handoff.Evidence) { ev.PINPolicy = "" }, false},
		"a card with no firmware or PIN":  {handoff.StoreOpenPGPCard, func(ev *handoff.Evidence) {}, true},
		"a card with an old firmware":     {handoff.StoreOpenPGPCard, func(ev *handoff.Evidence) { ev.Firmware = "5.1.0" }, false},
		"a KMS key with one role":         {handoff.StoreKMS, func(ev *handoff.Evidence) {}, true},
		"a KMS key with two principals": {handoff.StoreKMS, func(ev *handoff.Evidence) {
			ev.SignPrincipals = append(ev.SignPrincipals, handoff.Principal{ARN: "arn:aws:iam::123456789012:role/example-other", Kind: handoff.PrincipalRole})
		}, false},
		"a KMS key with the same role twice": {handoff.StoreKMS, func(ev *handoff.Evidence) { ev.SignPrincipals = append(ev.SignPrincipals, ev.SignPrincipals[0]) }, true},
		"a KMS key with no principal":        {handoff.StoreKMS, func(ev *handoff.Evidence) { ev.SignPrincipals = nil }, false},
		"a KMS key for the account root": {handoff.StoreKMS, func(ev *handoff.Evidence) {
			ev.SignPrincipals = []handoff.Principal{{ARN: "arn:aws:iam::123456789012:root", Kind: handoff.PrincipalRoot}}
		}, false},
		"a KMS key for a wildcard": {handoff.StoreKMS, func(ev *handoff.Evidence) {
			ev.SignPrincipals = []handoff.Principal{{ARN: "*", Kind: handoff.PrincipalWildcard}}
		}, false},
		"a KMS key for a user": {handoff.StoreKMS, func(ev *handoff.Evidence) {
			ev.SignPrincipals = []handoff.Principal{{ARN: "arn:aws:iam::123456789012:user/example-holder", Kind: handoff.PrincipalUser}}
		}, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, tc.store)
			ev := f.goodEvidence(tc.store)
			tc.change(ev)
			v, err := f.checker(withVerifier(tc.store, returning(ev))).Check(t.Context(), f.request())
			if tc.accept {
				wantAccepted(t, v, err)
				return
			}
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

func TestASubkeyThatIsAKeyOfTheBundleIsRefusedWithPolicy(t *testing.T) {
	root := newRoot(t, "Example Test Root")
	for name, build := range map[string]func(f *pgpFixture) (*pgpKey, func(c *handoff.Config)){
		"the key of the first primary": func(f *pgpFixture) (*pgpKey, func(c *handoff.Config)) { return f.primaries[0], nil },
		"the key of the last primary":  func(f *pgpFixture) (*pgpKey, func(c *handoff.Config)) { return f.primaries[1], nil },
		"the point of a primary with another creation time": func(f *pgpFixture) (*pgpKey, func(c *handoff.Config)) {
			return &pgpKey{priv: f.primaries[0].priv, created: f.primaries[0].created.Add(24 * time.Hour)}, nil
		},
		"the key of a root of the bundle": func(f *pgpFixture) (*pgpKey, func(c *handoff.Config)) {
			return &pgpKey{priv: root.key, created: pgpSubCreated}, func(c *handoff.Config) { c.Roots = []handoff.RootRef{root.ref()} }
		},
		"the key of the second root": func(f *pgpFixture) (*pgpKey, func(c *handoff.Config)) {
			return &pgpKey{priv: root.key, created: pgpSubCreated}, func(c *handoff.Config) {
				c.Roots = []handoff.RootRef{newRoot(t, "Another Root").ref(), root.ref()}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware)
			sub, change := build(f)
			f.sub = sub
			f.subPacket = sub.subkeyPacket()
			f.sigs = nil
			for _, p := range f.primaries {
				f.sigs = append(f.sigs, f.backSig(p, nil))
			}
			v, err := f.checker(change).Check(t.Context(), f.request())
			wantRefusal(t, v, err, handoff.CodePolicy, 9)
		})
	}
}

// What a delegation-free checker does for this type.

func TestACheckerWithNoDelegationRunsTheOpenPGPRulesItCanAndNamesTheOthersAsNotRun(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StorePIV)
	good := f.goodEvidence(handoff.StorePIV)
	noDeleg := func(c *handoff.Config) {
		c.Delegation = nil
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: returning(good)}
	}
	v, err := f.checker(noDeleg).Check(t.Context(), f.request())
	if err != nil {
		t.Fatal(err)
	}
	if got := statuses(v); got != "ppppppppn" {
		t.Fatalf("statuses %s", got)
	}
	if got := v.Checks[8].NotRun; !slices.Equal(got, []string{"delegation-type", "capability"}) {
		t.Errorf("check 9 names %v as not run", got)
	}
	if v.Accepted() || v.Complete() || v.Refused() || v.Key != nil || v.Evidence != nil || v.Subkey != nil {
		t.Errorf("accepted %v complete %v refused %v key %v evidence %v subkey %v", v.Accepted(), v.Complete(), v.Refused(), v.Key, v.Evidence, v.Subkey)
	}
	// A rule that can run still refuses.
	old := *good
	old.Firmware = "5.1.0"
	v, err = f.checker(func(c *handoff.Config) {
		c.Delegation = nil
		c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: returning(&old)}
	}).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
	// The same for a subkey that is a primary's key.
	g := newPGPFixture(t, 2, handoff.StoreSoftware)
	g.sub = g.primaries[0]
	g.subPacket = g.sub.subkeyPacket()
	g.sigs = nil
	for _, p := range g.primaries {
		g.sigs = append(g.sigs, g.backSig(p, nil))
	}
	v, err = g.checker(func(c *handoff.Config) { c.Delegation = nil }).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodePolicy, 9)
	// The faults of the earlier checks are told as with a delegation.
	h := newPGPFixture(t, 2, handoff.StoreSoftware)
	h.sigs = h.sigs[:1]
	v, err = h.checker(func(c *handoff.Config) { c.Delegation = nil }).Check(t.Context(), h.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
}

// The order of the checks: a request with two faults gets the code of the earlier check.

func TestARequestWithTwoFaultsGetsTheCodeOfTheEarlierCheck(t *testing.T) {
	odd := oddSubkey(pgpSubCreated, []byte{22}, bytes.Repeat([]byte{1}, 20))
	type tc struct {
		name   string
		build  func(t *testing.T) (*pgpFixture, func(c *handoff.Config))
		code   handoff.Code
		check  int
		errant bool
	}
	soft := func(t *testing.T) *pgpFixture { return newPGPFixture(t, 2, handoff.StoreSoftware) }
	piv := func(t *testing.T) *pgpFixture { return newPGPFixture(t, 2, handoff.StorePIV) }
	notAllowed := func(c *handoff.Config) { c.Policy.Stores = []handoff.Store{handoff.StoreSoftware} }
	for _, c := range []tc{
		{"a file that is not packets and a wrong digest", func(t *testing.T) (*pgpFixture, func(c *handoff.Config)) {
			f := soft(t)
			f.file, f.digest = []byte{1, 2}, digestHex(nil)
			return f, nil
		}, handoff.CodeMalformed, 2, false},
		{"a wrong digest and a wrong primary", func(t *testing.T) (*pgpFixture, func(c *handoff.Config)) {
			f := soft(t)
			f.digest, f.listed = digestHex(nil), fingerprints(2)
			return f, nil
		}, handoff.CodeRequestMismatch, 3, false},
		{"a wrong primary and an Ed25519 subkey", func(t *testing.T) (*pgpFixture, func(c *handoff.Config)) {
			f := soft(t)
			f.subPacket, f.listed = odd, fingerprints(2)
			return f, nil
		}, handoff.CodeUnknownPrimary, 3, false},
		{"an Ed25519 subkey and a store that is not allowed", func(t *testing.T) (*pgpFixture, func(c *handoff.Config)) {
			f := piv(t)
			f.subPacket = odd
			return f, notAllowed
		}, handoff.CodeAlgorithmUnsupported, 4, false},
		{"a bad back-signature and a store that is not allowed", func(t *testing.T) (*pgpFixture, func(c *handoff.Config)) {
			f := piv(t)
			f.sigs = f.sigs[:1]
			return f, notAllowed
		}, handoff.CodePossessionInvalid, 5, false},
		{"a bad back-signature and a verifier that refuses", func(t *testing.T) (*pgpFixture, func(c *handoff.Config)) {
			f := piv(t)
			f.sigs = f.sigs[:1]
			return f, withVerifier(handoff.StorePIV, failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "x"}))
		}, handoff.CodePossessionInvalid, 5, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, change := c.build(t)
			v, err := f.checker(change).Check(t.Context(), f.request())
			wantRefusal(t, v, err, c.code, c.check)
		})
	}

	t.Run("a store that is not allowed and a verifier that refuses", func(t *testing.T) {
		f := piv(t)
		sv := failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "x"})
		v, err := f.checker(func(c *handoff.Config) {
			notAllowed(c)
			c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{handoff.StorePIV: sv}
		}).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodeStoreNotAllowed, 6)
		if sv.calls.Load() != 0 {
			t.Error("the verifier was called")
		}
	})
	t.Run("a verifier that refuses and a wrong key", func(t *testing.T) {
		f := piv(t)
		v, err := f.checker(withVerifier(handoff.StorePIV, failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "x"}))).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
	})
	t.Run("a wrong key and a wrong capability", func(t *testing.T) {
		f := piv(t).edit(func(m map[string]any) { m["capabilities"] = []string{"authenticate"} })
		ev := f.goodEvidence(handoff.StorePIV)
		ev.Key = &newP384(t).PublicKey
		v, err := f.checker(withVerifier(handoff.StorePIV, returning(ev))).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodeKeyMismatch, 8)
	})
	t.Run("a wrong capability and a firmware that is too old", func(t *testing.T) {
		f := piv(t).edit(func(m map[string]any) { m["capabilities"] = []string{"authenticate"} })
		ev := f.goodEvidence(handoff.StorePIV)
		ev.Firmware = "5.6.9"
		v, err := f.checker(withVerifier(handoff.StorePIV, returning(ev))).Check(t.Context(), f.request())
		wantRefusal(t, v, err, handoff.CodePolicy, 9)
	})
}

// A checker is used by many calls at once.

func TestOneCheckerServesManyCallsAtOnceWithTheSameVerdicts(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StorePIV)
	good := f.goodEvidence(handoff.StorePIV)
	chk := f.checker(withVerifier(handoff.StorePIV, returning(good)))
	bad := newPGPFixture(t, 2, handoff.StorePIV)
	bad.primaries, bad.sub, bad.subPacket = f.primaries, f.sub, f.subPacket
	bad.sigs = f.sigs[:1]
	reqs := []*handoff.Request{f.request(), bad.request()}
	const workers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	verdicts := make([]handoff.Verdict, workers)
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			verdicts[i], errs[i] = chk.Check(context.Background(), reqs[i%2])
		}()
	}
	close(start)
	wg.Wait()
	for i := range workers {
		if i%2 == 0 {
			wantAccepted(t, verdicts[i], errs[i])
			if verdicts[i].Subkey.Fingerprint != f.sub.fingerprint() {
				t.Errorf("call %d: the fingerprint is %s", i, verdicts[i].Subkey.Fingerprint)
			}
			continue
		}
		wantRefusal(t, verdicts[i], errs[i], handoff.CodePossessionInvalid, 5)
	}
}

func TestTheDetailOfAnOpenPGPRefusalIsPlainTextWhateverTheRequestHolds(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StorePIV)
	hostile := "\x1b[2J" + string(rune(0x202e)) + "\u00e4"
	f.sigs = [][]byte{pgpPacket(pgpTagUserID, []byte(hostile)), f.sigs[1]}
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	if !plain(v.Detail) || strings.Contains(v.Detail, "\x1b") {
		t.Errorf("detail %q", v.Detail)
	}
	g := newPGPFixture(t, 2, handoff.StorePIV)
	v, err = g.checker(withVerifier(handoff.StorePIV, failing(&handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: hostile}))).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodeProofInvalid, 7)
	if !plain(v.Detail) {
		t.Errorf("detail %q", v.Detail)
	}
}

// Hostile input: size, depth, counts, wrong types and bytes that are not UTF-8 are refused and never crash.

func TestHostileOpenPGPInputIsRefusedAndNeverCrashes(t *testing.T) {
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	rawProof := func(f *pgpFixture, proof string) *handoff.Request {
		r := f.request()
		r.Files[handoff.FileProof] = []byte(proof)
		return r
	}
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	digest := digestHex(f.fileBytes())
	fps := f.fingerprints()
	good := func(extra string) string {
		return `{"handoff":1,"type":"openpgp-subkey","request_sha256":"` + digest + `","store":"software","primaries":["` + fps[0] + `","` + fps[1] + `"],"capabilities":["sign"]` + extra + `}`
	}
	cases := map[string]string{
		"primaries nested 10000 deep":                 strings.Replace(good(""), `["`+fps[0]+`","`+fps[1]+`"]`, deep(10000), 1),
		"capabilities nested 10000 deep":              strings.Replace(good(""), `["sign"]`, deep(10000), 1),
		"an unknown member 10000 deep":                good(`,"x":` + deep(10000)),
		"primaries a number":                          strings.Replace(good(""), `["`+fps[0]+`","`+fps[1]+`"]`, `1`, 1),
		"primaries an object":                         strings.Replace(good(""), `["`+fps[0]+`","`+fps[1]+`"]`, `{}`, 1),
		"primaries null":                              strings.Replace(good(""), `["`+fps[0]+`","`+fps[1]+`"]`, `null`, 1),
		"capabilities a number":                       strings.Replace(good(""), `["sign"]`, `1`, 1),
		"capabilities null":                           strings.Replace(good(""), `["sign"]`, `null`, 1),
		"capabilities holding a number":               strings.Replace(good(""), `["sign"]`, `[1]`, 1),
		"the store a number":                          strings.Replace(good(""), `"store":"software"`, `"store":1`, 1),
		"the type a list":                             strings.Replace(good(""), `"type":"openpgp-subkey"`, `"type":["openpgp-subkey"]`, 1),
		"the digest a number":                         strings.Replace(good(""), `"request_sha256":"`+digest+`"`, `"request_sha256":1`, 1),
		"evidence a list":                             good(`,"evidence":[]`),
		"a fingerprint with bytes that are not UTF-8": strings.Replace(good(""), fps[0], "\xff\xfe"+fps[0][2:], 1),
		"a digest with bytes that are not UTF-8":      strings.Replace(good(""), digest, "\xff"+digest[1:], 1),
		"a type with bytes that are not UTF-8":        strings.Replace(good(""), `openpgp-subkey`, "openpgp-\xffkey", 1),
		"a capability that is a lone surrogate":       strings.Replace(good(""), `["sign"]`, `["\ud800"]`, 1),
		"a NUL byte in a string":                      strings.Replace(good(""), `"software"`, "\"soft\\u0000ware\"", 1),
		"a byte order mark":                           string(rune(0xFEFF)) + good(""),
	}
	for name, proof := range cases {
		t.Run(name, func(t *testing.T) {
			v, err := f.checker(nil).Check(t.Context(), rawProof(f, proof))
			// Check 2 fails. Check 1 passed when the version could be read, and did not run when it could not.
			if err != nil || v.Code != handoff.CodeMalformed || v.Checks[1].Status != handoff.StatusFailed || v.Complete() || v.Accepted() ||
				(statuses(v) != "pfnnnnnnn" && statuses(v) != "nfnnnnnnn") || v.Key != nil || v.Evidence != nil || v.Subkey != nil {
				t.Fatalf("code %q, statuses %s, error %v", v.Code, statuses(v), err)
			}
			if v.Detail == "" || !plain(v.Detail) {
				t.Errorf("detail %q", v.Detail)
			}
		})
	}
	// The control: the proof as written is accepted.
	v, err := f.checker(nil).Check(t.Context(), rawProof(f, good("")))
	wantAccepted(t, v, err)
}

func TestABackSignatureWithAHugeAreaOrManySubpacketsIsRefusedInBoundedWork(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	// A hashed area of about 64 KiB of one-byte subpackets of type 99, and an unhashed area of the same size.
	many := func() []subpacket {
		var out []subpacket
		for range 20000 {
			out = append(out, subpacket{typ: 99})
		}
		return out
	}()
	f.sigs[0] = f.backSig(f.primaries[0], func(s *sigSpec) { s.hashed, s.unhashed = many, many })
	start := time.Now()
	v, err := f.checker(nil).Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	if time.Since(start) > 10*time.Second {
		t.Errorf("the refusal took %v", time.Since(start))
	}
	// A signature packet of the largest size that a file holds, and a subkey packet of that size.
	g := newPGPFixture(t, 1, handoff.StoreSoftware)
	g.sigs[0] = pgpPacket(pgpTagSignature, make([]byte, handoff.MaxFileSize-len(g.subPacket)-8))
	v, err = g.checker(nil).Check(t.Context(), g.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
	h := newPGPFixture(t, 1, handoff.StoreSoftware)
	h.subPacket = pgpPacket(pgpTagSubkey, make([]byte, handoff.MaxFileSize-8))
	h.sigs = nil
	v, err = h.checker(nil).Check(t.Context(), h.request())
	// A whole packet whose body is not a key: the version byte is not 4.
	wantRefusal(t, v, err, handoff.CodeAlgorithmUnsupported, 4)
}

func TestAnX509OrSSHDelegationHoldsNoPrimaryNotEvenOne(t *testing.T) {
	f := newPGPFixture(t, 1, handoff.StoreSoftware)
	for name, d := range map[string]*handoff.Delegation{
		"x509": defaultDelegation(),
		"ssh":  {Name: "n", Type: handoff.TypeSSH, Root: "r"},
	} {
		cfg := f.config(func(c *handoff.Config) { c.Delegation = d })
		if len(cfg.Primaries) != 1 {
			t.Fatal("test setup")
		}
		t.Run(name, func(t *testing.T) { wantConfigError(t, cfg) })
	}
}

func TestEverythingAtOneInstantIsAccepted(t *testing.T) {
	// The subkey, its back-signatures and the check are all at one second: nothing is after the check.
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	for i, p := range f.primaries {
		f.sigs[i] = f.backSig(p, func(s *sigSpec) { s.created = f.sub.created })
	}
	chk := f.checker(func(c *handoff.Config) { c.Now = func() time.Time { return f.sub.created } })
	v, err := chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	// One second earlier, the subkey is in the future.
	chk = f.checker(func(c *handoff.Config) { c.Now = func() time.Time { return f.sub.created.Add(-time.Second) } })
	v, err = chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodePossessionInvalid, 5)
}
