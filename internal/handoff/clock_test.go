package handoff_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// The clock of the configuration is given to the verifiers. It is called under the same protection as a
// verifier: a clock that panics gives ErrInternal and never an acceptance.

func TestAClockThatPanicsGivesAnErrorAndNeverAnAcceptance(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	for name, value := range map[string]any{
		"a string":                   "the clock broke",
		"an error":                   errors.New("the clock broke"),
		"nothing":                    nil,
		"a refusal of the evidence":  &handoff.CodeError{Code: handoff.CodeProofInvalid, Detail: "a panic that looks like a refusal"},
		"the internal error":         handoff.ErrInternal,
		"a text that is not plain":   "x \x1b[2J\n\u202e",
		"a number":                   42,
		"a nil pointer as the value": (*int)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			sv := returning(f.goodEvidence(handoff.StorePIV))
			chk := checkerWithCfg(t, handoff.StorePIV, sv, func(c *handoff.Config) {
				c.Now = func() time.Time { panic(value) }
			})
			v, err := chk.Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
			var refusal *handoff.CodeError
			if errors.As(err, &refusal) {
				t.Errorf("a clock that panics is a refusal: %v", err)
			}
			if !plain(err.Error()) {
				t.Errorf("the error is not plain text: %q", err.Error())
			}
			if !strings.Contains(err.Error(), "clock") {
				t.Errorf("the error does not say that the clock panicked: %q", err.Error())
			}
			if sv.calls.Load() != 0 {
				t.Errorf("the verifier was called %d times with no time to give it", sv.calls.Load())
			}
		})
	}
}

func TestAClockThatPanicsIsNeverReadForASoftwareKey(t *testing.T) {
	f := newFixture(t, handoff.StoreSoftware, csrSpec{})
	chk := newCheckerWith(t, func(c *handoff.Config) { c.Now = func() time.Time { panic("the clock broke") } })
	v, err := chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
}

func TestAClockThatPanicsOnceDoesNotStopTheNextCall(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	var reads atomic.Int32
	sv := returning(f.goodEvidence(handoff.StorePIV))
	chk := checkerWithCfg(t, handoff.StorePIV, sv, func(c *handoff.Config) {
		c.Now = func() time.Time {
			if reads.Add(1) == 1 {
				panic("the first read breaks")
			}
			return testNow
		}
	})
	v, err := chk.Check(t.Context(), f.request())
	wantUndecided(t, v, err, handoff.ErrInternal, "ppppppnnn")
	v, err = chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if sv.calls.Load() != 1 || reads.Load() != 2 {
		t.Errorf("the verifier was called %d times and the clock read %d times, want 1 and 2", sv.calls.Load(), reads.Load())
	}
}

func TestAClockIsReadAfterTheContextIsCheckedAndBeforeTheVerifier(t *testing.T) {
	// A stopped context is the answer before the clock is read at all; a clock that panics stops the
	// call before the verifier is called.
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	var reads atomic.Int32
	chk := checkerWithCfg(t, handoff.StorePIV, returning(f.goodEvidence(handoff.StorePIV)), func(c *handoff.Config) {
		c.Now = func() time.Time { reads.Add(1); panic("the clock broke") }
	})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := chk.Check(ctx, f.request())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v, want the cancellation of the context", err)
	}
	if reads.Load() != 0 {
		t.Errorf("the clock was read %d times after the context was stopped", reads.Load())
	}
}

func TestAClockThatGivesATimeInAnotherZoneIsGivenToTheVerifierInUTC(t *testing.T) {
	f := newFixture(t, handoff.StorePIV, csrSpec{})
	var got time.Time
	sv := &stub{fn: func(_ context.Context, _ *handoff.Request, _ *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
		got = now
		return f.goodEvidence(handoff.StorePIV), nil
	}}
	zone := time.FixedZone("far", 5*3600+1800)
	chk := checkerWithCfg(t, handoff.StorePIV, sv, func(c *handoff.Config) {
		c.Now = func() time.Time { return testNow.In(zone) }
	})
	v, err := chk.Check(t.Context(), f.request())
	wantAccepted(t, v, err)
	if !got.Equal(testNow) || got.Location() != time.UTC {
		t.Errorf("the verifier was given %v, want %v in UTC", got, testNow.UTC())
	}
}
