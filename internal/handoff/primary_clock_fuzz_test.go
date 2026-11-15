package handoff_test

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// The creation time of a primary and the clock of the checker are any numbers: New never panics, refuses a primary
// whose creation time an OpenPGP field cannot hold, refuses a clock that such a field cannot hold, refuses a primary
// that was created after a clock that such a field can hold (and names it by its fingerprint), and makes the checker
// in every other case.
func FuzzNewPrimaryAgainstTheClock(f *testing.F) {
	key := newPGPKey(f, testNow)
	baseCfg := newPGPFixture(f, 1, handoff.StoreSoftware).config(nil)
	now := testNow.Unix()
	for _, s := range [][3]int64{
		{now, now, 0}, {now + 1, now, 0}, {now - 1, now, 0}, {now + 1, now, 999_999_999}, {now, now, 999_999_999},
		{0, now, 0}, {1, 1, 0}, {1, 0, 0}, {2, 1, 0}, {-1, now, 0}, {math.MaxUint32, now, 0}, {math.MaxUint32, math.MaxUint32, 0},
		{math.MaxUint32 + 1, now, 0}, {now, -1, 0}, {now, math.MaxUint32, 0}, {now, math.MaxUint32 + 1, 0}, {now, 1 << 40, 0},
		{math.MinInt64, now, 0}, {math.MaxInt64, now, 0}, {now, math.MinInt64, 0}, {now, math.MaxInt64, 999_999_999},
	} {
		f.Add(s[0], s[1], s[2], true)
		f.Add(s[0], s[1], s[2], false)
	}
	f.Fuzz(func(t *testing.T, createdSec, clockSec, clockNanos int64, withDelegation bool) {
		created := time.Unix(createdSec, 0).UTC()
		clock := time.Unix(clockSec, clockNanos%1_000_000_000)
		k := &pgpKey{priv: key.priv, created: created}
		cfg := baseCfg
		cfg.Primaries = []handoff.PrimaryRef{k.ref()}
		cfg.Now = func() time.Time { return clock }
		if !withDelegation {
			cfg.Delegation = nil
		}
		chk, err := handoff.New(cfg)
		heldByAField := func(sec int64) bool { return sec >= 1 && sec <= math.MaxUint32 }
		clockSecs := clock.Truncate(time.Second).Unix()
		switch {
		case !heldByAField(createdSec):
			if !errors.Is(err, handoff.ErrConfig) || chk != nil {
				t.Fatalf("created %d, clock %v: New returned (%v, %v), want ErrConfig", createdSec, clock, chk, err)
			}
		case !heldByAField(clockSecs):
			// A clock that a field cannot hold cannot be held against a primary: a check that cannot run is
			// not a pass, and the error says so as a configuration fault and nothing else.
			if !errors.Is(err, handoff.ErrConfig) || chk != nil || errors.Is(err, handoff.ErrInternal) || errors.Is(err, handoff.ErrNoPrimaries) {
				t.Fatalf("created %d, clock %v: New returned (%v, %v), want ErrConfig for a clock that cannot be read", createdSec, clock, chk, err)
			}
		case createdSec > clockSecs:
			if !errors.Is(err, handoff.ErrConfig) || chk != nil || !strings.Contains(err.Error(), k.fingerprint()) {
				t.Fatalf("created %d, clock %v: New returned (%v, %v), want ErrConfig that names %s", createdSec, clock, chk, err, k.fingerprint())
			}
		default:
			if err != nil || chk == nil {
				t.Fatalf("created %d, clock %v: New refused a primary that is not late: %v", createdSec, clock, err)
			}
		}
	})
}

// The clock of the call is any number too, whatever the clock that New read: the call never panics, and its answer is
// by the clock that it read. A time that a field cannot hold is an ErrInternal; a primary created after the time is an
// ErrConfig that names the primary, with no code and no acceptance; in every other case the call is not that error.
func FuzzCheckPrimaryAgainstTheClockOfTheCall(f *testing.F) {
	key := newPGPKey(f, testNow)
	now := testNow.Unix()
	for _, s := range [][3]int64{
		{now, now, now}, {now, now, now - 1}, {now, now + 3600, now}, {now, now + 3600, now - 1}, {now - 3600, now, now - 3601},
		{now, now, 0}, {now, now, -1}, {now, now, 1 << 32}, {now, now, 1<<32 - 1}, {1, 1, 1}, {1<<32 - 1, 1<<32 - 1, 1<<32 - 1},
		{now, now, math.MinInt64}, {now, now, math.MaxInt64},
	} {
		f.Add(s[0], s[1], s[2], int64(0))
		f.Add(s[0], s[1], s[2], int64(999_999_999))
	}
	f.Fuzz(func(t *testing.T, createdSec, newSec, callSec, nanos int64) {
		heldByAField := func(sec int64) bool { return sec >= 1 && sec <= math.MaxUint32 }
		if !heldByAField(createdSec) || !heldByAField(newSec) || createdSec > newSec {
			t.Skip("New refuses it: the other fuzz target holds that")
		}
		nanos = ((nanos % 1_000_000_000) + 1_000_000_000) % 1_000_000_000
		fix := newPGPFixture(t, 1, handoff.StoreSoftware)
		k := &pgpKey{priv: key.priv, created: time.Unix(createdSec, 0).UTC()}
		fix.primaries = []*pgpKey{k}
		fix.sigs = [][]byte{fix.backSig(k, nil)}
		call := time.Unix(callSec, nanos)
		reads := 0
		chk, err := handoff.New(fix.config(func(c *handoff.Config) {
			c.Now = func() time.Time {
				reads++
				if reads == 1 {
					return time.Unix(newSec, 0)
				}
				return call
			}
		}))
		if err != nil || chk == nil {
			t.Fatalf("New refused a whole configuration: %v", err)
		}
		v, err := chk.Check(t.Context(), fix.request())
		callSecs := call.Truncate(time.Second).Unix()
		switch {
		case !heldByAField(callSecs):
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppnnnnn")
		case createdSec > callSecs:
			wantUndecided(t, v, err, handoff.ErrConfig, "ppppnnnnn")
			if !strings.Contains(err.Error(), k.fingerprint()) || v.Code != "" || errors.Is(err, handoff.ErrNoPrimaries) || errors.Is(err, handoff.ErrInternal) {
				t.Fatalf("created %d, call %d: error %v, code %q", createdSec, callSecs, err, v.Code)
			}
		default:
			if errors.Is(err, handoff.ErrConfig) {
				t.Fatalf("created %d, call %d: a primary that is not late gives %v", createdSec, callSecs, err)
			}
			if err != nil && !errors.Is(err, handoff.ErrInternal) {
				t.Fatalf("created %d, call %d: %v", createdSec, callSecs, err)
			}
		}
	})
}
