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
// whose creation time an OpenPGP field cannot hold, refuses a primary that was created after a clock that such a field
// can hold (and names it by its fingerprint), and makes the checker in every other case. A clock that such a field
// cannot hold is left to check 5.
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
			if err != nil || chk == nil {
				t.Fatalf("created %d, clock %v: New returned %v for a clock that is left to check 5", createdSec, clock, err)
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
