package pki

import (
	"errors"
	"testing"
	"time"
)

// checkEnd refuses the end of a validity that is 9999-12-31 23:59:59Z, whatever zone the instant is given in, and nothing else.
func TestCheckEnd(t *testing.T) {
	endOfTime := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	for _, c := range []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"the end of time", endOfTime, false},
		{"the end of time in a zone ahead of UTC", endOfTime.In(time.FixedZone("UTC+5", 5*3600)), false},
		{"the end of time in a zone behind UTC", endOfTime.In(time.FixedZone("UTC-7", -7*3600)), false},
		{"one second before", endOfTime.Add(-time.Second), true},
		{"a minute before", endOfTime.Add(-time.Minute), true},
		{"the first day of 9999", time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), true},
		{"23:59:59 of another day", time.Date(9999, 12, 30, 23, 59, 59, 0, time.UTC), true},
		{"23:59:59 of 31 December of another year", time.Date(9998, 12, 31, 23, 59, 59, 0, time.UTC), true},
		{"31 December 9999 at 23:59:58", time.Date(9999, 12, 31, 23, 59, 58, 0, time.UTC), true},
		{"31 December 9999 at 00:00:00", time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), true},
		{"an ordinary date", time.Date(2027, 12, 15, 12, 0, 0, 0, time.UTC), true},
	} {
		err := checkEnd(c.at)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
		if err != nil && !wrapsParamsKind(err) {
			t.Errorf("%s: the error is not ErrParams: %v", c.name, err)
		}
	}
}

// wrapsParamsKind says whether the error wraps ErrParams. (The tests of package pki_test hold every refusal to exactly one kind
// in refused; this one is an internal test and has no such helper.)
func wrapsParamsKind(err error) bool {
	return errors.Is(err, ErrParams) && !errors.Is(err, ErrRequest) && !errors.Is(err, ErrSignature)
}
