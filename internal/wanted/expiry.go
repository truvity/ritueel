package wanted

import (
	"fmt"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

// MaxValidMonths is the longest a key may be valid from the day it is judged: 36 calendar months, the three
// years of record 0008, rule 5.
const MaxValidMonths = 36

// ExpiryProblem says what is wrong with the day a key expires, judged against now, or "" when nothing is.
// The key expires at 00:00 UTC of ValidUntil, which must be after now, so today and every day before it are
// refused, and not after now plus [MaxValidMonths] calendar months ([pki.AddMonths]: the same day of the month,
// or the last day of a shorter month). The caller gives now, from the clock of its environment: this package
// never reads a clock. The text is fixed words and dates that the reader made.
func (k Key) ExpiryProblem(now time.Time) string {
	if k.ValidUntil.IsZero() {
		return "valid_until is not set"
	}
	if now.IsZero() {
		return "there is no clock: the time to judge the day against was not given"
	}
	now = now.UTC()
	latest, err := pki.AddMonths(now, MaxValidMonths)
	if err != nil {
		return "the clock gives a time that is outside the years 1 to 9999"
	}
	switch end := k.ValidUntil.Time(); {
	case !end.After(now):
		return fmt.Sprintf("valid_until %s is not after now: a key expires at 00:00 UTC of that day, and today in UTC is %s", k.ValidUntil, now.Format(time.DateOnly))
	case end.After(latest):
		return fmt.Sprintf("valid_until %s is more than %d months from now: a key expires at 00:00 UTC of that day, and the latest day is %s", k.ValidUntil, MaxValidMonths, latest.Format(time.DateOnly))
	}
	return ""
}
