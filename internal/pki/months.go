package pki

import "time"

// AddMonths returns t moved by a number of calendar months, in UTC: the same day and the same
// time of the month, or the last day of the month when the month has no such day (31 January
// plus one month is the last day of February). A negative number of months moves back. The
// result is always in UTC, whatever the zone of t, and 0 months returns the same instant in UTC.
// The time of day and the fraction of a second are kept.
//
// It is for dates that a certificate holds: t and the result are both in the years 1 to 9999
// (RFC 5280, section 4.1.2.5, in UTC). It returns an error that wraps [ErrParams], and no time,
// for a t outside those years, and for a number of months that moves the result outside them. That
// includes a number so large that the arithmetic on the month count would overflow: it is refused
// before it is added, and never wraps to a date that looks right.
func AddMonths(t time.Time, months int) (time.Time, error) {
	t = t.UTC()
	if err := checkYear("the time", t); err != nil {
		return time.Time{}, err
	}
	// The years of a certificate span 9999 * 12 months, so a number of months beyond that moves the
	// result out of them from any t, and it is refused here, where adding it cannot overflow.
	if months > 12*9999 || months < -12*9999 {
		return time.Time{}, fail(ErrParams, "%d months move the date out of the years 1 to 9999", months)
	}
	year, month, day := t.Date()
	// A month number from year 0, January: floor division so that a negative sum works.
	n := year*12 + int(month-time.January) + months
	y := n / 12
	m := n % 12
	if m < 0 {
		m += 12
		y--
	}
	if y < 1 || y > 9999 {
		return time.Time{}, fail(ErrParams, "the date %d months from the time is outside the years 1 to 9999", months)
	}
	nm := time.Month(m + 1)
	if last := daysIn(y, nm); day > last {
		day = last
	}
	return time.Date(y, nm, day, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC), nil
}

// checkYear refuses a time outside the years 1 to 9999: the years a certificate holds.
func checkYear(what string, t time.Time) error {
	if y := t.UTC().Year(); y < 1 || y > 9999 {
		return fail(ErrParams, "%s is outside the years 1 to 9999", what)
	}
	return nil
}

// daysIn is the number of days of a month: the day before the first of the next month.
func daysIn(year int, month time.Month) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC).Day()
}
