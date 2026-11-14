package pki_test

import (
	"fmt"
	"math"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/pki"
)

func TestAddMonths(t *testing.T) {
	plus5 := time.FixedZone("UTC+5", 5*3600)
	minus8 := time.FixedZone("UTC-8", -8*3600)
	cases := []struct {
		name   string
		in     time.Time
		months int
		want   time.Time
	}{
		// The cases of the hand-over and the brief.
		{"13 months from the ceremony", utc(2026, 11, 15, 12, 0, 0), 13, utc(2027, 12, 15, 12, 0, 0)},
		{"31 January plus 1 is the end of February", utc(2026, 1, 31, 0, 0, 0), 1, utc(2026, 2, 28, 0, 0, 0)},
		{"31 January plus 1 in a leap year", utc(2028, 1, 31, 0, 0, 0), 1, utc(2028, 2, 29, 0, 0, 0)},
		{"31 December plus 2", utc(2026, 12, 31, 0, 0, 0), 2, utc(2027, 2, 28, 0, 0, 0)},
		{"29 February plus 12 months", utc(2024, 2, 29, 0, 0, 0), 12, utc(2025, 2, 28, 0, 0, 0)},
		{"36 months from 1 January", utc(2026, 1, 1, 0, 0, 0), 36, utc(2029, 1, 1, 0, 0, 0)},
		{"minus 1 from 31 March", utc(2026, 3, 31, 0, 0, 0), -1, utc(2026, 2, 28, 0, 0, 0)},
		{"minus 2 from January", utc(2026, 1, 15, 0, 0, 0), -2, utc(2025, 11, 15, 0, 0, 0)},
		{"minus 13 from January", utc(2026, 1, 15, 0, 0, 0), -13, utc(2024, 12, 15, 0, 0, 0)},
		{"31 August plus 1 is 30 September", utc(2026, 8, 31, 0, 0, 0), 1, utc(2026, 9, 30, 0, 0, 0)},
		{"December plus 1 is January", utc(2026, 12, 15, 0, 0, 0), 1, utc(2027, 1, 15, 0, 0, 0)},

		// The edges of the arithmetic.
		{"0 months", utc(2026, 5, 17, 3, 4, 5), 0, utc(2026, 5, 17, 3, 4, 5)},
		{"0 months on 31 January", utc(2026, 1, 31, 3, 4, 5), 0, utc(2026, 1, 31, 3, 4, 5)},
		{"exactly 12 months", utc(2026, 5, 17, 0, 0, 0), 12, utc(2027, 5, 17, 0, 0, 0)},
		{"exactly minus 12 months", utc(2026, 5, 17, 0, 0, 0), -12, utc(2025, 5, 17, 0, 0, 0)},
		{"exactly minus 12 from January", utc(2026, 1, 17, 0, 0, 0), -12, utc(2025, 1, 17, 0, 0, 0)},
		{"minus 1 from January goes to December", utc(2026, 1, 17, 0, 0, 0), -1, utc(2025, 12, 17, 0, 0, 0)},
		{"minus 11 from December is January", utc(2026, 12, 17, 0, 0, 0), -11, utc(2026, 1, 17, 0, 0, 0)},
		{"minus 12 from December is December", utc(2026, 12, 17, 0, 0, 0), -12, utc(2025, 12, 17, 0, 0, 0)},
		{"plus 1 from November", utc(2026, 11, 30, 0, 0, 0), 1, utc(2026, 12, 30, 0, 0, 0)},
		{"plus 2 from November crosses the year", utc(2026, 11, 30, 0, 0, 0), 2, utc(2027, 1, 30, 0, 0, 0)},
		{"plus 3 from 30 November is the end of February", utc(2026, 11, 30, 0, 0, 0), 3, utc(2027, 2, 28, 0, 0, 0)},
		{"plus 12 months from 31 December", utc(2026, 12, 31, 0, 0, 0), 12, utc(2027, 12, 31, 0, 0, 0)},
		{"plus 1 from 31 December", utc(2026, 12, 31, 0, 0, 0), 1, utc(2027, 1, 31, 0, 0, 0)},
		{"plus 4 from 31 December is the end of April", utc(2026, 12, 31, 0, 0, 0), 4, utc(2027, 4, 30, 0, 0, 0)},
		{"29 February plus 48 months", utc(2024, 2, 29, 0, 0, 0), 48, utc(2028, 2, 29, 0, 0, 0)},
		{"29 February minus 12 months", utc(2024, 2, 29, 0, 0, 0), -12, utc(2023, 2, 28, 0, 0, 0)},
		{"29 February minus 48 months", utc(2024, 2, 29, 0, 0, 0), -48, utc(2020, 2, 29, 0, 0, 0)},
		{"30 January plus 1 in a leap year", utc(2028, 1, 30, 0, 0, 0), 1, utc(2028, 2, 29, 0, 0, 0)},
		{"29 January plus 1 in a common year", utc(2027, 1, 29, 0, 0, 0), 1, utc(2027, 2, 28, 0, 0, 0)},
		{"28 February plus 1", utc(2027, 2, 28, 0, 0, 0), 1, utc(2027, 3, 28, 0, 0, 0)},
		{"31 January plus 1 in 2100, which is not a leap year", utc(2100, 1, 31, 0, 0, 0), 1, utc(2100, 2, 28, 0, 0, 0)},
		{"31 January plus 1 in 2000, which is a leap year", utc(2000, 1, 31, 0, 0, 0), 1, utc(2000, 2, 29, 0, 0, 0)},
		{"31 May plus 1 is 30 June", utc(2026, 5, 31, 0, 0, 0), 1, utc(2026, 6, 30, 0, 0, 0)},
		{"31 July plus 1 is 31 August", utc(2026, 7, 31, 0, 0, 0), 1, utc(2026, 8, 31, 0, 0, 0)},
		{"30 April plus 1 is 30 May", utc(2026, 4, 30, 0, 0, 0), 1, utc(2026, 5, 30, 0, 0, 0)},
		{"31 October plus 1 is 30 November", utc(2026, 10, 31, 0, 0, 0), 1, utc(2026, 11, 30, 0, 0, 0)},
		{"the last day of a month plus 1 stays inside the next", utc(2026, 4, 30, 23, 59, 59), 1, utc(2026, 5, 30, 23, 59, 59)},
		{"a long way forward", utc(2026, 11, 15, 12, 0, 0), (9999 - 2026) * 12, utc(9999, 11, 15, 12, 0, 0)},
		{"a long way back", utc(9999, 12, 31, 0, 0, 0), -(9999 - 1) * 12, utc(1, 12, 31, 0, 0, 0)},
		{"a century", utc(2026, 1, 1, 0, 0, 0), 1200, utc(2126, 1, 1, 0, 0, 0)},
		{"into the year 2050, which changes the time format", utc(2049, 12, 31, 23, 59, 59), 1, utc(2050, 1, 31, 23, 59, 59)},

		// Before the year 1 the month number is negative, and the division must go the right way.
		{"January of the year 1 minus 1 month", utc(1, 1, 15, 0, 0, 0), -1, utc(0, 12, 15, 0, 0, 0)},
		{"January of the year 1 minus 13 months", utc(1, 1, 15, 0, 0, 0), -13, utc(-1, 12, 15, 0, 0, 0)},
		{"January of the year 0 minus 12 months", utc(0, 1, 15, 0, 0, 0), -12, utc(-1, 1, 15, 0, 0, 0)},
		{"January of the year 0 minus 24 months", utc(0, 1, 15, 0, 0, 0), -24, utc(-2, 1, 15, 0, 0, 0)},
		{"March of the year 0 minus 3 months", utc(0, 3, 31, 0, 0, 0), -3, utc(-1, 12, 31, 0, 0, 0)},
		{"March of the year 0 minus 1 month clamps", utc(0, 3, 31, 0, 0, 0), -1, utc(0, 2, 29, 0, 0, 0)},
		{"the year 0 back to year 1", utc(0, 6, 15, 0, 0, 0), 12, utc(1, 6, 15, 0, 0, 0)},

		// The time of day, the fraction and the zone.
		{"the time of day is kept", utc(2026, 11, 15, 23, 59, 59), 1, utc(2026, 12, 15, 23, 59, 59)},
		{"the nanoseconds are kept", time.Date(2026, 11, 15, 12, 0, 0, 123456789, time.UTC), 1, time.Date(2026, 12, 15, 12, 0, 0, 123456789, time.UTC)},
		{"midnight", utc(2026, 1, 31, 0, 0, 0), 1, utc(2026, 2, 28, 0, 0, 0)},
		{"a zone ahead of UTC is converted first: the day in UTC is the 31st", time.Date(2026, 2, 1, 2, 0, 0, 0, plus5), 1, utc(2026, 2, 28, 21, 0, 0)},
		{"a zone ahead of UTC, still the 31st in UTC", time.Date(2026, 1, 31, 23, 30, 0, 0, plus5), 1, utc(2026, 2, 28, 18, 30, 0)},
		{"a zone behind UTC is converted first: 31 January 20:00 at UTC-8 is 1 February 04:00 in UTC", time.Date(2026, 1, 31, 20, 0, 0, 0, minus8), 1, utc(2026, 3, 1, 4, 0, 0)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := pki.AddMonths(c.in, c.months)
			// The dates of a certificate are the years 1 to 9999: a time before the year 1, or a result
			// outside the years, is an error (ErrParams) and no time.
			if outsideYears(c.in) || outsideYears(c.want) {
				refused(t, err, pki.ErrParams)
				if !got.IsZero() {
					t.Errorf("a time %v came with the error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(c.want) {
				t.Errorf("AddMonths(%v, %d) = %v, want %v", c.in, c.months, got, c.want)
			}
			if got.Location() != time.UTC {
				t.Errorf("the result is in %v, want UTC", got.Location())
			}
		})
	}
}

// AddMonths against a second way of computing it: let time.Date normalise the month, then clamp
// the day to the last day of that month.
func TestAddMonthsAgainstReference(t *testing.T) {
	starts := []time.Time{
		utc(2026, 1, 1, 0, 0, 0), utc(2026, 1, 28, 1, 2, 3), utc(2026, 1, 29, 1, 2, 3), utc(2026, 1, 30, 1, 2, 3),
		utc(2026, 1, 31, 1, 2, 3), utc(2024, 2, 29, 23, 59, 59), utc(2026, 3, 31, 12, 0, 0), utc(2026, 4, 30, 12, 0, 0),
		utc(2026, 5, 31, 12, 0, 0), utc(2026, 8, 31, 12, 0, 0), utc(2026, 10, 31, 12, 0, 0), utc(2026, 12, 31, 23, 59, 59),
		utc(2100, 1, 31, 0, 0, 0), utc(2000, 2, 29, 0, 0, 0), utc(1999, 12, 31, 0, 0, 0),
		// Around the year 0, where the month number is negative.
		utc(1, 1, 31, 0, 0, 0), utc(1, 12, 31, 0, 0, 0), utc(0, 1, 31, 0, 0, 0), utc(0, 3, 31, 0, 0, 0), utc(0, 12, 31, 23, 59, 59), utc(-1, 12, 31, 0, 0, 0), utc(-3, 1, 15, 0, 0, 0),
	}
	checked, refusedCount := 0, 0
	for _, s := range starts {
		for m := -150; m <= 150; m++ {
			first := time.Date(s.Year(), s.Month()+time.Month(m), 1, s.Hour(), s.Minute(), s.Second(), 0, time.UTC)
			day := s.Day()
			if last := time.Date(first.Year(), first.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day(); day > last {
				day = last
			}
			want := time.Date(first.Year(), first.Month(), day, s.Hour(), s.Minute(), s.Second(), 0, time.UTC)
			got, err := pki.AddMonths(s, m)
			if outsideYears(s) || outsideYears(want) {
				refused(t, err, pki.ErrParams)
				refusedCount++
				continue
			}
			if err != nil || !got.Equal(want) {
				t.Fatalf("AddMonths(%v, %d) = %v, %v, want %v", s, m, got, err, want)
			}
			checked++
		}
	}
	if checked == 0 || refusedCount == 0 {
		t.Fatalf("checked %d, refused %d: nothing was checked on one side", checked, refusedCount)
	}
}

// Going forward and back by the same number of months from the first of a month returns to it.
func TestAddMonthsRoundTripFromFirstOfMonth(t *testing.T) {
	for m := 0; m <= 240; m++ {
		t.Run(fmt.Sprint(m), func(t *testing.T) {
			start := utc(2026, 1, 1, 6, 7, 8)
			there, err := pki.AddMonths(start, m)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := pki.AddMonths(there, -m); err != nil || !got.Equal(start) {
				t.Errorf("forward and back by %d months gives %v, %v, want %v", m, got, err, start)
			}
		})
	}
}

// outsideYears says whether a time is outside the years 1 to 9999, in UTC.
func outsideYears(t time.Time) bool {
	y := t.UTC().Year()
	return y < 1 || y > 9999
}

// The numbers of months and the times that AddMonths refuses: a month count that would overflow the
// arithmetic, a result outside the years 1 to 9999, a time outside them. The error is ErrParams and
// there is no time.
func TestAddMonthsRefuses(t *testing.T) {
	in := utc(2026, 11, 15, 12, 0, 0)
	const years = 12 * 9999
	cases := []struct {
		name   string
		in     time.Time
		months int
	}{
		{"the largest number of months", in, math.MaxInt},
		{"the smallest number of months", in, math.MinInt},
		{"the largest number that fits 32 bits", in, math.MaxInt32},
		{"one month more than the years of a certificate", in, years + 1},
		{"one month less than minus the years of a certificate", in, -years - 1},
		{"the first month of the year 10000", utc(9999, 12, 15, 0, 0, 0), 1},
		{"a month before the year 1", utc(1, 1, 15, 0, 0, 0), -1},
		{"a time in the year 10000", utc(10000, 1, 1, 0, 0, 0), 0},
		{"a time in the year 0", utc(0, 12, 31, 23, 59, 59), 0},
		{"a time in the year -1000", utc(-1000, 6, 1, 0, 0, 0), 0},
		{"a time that is in the year 10000 only in UTC", time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("UTC-5", -5*3600)), 0},
		{"a time that is in the year 0 only in UTC", time.Date(1, 1, 1, 4, 0, 0, 0, time.FixedZone("UTC+5", 5*3600)), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := pki.AddMonths(c.in, c.months)
			refused(t, err, pki.ErrParams)
			if !got.IsZero() {
				t.Errorf("a time %v came with the error", got)
			}
		})
	}
	// And the edges that are accepted: the first and the last month of the years.
	for _, c := range []struct {
		name   string
		in     time.Time
		months int
		want   time.Time
	}{
		{"January of the year 1", utc(1, 1, 31, 0, 0, 0), 0, utc(1, 1, 31, 0, 0, 0)},
		{"December of the year 9999", utc(9999, 12, 31, 23, 59, 59), 0, utc(9999, 12, 31, 23, 59, 59)},
		{"to the last month", utc(1, 1, 31, 0, 0, 0), years - 1, utc(9999, 12, 31, 0, 0, 0)},
		{"to the first month", utc(9999, 12, 31, 0, 0, 0), -(years - 1), utc(1, 1, 31, 0, 0, 0)},
		{"31 January plus 1 month", utc(2026, 1, 31, 0, 0, 0), 1, utc(2026, 2, 28, 0, 0, 0)},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := pki.AddMonths(c.in, c.months)
			if err != nil || !got.Equal(c.want) {
				t.Errorf("AddMonths = %v, %v, want %v", got, err, c.want)
			}
		})
	}
}
