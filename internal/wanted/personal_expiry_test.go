package wanted_test

import (
	"math/rand"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/wanted"
)

// The day a key expires, judged against a clock that the test fixes. A key expires at 00:00 UTC of its day: that
// instant must be after now, and not after now plus 36 calendar months (the same day of the month, or the last
// day of a shorter month, with the time of day of now).

func keyOn(t testing.TB, day string) wanted.Key {
	t.Helper()
	return mustRoot(t, "openpgp", swap(t, personalOpenPGP, "2029-11-26", day)).Keys()[0]
}

func utc(y int, m time.Month, d, h, mi, s, ns int) time.Time {
	return time.Date(y, m, d, h, mi, s, ns, time.UTC)
}

const (
	tooLate  = "is not after now"
	tooFar   = "is more than 36 months from now"
	todayWas = "today in UTC is "
)

func TestTheKeyExpiresAtMidnightUTCOfItsDay(t *testing.T) {
	day := keyOn(t, "2026-12-15")
	for name, tc := range map[string]struct {
		now  time.Time
		want string // "" when the day is accepted
	}{
		"a second before midnight":     {utc(2026, 12, 14, 23, 59, 59, 0), ""},
		"a nanosecond before midnight": {utc(2026, 12, 14, 23, 59, 59, 999999999), ""},
		"midnight itself":              {utc(2026, 12, 15, 0, 0, 0, 0), tooLate},
		"a nanosecond after":           {utc(2026, 12, 15, 0, 0, 0, 1), tooLate},
		"a second after":               {utc(2026, 12, 15, 0, 0, 1, 0), tooLate},
		"noon of the day":              {utc(2026, 12, 15, 12, 0, 0, 0), tooLate},
		"the day after":                {utc(2026, 12, 16, 0, 0, 0, 0), tooLate},
		"a year before":                {utc(2025, 12, 15, 0, 0, 0, 0), ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := day.ExpiryProblem(tc.now)
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("ExpiryProblem(%v) = %q, want %q", tc.now, got, tc.want)
			}
		})
	}
}

func TestTheKeyEndsAtMostThirtySixMonthsFromNow(t *testing.T) {
	// The day 2029-11-27 is the latest from 2026-11-27 00:00:00 UTC on: one second earlier is a day too soon.
	day := keyOn(t, "2029-11-27")
	for name, tc := range map[string]struct {
		now  time.Time
		want string
	}{
		"the first instant that is far enough":  {utc(2026, 11, 27, 0, 0, 0, 0), ""},
		"a nanosecond before it":                {utc(2026, 11, 26, 23, 59, 59, 999999999), tooFar},
		"a second before it":                    {utc(2026, 11, 26, 23, 59, 59, 0), tooFar},
		"a second after it":                     {utc(2026, 11, 27, 0, 0, 1, 0), ""},
		"the end of the day":                    {utc(2026, 11, 27, 23, 59, 59, 0), ""},
		"a month earlier":                       {utc(2026, 10, 27, 0, 0, 0, 0), tooFar},
		"the day before in a zone far east":     {time.Date(2026, 11, 27, 13, 59, 59, 0, time.FixedZone("east", 14*3600)), tooFar},
		"the same instant in a zone far east":   {time.Date(2026, 11, 27, 14, 0, 0, 0, time.FixedZone("east", 14*3600)), ""},
		"the day before in a zone far west":     {time.Date(2026, 11, 26, 11, 59, 59, 0, time.FixedZone("west", -12*3600)), tooFar},
		"the same instant in a zone far west":   {time.Date(2026, 11, 26, 12, 0, 0, 0, time.FixedZone("west", -12*3600)), ""},
		"a zone of a quarter hour, one second":  {time.Date(2026, 11, 27, 5, 44, 59, 0, time.FixedZone("nepal", 5*3600+45*60)), tooFar},
		"a zone of a quarter hour, at the mark": {time.Date(2026, 11, 27, 5, 45, 0, 0, time.FixedZone("nepal", 5*3600+45*60)), ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := day.ExpiryProblem(tc.now)
			if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
				t.Errorf("ExpiryProblem(%v) = %q, want %q", tc.now, got, tc.want)
			}
		})
	}
}

func TestTodayAndTomorrowInUTC(t *testing.T) {
	now := utc(2026, 11, 27, 15, 0, 0, 0)
	today, tomorrow := keyOn(t, "2026-11-27"), keyOn(t, "2026-11-28")
	if got := today.ExpiryProblem(now); !strings.Contains(got, tooLate) || !strings.Contains(got, todayWas+"2026-11-27") {
		t.Errorf("today: %q", got)
	}
	if got := tomorrow.ExpiryProblem(now); got != "" {
		t.Errorf("tomorrow: %q", got)
	}
	// Yesterday and the day before are in the past.
	for _, d := range []string{"2026-11-26", "2026-01-01", "2000-01-01"} {
		if got := keyOn(t, d).ExpiryProblem(now); !strings.Contains(got, tooLate) {
			t.Errorf("%s: %q", d, got)
		}
	}
	// The day of the calendar of the zone is not the day of UTC: at 12:30 on the 27th in a zone 13 hours east it
	// is still the 26th in UTC, so the 27th is tomorrow and is accepted, and the text names the day in UTC.
	late := time.Date(2026, 11, 27, 12, 30, 0, 0, time.FixedZone("east", 13*3600))
	if got := today.ExpiryProblem(late); got != "" {
		t.Errorf("the 27th at 12:30 +13:00 is 23:30 UTC of the 26th: %q", got)
	}
	if got := keyOn(t, "2026-11-26").ExpiryProblem(late); !strings.Contains(got, todayWas+"2026-11-26") {
		t.Errorf("the 26th at 23:30 UTC: %q", got)
	}
	// In a zone far west the calendar is a day behind: 20:00 on the 26th at -08:00 is 04:00 UTC on the 27th.
	west := time.Date(2026, 11, 26, 20, 0, 0, 0, time.FixedZone("west", -8*3600))
	if got := keyOn(t, "2026-11-27").ExpiryProblem(west); !strings.Contains(got, tooLate) || !strings.Contains(got, todayWas+"2026-11-27") {
		t.Errorf("the 27th in UTC: %q", got)
	}
}

func TestTheLastDayOfThirtySixCalendarMonths(t *testing.T) {
	// latest is the last day that a key may expire on, for a clock at noon UTC on start.
	for name, tc := range map[string]struct{ start, latest, after string }{
		"a normal day":                               {"2026-11-27", "2029-11-27", "2029-11-28"},
		"the first of a month":                       {"2026-11-01", "2029-11-01", "2029-11-02"},
		"the last day of a month of 30 days":         {"2026-11-30", "2029-11-30", "2029-12-01"},
		"the last day of a month of 31 days":         {"2026-01-31", "2029-01-31", "2029-02-01"},
		"the last day of the year":                   {"2026-12-31", "2029-12-31", "2030-01-01"},
		"the 31st into a month of 30 days":           {"2026-03-31", "2029-03-31", "2029-04-01"},
		"the last day of February, no leap year":     {"2026-02-28", "2029-02-28", "2029-03-01"},
		"the 27th of February is not the last":       {"2026-02-27", "2029-02-27", "2029-02-28"},
		"the 28th of February in a leap year":        {"2028-02-28", "2031-02-28", "2031-03-01"},
		"the leap day":                               {"2028-02-29", "2031-02-28", "2031-03-01"},
		"another leap day":                           {"2024-02-29", "2027-02-28", "2027-03-01"},
		"the last day of February, into a leap year": {"2025-02-28", "2028-02-28", "2028-02-29"},
		"the 29th of January into a short February":  {"2026-01-29", "2029-01-29", "2029-01-30"},
		"the 30th of August":                         {"2026-08-30", "2029-08-30", "2029-08-31"},
		"the last day of a month, into a leap day":   {"2025-02-28", "2028-02-28", "2028-02-29"},
		"the leap day of 2096, into a century year":  {"2096-02-29", "2099-02-28", "2099-03-01"},
		"the last day of February 2097 into 2100":    {"2097-02-28", "2100-02-28", "2100-03-01"},
		"a clock near the last year that a date has": {"2102-12-31", "2105-12-31", "2106-01-01"},
		"the 29th of February 2000, a leap year":     {"2000-02-29", "2003-02-28", "2003-03-01"},
	} {
		t.Run(name, func(t *testing.T) {
			start, err := time.Parse(time.DateOnly, tc.start)
			if err != nil {
				t.Fatal(err)
			}
			now := start.Add(12 * time.Hour)
			if got := keyOn(t, tc.latest).ExpiryProblem(now); got != "" {
				t.Errorf("the latest day %s from %s: %q", tc.latest, tc.start, got)
			}
			if tc.after != "2106-01-01" {
				got := keyOn(t, tc.after).ExpiryProblem(now)
				if !strings.Contains(got, tooFar) || !strings.Contains(got, "the latest day is "+tc.latest) || !strings.Contains(got, "00:00 UTC") {
					t.Errorf("the day after, %s from %s: %q", tc.after, tc.start, got)
				}
			}
		})
	}
}

// The same instant gives the same answer in every zone, and the answer is the one of an independent count of the
// months.
func TestTheSameInstantGivesTheSameAnswerInEveryZone(t *testing.T) {
	zones := []*time.Location{
		time.UTC, time.FixedZone("far east", 14*3600), time.FixedZone("far west", -12*3600),
		time.FixedZone("nepal", 5*3600+45*60), time.FixedZone("newfoundland", -(3*3600 + 30*60)),
	}
	days := []string{"2026-11-26", "2026-11-27", "2026-11-28", "2026-12-31", "2029-11-26", "2029-11-27", "2029-11-28", "2029-12-01", "2105-12-31"}
	instants := []time.Time{
		utc(2026, 11, 26, 23, 59, 59, 0), utc(2026, 11, 27, 0, 0, 0, 0), utc(2026, 11, 27, 0, 0, 1, 0),
		utc(2026, 11, 27, 11, 59, 59, 0), utc(2026, 11, 27, 23, 59, 59, 0), utc(2026, 11, 28, 0, 0, 0, 0),
		utc(2024, 2, 29, 12, 0, 0, 0), utc(2026, 12, 31, 23, 59, 59, 0),
	}
	for _, d := range days {
		key := keyOn(t, d)
		for _, at := range instants {
			want := key.ExpiryProblem(at)
			for _, z := range zones {
				if got := key.ExpiryProblem(at.In(z)); got != want {
					t.Errorf("%s at %v in %v: %q, in UTC %q", d, at, z, got, want)
				}
			}
		}
	}
}

// plus36 counts 36 calendar months by hand: the same day of the month, or the last day of a shorter month, with
// the same time of day.
func plus36(t time.Time) time.Time {
	t = t.UTC()
	y, m, d := t.Date()
	y += 3
	last := time.Date(y, m+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if d > last {
		d = last
	}
	return time.Date(y, m, d, t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}

func TestTheExpiryAgreesWithAnIndependentCountOfTheMonths(t *testing.T) {
	rng := rand.New(rand.NewSource(26112026))
	span := int64(25 * 365 * 24 * 3600)
	start := utc(2020, 1, 1, 0, 0, 0, 0).Unix()
	var days []string
	for _, d := range []time.Time{utc(2026, 1, 1, 0, 0, 0, 0), utc(2031, 6, 1, 0, 0, 0, 0)} {
		for i := range 700 {
			days = append(days, d.AddDate(0, 0, i).Format(time.DateOnly))
		}
	}
	keys := map[string]wanted.Key{}
	for _, d := range days {
		keys[d] = keyOn(t, d)
	}
	for range 400 {
		now := time.Unix(start+rng.Int63n(span), rng.Int63n(1e9)).UTC()
		// Pick the clock near the edge of a day or a month often, where the faults are.
		switch rng.Intn(4) {
		case 0:
			now = utc(now.Year(), now.Month(), 1, 0, 0, 0, 0).Add(-time.Duration(rng.Intn(3)) * time.Second)
		case 1:
			now = utc(now.Year(), now.Month()+1, 0, 23, 59, 59, 0).Add(time.Duration(rng.Intn(3)) * time.Second)
		}
		latest := plus36(now)
		for _, d := range days {
			end, _ := time.Parse(time.DateOnly, d)
			wantOK := end.After(now) && !end.After(latest)
			got := keys[d].ExpiryProblem(now)
			if wantOK != (got == "") {
				t.Fatalf("day %s, now %v, latest %v: ExpiryProblem = %q", d, now, latest, got)
			}
			switch {
			case wantOK:
			case !end.After(now):
				if !strings.Contains(got, tooLate) {
					t.Fatalf("day %s, now %v: %q", d, now, got)
				}
			case !strings.Contains(got, tooFar) || !strings.Contains(got, "the latest day is "+latest.Format(time.DateOnly)):
				t.Fatalf("day %s, now %v: %q", d, now, got)
			}
		}
	}
}

func TestTheClockThatIsNoClockOrOutsideTheYears(t *testing.T) {
	key := keyOn(t, "2029-11-26")
	for name, now := range map[string]time.Time{
		"the zero time":                 time.Time{},
		"the zero time in another zone": time.Time{}.In(time.FixedZone("east", 3600)),
		"the zero time in a far zone":   time.Time{}.In(time.FixedZone("west", -12*3600)),
	} {
		if got := key.ExpiryProblem(now); !strings.Contains(got, "no clock") {
			t.Errorf("%s: %q", name, got)
		}
		err := wanted.CheckPersonal(mustPersonal(t), []*wanted.Root{mustRoot(t, "openpgp", personalOpenPGP)}, nil, nil, nil, now)
		_ = wantFault(t, err, wanted.SettingsPath, 0, "no clock")
	}
	// The time of the Unix epoch is a clock, a wrong one: the key is far from it.
	if got := key.ExpiryProblem(time.Unix(0, 0)); !strings.Contains(got, tooFar) {
		t.Errorf("the epoch: %q", got)
	}
	// A clock whose 36 months end outside the years 1 to 9999.
	for _, now := range []time.Time{utc(9997, 1, 1, 0, 0, 0, 0), utc(9999, 12, 31, 23, 59, 59, 0), utc(10000, 1, 1, 0, 0, 0, 0)} {
		if got := key.ExpiryProblem(now); !strings.Contains(got, "outside the years 1 to 9999") {
			t.Errorf("%v: %q", now, got)
		}
	}
	if got := (wanted.Key{}).ExpiryProblem(utc(2026, 11, 27, 0, 0, 0, 0)); !strings.Contains(got, "not set") {
		t.Errorf("a key with no day: %q", got)
	}
}

func TestTheExpiryIsJudgedWithTheLineOfTheKey(t *testing.T) {
	s, r := mustPersonal(t), mustRoot(t, "openpgp", personalOpenPGP)
	for name, tc := range map[string]struct {
		now   time.Time
		words []string
	}{
		"a second before midnight of the day": {utc(2029, 11, 25, 23, 59, 59, 0), nil},
		"at midnight of the day":              {utc(2029, 11, 26, 0, 0, 0, 0), []string{"keys[1]", tooLate, "00:00 UTC", todayWas + "2029-11-26"}},
		"a day too far":                       {utc(2026, 11, 25, 23, 59, 59, 0), []string{"keys[1]", tooFar, "00:00 UTC", "the latest day is 2029-11-25"}},
		"the first day that is far enough":    {utc(2026, 11, 26, 0, 0, 0, 0), nil},
	} {
		t.Run(name, func(t *testing.T) {
			err := wanted.CheckPersonal(s, []*wanted.Root{r}, nil, nil, nil, tc.now)
			if tc.words == nil {
				if err != nil {
					t.Errorf("%v", err)
				}
				return
			}
			_ = wantFault(t, err, rootFile, keyLine, tc.words...)
		})
	}
}
