package rootlist_test

import (
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/rootlist"
)

// The host refuses, as malformed and at check 5, a list whose expires_at
// is not exactly 13 calendar months after its signed_at, and a list whose signed_at is later than
// the host's clock. The page's words for the first: "13 calendar months after signed_at: the same
// day and time of the month, or the last day of the month if it has none". The two rules are for a
// candidate. The list the host holds is not judged by them: the host took it under the clock of its
// day, and a held list that was signed before this rule, or by a clock that was ahead, is still the
// host's trust (ParseHeld does not apply them, and the tests below say so).

// daysIn is the number of days of a month of the Gregorian calendar, from the rules of the calendar
// and not from the time package.
func daysIn(year, month int) int {
	switch month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 31
}

// plusMonths is the second way to compute the date: whole months on the number year*12+month, then
// the day cut to the length of the month it lands in. Nothing of the time package's date arithmetic.
func plusMonths(t time.Time, months int) time.Time {
	t = t.UTC()
	total := t.Year()*12 + int(t.Month()) - 1 + months
	year, month := total/12, total%12+1
	day := t.Day()
	if n := daysIn(year, month); day > n {
		day = n
	}
	return time.Date(year, time.Month(month), day, t.Hour(), t.Minute(), t.Second(), 0, time.UTC)
}

func TestTheArithmeticOfThirteenMonths(t *testing.T) {
	// A table written by hand, from the calendar, for every kind of month end.
	for _, c := range []struct{ signed, expires string }{
		{"2026-01-01T00:00:00Z", "2027-02-01T00:00:00Z"},
		{"2026-11-15T12:00:00Z", "2027-12-15T12:00:00Z"},
		{"2026-01-31T12:00:00Z", "2027-02-28T12:00:00Z"}, // February of a year that is not a leap year
		{"2027-01-31T12:00:00Z", "2028-02-29T12:00:00Z"}, // February of a leap year
		{"2026-12-31T12:00:00Z", "2028-01-31T12:00:00Z"}, // January has 31 days
		{"2026-03-31T12:00:00Z", "2027-04-30T12:00:00Z"}, // April has 30
		{"2026-10-31T23:59:59Z", "2027-11-30T23:59:59Z"},
		{"2026-07-30T00:00:01Z", "2027-08-30T00:00:01Z"},
		{"2026-01-29T12:00:00Z", "2027-02-28T12:00:00Z"},
		{"2026-01-30T12:00:00Z", "2027-02-28T12:00:00Z"},
		{"2027-01-29T12:00:00Z", "2028-02-29T12:00:00Z"},
		{"2027-01-30T12:00:00Z", "2028-02-29T12:00:00Z"},
		{"2024-02-29T12:00:00Z", "2025-03-29T12:00:00Z"}, // signed on a leap day
		{"2028-02-29T12:00:00Z", "2029-03-29T12:00:00Z"},
		{"2027-11-30T12:00:00Z", "2028-12-30T12:00:00Z"},
		{"2026-12-01T12:00:00Z", "2028-01-01T12:00:00Z"}, // the year changes twice over
		{"1999-12-31T12:00:00Z", "2001-01-31T12:00:00Z"},
		{"2099-01-31T12:00:00Z", "2100-02-28T12:00:00Z"}, // 2100 is not a leap year
		{"2399-01-31T12:00:00Z", "2400-02-29T12:00:00Z"}, // 2400 is
		{"2000-02-29T00:00:00Z", "2001-03-29T00:00:00Z"},
	} {
		got := rootlist.ExpiresFor(mustTime(c.signed))
		if got.Format(rootlist.TimeLayout) != c.expires {
			t.Errorf("ExpiresFor(%s) = %s, want %s", c.signed, got.Format(rootlist.TimeLayout), c.expires)
		}
		if other := plusMonths(mustTime(c.signed), 13); other.Format(rootlist.TimeLayout) != c.expires {
			t.Fatalf("the test's own arithmetic is wrong for %s: %s, hand table %s", c.signed, other.Format(rootlist.TimeLayout), c.expires)
		}
	}
	if rootlist.ExpiryMonths != 13 {
		t.Errorf("ExpiryMonths is %d, the page says 13", rootlist.ExpiryMonths)
	}
}

func TestTheArithmeticOfThirteenMonthsOnEveryDay(t *testing.T) {
	// Every day of 1990 to 2110, at three times of the day, against the second way to compute it.
	n := 0
	for day := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC); day.Year() < 2111; day = day.AddDate(0, 0, 1) {
		for _, clock := range []time.Duration{0, 12*time.Hour + 34*time.Minute + 56*time.Second, 23*time.Hour + 59*time.Minute + 59*time.Second} {
			signed := day.Add(clock)
			got, want := rootlist.ExpiresFor(signed), plusMonths(signed, 13)
			if !got.Equal(want) || got.Location() != time.UTC {
				t.Fatalf("ExpiresFor(%s) = %s, want %s", signed.Format(time.RFC3339), got.Format(time.RFC3339), want.Format(time.RFC3339))
			}
			n++
		}
	}
	if n < 100000 {
		t.Fatalf("checked only %d days", n)
	}
	t.Run("a signing time in another zone is read as the instant it is", func(t *testing.T) {
		zoned := time.Date(2027, 1, 31, 23, 30, 0, 0, time.FixedZone("ahead", 5*3600)) // 18:30 UTC the same day
		if got := rootlist.ExpiresFor(zoned); !got.Equal(mustTime("2028-02-29T18:30:00Z")) {
			t.Errorf("got %s", got)
		}
		late := time.Date(2027, 1, 31, 23, 30, 0, 0, time.FixedZone("behind", -5*3600)) // 04:30 UTC on 1 February
		if got := rootlist.ExpiresFor(late); !got.Equal(mustTime("2028-03-01T04:30:00Z")) {
			t.Errorf("got %s", got)
		}
	})
}

// signedAtClock verifies a candidate list signed at the given time, with the given expiry text, at
// the given clock, against the held list of the base.
func (b *base) onDay(t testing.TB, s spec, clock time.Time) rootlist.Verdict {
	t.Helper()
	return rootlist.Verify(signed(t, s, b.w.a), b.trust(t), clock)
}

func TestTheDatesOfACandidateAtEveryMonthEnd(t *testing.T) {
	b := newBase(t)
	for _, signedText := range []string{
		"2026-01-31T12:00:00Z", "2027-01-31T12:00:00Z", "2026-12-31T12:00:00Z", "2026-03-31T12:00:00Z", "2026-11-30T23:59:59Z",
		"2028-02-29T12:00:00Z", "2026-01-29T12:00:00Z", "2026-01-30T00:00:00Z", "2026-11-15T12:00:00Z",
	} {
		t.Run(signedText, func(t *testing.T) {
			signedAt := mustTime(signedText)
			good := plusMonths(signedAt, 13)
			text := func(x time.Time) string { return `"` + x.Format(rootlist.TimeLayout) + `"` }
			s := listOf(8, b.w.a, b.w.b)
			s.signedAt = text(signedAt)
			clock := signedAt // the exact second at which the list was signed
			s.expiresAt = text(good)
			accepts(t, b.onDay(t, s, clock))
			// An expiry one second less or one second more, 12 and 14 months, a day, and none of the
			// month-end rules (the same day number in a month that has none is not a date).
			for name, bad := range map[string]time.Time{
				"one second less":    good.Add(-time.Second),
				"one second more":    good.Add(time.Second),
				"one day less":       good.AddDate(0, 0, -1),
				"one day more":       good.AddDate(0, 0, 1),
				"12 months":          plusMonths(signedAt, 12),
				"14 months":          plusMonths(signedAt, 14),
				"one year":           plusMonths(signedAt, 12),
				"two years":          plusMonths(signedAt, 24),
				"the signing time":   signedAt,
				"before the signing": signedAt.Add(-time.Hour),
			} {
				s.expiresAt = text(bad)
				v := b.onDay(t, s, clock)
				if bad.Equal(good) {
					continue
				}
				refuses(t, v, rootlist.Malformed, 5)
				_ = name
			}
		})
	}
	t.Run("the next day number that the month does not have is not the answer", func(t *testing.T) {
		// 2026-01-31 plus 13 months is 2027-02-28; 2027-03-03 is what a library that carries the days
		// over would write, and is refused.
		s := listOf(8, b.w.a, b.w.b)
		s.signedAt, s.expiresAt = `"2026-01-31T12:00:00Z"`, `"2027-03-03T12:00:00Z"`
		refuses(t, b.onDay(t, s, mustTime("2026-02-01T00:00:00Z")), rootlist.Malformed, 5)
		s.expiresAt = `"2027-02-28T12:00:00Z"`
		accepts(t, b.onDay(t, s, mustTime("2026-02-01T00:00:00Z")))
	})
	t.Run("the time of the day is part of it", func(t *testing.T) {
		s := listOf(8, b.w.a, b.w.b)
		s.signedAt, s.expiresAt = `"2026-11-15T12:00:00Z"`, `"2027-12-15T00:00:00Z"`
		refuses(t, b.onDay(t, s, now), rootlist.Malformed, 5)
	})
}

func TestTheSigningTimeAgainstTheClock(t *testing.T) {
	b := newBase(t)
	s := b.cand.at("2026-11-30T12:00:00Z")
	signedAt := mustTime("2026-11-30T12:00:00Z")
	accepts(t, b.onDay(t, s, signedAt))                      // the exact second
	accepts(t, b.onDay(t, s, signedAt.Add(time.Second)))     // a second later
	accepts(t, b.onDay(t, s, signedAt.Add(time.Nanosecond))) // a nanosecond later
	refuses(t, b.onDay(t, s, signedAt.Add(-time.Second)), rootlist.Malformed, 5)
	refuses(t, b.onDay(t, s, signedAt.Add(-time.Nanosecond)), rootlist.Malformed, 5)
	refuses(t, b.onDay(t, s, signedAt.Add(-24*time.Hour)), rootlist.Malformed, 5)
	t.Run("the clock in another zone is the instant it is", func(t *testing.T) {
		accepts(t, b.onDay(t, s, signedAt.In(time.FixedZone("ahead", 9*3600))))
		refuses(t, b.onDay(t, s, signedAt.Add(-time.Second).In(time.FixedZone("behind", -9*3600))), rootlist.Malformed, 5)
	})
	t.Run("a signing time that is far in the future", func(t *testing.T) {
		s := b.cand.at("2999-01-01T00:00:00Z")
		refuses(t, b.onDay(t, s, now), rootlist.Malformed, 5)
	})
	t.Run("a list that is signed at the clock and expires at once is not possible", func(t *testing.T) {
		// 13 months is always after the signing time, so a list signed now is never expired now.
		accepts(t, b.onDay(t, b.cand.at("2026-12-01T12:00:00Z"), now))
	})
	t.Run("against initial pins the clock counts too", func(t *testing.T) {
		pins := pinsOf(t, b.w.a.pin, b.w.b.pin)
		accepts(t, rootlist.Verify(signed(t, s, b.w.a), pins, signedAt))
		refuses(t, rootlist.Verify(signed(t, s, b.w.a), pins, signedAt.Add(-time.Second)), rootlist.Malformed, 5)
	})
}

func TestTheDatesAreCheckedAsMalformedAtCheck5(t *testing.T) {
	b := newBase(t)
	w := b.w
	wrong := func(s spec) spec { s.expiresAt = `"9999-12-31T00:00:00Z"`; return s } // far away, not expired
	t.Run("the code is malformed, not expired, for an expiry far away", func(t *testing.T) {
		v := b.verify(t, wrong(b.cand), w.a)
		refuses(t, v, rootlist.Malformed, 5)
		if !strings.Contains(v.Detail, "expires_at") {
			t.Errorf("the detail does not name the member: %q", v.Detail)
		}
	})
	t.Run("the code is malformed for a signing time in the future", func(t *testing.T) {
		v := b.verify(t, b.cand.at("2027-06-01T12:00:00Z"), w.a)
		refuses(t, v, rootlist.Malformed, 5)
		if !strings.Contains(v.Detail, "signed_at") {
			t.Errorf("the detail does not name the member: %q", v.Detail)
		}
	})
	t.Run("the order against the neighbouring checks", func(t *testing.T) {
		bad := wrong(b.cand)
		// Checks 1 to 4 come first.
		refuses(t, b.verify(t, bad, w.z), rootlist.UnknownSigner, 2)
		refuses(t, rootlist.Verify(rootlist.Signed{JSON: bad.json(), JWS: sign(t, b.cand.json(), w.a)}, b.trust(t), now), rootlist.SignatureInvalid, 3)
		v2 := bad
		v2.version = "2"
		refuses(t, b.verify(t, v2, w.a), rootlist.VersionUnsupported, 4)
		// Check 5 comes before checks 6 to 11.
		low := wrong(listOf(3, w.a, w.b))
		refuses(t, b.verify(t, low, w.a), rootlist.Malformed, 5) // not rollback
		same := wrong(listOf(7, w.a))
		refuses(t, b.verify(t, same, w.a), rootlist.Malformed, 5) // not sequence-conflict
		refuses(t, b.verify(t, wrong(listOf(8, w.a, w.b, w.z)), w.a, w.z, w.c), rootlist.Malformed, 5)
		bad10 := wrong(listOf(8, w.a))
		refuses(t, b.verify(t, bad10, w.a), rootlist.Malformed, 5) // not insufficient-signers
		old := b.cand.at(longAgo)
		old.expiresAt = `"2026-11-20T12:00:00Z"`                 // before the clock and not 13 months
		refuses(t, b.verify(t, old, w.a), rootlist.Malformed, 5) // not expired
		// With the dates right, each of those is refused by its own check.
		refuses(t, b.verify(t, b.cand.at(longAgo), w.a), rootlist.Expired, 11)
		refuses(t, b.verify(t, listOf(3, w.a, w.b), w.a), rootlist.Rollback, 6)
	})
	t.Run("the same list again is still read by check 5", func(t *testing.T) {
		// Page: a list again passes the signers and the removals. Check 5 and the clock still run: a
		// held list whose signing time is after the clock of this run is refused.
		held := listOf(8, w.a, w.b).at("2026-11-30T12:00:00Z")
		cand := signed(t, held, w.a)
		acceptsAgain(t, rootlist.Verify(cand, heldOf(t, held), mustTime("2026-12-01T00:00:00Z")))
		refuses(t, rootlist.Verify(cand, heldOf(t, held), mustTime("2026-11-29T00:00:00Z")), rootlist.Malformed, 5)
	})
	t.Run("a held list of the old shape is a trust, and its own bytes again are refused", func(t *testing.T) {
		// A list that the host took before the rule has an expiry that is not 13 months. It is the
		// host's trust (below). Received again, it is a candidate like any other, and check 5 refuses it.
		old := listOf(7, w.a, w.b)
		old.expiresAt = `"2027-06-15T12:00:00Z"`
		cand := signed(t, old, w.a)
		refuses(t, rootlist.Verify(cand, heldOf(t, old), now), rootlist.Malformed, 5)
		accepts(t, b.verifyAgainst(t, old, b.cand, w.a))
	})
}

// verifyAgainst verifies cand, signed by the signers, against a held list of the given spec.
func (b *base) verifyAgainst(t testing.TB, held, cand spec, signers ...*key) rootlist.Verdict {
	t.Helper()
	return rootlist.Verify(signed(t, cand, signers...), heldOf(t, held), now)
}

func TestTheHeldListIsNotJudgedByTheDateRules(t *testing.T) {
	// Why: the host accepted its held list under the clock of its day. The rules ask a list that
	// arrives now to be 13 months long and not signed in the future of the host's clock. A held list
	// may have been signed before the rule, or by a clock that is ahead of this one; refusing it now
	// would take the host's trust away for a reason that is not the list's fault. ParseHeld, which
	// reads the held list, does not apply the rules, and nothing rereads it as a candidate.
	w := newWorld(t)
	for name, s := range map[string]spec{
		"an expiry of 12 months":         func() spec { s := listOf(7, w.a, w.b); s.expiresAt = `"2027-11-15T12:00:00Z"`; return s }(),
		"an expiry far away":             func() spec { s := listOf(7, w.a, w.b); s.expiresAt = `"9999-12-31T00:00:00Z"`; return s }(),
		"an expiry before the signing":   func() spec { s := listOf(7, w.a, w.b); s.expiresAt = `"2026-11-14T12:00:00Z"`; return s }(),
		"a signing time in the future":   listOf(7, w.a, w.b).at("2999-01-01T00:00:00Z"),
		"an old signing time and expiry": listOf(7, w.a, w.b).at(longAgo),
	} {
		t.Run(name, func(t *testing.T) {
			h, err := rootlist.ParseHeld(s.json())
			if err != nil {
				t.Fatalf("the held list is refused: %v", err)
			}
			if _, err := rootlist.ParseList(s.json()); err != nil {
				t.Errorf("ParseList refuses it: %v", err)
			}
			// It is a trust: a candidate that is well formed is accepted against it.
			accepts(t, rootlist.Verify(signed(t, listOf(8, w.a, w.b).at("2026-11-30T12:00:00Z"), w.a), rootlist.HeldTrust(h), now))
			// And CheckHeld still judges only the expiry.
			got := rootlist.CheckHeld(h, now)
			if want := !now.Before(h.List.ExpiresAt); want != (len(got) == 1) {
				t.Errorf("CheckHeld = %v for the expiry %s", got, h.List.ExpiresAt)
			}
		})
	}
}

// TestTheListsOfTheVectorsThatAHostHoldsHaveTheDecidedShape: a list that an accepting case accepts
// or that a case names as held has its expiry exactly 13 months after its signing time, by the
// test's own arithmetic. A refusing case may carry a list of another shape (that is its point), so
// only the lists a host can hold are asked.
func TestTheListsOfTheVectorsThatAHostHoldsHaveTheDecidedShape(t *testing.T) {
	m := loadManifest(t)
	for _, id := range m.holdable(t) {
		l, err := rootlist.ParseList(m.listFiles(t, id).JSON)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if want := plusMonths(l.SignedAt, 13); !l.ExpiresAt.Equal(want) {
			t.Errorf("%s: expires_at %s is not 13 months after signed_at %s (%s)", id, l.ExpiresAt, l.SignedAt, want)
		}
	}
}
