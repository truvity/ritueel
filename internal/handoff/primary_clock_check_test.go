package handoff_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// Check 5 of an openpgp-subkey request holds every active primary to the clock that it read for
// that request, as New holds the primaries to the clock that it read: a clock that failed at New,
// or that has stepped back since, does not skip the guard. A primary created after the clock of
// the call ends the call with an error that wraps ErrConfig and names the primary by its
// fingerprint. It is "cannot decide", not a refusal: no reason code of the contract page names it,
// so the verdict has no code and is not accepted, and checks 1 to 4 passed and 5 to 9 did not run.

// clockOf is a clock that gives these times in turn, one for each read, and the last one for every
// read after them. It is safe to call from several goroutines.
func clockOf(times ...time.Time) (now func() time.Time, reads func() int) {
	var mu sync.Mutex
	n := 0
	now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		i := n
		n++
		if i >= len(times) {
			i = len(times) - 1
		}
		return times[i]
	}
	reads = func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
	return now, reads
}

// wantPrimaryAfterTheClock fails unless err is the error of a primary created after the clock of the call.
func wantPrimaryAfterTheClock(t testing.TB, v handoff.Verdict, err error, late []string, onTime []string) {
	t.Helper()
	wantUndecided(t, v, err, handoff.ErrConfig, "ppppnnnnn")
	if v.Code != "" {
		t.Errorf("the verdict has the code %q: no code of the contract names this case", v.Code)
	}
	for _, fp := range late {
		if !strings.Contains(err.Error(), fp) {
			t.Errorf("the error %q does not name the primary %s", err, fp)
		}
	}
	for _, fp := range onTime {
		if strings.Contains(err.Error(), fp) {
			t.Errorf("the error %q names the primary %s, which is not late", err, fp)
		}
	}
	if !strings.Contains(err.Error(), "was created after the clock that this check read") {
		t.Errorf("the error %q does not say that the primary was created after the clock that this check read", err)
	}
	if errors.Is(err, handoff.ErrNoPrimaries) {
		t.Errorf("the error is an ErrNoPrimaries: %v", err)
	}
	if errors.Is(err, handoff.ErrInternal) {
		t.Errorf("the error is an ErrInternal: %v", err)
	}
}

func TestCheckFiveHoldsEveryPrimaryToTheClockOfTheCall(t *testing.T) {
	created := testNow.Add(-time.Hour)
	zone := time.FixedZone("example", 5*3600)
	for name, tc := range map[string]struct {
		check time.Time
		late  bool
	}{
		"at the creation time":                      {created, false},
		"one second after":                          {created.Add(time.Second), false},
		"a fraction of a second after":              {created.Add(999 * time.Millisecond), false},
		"a day after":                               {created.Add(24 * time.Hour), false},
		"at the creation time, in another zone":     {created.In(zone), false},
		"one second before":                         {created.Add(-time.Second), true},
		"half a second before":                      {created.Add(-500 * time.Millisecond), true},
		"an hour before":                            {created.Add(-time.Hour), true},
		"a day before":                              {created.Add(-24 * time.Hour), true},
		"before the subkey was created":             {pgpSubCreated.Add(-time.Hour), true},
		"one second before, in another zone":        {created.Add(-time.Second).In(zone), true},
		"the second after the epoch, as a clock":    {time.Unix(1, 0), true},
		"the last second that a time field holds":   {time.Unix(1<<32-1, 0), false},
		"the clock is far ahead of every primary":   {testNow.Add(50 * 365 * 24 * time.Hour), false},
		"a clock that is only a fraction of a late": {created.Add(-time.Nanosecond), true},
	} {
		t.Run(name, func(t *testing.T) {
			f := primariesCreatedAt(t, created)
			// New reads a clock that is after the creation; the call reads another one.
			now, reads := clockOf(testNow, tc.check)
			chk := f.checker(func(c *handoff.Config) { c.Now = now })
			if reads() != 1 {
				t.Fatalf("New read the clock %d times", reads())
			}
			v, err := chk.Check(t.Context(), f.request())
			if tc.late {
				wantPrimaryAfterTheClock(t, v, err, []string{f.primaries[0].fingerprint()}, nil)
				return
			}
			wantAccepted(t, v, err)
		})
	}
}

// The guard is applied before the subkey is compared with the clock: a clock that stepped back to
// before the creation of the subkey and of the primary is the error of the primary, and not the
// refusal "the subkey was created after the time of the check".
func TestCheckFiveTheGuardOfThePrimariesComesBeforeTheTimeOfTheSubkey(t *testing.T) {
	f := primariesCreatedAt(t, testNow.Add(-time.Hour))
	now, _ := clockOf(testNow, pgpSubCreated.Add(-time.Second))
	chk := f.checker(func(c *handoff.Config) { c.Now = now })
	v, err := chk.Check(t.Context(), f.request())
	wantPrimaryAfterTheClock(t, v, err, []string{f.primaries[0].fingerprint()}, nil)
	// The control: primaries made before the subkey, the same clock: the subkey is the fault, and it is a refusal.
	g := newPGPFixture(t, 2, handoff.StoreSoftware)
	now, _ = clockOf(testNow, pgpSubCreated.Add(-time.Second))
	chk = g.checker(func(c *handoff.Config) { c.Now = now })
	v, err = chk.Check(t.Context(), g.request())
	if err != nil {
		t.Fatalf("the control: %v", err)
	}
	if v.Code != handoff.CodePossessionInvalid {
		t.Errorf("the control: code %q, want %q", v.Code, handoff.CodePossessionInvalid)
	}
}

// The error names the first of the primaries, in the order of the list, that is late for the clock
// of the call, and none that is on time.
func TestCheckFiveNamesTheFirstLatePrimaryAndNoOtherThat(t *testing.T) {
	ok1, ok2 := testNow.Add(-48*time.Hour), testNow.Add(-2*time.Hour)
	late1, late2 := testNow.Add(-time.Hour), testNow.Add(-30*time.Minute)
	for name, order := range map[string][]time.Time{
		"the last one":        {ok1, ok2, late1},
		"the first one":       {late1, ok1, ok2},
		"the middle one":      {ok1, late1, ok2},
		"the only one":        {late1},
		"two that are late":   {ok1, late1, late2, ok2},
		"the late ones first": {late2, late1, ok1},
	} {
		t.Run(name, func(t *testing.T) {
			f := primariesCreatedAt(t, order...)
			now, _ := clockOf(testNow, testNow.Add(-90*time.Minute))
			chk := f.checker(func(c *handoff.Config) { c.Now = now })
			v, err := chk.Check(t.Context(), f.request())
			var late string
			var rest []string
			for i, p := range f.primaries {
				switch {
				case late == "" && order[i].After(testNow.Add(-90*time.Minute)):
					late = p.fingerprint()
				default:
					rest = append(rest, p.fingerprint())
				}
			}
			wantPrimaryAfterTheClock(t, v, err, []string{late}, rest)
		})
	}
}

// Each call reads the clock for itself and keeps nothing: a call that is late is followed by calls
// that are not, and by one that is again.
func TestCheckFiveJudgesEachCallByItsOwnReadingOfTheClock(t *testing.T) {
	created := testNow.Add(-time.Hour)
	f := primariesCreatedAt(t, created)
	now, reads := clockOf(testNow, testNow, created.Add(-time.Second), testNow, created.Add(-time.Second), created.Add(-time.Second), testNow)
	chk := f.checker(func(c *handoff.Config) { c.Now = now })
	late := []bool{false, true, false, true, true, false}
	for i, l := range late {
		v, err := chk.Check(t.Context(), f.request())
		if l {
			wantPrimaryAfterTheClock(t, v, err, []string{f.primaries[0].fingerprint()}, nil)
		} else {
			wantAccepted(t, v, err)
		}
		if reads() != 2+i {
			t.Errorf("after call %d the clock was read %d times, want %d", i+1, reads(), 2+i)
		}
	}
}

// The clock is read once for a call: the guard does not read it again.
func TestCheckFiveReadsTheClockOnceForTheGuardAndTheRest(t *testing.T) {
	f := primariesCreatedAt(t, testNow.Add(-time.Hour))
	now, reads := clockOf(testNow)
	chk := f.checker(func(c *handoff.Config) { c.Now = now })
	before := reads()
	f.mustAccept(chk)
	if got := reads() - before; got != 1 {
		t.Errorf("a call read the clock %d times", got)
	}
}

// A clock that is broken at the call and was good at New is the fault of the clock that it always
// was: ErrInternal, no refusal, no acceptance, no new error.
func TestCheckFiveAClockThatBreaksAfterNewIsStillAnErrorOfTheChecker(t *testing.T) {
	for name, bad := range map[string]func() time.Time{
		"a panic":                  func() time.Time { panic("the clock broke") },
		"before 1970":              func() time.Time { return time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC) },
		"the epoch":                func() time.Time { return time.Unix(0, 0) },
		"one second before 1970":   func() time.Time { return time.Unix(-1, 0) },
		"the first second of 2106": func() time.Time { return time.Unix(1<<32, 0) },
		"the year 2200":            func() time.Time { return time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC) },
		"the zero time":            func() time.Time { return time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newPGPFixture(t, 2, handoff.StoreSoftware)
			var mu sync.Mutex
			n := 0
			chk := f.checker(func(c *handoff.Config) {
				c.Now = func() time.Time {
					mu.Lock()
					n++
					first := n == 1
					mu.Unlock()
					if first {
						return testNow
					}
					return bad()
				}
			})
			v, err := chk.Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppnnnnn")
			if v.Refused() || v.Accepted() {
				t.Errorf("the request was refused or accepted for a fault of the clock: %q", v.Code)
			}
			if errors.Is(err, handoff.ErrConfig) {
				t.Errorf("a clock that cannot be read at the call is not a fault of the configuration: %v", err)
			}
		})
	}
}

// Checks 1 to 4 come first: a request that fails one of them is refused for that, whatever the
// clock says about the primaries, and the clock is not read for it.
func TestCheckFiveAPrimaryAfterTheClockDoesNotHideARefusalOfAnEarlierCheck(t *testing.T) {
	f := primariesCreatedAt(t, testNow.Add(-time.Hour))
	f.digest = digestHex(nil)
	now, reads := clockOf(testNow, testNow.Add(-2*time.Hour))
	chk := f.checker(func(c *handoff.Config) { c.Now = now })
	v, err := chk.Check(t.Context(), f.request())
	wantRefusal(t, v, err, handoff.CodeRequestMismatch, 3)
	if reads() != 1 {
		t.Errorf("the clock was read %d times; one is the read of New", reads())
	}
}
