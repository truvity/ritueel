package handoff_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// A primary that was created after the clock of the checker cannot be bound: the ceremony refuses a ceremony time that
// is before the creation time of the key, so a request under such a primary would pass every check and fail only in
// the binding. New refuses it as a configuration error and names the primary by its fingerprint. A primary created at
// the clock, or before it, is accepted.

// configWithPrimaries is the configuration of a fixture whose primaries were created at the given times, with the
// clock of the tests, a delegation of type openpgp-subkey, and the signatures made for those primaries.
func primariesCreatedAt(t *testing.T, created ...time.Time) *pgpFixture {
	t.Helper()
	f := newPGPFixture(t, 1, handoff.StoreSoftware)
	f.primaries = nil
	f.sigs = nil
	for _, at := range created {
		p := newPGPKey(t, at)
		f.primaries = append(f.primaries, p)
		f.sigs = append(f.sigs, f.backSig(p, nil))
	}
	return f
}

func wantLateError(t *testing.T, err error, late, onTime []string) {
	t.Helper()
	if !errors.Is(err, handoff.ErrConfig) {
		t.Fatalf("New returned %v, want ErrConfig", err)
	}
	for _, fp := range late {
		if !strings.Contains(err.Error(), fp) {
			t.Errorf("the error %q does not name the late primary %s", err.Error(), fp)
		}
	}
	for _, fp := range onTime {
		if strings.Contains(err.Error(), fp) {
			t.Errorf("the error %q names the primary %s, which is not late", err.Error(), fp)
		}
	}
	if !strings.Contains(err.Error(), "was created after the clock of the checker") {
		t.Errorf("the error %q does not say that the primary was created after the clock", err.Error())
	}
	if errors.Is(err, handoff.ErrInternal) {
		t.Errorf("the error is an ErrInternal too: %v", err)
	}
}

func TestNewRefusesAPrimaryCreatedAfterTheClockAndAcceptsOneAtOrBeforeIt(t *testing.T) {
	zone := time.FixedZone("example", -7*3600)
	for name, tc := range map[string]struct {
		created time.Time
		clock   time.Time
		late    bool
	}{
		"one second after the clock":                     {testNow.Add(time.Second), testNow, true},
		"a minute after the clock":                       {testNow.Add(time.Minute), testNow, true},
		"a year after the clock":                         {testNow.Add(365 * 24 * time.Hour), testNow, true},
		"the last second that a field holds":             {time.Unix(1<<32-1, 0), testNow, true},
		"one second after a clock with a fraction":       {testNow.Add(time.Second), testNow.Add(999 * time.Millisecond), true},
		"one second after, the clock in another zone":    {testNow.Add(time.Second), testNow.In(zone), true},
		"at the clock":                                   {testNow, testNow, false},
		"at the clock, the clock with a fraction":        {testNow, testNow.Add(500 * time.Millisecond), false},
		"half a second before the next whole second":     {testNow, testNow.Add(999 * time.Millisecond), false},
		"one second before the clock":                    {testNow.Add(-time.Second), testNow, false},
		"a year before the clock":                        {testNow.Add(-365 * 24 * time.Hour), testNow, false},
		"at the clock, the clock in another zone":        {testNow, testNow.In(zone), false},
		"the second second of 1970 and a clock after":    {time.Unix(1, 0), testNow, false},
		"a primary of 2026 and a clock in the year 2105": {testNow.Add(time.Second), time.Date(2105, 1, 1, 0, 0, 0, 0, time.UTC), false},
		"a primary of the year 2100, a clock in 2026":    {time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), testNow, true},
		"a primary of the year 2100, a clock in 2101":    {time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2101, 1, 1, 0, 0, 0, 0, time.UTC), false},
		"a clock one second before the creation, 2100":   {time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2099, 12, 31, 23, 59, 59, 0, time.UTC), true},
	} {
		t.Run(name, func(t *testing.T) {
			f := primariesCreatedAt(t, tc.created)
			cfg := f.config(func(c *handoff.Config) { c.Now = func() time.Time { return tc.clock } })
			chk, err := handoff.New(cfg)
			if tc.late {
				if chk != nil {
					t.Error("New returned a checker beside an error")
				}
				wantLateError(t, err, []string{f.primaries[0].fingerprint()}, nil)
				return
			}
			if err != nil || chk == nil {
				t.Fatalf("New refused a primary that is not late: %v", err)
			}
		})
	}
}

// The same under no delegation: the primaries are checked whenever they are given, and a delegation of type
// openpgp-subkey is not needed for the check.
func TestAPrimaryCreatedAfterTheClockIsRefusedUnderAnOpenPGPDelegationAndUnderNone(t *testing.T) {
	late := primariesCreatedAt(t, testNow.Add(time.Second))
	for name, change := range map[string]func(c *handoff.Config){
		"an openpgp-subkey delegation": func(c *handoff.Config) {},
		"no delegation":                func(c *handoff.Config) { c.Delegation = nil },
		"an authenticate capability":   func(c *handoff.Config) { c.Delegation.Capability = "authenticate" },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := handoff.New(late.config(change))
			wantLateError(t, err, []string{late.primaries[0].fingerprint()}, nil)
		})
	}
	// The control: the same primary, the clock moved by one second, and the configuration is whole.
	_, err := handoff.New(late.config(func(c *handoff.Config) { c.Now = func() time.Time { return testNow.Add(time.Second) } }))
	if err != nil {
		t.Errorf("the control is refused: %v", err)
	}
}

// With several primaries the error names the one that is late and none that is not, whatever its place in the list.
func TestTheErrorNamesThePrimaryThatIsLateAndNotTheOthers(t *testing.T) {
	ok1, ok2, ok3 := testNow.Add(-48*time.Hour), testNow, testNow.Add(-time.Second)
	late := testNow.Add(time.Second)
	for name, order := range map[string][]time.Time{
		"the last one":      {ok1, ok2, late},
		"the first one":     {late, ok1, ok2},
		"the middle one":    {ok1, late, ok3},
		"the only one":      {late},
		"the second of two": {ok2, late},
	} {
		t.Run(name, func(t *testing.T) {
			f := primariesCreatedAt(t, order...)
			var lateFP string
			var okFP []string
			for i, p := range f.primaries {
				if order[i].Equal(late) {
					lateFP = p.fingerprint()
				} else {
					okFP = append(okFP, p.fingerprint())
				}
			}
			_, err := handoff.New(f.config(nil))
			wantLateError(t, err, []string{lateFP}, okFP)
		})
	}
	// Two that are late: the error names one of them, the first of the list, and no primary that is on time.
	f := primariesCreatedAt(t, ok1, late, late.Add(time.Hour), ok2)
	_, err := handoff.New(f.config(nil))
	if !errors.Is(err, handoff.ErrConfig) {
		t.Fatalf("New returned %v, want ErrConfig", err)
	}
	if !strings.Contains(err.Error(), f.primaries[1].fingerprint()) || strings.Contains(err.Error(), f.primaries[0].fingerprint()) || strings.Contains(err.Error(), f.primaries[3].fingerprint()) {
		t.Errorf("error = %q, want the first late primary named and no primary that is on time", err.Error())
	}
}

// A request under a primary that is not late is still accepted whole, and the primary created at the clock is accepted
// by the nine checks as well: the fault was not in the checks, and the refusal at New leaves them as they were.
func TestARequestUnderAPrimaryCreatedAtTheClockIsAcceptedByTheNineChecks(t *testing.T) {
	f := primariesCreatedAt(t, testNow, testNow.Add(-time.Hour))
	f.mustAccept(f.checker(nil))
}

// The clock is read once by New when primaries are given, and not at all when there are none.
func TestNewReadsTheClockOnceWhenPrimariesAreGivenAndNeverWhenNoneAre(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	for name, tc := range map[string]struct {
		change func(c *handoff.Config)
		reads  int
	}{
		"two primaries":                             {func(c *handoff.Config) {}, 1},
		"one primary":                               {func(c *handoff.Config) { c.Primaries = c.Primaries[:1] }, 1},
		"primaries and no delegation":               {func(c *handoff.Config) { c.Delegation = nil }, 1},
		"an x509 delegation and no primaries":       {func(c *handoff.Config) { c.Delegation = defaultDelegation(); c.Primaries = nil }, 0},
		"no delegation and no primaries":            {func(c *handoff.Config) { c.Delegation = nil; c.Primaries = nil }, 0},
		"an empty list of primaries, no delegation": {func(c *handoff.Config) { c.Delegation = nil; c.Primaries = []handoff.PrimaryRef{} }, 0},
	} {
		t.Run(name, func(t *testing.T) {
			var reads int
			cfg := f.config(func(c *handoff.Config) {
				tc.change(c)
				c.Now = func() time.Time { reads++; return testNow }
			})
			if _, err := handoff.New(cfg); err != nil {
				t.Fatal(err)
			}
			if reads != tc.reads {
				t.Errorf("New read the clock %d times, want %d", reads, tc.reads)
			}
		})
	}
	// A configuration that New refuses for another reason reads no clock for the primaries: the fault of the primaries
	// is not looked at when something earlier is wrong.
	var reads int
	cfg := f.config(func(c *handoff.Config) { c.Now = func() time.Time { reads++; return testNow }; c.Roots = nil })
	if _, err := handoff.New(cfg); !errors.Is(err, handoff.ErrConfig) {
		t.Fatalf("New returned %v", err)
	}
	if reads != 0 {
		t.Errorf("New read the clock %d times for a configuration with no roots", reads)
	}
}

// With primaries, a clock that cannot be read (it panics), or whose time an OpenPGP time field cannot hold (outside the
// years 1970 to 2106), is an ErrConfig that says the clock could not be read: a primary cannot be held to such a clock,
// and a check that cannot run is not a pass. It is neither an ErrInternal nor an ErrNoPrimaries, and New does not panic.
func TestNewWithPrimariesRefusesAClockThatCannotBeRead(t *testing.T) {
	for name, tc := range map[string]struct {
		clock func() time.Time
		words string
	}{
		"a panic":                                {func() time.Time { panic("the clock broke") }, "(it panicked)"},
		"before 1970":                            {func() time.Time { return time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC) }, "1970 to 2106"},
		"the epoch":                              {func() time.Time { return time.Unix(0, 0) }, "1970 to 2106"},
		"one second before 1970":                 {func() time.Time { return time.Unix(-1, 0) }, "1970 to 2106"},
		"the first second of 2106":               {func() time.Time { return time.Unix(1<<32, 0) }, "1970 to 2106"},
		"the year 2200":                          {func() time.Time { return time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC) }, "1970 to 2106"},
		"the zero time":                          {func() time.Time { return time.Time{} }, "1970 to 2106"},
		"half a second before 1970 is before it": {func() time.Time { return time.Unix(0, 500_000_000) }, "1970 to 2106"},
	} {
		for shape, change := range map[string]func(c *handoff.Config){
			"two primaries, a delegation": func(c *handoff.Config) {},
			"one primary":                 func(c *handoff.Config) { c.Primaries = c.Primaries[:1] },
			"primaries and no delegation": func(c *handoff.Config) { c.Delegation = nil },
			"an authenticate delegation":  func(c *handoff.Config) { c.Delegation.Capability = "authenticate" },
		} {
			t.Run(name+", "+shape, func(t *testing.T) {
				f := newPGPFixture(t, 2, handoff.StoreSoftware)
				chk, err := handoff.New(f.config(func(c *handoff.Config) { change(c); c.Now = tc.clock }))
				if chk != nil || err == nil {
					t.Fatalf("New returned (%v, %v) for primaries and a clock that cannot be read", chk, err)
				}
				if !errors.Is(err, handoff.ErrConfig) {
					t.Errorf("the error does not wrap ErrConfig: %v", err)
				}
				if errors.Is(err, handoff.ErrInternal) || errors.Is(err, handoff.ErrNoPrimaries) {
					t.Errorf("the error is an ErrInternal or an ErrNoPrimaries too: %v", err)
				}
				if !strings.Contains(err.Error(), "the clock of the checker could not be read") || !strings.Contains(err.Error(), tc.words) {
					t.Errorf("the error %q does not say that the clock could not be read, with %q", err.Error(), tc.words)
				}
			})
		}
	}
}

// A time that a field holds is read: the last second of 2105-2106, the second after the epoch.
func TestNewWithPrimariesReadsTheFirstAndTheLastSecondThatAFieldHolds(t *testing.T) {
	for name, at := range map[string]time.Time{
		"the second after the epoch, with a fraction": time.Unix(1, 999_999_999),
		"the last second that a field holds":          time.Unix(1<<32-1, 0),
		"the last second, with a fraction":            time.Unix(1<<32-1, 999_999_999),
	} {
		t.Run(name, func(t *testing.T) {
			f := primariesCreatedAt(t, time.Unix(1, 0))
			if _, err := handoff.New(f.config(func(c *handoff.Config) { c.Now = func() time.Time { return at } })); err != nil {
				t.Errorf("New refused a clock that a field holds: %v", err)
			}
		})
	}
}

// With no primaries the clock is not read by New, so a clock that cannot be read does not matter to it: the checker is
// made, and a request that needs no primaries is judged as before.
func TestNewWithNoPrimariesDoesNotReadTheClockAndAcceptsOneThatCannotBeRead(t *testing.T) {
	for name, clock := range map[string]func() time.Time{
		"a panic":       func() time.Time { panic("the clock broke") },
		"before 1970":   func() time.Time { return time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC) },
		"the year 2200": func() time.Time { return time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			cfg := defaultConfig(t)
			cfg.Now = func() time.Time { calls++; return clock() }
			chk, err := handoff.New(cfg)
			if err != nil || chk == nil {
				t.Fatalf("New refused a configuration with no primaries: %v", err)
			}
			if calls != 0 {
				t.Errorf("New read the clock %d times with no primaries", calls)
			}
		})
	}
}

// A configuration that is refused for another reason is refused for it, with a clock that cannot be read as well: the
// clock is read after the policy, the primaries, the delegation and the roots, and only when they are whole.
func TestNewTellsTheEarlierFaultBeforeTheFaultOfTheClock(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	for name, change := range map[string]func(c *handoff.Config){
		"no roots":         func(c *handoff.Config) { c.Roots = nil },
		"a bad capability": func(c *handoff.Config) { c.Delegation.Capability = "certify" },
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			_, err := handoff.New(f.config(func(c *handoff.Config) {
				change(c)
				c.Now = func() time.Time { calls++; panic("the clock broke") }
			}))
			if !errors.Is(err, handoff.ErrConfig) {
				t.Fatalf("New returned %v", err)
			}
			if strings.Contains(err.Error(), "the clock of the checker could not be read") {
				t.Errorf("the fault of the clock is told for a configuration with another fault: %v", err)
			}
			if calls != 0 {
				t.Errorf("the clock was read %d times", calls)
			}
		})
	}
}

// The clock is called the way a verifier is: from several goroutines at once at New, with no data race and the same
// answer for each. The test waits for every call to end and does not depend on how the calls are scheduled.
func TestNewWithAClockThatIsSharedGivesTheSameAnswerFromManyCalls(t *testing.T) {
	f := primariesCreatedAt(t, testNow.Add(time.Second))
	good := newPGPFixture(t, 2, handoff.StoreSoftware)
	var wg sync.WaitGroup
	errs := make([]error, 16)
	oks := make([]error, 16)
	for i := range errs {
		wg.Add(2)
		go func() { defer wg.Done(); _, errs[i] = handoff.New(f.config(nil)) }()
		go func() { defer wg.Done(); _, oks[i] = handoff.New(good.config(nil)) }()
	}
	wg.Wait()
	for i := range errs {
		if !errors.Is(errs[i], handoff.ErrConfig) {
			t.Errorf("call %d with a late primary: %v", i, errs[i])
		}
		if oks[i] != nil {
			t.Errorf("call %d with good primaries: %v", i, oks[i])
		}
	}
}

// What the caller does to the configuration after the refusal does not matter, and a refused configuration holds no
// checker: the next New with the same keys and a later clock is a checker that accepts the request.
func TestARefusedPrimaryBecomesAcceptedWhenTheClockIsLaterAndThenTheRequestIsAccepted(t *testing.T) {
	f := primariesCreatedAt(t, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	if _, err := handoff.New(f.config(nil)); !errors.Is(err, handoff.ErrConfig) {
		t.Fatalf("New returned %v, want ErrConfig", err)
	}
	f.mustAccept(f.checker(func(c *handoff.Config) { c.Now = func() time.Time { return testNow.Add(2 * time.Hour) } }))
}
