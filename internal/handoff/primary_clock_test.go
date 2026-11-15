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

// A clock that panics, and a clock whose time a field of OpenPGP cannot hold, are not judged by New: it makes the
// checker, even for a primary that would be late for a sane clock, and the call of check 5 tells the fault, as it
// always did, as an error of the checker and never as a refusal or an acceptance.
func TestAClockThatIsBrokenIsLeftToCheckFiveAndNewDoesNotRefuseOrPanic(t *testing.T) {
	for name, clock := range map[string]func() time.Time{
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
			chk, err := handoff.New(f.config(func(c *handoff.Config) { c.Now = clock }))
			if err != nil || chk == nil {
				t.Fatalf("New refused the configuration: %v", err)
			}
			v, err := chk.Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrInternal, "ppppnnnnn")
			if v.Refused() || v.Accepted() {
				t.Errorf("the request was refused or accepted for a fault of the clock: %q", v.Code)
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
