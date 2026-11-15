package handoff_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// ErrNoPrimaries is the one error for "the checker holds no primaries for this": an openpgp-subkey
// request on a checker that holds none (Check), and an openpgp-subkey delegation that New refuses
// without them. It wraps ErrConfig, so errors.Is(err, ErrConfig) stays true. No other error matches
// it, in particular none that only has the word "primaries" in its text, and not the errors of a
// clock that cannot be read or of a primary created after the clock. The texts are as they were.

func TestErrNoPrimariesIsAnErrConfigAndErrConfigIsNotIt(t *testing.T) {
	if !errors.Is(handoff.ErrNoPrimaries, handoff.ErrConfig) {
		t.Error("ErrNoPrimaries does not wrap ErrConfig")
	}
	if errors.Is(handoff.ErrConfig, handoff.ErrNoPrimaries) {
		t.Error("ErrConfig matches ErrNoPrimaries")
	}
	for _, other := range []error{handoff.ErrInternal, handoff.ErrNoVerifier, handoff.ErrTypeNotBuilt} {
		if errors.Is(other, handoff.ErrNoPrimaries) {
			t.Errorf("%v matches ErrNoPrimaries", other)
		}
	}
	if want := "handoff: invalid checker configuration: the checker holds no primaries for this"; handoff.ErrNoPrimaries.Error() != want {
		t.Errorf("ErrNoPrimaries says %q, want %q", handoff.ErrNoPrimaries.Error(), want)
	}
	// It is still found through more wrapping.
	wrapped := fmt.Errorf("a: %w", fmt.Errorf("b: %w", handoff.ErrNoPrimaries))
	if !errors.Is(wrapped, handoff.ErrNoPrimaries) || !errors.Is(wrapped, handoff.ErrConfig) {
		t.Errorf("a wrapped ErrNoPrimaries is not found: %v", wrapped)
	}
}

// Check gives it for an openpgp-subkey request on a checker with none, with the text as it was.
func TestCheckOfAnOpenPGPRequestWithNoPrimariesGivesErrNoPrimaries(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	for name, change := range map[string]func(c *handoff.Config){
		"an X.509 delegation": func(c *handoff.Config) { c.Delegation = defaultDelegation(); c.Primaries = nil },
		"an SSH delegation": func(c *handoff.Config) {
			c.Delegation = &handoff.Delegation{Name: "n", Type: handoff.TypeSSH, Root: "r"}
			c.Primaries = nil
		},
		"no delegation":                func(c *handoff.Config) { c.Delegation = nil; c.Primaries = nil },
		"no delegation, an empty list": func(c *handoff.Config) { c.Delegation = nil; c.Primaries = []handoff.PrimaryRef{} },
	} {
		t.Run(name, func(t *testing.T) {
			v, err := f.checker(change).Check(t.Context(), f.request())
			wantUndecided(t, v, err, handoff.ErrConfig, "ppnnnnnnn")
			if !errors.Is(err, handoff.ErrNoPrimaries) {
				t.Errorf("the error is not ErrNoPrimaries: %v", err)
			}
			if want := "handoff: invalid checker configuration: the checker holds no primaries"; err.Error() != want {
				t.Errorf("the text is %q, want %q", err.Error(), want)
			}
			if !errors.Is(errors.Unwrap(err), handoff.ErrConfig) || errors.Unwrap(errors.Unwrap(err)) != nil {
				t.Errorf("the error unwraps to %v, want ErrConfig and nothing under it", errors.Unwrap(err))
			}
		})
	}
}

// New gives it for an openpgp-subkey delegation with no primaries, with the text as it was.
func TestNewOfAnOpenPGPDelegationWithNoPrimariesGivesErrNoPrimaries(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	for name, change := range map[string]func(c *handoff.Config){
		"nil primaries": func(c *handoff.Config) { c.Primaries = nil },
		"an empty list": func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{} },
		"authenticate":  func(c *handoff.Config) { c.Primaries = nil; c.Delegation.Capability = "authenticate" },
	} {
		t.Run(name, func(t *testing.T) {
			chk, err := handoff.New(f.config(change))
			if chk != nil || err == nil {
				t.Fatalf("New returned (%v, %v)", chk, err)
			}
			if !errors.Is(err, handoff.ErrNoPrimaries) || !errors.Is(err, handoff.ErrConfig) {
				t.Errorf("the error is not ErrNoPrimaries and ErrConfig: %v", err)
			}
			if want := "handoff: invalid checker configuration: an openpgp-subkey delegation needs primaries"; err.Error() != want {
				t.Errorf("the text is %q, want %q", err.Error(), want)
			}
		})
	}
}

// No other error of the package matches it: not a plain ErrConfig whose text says "primaries", not
// the errors of the primaries, not those of the clock.
func TestNoOtherErrorOfThePackageIsErrNoPrimaries(t *testing.T) {
	f := newPGPFixture(t, 2, handoff.StoreSoftware)
	late := primariesCreatedAt(t, testNow.Add(time.Second))
	for name, cfg := range map[string]handoff.Config{
		"primaries with an X.509 delegation": f.config(func(c *handoff.Config) { c.Delegation = defaultDelegation() }),
		"a primary with a nil key":           f.config(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{{Fingerprint: c.Primaries[0].Fingerprint}} }),
		"a primary with a wrong fingerprint": f.config(func(c *handoff.Config) {
			p := c.Primaries[0]
			p.Fingerprint = fingerprints(1)[0]
			c.Primaries = []handoff.PrimaryRef{p}
		}),
		"the same primary twice":            f.config(func(c *handoff.Config) { c.Primaries = []handoff.PrimaryRef{c.Primaries[0], c.Primaries[0]} }),
		"a primary created after the clock": late.config(nil),
		"a clock that panics":               f.config(func(c *handoff.Config) { c.Now = func() time.Time { panic("the clock broke") } }),
		"a clock before 1970":               f.config(func(c *handoff.Config) { c.Now = func() time.Time { return time.Unix(-1, 0) } }),
		"no roots":                          f.config(func(c *handoff.Config) { c.Roots = nil }),
		"no clock":                          f.config(func(c *handoff.Config) { c.Now = nil }),
		"a bad capability":                  f.config(func(c *handoff.Config) { c.Delegation.Capability = "certify" }),
		"a capability with an X.509 type": f.config(func(c *handoff.Config) {
			c.Delegation = defaultDelegation()
			c.Delegation.Capability = "sign"
			c.Primaries = nil
		}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := handoff.New(cfg)
			if !errors.Is(err, handoff.ErrConfig) {
				t.Fatalf("New returned %v, want ErrConfig", err)
			}
			if errors.Is(err, handoff.ErrNoPrimaries) {
				t.Errorf("the error matches ErrNoPrimaries: %v", err)
			}
		})
	}
	// A request: a refusal is no error; the errors of the other faults are not it either.
	g := newPGPFixture(t, 2, handoff.StoreSoftware)
	now := 0
	chk := g.checker(func(c *handoff.Config) {
		c.Now = func() time.Time {
			now++
			if now == 1 {
				return testNow
			}
			return testNow.Add(-1000 * 24 * time.Hour)
		}
	})
	_, err := chk.Check(t.Context(), g.request())
	if !errors.Is(err, handoff.ErrConfig) || errors.Is(err, handoff.ErrNoPrimaries) {
		t.Errorf("a primary created after the clock of the call: %v", err)
	}
	// A Checker that New did not make refuses every request with ErrConfig, and says nothing of primaries.
	var zero handoff.Checker
	_, err = zero.Check(t.Context(), g.request())
	if !errors.Is(err, handoff.ErrConfig) || errors.Is(err, handoff.ErrNoPrimaries) {
		t.Errorf("a Checker that New did not make: %v", err)
	}
}

// A text that says "primaries" does not make an error ErrNoPrimaries, and a text that does not say it
// does not stop one from being it.
func TestErrNoPrimariesIsAMatchOfTheValueAndNotOfTheText(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("%w: the checker holds no primaries", handoff.ErrConfig),
		fmt.Errorf("%w: an openpgp-subkey delegation needs primaries", handoff.ErrConfig),
		errors.New("handoff: the checker holds no primaries for this"),
		errors.New(handoff.ErrNoPrimaries.Error()),
	} {
		if errors.Is(err, handoff.ErrNoPrimaries) {
			t.Errorf("%q matches ErrNoPrimaries by its words", err)
		}
	}
	if !errors.Is(fmt.Errorf("%w", handoff.ErrNoPrimaries), handoff.ErrNoPrimaries) {
		t.Error("a wrap of ErrNoPrimaries does not match it")
	}
}
