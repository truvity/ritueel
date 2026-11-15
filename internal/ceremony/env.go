package ceremony

import (
	"errors"
	"io"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
)

// Env is everything the engine reads from outside. Nothing here reads a global. The zero value
// reads nothing and makes nothing: a plan cannot be made without a clock, and nothing is printed
// without a [Console].
//
// [MakePlan] reads three fields and no other: the clock (Now), the source of the serials (Rand) and
// the description of the program (Self). It prints nothing, so a nil Out is no fault of MakePlan, and
// it never reads In or InIsTerminal. The rule that a nil Console is an error belongs to the part that
// prints a line: where a line must be printed and there is no Console, that part fails.
type Env struct {
	// Now is the clock. The plan takes whole seconds from it, once. A nil clock is an error: a
	// check that cannot run is not a pass.
	Now func() time.Time
	// Rand is the source of the serials; nil means crypto/rand.
	Rand io.Reader
	// Self describes the program that runs; nil means buildinfo.Self.
	Self func() (buildinfo.Program, error)
	// In is standard input, for the typed confirmation. It is not read by the plan.
	In io.Reader
	// InIsTerminal is true only when In is a terminal. A typed confirmation is read only then.
	InIsTerminal bool
	// Out is everything a person reads. A nil Console is an error where a line must be printed,
	// and never io.Discard. MakePlan does not use it.
	Out *Console
}

// errNoClock is the fault of an Env with no clock.
var errNoClock = errors.New("ceremony: there is no clock to take the time of the plan from")

// now reads the clock once and returns the time in UTC, in whole seconds, in the years 1 to 9999.
func (e Env) now() (time.Time, error) {
	if e.Now == nil {
		return time.Time{}, errNoClock
	}
	t, err := safeNow(e.Now)
	if err != nil {
		return time.Time{}, err
	}
	if y := t.Year(); y < 1 || y > 9999 {
		return time.Time{}, errors.New("ceremony: the clock gives a time outside the years 1 to 9999")
	}
	return t, nil
}

// program describes the running program.
func (e Env) program() (buildinfo.Program, error) {
	if e.Self != nil {
		return safeProgram(e.Self)
	}
	return buildinfo.Self()
}

// safeProgram calls self and turns a panic of it into an error.
func safeProgram(self func() (buildinfo.Program, error)) (p buildinfo.Program, err error) {
	defer func() {
		if recover() != nil {
			p, err = buildinfo.Program{}, errors.New("ceremony: the description of the program could not be made")
		}
	}()
	return self()
}

// safeNow reads the clock and turns a panic of it into an error.
func safeNow(now func() time.Time) (t time.Time, err error) {
	defer func() {
		if recover() != nil {
			t, err = time.Time{}, errors.New("ceremony: the clock could not be read")
		}
	}()
	return now().UTC().Truncate(time.Second), nil
}
