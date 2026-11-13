package cli

import (
	"io"
	"strings"
	"time"

	"ritueel.id/ritueel/internal/buildinfo"
)

// Env is everything a run needs from the outside: the three streams, the build information
// and the clock. Nothing in this package reads a global. A nil stream is replaced by an empty
// reader or by io.Discard, and a nil clock by time.Now.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Build  buildinfo.Info
	// Now is the clock; a command that needs the time calls it and reads nothing else.
	Now func() time.Time
}

// withDefaults returns the Env with every nil stream replaced, so that the command line
// library never falls back to the process's own streams.
func (e Env) withDefaults() Env {
	if e.Stdin == nil {
		e.Stdin = strings.NewReader("")
	}
	if e.Stdout == nil {
		e.Stdout = io.Discard
	}
	if e.Stderr == nil {
		e.Stderr = io.Discard
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	return e
}
