package cli

import (
	"io"
	"strings"

	"ritueel.id/ritueel/internal/buildinfo"
)

// Env is everything a run needs from the outside: the three streams and the build
// information. Nothing in this package reads a global. A nil stream is replaced by an empty
// reader or by io.Discard.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Build  buildinfo.Info
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
	return e
}
