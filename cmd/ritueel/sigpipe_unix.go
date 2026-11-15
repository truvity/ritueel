//go:build unix

package main

import (
	"os/signal"
	"syscall"
)

// ignoreBrokenPipe makes a write to a pipe whose reader has closed return an error. Without it the Go
// runtime ends a program at once when a write to standard output or standard error meets a closed pipe,
// so a ceremony that is running could die between two of its steps with no line to say where. With it
// the write fails, the console of the ceremony sees the failure (no signature is made before the
// fingerprints were shown), and the stop line goes to the stream that still takes it.
func ignoreBrokenPipe() { signal.Ignore(syscall.SIGPIPE) }
