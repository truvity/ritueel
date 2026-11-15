//go:build !unix

package main

// ignoreBrokenPipe does nothing where there is no signal for a broken pipe.
func ignoreBrokenPipe() {}
