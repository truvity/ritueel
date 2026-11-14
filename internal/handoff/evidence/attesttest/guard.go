package attesttest

import "testing"

// init stops a program that is not a test binary. This package builds attestation chains with keys that
// are made in memory, and shipped code must never link it. The repository keeps its test support in
// _test.go files, which a build of the program cannot import; a package that several test packages
// share cannot be one, so the guard is a failure at the start: a program that imports this package
// panics before main runs, and the test of a package that imports it still runs.
func init() {
	if !testing.Testing() {
		panic("attesttest: this package is test support and is linked into a program that is not a test binary")
	}
}
