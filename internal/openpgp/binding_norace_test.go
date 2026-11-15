//go:build !race

package openpgp

// raceEnabled is true when the tests are built with the race detector, under which the number of
// allocations of a call is not the number of the same call without it.
const raceEnabled = false
