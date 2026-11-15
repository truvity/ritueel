//go:build !race

package trustset

// raceEnabled is true when the tests run under the race detector, which allocates for its own
// bookkeeping, so the number of allocations of a call is not stable.
const raceEnabled = false
