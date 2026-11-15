// Package ceremonytest makes bundles for tests: a bundle of a software test root, with the first
// ceremony of it stopped at a named step, so that a test of a reader of the history (status, close,
// join, the check of the history) has the files that a stopped or a finished ceremony leaves,
// without the command apply.
//
// # Test support only
//
// The package is Go source that is not a _test.go file, so that the tests of other packages can
// import it, and only tests import it: it takes a testing.TB, it fails the test on any error, and
// no file of the program may import it (a test of the package scans the imports of the non-test
// files of the module). It never starts a program, reads no clock but the one it is given, asks
// no card, and talks to no cloud account. The keys are software test keys that a software store
// makes in a key folder that lies outside the bundle.
//
// A test that imports this package from a package that it is itself imported by (internal/history,
// internal/ceremony) is in an external test package (history_test, ceremony_test): this package
// imports both.
//
// # How a ceremony is made
//
// A bundle is made as a person makes one: bundle.Create with a test root, and the OpenPGP root
// file removed. The ceremony then runs with the exported pieces of internal/ceremony, in the order
// of record 0005, rules 10 to 12: the plan and the copies of the wanted files, the attempt and the
// two journals, the births, the fingerprints, the signatures, the end of the journals, the
// transcript, the artifacts (the root.json of each key, then the trust set), and the record. It
// stops where [Step] says and leaves what that step leaves; nothing is deleted.
//
// The clock, the source of the serials and the description of the program are fixed, so two calls
// with equal [Options] write the same bytes into plan.json and into the copies under wanted/. The
// keys differ between two calls, and so do the pins, the journals, the root list and the record.
package ceremonytest
