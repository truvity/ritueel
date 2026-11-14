// Package kmsreplay answers the read calls of package kms from one recorded file, the *.kms-stub.json files
// of the test vectors (testdata/hand-off/README.md, "The KMS stubs"), instead of calling AWS.
//
// It is for tests and for the vector test only. It is a package of its own so that a reader of package kms
// sees at once that the verifier has no test seam: the verifier asks a kms.Connector, and this is one of
// them. No file of the program imports it, and a test keeps it so. A stub that a user supplies would be a
// copy of the description, the policy or the key, which the contract forbids ("It never accepts a copy ...
// not even one marked unverified"), so nothing here can be reached from a command.
//
// The replay holds no key, opens no connection, reads no file by itself (it is given the bytes) and runs no
// program. It records the calls it was asked for, in order, so that a test can show which calls a verifier
// made and in which order.
package kmsreplay
