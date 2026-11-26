// Package port answers [keystore.Key] from the key port of atoom, a shared library
// (record 0012, rule 1): a key whose private half stays in a key store, which a ceremony reaches through
// the generated client of the port. The package knows no driver and opens no store: the caller gives it
// the client, with the driver linked in the process (internal/keystore/atoomsoftware) or, later, another
// way.
//
// A key is the key of one purpose, a name that the caller declared to the driver with its algorithm. Here
// the algorithm is ES384, ECDSA over P-384 with SHA-384, the algorithm of a root key (record 0002,
// rule 14). The signer is the Signer of atoom (key/signer), which checks every signature with the
// public key before it returns it and refuses an answer from another key than the one it saw.
//
// What a key says about its store, the kind and whether it can be copied, comes from what the store says
// about itself (Capabilities) through one table in this package, [Describe]. A store that the table does
// not hold is refused: a new kind of store is added to the table together with its first caller.
//
// [Birth] is the one way that a key is made here: the key must be absent, the store must say that it made
// the key, the public key must read back as the one that was made, and a signature must verify.
package port
