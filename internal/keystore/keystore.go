// Package keystore says what a ceremony asks of a private key, whatever key store holds it: the
// key signs through [crypto.Signer], tells its public key and where it lives, and says whether it
// can be copied. It never gives its private half.
//
// The interface is small on purpose. A ceremony's keys come from one implementation, the key port of
// atom (internal/keystore/port); the card and cloud key stores are further drivers behind the same
// port, and what they all need to create or open a key is added when the second one is built, not
// guessed here from one. internal/keystore/software also implements it, for the in-memory keys of tests.
package keystore

import "crypto"

// Kind is where a key lives: the member `store` of root.json and of a hand-off proof.
type Kind string

// KindSoftware is a key in memory that a key file holds between ceremonies. The other kinds are
// added by the packages that build their key stores.
const KindSoftware Kind = "software"

// WarningSoftwareCopyable is the code that a ceremony record carries for a key that can be copied
// (record 0002, rule 7; record 0005, rule 27).
const WarningSoftwareCopyable = "software-copyable"

// Key is one private key held by a key store. It signs and tells its public key; it never gives
// its private half. Sign takes the SHA-384 digest of what is signed (crypto.SHA384) and returns an
// ASN.1 ECDSA value; the key is on P-384 (record 0002, rule 14).
type Key interface {
	// Signer is Public and Sign, which is what internal/pki and internal/openpgp take.
	crypto.Signer
	// Kind is where the key lives.
	Kind() Kind
	// Copyable is true when the key can be copied: true for every software key.
	Copyable() bool
	// Warnings are the codes for the ceremony record, for a software key
	// [WarningSoftwareCopyable].
	Warnings() []string
	// Close ends the use of the key: after Close the key does not sign, and a second Close does
	// nothing.
	Close() error
}
