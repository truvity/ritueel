// Package openpgp builds the OpenPGP packets of the bundle profiles: the public certificate of a
// root key's primary with its self-signature, a later self-signature that extends it, a key
// revocation signature, and the binding of a subkey that a requester asked for. It reads
// docs/reference/bundle.md ("The OpenPGP primary"), docs/reference/revocation-material.md
// ("What is made") and docs/reference/hand-off-contract.md ("OpenPGP subkey"), and record 0009,
// rules 1, 2, 4 and 8.
//
// The key is a [crypto.Signer], so a card or a cloud key plugs in where a software key does. The
// signer is given the SHA-384 digest of the signed data and nothing else (crypto.SHA384), and
// returns an ASN.1 ECDSA signature; the package puts it in the packet.
//
// The packets of a key and the reading back of a finished signature use
// github.com/ProtonMail/go-crypto (record 0010, rule 20). Its signing path is not used: it writes
// the hashed subpackets in its own order and marks the creation time and the key flags critical,
// and it cannot put the issuer key ID in the unhashed area, which the profile and the test vectors
// have (the hand-off contract, "Issuer key ID"). So this package writes each signature packet
// whole: it builds both subpacket areas, hashes the data as RFC 9580 section 5.2.4 says, has the
// signer sign the digest and writes the packet. Before it returns bytes it reads the packet back
// with go-crypto and verifies the signature with the public key, so no signature that does not
// verify, and no packet that another reader does not read as built, is ever returned.
//
// The package also reads a subkey request, the file `<stem>.subkey.pgp` of the hand-off: it splits
// the file into packets ([SplitSubkeyFile]), reads the Public-Subkey packet ([ReadSubkey]), makes
// the key of a primary ([NewPrimaryKey]) and checks one back-signature ([VerifyBackSignature]).
// BindSubkey uses the same functions, so a request that passes these checks is a request that the
// ceremony binds. The faults of a request are [ErrForm], [ErrAlgorithm] and [ErrBackSignature],
// each of them also an [ErrRequest]. The reader opens no file and starts no program.
//
// It reads an answer in the same way: it splits the file `<stem>.bound.pgp` into its two packets
// ([SplitBoundFile]), reads the issuer of the binding ([BindingIssuer]) and verifies the binding of
// a subkey by a primary ([VerifyBinding]), with the subpackets of the page and no other, so that
// a binding that BindSubkey returns is a binding that the requester accepts, and no other. The
// faults of an answer are [ErrBoundFile], [ErrBinding] and [ErrBindingShape], each of them also an
// [ErrAnswer].
//
// A user ID has the one shape of the page, and each part of it follows the rule of its key in
// ritueel.yaml, so that no text of a caller can add a character that a person cannot read or an
// address that the user ID does not show.
//
// Every function returns no bytes when it returns an error. Times are whole seconds between 1970
// and 2106; a time with a fraction of a second is an error, never rounded. Every signature carries
// the Issuer Fingerprint subpacket (hashed) and the Issuer Key ID subpacket (unhashed).
package openpgp
