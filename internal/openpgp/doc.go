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
// It reads the keyring file of a trust set in its first form ([ReadKeyring]): the public
// certificates of the primaries, in the order of the root list, each held to the fingerprint of its
// entry. A certification that [NewPrimary] or [ExtendPrimary] returns is checked by the same
// function that the reader uses, so the builder returns a certificate that the reader accepts, and
// no other. The faults of that file are [ErrKeyringForm] and [ErrKeyringPrimaries], each of them
// also an [ErrKeyring].
//
// It reads the material that a software root keeps apart from its bundle: it splits one public
// certificate into its packets ([SplitCertificate]), reads a stored file of one signature, binary or
// one armour block ([ReadSignatureFile]), names the issuer of a revocation signature
// ([RevocationIssuer]) and reads a revocation signature with the primary that made it
// ([ReadRevocation]), which accepts exactly what [RevocationSignature] writes and verifies it, with
// the reason, the creation time and the SHA-256 of the packet that the bundle keeps. The faults are
// [ErrCertificateForm], [ErrSignatureFile], [ErrRevocation] and [ErrRevocationReason] (also an
// ErrRevocation). The readers open no file, read no clock and start no program.
//
// It reads a key that ritueel did not make, for the adoption of a person's own primary (record 0008,
// rule 5): [ReadForeignKey] reads the file of one exported secret key, binary or one armour block, and
// tells what it holds without a passphrase: the primary, each user ID with its self-signatures, each
// subkey with its form (public, stub or with a secret) and its binding, the direct-key signatures and
// revocations, and the counts of what is left out. [ForeignKey.Certificate] is not the packets of the
// file: it is assembled by the reader from what the primary's own signatures verify, with every packet
// written by the reader and the unhashed area of every signature rebuilt, so that an edited file cannot
// make it carry a byte that the primary did not sign (except within a signature's own value). The
// certifications of other people, user IDs and subkeys that no signature of the primary confirms, and
// signatures that do not verify are left out and counted. [ForeignKey.OpenSecret] opens the secret of
// the primary only, with the passphrase of the file, and returns a standard-library private key behind a
// signer ([ForeignSecret]). The secret of a subkey is never decrypted or kept. Unlike [ParseSecretKey]
// and [ReadKeyring], which guard the keys that ritueel makes and stay narrow, this reader takes the
// shapes of a long-lived key (many user IDs, subkeys, signatures), each held to a named limit, and
// refuses a malformed file by name: the faults are an [ErrForeignKey] with narrower kinds, and a wrong
// passphrase is an [ErrWrongPassphrase]. It uses go-crypto to read public keys and to verify signatures;
// it reads the framing, the armour, the S2K and the secret numbers itself, so that every buffer that held
// the passphrase or the secret is one that it clears. The reader opens no file, reads no clock and
// starts no program.
//
// A user ID has the one shape of the page, and each part of it follows the rule of its key in
// ritueel.yaml, so that no text of a caller can add a character that a person cannot read or an
// address that the user ID does not show.
//
// Every function returns no bytes when it returns an error. Times are whole seconds between 1970
// and 2106; a time with a fraction of a second is an error, never rounded. Every signature carries
// the Issuer Fingerprint subpacket (hashed) and the Issuer Key ID subpacket (unhashed).
package openpgp
