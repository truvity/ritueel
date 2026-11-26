package openpgp

import (
	"errors"
	"fmt"
)

var (
	// ErrParams marks a parameter that the builders refuse: a key that is not ECDSA on P-384, a
	// time that is not in whole seconds or is out of order, a user ID, or a part of it, that breaks
	// the rules of the pages, a capability or a reason that is not one of the profile's.
	ErrParams = errors.New("openpgp: refused parameter")
	// ErrRequest marks a subkey packet or a back-signature that cannot be bound: it does not
	// parse, is not the packet of the profile, is too long to embed, or the back-signature does not
	// verify or is one that a strict reader refuses. Every fault of a request is an ErrRequest,
	// also when it is one of the narrower kinds below.
	ErrRequest = errors.New("openpgp: refused request")
	// ErrForm marks a subkey file that is not whole OpenPGP packets, or whose first packet is not
	// one well-formed Public-Subkey packet of the profile. It is also an [ErrRequest].
	ErrForm error = &kindError{"openpgp: the subkey file is not whole packets of the profile", ErrRequest}
	// ErrAlgorithm marks a whole Public-Subkey packet whose key is not a version 4 ECDSA key on
	// P-384. It is also an [ErrRequest].
	ErrAlgorithm error = &kindError{"openpgp: the subkey is not a version 4 ECDSA key on P-384", ErrRequest}
	// ErrBackSignature marks a back-signature that is not exactly the one the contract page gives,
	// or that does not verify. It is also an [ErrRequest].
	ErrBackSignature error = &kindError{"openpgp: the back-signature is refused", ErrRequest}
	// ErrSignature marks a signature that the signer returned and that does not verify, or a
	// finished packet that does not read back as it was built. Nothing is returned with it.
	ErrSignature = errors.New("openpgp: the signature does not verify")
)

// kindError is a named kind of error that is also a kind of another: errors.Is finds both.
type kindError struct {
	msg    string
	parent error
}

func (e *kindError) Error() string { return e.msg }
func (e *kindError) Unwrap() error { return e.parent }

// fail returns an error that wraps kind and says what was wrong.
func fail(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}

// The faults of an answer: the files that come back from a ceremony, which the requester reads
// (docs/reference/hand-off-contract.md, "What comes back"). Each is an [ErrAnswer], so that a caller
// that wants "the answer is faulty" has one kind to ask for, as [ErrRequest] is for a request.
var (
	// ErrAnswer is the kind of every fault of an answer.
	ErrAnswer = errors.New("openpgp: refused answer")
	// ErrBoundFile marks a bound file that is not exactly two whole packets: a Public-Subkey packet,
	// then one Signature packet. It is also an [ErrAnswer].
	ErrBoundFile error = &kindError{"openpgp: the bound file is not a subkey packet and a signature packet", ErrAnswer}
	// ErrBinding marks a signature that is not a version 4 type 0x18 signature with ECDSA and SHA-384
	// by the named primary over that primary and that subkey, or that does not verify. It is also an
	// [ErrAnswer].
	ErrBinding error = &kindError{"openpgp: the subkey binding is refused", ErrAnswer}
	// ErrBindingShape marks a binding whose signature verified and whose subpackets are not the set
	// of the page. It is returned only after the signature verified, so it says that the issuer is
	// right and the profile is not. It is an [ErrAnswer] and not an [ErrBinding].
	ErrBindingShape error = &kindError{"openpgp: the subkey binding has not the subpackets of the page", ErrAnswer}
)

// The faults of the keyring file of a trust set, first form (docs/reference/keyring-package.md,
// "The first form of the keyring file"). Each is an [ErrKeyring], so that a caller that wants "the
// keyring file is refused" has one kind to ask for.
var (
	// ErrKeyring is the kind of every refusal of a keyring file. It wraps nothing, and it is not
	// an [ErrParams]: a refusal of the arguments of [ReadKeyring] is an ErrParams.
	ErrKeyring = errors.New("openpgp: refused keyring file")
	// ErrKeyringForm marks bytes that are not certificates of the first form: a file that is too
	// large or empty, armoured or not whole packets, a packet that the first form does not have, a
	// key that is not a version 4 ECDSA key on P-384, a user ID that is not the one shape of the
	// page, a certification that is not the self-signature of the page or does not verify, or a mix
	// of test and real primaries. It is also an [ErrKeyring].
	ErrKeyringForm error = &kindError{"openpgp: the keyring file is not certificates of the first form", ErrKeyring}
	// ErrKeyringPrimaries marks a file of the first form whose certificates are not the primaries
	// of the root list: one is missing, one is too many, one is not on the list, one stands at
	// another place, one repeats, or a user ID names another label than its entry. It is also an
	// [ErrKeyring].
	ErrKeyringPrimaries error = &kindError{"openpgp: the keyring file does not hold the primaries of the root list", ErrKeyring}
)

// The faults of the readers of stored OpenPGP material (docs/reference/revocation-material.md, "What
// is made"): a certificate that is split, a file that holds one signature, a revocation signature
// that is read and verified.
var (
	// ErrCertificateForm marks bytes that [SplitCertificate] refuses: not one Public-Key packet, one
	// User ID packet and one to [MaxCertifications] Signature packets, whole, in that order and
	// nothing else, or longer than [MaxKeyringBytes].
	ErrCertificateForm = errors.New("openpgp: the certificate is not of the first form")
	// ErrSignatureFile marks a file that [ReadSignatureFile] refuses: not the binary packet of one
	// signature and not exactly one armour block of one, or longer than [MaxSignatureFileBytes].
	ErrSignatureFile = errors.New("openpgp: the file is not one signature packet")
	// ErrRevocation marks a packet that [ReadRevocation] or [RevocationIssuer] refuses: it is not the
	// key revocation signature that [RevocationSignature] writes, or it does not verify with the
	// primary that it is given.
	ErrRevocation = errors.New("openpgp: refused revocation signature")
	// ErrRevocationReason marks a revocation signature whose reason for revocation subpacket is
	// missing, or whose code and word are not one of the four of the profile. It is also an
	// [ErrRevocation].
	ErrRevocationReason error = &kindError{"openpgp: the reason for revocation is refused", ErrRevocation}
)

// The faults of the reader of a key that ritueel did not make (docs/decisions/0008-a-persons-own-key.md,
// rule 5): [ReadForeignKey] reads the file of one exported secret key, and [ForeignKey.OpenSecret]
// opens the secret of its primary. Each fault of the file is an [ErrForeignKey], so that a caller that
// wants "this file is refused" has one kind to ask for; the narrower kinds say why, and the text of an
// error says which case of that kind it is. No text holds a byte of the file, a user ID or a secret.
var (
	// ErrForeignKey is the kind of every refusal of the file of a foreign key. It is not an
	// [ErrParams]: a refusal of the arguments of [ForeignKey.OpenSecret] is an ErrParams.
	ErrForeignKey = errors.New("openpgp: refused foreign key")
	// ErrForeignForm marks a file that is not the packets of one transferable key: not whole packets,
	// a length form that is not read (a partial length, an indeterminate length), a packet or a key
	// that does not read to its end, an order that RFC 9580 section 10.1 does not allow, or an empty
	// file. It is also an [ErrForeignKey].
	ErrForeignForm error = &kindError{"openpgp: the file is not the packets of one transferable key", ErrForeignKey}
	// ErrForeignLimit marks a file that passes a named limit of the reader: [MaxForeignKeyBytes],
	// [MaxForeignPackets], [MaxForeignUserIDs], [MaxForeignUserIDBytes], [MaxForeignSubkeys],
	// [MaxForeignSignatures], [MaxForeignClaimedSignatures] or [MaxForeignPacketBytes]. The text names the
	// constant. It is also an [ErrForeignKey].
	ErrForeignLimit error = &kindError{"openpgp: the file passes a limit of the reader", ErrForeignKey}
	// ErrForeignArmour marks an armoured file that is not exactly one block of type PGP PRIVATE KEY
	// BLOCK: another type (a public key block, a message, a signature), a second block, a header or a
	// line that the form does not allow, text after the end line, or a CRC-24 line that is wrong. It
	// is also an [ErrForeignKey].
	ErrForeignArmour error = &kindError{"openpgp: the file is not one armour block of a private key", ErrForeignKey}
	// ErrForeignPacket marks a packet that does not belong in a transferable key: a message, an
	// encrypted or compressed packet, a signature of the message kind, a padding or any other tag
	// that RFC 9580 section 10.1 does not list. The text names the tag. It is also an [ErrForeignKey].
	ErrForeignPacket error = &kindError{"openpgp: the file holds a packet that does not belong in a transferable key", ErrForeignKey}
	// ErrForeignPrimaries marks a file that holds a second primary key. It is also an
	// [ErrForeignKey].
	ErrForeignPrimaries error = &kindError{"openpgp: the file holds more than one primary key", ErrForeignKey}
	// ErrForeignVersion marks a primary key or a subkey that is not version 4: version 3, 5 and 6
	// each have a reason of their own. It is also an [ErrForeignKey].
	ErrForeignVersion error = &kindError{"openpgp: the key is not a version 4 key", ErrForeignKey}
	// ErrForeignAlgorithm marks a primary key that is not RSA with a 4096-bit modulus, EdDSA on
	// Ed25519 or ECDSA on P-384, and a subkey whose secret packet has a public part that the reader
	// cannot delimit. The text names the algorithm and its size or curve. It is also an
	// [ErrForeignKey].
	ErrForeignAlgorithm error = &kindError{"openpgp: the algorithm of the key is not one that is read", ErrForeignKey}
	// ErrForeignNoSecret marks a file that does not hold the secret of the primary key: a public key
	// packet, or the GNU extension that gpg writes when the secret is kept elsewhere (a dummy) or on a
	// card. The text says which, and never holds a card serial number. It is also an [ErrForeignKey].
	ErrForeignNoSecret error = &kindError{"openpgp: the file does not hold the secret of the primary key", ErrForeignKey}
	// ErrForeignProtection marks a primary key whose secret is protected in a form that is not read:
	// S2K usage 255, 253 or a cipher number, a cipher other than AES, an S2K that is not iterated and
	// salted, Argon2, or a hash that the reader has not. Each has a text of its own. It is also an
	// [ErrForeignKey].
	ErrForeignProtection error = &kindError{"openpgp: the secret of the primary key is protected in a form that is not read", ErrForeignKey}
	// ErrForeignSelfSignature marks a key none of whose user IDs has a valid self-signature: there is
	// no user ID, or every self-signature is made with a hash that does not count (MD5, RIPEMD-160), carries
	// a critical subpacket that is not understood, or does not verify. It is also an [ErrForeignKey].
	ErrForeignSelfSignature error = &kindError{"openpgp: no user ID has a valid self-signature", ErrForeignKey}
	// ErrForeignSubkey marks a file with a secret subkey (a secret key packet, with a secret or as a stub)
	// that no binding signature of the primary confirms: none verifies over the public part that the
	// packet's own length fields cut out, with SHA-1 or a stronger hash. It is also an [ErrForeignKey].
	ErrForeignSubkey error = &kindError{"openpgp: the file holds a secret subkey that no signature of the primary confirms", ErrForeignKey}
	// ErrForeignSecret marks a secret that opened and is not a good secret: its checksum is wrong, its
	// numbers do not read to their end, or it is not the secret of the public key in the same packet.
	// It is also an [ErrForeignKey].
	ErrForeignSecret error = &kindError{"openpgp: the secret of the primary key is damaged or is not the secret of its public key", ErrForeignKey}
	// ErrWrongPassphrase marks a passphrase that does not open the protected secret of the primary
	// key: the SHA-1 check of the standard (RFC 9580 section 5.5.3) failed. It is not an
	// [ErrForeignKey]. The standard gives no way to tell a wrong passphrase from a damaged ciphertext,
	// since both fail the same check: a damaged framing is an ErrForeignForm when the file is read,
	// and a damaged armour is an ErrForeignArmour.
	ErrWrongPassphrase = errors.New("openpgp: the passphrase does not open the secret key")
)
