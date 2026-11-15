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
