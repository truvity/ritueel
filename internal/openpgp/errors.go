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
