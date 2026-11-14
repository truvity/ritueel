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
	// verify or is one that a strict reader refuses.
	ErrRequest = errors.New("openpgp: refused request")
	// ErrSignature marks a signature that the signer returned and that does not verify, or a
	// finished packet that does not read back as it was built. Nothing is returned with it.
	ErrSignature = errors.New("openpgp: the signature does not verify")
)

// fail returns an error that wraps kind and says what was wrong.
func fail(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}
