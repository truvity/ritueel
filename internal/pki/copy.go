package pki

import (
	"bytes"
	"math/big"
	"slices"
)

// The copies that every exported function takes of its parameters.
//
// A parameter that is read more than once (a serial, the bytes of a request or of a name, a key) is
// copied once at the top of the call, and the call works on the copy only, so that one call never
// builds a body from two values of one parameter and a change that the caller makes after the copy
// has no effect. A caller that writes to a parameter while a call runs has a data race of its own,
// which the race detector reports as the caller's; the copy cannot be made atomic against it. The
// package does the most that it can: it takes each copy twice and refuses the call when the two are
// not the same, which catches a write that overlaps the copy (it cannot catch every one: a writer that
// stops half way through a number and stays stopped for the two copies is read as that number).

// A copy never falls back to the object that was given. A key whose copy is not a point on the curve,
// or that is not a P-384 key at all, is refused at the copy, with the words of its fault, and the call
// ends there; after the top of a call nothing reads a parameter of the caller again.

// errChanged is the refusal of a call whose parameter changed while it was copied.
func errChanged() error {
	return fail(ErrParams, "a parameter changed while the call copied it: the caller wrote to it during the call")
}

// copyBytes returns a copy of b that shares nothing with it, or an error when b changed while it was
// copied.
func copyBytes(b []byte) ([]byte, error) {
	c := slices.Clone(b)
	if !bytes.Equal(c, b) {
		return nil, errChanged()
	}
	return c, nil
}

// copySerial returns a copy of a serial that shares nothing with the caller's number (a nil serial
// stays nil, and the check of the serial refuses it), or an error when it changed while it was copied.
func copySerial(n *big.Int) (*big.Int, error) {
	if n == nil {
		return nil, nil
	}
	c := new(big.Int).Set(n)
	if c.Cmp(n) != 0 {
		return nil, errChanged()
	}
	return c, nil
}

// copyRoot copies the parameters of a root that are read more than once. The name and the label are
// strings, and the time is a value.
func copyRoot(p RootParams) (RootParams, error) {
	var err error
	if p.Serial, err = copySerial(p.Serial); err != nil {
		return p, err
	}
	p.Key = keyCopy(p.Key)
	if err := keyRefusal(p.Key); err != nil {
		return p, err
	}
	return p, nil
}

// copyIntermediate copies the parameters of an intermediate that are read more than once. The time
// is a value.
func copyIntermediate(p IntermediateParams) (IntermediateParams, error) {
	var err error
	if p.CSR, err = copyBytes(p.CSR); err != nil {
		return p, err
	}
	if p.IssuerSubject, err = copyBytes(p.IssuerSubject); err != nil {
		return p, err
	}
	if p.Serial, err = copySerial(p.Serial); err != nil {
		return p, err
	}
	p.IssuerKey = keyCopy(p.IssuerKey)
	if err := keyRefusal(p.IssuerKey); err != nil {
		return p, err
	}
	if p.Roots != nil {
		roots := make([]RootRef, len(p.Roots))
		for i, r := range p.Roots {
			if r.Subject, err = copyBytes(r.Subject); err != nil {
				return p, err
			}
			r.Key = keyCopy(r.Key)
			if err := keyRefusal(r.Key); err != nil {
				return p, err
			}
			roots[i] = r
		}
		p.Roots = roots
	}
	return p, nil
}
