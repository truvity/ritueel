package pki

import (
	"crypto/rand"
	"io"
	"math/big"
)

const (
	// serialBytes is the number of random octets that NewSerial reads.
	serialBytes = 20
	// maxSerialBits is the longest serial that fits in 20 octets of DER: the encoding of a
	// positive number of n bits has (n+8)/8 octets, a zero octet in front when the high bit of the
	// first is set (RFC 5280, section 4.1.2.2).
	maxSerialBits = 159
	// minSerialBits is the fewest bits a serial may have: a number shorter than 64 bits cannot
	// hold 64 random bits.
	minSerialBits = 64
)

// NewSerial returns a certificate serial number: positive, at most 20 octets in DER, with at
// least 64 random bits (the profile of the root and of the intermediate). It reads 20 octets
// from r, or from crypto/rand when r is nil, and clears the top bit so that the number is
// positive and fits, which leaves 159 random bits. A reader that fails or returns fewer octets is
// an error, and so is a reader that gives a number shorter than 64 bits, such as one that only
// gives zeros. A reader that is a nil pointer inside the interface (a typed nil, which is not equal
// to nil and would panic or read nothing) is an error too, and is not taken for "use crypto/rand".
// Production code passes nil. The error wraps [ErrParams].
//
// A reader that gives the same octets every time, or a counter, gives numbers that pass the
// length checks; that is the caller's to avoid. Nothing here can tell it from chance.
func NewSerial(r io.Reader) (*big.Int, error) {
	if r == nil {
		r = rand.Reader
	} else if isNil(r) {
		return nil, fail(ErrParams, "the source of random numbers is a nil value")
	}
	buf := make([]byte, serialBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, failWith(ErrParams, "the source of random numbers failed", err)
	}
	buf[0] &= 0x7f
	n := new(big.Int).SetBytes(buf)
	if err := CheckSerial(n); err != nil {
		return nil, fail(ErrParams, "the source of random numbers gave a number with fewer than %d bits", minSerialBits)
	}
	return n, nil
}

// CheckSerial returns nil when n is a serial of the profile: positive, at most 20 octets in
// DER, and at least 64 bits long (so that it can hold 64 random bits). The error wraps
// [ErrParams]. The builders call it on the serial they are given. The number is copied before it is
// read more than once.
func CheckSerial(n *big.Int) error {
	n, err := copySerial(n) // one reading of the caller's number; the checks below read the copy
	if err != nil {
		return err
	}
	switch {
	case n == nil:
		return fail(ErrParams, "no serial number")
	case n.Sign() <= 0:
		return fail(ErrParams, "the serial number is not positive")
	case n.BitLen() > maxSerialBits:
		return fail(ErrParams, "the serial number is longer than 20 octets")
	case n.BitLen() < minSerialBits:
		return fail(ErrParams, "the serial number is shorter than 64 bits")
	}
	return nil
}
