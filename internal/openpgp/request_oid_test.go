package openpgp_test

import (
	"bytes"
	"errors"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

// The length 0xFF of a curve identifier is reserved: a packet that has it is not a key of the profile, and it is
// a fault of the form and not of the algorithm, also when the body is long enough to hold 255 bytes of
// identifier. The check on the length of the body alone does not tell this case from a short body.
func TestReadSubkeyRefusesTheReservedIdentifierLengthAsAFormWhateverTheLengthOfTheBody(t *testing.T) {
	body := subkeyBody(t)
	for _, n := range []int{len(body), 262, 300, 1000} {
		long := bodyWith(body, setByte(6, 0xFF))
		for len(long) < n {
			long = append(long, 0xA5)
		}
		sub, err := openpgp.ReadSubkey(wrap(tagSubkey, long))
		if sub != nil {
			t.Errorf("a body of %d bytes: a Subkey came back with the error", n)
		}
		if !isRequestError(err, openpgp.ErrForm) || errors.Is(err, openpgp.ErrAlgorithm) {
			t.Errorf("a body of %d bytes: error = %v, want an ErrForm and not an ErrAlgorithm", n, err)
		}
	}
	// A length of 254 that fits the body is an identifier that is not the curve: an algorithm.
	long := append(bodyWith(body, setByte(6, 254)), bytes.Repeat([]byte{0xA5}, 300)...)
	if _, err := openpgp.ReadSubkey(wrap(tagSubkey, long)); !isRequestError(err, openpgp.ErrAlgorithm) {
		t.Errorf("an identifier of 254 bytes: error = %v, want an ErrAlgorithm", err)
	}
}
