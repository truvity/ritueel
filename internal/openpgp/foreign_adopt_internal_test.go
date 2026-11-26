package openpgp

import (
	"bytes"
	"errors"
	"testing"
)

// mpiOf writes a number of n bytes, all 0xFF, as a multiprecision integer.
func mpiOf(n int) []byte {
	return append([]byte{byte(n * 8 >> 8), byte(n * 8)}, bytes.Repeat([]byte{0xFF}, n)...)
}

func TestCanonicalRSANumbersHasItsOwnSizeGuard(t *testing.T) {
	small := []byte{0, 3, 5}
	for name, nums := range map[string][][]byte{
		"d over the bound": {mpiOf(maxRSASecretNumber + 1), small, small, small},
		"p over the bound": {small, mpiOf(maxRSASecretNumber + 1), small, small},
		"q over the bound": {small, small, mpiOf(maxRSASecretNumber + 1), small},
		"u over the bound": {small, small, small, mpiOf(maxRSASecretNumber + 1)},
	} {
		out, err := canonicalRSANumbers(bytes.Join(nums, nil))
		if !errors.Is(err, ErrForeignSecret) || out != nil {
			t.Errorf("%s: %v, want ErrForeignSecret and no numbers", name, err)
		}
	}
	// the output of the swap never grows past its first capacity: numbers at the bound fit
	p := mpiOf(maxRSASecretNumber)
	q := []byte{0, 7, 0x65} // a small q below p: p, q need not be primes for the guard
	_, err := canonicalRSANumbers(bytes.Join([][]byte{mpiOf(maxRSASecretNumber), p, q, {0, 1, 1}}, nil))
	if err != nil && !errors.Is(err, ErrForeignSecret) {
		t.Errorf("numbers at the bound: %v", err)
	}
}
