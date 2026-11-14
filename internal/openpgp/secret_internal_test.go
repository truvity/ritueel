package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// The multiprecision integer of RFC 9580, section 3.2, written by hand with a big number as the
// oracle: two bytes of bit length, then the bytes without leading zeros.
func mpiByNumber(d []byte) []byte {
	v := new(big.Int).SetBytes(d)
	return append([]byte{byte(v.BitLen() >> 8), byte(v.BitLen())}, v.Bytes()...)
}

func TestSecretMPIIsTheMultiprecisionIntegerOfTheScalarWithNoLeadingZeroByte(t *testing.T) {
	full := bytes.Repeat([]byte{0xFF}, secretScalarLen)
	cases := map[string][]byte{
		"one":                      append(make([]byte, secretScalarLen-1), 1),
		"two":                      append(make([]byte, secretScalarLen-1), 2),
		"0x80 in the last byte":    append(make([]byte, secretScalarLen-1), 0x80),
		"0x0100":                   append(make([]byte, secretScalarLen-2), 1, 0),
		"all ones":                 full,
		"the top bit alone":        append([]byte{0x80}, make([]byte, secretScalarLen-1)...),
		"the second bit alone":     append([]byte{0x40}, make([]byte, secretScalarLen-1)...),
		"one leading zero byte":    append([]byte{0, 0x01}, bytes.Repeat([]byte{0xAB}, secretScalarLen-2)...),
		"two leading zero bytes":   append([]byte{0, 0, 0x7F}, bytes.Repeat([]byte{0xCD}, secretScalarLen-3)...),
		"a zero byte inside":       append([]byte{0x12, 0, 0, 0x34}, bytes.Repeat([]byte{0}, secretScalarLen-4)...),
		"a zero byte at the end":   append(bytes.Repeat([]byte{0x55}, secretScalarLen-1), 0),
		"zeros then a low bit set": append(make([]byte, 10), bytes.Repeat([]byte{0x01}, secretScalarLen-10)...),
	}
	for name, d := range cases {
		before := bytes.Clone(d)
		got := secretMPI(d)
		if want := mpiByNumber(d); !bytes.Equal(got, want) {
			t.Errorf("%s: got % x, want % x", name, got, want)
		}
		if !bytes.Equal(d, before) {
			t.Errorf("%s: the input was changed", name)
		}
		// The result is a buffer of its own: clearing it leaves the input as it was.
		clear(got)
		if !bytes.Equal(d, before) {
			t.Errorf("%s: the result shares memory with the input", name)
		}
		// The checksum of the page is the sum of the bytes of this integer.
		if len(got) > 2+secretScalarLen {
			t.Errorf("%s: %d bytes", name, len(got))
		}
	}
}

func TestSecretMPIOfRandomScalarsAndOfEveryBitLength(t *testing.T) {
	for i := 0; i < 500; i++ {
		d := make([]byte, secretScalarLen)
		if _, err := rand.Read(d); err != nil {
			t.Fatal(err)
		}
		// Make the top i%48 bytes zero, so that every length of the integer is tried.
		clear(d[:i%secretScalarLen])
		if got, want := secretMPI(d), mpiByNumber(d); !bytes.Equal(got, want) {
			t.Fatalf("d = %x: got % x, want % x", d, got, want)
		}
	}
	for bits := 1; bits <= 8*secretScalarLen; bits++ {
		v := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		d := v.FillBytes(make([]byte, secretScalarLen))
		got := secretMPI(d)
		if n := int(got[0])<<8 | int(got[1]); n != bits {
			t.Fatalf("a scalar of %d bits has the length field %d", bits, n)
		}
		if !bytes.Equal(got, mpiByNumber(d)) {
			t.Fatalf("a scalar of %d bits: got % x", bits, got)
		}
	}
}

// Zero is not a scalar, and the caller never asks for it; the function still gives the integer
// of zero (length 0, no bytes) and does not panic on a short or empty input.
func TestSecretMPIOfZeroAndOfAShortInputDoesNotPanic(t *testing.T) {
	for _, d := range [][]byte{nil, {}, {0}, make([]byte, secretScalarLen), {1}, {0, 0, 5}} {
		if got, want := secretMPI(d), mpiByNumber(d); !bytes.Equal(got, want) {
			t.Errorf("%x: got % x, want % x", d, got, want)
		}
	}
}

func FuzzSecretMPI(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1})
	f.Add(bytes.Repeat([]byte{0xFF}, secretScalarLen))
	f.Add(append([]byte{0, 0, 0x80}, make([]byte, 45)...))
	f.Fuzz(func(t *testing.T, d []byte) {
		before := bytes.Clone(d)
		got := secretMPI(d)
		if want := mpiByNumber(d); !bytes.Equal(got, want) {
			t.Fatalf("got % x, want % x", got, want)
		}
		if !bytes.Equal(d, before) {
			t.Fatal("the input was changed")
		}
	})
}

func TestWipePrivateSetsTheNumberOfAKeyThatThisPackageMadeToZero(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	//nolint:staticcheck // the test looks at the deprecated number on purpose
	words := k.D.Bits()
	if len(words) == 0 {
		t.Fatal("no words")
	}
	nonzero := false
	for _, w := range words {
		nonzero = nonzero || w != 0
	}
	if !nonzero {
		t.Fatal("the scalar is zero before the call")
	}
	wipePrivate(k)
	for i, w := range words {
		if w != 0 {
			t.Errorf("word %d is not cleared", i)
		}
	}
	//nolint:staticcheck // the deprecated number
	if k.D.Sign() != 0 || k.D.BitLen() != 0 {
		t.Error("the number is not zero")
	}
}

func TestWipePrivateOfNothingDoesNothingAndDoesNotPanic(t *testing.T) {
	wipePrivate(nil)
	wipePrivate(&ecdsa.PrivateKey{})
	wipePrivate(&ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P384()}})
}

// Bytes hands out the scalar that the key keeps for itself. privateBytes must give a buffer of its
// own: clearing it leaves what the key gives out unchanged, and the key still signs.
func TestPrivateBytesGivesABufferOfItsOwn(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	held, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(held)
	got, err := privateBytes(k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("not the scalar")
	}
	clear(got)
	if !bytes.Equal(held, want) {
		t.Error("clearing the result cleared the bytes that the key keeps")
	}
	again, err := k.Bytes()
	if err != nil || !bytes.Equal(again, want) {
		t.Errorf("the key's own scalar changed: %v", err)
	}
	// A key with no scalar is an error, not a panic.
	for name, bad := range map[string]*ecdsa.PrivateKey{
		"nil":       nil,
		"empty":     {},
		"no scalar": {PublicKey: ecdsa.PublicKey{Curve: elliptic.P384()}},
	} {
		if raw, err := privateBytes(bad); err == nil || raw != nil {
			t.Errorf("%s: %x %v", name, raw, err)
		}
	}
}
