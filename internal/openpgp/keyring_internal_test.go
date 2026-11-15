package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

// readKeyBody holds the key packet of a keyring file to what the first form allows: a version 4
// ECDSA key on P-384 with its point on the curve, and nothing after it. The reader of the keyring
// file leans on it, and on go-crypto, which reads the packet a second time.

func TestTheBodyOfAKeyPacketIsReadOnlyInTheFormThatKeyBodyWrites(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1767225600, 0).UTC()
	good := keyBody(at, pt)
	gotAt, gotPt, err := readKeyBody(good)
	if err != nil || !gotAt.Equal(at) || !bytes.Equal(gotPt, pt) {
		t.Fatalf("readKeyBody(good) = %v, % x, %v", gotAt, gotPt[:4], err)
	}
	edit := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(good)) }
	offCurve := edit(func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b })
	cases := []struct {
		name string
		body []byte
	}{
		{"version 3", edit(func(b []byte) []byte { b[0] = 3; return b })},
		{"version 5", edit(func(b []byte) []byte { b[0] = 5; return b })},
		{"version 6", edit(func(b []byte) []byte { b[0] = 6; return b })},
		{"an algorithm that is not ECDSA", edit(func(b []byte) []byte { b[5] = 18; return b })},
		{"RSA", edit(func(b []byte) []byte { b[5] = 1; return b })},
		{"the curve identifier of P-521", edit(func(b []byte) []byte { b[11] = 0x23; return b })},
		{"the curve identifier of P-256", edit(func(b []byte) []byte { b[9] = 0x07; return b })},
		{"a curve identifier one byte shorter", edit(func(b []byte) []byte { b[6] = 4; return b })},
		{"a point that is not on the curve", offCurve},
		{"the number of bits of the point changed", edit(func(b []byte) []byte { b[13]++; return b })},
		{"a byte after the point", append(bytes.Clone(good), 0)},
		{"a byte less", good[:len(good)-1]},
		{"empty", nil},
		{"only the version", good[:1]},
	}
	if _, _, err := readKeyBody(offCurve); err == nil {
		t.Error("a point that is not on the curve was accepted")
	}
	for _, c := range cases {
		if _, _, err := readKeyBody(c.body); err == nil {
			t.Errorf("%s: a key body that the first form refuses was accepted", c.name)
		}
	}
	// A point that is the compressed form of a point of P-384 (49 bytes) is no point of the form.
	x := new(big.Int).SetBytes(pt[1:49])
	compressed := append([]byte{2 + byte(pt[96]&1)}, x.FillBytes(make([]byte, 48))...)
	short := cat2(good[:6], p384OID, mpi(new(big.Int).SetBytes(compressed)))
	if _, _, err := readKeyBody(short); err == nil {
		t.Error("a compressed point was accepted")
	}
}

func cat2(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
