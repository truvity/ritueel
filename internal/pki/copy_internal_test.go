//nolint:staticcheck // these tests write the numbers of a key in place, which is what a hostile caller does
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// The copies themselves, called directly: what they return shares nothing with what they were given; a key that is not a P-384
// key is left as it was given, so that the refusal comes in the same place; and the refusal for a parameter that changed during
// the copy is an ErrParams with its words. (That the comparison of the two copies finds a change cannot be shown without a writer
// in a second goroutine: see copies_norace_test.go, which reaches the refusal with one.)

func TestCopiesShareNothingWithTheirParameters(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	cb, err := copyBytes(b)
	if err != nil || !bytes.Equal(cb, b) {
		t.Fatalf("copyBytes = %x, %v", cb, err)
	}
	cb[0] = 99
	if b[0] != 1 {
		t.Error("the copy of the bytes shares them")
	}
	b[1] = 77
	if cb[1] == 77 {
		t.Error("the bytes share the copy")
	}
	if c, err := copyBytes(nil); err != nil || len(c) != 0 {
		t.Errorf("copyBytes(nil) = %x, %v", c, err)
	}
	n := big.NewInt(0).SetBytes([]byte{0x80, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	cn, err := copySerial(n)
	if err != nil || cn.Cmp(n) != 0 || cn == n {
		t.Fatalf("copySerial = %v, %v", cn, err)
	}
	cn.Add(cn, big.NewInt(1))
	if n.Cmp(cn) == 0 {
		t.Error("the copy of the serial shares its number")
	}
	n.Add(n, big.NewInt(5))
	if cn2, _ := copySerial(n); cn2.Cmp(n) != 0 {
		t.Error("a second copy is not the number")
	}
	if c, err := copySerial(nil); err != nil || c != nil {
		t.Errorf("copySerial(nil) = %v, %v: a nil serial stays nil and is refused by CheckSerial", c, err)
	}
	if err := CheckSerial(nil); !errors.Is(err, ErrParams) {
		t.Errorf("CheckSerial(nil) = %v", err)
	}

	k := newTestKey(t)
	pub := &k.PublicKey
	kc := keyCopy(pub).(*ecdsa.PublicKey)
	if kc == pub || kc.X == pub.X || kc.Y == pub.Y || !kc.Equal(pub) {
		t.Error("the copy of a key shares the object or its numbers, or is another key")
	}
	pub.X.Add(pub.X, big.NewInt(1))
	if kc.X.Cmp(pub.X) == 0 {
		t.Error("the key changed with the caller's key")
	}
	pub.X.Sub(pub.X, big.NewInt(1))
	got, err := p384(pub)
	if err != nil || got == pub || got.X == pub.X || got.Y == pub.Y {
		t.Errorf("p384 returns the caller's key or its numbers: %v", err)
	}
	// A key that is not a P-384 key, or nothing, has no copy: the copy is a refusal that wraps ErrParams and no other kind, and keyCopy
	// never returns the object that it was given (an earlier version fell back to the caller's own object, which a racing caller
	// could then change between two reads).
	var none *ecdsa.PublicKey
	for name, in := range map[string]any{"nil": nil, "a typed nil": none, "a string": "not a key", "a key of no point": &ecdsa.PublicKey{}, "a key of another curve": &ecdsa.PublicKey{Curve: elliptic.P256()}} {
		out := keyCopy(in)
		if out == in {
			t.Errorf("%s: keyCopy returned the object that it was given", name)
		}
		err := keyRefusal(out)
		if err == nil || !wrapsParamsKind(err) {
			t.Errorf("%s: the copy is not a refusal that wraps ErrParams alone: %v", name, err)
		}
		if _, err := p384(in); !wrapsParamsKind(err) {
			t.Errorf("%s: p384 = %v", name, err)
		}
	}
	// A key that is good is copied, and the copy is not a refusal.
	if keyRefusal(keyCopy(pub)) != nil {
		t.Error("a good key is refused")
	}
}

func TestTheRefusalForAParameterThatChangedWhileItWasCopied(t *testing.T) {
	err := errChanged()
	if !errors.Is(err, ErrParams) || errors.Is(err, ErrRequest) || errors.Is(err, ErrSignature) {
		t.Errorf("errChanged is not one ErrParams: %v", err)
	}
	if !strings.Contains(err.Error(), "a parameter changed while the call copied it") {
		t.Errorf("the words are not there: %q", err.Error())
	}
	for _, r := range err.Error() {
		if r < 0x20 || r > 0x7e {
			t.Errorf("the text is not printable ASCII: %q", err.Error())
			break
		}
	}
}
