package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
)

// keyIDLen is the length of a key identifier: 160 bits (RFC 7093, section 2, method 1).
const keyIDLen = 20

// p384 returns a copy of the key as an ECDSA public key on P-384, or an error that wraps
// [ErrParams]. A nil key, another type, another curve and a point that is not on the curve are
// refused. The key that is returned is a value of its own: it shares no big number with the key that
// was given, which the caller or a signer may still change. The given object is read here and nowhere
// else: its two coordinates are copied (each once, by a copy that cannot panic on a number that is
// being written), the copies are checked against the object again, and the point is made from the
// copies only. A key that changed while it was copied is refused as a change (the caller wrote to
// it during the call); a key whose copy is not a point, and has not changed, is refused as not a
// point on P-384. Nothing falls back to the object that was given.
func p384(pub crypto.PublicKey) (*ecdsa.PublicKey, error) {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k == nil || k.Curve != elliptic.P384() {
		return nil, fail(ErrParams, "the public key is not an ECDSA key on P-384")
	}
	x, y := k.X, k.Y //nolint:staticcheck // the coordinates are the key; they are read here, once
	if x == nil || y == nil {
		return nil, fail(ErrParams, "the public key has no point")
	}
	//nolint:staticcheck // a key made from the copies, and the object read again to see that it did not change
	mine := &ecdsa.PublicKey{Curve: elliptic.P384(), X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
	if k.X != x || k.Y != y || mine.X.Cmp(x) != 0 || mine.Y.Cmp(y) != 0 { //nolint:staticcheck // see above
		return nil, errChanged()
	}
	b, err := mine.Bytes()
	if err != nil {
		return nil, fail(ErrParams, "the public key is not a point on P-384")
	}
	c, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), b)
	if err != nil {
		return nil, fail(ErrParams, "the public key is not a point on P-384")
	}
	return c, nil
}

// refusedKey stands, in the place of a key, for a key that has no copy: it holds the refusal.
type refusedKey struct{ err error }

// keyCopy is the copy of a key that a function takes at its top: a P-384 key as a value of its own, or
// a refusedKey that holds the refusal of the key (the function that took the copy returns it at once).
// It never returns the object that was given.
func keyCopy(pub crypto.PublicKey) crypto.PublicKey {
	k, err := p384(pub)
	if err != nil {
		return refusedKey{err}
	}
	return k
}

// keyRefusal returns the refusal that a copy of a key holds, or nil for a key that was copied.
func keyRefusal(pub crypto.PublicKey) error {
	if r, ok := pub.(refusedKey); ok {
		return r.err
	}
	return nil
}

// spki returns the DER SubjectPublicKeyInfo of a P-384 key, and the content of its
// subjectPublicKey BIT STRING: the uncompressed point.
func spki(pub crypto.PublicKey) (der, point []byte, err error) {
	k, err := p384(pub)
	if err != nil {
		return nil, nil, err
	}
	der, err = x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, nil, failWith(ErrParams, "the public key does not encode", err)
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, nil, fail(ErrParams, "the public key does not decode")
	}
	if info.PublicKey.BitLength != 8*len(info.PublicKey.Bytes) {
		return nil, nil, fail(ErrParams, "the public key is not a whole number of octets")
	}
	return der, info.PublicKey.Bytes, nil
}

// SPKISHA256 is the pin of a key (record 0006, rule 16): the SHA-256 of the DER
// SubjectPublicKeyInfo of the key, as 64 lower-case hexadecimal digits. The key is ECDSA on
// P-384; anything else is an error that wraps [ErrParams].
func SPKISHA256(pub crypto.PublicKey) (string, error) {
	der, _, err := spki(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// KeyIdentifier is the key identifier of RFC 7093, section 2, method 1: the leftmost 160 bits
// (20 octets) of the SHA-256 of the value of the subjectPublicKey BIT STRING, leaving out the tag,
// the length and the number of unused bits. The key is ECDSA on P-384; anything else is an error
// that wraps [ErrParams].
func KeyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	_, point, err := spki(pub)
	if err != nil {
		return nil, err
	}
	return keyIdentifier(point), nil
}

// keyIdentifier is the identifier of the bits of a subjectPublicKey.
func keyIdentifier(point []byte) []byte {
	sum := sha256.Sum256(point)
	return sum[:keyIDLen]
}
