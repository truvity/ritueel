package software

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"ritueel.id/ritueel/internal/keystore"
)

// digestLen is the length of the SHA-384 digest that Sign takes.
const digestLen = 48

// keyText is what a key prints as under every verb.
const keyText = "software key (private half not shown)"

// errSignature marks a signature that the key made and that its own public key does not verify.
// Nothing is returned with it.
var errSignature = errors.New("software: the signature does not verify with the key's own public key")

// Key is a software key: an ECDSA P-384 key made in memory (record 0002, rules 4 and 14). It
// implements [keystore.Key]. Every method is safe on a nil or zero *Key and returns an error,
// never panics. It prints as a fixed text under %v, %+v, %#v, %s, %q and %x, and marshals to
// nothing, because it has no exported field.
//
// What [Key.Close] clears. It sets the scalar of the key object to zero, word by word, and drops
// the key's own references to the key. Go does not promise that every copy of a secret in memory
// is cleared: the big numbers inside ecdsa.PrivateKey, the copies that the runtime or the garbage
// collector made, and the bytes that crypto/ecdsa and crypto/x509 handled while the key signed or
// was written are not reachable from here. Close makes the key refuse to sign and clears what the
// key object holds; it does not claim more.
type Key struct{ s *keyState }

// keyState is the state of a key. A Key value holds only the pointer to it, so a copy of a Key
// shares one state (and one lock) with the original.
type keyState struct {
	mu     sync.Mutex
	priv   *ecdsa.PrivateKey // the key object; its scalar is zero after Close
	closed bool
	saved  bool
	// tamper, when set (by a test in this package), changes the signature after it was made and
	// before the key checks it, to show that a signature that does not verify is never returned.
	tamper func(sig []byte) []byte
}

// Generate makes an ECDSA P-384 key from crypto/rand, in memory. It writes nothing. It takes no
// random source: from Go 1.26 crypto/ecdsa ignores one, so a parameter would promise what the
// call cannot keep.
func Generate() (*Key, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, errors.New("software: no key could be generated")
	}
	return &Key{s: &keyState{priv: priv}}, nil
}

// fromPrivate wraps a private key that was read from a key file.
func fromPrivate(priv *ecdsa.PrivateKey) *Key {
	return &Key{s: &keyState{priv: priv}}
}

// state returns the state of the key, or nil for a nil or zero key.
func (k *Key) state() *keyState {
	if k == nil {
		return nil
	}
	return k.s
}

// Format prints the fixed text whatever the verb is.
func (Key) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, keyText)
}

// Public returns a new *ecdsa.PublicKey, built from copies of the point, on every call, so that a
// caller that changes it changes nothing in the key. A closed, nil or zero key returns nil.
func (k *Key) Public() crypto.PublicKey {
	pub := k.publicCopy()
	if pub == nil {
		return nil
	}
	return pub
}

// publicCopy is Public with its own type.
func (k *Key) publicCopy() *ecdsa.PublicKey {
	s := k.state()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.priv == nil {
		return nil
	}
	point, err := s.priv.PublicKey.Bytes()
	if err != nil {
		return nil
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
	if err != nil {
		return nil
	}
	return pub
}

// Sign signs a SHA-384 digest of exactly 48 bytes and returns the ASN.1 ECDSA value. opts must
// say crypto.SHA384; anything else, a nil key, a closed key and a digest of another length is an
// [ErrParams]. The signature is verified with the key's own public key before it is returned
// (record 0002, rule 14). The io.Reader argument is ignored, as in [Generate], and may be nil.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s := k.state()
	if s == nil {
		return nil, refuse(ErrParams, "there is no key")
	}
	if h, ok := hashOf(opts); !ok || h != crypto.SHA384 {
		return nil, refuse(ErrParams, "the key signs a SHA-384 digest only")
	}
	if len(digest) != digestLen {
		return nil, refuse(ErrParams, "the digest is not 48 bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.priv == nil {
		return nil, refuse(ErrParams, "the key is closed")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, digest)
	if err != nil {
		return nil, errors.New("software: the key could not sign")
	}
	if s.tamper != nil {
		sig = s.tamper(sig)
	}
	if !ecdsa.VerifyASN1(&s.priv.PublicKey, digest, sig) {
		return nil, errSignature
	}
	return sig, nil
}

// hashOf is opts.HashFunc() for any opts: a nil opts, or a typed nil pointer whose method panics,
// is not one.
func hashOf(opts crypto.SignerOpts) (h crypto.Hash, ok bool) {
	if opts == nil {
		return 0, false
	}
	defer func() {
		if recover() != nil {
			h, ok = 0, false
		}
	}()
	return opts.HashFunc(), true
}

// Kind is [keystore.KindSoftware].
func (k *Key) Kind() keystore.Kind { return keystore.KindSoftware }

// Copyable is true: every software key can be copied.
func (k *Key) Copyable() bool { return true }

// Warnings returns the one code of the ceremony record, [keystore.WarningSoftwareCopyable], in a
// new list on every call.
func (k *Key) Warnings() []string { return []string{keystore.WarningSoftwareCopyable} }

// Close clears the scalar of the key object as far as Go allows (see [Key]) and makes the key
// refuse to sign. A second Close does nothing and returns nil, and so does Close of a nil or zero
// key.
func (k *Key) Close() error {
	s := k.state()
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	wipe(s.priv)
	return nil
}

// wipe sets the numbers of a private key to zero, word by word.
func wipe(priv *ecdsa.PrivateKey) {
	if priv == nil {
		return
	}
	// The numbers are the only way to reach what the key object holds, and only to clear it.
	//nolint:staticcheck // clearing the deprecated fields is the point of the call
	for _, n := range []*big.Int{priv.D, priv.X, priv.Y} {
		if n == nil {
			continue
		}
		clear(n.Bits())
		n.SetInt64(0)
	}
}

// Saved is true once a Save call wrote the key file, read it back and checked it. A key that was
// opened from a key file is not Saved by that: the call that opened it saved nothing. A nil or
// zero key is not Saved.
func (k *Key) Saved() bool {
	s := k.state()
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saved
}

// markSaved is called by a Store after the read back of a save.
func (k *Key) markSaved() {
	s := k.state()
	if s == nil {
		return
	}
	s.mu.Lock()
	s.saved = true
	s.mu.Unlock()
}

// withPrivate runs fn with the private key of an open key, under the key's lock. A nil, zero or
// closed key is an [ErrParams]. fn must not keep the key.
func (k *Key) withPrivate(fn func(priv *ecdsa.PrivateKey) error) error {
	s := k.state()
	if s == nil {
		return refuse(ErrParams, "there is no key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.priv == nil {
		return refuse(ErrParams, "the key is closed or has no private half")
	}
	return fn(s.priv)
}

var _ keystore.Key = (*Key)(nil)
