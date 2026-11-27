package openpgp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"math/big"
)

// AdoptedIssuer signs as the primary key of an adopted key (record 0008, rule 5): a key that a person had
// before ritueel, RSA with 4096 bits, Ed25519 or ECDSA on P-384, that [ReadForeignKey] read from its
// export or [ReadForeignCertificate] read from the certificate that the export gave. It joins what the
// reader confirmed of the key (the snapshot, which no caller can edit) to a [crypto.Signer] that holds the
// secret, and it signs with SHA-384 whatever the key is (record 0002, rule 14). The signer may be the
// [ForeignSigner] of the same key or any other [crypto.Signer] of the right key. An AdoptedIssuer holds no
// secret of its own.
type AdoptedIssuer struct {
	// ident is the primary as the builders use it. Its fields are those of a key that was made with
	// [readKey], and they are set for every algorithm except ec, which is set only for P-384: a builder
	// that needs the point of a P-384 key must look at the algorithm first.
	ident *key
	snap  fkSnapshot
	pub   signKey
	s     crypto.Signer
}

// NewAdoptedIssuer makes the issuer of the primary of k, which signs with s. It refuses with an
// [ErrParams] a nil key, a key that was not made by [ReadForeignKey] or [ReadForeignCertificate], a nil
// signer, a signer that was wiped ([ErrSecretWiped] after [ForeignSecret.Wipe]), a signer whose public key
// is not the primary key of k (the keys are compared, not the pointers), and a key whose primary is
// revoked. The signer's answers are checked against the public key of the primary before they are used.
func NewAdoptedIssuer(k *ForeignKey, s crypto.Signer) (*AdoptedIssuer, error) {
	if k == nil || len(k.snap.packet) == 0 {
		return nil, fail(ErrParams, "there is no key: it is nil, or it was not made by ReadForeignKey or ReadForeignCertificate")
	}
	if isNil(s) {
		return nil, fail(ErrParams, "there is no signer")
	}
	if k.snap.revoked {
		return nil, fail(ErrParams, "the primary key is revoked")
	}
	if f, ok := s.(*ForeignSigner); ok && f.wiped() {
		return nil, fmt.Errorf("%w: the signer was wiped: %w", ErrParams, ErrSecretWiped)
	}
	pub, err := parseForeignPublic("the primary key", k.snap.body, true, true)
	if err != nil {
		return nil, fail(ErrParams, "the primary key does not read: %v", err)
	}
	sk, public, err := signKeyOf(pub)
	if err != nil {
		return nil, err
	}
	if !samePublic(public, s) {
		return nil, fail(ErrParams, "the public key of the signer is not the primary key")
	}
	pk, err := agreePublic(k.snap.packet, k.snap.body, k.snap.fp, false)
	if err != nil {
		return nil, fail(ErrParams, "the primary key does not read: %v", err)
	}
	ident := &key{
		ec:      sk.ec,
		pk:      pk,
		created: k.snap.created,
		body:    append([]byte(nil), k.snap.body...),
		packet:  append([]byte(nil), k.snap.packet...),
		fp:      append([]byte(nil), k.snap.fp...),
		keyID:   append([]byte(nil), k.snap.fp[12:]...),
	}
	return &AdoptedIssuer{ident: ident, snap: k.snap, pub: sk, s: s}, nil
}

// sign makes the body of a signature that the primary makes: the SHA-384 digest of the data of the spec
// goes to the signer, and the answer is checked with the public key of the primary packet.
func (a *AdoptedIssuer) sign(rnd io.Reader, spec sigSpec) ([]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	return signWith(rnd, a.s, a.pub, spec)
}

// issuerFingerprint and issuerKeyID are the two subpackets that every signature of the primary carries
// (record 0009, rule 8).
func (a *AdoptedIssuer) issuerFingerprint() subpacket { return a.ident.issuerFingerprint() }
func (a *AdoptedIssuer) issuerKeyID() subpacket       { return a.ident.issuerKeyID() }

// signKeyOf makes the public key of a primary that the reader took, in the form of the standard library:
// the key that a signature is checked with, and the same key as a [crypto.PublicKey] to compare.
func signKeyOf(pub fkPublic) (signKey, crypto.PublicKey, error) {
	switch pub.alg.ID {
	case algoRSA:
		e := new(big.Int).SetBytes(pub.rsaE)
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() >= 1<<31 {
			return signKey{}, nil, fail(ErrParams, "the public exponent of the primary key is not a number that crypto/rsa takes")
		}
		k := &rsa.PublicKey{N: new(big.Int).SetBytes(pub.rsaN), E: int(e.Int64())}
		return signKey{algo: algoRSA, rsa: k}, k, nil
	case algoEdDSA:
		if len(pub.point) != 33 || pub.point[0] != 0x40 {
			return signKey{}, nil, fail(ErrParams, "the public key of the primary is not 0x40 and 32 bytes")
		}
		k := ed25519.PublicKey(append([]byte(nil), pub.point[1:]...))
		return signKey{algo: algoEdDSA, ed: k}, k, nil
	case algoECDSA:
		k, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pub.point)
		if err != nil {
			return signKey{}, nil, fail(ErrParams, "the point of the primary key is not a point on P-384")
		}
		return signKey{algo: algoECDSA, ec: k}, k, nil
	}
	return signKey{}, nil, fail(ErrParams, "the algorithm of the primary key is not one that signs here")
}

// samePublic tells whether the public key of the signer is the key of the primary, by comparing the keys
// with the Equal method of the standard library. A signer that panics or answers a key of no known type
// is not the key.
func samePublic(mine crypto.PublicKey, s crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	same := false
	err := safely(func() error {
		theirs := s.Public()
		e, ok := mine.(equaler)
		if !ok || isNil(theirs) {
			return nil
		}
		same = e.Equal(theirs)
		return nil
	})
	return err == nil && same
}

// wiped tells whether the secret that the signer was made from has been wiped. It reads what Sign reads.
func (f *ForeignSigner) wiped() bool {
	if f == nil || f.secret == nil {
		return true
	}
	f.secret.mu.RLock()
	defer f.secret.mu.RUnlock()
	return f.secret.key == nil
}
