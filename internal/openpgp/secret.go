package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"time"

	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ErrSecretKey marks bytes that are not the transferable secret key that [SecretKey] writes: not
// the packets of the profile, a key that is protected, of another version, algorithm or curve, a
// checksum that is wrong, a scalar that does not match its point, or a certificate whose
// self-signature does not verify. [ParseSecretKey] returns no key with it.
var ErrSecretKey = errors.New("openpgp: not a secret key of the profile")

const (
	tagSecretKey = 5

	// secretPublicLen is the length of the public part of a secret key packet: the body of the
	// public key packet that the certificate carries (version, time, algorithm, curve, point).
	secretPublicLen = 1 + 4 + 1 + 6 + 2 + 97
	// secretScalarLen is the length of a P-384 scalar in bytes.
	secretScalarLen = 48
)

// SecretKey turns a public certificate (the packets [NewPrimary] returns: the primary's public key
// packet, one user ID and the self-signature) and the primary's private key into a transferable
// secret key (RFC 9580, section 10.2; docs/reference/bundle.md, "The software root's key files"):
// the public key packet replaced by a secret key packet, version 4, S2K usage 0 (no protection
// inside), the scalar as a multiprecision integer and the two-octet checksum of it (section
// 5.5.3), then the user ID and the self-signature unchanged.
//
// The certificate must hold exactly those three packets, and its self-signature must verify. A key
// that is not the key of the certificate, a nil key, a key with no scalar or with a scalar of 0 or
// not below the order of the group, and a key that is not on P-384 are an [ErrParams]. The result
// is read back with [ParseSecretKey] and with go-crypto before it is returned, so no bytes that
// another reader does not read as built are returned. Nothing is returned with an error.
func SecretKey(cert []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	d, point, err := secretScalar(priv)
	if err != nil {
		return nil, err
	}
	defer clear(d)
	parts, err := secretSplitCert(ErrParams, cert)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(point, mustPoint(parts.key)) {
		return nil, fail(ErrParams, "the private key is not the key of the certificate")
	}
	scalar := secretMPI(d)
	defer clear(scalar)
	// Every buffer that holds the scalar is made at its final size, so that no append moves it
	// and leaves the old copy behind where this function cannot clear it.
	body := make([]byte, 0, len(parts.key.body)+1+len(scalar)+2)
	body = append(body, parts.key.body...)
	body = append(body, 0) // S2K usage 0: the secret material is not protected inside
	body = append(body, scalar...)
	sum := secretChecksum(scalar)
	body = append(body, byte(sum>>8), byte(sum))
	head := header(tagSecretKey, len(body))
	out := make([]byte, 0, len(head)+len(body)+len(parts.rest))
	out = append(out, head...)
	out = append(out, body...)
	clear(body)
	out = append(out, parts.rest...)

	if err := secretReadBack(out, cert, d, parts.key); err != nil {
		clear(out)
		return nil, err
	}
	return out, nil
}

// secretReadBack checks that out reads back, with [ParseSecretKey] and with go-crypto, as the key
// and the certificate that were given.
func secretReadBack(out, cert, d []byte, k *key) error {
	p2, created, cert2, err := ParseSecretKey(out)
	if err != nil {
		return fail(ErrSignature, "the secret key does not read back as it was built")
	}
	defer wipePrivate(p2)
	// Bytes returns the scalar that the key keeps for itself: a copy is compared and cleared.
	got, err := privateBytes(p2)
	defer clear(got)
	if err != nil || !bytes.Equal(got, d) || !created.Equal(k.created) || !bytes.Equal(cert2, cert) {
		return fail(ErrSignature, "the secret key does not read back as it was built")
	}
	pkt, err := packet.Read(bytes.NewReader(out))
	if err != nil {
		return fail(ErrSignature, "the secret key does not read back with go-crypto")
	}
	sk, ok := pkt.(*packet.PrivateKey)
	if !ok || sk.Encrypted || sk.Version != 4 || sk.IsSubkey || sk.PubKeyAlgo != packet.PubKeyAlgoECDSA ||
		!bytes.Equal(sk.Fingerprint, k.fp) {
		return fail(ErrSignature, "the secret key does not read back with go-crypto")
	}
	g, ok := sk.PrivateKey.(*pgpecdsa.PrivateKey)
	if !ok || g.D == nil {
		return fail(ErrSignature, "the secret key does not read back with go-crypto")
	}
	defer clear(g.D.Bits())
	// The number is compared as bytes: no copy of it is made as a number.
	theirs := make([]byte, secretScalarLen)
	defer clear(theirs)
	if g.D.Sign() < 0 || g.D.BitLen() > 8*secretScalarLen {
		return fail(ErrSignature, "the secret key does not read back with go-crypto")
	}
	g.D.FillBytes(theirs)
	if !bytes.Equal(theirs, d) {
		return fail(ErrSignature, "the secret key does not read back with go-crypto")
	}
	return nil
}

// ParseSecretKey reads exactly what [SecretKey] writes and returns the private key, the creation
// time that fixes the fingerprint, and the public certificate (the secret key packet turned back
// into the public key packet, then the user ID and the self-signature).
//
// It accepts one secret key packet (tag 5) of version 4, algorithm ECDSA, curve P-384, with the
// shortest header, S2K usage 0 and a correct checksum, then one user ID packet and one signature
// packet, and nothing else: no subkey, no second user ID, no trust packet, no byte after the last
// packet. A key that is protected (S2K usage 254 or 255), another algorithm, version or curve, a
// wrong checksum, a scalar of 0 or not below the order, a scalar that does not match the point, a
// packet with a partial or an indeterminate length and a self-signature that does not verify are
// an [ErrSecretKey]. The public part is the same bytes as the public key packet of the
// certificate. The length of data is the caller's to bound before the call.
func ParseSecretKey(data []byte) (priv *ecdsa.PrivateKey, created time.Time, cert []byte, err error) {
	tag, body, rest, err := splitPacket(data)
	if err != nil || tag != tagSecretKey {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the first packet is not one secret key packet")
	}
	if !bytes.Equal(data[:len(data)-len(rest)], wrap(tagSecretKey, body)) {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the header of the secret key packet is not the shortest one")
	}
	// public part, S2K usage, the scalar, the two-octet checksum
	if len(body) < secretPublicLen+1+2+1+2 {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the secret key packet is too short")
	}
	pub, usage, secret := body[:secretPublicLen], body[secretPublicLen], body[secretPublicLen+1:]
	if usage != 0 {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the secret key is protected inside (S2K usage is not 0)")
	}
	value, after, err := readMPI(secret)
	if err != nil || len(after) != 2 || len(value) > secretScalarLen {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the secret key material is not one scalar and a checksum")
	}
	mpiLen := len(secret) - len(after)
	if uint16(after[0])<<8|uint16(after[1]) != secretChecksum(secret[:mpiLen]) {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the checksum of the secret key material is wrong")
	}
	when, point, err := readKeyBody(pub)
	if err != nil {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the public part is not a version 4 ECDSA P-384 key")
	}
	raw := make([]byte, secretScalarLen)
	defer clear(raw)
	copy(raw[secretScalarLen-len(value):], value)
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), raw)
	if err != nil {
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the scalar is not a private key of the group")
	}
	if own, err := pointBytes(&k.PublicKey); err != nil || !bytes.Equal(own, point) {
		wipePrivate(k)
		return nil, time.Time{}, nil, fail(ErrSecretKey, "the scalar does not match the public point")
	}
	cert = append(wrap(tagPublicKey, pub), rest...)
	if _, err := secretSplitCert(ErrSecretKey, cert); err != nil {
		wipePrivate(k)
		return nil, time.Time{}, nil, err
	}
	return k, when, cert, nil
}

// secretChecksum is the checksum of the secret key material (RFC 9580, section 5.5.3): the sum of
// the octets of the material, here the multiprecision integer with its length, modulo 65536.
func secretChecksum(material []byte) uint16 {
	var sum uint16
	for _, b := range material {
		sum += uint16(b)
	}
	return sum
}

// secretScalar checks a private key and returns its scalar (48 bytes, to be cleared by the
// caller) and the uncompressed point derived from it. It never panics on a nil or half-made key.
func secretScalar(priv *ecdsa.PrivateKey) (scalar, point []byte, err error) {
	if priv == nil || priv.Curve != elliptic.P384() {
		return nil, nil, fail(ErrParams, "the private key is not an ECDSA key on P-384")
	}
	scalar, err = privateBytes(priv)
	if err != nil {
		return nil, nil, fail(ErrParams, "the private key has no scalar")
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), scalar)
	if err != nil {
		clear(scalar)
		return nil, nil, fail(ErrParams, "the private scalar is not between 1 and the order of the group")
	}
	defer wipePrivate(k)
	point, err = pointBytes(&k.PublicKey)
	if err != nil {
		clear(scalar)
		return nil, nil, fail(ErrParams, "the private key has no point")
	}
	return scalar, point, nil
}

// privateBytes is the scalar of a private key as 48 bytes, in a slice of its own. A key with no
// scalar has none to write: Bytes panics on it, and that is an error here. Bytes hands out the
// scalar that the key keeps for itself, and a slice that the caller got from it before is the same
// memory, so the result is copied before anyone clears it.
func privateBytes(priv *ecdsa.PrivateKey) (raw []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			raw, err = nil, errFrame
		}
	}()
	shared, err := priv.Bytes()
	if err != nil {
		return nil, err
	}
	return bytes.Clone(shared), nil
}

// wipePrivate sets the number of a private key that this package made to zero, word by word. It
// is called on a key that nobody else holds; the copies inside crypto/ecdsa are out of reach.
func wipePrivate(k *ecdsa.PrivateKey) {
	if k == nil {
		return
	}
	//nolint:staticcheck // clearing the deprecated field is the point of the call
	n := k.D
	if n == nil {
		return
	}
	clear(n.Bits())
	n.SetInt64(0)
}

// secretMPI writes the scalar d (48 bytes, not zero) as a multiprecision integer (RFC 9580,
// section 3.2) without a big number: the bit length, then the bytes without leading zeros. The
// result is a new slice for the caller to clear.
func secretMPI(d []byte) []byte {
	i := 0
	for i < len(d) && d[i] == 0 {
		i++
	}
	v := d[i:]
	bits := 0
	if len(v) > 0 {
		bits = (len(v)-1)*8 + bitLen(v[0])
	}
	out := make([]byte, 0, 2+len(v))
	out = append(out, byte(bits>>8), byte(bits))
	return append(out, v...)
}

// mustPoint is the uncompressed point of a key that readKey has made, which cannot fail.
func mustPoint(k *key) []byte {
	p, err := pointBytes(k.ec)
	if err != nil {
		return nil
	}
	return p
}

// secretParts is a certificate taken apart.
type secretParts struct {
	key  *key
	rest []byte // the user ID packet and the self-signature, as they stand
}

// secretSplitCert reads a certificate of the profile: the public key packet of a primary (with the
// shortest header), one user ID packet and one self-signature (a positive certification) that
// verifies with the key, and nothing else. A fault is an error that wraps kind.
func secretSplitCert(kind error, cert []byte) (*secretParts, error) {
	tag, body, rest, err := splitPacket(cert)
	if err != nil || tag != tagPublicKey {
		return nil, fail(kind, "the certificate does not start with a primary key packet")
	}
	keyPkt := cert[:len(cert)-len(rest)]
	if !bytes.Equal(keyPkt, wrap(tagPublicKey, body)) {
		return nil, fail(kind, "the header of the key packet is not the shortest one")
	}
	k, err := readKey(keyPkt, tagPublicKey)
	if err != nil {
		return nil, fail(kind, "the primary is not a version 4 ECDSA P-384 key")
	}
	uidTag, uid, afterUID, err := splitPacket(rest)
	if err != nil || uidTag != tagUserID {
		return nil, fail(kind, "the key packet is not followed by one user ID packet")
	}
	sigTag, _, tail, err := splitPacket(afterUID)
	if err != nil || sigTag != tagSignature || len(tail) != 0 {
		return nil, fail(kind, "the user ID is not followed by one signature packet and nothing else")
	}
	p, err := packet.Read(bytes.NewReader(afterUID))
	if err != nil {
		return nil, fail(kind, "the self-signature does not parse")
	}
	sig, ok := p.(*packet.Signature)
	if !ok || sig.SigType != sigPositiveCertification {
		return nil, fail(kind, "the signature is not a positive certification")
	}
	if err := k.pk.VerifyUserIdSignature(string(uid), k.pk, sig); err != nil {
		return nil, fail(kind, "the self-signature does not verify with the key")
	}
	return &secretParts{key: k, rest: bytes.Clone(rest)}, nil
}
