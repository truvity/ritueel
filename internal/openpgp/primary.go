package openpgp

import (
	"bytes"
	"crypto"
	"io"
	"math"
	"time"
)

// PrimaryParams names a root key's OpenPGP primary and the moment of one ceremony.
type PrimaryParams struct {
	// Key signs. Its public key must be ECDSA on P-384. A card or a cloud key plugs in here: it is
	// given the SHA-384 digest of what is signed (crypto.SHA384) and returns an ASN.1 signature.
	Key crypto.Signer
	// CreationTime is the OpenPGP creation time of the primary. It fixes the fingerprint
	// (docs/reference/bundle.md, "root.json": openpgp_created). Whole seconds.
	CreationTime time.Time
	// CeremonyTime is the time every signature carries. Whole seconds, not before CreationTime.
	CeremonyTime time.Time
	// ExpiresAt is the instant the key expires, after CeremonyTime. The caller passes the ceremony
	// time plus 36 calendar months. The key expiration time is written in seconds after
	// CreationTime, as the standard says, so that the key ends at this instant.
	ExpiresAt time.Time
	// UserID is the user ID, see [UserID]. One that has not the shape of [UserID], or holds a part
	// that breaks its rules, is refused.
	UserID string
}

// newPrimarySigner checks what every builder needs of the parameters (the key, the creation time
// and the ceremony time) and makes the signer.
func newPrimarySigner(rnd io.Reader, p PrimaryParams) (*signer, error) {
	g, err := newSigner(rnd, p.Key, p.CreationTime)
	if err != nil {
		return nil, err
	}
	if err := checkTime("the ceremony time", p.CeremonyTime); err != nil {
		return nil, err
	}
	if p.CeremonyTime.Before(p.CreationTime) {
		return nil, fail(ErrParams, "the ceremony time is before the creation time of the key")
	}
	return g, nil
}

// lifetime is the number of seconds from start to end, which must be a positive number that fits
// a key expiration time, and end must be after the ceremony.
func lifetime(what string, start, end, ceremony time.Time) (uint32, error) {
	if err := checkTime(what, end); err != nil {
		return 0, err
	}
	if !end.After(ceremony) {
		return 0, fail(ErrParams, "%s is not after the ceremony time", what)
	}
	d := end.Unix() - start.Unix()
	if d <= 0 || d > math.MaxUint32 {
		return 0, fail(ErrParams, "%s is not between 1 second and 136 years after the key was created", what)
	}
	return uint32(d), nil
}

// NewPrimary returns the public certificate of the primary: the primary key packet, the user ID
// packet and the self-signature. The self-signature is a positive certification (type 0x13) with
// SHA-384; its hashed area holds the signature creation time (the ceremony time), the key flags
// 0x01 (certify only), the key expiration time marked critical, and the issuer fingerprint; its
// unhashed area holds the issuer key ID. The certificate has no subkey.
//
// docs/reference/bundle.md, "The OpenPGP primary"; record 0009, rules 1, 2, 4 and 8. The signature
// is verified before the bytes are returned; nothing is returned with an error.
func NewPrimary(rnd io.Reader, p PrimaryParams) (cert []byte, err error) {
	g, sig, err := selfSign(rnd, p)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = append(out, g.packet...)
	out = append(out, wrap(tagUserID, []byte(p.UserID))...)
	return append(out, sig...), nil
}

// ExtendPrimary returns a new self-signature of the same shape as the one of [NewPrimary], at
// p.CeremonyTime: "each use extends it" (docs/reference/bundle.md, "The OpenPGP primary"). It is
// one signature packet, to be added to the certificate. The newest signature gives the expiry.
func ExtendPrimary(rnd io.Reader, p PrimaryParams) (selfSig []byte, err error) {
	_, sig, err := selfSign(rnd, p)
	return sig, err
}

// selfSign makes the self-signature packet of p and reads it back.
func selfSign(rnd io.Reader, p PrimaryParams) (*signer, []byte, error) {
	if err := checkUserID(p.UserID); err != nil {
		return nil, nil, err
	}
	g, err := newPrimarySigner(rnd, p)
	if err != nil {
		return nil, nil, err
	}
	life, err := lifetime("the expiry of the key", g.created, p.ExpiresAt, p.CeremonyTime)
	if err != nil {
		return nil, nil, err
	}
	uid := []byte(p.UserID)
	body, err := g.sign(sigSpec{
		sigType: sigPositiveCertification,
		hashed: []subpacket{
			{typ: spCreationTime, data: u32(unixU32(p.CeremonyTime))},
			{typ: spKeyFlags, data: []byte{flagCertify}},
			{typ: spKeyExpiration, critical: true, data: u32(life)},
			g.issuerFingerprint(),
		},
		unhashed: []subpacket{g.issuerKeyID()},
		data: [][]byte{
			hashPrefix(g.body),
			{0xB4, byte(len(uid) >> 24), byte(len(uid) >> 16), byte(len(uid) >> 8), byte(len(uid))},
			uid,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	pkt := wrap(tagSignature, body)
	sig, err := readBack(pkt, g.key)
	if err != nil {
		return nil, nil, err
	}
	if err := g.pk.VerifyUserIdSignature(p.UserID, g.pk, sig); err != nil {
		return nil, nil, fail(ErrSignature, "the self-signature does not verify: %v", err)
	}
	if sig.SigType != sigPositiveCertification || !sig.CreationTime.Equal(p.CeremonyTime) ||
		sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs != life ||
		!sig.FlagsValid || !sig.FlagCertify || sig.FlagSign || sig.FlagAuthenticate ||
		sig.FlagEncryptCommunications || sig.FlagEncryptStorage || sig.FlagSplitKey || sig.FlagGroupKey {
		return nil, nil, fail(ErrSignature, "the self-signature does not read back as it was built")
	}
	return g, bytes.Clone(pkt), nil
}
