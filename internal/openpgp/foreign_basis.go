package openpgp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ForeignBasis describes what the builders of later signatures will sign from, for a ceremony to show and
// to put into the plan that it asks the person to confirm. It is made by [ForeignKey.SigningBasis] from the
// snapshot of the key, which the reader fills out of the signatures that counted, and it holds plain values
// and no slice that the key shares. It is not the view of the key: the per-signature view of a
// [ForeignKey] is for a person to read and a caller may edit it, and what a later signature is made from is
// this.
type ForeignBasis struct {
	// Fingerprint and Algorithm are the primary's, and CertificateSHA256 is the SHA-256 of what
	// [ForeignKey.Certificate] holds, so that a ceremony takes all three from the basis and not from the view
	// that a caller can edit. The digest is made here from the certificate and is not a [HeldDigest]: that must
	// come from a record.
	Fingerprint       string
	Algorithm         ForeignAlgorithm
	CertificateSHA256 [sha256.Size]byte
	// Revoked is true when a key revocation counts: no signature is made.
	Revoked bool
	// ExpiryEarliest, ExpiryAny, ExpiryAgree and ExpiryMarked are the answers about the end of the key. The
	// sources are the newest self-signature of each live user ID and the newest direct-key signature: programs
	// differ in where they read the end, so each is kept. ExpiryEarliest is the earliest end among them (zero
	// when no source has an end), ExpiryAny is true when there is a source at all (a key with none must not be
	// signed from), ExpiryAgree is true when every source says the same end, and ExpiryMarked is true when the
	// newest signature of some source has a signature expiration time, which is not judged here. A user ID
	// that is revoked is not a source.
	ExpiryEarliest                       time.Time
	ExpiryAny, ExpiryAgree, ExpiryMarked bool
	// PrimaryFlagged is the number of live user IDs whose source signature carries the primary flag: 0, 1 or
	// more. A ceremony must not write the primary flag on a user ID because the basis picked one: where to
	// write it is a parameter that the ceremony takes from the person.
	PrimaryFlagged int
	// The direct-key source, the newest direct-key signature that counts: whether there is one, its end of
	// the key (zero is none), whether its hash is SHA-1, whether it has a signature expiration time, whether
	// it was chosen by the bytes of the packets and the choice matters (DirectTied), the preference
	// subpackets that a re-signing carries over and the types of its hashed subpackets that it does not.
	DirectHave, DirectWeak, DirectSigExpires, DirectTied bool
	DirectEnd                                            time.Time
	DirectPrefs                                          []ForeignBasisPref
	DirectDropped                                        []uint8
	// Newest is the creation time of the newest signature that counts anywhere in the certificate: the next
	// signature must be dated after it.
	Newest time.Time
	// UserIDs are the user IDs of the certificate, by their text bytes, and Subkeys the subkeys, by their
	// fingerprint, whatever the order of the file.
	UserIDs []ForeignBasisUserID
	Subkeys []ForeignBasisSubkey
}

// ForeignBasisPref is a carried preference subpacket: its type (11, 21, 22, 23, 30 or 39) and its bytes.
type ForeignBasisPref struct {
	Type uint8
	Data []byte
}

// ForeignBasisUserID is a user ID of the basis, with what its newest self-signature (its source) says.
type ForeignBasisUserID struct {
	// Text is the bytes of the user ID packet, exactly.
	Text string
	// Revoked is true when the user ID is revoked, and it is live when it is not.
	Revoked bool
	// Signed is the creation time of its source signature, the newest self-signature that counts, whatever
	// its hash.
	Signed time.Time
	// KeyFlags, Primary and KeyExpires are the first key flags octet, the primary flag and the end of the key
	// (zero if none) that the source signature says. IsPrimary is true when this is THE primary user ID, by
	// the one rule of the snapshot: among the live user IDs whose source carries the primary flag the newest
	// source, a tie by the smaller text, and none when no live user ID carries it (see PrimaryFlagged).
	KeyFlags   uint8
	Primary    bool
	IsPrimary  bool
	KeyExpires time.Time
	// Prefs are the preference subpackets of the source that a re-signing carries over, in the order in which
	// they are written, and Dropped are the types of its hashed subpackets that it does not carry (a
	// designated revoker, a notation, a policy URL, any unknown type), sorted, numbers only.
	Prefs   []ForeignBasisPref
	Dropped []uint8
	// SigExpires is true when the source signature has a signature expiration time, which is not judged here.
	SigExpires bool
	// Weak is true when the source signature is made with SHA-1: its flags, primary flag, end and
	// preferences come from a weak signature, and a re-signing takes them over. AnyStrong is true when some
	// self-signature of the user ID that counts is not made with SHA-1. Tied is true when the source was chosen
	// by the bytes of the packets, the same second and the same end in two packets.
	Weak, AnyStrong, Tied bool
	// TextOK is true when the text passes the rule for a user ID that the key already has (UTF-8, no control
	// or format character, within the limit of the reader), so that a re-signing may cover it.
	TextOK bool
}

// ForeignBasisSubkey is a subkey of the basis.
type ForeignBasisSubkey struct {
	// Fingerprint is the version 4 fingerprint: 40 lower-case hexadecimal digits.
	Fingerprint string
	Algorithm   ForeignAlgorithm
	Revoked     bool
	// Weak is true when the newest binding that counts is made with SHA-1, AnyStrong when some binding that
	// counts is not, and Tied when the newest was chosen by the bytes of the packets.
	Weak, AnyStrong, Tied bool
}

// SigningBasis describes what later signatures of the key are made from. It works for a key that
// [ReadForeignKey] read from an export and for one that [ReadForeignCertificate] read from a certificate,
// and gives the same answer for the two. This, and not the per-signature view of the key, is what later
// signatures are made from: a ceremony shows this and puts it into the plan that the person confirms. It
// returns a value with no slice shared with the key, and the zero value for a nil key or one that nothing
// read.
func (k *ForeignKey) SigningBasis() ForeignBasis {
	if k == nil || len(k.snap.packet) == 0 {
		return ForeignBasis{}
	}
	s := &k.snap
	e := s.expiry()
	b := ForeignBasis{
		Fingerprint: hex.EncodeToString(s.fp), Algorithm: k.pub.alg, CertificateSHA256: sha256.Sum256(k.cert),
		Revoked:        s.revoked,
		ExpiryEarliest: e.earliest, ExpiryAny: e.any, ExpiryAgree: e.agree, ExpiryMarked: e.marked,
		PrimaryFlagged: s.flaggedUserIDs(),
		DirectHave:     s.direct.have, DirectWeak: s.direct.weak, DirectSigExpires: s.direct.sigExpires, DirectTied: s.direct.tied,
		DirectEnd: s.direct.expires, DirectPrefs: basisPrefs(s.direct.prefs), DirectDropped: bytes.Clone(s.direct.dropped),
		Newest: s.newest,
	}
	primary, havePrimary := s.primaryUserID()
	for i, u := range s.users {
		b.UserIDs = append(b.UserIDs, ForeignBasisUserID{
			Text: string(u.text), Revoked: u.revoked, Signed: u.signed,
			KeyFlags: u.flags, Primary: u.primary, IsPrimary: havePrimary && i == primary, KeyExpires: u.expires,
			Prefs: basisPrefs(u.prefs), Dropped: bytes.Clone(u.dropped),
			SigExpires: u.sigExpires, Weak: u.weak, AnyStrong: u.anyStrong, Tied: u.tied,
			TextOK: checkExistingUserID(u.text) == nil,
		})
	}
	for _, sub := range s.subkeys {
		b.Subkeys = append(b.Subkeys, ForeignBasisSubkey{
			Fingerprint: hex.EncodeToString(sub.fp), Algorithm: sub.alg, Revoked: sub.revoked,
			Weak: sub.weak, AnyStrong: sub.anyStrong, Tied: sub.tied,
		})
	}
	return b
}

// basisPrefs copies carried subpackets into the values of the basis.
func basisPrefs(prefs []subpacket) []ForeignBasisPref {
	var out []ForeignBasisPref
	for _, p := range prefs {
		out = append(out, ForeignBasisPref{Type: p.typ, Data: bytes.Clone(p.data)})
	}
	return out
}
