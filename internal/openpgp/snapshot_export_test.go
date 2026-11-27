package openpgp

import "time"

// The names below are visible to the tests of the package that stand outside it. They show the snapshot
// of a key, so that a test can compare two of them and the view with them.

// SnapshotOf returns the snapshot that the reader filled in k, as a value that holds no secret. Two of
// them are equal (reflect.DeepEqual) when the reader found the same key in two inputs.
func SnapshotOf(k *ForeignKey) any { return k.snap }

// SnapPref is a carried subpacket of the snapshot.
type SnapPref struct {
	Type byte
	Data []byte
}

// SnapUser is a user ID of the snapshot as a test reads it.
type SnapUser struct {
	Text    string
	Revoked bool
	Signed  time.Time
	Flags   uint8
	Primary bool
	Expires time.Time
	Prefs   []SnapPref
	// SigExpires: the newest self-signature has a signature expiration time. Weak: it is SHA-1.
	// AnyStrong: some self-signature that counts is not.
	SigExpires, Weak, AnyStrong, Tied bool
}

// SnapSubkey is a subkey of the snapshot as a test reads it.
type SnapSubkey struct {
	Fingerprint []byte
	Body        []byte
	Revoked     bool
	Bound       time.Time
	// Weak: the newest binding is SHA-1. AnyStrong: some binding that counts is not.
	Weak, AnyStrong, Tied bool
}

// SnapKey is the key level of the snapshot as a test reads it.
type SnapKey struct {
	Packet, Body, Fingerprint []byte
	Created                   time.Time
	Revoked                   bool
	Newest                    time.Time
	Expiry                    ExpiryAnswer
	DirectTied                bool
}

// ExpiryAnswer is what the snapshot says of the end of the key.
type ExpiryAnswer struct {
	Earliest           time.Time
	Any, Agree, Marked bool
}

// SnapshotKey returns the key level of the snapshot.
func SnapshotKey(k *ForeignKey) SnapKey {
	s := k.snap
	return SnapKey{Packet: s.packet, Body: s.body, Fingerprint: s.fp, Created: s.created, Revoked: s.revoked, Newest: s.newest, Expiry: SnapshotExpiry(k), DirectTied: s.direct.tied}
}

// SnapshotExpiry returns the answer of the snapshot about the end of the key.
func SnapshotExpiry(k *ForeignKey) ExpiryAnswer {
	a := k.snap.expiry()
	return ExpiryAnswer{Earliest: a.earliest, Any: a.any, Agree: a.agree, Marked: a.marked}
}

// SnapshotUsers returns the user IDs of the snapshot in order.
func SnapshotUsers(k *ForeignKey) []SnapUser {
	var out []SnapUser
	for _, u := range k.snap.users {
		su := SnapUser{Text: string(u.text), Revoked: u.revoked, Signed: u.signed, Flags: u.flags, Primary: u.primary, Expires: u.expires,
			SigExpires: u.sigExpires, Weak: u.weak, AnyStrong: u.anyStrong, Tied: u.tied}
		for _, p := range u.prefs {
			su.Prefs = append(su.Prefs, SnapPref{p.typ, p.data})
		}
		out = append(out, su)
	}
	return out
}

// SnapshotSubkeys returns the subkeys of the snapshot in order.
func SnapshotSubkeys(k *ForeignKey) []SnapSubkey {
	var out []SnapSubkey
	for _, s := range k.snap.subkeys {
		out = append(out, SnapSubkey{Fingerprint: s.fp, Body: s.body, Revoked: s.revoked, Bound: s.bound, Weak: s.weak, AnyStrong: s.anyStrong, Tied: s.tied})
	}
	return out
}

// SnapshotNewest is the creation time of the newest signature that counts anywhere in the certificate.
func SnapshotNewest(k *ForeignKey) time.Time { return k.snap.newest }

// SnapshotPrimaryUserID is the text of the user ID that the snapshot answers to "which is the primary".
func SnapshotPrimaryUserID(k *ForeignKey) (string, bool) {
	i, ok := k.snap.primaryUserID()
	if !ok {
		return "", false
	}
	return string(k.snap.users[i].text), true
}
