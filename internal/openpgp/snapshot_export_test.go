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
}

// SnapSubkey is a subkey of the snapshot as a test reads it.
type SnapSubkey struct {
	Fingerprint []byte
	Body        []byte
	Revoked     bool
	Bound       time.Time
}

// SnapKey is the key level of the snapshot as a test reads it.
type SnapKey struct {
	Packet, Body, Fingerprint []byte
	Created                   time.Time
	Revoked                   bool
	Newest, Expires           time.Time
}

// SnapshotKey returns the key level of the snapshot.
func SnapshotKey(k *ForeignKey) SnapKey {
	s := k.snap
	return SnapKey{Packet: s.packet, Body: s.body, Fingerprint: s.fp, Created: s.created, Revoked: s.revoked, Newest: s.newest, Expires: s.expires}
}

// SnapshotUsers returns the user IDs of the snapshot in order.
func SnapshotUsers(k *ForeignKey) []SnapUser {
	var out []SnapUser
	for _, u := range k.snap.users {
		su := SnapUser{Text: string(u.text), Revoked: u.revoked, Signed: u.signed, Flags: u.flags, Primary: u.primary, Expires: u.expires}
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
		out = append(out, SnapSubkey{Fingerprint: s.fp, Body: s.body, Revoked: s.revoked, Bound: s.bound})
	}
	return out
}

// SnapshotNewest is the creation time of the newest signature that counts anywhere in the certificate.
func SnapshotNewest(k *ForeignKey) time.Time { return k.snap.newest }
