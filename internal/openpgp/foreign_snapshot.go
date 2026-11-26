package openpgp

import (
	"bytes"
	"time"
)

// This file is the snapshot of a foreign key: what the signing of an adopted key is allowed to know of
// the key, written by the reader out of the signatures that counted and out of nothing else. The
// exported view of [ForeignKey] is for reading by a person, and a caller can change it: no builder reads
// it. A builder reads the snapshot, which is unexported and is filled once, when the reader makes the
// certificate, and which holds exactly what the certificate holds: a key read from its export
// ([ReadForeignKey]) and the same key read from [ForeignKey.Certificate] ([ReadForeignCertificate]) have
// the same snapshot. Whatever the file said and the certificate left out (a certification of another key,
// a signature that does not count, a user ID or a subkey that nothing confirms) is not in it.

// snapSig is a signature that counted, as the reader keeps it for the snapshot: what the view says of it,
// and, for a certification, the preference subpackets of its hashed area that a later signature may
// carry over.
type snapSig struct {
	sig   ForeignSignature
	prefs []subpacket
}

// carriedTypes are the subpacket types of a self-signature that a later one may carry over as they are,
// in the order in which a later signature writes them: the preferred symmetric algorithms (11), hash
// algorithms (21), compression algorithms (22), the key server preferences (23), the features (30) and
// the preferred AEAD ciphersuites (39). Every other type is dropped.
var carriedTypes = []byte{11, 21, 22, 23, 30, 39}

// maxCarried is the most octets of the contents of one carried subpacket. A longer one is dropped.
const maxCarried = 32

// carriedSubpackets picks from a hashed area the subpackets that a later signature carries over: the
// types of [carriedTypes] that occur once, with at most [maxCarried] octets. A type that occurs twice is
// dropped, since a verifier may take either of them. The critical bit is not carried: a preference
// is advice, and a reader that does not know the type should skip it and not refuse the signature.
func carriedSubpackets(hashed []subpacket) []subpacket {
	var out []subpacket
	for _, typ := range carriedTypes {
		if count(hashed, typ) != 1 {
			continue
		}
		data, _ := find(hashed, typ)
		if len(data) > maxCarried {
			continue
		}
		out = append(out, subpacket{typ: typ, data: bytes.Clone(data)})
	}
	return out
}

// snapUserID is a user ID of the certificate with a self-signature that counts.
type snapUserID struct {
	text []byte // the bytes of the user ID packet, exactly
	// revoked is the verdict of the view: a hard revocation, or a soft one that is not older than the
	// newest self-signature. A user ID is live when it is not revoked.
	revoked bool
	// signed is the time of its newest self-signature that counts.
	signed time.Time
	// flags, primary and expires are what its newest self-signature says (the newest strong one when
	// there is one): the first key flags octet, the primary mark, and the end of the key (zero if none).
	flags   uint8
	primary bool
	expires time.Time
	// prefs are the carried subpackets of that self-signature.
	prefs []subpacket
}

// snapSubkey is a subkey of the certificate, which a binding of the primary confirms.
type snapSubkey struct {
	fp      []byte // 20 bytes
	body    []byte // the body of its public subkey packet
	revoked bool
	bound   time.Time // the time of its newest binding that counts
}

// fkSnapshot is the snapshot: the primary, and what the signatures of the primary say of the key, the
// user IDs and the subkeys.
type fkSnapshot struct {
	packet  []byte // the public key packet of the primary, whole, with the shortest header
	body    []byte // its body
	fp      []byte // 20 bytes
	created time.Time
	// revoked is true when a key revocation counts.
	revoked bool
	// newest is the creation time of the newest signature that counts anywhere in the certificate. A new
	// signature is dated after it, so that a signature dated in the future that the file held does not
	// outrank it.
	newest time.Time
	// expires is the end of the key that its newest self-signature says (a direct-key signature or the
	// certification of a user ID that is not revoked; the later one in the certificate when the times are
	// equal), and zero if that signature has no key expiration time.
	expires time.Time
	users   []snapUserID
	subkeys []snapSubkey
}

// expiryCandidate is the newest self-signature that can give the expiry of the key, so far.
type expiryCandidate struct {
	have    bool
	created time.Time
	expires time.Time
}

// noteNewest raises newest to t.
func (o *fkOutput) noteNewest(t time.Time) {
	if t.After(o.newest) {
		o.newest = t
	}
}

// noteExpiry offers a self-signature that counts as the source of the key's expiry; the later one in the
// certificate wins when the times are equal.
func (o *fkOutput) noteExpiry(s ForeignSignature) {
	if !o.expiry.have || !s.Created.Before(o.expiry.created) {
		o.expiry = expiryCandidate{have: true, created: s.Created, expires: s.KeyExpires}
	}
}

// noteCounted notes the times of signatures that counted and are in the certificate.
func (o *fkOutput) noteCounted(counted []snapSig) {
	for _, c := range counted {
		o.noteNewest(c.sig.Created)
	}
}

// addUser adds the user ID of a group that goes into the certificate: counted are the signatures of the
// primary on it that counted, once each, in the order of the certificate.
func (o *fkOutput) addUser(text []byte, counted []snapSig) {
	o.noteCounted(counted)
	sigs := make([]ForeignSignature, len(counted))
	for i, c := range counted {
		sigs[i] = c.sig
	}
	view := ForeignUserID{Signatures: sigs}
	summariseUserID(&view)
	u := snapUserID{
		text: bytes.Clone(text), revoked: view.Revoked,
		flags: view.KeyFlags, primary: view.Primary, expires: view.KeyExpires,
	}
	for _, c := range counted {
		if !isCertification(c.sig.Type) {
			continue
		}
		if c.sig.Created.After(u.signed) {
			u.signed = c.sig.Created
		}
		if !view.Valid {
			continue
		}
		// the source of the fields is the last of the signatures with the creation time and the
		// strength that summariseUserID chose
		if c.sig.Created.Equal(view.Created) && (c.sig.Status == SignatureValid) == !view.WeakHash {
			u.prefs = c.prefs
		}
		if !view.Revoked {
			o.noteExpiry(c.sig)
		}
	}
	o.users = append(o.users, u)
}

// addSubkey adds the subkey of a group that goes into the certificate.
func (o *fkOutput) addSubkey(fp, body []byte, counted []snapSig) {
	o.noteCounted(counted)
	sigs := make([]ForeignSignature, len(counted))
	for i, c := range counted {
		sigs[i] = c.sig
	}
	view := ForeignSubkey{Signatures: sigs}
	summariseSubkey(&view)
	o.subSnaps = append(o.subSnaps, snapSubkey{
		fp: bytes.Clone(fp), body: bytes.Clone(body), revoked: view.Revoked, bound: view.BoundAt,
	})
}

// snapshot is the snapshot of the key whose walk and verifier these are, once the judging of every
// signature is done.
func (o *fkOutput) snapshot(w *fkWalk, v *fkVerifier) fkSnapshot {
	return fkSnapshot{
		packet:  bytes.Clone(w.primaryPacket),
		body:    bytes.Clone(w.primaryBody),
		fp:      bytes.Clone(v.fp),
		created: v.created,
		revoked: o.revoked,
		newest:  o.newest,
		expires: o.expiry.expires,
		users:   o.users,
		subkeys: o.subSnaps,
	}
}
