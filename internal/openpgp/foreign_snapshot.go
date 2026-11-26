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
//
// Every choice of "the newest" signature here is made by [outranks]: the newest by time, whatever its hash,
// and a tie in time is broken by what the signatures say and never by where they stand in the file, so that
// the order of the packets, which the person who writes the file may choose, decides nothing.

// snapSig is a signature that counted, as the reader keeps it for the snapshot: what the view says of it,
// the packet that the reader wrote for it, whether its hashed area has a signature expiration time (type 3),
// which this layer does not judge, and, for a certification, the preference subpackets of its hashed area
// that a later signature may carry over.
type snapSig struct {
	sig        ForeignSignature
	raw        []byte
	sigExpires bool
	prefs      []subpacket
}

// earlierEnd tells whether the key end x is earlier than the key end y. No end (the zero time) is the
// latest: a key that never ends ends after every key that does.
func earlierEnd(x, y time.Time) bool {
	switch {
	case x.IsZero():
		return false
	case y.IsZero():
		return true
	}
	return x.Before(y)
}

// outranks tells whether the signature b is chosen over the signature a as the newest. The newer creation
// time wins, whatever the hash. In a tie of the time the conservative one wins, in this order: the earlier
// end of the key (no end counts as the latest), then the smaller bytes of the packet that the reader wrote.
// It does not depend on the order of the file. It is the one helper of every "newest" choice of the snapshot.
func outranks(b, a snapSig) bool {
	if !b.sig.Created.Equal(a.sig.Created) {
		return b.sig.Created.After(a.sig.Created)
	}
	if !b.sig.KeyExpires.Equal(a.sig.KeyExpires) {
		return earlierEnd(b.sig.KeyExpires, a.sig.KeyExpires)
	}
	return bytes.Compare(b.raw, a.raw) < 0
}

// newestSig is the signature of the list that [outranks] all the others that pass keep, its place in the
// list, and false when none passes. tied is true when the choice was made by the bytes of the packets: some
// other signature that passes keep has the same time and the same end of the key and is another packet. Such
// a choice does not depend on the order of the file, and it is arbitrary; a ceremony shows it.
func newestSig(sigs []snapSig, keep func(ForeignSignature) bool) (best snapSig, idx int, tied, ok bool) {
	for i, s := range sigs {
		if keep(s.sig) && (!ok || outranks(s, best)) {
			best, idx, ok = s, i, true
		}
	}
	if !ok {
		return best, -1, false, false
	}
	for i, s := range sigs {
		if i != idx && keep(s.sig) && s.sig.Created.Equal(best.sig.Created) && s.sig.KeyExpires.Equal(best.sig.KeyExpires) && !bytes.Equal(s.raw, best.raw) {
			tied = true
			break
		}
	}
	return best, idx, tied, true
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
	// signed is the time of its newest self-signature that counts, of any hash.
	signed time.Time
	// flags, primary and expires are what that newest self-signature says (see [outranks]): the first key
	// flags octet, the primary mark, and the end of the key (zero if none). prefs are its carried
	// subpackets. They describe what the person last chose, whatever the hash of that signature.
	flags   uint8
	primary bool
	expires time.Time
	prefs   []subpacket
	// sigExpires is true when that signature has a signature expiration time (type 3), which this layer
	// does not judge.
	sigExpires bool
	// weak is true when that signature is made with SHA-1, and anyStrong when some self-signature of the
	// user ID that counts is not. A user ID with weak true and anyStrong false is held by SHA-1 only.
	weak, anyStrong bool
	// tied is true when the choice of that signature was made by the bytes of the packets (see [newestSig]).
	tied bool
}

// snapSubkey is a subkey of the certificate, which a binding of the primary confirms.
type snapSubkey struct {
	fp      []byte // 20 bytes
	body    []byte // the body of its public subkey packet
	revoked bool
	bound   time.Time // the time of its newest binding that counts, of any hash
	// weak is true when that newest binding is made with SHA-1, and anyStrong when some binding that
	// counts is not.
	weak, anyStrong bool
	// tied is true when the choice of the newest binding was made by the bytes of the packets.
	tied bool
}

// snapDirect is the newest direct-key signature that counts, which is a source of the key's expiry.
type snapDirect struct {
	have       bool
	expires    time.Time
	sigExpires bool
	tied       bool // the choice of the newest was made by the bytes of the packets
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
	newest  time.Time
	direct  snapDirect
	users   []snapUserID
	subkeys []snapSubkey
}

// expiryAnswer is what the snapshot says of the end of the key. Programs differ in where they look for it
// (the primary user ID, any user ID, the direct-key signature), so the answer keeps every source apart: the
// newest self-signature of each live user ID and the newest direct-key signature.
type expiryAnswer struct {
	// earliest is the earliest end among the sources that have one, the one that no program will believe
	// later than; zero when no source has an end.
	earliest time.Time
	// any is true when there is at least one source. Zero in earliest with any true means that the sources
	// all say that the key never ends.
	any bool
	// agree is true when every source says the same end (or all say none).
	agree bool
	// marked is true when the newest signature of some source has a signature expiration time (type 3).
	marked bool
}

// expiry answers the three questions of the end of the key, and marks a source that this layer does not
// judge. A builder that adds a user ID or certifies another key must refuse when the sources do not agree or
// one is marked.
func (s *fkSnapshot) expiry() expiryAnswer {
	a := expiryAnswer{agree: true}
	var first time.Time // the end of the first source: agreement is equality with it, whatever the order
	add := func(expires time.Time, sigExpires bool) {
		if !a.any {
			a.any, a.earliest, first = true, expires, expires
		} else {
			a.agree = a.agree && expires.Equal(first)
			if earlierEnd(expires, a.earliest) {
				a.earliest = expires
			}
		}
		a.marked = a.marked || sigExpires
	}
	if s.direct.have {
		add(s.direct.expires, s.direct.sigExpires)
	}
	for _, u := range s.users {
		if !u.revoked {
			add(u.expires, u.sigExpires)
		}
	}
	return a
}

// noteNewest raises newest to t.
func (o *fkOutput) noteNewest(t time.Time) {
	if t.After(o.newest) {
		o.newest = t
	}
}

// noteCounted notes the times of signatures that counted and are in the certificate.
func (o *fkOutput) noteCounted(counted []snapSig) {
	for _, c := range counted {
		o.noteNewest(c.sig.Created)
	}
}

// addUser adds the user ID of a group that goes into the certificate: counted are the signatures of the
// primary on it that counted, once each.
func (o *fkOutput) addUser(text []byte, counted []snapSig) {
	o.noteCounted(counted)
	sigs := make([]ForeignSignature, len(counted))
	for i, c := range counted {
		sigs[i] = c.sig
	}
	view := ForeignUserID{Signatures: sigs}
	raws := make([][]byte, len(counted))
	for i, c := range counted {
		raws[i] = c.raw
	}
	summariseUserID(&view, raws)
	u := snapUserID{text: bytes.Clone(text), revoked: view.Revoked}
	for _, c := range counted {
		if isCertification(c.sig.Type) {
			u.signed = laterOf(u.signed, c.sig.Created)
			u.anyStrong = u.anyStrong || c.sig.Status == SignatureValid
		}
	}
	if src, _, tied, ok := newestSig(counted, func(s ForeignSignature) bool { return isCertification(s.Type) }); ok {
		u.flags, u.primary, u.expires, u.prefs = src.sig.KeyFlags, src.sig.Primary, src.sig.KeyExpires, src.prefs
		u.sigExpires, u.weak, u.tied = src.sigExpires, src.sig.Status == SignatureValidWeakHash, tied
	}
	o.users = append(o.users, u)
}

// laterOf is the later of two times.
func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// addSubkey adds the subkey of a group that goes into the certificate.
func (o *fkOutput) addSubkey(fp, body []byte, counted []snapSig) {
	o.noteCounted(counted)
	sigs := make([]ForeignSignature, len(counted))
	for i, c := range counted {
		sigs[i] = c.sig
	}
	view := ForeignSubkey{Signatures: sigs}
	raws := make([][]byte, len(counted))
	for i, c := range counted {
		raws[i] = c.raw
	}
	summariseSubkey(&view, raws)
	k := snapSubkey{fp: bytes.Clone(fp), body: bytes.Clone(body), revoked: view.Revoked}
	for _, c := range counted {
		if c.sig.Type == sigSubkeyBinding {
			k.anyStrong = k.anyStrong || c.sig.Status == SignatureValid
		}
	}
	if src, _, tied, ok := newestSig(counted, func(s ForeignSignature) bool { return s.Type == sigSubkeyBinding }); ok {
		k.bound, k.weak, k.tied = src.sig.Created, src.sig.Status == SignatureValidWeakHash, tied
	}
	o.subSnaps = append(o.subSnaps, k)
}

// snapshot is the snapshot of the key whose walk and verifier these are, once the judging of every
// signature is done.
func (o *fkOutput) snapshot(w *fkWalk, v *fkVerifier) fkSnapshot {
	s := fkSnapshot{
		packet:  bytes.Clone(w.primaryPacket),
		body:    bytes.Clone(w.primaryBody),
		fp:      bytes.Clone(v.fp),
		created: v.created,
		revoked: o.revoked,
		newest:  o.newest,
		users:   o.users,
		subkeys: o.subSnaps,
	}
	if d, _, tied, ok := newestSig(o.direct, func(ForeignSignature) bool { return true }); ok {
		s.direct = snapDirect{have: true, expires: d.sig.KeyExpires, sigExpires: d.sigExpires, tied: tied}
	}
	return s
}
