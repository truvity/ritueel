package openpgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// This file decides what the signatures of a foreign key are worth. A signature counts only when the
// primary made it, it is version 4, it uses SHA-256, SHA-384 or SHA-512, it has no critical subpacket
// that the reader does not understand, and go-crypto verifies it with the primary key. The fields
// that a person sees are read from the hashed area, which the signature covers, and nowhere else.

// Signature types (RFC 9580, section 5.2.1) that this file adds to those of frame.go.
const (
	sigCertGeneric    = 0x10
	sigDirectKey      = 0x1F
	sigSubkeyRevoke   = 0x28
	sigCertRevocation = 0x30
)

// Signature subpacket types (RFC 9580, section 5.2.3) that this file adds to those of frame.go.
const (
	spPrimaryUserID = 25
)

// understoodSubpackets are the subpacket types that may be critical in a signature that counts: the
// ones that the reader reads (2, 3, 9, 16, 25, 27, 29, 32, 33) and the ones that only state a
// preference or a note and cannot change what the signature says (11, 21 to 24, 26, 28, 30, 39).
// Every other type, notation data and the exportable, trust, regular expression, revocable,
// revocation key, target, intended recipient and key block types included, is not understood.
var understoodSubpackets = map[byte]bool{
	2: true, 3: true, 9: true, 11: true, 16: true, 21: true, 22: true, 23: true, 24: true, 25: true,
	26: true, 27: true, 28: true, 29: true, 30: true, 32: true, 33: true, 39: true,
}

// fkVerifier holds the primary key as go-crypto reads it, and the facts that decide whether a
// signature is the primary's.
type fkVerifier struct {
	pk      *packet.PublicKey
	fp      []byte
	keyID   []byte
	fpHex   string
	idHex   string
	created time.Time
	alg     byte
}

// newForeignVerifier computes the fingerprint of the primary and has go-crypto read its public key
// packet: the two must agree on the version, the algorithm and the fingerprint, or the file is an
// [ErrForeignForm].
func newForeignVerifier(w *fkWalk) (*fkVerifier, error) {
	fp, err := foreignFingerprint(w.primaryBody)
	if err != nil {
		return nil, err
	}
	pk, err := agreePublic(w.primaryPacket, w.primaryBody, fp, false)
	if err != nil {
		return nil, err
	}
	if byte(pk.PubKeyAlgo) != w.pub.alg.ID {
		return nil, fail(ErrForeignForm, "go-crypto does not read the public key of the primary as it is read here")
	}
	v := &fkVerifier{pk: pk, fp: fp, keyID: fp[12:], created: w.pub.created, alg: w.pub.alg.ID}
	v.fpHex, v.idHex = fingerprintHex(fp)
	return v, nil
}

// issuer is what a signature says about who made it.
type issuer uint8

const (
	// issuerUnknown is a signature that does not say, or says in a form that the reader does not read,
	// or says only in its unhashed area (which nothing protects), or is not version 4.
	issuerUnknown issuer = iota
	// issuerPrimary is a signature that names the primary.
	issuerPrimary
	// issuerOther is a signature that names another key in its hashed area: its fingerprint, or its
	// key ID when it has no fingerprint, is not the primary's.
	issuerOther
)

// fkHead is what is read of a signature before it is judged: its version and type, the fixed fields of
// a version 4 signature, its areas, and who it says made it.
type fkHead struct {
	version byte
	typ     byte
	algo    byte
	hash    byte
	parsed  bool // a version 4 signature whose areas read, each with at most maxBindingSubpackets
	areas   sigAreas
	issuer  issuer
}

// isRevocationType tells whether a type is a revocation: of the key (0x20), of a subkey (0x28) or of a
// certification (0x30).
func isRevocationType(t byte) bool {
	return t == sigKeyRevocation || t == sigSubkeyRevoke || t == sigCertRevocation
}

// claimed tells whether the primary has to answer for the signature: it names the primary, or it is a
// revocation that is not provably another key's. A revocation that cannot be read must not hide behind
// that: it is listed, with the status unreadable, on the component that it stands on.
func (h fkHead) claimed() bool {
	switch h.issuer {
	case issuerPrimary:
		return true
	case issuerOther:
		return false
	}
	return isRevocationType(h.typ)
}

// head reads the head of a signature. A version 3 signature names the primary by its key ID, and
// anything else of it is unknown; a version 4 signature names its issuer by its hashed issuer
// fingerprint, or by its hashed issuer key ID when it has no fingerprint, and by its issuer key ID in
// the unhashed area only to name the primary (which is how gpg writes old signatures); a signature of
// another version names nothing.
func (v *fkVerifier) head(s fkSig) fkHead {
	var h fkHead
	b := s.body
	if len(b) < 2 {
		return h
	}
	h.version = b[0]
	switch b[0] {
	case 3:
		if len(b) >= 17 {
			h.typ, h.algo, h.hash = b[2], b[15], b[16]
			if bytes.Equal(b[7:15], v.keyID) {
				h.issuer = issuerPrimary
			}
		}
	case 4:
		h.typ = b[1]
		if len(b) >= 4 {
			h.algo, h.hash = b[2], b[3]
		}
		if scanAreasOf(errFrame, b) == nil {
			if a, err := splitSig(b); err == nil {
				h.areas, h.parsed = a, true
				h.issuer = v.issuerV4(a)
			}
		}
	default:
		h.typ = b[1]
	}
	return h
}

// issuerV4 reads who a version 4 signature says made it.
func (v *fkVerifier) issuerV4(a sigAreas) issuer {
	if count(a.hashed, spIssuerFingerprint) > 0 {
		fp, ok := find(a.hashed, spIssuerFingerprint)
		switch {
		case !ok:
			return issuerUnknown
		case len(fp) == 21 && fp[0] == 4:
			if bytes.Equal(fp[1:], v.fp) {
				return issuerPrimary
			}
			return issuerOther
		case len(fp) == 33 && (fp[0] == 5 || fp[0] == 6):
			return issuerOther // the fingerprint of a key of another version
		}
		return issuerUnknown
	}
	if count(a.hashed, spIssuerKeyID) > 0 {
		id, ok := find(a.hashed, spIssuerKeyID)
		switch {
		case !ok || len(id) != 8:
			return issuerUnknown
		case bytes.Equal(id, v.keyID):
			return issuerPrimary
		}
		return issuerOther
	}
	if id, ok := find(a.unhashed, spIssuerKeyID); ok && bytes.Equal(id, v.keyID) {
		return issuerPrimary
	}
	return issuerUnknown
}

// hasUnknownCritical tells whether either area has a critical subpacket of a type that is not in
// understoodSubpackets.
func (h fkHead) hasUnknownCritical() bool {
	for _, area := range [][]subpacket{h.areas.hashed, h.areas.unhashed} {
		for _, sp := range area {
			if sp.critical && !understoodSubpackets[sp.typ] {
				return true
			}
		}
	}
	return false
}

// hashName names a signature hash by its number (RFC 9580, section 9.5).
func hashName(id byte) string {
	names := map[byte]string{
		1: "MD5", 2: "SHA-1", 3: "RIPEMD-160", 8: "SHA-256", 9: "SHA-384", 10: "SHA-512",
		11: "SHA-224", 12: "SHA3-256", 14: "SHA3-512",
	}
	if n, ok := names[id]; ok {
		return n
	}
	return fmt.Sprintf("hash %d", id)
}

// hashStatus is the status that a signature hash gives, or 0 when the hash may go on to be verified.
// SHA-256, SHA-384 and SHA-512 are strong; SHA-1 is weak, and a SHA-1 signature that verifies still
// proves that the key made it, so it goes on to be verified and counts with the status
// [SignatureValidWeakHash]. MD5, RIPEMD-160 and the other obsolete hashes never count.
func hashStatus(id byte) SignatureStatus {
	switch id {
	case 8, 9, 10, 2:
		return 0
	case 1, 3, 4, 5, 6, 7:
		return SignatureWeakHash
	}
	return SignatureHashNotAccepted
}

// safely runs f and turns a panic of a reader into an error, so that one signature that a library
// cannot read costs that signature and not the file.
func safely(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errFrame
		}
	}()
	return f()
}

// fillFields reads what a person sees from the hashed area: the creation time (required, once, four
// bytes), and the optional signature expiration, key expiration, key flags, primary user ID flag
// and reason for revocation, each at most once. keyCreated is the creation of the key that the key
// expiration counts from. It returns false for a signature whose hashed area is not in that form.
func fillFields(fs *ForeignSignature, a sigAreas, keyCreated time.Time) bool {
	once := func(typ byte, min, max int) ([]byte, bool, bool) {
		switch count(a.hashed, typ) {
		case 0:
			return nil, false, true
		case 1:
			d, _ := find(a.hashed, typ)
			return d, true, len(d) >= min && len(d) <= max
		}
		return nil, false, false
	}
	at := func(d []byte) time.Time { return time.Unix(int64(binary.BigEndian.Uint32(d)), 0).UTC() }
	d, ok, good := once(spCreationTime, 4, 4)
	if !ok || !good {
		return false
	}
	fs.Created = at(d)
	if d, ok, good = once(spSigExpiration, 4, 4); !good {
		return false
	} else if ok && binary.BigEndian.Uint32(d) != 0 {
		fs.Expires = fs.Created.Add(time.Duration(binary.BigEndian.Uint32(d)) * time.Second)
	}
	if d, ok, good = once(spKeyExpiration, 4, 4); !good {
		return false
	} else if ok && binary.BigEndian.Uint32(d) != 0 {
		fs.KeyExpires = keyCreated.Add(time.Duration(binary.BigEndian.Uint32(d)) * time.Second)
	}
	if d, ok, good = once(spKeyFlags, 1, 255); !good {
		return false
	} else if ok {
		fs.KeyFlags = d[0]
	}
	if d, ok, good = once(spPrimaryUserID, 1, 1); !good {
		return false
	} else if ok {
		fs.Primary = d[0] != 0
	}
	if d, ok, good = once(spRevocationReason, 1, 255); !good {
		return false
	} else if ok {
		fs.Reason, fs.HasReason = d[0], true
	}
	return true
}

// evaluate judges one signature that the primary claims. check is go-crypto's verification for the
// kind of signature, run only after every cheaper test has passed.
func (v *fkVerifier) evaluate(s fkSig, h fkHead, keyCreated time.Time, check func(*packet.Signature) error) ForeignSignature {
	fs := ForeignSignature{Type: h.typ, Hash: hashName(h.hash), Status: SignatureUnreadable}
	if h.version != 4 || !h.parsed || !fillFields(&fs, h.areas, keyCreated) {
		return fs
	}
	if h.hasUnknownCritical() {
		fs.Status = SignatureUnknownCritical
		return fs
	}
	if st := hashStatus(h.hash); st != 0 {
		fs.Status = st
		return fs
	}
	fs.Status = SignatureNotVerified
	if h.algo != v.alg {
		return fs
	}
	var sig *packet.Signature
	err := safely(func() error {
		p, err := packet.Read(bytes.NewReader(s.raw))
		if err != nil {
			return err
		}
		var ok bool
		if sig, ok = p.(*packet.Signature); !ok {
			return errFrame
		}
		return nil
	})
	if err != nil || sig.Version != 4 || byte(sig.SigType) != h.typ || !sig.CreationTime.Equal(fs.Created) {
		fs.Status = SignatureUnreadable
		return fs
	}
	if safely(func() error { return check(sig) }) == nil {
		fs.Status = SignatureValid
		if h.hash == 2 {
			fs.Status = SignatureValidWeakHash
		}
	}
	return fs
}

// isCertification tells whether a type is one of the four certifications of a user ID.
func isCertification(t byte) bool { return t >= sigCertGeneric && t <= sigPositiveCertification }

// keyLevel judges the signatures on the primary key itself: the direct-key signatures and the key
// revocations that it claims, and a count of the others. unreadable counts the revocations that could
// not be used.
func (v *fkVerifier) keyLevel(w *fkWalk) (sigs []ForeignSignature, other, unreadable int) {
	for _, s := range w.keyT.sigs {
		h := v.head(s)
		switch {
		case !h.claimed():
			other++
		case h.typ == sigDirectKey:
			sigs = append(sigs, v.evaluate(s, h, v.created, func(g *packet.Signature) error { return v.pk.VerifyDirectKeySignature(g) }))
		case h.typ == sigKeyRevocation:
			sigs = append(sigs, v.evaluate(s, h, v.created, func(g *packet.Signature) error { return v.pk.VerifyRevocationSignature(g) }))
		default:
			sigs = append(sigs, misplaced(h))
		}
	}
	return sigs, other, unusableRevocations(sigs)
}

// unusableRevocations counts the revocations in a list that the primary claims and that the reader could
// not use: unreadable, with a critical subpacket that it does not understand, or with a hash that it does
// not take. A signature that does not verify is not counted: it was read and it is not the primary's.
func unusableRevocations(sigs []ForeignSignature) int {
	n := 0
	for _, s := range sigs {
		if !isRevocationType(s.Type) {
			continue
		}
		switch s.Status {
		case SignatureUnreadable, SignatureUnknownCritical, SignatureWeakHash, SignatureHashNotAccepted:
			n++
		}
	}
	return n
}

// misplaced is the entry for a signature of the primary of a type that does not belong where it
// stands.
func misplaced(h fkHead) ForeignSignature {
	return ForeignSignature{Type: h.typ, Status: SignatureMisplaced, Hash: hashName(h.hash)}
}

// userIDs judges the signatures on each user ID and returns the user IDs and the number of them that
// have a valid self-signature.
func (v *fkVerifier) userIDs(w *fkWalk) (ids []ForeignUserID, valid int) {
	for _, u := range w.users {
		text := string(u.text)
		fu := ForeignUserID{Text: text}
		for _, s := range u.t.sigs {
			h := v.head(s)
			switch {
			case !h.claimed() && isCertification(h.typ):
				fu.Certifications++
			case !h.claimed():
				fu.OtherSignatures++
			case isCertification(h.typ) || h.typ == sigCertRevocation:
				fu.Signatures = append(fu.Signatures, v.evaluate(s, h, v.created, func(g *packet.Signature) error {
					return v.pk.VerifyUserIdSignature(text, v.pk, g)
				}))
			default:
				fu.Signatures = append(fu.Signatures, misplaced(h))
			}
		}
		summariseUserID(&fu)
		fu.UnreadableRevocations = unusableRevocations(fu.Signatures)
		if fu.Valid {
			valid++
		}
		ids = append(ids, fu)
	}
	return ids, valid
}

// hardRevocation tells whether a revocation cannot be undone by a later signature: it has no reason, or
// the reason is "no reason" (0), "key material compromised" (2) or a code that is not known. Only
// "superseded" (1), "retired" (3) and "user ID no longer valid" (32) are soft.
func hardRevocation(s *ForeignSignature) bool {
	return !s.HasReason || (s.Reason != 1 && s.Reason != 3 && s.Reason != 32)
}

// revocationOf picks the revocation that revokes: a hard one whatever its date (the newest), or else a
// soft one that is not older than the newest valid signature that it revokes (when there is one). It
// returns nil when nothing revokes.
func revocationOf(revs []*ForeignSignature, newest *ForeignSignature) *ForeignSignature {
	var hard, soft *ForeignSignature
	for _, r := range revs {
		switch {
		case hardRevocation(r) && (hard == nil || !r.Created.Before(hard.Created)):
			hard = r
		case !hardRevocation(r) && (soft == nil || !r.Created.Before(soft.Created)):
			soft = r
		}
	}
	switch {
	case hard != nil:
		return hard
	case soft != nil && (newest == nil || !soft.Created.Before(newest.Created)):
		return soft
	}
	return nil
}

// summariseUserID fills what the newest valid self-signature and the revocations say.
func summariseUserID(fu *ForeignUserID) {
	var self *ForeignSignature
	var revs []*ForeignSignature
	strong := false
	for i := range fu.Signatures {
		s := &fu.Signatures[i]
		if !s.Status.Counts() {
			continue
		}
		switch {
		case isCertification(s.Type):
			strong = strong || s.Status == SignatureValid
			if self == nil || !s.Created.Before(self.Created) {
				self = s
			}
		case s.Type == sigCertRevocation:
			revs = append(revs, s)
		}
	}
	if self != nil {
		fu.Valid, fu.WeakHash = true, !strong
		fu.Created, fu.KeyExpires, fu.KeyFlags, fu.Primary = self.Created, self.KeyExpires, self.KeyFlags, self.Primary
	}
	if r := revocationOf(revs, self); r != nil {
		fu.Revoked, fu.RevokedAt = true, r.Created
	}
}

// subkeys judges the signatures on each subkey. A subkey that go-crypto cannot read has its claimed
// signatures marked unreadable: they cannot be verified.
func (v *fkVerifier) subkeys(w *fkWalk) []ForeignSubkey {
	var out []ForeignSubkey
	for _, s := range w.subs {
		fs := ForeignSubkey{Algorithm: s.pub.alg, Created: s.pub.created, Form: s.form}
		fs.Fingerprint, fs.KeyID = fingerprintHex(s.fp)
		sub, subErr := s.gopk, error(nil)
		if sub == nil {
			subErr = safely(func() error {
				var err error
				sub, err = goCryptoPublic(s.pubPacket)
				return err
			})
		}
		for _, g := range s.t.sigs {
			h := v.head(g)
			switch {
			case !h.claimed():
				fs.OtherSignatures++
			case subErr != nil && (h.typ == sigSubkeyBinding || h.typ == sigSubkeyRevoke):
				fs.Signatures = append(fs.Signatures, ForeignSignature{Type: h.typ, Status: SignatureUnreadable, Hash: hashName(h.hash)})
			case h.typ == sigSubkeyBinding:
				fs.Signatures = append(fs.Signatures, v.evaluate(g, h, s.pub.created, func(x *packet.Signature) error { return v.pk.VerifyKeySignature(sub, x) }))
			case h.typ == sigSubkeyRevoke:
				fs.Signatures = append(fs.Signatures, v.evaluate(g, h, s.pub.created, func(x *packet.Signature) error { return v.pk.VerifySubkeyRevocationSignature(x, sub) }))
			default:
				fs.Signatures = append(fs.Signatures, misplaced(h))
			}
		}
		summariseSubkey(&fs)
		fs.UnreadableRevocations = unusableRevocations(fs.Signatures)
		out = append(out, fs)
	}
	return out
}

// summariseSubkey fills what the newest valid binding and the revocations say.
func summariseSubkey(fs *ForeignSubkey) {
	var bind *ForeignSignature
	var revs []*ForeignSignature
	strong := false
	for i := range fs.Signatures {
		s := &fs.Signatures[i]
		if !s.Status.Counts() {
			continue
		}
		switch s.Type {
		case sigSubkeyBinding:
			strong = strong || s.Status == SignatureValid
			if bind == nil || !s.Created.Before(bind.Created) {
				bind = s
			}
		case sigSubkeyRevoke:
			revs = append(revs, s)
		}
	}
	if bind != nil {
		fs.Bound, fs.WeakHash = true, !strong
		fs.BoundAt, fs.Flags, fs.Expires = bind.Created, bind.KeyFlags, bind.KeyExpires
	}
	fs.Revoked = revocationOf(revs, bind) != nil
}

// countClaimed counts the signatures in the file that the primary has to answer for, which are the ones
// that are verified, before any of them is.
func (v *fkVerifier) countClaimed(w *fkWalk) int {
	n := 0
	count := func(t *fkTarget) {
		for _, s := range t.sigs {
			if v.head(s).claimed() {
				n++
			}
		}
	}
	count(&w.keyT)
	for _, u := range w.users {
		count(&u.t)
	}
	for _, s := range w.subs {
		count(&s.t)
	}
	return n
}
