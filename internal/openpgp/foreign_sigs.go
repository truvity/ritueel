package openpgp

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
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
	// hashed is the number of bytes that the checks of signatures have been charged so far, and err the
	// refusal that the budget [MaxForeignHashedBytes] makes when it is passed.
	hashed int64
	// verifs is the number of public-key verifications charged so far, against [MaxForeignVerifications].
	verifs int
	err    error
}

// chargeVerify counts n public-key verifications against [MaxForeignVerifications], before they are done,
// like [fkVerifier.charge]: it returns false, and keeps the refusal in v.err, when the budget would be
// passed.
func (v *fkVerifier) chargeVerify(n int) bool {
	if v.err != nil {
		return false
	}
	v.verifs += n
	if v.verifs > MaxForeignVerifications {
		v.err = fail(ErrForeignLimit, "the file needs more than MaxForeignVerifications (%d) public-key verifications of signatures", MaxForeignVerifications)
		return false
	}
	return true
}

// charge counts n bytes of hashing against [MaxForeignHashedBytes], before the hashing is done. It
// returns false, and keeps the refusal in v.err for the caller of the judging, when the budget would
// be passed; nothing is hashed after that.
func (v *fkVerifier) charge(n int64) bool {
	if v.err != nil {
		return false
	}
	v.hashed += n
	if v.hashed > MaxForeignHashedBytes {
		v.err = fail(ErrForeignLimit, "the signature checks of the file would hash more than MaxForeignHashedBytes (%d bytes)", int64(MaxForeignHashedBytes))
		return false
	}
	return true
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
// revocation or a subkey binding that is not provably another key's. A revocation that cannot be read must not hide behind
// that: it is listed, with the status unreadable, on the component that it stands on.
func (h fkHead) claimed() bool {
	switch h.issuer {
	case issuerPrimary:
		return true
	case issuerOther:
		return false
	}
	return isRevocationType(h.typ) || h.typ == sigSubkeyBinding
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

// fkCtx is what judging one signature needs besides the signature: the bytes that it covers before its
// own fields, and how to verify it.
type fkCtx struct {
	// data is what the signature hashes before its own fields (RFC 9580, section 5.2.4): the key
	// prefix of the primary, then the key prefix of the subkey, or the user ID or attribute prefix and
	// its body. These are the bytes that the certificate gets, hashed here by this package for the
	// check of the hash tag, and hashed by go-crypto from its own serialisation for the verification.
	data       []byte
	keyCreated time.Time
	// verify is go-crypto's verification of the kind of signature; a signature counts only if it
	// passes.
	verify func(*packet.Signature) error
	// strong, when it is set, is a stricter verification that only changes the view: a signature that
	// passes verify and fails strong counts for the certificate and is reported as not verified.
	strong func(*packet.Signature) error
	// sub, for a binding, is the subkey: a back-signature in the unhashed area that verifies with it
	// is carried over.
	sub *packet.PublicKey
	// back remembers, per subkey, the back-signatures that were already judged (by their bytes), so that
	// a binding that is repeated does not repeat the verification; nil means that it did not verify.
	back map[string][]byte
	// incomplete, for a binding or a subkey revocation, is set when the signature verifies and cannot go
	// into a certificate that the library's key-ring reader reads: see [fkVerifier.evaluate].
	incomplete *bool
}

// hashers are the hashes of the signatures that can count, by their numbers.
var hashers = map[byte]func() hash.Hash{2: sha1.New, 8: sha256.New, 9: sha512.New384, 10: sha512.New}

// tagOK tells whether the two octets that follow the unhashed area of a signature are the first two of its
// digest, which this package computes over data, the hashed fields and the trailer (RFC 9580, section
// 5.2.4). go-crypto does not compare them for a version 4 signature.
func tagOK(hashID byte, a sigAreas, data []byte) bool {
	h := hashers[hashID]
	if h == nil || len(a.rest) < 2 {
		return false
	}
	d := h()
	d.Write(data)
	d.Write(a.fields)
	trailer := []byte{4, 0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(a.fields)))
	d.Write(trailer)
	return bytes.Equal(a.rest[:2], d.Sum(nil)[:2])
}

// canonicalValues tells whether what follows the unhashed area of a signature is the hash tag and the
// signature values of the algorithm, each number in the form of RFC 9580 section 3.2, and nothing
// after them: a signature that is not in this form is not carried over, and its value is never changed.
func canonicalValues(algo byte, rest []byte) bool {
	if len(rest) < 2 {
		return false
	}
	vals := rest[2:]
	n := 0
	switch algo {
	case algoRSA, algoRSASign:
		n = 1
	case algoDSA, algoECDSA, algoEdDSA:
		n = 2
	case algoEd25519:
		return len(vals) == 64
	default:
		return false
	}
	for i := 0; i < n; i++ {
		var err error
		if _, vals, err = readMPI(vals); err != nil {
			return false
		}
	}
	return len(vals) == 0
}

// emitBody writes the body of a signature that has been verified, from the bytes that were verified and
// from nothing else: the fixed fields and the hashed area exactly as they were hashed (a.fields), an
// unhashed area that this package builds (the issuer key ID, the issuer fingerprint when the hashed area
// has none, and a back-signature that was verified), and the hash tag and the values as they stood
// (a.rest), which [canonicalValues] and [tagOK] have judged. Nothing of the unhashed area of the file is
// carried over.
func emitBody(a sigAreas, issuerFP []byte, embedded []byte) []byte {
	subs := []subpacket{{typ: spIssuerKeyID, data: issuerFP[12:]}}
	if count(a.hashed, spIssuerFingerprint) == 0 {
		subs = append(subs, subpacket{typ: spIssuerFingerprint, data: append([]byte{4}, issuerFP...)})
	}
	if embedded != nil {
		subs = append(subs, subpacket{typ: spEmbeddedSignature, data: embedded})
	}
	un := encodeArea(subs)
	body := make([]byte, 0, len(a.fields)+2+len(un)+len(a.rest))
	body = append(body, a.fields...)
	body = append(body, byte(len(un)>>8), byte(len(un)))
	body = append(body, un...)
	return append(body, a.rest...)
}

// readSignature has go-crypto read a signature packet.
func readSignature(raw []byte) (*packet.Signature, error) {
	var sig *packet.Signature
	err := safely(func() error {
		p, err := packet.Read(bytes.NewReader(raw))
		if err != nil {
			return err
		}
		var ok bool
		if sig, ok = p.(*packet.Signature); !ok {
			return errFrame
		}
		return nil
	})
	return sig, err
}

// evaluate judges one signature that the primary claims and, when it counts, returns the packet that the
// certificate gets for it, written by this package (see [emitBody]). The tests run in this order, the
// cheapest first: version and fields, critical subpackets, hash, algorithm, the form of the values, the
// hash tag, then go-crypto's verification.
func (v *fkVerifier) evaluate(s fkSig, h fkHead, c fkCtx) (ForeignSignature, []byte) {
	fs := ForeignSignature{Type: h.typ, Hash: hashName(h.hash), Status: SignatureUnreadable}
	if h.version != 4 || !h.parsed || !fillFields(&fs, h.areas, c.keyCreated) {
		return fs, nil
	}
	if h.hasUnknownCritical() {
		fs.Status = SignatureUnknownCritical
		return fs, nil
	}
	if st := hashStatus(h.hash); st != 0 {
		fs.Status = st
		return fs, nil
	}
	fs.Status = SignatureNotVerified
	if h.algo != v.alg {
		return fs, nil
	}
	if !canonicalValues(h.algo, h.areas.rest) {
		fs.Status = SignatureUnreadable
		return fs, nil
	}
	passes := int64(2) // the hash tag here, and go-crypto's verification
	if c.strong != nil {
		passes++
	}
	if !v.charge(passes * int64(len(c.data)+len(h.areas.fields)+6)) {
		fs.Status = SignatureUnreadable
		return fs, nil
	}
	if !tagOK(h.hash, h.areas, c.data) {
		return fs, nil
	}
	sig, err := readSignature(s.raw)
	if err != nil || sig.Version != 4 || byte(sig.SigType) != h.typ || !sig.CreationTime.Equal(fs.Created) {
		fs.Status = SignatureUnreadable
		return fs, nil
	}
	if !v.chargeVerify(1) {
		fs.Status = SignatureUnreadable
		return fs, nil
	}
	if safely(func() error { return c.verify(sig) }) != nil {
		return fs, nil
	}
	fs.Status = SignatureValid
	if h.hash == 2 {
		fs.Status = SignatureValidWeakHash
	}
	// A binding of a subkey that can sign or certify (key flags 0x02 or 0x01) is complete only with a
	// back-signature that verifies with the subkey's key, in either area; a binding with no key flags
	// subpacket asks for none, as go-crypto's strict pass does (its flag for signing is false when
	// the subpacket is absent). An incomplete binding is not written: the library's key-ring reader refuses a
	// whole certificate that holds one.
	var embedded []byte
	if c.sub != nil {
		var backOK bool
		embedded, backOK = v.backSignature(h.areas, c)
		if fs.KeyFlags&0x03 != 0 && !backOK {
			fs.Status = SignatureNotVerified
			*c.incomplete = true
			return fs, nil
		}
	}
	// The strict pass verifies the binding and, for a subkey that can sign, the cross-signature in it; it is
	// the check that the library's key-ring reader makes of every signature of a subkey, so a signature that
	// fails it is not written.
	if c.strong != nil && (!v.chargeVerify(2) || safely(func() error { return c.strong(sig) }) != nil) {
		if c.incomplete != nil {
			*c.incomplete = true
		}
		if h.typ == sigSubkeyBinding {
			fs.Status = SignatureNotVerified
		}
		return fs, nil
	}
	return fs, wrap(tagSignature, emitBody(h.areas, v.fp, embedded))
}

// backSignature looks for the back-signature (type 0x19) of a binding: the first embedded signature
// subpacket of the hashed area, which the binding covers and which is carried over with it as it stands,
// or else the first of the unhashed area. It returns whether that signature verifies with the subkey over
// the primary and the subkey, and, for one in the unhashed area, its body written again with the
// issuer of the subkey and nothing else from its unhashed area (it is carried over only if it verifies).
// Only the first embedded signature subpacket is tried (go-crypto rejects a binding with two, so such a
// binding does not count), and a result is remembered per subkey, so that a binding that is repeated
// many times does not repeat the work.
func (v *fkVerifier) backSignature(a sigAreas, c fkCtx) (embedded []byte, ok bool) {
	for n, area := range [][]subpacket{a.hashed, a.unhashed} {
		for _, sp := range area {
			if sp.typ != spEmbeddedSignature {
				continue
			}
			if len(sp.data) > maxBindingBody {
				return nil, false
			}
			got, seen := c.back[string(sp.data)]
			if !seen {
				got = v.verifyBack(sp.data, c)
				c.back[string(sp.data)] = got
			}
			if n == 0 {
				return nil, got != nil
			}
			return got, got != nil
		}
	}
	return nil, false
}

// verifyBack judges one embedded signature (its body) and returns its body written again, or nil.
func (v *fkVerifier) verifyBack(body []byte, c fkCtx) []byte {
	e, err := splitSig(body)
	if err != nil || scanAreasOf(errFrame, body) != nil || e.sigType != sigPrimaryKeyBinding ||
		hashStatus(e.hash) != 0 || e.algo != byte(c.sub.PubKeyAlgo) || (fkHead{areas: e}).hasUnknownCritical() ||
		!canonicalValues(e.algo, e.rest) || !v.charge(2*int64(len(c.data)+len(e.fields)+6)) || !tagOK(e.hash, e, c.data) {
		return nil
	}
	sig, err := readSignature(wrap(tagSignature, body))
	if err != nil || sig.Version != 4 || !v.chargeVerify(1) {
		return nil
	}
	verified := safely(func() error {
		hh, err := sig.PrepareVerify()
		if err != nil {
			return err
		}
		if err := v.pk.SerializeForHash(hh); err != nil {
			return err
		}
		if err := c.sub.SerializeForHash(hh); err != nil {
			return err
		}
		return c.sub.VerifySignature(hh, sig)
	}) == nil
	if !verified {
		return nil
	}
	return emitBody(e, c.sub.Fingerprint, nil)
}

// maxBindingBody is the most bytes of an embedded signature that is looked at.
const maxBindingBody = 4096

// isCertification tells whether a type is one of the four certifications of a user ID.
func isCertification(t byte) bool { return t >= sigCertGeneric && t <= sigPositiveCertification }

// fkOutput is what the judging of the signatures decides goes into the certificate, written by this
// package: the packets of each part that passed, in the order of the standard.
type fkOutput struct {
	keySigs [][]byte // direct-key signatures and key revocations of the primary that verify
	comps   [][]byte // per user ID or attribute of the walk, or nil when it is left out
	subs    [][]byte // per subkey of the walk, or nil when it is left out
	dups    int      // the duplicates that were dropped: signatures, user IDs, attributes and subkeys
}

// fkGroup is the occurrences of one user ID, user attribute or subkey that have the same bytes, merged
// into the first of them: their verified signatures go to it, and a signature whose written bytes are
// identical to one already written is written once.
type fkGroup struct {
	first   int               // the place of the first occurrence in the file
	emits   []byte            // the verified signatures, written
	seen    map[string]bool   // the signature packets written so far
	bad     bool              // a user attribute whose body is not a sequence of subpackets
	partial bool              // a binding verified and is not complete
	broken  bool              // a subkey revocation that the library's key-ring reader would refuse: the subkey is left out
	ok      bool              // some occurrence has what the part needs (a certification, a binding)
	back    map[string][]byte // the back-signatures judged for a subkey, by their bytes
}

// add merges the written signature packet of one occurrence into the group, counting a duplicate.
func (g *fkGroup) add(emit []byte, out *fkOutput) {
	if g.seen[string(emit)] {
		out.dups++
		return
	}
	g.seen[string(emit)] = true
	g.emits = append(g.emits, emit...)
}

// groupOf returns the group of a key, making it at place i when it is the first.
func (o *fkOutput) groupOf(groups map[string]*fkGroup, key string, i int) *fkGroup {
	if g, ok := groups[key]; ok {
		o.dups++
		return g
	}
	g := &fkGroup{first: i, seen: map[string]bool{}}
	groups[key] = g
	return g
}

// assemble writes the certificate: the primary key packet, its signatures, the user IDs and attributes
// that passed, each with its signatures, and the subkeys that passed, each with its signatures. Every
// packet is written by this package (new-format headers with the shortest length); every byte of
// content is covered by a signature of the primary that verified.
func (o *fkOutput) assemble(primaryPacket []byte) []byte {
	cert := bytes.Clone(primaryPacket)
	for _, p := range o.keySigs {
		cert = append(cert, p...)
	}
	for _, p := range o.comps {
		cert = append(cert, p...)
	}
	for _, p := range o.subs {
		cert = append(cert, p...)
	}
	return cert
}

// keyData is the prefix that every signature of the primary covers: its public key.
func (v *fkVerifier) keyData(w *fkWalk) []byte { return hashPrefix(w.primaryBody) }

// keyLevel judges the signatures on the primary key itself: the direct-key signatures and the key
// revocations that it claims, and a count of the others. unreadable counts the revocations that could
// not be used, otherRev the key revocations of other keys that are left out.
func (v *fkVerifier) keyLevel(w *fkWalk, out *fkOutput) (sigs []ForeignSignature, other, otherRev, unreadable int) {
	data := v.keyData(w)
	seen := map[string]bool{}
	for _, s := range w.keyT.sigs {
		h := v.head(s)
		var fs ForeignSignature
		var emit []byte
		switch {
		case !h.claimed():
			other++
			if h.typ == sigKeyRevocation {
				otherRev++
			}
			continue
		case h.typ == sigDirectKey:
			fs, emit = v.evaluate(s, h, fkCtx{data: data, keyCreated: v.created, verify: func(g *packet.Signature) error { return v.pk.VerifyDirectKeySignature(g) }})
		case h.typ == sigKeyRevocation:
			fs, emit = v.evaluate(s, h, fkCtx{data: data, keyCreated: v.created, verify: func(g *packet.Signature) error { return v.pk.VerifyRevocationSignature(g) }})
			if strayed(h, fs) {
				other++
				otherRev++
			}
		default:
			fs = misplaced(h)
		}
		sigs = append(sigs, fs)
		switch {
		case emit == nil:
		case seen[string(emit)]:
			out.dups++
		default:
			seen[string(emit)] = true
			out.keySigs = append(out.keySigs, emit)
		}
	}
	return sigs, other, otherRev, unusableRevocations(sigs)
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

// strayed tells whether a revocation-type signature (0x20, 0x28, 0x30) that was judged is one that may be
// another key's: it names no issuer that can be read (version 4, so not a version 3 or 5 form, which is counted as
// unreadable) and it does not verify with the primary's key. A designated revoker's revocation whose
// issuer was stripped looks like this, so it is counted with the revocations of other keys.
func strayed(h fkHead, fs ForeignSignature) bool {
	return isRevocationType(h.typ) && h.version == 4 && h.parsed && h.issuer == issuerUnknown && fs.Status == SignatureNotVerified
}

// misplaced is the entry for a signature of the primary of a type that does not belong where it
// stands.
func misplaced(h fkHead) ForeignSignature {
	return ForeignSignature{Type: h.typ, Status: SignatureMisplaced, Hash: hashName(h.hash)}
}

// componentData is what a signature on a user ID or a user attribute covers before its own fields: the
// key prefix, then 0xB4 (user ID) or 0xD1 (user attribute), the four-octet length and the body.
func (v *fkVerifier) componentData(w *fkWalk, u *fkUser) []byte {
	lead := byte(0xB4)
	if u.attr {
		lead = 0xD1
	}
	data := append(v.keyData(w), lead, byte(len(u.text)>>24), byte(len(u.text)>>16), byte(len(u.text)>>8), byte(len(u.text)))
	return append(data, u.text...)
}

// components judges the signatures on each user ID and user attribute. It returns the view of the user
// IDs, the number of them that have a valid self-signature, and the number of user attributes that are left
// out. A user ID or a user attribute goes into the certificate only with at least one certification that
// verifies; it then goes with every certification and certification revocation of the primary that
// verifies. Other keys' certifications are counted and left out.
func (v *fkVerifier) components(w *fkWalk, out *fkOutput) (ids []ForeignUserID, valid, attrsLeftOut int) {
	out.comps = make([][]byte, len(w.users))
	groups := map[string]*fkGroup{}
	group := make([]*fkGroup, len(w.users))
	for i, u := range w.users {
		data := v.componentData(w, u)
		text := string(u.text)
		key := "u" + text
		verify := func(g *packet.Signature) error { return v.pk.VerifyUserIdSignature(text, v.pk, g) }
		if u.attr {
			key = "a" + text
			verify = func(g *packet.Signature) error { return v.verifyAttribute(w, u.text, g) }
		}
		grp := out.groupOf(groups, key, i)
		group[i] = grp
		if u.attr && !wellFormedAttribute(u.text) {
			// A body that is not a sequence of subpackets would make other readers refuse the whole
			// certificate: the attribute is left out, as one with no valid certification is, and its
			// signatures are not checked.
			grp.bad = true
			continue
		}
		fu := ForeignUserID{Text: text}
		for _, s := range u.t.sigs {
			h := v.head(s)
			switch {
			case !h.claimed() && isCertification(h.typ):
				fu.Certifications++
			case !h.claimed():
				fu.OtherSignatures++
				if h.typ == sigCertRevocation {
					fu.OtherRevocations++
				}
			case isCertification(h.typ) || h.typ == sigCertRevocation:
				fs, emit := v.evaluate(s, h, fkCtx{data: data, keyCreated: v.created, verify: verify})
				fu.Signatures = append(fu.Signatures, fs)
				if strayed(h, fs) {
					fu.OtherSignatures++
					fu.OtherRevocations++
				}
				if emit != nil {
					grp.add(emit, out)
					grp.ok = grp.ok || isCertification(h.typ)
				}
			default:
				fu.Signatures = append(fu.Signatures, misplaced(h))
			}
		}
		if u.attr {
			continue
		}
		summariseUserID(&fu)
		fu.UnreadableRevocations = unusableRevocations(fu.Signatures)
		if fu.Valid {
			valid++
		}
		ids = append(ids, fu)
	}
	counted := map[*fkGroup]bool{} // a user attribute that is left out counts once, however often it appears
	for i, u := range w.users {
		g := group[i]
		switch {
		case (!g.ok || g.bad) && u.attr:
			if !counted[g] {
				counted[g] = true
				attrsLeftOut++
			}
		case g.ok && !g.bad && g.first == i && u.attr:
			out.comps[i] = append(wrap(tagUserAttribute, u.text), g.emits...)
		case g.ok && g.first == i:
			out.comps[i] = append(wrap(tagUserID, u.text), g.emits...)
		}
	}
	return ids, valid, attrsLeftOut
}

// wellFormedAttribute tells whether the body of a user attribute packet is a sequence of attribute
// subpackets (RFC 9580, section 5.12): each with a length in one of the forms of section 5.2.3.7 that counts
// the type octet and so is at least 1, running exactly to the end of the body. The types need not be known.
func wellFormedAttribute(body []byte) bool {
	_, err := parseArea(body)
	return err == nil
}

// verifyAttribute verifies a signature over a user attribute packet with the primary key.
func (v *fkVerifier) verifyAttribute(w *fkWalk, body []byte, g *packet.Signature) error {
	h, err := g.PrepareVerify()
	if err != nil {
		return err
	}
	if err := v.pk.SerializeForHash(h); err != nil {
		return err
	}
	h.Write([]byte{0xD1, byte(len(body) >> 24), byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	return v.pk.VerifySignature(h, g)
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

// summariseUserID fills the view from the signatures that count. The fields (creation time, key
// expiry, key flags, primary mark) come from the newest strong self-signature when there is one, and
// from the newest weak (SHA-1) one only when there is no strong one: WeakHash means exactly that the
// fields come from a weak signature. A soft revocation is compared with the newest self-signature of
// either kind.
func summariseUserID(fu *ForeignUserID) {
	var strong, weak, newest *ForeignSignature
	var revs []*ForeignSignature
	for i := range fu.Signatures {
		s := &fu.Signatures[i]
		if !s.Status.Counts() {
			continue
		}
		switch {
		case isCertification(s.Type):
			newest = newer(newest, s)
			if s.Status == SignatureValid {
				strong = newer(strong, s)
			} else {
				weak = newer(weak, s)
			}
		case s.Type == sigCertRevocation:
			revs = append(revs, s)
		}
	}
	src := strong
	if src == nil {
		src = weak
	}
	if src != nil {
		fu.Valid, fu.WeakHash = true, strong == nil
		fu.Created, fu.KeyExpires, fu.KeyFlags, fu.Primary = src.Created, src.KeyExpires, src.KeyFlags, src.Primary
	}
	if r := revocationOf(revs, newest); r != nil {
		fu.Revoked, fu.RevokedAt = true, r.Created
	}
}

// newer returns the later of two signatures by creation time, the later one in the file when equal. a may
// be nil.
func newer(a, b *ForeignSignature) *ForeignSignature {
	if a == nil || !b.Created.Before(a.Created) {
		return b
	}
	return a
}

// subkeys judges the signatures on each subkey. A subkey goes into the certificate only if at least
// one binding of the primary verifies over its public bytes (SHA-1 or stronger; the back-signature of a
// subkey that can sign is asked for in the view and not here); it is then written as a public subkey packet
// built from the cut that was confirmed, with its bindings and subkey revocations that verify. Every
// other subkey, whatever packet it came in, is left out and reported, with no fingerprint: an
// unconfirmed cut is not to be trusted.
func (v *fkVerifier) subkeys(w *fkWalk, out *fkOutput) []ForeignSubkey {
	views := make([]ForeignSubkey, 0, len(w.subs))
	out.subs = make([][]byte, len(w.subs))
	groups := map[string]*fkGroup{}
	group := make([]*fkGroup, len(w.subs))
	for i, s := range w.subs {
		fs := ForeignSubkey{Form: s.form}
		var data []byte
		var grp *fkGroup
		if !s.unread {
			fs.Algorithm, fs.Created = s.pub.alg, s.pub.created
			data = append(v.keyData(w), hashPrefix(s.pubBody)...)
			grp = out.groupOf(groups, string(s.pubBody), i)
			if grp.back == nil {
				grp.back = map[string][]byte{}
			}
		}
		group[i] = grp
		partial := false // a binding verified and is not complete (no back-signature that verifies)
		broken := false  // a subkey revocation that the library's key-ring reader would refuse
		for _, g := range s.t.sigs {
			h := v.head(g)
			unreadable := s.gopk == nil && (h.typ == sigSubkeyBinding || h.typ == sigSubkeyRevoke)
			var sg ForeignSignature
			var emit []byte
			switch {
			case !h.claimed():
				fs.OtherSignatures++
				if h.typ == sigSubkeyRevoke {
					fs.OtherRevocations++
				}
				continue
			case unreadable:
				sg = ForeignSignature{Type: h.typ, Status: SignatureUnreadable, Hash: hashName(h.hash)}
			case h.typ == sigSubkeyBinding:
				sub := s.gopk
				sg, emit = v.evaluate(g, h, fkCtx{
					data: data, keyCreated: s.pub.created, sub: sub, back: grp.back, incomplete: &partial,
					verify: func(x *packet.Signature) error { return v.pk.VerifySubkeyRevocationSignature(x, sub) },
					strong: func(x *packet.Signature) error { return v.pk.VerifyKeySignature(sub, x) },
				})
				grp.ok = grp.ok || emit != nil
			case h.typ == sigSubkeyRevoke:
				sub := s.gopk
				sg, emit = v.evaluate(g, h, fkCtx{
					data: data, keyCreated: s.pub.created, incomplete: &broken,
					verify: func(x *packet.Signature) error { return v.pk.VerifySubkeyRevocationSignature(x, sub) },
					strong: func(x *packet.Signature) error { return v.pk.VerifyKeySignature(sub, x) },
				})
			default:
				sg = misplaced(h)
			}
			fs.Signatures = append(fs.Signatures, sg)
			if strayed(h, sg) {
				fs.OtherSignatures++
				fs.OtherRevocations++
			}
			if emit != nil {
				grp.add(emit, out)
			}
		}
		summariseSubkey(&fs)
		fs.UnreadableRevocations = unusableRevocations(fs.Signatures)
		if grp != nil {
			grp.partial = grp.partial || partial
			grp.broken = grp.broken || broken
		}
		views = append(views, fs)
	}
	for i, s := range w.subs {
		g := group[i]
		if g != nil && !g.ok && g.partial {
			// Its public bytes were confirmed by a binding of the primary that verifies, so the view keeps
			// its fingerprint; it is left out of the certificate because no binding of it is complete.
			views[i].IncompleteBinding = true
			views[i].Fingerprint, views[i].KeyID = fingerprintHex(s.fp)
		}
		if g == nil || !g.ok || g.broken {
			continue
		}
		views[i].InCertificate = true
		views[i].Fingerprint, views[i].KeyID = fingerprintHex(s.fp)
		if g.first == i {
			out.subs[i] = append(wrap(tagSubkey, s.pubBody), g.emits...)
		}
	}
	return views
}

// summariseSubkey fills the view from the bindings that count, by the rule of [summariseUserID]: the
// fields come from the newest strong binding when there is one, and WeakHash means that they come from a
// weak (SHA-1) one.
func summariseSubkey(fs *ForeignSubkey) {
	var strong, weak, newest *ForeignSignature
	var revs []*ForeignSignature
	for i := range fs.Signatures {
		s := &fs.Signatures[i]
		if !s.Status.Counts() {
			continue
		}
		switch s.Type {
		case sigSubkeyBinding:
			newest = newer(newest, s)
			if s.Status == SignatureValid {
				strong = newer(strong, s)
			} else {
				weak = newer(weak, s)
			}
		case sigSubkeyRevoke:
			revs = append(revs, s)
		}
	}
	src := strong
	if src == nil {
		src = weak
	}
	if src != nil {
		fs.Bound, fs.WeakHash = true, strong == nil
		fs.BoundAt, fs.Flags, fs.Expires = src.Created, src.KeyFlags, src.KeyExpires
	}
	fs.Revoked = revocationOf(revs, newest) != nil
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
