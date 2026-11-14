package openpgp

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// maxUnhashedArea is the longest unhashed subpacket area, in bytes, that gpgv reads: it says
// "unhashed data too long" for a longer one and then reads no signature of the binding. A binding
// whose unhashed area would be longer is refused, so that the root never signs what gpgv cannot read.
const maxUnhashedArea = 10000

// BindParams names the subkey that a primary binds at a ceremony.
type BindParams struct {
	// Primary is the primary that binds. Only its key, creation time and ceremony time are used.
	Primary PrimaryParams
	// Subkey is the request's Public-Subkey packet, as it came: one packet, version 4, ECDSA on
	// P-384, created at or before the ceremony time.
	Subkey []byte
	// BackSig is the request's back-signature for this primary: one signature packet of type 0x19
	// made by the subkey over this primary and the subkey, with SHA-384. It has exactly one shape.
	// Its hashed area holds the signature creation time and the issuer fingerprint of the subkey
	// and nothing else. Its unhashed area holds the issuer key ID of the subkey and nothing else.
	// No subpacket is marked critical. The creation time is not before the creation of the subkey
	// and not after the ceremony time. Anything else is refused as a fault of the request
	// ([ErrRequest]). It is embedded unchanged.
	BackSig []byte
	// Capability is "sign" (key flag 0x02) or "authenticate" (0x20) and nothing else.
	Capability string
	// ExpiresAt is the instant the subkey ends, after the ceremony time. It is written as seconds
	// after the creation time of the subkey.
	ExpiresAt time.Time
}

// BindSubkey returns the two packets of an answer: the Public-Subkey packet, as the request has it,
// and the subkey binding signature (type 0x18) by the primary
// (docs/reference/hand-off-contract.md, "What comes back"). The hashed area holds the signature
// creation time (the ceremony time), the key flags of the capability and nothing else, the key
// expiration time marked critical, in seconds after the subkey's creation, and the issuer
// fingerprint of the primary; the unhashed area holds the issuer key ID and the embedded signature
// (subpacket 32), the request's back-signature unchanged. The binding signs the primary key and
// then the subkey, each as 0x99, a two-byte length and the packet body.
//
// The back-signature is verified with the subkey over the primary and the subkey before it is
// embedded, and the finished binding is verified with the primary before it is returned. A subkey
// or a back-signature that is refused is an [ErrRequest]; nothing is returned with an error. A
// back-signature is refused before the signer is asked when it has not exactly the shape the
// contract page gives (see [BindParams].BackSig and checkBackSig), or when the unhashed area of the
// binding would be longer than gpgv reads (10000 bytes).
//
// The subkey may end after its primary ends: the primary is extended at each use (record 0007,
// rule 15), so the end of the subkey is not held to the end of the primary at one ceremony.
func BindSubkey(rnd io.Reader, b BindParams) ([]byte, error) {
	var flag byte
	switch b.Capability {
	case "sign":
		flag = flagSign
	case "authenticate":
		flag = flagAuthenticate
	default:
		return nil, fail(ErrParams, "the capability is not sign or authenticate")
	}
	g, err := newPrimarySigner(rnd, b.Primary)
	if err != nil {
		return nil, err
	}
	// The request is copied at once: what is checked is what is signed and returned.
	subRaw := bytes.Clone(b.Subkey)
	backRaw := bytes.Clone(b.BackSig)
	sub, err := parseSubkey(subRaw, g, b.Primary.CeremonyTime)
	if err != nil {
		return nil, err
	}
	life, err := lifetime("the expiry of the subkey", sub.created, b.ExpiresAt, b.Primary.CeremonyTime)
	if err != nil {
		return nil, err
	}
	backBody, err := checkBackSig(backRaw, g, sub, b.Primary.CeremonyTime)
	if err != nil {
		return nil, err
	}
	// The unhashed area of the binding holds the issuer key ID and the back-signature. gpgv reads
	// no area of more than maxUnhashedArea bytes, so a back-signature that makes it longer is a
	// fault of the request, found before the signer is asked.
	unhashed := []subpacket{g.issuerKeyID(), {typ: spEmbeddedSignature, data: backBody}}
	if len(encodeArea(unhashed)) > maxUnhashedArea {
		return nil, fail(ErrRequest, "the back-signature is too long to embed: gpgv reads no unhashed area of more than %d bytes", maxUnhashedArea)
	}

	body, err := g.sign(sigSpec{
		sigType: sigSubkeyBinding,
		hashed: []subpacket{
			{typ: spCreationTime, data: u32(unixU32(b.Primary.CeremonyTime))},
			{typ: spKeyFlags, data: []byte{flag}},
			{typ: spKeyExpiration, critical: true, data: u32(life)},
			g.issuerFingerprint(),
		},
		unhashed: unhashed,
		data:     [][]byte{hashPrefix(g.body), hashPrefix(sub.body)},
	})
	if err != nil {
		return nil, err
	}
	pkt := wrap(tagSignature, body)
	sig, err := readBack(pkt, g.key)
	if err != nil {
		return nil, err
	}
	if err := g.pk.VerifyKeySignature(sub.pk, sig); err != nil {
		return nil, fail(ErrSignature, "the binding does not verify: %v", err)
	}
	a, err := splitSig(body)
	if err != nil {
		return nil, fail(ErrSignature, "the binding does not read back as it was built")
	}
	if emb, ok := find(a.unhashed, spEmbeddedSignature); !ok || !bytes.Equal(emb, backBody) {
		return nil, fail(ErrSignature, "the embedded signature is not the back-signature of the request")
	}
	want := packet.Signature{FlagSign: flag == flagSign, FlagAuthenticate: flag == flagAuthenticate}
	if sig.SigType != sigSubkeyBinding || !sig.CreationTime.Equal(b.Primary.CeremonyTime) ||
		sig.KeyLifetimeSecs == nil || *sig.KeyLifetimeSecs != life ||
		!sig.FlagsValid || sig.FlagSign != want.FlagSign || sig.FlagAuthenticate != want.FlagAuthenticate ||
		sig.FlagCertify || sig.FlagEncryptCommunications || sig.FlagEncryptStorage || sig.FlagSplitKey || sig.FlagGroupKey {
		return nil, fail(ErrSignature, "the binding does not read back as it was built")
	}
	out := bytes.Clone(subRaw)
	return append(out, pkt...), nil
}

// parseSubkey checks that raw is exactly one Public-Subkey packet of the profile: version 4, ECDSA
// on P-384 with a point on the curve, written in the form that go-crypto writes it again (so that
// what is hashed here is what a verifier hashes), created at or before the ceremony, and not the
// primary's own key (the same point, whatever the creation time).
func parseSubkey(raw []byte, primary *signer, ceremony time.Time) (*key, error) {
	k, err := readKey(raw, tagSubkey)
	if err != nil {
		return nil, fail(ErrRequest, "the subkey is not one Public-Subkey packet of the profile: %v", err)
	}
	if err := checkTime("the creation time of the subkey", k.created); err != nil {
		return nil, fail(ErrRequest, "%v", err)
	}
	if k.created.After(ceremony) {
		return nil, fail(ErrRequest, "the subkey was created after the ceremony time")
	}
	if k.ec.Equal(primary.ec) {
		return nil, fail(ErrRequest, "the public point of the subkey is the primary's own")
	}
	return k, nil
}

// checkBackSig checks the request's back-signature for this primary and returns its body, which is
// what the binding embeds. It must be one signature packet of type 0x19 made by the subkey, with
// ECDSA and SHA-384, and it must verify with the subkey over the primary and the subkey. Its shape
// is the one the contract page gives (docs/reference/hand-off-contract.md, "The request"): "Its
// hashed area has the signature creation time and the issuer fingerprint of the subkey. Its
// unhashed area has the issuer key ID of the subkey." So the hashed area holds exactly those two
// subpackets and the unhashed area exactly that one, none with the critical bit, each of its
// length, and the creation time is not before the subkey and not after the ceremony (record 0009,
// rule 8). Anything else is refused, because the root signs the binding with the back-signature
// inside, and gpgv or sqv refuse the binding for a subpacket that go-crypto passes over. The
// packet also ends exactly after the two numbers of the signature, and the two bytes of the hash
// tag are the first two bytes of the digest.
func checkBackSig(raw []byte, primary *signer, sub *key, ceremony time.Time) ([]byte, error) {
	tag, body, rest, err := splitPacket(raw)
	if err != nil || tag != tagSignature || len(rest) != 0 {
		return nil, fail(ErrRequest, "the back-signature is not one signature packet")
	}
	a, err := splitSig(body)
	if err != nil {
		return nil, fail(ErrRequest, "the back-signature does not parse")
	}
	if a.sigType != sigPrimaryKeyBinding || a.algo != algoECDSA || a.hash != hashSHA384 {
		return nil, fail(ErrRequest, "the back-signature is not a type 0x19 signature with ECDSA and SHA-384")
	}
	if err := checkIssuers(ErrRequest, body, sub); err != nil {
		return nil, err
	}
	if err := checkBackSigTimes(a, sub.created, ceremony); err != nil {
		return nil, err
	}
	if err := checkBackSigEnd(a, primary.body, sub.body); err != nil {
		return nil, err
	}
	p, err := packet.Read(bytes.NewReader(raw))
	if err != nil {
		return nil, fail(ErrRequest, "the back-signature does not parse: %v", err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		return nil, fail(ErrRequest, "the back-signature does not parse as a signature")
	}
	h, err := sig.PrepareVerify()
	if err != nil {
		return nil, fail(ErrRequest, "the back-signature cannot be checked: %v", err)
	}
	if err := primary.pk.SerializeForHash(h); err != nil {
		return nil, fail(ErrRequest, "the back-signature cannot be checked: %v", err)
	}
	if err := sub.pk.SerializeForHash(h); err != nil {
		return nil, fail(ErrRequest, "the back-signature cannot be checked: %v", err)
	}
	if err := sub.pk.VerifySignature(h, sig); err != nil {
		return nil, fail(ErrRequest, "the back-signature does not verify over this primary and the subkey: %v", err)
	}
	return bytes.Clone(body), nil
}

// checkBackSigTimes requires the exact shape of the page: in the hashed area one signature creation
// time of 4 bytes and the issuer fingerprint of 21 bytes, in the unhashed area the issuer key ID of
// 8 bytes, and nothing else in either area; no subpacket has the critical bit. A signature
// expiration, a notation, a key expiration or any other subpacket is thus refused, with a critical
// bit or without, in either area. The creation time must not be before the creation of the subkey
// (sqv and gpgv both refuse the binding then) and not after the ceremony (sqv takes the signature
// as not live before its creation time). The issuers have been checked by checkIssuers.
func checkBackSigTimes(a sigAreas, subCreated, ceremony time.Time) error {
	if len(a.hashed) != 2 || len(a.unhashed) != 1 {
		return fail(ErrRequest, "the back-signature has not exactly the creation time and the issuer fingerprint in its hashed area and the issuer key ID in its unhashed area")
	}
	for _, area := range [][]subpacket{a.hashed, a.unhashed} {
		for _, sp := range area {
			if sp.critical {
				return fail(ErrRequest, "the back-signature has a subpacket marked critical (type %d)", sp.typ)
			}
		}
	}
	// The issuer fingerprint (21 bytes) and the issuer key ID (8 bytes) are held to their exact
	// values by checkIssuers; the creation time is held to its 4 bytes here.
	created, ok := find(a.hashed, spCreationTime)
	if !ok || len(created) != 4 {
		return fail(ErrRequest, "the back-signature has no one creation time of 4 bytes in its hashed area")
	}
	at := time.Unix(int64(binary.BigEndian.Uint32(created)), 0)
	if at.Before(subCreated) {
		return fail(ErrRequest, "the back-signature was created before the subkey")
	}
	if at.After(ceremony) {
		return fail(ErrRequest, "the back-signature was created after the ceremony time")
	}
	return nil
}

// checkBackSigEnd requires the packet to end exactly after the hash tag and the two numbers of the
// signature, and the hash tag to be the first two bytes of the digest that the signature covers:
// the primary, the subkey, the fields of the signature and its trailer.
func checkBackSigEnd(a sigAreas, primaryBody, subBody []byte) error {
	if len(a.rest) < 2 {
		return fail(ErrRequest, "the back-signature has no hash tag")
	}
	_, tail, err := readMPI(a.rest[2:])
	if err != nil {
		return fail(ErrRequest, "the back-signature has no first number")
	}
	if _, tail, err = readMPI(tail); err != nil {
		return fail(ErrRequest, "the back-signature has no second number")
	}
	if len(tail) != 0 {
		return fail(ErrRequest, "the back-signature has bytes after its two numbers")
	}
	trailer := []byte{4, 0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(a.fields)))
	h := sha512.New384()
	h.Write(hashPrefix(primaryBody))
	h.Write(hashPrefix(subBody))
	h.Write(a.fields)
	h.Write(trailer)
	if !bytes.Equal(a.rest[:2], h.Sum(nil)[:2]) {
		return fail(ErrRequest, "the hash tag of the back-signature is not the start of its digest")
	}
	return nil
}
