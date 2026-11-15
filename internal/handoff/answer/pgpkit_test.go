package answer_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
	"ritueel.id/ritueel/internal/handoff/answer"
	"ritueel.id/ritueel/internal/openpgp"
)

// This file writes OpenPGP requests and bindings for the tests. It is written apart from package openpgp (it
// signs with crypto/ecdsa and hashes with the standard library, and writes each packet itself), so that a
// mistake of the reader under test is not copied into the tests. A valid binding is the one that
// openpgp.BindSubkey writes; a binding that the page forbids is written by hand here, and still verifies.

// pgpKey is a P-384 key with the creation time of its key packet.
type pgpKey struct {
	priv    *ecdsa.PrivateKey
	created time.Time
}

func newPGPKey(t testing.TB, created time.Time) *pgpKey {
	t.Helper()
	return &pgpKey{priv: newP384(t), created: created.UTC().Truncate(time.Second)}
}

func (k *pgpKey) pub() *ecdsa.PublicKey { return &k.priv.PublicKey }

func mpi(n *big.Int) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(n.BitLen()))
	return append(out, n.Bytes()...)
}

func (k *pgpKey) body() []byte {
	point, err := k.pub().Bytes()
	if err != nil {
		panic(err)
	}
	out := []byte{4}
	out = binary.BigEndian.AppendUint32(out, uint32(k.created.Unix()))
	out = append(out, 19, 5, 0x2B, 0x81, 0x04, 0x00, 0x22)
	return append(out, mpi(new(big.Int).SetBytes(point))...)
}

func (k *pgpKey) hashedForm() []byte {
	b := k.body()
	return append([]byte{0x99, byte(len(b) >> 8), byte(len(b))}, b...)
}

func (k *pgpKey) fingerprintBytes() []byte {
	h := sha1.New() //nolint:gosec // see the import
	h.Write(k.hashedForm())
	return h.Sum(nil)
}

func (k *pgpKey) fingerprint() string { return hex.EncodeToString(k.fingerprintBytes()) }

func (k *pgpKey) ref() handoff.PrimaryRef {
	return handoff.PrimaryRef{Fingerprint: k.fingerprint(), Key: k.pub(), Created: k.created}
}

// pgpPacket writes one packet with a new-format header.
func pgpPacket(tag byte, body []byte) []byte {
	out := []byte{0xC0 | tag}
	n := len(body)
	switch {
	case n < 192:
		out = append(out, byte(n))
	case n < 8384:
		n -= 192
		out = append(out, byte(n>>8)+192, byte(n))
	default:
		out = append(out, 0xFF)
		out = binary.BigEndian.AppendUint32(out, uint32(n))
	}
	return append(out, body...)
}

// pgpOldPacket writes one packet with an old-format header of the shortest length form that fits.
func pgpOldPacket(tag byte, body []byte) []byte {
	n := len(body)
	switch {
	case n < 256:
		return append([]byte{0x80 | tag<<2, byte(n)}, body...)
	case n < 65536:
		return append([]byte{0x80 | tag<<2 | 1, byte(n >> 8), byte(n)}, body...)
	}
	out := []byte{0x80 | tag<<2 | 2}
	out = binary.BigEndian.AppendUint32(out, uint32(n))
	return append(out, body...)
}

const (
	pgpTagSignature = 2
	pgpTagSubkey    = 14
)

func (k *pgpKey) subkeyPacket() []byte { return pgpPacket(pgpTagSubkey, k.body()) }

type subpacket struct {
	typ      byte
	critical bool
	data     []byte
}

func (s subpacket) bytes() []byte {
	n := len(s.data) + 1
	var out []byte
	if n < 192 {
		out = []byte{byte(n)}
	} else {
		n -= 192
		out = []byte{byte(n>>8) + 192, byte(n)}
	}
	t := s.typ
	if s.critical {
		t |= 0x80
	}
	out = append(out, t)
	return append(out, s.data...)
}

func subpackets(list []subpacket) []byte {
	var out []byte
	for _, s := range list {
		out = append(out, s.bytes()...)
	}
	return out
}

const (
	spCreationTime  = 2
	spKeyExpiration = 9
	spIssuerKeyID   = 16
	spKeyFlags      = 27
	spEmbedded      = 32
	spIssuerFP      = 33
)

func spCreated(at time.Time) subpacket {
	return subpacket{typ: spCreationTime, data: binary.BigEndian.AppendUint32(nil, uint32(at.Unix()))}
}

func spIssuerFingerprint(k *pgpKey) subpacket {
	return subpacket{typ: spIssuerFP, data: append([]byte{4}, k.fingerprintBytes()...)}
}

func spIssuerID(k *pgpKey) subpacket {
	fp := k.fingerprintBytes()
	return subpacket{typ: spIssuerKeyID, data: slices.Clone(fp[12:])}
}

// sigSpec says how to write a signature that covers a primary and a subkey (type 0x19, the back-signature, or
// type 0x18, the binding). A zero field takes the value that the page gives the back-signature.
type sigSpec struct {
	sigType  byte        // 0x19
	signer   *pgpKey     // the subkey; for a binding, the primary
	primary  *pgpKey     // the primary that the signature covers
	sub      *pgpKey     // the subkey that it covers
	created  time.Time   // one minute after the subkey
	hashed   []subpacket // the creation time and the issuer fingerprint of the signer
	unhashed []subpacket // the issuer key ID of the signer
}

func (s sigSpec) body(t testing.TB) []byte {
	t.Helper()
	sigType := s.sigType
	if sigType == 0 {
		sigType = 0x19
	}
	signer := s.signer
	if signer == nil {
		signer = s.sub
	}
	created := s.created
	if created.IsZero() {
		created = s.sub.created.Add(time.Minute)
	}
	hashed, unhashed := s.hashed, s.unhashed
	if hashed == nil {
		hashed = []subpacket{spCreated(created), spIssuerFingerprint(signer)}
	}
	if unhashed == nil {
		unhashed = []subpacket{spIssuerID(signer)}
	}
	hashedBytes := subpackets(hashed)
	head := []byte{4, sigType, 19, 9}
	head = binary.BigEndian.AppendUint16(head, uint16(len(hashedBytes)))
	head = append(head, hashedBytes...)
	h := sha512.New384()
	h.Write(s.primary.hashedForm())
	h.Write(s.sub.hashedForm())
	h.Write(head)
	h.Write([]byte{4, 0xFF})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(head))))
	digest := h.Sum(nil)
	der, err := ecdsa.SignASN1(rand.Reader, signer.priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}
	unhashedBytes := subpackets(unhashed)
	out := slices.Clone(head)
	out = binary.BigEndian.AppendUint16(out, uint16(len(unhashedBytes)))
	out = append(out, unhashedBytes...)
	out = append(out, digest[:2]...)
	out = append(out, mpi(rs.R)...)
	out = append(out, mpi(rs.S)...)
	return out
}

func (s sigSpec) packet(t testing.TB) []byte { return pgpPacket(pgpTagSignature, s.body(t)) }

// The times of the requests: the clock of the tests is 2026-11-15T12:00:00Z, the subkey was made on
// 2026-10-20 and the primaries on 2026-01-01, as in the vectors.
var (
	pgpPrimaryAt  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pgpSubCreated = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	pgpEnds       = time.Date(2027, 12, 15, 12, 0, 0, 0, time.UTC) // 13 months after the ceremony
)

// pgpRequest is a request of type openpgp-subkey that the test made: a subkey, the primaries it is bound to
// and one back-signature for each.
type pgpRequest struct {
	t          testing.TB
	primaries  []*pgpKey
	sub        *pgpKey
	subPacket  []byte
	sigs       [][]byte // the packets
	backBodies [][]byte // the bodies, which a binding embeds
	capability string
	proofEdit  func(m map[string]any)
}

func newPGPRequest(t testing.TB, primaries []*pgpKey, capability string) *pgpRequest {
	t.Helper()
	r := &pgpRequest{t: t, primaries: primaries, sub: newPGPKey(t, pgpSubCreated), capability: capability}
	r.subPacket = r.sub.subkeyPacket()
	for _, p := range primaries {
		s := sigSpec{primary: p, sub: r.sub}
		body := s.body(t) // one signature: a second call would write another one
		r.sigs = append(r.sigs, pgpPacket(pgpTagSignature, body))
		r.backBodies = append(r.backBodies, body)
	}
	return r
}

func (r *pgpRequest) file() []byte {
	out := slices.Clone(r.subPacket)
	for _, s := range r.sigs {
		out = append(out, s...)
	}
	return out
}

func (r *pgpRequest) fingerprints() []string {
	var out []string
	for _, p := range r.primaries {
		out = append(out, p.fingerprint())
	}
	return out
}

func (r *pgpRequest) request() *handoff.Request {
	r.t.Helper()
	file := r.file()
	proof := map[string]any{
		"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha256Hex(file),
		"store": "software", "primaries": r.fingerprints(), "capabilities": []string{r.capability},
	}
	if r.proofEdit != nil {
		r.proofEdit(proof)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		r.t.Fatal(err)
	}
	return &handoff.Request{Stem: "example-request", Files: map[string][]byte{handoff.FileProof: raw, handoff.FileSubkey: file}}
}

func (r *pgpRequest) asked() *answer.Asked {
	r.t.Helper()
	a, err := answer.AskedFromRequest(r.request())
	if err != nil {
		r.t.Fatalf("AskedFromRequest: %v", err)
	}
	return a
}

// bind is the binding of the page by the primary i of the request, as openpgp.BindSubkey writes it: the
// two packets of a bound file.
func (r *pgpRequest) bind(i int) []byte {
	r.t.Helper()
	return r.bindWith(i, r.capability, pgpEnds)
}

func (r *pgpRequest) bindWith(i int, capability string, ends time.Time) []byte {
	r.t.Helper()
	p := r.primaries[i]
	out, err := openpgp.BindSubkey(rand.Reader, openpgp.BindParams{
		Primary: openpgp.PrimaryParams{Key: p.priv, CreationTime: p.created, CeremonyTime: testNow, ExpiresAt: ends},
		Subkey:  r.subPacket, BackSig: r.sigs[i], Capability: capability, ExpiresAt: ends,
	})
	if err != nil {
		r.t.Fatalf("BindSubkey: %v", err)
	}
	return out
}

// bindingSpec is the binding of the page as a signature to write by hand: flags 0x02, the key expiration
// critical, the issuer fingerprint, the issuer key ID and the embedded back-signature. A test changes a field
// to make a binding that the page forbids, which still verifies.
type bindingSpec struct {
	r        *pgpRequest
	by       int // the index of the signing primary
	created  time.Time
	flags    byte
	life     uint32
	hashed   func(base []subpacket) []subpacket
	unhashed func(base []subpacket) []subpacket
	embed    []byte  // the embedded body when it is not the request's for the primary
	signedBy *pgpKey // the key that signs when it is not the primary that the binding names
}

func (r *pgpRequest) spec(by int) bindingSpec {
	flag := byte(0x02)
	if r.capability == "authenticate" {
		flag = 0x20
	}
	return bindingSpec{r: r, by: by, created: testNow, flags: flag,
		life: uint32(pgpEnds.Unix() - r.sub.created.Unix())}
}

// packet writes the whole bound file: the subkey packet and the signature packet.
func (b bindingSpec) file(t testing.TB) []byte {
	t.Helper()
	p := b.r.primaries[b.by]
	hashed := []subpacket{
		spCreated(b.created),
		{typ: spKeyFlags, data: []byte{b.flags}},
		{typ: spKeyExpiration, critical: true, data: binary.BigEndian.AppendUint32(nil, b.life)},
		spIssuerFingerprint(p),
	}
	embed := b.embed
	if embed == nil {
		embed = b.r.backBodies[b.by]
	}
	unhashed := []subpacket{spIssuerID(p), {typ: spEmbedded, data: embed}}
	if b.hashed != nil {
		hashed = b.hashed(hashed)
	}
	if b.unhashed != nil {
		unhashed = b.unhashed(unhashed)
	}
	signer := p
	if b.signedBy != nil {
		signer = b.signedBy
	}
	s := sigSpec{sigType: 0x18, signer: signer, primary: p, sub: b.r.sub, created: b.created, hashed: hashed, unhashed: unhashed}
	return append(slices.Clone(b.r.subPacket), s.packet(t)...)
}

// subset is the request that names only the first n primaries, with the same subkey and their back-signatures:
// what the requester holds when the certifier answers with a request that named more.
func (r *pgpRequest) subset(n int) *pgpRequest {
	out := *r
	out.primaries, out.sigs, out.backBodies = r.primaries[:n], r.sigs[:n], r.backBodies[:n]
	return &out
}

// pgpCase is one in-memory answer to a request of type openpgp-subkey.
type pgpCase struct {
	t       testing.TB
	req     *pgpRequest
	bound   []byte
	stem    string
	edits   []func(m map[string]any)
	rawJSON []byte
	issuer  string // empty takes the fingerprint of the signing primary
	by      *pgpKey
	extra   map[string][]byte
	asked_  *pgpRequest // the request that the requester holds, when it is not req
}

func (k *memKit) newPGP(capability string) *pgpCase {
	k.t.Helper()
	r := newPGPRequest(k.t, []*pgpKey{k.a.primary, k.b.primary}, capability)
	return &pgpCase{t: k.t, req: r, stem: "example-answer", by: k.a.primary, bound: r.bind(0)}
}

func (c *pgpCase) with(change func(m map[string]any)) *pgpCase {
	c.edits = append(c.edits, change)
	return c
}

func (c *pgpCase) files() map[string][]byte {
	c.t.Helper()
	raw := c.rawJSON
	if raw == nil {
		digestOf := c.req
		if c.asked_ != nil {
			digestOf = c.asked_
		}
		issuer := c.issuer
		if issuer == "" {
			issuer = c.by.fingerprint()
		}
		m := map[string]any{
			"handoff": 1, "type": "openpgp-subkey", "request_sha256": sha256Hex(digestOf.file()),
			"outcome":    "issued",
			"artifacts":  []map[string]any{{"name": c.stem + ".bound.pgp", "sha256": sha256Hex(c.bound)}},
			"valid_from": formatTime(testNow), "valid_until": formatTime(pgpEnds),
			"issuer": issuer, "trust_sequence": 7,
		}
		for _, e := range c.edits {
			e(m)
		}
		var err error
		if raw, err = json.Marshal(m); err != nil {
			c.t.Fatal(err)
		}
	}
	out := map[string][]byte{answer.FileResult: slices.Clone(raw), answer.FileBound: slices.Clone(c.bound)}
	for k, v := range c.extra {
		out[k] = v
	}
	return out
}

func (c *pgpCase) answer() *answer.Answer {
	c.t.Helper()
	return &answer.Answer{Stem: c.stem, Files: c.files()}
}

func (c *pgpCase) check(chk *answer.Checker) (answer.Verdict, error) {
	c.t.Helper()
	if c.asked_ != nil {
		return chk.Check(c.asked_.asked(), c.answer())
	}
	return chk.Check(c.req.asked(), c.answer())
}
