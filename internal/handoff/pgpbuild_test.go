package handoff_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math/big"
	"slices"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/handoff"
)

// This file is a writer of subkey requests for the tests of the OpenPGP checks. It is written apart from
// package openpgp (it signs with crypto/ecdsa and hashes with the standard library, and writes each packet
// itself), so that a mistake of the reader under test is not copied into the tests. It writes what the
// contract page gives: one Public-Subkey packet, and for each listed primary one back-signature of type
// 0x19 made by the subkey over the primary and the subkey, whose hashed area holds the signature creation
// time and the issuer fingerprint and whose unhashed area holds the issuer key ID.

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

// mpi writes a multiprecision integer: the bit count in two bytes and the bytes without leading zeros.
func mpi(n *big.Int) []byte {
	b := n.Bytes()
	out := binary.BigEndian.AppendUint16(nil, uint16(n.BitLen()))
	return append(out, b...)
}

// pointBytes is the uncompressed point of a key.
func pointBytes(pub *ecdsa.PublicKey) []byte {
	b, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// body is the body of the key packet of a version 4 ECDSA key on P-384 (algorithm 19, OID 1.3.132.0.34).
func (k *pgpKey) body() []byte {
	out := []byte{4}
	out = binary.BigEndian.AppendUint32(out, uint32(k.created.Unix()))
	out = append(out, 19, 5, 0x2B, 0x81, 0x04, 0x00, 0x22)
	return append(out, mpi(new(big.Int).SetBytes(pointBytes(k.pub())))...)
}

// fingerprintBytes is the version 4 fingerprint: SHA-1 over 0x99, the two-byte length and the body.
func (k *pgpKey) fingerprintBytes() []byte {
	b := k.body()
	h := sha1.New() //nolint:gosec // see the import
	h.Write([]byte{0x99, byte(len(b) >> 8), byte(len(b))})
	h.Write(b)
	return h.Sum(nil)
}

func (k *pgpKey) fingerprint() string { return hex.EncodeToString(k.fingerprintBytes()) }

// hashedForm is what a signature over a key hashes: 0x99, the two-byte length and the body.
func (k *pgpKey) hashedForm() []byte {
	b := k.body()
	return append([]byte{0x99, byte(len(b) >> 8), byte(len(b))}, b...)
}

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
	pgpTagPrimary   = 6
	pgpTagUserID    = 13
	pgpTagSubkey    = 14
)

func (k *pgpKey) subkeyPacket() []byte { return pgpPacket(pgpTagSubkey, k.body()) }

// subpacket is one signature subpacket.
type subpacket struct {
	typ      byte
	critical bool
	data     []byte
}

func (s subpacket) bytes() []byte {
	n := len(s.data) + 1
	var out []byte
	switch {
	case n < 192:
		out = []byte{byte(n)}
	default:
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

// The subpacket types that the page names.
const (
	spCreationTime = 2
	spIssuerKeyID  = 16
	spIssuerFP     = 33
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

// sigSpec says how to write a back-signature. A zero field takes the value that the page gives.
type sigSpec struct {
	version  byte        // 4
	sigType  byte        // 0x19
	hashAlgo byte        // 9, SHA-384
	signer   *pgpKey     // the subkey
	primary  *pgpKey     // required: the primary that the signature covers
	sub      *pgpKey     // required: the subkey that it covers
	created  time.Time   // one minute after the subkey
	hashed   []subpacket // the creation time and the issuer fingerprint of the subkey
	unhashed []subpacket // the issuer key ID of the subkey
	// noHashed and noUnhashed say that the area is empty, which a nil list cannot say.
	noHashed, noUnhashed bool
	trailing             []byte // bytes after the two numbers
	grindTag             bool   // choose the creation time so that the hash tag does not tell the hash
	headerOld            bool
}

func (s sigSpec) hasher() hash.Hash {
	switch s.hashAlgo {
	case 8:
		return sha256.New()
	case 10:
		return sha512.New()
	}
	return sha512.New384()
}

// body writes the body of the signature packet, signed.
func (s sigSpec) body(t testing.TB) []byte {
	t.Helper()
	version, sigType, hashAlgo := s.version, s.sigType, s.hashAlgo
	if version == 0 {
		version = 4
	}
	if sigType == 0 {
		sigType = 0x19
	}
	if hashAlgo == 0 {
		hashAlgo = 9
		s.hashAlgo = 9
	}
	signer := s.signer
	if signer == nil {
		signer = s.sub
	}
	created := s.created
	if created.IsZero() {
		created = s.sub.created.Add(time.Minute)
	}
	// parts writes the two areas and the hashed head for one creation time, and the digest over them.
	parts := func(created time.Time, h hash.Hash) (head, unhashedBytes, digest []byte) {
		hashed, unhashed := s.hashed, s.unhashed
		switch {
		case s.noHashed:
			hashed = nil
		case hashed == nil:
			hashed = []subpacket{spCreated(created), spIssuerFingerprint(s.sub)}
		}
		switch {
		case s.noUnhashed:
			unhashed = nil
		case unhashed == nil:
			unhashed = []subpacket{spIssuerID(s.sub)}
		}
		hashedBytes := subpackets(hashed)
		head = []byte{version, sigType, 19, hashAlgo}
		head = binary.BigEndian.AppendUint16(head, uint16(len(hashedBytes)))
		head = append(head, hashedBytes...)
		h.Write(s.primary.hashedForm())
		h.Write(s.sub.hashedForm())
		h.Write(head)
		h.Write([]byte{4, 0xFF})
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(head))))
		return head, subpackets(unhashed), h.Sum(nil)
	}
	if s.grindTag {
		// Find a creation time at which the first two bytes of the digest of the claimed hash are those of
		// the SHA-384 digest of the same data, so that the hash tag cannot tell the hash that was claimed.
		for i := range 1 << 22 {
			_, _, mine := parts(created.Add(time.Duration(i)*time.Second), s.hasher())
			_, _, theirs := parts(created.Add(time.Duration(i)*time.Second), sha512.New384())
			if mine[0] == theirs[0] && mine[1] == theirs[1] {
				created = created.Add(time.Duration(i) * time.Second)
				break
			}
		}
	}
	head, unhashedBytes, digest := parts(created, s.hasher())

	der, err := ecdsa.SignASN1(rand.Reader, signer.priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}

	out := slices.Clone(head)
	out = binary.BigEndian.AppendUint16(out, uint16(len(unhashedBytes)))
	out = append(out, unhashedBytes...)
	out = append(out, digest[:2]...)
	out = append(out, mpi(rs.R)...)
	out = append(out, mpi(rs.S)...)
	return append(out, s.trailing...)
}

// packet writes the whole signature packet.
func (s sigSpec) packet(t testing.TB) []byte {
	t.Helper()
	if s.headerOld {
		return pgpOldPacket(pgpTagSignature, s.body(t))
	}
	return pgpPacket(pgpTagSignature, s.body(t))
}

// pgpClock is the time that the in-memory requests are made for: the clock of the tests.
var (
	pgpSubCreated     = testNow.Add(-30 * 24 * time.Hour).Truncate(time.Second)
	pgpPrimaryCreated = testNow.Add(-200 * 24 * time.Hour).Truncate(time.Second)
)

// pgpFixture is one request of type openpgp-subkey: a subkey, the primaries it is bound to, one back-signature
// for each, and the proof. The proof's digest and primaries are written from the file and the primaries every
// time request() is called, unless the test sets digest or listed.
type pgpFixture struct {
	t         testing.TB
	primaries []*pgpKey
	sub       *pgpKey
	subPacket []byte
	sigs      [][]byte
	proof     map[string]any
	// listed overrides the primaries member of the proof; digest overrides request_sha256; file overrides
	// the bytes of the subkey file (the digest is then of these bytes).
	listed []string
	digest string
	file   []byte
	// edits are applied to the proof's members last, so that a test can drop or change a member.
	edits []func(m map[string]any)
}

// edit adds a change of the proof's members, applied last.
func (f *pgpFixture) edit(change func(m map[string]any)) *pgpFixture {
	if change != nil {
		f.edits = append(f.edits, change)
	}
	return f
}

// newPGPFixture makes a good request for n primaries and the store.
func newPGPFixture(t testing.TB, n int, store handoff.Store) *pgpFixture {
	t.Helper()
	f := &pgpFixture{t: t, sub: newPGPKey(t, pgpSubCreated)}
	for range n {
		f.primaries = append(f.primaries, newPGPKey(t, pgpPrimaryCreated))
	}
	f.subPacket = f.sub.subkeyPacket()
	for _, p := range f.primaries {
		f.sigs = append(f.sigs, f.backSig(p, nil))
	}
	f.proof = map[string]any{
		"handoff":      1,
		"type":         "openpgp-subkey",
		"store":        string(store),
		"capabilities": []string{"sign"},
	}
	switch store {
	case handoff.StoreKMS:
		f.proof["evidence"] = kmsEvidence(f.sub.pub())
	default:
		if ev := evidenceFor(store); ev != nil {
			f.proof["evidence"] = ev
		}
	}
	return f
}

// backSig writes the back-signature of primary p, with the change applied to the spec first.
func (f *pgpFixture) backSig(p *pgpKey, change func(s *sigSpec)) []byte {
	f.t.Helper()
	s := sigSpec{primary: p, sub: f.sub}
	if change != nil {
		change(&s)
	}
	return s.packet(f.t)
}

// fileBytes are the bytes of the subkey file.
func (f *pgpFixture) fileBytes() []byte {
	if f.file != nil {
		return slices.Clone(f.file)
	}
	out := slices.Clone(f.subPacket)
	for _, s := range f.sigs {
		out = append(out, s...)
	}
	return out
}

// fingerprints are the fingerprints of the primaries, in order.
func (f *pgpFixture) fingerprints() []string {
	var out []string
	for _, p := range f.primaries {
		out = append(out, p.fingerprint())
	}
	return out
}

// request renders the proof and the subkey file.
func (f *pgpFixture) request() *handoff.Request {
	f.t.Helper()
	file := f.fileBytes()
	proof := map[string]any{}
	for k, v := range f.proof {
		proof[k] = v
	}
	if _, ok := proof["request_sha256"]; !ok {
		proof["request_sha256"] = digestHex(file)
		if f.digest != "" {
			proof["request_sha256"] = f.digest
		}
	}
	if _, ok := proof["primaries"]; !ok {
		proof["primaries"] = f.fingerprints()
		if f.listed != nil {
			proof["primaries"] = f.listed
		}
	}
	for _, e := range f.edits {
		e(proof)
	}
	return &handoff.Request{Stem: testStem, Files: map[string][]byte{
		handoff.FileProof:  mustJSON(f.t, proof),
		handoff.FileSubkey: file,
	}}
}

// refs are the primaries as the checker holds them.
func (f *pgpFixture) refs() []handoff.PrimaryRef {
	var out []handoff.PrimaryRef
	for _, p := range f.primaries {
		out = append(out, p.ref())
	}
	return out
}

// config is the configuration of a checker for this fixture: a delegation of type openpgp-subkey for the
// capability sign, the primaries of the fixture, a root, and the clock of the tests.
func (f *pgpFixture) config(change func(c *handoff.Config)) handoff.Config {
	f.t.Helper()
	cfg := defaultConfig(f.t)
	cfg.Delegation = &handoff.Delegation{Name: "example-subkey", Type: handoff.TypeOpenPGP, Root: "example-root", Capability: "sign"}
	cfg.Primaries = f.refs()
	if change != nil {
		change(&cfg)
	}
	return cfg
}

// checker is the checker of the fixture, made after the change.
func (f *pgpFixture) checker(change func(c *handoff.Config)) *handoff.Checker {
	f.t.Helper()
	return mustNew(f.t, f.config(change))
}

// withVerifier is a change that registers the verifier of a store.
func withVerifier(store handoff.Store, v handoff.EvidenceVerifier) func(c *handoff.Config) {
	return func(c *handoff.Config) { c.Evidence = map[handoff.Store]handoff.EvidenceVerifier{store: v} }
}

// goodEvidence is what a verifier would read from a good key of the store: the key of the subkey, and the
// values that the policy allows.
func (f *pgpFixture) goodEvidence(store handoff.Store) *handoff.Evidence {
	ev := &handoff.Evidence{Key: f.sub.pub()}
	switch store {
	case handoff.StorePIV:
		ev.Firmware, ev.PINPolicy, ev.TouchPolicy = "5.8.0", handoff.PINOnce, "always"
	case handoff.StoreKMS:
		ev.SignPrincipals = []handoff.Principal{{ARN: "arn:aws:iam::123456789012:role/example-holder", Kind: handoff.PrincipalRole}}
	}
	return ev
}

// accepts runs the checker on the request and checks that the request is accepted.
func (f *pgpFixture) mustAccept(c *handoff.Checker) handoff.Verdict {
	f.t.Helper()
	v, err := c.Check(f.t.Context(), f.request())
	wantAccepted(f.t, v, err)
	return v
}

// subPublicKeyDER is the SubjectPublicKeyInfo of the subkey.
func (f *pgpFixture) subPublicKeyDER() []byte {
	der, err := x509.MarshalPKIXPublicKey(f.sub.pub())
	if err != nil {
		f.t.Fatal(err)
	}
	return der
}

// flipBit returns a copy of b with one bit changed.
func flipBit(b []byte, i int) []byte {
	out := slices.Clone(b)
	out[i/8] ^= 1 << (i % 8)
	return out
}

// verifierOf is a verifier that gives the subkey's key (read from the request's file by the test itself) and the
// evidence of a good key, and records what it was given.
type recordingVerifier struct {
	fixture *pgpFixture
	store   handoff.Store
	calls   int
	req     *handoff.Request
	proof   *handoff.Proof
	now     time.Time
}

func (r *recordingVerifier) Verify(_ context.Context, req *handoff.Request, p *handoff.Proof, now time.Time) (*handoff.Evidence, error) {
	r.calls++
	r.req, r.proof, r.now = req, p, now
	return r.fixture.goodEvidence(r.store), nil
}
