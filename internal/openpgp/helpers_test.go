package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math/big"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// The moments of the test vectors: the creation time of the primaries (2026-01-01) and a ceremony
// time (2026-11-15 12:00:00 UTC).
var (
	created  = time.Unix(1767225600, 0).UTC()
	ceremony = time.Unix(1794744000, 0).UTC()
)

const (
	tagSignature = 2
	tagPublicKey = 6
	tagUserID    = 13
	tagSubkey    = 14
)

// A packet reader of the tests. It is written apart from the code under test, so that the layout
// is read by a second reader.

type packet struct {
	Tag       byte
	Body      []byte
	HeaderLen int
	Raw       []byte
}

// splitPackets reads every packet of b, in the new format (any length form) and the old format.
func splitPackets(t testing.TB, b []byte) []packet {
	t.Helper()
	var out []packet
	for len(b) > 0 {
		if len(b) < 2 || b[0]&0x80 == 0 {
			t.Fatalf("splitPackets: not a packet header: % x", b[:min(len(b), 8)])
		}
		var tag byte
		var hl, n int
		if b[0]&0x40 != 0 {
			tag = b[0] & 0x3F
			switch l := int(b[1]); {
			case l < 192:
				hl, n = 2, l
			case l < 224:
				hl, n = 3, (l-192)<<8+int(b[2])+192
			case l == 255:
				hl, n = 6, int(binary.BigEndian.Uint32(b[2:6]))
			default:
				t.Fatalf("splitPackets: a partial length")
			}
		} else {
			tag = (b[0] >> 2) & 0x0F
			switch b[0] & 3 {
			case 0:
				hl, n = 2, int(b[1])
			case 1:
				hl, n = 3, int(binary.BigEndian.Uint16(b[1:3]))
			case 2:
				hl, n = 5, int(binary.BigEndian.Uint32(b[1:5]))
			default:
				t.Fatalf("splitPackets: an indeterminate length")
			}
		}
		if hl+n > len(b) {
			t.Fatalf("splitPackets: a packet of %d bytes in %d", hl+n, len(b))
		}
		out = append(out, packet{Tag: tag, Body: b[hl : hl+n], HeaderLen: hl, Raw: b[:hl+n]})
		b = b[hl+n:]
	}
	return out
}

func tags(ps []packet) []byte {
	var out []byte
	for _, p := range ps {
		out = append(out, p.Tag)
	}
	return out
}

// sub is one signature subpacket.
type sub struct {
	Type     byte
	Critical bool
	Data     []byte
}

func parseSubs(t testing.TB, b []byte) []sub {
	t.Helper()
	var out []sub
	for len(b) > 0 {
		var n, hl int
		switch l := int(b[0]); {
		case l < 192:
			n, hl = l, 1
		case l < 255:
			n, hl = (l-192)<<8+int(b[1])+192, 2
		default:
			n, hl = int(binary.BigEndian.Uint32(b[1:5])), 5
		}
		if n < 1 || hl+n > len(b) {
			t.Fatalf("parseSubs: a subpacket of %d bytes in %d", hl+n, len(b))
		}
		out = append(out, sub{Type: b[hl] & 0x7F, Critical: b[hl]&0x80 != 0, Data: b[hl+1 : hl+n]})
		b = b[hl+n:]
	}
	return out
}

func types(s []sub) []byte {
	var out []byte
	for _, x := range s {
		out = append(out, x.Type)
	}
	return out
}

func critical(s []sub) []byte {
	var out []byte
	for _, x := range s {
		if x.Critical {
			out = append(out, x.Type)
		}
	}
	return out
}

// sigInfo is a version 4 signature taken apart.
type sigInfo struct {
	Version, Type, Algo, Hash byte
	HashedRaw, UnhashedRaw    []byte
	Hashed, Unhashed          []sub
	Tag                       []byte
	R, S                      *big.Int
	Fields                    []byte // version up to the end of the hashed area: what the hash covers
}

func parseSig(t testing.TB, body []byte) sigInfo {
	t.Helper()
	var s sigInfo
	if len(body) < 8 {
		t.Fatalf("parseSig: a signature body of %d bytes", len(body))
	}
	s.Version, s.Type, s.Algo, s.Hash = body[0], body[1], body[2], body[3]
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	s.Fields = body[:6+hl]
	s.HashedRaw = body[6 : 6+hl]
	ul := int(binary.BigEndian.Uint16(body[6+hl : 8+hl]))
	s.UnhashedRaw = body[8+hl : 8+hl+ul]
	s.Hashed = parseSubs(t, s.HashedRaw)
	s.Unhashed = parseSubs(t, s.UnhashedRaw)
	rest := body[8+hl+ul:]
	s.Tag, rest = rest[:2], rest[2:]
	read := func() *big.Int {
		bits := int(binary.BigEndian.Uint16(rest[:2]))
		n := (bits + 7) / 8
		v := new(big.Int).SetBytes(rest[2 : 2+n])
		rest = rest[2+n:]
		return v
	}
	s.R = read()
	s.S = read()
	if len(rest) != 0 {
		t.Fatalf("parseSig: %d bytes after the two values", len(rest))
	}
	return s
}

// find returns the one subpacket of a type, and fails when there is not exactly one.
func find(t testing.TB, subs []sub, typ byte) sub {
	t.Helper()
	var got []sub
	for _, s := range subs {
		if s.Type == typ {
			got = append(got, s)
		}
	}
	if len(got) != 1 {
		t.Fatalf("%d subpackets of type %d, want 1", len(got), typ)
	}
	return got[0]
}

// A key of the tests.

func genKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mpi(v *big.Int) []byte {
	return append([]byte{byte(v.BitLen() >> 8), byte(v.BitLen())}, v.Bytes()...)
}

func u32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func point(pub *ecdsa.PublicKey) []byte {
	b, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// keyBody is the body of a version 4 ECDSA P-384 key packet.
func keyBody(pub *ecdsa.PublicKey, at time.Time) []byte {
	b := []byte{4}
	b = append(b, u32(uint32(at.Unix()))...)
	b = append(b, 19, 5, 0x2B, 0x81, 0x04, 0x00, 0x22)
	return append(b, mpi(new(big.Int).SetBytes(point(pub)))...)
}

func wrap(tag byte, body []byte) []byte {
	h := []byte{0xC0 | tag}
	switch n := len(body); {
	case n < 192:
		h = append(h, byte(n))
	case n < 8384:
		h = append(h, byte((n-192)>>8)+192, byte(n-192))
	default:
		h = append(h, 0xFF, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(h, body...)
}

// wrapLong writes a packet with the five-byte length that the test vectors use.
func wrapLong(tag byte, body []byte) []byte {
	n := len(body)
	h := []byte{0xC0 | tag, 0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	return append(h, body...)
}

// fingerprint is the version 4 fingerprint by the standard: SHA-1 over 0x99, the length and the body.
func fingerprint(pub *ecdsa.PublicKey, at time.Time) []byte {
	body := keyBody(pub, at)
	h := sha1.New() //nolint:gosec // see the import
	h.Write([]byte{0x99, byte(len(body) >> 8), byte(len(body))})
	h.Write(body)
	return h.Sum(nil)
}

func hashPrefix(pub *ecdsa.PublicKey, at time.Time) []byte {
	body := keyBody(pub, at)
	return append([]byte{0x99, byte(len(body) >> 8), byte(len(body))}, body...)
}

func encodeSub(s sub) []byte {
	n := len(s.Data) + 1
	var out []byte
	switch {
	case n < 192:
		out = []byte{byte(n)}
	case n < 16320:
		out = []byte{byte((n-192)>>8) + 192, byte(n - 192)}
	default:
		out = []byte{0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	typ := s.Type
	if s.Critical {
		typ |= 0x80
	}
	return append(append(out, typ), s.Data...)
}

func encodeSubs(subs []sub) []byte {
	var out []byte
	for _, s := range subs {
		out = append(out, encodeSub(s)...)
	}
	return out
}

// encodeSubLong writes a subpacket with the five-octet length form, which the standard allows for
// any length.
func encodeSubLong(s sub) []byte {
	n := len(s.Data) + 1
	typ := s.Type
	if s.Critical {
		typ |= 0x80
	}
	out := []byte{0xFF, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), typ}
	return append(out, s.Data...)
}

func encodeSubsLong(subs []sub) []byte {
	var out []byte
	for _, s := range subs {
		out = append(out, encodeSubLong(s)...)
	}
	return out
}

// oldHeader writes a packet in the old format (RFC 4880, section 4.2.1), with the shortest length
// form that holds the body.
func oldHeader(tag byte, body []byte) []byte {
	n := len(body)
	if n < 256 {
		return append([]byte{0x80 | tag<<2, byte(n)}, body...)
	}
	return append([]byte{0x80 | tag<<2 | 1, byte(n >> 8), byte(n)}, body...)
}

// sigSpec is a signature the tests build by hand, with the knobs of a bad one.
type sigSpec struct {
	Type     byte
	Hashed   []sub
	Unhashed []sub
	Data     [][]byte // what the hash covers before the fields
	Key      *ecdsa.PrivateKey
	// Hash is the OpenPGP hash identifier: 8 SHA-256, 9 SHA-384 (the default), 10 SHA-512.
	Hash byte
	// TagXOR is XORed into the two bytes that the packet holds as the start of the digest; the
	// signature itself is made over the true digest, so it still verifies.
	TagXOR [2]byte
	// Trailing is written after the two numbers of the signature.
	Trailing []byte
	// Numbers, when set, writes the two numbers of the signature in place of the usual form.
	Numbers func(r, s *big.Int) []byte
	// LongLengths writes every subpacket with the five-octet length form.
	LongLengths bool
	// OldHeader writes the packet with an old-format header.
	OldHeader bool
}

// build writes the signature packet of spec: the fields, the hash by the standard, the signature
// by Key. It is the tests' own builder, not the code under test.
func (sp sigSpec) build(t testing.TB) []byte {
	t.Helper()
	enc := encodeSubs
	if sp.LongLengths {
		enc = encodeSubsLong
	}
	hashed := enc(sp.Hashed)
	unhashed := enc(sp.Unhashed)
	hashID := sp.Hash
	if hashID == 0 {
		hashID = 9
	}
	fields := []byte{4, sp.Type, 19, hashID, byte(len(hashed) >> 8), byte(len(hashed))}
	fields = append(fields, hashed...)
	trailer := []byte{4, 0xFF}
	trailer = append(trailer, u32(uint32(len(fields)))...)
	var h hash.Hash
	switch hashID {
	case 8:
		h = sha256.New()
	case 10:
		h = sha512.New()
	default:
		h = sha512.New384()
	}
	for _, d := range sp.Data {
		h.Write(d)
	}
	h.Write(fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	der, err := ecdsa.SignASN1(rand.Reader, sp.Key, digest)
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}
	body := append([]byte{}, fields...)
	body = append(body, byte(len(unhashed)>>8), byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, digest[0]^sp.TagXOR[0], digest[1]^sp.TagXOR[1])
	if sp.Numbers != nil {
		body = append(body, sp.Numbers(rs.R, rs.S)...)
	} else {
		body = append(body, mpi(rs.R)...)
		body = append(body, mpi(rs.S)...)
	}
	body = append(body, sp.Trailing...)
	if sp.OldHeader {
		return oldHeader(tagSignature, body)
	}
	return wrap(tagSignature, body)
}

// verifySig checks a signature the way the standard says, with the tests' own code: the hash of
// the data, the fields and the trailer, and the ECDSA check with pub.
func verifySig(t testing.TB, pub *ecdsa.PublicKey, body []byte, data ...[]byte) bool {
	t.Helper()
	s := parseSig(t, body)
	trailer := []byte{4, 0xFF}
	trailer = append(trailer, u32(uint32(len(s.Fields)))...)
	h := sha512.New384()
	for _, d := range data {
		h.Write(d)
	}
	h.Write(s.Fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	if !bytes.Equal(digest[:2], s.Tag) {
		return false
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{s.R, s.S})
	if err != nil {
		t.Fatal(err)
	}
	return ecdsa.VerifyASN1(pub, digest, der)
}

// The subkey and its back-signature, as a requester makes them.

type subkeyMaterial struct {
	Key       *ecdsa.PrivateKey
	Created   time.Time
	Packet    []byte // the Public-Subkey packet
	BackSig   []byte // the back-signature packet over the given primary
	BackBody  []byte
	Primary   *ecdsa.PublicKey
	PrimaryAt time.Time
}

func (m subkeyMaterial) body() []byte { return keyBody(&m.Key.PublicKey, m.Created) }

// newSubkey makes a subkey created at subAt and its back-signature (type 0x19) over the primary.
func newSubkey(t testing.TB, primary *ecdsa.PublicKey, primaryAt, subAt time.Time) subkeyMaterial {
	t.Helper()
	return newSubkeyWith(t, primary, primaryAt, subAt, nil)
}

// newSubkeyWith is newSubkey with a change to the spec of the back-signature before it is built.
func newSubkeyWith(t testing.TB, primary *ecdsa.PublicKey, primaryAt, subAt time.Time, tweak func(*sigSpec)) subkeyMaterial {
	t.Helper()
	k := genKey(t)
	m := subkeyMaterial{Key: k, Created: subAt, Primary: primary, PrimaryAt: primaryAt}
	m.Packet = wrap(tagSubkey, keyBody(&k.PublicKey, subAt))
	m.BackSig = backSig(t, k, subAt, primary, primaryAt, tweak)
	m.BackBody = splitPackets(t, m.BackSig)[0].Body
	return m
}

// backSig builds the back-signature of subkey k, made at the creation time of the subkey. tweak may
// change the spec before it is built.
func backSig(t testing.TB, k *ecdsa.PrivateKey, subAt time.Time, primary *ecdsa.PublicKey, primaryAt time.Time, tweak func(*sigSpec)) []byte {
	t.Helper()
	fp := fingerprint(&k.PublicKey, subAt)
	sp := sigSpec{
		Type: 0x19,
		Hashed: []sub{
			{Type: 2, Data: u32(uint32(subAt.Unix()))},
			{Type: 33, Data: append([]byte{4}, fp...)},
		},
		Unhashed: []sub{{Type: 16, Data: fp[12:]}},
		Data:     [][]byte{hashPrefix(primary, primaryAt), hashPrefix(&k.PublicKey, subAt)},
		Key:      k,
	}
	if tweak != nil {
		tweak(&sp)
	}
	return sp.build(t)
}

// A signer of the tests that holds its key privately, as a card or a cloud key does.

type privateSigner struct {
	key     *ecdsa.PrivateKey
	calls   int
	digests [][]byte
	hashes  []crypto.SignerOpts
	rands   []io.Reader
	// sign, when set, makes the answer.
	sign func(digest []byte) ([]byte, error)
}

func newSigner(t testing.TB) *privateSigner { return &privateSigner{key: genKey(t)} }

func (s *privateSigner) Public() crypto.PublicKey { return &s.key.PublicKey }

func (s *privateSigner) Sign(rnd io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls++
	s.rands = append(s.rands, rnd)
	s.digests = append(s.digests, bytes.Clone(digest))
	s.hashes = append(s.hashes, opts)
	if s.sign != nil {
		return s.sign(digest)
	}
	return ecdsa.SignASN1(rand.Reader, s.key, digest)
}

// A signer that is not an ECDSA key of Go's: it names some other public key.
type fixedPublic struct {
	pub crypto.PublicKey
}

func (f fixedPublic) Public() crypto.PublicKey { return f.pub }
func (f fixedPublic) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("fixedPublic must not be asked to sign")
}

func (s *privateSigner) params() openpgp.PrimaryParams {
	return openpgp.PrimaryParams{
		Key:          s,
		CreationTime: created,
		CeremonyTime: ceremony,
		ExpiresAt:    ceremony.AddDate(3, 0, 0),
		UserID:       exampleUserID(true),
	}
}

// exampleUserID is the user ID of the vectors ("Example Test Release Root A", with the test mark
// when test is set), made by UserID.
func exampleUserID(test bool) string {
	id, err := openpgp.UserID("Example Test", "A", "release@example.org", test)
	if err != nil {
		panic(err)
	}
	return id
}

// fingerprintOf is the fingerprint of a key at a creation time, by the function under test.
func fingerprintOf(t testing.TB, pub *ecdsa.PublicKey, at time.Time) string {
	t.Helper()
	fp, err := openpgp.Fingerprint(pub, at)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	return fp
}

// The vectors.

func vector(t testing.TB, elem ...string) []byte {
	t.Helper()
	return testrepo.Read(t, append([]string{"testdata", "hand-off", "v1"}, elem...)...)
}

// vectorPrimary reads the public key of a vector primary: its key packet, its user ID and its
// self-signature.
func vectorPrimary(t testing.TB, label string) (pub *ecdsa.PublicKey, ps []packet) {
	t.Helper()
	ps = splitPackets(t, vector(t, "pki", "test-primary-"+label+".pgp"))
	if len(ps) != 3 || ps[0].Tag != tagPublicKey {
		t.Fatalf("the vector primary %s has tags % d", label, tags(ps))
	}
	body := ps[0].Body
	pt := body[6+6+2:]
	x, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pt)
	if err != nil {
		t.Fatal(err)
	}
	return x, ps
}

// assertRefused runs f and checks that it fails with kind and returns no bytes. A panic is a
// failure of the test that names it, and does not stop the other cases.
func assertRefused(t testing.TB, what string, f func() ([]byte, error), kind error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", what, r)
		}
	}()
	out, err := f()
	if !errors.Is(err, kind) {
		t.Errorf("%s: error = %v, want one that wraps %v", what, err, kind)
	}
	if out != nil {
		t.Errorf("%s returned %d bytes with an error", what, len(out))
	}
}

func hexLower(b []byte) string { return hex.EncodeToString(b) }

// offCurve is a key of the right type whose point is not on the curve P-384: the abscissa of one key
// and the ordinate of another.
func offCurve(t testing.TB) *ecdsa.PublicKey {
	t.Helper()
	a, b := genKey(t), genKey(t)
	//nolint:staticcheck // the coordinates are the only way to make a point that is not on the curve
	return &ecdsa.PublicKey{Curve: elliptic.P384(), X: a.X, Y: b.Y}
}

// abscissaOnly is a key on P-384 that has the abscissa of a key and no ordinate.
func abscissaOnly(t testing.TB) *ecdsa.PublicKey {
	t.Helper()
	//nolint:staticcheck // the coordinates are the only way to make a key with one of them missing
	return &ecdsa.PublicKey{Curve: elliptic.P384(), X: genKey(t).X}
}

// ordinateOnly is a key on P-384 that has the ordinate of a key and no abscissa.
func ordinateOnly(t testing.TB) *ecdsa.PublicKey {
	t.Helper()
	//nolint:staticcheck // the coordinates are the only way to make a key with one of them missing
	return &ecdsa.PublicKey{Curve: elliptic.P384(), Y: genKey(t).Y}
}
