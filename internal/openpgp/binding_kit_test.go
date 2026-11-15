package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"testing"
	"unicode/utf8"

	gopacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
)

// The helpers of the tests of the binding reader (docs/reference/hand-off-contract.md, "OpenPGP
// subkey", "What comes back"). They write bindings by hand, with their own signer and their own
// packet reader, so that the code under test is never the one that made or read its input.

// bindKit is a primary, a subkey with a back-signature for that primary, and the pieces that a
// binding of the page is made of. spec gives the page's binding as a signature to build; a test
// changes the spec to make a binding that the page forbids, and the signature still verifies.
type bindKit struct {
	key     *ecdsa.PrivateKey // the primary's private key
	primary *openpgp.PrimaryKey
	sub     subkeyMaterial
	subKey  *openpgp.Subkey
	fp      []byte // the 20 bytes of the primary's fingerprint
	life    uint32 // the key expiration time, in seconds after the subkey's creation
}

// kitLife is the expiry the kit asks for: 13 months after the ceremony, as the page's certificates.
func kitLife() uint32 {
	return uint32(ceremony.AddDate(1, 1, 0).Unix() - subAt.Unix())
}

// newBindKit makes a kit with fresh keys: the primary was created at `created`, the subkey two
// hours before the ceremony.
func newBindKit(t testing.TB) bindKit {
	t.Helper()
	return kitFromKeys(t, genKey(t), genKey(t))
}

// fixedKey is a P-384 key made from a label, so that a fuzz target built in several processes has
// the same keys in each of them.
func fixedKey(t testing.TB, label string) *ecdsa.PrivateKey {
	t.Helper()
	sum := sha512.Sum512([]byte("ritueel binding test key: " + label))
	d := new(big.Int).SetBytes(sum[:])
	d.Mod(d, new(big.Int).Sub(elliptic.P384().Params().N, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P384(), d.FillBytes(make([]byte, 48)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newFixedBindKit(t testing.TB, label string) bindKit {
	t.Helper()
	return kitFromKeys(t, fixedKey(t, label+" primary"), fixedKey(t, label+" subkey"))
}

func kitFromKeys(t testing.TB, primary, sub *ecdsa.PrivateKey) bindKit {
	t.Helper()
	pk, err := openpgp.NewPrimaryKey(&primary.PublicKey, created)
	if err != nil {
		t.Fatalf("NewPrimaryKey: %v", err)
	}
	m := subkeyMaterial{Key: sub, Created: subAt, Primary: &primary.PublicKey, PrimaryAt: created}
	m.Packet = wrap(tagSubkey, keyBody(&sub.PublicKey, subAt))
	m.BackSig = backSig(t, sub, subAt, &primary.PublicKey, created, nil)
	m.BackBody = splitPackets(t, m.BackSig)[0].Body
	sk, err := openpgp.ReadSubkey(m.Packet)
	if err != nil {
		t.Fatalf("ReadSubkey: %v", err)
	}
	return bindKit{key: primary, primary: pk, sub: m, subKey: sk, fp: fingerprint(&primary.PublicKey, created), life: kitLife()}
}

// spec is the binding of the page, as BindSubkey writes it, for the capability "sign".
func (k bindKit) spec() sigSpec {
	return sigSpec{
		Type: 0x18,
		Hashed: []sub{
			{Type: 2, Data: u32(uint32(ceremony.Unix()))},
			{Type: 27, Data: []byte{0x02}},
			{Type: 9, Critical: true, Data: u32(k.life)},
			{Type: 33, Data: append([]byte{4}, k.fp...)},
		},
		Unhashed: []sub{
			{Type: 16, Data: bytes.Clone(k.fp[12:])},
			{Type: 32, Data: bytes.Clone(k.sub.BackBody)},
		},
		Data: [][]byte{hashPrefix(&k.key.PublicKey, created), hashPrefix(&k.sub.Key.PublicKey, k.sub.Created)},
		Key:  k.key,
	}
}

// build writes the binding packet of the spec after tweak has changed it.
func (k bindKit) build(t testing.TB, tweak func(*sigSpec)) []byte {
	t.Helper()
	sp := k.spec()
	if tweak != nil {
		tweak(&sp)
	}
	return sp.build(t)
}

// verify is VerifyBinding with the primary and the subkey of the kit.
func (k bindKit) verify(pkt []byte) (*openpgp.Binding, error) {
	return openpgp.VerifyBinding(pkt, k.primary, k.subKey)
}

// verifySafely is verify that reports a panic as a failure of the test and not as a crash.
func (k bindKit) verifySafely(t testing.TB, what string, pkt []byte) (b *openpgp.Binding, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: VerifyBinding panicked: %v", what, r)
			b, err = nil, errors.New("panic")
		}
	}()
	return k.verify(pkt)
}

// assertAccepted fails the test unless the kit accepts pkt.
func (k bindKit) assertAccepted(t testing.TB, what string, pkt []byte) *openpgp.Binding {
	t.Helper()
	b, err := k.verifySafely(t, what, pkt)
	if err != nil || b == nil {
		t.Errorf("%s: VerifyBinding = %v, %v; want an accepted binding", what, b, err)
		return nil
	}
	return b
}

// assertFault fails the test unless the kit refuses pkt with kind, and with nothing else: no binding
// is returned, the error is an ErrAnswer, an ErrBinding is not an ErrBindingShape and an
// ErrBindingShape is not an ErrBinding, and the text is short and valid UTF-8.
func (k bindKit) assertFault(t testing.TB, what string, pkt []byte, kind error) {
	t.Helper()
	b, err := k.verifySafely(t, what, pkt)
	assertFaultResult(t, what, b, err, kind)
}

func assertFaultResult(t testing.TB, what string, b *openpgp.Binding, err error, kind error) {
	t.Helper()
	if b != nil {
		t.Errorf("%s: a binding was returned with the error %v", what, err)
	}
	if !errors.Is(err, kind) {
		t.Errorf("%s: error = %v, want one of kind %v", what, err, kind)
		return
	}
	if !errors.Is(err, openpgp.ErrAnswer) {
		t.Errorf("%s: error %v is not an ErrAnswer", what, err)
	}
	other := openpgp.ErrBindingShape
	if errors.Is(kind, openpgp.ErrBindingShape) {
		other = openpgp.ErrBinding
	}
	if errors.Is(err, other) {
		t.Errorf("%s: error %v is also %v", what, err, other)
	}
	if errors.Is(err, openpgp.ErrParams) || errors.Is(err, openpgp.ErrRequest) || errors.Is(err, openpgp.ErrBoundFile) {
		t.Errorf("%s: error %v is of a kind that is not a fault of a binding", what, err)
	}
	checkErrorText(t, what, err)
}

// checkErrorText holds the text of an error to what a person can read: valid UTF-8, one line, short.
// No byte of an answer is copied into it.
func checkErrorText(t testing.TB, what string, err error) {
	t.Helper()
	text := err.Error()
	if !utf8.ValidString(text) || len(text) > 300 || bytes.ContainsAny([]byte(text), "\n\r\x00") {
		t.Errorf("%s: the text of the error is not one short line of UTF-8: %q", what, text)
	}
}

// layout is where the parts of a signature body are.
type layout struct {
	hashedLen, unhashedLen          int
	hashedAt, unhashedAt, tagAt, rs int
}

func layoutOf(body []byte) layout {
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	ul := int(binary.BigEndian.Uint16(body[6+hl : 8+hl]))
	return layout{hashedLen: hl, unhashedLen: ul, hashedAt: 6, unhashedAt: 8 + hl, tagAt: 8 + hl + ul, rs: 10 + hl + ul}
}

// bodyOf is the body of the one signature packet of pkt, as a copy that the test may change.
func bodyOf(t testing.TB, pkt []byte) []byte {
	t.Helper()
	ps := splitPackets(t, pkt)
	if len(ps) != 1 || ps[0].Tag != tagSignature {
		t.Fatalf("bodyOf: tags % d, want one signature", tags(ps))
	}
	return bytes.Clone(ps[0].Body)
}

// withBody is a signature packet with a new-format header and the given body.
func withBody(body []byte) []byte { return wrap(tagSignature, body) }

// withEmbedded is a spec tweak that puts the given bytes in the embedded signature subpacket.
func withEmbedded(data []byte) func(*sigSpec) {
	return func(sp *sigSpec) { sp.Unhashed[1].Data = data }
}

// The independent reader: a second way to read a version 4 signature, which reports a fault as a
// value and never stops the test, so that a fuzz target can compare it with the code under test.

type softSig struct {
	hashed, unhashed []sub
	fields, rest     []byte
	typ, algo, hash  byte
}

// softPacket reads the first packet of b. ok is false for a packet that is not whole, with a partial
// or an indeterminate length.
func softPacket(b []byte) (tag byte, body, rest []byte, ok bool) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return 0, nil, nil, false
	}
	var hl, n int
	if b[0]&0x40 != 0 {
		tag = b[0] & 0x3F
		switch l := int(b[1]); {
		case l < 192:
			hl, n = 2, l
		case l < 224:
			if len(b) < 3 {
				return 0, nil, nil, false
			}
			hl, n = 3, (l-192)<<8+int(b[2])+192
		case l == 255:
			if len(b) < 6 {
				return 0, nil, nil, false
			}
			hl, n = 6, int(binary.BigEndian.Uint32(b[2:6]))
		default:
			return 0, nil, nil, false
		}
	} else {
		tag = (b[0] >> 2) & 0x0F
		switch b[0] & 3 {
		case 0:
			hl, n = 2, int(b[1])
		case 1:
			if len(b) < 3 {
				return 0, nil, nil, false
			}
			hl, n = 3, int(binary.BigEndian.Uint16(b[1:3]))
		case 2:
			if len(b) < 5 {
				return 0, nil, nil, false
			}
			hl, n = 5, int(binary.BigEndian.Uint32(b[1:5]))
		default:
			return 0, nil, nil, false
		}
	}
	if n < 0 || hl+n > len(b) {
		return 0, nil, nil, false
	}
	return tag, b[hl : hl+n], b[hl+n:], true
}

// softPackets reads every packet of b, or says that b is not whole packets.
func softPackets(b []byte) (tags []byte, bodies [][]byte, ok bool) {
	for len(b) > 0 {
		tag, body, rest, ok := softPacket(b)
		if !ok {
			return nil, nil, false
		}
		tags = append(tags, tag)
		bodies = append(bodies, body)
		b = rest
	}
	return tags, bodies, true
}

// softSubs reads a subpacket area, with at most limit subpackets (limit < 0: no limit).
func softSubs(b []byte, limit int) (out []sub, ok bool) {
	for len(b) > 0 {
		if limit >= 0 && len(out) >= limit {
			return nil, false
		}
		var n, hl int
		switch l := int(b[0]); {
		case l < 192:
			n, hl = l, 1
		case l < 255:
			if len(b) < 2 {
				return nil, false
			}
			n, hl = (l-192)<<8+int(b[1])+192, 2
		default:
			if len(b) < 5 {
				return nil, false
			}
			n, hl = int(binary.BigEndian.Uint32(b[1:5])), 5
		}
		if n < 1 || hl+n > len(b) {
			return nil, false
		}
		out = append(out, sub{Type: b[hl] & 0x7F, Critical: b[hl]&0x80 != 0, Data: b[hl+1 : hl+n]})
		b = b[hl+n:]
	}
	return out, true
}

// softSigBody reads the fixed fields and the two areas of a version 4 signature body, with at most
// limit subpackets in each area.
func softSigBody(body []byte, limit int) (softSig, bool) {
	var s softSig
	if len(body) < 8 || body[0] != 4 {
		return s, false
	}
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	if len(body) < 8+hl {
		return s, false
	}
	ul := int(binary.BigEndian.Uint16(body[6+hl : 8+hl]))
	if len(body) < 8+hl+ul {
		return s, false
	}
	var ok bool
	if s.hashed, ok = softSubs(body[6:6+hl], limit); !ok {
		return s, false
	}
	if s.unhashed, ok = softSubs(body[8+hl:8+hl+ul], limit); !ok {
		return s, false
	}
	s.typ, s.algo, s.hash = body[1], body[2], body[3]
	s.fields = body[:6+hl]
	s.rest = body[8+hl+ul:]
	return s, true
}

// onlyOne returns the data of the one subpacket of a type.
func onlyOne(subs []sub, typ byte) ([]byte, bool) {
	var out []byte
	n := 0
	for _, s := range subs {
		if s.Type == typ {
			out = s.Data
			n++
		}
	}
	return out, n == 1
}

// softSignatureValid checks, with the tests' own code, that body is a signature of the primary over
// the primary and the subkey: the hash tag is the start of the digest, the numbers are the two
// numbers of the standard and nothing follows them, and the ECDSA check passes.
func softSignatureValid(body []byte, primary, subPub *ecdsa.PublicKey, primaryAt, subCreated int64) bool {
	s, ok := softSigBody(body, -1)
	if !ok || len(s.rest) < 2 {
		return false
	}
	r, rest, ok := softMPI(s.rest[2:])
	if !ok {
		return false
	}
	v, rest, ok := softMPI(rest)
	if !ok || len(rest) != 0 {
		return false
	}
	trailer := []byte{4, 0xFF}
	trailer = append(trailer, u32(uint32(len(s.fields)))...)
	h := sha512.New384()
	h.Write(hashPrefixAt(primary, primaryAt))
	h.Write(hashPrefixAt(subPub, subCreated))
	h.Write(s.fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	if !bytes.Equal(digest[:2], s.rest[:2]) {
		return false
	}
	return ecdsa.Verify(primary, digest, new(big.Int).SetBytes(r), new(big.Int).SetBytes(v))
}

func hashPrefixAt(pub *ecdsa.PublicKey, at int64) []byte {
	body := []byte{4}
	body = append(body, u32(uint32(at))...)
	body = append(body, 19, 5, 0x2B, 0x81, 0x04, 0x00, 0x22)
	body = append(body, mpi(new(big.Int).SetBytes(point(pub)))...)
	return append([]byte{0x99, byte(len(body) >> 8), byte(len(body))}, body...)
}

// softMPI reads one number in the form the standard gives it, with no leading zero byte.
func softMPI(b []byte) (v, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	bits := int(binary.BigEndian.Uint16(b))
	n := (bits + 7) / 8
	if bits == 0 || len(b) < 2+n {
		return nil, nil, false
	}
	top := 0
	for c := b[2]; c != 0; c >>= 1 {
		top++
	}
	if bits != (n-1)*8+top {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

// goCryptoAccepts is go-crypto's own verdict on a binding, which is a third reader: it reads the
// two packets and verifies the binding with the key of the primary over the primary and the subkey,
// and for a signing subkey it also verifies the embedded signature.
func goCryptoAccepts(t testing.TB, primaryPub, subPub *ecdsa.PublicKey, primaryAt, subCreated int64, bindingPkt []byte) bool {
	t.Helper()
	read := func(tag byte, pub *ecdsa.PublicKey, at int64) *gopacket.PublicKey {
		body := []byte{4}
		body = append(body, u32(uint32(at))...)
		body = append(body, 19, 5, 0x2B, 0x81, 0x04, 0x00, 0x22)
		body = append(body, mpi(new(big.Int).SetBytes(point(pub)))...)
		p, err := gopacket.Read(bytes.NewReader(wrap(tag, body)))
		if err != nil {
			t.Fatalf("go-crypto cannot read a key: %v", err)
		}
		return p.(*gopacket.PublicKey)
	}
	p, err := gopacket.Read(bytes.NewReader(bindingPkt))
	if err != nil {
		return false
	}
	sig, ok := p.(*gopacket.Signature)
	if !ok {
		return false
	}
	return read(tagPublicKey, primaryPub, primaryAt).VerifyKeySignature(read(tagSubkey, subPub, subCreated), sig) == nil
}

// buildClaiming writes the binding of the spec with the algorithm and the hash that it names in its
// fields, whatever they are, and signs the SHA-384 digest of those fields, as a signature of the
// page does. The signature verifies under the digest that the reader computes, and what it declares
// is not what the page says; a program that reads the declared hash computes another digest.
func (k bindKit) buildClaiming(t testing.TB, algo, hash byte) []byte {
	t.Helper()
	sp := k.spec()
	hashed, unhashed := encodeSubs(sp.Hashed), encodeSubs(sp.Unhashed)
	fields := []byte{4, sp.Type, algo, hash, byte(len(hashed) >> 8), byte(len(hashed))}
	fields = append(fields, hashed...)
	trailer := []byte{4, 0xFF}
	trailer = append(trailer, u32(uint32(len(fields)))...)
	h := sha512.New384()
	for _, d := range sp.Data {
		h.Write(d)
	}
	h.Write(fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, k.key, digest)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Clone(fields)
	body = append(body, byte(len(unhashed)>>8), byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, digest[0], digest[1])
	body = append(body, mpi(r)...)
	body = append(body, mpi(s)...)
	return wrap(tagSignature, body)
}
