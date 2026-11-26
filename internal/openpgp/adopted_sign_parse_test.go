package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
	"math/bits"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/verifier"
)

// The signatures that an adopted key makes, read by a parser of the tests that shares nothing with the
// code under test (it is written from RFC 9580, sections 4 and 5.2), and verified with the standard
// library, with go-crypto and, through internal/verifier, with gpgv and sqv.

// qaSub is one subpacket of an area.
type qaSub struct {
	Typ      byte
	Critical bool
	Data     []byte
}

// qaSig is a version 4 signature packet as the parser of the tests reads it.
type qaSig struct {
	HeaderLen                 int
	Version, Type, Algo, Hash byte
	HashedRaw, UnhashedRaw    []byte
	Hashed, Unhashed          []qaSub
	Fields                    []byte // what the hash covers after the data: version to the end of the hashed area
	Check                     []byte
	Values                    [][]byte // the numbers, without their bit counts
	Bits                      []int    // the bit counts as written
	Body                      []byte
}

// qaPacket reads one packet of the new format with the shortest header and nothing after it.
func qaPacket(t testing.TB, b []byte) (tag byte, hdr int, body []byte) {
	t.Helper()
	if len(b) < 2 || b[0]&0xC0 != 0xC0 {
		t.Fatalf("not a packet of the new format: % x", b[:min(len(b), 6)])
	}
	tag = b[0] & 0x3F
	var n int
	switch {
	case b[1] < 192:
		hdr, n = 2, int(b[1])
	case b[1] < 224:
		hdr, n = 3, (int(b[1])-192)<<8+int(b[2])+192
	case b[1] == 255:
		hdr, n = 6, int(binary.BigEndian.Uint32(b[2:6]))
	default:
		t.Fatalf("a partial length in a packet header")
	}
	short := 2
	if n >= 192 {
		short = 3
	}
	if n > 8383 {
		short = 6
	}
	if hdr != short {
		t.Fatalf("the header of the packet is %d bytes, the shortest for %d bytes is %d", hdr, n, short)
	}
	if len(b) != hdr+n {
		t.Fatalf("the packet is %d bytes, its header says %d", len(b), hdr+n)
	}
	return tag, hdr, b[hdr:]
}

// qaSubs reads the subpackets of an area, each with its length in the form of the standard.
func qaSubs(t testing.TB, area []byte) []qaSub {
	t.Helper()
	var out []qaSub
	for len(area) > 0 {
		var n, h int
		switch {
		case area[0] < 192:
			n, h = int(area[0]), 1
		case area[0] < 255:
			n, h = (int(area[0])-192)<<8+int(area[1])+192, 2
		default:
			n, h = int(binary.BigEndian.Uint32(area[1:5])), 5
		}
		if n < 1 || h+n > len(area) {
			t.Fatalf("a subpacket of length %d in %d bytes", n, len(area)-h)
		}
		out = append(out, qaSub{Typ: area[h] & 0x7F, Critical: area[h]&0x80 != 0, Data: bytes.Clone(area[h+1 : h+n])})
		area = area[h+n:]
	}
	return out
}

// qaParse reads a signature packet and holds the numbers to the form of RFC 9580, section 3.2: the bit
// count is that of the number and there is no leading zero byte.
func qaParse(t testing.TB, pkt []byte) qaSig {
	t.Helper()
	tag, hdr, body := qaPacket(t, pkt)
	if tag != 2 {
		t.Fatalf("the packet is tag %d, not a signature", tag)
	}
	s := qaSig{HeaderLen: hdr, Body: body}
	s.Version, s.Type, s.Algo, s.Hash = body[0], body[1], body[2], body[3]
	hl := int(binary.BigEndian.Uint16(body[4:6]))
	s.Fields = body[:6+hl]
	s.HashedRaw = body[6 : 6+hl]
	ul := int(binary.BigEndian.Uint16(body[6+hl:]))
	s.UnhashedRaw = body[8+hl : 8+hl+ul]
	s.Hashed, s.Unhashed = qaSubs(t, s.HashedRaw), qaSubs(t, s.UnhashedRaw)
	rest := body[8+hl+ul:]
	s.Check, rest = rest[:2], rest[2:]
	for len(rest) > 0 {
		n := int(binary.BigEndian.Uint16(rest))
		size := (n + 7) / 8
		if size == 0 || len(rest) < 2+size {
			t.Fatalf("a number of %d bits does not fit", n)
		}
		v := rest[2 : 2+size]
		if v[0] == 0 || n != (size-1)*8+bits.Len8(v[0]) {
			t.Fatalf("a number that is not in the minimal form: %d bits, first byte %#x, %d bytes", n, v[0], size)
		}
		s.Values, s.Bits = append(s.Values, bytes.Clone(v)), append(s.Bits, n)
		rest = rest[2+size:]
	}
	return s
}

// qaDigest is the SHA-384 digest of a signature over data (RFC 9580, section 5.2.4).
func (s qaSig) digest(data ...[]byte) []byte {
	h := sha512.New384()
	for _, d := range data {
		h.Write(d)
	}
	h.Write(s.Fields)
	h.Write([]byte{4, 0xFF})
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s.Fields))))
	return h.Sum(nil)
}

func qaPad(v []byte, n int) []byte {
	if len(v) > n {
		return nil
	}
	return append(make([]byte, n-len(v)), v...)
}

// qaVerifyValues checks the numbers of the signature with the standard library.
func qaVerifyValues(t testing.TB, pub crypto.PublicKey, s qaSig, digest []byte) {
	t.Helper()
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if s.Algo != 1 || len(s.Values) != 1 {
			t.Fatalf("an RSA key: algorithm %d with %d numbers", s.Algo, len(s.Values))
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA384, digest, qaPad(s.Values[0], (k.N.BitLen()+7)/8)); err != nil {
			t.Errorf("the RSA number does not verify: %v", err)
		}
	case ed25519.PublicKey:
		if s.Algo != 22 || len(s.Values) != 2 {
			t.Fatalf("an Ed25519 key: algorithm %d with %d numbers", s.Algo, len(s.Values))
		}
		raw := append(qaPad(s.Values[0], 32), qaPad(s.Values[1], 32)...)
		if len(raw) != 64 || !ed25519.Verify(k, digest, raw) {
			t.Errorf("the two Ed25519 numbers do not verify")
		}
	case *ecdsa.PublicKey:
		if s.Algo != 19 || len(s.Values) != 2 {
			t.Fatalf("an ECDSA key: algorithm %d with %d numbers", s.Algo, len(s.Values))
		}
		if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(s.Values[0]), new(big.Int).SetBytes(s.Values[1])) {
			t.Errorf("the two ECDSA numbers do not verify")
		}
	default:
		t.Fatalf("a public key of type %T", pub)
	}
}

// qaMade is an adopted key of the kit, its issuer, and its public key in the form of the standard library.
type qaMade struct {
	b       *fkBase
	k       *openpgp.ForeignKey
	a       *openpgp.AdoptedIssuer
	pub     crypto.PublicKey
	pubBody []byte
	fp      []byte
}

func qaNew(t testing.TB, b *fkBase) qaMade {
	t.Helper()
	k, a := fkAdopted(t, b)
	return qaMade{b: b, k: k, a: a, pub: fkStdSigner(t, b).Public(), pubBody: fkSplit(t, k.Certificate())[0].Body, fp: bytes.Clone(b.ent.PrimaryKey.Fingerprint)}
}

// keyData is what a signature of the key itself covers before its fields.
func (m qaMade) keyData() []byte {
	return append([]byte{0x99, byte(len(m.pubBody) >> 8), byte(len(m.pubBody))}, m.pubBody...)
}

// qaCheck reads the signature that an adopted key made as the standard has it, and verifies it with the
// standard library. It returns the parsed signature.
func (m qaMade) check(t testing.TB, pkt []byte, typ byte, at time.Time, data ...[]byte) qaSig {
	t.Helper()
	s := qaParse(t, pkt)
	want := map[string]byte{"rsa4096": 1, "ed25519": 22, "p384": 19}[m.b.name]
	if s.Version != 4 || s.Type != typ || s.Algo != want || s.Hash != 9 {
		t.Errorf("version %d type %#x algorithm %d hash %d, want 4 %#x %d 9 (SHA-384)", s.Version, s.Type, s.Algo, s.Hash, typ, want)
	}
	// the hashed area: the creation time, then the issuer fingerprint last, nothing else, nothing critical
	if len(s.Hashed) != 2 || s.Hashed[0].Typ != 2 || s.Hashed[1].Typ != 33 {
		t.Fatalf("the hashed area is %+v, want the creation time and the issuer fingerprint", s.Hashed)
	}
	if got := binary.BigEndian.Uint32(s.Hashed[0].Data); len(s.Hashed[0].Data) != 4 || int64(got) != at.Unix() {
		t.Errorf("the creation time is %v, want %d", s.Hashed[0].Data, at.Unix())
	}
	if !bytes.Equal(s.Hashed[1].Data, append([]byte{4}, m.fp...)) {
		t.Errorf("the issuer fingerprint is %x, want 04 and %x", s.Hashed[1].Data, m.fp)
	}
	// the unhashed area: the issuer key ID alone
	if len(s.Unhashed) != 1 || s.Unhashed[0].Typ != 16 || !bytes.Equal(s.Unhashed[0].Data, m.fp[12:]) {
		t.Errorf("the unhashed area is %+v, want the issuer key ID alone", s.Unhashed)
	}
	for _, p := range qaConcat(s.Hashed, s.Unhashed) {
		if p.Critical {
			t.Errorf("subpacket %d is critical", p.Typ)
		}
	}
	d := s.digest(data...)
	if !bytes.Equal(s.Check, d[:2]) {
		t.Errorf("the two check bytes are %x, the digest starts %x", s.Check, d[:2])
	}
	qaVerifyValues(t, m.pub, s, d)
	return s
}

func qaConcat(a, b []qaSub) []qaSub { return append(append([]qaSub(nil), a...), b...) }

// qaTools runs a detached signature through go-crypto, gpgv and sqv: the three accept it when want is true
// and refuse it when it is false. The ring is the certificate with a direct-key signature after the
// primary, as in the measurement.
func (m qaMade) tools(t *testing.T, ring, sig, msg []byte, at time.Time, want bool) {
	t.Helper()
	ents, err := pgp.ReadKeyRing(bytes.NewReader(ring))
	if err != nil || len(ents) != 1 {
		t.Fatalf("go-crypto does not read the ring: %v", err)
	}
	_, gerr := pgp.CheckDetachedSignature(ents, bytes.NewReader(msg), bytes.NewReader(sig), nil)
	if (gerr == nil) != want {
		t.Errorf("go-crypto: %v, want accepted=%v", gerr, want)
	}
	fp := m.k.Primary.Fingerprint
	if err := verifier.GPGVVerify(t, ring, sig, msg, fp); (err == nil) != want {
		t.Errorf("gpgv: %v, want accepted=%v", err, want)
	}
	if err := verifier.SQVVerify(t, ring, sig, msg, fp, at.Add(time.Hour)); (err == nil) != want {
		t.Errorf("sqv: %v, want accepted=%v", err, want)
	}
}

func TestQAAdoptedSignatureIsWhatTheStandardSaysAndEveryVerifierAgrees(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		m := qaNew(t, b)
		dksAt, msgAt := fkEpoch.Add(24*time.Hour), fkEpoch.Add(48*time.Hour)
		msg := []byte("the release of example.org version 2.0.0\n")
		dks, err := openpgp.DirectKeySignatureFor(rand.Reader, m.a, dksAt)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := openpgp.DetachedSignatureFor(rand.Reader, m.a, msgAt, msg)
		if err != nil {
			t.Fatal(err)
		}
		ds := m.check(t, dks, 0x1F, dksAt, m.keyData())
		ss := m.check(t, sig, 0x00, msgAt, msg)
		// the number of numbers and their size
		wantN := map[string]int{"rsa4096": 1, "ed25519": 2, "p384": 2}[b.name]
		if len(ds.Values) != wantN || len(ss.Values) != wantN {
			t.Errorf("%d and %d numbers, want %d", len(ds.Values), len(ss.Values), wantN)
		}
		// the same packet is not made twice for another time: the creation time is the caller's
		sig2, err := openpgp.DetachedSignatureFor(rand.Reader, m.a, msgAt.Add(time.Second), msg)
		if err != nil || bytes.Equal(sig, sig2) {
			t.Errorf("a signature at another time: %v, equal=%v", err, bytes.Equal(sig, sig2))
		}
		m.check(t, sig2, 0x00, msgAt.Add(time.Second), msg)

		// go-crypto reads and verifies the direct-key signature in its own way
		ring := fkWithKeySig(t, m.k.Certificate(), dks)
		ents, err := pgp.ReadKeyRing(bytes.NewReader(ring))
		if err != nil || len(ents) != 1 {
			t.Fatalf("go-crypto does not read the ring: %v", err)
		}
		p, err := gpacket.Read(bytes.NewReader(dks))
		if err != nil {
			t.Fatal(err)
		}
		g := p.(*gpacket.Signature)
		if g.SigType != gpacket.SigTypeDirectSignature || g.Hash != crypto.SHA384 || !g.CreationTime.Equal(dksAt) {
			t.Errorf("go-crypto reads %+v", g)
		}
		if err := ents[0].PrimaryKey.VerifyDirectKeySignature(g); err != nil {
			t.Errorf("go-crypto does not verify the direct-key signature: %v", err)
		}
		if len(ents[0].Identities) == 0 {
			t.Fatal("no identity")
		}

		// the three verifiers accept; each refuses one bit changed in the number, in the message, and in the
		// creation time that the hash covers
		m.tools(t, ring, sig, msg, msgAt, true)
		flipped := bytes.Clone(sig)
		flipped[len(flipped)-1] ^= 1
		m.tools(t, ring, flipped, msg, msgAt, false)
		creation := bytes.Clone(sig)
		creation[ss.HeaderLen+6+1+1+3] ^= 1 // the last byte of the creation time, which the hash covers
		m.tools(t, ring, creation, msg, msgAt, false)
		badMsg := bytes.Clone(msg)
		badMsg[3] ^= 1
		m.tools(t, ring, sig, badMsg, msgAt, false)
		numbers := 0
		for _, v := range ss.Values {
			numbers += 2 + len(v)
		}
		firstByte := bytes.Clone(sig)
		firstByte[len(sig)-numbers+2] ^= 0x10 // the first byte of the first number
		m.tools(t, ring, firstByte, msg, msgAt, false)
	})
}

// A number with a leading zero byte is written without it, and every reader pads it again. RSA makes
// one in 256 signatures with such a number, ECDSA one in 256 for each of its two, Ed25519 one in 256 for R
// and one in 16 for S. The signatures are made until one of each kind is found (the loops are bounded),
// each found one is read by the parser of the tests, verified by the standard library and go-crypto, and
// one of each kind by gpgv and sqv.
func TestQAShortNumbersAreWrittenWithoutTheirLeadingZero(t *testing.T) {
	fkEachBase(t, func(t *testing.T, b *fkBase) {
		m := qaNew(t, b)
		full := map[string]int{"rsa4096": 512, "ed25519": 32, "p384": 48}[b.name]
		bound := map[string]int{"rsa4096": 6000, "ed25519": 3000, "p384": 6000}[b.name]
		msg := []byte("a message for the short numbers\n")
		type found struct {
			sig []byte
			at  time.Time
		}
		got := map[int]found{}
		want := map[string]int{"rsa4096": 1, "ed25519": 2, "p384": 2}[b.name]
		start := time.Now()
		tries := 0
		for i := 0; i < bound && len(got) < want; i++ {
			at := fkEpoch.Add(time.Hour + time.Duration(i)*time.Second)
			sig, err := openpgp.DetachedSignatureFor(rand.Reader, m.a, at, msg)
			if err != nil {
				t.Fatal(err)
			}
			tries++
			s := qaParse(t, sig) // refuses a number that is not minimal
			for j, v := range s.Values {
				if _, ok := got[j]; !ok && len(v) < full {
					got[j] = found{sig, at}
				}
			}
		}
		t.Logf("%s: %d signatures made in %v, short numbers found at positions %v", b.name, tries, time.Since(start), len(got))
		if len(got) < want {
			t.Fatalf("%d of %d kinds of short number in %d signatures", len(got), want, bound)
		}
		for j, f := range got {
			s := m.check(t, f.sig, 0x00, f.at, msg)
			if len(s.Values[j]) >= full {
				t.Fatalf("the number %d is not short", j)
			}
			// the number as the standard writes it: the bit count is of the number, and the verifiers pad
			ring := m.k.Certificate()
			m.tools(t, ring, f.sig, msg, f.at, true)
		}
	})
}
