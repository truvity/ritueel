package software

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"ritueel.id/ritueel/internal/openpgp"
)

// The OpenPGP helpers of the tests. They write packets by the standard (RFC 9580, section 5) apart
// from the code under test, so a file is checked by a second writer.

func pgpU32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func pgpMPI(v *big.Int) []byte {
	return append([]byte{byte(v.BitLen() >> 8), byte(v.BitLen())}, v.Bytes()...)
}

// pgpWrap writes a packet with a new-format header and the shortest length.
func pgpWrap(tag byte, body []byte) []byte {
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

// pgpKeyBody is the body of a version 4 ECDSA P-384 key packet.
func pgpKeyBody(pub *ecdsa.PublicKey, at time.Time) []byte {
	point, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	b := []byte{4}
	b = append(b, pgpU32(uint32(at.Unix()))...)
	b = append(b, 19, 5, 0x2B, 0x81, 0x04, 0x00, 0x22)
	return append(b, pgpMPI(new(big.Int).SetBytes(point))...)
}

func pgpHashPrefix(pub *ecdsa.PublicKey, at time.Time) []byte {
	body := pgpKeyBody(pub, at)
	return append([]byte{0x99, byte(len(body) >> 8), byte(len(body))}, body...)
}

func pgpFingerprint(pub *ecdsa.PublicKey, at time.Time) []byte {
	sum := sha1.Sum(pgpHashPrefix(pub, at)) //nolint:gosec // the version 4 fingerprint is a SHA-1 by the standard
	return sum[:]
}

// pgpSubpacket writes one signature subpacket with a length under 192.
func pgpSubpacket(typ byte, data []byte) []byte {
	n := len(data) + 1
	var out []byte
	switch {
	case n < 192:
		out = []byte{byte(n)}
	default:
		out = []byte{byte((n-192)>>8) + 192, byte(n - 192)}
	}
	out = append(out, typ)
	return append(out, data...)
}

// pgpSig writes a version 4 ECDSA signature packet with SHA-384 over data parts, the hashed and
// the unhashed areas as given, made with key.
func pgpSig(t testing.TB, sigType byte, hashed, unhashed []byte, data [][]byte, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	fields := []byte{4, sigType, 19, 9, byte(len(hashed) >> 8), byte(len(hashed))}
	fields = append(fields, hashed...)
	trailer := append([]byte{4, 0xFF}, pgpU32(uint32(len(fields)))...)
	h := sha512.New384()
	for _, d := range data {
		h.Write(d)
	}
	h.Write(fields)
	h.Write(trailer)
	digest := h.Sum(nil)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &rs); err != nil {
		t.Fatal(err)
	}
	body := bytes.Clone(fields)
	body = append(body, byte(len(unhashed)>>8), byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, digest[0], digest[1])
	body = append(body, pgpMPI(rs.R)...)
	body = append(body, pgpMPI(rs.S)...)
	return pgpWrap(2, body)
}

// pgpIssuer is the two subpackets that name the issuer: the fingerprint (hashed) and the key ID
// (unhashed).
func pgpIssuer(pub *ecdsa.PublicKey, at time.Time) (hashed, unhashed []byte) {
	fp := pgpFingerprint(pub, at)
	return pgpSubpacket(33, append([]byte{4}, fp...)), pgpSubpacket(16, fp[12:])
}

// pgpRevocation writes a key revocation signature (type 0x20) by key over its own public key, with
// the padding (an unhashed subpacket of a private type) that makes the packet as long as wanted
// when pad is more than zero.
func pgpRevocation(t testing.TB, key *ecdsa.PrivateKey, at time.Time, sigType byte, pad int) []byte {
	t.Helper()
	ih, iu := pgpIssuer(&key.PublicKey, at)
	hashed := append(pgpSubpacket(2, pgpU32(uint32(at.Unix()))), pgpSubpacket(29, append([]byte{2}, "compromised"...))...)
	hashed = append(hashed, ih...)
	unhashed := iu
	if pad > 0 {
		unhashed = append(unhashed, pgpSubpacket(110, make([]byte, pad))...)
	}
	return pgpSig(t, sigType, hashed, unhashed, [][]byte{pgpHashPrefix(&key.PublicKey, at)}, key)
}

// pgpArmor writes data as one armour block with the given headers and a final LF.
func pgpArmor(t testing.TB, blockType string, headers map[string]string, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, blockType, headers)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b.WriteByte('\n')
	return b.Bytes()
}

// testOnly is the one header of a test root's armour.
var testOnly = map[string]string{"Comment": "TEST ONLY"}

// pgpUnarmor reads an armour block with go-crypto and returns its type, headers and body.
func pgpUnarmor(t testing.TB, file []byte) (string, map[string]string, []byte) {
	t.Helper()
	blk, err := armor.Decode(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("armor.Decode: %v", err)
	}
	body := new(bytes.Buffer)
	if _, err := body.ReadFrom(blk.Body); err != nil {
		t.Fatalf("armor body: %v", err)
	}
	return blk.Type, blk.Header, body.Bytes()
}

// pgpPackets splits a run of packets with one- and two-byte lengths, as the packets of the
// profile have.
func pgpPackets(t testing.TB, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 2 || b[0]&0xC0 != 0xC0 {
			t.Fatalf("not a packet header: % x", b[:min(len(b), 4)])
		}
		hl, n := 2, int(b[1])
		switch {
		case n >= 224:
			t.Fatal("a length form the helper does not read")
		case n == 255:
			hl, n = 6, int(binary.BigEndian.Uint32(b[2:6]))
		case n >= 192:
			hl, n = 3, (n-192)<<8+int(b[2])+192
		}
		out = append(out, b[:hl+n])
		b = b[hl+n:]
	}
	return out
}

// pgpBody returns the body of a packet that pgpPackets returned.
func pgpBody(p []byte) []byte {
	switch {
	case p[1] == 255:
		return p[6:]
	case p[1] >= 192:
		return p[3:]
	}
	return p[2:]
}

// secretOf is the transferable secret key of a key and its certificate, from the package under test.
func secretOf(t testing.TB, k *Key, cert []byte) []byte {
	t.Helper()
	var out []byte
	if err := k.withPrivate(func(priv *ecdsa.PrivateKey) (err error) {
		out, err = openpgp.SecretKey(cert, priv)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}
