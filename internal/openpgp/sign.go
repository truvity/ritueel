package openpgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math/big"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// signer is the key that signs: the public half the builders use, and the crypto.Signer that makes
// the signature. The public half is asked of the signer once and copied.
type signer struct {
	*key
	s   crypto.Signer
	rnd io.Reader
}

// newSigner makes the signer of a primary from the parameters. The key of the signer must be an
// ECDSA P-384 key; the creation time is the primary's.
func newSigner(rnd io.Reader, s crypto.Signer, created time.Time) (*signer, error) {
	if isNil(s) {
		return nil, fail(ErrParams, "there is no key")
	}
	k, err := newKey(s.Public(), created)
	if err != nil {
		return nil, err
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	return &signer{key: k, s: s, rnd: rnd}, nil
}

// sigSpec is a signature to make: its type, its two subpacket areas, and the data it covers.
type sigSpec struct {
	sigType  byte
	hashed   []subpacket
	unhashed []subpacket
	data     [][]byte // what the hash covers before the signature's own fields
}

// sign makes the body of a version 4 signature packet: it hashes the data and the signature's
// fields (RFC 9580, section 5.2.4), has the signer sign the SHA-384 digest, checks the answer with
// the public key and writes the fields. It returns the body, which the caller wraps in a packet and
// reads back.
func (g *signer) sign(spec sigSpec) ([]byte, error) {
	hashed := encodeArea(spec.hashed)
	unhashed := encodeArea(spec.unhashed)
	if len(hashed) > 0xFFFF || len(unhashed) > 0xFFFF {
		return nil, fail(ErrParams, "a subpacket area is longer than 65535 bytes")
	}
	fields := []byte{4, spec.sigType, algoECDSA, hashSHA384, byte(len(hashed) >> 8), byte(len(hashed))}
	fields = append(fields, hashed...)
	trailer := []byte{4, 0xFF, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(trailer[2:], uint32(len(fields)))

	h := sha512.New384()
	for _, d := range spec.data {
		h.Write(d)
	}
	h.Write(fields)
	h.Write(trailer)
	digest := h.Sum(nil)

	// The signer is given a copy of the digest and never sees the data.
	der, err := g.s.Sign(g.rnd, bytes.Clone(digest), crypto.SHA384)
	if err != nil {
		return nil, fail(ErrSignature, "the signer failed: %v", err)
	}
	if !ecdsa.VerifyASN1(g.ec, digest, der) {
		return nil, fail(ErrSignature, "the signature of the signer does not verify with the public key")
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &rs); err != nil || len(rest) != 0 || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 {
		return nil, fail(ErrSignature, "the signature of the signer is not a DER ECDSA value")
	}

	body := bytes.Clone(fields)
	body = append(body, byte(len(unhashed)>>8), byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, digest[:2]...)
	body = append(body, mpi(rs.R)...)
	return append(body, mpi(rs.S)...), nil
}

// issuers are the two subpackets that every signature carries (record 0009, rule 8): the issuer
// fingerprint in the hashed area and the issuer key ID in the unhashed area.
func (k *key) issuerFingerprint() subpacket {
	return subpacket{typ: spIssuerFingerprint, data: append([]byte{4}, k.fp...)}
}

func (k *key) issuerKeyID() subpacket {
	return subpacket{typ: spIssuerKeyID, data: bytes.Clone(k.keyID)}
}

// readBack reads a finished signature packet with go-crypto and returns it. It must be exactly one
// signature packet, and both issuer subpackets must be where record 0009, rule 8 puts them: the
// fingerprint of the issuer in the hashed area, the key ID in the unhashed area.
func readBack(pkt []byte, issuer *key) (*packet.Signature, error) {
	tag, body, rest, err := splitPacket(pkt)
	if err != nil || tag != tagSignature || len(rest) != 0 {
		return nil, fail(ErrSignature, "the signature is not one packet")
	}
	if err := checkIssuers(ErrSignature, body, issuer); err != nil {
		return nil, err
	}
	p, err := packet.Read(bytes.NewReader(pkt))
	if err != nil {
		return nil, fail(ErrSignature, "the signature does not read back: %v", err)
	}
	sig, ok := p.(*packet.Signature)
	if !ok {
		return nil, fail(ErrSignature, "the packet does not read back as a signature")
	}
	return sig, nil
}

// checkIssuers checks that a signature body names issuer by its fingerprint (hashed area) and by
// its key ID (unhashed area), once each.
func checkIssuers(kind error, body []byte, issuer *key) error {
	a, err := splitSig(body)
	if err != nil {
		return fail(kind, "the signature fields are damaged")
	}
	fp, ok := find(a.hashed, spIssuerFingerprint)
	if !ok || !bytes.Equal(fp, append([]byte{4}, issuer.fp...)) {
		return fail(kind, "the hashed area has no issuer fingerprint of the issuer")
	}
	id, ok := find(a.unhashed, spIssuerKeyID)
	if !ok || !bytes.Equal(id, issuer.keyID) {
		return fail(kind, "the unhashed area has no issuer key ID of the issuer")
	}
	if count(a.hashed, spIssuerKeyID) != 0 || count(a.unhashed, spIssuerFingerprint) != 0 {
		return fail(kind, "an issuer subpacket is in the wrong area")
	}
	return nil
}
