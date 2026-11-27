package openpgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
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

// sign makes the body of a version 4 signature packet with the key of the signer: ECDSA on P-384,
// as it always did (see [signWith]).
func (g *signer) sign(spec sigSpec) ([]byte, error) {
	return signWith(g.rnd, g.s, signKey{algo: algoECDSA, ec: g.ec}, spec)
}

// signKey is the public key that a signature is made and checked with, of one of the three
// algorithms of the signing step: RSA (PKCS#1 v1.5), EdDSA legacy on Ed25519 (algorithm 22) and ECDSA
// on P-384, each with SHA-384 (record 0002, rule 14). Only the field of its algorithm is set.
type signKey struct {
	algo byte
	rsa  *rsa.PublicKey
	ed   ed25519.PublicKey
	ec   *ecdsa.PublicKey
}

// opts is what the signer is told about the digest: its hash, which is SHA-384, except for Ed25519,
// which signs the digest as a message of its own and takes no hash (crypto.Hash(0)); the standard
// library refuses a hash in the options of an Ed25519 key.
func (k signKey) opts() crypto.SignerOpts {
	if k.algo == algoEdDSA {
		return crypto.Hash(0)
	}
	return crypto.SHA384
}

// values checks the answer of the signer against the public key with the standard library and writes
// the values of the signature as the standard has them (RFC 9580, section 5.2.3): for RSA the one number
// of the signature, for EdDSA and ECDSA the two numbers R and S. Nothing the signer answered is used
// before it verifies.
func (k signKey) values(digest, raw []byte) ([]byte, error) {
	notVerified := func() error {
		return fail(ErrSignature, "the signature of the signer does not verify with the public key")
	}
	switch k.algo {
	case algoRSA:
		if k.rsa == nil || rsa.VerifyPKCS1v15(k.rsa, crypto.SHA384, digest, raw) != nil {
			return nil, notVerified()
		}
		return mpi(new(big.Int).SetBytes(raw)), nil
	case algoEdDSA:
		if len(k.ed) != ed25519.PublicKeySize || len(raw) != ed25519.SignatureSize || !ed25519.Verify(k.ed, digest, raw) {
			return nil, notVerified()
		}
		out := mpi(new(big.Int).SetBytes(raw[:32]))
		return append(out, mpi(new(big.Int).SetBytes(raw[32:]))...), nil
	case algoECDSA:
		if k.ec == nil || !ecdsa.VerifyASN1(k.ec, digest, raw) {
			return nil, notVerified()
		}
		var rs struct{ R, S *big.Int }
		if rest, err := asn1.Unmarshal(raw, &rs); err != nil || len(rest) != 0 || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 {
			return nil, fail(ErrSignature, "the signature of the signer is not a DER ECDSA value")
		}
		return append(mpi(rs.R), mpi(rs.S)...), nil
	}
	return nil, fail(ErrSignature, "the algorithm of the key is not one that signs here")
}

// callSigner asks the signer for its answer and returns a copy of it: the check of the answer and its use
// are done on the copy, so that a signer that keeps its slice and changes it later changes nothing that was
// checked. A panic of the signer is a signature error with no bytes, as a panic of its Public is a refusal
// of the key. The cause that the signer gives is kept in the error, so that errors.Is finds it.
func callSigner(s crypto.Signer, rnd io.Reader, digest []byte, opts crypto.SignerOpts) (raw []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			raw, err = nil, fail(ErrSignature, "the signer panicked")
		}
	}()
	answer, err := s.Sign(rnd, digest, opts)
	if err != nil {
		return nil, fmt.Errorf("%w: the signer failed: %w", ErrSignature, err)
	}
	return bytes.Clone(answer), nil
}

// signWith makes the body of a version 4 signature packet: it hashes the data and the signature's
// fields (RFC 9580, section 5.2.4), has s sign the SHA-384 digest, checks the answer with the public
// key and writes the fields. It returns the body, which the caller wraps in a packet and reads back.
// The cause that the signer gives is kept in the error, so that errors.Is finds it.
func signWith(rnd io.Reader, s crypto.Signer, k signKey, spec sigSpec) ([]byte, error) {
	hashed := encodeArea(spec.hashed)
	unhashed := encodeArea(spec.unhashed)
	if len(hashed) > 0xFFFF || len(unhashed) > 0xFFFF {
		return nil, fail(ErrParams, "a subpacket area is longer than 65535 bytes")
	}
	fields := []byte{4, spec.sigType, k.algo, hashSHA384, byte(len(hashed) >> 8), byte(len(hashed))}
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
	raw, err := callSigner(s, rnd, bytes.Clone(digest), k.opts())
	if err != nil {
		return nil, err
	}
	vals, err := k.values(digest, raw)
	if err != nil {
		return nil, err
	}

	body := bytes.Clone(fields)
	body = append(body, byte(len(unhashed)>>8), byte(len(unhashed)))
	body = append(body, unhashed...)
	body = append(body, digest[:2]...)
	return append(body, vals...), nil
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
