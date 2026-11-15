package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"time"
)

// This file reads a subkey request: the file `<stem>.subkey.pgp` of the hand-off
// (docs/reference/hand-off-contract.md, "OpenPGP subkey", "The request"). It holds one
// Public-Subkey packet followed by one back-signature for each listed primary. The functions here
// are the reader that the certifier's checks use and the reader that [BindSubkey] uses, so that the
// request that is checked is the request that is bound.

// PrimaryKey is the public key packet of one active primary, as the certifier holds it: the key and
// its creation time, which together fix the fingerprint and the bytes that a back-signature covers.
// The zero value holds no key and is refused wherever a key is needed.
type PrimaryKey struct {
	k *key
	// test is set by [ReadKeyring] when the user ID of the certificate that the primary was read from
	// carries the test mark.
	test bool
}

// NewPrimaryKey makes the primary of a public key and its creation time (openpgp_created of
// root.json). A key that is nil, is not ECDSA, is not on P-384, is not a point of the curve, or a
// time that has a fraction of a second or is outside the years 1970 to 2106, is an [ErrParams].
// Nothing is returned with an error.
func NewPrimaryKey(pub *ecdsa.PublicKey, created time.Time) (*PrimaryKey, error) {
	if pub == nil {
		return nil, fail(ErrParams, "there is no key")
	}
	k, err := newKey(pub, created)
	if err != nil {
		return nil, err
	}
	return &PrimaryKey{k: k}, nil
}

// Fingerprint is the version 4 fingerprint of the primary: 40 lower-case hexadecimal digits. It is
// empty for a nil or zero value.
func (p *PrimaryKey) Fingerprint() string {
	if p == nil || p.k == nil {
		return ""
	}
	return hex.EncodeToString(p.k.fp)
}

// Created is the creation time of the primary, in UTC. It is the zero time for a nil or zero value.
func (p *PrimaryKey) Created() time.Time {
	if p == nil || p.k == nil {
		return time.Time{}
	}
	return p.k.created
}

// TestMark reports whether the primary was read by [ReadKeyring] from a certificate whose user ID
// carries the mark " (TEST ONLY)". All the primaries of one accepted keyring file give the same
// answer, because a file that mixes the two is refused. It is false for a primary that
// [NewPrimaryKey] made, which has no user ID, and for a nil or zero value.
func (p *PrimaryKey) TestMark() bool {
	return p != nil && p.k != nil && p.test
}

// PublicKey is a copy of the public key of the primary. It is nil for a nil or zero value.
func (p *PrimaryKey) PublicKey() *ecdsa.PublicKey {
	if p == nil || p.k == nil {
		return nil
	}
	return p.k.publicKey()
}

// Subkey is a Public-Subkey packet that [ReadSubkey] accepted. The zero value holds no key and is
// refused wherever a key is needed.
type Subkey struct {
	k *key
}

// ReadSubkey reads one Public-Subkey packet (tag 14), as it is in the subkey file. The packet is
// exactly the packet of the profile: version 4, ECDSA (algorithm 19) on P-384, the point on the
// curve in the one form that go-crypto writes again, a creation time of at least one second, and
// no byte after the packet.
//
// A packet that is not whole, is not tag 14, has a body in another form, or has a creation time of
// zero is an [ErrForm]. A whole packet whose key is not a version 4 ECDSA key on P-384 is an
// [ErrAlgorithm]: that is any version other than 4, any algorithm other than 19, and algorithm 19
// with another curve. The version, the algorithm and the curve are read first, so a key of another
// kind is an ErrAlgorithm whatever follows them. Both are an [ErrRequest]. Nothing is returned with
// an error.
func ReadSubkey(packet []byte) (*Subkey, error) {
	k, err := readSubkey(packet)
	if err != nil {
		return nil, err
	}
	return &Subkey{k: k}, nil
}

// Fingerprint is the version 4 fingerprint of the subkey: 40 lower-case hexadecimal digits. It is
// empty for a nil or zero value.
func (s *Subkey) Fingerprint() string {
	if s == nil || s.k == nil {
		return ""
	}
	return hex.EncodeToString(s.k.fp)
}

// Created is the creation time that the packet holds, in UTC. It is the zero time for a nil or zero
// value.
func (s *Subkey) Created() time.Time {
	if s == nil || s.k == nil {
		return time.Time{}
	}
	return s.k.created
}

// PublicKey is a copy of the public key of the subkey. It is nil for a nil or zero value.
func (s *Subkey) PublicKey() *ecdsa.PublicKey {
	if s == nil || s.k == nil {
		return nil
	}
	return s.k.publicKey()
}

// publicKey is a copy of the key, so that the caller cannot change what is checked.
func (k *key) publicKey() *ecdsa.PublicKey {
	point, err := pointBytes(k.ec)
	if err != nil {
		return nil
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
	if err != nil {
		return nil
	}
	return pub
}

// readSubkey is the reader behind [ReadSubkey] and parseSubkey.
func readSubkey(pkt []byte) (*key, error) {
	tag, body, rest, err := splitPacket(pkt)
	if err != nil {
		return nil, fail(ErrForm, "the packet is not whole")
	}
	if tag != tagSubkey {
		return nil, fail(ErrForm, "the packet is not a Public-Subkey packet (tag %d)", tag)
	}
	if len(rest) != 0 {
		return nil, fail(ErrForm, "there are bytes after the packet")
	}
	if err := checkSubkeyKind(body); err != nil {
		return nil, err
	}
	k, err := readKey(pkt, tagSubkey)
	if err != nil {
		return nil, fail(ErrForm, "the key is not in the form of the profile")
	}
	if k.created.Unix() < 1 {
		return nil, fail(ErrForm, "the creation time is zero")
	}
	return k, nil
}

// checkSubkeyKind reads the first bytes of the body of a Public-Subkey packet and decides whether
// the key is of the kind of the profile: version 4, algorithm 19, the curve P-384. It reads no
// further than it must for that, so that a key of another kind is an [ErrAlgorithm] and a damaged
// packet of the right kind is an [ErrForm].
func checkSubkeyKind(body []byte) error {
	// version (1), creation time (4), algorithm (1), the length of the curve OID (1), the OID.
	if len(body) == 0 {
		return fail(ErrForm, "the packet has no body")
	}
	if body[0] != 4 {
		return fail(ErrAlgorithm, "the version of the key is %d", body[0])
	}
	if len(body) < 6 {
		return fail(ErrForm, "the packet is too short for a key")
	}
	if body[5] != algoECDSA {
		return fail(ErrAlgorithm, "the algorithm of the key is %d", body[5])
	}
	if len(body) < 7 {
		return fail(ErrForm, "the packet has no curve")
	}
	n := int(body[6])
	if n == 0 || n == 0xFF || 7+n > len(body) {
		return fail(ErrForm, "the length of the curve identifier is not a length")
	}
	if !bytes.Equal(body[6:7+n], p384OID) {
		return fail(ErrAlgorithm, "the curve of the key is not P-384")
	}
	return nil
}

// SplitSubkeyFile splits the file `<stem>.subkey.pgp` into its first packet, which must be a
// Public-Subkey packet, and the packets after it, each whole with its header, in file order,
// whatever their tag. It never returns more than maxSignatures of them: a file with more packets is
// an [ErrForm], and the walk stops at the bound, so that a hostile count costs nothing. The returned
// packets are copies of the bytes of the file.
//
// A file with no packet, a packet that is not whole, a partial or an indeterminate length, bytes
// after the last packet that are not a packet, a first packet that is not tag 14, or more than
// maxSignatures packets after it is an ErrForm. A maxSignatures below zero is an [ErrParams]. Both
// old-format and new-format headers are read. Nothing is returned with an error.
func SplitSubkeyFile(file []byte, maxSignatures int) (subkey []byte, signatures [][]byte, err error) {
	if maxSignatures < 0 {
		return nil, nil, fail(ErrParams, "the bound on the number of signatures is below zero")
	}
	if len(file) == 0 {
		return nil, nil, fail(ErrForm, "the file is empty")
	}
	rest := file
	var first []byte
	var sigs [][]byte
	for len(rest) > 0 {
		tag, _, next, err := splitPacket(rest)
		if err != nil {
			return nil, nil, fail(ErrForm, "the file is not whole packets")
		}
		whole := rest[:len(rest)-len(next)]
		rest = next
		if first == nil {
			if tag != tagSubkey {
				return nil, nil, fail(ErrForm, "the first packet is not a Public-Subkey packet (tag %d)", tag)
			}
			first = bytes.Clone(whole)
			continue
		}
		if len(sigs) >= maxSignatures {
			return nil, nil, fail(ErrForm, "the file has more than %d packets after the subkey", maxSignatures)
		}
		sigs = append(sigs, bytes.Clone(whole))
	}
	if sigs == nil {
		sigs = [][]byte{}
	}
	return first, sigs, nil
}

// VerifyBackSignature is check 5 for one back-signature: the signature packet sig is exactly the
// back-signature that [BindSubkey] accepts for this primary and this subkey at the time of the
// ceremony. It is the function that BindSubkey calls (checkBackSig), not a copy of it: one signature
// packet of type 0x19 made by the subkey over the primary and the subkey with ECDSA and SHA-384; in
// its hashed area the signature creation time and the issuer fingerprint of the subkey, in its
// unhashed area the issuer key ID of the subkey, and nothing else in either area; no subpacket
// marked critical; a creation time not before the subkey and not after the ceremony; a hash tag
// that is the start of the digest; and no byte after the two numbers (record 0009, rule 8).
//
// A fault of the signature is an [ErrBackSignature], and so an [ErrRequest]. A nil or zero primary
// or subkey, or a ceremony time that is not whole seconds in the years 1970 to 2106, is an
// [ErrParams] and never a refusal of the request. It does not check that the subkey is not the
// primary's own key; the caller that needs that rule applies it.
func VerifyBackSignature(sig []byte, primary *PrimaryKey, sub *Subkey, ceremony time.Time) error {
	if primary == nil || primary.k == nil {
		return fail(ErrParams, "there is no primary")
	}
	if sub == nil || sub.k == nil {
		return fail(ErrParams, "there is no subkey")
	}
	if err := checkTime("the ceremony time", ceremony); err != nil {
		return err
	}
	_, err := checkBackSig(ErrBackSignature, sig, primary.k, sub.k, ceremony)
	return err
}
