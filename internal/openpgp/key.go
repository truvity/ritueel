package openpgp

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"math"
	"math/big"
	"reflect"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// key is a version 4 ECDSA P-384 key as the builders use it: the public key (a copy, so that a
// caller that changes its own key object during a call changes nothing here), the packet that
// carries it, and the identifiers that follow from it.
type key struct {
	ec      *ecdsa.PublicKey
	pk      *packet.PublicKey
	created time.Time
	body    []byte // the body of the key packet: version, time, algorithm, curve, point
	packet  []byte // the packet of the primary, with its header
	fp      []byte // 20 bytes
	keyID   []byte // the last 8 bytes of fp
}

// checkTime refuses a time that does not fit the four seconds of an OpenPGP time field, or that
// has a fraction of a second.
func checkTime(what string, t time.Time) error {
	if t.Nanosecond() != 0 {
		return fail(ErrParams, "%s has a fraction of a second", what)
	}
	if u := t.Unix(); u < 1 || u > math.MaxUint32 {
		return fail(ErrParams, "%s is outside the years 1970 to 2106", what)
	}
	return nil
}

// unixU32 is the OpenPGP time of t, which checkTime has accepted.
func unixU32(t time.Time) uint32 { return uint32(t.Unix()) }

// p384OID is the object identifier of the curve P-384 as OpenPGP writes it (RFC 9580, section 9.2),
// with its length octet.
var p384OID = []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}

// keyBody writes the body of a version 4 ECDSA P-384 key packet (RFC 9580, section 5.5.2).
func keyBody(created time.Time, point []byte) []byte {
	body := []byte{4}
	body = append(body, u32(unixU32(created))...)
	body = append(body, algoECDSA)
	body = append(body, p384OID...)
	return append(body, mpi(new(big.Int).SetBytes(point))...)
}

// readKeyBody reads the body of an ECDSA P-384 key packet and returns the creation time and the
// point (the 97 bytes of the uncompressed form). It accepts only what [keyBody] writes: version 4,
// the curve P-384, a point on the curve, and nothing after the point.
func readKeyBody(body []byte) (time.Time, []byte, error) {
	const pointLen = 97
	if len(body) != 1+4+1+len(p384OID)+2+pointLen || body[0] != 4 || body[5] != algoECDSA ||
		!bytes.Equal(body[6:6+len(p384OID)], p384OID) {
		return time.Time{}, nil, errFrame
	}
	point := body[6+len(p384OID)+2:]
	if !bytes.Equal(body[6+len(p384OID):6+len(p384OID)+2], mpi(new(big.Int).SetBytes(point))[:2]) {
		return time.Time{}, nil, errFrame
	}
	if _, err := ecdh.P384().NewPublicKey(point); err != nil {
		return time.Time{}, nil, errFrame
	}
	created := time.Unix(int64(binary.BigEndian.Uint32(body[1:5])), 0).UTC()
	return created, bytes.Clone(point), nil
}

// newKey makes the key of a public key and its creation time. It accepts only an *ecdsa.PublicKey
// on P-384 with a point on the curve.
func newKey(pub crypto.PublicKey, created time.Time) (*key, error) {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec == nil {
		return nil, fail(ErrParams, "the key is not an ECDSA public key")
	}
	if ec.Curve != elliptic.P384() {
		return nil, fail(ErrParams, "the key is not on the curve P-384")
	}
	point, err := pointBytes(ec)
	if err != nil {
		return nil, fail(ErrParams, "the point of the key is not on the curve P-384")
	}
	own, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
	if err != nil {
		return nil, fail(ErrParams, "the point of the key is not on the curve P-384")
	}
	if err := checkTime("the creation time of the key", created); err != nil {
		return nil, err
	}
	pkt := wrap(tagPublicKey, keyBody(created, point))
	k, err := readKey(pkt, tagPublicKey)
	if err != nil {
		return nil, fail(ErrParams, "the key packet is not the packet of a primary: %v", err)
	}
	k.ec = own
	return k, nil
}

// pointBytes is the uncompressed point of a public key. A key with a curve and no point (or one
// coordinate) has no point to write: ec.Bytes panics on it, and that is an error here.
func pointBytes(ec *ecdsa.PublicKey) (point []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			point, err = nil, errFrame
		}
	}()
	return ec.Bytes()
}

// readKey reads one key packet of a given tag (6 or 14) written in the form of [keyBody]. go-crypto
// reads it too, and writes it again to the same bytes, so that what is hashed here is what a
// verifier hashes.
func readKey(pkt []byte, wantTag byte) (*key, error) {
	tag, body, rest, err := splitPacket(pkt)
	if err != nil || tag != wantTag || len(rest) != 0 {
		return nil, errFrame
	}
	created, point, err := readKeyBody(body)
	if err != nil {
		return nil, err
	}
	p, err := packet.Read(bytes.NewReader(pkt))
	if err != nil {
		return nil, err
	}
	pk, ok := p.(*packet.PublicKey)
	if !ok || pk.Version != 4 || pk.IsSubkey != (wantTag == tagSubkey) || pk.PubKeyAlgo != packet.PubKeyAlgoECDSA ||
		len(pk.Fingerprint) != 20 || !pk.CreationTime.Equal(created) {
		return nil, errFrame
	}
	var again bytes.Buffer
	if err := pk.Serialize(&again); err != nil {
		return nil, err
	}
	if _, body2, _, err := splitPacket(again.Bytes()); err != nil || !bytes.Equal(body2, body) {
		return nil, errFrame
	}
	ec, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), point)
	if err != nil {
		return nil, err
	}
	return &key{
		ec:      ec,
		pk:      pk,
		created: created,
		body:    bytes.Clone(body),
		packet:  bytes.Clone(pkt),
		fp:      bytes.Clone(pk.Fingerprint),
		keyID:   bytes.Clone(pk.Fingerprint[12:]),
	}, nil
}

// Fingerprint is the version 4 fingerprint of an ECDSA P-384 public key with the given creation
// time: 40 lower-case hexadecimal digits. A key that is not on P-384, a nil key, a point that is not
// on the curve, or a time that is not in whole seconds from 1970 to 2106 is an [ErrParams], and the
// text is empty.
func Fingerprint(pub *ecdsa.PublicKey, creation time.Time) (string, error) {
	k, err := newKey(pub, creation)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(k.fp), nil
}

// hashPrefix is what a signature over a key hashes for that key: 0x99, the two-byte length of the
// packet body, and the body (RFC 9580, section 5.2.4).
func hashPrefix(body []byte) []byte {
	out := make([]byte, 0, 3+len(body))
	out = append(out, 0x99, byte(len(body)>>8), byte(len(body)))
	return append(out, body...)
}

// isNil tells whether v is nil, or an interface that holds a nil pointer.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch r := reflect.ValueOf(v); r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return r.IsNil()
	}
	return false
}
