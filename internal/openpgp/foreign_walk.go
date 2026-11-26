package openpgp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// This file walks the packets of a transferable key (RFC 9580, section 10.1) and builds its public
// certificate. It reads framing and order only: no signature is verified here.

// fkSig is one signature packet of a component, whole and by its body.
type fkSig struct {
	raw, body []byte
}

// fkTarget is the signatures of one component. n counts every signature read, kept or not.
type fkTarget struct {
	sigs []fkSig
	n    int
	drop bool // the signatures are counted and not kept (a user attribute)
}

type fkUser struct {
	text []byte
	t    fkTarget
}

type fkSub struct {
	pub       fkPublic
	fp        []byte            // the fingerprint
	pubBody   []byte            // the public part of the body, for the fingerprint
	pubPacket []byte            // the public subkey packet, for go-crypto
	gopk      *packet.PublicKey // go-crypto's reading of it, set for a secret subkey
	form      SubkeyForm
	t         fkTarget
}

// fkWalk is a transferable key taken apart. Its slices point into the bytes that were walked, which
// the caller clears after the key is read, so nothing of it outlives [readForeignKey].
type fkWalk struct {
	pub           fkPublic
	prot          fkProtection
	primaryBody   []byte // the public part of the primary's body
	primaryPacket []byte // the public key packet of the primary, in the new format
	keyT          fkTarget
	users         []*fkUser
	subs          []*fkSub
	attrs         int
	attrBytes     int
	cert          []byte
}

// walkForeign reads the packets of data and groups them by the order of the standard: the primary,
// its signatures, each user ID and attribute with its signatures, each subkey with its signatures.
// It skips trust and marker packets, counts the limits, and builds the public certificate as it
// goes, in the order of the file.
func walkForeign(data []byte) (*fkWalk, error) {
	w := &fkWalk{cert: make([]byte, 0, len(data))}
	done := false
	defer func() {
		if !done {
			w.clearSecret()
		}
	}()
	var cur *fkTarget
	started := false
	rest := data
	for n := 1; len(rest) > 0; n++ {
		if n > MaxForeignPackets {
			return nil, fail(ErrForeignLimit, "the file has more than MaxForeignPackets (%d) packets", MaxForeignPackets)
		}
		tag, raw, body, after, err := splitForeignPacket(rest, n)
		if err != nil {
			return nil, err
		}
		rest = after
		if tag == tagMarker || tag == tagTrust {
			continue
		}
		if !started {
			if err := w.start(tag, body); err != nil {
				return nil, err
			}
			started, cur = true, &w.keyT
			continue
		}
		if cur, err = w.add(cur, tag, raw, body); err != nil {
			return nil, err
		}
	}
	if !started {
		return nil, fail(ErrForeignForm, "the file holds no key packet")
	}
	done = true
	return w, nil
}

// clearSecret clears the copy of the secret region of the primary that the walk holds.
func (w *fkWalk) clearSecret() {
	clear(w.prot.data)
	clear(w.prot.iv)
}

// start reads the first packet that counts: the secret key packet of the primary.
func (w *fkWalk) start(tag byte, body []byte) error {
	switch tag {
	case tagSecretKey:
	case tagPublicKey:
		return fail(ErrForeignNoSecret, "the file holds a public key packet, which has no secret")
	case tagSecretSubkey, tagSubkey:
		return fail(ErrForeignForm, "the file starts with a subkey packet: a transferable key starts with its primary key")
	case tagSignature, tagUserID, tagUserAttribute:
		return fail(ErrForeignForm, "the file starts with %s: a transferable key starts with its primary key", tagName(tag))
	default:
		return fail(ErrForeignPacket, "the file holds %s, which does not belong in a transferable key", tagName(tag))
	}
	pub, err := parseForeignPublic("the primary key", body, false)
	if err != nil {
		return err
	}
	if err := checkPrimary(pub); err != nil {
		return err
	}
	prot, err := classifyPrimarySecret(body[pub.length:])
	if err != nil {
		return err
	}
	w.pub, w.prot = pub, prot
	w.primaryBody = body[:pub.length]
	w.primaryPacket = wrap(tagPublicKey, w.primaryBody)
	w.cert = append(w.cert, w.primaryPacket...)
	return nil
}

// checkPrimary holds the primary to the three algorithms that are read, and its public numbers to
// their form.
func checkPrimary(pub fkPublic) error {
	refuse := func() error {
		return fail(ErrForeignAlgorithm, "the primary is %s: only RSA with a 4096-bit modulus, EdDSA on Ed25519 and ECDSA on P-384 are read", pub.alg)
	}
	switch pub.alg.ID {
	case algoRSA:
		if pub.alg.Bits != rsaPrimaryBits {
			return refuse()
		}
	case algoECDSA:
		if !bytes.Equal(pub.oid, p384OID) {
			return refuse()
		}
		if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pub.point); err != nil {
			return fail(ErrForeignForm, "the point of the primary is not a point on P-384")
		}
	case algoEdDSA:
		if !bytes.Equal(pub.oid, ed25519OID) {
			return refuse()
		}
		if len(pub.point) != 33 || pub.point[0] != 0x40 {
			return fail(ErrForeignForm, "the public key of the primary is not 0x40 and 32 bytes")
		}
	default:
		return refuse()
	}
	return nil
}

// add reads one packet that follows the primary and returns the component that the next signature
// belongs to.
func (w *fkWalk) add(cur *fkTarget, tag byte, raw, body []byte) (*fkTarget, error) {
	switch tag {
	case tagSecretKey, tagPublicKey:
		return nil, fail(ErrForeignPrimaries, "the file holds a second primary key (%s)", tagName(tag))
	case tagSignature:
		cur.n++
		if cur.n > MaxForeignSignatures {
			return nil, fail(ErrForeignLimit, "a component of the key has more than MaxForeignSignatures (%d) signatures", MaxForeignSignatures)
		}
		w.cert = append(w.cert, raw...)
		if !cur.drop {
			cur.sigs = append(cur.sigs, fkSig{raw: raw, body: body})
		}
		return cur, nil
	case tagUserID:
		if len(w.subs) > 0 {
			return nil, fail(ErrForeignForm, "a user ID follows a subkey: a transferable key has its user IDs before its subkeys")
		}
		if len(body) > MaxForeignUserIDBytes {
			return nil, fail(ErrForeignLimit, "a user ID packet is longer than MaxForeignUserIDBytes (%d bytes)", MaxForeignUserIDBytes)
		}
		if len(w.users) == MaxForeignUserIDs {
			return nil, fail(ErrForeignLimit, "the file has more than MaxForeignUserIDs (%d) user IDs", MaxForeignUserIDs)
		}
		u := &fkUser{text: body}
		w.users = append(w.users, u)
		w.cert = append(w.cert, raw...)
		return &u.t, nil
	case tagUserAttribute:
		if len(w.subs) > 0 {
			return nil, fail(ErrForeignForm, "a user attribute follows a subkey: a transferable key has its user attributes before its subkeys")
		}
		if w.attrs == MaxForeignUserIDs {
			return nil, fail(ErrForeignLimit, "the file has more than MaxForeignUserIDs (%d) user attributes", MaxForeignUserIDs)
		}
		w.attrs++
		w.attrBytes += len(body)
		w.cert = append(w.cert, raw...)
		return &fkTarget{drop: true}, nil
	case tagSecretSubkey, tagSubkey:
		s, err := w.subkey(tag, raw, body)
		if err != nil {
			return nil, err
		}
		return &s.t, nil
	}
	return nil, fail(ErrForeignPacket, "the file holds %s, which does not belong in a transferable key", tagName(tag))
}

// subkey reads a subkey packet, public or secret. A secret subkey is turned into its public
// subkey packet in the certificate, and its secret bytes are not read, copied or kept: all that is
// asked of them is whether they are the GNU stub.
func (w *fkWalk) subkey(tag byte, raw, body []byte) (*fkSub, error) {
	if len(w.subs) == MaxForeignSubkeys {
		return nil, fail(ErrForeignLimit, "the file has more than MaxForeignSubkeys (%d) subkeys", MaxForeignSubkeys)
	}
	pub, err := parseForeignPublic("a subkey", body, tag == tagSubkey)
	if err != nil {
		return nil, err
	}
	fp, err := foreignFingerprint(body[:pub.length])
	if err != nil {
		return nil, err
	}
	s := &fkSub{pub: pub, fp: fp, pubBody: body[:pub.length]}
	if tag == tagSubkey {
		s.form, s.pubPacket = SubkeyPublic, raw
		w.cert = append(w.cert, raw...)
	} else {
		// A secret subkey: the public part ends where its own length fields say, so it is held to
		// two more checks before one byte of it goes into the certificate. A second parser must read
		// the public packet that the cut makes, and the bytes after the cut must start a secret
		// area (usage octet, S2K specifier) of a known form.
		s.pubPacket = wrap(tagSubkey, s.pubBody)
		if s.gopk, err = agreePublic(s.pubPacket, s.pubBody, fp, true); err != nil {
			return nil, err
		}
		stub, err := checkSecretStart(body[pub.length:])
		if err != nil {
			return nil, err
		}
		s.form = SubkeyWithSecret
		if stub {
			s.form = SubkeyStub
		}
		w.cert = append(w.cert, s.pubPacket...)
	}
	w.subs = append(w.subs, s)
	return s, nil
}
