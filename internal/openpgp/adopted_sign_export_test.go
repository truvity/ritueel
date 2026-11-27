package openpgp

import (
	"io"
	"time"
)

// The names below are visible to the tests of the package that stand outside it. They make the one
// signature that the foundation of the signing by an adopted key can make with no builder of its own, and
// a second one for a message, through the one signing step.

// sigTypeBinary is the type of a signature over a binary document (RFC 9580, section 5.2.1).
const sigTypeBinary = 0x00

// DirectKeySignatureFor makes a direct-key signature (type 0x1F) of the primary at t, over the primary
// alone, with the hashed subpackets creation time (2) and issuer fingerprint (33) and the unhashed
// issuer key ID (16), through the issuer. It returns the whole packet, read back by go-crypto as the
// builders read their signatures.
func DirectKeySignatureFor(rnd io.Reader, a *AdoptedIssuer, t time.Time) ([]byte, error) {
	return signatureFor(rnd, a, sigDirectKey, [][]byte{hashPrefix(a.ident.body)}, t)
}

// DetachedSignatureFor makes a detached signature over msg (type 0x00) at t by the primary, with the
// same subpackets, through the same step.
func DetachedSignatureFor(rnd io.Reader, a *AdoptedIssuer, t time.Time, msg []byte) ([]byte, error) {
	return signatureFor(rnd, a, sigTypeBinary, [][]byte{msg}, t)
}

func signatureFor(rnd io.Reader, a *AdoptedIssuer, typ byte, data [][]byte, t time.Time) ([]byte, error) {
	if err := checkTime("the signature time", t); err != nil {
		return nil, err
	}
	body, err := a.sign(rnd, sigSpec{
		sigType: typ,
		hashed: []subpacket{
			{typ: spCreationTime, data: u32(unixU32(t))},
			a.issuerFingerprint(),
		},
		unhashed: []subpacket{a.issuerKeyID()},
		data:     data,
	})
	if err != nil {
		return nil, err
	}
	pkt := wrap(tagSignature, body)
	if _, err := readBack(pkt, a.ident); err != nil {
		return nil, err
	}
	return pkt, nil
}
