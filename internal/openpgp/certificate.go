package openpgp

import "bytes"

// Certificate is the three kinds of packet of the public certificate that [NewPrimary] returns,
// each whole with its header: the primary key packet, the one user ID packet and the signature
// packets in the order they stand.
type Certificate struct {
	Key, UserID []byte
	Signatures  [][]byte // one or more; each is one whole signature packet
}

// SplitCertificate splits the bytes of one certificate of the first form (docs/reference/keyring-package.md,
// "The first form of the keyring file"): one Public-Key packet, one User ID packet and one to
// [MaxCertifications] Signature packets, in that order, with nothing before, between or after. It
// reads both header forms of RFC 9580, section 4.2, and refuses a partial or an indeterminate
// length. The size is checked against [MaxKeyringBytes] before the first packet is read, and the
// walk stops at the first packet that the form does not have, so its cost is bounded by the
// input.
//
// It verifies nothing and parses no key: the key, the user ID and the signatures are for
// [ReadKeyring]. It returns copies, so that a caller that changes the result changes nothing of the
// input, and no Certificate with an error. A subkey, a second user ID, a certificate with no
// signature, a trailing byte, an empty input and an input of more than [MaxKeyringBytes] bytes are
// an [ErrCertificateForm]. The text of an error names a position and a tag and holds no byte of the
// input.
func SplitCertificate(cert []byte) (*Certificate, error) {
	if len(cert) == 0 {
		return nil, fail(ErrCertificateForm, "the certificate is empty")
	}
	if len(cert) > MaxKeyringBytes {
		return nil, fail(ErrCertificateForm, "the certificate is longer than %d bytes", MaxKeyringBytes)
	}
	out := &Certificate{}
	rest := cert
	for n := 1; len(rest) > 0; n++ {
		tag, _, after, err := splitPacket(rest)
		if err != nil {
			return nil, fail(ErrCertificateForm, "packet %d is not whole, or its length is a form that is not read", n)
		}
		raw := bytes.Clone(rest[:len(rest)-len(after)]) // the whole packet, with its header
		rest = after
		switch {
		case n == 1:
			if tag != tagPublicKey {
				return nil, fail(ErrCertificateForm, "the first packet is not a Public-Key packet (tag %d)", tag)
			}
			out.Key = raw
		case n == 2:
			if tag != tagUserID {
				return nil, fail(ErrCertificateForm, "the second packet is not a User ID packet (tag %d)", tag)
			}
			out.UserID = raw
		case tag != tagSignature:
			return nil, fail(ErrCertificateForm, "packet %d is not a Signature packet (tag %d)", n, tag)
		case len(out.Signatures) == MaxCertifications:
			return nil, fail(ErrCertificateForm, "the certificate has more than %d signatures", MaxCertifications)
		default:
			out.Signatures = append(out.Signatures, raw)
		}
	}
	if out.UserID == nil {
		return nil, fail(ErrCertificateForm, "the certificate has no User ID packet")
	}
	if len(out.Signatures) == 0 {
		return nil, fail(ErrCertificateForm, "the certificate has no signature packet")
	}
	return out, nil
}
