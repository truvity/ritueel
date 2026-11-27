package openpgp

import (
	"crypto/sha256"
	"encoding/hex"
)

// HeldDigest is the SHA-256 of a kept certificate as a record of the bundle's history holds it, and it must
// come from such a record and never from the certificate's own bytes. Its one field is unexported, so that no
// code outside the package can make one from a byte array, and the only way to make one is
// [ParseHeldDigest], from the text that the record holds. The zero value is no digest, and
// [ReadForeignCertificate] refuses it.
type HeldDigest struct {
	sum [sha256.Size]byte
}

// ParseHeldDigest reads a digest as the records write it: 64 lower-case hexadecimal digits and nothing else.
// It refuses upper case, a different length, any other character, white space, and the digest of 64 zeros,
// with an [ErrParams]. The text of the error holds no byte of the text.
func ParseHeldDigest(text string) (HeldDigest, error) {
	var d HeldDigest
	if len(text) != 2*sha256.Size {
		return d, fail(ErrParams, "the digest is not 64 lower-case hexadecimal digits")
	}
	for i := 0; i < len(text); i++ {
		if c := text[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return d, fail(ErrParams, "the digest is not 64 lower-case hexadecimal digits")
		}
	}
	if _, err := hex.Decode(d.sum[:], []byte(text)); err != nil {
		return HeldDigest{}, fail(ErrParams, "the digest is not 64 lower-case hexadecimal digits")
	}
	if d == (HeldDigest{}) {
		return d, fail(ErrParams, "the digest is the zero digest, which is no digest")
	}
	return d, nil
}

// String is the digest as the records write it: 64 lower-case hexadecimal digits, and empty for the zero
// value.
func (d HeldDigest) String() string {
	if d == (HeldDigest{}) {
		return ""
	}
	return hex.EncodeToString(d.sum[:])
}
