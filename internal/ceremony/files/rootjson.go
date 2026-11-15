package files

import (
	"bytes"
	"errors"

	"ritueel.id/ritueel/internal/canonjson"
)

// RootJSONFile is the name of the file that holds the facts of one root key, roots/<label>/root.json
// (docs/reference/bundle.md, "`root.json`"; record 0006, rule 31).
const RootJSONFile = "root.json"

// The key stores that a root.json may name (docs/reference/bundle.md, "`root.json`", member store).
const (
	// StoreSoftware is a key in a key file.
	StoreSoftware = "software"
	// StorePIV is a key on a PIV card.
	StorePIV = "piv"
	// StoreAWSKMS is a key in a cloud key store.
	StoreAWSKMS = "aws-kms"
)

// RootJSON is roots/<label>/root.json, version 1: the facts of one root key, written once by the
// ceremony that makes the key and never changed (record 0006, rule 31). It holds the members of the
// table of "`root.json`" in docs/reference/bundle.md that this version writes: version, label, store,
// test, created_at, x509_spki_sha256, openpgp_fingerprint, openpgp_created, revocations and
// removal_sha256. The members adopted, store_ref, vouched_by and vouches are written by later
// parts, and this reader refuses them as unknown members until the part that writes one gives it a
// typed shape: a reader of exactly what is written, and nothing else, accepts nothing that no
// writer makes.
//
// [ReadRootJSON] requires version, label, store and created_at, and at least one key: an X.509 pin,
// or an OpenPGP fingerprint with its creation time. A root key with a primary has revocations, and
// only such a root key has (record 0007, rule 21).
type RootJSON struct {
	// Version is 1.
	Version int64 `json:"version"`
	// Label is the label of the root key: one upper-case letter.
	Label string `json:"label"`
	// Store is the key store: software, piv or aws-kms.
	Store string `json:"store"`
	// Test is true for a test root key; the member is left out for a key that is not.
	Test bool `json:"test,omitempty"`
	// CreatedAt is when the key was made: the time of its ceremony.
	CreatedAt string `json:"created_at"`
	// X509SPKISHA256 is the pin of the X.509 root key: 64 lower-case hexadecimal digits.
	X509SPKISHA256 string `json:"x509_spki_sha256,omitempty"`
	// OpenPGPFingerprint is the fingerprint of the OpenPGP primary: 40 lower-case hexadecimal
	// digits. It is written for a root key that has a primary and left out for one that has not.
	OpenPGPFingerprint string `json:"openpgp_fingerprint,omitempty"`
	// OpenPGPCreated is the OpenPGP creation time of the primary, present with the fingerprint.
	OpenPGPCreated string `json:"openpgp_created,omitempty"`
	// Revocations is an object from a reason to the SHA-256 of the binary packet of that revocation
	// signature of the primary. It is present exactly when OpenPGPFingerprint is, holds compromised
	// and superseded, and may hold retired and no-reason; no other key, and no other value than a
	// digest. The signatures are kept apart from the bundle (record 0007, rule 23): only their
	// digests are here. It is written in the canonical form like every member, keys in the order of
	// RFC 8785.
	Revocations map[string]string `json:"revocations,omitempty"`
	// RemovalSHA256 is the SHA-256 of the key's removal authorisation, as stored: the digest of its
	// text.
	RemovalSHA256 string `json:"removal_sha256,omitempty"`
}

// rootJSONNoEmpty are the optional members of a root.json that are left out rather than written as an
// empty text.
var rootJSONNoEmpty = []string{"x509_spki_sha256", "openpgp_fingerprint", "openpgp_created", "removal_sha256"}

// ReadRootJSON reads the bytes of one root.json. It reads the version first and alone: a version
// other than 1 is a *[VersionError] and nothing else of the file is read. Any other fault wraps
// strictjson.ErrMalformed (a member twice, a member that is null, an unknown member, a number that is
// not an integer, more than strictjson.DefaultMaxBytes bytes) or is a *[FormatError] (a member that
// is missing, an empty text, a digest, a time, a label or a word that is not in its form). It requires
// the canonical form: the bytes are the same as [RootJSON.Canonical] of the value that was read, so a
// file that spells a member in another way (a test member that says false, a member out of order, a
// space, a line feed at the end) is refused, and what is read is exactly what the writer writes.
func ReadRootJSON(b []byte) (*RootJSON, error) {
	var r RootJSON
	if err := readVersioned(b, "root.json", &r, rootJSONNoEmpty...); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	again, err := r.Canonical()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, formatError("root.json", "file", "is not in the canonical form that ritueel writes")
	}
	return &r, nil
}

// Canonical returns the file in the canonical form of RFC 8785, with no trailing newline: the bytes
// that ritueel writes and that a digest is over. A value that breaks the rules of [ReadRootJSON], and
// a nil value, are an error and no bytes come with it.
func (r *RootJSON) Canonical() ([]byte, error) {
	if r == nil {
		return nil, errors.New("root.json: there is no value")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return canonjson.Marshal(r)
}

func (r *RootJSON) validate() error {
	c := checker{what: "root.json"}
	if r.Version != FormatVersion {
		return &VersionError{What: c.what, Version: r.Version}
	}
	for _, err := range []error{
		c.label("label", r.Label),
		c.oneOf("store", r.Store, StoreSoftware, StorePIV, StoreAWSKMS),
		c.time("created_at", r.CreatedAt, true),
		c.digest("x509_spki_sha256", r.X509SPKISHA256, false),
		c.time("openpgp_created", r.OpenPGPCreated, false),
		c.digest("removal_sha256", r.RemovalSHA256, false),
	} {
		if err != nil {
			return err
		}
	}
	if r.OpenPGPFingerprint != "" && !isHex(r.OpenPGPFingerprint, 40) {
		return formatError(c.what, "openpgp_fingerprint", "%s is not an OpenPGP fingerprint of 40 lower-case hexadecimal characters", shown(r.OpenPGPFingerprint))
	}
	if (r.OpenPGPFingerprint == "") != (r.OpenPGPCreated == "") {
		return formatError(c.what, "openpgp_created", "stands with openpgp_fingerprint, both or neither")
	}
	// A member that is there, even as an empty object, is present: an empty object is not a root.json
	// that ritueel writes, whether the key has a primary or not.
	if (r.OpenPGPFingerprint == "") != (r.Revocations == nil) {
		return formatError(c.what, "revocations", "stands with openpgp_fingerprint, both or neither")
	}
	if r.Revocations != nil {
		if err := c.revocationDigests(r.Revocations); err != nil {
			return err
		}
	}
	if r.X509SPKISHA256 == "" && r.OpenPGPFingerprint == "" {
		return formatError(c.what, "x509_spki_sha256", "is required and missing: a root key has an X.509 pin or an OpenPGP fingerprint")
	}
	return nil
}
