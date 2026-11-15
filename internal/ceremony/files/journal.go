package files

import (
	"bytes"
	"errors"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/strictjson"
)

// MaxJournalLine is the most bytes of one line of a journal, without its line feed: 4,096. A line
// holds six members of at most 255 bytes each, so a line of this program is under a kilobyte;
// the limit is checked before a line is parsed.
const MaxJournalLine = 4096

// MaxJournalLines is the most lines that a journal of one ceremony holds: 7 for each of the 26
// labels that a trust set can hold (a certificate, a removal authorisation, a self-signature and up
// to four revocation signatures, one for each reason: compromised and superseded are always made,
// retired and no-reason when the holder asks) and 8 more. A journal that is longer is not a journal
// of this program. The journal of births holds at most two lines for each label (an X.509 key and a
// primary), far below the limit; both journals share it.
const MaxJournalLines = 7*26 + 8

// maxPlaceBytes is the most bytes of the member place of a birth line.
const maxPlaceBytes = 255

// The kinds of signature that the page "The plan" lists for `signatures[].kind`, and that a line
// of the journal of signatures may carry.
const (
	// KindIntermediateCertificate is the certificate of an intermediate key.
	KindIntermediateCertificate = "intermediate-certificate"
	// KindSubkeyBinding is the binding signature of an OpenPGP subkey.
	KindSubkeyBinding = "subkey-binding"
	// KindRootCertificate is the self-signed certificate of a root key.
	KindRootCertificate = "root-certificate"
	// KindPrimarySelfSignature is the self-signature of an OpenPGP primary.
	KindPrimarySelfSignature = "primary-self-signature"
	// KindPrimaryRevocation is a revocation signature of an OpenPGP primary.
	KindPrimaryRevocation = "primary-revocation"
	// KindRootRemoval is the removal authorisation of a root key.
	KindRootRemoval = "root-removal"
	// KindCrossCertificate is the certificate that one root key gives another.
	KindCrossCertificate = "cross-certificate"
	// KindOpenPGPVouch is the vouching signature of a root key for another.
	KindOpenPGPVouch = "openpgp-vouch"
	// KindRootList is the signature of a root list.
	KindRootList = "root-list"
	// KindCRL is the signature of a revocation list of certificates.
	KindCRL = "crl"
	// KindSSHCAKeyList is the signature of the list of SSH CA keys.
	KindSSHCAKeyList = "ssh-ca-key-list"
)

var signatureKinds = []string{
	KindIntermediateCertificate, KindSubkeyBinding, KindRootCertificate, KindPrimarySelfSignature,
	KindPrimaryRevocation, KindRootRemoval, KindCrossCertificate, KindOpenPGPVouch, KindRootList,
	KindCRL, KindSSHCAKeyList,
}

// BirthLine is one line of births.jsonl, the birth journal: the members of "The birth journal" of
// docs/reference/ceremony-record.md. A line is written after the key exists. It holds no secret.
// [ReadBirthLine] requires every member: a line has no optional member. A label may have two lines,
// one for each purpose (its X.509 key and its OpenPGP primary): the pair of label and purpose is
// born once, and the reader of one line does not know the others.
type BirthLine struct {
	// At is when the key existed: a time.
	At string `json:"at"`
	// Label is the key's label: one upper-case letter.
	Label string `json:"label"`
	// Purpose is what the key is for, a word of lower-case letters, digits and hyphens, for
	// example x509-root or openpgp-primary (the words are Proposed on the page).
	Purpose string `json:"purpose"`
	// Store is the key store, a word as Purpose is.
	Store string `json:"store"`
	// Place is where the key is, as the plan gives it: printable ASCII, at most 255 bytes.
	Place string `json:"place"`
	// PublicKeySHA256 is the SHA-256 digest of the public key: the DER SubjectPublicKeyInfo of an
	// X.509 key, which is its pin, and of the same encoding of an OpenPGP primary's key (the member
	// has 64 digits for both; the 40-digit fingerprint of a primary is in the signature lines).
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// SignatureLine is one line of signatures.jsonl, the journal of signatures: the members that the
// page proposes. A line is written after the signature is made, and holds no signature.
// [ReadSignatureLine] requires every member.
type SignatureLine struct {
	// At is when the signature was made: a time.
	At string `json:"at"`
	// N is the place of the signature in the plan's signatures, from 1.
	N int64 `json:"n"`
	// Kind is one of the kinds that the page lists.
	Kind string `json:"kind"`
	// Key is the fingerprint of the signing key: 64 digits of the SHA-256 of an X.509 key, or the 40
	// digits of an OpenPGP primary.
	Key string `json:"key"`
	// SignatureSHA256 is the SHA-256 digest of the signature that was made.
	SignatureSHA256 string `json:"signature_sha256"`
}

// ReadBirthLine reads the bytes of one line of the birth journal, without its line feed. The line
// is one JSON object under the rules of the page's "Common rules" (at most [MaxJournalLine]
// bytes, checked first), holds every member and no other, and is in the canonical form of RFC
// 8785, so a line that is accepted is the line [BirthLine.Canonical] writes.
func ReadBirthLine(b []byte) (*BirthLine, error) {
	var l BirthLine
	if err := readLine(b, "birth journal line", &l); err != nil {
		return nil, err
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &l, nil
}

// ReadSignatureLine reads the bytes of one line of the journal of signatures as [ReadBirthLine]
// reads a line of the birth journal.
func ReadSignatureLine(b []byte) (*SignatureLine, error) {
	var l SignatureLine
	if err := readLine(b, "signature journal line", &l); err != nil {
		return nil, err
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return &l, nil
}

// Canonical returns the line in the canonical form of RFC 8785, with no line feed. A line that
// breaks the rules of [ReadBirthLine] is an error and nothing is returned, so the zero value, and
// a nil line, are refused.
func (l *BirthLine) Canonical() ([]byte, error) {
	if l == nil {
		return nil, errors.New("birth journal line: there is no line")
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return canonjson.Marshal(l)
}

// Canonical returns the line in the canonical form of RFC 8785, with no line feed, as
// [BirthLine.Canonical] does.
func (l *SignatureLine) Canonical() ([]byte, error) {
	if l == nil {
		return nil, errors.New("signature journal line: there is no line")
	}
	if err := l.validate(); err != nil {
		return nil, err
	}
	return canonjson.Marshal(l)
}

func (l *BirthLine) validate() error {
	c := checker{what: "birth journal line"}
	for _, err := range []error{
		c.time("at", l.At, true),
		c.label("label", l.Label),
		c.word("purpose", l.Purpose),
		c.word("store", l.Store),
		c.place("place", l.Place),
		c.digest("public_key_sha256", l.PublicKeySHA256, true),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

func (l *SignatureLine) validate() error {
	c := checker{what: "signature journal line"}
	if l.N < 1 || l.N > MaxJournalLines {
		return formatError(c.what, "n", "is %d, not a place from 1 to %d", l.N, MaxJournalLines)
	}
	for _, err := range []error{
		c.time("at", l.At, true),
		c.oneOf("kind", l.Kind, signatureKinds...),
		c.fingerprint("key", l.Key),
		c.digest("signature_sha256", l.SignatureSHA256, true),
	} {
		if err != nil {
			return err
		}
	}
	return nil
}

// readLine reads one line of a journal into v: bounded, one line, one JSON object, the strict
// reader, and the canonical form.
func readLine(b []byte, what string, v any) error {
	if len(b) > MaxJournalLine {
		return formatError(what, "line", "is longer than %d bytes", MaxJournalLine)
	}
	if bytes.ContainsAny(b, "\r\n") {
		return formatError(what, "line", "holds a line break; a journal line is one line")
	}
	if err := strictjson.Unmarshal(b, v, strictjson.Options{MaxBytes: MaxJournalLine}); err != nil {
		return err
	}
	ok, err := canonjson.IsCanonical(b)
	if err != nil {
		return err
	}
	if !ok {
		return formatError(what, "line", "is not in the canonical form of RFC 8785")
	}
	return nil
}

// label is a label of a root key: one upper-case letter.
func (c checker) label(member, s string) error {
	if len(s) != 1 || s[0] < 'A' || s[0] > 'Z' {
		return formatError(c.what, member, "%s is not one upper-case letter", shown(s))
	}
	return nil
}

// word is a word of lower-case letters, digits and hyphens, at most 64 bytes, that starts with a
// letter or a digit.
func (c checker) word(member, s string) error {
	if s == "" {
		return c.missing(member)
	}
	ok := len(s) <= 64 && s[0] != '-'
	for i := 0; ok && i < len(s); i++ {
		ch := s[i]
		ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-'
	}
	if !ok {
		return formatError(c.what, member, "%s is not a word of lower-case letters, digits and hyphens, at most 64 bytes", shown(s))
	}
	return nil
}

// place is a text of printable ASCII (a space is allowed inside), at most 255 bytes, with no space
// at its start or its end.
func (c checker) place(member, s string) error {
	if s == "" {
		return c.missing(member)
	}
	ok := len(s) <= maxPlaceBytes && s[0] != ' ' && s[len(s)-1] != ' '
	for i := 0; ok && i < len(s); i++ {
		ok = s[i] >= 0x20 && s[i] < 0x7f
	}
	if !ok {
		return formatError(c.what, member, "%s is not printable ASCII of at most %d bytes with no space at either end", shown(s), maxPlaceBytes)
	}
	return nil
}

// fingerprint is the fingerprint of a key as the page's "Common rules" gives it: 64 lower-case
// hexadecimal digits (an X.509 key) or 40 (an OpenPGP key).
func (c checker) fingerprint(member, s string) error {
	if s == "" {
		return c.missing(member)
	}
	if IsDigest(s) || isHex(s, 40) {
		return nil
	}
	return formatError(c.what, member, "%s is not a key fingerprint of 64 or 40 lower-case hexadecimal characters", shown(s))
}

// isHex reports whether s is n lower-case hexadecimal characters.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}
