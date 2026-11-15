package openpgp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// The limits of the keyring file (docs/reference/keyring-package.md, "The first form of the keyring
// file"). Passing one is an [ErrKeyringForm]. The values are proposed: no page names them.
const (
	// MaxKeyringBytes is the most bytes of the file: 1 MiB. It is checked before the first packet is
	// read.
	MaxKeyringBytes = 1 << 20
	// MaxKeyringCertificates is the most certificates in the file, and the most entries of a list
	// that [ReadKeyring] is given: 26, one for each label A to Z.
	MaxKeyringCertificates = 26
	// MaxCertifications is the most self-certifications of one primary: 256.
	MaxCertifications = 256

	// maxKeyringPackets is the most packets that the walk of a file reads.
	maxKeyringPackets = MaxKeyringCertificates * (2 + MaxCertifications)
	// armourLine is how an armoured file starts. The first form is binary.
	armourLine = "-----BEGIN"
	// maxDetail is the most characters of a fault of a user ID that an error shows.
	maxDetail = 160
)

// KeyringEntry is one entry of the root list that has an openpgp_fingerprint: its label and the
// fingerprint of its primary, 40 lower-case hexadecimal digits.
type KeyringEntry struct {
	Label       string // one capital letter, A to Z
	Fingerprint string // 40 lower-case hexadecimal digits, version 4
}

// ReadKeyring reads the keyring file of a trust set in its first form and holds it to want: the
// entries of the root list that have a fingerprint, in the order of the list. It returns the
// primaries in the order of want, each made from the key packet of its certificate, so that the
// key and the creation time are copies and the caller that changes the file afterwards changes
// nothing. It reads no file and writes nothing, and it returns no primary with an error.
//
// The first form is binary OpenPGP packets, one certificate for each entry of want, in its order.
// A certificate is, in this order, one Public-Key packet (tag 6), one User ID packet (tag 13) and
// one or more Signature packets (tag 2): the self-certifications of the primary, in creation
// order. No other packet is read: a subkey comes with a later form. Both packet header formats and
// every fixed length of RFC 9580, section 4.2 are read, as [SplitBoundFile] reads them, so the
// certificate files of the hand-off, whose packets have five-octet lengths, are read as they are;
// a partial or an indeterminate length is refused. The bytes of the file are the bytes of its
// certificates: nothing stands between them and nothing after the last.
//
// The key of each certificate is a version 4 ECDSA key on P-384 with its point on the curve and a
// creation time that is not zero, and its fingerprint is the fingerprint of the entry at its
// position. The user ID has the one shape of [UserID] and names the label of its entry. Every
// certification is the self-signature of [NewPrimary] ([ExtendPrimary] makes the later ones): the
// one shape that [NewPrimary] writes, which verifies with the key over the user ID, dated not
// before the key and not before the certification before it. The user IDs of all certificates carry
// the mark " (TEST ONLY)" or none does: a file that mixes test and real primaries is refused. The
// expiry of a primary is not compared with a clock here, and the root list is not read.
//
// The checks run in this order, the cheapest first, and the first fault gives the error, made once:
//
//  1. want: empty, longer than [MaxKeyringCertificates], a label that is not one capital letter, a
//     fingerprint that is not 40 lower-case hexadecimal digits, or a label or a fingerprint twice,
//     is an [ErrParams], and the file is not read.
//  2. The size: an empty file or one over [MaxKeyringBytes] is an [ErrKeyringForm], before any
//     packet is read. A file that starts with the armour line is an ErrKeyringForm.
//  3. The walk of the packets and their grouping into certificates, by the order above, at most
//     26 * (2 + MaxCertifications) packets, at most [MaxKeyringCertificates] certificates and
//     [MaxCertifications] certifications for each: any fault is an ErrKeyringForm. Then the number of
//     certificates against len(want): fewer is "missing", more is "one too many", each an
//     [ErrKeyringPrimaries].
//  4. Every certificate in order, with no signature check: the key (an ErrKeyringForm), whether its
//     fingerprint repeats an earlier one or its point is an earlier one's, then its fingerprint
//     against want[i] (a fingerprint that is on the list at another place is "out of order", one that
//     is not on the list is "not on the list"; each an ErrKeyringPrimaries), the user ID, its label
//     against the label of the entry (an ErrKeyringPrimaries), and whether one certification of it
//     repeats another, compared by the body of the packet, so that the same certification in
//     another header form is a repeat too (an ErrKeyringForm).
//  5. No mix of the test mark over all the certificates.
//  6. Only then the certifications, certificate by certificate and in order, each verified: a file
//     whose last certificate holds a foreign key, or that mixes test and real primaries, costs no
//     signature check.
//
// A fault of the arguments is an [ErrParams]. A fault of the file is an ErrKeyringForm or an
// ErrKeyringPrimaries, and both are an [ErrKeyring]. The text of an error names a position and a
// label and holds no byte of the file; a fault of a user ID shows code points only as U+XXXX.
// The cost of one run is at most one signature check for each certification of the file, and the
// limits bound the number of them.
func ReadKeyring(file []byte, want []KeyringEntry) (keys []*PrimaryKey, err error) {
	want = append([]KeyringEntry(nil), want...)
	if err := checkKeyringEntries(want); err != nil {
		return nil, err
	}
	defer func() {
		if r := recover(); r != nil {
			keys, err = nil, fail(ErrKeyringForm, "the file could not be read")
		}
	}()
	return readKeyring(file, want, checkCertification)
}

// certChecker is the check of one self-certification that the reader runs for each certification
// of the file: [checkCertification] in [ReadKeyring].
type certChecker func(pkt []byte, k *key, userID string, notBefore time.Time) (certification, error)

// readKeyring is the work of [ReadKeyring] after the check of want: it has no recover, so that a
// panic in it can be seen by a test of the package, and it takes the check of one certification as
// a parameter, so that a test can count the checks that a file costs. want is held to its rules.
func readKeyring(file []byte, want []KeyringEntry, check certChecker) ([]*PrimaryKey, error) {
	if len(file) == 0 {
		return nil, fail(ErrKeyringForm, "the file is empty")
	}
	if len(file) > MaxKeyringBytes {
		return nil, fail(ErrKeyringForm, "the file is longer than %d bytes", MaxKeyringBytes)
	}
	if bytes.HasPrefix(file, []byte(armourLine)) {
		return nil, fail(ErrKeyringForm, "the file is armoured: the keyring file of a trust set is binary packets, not armour")
	}
	certs, err := groupKeyring(file, want)
	if err != nil {
		return nil, err
	}
	if len(certs) < len(want) {
		return nil, fail(ErrKeyringPrimaries, "missing: the file has %d of %d certificates, and the certificate of position %d (label %s) is not there",
			len(certs), len(want), len(certs)+1, want[len(certs)].Label)
	}
	if len(certs) > len(want) {
		return nil, fail(ErrKeyringPrimaries, "one too many: the file has %d certificates, and the list has %d entries", len(certs), len(want))
	}
	return readCertificates(certs, want, check)
}

// checkKeyringEntries holds want to its rules: an [ErrParams] for each fault.
func checkKeyringEntries(want []KeyringEntry) error {
	if len(want) == 0 {
		return fail(ErrParams, "the list has no entry with a fingerprint")
	}
	if len(want) > MaxKeyringCertificates {
		return fail(ErrParams, "the list has more than %d entries", MaxKeyringCertificates)
	}
	labels := make(map[string]bool, len(want))
	prints := make(map[string]bool, len(want))
	for i, e := range want {
		if err := checkLabel(e.Label); err != nil {
			return fail(ErrParams, "entry %d: the label is not one capital letter from A to Z", i+1)
		}
		if !isFingerprint(e.Fingerprint) {
			return fail(ErrParams, "entry %d (label %s): the fingerprint is not 40 lower-case hexadecimal digits", i+1, e.Label)
		}
		if labels[e.Label] {
			return fail(ErrParams, "entry %d: the label %s is twice in the list", i+1, e.Label)
		}
		if prints[e.Fingerprint] {
			return fail(ErrParams, "entry %d (label %s): the fingerprint is twice in the list", i+1, e.Label)
		}
		labels[e.Label], prints[e.Fingerprint] = true, true
	}
	return nil
}

// isFingerprint tells whether s is 40 lower-case hexadecimal digits.
func isFingerprint(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// keyringCert is the packets of one certificate, each whole with its header.
type keyringCert struct {
	key  []byte
	uid  []byte   // the body of the User ID packet
	has  bool     // whether the User ID packet was read
	sigs [][]byte // each whole with its header
	// bodies are the bodies of sigs, to compare two of them whatever their header forms.
	bodies [][]byte
}

// where names a certificate by its position and, when the list has an entry there, its label.
func where(i int, want []KeyringEntry) string {
	if i < len(want) {
		return fmt.Sprintf("certificate %d (label %s)", i+1, want[i].Label)
	}
	return fmt.Sprintf("certificate %d", i+1)
}

// groupKeyring walks the packets of the file and groups them into certificates of the first form.
func groupKeyring(file []byte, want []KeyringEntry) ([]keyringCert, error) {
	var certs []keyringCert
	rest := file
	for n := 1; len(rest) > 0; n++ {
		if n > maxKeyringPackets {
			return nil, fail(ErrKeyringForm, "the file has more than %d packets", maxKeyringPackets)
		}
		tag, body, after, err := splitPacket(rest)
		if err != nil {
			return nil, fail(ErrKeyringForm, "packet %d is not whole, or its length is a form that is not read", n)
		}
		raw := rest[:len(rest)-len(after)] // the whole packet, with its header
		rest = after
		if len(certs) == 0 && tag != tagPublicKey {
			return nil, fail(ErrKeyringForm, "the first packet is not a Public-Key packet (tag %d)", tag)
		}
		if tag == tagPublicKey {
			if len(certs) > 0 {
				if err := certComplete(certs, len(certs)-1, want); err != nil {
					return nil, err
				}
			}
			if len(certs) == MaxKeyringCertificates {
				return nil, fail(ErrKeyringForm, "the file has more than %d certificates", MaxKeyringCertificates)
			}
			certs = append(certs, keyringCert{key: raw})
			continue
		}
		cur := &certs[len(certs)-1]
		at := where(len(certs)-1, want)
		switch tag {
		case tagUserID:
			if cur.has {
				return nil, fail(ErrKeyringForm, "%s has a second user ID packet", at)
			}
			cur.uid, cur.has = body, true
		case tagSignature:
			if !cur.has {
				return nil, fail(ErrKeyringForm, "%s has a certification before its user ID packet", at)
			}
			if len(cur.sigs) == MaxCertifications {
				return nil, fail(ErrKeyringForm, "%s has more than %d certifications", at, MaxCertifications)
			}
			cur.sigs, cur.bodies = append(cur.sigs, raw), append(cur.bodies, body)
		case tagSubkey:
			return nil, fail(ErrKeyringForm, "%s has a Public-Subkey packet: subkeys come with M5, and the first form has none", at)
		default:
			return nil, fail(ErrKeyringForm, "%s has a packet of tag %d, which the first form does not have", at, tag)
		}
	}
	if err := certComplete(certs, len(certs)-1, want); err != nil {
		return nil, err
	}
	return certs, nil
}

// certComplete refuses a certificate that has no user ID packet or no certification.
func certComplete(certs []keyringCert, i int, want []KeyringEntry) error {
	switch c := certs[i]; {
	case !c.has:
		return fail(ErrKeyringForm, "%s has no user ID packet", where(i, want))
	case len(c.sigs) == 0:
		return fail(ErrKeyringForm, "%s has no certification", where(i, want))
	}
	return nil
}

// readCertificates reads the certificates against the entries of their positions and returns the
// primaries. It makes the checks that need no signature check for all certificates first, and
// checks the certifications of the first certificate only after every certificate has passed them.
func readCertificates(certs []keyringCert, want []KeyringEntry, check certChecker) ([]*PrimaryKey, error) {
	read := make([]*key, 0, len(certs))
	keys := make([]*PrimaryKey, 0, len(certs))
	prints := make(map[string]int, len(certs))
	points := make(map[string]int, len(certs))
	var test, plain int
	for i, c := range certs {
		at := where(i, want)
		k, err := readKey(c.key, tagPublicKey)
		if err != nil || k.created.Unix() < 1 {
			return nil, fail(ErrKeyringForm, "%s: the key packet is not a version 4 ECDSA key on P-384 with its point on the curve and a creation time that is not zero", at)
		}
		fp := hex.EncodeToString(k.fp)
		point := string(k.body[len(k.body)-97:])
		if j, ok := prints[fp]; ok {
			return nil, fail(ErrKeyringPrimaries, "repeats: %s holds the key of certificate %d", at, j+1)
		}
		if j, ok := points[point]; ok {
			return nil, fail(ErrKeyringPrimaries, "repeats: %s holds the key point of certificate %d", at, j+1)
		}
		prints[fp], points[point] = i, i
		if fp != want[i].Fingerprint {
			for j, e := range want {
				if e.Fingerprint == fp {
					return nil, fail(ErrKeyringPrimaries, "out of order: %s holds the key of position %d (label %s)", at, j+1, e.Label)
				}
			}
			return nil, fail(ErrKeyringPrimaries, "not on the list: %s holds a key that no entry names", at)
		}
		uid := string(c.uid)
		if err := checkUserID(uid); err != nil {
			return nil, fail(ErrKeyringForm, "%s: the user ID is refused: %s", at, detail(err))
		}
		label, isTest := userIDLabel(uid)
		if label != want[i].Label {
			return nil, fail(ErrKeyringPrimaries, "%s: the user ID names the label %s", at, label)
		}
		if isTest {
			test++
		} else {
			plain++
		}
		seen := make(map[string]int, len(c.bodies))
		for j, body := range c.bodies {
			if first, ok := seen[string(body)]; ok {
				return nil, fail(ErrKeyringForm, "%s: certification %d repeats certification %d", at, j+1, first+1)
			}
			seen[string(body)] = j
		}
		pk, err := NewPrimaryKey(k.ec, k.created)
		if err != nil || pk.Fingerprint() != fp {
			return nil, fail(ErrKeyringForm, "%s: the key packet is not read as it is", at)
		}
		read, keys = append(read, k), append(keys, pk)
	}
	if test > 0 && plain > 0 {
		return nil, fail(ErrKeyringForm, "the file mixes test and real primaries: %d with the mark %q and %d without it", test, strings.TrimSpace(testMark), plain)
	}
	for i, c := range certs {
		notBefore := read[i].created
		for j, sig := range c.sigs {
			cert, err := check(sig, read[i], string(c.uid), notBefore)
			if err != nil {
				return nil, fail(ErrKeyringForm, "%s, certification %d: %v", where(i, want), j+1, err)
			}
			notBefore = cert.created
		}
	}
	return keys, nil
}

// userIDLabel returns the label and the test mark of a user ID that checkUserID accepted.
func userIDLabel(id string) (label string, test bool) {
	rest := strings.TrimSuffix(id, ">")
	head := rest[:strings.LastIndex(rest, " <")]
	head, test = strings.CutSuffix(head, testMark)
	return head[strings.LastIndex(head, releaseRoot)+len(releaseRoot):], test
}

// detail is the text of a fault of the builders' rules without its kind, kept to printable ASCII and
// cut, so that an error that shows it holds no byte of a file.
func detail(err error) string {
	s := strings.TrimPrefix(err.Error(), ErrParams.Error()+": ")
	var b strings.Builder
	for i := 0; i < len(s) && i < maxDetail; i++ {
		if c := s[i]; c >= ' ' && c <= '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
