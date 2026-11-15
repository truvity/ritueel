package openpgp_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/openpgp"
)

// Every refusal of the reader has its own test below: the arguments (ErrParams, the file is not
// read), the form of the file (ErrKeyringForm), and the primaries (ErrKeyringPrimaries). A refusal
// returns no primary, shows no byte of the file, and says where.

func TestTheArgumentsAreRefusedBeforeTheFileIsReadWhateverTheFileIs(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	good := wantOf(m)
	fp := m.fp
	cases := []struct {
		name string
		want []openpgp.KeyringEntry
	}{
		{"a nil list", nil},
		{"an empty list", []openpgp.KeyringEntry{}},
		{"27 entries", append(wantOfN(26), openpgp.KeyringEntry{Label: "A", Fingerprint: fmt.Sprintf("%040x", 99)})},
		{"the zero entry", []openpgp.KeyringEntry{{}}},
		{"a lower-case label", []openpgp.KeyringEntry{{Label: "a", Fingerprint: fp}}},
		{"a label of two letters", []openpgp.KeyringEntry{{Label: "AA", Fingerprint: fp}}},
		{"a digit for a label", []openpgp.KeyringEntry{{Label: "1", Fingerprint: fp}}},
		{"an empty label", []openpgp.KeyringEntry{{Label: "", Fingerprint: fp}}},
		{"a bracket for a label", []openpgp.KeyringEntry{{Label: "<", Fingerprint: fp}}},
		{"a label with a space", []openpgp.KeyringEntry{{Label: "A ", Fingerprint: fp}}},
		{"a label that is a letter of another script", []openpgp.KeyringEntry{{Label: "А", Fingerprint: fp}}},
		{"an upper-case fingerprint", []openpgp.KeyringEntry{{Label: "A", Fingerprint: strings.ToUpper(fp)}}},
		{"a fingerprint of 39 digits", []openpgp.KeyringEntry{{Label: "A", Fingerprint: fp[1:]}}},
		{"a fingerprint of 41 digits", []openpgp.KeyringEntry{{Label: "A", Fingerprint: fp + "0"}}},
		{"a fingerprint with a space", []openpgp.KeyringEntry{{Label: "A", Fingerprint: fp[:20] + " " + fp[21:]}}},
		{"a fingerprint with a letter that is not a digit", []openpgp.KeyringEntry{{Label: "A", Fingerprint: "g" + fp[1:]}}},
		{"a fingerprint with a prefix", []openpgp.KeyringEntry{{Label: "A", Fingerprint: "0x" + fp[2:]}}},
		{"an empty fingerprint", []openpgp.KeyringEntry{{Label: "A", Fingerprint: ""}}},
		{"a label twice", []openpgp.KeyringEntry{{Label: "A", Fingerprint: fp}, {Label: "A", Fingerprint: fmt.Sprintf("%040x", 5)}}},
		{"a fingerprint twice", []openpgp.KeyringEntry{{Label: "A", Fingerprint: fp}, {Label: "B", Fingerprint: fp}}},
		{"a good entry and a bad one", append(append([]openpgp.KeyringEntry{}, good...), openpgp.KeyringEntry{Label: "b", Fingerprint: fmt.Sprintf("%040x", 5)})},
	}
	files := map[string][]byte{
		"a good file":  m.good(t),
		"no file":      nil,
		"garbage":      []byte("not a keyring"),
		"over the cap": bytes.Repeat([]byte{1}, openpgp.MaxKeyringBytes+1),
		"armour":       []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
	}
	for _, c := range cases {
		for name, file := range files {
			what := c.name + " with " + name
			keys, err := readSafely(t, what, file, c.want)
			if !errors.Is(err, openpgp.ErrParams) {
				t.Errorf("%s: error = %v, want an ErrParams", what, err)
				continue
			}
			if keys != nil || errors.Is(err, openpgp.ErrKeyring) {
				t.Errorf("%s: %d primaries, or an error that is an ErrKeyring: %v", what, len(keys), err)
			}
			checkText(t, what, err)
		}
	}
}

// wantOfN is n entries with distinct labels A.. and distinct fingerprints that no key gives.
func wantOfN(n int) []openpgp.KeyringEntry {
	out := make([]openpgp.KeyringEntry, n)
	for i := range out {
		out[i] = openpgp.KeyringEntry{Label: string(rune('A' + i)), Fingerprint: fmt.Sprintf("%040x", i+1)}
	}
	return out
}

func TestTheArgumentsOfTwentySixEntriesAreAcceptedAsArguments(t *testing.T) {
	// The negative control of the 27 above: 26 entries are not refused as arguments. The file is
	// garbage, so the refusal is the file's.
	keys, err := readSafely(t, "26 entries", []byte("garbage"), wantOfN(26))
	if keys != nil || !errors.Is(err, openpgp.ErrKeyringForm) {
		t.Errorf("26 entries and a garbage file: error = %v, want an ErrKeyringForm", err)
	}
}

func TestAFileThatIsNotTheFirstFormIsRefusedAsFormAndNoPrimaryComesBack(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	other := newKeyringPrimary(t, "B", true)
	good := m.good(t)
	sig := m.sig(t, ceremony, nil)
	want := wantOf(m)
	armour := []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQ==\n=abcd\n-----END PGP PUBLIC KEY BLOCK-----\n")
	subkeyBody := keyBody(&other.key.PublicKey, created)
	cases := []struct {
		name  string
		file  []byte
		words string
	}{
		{"a nil file", nil, "empty"},
		{"an empty file", []byte{}, "empty"},
		{"one byte over the limit", bytes.Repeat([]byte{0xAB}, openpgp.MaxKeyringBytes+1), "longer than 1048576"},
		{"a good certificate padded over the limit", append(bytes.Clone(good), make([]byte, openpgp.MaxKeyringBytes)...), "longer than 1048576"},
		{"armour over the limit", append(bytes.Clone(armour), make([]byte, openpgp.MaxKeyringBytes)...), "longer than 1048576"},
		{"armour", armour, "armoured"},
		{"armour that holds a good certificate", append([]byte("-----BEGIN"), good...), "armoured"},
		{"text before the first packet", cat([]byte("hello"), good), "packet 1"},
		{"a space before the first packet", cat([]byte{' '}, good), "packet 1"},
		{"a byte after the last packet", cat(good, []byte{0x00}), "packet 4"},
		{"a header after the last packet", cat(good, []byte{0xC2}), "packet 4"},
		{"text after the last packet", cat(good, []byte("trailing")), "packet 4"},
		{"a header cut to one byte", good[:1], "packet 1"},
		{"a header cut inside its length", good[:4], "packet 1"},
		{"the last packet cut by one byte", good[:len(good)-1], "packet 3"},
		{"the first packet cut by one byte", good[:len(m.keyPacket())-1], "packet 1"},
		{"a partial length", cat(m.keyPacket(), []byte{0xCD, 0xE1, 0, 0, 0, 2, 'a', 'b'}), "packet 2"},
		{"a partial length that a five-octet reader would take whole", cat(m.keyPacket(), []byte{0xCD, 0xE0, 0, 0, 0, 2, 'a', 'b'}, m.sig(t, ceremony, nil)), "packet 2"},
		{"a partial length at the first packet", []byte{0xC6, 0xE0, 0x01}, "packet 1"},
		{"an indeterminate length", cat([]byte{0x9B}, m.keyPacket()[2:]), "packet 1"},
		{"an indeterminate length after the key", cat(m.keyPacket(), []byte{0xB7, 'a'}), "packet 2"},
		{"a length that leaves the file by one byte", cat(m.keyPacket(), []byte{0xCD, 0xFF, 0, 0, 0, 5, 'a', 'b', 'c', 'd'}), "packet 2"},
		{"a length of four gibibytes", cat(m.keyPacket(), []byte{0xCD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 'a'}), "packet 2"},
		{"a length of four gibibytes in the old format", cat(m.keyPacket(), []byte{0xB6, 0xFF, 0xFF, 0xFF, 0xFF, 'a'}), "packet 2"},
		{"a first packet of four gibibytes", []byte{0xC6, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, "packet 1"},
		{"a two-octet length that leaves the file", cat(m.keyPacket(), []byte{0xCD, 0xC5, 0xFF, 'a'}), "packet 2"},
		{"a packet that does not start with a set high bit", cat(m.keyPacket(), []byte{0x40, 0x01, 'a'}), "packet 2"},
		{"a certificate that is only a key packet", m.keyPacket(), "no user ID"},
		{"a key and a user ID with no certification", cat(m.keyPacket(), m.uidPacket()), "no certification"},
		{"a key and a certification with no user ID", cat(m.keyPacket(), sig), "before its user ID"},
		{"a second user ID", cat(m.keyPacket(), m.uidPacket(), m.uidPacket(), sig), "second user ID"},
		{"a user ID after the certification", cat(m.keyPacket(), m.uidPacket(), sig, m.uidPacket()), "second user ID"},
		{"a subkey after the certification", cat(good, wrap(tagSubkey, subkeyBody)), "M5"},
		{"a subkey before the certification", cat(m.keyPacket(), m.uidPacket(), wrap(tagSubkey, subkeyBody), sig), "M5"},
		{"a trust packet", cat(m.keyPacket(), m.uidPacket(), wrap(12, []byte{1}), sig), "tag 12"},
		{"a user attribute packet", cat(m.keyPacket(), m.uidPacket(), wrap(17, []byte{1, 2, 3}), sig), "tag 17"},
		{"a literal data packet", cat(good, wrap(11, []byte("x"))), "tag 11"},
		{"a compressed data packet", cat(good, wrap(8, []byte("x"))), "tag 8"},
		{"a secret subkey packet", cat(good, wrap(7, []byte("x"))), "tag 7"},
		{"a reserved packet tag", cat(good, wrap(0, []byte("x"))), "tag 0"},
		{"the highest packet tag", cat(good, wrap(63, []byte("x"))), "tag 63"},
		{"a secret key packet in place of the public key", cat(wrap(5, keyBody(&m.key.PublicKey, created)), m.uidPacket(), sig), "first packet"},
		{"a user ID first", cat(m.uidPacket(), m.keyPacket(), sig), "first packet"},
		{"a certification first", cat(sig, m.keyPacket(), m.uidPacket()), "first packet"},
		{"a subkey first", cat(wrap(tagSubkey, subkeyBody), m.uidPacket(), sig), "first packet"},
		{"a second key packet where the user ID should be", cat(m.keyPacket(), m.keyPacket(), m.uidPacket(), sig), "no user ID"},
		{"a certificate of a key and a user ID, then a whole one", cat(m.keyPacket(), m.uidPacket(), good), "no certification"},
		{"257 certifications", m.assemble(bytes.Repeat(sig, openpgp.MaxCertifications+1)), "more than 256 certifications"},
		{"27 certificates of 26 entries", bytes.Repeat(good, openpgp.MaxKeyringCertificates+1), "more than 26 certificates"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertKeyringRefused(t, c.name, c.file, want, openpgp.ErrKeyringForm, c.words)
		})
	}
	// The same 27 certificates against a list of one entry are a form fault too: the file is judged
	// before it is held to the list.
	assertKeyringRefused(t, "27 certificates against one entry", bytes.Repeat(good, 27), want, openpgp.ErrKeyringForm, "more than 26 certificates")
	// The boundary of the size: a file of exactly the limit is not refused for its size.
	_, err := readSafely(t, "a file of 1 MiB", bytes.Repeat([]byte{0xAB}, openpgp.MaxKeyringBytes), want)
	if err == nil || strings.Contains(err.Error(), "longer than") {
		t.Errorf("a file of exactly the limit: error = %v, want a refusal that is not about the size", err)
	}
}

func TestTheNumberOfPacketsOfTheWalkIsBoundedAndTheLimitIsTheOnePublished(t *testing.T) {
	// 26 certificates of a tiny key packet, a tiny user ID and 256 tiny certifications are 6,708
	// packets in 13,416 bytes: the walk reads them. One packet more is refused by the count of
	// packets, before the limit of certifications of that certificate is looked at.
	cert := cat([]byte{0xC6, 0x00}, []byte{0xCD, 0x00}, bytes.Repeat([]byte{0xC2, 0x00}, openpgp.MaxCertifications))
	file := bytes.Repeat(cert, openpgp.MaxKeyringCertificates)
	if got := len(splitPackets(t, file)); got != openpgp.MaxKeyringPackets {
		t.Fatalf("the file has %d packets, want %d", got, openpgp.MaxKeyringPackets)
	}
	want := wantOfN(26)
	keys, err := readSafely(t, "6708 packets", file, want)
	if keys != nil || !errors.Is(err, openpgp.ErrKeyringForm) || strings.Contains(err.Error(), "packets") {
		t.Errorf("6708 packets: error = %v, want a refusal of the first key packet, not of the count", err)
	}
	assertKeyringRefused(t, "6709 packets", cat(file, []byte{0xC2, 0x00}), want, openpgp.ErrKeyringForm, "more than 6708 packets")
	assertKeyringRefused(t, "6709 packets, the last one a key", cat(file, []byte{0xC6, 0x00}), want, openpgp.ErrKeyringForm, "more than 6708 packets")
	// Only a tiny packet can be that many: a thousand bytes of padding is a whole packet, and the
	// count is by packets and not by bytes.
	assertKeyringRefused(t, "256 certifications and one more of a certificate", cat(
		[]byte{0xC6, 0x00}, []byte{0xCD, 0x00}, bytes.Repeat([]byte{0xC2, 0x00}, openpgp.MaxCertifications+1)),
		wantOfN(1), openpgp.ErrKeyringForm, "more than 256 certifications")
}

func TestAKeyThatIsNotAVersion4EcdsaKeyOnP384WithItsPointOnTheCurveIsRefused(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	uid, sig := m.uidPacket(), m.sig(t, ceremony, nil)
	body := keyBody(&m.key.PublicKey, created)
	edit := func(f func(b []byte)) []byte {
		b := bytes.Clone(body)
		f(b)
		return b
	}
	// A point that is not on the curve: the last byte of the ordinate changed. The precondition is
	// checked, so that the case cannot become a case of a good key.
	offCurve := edit(func(b []byte) { b[len(b)-1] ^= 0x01 })
	if _, err := ecdh.P384().NewPublicKey(offCurve[len(offCurve)-97:]); err == nil {
		t.Fatal("the point that was meant to be off the curve is on it")
	}
	rsaKey, err := newRSAKeyBody()
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256pt, err := p256.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	edpub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256Body := cat([]byte{4}, u32(uint32(created.Unix())), []byte{19, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}, mpi(new(big.Int).SetBytes(p256pt)))
	edBody := cat([]byte{4}, u32(uint32(created.Unix())), []byte{22, 9, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}, mpi(new(big.Int).SetBytes(append([]byte{0x40}, edpub...))))
	cases := []struct {
		name string
		body []byte
	}{
		{"a version 3 key", edit(func(b []byte) { b[0] = 3 })},
		{"a version 5 key", edit(func(b []byte) { b[0] = 5 })},
		{"a version 6 key", edit(func(b []byte) { b[0] = 6 })},
		{"a RSA key", rsaKey},
		{"a P-256 key", p256Body},
		{"an Ed25519 key", edBody},
		{"an ECDH algorithm on the curve P-384", edit(func(b []byte) { b[5] = 18 })},
		{"the curve identifier of P-521", edit(func(b []byte) { b[11] = 0x23 })},
		{"a point that is not on the curve", offCurve},
		{"a point of 49 bytes", cat(body[:6], []byte{5, 0x2B, 0x81, 0x04, 0x00, 0x22}, mpi(new(big.Int).SetBytes(append([]byte{2}, make([]byte, 48)...))))},
		{"a byte after the point", append(bytes.Clone(body), 0x00)},
		{"a key packet cut short", body[:30]},
		{"a creation time of zero", edit(func(b []byte) { copy(b[1:5], []byte{0, 0, 0, 0}) })},
		{"a key that is only a version byte", body[:1]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The user ID and the certification are those of a good key: the refusal is the key's.
			file := cat(wrap(tagPublicKey, c.body), uid, sig)
			assertKeyringRefused(t, c.name, file, wantOf(m), openpgp.ErrKeyringForm, "certificate 1 (label A)", "key packet")
		})
	}
}

func newRSAKeyBody() ([]byte, error) {
	n, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	m, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	return cat([]byte{4}, u32(uint32(created.Unix())), []byte{1}, mpi(new(big.Int).Mul(n, m)), mpi(big.NewInt(65537))), nil
}

func TestACreationTimeOfZeroIsRefusedWhateverTheRestOfACertificateIs(t *testing.T) {
	// A key made with the time 0 and a certification that is good for it: the key is the fault.
	k := genKey(t)
	zero := time.Unix(0, 0).UTC()
	body := keyBody(&k.PublicKey, zero)
	if !bytes.Equal(body[1:5], []byte{0, 0, 0, 0}) {
		t.Fatalf("the key body holds the time % x", body[1:5])
	}
	m := keyringPrimaryOf(t, k, "A", true, created, "release@example.org")
	m.at = zero
	file := cat(wrap(tagPublicKey, body), m.uidPacket(), m.sig(t, ceremony, nil))
	fpOfZero := hexLower(fingerprint(&k.PublicKey, zero))
	assertKeyringRefused(t, "created at 0", file, []openpgp.KeyringEntry{{Label: "A", Fingerprint: fpOfZero}}, openpgp.ErrKeyringForm, "key packet")
}

func TestTheCertificatesAreHeldToTheListAndEachFaultHasItsOwnWords(t *testing.T) {
	v := loadVectorKeyring(t)
	a, b, z := v.a, v.b, v.z
	fpA, fpB := v.want[0], v.want[1]
	m := newKeyringPrimary(t, "A", true)
	cases := []struct {
		name  string
		file  []byte
		want  []openpgp.KeyringEntry
		words []string
	}{
		{"the two in the other order", cat(b, a), v.want, []string{"out of order", "certificate 1 (label A)", "position 2 (label B)"}},
		{"a primary that is not on the list in the second place", cat(a, z), v.want, []string{"not on the list", "certificate 2 (label B)"}},
		{"a primary that is not on the list in the first place", cat(z, b), v.want, []string{"not on the list", "certificate 1 (label A)"}},
		{"one certificate for two entries", a, v.want, []string{"missing", "1 of 2", "label B"}},
		{"no entry for the third certificate", cat(a, b, z), v.want, []string{"one too many", "3 certificates", "2 entries"}},
		{"the same certificate twice", cat(a, a), v.want, []string{"repeats", "certificate 2 (label B)", "holds the key of certificate 1"}},
		{"a certificate for an entry that gives its key to another", a, []openpgp.KeyringEntry{{Label: "A", Fingerprint: fpB.Fingerprint}}, []string{"not on the list"}},
		{"a certificate for an entry that no key gives", a, []openpgp.KeyringEntry{{Label: "A", Fingerprint: fmt.Sprintf("%040x", 7)}}, []string{"not on the list"}},
		{"the user ID of one label for the entry of another", a, []openpgp.KeyringEntry{{Label: "B", Fingerprint: fpA.Fingerprint}}, []string{"user ID names the label A", "certificate 1 (label B)"}},
		{"the second user ID names the label of the first", cat(a, b), []openpgp.KeyringEntry{fpA, {Label: "C", Fingerprint: fpB.Fingerprint}}, []string{"user ID names the label B", "label C"}},
		{"a good certificate and the second key twice in a file of three", cat(a, b, b), []openpgp.KeyringEntry{fpA, fpB, {Label: "C", Fingerprint: fmt.Sprintf("%040x", 3)}}, []string{"repeats", "certificate 3", "holds the key of certificate 2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertKeyringRefused(t, c.name, c.file, c.want, openpgp.ErrKeyringPrimaries, c.words...)
		})
	}
	// The negative control of the order: each certificate alone for its own entry is accepted.
	assertRead(t, "a for A", a, v.want[:1])
	assertRead(t, "b for B", b, v.want[1:])
	// A key that is not the entry's gives no primary even when its user ID is the entry's.
	other := newKeyringPrimary(t, "A", true)
	assertKeyringRefused(t, "a good certificate of another key", other.good(t), wantOf(m), openpgp.ErrKeyringPrimaries, "not on the list")
}

// Two certificates of one key made at two moments one second apart have two fingerprints and one point.
func TestTwoCertificatesOfOneKeyPointAndTwoFingerprintsAreRefusedAsARepeat(t *testing.T) {
	k := genKey(t)
	m1 := keyringPrimaryOf(t, k, "A", true, created, "release@example.org")
	m2 := keyringPrimaryOf(t, k, "B", true, created.Add(time.Second), "release@example.org")
	if m1.fp == m2.fp {
		t.Fatal("one second apart gives one fingerprint")
	}
	assertKeyringRefused(t, "one point", cat(m1.good(t), m2.good(t)), wantOf(m1, m2), openpgp.ErrKeyringPrimaries, "repeats", "holds the key point of certificate 1", "certificate 2 (label B)")
}

func TestAMixOfTestAndRealPrimariesIsRefusedAndTwoOfOneKindAreNot(t *testing.T) {
	for _, order := range [][]bool{{true, false}, {false, true}, {true, true, false}, {false, true, true}, {true, false, true}} {
		var ms []keyringPrimary
		var file []byte
		for i, test := range order {
			m := newKeyringPrimary(t, string(rune('A'+i)), test)
			ms = append(ms, m)
			file = append(file, m.good(t)...)
		}
		assertKeyringRefused(t, fmt.Sprintf("a mix %v", order), file, wantOf(ms...), openpgp.ErrKeyringForm, "mixes test and real primaries")
	}
	// The mix is refused after each certificate was read: a certificate that is not good is the first fault.
	test, real := newKeyringPrimary(t, "A", true), newKeyringPrimary(t, "B", false)
	broken := real.assemble(real.sig(t, ceremony, func(sp *sigSpec) { sp.Type = 0x10 }))
	assertKeyringRefused(t, "a mix with a bad certification", cat(test.good(t), broken), wantOf(test, real), openpgp.ErrKeyringForm, "certification 1")
}

func TestAUserIDThatIsNotTheOneShapeOfThePageIsRefusedAndShownOnlyAsAnEscape(t *testing.T) {
	m := newKeyringPrimary(t, "A", true)
	long := func(n int) string {
		base := "Example Test Release Root A (TEST ONLY) <" // the address follows
		return base + strings.Repeat("a", n-len(base)-len("@example.org>")) + "@example.org>"
	}
	cases := []struct {
		name  string
		uid   string
		words []string
	}{
		{"a control character", m.uid + "\x1b[31m", []string{"U+001B"}},
		{"a line break", "Example Test Release Root A (TEST ONLY) <a@example.org>\n", []string{"U+000A"}},
		{"a line break in the name", "Example\nTest Release Root A (TEST ONLY) <a@example.org>", []string{"U+000A"}},
		{"a bidirectional override", "Example Test Release Root A (TEST ONLY) <a@example.org>\u202e", []string{"U+202E"}},
		{"a zero-width space", "Example\u200bTest Release Root A (TEST ONLY) <a@example.org>", []string{"U+200B"}},
		{"a NUL", "Example Test Release Root A (TEST ONLY) <a@example.org>\x00", []string{"U+0000"}},
		{"bytes that are not UTF-8", "Example Test Release Root A (TEST ONLY) <a@example.org>\xff\xfe", []string{"not UTF-8"}},
		{"1,025 bytes", long(1025), []string{"1024"}},
		{"not the shape of the page", "Example Person <person@example.org>", nil},
		{"the name of a person with a comment", "Example Person (comment) <person@example.org>", nil},
		{"no address", "Example Test Release Root A (TEST ONLY)", nil},
		{"two addresses", m.uid + " <b@example.org>", nil},
		{"a label of two letters", "Example Test Release Root AB (TEST ONLY) <a@example.org>", nil},
		{"a lower-case label", "Example Test Release Root a (TEST ONLY) <a@example.org>", nil},
		{"an empty user ID", "", nil},
		{"a space at the end", m.uid + " ", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bad := m.withUserID(c.uid)
			file := bad.good(t)
			if c.uid == "" {
				// An empty user ID packet is whole: the packet is one with no body.
				file = cat(m.keyPacket(), []byte{0xCD, 0x00}, m.sig(t, ceremony, nil))
			}
			assertKeyringRefused(t, c.name, file, wantOf(m), openpgp.ErrKeyringForm, append([]string{"certificate 1 (label A)", "user ID"}, c.words...)...)
		})
	}
	// A user ID that carries a marker text never shows the marker in the error.
	marker := "Example Test Release Root A (TEST ONLY) <a@example.org> SECRETMARKER\x1b"
	bad := m.withUserID(marker)
	_, err := readSafely(t, "marker", bad.good(t), wantOf(m))
	if err == nil || strings.Contains(err.Error(), "SECRETMARKER") {
		t.Errorf("error = %v, want one that does not show the text of the user ID", err)
	}
}

func TestAUserIDOfExactly1024BytesIsReadAndOneMoreByteIsRefused(t *testing.T) {
	base := len("Example Test Release Root A (TEST ONLY) <@example.org>")
	m := keyringPrimaryOf(t, genKey(t), "A", true, created, strings.Repeat("a", openpgp.MaxUserIDBytes-base)+"@example.org")
	if len(m.uid) != openpgp.MaxUserIDBytes {
		t.Fatalf("the user ID has %d bytes, want %d", len(m.uid), openpgp.MaxUserIDBytes)
	}
	assertRead(t, "1024 bytes", m.good(t), wantOf(m), m)
	// UserID writes no more than 1024 bytes, so the user ID of 1025 bytes is written by hand.
	over := m.withUserID(strings.Replace(m.uid, "@", "a@", 1))
	assertKeyringRefused(t, "1025 bytes", over.good(t), wantOf(over), openpgp.ErrKeyringForm, "1024")
}

// The order in which the reader checks, which a test shows by a file that has two faults.

func TestTheReaderChecksInTheOrderOfThePageAndTheFirstFaultGivesTheError(t *testing.T) {
	v := loadVectorKeyring(t)
	m := newKeyringPrimary(t, "A", true)
	bad := m.withUserID
	badCert := func(sp *sigSpec) { sp.Type = 0x10 }
	plain := cat(v.a, v.b)
	cases := []struct {
		name  string
		file  []byte
		want  []openpgp.KeyringEntry
		kind  error
		words string
	}{
		{"the size comes before the armour line", append([]byte("-----BEGIN"), make([]byte, openpgp.MaxKeyringBytes)...), v.want, openpgp.ErrKeyringForm, "longer than"},
		{"the armour line comes before the walk", []byte("-----BEGIN \xff"), v.want, openpgp.ErrKeyringForm, "armoured"},
		{"a fault of the walk comes before a missing certificate", cat(v.a, []byte{0x00}), v.want, openpgp.ErrKeyringForm, "packet 4"},
		{"a fault of the walk comes before one too many", cat(v.a, v.b, v.z, []byte{0x00}), v.want, openpgp.ErrKeyringForm, "packet 10"},
		{"a missing certificate comes before a bad key", cat(wrap(tagPublicKey, []byte{5, 0, 0, 0, 1}), m.uidPacket(), m.sig(t, ceremony, nil)), wantOf(m, newKeyringPrimary(t, "B", true)), openpgp.ErrKeyringPrimaries, "missing"},
		{"one too many comes before a bad key", cat(m.good(t), wrap(tagPublicKey, []byte{5, 0, 0, 0, 1}), m.uidPacket(), m.sig(t, ceremony, nil)), wantOf(m), openpgp.ErrKeyringPrimaries, "one too many"},
		{"a bad key comes before a fingerprint that is not on the list", cat(wrap(tagPublicKey, []byte{5, 0, 0, 0, 1}), m.uidPacket(), m.sig(t, ceremony, nil)), wantOf(m), openpgp.ErrKeyringForm, "key packet"},
		{"a fingerprint that is not on the list comes before a bad user ID", bad("junk").good(t), wantOf(newKeyringPrimary(t, "A", true)), openpgp.ErrKeyringPrimaries, "not on the list"},
		{"a bad user ID comes before a label that is not the entry's", bad("junk").good(t), []openpgp.KeyringEntry{{Label: "B", Fingerprint: m.fp}}, openpgp.ErrKeyringForm, "user ID"},
		{"a label that is not the entry's comes before a bad certification", m.assemble(m.sig(t, ceremony, badCert)), []openpgp.KeyringEntry{{Label: "B", Fingerprint: m.fp}}, openpgp.ErrKeyringPrimaries, "label A"},
		{"a repeat comes before the list is looked at", cat(plain[:len(v.a)], v.a), []openpgp.KeyringEntry{v.want[0], {Label: "B", Fingerprint: fmt.Sprintf("%040x", 9)}}, openpgp.ErrKeyringPrimaries, "repeats"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assertKeyringRefused(t, c.name, c.file, c.want, c.kind, c.words)
		})
	}
}
