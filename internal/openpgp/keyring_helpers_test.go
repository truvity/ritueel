package openpgp_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"

	"ritueel.id/ritueel/internal/openpgp"
	"ritueel.id/ritueel/internal/testrepo"
)

// keyringPrimary is one primary of a keyring file, made in memory: its key, the moment it was created, its
// label and its user ID. The packets of its certificate are written by hand (the tests' own
// writers) or by NewPrimary and ExtendPrimary, as a test needs.
type keyringPrimary struct {
	key   *ecdsa.PrivateKey
	at    time.Time
	label string
	test  bool
	uid   string
	fp    string
}

func newKeyringPrimary(t testing.TB, label string, test bool) keyringPrimary {
	t.Helper()
	return keyringPrimaryOf(t, genKey(t), label, test, created, "release@example.org")
}

// keyringPrimaryOf makes the primary of a key, a creation time and an address.
func keyringPrimaryOf(t testing.TB, key *ecdsa.PrivateKey, label string, test bool, at time.Time, address string) keyringPrimary {
	t.Helper()
	uid, err := openpgp.UserID("Example Test", label, address, test)
	if err != nil {
		t.Fatalf("UserID: %v", err)
	}
	return keyringPrimary{key: key, at: at, label: label, test: test, uid: uid, fp: fingerprintOf(t, &key.PublicKey, at)}
}

// withUserID is the primary with another user ID text, which need not be one that UserID writes.
func (m keyringPrimary) withUserID(uid string) keyringPrimary {
	m.uid = uid
	return m
}

func (m keyringPrimary) keyPacket() []byte {
	return wrap(tagPublicKey, keyBody(&m.key.PublicKey, m.at))
}
func (m keyringPrimary) uidPacket() []byte { return wrap(tagUserID, []byte(m.uid)) }

func (m keyringPrimary) entry() openpgp.KeyringEntry {
	return openpgp.KeyringEntry{Label: m.label, Fingerprint: m.fp}
}

func (m keyringPrimary) params(at time.Time) openpgp.PrimaryParams {
	return openpgp.PrimaryParams{Key: m.key, CreationTime: m.at, CeremonyTime: at, ExpiresAt: at.AddDate(3, 0, 0), UserID: m.uid}
}

// cert is the certificate that NewPrimary writes for the primary, at the ceremony time of the tests.
func (m keyringPrimary) cert(t testing.TB) []byte {
	t.Helper()
	c, err := openpgp.NewPrimary(rand.Reader, m.params(ceremony))
	if err != nil {
		t.Fatalf("NewPrimary: %v", err)
	}
	return c
}

// extension is the signature packet that ExtendPrimary writes for the primary at a moment.
func (m keyringPrimary) extension(t testing.TB, at time.Time) []byte {
	t.Helper()
	s, err := openpgp.ExtendPrimary(rand.Reader, m.params(at))
	if err != nil {
		t.Fatalf("ExtendPrimary: %v", err)
	}
	return s
}

// life is the key expiration time of a certification made at a moment: 36 calendar months later.
func (m keyringPrimary) life(at time.Time) uint32 {
	return uint32(at.AddDate(3, 0, 0).Unix() - m.at.Unix())
}

// spec is the self-certification that the page gives, made at a moment, ready to be changed.
func (m keyringPrimary) spec(at time.Time) sigSpec {
	fp, err := hex.DecodeString(m.fp)
	if err != nil {
		panic(err)
	}
	return sigSpec{
		Type: 0x13,
		Hashed: []sub{
			{Type: 2, Data: u32(uint32(at.Unix()))},
			{Type: 27, Data: []byte{0x01}},
			{Type: 9, Critical: true, Data: u32(m.life(at))},
			{Type: 33, Data: append([]byte{4}, fp...)},
		},
		Unhashed: []sub{{Type: 16, Data: fp[12:]}},
		Data:     selfSigData(&m.key.PublicKey, m.at, m.uid),
		Key:      m.key,
	}
}

// sig is the packet of the self-certification of the primary at a moment, after tweak changed its spec.
func (m keyringPrimary) sig(t testing.TB, at time.Time, tweak func(*sigSpec)) []byte {
	t.Helper()
	sp := m.spec(at)
	if tweak != nil {
		tweak(&sp)
	}
	return sp.build(t)
}

// assemble is the key packet, the user ID packet and the given signature packets.
func (m keyringPrimary) assemble(sigs ...[]byte) []byte {
	return cat(append([][]byte{m.keyPacket(), m.uidPacket()}, sigs...)...)
}

// good is the certificate of the primary written by the tests' own writers: one certification at the
// ceremony time.
func (m keyringPrimary) good(t testing.TB) []byte {
	t.Helper()
	return m.assemble(m.sig(t, ceremony, nil))
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func wantOf(ms ...keyringPrimary) []openpgp.KeyringEntry {
	out := make([]openpgp.KeyringEntry, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.entry())
	}
	return out
}

// readSafely calls ReadKeyring and turns a panic into a failure of the test that names it.
func readSafely(t testing.TB, what string, file []byte, want []openpgp.KeyringEntry) (keys []*openpgp.PrimaryKey, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: ReadKeyring panicked: %v", what, r)
			keys, err = nil, errors.New("panic")
		}
	}()
	return openpgp.ReadKeyring(file, want)
}

// ringFingerprints reads a file with go-crypto, which did not write it, and returns the fingerprints
// of its primaries in file order.
func ringFingerprints(t testing.TB, file []byte) []string {
	t.Helper()
	ring, err := pgp.ReadKeyRing(bytes.NewReader(file))
	if err != nil {
		t.Fatalf("go-crypto ReadKeyRing: %v", err)
	}
	var out []string
	for _, e := range ring {
		out = append(out, hex.EncodeToString(e.PrimaryKey.Fingerprint))
	}
	return out
}

// assertRead reads a file that must be accepted. It checks the primaries against want (the
// fingerprint, the creation time and, when primaries are given, the key), that the arguments are as
// they were, and that go-crypto reads the same fingerprints in the same order.
func assertRead(t testing.TB, what string, file []byte, want []openpgp.KeyringEntry, primaries ...keyringPrimary) []*openpgp.PrimaryKey {
	t.Helper()
	fileBefore, wantBefore := bytes.Clone(file), slices.Clone(want)
	keys, err := readSafely(t, what, file, want)
	if err != nil {
		t.Fatalf("%s: error = %v, want none", what, err)
	}
	if !bytes.Equal(file, fileBefore) || !slices.Equal(want, wantBefore) {
		t.Errorf("%s: ReadKeyring changed its arguments", what)
	}
	if len(keys) != len(want) {
		t.Fatalf("%s: %d primaries, want %d", what, len(keys), len(want))
	}
	var fps []string
	for i, k := range keys {
		if k == nil {
			t.Fatalf("%s: primary %d is nil", what, i)
		}
		if k.Fingerprint() != want[i].Fingerprint {
			t.Errorf("%s: primary %d has the fingerprint %s, want %s", what, i, k.Fingerprint(), want[i].Fingerprint)
		}
		fps = append(fps, k.Fingerprint())
	}
	for i, m := range primaries {
		if !keys[i].PublicKey().Equal(&m.key.PublicKey) {
			t.Errorf("%s: primary %d is not the key of its own", what, i)
		}
		if !keys[i].Created().Equal(m.at) {
			t.Errorf("%s: primary %d was created at %v, want %v", what, i, keys[i].Created(), m.at)
		}
	}
	if got := ringFingerprints(t, file); !slices.Equal(got, fps) {
		t.Errorf("%s: go-crypto reads the fingerprints %v, ReadKeyring %v", what, got, fps)
	}
	return keys
}

// checkText holds the text of a refusal of a file to what is safe to show: printable ASCII only, one
// short line. No byte of a file reaches it except as a code point written U+XXXX.
func checkText(t testing.TB, what string, err error) {
	t.Helper()
	text := err.Error()
	if len(text) > 400 {
		t.Errorf("%s: the text of the error is %d bytes long: %q", what, len(text), text)
	}
	for i := 0; i < len(text); i++ {
		if c := text[i]; c < 0x20 || c > 0x7E {
			t.Errorf("%s: the text of the error holds the byte %#x: %q", what, c, text)
			return
		}
	}
}

// assertKeyringRefused reads a file that must be refused with kind (ErrKeyringForm or
// ErrKeyringPrimaries, both also ErrKeyring), returns no primary, shows nothing of the file, and
// names every one of the words given.
func assertKeyringRefused(t testing.TB, what string, file []byte, want []openpgp.KeyringEntry, kind error, words ...string) {
	t.Helper()
	fileBefore, wantBefore := bytes.Clone(file), slices.Clone(want)
	keys, err := readSafely(t, what, file, want)
	if err == nil {
		t.Errorf("%s: no error, want one of kind %v", what, kind)
		return
	}
	if keys != nil {
		t.Errorf("%s: %d primaries with an error", what, len(keys))
	}
	if !errors.Is(err, kind) || !errors.Is(err, openpgp.ErrKeyring) {
		t.Errorf("%s: error = %v, want a %v that is also an ErrKeyring", what, err, kind)
	}
	other := openpgp.ErrKeyringPrimaries
	if errors.Is(kind, openpgp.ErrKeyringPrimaries) {
		other = openpgp.ErrKeyringForm
	}
	if errors.Is(err, other) || errors.Is(err, openpgp.ErrParams) {
		t.Errorf("%s: error = %v is also of the other kind", what, err)
	}
	if !bytes.Equal(file, fileBefore) || !slices.Equal(want, wantBefore) {
		t.Errorf("%s: ReadKeyring changed its arguments", what)
	}
	checkText(t, what, err)
	for _, w := range words {
		if !bytes.Contains([]byte(err.Error()), []byte(w)) {
			t.Errorf("%s: the text %q does not hold %q", what, err.Error(), w)
		}
	}
}

// The vector primaries and the root list that pins two of them.

type vectorKeyring struct {
	a, b, z []byte
	want    []openpgp.KeyringEntry // (A, fingerprint of a), (B, fingerprint of b)
	zPrint  string
}

func loadVectorKeyring(t testing.TB) vectorKeyring {
	t.Helper()
	v := vectorKeyring{a: vector(t, "pki", "test-primary-a.pgp"), b: vector(t, "pki", "test-primary-b.pgp"), z: vector(t, "pki", "test-primary-z.pgp")}
	var list struct {
		Roots []struct {
			Label       string `json:"label"`
			Fingerprint string `json:"openpgp_fingerprint"`
		} `json:"roots"`
	}
	if err := json.Unmarshal(testrepo.Read(t, "testdata", "root-list", "v1", "lists", "seq7-a.json"), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Roots) != 2 {
		t.Fatalf("the vector list has %d roots, want 2", len(list.Roots))
	}
	for _, r := range list.Roots {
		v.want = append(v.want, openpgp.KeyringEntry{Label: r.Label, Fingerprint: r.Fingerprint})
	}
	v.zPrint = ringFingerprints(t, v.z)[0]
	return v
}

// A header written in each form of RFC 9580, section 4.2.

// packetIn writes a packet with a header form: new1 (one octet), new2 (two octets), new5 (five
// octets), old1, old2 and old4 (the old format with a length of one, two and four octets). ok is
// false when the body does not fit the form.
func packetIn(form string, tag byte, body []byte) (pkt []byte, ok bool) {
	n := len(body)
	switch form {
	case "new1":
		if n >= 192 {
			return nil, false
		}
		return append([]byte{0xC0 | tag, byte(n)}, body...), true
	case "new2":
		if n < 192 || n >= 8384 {
			return nil, false
		}
		return append([]byte{0xC0 | tag, byte((n-192)>>8) + 192, byte(n - 192)}, body...), true
	case "new5":
		return wrapLong(tag, body), true
	case "old1":
		if n >= 256 {
			return nil, false
		}
		return append([]byte{0x80 | tag<<2, byte(n)}, body...), true
	case "old2":
		if n >= 65536 {
			return nil, false
		}
		return append([]byte{0x80 | tag<<2 | 1, byte(n >> 8), byte(n)}, body...), true
	case "old4":
		return append([]byte{0x80 | tag<<2 | 2, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, body...), true
	}
	panic("unknown header form " + form)
}

// repack writes the packets of a file again, each with the header form given; a packet that does not
// fit the form keeps its own header. It reports whether any packet changed.
func repack(t testing.TB, file []byte, form string) []byte {
	t.Helper()
	var out []byte
	for _, p := range splitPackets(t, file) {
		if pkt, ok := packetIn(form, p.Tag, p.Body); ok {
			out = append(out, pkt...)
		} else {
			out = append(out, p.Raw...)
		}
	}
	return out
}

// loadRingKey is the key of the first primary of a file, as go-crypto reads it.
func loadRingKey(t testing.TB, file []byte) *ecdsa.PublicKey {
	t.Helper()
	ring, err := pgp.ReadKeyRing(bytes.NewReader(file))
	if err != nil || len(ring) == 0 {
		t.Fatalf("go-crypto ReadKeyRing: %v", err)
	}
	pub, ok := ring[0].PrimaryKey.PublicKey.(*pgpecdsa.PublicKey)
	if !ok {
		t.Fatalf("go-crypto reads a key of type %T", ring[0].PrimaryKey.PublicKey)
	}
	pt := make([]byte, 97)
	pt[0] = 4
	pub.X.FillBytes(pt[1:49])
	pub.Y.FillBytes(pt[49:])
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P384(), pt)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// ecdsaSign is an ASN.1 signature of a digest by a key.
func ecdsaSign(k *ecdsa.PrivateKey, digest []byte) []byte {
	der, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		panic(err)
	}
	return der
}
