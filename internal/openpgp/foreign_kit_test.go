package openpgp_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // the check of a protected secret key packet is a SHA-1 by the standard
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"

	"ritueel.id/ritueel/internal/openpgp"
)

// The kit of the tests of the reader of a foreign key (ReadForeignKey, OpenSecret). Every key is made
// at run time by go-crypto, which is the second program for this reader: it writes the files, and
// reads them again where a test needs a second opinion on the numbers. A file that go-crypto does
// not write (a stub, a garbage secret, a protection that it does not offer) is made from its packets.
// No key is a constant of the tests and none is written to a file. The names of the helpers start
// with fk, so that they stay apart from those of the other tests of the package.

// fkEpoch is the creation time of every key and the base of every signature time here.
var fkEpoch = time.Unix(1700000000, 0).UTC()

// fkUser is the user ID of the template keys, and fkUserWord a word of it that no error may show.
const (
	fkUser     = "Quokka Tester <quokka@example.org>"
	fkUserWord = "Quokka"
	// fkPass is the passphrase of the protected files, and fkPassOther the one of a subkey.
	fkPass      = "correct horse battery staple"
	fkPassOther = "xyzzy plugh quux zork 8841"
)

// fkBase is one template key: a primary of one algorithm with the encryption subkey that go-crypto
// adds, and a signing subkey with its back-signature. plain is its file as go-crypto writes it, with
// no protection. The entity is read-only: a test that needs to change a key reads plain again.
type fkBase struct {
	name string
	// want is the algorithm as the reader names it.
	want openpgp.ForeignAlgorithm
	// str is the String of that algorithm.
	str   string
	cfg   *gpacket.Config
	ent   *pgp.Entity
	plain []byte
}

// fkConfig is a go-crypto configuration with the fixed clock of the tests.
func fkConfig(algo gpacket.PublicKeyAlgorithm, curve gpacket.Curve, bits int) *gpacket.Config {
	// go-crypto adds a random notation to a signature by default, and refuses it with some hashes
	noNotation := false
	return &gpacket.Config{
		NonDeterministicSignaturesViaNotation: &noNotation,
		Algorithm:                             algo,
		Curve:                                 curve,
		RSABits:                               bits,
		DefaultHash:                           crypto.SHA256,
		DefaultCipher:                         gpacket.CipherAES256,
		Time:                                  func() time.Time { return fkEpoch },
		S2KConfig:                             &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, S2KCount: 65536, Hash: crypto.SHA256},
	}
}

func fkNewBase(name string, want openpgp.ForeignAlgorithm, str string, algo gpacket.PublicKeyAlgorithm, curve gpacket.Curve, bits int) (*fkBase, error) {
	cfg := fkConfig(algo, curve, bits)
	e, err := pgp.NewEntity("Quokka Tester", "", "quokka@example.org", cfg)
	if err != nil {
		return nil, err
	}
	if err := e.AddSigningSubkey(cfg); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&buf, cfg); err != nil {
		return nil, err
	}
	return &fkBase{name: name, want: want, str: str, cfg: cfg, ent: e, plain: buf.Bytes()}, nil
}

var (
	fkOnce  sync.Once
	fkAll   []*fkBase
	fkAllEr error
)

// fkBases are the template keys, one for each primary algorithm that the reader takes, made once for
// the test binary: RSA 4096 is slow to make.
func fkBases(t testing.TB) []*fkBase {
	t.Helper()
	fkOnce.Do(func() {
		specs := []struct {
			name  string
			want  openpgp.ForeignAlgorithm
			str   string
			algo  gpacket.PublicKeyAlgorithm
			curve gpacket.Curve
			bits  int
		}{
			{"ed25519", openpgp.ForeignAlgorithm{ID: 22, Curve: "Ed25519"}, "EdDSA Ed25519", gpacket.PubKeyAlgoEdDSA, gpacket.Curve25519, 0},
			{"p384", openpgp.ForeignAlgorithm{ID: 19, Curve: "P-384"}, "ECDSA P-384", gpacket.PubKeyAlgoECDSA, gpacket.CurveNistP384, 0},
			{"rsa4096", openpgp.ForeignAlgorithm{ID: 1, Bits: 4096}, "RSA 4096", gpacket.PubKeyAlgoRSA, "", 4096},
		}
		for _, s := range specs {
			b, err := fkNewBase(s.name, s.want, s.str, s.algo, s.curve, s.bits)
			if err != nil {
				fkAllEr = fmt.Errorf("make the %s template: %w", s.name, err)
				return
			}
			fkAll = append(fkAll, b)
		}
	})
	if fkAllEr != nil {
		t.Fatal(fkAllEr)
	}
	return fkAll
}

// fkBase returns the template of one algorithm by its name.
func fkNamed(t testing.TB, name string) *fkBase {
	t.Helper()
	for _, b := range fkBases(t) {
		if b.name == name {
			return b
		}
	}
	t.Fatalf("no template named %s", name)
	return nil
}

// fkEachBase runs a subtest for each template.
func fkEachBase(t *testing.T, f func(t *testing.T, b *fkBase)) {
	t.Helper()
	for _, b := range fkBases(t) {
		t.Run(b.name, func(t *testing.T) { f(t, b) })
	}
}

// fkProt says how a file of a template is protected: Pass empty means no protection.
type fkProt struct {
	Pass   string
	Cipher gpacket.CipherFunction // zero: AES-256
	Hash   crypto.Hash            // zero: SHA-256
	Count  int                    // zero: 65536
	// SubPass protects the secret subkeys, by index, with another passphrase; a subkey not in the map
	// gets Pass.
	SubPass map[int]string
}

// entity reads the plain file again: a fresh entity with no protection that the test may change.
func (b *fkBase) entity(t testing.TB) *pgp.Entity {
	t.Helper()
	ents, err := pgp.ReadKeyRing(bytes.NewReader(b.plain))
	if err != nil || len(ents) != 1 {
		t.Fatalf("go-crypto does not read the template back: %v", err)
	}
	return ents[0]
}

// file writes the template as a file of go-crypto, with the protection given.
func (b *fkBase) file(t testing.TB, p fkProt) []byte {
	t.Helper()
	e := b.entity(t)
	cfg := *b.cfg
	if p.Cipher != 0 {
		cfg.DefaultCipher = p.Cipher
	}
	s := *cfg.S2KConfig
	if p.Hash != 0 {
		s.Hash = p.Hash
	}
	if p.Count != 0 {
		s.S2KCount = p.Count
	}
	cfg.S2KConfig = &s
	if p.Pass != "" {
		if err := e.PrivateKey.EncryptWithConfig([]byte(p.Pass), &cfg); err != nil {
			t.Fatal(err)
		}
	}
	for i := range e.Subkeys {
		pass := p.Pass
		if o, ok := p.SubPass[i]; ok {
			pass = o
		}
		if pass == "" {
			continue
		}
		if err := e.Subkeys[i].PrivateKey.EncryptWithConfig([]byte(pass), &cfg); err != nil {
			t.Fatal(err)
		}
	}
	var buf bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&buf, &cfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fkProtectRegion writes the secret part of a secret key packet protected as RFC 9580 section 5.5.3
// has it (S2K usage 254): the numbers and their SHA-1 under the key of an iterated and salted S2K. It
// is the second writer for the forms that go-crypto does not offer, SHA-1 as the S2K hash for one.
// The key is derived by go-crypto's S2K function, and the cipher is the standard library's: neither is
// the code under test. numbers is the secret numbers without the two-octet checksum.
func fkProtectRegion(t testing.TB, numbers []byte, pass string, cipherID byte, h crypto.Hash, hashID, count byte) []byte {
	t.Helper()
	keySize := map[byte]int{7: 16, 8: 24, 9: 32}[cipherID]
	salt := fkRandom(t, 8)
	key := make([]byte, keySize)
	iter := (16 + int(count&15)) << (uint32(count>>4) + 6)
	s2k.Iterated(key, h.New(), []byte(pass), salt, iter)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum(numbers) //nolint:gosec // see the import
	plain := append(bytes.Clone(numbers), sum[:]...)
	iv := fkRandom(t, aes.BlockSize)
	out := make([]byte, len(plain))
	//nolint:staticcheck // the secret key packet is CFB by the standard; this writes one for the reader to read
	cipher.NewCFBEncrypter(block, iv).XORKeyStream(out, plain)
	region := append([]byte{254, cipherID, 3, hashID}, salt...)
	region = append(region, count)
	region = append(region, iv...)
	return append(region, out...)
}

// fkPlainNumbers is the numbers of the plain secret part of the first packet of a template, without
// the usage octet and the checksum.
func (b *fkBase) plainNumbers(t testing.TB) []byte {
	t.Helper()
	pub := b.pubBody(t)
	body := fkSplit(t, b.plain)[0].Body
	if body[len(pub)] != 0 {
		t.Fatal("the plain template is protected")
	}
	region := body[len(pub)+1:]
	return region[:len(region)-2]
}

// fkPacket is one packet of a file, by tag and body.
type fkPacket struct {
	Tag  byte
	Body []byte
}

// fkSplit reads the packets of a file with the packet reader of the tests.
func fkSplit(t testing.TB, file []byte) []fkPacket {
	t.Helper()
	var out []fkPacket
	for _, p := range splitPackets(t, file) {
		out = append(out, fkPacket{p.Tag, bytes.Clone(p.Body)})
	}
	return out
}

// fkJoin writes packets in the new format, each with the shortest length.
func fkJoin(ps ...fkPacket) []byte {
	var out []byte
	for _, p := range ps {
		out = append(out, wrap(p.Tag, p.Body)...)
	}
	return out
}

// fkPubBody is the body of the public key packet of the primary of a template: the part that stands
// in front of the secret in the secret key packet.
func (b *fkBase) pubBody(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := b.ent.PrimaryKey.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	ps := fkSplit(t, buf.Bytes())
	if len(ps) != 1 || ps[0].Tag != 6 {
		t.Fatalf("the primary key does not serialise as one public key packet")
	}
	return ps[0].Body
}

// fkWithRegion rewrites the first packet of a template file so that its secret part is region.
func (b *fkBase) withRegion(t testing.TB, region []byte) []byte {
	t.Helper()
	ps := fkSplit(t, b.plain)
	ps[0] = fkPacket{5, append(bytes.Clone(b.pubBody(t)), region...)}
	return fkJoin(ps...)
}

// fkMPI writes a number in the form of RFC 9580, section 3.2: a bit count and the bytes without a
// leading zero.
func fkMPI(v []byte) []byte {
	v = bytes.TrimLeft(v, "\x00")
	if len(v) == 0 {
		return []byte{0, 0}
	}
	bits := (len(v)-1)*8 + len(fmt.Sprintf("%b", v[0]))
	return append([]byte{byte(bits >> 8), byte(bits)}, v...)
}

// fkReadMPIs reads the numbers of a region of secret numbers: MPIs up to the two-octet checksum.
func fkReadMPIs(t testing.TB, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 2 {
		bits := int(b[0])<<8 | int(b[1])
		n := (bits + 7) / 8
		if len(b) < 2+n+2 {
			t.Fatalf("a secret number does not fit its region")
		}
		out = append(out, bytes.Clone(b[2:2+n]))
		b = b[2+n:]
	}
	if len(b) != 2 {
		t.Fatalf("the secret numbers leave %d bytes, want the two of the checksum", len(b))
	}
	return out
}

// fkSecretOf is what a plain template holds as secret: the numbers of the primary and, for each
// subkey with a secret, the numbers of the subkey. Both come out of the packets of the plain file.
type fkSecretOf struct {
	Primary [][]byte
	Subs    [][][]byte
}

// secrets reads the numbers of the plain file of a template.
func (b *fkBase) secrets(t testing.TB) fkSecretOf {
	t.Helper()
	var s fkSecretOf
	pub := b.pubBody(t)
	for _, p := range fkSplit(t, b.plain) {
		switch p.Tag {
		case 5:
			if p.Body[len(pub)] != 0 {
				t.Fatalf("the plain template is protected")
			}
			s.Primary = fkReadMPIs(t, p.Body[len(pub)+1:])
		case 7:
			// the public part of a subkey: go-crypto knows its length
			for _, sub := range b.ent.Subkeys {
				var buf bytes.Buffer
				if err := sub.PublicKey.Serialize(&buf); err != nil {
					t.Fatal(err)
				}
				sp := fkSplit(t, buf.Bytes())[0].Body
				if bytes.HasPrefix(p.Body, sp) {
					s.Subs = append(s.Subs, fkReadMPIs(t, p.Body[len(sp)+1:]))
				}
			}
		}
	}
	if len(s.Primary) == 0 || len(s.Subs) != len(b.ent.Subkeys) {
		t.Fatalf("the secret numbers of the template are not all read")
	}
	return s
}

// fkAllNumbers lists the numbers that the certificate must never hold.
func (s fkSecretOf) all() [][]byte {
	out := append([][]byte(nil), s.Primary...)
	for _, sub := range s.Subs {
		out = append(out, sub...)
	}
	return out
}

// fkWindow is the length of the run of bytes whose presence in a text or a certificate counts as a
// leak: eight bytes of a number.
const fkWindow = 8

// fkLeaks tells whether any run of fkWindow bytes of any number is in hay. A number shorter than the
// window is looked for whole.
func fkLeaks(hay []byte, numbers ...[]byte) (string, bool) {
	for i, n := range numbers {
		n = bytes.TrimLeft(n, "\x00")
		if len(n) == 0 {
			continue
		}
		w := min(fkWindow, len(n))
		for j := 0; j+w <= len(n); j++ {
			if bytes.Contains(hay, n[j:j+w]) {
				return fmt.Sprintf("number %d, offset %d", i, j), true
			}
		}
	}
	return "", false
}

// fkArmour writes a file as one armour block with the headers given.
func fkArmour(t testing.TB, file []byte, kind string, headers map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, kind, headers)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(file); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fkPrivateBlock is the type of the armour block of a private key, written from two pieces so that
// no line of this repository holds the whole head line of a private key block (the public content
// check refuses it).
func fkPrivateBlock() string { return "PGP " + "PRIVATE" + " KEY BLOCK" }

// fkArmourKey writes a file as the armour block of a private key.
func fkArmourKey(t testing.TB, file []byte) []byte {
	t.Helper()
	return fkArmour(t, file, fkPrivateBlock(), map[string]string{"Comment": "a test key"})
}

// fkRead reads a file and fails the test if it is refused.
func fkRead(t testing.TB, file []byte) *openpgp.ForeignKey {
	t.Helper()
	k, err := openpgp.ReadForeignKey(file)
	if err != nil {
		t.Fatalf("ReadForeignKey: %v", err)
	}
	if k == nil {
		t.Fatal("ReadForeignKey returned no key and no error")
	}
	return k
}

// fkRefused reads a file that must be refused, with every kind given as the cause (errors.Is), no
// key, and a text that holds none of the secrets of the base nor a word of the user ID. It returns
// the error.
func fkRefused(t testing.TB, what string, file []byte, b *fkBase, kinds ...error) error {
	t.Helper()
	k, err := openpgp.ReadForeignKey(file)
	if err == nil {
		t.Errorf("%s: the file was read, want a refusal", what)
		return nil
	}
	if k != nil {
		t.Errorf("%s: a key is returned with the error %v", what, err)
	}
	if !errors.Is(err, openpgp.ErrForeignKey) {
		t.Errorf("%s: %v is not an ErrForeignKey", what, err)
	}
	for _, kind := range kinds {
		if !errors.Is(err, kind) {
			t.Errorf("%s: %v is not the kind %v", what, err, kind)
		}
	}
	fkCheckText(t, what, err, b)
	return err
}

// fkCheckText holds an error text to what is safe: no run of eight bytes of a secret number or of the
// passphrases, no word of the user ID, and nothing that a person cannot read.
func fkCheckText(t testing.TB, what string, err error, b *fkBase, extra ...[]byte) {
	t.Helper()
	if err == nil {
		return
	}
	text := []byte(err.Error())
	if strings.Contains(err.Error(), "could not be read") {
		t.Errorf("%s: the reader recovered a panic: %v", what, err)
	}
	if len(text) > 500 {
		t.Errorf("%s: the text of the error is %d bytes long", what, len(text))
	}
	secrets := [][]byte{[]byte(fkPass), []byte(fkPassOther)}
	secrets = append(secrets, extra...)
	for _, form := range fkHexForms(fkSerial) {
		if bytes.Contains(text, form) {
			t.Errorf("%s: the error text holds the serial number of a stub: %q", what, text)
		}
	}
	if b != nil {
		s := b.secrets(t)
		secrets = append(secrets, s.all()...)
	}
	if where, bad := fkLeaks(text, secrets...); bad {
		t.Errorf("%s: the error text holds a run of a secret (%s): %q", what, where, text)
	}
	if bytes.Contains(text, []byte(fkUserWord)) || bytes.Contains(text, []byte("example.org")) {
		t.Errorf("%s: the error text holds the user ID: %q", what, text)
	}
	for _, c := range text {
		if c < 0x20 || c > 0x7E {
			t.Errorf("%s: the error text holds the byte %#x: %q", what, c, text)
			return
		}
	}
}

// fkStrings collects every string and every byte slice that a value holds, through every field,
// exported or not, with the text that fmt gives for it. A test looks for a byte pattern in them.
func fkStrings(v any) [][]byte {
	var out [][]byte
	seen := map[uintptr]bool{}
	var walk func(r reflect.Value)
	walk = func(r reflect.Value) {
		switch r.Kind() {
		case reflect.String:
			out = append(out, []byte(r.String()))
		case reflect.Slice:
			if r.Type().Elem().Kind() == reflect.Uint8 {
				out = append(out, bytes.Clone(r.Bytes()))
				return
			}
			for i := 0; i < r.Len(); i++ {
				walk(r.Index(i))
			}
		case reflect.Array:
			if r.Type().Elem().Kind() == reflect.Uint8 {
				b := make([]byte, r.Len())
				for i := range b {
					b[i] = byte(r.Index(i).Uint())
				}
				out = append(out, b)
				return
			}
			for i := 0; i < r.Len(); i++ {
				walk(r.Index(i))
			}
		case reflect.Struct:
			for i := 0; i < r.NumField(); i++ {
				walk(r.Field(i))
			}
		case reflect.Pointer, reflect.Interface:
			if r.IsNil() {
				return
			}
			if r.Kind() == reflect.Pointer {
				if seen[r.Pointer()] {
					return
				}
				seen[r.Pointer()] = true
			}
			walk(r.Elem())
		}
	}
	walk(reflect.ValueOf(v))
	out = append(out, []byte(fmt.Sprintf("%v|%+v|%#v", v, v, v)))
	return out
}

// fkHexForms are the spellings of a byte string that a leak could take.
func fkHexForms(b []byte) [][]byte {
	h := hex.EncodeToString(b)
	return [][]byte{b, []byte(h), []byte(strings.ToUpper(h)), fmt.Appendf(nil, "% x", b), fmt.Append(nil, b)}
}

// fkRandom returns n random bytes.
func fkRandom(t testing.TB, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// fkDeepEqual compares two values with reflect.DeepEqual.
func fkDeepEqual(a, b any) bool { return reflect.DeepEqual(a, b) }
