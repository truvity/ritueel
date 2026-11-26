package software

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	gpacket "github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"

	"ritueel.id/ritueel/internal/fsx"
	"ritueel.id/ritueel/internal/keystore"
	"ritueel.id/ritueel/internal/openpgp"
)

// The tests of the adopted key: SaveAdopted, OpenAdopted, CheckAdopted and AdoptedKey. Every key is
// made at run time by go-crypto, which writes the export that a person's OpenPGP program would, and
// no key is a constant of the tests.

// Passphrases of the tests: of the exported file, and of the key file (testPass is in agehelpers).
const (
	exportPass = "export pass"
	// a user ID that every test key has
	adoptedUserName = "Quokka Tester"
)

var adoptedEpoch = time.Unix(1700000000, 0).UTC()

// adoptedBase is the export of one algorithm, written once and plain.
type adoptedBase struct {
	name  string
	cfg   *gpacket.Config
	plain []byte
}

var (
	adoptedOnce sync.Once
	adoptedAll  []*adoptedBase
	adoptedErr  error
)

func adoptedBases(t testing.TB) []*adoptedBase {
	t.Helper()
	adoptedOnce.Do(func() {
		noNotation := false
		for _, s := range []struct {
			name  string
			algo  gpacket.PublicKeyAlgorithm
			curve gpacket.Curve
			bits  int
		}{
			{"ed25519", gpacket.PubKeyAlgoEdDSA, gpacket.Curve25519, 0},
			{"p384", gpacket.PubKeyAlgoECDSA, gpacket.CurveNistP384, 0},
			{"rsa4096", gpacket.PubKeyAlgoRSA, "", 4096},
		} {
			cfg := &gpacket.Config{
				NonDeterministicSignaturesViaNotation: &noNotation,
				Algorithm:                             s.algo, Curve: s.curve, RSABits: s.bits,
				DefaultHash: crypto.SHA256, DefaultCipher: gpacket.CipherAES256,
				Time:      func() time.Time { return adoptedEpoch },
				S2KConfig: &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, S2KCount: 65536, Hash: crypto.SHA256},
			}
			e, err := pgp.NewEntity(adoptedUserName, "", "quokka@example.org", cfg)
			if err != nil {
				adoptedErr = err
				return
			}
			var buf bytes.Buffer
			if err := e.SerializePrivateWithoutSigning(&buf, cfg); err != nil {
				adoptedErr = err
				return
			}
			adoptedAll = append(adoptedAll, &adoptedBase{name: s.name, cfg: cfg, plain: buf.Bytes()})
		}
	})
	if adoptedErr != nil {
		t.Fatal(adoptedErr)
	}
	return adoptedAll
}

func adoptedNamed(t testing.TB, name string) *adoptedBase {
	t.Helper()
	for _, b := range adoptedBases(t) {
		if b.name == name {
			return b
		}
	}
	t.Fatalf("no base named %s", name)
	return nil
}

// export writes the file of an export, protected with pass when it is not empty.
func (b *adoptedBase) export(t testing.TB, pass string) []byte {
	t.Helper()
	ents, err := pgp.ReadKeyRing(bytes.NewReader(b.plain))
	if err != nil || len(ents) != 1 {
		t.Fatalf("go-crypto does not read the base back: %v", err)
	}
	e := ents[0]
	if pass != "" {
		if err := e.PrivateKey.EncryptWithConfig([]byte(pass), b.cfg); err != nil {
			t.Fatal(err)
		}
		for i := range e.Subkeys {
			if err := e.Subkeys[i].PrivateKey.EncryptWithConfig([]byte(pass), b.cfg); err != nil {
				t.Fatal(err)
			}
		}
	}
	var buf bytes.Buffer
	if err := e.SerializePrivateWithoutSigning(&buf, b.cfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// foreign reads an export with the reader of internal/openpgp.
func (b *adoptedBase) foreign(t testing.TB, pass string) *openpgp.ForeignKey {
	t.Helper()
	k, err := openpgp.ReadForeignKey(b.export(t, pass))
	if err != nil {
		t.Fatalf("ReadForeignKey: %v", err)
	}
	t.Cleanup(k.Wipe)
	return k
}

// expectOf is what the bundle would say of a key of an export.
func expectOf(k *openpgp.ForeignKey) Expect {
	return Expect{Fingerprint: k.Primary.Fingerprint, Created: k.Primary.Created, Cert: k.Certificate()}
}

// adoptedSource answers the three roles with the passphrases of the tests.
func adoptedSource(importPass string) *passSource {
	src := newPassSource(testPass)
	src.by = map[Purpose]string{
		{Label: "A", File: FileOpenPGP, Role: Import}: importPass,
		{Label: "B", File: FileOpenPGP, Role: Import}: importPass,
		{Label: "A", File: FileOpenPGP, Role: Choose}: testPass,
		{Label: "B", File: FileOpenPGP, Role: Choose}: testPass,
	}
	return src
}

// eachAdopted runs a subtest for each algorithm, protected and not.
func eachAdopted(t *testing.T, f func(t *testing.T, b *adoptedBase, protected bool)) {
	t.Helper()
	for _, b := range adoptedBases(t) {
		for _, protected := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/protected=%v", b.name, protected), func(t *testing.T) { f(t, b, protected) })
		}
	}
}

func importPassOf(protected bool) string {
	if protected {
		return exportPass
	}
	return ""
}

// signAndVerify signs with an adopted key in the way of its algorithm and verifies with the public
// key with the standard library, which is not the code under test.
func signAndVerify(t testing.TB, k *AdoptedKey) {
	t.Helper()
	msg := []byte("a message to sign")
	switch pub := k.Public().(type) {
	case *rsa.PublicKey:
		d := sha512.Sum512(msg)
		sig, err := k.Sign(rand.Reader, d[:], crypto.SHA512)
		if err != nil || rsa.VerifyPKCS1v15(pub, crypto.SHA512, d[:], sig) != nil {
			t.Fatalf("RSA: %v", err)
		}
		d256 := sha256.Sum256(msg)
		sig, err = k.Sign(rand.Reader, d256[:], crypto.SHA256)
		if err != nil || rsa.VerifyPKCS1v15(pub, crypto.SHA256, d256[:], sig) != nil {
			t.Fatalf("RSA with SHA-256: %v", err)
		}
	case ed25519.PublicKey:
		sig, err := k.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil || !ed25519.Verify(pub, msg, sig) {
			t.Fatalf("Ed25519: %v", err)
		}
	case *ecdsa.PublicKey:
		for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			d := make([]byte, h.Size())
			_, _ = rand.Read(d)
			sig, err := k.Sign(rand.Reader, d, h)
			if err != nil || !ecdsa.VerifyASN1(pub, d, sig) {
				t.Fatalf("ECDSA with %v: %v", h, err)
			}
		}
	default:
		t.Fatalf("the public key is %T", pub)
	}
}

func TestAdoptedKeyIsSavedAndOpened(t *testing.T) {
	lowWork(t)
	eachAdopted(t, func(t *testing.T, b *adoptedBase, protected bool) {
		fk := b.foreign(t, importPassOf(protected))
		src := adoptedSource(importPassOf(protected))
		s, _, keys := openPassStore(t, src)
		if err := s.SaveAdopted(bg(), "A", fk); err != nil {
			t.Fatalf("SaveAdopted: %v", err)
		}
		want := []Purpose{{Label: "A", File: FileOpenPGP, Role: Choose}}
		if protected {
			want = []Purpose{{Label: "A", File: FileOpenPGP, Role: Import}, want[0]}
		}
		if got := src.purposes(); !samePurposes(got, want) {
			t.Errorf("the source was asked %v, want %v", got, want)
		}
		if names := dirNames(t, keys); len(names) != 1 || names[0] != "A.openpgp.key.age" {
			t.Fatalf("the folder holds %v, want the one key file", names)
		}
		if fi, err := os.Stat(filepath.Join(keys, "A.openpgp.key.age")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("the key file: %v %v", fi, err)
		}
		k, err := s.OpenAdopted(bg(), "A", expectOf(fk))
		if err != nil {
			t.Fatalf("OpenAdopted: %v", err)
		}
		if k.Fingerprint() != fk.Primary.Fingerprint || !k.Created().Equal(fk.Primary.Created) || k.Algorithm() != fk.Primary.Algorithm {
			t.Errorf("the key says %s %v %v", k.Fingerprint(), k.Created(), k.Algorithm())
		}
		if k.Kind() != keystore.KindSoftware || !k.Copyable() || len(k.Warnings()) != 1 || k.Warnings()[0] != keystore.WarningSoftwareCopyable {
			t.Errorf("the key answers Kind %v, Copyable %v, Warnings %v", k.Kind(), k.Copyable(), k.Warnings())
		}
		signAndVerify(t, k)
		if err := s.CheckAdopted(bg(), "A", expectOf(fk)); err != nil {
			t.Errorf("CheckAdopted: %v", err)
		}
		if err := k.Close(); err != nil || k.Close() != nil {
			t.Errorf("Close: %v", err)
		}
		if _, err := k.Sign(nil, make([]byte, 32), crypto.Hash(0)); !errors.Is(err, ErrParams) {
			t.Errorf("Sign after Close: %v, want ErrParams", err)
		}
		if k.Public() != nil {
			t.Errorf("Public after Close is not nil")
		}
	})
}

func TestAnAdoptedKeySignsLikeTheExportedKey(t *testing.T) {
	// the signature that the adopted key makes verifies with the key of the certificate that
	// go-crypto reads, the second program
	lowWork(t)
	b := adoptedNamed(t, "p384")
	fk := b.foreign(t, "")
	s, _, _ := openPassStore(t, adoptedSource(""))
	if err := s.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatal(err)
	}
	k, err := s.OpenAdopted(bg(), "A", expectOf(fk))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = k.Close() }()
	ring, err := pgp.ReadKeyRing(bytes.NewReader(fk.Certificate()))
	if err != nil || len(ring) != 1 {
		t.Fatalf("go-crypto does not read the certificate: %v", err)
	}
	if got := fmt.Sprintf("%X", ring[0].PrimaryKey.Fingerprint); !strings.EqualFold(got, k.Fingerprint()) {
		t.Errorf("the fingerprint is %s, go-crypto says %s", k.Fingerprint(), got)
	}
	theirs, ok := ring[0].PrimaryKey.PublicKey.(*pgpecdsa.PublicKey)
	ours, ok2 := k.Public().(*ecdsa.PublicKey)
	if !ok || !ok2 {
		t.Fatalf("the public keys are %T and %T", ring[0].PrimaryKey.PublicKey, k.Public())
	}
	point, err := ours.Bytes()
	if err != nil || !bytes.Equal(point, append(append([]byte{4}, theirs.X.FillBytes(make([]byte, 48))...), theirs.Y.FillBytes(make([]byte, 48))...)) {
		t.Errorf("the public key of the adopted key is not the public key of the certificate")
	}
}

func TestAdoptedKeyFilesAreNotPlain(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "ed25519")
	fk := b.foreign(t, "")
	s, _, keys := openPassStore(t, adoptedSource(""))
	if err := s.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatal(err)
	}
	file := readKeyFile(t, keys, "A.openpgp.key.age")
	pkt, err := fk.SecretPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pkt)
	if !bytes.HasPrefix(file, []byte("age-encryption.org/v1\n")) || bytes.Contains(file, pkt[len(pkt)-40:]) {
		t.Errorf("the key file is not an age file, or holds the end of the packet as it is")
	}
	// the payload of the file is the lone packet and nothing else
	back, err := ageFormat{}.unwrapWith([]byte(testPass), FileOpenPGP, file)
	if err != nil || !bytes.Equal(back, pkt) {
		t.Errorf("the payload is not the lone secret key packet: %v", err)
	}
	clear(back)
}

func TestAdoptedKeyIsNeverWrittenInTheTestMode(t *testing.T) {
	b := adoptedNamed(t, "p384")
	fk := b.foreign(t, "")
	s, _, keys := openStore(t)
	err := s.SaveAdopted(bg(), "A", fk)
	wantRefusal(t, err, ErrParams, "")
	if !strings.Contains(err.Error(), "never written without encryption") {
		t.Errorf("the text does not say why: %v", err)
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("the folder holds %v", names)
	}
	if _, err := s.OpenAdopted(bg(), "A", expectOf(fk)); !errors.Is(err, ErrParams) {
		t.Errorf("OpenAdopted in the test mode: %v, want ErrParams", err)
	}
	if err := s.CheckAdopted(bg(), "A", expectOf(fk)); !errors.Is(err, ErrParams) {
		t.Errorf("CheckAdopted in the test mode: %v, want ErrParams", err)
	}
}

func TestAdoptedParametersAreRefusedBeforeAnythingIsAsked(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "p384")
	fk := b.foreign(t, exportPass)
	src := adoptedSource(exportPass)
	s, _, keys := openPassStore(t, src)
	var nilStore *Store
	if err := nilStore.SaveAdopted(bg(), "A", fk); !errors.Is(err, ErrParams) {
		t.Errorf("a nil store: %v", err)
	}
	var noCtx context.Context
	if err := s.SaveAdopted(noCtx, "A", fk); !errors.Is(err, ErrParams) {
		t.Errorf("a nil context: %v", err)
	}
	for _, label := range []string{"", "a", "AB", "1"} {
		if err := s.SaveAdopted(bg(), label, fk); !errors.Is(err, ErrParams) {
			t.Errorf("label %q: %v", label, err)
		}
		if _, err := s.OpenAdopted(bg(), label, expectOf(fk)); !errors.Is(err, ErrParams) {
			t.Errorf("open, label %q: %v", label, err)
		}
	}
	if err := s.SaveAdopted(bg(), "A", nil); !errors.Is(err, ErrParams) {
		t.Errorf("a nil key: %v", err)
	}
	good := expectOf(fk)
	zero := []Expect{
		{},
		{Created: good.Created, Cert: good.Cert},
		{Fingerprint: good.Fingerprint, Cert: good.Cert},
		{Fingerprint: good.Fingerprint, Created: good.Created},
		{Fingerprint: good.Fingerprint, Created: good.Created, Cert: []byte{0xC6, 0x00}},
		{Fingerprint: good.Fingerprint, Created: good.Created, Cert: good.Cert[:3]},
	}
	for i, e := range zero {
		if _, err := s.OpenAdopted(bg(), "A", e); !errors.Is(err, ErrParams) {
			t.Errorf("expectation %d: %v, want ErrParams", i, err)
		}
		if err := s.CheckAdopted(bg(), "A", e); !errors.Is(err, ErrParams) {
			t.Errorf("check, expectation %d: %v, want ErrParams", i, err)
		}
	}
	if err := s.SaveAdopted(bg(), "A", &openpgp.ForeignKey{}); !errors.Is(err, ErrParams) {
		t.Errorf("a key that ReadForeignKey did not make: %v", err)
	}
	if src.calls() != 0 {
		t.Errorf("the source was asked %d times for a call that was refused", src.calls())
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("the folder holds %v", names)
	}
}

func TestAdoptedKeyIsNeverReplaced(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "p384")
	fk := b.foreign(t, exportPass)
	src := adoptedSource(exportPass)
	s, _, keys := openPassStore(t, src)
	if err := s.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatal(err)
	}
	first := readKeyFile(t, keys, "A.openpgp.key.age")
	asked := src.calls()
	err := s.SaveAdopted(bg(), "A", fk)
	wantRefusal(t, err, ErrKeyExists, "key-exists", exportPass, testPass)
	if src.calls() != asked {
		t.Errorf("the source was asked for a file that stands there")
	}
	if !bytes.Equal(first, readKeyFile(t, keys, "A.openpgp.key.age")) || len(dirNames(t, keys)) != 1 {
		t.Errorf("the file was changed or a file was left")
	}
}

func TestAnExistingBornKeyFileIsNeverReplacedByAnAdoptedOne(t *testing.T) {
	lowWork(t)
	src := adoptedSource("")
	s, _, keys := openPassStore(t, src)
	born := mustGenerate(t)
	if err := s.SaveOpenPGP("A", born, certFor(t, born)); err != nil {
		t.Fatal(err)
	}
	first := readKeyFile(t, keys, "A.openpgp.key.age")
	asked := src.calls()
	fk := adoptedNamed(t, "p384").foreign(t, "")
	wantRefusal(t, s.SaveAdopted(bg(), "A", fk), ErrKeyExists, "key-exists")
	if src.calls() != asked || !bytes.Equal(first, readKeyFile(t, keys, "A.openpgp.key.age")) {
		t.Errorf("a passphrase was asked, or the file changed")
	}
}

func TestAnAdoptedKeyIsNotWrittenBesideAFileOfTheOtherMode(t *testing.T) {
	lowWork(t)
	src := adoptedSource("")
	s, _, keys := openPassStore(t, src)
	writeKeyFile(t, keys, "Z.x509.key.pem", []byte("TEST ONLY"))
	err := s.SaveAdopted(bg(), "A", adoptedNamed(t, "p384").foreign(t, ""))
	wantRefusal(t, err, ErrWrongMode, "key-file-mode")
	if src.calls() != 0 {
		t.Errorf("the source was asked")
	}
}

func TestAnAdoptedKeyNeedsTheKeyDirectory(t *testing.T) {
	lowWork(t)
	src := adoptedSource("")
	s, _, keys := openPassStore(t, src)
	if err := os.RemoveAll(keys); err != nil {
		t.Fatal(err)
	}
	err := s.SaveAdopted(bg(), "A", adoptedNamed(t, "p384").foreign(t, ""))
	wantRefusal(t, err, ErrKeyDir, "key-dir")
}

func TestTheWrongPassphraseOfTheExportIsSaidToBeTheExports(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "p384")
	fk := b.foreign(t, exportPass)
	s, _, keys := openPassStore(t, adoptedSource("not the passphrase of the export"))
	err := s.SaveAdopted(bg(), "A", fk)
	wantRefusal(t, err, ErrWrongPassphrase, "passphrase-wrong", exportPass, testPass, "not the passphrase")
	if !strings.Contains(err.Error(), "exported file") {
		t.Errorf("the text does not say that the exported file did not open: %v", err)
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("the folder holds %v", names)
	}
}

func TestTheWrongPassphraseOfTheKeyFileIsSaidToBeTheKeyFiles(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "p384")
	fk := b.foreign(t, "")
	s, _, _ := openPassStore(t, adoptedSource(""))
	if err := s.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatal(err)
	}
	src := newPassSource("another passphrase of the file")
	s.source = src
	_, err := s.OpenAdopted(bg(), "A", expectOf(fk))
	wantRefusal(t, err, ErrWrongPassphrase, "passphrase-wrong", "another passphrase", testPass)
	if !strings.Contains(err.Error(), "key file") || strings.Contains(err.Error(), "exported") {
		t.Errorf("the text does not say that the key file did not open: %v", err)
	}
}

func TestThePassphraseRulesOfTheRoles(t *testing.T) {
	lowWork(t)
	b := adoptedNamed(t, "p384")
	for _, c := range []struct {
		name       string
		importPass string
		choose     string
		want       error
		text       string
	}{
		{"a short passphrase of the export is fine", "abc", testPass, nil, ""},
		{"a long passphrase of the export is fine", strings.Repeat("x", 1000), testPass, nil, ""},
		{"a short new passphrase is refused", "abc", "too short", ErrPassphrase, "shorter than 15"},
	} {
		t.Run(c.name, func(t *testing.T) {
			fk := b.foreign(t, c.importPass)
			src := adoptedSource(c.importPass)
			src.by[Purpose{Label: "A", File: FileOpenPGP, Role: Choose}] = c.choose
			s, _, keys := openPassStore(t, src)
			err := s.SaveAdopted(bg(), "A", fk)
			if c.want == nil {
				if err != nil {
					t.Fatalf("SaveAdopted: %v", err)
				}
				return
			}
			wantRefusal(t, err, c.want, "passphrase", c.importPass, c.choose)
			if !strings.Contains(err.Error(), c.text) {
				t.Errorf("the text does not name the rule: %v", err)
			}
			if names := dirNames(t, keys); len(names) != 0 {
				t.Errorf("the folder holds %v", names)
			}
		})
	}
}

func TestCheckPassphraseForTheRoles(t *testing.T) {
	long := strings.Repeat("x", openpgp.MaxForeignPassphraseBytes)
	cases := []struct {
		role Role
		pass string
		ok   bool
	}{
		{KeyFile, "abc", false}, {Choose, "abc", false}, {Import, "abc", true},
		{KeyFile, testPass, true}, {Choose, testPass, true}, {Import, testPass, true},
		{Import, "", false}, {KeyFile, "", false}, {Choose, "", false},
		{Import, long, true}, {Import, long + "x", false},
		{Choose, long, false}, {KeyFile, long, false},
		{Import, "a passphrase\xff of latin one", true},
	}
	for i, c := range cases {
		err := CheckPassphraseFor(c.role, []byte(c.pass))
		if (err == nil) != c.ok {
			t.Errorf("case %d (role %d, %d bytes): %v, want ok=%v", i, c.role, len(c.pass), err, c.ok)
		}
		if err != nil && (!errors.Is(err, ErrPassphrase) || strings.Contains(err.Error(), "abc")) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	if err := CheckPassphraseFor(Role(9), []byte(testPass)); !errors.Is(err, ErrParams) {
		t.Errorf("an unknown role: %v, want ErrParams", err)
	}
	if err := CheckPassphrase([]byte("abc")); !errors.Is(err, ErrPassphrase) {
		t.Errorf("CheckPassphrase is not the rule of the key file any more: %v", err)
	}
}

func TestReaderSourceHoldsTheRolesToTheirRules(t *testing.T) {
	long := strings.Repeat("y", 3000)
	src := ReaderSource(strings.NewReader("abc\r\n" + long + "\n" + "short\n" + strings.Repeat("z", openpgp.MaxForeignPassphraseBytes+1) + "\n"))
	imp := Purpose{Label: "A", File: FileOpenPGP, Role: Import}
	got, err := src.Passphrase(bg(), imp)
	if err != nil || string(got) != "abc" {
		t.Fatalf("a short line for an import: %q %v", got, err)
	}
	got, err = src.Passphrase(bg(), imp)
	if err != nil || string(got) != long {
		t.Fatalf("a line of 3000 bytes for an import: %v", err)
	}
	if _, err := src.Passphrase(bg(), Purpose{Label: "A", File: FileOpenPGP, Role: Choose}); !errors.Is(err, ErrPassphrase) {
		t.Errorf("a short line for a new passphrase: %v, want ErrPassphrase", err)
	}
	if _, err := src.Passphrase(bg(), imp); !errors.Is(err, ErrPassphrase) {
		t.Errorf("a line of 4097 bytes for an import: %v, want ErrPassphrase", err)
	}
	if _, err := ReaderSource(strings.NewReader("abcdefghijklmnop\n")).Passphrase(bg(), Purpose{Role: 7}); !errors.Is(err, ErrParams) {
		t.Errorf("an unknown role: %v, want ErrParams", err)
	}
	// a line of 1100 bytes is too long for a key file and fine for an import
	l := strings.Repeat("q", 1100) + "\n"
	if _, err := ReaderSource(strings.NewReader(l)).Passphrase(bg(), Purpose{}); !errors.Is(err, ErrPassphrase) {
		t.Errorf("a line of 1100 bytes for a key file: %v", err)
	}
	if got, err := ReaderSource(strings.NewReader(l)).Passphrase(bg(), imp); err != nil || len(got) != 1100 {
		t.Errorf("a line of 1100 bytes for an import: %v", err)
	}
}

func TestAReaderSourceServesTheTwoPassphrasesOfASave(t *testing.T) {
	lowWork(t)
	fk := adoptedNamed(t, "ed25519").foreign(t, "short")
	s, _, _ := openPassStore(t, ReaderSource(strings.NewReader("short\n"+testPass+"\n"+testPass+"\n")))
	if err := s.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatalf("SaveAdopted: %v", err)
	}
	k, err := s.OpenAdopted(bg(), "A", expectOf(fk))
	if err != nil {
		t.Fatalf("OpenAdopted: %v", err)
	}
	signAndVerify(t, k)
	_ = k.Close()
}

func TestAKeyFileOfAnotherKeyIsRefusedBeforeASignerIsReturned(t *testing.T) {
	lowWork(t)
	a := adoptedNamed(t, "p384").foreign(t, "")
	other := adoptedNamed(t, "ed25519").foreign(t, "")
	s, _, _ := openPassStore(t, adoptedSource(""))
	if err := s.SaveAdopted(bg(), "A", a); err != nil {
		t.Fatal(err)
	}
	good := expectOf(a)
	oth := expectOf(other)
	oth.Created = oth.Created.Add(time.Hour) // both test keys are made at the same time
	cases := []struct {
		name string
		want Expect
		in   []string
		out  []string
	}{
		{"all three", oth, []string{"the fingerprint", "the creation time", "the public part"}, nil},
		{"the fingerprint", Expect{Fingerprint: oth.Fingerprint, Created: good.Created, Cert: good.Cert}, []string{"the fingerprint"}, []string{"creation time", "public part"}},
		{"the creation time", Expect{Fingerprint: good.Fingerprint, Created: good.Created.Add(time.Second), Cert: good.Cert}, []string{"the creation time"}, []string{"fingerprint", "public part"}},
		{"the public part", Expect{Fingerprint: good.Fingerprint, Created: good.Created, Cert: oth.Cert}, []string{"the public part"}, []string{"fingerprint", "creation time"}},
	}
	for _, c := range cases {
		k, err := s.OpenAdopted(bg(), "A", c.want)
		if k != nil {
			t.Errorf("%s: a key is returned", c.name)
		}
		wantRefusal(t, err, ErrKeyFile, "key-file", a.Primary.Fingerprint, other.Primary.Fingerprint, testPass)
		for _, w := range c.in {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the text does not say %q: %v", c.name, w, err)
			}
		}
		for _, w := range c.out {
			if strings.Contains(err.Error(), w) {
				t.Errorf("%s: the text says %q, which does not differ: %v", c.name, w, err)
			}
		}
		if err := s.CheckAdopted(bg(), "A", c.want); !errors.Is(err, ErrKeyFile) {
			t.Errorf("%s: CheckAdopted: %v", c.name, err)
		}
	}
}

func TestTheTwoFormsOfAnOpenPGPKeyFileAreToldApart(t *testing.T) {
	lowWork(t)
	s, _, _ := openPassStore(t, adoptedSource(""))
	born := mustGenerate(t)
	if err := s.SaveOpenPGP("A", born, certFor(t, born)); err != nil {
		t.Fatal(err)
	}
	fk := adoptedNamed(t, "p384").foreign(t, "")
	if err := s.SaveAdopted(bg(), "B", fk); err != nil {
		t.Fatal(err)
	}
	// a born key through the reader of the adopted form
	_, err := s.OpenAdopted(bg(), "A", expectOf(fk))
	wantRefusal(t, err, ErrKeyFile, "key-file", testPass)
	if !strings.Contains(err.Error(), "a key that ritueel made") {
		t.Errorf("the text does not say which form it found: %v", err)
	}
	// an adopted key through the reader of the born form
	_, err = s.OpenOpenPGP(bg(), "B")
	wantRefusal(t, err, ErrKeyFile, "key-file", testPass)
	if !strings.Contains(err.Error(), "adopted key") {
		t.Errorf("the text does not say which form it found: %v", err)
	}
	// the born key still opens as it did
	if k, err := s.OpenOpenPGP(bg(), "A"); err != nil || k.Key == nil {
		t.Errorf("the born key does not open: %v", err)
	}
}

func TestAnAdoptedKeyThatDoesNotReadBackIsReportedAsWrittenAndNotGood(t *testing.T) {
	lowWork(t)
	a := adoptedNamed(t, "p384").foreign(t, "")
	other := adoptedNamed(t, "ed25519").foreign(t, "")
	otherPkt, err := other.SecretPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	s, _, keys := openPassStore(t, adoptedSource(""))
	// the file that is read back opens as the packet of another key
	s.format = swapPayload{inner: ageFormat{}, payload: otherPkt}
	err = s.SaveAdopted(bg(), "A", a)
	wantRefusal(t, err, ErrKeyFile, "key-file", testPass)
	text := err.Error()
	for _, w := range []string{"A.openpgp.key.age", "was written", "failed its check", "the fingerprint", "the public part"} {
		if !strings.Contains(text, w) {
			t.Errorf("the text does not say %q: %v", w, err)
		}
	}
	if names := dirNames(t, keys); len(names) != 1 || names[0] != "A.openpgp.key.age" {
		t.Errorf("the file that was written is not left where it is: %v", names)
	}
}

// swapPayload is the age format with a read that gives another payload than the file holds.
type swapPayload struct {
	inner   ageFormat
	payload []byte
}

func (f swapPayload) wrap(k FileKind, p []byte) ([]byte, error) { return f.inner.wrap(k, p) }
func (f swapPayload) unwrap(k FileKind, p []byte) ([]byte, error) {
	return f.inner.unwrap(k, p)
}
func (f swapPayload) inspect(file []byte) error { return f.inner.inspect(file) }
func (f swapPayload) wrapWith(pass []byte, k FileKind, p []byte) ([]byte, error) {
	return f.inner.wrapWith(pass, k, p)
}

func (f swapPayload) unwrapWith(pass []byte, k FileKind, file []byte) ([]byte, error) {
	if _, err := f.inner.unwrapWith(pass, k, file); err != nil {
		return nil, err
	}
	return bytes.Clone(f.payload), nil
}

func TestAWriteThatFailsNamesTheTemporaryFileOfAnAdoptedKey(t *testing.T) {
	lowWork(t)
	s, _, keys := openPassStore(t, adoptedSource(""))
	failAt(t, s, keys, fsx.StepSyncFile)
	err := s.SaveAdopted(bg(), "A", adoptedNamed(t, "p384").foreign(t, ""))
	if err == nil {
		t.Fatal("the write did not fail")
	}
	if !strings.Contains(err.Error(), "was not written whole") || !strings.Contains(err.Error(), "may hold the key: remove it") {
		t.Errorf("the error does not name the temporary file: %v", err)
	}
}

func TestAnAdoptedKeyIsWipedWhenItIsClosed(t *testing.T) {
	lowWork(t)
	fk := adoptedNamed(t, "ed25519").foreign(t, "")
	s, _, _ := openPassStore(t, adoptedSource(""))
	if err := s.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatal(err)
	}
	k, err := s.OpenAdopted(bg(), "A", expectOf(fk))
	if err != nil {
		t.Fatal(err)
	}
	handle := k.s.secret.Signer()
	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := handle.Sign(rand.Reader, []byte("m"), crypto.Hash(0)); !errors.Is(err, openpgp.ErrSecretWiped) {
		t.Errorf("the handle signs after Close: %v", err)
	}
	var nilKey *AdoptedKey
	if nilKey.Close() != nil || nilKey.Public() != nil || nilKey.Fingerprint() != "" || !nilKey.Created().IsZero() {
		t.Errorf("a nil key answers something")
	}
	if _, err := nilKey.Sign(nil, nil, crypto.Hash(0)); !errors.Is(err, ErrParams) {
		t.Errorf("a nil key signs: %v", err)
	}
	if _, err := (&AdoptedKey{}).Sign(nil, nil, crypto.Hash(0)); !errors.Is(err, ErrParams) {
		t.Errorf("a zero key signs: %v", err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		if got := fmt.Sprintf(f, k); got != adoptedKeyText {
			t.Errorf("%s prints %q", f, got)
		}
	}
}

func TestAnAdoptedKeyRefusesWhatItIsNotMeantToSign(t *testing.T) {
	lowWork(t)
	open := func(name string) *AdoptedKey {
		fk := adoptedNamed(t, name).foreign(t, "")
		s, _, _ := openPassStore(t, adoptedSource(""))
		if err := s.SaveAdopted(bg(), "A", fk); err != nil {
			t.Fatal(err)
		}
		k, err := s.OpenAdopted(bg(), "A", expectOf(fk))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = k.Close() })
		return k
	}
	d := func(n int) []byte { return make([]byte, n) }
	type try struct {
		name   string
		digest []byte
		opts   crypto.SignerOpts
	}
	refused := map[string][]try{
		"rsa4096": {
			{"PSS", d(32), &rsa.PSSOptions{Hash: crypto.SHA256}},
			{"a typed nil PSS option", d(32), (*rsa.PSSOptions)(nil)},
			{"a type that embeds a PSS option", d(32), embedsPSS{&rsa.PSSOptions{Hash: crypto.SHA256}}},
			{"a type that names SHA-256", d(32), namesHash{crypto.SHA256}},
			{"SHA-1", d(20), crypto.SHA1},
			{"SHA-224", d(28), crypto.SHA224},
			{"no hash", d(32), crypto.Hash(0)},
			{"nil options", d(32), nil},
			{"a digest of another length", d(33), crypto.SHA256},
			{"SHA-512 for a SHA-256 digest", d(32), crypto.SHA512},
		},
		"ed25519": {
			{"SHA-512 (Ed25519ph)", d(64), crypto.SHA512},
			{"SHA-256", d(32), crypto.SHA256},
			{"nil options", d(32), nil},
			{"an Ed25519 option", d(32), &ed25519.Options{Hash: crypto.Hash(0)}},
			{"a type that names no hash", d(32), namesHash{0}},
		},
		"p384": {
			{"a type that embeds a PSS option", d(48), embedsPSS{&rsa.PSSOptions{Hash: crypto.SHA384}}},
			{"a type that names SHA-384", d(48), namesHash{crypto.SHA384}},
			{"SHA-1", d(20), crypto.SHA1},
			{"no hash", d(48), crypto.Hash(0)},
			{"nil options", d(48), nil},
			{"SHA-384 for a short digest", d(32), crypto.SHA384},
			{"SHA-256 for a SHA-384 digest", d(48), crypto.SHA256},
			{"a PSS option", d(48), &rsa.PSSOptions{Hash: crypto.SHA384}},
		},
	}
	for _, b := range adoptedBases(t) {
		k := open(b.name)
		for _, c := range refused[b.name] {
			sig, err := k.Sign(rand.Reader, c.digest, c.opts)
			if !errors.Is(err, ErrParams) || sig != nil {
				t.Errorf("%s, %s: %v, want ErrParams and no signature", b.name, c.name, err)
			}
		}
	}
}

func TestASignatureThatDoesNotVerifyIsNeverReturned(t *testing.T) {
	lowWork(t)
	for _, b := range adoptedBases(t) {
		fk := b.foreign(t, "")
		s, _, _ := openPassStore(t, adoptedSource(""))
		if err := s.SaveAdopted(bg(), "A", fk); err != nil {
			t.Fatal(err)
		}
		k, err := s.OpenAdopted(bg(), "A", expectOf(fk))
		if err != nil {
			t.Fatal(err)
		}
		k.s.tamper = func(sig []byte) []byte { sig = bytes.Clone(sig); sig[len(sig)-1] ^= 1; return sig }
		in, opts := make([]byte, 32), crypto.SignerOpts(crypto.SHA256)
		if b.name == "ed25519" {
			opts = crypto.Hash(0)
		}
		if b.name == "p384" {
			in, opts = make([]byte, 48), crypto.SHA384
		}
		sig, err := k.Sign(nil, in, opts)
		if !errors.Is(err, errAdoptedSignature) || sig != nil {
			t.Errorf("%s: %v, want the refusal of a signature that does not verify", b.name, err)
		}
		if err := k.selfCheck(); !errors.Is(err, ErrKeyFile) {
			t.Errorf("%s: selfCheck: %v, want ErrKeyFile", b.name, err)
		}
		_ = k.Close()
	}
}

func TestAnAdoptedKeyRSA4096FitsThePayloadCap(t *testing.T) {
	lowWork(t)
	fk := adoptedNamed(t, "rsa4096").foreign(t, "")
	pkt, err := fk.SecretPacket(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pkt)
	s, _, keys := openPassStore(t, adoptedSource(""))
	if err := s.SaveAdopted(bg(), "A", fk); err != nil {
		t.Fatal(err)
	}
	file := readKeyFile(t, keys, "A.openpgp.key.age")
	t.Logf("the lone packet of RSA-4096 is %d bytes and its key file %d bytes; the cap of the payload and of the file is %d", len(pkt), len(file), MaxKeyFileSize)
	if len(pkt) > MaxKeyFileSize/20 || len(file) > MaxKeyFileSize {
		t.Errorf("the packet is %d bytes and the file %d", len(pkt), len(file))
	}
}

// embedsPSS is an option that embeds the options of PSS and so answers its methods.
type embedsPSS struct{ *rsa.PSSOptions }

// namesHash is an option of another type than crypto.Hash that names a hash.
type namesHash struct{ h crypto.Hash }

func (n namesHash) HashFunc() crypto.Hash { return n.h }

func TestAWipedExportAsksNoPassphrase(t *testing.T) {
	lowWork(t)
	fk := adoptedNamed(t, "p384").foreign(t, exportPass)
	fk.Wipe()
	src := adoptedSource(exportPass)
	s, _, keys := openPassStore(t, src)
	err := s.SaveAdopted(bg(), "A", fk)
	wantRefusal(t, err, ErrParams, "", exportPass, testPass)
	if src.calls() != 0 {
		t.Errorf("the source was asked %d times for a key that was wiped", src.calls())
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("the folder holds %v", names)
	}
}
