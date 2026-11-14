package software

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/go-crypto/openpgp"
	"ritueel.id/ritueel/internal/openpgp"
)

func TestSaveOpenPGPThenOpenOpenPGPGivesTheSameKeyTimeAndCertificate(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	cert := certFor(t, k)
	if err := s.SaveOpenPGP("A", k, cert); err != nil {
		t.Fatalf("SaveOpenPGP: %v", err)
	}
	if !k.Saved() {
		t.Error("not Saved after the save")
	}
	got, err := s.OpenOpenPGP(bg(), "A")
	if err != nil {
		t.Fatalf("OpenOpenPGP: %v", err)
	}
	defer func() { _ = got.Key.Close() }()
	if !samePublic(k, got.Key) {
		t.Error("another key")
	}
	if !got.Created.Equal(testCreated) {
		t.Errorf("creation time %v, want %v", got.Created, testCreated)
	}
	if !bytes.Equal(got.Cert, cert) {
		t.Error("the certificate differs")
	}
	want, err := openpgp.Fingerprint(k.Public().(*ecdsa.PublicKey), testCreated)
	if err != nil {
		t.Fatal(err)
	}
	have, err := openpgp.Fingerprint(got.Key.Public().(*ecdsa.PublicKey), got.Created)
	if err != nil || have != want {
		t.Errorf("fingerprint %s, want %s (%v)", have, want, err)
	}
	if got.Key.Saved() {
		t.Error("an opened key is Saved")
	}

	// The file: one armour block, the one header, a valid checksum, the body of openpgp.SecretKey.
	file := readKeyFile(t, keys, "A.openpgp.key.asc")
	if !bytes.HasPrefix(file, []byte(armourLine("BEGIN", "PGP PRIVATE KEY BLOCK")+"\nComment: TEST ONLY\n\n")) ||
		!bytes.HasSuffix(file, []byte(armourLine("END", "PGP PRIVATE KEY BLOCK")+"\n")) || bytes.HasSuffix(file, []byte("\n\n")) {
		t.Errorf("the armour is not the one of the page: %q ... %q", file[:min(len(file), 80)], file[max(0, len(file)-40):])
	}
	typ, headers, body := pgpUnarmor(t, file)
	if typ != "PGP PRIVATE KEY BLOCK" || len(headers) != 1 || headers["Comment"] != "TEST ONLY" {
		t.Errorf("type %q headers %v", typ, headers)
	}
	if want := secretOf(t, k, cert); !bytes.Equal(body, want) {
		t.Error("the body is not what openpgp.SecretKey writes")
	}
	if i := bytes.LastIndex(file, []byte("\n=")); i < 0 || len(bytes.TrimSpace(file[i+2:bytes.LastIndex(file, []byte("\n-----END"))])) != 4 {
		t.Error("the armour has no checksum line of four characters")
	}
	// go-crypto reads the whole file as a key ring with an unprotected primary.
	ring, err := pgp.ReadArmoredKeyRing(bytes.NewReader(file))
	if err != nil || len(ring) != 1 || ring[0].PrivateKey == nil || ring[0].PrivateKey.Encrypted {
		t.Fatalf("go-crypto does not read the file as a secret key: %v", err)
	}
	if info, err := os.Stat(filepath.Join(keys, "A.openpgp.key.asc")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v (%v), want 0600", info.Mode().Perm(), err)
	}
}

func TestSaveOpenPGPRefusesWhatIsNotTheCertificateOfTheKeyAndWritesNothing(t *testing.T) {
	k := mustGenerate(t)
	other := mustGenerate(t)
	cert := certFor(t, k)
	closed := mustGenerate(t)
	_ = closed.Close()
	cases := []struct {
		name string
		key  *Key
		cert []byte
	}{
		{"the certificate of another key", k, certFor(t, other)},
		{"a nil certificate", k, nil},
		{"an empty certificate", k, []byte{}},
		{"a certificate of 100 bytes of junk", k, bytes.Repeat([]byte{0xA5}, 100)},
		{"a certificate cut by one byte", k, cert[:len(cert)-1]},
		{"a certificate with a trailing byte", k, append(bytes.Clone(cert), 0)},
		{"the secret key where a certificate is meant", k, secretOf(t, k, cert)},
		{"a nil key", nil, cert},
		{"a zero key", &Key{}, cert},
		{"a closed key", closed, cert},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, keys := openStore(t)
			rec := record(s)
			err := s.SaveOpenPGP("A", c.key, c.cert)
			if !errors.Is(err, ErrParams) {
				t.Fatalf("the error is not ErrParams: %v", err)
			}
			if rec.calls() != 0 || len(dirNames(t, keys)) != 0 {
				t.Errorf("a file was written: %v, %d calls", dirNames(t, keys), rec.calls())
			}
			if c.key.Saved() {
				t.Error("Saved is true")
			}
			// A refusal is not a stop: a good save works after it.
			fresh := mustGenerate(t)
			if err := s.SaveOpenPGP("A", fresh, certFor(t, fresh)); err != nil {
				t.Errorf("a good save after a refusal: %v", err)
			}
		})
	}
}

// openPGPRefusals are files that OpenOpenPGP must refuse, made from a good key.
func openPGPRefusals(t testing.TB, k *Key, cert []byte) []x509Refusal {
	t.Helper()
	secret := secretOf(t, k, cert)
	good := pgpArmor(t, "PGP PRIVATE KEY BLOCK", testOnly, secret)
	armorOf := func(payload []byte) []byte { return pgpArmor(t, "PGP PRIVATE KEY BLOCK", testOnly, payload) }
	pk := pgpPackets(t, secret)
	first := pgpBody(pk[0])
	rest := bytes.Join(pk[1:], nil)
	rebuild := func(f func(b []byte) []byte) []byte {
		return armorOf(append(pgpWrap(5, f(bytes.Clone(first))), rest...))
	}
	checksum := func(b []byte) []byte { // the checksum of the standard over the integer
		var sum uint16
		for _, c := range b {
			sum += uint16(c)
		}
		return []byte{byte(sum >> 8), byte(sum)}
	}
	const pubLen, usage = 111, 111
	order := elliptic.P384().Params().N
	other := mustGenerate(t)
	otherScalar := new(big.Int).SetBytes(scalarBytes(t, other))
	withScalar := func(v *big.Int) []byte {
		return rebuild(func(b []byte) []byte {
			m := pgpMPI(v)
			return append(append(b[:usage+1], m...), checksum(m)...)
		})
	}
	flip := func(s []byte, at int) []byte { c := bytes.Clone(s); c[at] ^= 1; return c }
	nl := []byte("\n")
	crcAt := bytes.LastIndex(good, []byte("\n=")) + 2
	lines := bytes.SplitN(good, nl, 3)
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	pubSecret := armorOf(cert) // a public certificate under the type of a secret key
	return []x509Refusal{
		// the armour
		{"an empty file", nil},
		{"no armour", secret},
		{"a second header", pgpArmor(t, "PGP PRIVATE KEY BLOCK", map[string]string{"Comment": "TEST ONLY", "Version": "x"}, secret)},
		{"the header in lower case", pgpArmor(t, "PGP PRIVATE KEY BLOCK", map[string]string{"Comment": "test only"}, secret)},
		{"the header with another value", pgpArmor(t, "PGP PRIVATE KEY BLOCK", map[string]string{"Comment": "TEST ONLY!"}, secret)},
		{"another header name", pgpArmor(t, "PGP PRIVATE KEY BLOCK", map[string]string{"Hash": "TEST ONLY"}, secret)},
		{"no header", pgpArmor(t, "PGP PRIVATE KEY BLOCK", nil, secret)},
		{"the type PGP PUBLIC KEY BLOCK", pgpArmor(t, "PGP PUBLIC KEY BLOCK", testOnly, secret)},
		{"the type PGP MESSAGE", pgpArmor(t, "PGP MESSAGE", testOnly, secret)},
		{"the type PGP SIGNATURE", pgpArmor(t, "PGP SIGNATURE", testOnly, secret)},
		{"a wrong checksum", flip(good, crcAt)},
		{"a changed body character", flip(good, len(lines[0])+len(lines[1])+4)},
		{"a missing end line", good[:bytes.LastIndex(good, []byte("-----END"))]},
		{"text after the end line", cat(good, []byte("a note\n"))},
		{"text before the begin line", cat([]byte("a note\n"), good)},
		{"two blocks", cat(good, good)},
		{"a space after the end line", cat(bytes.TrimSuffix(good, nl), []byte(" \n"))},
		{"two final newlines", cat(good, nl)},
		{"CRLF line ends", bytes.ReplaceAll(good, nl, []byte("\r\n"))},
		{"a blank line after the header removed", bytes.Replace(good, []byte("TEST ONLY\n\n"), []byte("TEST ONLY\n"), 1)},
		{"a blank line more after the header", bytes.Replace(good, []byte("TEST ONLY\n\n"), []byte("TEST ONLY\n\n\n"), 1)},
		// the packets
		{"a public certificate under the armour of a secret key", pubSecret},
		{"S2K usage 254", rebuild(func(b []byte) []byte { b[usage] = 254; return b })},
		{"S2K usage 255", rebuild(func(b []byte) []byte { b[usage] = 255; return b })},
		{"a wrong checksum of the secret material", rebuild(func(b []byte) []byte { b[len(b)-1] ^= 1; return b })},
		{"a version 5 key", rebuild(func(b []byte) []byte { b[0] = 5; return b })},
		{"an RSA key", rebuild(func(b []byte) []byte { b[5] = 1; return b })},
		{"an EdDSA key", rebuild(func(b []byte) []byte { b[5] = 22; return b })},
		{"a curve other than P-384", rebuild(func(b []byte) []byte { b[7] = 0x03; b[8] = 0x01; return b })},
		{"the scalar of another key", withScalar(otherScalar)},
		{"a scalar equal to the group order", withScalar(order)},
		{"a scalar of one", withScalar(big.NewInt(1))},
		{"a second user ID", armorOf(bytes.Join([][]byte{pgpWrap(5, first), pk[1], pk[1], pk[2]}, nil))},
		{"a subkey after the signature", armorOf(append(bytes.Clone(secret), pgpWrap(14, first[:pubLen])...))},
		{"a secret subkey after the signature", armorOf(append(bytes.Clone(secret), pgpWrap(7, first)...))},
		{"a trust packet after the signature", armorOf(append(bytes.Clone(secret), pgpWrap(12, []byte{0})...))},
		{"a second signature", armorOf(append(bytes.Clone(secret), pk[2]...))},
		{"no self-signature", armorOf(bytes.Join(pk[:2], nil))},
		{"an indeterminate length", armorOf(append([]byte{0x80 | 5<<2 | 3}, append(bytes.Clone(first), rest...)...))},
		{"a partial length", armorOf(append(append([]byte{0xC5, 0xE0 | 7}, first[:128]...), append([]byte{byte(len(first) - 128)}, append(bytes.Clone(first[128:]), rest...)...)...))},
		{"a five-byte length where one byte is enough", armorOf(append(append([]byte{0xC5, 0xFF, 0, 0, 0, byte(len(first))}, first...), rest...))},
		{"an old-format header", armorOf(append(append([]byte{0x80 | 5<<2, byte(len(first))}, first...), rest...))},
	}
}

func TestOpenOpenPGPRefusesEveryFileThatIsNotExactlyTheShapeOfThePage(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	cert := certFor(t, k)
	secrets := keysOf(t, k, cert)
	// The control: the file of the helper is the file of the page.
	writeKeyFile(t, keys, "A.openpgp.key.asc", pgpArmor(t, "PGP PRIVATE KEY BLOCK", testOnly, secretOf(t, k, cert)))
	if got, err := s.OpenOpenPGP(bg(), "A"); err != nil {
		t.Fatalf("the good file made by the helper is refused: %v", err)
	} else {
		_ = got.Key.Close()
	}
	for _, c := range openPGPRefusals(t, k, cert) {
		t.Run(c.name, func(t *testing.T) {
			writeKeyFile(t, keys, "A.openpgp.key.asc", c.file)
			got, err := s.OpenOpenPGP(bg(), "A")
			if err == nil {
				_ = got.Key.Close()
				t.Fatal("accepted")
			}
			if got != nil {
				t.Error("a refusal returned a value")
			}
			if !errors.Is(err, ErrKeyFile) || Code(err) != "key-file" {
				t.Errorf("the error is not ErrKeyFile (code %q): %v", Code(err), err)
			}
			if f := secrets.findText(err.Error()); f != "" {
				t.Errorf("the error text holds a canary (%s)", f)
			}
		})
	}
}

func TestOpenOpenPGPAcceptsAMissingFinalNewlineAndRefusesTwo(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	cert := certFor(t, k)
	good := pgpArmor(t, "PGP PRIVATE KEY BLOCK", testOnly, secretOf(t, k, cert))
	writeKeyFile(t, keys, "A.openpgp.key.asc", bytes.TrimSuffix(good, []byte("\n")))
	got, err := s.OpenOpenPGP(bg(), "A")
	if err != nil {
		t.Fatalf("a missing final newline is refused: %v", err)
	}
	_ = got.Key.Close()
}

func TestOpenOpenPGPRefusesAFileOverTheLimitBeforeAnyParse(t *testing.T) {
	s, _, keys := openStore(t)
	rec := recordFormat(s)
	k := mustGenerate(t)
	cert := certFor(t, k)
	good := pgpArmor(t, "PGP PRIVATE KEY BLOCK", testOnly, secretOf(t, k, cert))
	writeKeyFile(t, keys, "A.openpgp.key.asc", append(good, bytes.Repeat([]byte("\n"), MaxKeyFileSize)...))
	if _, err := s.OpenOpenPGP(bg(), "A"); !errors.Is(err, ErrKeyFile) {
		t.Errorf("%v", err)
	}
	if rec.unwraps != 0 {
		t.Error("the parser was called")
	}
}

func TestSaveOpenPGPOverAnExistingFileIsErrKeyExistsAndLeavesItAlone(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	writeKeyFile(t, keys, "A.openpgp.key.asc", []byte("keep"))
	err := s.SaveOpenPGP("A", k, certFor(t, k))
	if !errors.Is(err, ErrKeyExists) {
		t.Fatalf("%v", err)
	}
	if string(readKeyFile(t, keys, "A.openpgp.key.asc")) != "keep" {
		t.Error("the file changed")
	}
	if k.Saved() {
		t.Error("Saved")
	}
}

func TestTheTwoKeyFilesOfOneLabelLiveSideBySide(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveOpenPGP("A", k, certFor(t, k)); err != nil {
		t.Fatal(err)
	}
	other := mustGenerate(t)
	if err := s.SaveX509("B", other); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(dirNames(t, keys), " "); got != "A.openpgp.key.asc A.x509.key.pem B.x509.key.pem" {
		t.Errorf("the folder holds %q", got)
	}
	if got, err := s.OpenX509(bg(), "B"); err != nil || !samePublic(got, other) {
		t.Errorf("B: %v", err)
	}
}

func TestTheOpenedPrimaryKeepsWholeSecondsInUTCAndSignsASelfSignature(t *testing.T) {
	s, _, _ := openStore(t)
	k := mustGenerate(t)
	cert := certFor(t, k)
	if err := s.SaveOpenPGP("A", k, cert); err != nil {
		t.Fatal(err)
	}
	got, err := s.OpenOpenPGP(bg(), "A")
	if err != nil {
		t.Fatal(err)
	}
	if got.Created.Location().String() != "UTC" || got.Created.Nanosecond() != 0 {
		t.Errorf("creation time %v is not whole seconds in UTC", got.Created)
	}
	// A key that came from the file signs for the certificate: the primary's own key.
	if _, err := openpgp.ExtendPrimary(rand.Reader, openpgp.PrimaryParams{
		Key: got.Key, CreationTime: got.Created, CeremonyTime: testCeremony,
		ExpiresAt: testCeremony.AddDate(3, 0, 0), UserID: mustUserID(t),
	}); err != nil {
		t.Errorf("the opened key does not sign a self-signature: %v", err)
	}
}
