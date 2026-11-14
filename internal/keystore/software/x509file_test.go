package software

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"ritueel.id/ritueel/internal/verifier"
)

func TestSaveX509ThenOpenX509GivesTheSameKeyAndTheFileIsTheMarkerLineAndOnePEMBlock(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatalf("SaveX509: %v", err)
	}
	if !k.Saved() {
		t.Error("the key is not Saved after the save")
	}
	got := readKeyFile(t, keys, "A.x509.key.pem")
	// The expected file is built here, not by the code under test.
	var priv *ecdsa.PrivateKey
	_ = k.withPrivate(func(p *ecdsa.PrivateKey) error { priv = p; return nil })
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	want := "TEST ONLY: a test root with no passphrase; anyone with this file can sign as this root.\n" +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if string(got) != want {
		t.Errorf("the file is not the marker line, LF and one PEM block:\n%q", got[:min(len(got), 120)])
	}
	lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
	if lines[0] != testMarker || lines[1] != armourLine("BEGIN", "PRIVATE KEY") || lines[len(lines)-1] != armourLine("END", "PRIVATE KEY") {
		t.Errorf("the lines are %q ... %q", lines[:2], lines[len(lines)-1])
	}
	for _, l := range lines[2 : len(lines)-1] {
		if len(l) > 64 {
			t.Errorf("a line of the body has %d characters", len(l))
		}
	}
	if bytes.ContainsRune(got, '\r') || !bytes.HasSuffix(got, []byte("-----\n")) || bytes.HasSuffix(got, []byte("\n\n")) {
		t.Error("the file has a CR, or does not end in exactly one LF")
	}

	again, err := s.OpenX509(bg(), "A")
	if err != nil {
		t.Fatalf("OpenX509: %v", err)
	}
	defer func() { _ = again.Close() }()
	if !samePublic(k, again) {
		t.Error("the key that was opened is not the key that was saved")
	}
	if !bytes.Equal(scalarBytes(t, k), scalarBytes(t, again)) {
		t.Error("the scalar differs")
	}
	if again.Saved() {
		t.Error("a key that was opened is Saved: the call that opened it saved nothing")
	}
	d := digest48()
	sig, err := again.Sign(nil, d, crypto.SHA384)
	if err != nil || !ecdsa.VerifyASN1(k.Public().(*ecdsa.PublicKey), d, sig) {
		t.Errorf("the opened key does not sign for the saved one: %v", err)
	}
	for _, n := range dirNames(t, keys) {
		if strings.HasPrefix(n, ".rt-") {
			t.Errorf("a temporary file stays: %s", n)
		}
	}
}

func TestAnotherStoreOnTheSameFolderOpensTheSavedKey(t *testing.T) {
	s, bundle, keys := openStore(t)
	k := mustGenerate(t)
	if err := s.SaveX509("B", k); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(Config{KeyDir: keys, BundleDir: bundle, Mode: ModeTest})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	k2, err := s2.OpenX509(bg(), "B")
	if err != nil || !samePublic(k, k2) {
		t.Fatalf("a second store does not open the key: %v", err)
	}
	defer func() { _ = k2.Close() }()
	if _, err := s2.OpenX509(bg(), "A"); !errors.Is(err, ErrKeyFile) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a label with no file: %v (want ErrKeyFile that wraps fs.ErrNotExist)", err)
	}
}

// The umask is a property of the process, so these two tests do not run in parallel.
func TestTheKeyFileIs0600WhateverTheUmaskIs(t *testing.T) {
	for _, mask := range []int{0o022, 0o000, 0o077, 0o277} {
		s, _, keys := openStore(t)
		k := mustGenerate(t)
		old := syscall.Umask(mask)
		err := s.SaveX509("A", k)
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("umask %04o: %v", mask, err)
		}
		info, err := os.Stat(filepath.Join(keys, "A.x509.key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		want := fs.FileMode(0o600) &^ fs.FileMode(mask)
		if info.Mode().Perm() != want {
			t.Errorf("umask %04o: mode %v, want %v", mask, info.Mode().Perm(), want)
		}
	}
}

func TestEveryWriteAsksFor0600AndForTheNameOfAFileOnly(t *testing.T) {
	s, _, _ := openStore(t)
	rec := record(s)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	if len(rec.writes) != 1 {
		t.Fatalf("%d writes, want 1", len(rec.writes))
	}
	w := rec.writes[0]
	if w.perm != 0o600 || w.name != "A.x509.key.pem" || strings.ContainsAny(w.name, `/\`) {
		t.Errorf("the write is %q with mode %v", w.name, w.perm)
	}
}

// OpenSSL is a second reader of the file. It skips the line before the armour.
func TestOpenSSLReadsTheKeyFileAndFindsTheSamePublicKey(t *testing.T) {
	bin := verifier.Require(t, "openssl")
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(keys, "A.x509.key.pem")
	run := func(args ...string) ([]byte, string) {
		ctx, cancel := context.WithTimeout(bg(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("openssl %v: %v: %s", args[0], err, stderr.String())
		}
		return out, stderr.String()
	}
	out, _ := run("pkey", "-in", path, "-noout", "-check")
	if !strings.Contains(string(out), "Key is valid") {
		t.Errorf("openssl pkey -check prints %q, want Key is valid", out)
	}
	pubDER, _ := run("pkey", "-in", path, "-pubout", "-outform", "DER")
	want, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubDER, want) {
		t.Error("the public key that OpenSSL finds is not the public key of the key")
	}
	text, _ := run("pkey", "-in", path, "-noout", "-text")
	if !strings.Contains(string(text), "NIST CURVE: P-384") && !strings.Contains(string(text), "secp384r1") {
		t.Errorf("OpenSSL does not name the curve P-384: %q", text[:min(len(text), 200)])
	}
}

// hand-made PKCS#8 of an EC key, with the knobs of a bad one. It is written here with
// encoding/asn1, apart from the reader under test.
var (
	testOIDEC   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	testOIDP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	testOIDP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	testOIDP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

type testPKCS8 struct {
	Version int
	Algo    pkix.AlgorithmIdentifier
	Key     []byte
}

type testECKey struct {
	Version int
	Priv    []byte
	Curve   asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	Pub     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pk8Knobs struct {
	version    int // of the wrapper
	ecVersion  int
	wrapperOID asn1.ObjectIdentifier
	curve      asn1.ObjectIdentifier // in the ECPrivateKey; nil leaves it out
	pub        []byte                // in the ECPrivateKey; nil leaves it out
	pubBits    int                   // the bit length of that bit string, when it is not a whole number of bytes
	extraInner []byte                // a whole DER element after the last field of the ECPrivateKey
	extraOuter []byte                // a whole DER element after the last field of the wrapper
	trailing   []byte                // bytes after the whole DER
}

func goodKnobs() pk8Knobs {
	return pk8Knobs{ecVersion: 1, wrapperOID: testOIDP384}
}

func marshalFail(t testing.TB, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// buildPKCS8 writes the DER of a PKCS#8 with the scalar given, as the knobs say.
func buildPKCS8(t testing.TB, scalar []byte, kn pk8Knobs) []byte {
	t.Helper()
	ec := testECKey{Version: kn.ecVersion, Priv: scalar, Curve: kn.curve}
	if kn.pub != nil {
		ec.Pub = asn1.BitString{Bytes: kn.pub, BitLength: 8 * len(kn.pub)}
		if kn.pubBits != 0 {
			ec.Pub.BitLength = kn.pubBits
		}
	}
	inner := marshalFail(t, ec)
	if kn.extraInner != nil {
		// put the element inside the SEQUENCE of the ECPrivateKey
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(inner, &raw); err != nil {
			t.Fatal(err)
		}
		inner = marshalFail(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(bytes.Clone(raw.Bytes), kn.extraInner...)})
	}
	params := marshalFail(t, kn.wrapperOID)
	outer := testPKCS8{Version: kn.version, Algo: pkix.AlgorithmIdentifier{Algorithm: testOIDEC, Parameters: asn1.RawValue{FullBytes: params}}, Key: inner}
	der := marshalFail(t, outer)
	if kn.extraOuter != nil {
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(der, &raw); err != nil {
			t.Fatal(err)
		}
		der = marshalFail(t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: append(bytes.Clone(raw.Bytes), kn.extraOuter...)})
	}
	return append(der, kn.trailing...)
}

func pointOf(t testing.TB, k *Key) []byte {
	t.Helper()
	b, err := k.publicCopy().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// x509Refusal is a file that OpenX509 must refuse.
type x509Refusal struct {
	name string
	file []byte
}

func x509Refusals(t testing.TB, k *Key) []x509Refusal {
	t.Helper()
	good := pemOf(t, k)
	marker := []byte(testMarker + "\n")
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	scalar := scalarBytes(t, k)
	point := pointOf(t, k)
	var priv *ecdsa.PrivateKey
	_ = k.withPrivate(func(p *ecdsa.PrivateKey) error { priv = p; return nil })
	der := derOf(t, priv)
	order := elliptic.P384().Params().N
	other := mustGenerate(t)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8Of := func(key any) []byte {
		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	sec1, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	bigger := new(big.Int).Add(order, big.NewInt(1)).FillBytes(make([]byte, 48))
	withTweak := func(f func(*pk8Knobs)) []byte {
		kn := goodKnobs()
		f(&kn)
		return pemFile("PRIVATE KEY", buildPKCS8(t, scalar, kn))
	}
	withScalar := func(sc []byte, f func(*pk8Knobs)) []byte {
		kn := goodKnobs()
		if f != nil {
			f(&kn)
		}
		return pemFile("PRIVATE KEY", buildPKCS8(t, sc, kn))
	}
	wide := bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n"))
	b64 := strings.Join(strings.Split(strings.TrimSpace(string(good)), "\n")[1:len(strings.Split(strings.TrimSpace(string(good)), "\n"))-1], "")
	var wrapped76 strings.Builder
	wrapped76.WriteString(armourLine("BEGIN", "PRIVATE KEY") + "\n")
	for len(b64) > 0 {
		n := min(76, len(b64))
		wrapped76.WriteString(b64[:n] + "\n")
		b64 = b64[n:]
	}
	wrapped76.WriteString(armourLine("END", "PRIVATE KEY") + "\n")
	withHeaders := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der})

	return []x509Refusal{
		{"an empty file", nil},
		{"only the marker line", marker},
		{"only a newline", []byte("\n")},
		{"no marker line", good},
		{"the marker with one word changed", cat([]byte(strings.Replace(testMarker, "anyone", "anybody", 1)+"\n"), good)},
		{"the marker in lower case", cat([]byte(strings.ToLower(testMarker)+"\n"), good)},
		{"the marker cut short", cat([]byte(testMarker[:len(testMarker)-1]+"\n"), good)},
		{"the marker with a trailing space", cat([]byte(testMarker+" \n"), good)},
		{"the marker with a leading space", cat([]byte(" "+testMarker+"\n"), good)},
		{"a byte order mark before the marker", cat([]byte("\xEF\xBB\xBF"), marker, good)},
		{"a blank line before the marker", cat([]byte("\n"), marker, good)},
		{"another line before the marker", cat([]byte("a note\n"), marker, good)},
		{"the marker twice", cat(marker, marker, good)},
		{"no newline after the marker", cat([]byte(testMarker), good)},
		{"a CR LF after the marker", cat([]byte(testMarker+"\r\n"), good)},
		{"a blank line between the marker and the block", cat(marker, []byte("\n"), good)},
		{"CRLF line ends all through", wide},
		{"two PEM blocks", cat(marker, good, good)},
		{"two blocks of two keys", cat(marker, good, pemOf(t, other))},
		{"the label EC PRIVATE KEY", cat(marker, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))},
		{"the label EC PRIVATE KEY over the PKCS#8", pemFile("EC PRIVATE KEY", der)},
		{"the label ENCRYPTED PRIVATE KEY", pemFile("ENCRYPTED PRIVATE KEY", der)},
		{"the label RSA PRIVATE KEY", pemFile("RSA PRIVATE KEY", der)},
		{"the label CERTIFICATE", pemFile("CERTIFICATE", der)},
		{"the label PUBLIC KEY", pemFile("PUBLIC KEY", der)},
		{"the label in lower case", pemFile("private key", der)},
		{"a header line in the block", cat(marker, withHeaders)},
		{"text after the block", cat(marker, good, []byte("a note\n"))},
		{"text after the block with no newline", cat(marker, good, []byte("a note"))},
		{"a space after the block", cat(marker, good, []byte(" "))},
		{"two final newlines", cat(marker, good, []byte("\n"))},
		{"a NUL after the block", cat(marker, good, []byte{0})},
		{"text between the marker and the block", cat(marker, []byte("note\n"), good)},
		{"lines of 76 characters", cat(marker, []byte(wrapped76.String()))},
		{"a block with no end line", cat(marker, good[:len(good)-len(armourLine("END", "PRIVATE KEY")+"\n")])},
		{"a block with no begin line", cat(marker, good[len(armourLine("BEGIN", "PRIVATE KEY")+"\n"):])},
		{"the DER with one trailing byte", withScalar(scalar, func(kn *pk8Knobs) { kn.trailing = []byte{0} })},
		{"the DER cut by one byte", pemFile("PRIVATE KEY", der[:len(der)-1])},
		{"the DER with one byte changed in the scalar", pemFile("PRIVATE KEY", append(append(bytes.Clone(der[:40]), der[40]^1), der[41:]...))},
		{"a PKCS#8 of P-256", pemFile("PRIVATE KEY", pkcs8Of(p256))},
		{"a PKCS#8 of P-521", pemFile("PRIVATE KEY", pkcs8Of(p521))},
		{"a PKCS#8 of RSA-2048", pemFile("PRIVATE KEY", pkcs8Of(rsaKey))},
		{"a PKCS#8 of Ed25519", pemFile("PRIVATE KEY", pkcs8Of(edKey))},
		{"a PKCS#8 of X25519", pemFile("PRIVATE KEY", pkcs8Of(xKey))},
		{"a P-384 scalar under the OID of P-256", withTweak(func(kn *pk8Knobs) { kn.wrapperOID = testOIDP256 })},
		{"a P-384 scalar under the OID of P-521", withTweak(func(kn *pk8Knobs) { kn.wrapperOID = testOIDP521 })},
		{"a curve of P-256 inside the ECPrivateKey", withTweak(func(kn *pk8Knobs) { kn.curve = testOIDP256 })},
		{"a scalar of zero", withScalar(make([]byte, 48), nil)},
		{"a scalar equal to the group order", withScalar(order.FillBytes(make([]byte, 48)), nil)},
		{"a scalar above the group order", withScalar(bigger, nil)},
		{"a scalar of all ones", withScalar(bytes.Repeat([]byte{0xFF}, 48), nil)},
		{"a scalar of 47 bytes", withScalar(scalar[1:], nil)},
		{"a scalar of 49 bytes", withScalar(append([]byte{0}, scalar...), nil)},
		{"an empty scalar", withScalar([]byte{}, nil)},
		{"a public point of another key", withTweak(func(kn *pk8Knobs) { kn.pub = pointOf(t, other) })},
		{"a public point with one byte changed", withTweak(func(kn *pk8Knobs) {
			kn.pub = append(bytes.Clone(point[:50]), append([]byte{point[50] ^ 1}, point[51:]...)...)
		})},
		{"a public point in a bit string with one unused bit", withTweak(func(kn *pk8Knobs) { kn.pub = point; kn.pubBits = 8*len(point) - 1 })},
		{"a public point in a bit string of 8 unused bits", withTweak(func(kn *pk8Knobs) { kn.pub = append(bytes.Clone(point), 0); kn.pubBits = 8 * len(point) })},
		{"a public point of 96 bytes", withTweak(func(kn *pk8Knobs) { kn.pub = point[:96] })},
		{"a compressed public point", withTweak(func(kn *pk8Knobs) { kn.pub = append([]byte{2 + point[96]&1}, point[1:49]...) })},
		{"a public point of one byte", withTweak(func(kn *pk8Knobs) { kn.pub = []byte{4} })},
		{"a wrapper of version 1", withTweak(func(kn *pk8Knobs) { kn.version = 1 })},
		{"an ECPrivateKey of version 0", withTweak(func(kn *pk8Knobs) { kn.ecVersion = 0 })},
		{"an ECPrivateKey of version 2", withTweak(func(kn *pk8Knobs) { kn.ecVersion = 2 })},
		{"an element after the ECPrivateKey fields", withTweak(func(kn *pk8Knobs) { kn.extraInner = marshalFail(t, 7) })},
		{"an attribute after the key in the wrapper", withTweak(func(kn *pk8Knobs) {
			kn.extraOuter = marshalFail(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: nil})
		})},
		{"a public key after the key in the wrapper", withTweak(func(kn *pk8Knobs) {
			kn.extraOuter = marshalFail(t, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: []byte{0, 1, 2}})
		})},
	}
}

func TestOpenX509RefusesEveryFileThatIsNotExactlyTheShapeOfThePage(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	secrets := keysOf(t, k, nil)
	for _, c := range x509Refusals(t, k) {
		t.Run(c.name, func(t *testing.T) {
			writeKeyFile(t, keys, "A.x509.key.pem", c.file)
			key, err := s.OpenX509(bg(), "A")
			if err == nil {
				_ = key.Close()
				t.Fatal("accepted")
			}
			if key != nil {
				t.Error("a refusal returned a key")
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

// Controls for the table above: the shapes that the page allows are accepted, so that a refusal
// above is a refusal of the thing that was changed and not of the helper.
func TestOpenX509AcceptsTheShapesThatThePageAllows(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	scalar := scalarBytes(t, k)
	point := pointOf(t, k)
	cases := []struct {
		name string
		file []byte
	}{
		{"the file as it is written", x509File(t, k)},
		{"a missing final newline is accepted", bytes.TrimSuffix(x509File(t, k), []byte("\n"))},
		{"the scalar alone", pemFile("PRIVATE KEY", buildPKCS8(t, scalar, goodKnobs()))},
		{"the scalar and the curve", pemFile("PRIVATE KEY", buildPKCS8(t, scalar, pk8Knobs{ecVersion: 1, wrapperOID: testOIDP384, curve: testOIDP384}))},
		{"the scalar, the curve and the point", pemFile("PRIVATE KEY", buildPKCS8(t, scalar, pk8Knobs{ecVersion: 1, wrapperOID: testOIDP384, curve: testOIDP384, pub: point}))},
		{"the scalar and the point", pemFile("PRIVATE KEY", buildPKCS8(t, scalar, pk8Knobs{ecVersion: 1, wrapperOID: testOIDP384, pub: point}))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeKeyFile(t, keys, "A.x509.key.pem", c.file)
			got, err := s.OpenX509(bg(), "A")
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			defer func() { _ = got.Close() }()
			if !samePublic(k, got) {
				t.Error("another key")
			}
		})
	}
}

func TestAScalarWithLeadingZeroBytesRoundTripsThroughTheFile(t *testing.T) {
	s, _, _ := openStore(t)
	for i := 0; i < 5000; i++ {
		k := mustGenerate(t)
		if scalarBytes(t, k)[0] != 0 {
			continue
		}
		if err := s.SaveX509("A", k); err != nil {
			t.Fatalf("a key with a leading zero byte: %v", err)
		}
		got, err := s.OpenX509(bg(), "A")
		if err != nil || !samePublic(k, got) {
			t.Fatalf("a key with a leading zero byte does not read back: %v", err)
		}
		return
	}
	t.Skip("no scalar with a leading zero byte in 5000 keys")
}

func TestOpenX509RefusesAFileOfTheLimitThatIsJunkAndAFileOverTheLimitBeforeAnyParse(t *testing.T) {
	s, _, keys := openStore(t)
	rec := recordFormat(s)
	junk := func(n int) []byte {
		return append([]byte(testMarker+"\n"), bytes.Repeat([]byte("a"), n-len(testMarker)-1)...)
	}
	writeKeyFile(t, keys, "A.x509.key.pem", junk(MaxKeyFileSize))
	if _, err := s.OpenX509(bg(), "A"); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a junk file of the limit: %v", err)
	}
	if rec.unwraps != 1 || rec.lastLen != MaxKeyFileSize {
		t.Errorf("the parser was called %d times (length %d): a file of exactly the limit is read", rec.unwraps, rec.lastLen)
	}
	writeKeyFile(t, keys, "A.x509.key.pem", junk(MaxKeyFileSize+1))
	if _, err := s.OpenX509(bg(), "A"); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a junk file over the limit: %v", err)
	}
	if rec.unwraps != 1 {
		t.Errorf("the parser was called for a file over the limit (%d calls in all)", rec.unwraps)
	}
	// A file that is whole and valid but too long (padding after the block) is refused by size.
	k := mustGenerate(t)
	writeKeyFile(t, keys, "A.x509.key.pem", append(x509File(t, k), bytes.Repeat([]byte("\n"), MaxKeyFileSize)...))
	if _, err := s.OpenX509(bg(), "A"); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a valid key file with padding over the limit: %v", err)
	}
	if rec.unwraps != 1 {
		t.Error("the parser was called for a padded file over the limit")
	}
}

func TestOpenX509RefusesAFileLongerThanTheReaderOfTheFolderReads(t *testing.T) {
	s, _, keys := openStore(t)
	rec := recordFormat(s)
	writeKeyFile(t, keys, "A.x509.key.pem", bytes.Repeat([]byte("a"), 8<<20+1))
	if _, err := s.OpenX509(bg(), "A"); !errors.Is(err, ErrKeyFile) {
		t.Errorf("a file of 8 MiB and one byte: %v", err)
	}
	if rec.unwraps != 0 {
		t.Error("the parser was called")
	}
}

func TestOpenX509RefusesAnythingThatIsNotARegularFileAndDoesNotWait(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, x509File(t, k), 0o600); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(keys, "A.x509.key.pem")
	makers := map[string]func(){
		"a symbolic link to a good key file": func() {
			if err := os.Symlink(target, name); err != nil {
				t.Fatal(err)
			}
		},
		"a dangling symbolic link": func() {
			if err := os.Symlink(filepath.Join(keys, "nowhere"), name); err != nil {
				t.Fatal(err)
			}
		},
		"a symbolic link to the key folder": func() {
			if err := os.Symlink(keys, name); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func() {
			if err := os.Mkdir(name, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"a named pipe with nobody writing": func() {
			if err := syscall.Mkfifo(name, 0o600); err != nil {
				t.Skipf("no named pipes here: %v", err)
			}
		},
	}
	for what, make := range makers {
		t.Run(what, func(t *testing.T) {
			make()
			defer func() { _ = os.Remove(name) }()
			got, err := s.OpenX509(bg(), "A")
			if err == nil {
				_ = got.Close()
				t.Fatal("accepted")
			}
			if got != nil || !errors.Is(err, ErrKeyFile) {
				t.Errorf("got %v and %v", got, err)
			}
			if strings.Contains(err.Error(), keys) {
				t.Error("the error holds the key folder")
			}
		})
	}
}

func TestSaveX509OverAnythingThatStandsAtTheNameIsErrKeyExists(t *testing.T) {
	for what, make := range map[string]func(name string){
		"a file": func(name string) { _ = os.WriteFile(name, []byte("keep"), 0o600) },
		"a folder": func(name string) {
			_ = os.Mkdir(name, 0o700)
		},
		"a dangling link": func(name string) { _ = os.Symlink(name+".nowhere", name) },
	} {
		t.Run(what, func(t *testing.T) {
			s, _, keys := openStore(t)
			name := filepath.Join(keys, "A.x509.key.pem")
			make(name)
			k := mustGenerate(t)
			err := s.SaveX509("A", k)
			if !errors.Is(err, ErrKeyExists) || Code(err) != "key-exists" {
				t.Fatalf("the error is %v (code %q)", err, Code(err))
			}
			if k.Saved() {
				t.Error("Saved is true")
			}
			if what == "a file" {
				if got := readKeyFile(t, keys, "A.x509.key.pem"); string(got) != "keep" {
					t.Error("the existing file changed")
				}
			}
		})
	}
}

func TestContextIsCheckedBeforeTheFileIsRead(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	if err := s.SaveX509("A", k); err != nil {
		t.Fatal(err)
	}
	rec := recordFormat(s)
	ctx, cancel := context.WithCancel(bg())
	cancel()
	got, err := s.OpenX509(ctx, "A")
	if got != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled context: %v, %v", got, err)
	}
	if rec.unwraps != 0 {
		t.Error("a file was parsed for a cancelled context")
	}
	//nolint:staticcheck // a nil context is the case under test
	if got, err := s.OpenX509(nil, "A"); got != nil || !errors.Is(err, ErrParams) {
		t.Errorf("a nil context: %v, %v", got, err)
	}
	if len(dirNames(t, keys)) != 1 {
		t.Errorf("the folder holds %v", dirNames(t, keys))
	}
}
