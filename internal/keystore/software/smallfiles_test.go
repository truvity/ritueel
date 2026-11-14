package software

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/openpgp"
)

var allReasons = []openpgp.Reason{openpgp.Compromised, openpgp.Superseded, openpgp.Retired, openpgp.NoReason}

func revocationFor(t testing.TB, k *Key, r openpgp.Reason) []byte {
	t.Helper()
	sig, err := openpgp.RevocationSignature(rand.Reader, openpgp.PrimaryParams{
		Key: k, CreationTime: testCreated, CeremonyTime: testCeremony, ExpiresAt: testCeremony.AddDate(3, 0, 0), UserID: mustUserID(t),
	}, r)
	if err != nil {
		t.Fatalf("RevocationSignature: %v", err)
	}
	return sig
}

func TestEachOfTheFourRevocationReasonsRoundTripsAsAnArmouredSignaturePacket(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	for _, r := range allReasons {
		sig := revocationFor(t, k, r)
		if err := s.SaveRevocation("A", r.Text, sig); err != nil {
			t.Fatalf("%s: %v", r.Text, err)
		}
		name := "A.revocation." + r.Text + ".asc"
		file := readKeyFile(t, keys, name)
		typ, headers, body := pgpUnarmor(t, file)
		if typ != "PGP SIGNATURE" || len(headers) != 1 || headers["Comment"] != "TEST ONLY" || !bytes.Equal(body, sig) {
			t.Errorf("%s: type %q headers %v, body equal %v", r.Text, typ, headers, bytes.Equal(body, sig))
		}
		if !bytes.HasPrefix(file, []byte("-----BEGIN PGP SIGNATURE-----\nComment: TEST ONLY\n\n")) || !bytes.HasSuffix(file, []byte("-----END PGP SIGNATURE-----\n")) {
			t.Errorf("%s: the armour is not the one of the page", r.Text)
		}
		got, err := s.ReadRevocation(bg(), "A", r.Text)
		if err != nil || !bytes.Equal(got, sig) {
			t.Errorf("%s: read back %v", r.Text, err)
		}
	}
	if got := len(dirNames(t, keys)); got != 4 {
		t.Errorf("%d files, want 4", got)
	}
	// A reason with no file is a missing file, not another reason's file.
	s2, _, _ := openStore(t)
	if _, err := s2.ReadRevocation(bg(), "A", "compromised"); !errors.Is(err, ErrKeyFile) {
		t.Errorf("no file: %v", err)
	}
}

func TestSaveRevocationAcceptsOnlyOneVersion4KeyRevocationPacketOfAtMost1KiB(t *testing.T) {
	k := mustGenerate(t)
	priv := k.s.priv
	cert := certFor(t, k)
	secrets := keysOf(t, k, cert)
	good := revocationFor(t, k, openpgp.Compromised)
	grown := func(total int) []byte {
		// Pad the unhashed area with a subpacket of a private type until the packet is total bytes.
		// The length of a signature varies by a byte or two with the signature itself (the two
		// integers lose a leading zero byte now and then), so the padding is adjusted by what is
		// missing and the signature is made again, until the length is right.
		pad := total - 300
		for attempt := 0; attempt < 400; attempt++ {
			p := pgpRevocation(t, priv, testCeremony, 0x20, pad)
			if len(p) == total {
				return p
			}
			pad += total - len(p)
			if pad < 1 {
				pad = 1
			}
		}
		t.Fatalf("no padding gives %d bytes", total)
		return nil
	}
	at1024, at1025 := grown(1024), grown(1025)
	cert3 := pgpRevocation(t, priv, testCeremony, 0x10, 0)
	subkeyRev := pgpRevocation(t, priv, testCeremony, 0x28, 0)
	v3 := bytes.Clone(good)
	v3[len(good)-len(pgpBody(good))] = 3 // the version byte, the first of the body
	// A version 3 signature of type 0x20 that parses: only its version tells it from a good one.
	v3real := pgpWrap(2, append(append(append([]byte{3, 5, 0x20}, make([]byte, 12)...), 19, 9, 0, 0),
		append(pgpMPI(big.NewInt(1<<40)), pgpMPI(big.NewInt(1<<41))...)...))
	cases := []struct {
		name string
		sig  []byte
		ok   bool
	}{
		{"a version 4 key revocation of the primary", good, true},
		{"a version 3 key revocation that parses", v3real, false},
		{"exactly 1024 bytes", at1024, true},
		{"1025 bytes", at1025, false},
		{"a certification (type 0x10)", cert3, false},
		{"a subkey revocation (type 0x28)", subkeyRev, false},
		{"a signature of type 0x00", pgpRevocation(t, priv, testCeremony, 0x00, 0), false},
		{"a version 3 signature", v3, false},
		{"a packet that does not parse", []byte{0xC2, 0x05, 1, 2, 3, 4, 5}, false},
		{"junk", bytes.Repeat([]byte{0xA5}, 100), false},
		{"empty", []byte{}, false},
		{"nil", nil, false},
		{"one trailing byte", append(bytes.Clone(good), 0), false},
		{"two packets", append(bytes.Clone(good), good...), false},
		{"a cut packet", good[:len(good)-1], false},
		{"a user ID packet", pgpWrap(13, []byte("Example Test")), false},
		{"a public key packet", pgpWrap(6, pgpKeyBody(&priv.PublicKey, testCreated)), false},
		{"3000 bytes", bytes.Repeat([]byte{0xC2}, 3000), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, keys := openStore(t)
			err := s.SaveRevocation("A", "compromised", c.sig)
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrParams) {
				t.Fatalf("the error is not ErrParams: %v", err)
			}
			if names := dirNames(t, keys); len(names) != 0 {
				t.Errorf("a file was written: %v", names)
			}
			if f := secrets.findText(err.Error()); f != "" {
				t.Errorf("the error text holds a canary (%s)", f)
			}
			// a refusal does not stop the store
			if err := s.SaveRevocation("A", "compromised", good); err != nil {
				t.Errorf("a good revocation after a refusal: %v", err)
			}
		})
	}
}

func TestSaveRevocationRefusesAReasonThatIsNotOneOfTheFour(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	good := revocationFor(t, k, openpgp.Compromised)
	for _, reason := range []string{"Compromised", "COMPROMISED", "stolen", "", "../x", "no_reason", "no reason", " compromised", "compromised ", "compromised\x00", "compromised.asc", "a/b", `a\b`, "é", strings.Repeat("a", 300)} {
		if err := s.SaveRevocation("A", reason, good); !errors.Is(err, ErrParams) {
			t.Errorf("reason %q: %v", reason, err)
		}
		if _, err := s.ReadRevocation(bg(), "A", reason); !errors.Is(err, ErrParams) {
			t.Errorf("read of reason %q: %v", reason, err)
		}
	}
	if names := dirNames(t, keys); len(names) != 0 {
		t.Errorf("files were written: %v", names)
	}
}

func TestReadRevocationRefusesAFileThatIsNotAnArmouredRevocationPacket(t *testing.T) {
	s, _, keys := openStore(t)
	k := mustGenerate(t)
	good := revocationFor(t, k, openpgp.Superseded)
	armor := func(typ string, h map[string]string, b []byte) []byte { return pgpArmor(t, typ, h, b) }
	files := map[string][]byte{
		"a certification packet":      armor("PGP SIGNATURE", testOnly, pgpRevocation(t, k.s.priv, testCeremony, 0x10, 0)),
		"the type PGP MESSAGE":        armor("PGP MESSAGE", testOnly, good),
		"the type of a secret key":    armor("PGP PRIVATE KEY BLOCK", testOnly, good),
		"no header":                   armor("PGP SIGNATURE", nil, good),
		"a second header":             armor("PGP SIGNATURE", map[string]string{"Comment": "TEST ONLY", "Version": "1"}, good),
		"a lower-case header":         armor("PGP SIGNATURE", map[string]string{"Comment": "test only"}, good),
		"two packets":                 armor("PGP SIGNATURE", testOnly, append(bytes.Clone(good), good...)),
		"a trailing byte":             armor("PGP SIGNATURE", testOnly, append(bytes.Clone(good), 0)),
		"the packet cut":              armor("PGP SIGNATURE", testOnly, good[:len(good)-2]),
		"an empty body":               armor("PGP SIGNATURE", testOnly, nil),
		"text after the end line":     append(armor("PGP SIGNATURE", testOnly, good), "x\n"...),
		"two final newlines":          append(armor("PGP SIGNATURE", testOnly, good), '\n'),
		"no armour at all":            good,
		"a signature over 1024 bytes": armor("PGP SIGNATURE", testOnly, pgpRevocation(t, k.s.priv, testCeremony, 0x20, 1100)),
	}
	for name, file := range files {
		t.Run(name, func(t *testing.T) {
			writeKeyFile(t, keys, "A.revocation.superseded.asc", file)
			got, err := s.ReadRevocation(bg(), "A", "superseded")
			if err == nil || got != nil || !errors.Is(err, ErrKeyFile) {
				t.Errorf("got %d bytes and %v", len(got), err)
			}
		})
	}
	writeKeyFile(t, keys, "A.revocation.superseded.asc", armor("PGP SIGNATURE", testOnly, good))
	if got, err := s.ReadRevocation(bg(), "A", "superseded"); err != nil || !bytes.Equal(got, good) {
		t.Errorf("the control: %v", err)
	}
}

func jwsOf(parts ...string) []byte {
	enc := make([]string, len(parts))
	for i, p := range parts {
		enc[i] = base64.RawURLEncoding.EncodeToString([]byte(p))
	}
	return []byte(strings.Join(enc, "."))
}

func TestRemovalRoundTripsAsTheTextOfTheJWSAndNothingElse(t *testing.T) {
	s, _, keys := openStore(t)
	jws := jwsOf(`{"alg":"ES384","typ":"example"}`, `{"version":1}`, "signature bytes")
	if err := s.SaveRemoval("A", jws); err != nil {
		t.Fatal(err)
	}
	if got := readKeyFile(t, keys, "A.removal.jws"); !bytes.Equal(got, jws) {
		t.Errorf("the file is %q, want the text of the JWS and nothing else", got)
	}
	got, err := s.ReadRemoval(bg(), "A")
	if err != nil || !bytes.Equal(got, jws) {
		t.Errorf("read back %q: %v", got, err)
	}
}

func TestSaveRemovalAcceptsThreeBase64urlPartsOfAtMost4KiBAndNothingElse(t *testing.T) {
	a := func(n int) string { return strings.Repeat("A", n) }
	cases := []struct {
		name string
		jws  string
		ok   bool
	}{
		{"three parts", "AAAA.BBBB.CCCC", true},
		{"parts that need no padding", "AA.AAA.AAAA", true},
		{"4096 bytes", a(1364) + "." + a(1364) + "." + a(1366), true},
		{"4097 bytes", a(1364) + "." + a(1364) + "." + a(1367), false},
		{"far over", a(5000) + "." + a(5000) + "." + a(5000), false},
		{"no dot", "AAAA", false},
		{"one dot", "AAAA.BBBB", false},
		{"four parts", "AAAA.BBBB.CCCC.DDDD", false},
		{"an empty first part", ".BBBB.CCCC", false},
		{"an empty middle part", "AAAA..CCCC", false},
		{"an empty last part", "AAAA.BBBB.", false},
		{"only dots", "..", false},
		{"empty", "", false},
		{"a plus sign", "AA+A.BBBB.CCCC", false},
		{"a slash", "AA/A.BBBB.CCCC", false},
		{"padding", "AAA=.BBBB.CCCC", false},
		{"a space", "AAAA .BBBB.CCCC", false},
		{"a newline at the end", "AAAA.BBBB.CCCC\n", false},
		{"a newline inside", "AAAA.BB\nBB.CCCC", false},
		{"a CR", "AAAA.BBBB.CCCC\r", false},
		{"a letter outside ASCII", "AAAé.BBBB.CCCC", false},
		{"a NUL", "AAAA.BB\x00B.CCCC", false},
		{"a part of one character", "A.BBBB.CCCC", false},
		{"left-over bits that are not zero", "AB.BBBB.CCCC", false},
		{"left-over bits in the last part", "AAAA.BBBB.AAAB", true}, // four characters have none
		{"left-over bits in a three-character part", "AAAA.BBBB.AAB", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, keys := openStore(t)
			err := s.SaveRemoval("A", []byte(c.jws))
			if c.ok {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrParams) {
				t.Fatalf("the error is not ErrParams: %v", err)
			}
			if names := dirNames(t, keys); len(names) != 0 {
				t.Errorf("a file was written: %v", names)
			}
		})
	}
	var nilStore *Store
	if err := nilStore.SaveRemoval("A", []byte("AAAA.BBBB.CCCC")); !errors.Is(err, ErrParams) {
		t.Errorf("a nil store: %v", err)
	}
}

func TestReadRemovalRefusesWhatSaveRemovalWouldRefuseAndAStrayNewline(t *testing.T) {
	s, _, keys := openStore(t)
	for name, content := range map[string]string{
		"two parts":                "AAAA.BBBB",
		"four parts":               "AAAA.BBBB.CCCC.DDDD",
		"a final newline":          "AAAA.BBBB.CCCC\n",
		"a CRLF":                   "AAAA.BBBB.CCCC\r\n",
		"padding":                  "AAA=.BBBB.CCCC",
		"empty":                    "",
		"4097 bytes":               strings.Repeat("A", 1364) + "." + strings.Repeat("A", 1364) + "." + strings.Repeat("A", 1367),
		"text of a JSON signature": `{"payload":"x"}`,
	} {
		t.Run(name, func(t *testing.T) {
			writeKeyFile(t, keys, "A.removal.jws", []byte(content))
			got, err := s.ReadRemoval(bg(), "A")
			if err == nil || got != nil || !errors.Is(err, ErrKeyFile) {
				t.Errorf("got %q and %v", got, err)
			}
		})
	}
}

func TestSmallFilesAreWrittenWithMode0600AndTheirOwnNames(t *testing.T) {
	s, _, keys := openStore(t)
	rec := record(s)
	k := mustGenerate(t)
	if err := s.SaveRevocation("B", "retired", revocationFor(t, k, openpgp.Retired)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveRemoval("B", jwsOf("a", "b", "c")); err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, w := range rec.writes {
		got = append(got, w.name+":"+w.perm.String())
	}
	if want := "B.revocation.retired.asc:-rw------- B.removal.jws:-rw-------"; strings.Join(got, " ") != want {
		t.Errorf("writes %q, want %q", strings.Join(got, " "), want)
	}
	for _, n := range dirNames(t, keys) {
		if filepath.Ext(n) == "" {
			t.Errorf("a name with no extension: %s", n)
		}
	}
}
