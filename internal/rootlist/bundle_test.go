package rootlist_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// bundleOf is a CA bundle as the page writes it: the first line and a block for each key.
func bundleOf(seq int, keys ...*key) string {
	var b strings.Builder
	b.WriteString("# trust-sequence: " + strconv.Itoa(seq) + "\n")
	for _, k := range keys {
		b.WriteString(k.certPEM())
	}
	return b.String()
}

// listFor is the accepted list that a bundle goes with.
func listFor(t testing.TB, seq int, keys ...*key) *rootlist.List {
	t.Helper()
	l, err := rootlist.ParseList(listOf(seq, keys...).json())
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func mismatch(t testing.TB, v rootlist.Verdict) {
	t.Helper()
	if v.Accepted || v.Reason != rootlist.CABundleMismatch || v.Check != 0 || v.List != nil {
		t.Fatalf("want ca-bundle-mismatch with no check and no list, got %+v", v)
	}
	if v.Detail == "" {
		t.Errorf("a refusal has no detail")
	}
	mustBeASCII(t, "Detail", v.Detail)
}

// reissued is another certificate over the key of k: another serial, the same public key.
func reissued(t testing.TB, k *key) string {
	t.Helper()
	tmpl := *k.cert
	tmpl.SerialNumber = big.NewInt(77)
	tmpl.Raw, tmpl.RawTBSCertificate, tmpl.RawSubjectPublicKeyInfo = nil, nil, nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &k.priv.PublicKey, k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestVerifyCABundleAccepts(t *testing.T) {
	w := newWorld(t)
	for _, c := range []struct {
		name   string
		seq    int
		keys   []*key
		bundle string
	}{
		{"two root keys", 7, []*key{w.a, w.b}, bundleOf(7, w.a, w.b)},
		{"one root key", 8, []*key{w.b}, bundleOf(8, w.b)},
		{"three root keys in the order of the list", 9, []*key{w.c, w.a, w.b}, bundleOf(9, w.c, w.a, w.b)},
		{"a sequence of several digits", 1234, []*key{w.a}, bundleOf(1234, w.a)},
		{"the largest sequence", 9007199254740991, []*key{w.a}, bundleOf(9007199254740991, w.a)},
		{"a certificate issued again over the same key", 7, []*key{w.a, w.b}, "# trust-sequence: 7\n" + reissued(t, w.a) + w.b.certPEM()},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := listFor(t, 1, c.keys...)
			l.Sequence = int64(c.seq)
			v := rootlist.VerifyCABundle([]byte(c.bundle), l)
			if !v.Accepted || v.Reason != "" || v.Check != 0 || v.Detail != "" || v.List != l {
				t.Fatalf("refused or wrong verdict: %+v", v)
			}
		})
	}
	t.Run("the certificate has the label CERTIFICATE and lines of 64 characters", func(t *testing.T) {
		// The reference text, written out: a change of how the test writes a block is seen here.
		b := w.a.certPEM()
		lines := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
		if lines[0] != "-----BEGIN CERTIFICATE-----" || lines[len(lines)-1] != "-----END CERTIFICATE-----" {
			t.Fatalf("the block is not armoured as RFC 7468 says: %q", lines)
		}
		for _, l := range lines[1 : len(lines)-2] {
			if len(l) != 64 {
				t.Fatalf("a line of %d characters", len(l))
			}
		}
		if n := len(lines[len(lines)-2]); n == 0 || n > 64 {
			t.Fatalf("the last line has %d characters", n)
		}
	})
}

func TestVerifyCABundleRefuses(t *testing.T) {
	w := newWorld(t)
	l := listFor(t, 7, w.a, w.b)
	a, b, c, z := w.a.certPEM(), w.b.certPEM(), w.c.certPEM(), w.z.certPEM()
	first := "# trust-sequence: 7\n"
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	body := func(pemText string) []string { return strings.Split(strings.TrimSuffix(pemText, "\n"), "\n") }
	lines := body(a)
	rewrapped := func(width int) string {
		b64 := strings.Join(lines[1:len(lines)-1], "")
		var out []string
		out = append(out, lines[0])
		for len(b64) > width {
			out = append(out, b64[:width])
			b64 = b64[width:]
		}
		out = append(out, b64, lines[len(lines)-1])
		return strings.Join(out, "\n") + "\n"
	}
	for _, tc := range []struct{ name, bundle string }{
		{"the root keys in the other order", first + b + a},
		{"one certificate missing", first + a},
		{"the other certificate missing", first + b},
		{"no certificate at all", first},
		{"an extra certificate", first + a + b + c},
		{"an extra certificate first", first + c + a + b},
		{"the same certificate twice", first + a + a},
		{"a certificate that is not on the list", first + a + z},
		{"a certificate of a key on no list in the first place", first + z + b},
		{"the sequence of the next list", "# trust-sequence: 8\n" + a + b},
		{"the sequence of the last list", "# trust-sequence: 6\n" + a + b},
		{"a sequence with another digit after it", "# trust-sequence: 70\n" + a + b},
		{"a sequence with a digit before it", "# trust-sequence: 17\n" + a + b},
		{"a leading zero", "# trust-sequence: 07\n" + a + b},
		{"a plus sign", "# trust-sequence: +7\n" + a + b},
		{"a trailing space on the first line", "# trust-sequence: 7 \n" + a + b},
		{"a tab on the first line", "# trust-sequence:\t7\n" + a + b},
		{"two spaces after the colon", "# trust-sequence:  7\n" + a + b},
		{"no space after the colon", "# trust-sequence:7\n" + a + b},
		{"no space after the hash", "#trust-sequence: 7\n" + a + b},
		{"two hashes", "## trust-sequence: 7\n" + a + b},
		{"a space before the hash", " # trust-sequence: 7\n" + a + b},
		{"the first line in capitals", "# TRUST-SEQUENCE: 7\n" + a + b},
		{"the first line with another word", "# trust-seq: 7\n" + a + b},
		{"the sequence in hexadecimal", "# trust-sequence: 0x7\n" + a + b},
		{"the sequence with a decimal point", "# trust-sequence: 7.0\n" + a + b},
		{"the sequence in Arabic-Indic digits", "# trust-sequence: \u0667\n" + a + b},
		{"a full-width digit", "# trust-sequence: \uff17\n" + a + b},
		{"no sequence", "# trust-sequence: \n" + a + b},
		{"no first line", a + b},
		{"an empty first line", "\n" + a + b},
		{"a first line with a carriage return", "# trust-sequence: 7\r\n" + a + b},
		{"the first line twice", first + first + a + b},
		{"a second comment line", first + "# a note\n" + a + b},
		{"a comment line after the first block", first + a + "# a note\n" + b},
		{"a byte order mark", "\xef\xbb\xbf" + first + a + b},
		{"a blank line before the first line", "\n" + first + a + b},
		{"a blank line after the first line", first + "\n" + a + b},
		{"a blank line between the blocks", first + a + "\n" + b},
		{"a blank line at the end", first + a + b + "\n"},
		{"text between the blocks", first + a + "text\n" + b},
		{"text before the first block on the line of the label", first + "x" + a + b},
		{"text on the line after the last block", first + a + b + "text\n"},
		{"text after the last block with no line end", first + a + b + "text"},
		{"a byte after the last block", first + a + b + "x"},
		{"a NUL after the last block", first + a + b + "\x00"},
		{"a space after the last block", first + a + b + " "},
		{"a second bundle after the first", first + a + b + first + a + b},
		{"carriage returns and line feeds", crlf(first + a + b)},
		{"carriage returns in the blocks only", first + crlf(a) + crlf(b)},
		{"a carriage return in one line of a block", first + strings.Replace(a, "\n", "\r\n", 2) + b},
		{"no final line feed", strings.TrimSuffix(first+a+b, "\n")},
		{"no line feed after the last line of the first block", first + strings.TrimSuffix(a, "\n") + b},
		{"a header line", first + strings.Replace(a, lines[0]+"\n", lines[0]+"\nProc-Type: 4,ENCRYPTED\n\n", 1) + b},
		{"a header line in the second block", first + a + strings.Replace(b, body(b)[0]+"\n", body(b)[0]+"\nNote: x\n\n", 1)},
		{"the label TRUSTED CERTIFICATE", first + strings.NewReplacer("BEGIN CERTIFICATE", "BEGIN TRUSTED CERTIFICATE", "END CERTIFICATE", "END TRUSTED CERTIFICATE").Replace(a) + b},
		{"the label X509 CERTIFICATE", first + strings.NewReplacer("BEGIN CERTIFICATE", "BEGIN X509 CERTIFICATE", "END CERTIFICATE", "END X509 CERTIFICATE").Replace(a) + b},
		{"the label in lower case", first + strings.NewReplacer("BEGIN CERTIFICATE", "BEGIN certificate", "END CERTIFICATE", "END certificate").Replace(a) + b},
		{"the label of a public key", first + strings.NewReplacer("CERTIFICATE", "PUBLIC KEY").Replace(a) + b},
		{"the label CERTIFICATE REQUEST", first + strings.NewReplacer("BEGIN CERTIFICATE", "BEGIN CERTIFICATE REQUEST", "END CERTIFICATE", "END CERTIFICATE REQUEST").Replace(a) + b},
		{"a block whose end names another label", first + strings.Replace(a, "END CERTIFICATE", "END PUBLIC KEY", 1) + b},
		{"a block with no end", first + strings.TrimSuffix(a, lines[len(lines)-1]+"\n") + b},
		{"a block with no begin", first + strings.TrimPrefix(a, lines[0]+"\n") + b},
		{"a block with five dashes short", first + strings.Replace(a, "-----BEGIN", "----BEGIN", 1) + b},
		{"lines of 76 characters", first + rewrapped(76) + b},
		{"lines of 32 characters", first + rewrapped(32) + b},
		{"lines of 65 characters", first + rewrapped(65) + b},
		{"lines of 63 characters", first + rewrapped(63) + b},
		{"one long line", first + rewrapped(100000) + b},
		{"a trailing space on a line of a block", first + strings.Replace(a, lines[1]+"\n", lines[1]+" \n", 1) + b},
		{"a leading space on a line of a block", first + strings.Replace(a, lines[1]+"\n", " "+lines[1]+"\n", 1) + b},
		{"a trailing space after the begin line", first + strings.Replace(a, lines[0]+"\n", lines[0]+" \n", 1) + b},
		{"base64 that is not base64", first + strings.Replace(a, lines[1], "!"+lines[1][1:], 1) + b},
		{"a block that is Base64 and no certificate", first + "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n" + b},
		{"an empty block", first + "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n" + b},
		{"a certificate with a byte after it", first + pemOf(append(append([]byte{}, w.a.cert.Raw...), 0)) + b},
		{"a certificate cut short", first + pemOf(w.a.cert.Raw[:len(w.a.cert.Raw)-1]) + b},
		{"the key of a certificate in the place of the certificate", first + pemOf(spkiOf(t, w.a)) + b},
		{"nothing", ""},
		{"a line feed", "\n"},
		{"the first line with no line feed", "# trust-sequence: 7"},
		{"the certificates with no first line and a comment elsewhere", a + "# trust-sequence: 7\n" + b},
	} {
		t.Run(tc.name, func(t *testing.T) { mismatch(t, rootlist.VerifyCABundle([]byte(tc.bundle), l)) })
	}
	t.Run("nil bytes", func(t *testing.T) { mismatch(t, rootlist.VerifyCABundle(nil, l)) })
	t.Run("the witness", func(t *testing.T) {
		if v := rootlist.VerifyCABundle([]byte(first+a+b), l); !v.Accepted {
			t.Fatalf("%+v", v)
		}
	})
	t.Run("a bundle for a list with other root keys", func(t *testing.T) {
		mismatch(t, rootlist.VerifyCABundle([]byte(first+a+b), listFor(t, 7, w.a, w.c)))
		mismatch(t, rootlist.VerifyCABundle([]byte(first+a+b), listFor(t, 7, w.b, w.a)))
		mismatch(t, rootlist.VerifyCABundle([]byte(first+a+b), listFor(t, 7, w.a)))
		mismatch(t, rootlist.VerifyCABundle([]byte(first+a+b), listFor(t, 7, w.a, w.b, w.c)))
		mismatch(t, rootlist.VerifyCABundle([]byte(first+a+b), listFor(t, 8, w.a, w.b)))
	})
}

func pemOf(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func spkiOf(t testing.TB, k *key) []byte {
	t.Helper()
	return k.cert.RawSubjectPublicKeyInfo
}

func TestVerifyCABundleNeedsAnAcceptedList(t *testing.T) {
	// A nil list or one with no root key is a fault of the caller, not of a file: it panics.
	for name, l := range map[string]*rootlist.List{"nil": nil, "empty": {}, "no roots": {Sequence: 7}} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("no panic")
				}
			}()
			rootlist.VerifyCABundle([]byte("# trust-sequence: 7\n"), l)
		})
	}
}

func TestVerifyCABundleDoesNotChangeItsInput(t *testing.T) {
	w := newWorld(t)
	data := []byte(bundleOf(7, w.a, w.b))
	copyOf := string(data)
	rootlist.VerifyCABundle(data, listFor(t, 7, w.a, w.b))
	if string(data) != copyOf {
		t.Errorf("the bundle was changed")
	}
}
