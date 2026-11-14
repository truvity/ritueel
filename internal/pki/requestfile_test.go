package pki_test

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The request file, `<stem>.csr.pem` of the hand-off contract: "a PKCS#10 certificate request (RFC 2986), PEM-armoured with
// the label CERTIFICATE REQUEST. The file holds one such block and nothing else." ParseRequestFile reads the lines of one block
// that start at the first octet, with LF or CRLF throughout, lines of base64 of 1 to 76 characters that are the one standard text of
// the DER, and at most one final line end. Every file that it accepts is one that `openssl req -verify` accepts too; what OpenSSL does
// with the files that it refuses is logged, and a file that OpenSSL reads and the package does not is the refusing direction (the
// package is the stricter reader, on purpose). requestfile_rule_test.go holds the rule against a second statement of it.

func armor(der []byte, label string, lineEnd string) string {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN " + label + "-----" + lineEnd)
	for len(b64) > 64 {
		sb.WriteString(b64[:64] + lineEnd)
		b64 = b64[64:]
	}
	sb.WriteString(b64 + lineEnd)
	sb.WriteString("-----END " + label + "-----")
	return sb.String()
}

// wrapFile is the file of a request: the begin line, the base64 text of the DER in lines of n characters (the last may be shorter),
// the end line, each line end eol, and final after the end line.
func wrapFile(der []byte, n int, eol, final string) string {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN CERTIFICATE REQUEST-----" + eol)
	for len(b64) > n {
		sb.WriteString(b64[:n] + eol)
		b64 = b64[n:]
	}
	sb.WriteString(b64 + eol)
	sb.WriteString("-----END CERTIFICATE REQUEST-----" + final)
	return sb.String()
}

// opensslVerifiesRequest runs `openssl req -in FILE -noout -verify` and says whether it accepts the file: exit 0 and "verify OK".
func opensslVerifiesRequest(t *testing.T, content []byte) (bool, string) {
	t.Helper()
	bin := verifier.Require(t, "openssl")
	file := filepath.Join(t.TempDir(), "request.csr.pem")
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "req", "-in", file, "-noout", "-verify").CombinedOutput()
	text := strings.TrimSpace(string(out))
	return err == nil && strings.Contains(text, "verify OK"), text
}

func TestParseRequestFile(t *testing.T) {
	good := goodRequest(t)
	der := good.DER()
	label := "CERTIFICATE REQUEST"
	one := armor(der, label, "\n")
	second := armor(goodRequest(t).DER(), label, "\n")
	type row struct {
		name   string
		file   string
		accept bool
		words  string
	}
	rows := []row{
		{"one block with a final line end", one + "\n", true, ""},
		{"one block with no final line end", one, true, ""},
		{"one block of LF lines with a CRLF final line end (the two kinds of line end are mixed)", one + "\r\n", false, "not a PEM block"},
		{"one block of CRLF lines with an LF final line end (the two kinds of line end are mixed)", armor(der, label, "\r\n") + "\n", false, "not a PEM block"},
		{"one block with lines of 76 characters", wrapFile(der, 76, "\n", "\n"), true, ""},
		{"one block with lines of 1 character", wrapFile(der, 1, "\n", ""), true, ""},
		{"one block with a CRLF after every line", armor(der, label, "\r\n") + "\r\n", true, ""},
		{"one block with a CRLF after every line and no final line end", armor(der, label, "\r\n"), true, ""},
		{"text before the block", "a request:\n" + one + "\n", false, "does not start with a PEM block"},
		{"a line end before the block", "\n" + one + "\n", false, "does not start with a PEM block"},
		{"a space before the block", " " + one + "\n", false, "does not start with a PEM block"},
		{"a byte order mark before the block", "\xef\xbb\xbf" + one + "\n", false, "does not start with a PEM block"},
		{"a second block of the same request", one + "\n" + one + "\n", false, "something after its PEM block"},
		{"a second block of another request", one + "\n" + second + "\n", false, "something after its PEM block"},
		{"text after the block", one + "\nthe end\n", false, "something after its PEM block"},
		{"a second line end after the block", one + "\n\n", false, "something after its PEM block"},
		{"a space after the begin line", "-----BEGIN CERTIFICATE REQUEST----- \n" + strings.SplitN(one, "\n", 2)[1] + "\n", false, "line end of LF or CRLF"},
		{"lines of 77 characters", wrapFile(der, 77, "\n", "\n"), false, "longer than 76"},
		{"a blank line inside the text", strings.Replace(one, "\n", "\n\n", 2) + "\n", false, "empty"},
		{"a CRLF and a line end after the block", one + "\r\n\n", false, "not a PEM block"},
		{"a CRLF line end twice after a block of CRLF lines", armor(der, label, "\r\n") + "\r\n\r\n", false, "something after its PEM block"},
		{"a space after the block", one + "\n ", false, "something after its PEM block"},
		{"a zero octet after the block", one + "\n\x00", false, "something after its PEM block"},
		{"the label CERTIFICATE", armor(der, "CERTIFICATE", "\n") + "\n", false, "label CERTIFICATE REQUEST"},
		{"the label NEW CERTIFICATE REQUEST", armor(der, "NEW CERTIFICATE REQUEST", "\n") + "\n", false, "label CERTIFICATE REQUEST"},
		{"the label in lower case", armor(der, "certificate request", "\n") + "\n", false, "label CERTIFICATE REQUEST"},
		{"the label with a space more", armor(der, "CERTIFICATE  REQUEST", "\n") + "\n", false, "label CERTIFICATE REQUEST"},
		{"a header inside the block", "-----BEGIN CERTIFICATE REQUEST-----\nProc-Type: 4,ENCRYPTED\n\n" + strings.SplitN(one, "\n", 2)[1] + "\n", false, "headers"},
		{"a header of one line", "-----BEGIN CERTIFICATE REQUEST-----\nComment: x\n\n" + strings.SplitN(one, "\n", 2)[1] + "\n", false, "headers"},
		{"garbage inside the block", "-----BEGIN CERTIFICATE REQUEST-----\n!!!!not base64!!!!\n-----END CERTIFICATE REQUEST-----\n", false, "not the standard base64"},
		{"a block of a request that is cut", armor(der[:len(der)-3], label, "\n") + "\n", false, ""},
		{"a block of a request with a byte more", armor(append(append([]byte(nil), der...), 0), label, "\n") + "\n", false, ""},
		{"a block that is a certificate", armor(buildRoot(t, nil).cert, label, "\n") + "\n", false, ""},
		{"a block with no end line", "-----BEGIN CERTIFICATE REQUEST-----\n" + strings.SplitN(one, "\n", 2)[1][:100], false, "not a PEM block"},
		{"an empty file", "", false, "does not start with a PEM block"},
		{"a line end", "\n", false, "does not start with a PEM block"},
		{"only the begin line", "-----BEGIN CERTIFICATE REQUEST-----\n", false, "not a PEM block"},
		{"the DER itself", string(der), false, "does not start with a PEM block"},
		{"a block that ends with the wrong label", strings.Replace(one, "-----END CERTIFICATE REQUEST-----", "-----END CERTIFICATE-----", 1) + "\n", false, "not a PEM block"},
	}
	accepted, refusedN := 0, 0
	opensslAccepts := map[string]bool{}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			req, err := pki.ParseRequestFile([]byte(r.file))
			if r.accept {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if !bytes.Equal(req.DER(), der) {
					t.Error("the request read is not the DER inside the file")
				}
				// The same request as ParseRequest reads it.
				if direct, err := pki.ParseRequest(der); err != nil || !bytes.Equal(direct.Subject(), req.Subject()) {
					t.Errorf("ParseRequest of the DER: %v", err)
				}
				if ok, text := opensslVerifiesRequest(t, []byte(r.file)); !ok {
					t.Errorf("OpenSSL does not accept a file that the package accepts: %s", text)
				}
				if key, err := pki.RequestKeyFile([]byte(r.file)); err != nil || !key.Equal(req.PublicKey()) {
					t.Errorf("RequestKeyFile: %v, %v", key, err)
				}
				accepted++
				return
			}
			refused(t, err, pki.ErrRequest)
			if req != nil {
				t.Error("a request came with the error")
			}
			if err != nil && !strings.Contains(err.Error(), r.words) {
				t.Errorf("the text does not say %q: %q", r.words, err.Error())
			}
			// A file that is not a block of the contract is a fault of form, check 2, whatever is wrong with it (a row with no words is a
			// file that is a block, with a request in it that is refused for its own reasons), and the reader of the key says the same
			// with no key.
			if got := pki.CheckOf(err); r.words != "" && got != pki.CheckMalformed {
				t.Errorf("check %q, want malformed: %v", got, err)
			}
			if key, kerr := pki.RequestKeyFile([]byte(r.file)); key != nil || kerr == nil || kerr.Error() != err.Error() {
				t.Errorf("RequestKeyFile: %v, %v", key, kerr)
			}
			ok, _ := opensslVerifiesRequest(t, []byte(r.file))
			opensslAccepts[r.name] = ok
			refusedN++
		})
	}
	var reads, refuses []string
	for _, r := range rows {
		if r.accept {
			continue
		}
		if opensslAccepts[r.name] {
			reads = append(reads, r.name)
		} else {
			refuses = append(refuses, r.name)
		}
	}
	t.Logf("%d files accepted by the package and by OpenSSL; %d refused by the package, of which OpenSSL reads %d and refuses %d", accepted, refusedN, len(reads), len(refuses))
	t.Logf("OpenSSL reads, and the package refuses: %s", strings.Join(reads, "; "))
	t.Logf("OpenSSL refuses too: %s", strings.Join(refuses, "; "))
	if accepted < 6 || refusedN < 30 {
		t.Errorf("accepted %d, refused %d: too few rows", accepted, refusedN)
	}
}

// The size of the file: exactly MaxRequestSize octets is read, one more is refused before it is decoded (the text says so, and
// a file of that length that is not a PEM block is refused as too long and not as a bad block).
func TestParseRequestFileSizeEdge(t *testing.T) {
	label := "CERTIFICATE REQUEST"
	// A file of exactly the limit: find a request whose armor, with one of the three line ends of the end, has that length.
	var exact, over []byte
	// The armor is the begin line (35 octets and a line end), the base64 of 4 octets for each 3 of the DER in lines of 64 with
	// a line end each, and the end line (33 octets), then no final line end, or one, or a CRLF. So the length for a DER of 3m-2
	// to 3m octets is 35+k + 4m + k*ceil(m/16) + 33 + e, with k the length of a line end.
	for _, ls := range []string{"\n", "\r\n"} {
		k := len(ls)
		for _, end := range []string{"", "\n", "\r\n"} {
			for m := 1; m < pki.MaxRequestSize && exact == nil; m++ {
				if 35+k+4*m+k*((m+15)/16)+33+len(end) == pki.MaxRequestSize {
					for _, size := range []int{3 * m, 3*m - 1, 3*m - 2} {
						der := exactRequest(t, size)
						if f := armor(der, label, ls) + end; len(f) == pki.MaxRequestSize && exact == nil {
							exact = []byte(f)
							over = []byte(armor(der, label, ls) + end + "\n")
						}
					}
				}
			}
		}
	}
	if exact == nil {
		t.Fatal("no request gives a file of exactly the limit")
	}
	t.Run("a file of exactly the limit is read", func(t *testing.T) {
		req, err := pki.ParseRequestFile(exact)
		if err != nil {
			t.Fatal(err)
		}
		if len(req.DER()) <= pki.MaxRequestSize/2 {
			t.Errorf("the request inside is %d octets", len(req.DER()))
		}
		if ok, text := opensslVerifiesRequest(t, exact); !ok {
			t.Errorf("OpenSSL does not accept the file of the limit: %.200s", text)
		}
	})
	t.Run("one octet more is refused as too long, before it is decoded", func(t *testing.T) {
		if len(over) != pki.MaxRequestSize+1 {
			t.Fatalf("the file is %d octets", len(over))
		}
		_, err := pki.ParseRequestFile(over)
		refused(t, err, pki.ErrRequest)
		if err != nil && !strings.Contains(err.Error(), "longer than") {
			t.Errorf("not the size rule: %q", err.Error())
		}
	})
	t.Run("a file of the limit that is no PEM block, and one octet more", func(t *testing.T) {
		_, err := pki.ParseRequestFile(make([]byte, pki.MaxRequestSize))
		refused(t, err, pki.ErrRequest)
		if err != nil && strings.Contains(err.Error(), "longer than") {
			t.Errorf("the limit itself is refused as too long: %q", err.Error())
		}
		_, err = pki.ParseRequestFile(make([]byte, pki.MaxRequestSize+1))
		refused(t, err, pki.ErrRequest)
		if err != nil && !strings.Contains(err.Error(), "longer than") {
			t.Errorf("not the size rule: %q", err.Error())
		}
		// A PEM block that is valid in its first part, and long: the size is the first refusal.
		long := append([]byte("-----BEGIN CERTIFICATE REQUEST-----\n"), bytes.Repeat([]byte("A"), pki.MaxRequestSize)...)
		_, err = pki.ParseRequestFile(long)
		if err == nil || !strings.Contains(err.Error(), "longer than") {
			t.Errorf("a long file: %v", err)
		}
	})
}

func TestParseRequestFileReadsWhatOpenSSLMade(t *testing.T) {
	bin := verifier.Require(t, "openssl")
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pem")
	csr := filepath.Join(dir, "r.csr.pem")
	if out, err := exec.Command(bin, "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	args := []string{"req", "-new", "-key", key, "-sha384", "-utf8", "-subj", "/O=acme/CN=acme example ca",
		"-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
		"-addext", "nameConstraints=critical,permitted;DNS:example.org", "-addext", "extendedKeyUsage=serverAuth,clientAuth", "-out", csr}
	if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	data, err := os.ReadFile(csr)
	if err != nil {
		t.Fatal(err)
	}
	req, err := pki.ParseRequestFile(data)
	if err != nil {
		t.Fatalf("a file that OpenSSL made is refused: %v", err)
	}
	block, _ := pem.Decode(data)
	if !bytes.Equal(req.DER(), block.Bytes) {
		t.Error("the request read is not the DER of the file")
	}
	if nc := req.NameConstraints(); len(nc.PermittedDNS) != 1 || nc.PermittedDNS[0] != "example.org" {
		t.Errorf("name constraints %+v", nc)
	}
}
