package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"ritueel.id/ritueel/internal/pki"
	"ritueel.id/ritueel/internal/verifier"
)

// The file of a request, by the rule of the doc comment of ParseRequestFile and the sentence of the contract that it comes from:
// "The file holds one such block and nothing else." The rule is, from the first octet to the last:
//
//	the line -----BEGIN CERTIFICATE REQUEST-----, a line end (LF or CRLF, one kind in the whole file),
//	one or more lines of 1 to 76 characters of the base64 alphabet and padding,
//	the line -----END CERTIFICATE REQUEST-----, and nothing or one line end of the same kind;
//
// and the lines together are the standard base64 text of the DER, with its padding and with no bits after the data.
//
// fileRule below is that rule written as a regular expression and a strict decoder, so that it shares no code with the reader that is
// tested. A test that asks every file of a large set what the rule says, and compares, holds the reader to the rule on every byte.

var (
	ruleLF   = regexp.MustCompile(`^-----BEGIN CERTIFICATE REQUEST-----\n((?:[A-Za-z0-9+/=]{1,76}\n)+)-----END CERTIFICATE REQUEST-----\n?$`)
	ruleCRLF = regexp.MustCompile(`^-----BEGIN CERTIFICATE REQUEST-----\r\n((?:[A-Za-z0-9+/=]{1,76}\r\n)+)-----END CERTIFICATE REQUEST-----(?:\r\n)?$`)
)

// fileRule is the DER that the rule gives for a file, and false when the rule refuses the file.
func fileRule(file []byte) ([]byte, bool) {
	for _, r := range []struct {
		re  *regexp.Regexp
		eol string
	}{{ruleLF, "\n"}, {ruleCRLF, "\r\n"}} {
		m := r.re.FindSubmatch(file)
		if m == nil {
			continue
		}
		text := strings.ReplaceAll(string(m[1]), r.eol, "")
		der, err := base64.StdEncoding.Strict().DecodeString(text)
		if err != nil || len(der) == 0 {
			return nil, false
		}
		return der, true
	}
	return nil, false
}

// derOfLength is a good request whose DER has the given length modulo 3 (the padding of its base64 text depends on it).
func derOfLength(t *testing.T, mod int) []byte {
	t.Helper()
	for try := 0; try < 400; try++ {
		if der := goodRequest(t).DER(); len(der)%3 == mod {
			return der
		}
	}
	t.Fatalf("no request of a length that is %d modulo 3 in 400 tries", mod)
	return nil
}

// readResult is what ParseRequest and RequestKey say about a DER.
type readResult struct {
	req  *pki.Request
	err  error
	key  *ecdsa.PublicKey
	kerr error
}

// readOnce is ParseRequest and RequestKey of a DER, remembered: a signature takes about a millisecond to check, and the set of files holds
// the same request in many forms.
func readOnce(der []byte) readResult {
	if v, ok := readCache.Load(string(der)); ok {
		return v.(readResult)
	}
	req, err := pki.ParseRequest(der)
	key, kerr := pki.RequestKey(der)
	r := readResult{req, err, key, kerr}
	readCache.Store(string(der), r)
	return r
}

var readCache sync.Map

// fileAgainstRule reads one file with the four readers of a file and checks them against fileRule: when the rule refuses the file, both
// readers refuse it as malformed, with no request and no key; when the rule accepts it, both readers do what ParseRequest and RequestKey do
// with the DER that the rule gives. It reports whether the rule accepted the file.
func fileAgainstRule(t *testing.T, name string, file []byte) bool {
	t.Helper()
	der, ok := fileRule(file)
	req, err := pki.ParseRequestFile(file)
	key, kerr := pki.RequestKeyFile(file)
	if !ok {
		if err != nil {
			refused(t, err, pki.ErrRequest)
		}
		switch {
		case err == nil || req != nil:
			t.Errorf("%s: ParseRequestFile reads a file that the rule refuses (request %v, error %v)", name, req != nil, err)
		case pki.CheckOf(err) != pki.CheckMalformed:
			t.Errorf("%s: check %q, want malformed: %v", name, pki.CheckOf(err), err)
		case key != nil || kerr == nil || kerr.Error() != err.Error():
			t.Errorf("%s: RequestKeyFile gives %v, %v, and ParseRequestFile %v", name, key, kerr, err)
		}
		return false
	}
	w := readOnce(der)
	want, werr, wkey, wkerr := w.req, w.err, w.key, w.kerr
	switch {
	case (err == nil) != (werr == nil) || (err != nil && err.Error() != werr.Error()):
		t.Errorf("%s: the rule accepts the file, ParseRequestFile says %v and ParseRequest of its DER says %v", name, err, werr)
	case err == nil && !bytes.Equal(req.DER(), want.DER()):
		t.Errorf("%s: the request read is not the DER inside the file", name)
	case (kerr == nil) != (wkerr == nil) || (kerr != nil && kerr.Error() != wkerr.Error()):
		t.Errorf("%s: the rule accepts the file, RequestKeyFile says %v and RequestKey of its DER says %v", name, kerr, wkerr)
	case kerr == nil && !key.Equal(wkey):
		t.Errorf("%s: RequestKeyFile and RequestKey give two keys", name)
	}
	return true
}

// Every file in a large set is judged by the rule and by the reader, and they agree. The set is made of four good files (LF and CRLF,
// lines of 64 and of 76, with and without the last line end) and, for each, every change of one place: the byte at every position
// deleted, replaced and followed by an inserted byte, for the bytes that a rule of lines could be wrong about; every cut of the front and
// of the end; and a doubled line end at every line end.
func TestEveryFileOfAFamilyIsReadByTheRuleOfTheFile(t *testing.T) {
	der := goodRequest(t).DER()
	bases := []struct{ name, file string }{
		{"LF, 64, a last line end", wrapFile(der, 64, "\n", "\n")},
		{"LF, 64, no last line end", wrapFile(der, 64, "\n", "")},
		{"CRLF, 64, a last line end", wrapFile(der, 64, "\r\n", "\r\n")},
		{"CRLF, 76, no last line end", wrapFile(der, 76, "\r\n", "")},
		{"LF, 76, a last line end", wrapFile(der, 76, "\n", "\n")},
	}
	// The bytes that matter to a rule of lines: spaces, line ends, a NUL, a byte above ASCII, a dash and a colon (the frame and a header),
	// characters of the alphabet and of the padding, and a character that is in no alphabet. Inside the base64 text, away from the frame and
	// from the line ends, a changed character only makes another request (which takes the time of a signature to refuse), so there a few
	// bytes are tried; at the frame, at every line end and in the first and the last lines all of them are.
	inserts := []byte{' ', '\t', '\r', '\n', 0x00, 0x0b, 0xef, '-', ':', '#', 'A', '+', '=', '_', '!'}
	interior := []byte{' ', '\r', '\n', ':', '='}
	isText := func(c byte) bool {
		return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
	}
	for _, b := range bases {
		t.Run(b.name, func(t *testing.T) {
			file := []byte(b.file)
			if !fileAgainstRule(t, "the base file", file) {
				t.Fatal("the base file is not accepted by the rule")
			}
			if req, err := pki.ParseRequestFile(file); err != nil || !bytes.Equal(req.DER(), der) {
				t.Fatalf("the base file is refused: %v", err)
			}
			accepted, total := 0, 0
			try := func(name string, f []byte) {
				total++
				if fileAgainstRule(t, name, f) {
					accepted++
				}
			}
			for i := 0; i <= len(file); i++ {
				set := inserts
				if i > 70 && i < len(file)-70 && i < len(file) && isText(file[i]) && isText(file[i-1]) {
					set = interior
				}
				if i < len(file) {
					try("delete "+itoa(i), append(append([]byte(nil), file[:i]...), file[i+1:]...))
				}
				for _, c := range set {
					try("insert "+itoa(i)+" "+itoa(int(c)), append(append(append([]byte(nil), file[:i]...), c), file[i:]...))
					if i < len(file) {
						try("replace "+itoa(i)+" "+itoa(int(c)), append(append(append([]byte(nil), file[:i]...), c), file[i+1:]...))
					}
				}
				try("cut front "+itoa(i), append([]byte(nil), file[i:]...))
				try("cut end "+itoa(i), append([]byte(nil), file[:i]...))
			}
			try("twice", append(append([]byte(nil), file...), file...))
			t.Logf("%d files, %d accepted by the rule (all of them read as the rule says)", total, accepted)
			if accepted < 1 || total < 5000 {
				t.Errorf("the rule accepted %d of %d files: the set does not test what it should", accepted, total)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// The shapes that the doc comment of ParseRequestFile names, one by one, each with the one result: accepted (the request is the request
// inside, and OpenSSL reads the same file) or refused as malformed, with no request and no key.
func TestTheShapesOfAFileOfARequest(t *testing.T) {
	der := goodRequest(t).DER()
	good := wrapFile(der, 64, "\n", "\n")
	b64 := base64.StdEncoding.EncodeToString(der)
	header, footer := "-----BEGIN CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST-----"
	lines := func(n int, eol string) string {
		var sb strings.Builder
		for s := b64; len(s) > 0; {
			k := min(n, len(s))
			sb.WriteString(s[:k] + eol)
			s = s[k:]
		}
		return sb.String()
	}
	accept := []struct{ name, file string }{
		{"LF, lines of 64, a last line end", good},
		{"LF, lines of 64, no last line end", wrapFile(der, 64, "\n", "")},
		{"CRLF, lines of 64, a last line end", wrapFile(der, 64, "\r\n", "\r\n")},
		{"CRLF, lines of 64, no last line end", wrapFile(der, 64, "\r\n", "")},
		{"LF, lines of 1", wrapFile(der, 1, "\n", "\n")},
		{"LF, lines of 76", wrapFile(der, 76, "\n", "\n")},
		{"CRLF, lines of 76", wrapFile(der, 76, "\r\n", "")},
		{"LF, lines of 75", wrapFile(der, 75, "\n", "\n")},
	}
	for _, c := range accept {
		t.Run("accepted: "+c.name, func(t *testing.T) {
			req, err := pki.ParseRequestFile([]byte(c.file))
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !bytes.Equal(req.DER(), der) {
				t.Error("the request read is not the DER inside the file")
			}
			if key, err := pki.RequestKeyFile([]byte(c.file)); err != nil || !key.Equal(req.PublicKey()) {
				t.Errorf("RequestKeyFile: %v, %v", key, err)
			}
			if ok, text := opensslVerifiesRequest(t, []byte(c.file)); !ok {
				t.Errorf("OpenSSL does not read a file that the package reads: %s", text)
			}
			if !fileAgainstRule(t, c.name, []byte(c.file)) {
				t.Error("the rule refuses the file")
			}
		})
	}
	if len(b64) < 200 {
		t.Fatal("the request is too short for the shapes")
	}
	refuse := []struct{ name, file, words string }{
		{"lines of 77", wrapFile(der, 77, "\n", "\n"), "longer than 76"},
		{"lines of 100", wrapFile(der, 100, "\n", "\n"), "longer than 76"},
		{"one line", header + "\n" + b64 + "\n" + footer + "\n", "longer than 76"},
		{"the first line one character too long, the rest short", header + "\n" + b64[:77] + "\n" + b64[77:] + "\n" + footer + "\n", "longer than 76"},
		{"one character more at the end of the text", header + "\n" + lines(76, "\n")[:len(lines(76, "\n"))-1] + "X\n" + footer + "\n", ""},
		{"two line ends after the footer", good + "\n", "something after"},
		{"two line ends after the footer (CRLF)", wrapFile(der, 64, "\r\n", "\r\n\r\n"), "something after"},
		{"a space after the footer", wrapFile(der, 64, "\n", " "), ""},
		{"a space and a line end after the footer", wrapFile(der, 64, "\n", " \n"), ""},
		{"a tab after the footer", wrapFile(der, 64, "\n", "\t\n"), ""},
		{"text after the footer", wrapFile(der, 64, "\n", "\nthe end\n"), "something after"},
		{"a second block", good + good, "something after"},
		{"a second block of the same request after a blank line", good + "\n" + good, "something after"},
		{"a space after the header", header + " \n" + lines(64, "\n") + footer + "\n", "line end"},
		{"a tab after the header", header + "\t\n" + lines(64, "\n") + footer + "\n", "line end"},
		{"no line end after the header", header + lines(64, "\n") + footer + "\n", "line end"},
		{"a bare carriage return as the line end after the header", header + "\r" + lines(64, "\r") + footer + "\r", "line end"},
		{"a blank line after the header", header + "\n\n" + lines(64, "\n") + footer + "\n", "empty"},
		{"a blank line inside the text", header + "\n" + lines(64, "\n")[:65] + "\n" + lines(64, "\n")[65:] + footer + "\n", "empty"},
		{"a blank line before the footer", header + "\n" + lines(64, "\n") + "\n" + footer + "\n", "empty"},
		{"a space inside a line", header + "\n" + b64[:10] + " " + b64[10:64] + "\n" + lines(64, "\n")[65:] + footer + "\n", "standard base64"},
		{"a space at the end of a line", header + "\n" + b64[:64] + " \n" + lines(64, "\n")[65:] + footer + "\n", "standard base64"},
		{"a tab at the end of a line", header + "\n" + b64[:64] + "\t\n" + lines(64, "\n")[65:] + footer + "\n", "standard base64"},
		{"a space at the start of a line", header + "\n " + lines(64, "\n") + footer + "\n", "standard base64"},
		{"a line end before the block", "\n" + good, "does not start"},
		{"a CRLF before the block", "\r\n" + good, "does not start"},
		{"text before the block", "a request:\n" + good, "does not start"},
		{"a space before the block", " " + good, "does not start"},
		{"a byte order mark before the block", "\xef\xbb\xbf" + good, "does not start"},
		{"mixed line ends: one CRLF in LF lines", strings.Replace(good, "\n", "\r\n", 1), ""},
		{"mixed line ends: one LF in CRLF lines", strings.Replace(wrapFile(der, 64, "\r\n", "\r\n"), "\r\n", "\n", 2), ""},
		{"a bare carriage return at the end of an LF line", strings.Replace(good, "\n", "\r\n", 3), ""},
		{"a carriage return inside a line", header + "\n" + b64[:10] + "\r" + b64[10:64] + "\n" + lines(64, "\n")[65:] + footer + "\n", "standard base64"},
		{"a header line", header + "\nProc-Type: 4,ENCRYPTED\n\n" + lines(64, "\n") + footer + "\n", "headers"},
		{"a header line with a short value", header + "\nA:b\n" + lines(64, "\n") + footer + "\n", "headers"},
		{"a header line after the text", header + "\n" + lines(64, "\n") + "A:b\n" + footer + "\n", "headers"},
		{"a line that starts with a colon", header + "\n:" + b64[1:64] + "\n" + lines(64, "\n")[65:] + footer + "\n", "headers"},
		{"a line that is a colon only", header + "\n:\n" + lines(64, "\n") + footer + "\n", "headers"},
		{"a line that ends with a colon", header + "\n" + b64[:63] + ":\n" + lines(64, "\n")[65:] + footer + "\n", "headers"},
		{"a colon inside a line of text", header + "\n" + b64[:10] + ":" + b64[11:64] + "\n" + lines(64, "\n")[65:] + footer + "\n", "headers"},
		{"the label CERTIFICATE", strings.NewReplacer("CERTIFICATE REQUEST", "CERTIFICATE").Replace(good), "label"},
		{"the label NEW CERTIFICATE REQUEST", strings.NewReplacer("BEGIN CERTIFICATE REQUEST", "BEGIN NEW CERTIFICATE REQUEST", "END CERTIFICATE REQUEST", "END NEW CERTIFICATE REQUEST").Replace(good), "label"},
		{"the label in lower case", strings.NewReplacer("CERTIFICATE REQUEST", "certificate request").Replace(good), "label"},
		{"the begin line with four dashes at the end", strings.Replace(good, "REQUEST-----\n", "REQUEST----\n", 1), "label"},
		{"the begin line with six dashes at the start", strings.Replace(good, "-----BEGIN", "------BEGIN", 1), "does not start"},
		{"the end line with four dashes", strings.Replace(good, "-----END CERTIFICATE REQUEST-----", "-----END CERTIFICATE REQUEST----", 1), "not a PEM block"},
		{"the end line with another label", strings.Replace(good, "END CERTIFICATE REQUEST", "END CERTIFICATE", 1), "not a PEM block"},
		{"no end line", header + "\n" + lines(64, "\n"), "not a PEM block"},
		{"no end line and no last line end", header + "\n" + strings.TrimSuffix(lines(64, "\n"), "\n"), "not a PEM block"},
		{"the begin line only", header + "\n", "not a PEM block"},
		{"the begin line only, no line end", header, "line end"},
		{"an empty block", header + "\n" + footer + "\n", "standard base64"},
		{"an empty file", "", "does not start"},
		{"a line end only", "\n", "does not start"},
		{"the DER", string(der), "does not start"},
		{"the text without the frame", b64 + "\n", "does not start"},
		{"a NUL after the footer", good + "\x00", "something after"},
		{"a NUL inside a line", header + "\n" + b64[:10] + "\x00" + b64[10:64] + "\n" + lines(64, "\n")[65:] + footer + "\n", "standard base64"},
		{"a character outside the alphabet", header + "\n" + b64[:10] + "_" + b64[11:64] + "\n" + lines(64, "\n")[65:] + footer + "\n", "standard base64"},
	}
	if strings.ContainsAny(b64, "+/") {
		refuse = append(refuse, struct{ name, file, words string }{"the URL alphabet in place of the standard one", header + "\n" + strings.NewReplacer("+", "-", "/", "_").Replace(lines(64, "\n")) + footer + "\n", "standard base64"})
	}
	for _, c := range refuse {
		t.Run("refused: "+c.name, func(t *testing.T) {
			if c.words != "" {
				req, err := pki.ParseRequestFile([]byte(c.file))
				if err == nil || req != nil {
					t.Fatalf("the file is read: %v", err)
				}
				if !strings.Contains(err.Error(), c.words) {
					t.Errorf("the text does not say %q: %q", c.words, err.Error())
				}
			}
			if fileAgainstRule(t, c.name, []byte(c.file)) {
				t.Error("the rule accepts the file: the row is not a refusal")
			}
		})
	}
}

// The base64 text is the one text of the DER: no padding left out, no padding more, no bits after the data.
func TestTheBase64TextOfAFileIsTheCanonicalOne(t *testing.T) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for _, mod := range []int{0, 1, 2} {
		der := derOfLength(t, mod)
		text := base64.StdEncoding.EncodeToString(der)
		file := func(text string) []byte {
			var sb strings.Builder
			sb.WriteString("-----BEGIN CERTIFICATE REQUEST-----\n")
			for len(text) > 64 {
				sb.WriteString(text[:64] + "\n")
				text = text[64:]
			}
			sb.WriteString(text + "\n-----END CERTIFICATE REQUEST-----\n")
			return []byte(sb.String())
		}
		t.Run("length "+itoa(mod)+" modulo 3: the canonical text is read", func(t *testing.T) {
			req, err := pki.ParseRequestFile(file(text))
			if err != nil || !bytes.Equal(req.DER(), der) {
				t.Fatalf("refused: %v", err)
			}
		})
		if mod == 0 {
			t.Run("a text of whole groups has no bits after the data and no padding to leave out", func(t *testing.T) {
				if strings.Contains(text, "=") {
					t.Fatal("padding in a text of whole groups")
				}
			})
			continue
		}
		pad := strings.Count(text, "=")
		if pad != 3-mod {
			t.Fatalf("a DER of %d modulo 3 has %d padding characters", mod, pad)
		}
		t.Run("length "+itoa(mod)+" modulo 3: the padding left out is refused", func(t *testing.T) {
			if !fileAgainstRule(t, "no padding", file(strings.TrimRight(text, "="))) {
				t.Log("the rule refuses a text with no padding, as the reader does")
			}
			req, err := pki.ParseRequestFile(file(strings.TrimRight(text, "=")))
			if err == nil || req != nil || pki.CheckOf(err) != pki.CheckMalformed {
				t.Errorf("a text with no padding: %v", err)
			}
		})
		t.Run("length "+itoa(mod)+" modulo 3: one padding character too many is refused", func(t *testing.T) {
			req, err := pki.ParseRequestFile(file(text + "="))
			if err == nil || req != nil || pki.CheckOf(err) != pki.CheckMalformed {
				t.Errorf("a text with a padding character more: %v", err)
			}
			fileAgainstRule(t, "a padding character more", file(text+"="))
		})
		t.Run("length "+itoa(mod)+" modulo 3: every character before the padding that changes only the unused bits is refused", func(t *testing.T) {
			// The last character before the padding holds 4 bits (mod 1) or 2 bits (mod 2) that the data does not use. Every other character of the
			// alphabet with the same used bits decodes to the same DER with the standard library, and is another text of the same request.
			last := len(text) - pad - 1
			idx := strings.IndexByte(alphabet, text[last])
			unused := 1<<(2*pad) - 1 // 3 for one padding character, 15 for two
			changed := 0
			for c := 0; c < 64; c++ {
				if c == idx || c&^unused != idx&^unused {
					continue
				}
				other := text[:last] + string(alphabet[c]) + text[last+1:]
				// The lenient decoder reads it as the same DER: this is the case that the rule is about.
				got, err := base64.StdEncoding.DecodeString(other)
				if err != nil || !bytes.Equal(got, der) {
					t.Fatalf("the test's own reading: %v", err)
				}
				req, rerr := pki.ParseRequestFile(file(other))
				if rerr == nil || req != nil || pki.CheckOf(rerr) != pki.CheckMalformed || !strings.Contains(rerr.Error(), "standard base64") {
					t.Errorf("a text with bits after the data (%q): %v", alphabet[c], rerr)
				}
				key, kerr := pki.RequestKeyFile(file(other))
				if key != nil || kerr == nil || kerr.Error() != rerr.Error() {
					t.Errorf("RequestKeyFile of a text with bits after the data: %v, %v", key, kerr)
				}
				if fileAgainstRule(t, "bits after the data", file(other)) {
					t.Error("the rule accepts a text with bits after the data")
				}
				changed++
			}
			if changed != unused {
				t.Errorf("%d other texts tried, want %d", changed, unused)
			}
		})
		t.Run("length "+itoa(mod)+" modulo 3: a padding character inside the text is refused", func(t *testing.T) {
			bad := text[:40] + "=" + text[41:]
			req, err := pki.ParseRequestFile(file(bad))
			if err == nil || req != nil || pki.CheckOf(err) != pki.CheckMalformed {
				t.Errorf("a padding character inside: %v", err)
			}
		})
	}
}

// A file that OpenSSL wrote, and a file that Go wrote, are read; with CRLF and without the last line end they are read too, and each is a
// file that OpenSSL reads.
func TestAFileThatOpenSSLWroteAndAFileThatGoWroteAreRead(t *testing.T) {
	bin := verifier.Require(t, "openssl")
	dir := t.TempDir()
	key := filepath.Join(dir, "k.pem")
	if out, err := exec.Command(bin, "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", key).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	// Different subjects make requests of different lengths, so that each length of the padding is met.
	var seen = map[int]bool{}
	for i, cn := range []string{"a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"} {
		csr := filepath.Join(dir, "r"+itoa(i)+".csr.pem")
		args := []string{"req", "-new", "-key", key, "-sha384", "-utf8", "-subj", "/O=acme/CN=" + cn,
			"-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
			"-addext", "nameConstraints=critical,permitted;DNS:example.org", "-addext", "extendedKeyUsage=serverAuth,clientAuth", "-out", csr}
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		written, err := os.ReadFile(csr)
		if err != nil {
			t.Fatal(err)
		}
		der, ok := fileRule(written)
		if !ok {
			t.Fatalf("the file that OpenSSL wrote is not a file by the rule:\n%s", written)
		}
		seen[len(der)%3] = true
		forms := map[string][]byte{
			"as OpenSSL wrote it":                    written,
			"with no last line end":                  bytes.TrimSuffix(written, []byte("\n")),
			"with CRLF":                              bytes.ReplaceAll(written, []byte("\n"), []byte("\r\n")),
			"with CRLF and no last line end":         bytes.TrimSuffix(bytes.ReplaceAll(written, []byte("\n"), []byte("\r\n")), []byte("\r\n")),
			"as Go writes it (pem.Encode, 64)":       []byte(wrapFile(der, 64, "\n", "\n")),
			"as Go writes it, CRLF":                  []byte(wrapFile(der, 64, "\r\n", "\r\n")),
			"in lines of 76":                         []byte(wrapFile(der, 76, "\n", "\n")),
			"in lines of 76, CRLF, no last line end": []byte(wrapFile(der, 76, "\r\n", "")),
		}
		for name, f := range forms {
			t.Run(cn+" "+name, func(t *testing.T) {
				for _, e := range []struct {
					name string
					file []byte
				}{{"ParseRequestFile", f}} {
					req, err := pki.ParseRequestFile(e.file)
					if err != nil {
						t.Fatalf("%s refuses the file: %v", e.name, err)
					}
					if !bytes.Equal(req.DER(), der) {
						t.Error("the request read is not the DER of the file")
					}
				}
				if k, err := pki.RequestKeyFile(f); err != nil || k == nil {
					t.Errorf("RequestKeyFile: %v", err)
				}
				if ok, text := opensslVerifiesRequest(t, f); !ok {
					t.Errorf("OpenSSL does not read a file that the package reads: %s", text)
				}
			})
		}
	}
	for mod := 0; mod < 3; mod++ {
		if !seen[mod] {
			t.Logf("no request of a length that is %d modulo 3 among the requests of OpenSSL", mod)
		}
	}
}

// A caller that reads a request twice reads two requests when the bytes changed between the two reads. The package reads only what it is
// given, so the key of the request that a builder reads is its own, and the way to see that two calls were given two requests is the one
// that the doc comments of RequestKey and ParseRequest name: compare Request.PublicKey with the key that RequestKey returned.
func TestTheKeyOfRequestKeyIsComparedWithTheKeyOfTheRequestRead(t *testing.T) {
	a, b := goodRequest(t), goodRequest(t)
	if a.Key.Equal(&b.Key.PublicKey) {
		t.Fatal("two requests with one key")
	}
	derA, derB := a.DER(), b.DER()
	keyA, err := pki.RequestKey(derA)
	if err != nil {
		t.Fatal(err)
	}
	same, err := pki.ParseRequest(derA)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pki.ParseRequest(derB)
	if err != nil {
		t.Fatal(err)
	}
	if !keyA.Equal(same.PublicKey()) {
		t.Error("the same bytes give two keys")
	}
	if keyA.Equal(other.PublicKey()) {
		t.Error("two requests give one key")
	}
	// The same through a file read once and given to the two readers of a file, with the DER of the request for the builders.
	file := []byte(wrapFile(derA, 64, "\n", "\n"))
	fk, ferr := pki.RequestKeyFile(file)
	fr, rerr := pki.ParseRequestFile(file)
	if ferr != nil || rerr != nil || !fk.Equal(fr.PublicKey()) || !bytes.Equal(fr.DER(), derA) {
		t.Errorf("the file read once: %v, %v", ferr, rerr)
	}
}
