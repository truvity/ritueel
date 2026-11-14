package pki_test

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/pki"
)

// hostile are texts that must never reach an error as they are: control characters, bytes that are
// not UTF-8, letters that look like others, characters that change the direction of a text, and
// format verbs. They are written with escapes so that this file is ASCII.
func hostile() map[string]string {
	return map[string]string{
		"a NUL":                             "a\x00b",
		"an escape sequence":                "\x1b[31mred\x1b[0m",
		"a line feed":                       "line one\nline two",
		"a carriage return and a line feed": "a\r\nb",
		"a tab":                             "a\tb",
		"a bell":                            "a\x07b",
		"DEL":                               "a\x7fb",
		"a C1 control":                      "a" + string(rune(0x85)) + "b",
		"the line separator":                "a" + string(rune(0x2028)) + "b",
		"a byte that is not UTF-8":          "a\xffb",
		"two bytes that are not UTF-8":      "\xfe\xff",
		"a truncated sequence":              "a\xc3",
		"an overlong sequence":              "\xc0\xaf",
		"a surrogate half":                  "\xed\xa0\x80",
		"a Cyrillic letter":                 "Ex" + string(rune(0x0430)) + "mple",
		"a Greek letter":                    "Alph" + string(rune(0x03b1)),
		"a full-width letter":               string(rune(0xff21)),
		"the Kelvin sign":                   string(rune(0x212a)),
		"a right-to-left override":          "a" + string(rune(0x202e)) + "b",
		"a zero-width space":                "a" + string(rune(0x200b)) + "b",
		"the byte order mark":               string(rune(0xfeff)) + "a",
		"an emoji":                          "a" + string(rune(0x1f600)),
		"a Chinese text":                    string(rune(0x4e2d)) + string(rune(0x6587)),
		"format verbs":                      "%s %d %v %x %!(EXTRA int=1) %[1]s %",
		"a backslash escape":                `A \x41 \n`,
		"a quote":                           `"quoted" 'single' ` + "`back`",
		"a long text":                       strings.Repeat("x\x00y", 20000),
	}
}

func TestHostileNamesAndLabels(t *testing.T) {
	key := newKey(t).PublicKey
	for name, text := range hostile() {
		t.Run(name, func(t *testing.T) {
			for _, test := range []bool{false, true} {
				cn, err := pki.RootCommonName(text, "A", test)
				refused(t, err, pki.ErrParams)
				if cn != "" {
					t.Errorf("a name %q came with the error", cn)
				}
				_, err = pki.RootCommonName("n", text, test)
				refused(t, err, pki.ErrParams)
			}
			p := rootParams(&key)
			p.Name = text
			_, err := pki.RootTBS(p)
			refused(t, err, pki.ErrParams)
			p = rootParams(&key)
			p.Label = text
			_, err = pki.RootTBS(p)
			refused(t, err, pki.ErrParams)
		})
	}
	// The text of the error does not repeat the name: it says where the fault is.
	_, err := pki.RootCommonName("ab"+string(rune(0x0430)), "A", false)
	refused(t, err, pki.ErrParams)
	if strings.Contains(err.Error(), "ab") {
		t.Errorf("the error repeats the name: %q", err.Error())
	}
}

func TestHostileErrorsOfAReader(t *testing.T) {
	for name, text := range hostile() {
		t.Run(name, func(t *testing.T) {
			cause := errors.New(text)
			serial, err := pki.NewSerial(failReader{cause})
			refused(t, err, pki.ErrParams)
			if serial != nil {
				t.Errorf("a serial came with the error")
			}
			if !errors.Is(err, cause) {
				t.Error("the error of the reader is not reachable")
			}
			// The text of the cause is shown, escaped: a plain ASCII text is the same text.
			if printable(text) && !strings.Contains(err.Error(), text) {
				t.Errorf("the printable cause %q is not in the error %q", text, err.Error())
			}
		})
	}
}

func TestHostileErrorsOfASigner(t *testing.T) {
	for name, text := range hostile() {
		t.Run(name, func(t *testing.T) {
			cause := errors.New(text)
			s := newOpaque(t)
			tbs := mustRootTBS(t, s.key) // a body for the key of the signer, or Sign would refuse it before the signer
			s.tweak = func([]byte, *ecdsa.PrivateKey, []byte) ([]byte, error) { return nil, cause }
			sig, err := pki.SignRoot(nil, s, rootParams(&s.key.PublicKey), tbs)
			refused(t, err, pki.ErrSignature)
			if sig != nil {
				t.Errorf("a signature came with the error")
			}
			if !errors.Is(err, cause) {
				t.Error("the error of the signer is not reachable")
			}
			if printable(text) && !strings.Contains(err.Error(), text) {
				t.Errorf("the printable cause %q is not in the error %q", text, err.Error())
			}
			// A signature made of hostile bytes.
			s.tweak = func([]byte, *ecdsa.PrivateKey, []byte) ([]byte, error) { return []byte(text), nil }
			_, err = pki.SignRoot(nil, s, rootParams(&s.key.PublicKey), tbs)
			refused(t, err, pki.ErrSignature)
		})
	}
}

// Hostile bytes where a request, a name or a certificate is expected.
func TestHostileBytes(t *testing.T) {
	root := buildRoot(t, nil)
	good := withExtensions(t, goodExtensions()...)
	for name, text := range hostile() {
		t.Run(name, func(t *testing.T) {
			// As the issuer name.
			p := root.interParams(good)
			p.IssuerSubject = []byte(text)
			_, err := intermediateTBS(t, p)
			refused(t, err, pki.ErrParams)

			// As the subject of the request.
			csr := copyCSR(good)
			csr.RawSubject = []byte(text)
			_, err = intermediateTBS(t, root.interParams(csr))
			refused(t, err, pki.ErrRequest)

			// As the value of each extension of the request.
			for i := range good.Extensions {
				csr := copyCSR(good)
				csr.Extensions[i].Value = []byte(text)
				_, err := intermediateTBS(t, root.interParams(csr))
				refused(t, err, pki.ErrRequest)
			}

			// As the body and as the signature of a certificate.
			_, err = pki.Assemble([]byte(text), []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, &root.key.PublicKey)
			refused(t, err, pki.ErrSignature)
			_, err = pki.Assemble(root.tbs, []byte(text), &root.key.PublicKey)
			refused(t, err, pki.ErrSignature)
		})
	}
}

// A request that is hostile in a way that a parser reports: the text of the parser is not shown as it
// is. The request whose own signature does not verify, whose body does not parse as a certificate.
func TestHostileTextsFromParsers(t *testing.T) {
	root := buildRoot(t, nil)
	// A body whose names carry bytes that are not UTF-8, so that Go refuses the certificate and says why.
	// Seven bytes each, the length of "Example", so that the lengths of the body stay right.
	for name, junk := range map[string]string{"not UTF-8": "\xff\xfe\xfd\xfc\xfb\xfa\xf9", "a NUL": "a\x00b\x00c\x00d", "an escape": "\x1b[31m\x1b[0m"[:7], "a truncated sequence": "abcdef\xc3", "a look-alike": "Ex\xd0\xb0mpl"} {
		t.Run("a certificate with "+name+" in its subject", func(t *testing.T) {
			body := bytes.Replace(root.tbs, []byte("Example"), []byte(junk), 2)
			if bytes.Equal(body, root.tbs) {
				t.Fatal("the body was not changed")
			}
			der, err := pki.Assemble(body, signatureOf(t, root.key, root.tbs), &root.key.PublicKey)
			if err == nil {
				// A parser that accepts the text is no fault: the bytes are then in the certificate.
				if len(der) == 0 {
					t.Error("no certificate and no error")
				}
				return
			}
			refused(t, err, pki.ErrSignature)
		})
	}
}
