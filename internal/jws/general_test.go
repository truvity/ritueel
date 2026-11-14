package jws_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jws"
)

// refuses fails the test unless data is refused by ParseGeneral with an error that wraps
// ErrMalformed and shows printable ASCII only.
func refuses(t *testing.T, data []byte, typ string) {
	t.Helper()
	g, err := jws.ParseGeneral(data, typ)
	if err == nil {
		t.Fatalf("accepted; want an error that wraps ErrMalformed (%d signatures)", len(g.Signatures))
	}
	if g != nil {
		t.Errorf("a refusal returned a value")
	}
	if !errors.Is(err, jws.ErrMalformed) {
		t.Errorf("the error does not wrap ErrMalformed: %v", err)
	}
	mustBeASCII(t, "the error text", err.Error())
}

func TestParseGeneralAccepts(t *testing.T) {
	f := newFixture(t)
	t.Run("one signature", func(t *testing.T) {
		g, err := jws.ParseGeneral(file(f.entry()), typList)
		if err != nil {
			t.Fatal(err)
		}
		if len(g.Signatures) != 1 {
			t.Fatalf("got %d signatures, want 1", len(g.Signatures))
		}
		s := g.Signatures[0]
		if s.Protected != f.protected {
			t.Errorf("Protected is not the text as read")
		}
		if s.Header.Alg != "ES384" || s.Header.Typ != typList || s.Header.Kid != f.k.pin || len(s.Header.X5C) != 1 || s.Header.X5C[0] != f.k.x5c() {
			t.Errorf("header read wrongly: %+v", s.Header)
		}
		if len(s.Sig) != 96 || b64u(s.Sig) != f.sig {
			t.Errorf("the signature is not the 96 bytes of the text")
		}
		if s.Cert == nil || jws.Pin(s.Cert) != f.k.pin {
			t.Errorf("the certificate is not the one of x5c")
		}
		if err := s.Verify(f.payload); err != nil {
			t.Errorf("a good signature does not verify: %v", err)
		}
	})
	t.Run("two signatures keep their order", func(t *testing.T) {
		second := goodEntry(t, f.other, typList, f.payload)
		g, err := jws.ParseGeneral(file(f.entry(), second), typList)
		if err != nil {
			t.Fatal(err)
		}
		if len(g.Signatures) != 2 || g.Signatures[0].Header.Kid != f.k.pin || g.Signatures[1].Header.Kid != f.other.pin {
			t.Fatalf("the signatures are not in the order of the file")
		}
		for i, s := range g.Signatures {
			if err := s.Verify(f.payload); err != nil {
				t.Errorf("signature %d: %v", i, err)
			}
		}
	})
	t.Run("the header may be in any order and spelt with white space", func(t *testing.T) {
		h := goodHeader(f.k, typList)
		text := b64u([]byte(`{ "x5c" : ` + h.x5c + ` , "typ":` + h.typ + `,"kid":` + h.kid + ",\n\"alg\":" + h.alg + " }"))
		sig := sigOver(t, f.k, text, f.payload)
		g, err := jws.ParseGeneral(file(entry(text, sig)), typList)
		if err != nil {
			t.Fatal(err)
		}
		if g.Signatures[0].Protected != text {
			t.Errorf("Protected was written again")
		}
		if err := g.Signatures[0].Verify(f.payload); err != nil {
			t.Errorf("the signature over the text as read does not verify: %v", err)
		}
	})
	t.Run("white space around the object and the members is not enforced", func(t *testing.T) {
		// The page says the writer uses the canonical form; the host does not demand it, because it
		// verifies the signed bytes and reads the rest. The page leaves the form of the file to the writer.
		data := []byte(" \n{ \"signatures\" : [ " + f.entry() + " ] }\n")
		if _, err := jws.ParseGeneral(data, typList); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a key on another curve is read, and refused when it verifies", func(t *testing.T) {
		p256 := newKeyOn(t, elliptic.P256())
		e := goodEntry(t, p256, typList, f.payload)
		g, err := jws.ParseGeneral(file(e), typList)
		if err != nil {
			t.Fatalf("the form is right and the kid is the key's pin: %v", err)
		}
		if err := g.Signatures[0].Verify(f.payload); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("a P-256 key verified or gave the wrong error: %v", err)
		}
	})
}

func TestParseGeneralRefusesAlgorithms(t *testing.T) {
	f := newFixture(t)
	for _, alg := range []string{
		`"none"`, `"None"`, `"NONE"`, `""`, `"ES256"`, `"ES512"`, `"HS384"`, `"RS384"`, `"PS384"`, `"EdDSA"`,
		`"es384"`, `"Es384"`, `"ES384 "`, `" ES384"`, `"ES 384"`, `"ES-384"`, `"ES384\u0000"`, `"ES384\n"`,
		`"\u0415S384"`,                     // Cyrillic capital Ie for the Latin E
		`"E\u0405384"`,                     // Cyrillic capital Dze for the Latin S
		`"\uff25\uff33\uff13\uff18\uff14"`, // full-width letters
		"\"\u0415S384\"",                   // the same, as UTF-8 text
		`"ES384","alg":"ES384"`,            // twice
		`384`, `null`, `true`, `["ES384"]`, `{"a":"ES384"}`,
	} {
		t.Run(alg, func(t *testing.T) {
			h := goodHeader(f.k, typList)
			h.alg = alg
			p := h.text()
			refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
		})
	}
	t.Run("no alg", func(t *testing.T) {
		h := goodHeader(f.k, typList)
		h.drop = "alg"
		p := h.text()
		refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
	})
	t.Run("the algorithm is not read from the type asked for", func(t *testing.T) {
		h := goodHeader(f.k, typList)
		h.alg = `"ES256"`
		p := h.text()
		refuses(t, file(entry(p, f.sig)), typList)
	})
}

func TestParseGeneralRefusesType(t *testing.T) {
	f := newFixture(t)
	for _, typ := range []string{
		`""`, `"root-list"`, `"root-list+json "`, `" root-list+json"`, `"Root-List+JSON"`, `"ROOT-LIST+JSON"`,
		`"application/root-list+json"`, `"root-removal+json"`, `"JWT"`, `"JOSE"`, `"ssh-ca-key-list+json"`,
		`"root-list+js\u043en"`, // Cyrillic o
		`"root\u2011list+json"`, // a hyphen that is not
		`1`, `null`, `["root-list+json"]`,
	} {
		t.Run(typ, func(t *testing.T) {
			h := goodHeader(f.k, typList)
			h.typ = typ
			p := h.text()
			refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
		})
	}
	t.Run("no typ", func(t *testing.T) {
		h := goodHeader(f.k, typList)
		h.drop = "typ"
		p := h.text()
		refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
	})
	t.Run("a signature of the other kind of document is refused whichever way it goes", func(t *testing.T) {
		removal := goodEntry(t, f.k, typRemoval, f.payload)
		refuses(t, file(removal), typList)
		if _, err := jws.ParseGeneral(file(f.entry()), typRemoval); err == nil {
			t.Errorf("a list signature was read as a removal authorisation")
		}
	})
	t.Run("a second signature of the wrong type spoils the file", func(t *testing.T) {
		refuses(t, file(f.entry(), goodEntry(t, f.other, typRemoval, f.payload)), typList)
	})
	t.Run("the type is the one the caller asks for", func(t *testing.T) {
		e := goodEntry(t, f.k, "example+json", f.payload)
		if _, err := jws.ParseGeneral(file(e), "example+json"); err != nil {
			t.Errorf("the requested type is not honoured: %v", err)
		}
		refuses(t, file(e), typList)
		refuses(t, file(e), "")
	})
}

func TestParseGeneralRefusesExtraHeaders(t *testing.T) {
	f := newFixture(t)
	for _, extra := range []string{
		`,"crit":["b64"]`, `,"crit":[]`, `,"b64":false`, `,"b64":true`, `,"jwk":{"kty":"EC"}`,
		`,"jku":"https://example.org/keys"`, `,"x5u":"https://example.org/cert"`, `,"x5t":"abc"`,
		`,"x5t#S256":"abc"`, `,"zip":"DEF"`, `,"cty":"json"`, `,"jti":"1"`, `,"iat":1`, `,"exp":1`,
		`,"nonce":"x"`, `,"x":null`, `,"":""`,
		`,"Alg":"ES384"`, `,"ALG":"ES384"`, `,"KID":"x"`, `,"Typ":"root-list+json"`, `,"X5C":[]`,
		`,"alg":"ES384"`, `,"kid":"x"`, `,"typ":"root-list+json"`, `,"x5c":[]`, // each member twice
		`,"kid":"` + f.k.pin + `"`, // the same kid twice
		`,"\u0430lg":"ES384"`,      // Cyrillic a in the name
		`,"al\u0067":"ES384"`,      // a name that the escape spells "alg" again
	} {
		t.Run(extra, func(t *testing.T) {
			h := goodHeader(f.k, typList)
			h.extra = extra
			p := h.text()
			refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
		})
	}
	t.Run("a header that is not an object", func(t *testing.T) {
		for _, raw := range []string{``, `[]`, `"x"`, `null`, `1`, `{`, `{}`, `{"alg":"ES384"}`, "\xef\xbb\xbf" + goodHeader(f.k, typList).json(), goodHeader(f.k, typList).json() + "x", goodHeader(f.k, typList).json() + goodHeader(f.k, typList).json()} {
			p := b64u([]byte(raw))
			refuses(t, file(entry(p, f.sig)), typList)
		}
	})
}

func TestParseGeneralRefusesMissingAndWrongTypedMembers(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"alg", "kid", "typ", "x5c"} {
		t.Run("no "+name, func(t *testing.T) {
			h := goodHeader(f.k, typList)
			h.drop = name
			p := h.text()
			refuses(t, file(entry(p, f.sig)), typList)
		})
	}
	good := goodHeader(f.k, typList)
	for _, c := range []struct {
		name string
		edit func(*header)
	}{
		{"kid null", func(h *header) { h.kid = "null" }},
		{"kid a number", func(h *header) { h.kid = "1" }},
		{"kid a list", func(h *header) { h.kid = `["` + f.k.pin + `"]` }},
		{"x5c null", func(h *header) { h.x5c = "null" }},
		{"x5c a string", func(h *header) { h.x5c = `"` + f.k.x5c() + `"` }},
		{"x5c an object", func(h *header) { h.x5c = `{"0":"` + f.k.x5c() + `"}` }},
		{"x5c holds null", func(h *header) { h.x5c = `[null]` }},
		{"x5c holds a number", func(h *header) { h.x5c = `[1]` }},
		{"x5c holds a list", func(h *header) { h.x5c = `[["` + f.k.x5c() + `"]]` }},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := good
			c.edit(&h)
			p := h.text()
			refuses(t, file(entry(p, f.sig)), typList)
		})
	}
}

func TestParseGeneralRefusesCertificates(t *testing.T) {
	f := newFixture(t)
	c1, c2 := `"`+f.k.x5c()+`"`, `"`+f.other.x5c()+`"`
	der := f.k.cert.Raw
	for _, c := range []struct{ name, x5c string }{
		{"no certificate", `[]`},
		{"two certificates", `[` + c1 + `,` + c2 + `]`},
		{"the same certificate twice", `[` + c1 + `,` + c1 + `]`},
		{"three certificates", `[` + c1 + `,` + c2 + `,` + c1 + `]`},
		{"an empty text", `[""]`},
		{"text that is Base64 but not a certificate", `["` + stdB64([]byte("not a certificate")) + `"]`},
		{"a certificate with a byte after it", `["` + stdB64(append(bytes.Clone(der), 0)) + `"]`},
		{"a certificate cut short", `["` + stdB64(der[:len(der)-1]) + `"]`},
		{"a certificate cut to half", `["` + stdB64(der[:len(der)/2]) + `"]`},
		{"a certificate of one byte", `["` + stdB64(der[:1]) + `"]`},
		{"a certificate in url Base64", `["` + b64u(der) + `"]`},
		{"a certificate that is a key", `["` + stdB64(marshalPKIX(t, f.k)) + `"]`},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := goodHeader(f.k, typList)
			h.x5c = c.x5c
			p := h.text()
			refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
		})
	}
	for _, v := range b64Variants(f.k.x5c(), true) {
		t.Run("x5c: "+v.name, func(t *testing.T) {
			h := goodHeader(f.k, typList)
			h.x5c = `["` + v.text + `"]`
			p := h.text()
			refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
		})
	}
}

func TestParseGeneralRefusesKids(t *testing.T) {
	f := newFixture(t)
	pin := f.k.pin
	for _, c := range []struct{ name, kid string }{
		{"the pin of another key", f.other.pin},
		{"the pin in upper case", strings.ToUpper(pin)},
		{"one letter of the pin in upper case", upperFirstLetter(pin)},
		{"the last digit of the pin changed", pin[:63] + flipHex(pin[63])},
		{"the pin with a space before", " " + pin},
		{"the pin with a space after", pin + " "},
		{"the pin with a line feed after", pin + `\n`},
		{"63 digits", pin[:63]},
		{"65 digits", pin + "0"},
		{"empty", ""},
		{"64 characters that are not hexadecimal", strings.Repeat("g", 64)},
		{"the pin with a Cyrillic letter for a Latin one", "\u0430" + pin[1:]},
		{"the pin of the key as Base64url", b64u([]byte(pin))},
		{"the pin of the whole certificate", certPin(f.k)},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := goodHeader(f.k, typList)
			h.kid = `"` + c.kid + `"`
			p := h.text()
			refuses(t, file(entry(p, sigOver(t, f.k, p, f.payload))), typList)
		})
	}
}

func TestParseGeneralRefusesTheSameKidTwice(t *testing.T) {
	f := newFixture(t)
	t.Run("the same signature twice", func(t *testing.T) {
		refuses(t, file(f.entry(), f.entry()), typList)
	})
	t.Run("two signatures by one key, one header apart", func(t *testing.T) {
		h := goodHeader(f.k, typList)
		h.extra = ""
		h.x5c = `[ "` + f.k.x5c() + `" ]` // another text, the same kid
		p := h.text()
		refuses(t, file(f.entry(), entry(p, sigOver(t, f.k, p, f.payload))), typList)
	})
	t.Run("two certificates of one key are one kid", func(t *testing.T) {
		again := reissue(t, f.k)
		h := goodHeader(f.k, typList)
		h.x5c = `["` + stdB64(again.Raw) + `"]`
		p := h.text()
		refuses(t, file(f.entry(), entry(p, sigOver(t, f.k, p, f.payload))), typList)
	})
	t.Run("three signatures where the first and the last agree", func(t *testing.T) {
		refuses(t, file(f.entry(), goodEntry(t, f.other, typList, f.payload), f.entry()), typList)
	})
	t.Run("two keys are two kids", func(t *testing.T) {
		if _, err := jws.ParseGeneral(file(f.entry(), goodEntry(t, f.other, typList, f.payload)), typList); err != nil {
			t.Fatal(err)
		}
	})
}

func TestParseGeneralRefusesBase64Forms(t *testing.T) {
	f := newFixture(t)
	for _, v := range b64Variants(f.protected, false) {
		t.Run("protected: "+v.name, func(t *testing.T) {
			refuses(t, file(entry(v.text, f.sig)), typList)
		})
	}
	for _, v := range b64Variants(f.sig, false) {
		t.Run("signature: "+v.name, func(t *testing.T) {
			refuses(t, file(entry(f.protected, v.text)), typList)
		})
	}
	t.Run("protected whose header would be good in another form", func(t *testing.T) {
		// The text of a good header in standard Base64 with padding: the same bytes, the wrong spelling.
		// A header of ASCII has the same characters in both alphabets, so the wrong spelling that
		// remains is the padding: white space after the object makes the length one that needs it.
		padded := 0
		for spaces := range 3 {
			raw := goodHeader(f.k, typList).json() + strings.Repeat(" ", spaces)
			std := stdB64([]byte(raw))
			if !strings.HasSuffix(std, "=") {
				continue
			}
			padded++
			refuses(t, file(entry(std, f.sig)), typList)
		}
		if padded == 0 {
			t.Fatal("no length of the header needs padding: the test checked nothing")
		}
	})
}

func TestParseGeneralRefusesBase64PaddingBitsOfTheHeader(t *testing.T) {
	f := newFixture(t)
	// A header whose JSON has a length that leaves padding bits, with the last character moved to
	// the next one: the bytes decode to the same header, and the text is not the one spelling.
	for pad := range 3 {
		h := goodHeader(f.k, typList)
		h.extra = ""
		raw := h.json() + strings.Repeat(" ", pad) // white space after the object is allowed JSON
		text := b64u([]byte(raw))
		v, ok := nonZeroPaddingBits(text)
		if !ok {
			continue
		}
		if _, err := jws.ParseGeneral(file(entry(text, f.sig)), typList); err != nil {
			t.Fatalf("pad %d: the canonical spelling is refused: %v", pad, err)
		}
		refuses(t, file(entry(v, f.sig)), typList)
	}
}

func TestParseGeneralRefusesSignatureSizes(t *testing.T) {
	f := newFixture(t)
	der, err := ecdsa.SignASN1(rand.Reader, f.k.priv, make([]byte, 48))
	if err != nil {
		t.Fatal(err)
	}
	if len(der) == 96 {
		t.Fatalf("the DER form happens to be 96 bytes; run again")
	}
	good := f.k.rawSign(t, []byte("x"))
	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"empty", nil},
		{"one byte", good[:1]},
		{"r only", good[:48]},
		{"95 bytes", good[:95]},
		{"97 bytes", append(bytes.Clone(good), 0)},
		{"98 bytes", append(bytes.Clone(good), 0, 0)},
		{"the ASN.1 form of the same size class", der},
		{"the ASN.1 form of 103 bytes", der103()},
		{"two signatures end to end", append(bytes.Clone(good), good...)},
		{"a P-256 signature", make([]byte, 64)},
		{"a P-521 signature", make([]byte, 132)},
	} {
		t.Run(c.name, func(t *testing.T) {
			refuses(t, file(entry(f.protected, b64u(c.sig))), typList)
		})
	}
	t.Run("96 bytes of anything are read, and fail only when checked", func(t *testing.T) {
		g, err := jws.ParseGeneral(file(entry(f.protected, b64u(make([]byte, 96)))), typList)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.Signatures[0].Verify(f.payload); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("the zero signature verified or gave the wrong error: %v", err)
		}
	})
}

func TestParseGeneralRefusesTheContainer(t *testing.T) {
	f := newFixture(t)
	e := f.entry()
	for _, c := range []struct{ name, data string }{
		{"empty file", ``},
		{"white space only", " \n"},
		{"null", `null`},
		{"an array", `[` + e + `]`},
		{"a string", `"signatures"`},
		{"a number", `1`},
		{"no members", `{}`},
		{"signatures empty", `{"signatures":[]}`},
		{"signatures null", `{"signatures":null}`},
		{"signatures an object", `{"signatures":` + e + `}`},
		{"signatures a string", `{"signatures":"x"}`},
		{"signatures a list of strings", `{"signatures":["x"]}`},
		{"signatures a list of lists", `{"signatures":[[]]}`},
		{"the flattened form", e},
		{"unterminated", `{"signatures":[` + e + `]`},
		{"cut in the middle of an entry", `{"signatures":[` + e[:len(e)/2]},
		{"a byte order mark", "\xef\xbb\xbf" + string(file(e))},
		{"a byte after the object", string(file(e)) + `x`},
		{"a second object after the first", string(file(e)) + string(file(e))},
		{"a comma after the object", string(file(e)) + `,`},
		{"signatures twice", `{"signatures":[` + e + `],"signatures":[` + e + `]}`},
		{"a payload member", `{"payload":"e30","signatures":[` + e + `]}`},
		{"an empty payload member", `{"payload":"","signatures":[` + e + `]}`},
		{"an unprotected header", `{"header":{"kid":"x"},"signatures":[` + e + `]}`},
		{"an empty unprotected header", `{"header":{},"signatures":[` + e + `]}`},
		{"a protected member beside the signatures", `{"protected":"` + f.protected + `","signatures":[` + e + `]}`},
		{"a signature member beside the signatures", `{"signature":"` + f.sig + `","signatures":[` + e + `]}`},
		{"an unknown member", `{"signatures":[` + e + `],"x":1}`},
		{"a member in another letter case", `{"Signatures":[` + e + `]}`},
		{"a look-alike member name", "{\"sign\u0430tures\":[" + e + "]}"}, // Cyrillic a
		{"a member name that is not UTF-8", "{\"signatures\xff\":[" + e + "]}"},
		{"a member name with a control character", "{\"signatures\\u0000\":[" + e + "]}"},
		{"a member name that is a lone surrogate", `{"signatures\ud800":[` + e + `]}`},
		{"an entry with no members", `{"signatures":[{}]}`},
		{"an entry null", `{"signatures":[null]}`},
		{"an entry a string", `{"signatures":["` + f.protected + `"]}`},
		{"an entry without protected", `{"signatures":[{"signature":"` + f.sig + `"}]}`},
		{"an entry without signature", `{"signatures":[{"protected":"` + f.protected + `"}]}`},
		{"an entry with an unprotected header", `{"signatures":[{"header":{"kid":"x"},"protected":"` + f.protected + `","signature":"` + f.sig + `"}]}`},
		{"an entry with an empty unprotected header", `{"signatures":[{"header":{},"protected":"` + f.protected + `","signature":"` + f.sig + `"}]}`},
		{"an entry with a payload", `{"signatures":[{"payload":"e30","protected":"` + f.protected + `","signature":"` + f.sig + `"}]}`},
		{"an entry with an unknown member", `{"signatures":[{"protected":"` + f.protected + `","signature":"` + f.sig + `","x":1}]}`},
		{"an entry with protected twice", `{"signatures":[{"protected":"` + f.protected + `","protected":"` + f.protected + `","signature":"` + f.sig + `"}]}`},
		{"an entry with signature twice", `{"signatures":[{"protected":"` + f.protected + `","signature":"` + f.sig + `","signature":"` + f.sig + `"}]}`},
		{"protected null", `{"signatures":[{"protected":null,"signature":"` + f.sig + `"}]}`},
		{"protected a number", `{"signatures":[{"protected":1,"signature":"` + f.sig + `"}]}`},
		{"protected an object", `{"signatures":[{"protected":{},"signature":"` + f.sig + `"}]}`},
		{"signature null", `{"signatures":[{"protected":"` + f.protected + `","signature":null}]}`},
		{"signature a number", `{"signatures":[{"protected":"` + f.protected + `","signature":1}]}`},
		{"signature a list", `{"signatures":[{"protected":"` + f.protected + `","signature":["` + f.sig + `"]}]}`},
		{"the second entry is broken", `{"signatures":[` + e + `,{}]}`},
		{"a float in an unknown member", `{"signatures":[` + e + `],"x":1.5}`},
		{"a nesting bomb", `{"signatures":[` + e + `],"x":` + strings.Repeat(`[`, 20000) + strings.Repeat(`]`, 20000) + `}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			refuses(t, []byte(c.data), typList)
		})
	}
	t.Run("protected with an escaped character", func(t *testing.T) {
		// The text must be the one that was signed: a JSON escape that spells the same characters is
		// read as them, and a text that decodes the same is the same text.
		escaped := strings.Replace(f.protected, f.protected[:1], `\u`+hex4(f.protected[0]), 1)
		g, err := jws.ParseGeneral(file(entry(escaped, f.sig)), typList)
		if err != nil {
			t.Fatalf("an escape of a plain character is the same text: %v", err)
		}
		if g.Signatures[0].Protected != f.protected {
			t.Errorf("Protected is not the text that the escape spells")
		}
	})
}

func TestParseGeneralAnyErrorIsASCIIForHostileText(t *testing.T) {
	f := newFixture(t)
	hostile := []string{
		"\xff\xfe", "\x00", "\x1b[31m", "\u0430\u0431", "\u212a", "\u202e", "\u200b", "\r\n", "\U0001f600", strings.Repeat("\u0430", 500),
		`\ud800`, `\u0000`,
	}
	for _, h := range hostile {
		for _, c := range []struct {
			name string
			edit func(*header, string)
		}{
			{"alg", func(x *header, s string) { x.alg = `"` + s + `"` }},
			{"typ", func(x *header, s string) { x.typ = `"` + s + `"` }},
			{"kid", func(x *header, s string) { x.kid = `"` + s + `"` }},
			{"x5c", func(x *header, s string) { x.x5c = `["` + s + `"]` }},
			{"member name", func(x *header, s string) { x.extra = `,"` + s + `":1` }},
		} {
			t.Run(c.name+" "+h, func(t *testing.T) {
				hd := goodHeader(f.k, typList)
				c.edit(&hd, h)
				refuses(t, file(entry(hd.text(), f.sig)), typList)
			})
		}
		t.Run("member name of the container "+h, func(t *testing.T) {
			refuses(t, []byte(`{"signatures":[`+f.entry()+`],"`+h+`":1}`), typList)
		})
		t.Run("member name of the entry "+h, func(t *testing.T) {
			refuses(t, []byte(`{"signatures":[{"protected":"`+f.protected+`","signature":"`+f.sig+`","`+h+`":1}]}`), typList)
		})
	}
}

// der103 is an ASN.1 sequence of two integers with the 48-byte r and the 49-byte s (a leading zero
// keeps it positive): the form that a library of ECDSA writes, 103 bytes.
func der103() []byte {
	r := bytes.Repeat([]byte{0x01}, 48)
	s := append([]byte{0x00}, bytes.Repeat([]byte{0x81}, 48)...)
	out := []byte{0x30, 0x65, 0x02, 0x30}
	out = append(out, r...)
	out = append(out, 0x02, 0x31)
	out = append(out, s...)
	return out
}
