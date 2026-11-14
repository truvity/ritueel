package jws_test

import (
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/jws"
)

// refusesCompact fails the test unless s is refused by ParseCompact with an error that wraps
// ErrMalformed and shows printable ASCII only.
func refusesCompact(t *testing.T, s, typ string) {
	t.Helper()
	c, err := jws.ParseCompact(s, typ)
	if err == nil {
		t.Fatalf("accepted; want an error that wraps ErrMalformed (payload %d bytes)", len(c.Payload))
	}
	if c != nil {
		t.Errorf("a refusal returned a value")
	}
	if !errors.Is(err, jws.ErrMalformed) {
		t.Errorf("the error does not wrap ErrMalformed: %v", err)
	}
	mustBeASCII(t, "the error text", err.Error())
}

// raw turns the JSON escapes of a variant into the characters, for a text that is not in JSON.
func raw(s string) string {
	return strings.NewReplacer(`\n`, "\n", `\r`, "\r", `\t`, "\t").Replace(s)
}

func TestParseCompactAccepts(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"version":1,"x509_spki_sha256":"` + k.pin + `"}`)
	s := goodCompact(t, k, typRemoval, payload)
	c, err := jws.ParseCompact(s, typRemoval)
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Payload) != string(payload) || c.PayloadText != b64u(payload) {
		t.Errorf("the payload is not read as it is")
	}
	if c.Header.Kid != k.pin || c.Header.Typ != typRemoval || c.Header.Alg != "ES384" || len(c.Header.X5C) != 1 {
		t.Errorf("header read wrongly: %+v", c.Header)
	}
	if c.Protected != strings.SplitN(s, ".", 3)[0] || len(c.Sig) != 96 || c.Cert == nil || jws.Pin(c.Cert) != k.pin {
		t.Errorf("the parts are not as read")
	}
	if err := c.Verify(); err != nil {
		t.Errorf("a good signature does not verify: %v", err)
	}
	t.Run("an empty-looking payload is still three parts", func(t *testing.T) {
		// A payload of one byte is the shortest that the form allows.
		if _, err := jws.ParseCompact(goodCompact(t, k, typRemoval, []byte("x")), typRemoval); err != nil {
			t.Error(err)
		}
	})
}

func TestParseCompactRefusesTheShape(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"version":1}`)
	good := goodCompact(t, k, typRemoval, payload)
	parts := strings.Split(good, ".")
	for _, c := range []struct{ name, s string }{
		{"empty", ""},
		{"a dot", "."},
		{"two dots", ".."},
		{"one part", parts[0]},
		{"two parts", parts[0] + "." + parts[1]},
		{"four parts", good + "." + parts[2]},
		{"an empty header", "." + parts[1] + "." + parts[2]},
		{"an empty payload", parts[0] + ".." + parts[2]},
		{"an empty signature", parts[0] + "." + parts[1] + "."},
		{"a line feed at the end", good + "\n"},
		{"a carriage return and line feed at the end", good + "\r\n"},
		{"a space at the end", good + " "},
		{"a space at the start", " " + good},
		{"a space before a dot", parts[0] + " ." + parts[1] + "." + parts[2]},
		{"a line feed in the payload", parts[0] + "." + parts[1][:3] + "\n" + parts[1][3:] + "." + parts[2]},
		{"the general form", string(file(entry(parts[0], parts[2])))},
		{"a byte order mark", "\xef\xbb\xbf" + good},
		{"a byte that is not UTF-8", good[:10] + "\xff" + good[11:]},
		{"a NUL", good + "\x00"},
		{"the three parts in another order", parts[2] + "." + parts[1] + "." + parts[0]},
	} {
		t.Run(c.name, func(t *testing.T) { refusesCompact(t, c.s, typRemoval) })
	}
}

func TestParseCompactRefusesBase64Forms(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"version":1,"note":"a payload that is long enough to hold bytes of both kinds: ~~~ >>> ???"}`)
	p := goodHeader(k, typRemoval).text()
	sig := sigOver(t, k, p, payload)
	text := b64u(payload)
	for _, v := range b64Variants(p, false) {
		t.Run("protected: "+v.name, func(t *testing.T) { refusesCompact(t, compact(raw(v.text), text, sig), typRemoval) })
	}
	for _, v := range b64Variants(text, false) {
		t.Run("payload: "+v.name, func(t *testing.T) {
			// An empty part is refused by the shape of the three parts, and is a case like the others.
			refusesCompact(t, compact(p, raw(v.text), sig), typRemoval)
		})
	}
	for _, v := range b64Variants(sig, false) {
		t.Run("signature: "+v.name, func(t *testing.T) { refusesCompact(t, compact(p, text, raw(v.text)), typRemoval) })
	}
}

func TestParseCompactRefusesTheHeader(t *testing.T) {
	k, other := newKey(t), newKey(t)
	payload := []byte(`{"version":1}`)
	mk := func(edit func(*header)) string {
		h := goodHeader(k, typRemoval)
		edit(&h)
		p := h.text()
		return compact(p, b64u(payload), sigOver(t, k, p, payload))
	}
	for _, c := range []struct {
		name string
		edit func(*header)
	}{
		{"alg none", func(h *header) { h.alg = `"none"` }},
		{"alg ES256", func(h *header) { h.alg = `"ES256"` }},
		{"alg es384", func(h *header) { h.alg = `"es384"` }},
		{"alg with a Cyrillic letter", func(h *header) { h.alg = "\"\u0415S384\"" }},
		{"no alg", func(h *header) { h.drop = "alg" }},
		{"typ of the list", func(h *header) { h.typ = `"` + typList + `"` }},
		{"typ in upper case", func(h *header) { h.typ = `"ROOT-REMOVAL+JSON"` }},
		{"no typ", func(h *header) { h.drop = "typ" }},
		{"no kid", func(h *header) { h.drop = "kid" }},
		{"kid of another key", func(h *header) { h.kid = `"` + other.pin + `"` }},
		{"kid in upper case", func(h *header) { h.kid = `"` + strings.ToUpper(k.pin) + `A"` }},
		{"no x5c", func(h *header) { h.drop = "x5c" }},
		{"x5c empty", func(h *header) { h.x5c = `[]` }},
		{"x5c twice", func(h *header) { h.x5c = `["` + k.x5c() + `","` + k.x5c() + `"]` }},
		{"x5c of another key", func(h *header) { h.x5c = `["` + other.x5c() + `"]` }},
		{"crit", func(h *header) { h.extra = `,"crit":["b64"]` }},
		{"b64 false", func(h *header) { h.extra = `,"b64":false` }},
		{"jwk", func(h *header) { h.extra = `,"jwk":{}` }},
		{"another kid", func(h *header) { h.extra = `,"kid":"` + k.pin + `"` }},
	} {
		t.Run(c.name, func(t *testing.T) { refusesCompact(t, mk(c.edit), typRemoval) })
	}
	t.Run("the type asked for is the one read", func(t *testing.T) {
		s := goodCompact(t, k, typList, payload)
		refusesCompact(t, s, typRemoval)
		if _, err := jws.ParseCompact(s, typList); err != nil {
			t.Errorf("the list type is refused when it is asked for: %v", err)
		}
	})
}

func TestParseCompactRefusesSignatureSizes(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"version":1}`)
	p := goodHeader(k, typRemoval).text()
	good := k.rawSign(t, []byte(p+"."+b64u(payload)))
	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"one byte", good[:1]},
		{"95 bytes", good[:95]},
		{"97 bytes", append(append([]byte{}, good...), 0)},
		{"the ASN.1 form", der103()},
		{"192 bytes", append(append([]byte{}, good...), good...)},
	} {
		t.Run(c.name, func(t *testing.T) { refusesCompact(t, compact(p, b64u(payload), b64u(c.sig)), typRemoval) })
	}
}

func TestCompactVerify(t *testing.T) {
	k, other := newKey(t), newKey(t)
	payload := []byte(`{"version":1,"x509_spki_sha256":"` + k.pin + `"}`)
	p := goodHeader(k, typRemoval).text()
	good := compact(p, b64u(payload), sigOver(t, k, p, payload))
	t.Run("good", func(t *testing.T) {
		c, err := jws.ParseCompact(good, typRemoval)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Verify(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another payload under the same signature", func(t *testing.T) {
		for _, other := range [][]byte{[]byte(`{"version":1}`), append([]byte{}, append(payload, ' ')...), payload[:len(payload)-1], []byte("x")} {
			c, err := jws.ParseCompact(compact(p, b64u(other), strings.Split(good, ".")[2]), typRemoval)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Verify(); !errors.Is(err, jws.ErrSignature) {
				t.Errorf("payload %q: got %v, want ErrSignature", other, err)
			}
		}
	})
	t.Run("a signature by another key under this key's header", func(t *testing.T) {
		c, err := jws.ParseCompact(compact(p, b64u(payload), sigOver(t, other, p, payload)), typRemoval)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Verify(); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("got %v, want ErrSignature", err)
		}
	})
	t.Run("the signature of the list type over the same bytes", func(t *testing.T) {
		pl := goodHeader(k, typList).text()
		c, err := jws.ParseCompact(compact(pl, b64u(payload), sigOver(t, k, p, payload)), typList)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Verify(); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("a signature over another protected text verified: %v", err)
		}
	})
	t.Run("a payload text that decodes to other bytes than the text says", func(t *testing.T) {
		c, err := jws.ParseCompact(good, typRemoval)
		if err != nil {
			t.Fatal(err)
		}
		c.PayloadText = b64u(append(append([]byte{}, c.Payload...), ' '))
		if err := c.Verify(); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("Verify did not cover the payload text: %v", err)
		}
	})
	t.Run("a compact value with no certificate", func(t *testing.T) {
		c := &jws.Compact{Protected: p, PayloadText: b64u(payload), Sig: make([]byte, 96)}
		if err := c.Verify(); !errors.Is(err, jws.ErrSignature) {
			t.Errorf("got %v, want ErrSignature", err)
		}
	})
}

func TestParseCompactAnyErrorIsASCIIForHostileText(t *testing.T) {
	k := newKey(t)
	payload := []byte(`{"version":1}`)
	for _, h := range []string{"\xff\xfe", "\x00", "\x1b[31m", "\u0430\u0431", "\u212a", "\u202e", "\r\n", "\U0001f600", strings.Repeat("\u0430", 500), `\ud800`, `\u0000`} {
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
				hd := goodHeader(k, typRemoval)
				c.edit(&hd, h)
				p := hd.text()
				refusesCompact(t, compact(p, b64u(payload), sigOver(t, k, p, payload)), typRemoval)
			})
		}
	}
	t.Run("a header that is not UTF-8 at all", func(t *testing.T) {
		p := b64u([]byte("\xff\xfe\x00\x01"))
		refusesCompact(t, compact(p, b64u(payload), b64u(make([]byte, 96))), typRemoval)
	})
}
