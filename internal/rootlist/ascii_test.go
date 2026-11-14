package rootlist_test

import (
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/rootlist"
)

// hostile is text that a file could carry in a place where the host shows it: bytes that are not
// UTF-8, control characters, characters that look like Latin letters, characters that change how
// text is shown, and text that is very long. Each is inserted into a JSON string as it is.
var hostile = []string{
	"\xff\xfe", "\x80", "\xc3\x28", "\xe2\x28\xa1", "\xf0\x28\x8c\xbc", "\xed\xa0\x80", "\xc0\xaf",
	"\x00", "\x01\x02", "\x1b[31mred", "\x7f", "\x0b\x0c",
	"\xd0\xb0",         // Cyrillic small a
	"\xd0\x90",         // Cyrillic capital A
	"\xd0\x95S384",     // Cyrillic capital Ie then S384
	"\xe2\x84\xaa",     // the Kelvin sign
	"\xe2\x80\xae",     // right-to-left override
	"\xe2\x80\x8b",     // zero width space
	"\xef\xbb\xbf",     // a byte order mark
	"\xf0\x9f\x98\x80", // an emoji
	"\xcc\x81",         // a combining accent
	"\xe2\x80\xa8",     // the line separator
	"\xc2\x85",         // next line
	"a\xd0\xb0b",       // a Cyrillic letter inside Latin ones
	strings.Repeat("\xd0\xb0", 500),
	strings.Repeat("a", 10000),
}

// hostileEscapes are escapes that a JSON reader turns into such characters.
var hostileEscapes = []string{`\u0000`, `\u0001`, `\ud800`, `\udc00`, `\ud800A`, `\u0430`, `\u202e`, `\n`, `\t`, `\U0001f600`, `\u212a`, `\u007f`, `\ufeff`}

func allHostile() []string { return append(append([]string{}, hostile...), hostileEscapes...) }

// shows fails the test when a verdict, or an error, carries text that is not printable ASCII.
func shows(t *testing.T, v rootlist.Verdict, err error) {
	t.Helper()
	mustBeASCII(t, "Detail", v.Detail)
	if err != nil {
		mustBeASCII(t, "the error text", err.Error())
	}
}

func TestTheListReaderShowsOnlyPrintableASCII(t *testing.T) {
	b := newBase(t)
	w := b.w
	j := b.cand.json()
	trust := b.trust(t)
	places := []struct {
		name string
		put  func(t testing.TB, h string) []byte
	}{
		{"a member name", func(t testing.TB, h string) []byte { return replace(t, j, `"version":1}`, `"version":1,"`+h+`":1}`) }},
		{"a member name in a root", func(t testing.TB, h string) []byte { return replace(t, j, `"label":"A"`, `"label":"A","`+h+`":1`) }},
		{"a label", func(t testing.TB, h string) []byte { return replace(t, j, `"label":"A"`, `"label":"`+h+`"`) }},
		{"a pin", func(t testing.TB, h string) []byte {
			return replace(t, j, `"x509_spki_sha256":"`+w.a.pin+`"`, `"x509_spki_sha256":"`+h+`"`)
		}},
		{"a fingerprint", func(t testing.TB, h string) []byte {
			return replace(t, j, `"openpgp_fingerprint":"`+w.a.fp()+`"`, `"openpgp_fingerprint":"`+h+`"`)
		}},
		{"a digest", func(t testing.TB, h string) []byte {
			return replace(t, j, `"last_record_sha256":"`+defaultLast+`"`, `"last_record_sha256":"`+h+`"`)
		}},
		{"a time", func(t testing.TB, h string) []byte {
			return replace(t, j, `"signed_at":"`+signedAt+`"`, `"signed_at":"`+h+`"`)
		}},
		{"an unknown string value", func(t testing.TB, h string) []byte { return replace(t, j, `"version":1}`, `"version":1,"x":"`+h+`"}`) }},
		{"the version", func(t testing.TB, h string) []byte { return replace(t, j, `"version":1`, `"version":"`+h+`"`) }},
		{"a removals entry", func(t testing.TB, h string) []byte {
			return replace(t, j, `"roots":[`, `"removals":[{"authorisation":"`+h+`","label":"`+h+`","x509_spki_sha256":"`+h+`","`+h+`":1}],"roots":[`)
		}},
	}
	for _, p := range places {
		for _, h := range allHostile() {
			name := p.name + " " + printableName(h)
			t.Run(name, func(t *testing.T) {
				data := p.put(t, h)
				v := rootlist.Verify(signedBytes(t, data, w.a), trust, now)
				if v.Accepted {
					t.Fatalf("accepted")
				}
				shows(t, v, nil)
				_, err := rootlist.ParseList(data)
				if err == nil {
					t.Fatalf("ParseList accepted")
				}
				shows(t, v, err)
				_, err = rootlist.ParseHeld(data)
				shows(t, v, err)
			})
		}
	}
}

func printableName(h string) string {
	var b strings.Builder
	for i := 0; i < len(h) && b.Len() < 24; i++ {
		c := h[i]
		if c >= 0x20 && c < 0x7f && c != '\\' {
			b.WriteByte(c)
		} else {
			b.WriteString("?")
		}
	}
	return b.String()
}

func TestTheSignatureReaderShowsOnlyPrintableASCII(t *testing.T) {
	b := newBase(t)
	w := b.w
	payload := b.cand.json()
	trust := b.trust(t)
	places := []struct {
		name string
		edit func(h *header, s string)
	}{
		{"alg", func(h *header, s string) { h.alg = `"` + s + `"` }},
		{"typ", func(h *header, s string) { h.typ = `"` + s + `"` }},
		{"kid", func(h *header, s string) { h.kid = `"` + s + `"` }},
		{"x5c", func(h *header, s string) { h.x5c = `["` + s + `"]` }},
		{"an extra member name", func(h *header, s string) { h.extra = `,"` + s + `":1` }},
		{"an extra member value", func(h *header, s string) { h.extra = `,"x":"` + s + `"` }},
	}
	for _, p := range places {
		for _, hs := range allHostile() {
			t.Run(p.name+" "+printableName(hs), func(t *testing.T) {
				h := goodHeader(w.a, typList)
				p.edit(&h, hs)
				pr := h.text()
				jws := jwsFile(entry(pr, sigOver(t, w.a, pr, payload)))
				v := rootlist.Verify(rootlist.Signed{JSON: payload, JWS: jws}, trust, now)
				refuses(t, v, rootlist.Malformed, 1)
			})
		}
	}
	containers := []struct {
		name string
		put  func(h string, e string) []byte
	}{
		{"a member name of the file", func(h, e string) []byte { return []byte(`{"signatures":[` + e + `],"` + h + `":1}`) }},
		{"a member name of an entry", func(h, e string) []byte {
			return []byte(`{"signatures":[` + strings.Replace(e, `{"protected"`, `{"`+h+`":1,"protected"`, 1) + `]}`)
		}},
		{"the protected text", func(h, e string) []byte { return []byte(`{"signatures":[{"protected":"` + h + `","signature":"AA"}]}`) }},
		{"the signature text", func(h, e string) []byte { return []byte(`{"signatures":[{"protected":"AA","signature":"` + h + `"}]}`) }},
		{"the whole file", func(h, e string) []byte { return []byte(h) }},
	}
	good := goodEntry(t, w.a, typList, payload)
	for _, c := range containers {
		for _, hs := range allHostile() {
			t.Run(c.name+" "+printableName(hs), func(t *testing.T) {
				v := rootlist.Verify(rootlist.Signed{JSON: payload, JWS: c.put(hs, good)}, trust, now)
				refuses(t, v, rootlist.Malformed, 1)
			})
		}
	}
}

func TestTheRemovalReaderShowsOnlyPrintableASCII(t *testing.T) {
	b := newBase(t)
	w := b.w
	for _, hs := range allHostile() {
		for _, c := range []struct {
			name string
			auth func(h string) string
		}{
			{"the whole authorisation", func(h string) string { return h }},
			{"a part of it", func(h string) string { return "AA." + h + ".AA" }},
			{"the protected part", func(h string) string { return h + "." + b64u([]byte("{}")) + "." + b64u(make([]byte, 96)) }},
			{"the payload part", func(h string) string {
				return goodHeader(w.a, typRemoval).text() + "." + h + "." + b64u(make([]byte, 96))
			}},
			{"an alg", func(h string) string {
				hd := goodHeader(w.a, typRemoval)
				hd.alg = `"` + h + `"`
				return authWith(t, w.a, hd, removalPayload(w.a.pin))
			}},
			{"a typ", func(h string) string {
				hd := goodHeader(w.a, typRemoval)
				hd.typ = `"` + h + `"`
				return authWith(t, w.a, hd, removalPayload(w.a.pin))
			}},
			{"a kid", func(h string) string {
				hd := goodHeader(w.a, typRemoval)
				hd.kid = `"` + h + `"`
				return authWith(t, w.a, hd, removalPayload(w.a.pin))
			}},
			{"a payload", func(h string) string { return authWith(t, w.a, goodHeader(w.a, typRemoval), []byte(h)) }},
		} {
			t.Run(c.name+" "+printableName(hs), func(t *testing.T) {
				auth := c.auth(hs)
				// The text goes into the JSON of the list as a string, so quote what JSON needs.
				if !strings.ContainsAny(hs, "\\\"") && !strings.ContainsAny(hs, "\x00\x01\x02\x0b\x0c\x1b\x7f") && validUTF8(auth) {
					v := removalVerdict(t, b, auth)
					refuses(t, v, rootlist.RemovalInvalid, 9)
				}
				// The same text through CheckRemoval, which takes any bytes.
				err := rootlist.CheckRemoval(rootlist.Removal{Label: "A", X509SPKISHA256: w.a.pin, Authorisation: auth}, listFor(t, 8, w.b), []string{w.a.pin, w.b.pin})
				if err == nil {
					t.Fatalf("accepted")
				}
				mustBeASCII(t, "the error text", err.Error())
			})
		}
	}
}

func validUTF8(s string) bool { return strings.ToValidUTF8(s, "") == s }

func TestTheCABundleVerdictShowsOnlyPrintableASCII(t *testing.T) {
	w := newWorld(t)
	l := listFor(t, 7, w.a, w.b)
	for _, hs := range allHostile() {
		for name, bundle := range map[string]string{
			"as the whole bundle":     hs,
			"after the first line":    "# trust-sequence: 7\n" + hs,
			"as the first line":       hs + "\n" + w.a.certPEM() + w.b.certPEM(),
			"between the blocks":      "# trust-sequence: 7\n" + w.a.certPEM() + hs + "\n" + w.b.certPEM(),
			"after the blocks":        bundleOf(7, w.a, w.b) + hs,
			"in a header line":        "# trust-sequence: 7\n-----BEGIN CERTIFICATE-----\nX: " + hs + "\n\n" + strings.TrimPrefix(w.a.certPEM(), "-----BEGIN CERTIFICATE-----\n") + w.b.certPEM(),
			"as a label":              "# trust-sequence: 7\n-----BEGIN " + hs + "-----\nAA==\n-----END " + hs + "-----\n",
			"as the sequence":         "# trust-sequence: " + hs + "\n" + w.a.certPEM() + w.b.certPEM(),
			"in the base64 of a cert": "# trust-sequence: 7\n-----BEGIN CERTIFICATE-----\n" + hs + "\n-----END CERTIFICATE-----\n",
		} {
			t.Run(name+" "+printableName(hs), func(t *testing.T) { mismatch(t, rootlist.VerifyCABundle([]byte(bundle), l)) })
		}
	}
}

func TestPinTrustShowsOnlyPrintableASCII(t *testing.T) {
	for _, hs := range allHostile() {
		_, err := rootlist.PinTrust([]string{hs})
		if err == nil {
			t.Errorf("accepted %q", printableName(hs))
			continue
		}
		mustBeASCII(t, "the error text", err.Error())
	}
}

// TestLookAlikesAreNotTheLetters writes each look-alike as UTF-8 in the places where the page
// wants an ASCII letter or a hexadecimal digit.
func TestLookAlikesAreNotTheLetters(t *testing.T) {
	b := newBase(t)
	w := b.w
	j := b.cand.json()
	trust := b.trust(t)
	pinA, fpA := w.a.pin, w.a.fp()
	for name, edit := range map[string]func() []byte{
		"a Cyrillic A for the label A":              func() []byte { return replace(t, j, `"label":"A"`, "\"label\":\"\u0410\"") },
		"a Greek capital Alpha for the label A":     func() []byte { return replace(t, j, `"label":"A"`, "\"label\":\"\u0391\"") },
		"a full-width A for the label A":            func() []byte { return replace(t, j, `"label":"A"`, "\"label\":\"\uff21\"") },
		"the Kelvin sign for the label K":           func() []byte { return replace(t, j, `"label":"B"`, "\"label\":\"\u212a\"") },
		"a Cyrillic a in a pin":                     func() []byte { return replace(t, j, pinA, "\u0430"+pinA[1:]) },
		"a Cyrillic o for a zero in a pin":          func() []byte { return replace(t, j, pinA, strings.Replace(pinA, pinA[:1], "\u043e", 1)) },
		"a Cyrillic e in a fingerprint":             func() []byte { return replace(t, j, fpA, "\u0435"+fpA[1:]) },
		"a Cyrillic e in a member name":             func() []byte { return replace(t, j, `"expires_at"`, "\"\u0435xpires_at\"") },
		"a Cyrillic o in a member name":             func() []byte { return replace(t, j, `"roots"`, "\"r\u043eots\"") },
		"a Cyrillic a in a member name of a root":   func() []byte { return replace(t, j, `"label"`, "\"l\u0430bel\"") },
		"a full-width digit in the sequence text":   func() []byte { return replace(t, j, `"sequence":8`, "\"sequence\":\uff18") },
		"a non-breaking hyphen in a member name":    func() []byte { return replace(t, j, `"signed_at"`, "\"signed\u2011at\"") },
		"a zero width space in a member name":       func() []byte { return replace(t, j, `"version"`, "\"vers\u200bion\"") },
		"a zero width joiner in the label":          func() []byte { return replace(t, j, `"label":"A"`, "\"label\":\"A\u200d\"") },
		"a Cyrillic letter in a digit of a time":    func() []byte { return replace(t, j, `"signed_at":"2026`, "\"signed_at\":\"\u0662026") },
		"an A with a combining ring above the root": func() []byte { return replace(t, j, `"label":"A"`, "\"label\":\"A\u030a\"") },
	} {
		t.Run(name, func(t *testing.T) {
			data := edit()
			v := rootlist.Verify(signedBytes(t, data, w.a), trust, now)
			if v.Accepted {
				t.Fatal("accepted")
			}
			if v.Reason != rootlist.Malformed || v.Check != 5 {
				t.Errorf("refused with %q at check %d: %s", v.Reason, v.Check, v.Detail)
			}
			mustBeASCII(t, "Detail", v.Detail)
		})
	}
	for name, h := range map[string]func(*header){
		"a Cyrillic E in alg":           func(h *header) { h.alg = "\"\u0415S384\"" },
		"a Cyrillic S in alg":           func(h *header) { h.alg = "\"E\u0405384\"" },
		"a Cyrillic o in typ":           func(h *header) { h.typ = "\"r\u043eot-list+json\"" },
		"a non-breaking hyphen":         func(h *header) { h.typ = "\"root\u2011list+json\"" },
		"a Cyrillic a in the kid":       func(h *header) { h.kid = "\"\u0430" + w.a.pin[1:] + "\"" },
		"a full-width digit in the kid": func(h *header) { h.kid = "\"\uff11" + w.a.pin[1:] + "\"" },
		"a Cyrillic a in a member":      func(h *header) { h.extra = ",\"\u0430lg\":\"ES384\"" },
	} {
		t.Run(name, func(t *testing.T) {
			hd := goodHeader(w.a, typList)
			h(&hd)
			p := hd.text()
			jws := jwsFile(entry(p, sigOver(t, w.a, p, j)))
			v := rootlist.Verify(rootlist.Signed{JSON: j, JWS: jws}, trust, now)
			refuses(t, v, rootlist.Malformed, 1)
		})
	}
}
