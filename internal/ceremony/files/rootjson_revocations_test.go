package files_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/strictjson"
)

// roots/<label>/root.json of a label with an OpenPGP primary (docs/reference/bundle.md,
// "`root.json`"; record 0007, rule 21): besides the X.509 members it holds openpgp_fingerprint,
// openpgp_created and revocations, an object from a reason to the SHA-256 of that revocation
// signature packet. The reasons compromised and superseded are always made; retired and no-reason
// when the holder asks. A label without a primary has none of the three members.

const (
	pgpFpr     = "0123456789abcdef0123456789abcdef01234567"
	pgpCreated = "2026-11-20T09:00:00Z"
)

// rjPrimaryDoc is the root.json of a label that has both kinds of key.
func rjPrimaryDoc() map[string]any {
	m := rjDoc()
	m["openpgp_fingerprint"] = pgpFpr
	m["openpgp_created"] = pgpCreated
	m["revocations"] = map[string]any{"compromised": dg('1'), "superseded": dg('2')}
	return m
}

func revsOf(m map[string]any) map[string]any { return m["revocations"].(map[string]any) }

func rjPrimaryRead(t *testing.T, edit func(map[string]any)) (*files.RootJSON, error) {
	t.Helper()
	return files.ReadRootJSON(encode(t, rjPrimaryDoc(), edit))
}

// The bytes of the file as the page gives its members, sorted as RFC 8785 sorts them, written by
// hand and not by the code under test.
func rjPrimaryText(revs string) string {
	return `{"created_at":"2026-11-20T10:00:00Z","label":"A","openpgp_created":"` + pgpCreated +
		`","openpgp_fingerprint":"` + pgpFpr + `","removal_sha256":"` + dg('c') + `","revocations":` + revs +
		`,"store":"software","test":true,"version":1,"x509_spki_sha256":"` + dg('a') + `"}`
}

func TestARootJSONOfALabelWithAPrimaryIsReadAndWrittenInTheCanonicalOrder(t *testing.T) {
	want := rjPrimaryText(`{"compromised":"` + dg('1') + `","superseded":"` + dg('2') + `"}`)
	r, err := files.ReadRootJSON([]byte(want))
	if err != nil {
		t.Fatalf("ReadRootJSON: %v", err)
	}
	wantVal := files.RootJSON{
		Version: 1, Label: "A", Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z",
		X509SPKISHA256: dg('a'), OpenPGPFingerprint: pgpFpr, OpenPGPCreated: pgpCreated,
		Revocations:   map[string]string{"compromised": dg('1'), "superseded": dg('2')},
		RemovalSHA256: dg('c'),
	}
	if !reflect.DeepEqual(*r, wantVal) {
		t.Errorf("got %+v, want %+v", *r, wantVal)
	}
	got, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("Canonical:\n%s\nwant\n%s", got, want)
	}
	if ok, err := canonjson.IsCanonical(got); err != nil || !ok {
		t.Errorf("IsCanonical = %v, %v", ok, err)
	}
	// The same value written from a struct in any order of insertion gives the same bytes.
	again, err := wantVal.Canonical()
	if err != nil || !bytes.Equal(again, got) {
		t.Errorf("Canonical of the built value = %s, %v", again, err)
	}
}

func TestARootJSONMayHoldTheTwoReasonsThatTheHolderAsksFor(t *testing.T) {
	sets := map[string][]string{
		"the two always made":    {"compromised", "superseded"},
		"with retired":           {"compromised", "superseded", "retired"},
		"with no-reason":         {"compromised", "superseded", "no-reason"},
		"with all four reasons":  {"compromised", "superseded", "retired", "no-reason"},
		"all four, other order":  {"no-reason", "retired", "superseded", "compromised"},
		"only retired and below": {"superseded", "compromised", "retired"},
	}
	for name, reasons := range sets {
		t.Run(name, func(t *testing.T) {
			revs := map[string]any{}
			for i, w := range reasons {
				revs[w] = dg("0123456789abcdef"[i+3])
			}
			b := encode(t, rjPrimaryDoc(), set("revocations", revs))
			r, err := files.ReadRootJSON(b)
			if err != nil {
				t.Fatalf("ReadRootJSON: %v", err)
			}
			if len(r.Revocations) != len(reasons) {
				t.Fatalf("read %d reasons, want %d", len(r.Revocations), len(reasons))
			}
			for i, w := range reasons {
				if r.Revocations[w] != dg("0123456789abcdef"[i+3]) {
					t.Errorf("reason %s holds %q", w, r.Revocations[w])
				}
			}
			out, err := r.Canonical()
			if err != nil || !bytes.Equal(out, b) {
				t.Errorf("Canonical = %s, %v; want the bytes that were read %s", out, err, b)
			}
			// The keys come in the order of RFC 8785: byte order of the names.
			i1, i2 := strings.Index(string(out), `"compromised"`), strings.Index(string(out), `"superseded"`)
			if i1 < 0 || i2 < i1 {
				t.Errorf("the keys are not in order: %s", out)
			}
			if i, j := strings.Index(string(out), `"no-reason"`), strings.Index(string(out), `"retired"`); i >= 0 && j >= 0 && i > j {
				t.Errorf("no-reason must come before retired: %s", out)
			}
		})
	}
}

func TestARootJSONOfAnX509KeyOnlyHasNoOpenPGPMembersAndKeepsItsBytes(t *testing.T) {
	// The root.json that part 13 wrote for a test root: the same bytes now, as the page lists them.
	text := `{"created_at":"2026-11-20T10:00:00Z","label":"A","removal_sha256":"` + dg('c') +
		`","store":"software","test":true,"version":1,"x509_spki_sha256":"` + dg('a') + `"}`
	r, err := files.ReadRootJSON([]byte(text))
	if err != nil {
		t.Fatalf("ReadRootJSON: %v", err)
	}
	if r.Revocations != nil || r.OpenPGPFingerprint != "" || r.OpenPGPCreated != "" {
		t.Errorf("an X.509 key has OpenPGP members: %+v", r)
	}
	out, err := r.Canonical()
	if err != nil || string(out) != text {
		t.Errorf("Canonical = %s, %v; want %s", out, err, text)
	}
	for _, w := range []string{"revocations", "openpgp"} {
		if strings.Contains(string(out), w) {
			t.Errorf("the file of an X.509 key holds %q: %s", w, out)
		}
	}
}

func TestEveryRootJSONWithRevocationsThatBreaksARuleIsRefusedWithTheMemberNamed(t *testing.T) {
	long := strings.Repeat("a", 300)
	cases := []struct {
		name   string
		edit   func(map[string]any)
		member string
	}{
		{"revocations with no fingerprint", without("openpgp_fingerprint", "openpgp_created"), "revocations"},
		{"revocations with no fingerprint and no pin", without("openpgp_fingerprint", "openpgp_created", "x509_spki_sha256"), "revocations"},
		{"a fingerprint with no revocations", without("revocations"), "revocations"},
		{"a fingerprint with no revocations and no pin", without("revocations", "x509_spki_sha256"), "revocations"},
		{"no compromised", func(m map[string]any) { delete(revsOf(m), "compromised") }, "revocations.compromised"},
		{"no superseded", func(m map[string]any) { delete(revsOf(m), "superseded") }, "revocations.superseded"},
		{"only retired", func(m map[string]any) { m["revocations"] = map[string]any{"retired": dg('3')} }, "revocations.compromised"},
		{"an empty object", set("revocations", map[string]any{}), "revocations.compromised"},
		{"an empty object with no fingerprint", func(m map[string]any) {
			delete(m, "openpgp_fingerprint")
			delete(m, "openpgp_created")
			m["revocations"] = map[string]any{}
		}, "revocations"},
		{"the key root-removal", func(m map[string]any) { revsOf(m)["root-removal"] = dg('3') }, "revocations"},
		{"a key in capitals", func(m map[string]any) { revsOf(m)["Retired"] = dg('3') }, "revocations"},
		{"a key with a space", func(m map[string]any) { revsOf(m)["retired "] = dg('3') }, "revocations"},
		{"an empty key", func(m map[string]any) { revsOf(m)[""] = dg('3') }, "revocations"},
		{"a fifth key", func(m map[string]any) {
			revsOf(m)["retired"], revsOf(m)["no-reason"], revsOf(m)["lost"] = dg('3'), dg('4'), dg('5')
		}, "revocations"},
		{"a long key", func(m map[string]any) { revsOf(m)[long] = dg('3') }, "revocations"},
		{"a value of 63 digits", func(m map[string]any) { revsOf(m)["compromised"] = dg('1')[:63] }, "revocations.compromised"},
		{"a value of 65 digits", func(m map[string]any) { revsOf(m)["superseded"] = dg('2') + "2" }, "revocations.superseded"},
		{"a value in upper case", func(m map[string]any) { revsOf(m)["compromised"] = strings.ToUpper(dg('a')) }, "revocations.compromised"},
		{"a value that is not hexadecimal", func(m map[string]any) { revsOf(m)["superseded"] = strings.Repeat("g", 64) }, "revocations.superseded"},
		{"an empty value", func(m map[string]any) { revsOf(m)["compromised"] = "" }, "revocations.compromised"},
		{"an empty retired value", func(m map[string]any) { revsOf(m)["retired"] = "" }, "revocations.retired"},
		{"a bad no-reason value", func(m map[string]any) { revsOf(m)["no-reason"] = "x" }, "revocations.no-reason"},
		{"a fingerprint of 39 digits", set("openpgp_fingerprint", pgpFpr[:39]), "openpgp_fingerprint"},
		{"a fingerprint of 41 digits", set("openpgp_fingerprint", pgpFpr+"0"), "openpgp_fingerprint"},
		{"a fingerprint in upper case", set("openpgp_fingerprint", strings.ToUpper(pgpFpr)), "openpgp_fingerprint"},
		{"a 64-digit digest in the place of the fingerprint", set("openpgp_fingerprint", dg('a')), "openpgp_fingerprint"},
		{"a creation time with no fingerprint", without("openpgp_fingerprint", "revocations"), "openpgp_created"},
		{"a fingerprint with no creation time", without("openpgp_created"), "openpgp_created"},
		{"a bad creation time", set("openpgp_created", "2026-11-20 09:00:00"), "openpgp_created"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := rjPrimaryRead(t, c.edit)
			if r != nil || err == nil {
				t.Fatalf("the file is read: %+v, %v", r, err)
			}
			wantMember(t, err, c.member)
			refused(t, err)
		})
	}
}

func TestARootJSONWithRevocationsOfTheWrongShapeIsRefusedAndNeverPanics(t *testing.T) {
	cases := map[string]any{
		"null":                   nil,
		"a string":               "compromised",
		"a number":               1,
		"true":                   true,
		"a list":                 []any{dg('1'), dg('2')},
		"a list of objects":      []any{map[string]any{"reason": "compromised", "sha256": dg('1')}},
		"an empty list":          []any{},
		"a value that is null":   map[string]any{"compromised": nil, "superseded": dg('2')},
		"a value that is a list": map[string]any{"compromised": []any{dg('1')}, "superseded": dg('2')},
		"a value that is a map":  map[string]any{"compromised": map[string]any{"sha256": dg('1')}, "superseded": dg('2')},
		"a value that is 1":      map[string]any{"compromised": 1, "superseded": dg('2')},
		"a value that is true":   map[string]any{"compromised": true, "superseded": dg('2')},
		"a nested object that is deep": func() any {
			var v any = dg('1')
			for range 300 {
				v = map[string]any{"a": v}
			}
			return map[string]any{"compromised": v, "superseded": dg('2')}
		}(),
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := rjPrimaryRead(t, set("revocations", v))
			if r != nil || err == nil {
				t.Fatalf("the file is read: %+v, %v", r, err)
			}
			refused(t, err)
		})
	}
	// The member that holds a map, left out with a null or an empty object, is not a way to say none.
	for _, text := range []string{
		rjPrimaryText(`null`), rjPrimaryText(`{}`), rjPrimaryText(`[]`),
		strings.Replace(rjPrimaryText(`{}`), `"revocations":{},`, ``, 1),
	} {
		r, err := files.ReadRootJSON([]byte(text))
		if r != nil || err == nil {
			t.Errorf("read %s: %+v, %v", text, r, err)
			continue
		}
		refused(t, err)
	}
}

func TestARootJSONWithRevocationsThatIsNotCanonicalIsRefused(t *testing.T) {
	bs := string(rune(0x5c))
	good := `{"compromised":"` + dg('1') + `","superseded":"` + dg('2') + `"}`
	if _, err := files.ReadRootJSON([]byte(rjPrimaryText(good))); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	cases := map[string]string{
		"the two keys out of order":        rjPrimaryText(`{"superseded":"` + dg('2') + `","compromised":"` + dg('1') + `"}`),
		"a space after a colon":            rjPrimaryText(`{"compromised": "` + dg('1') + `","superseded":"` + dg('2') + `"}`),
		"a space after a comma":            rjPrimaryText(`{"compromised":"` + dg('1') + `", "superseded":"` + dg('2') + `"}`),
		"a line feed in the object":        rjPrimaryText("{\n\"compromised\":\"" + dg('1') + `","superseded":"` + dg('2') + `"}`),
		"a key spelled with an escape":     rjPrimaryText(`{"compromis` + bs + `u0065d":"` + dg('1') + `","superseded":"` + dg('2') + `"}`),
		"retired before no-reason":         rjPrimaryText(`{"compromised":"` + dg('1') + `","retired":"` + dg('3') + `","no-reason":"` + dg('4') + `","superseded":"` + dg('2') + `"}`),
		"the members of the file reversed": rjReverse(t, rjPrimaryText(good)),
		"a line feed at the end":           rjPrimaryText(good) + "\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := files.ReadRootJSON([]byte(text))
			if r != nil || err == nil {
				t.Fatalf("read: %+v, %v", r, err)
			}
			refused(t, err)
		})
	}
}

func TestARootJSONWithAKeyOfRevocationsTwiceIsRefused(t *testing.T) {
	text := rjPrimaryText(`{"compromised":"` + dg('1') + `","compromised":"` + dg('1') + `","superseded":"` + dg('2') + `"}`)
	r, err := files.ReadRootJSON([]byte(text))
	if r != nil || !errors.Is(err, strictjson.ErrMalformed) {
		t.Fatalf("read: %+v, %v; want ErrMalformed", r, err)
	}
	// A member of the file twice, with the object once each time.
	text = strings.Replace(rjPrimaryText(`{"compromised":"`+dg('1')+`","superseded":"`+dg('2')+`"}`), `"store"`, `"revocations":{"compromised":"`+dg('1')+`","superseded":"`+dg('2')+`"},"store"`, 1)
	r, err = files.ReadRootJSON([]byte(text))
	if r != nil || !errors.Is(err, strictjson.ErrMalformed) {
		t.Fatalf("read: %+v, %v; want ErrMalformed", r, err)
	}
}

func TestARootJSONWithAHostileKeyInRevocationsIsRefusedWithPrintableText(t *testing.T) {
	keys := map[string]string{
		"a control character":      `"comp\u0001romised"`,
		"a NUL":                    `"\u0000"`,
		"a lone surrogate":         `"\ud800"`,
		"a newline":                `"a\nb"`,
		"a byte that is not UTF-8": "\"\xff\xfe\"",
		"a right-to-left mark":     "\"\u202ex\"",
		"a very long key":          `"` + strings.Repeat("k", 100000) + `"`,
	}
	for name, k := range keys {
		t.Run(name, func(t *testing.T) {
			text := `{"created_at":"2026-11-20T10:00:00Z","label":"A","openpgp_created":"` + pgpCreated + `","openpgp_fingerprint":"` + pgpFpr +
				`","revocations":{"compromised":"` + dg('1') + `","superseded":"` + dg('2') + `",` + k + `:"` + dg('3') +
				`"},"store":"software","test":true,"version":1,"x509_spki_sha256":"` + dg('a') + `"}`
			r, err := files.ReadRootJSON([]byte(text))
			if r != nil || err == nil {
				t.Fatalf("read: %+v, %v", r, err)
			}
			refused(t, err)
		})
	}
}

func TestARootJSONThatIsTooBigOrTooDeepIsRefusedBeforeItIsRead(t *testing.T) {
	// A file longer than the limit of the reader is refused, whatever it holds.
	big := rjPrimaryText(`{"compromised":"`+dg('1')+`","superseded":"`+dg('2')+`"}`) + strings.Repeat(" ", strictjson.DefaultMaxBytes)
	if r, err := files.ReadRootJSON([]byte(big)); r != nil || err == nil {
		t.Errorf("a file of %d bytes is read: %v", len(big), err)
	} else {
		refused(t, err)
	}
	// An object of many keys, each short: refused for its size or for its keys, and fast.
	var sb strings.Builder
	sb.WriteString(`{"compromised":"` + dg('1') + `","superseded":"` + dg('2') + `"`)
	for i := 0; i < 20000; i++ {
		sb.WriteString(`,"k` + strings.Repeat("x", 12) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676%26)) + `":"` + dg('3') + `"`)
	}
	sb.WriteString("}")
	text := rjPrimaryText(sb.String())
	if r, err := files.ReadRootJSON([]byte(text)); r != nil || err == nil {
		t.Errorf("a file of %d bytes with 20000 reasons is read: %v", len(text), err)
	} else {
		refused(t, err)
	}
	// Nesting past the limit of the reader.
	deep := strings.Repeat(`{"a":`, strictjson.MaxDepth+10) + `"x"` + strings.Repeat("}", strictjson.MaxDepth+10)
	text = rjPrimaryText(deep)
	if r, err := files.ReadRootJSON([]byte(text)); r != nil || err == nil {
		t.Errorf("a deep file is read: %v", err)
	} else {
		refused(t, err)
	}
}

func TestCanonicalOfARootJSONWithRevocationsRefusesWhatTheReaderRefuses(t *testing.T) {
	good := func() files.RootJSON {
		return files.RootJSON{
			Version: 1, Label: "A", Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z", X509SPKISHA256: dg('a'),
			OpenPGPFingerprint: pgpFpr, OpenPGPCreated: pgpCreated, RemovalSHA256: dg('c'),
			Revocations: map[string]string{"compromised": dg('1'), "superseded": dg('2')},
		}
	}
	if _, err := (func() *files.RootJSON { g := good(); return &g })().Canonical(); err != nil {
		t.Fatalf("the control is refused: %v", err)
	}
	edits := map[string]func(*files.RootJSON){
		"no revocations with a fingerprint":      func(r *files.RootJSON) { r.Revocations = nil },
		"an empty map with a fingerprint":        func(r *files.RootJSON) { r.Revocations = map[string]string{} },
		"revocations with no fingerprint":        func(r *files.RootJSON) { r.OpenPGPFingerprint, r.OpenPGPCreated = "", "" },
		"no compromised":                         func(r *files.RootJSON) { delete(r.Revocations, "compromised") },
		"no superseded":                          func(r *files.RootJSON) { delete(r.Revocations, "superseded") },
		"a fifth key":                            func(r *files.RootJSON) { r.Revocations["x"] = dg('3') },
		"the key root-removal":                   func(r *files.RootJSON) { r.Revocations["root-removal"] = dg('3') },
		"a value that is not a digest":           func(r *files.RootJSON) { r.Revocations["retired"] = "abc" },
		"an empty value":                         func(r *files.RootJSON) { r.Revocations["compromised"] = "" },
		"a value in upper case":                  func(r *files.RootJSON) { r.Revocations["superseded"] = strings.ToUpper(dg('a')) },
		"a fingerprint of 64 digits":             func(r *files.RootJSON) { r.OpenPGPFingerprint = dg('a') },
		"a map with revocations on an X.509 key": func(r *files.RootJSON) { r.OpenPGPFingerprint, r.OpenPGPCreated = "", "" },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			r := good()
			edit(&r)
			b, err := r.Canonical()
			if err == nil || b != nil {
				t.Fatalf("Canonical = %s, %v", b, err)
			}
		})
	}
}

func TestCanonicalOfARootJSONDoesNotChangeItsValueAndIsStableOverReads(t *testing.T) {
	r := files.RootJSON{
		Version: 1, Label: "B", Store: "piv", CreatedAt: "2026-11-20T10:00:00Z", X509SPKISHA256: dg('a'),
		OpenPGPFingerprint: pgpFpr, OpenPGPCreated: pgpCreated,
		Revocations: map[string]string{"no-reason": dg('4'), "retired": dg('3'), "superseded": dg('2'), "compromised": dg('1')},
	}
	before := map[string]string{}
	for k, v := range r.Revocations {
		before[k] = v
	}
	first, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Revocations, before) {
		t.Errorf("Canonical changed the map: %v", r.Revocations)
	}
	back, err := files.ReadRootJSON(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := back.Canonical()
	if err != nil || !bytes.Equal(first, second) {
		t.Errorf("Canonical is not stable: %s %s %v", first, second, err)
	}
	// The value read does not share its map with a caller that changes it afterwards.
	back.Revocations["compromised"] = dg('9')
	third, err := files.ReadRootJSON(first)
	if err != nil || third.Revocations["compromised"] != dg('1') {
		t.Errorf("a second read changed: %+v %v", third, err)
	}
}
