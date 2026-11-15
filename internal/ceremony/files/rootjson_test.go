package files_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/strictjson"
)

// roots/<label>/root.json (docs/reference/bundle.md, "`root.json`"): the facts of one root key,
// one canonical JSON object, written once by the ceremony that makes the key.

func rjDoc() map[string]any {
	return map[string]any{
		"version": 1, "label": "A", "store": "software", "test": true, "created_at": "2026-11-20T10:00:00Z",
		"x509_spki_sha256": dg('a'), "removal_sha256": dg('c'),
	}
}

func rjRead(t *testing.T, edit func(map[string]any)) (*files.RootJSON, error) {
	t.Helper()
	return files.ReadRootJSON(encode(t, rjDoc(), edit))
}

func TestARootJSONOfTheFirstApplyIsReadWithEveryMember(t *testing.T) {
	r, err := rjRead(t, nil)
	if err != nil {
		t.Fatalf("ReadRootJSON: %v", err)
	}
	want := files.RootJSON{Version: 1, Label: "A", Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z", X509SPKISHA256: dg('a'), RemovalSHA256: dg('c')}
	if *r != want {
		t.Errorf("got %+v, want %+v", *r, want)
	}
}

func TestRootJSONCanonicalIsTheCanonicalFormWithTheMembersSortedAndNoLineFeed(t *testing.T) {
	r, err := rjRead(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"created_at":"2026-11-20T10:00:00Z","label":"A","removal_sha256":"` + dg('c') + `","store":"software","test":true,"version":1,"x509_spki_sha256":"` + dg('a') + `"}`
	if string(b) != want {
		t.Errorf("Canonical:\n%s\nwant\n%s", b, want)
	}
	if ok, err := canonjson.IsCanonical(b); err != nil || !ok {
		t.Errorf("IsCanonical = %v, %v", ok, err)
	}
	back, err := files.ReadRootJSON(b)
	if err != nil || *back != *r {
		t.Errorf("the canonical bytes read back as %+v, %v", back, err)
	}
	again, err := back.Canonical()
	if err != nil || !bytes.Equal(again, b) {
		t.Error("Canonical is not stable over a read")
	}
}

func TestARootJSONOfAnotherLabelAndStoreIsRead(t *testing.T) {
	for _, l := range []string{"A", "B", "M", "Z"} {
		for _, s := range []string{"software", "piv", "aws-kms"} {
			if _, err := rjRead(t, func(m map[string]any) { m["label"], m["store"] = l, s }); err != nil {
				t.Errorf("label %s store %s: %v", l, s, err)
			}
		}
	}
}

func TestARootJSONThatHoldsOnlyAnOpenPGPKeyIsRead(t *testing.T) {
	// A key that has no X.509 pin has an OpenPGP fingerprint and its creation time.
	r, err := rjRead(t, func(m map[string]any) {
		delete(m, "x509_spki_sha256")
		m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("ab", 20), "2026-11-20T09:00:00Z"
	})
	if err != nil {
		t.Fatal(err)
	}
	if r.X509SPKISHA256 != "" || r.OpenPGPFingerprint != strings.Repeat("ab", 20) || r.OpenPGPCreated != "2026-11-20T09:00:00Z" {
		t.Errorf("got %+v", r)
	}
	b, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "x509_spki_sha256") {
		t.Errorf("the member of the pin is written empty: %s", b)
	}
}

func TestARootJSONMayLeaveOutTestAndTheRemovalDigest(t *testing.T) {
	// A personal bundle has no removal authorisation (the page), and a key that is not a test key
	// has no test member in this version.
	r, err := rjRead(t, func(m map[string]any) { delete(m, "test"); delete(m, "removal_sha256") })
	if err != nil {
		t.Fatal(err)
	}
	if r.Test || r.RemovalSHA256 != "" {
		t.Errorf("got %+v", r)
	}
	b, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"test"`) || strings.Contains(string(b), "removal_sha256") {
		t.Errorf("a member that is left out is written: %s", b)
	}
}

func TestEveryRootJSONThatBreaksARuleIsRefusedWithTheMemberNamed(t *testing.T) {
	long := strings.Repeat("a", 300)
	cases := []struct {
		name   string
		edit   func(map[string]any)
		member string
	}{
		{"no label", without("label"), "label"},
		{"no store", without("store"), "store"},
		{"no created_at", without("created_at"), "created_at"},
		{"no key at all", without("x509_spki_sha256"), "x509_spki_sha256"},
		{"an empty label", set("label", ""), "label"},
		{"a label in lower case", set("label", "a"), "label"},
		{"a label of two letters", set("label", "AB"), "label"},
		{"a label that is a digit", set("label", "1"), "label"},
		{"a label that is a space", set("label", " "), "label"},
		{"a label with a line feed", set("label", "A\n"), "label"},
		{"a label that is not ASCII", set("label", "Ä"), "label"},
		{"a label with a path in it", set("label", "../A"), "label"},
		{"an empty store", set("store", ""), "store"},
		{"a store that is not listed", set("store", "hsm"), "store"},
		{"a store in upper case", set("store", "Software"), "store"},
		{"a store with a space", set("store", "software "), "store"},
		{"a store that is long", set("store", long), "store"},
		{"an empty time", set("created_at", ""), "created_at"},
		{"a time with a fraction", set("created_at", "2026-11-20T10:00:00.5Z"), "created_at"},
		{"a time with an offset", set("created_at", "2026-11-20T10:00:00+00:00"), "created_at"},
		{"a time that is a date", set("created_at", "2026-11-20"), "created_at"},
		{"a time in lower case", set("created_at", "2026-11-20t10:00:00z"), "created_at"},
		{"a time with a space", set("created_at", "2026-11-20 10:00:00Z"), "created_at"},
		{"a day that does not exist", set("created_at", "2026-02-30T10:00:00Z"), "created_at"},
		{"an hour that does not exist", set("created_at", "2026-11-20T25:00:00Z"), "created_at"},
		{"a pin of 63 digits", set("x509_spki_sha256", dg('a')[:63]), "x509_spki_sha256"},
		{"a pin of 65 digits", set("x509_spki_sha256", dg('a')+"a"), "x509_spki_sha256"},
		{"a pin in upper case", set("x509_spki_sha256", strings.ToUpper(dg('a'))), "x509_spki_sha256"},
		{"a pin that is not hexadecimal", set("x509_spki_sha256", strings.Repeat("g", 64)), "x509_spki_sha256"},
		{"an empty pin", set("x509_spki_sha256", ""), "x509_spki_sha256"},
		{"a pin with a prefix", set("x509_spki_sha256", "sha256:"+dg('a')), "x509_spki_sha256"},
		{"an empty pin beside an OpenPGP key", func(m map[string]any) {
			m["x509_spki_sha256"] = ""
			m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("ab", 20), "2026-11-20T09:00:00Z"
		}, "x509_spki_sha256"},
		{"a removal digest of 63 digits", set("removal_sha256", dg('c')[:63]), "removal_sha256"},
		{"a removal digest in upper case", set("removal_sha256", strings.ToUpper(dg('c'))), "removal_sha256"},
		{"an empty removal digest", set("removal_sha256", ""), "removal_sha256"},
		{"a fingerprint with no creation time", set("openpgp_fingerprint", strings.Repeat("ab", 20)), "openpgp_created"},
		{"a creation time with no fingerprint", set("openpgp_created", "2026-11-20T09:00:00Z"), "openpgp_created"},
		{"a fingerprint of 39 digits", func(m map[string]any) {
			m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("ab", 20)[:39], "2026-11-20T09:00:00Z"
		}, "openpgp_fingerprint"},
		{"a fingerprint in upper case", func(m map[string]any) {
			m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("AB", 20), "2026-11-20T09:00:00Z"
		}, "openpgp_fingerprint"},
		{"a fingerprint of a key of 64 digits", func(m map[string]any) {
			m["openpgp_fingerprint"], m["openpgp_created"] = dg('a'), "2026-11-20T09:00:00Z"
		}, "openpgp_fingerprint"},
		{"an empty fingerprint", func(m map[string]any) { m["openpgp_fingerprint"], m["openpgp_created"] = "", "2026-11-20T09:00:00Z" }, "openpgp_fingerprint"},
		{"an empty creation time", func(m map[string]any) {
			m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("ab", 20), ""
		}, "openpgp_created"},
		{"a creation time with a fraction", func(m map[string]any) {
			m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("ab", 20), "2026-11-20T09:00:00.1Z"
		}, "openpgp_created"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := rjRead(t, tc.edit)
			if err == nil || r != nil {
				t.Fatalf("accepted: %+v, %v", r, err)
			}
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("the error is %T: %v", err, err)
			}
			if fe.Member != tc.member {
				t.Errorf("the error names %q, want %q: %v", fe.Member, tc.member, err)
			}
			if !printableASCII(err.Error()) || len(err.Error()) > 2000 {
				t.Errorf("the text is not printable ASCII or is long: %.200q", err.Error())
			}
		})
	}
}

func TestARootJSONOfAnotherVersionIsAVersionErrorAndTheRestOfTheFileIsNotRead(t *testing.T) {
	for _, v := range []any{0, 2, 3, -1, 1000, 9007199254740991} {
		_, err := rjRead(t, func(m map[string]any) {
			m["version"] = v
			// The rest of the file is wrong on purpose.
			m["label"], m["store"] = "zz", 7
		})
		var ve *files.VersionError
		if !errors.As(err, &ve) {
			t.Errorf("version %v: the error is %T: %v", v, err, err)
		}
	}
	// A version that is not an integer, or not there, is not a VersionError.
	for name, edit := range map[string]func(map[string]any){
		"missing":    without("version"),
		"a string":   set("version", "1"),
		"a float":    set("version", 1.5),
		"a boolean":  set("version", true),
		"an object":  set("version", map[string]any{}),
		"null":       set("version", nil),
		"a big one":  set("version", 1e300),
		"as an exp.": nil,
	} {
		if edit == nil {
			continue
		}
		r, err := rjRead(t, edit)
		if err == nil || r != nil {
			t.Errorf("version %s accepted", name)
		}
	}
}

func TestARootJSONThatIsNotExactlyOneStrictObjectIsRefused(t *testing.T) {
	good := string(encode(t, rjDoc(), nil))
	cases := map[string]string{
		"empty":                           "",
		"white space":                     "  \n",
		"null":                            "null",
		"an array":                        "[" + good + "]",
		"a string":                        `"x"`,
		"a number":                        "1",
		"two objects":                     good + good,
		"text after":                      good + " x",
		"text before":                     "x" + good,
		"a byte order mark":               "\xef\xbb\xbf" + good,
		"a comment":                       "/* x */" + good,
		"a trailing comma":                good[:len(good)-1] + ",}",
		"a single quote":                  strings.ReplaceAll(good, `"`, "'"),
		"a member twice":                  strings.Replace(good, `{`, `{"label":"A",`, 1),
		"a member twice, escaped":         strings.Replace(good, `{`, `{"label":"B",`, 1),
		"a member in another letter case": strings.Replace(good, `{`, `{"Label":"A",`, 1),
		"an unknown member":               strings.Replace(good, `{`, `{"extra":1,`, 1),
		"a member that is null":           strings.Replace(good, `"test":true`, `"test":null`, 1),
		"a string for a boolean":          strings.Replace(good, `"test":true`, `"test":"true"`, 1),
		"a number for a string":           strings.Replace(good, `"label":"A"`, `"label":65`, 1),
		"an array for a string":           strings.Replace(good, `"label":"A"`, `"label":["A"]`, 1),
		"an object for a string":          strings.Replace(good, `"label":"A"`, `"label":{}`, 1),
		"a float version":                 strings.Replace(good, `"version":1`, `"version":1.0`, 1),
		"an exponent version":             strings.Replace(good, `"version":1`, `"version":1e0`, 1),
		"not UTF-8":                       strings.Replace(good, `"label":"A"`, "\"label\":\"\xff\"", 1),
		"a lone surrogate":                strings.Replace(good, `"label":"A"`, `"label":"\ud800"`, 1),
		"a NUL in a name":                 strings.Replace(good, `"label"`, "\"lab\\u0000el\"", 1),
		"a raw control":                   strings.Replace(good, `"label":"A"`, "\"label\":\"\x01\"", 1),
		"a nested object":                 strings.Replace(good, `"test":true`, `"test":{"a":1}`, 1),
		"revocations (later)":             strings.Replace(good, `{`, `{"revocations":{},`, 1),
		"adopted (later)":                 strings.Replace(good, `{`, `{"adopted":true,`, 1),
		"store_ref (later)":               strings.Replace(good, `{`, `{"store_ref":{},`, 1),
		"vouched_by (later)":              strings.Replace(good, `{`, `{"vouched_by":[],`, 1),
		"vouches (later)":                 strings.Replace(good, `{`, `{"vouches":[],`, 1),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := files.ReadRootJSON([]byte(text))
			if err == nil || r != nil {
				t.Fatalf("accepted: %+v", r)
			}
			refused(t, err)
		})
	}
}

func TestARootJSONThatIsHostileInSizeOrDepthIsRefusedAndDoesNotCrash(t *testing.T) {
	good := string(encode(t, rjDoc(), nil))
	over := strings.Replace(good, `"label":"A"`, `"label":"`+strings.Repeat("A", strictjson.DefaultMaxBytes)+`"`, 1)
	deep := func(n int) string {
		return `{"version":1,"x":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
	}
	deepObj := func(n int) string {
		return `{"version":1,"x":` + strings.Repeat(`{"a":`, n) + "1" + strings.Repeat("}", n) + `}`
	}
	many := `{"version":1` + strings.Repeat(`,"m":1`, 20000) + `}`
	cases := map[string]string{
		"one byte over the limit":      over,
		"the limit exactly, of spaces": good + strings.Repeat(" ", strictjson.DefaultMaxBytes),
		"nesting of 20000 arrays":      deep(20000),
		"nesting of 10001 arrays":      deep(10001),
		"nesting of 20000 objects":     deepObj(20000),
		"20000 members of one name":    many,
		"a huge number":                `{"version":1,"x":` + strings.Repeat("9", 100000) + `}`,
		"a long name":                  `{"version":1,"` + strings.Repeat("n", 100000) + `":1}`,
		"many escapes":                 `{"version":1,"label":"` + strings.Repeat(`A`, 40000) + `"}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := files.ReadRootJSON([]byte(text))
			if err == nil || r != nil {
				t.Fatalf("accepted")
			}
			if len(err.Error()) > 4000 {
				t.Errorf("the error is %d bytes long", len(err.Error()))
			}
			if !printableASCII(err.Error()) {
				t.Errorf("the text of the error is not printable ASCII")
			}
		})
	}
}

func TestTheCanonicalFormOfARootJSONThatBreaksARuleIsAnErrorAndGivesNoBytes(t *testing.T) {
	var nilDoc *files.RootJSON
	if b, err := nilDoc.Canonical(); err == nil || b != nil {
		t.Errorf("a nil value: %q, %v", b, err)
	}
	good := files.RootJSON{Version: 1, Label: "A", Store: "software", Test: true, CreatedAt: "2026-11-20T10:00:00Z", X509SPKISHA256: dg('a'), RemovalSHA256: dg('c')}
	edits := map[string]func(*files.RootJSON){
		"version 2":               func(r *files.RootJSON) { r.Version = 2 },
		"version 0":               func(r *files.RootJSON) { r.Version = 0 },
		"no label":                func(r *files.RootJSON) { r.Label = "" },
		"label a":                 func(r *files.RootJSON) { r.Label = "a" },
		"a store that is not one": func(r *files.RootJSON) { r.Store = "x" },
		"no time":                 func(r *files.RootJSON) { r.CreatedAt = "" },
		"a time with a fraction":  func(r *files.RootJSON) { r.CreatedAt = "2026-11-20T10:00:00.5Z" },
		"no key":                  func(r *files.RootJSON) { r.X509SPKISHA256 = "" },
		"a bad pin":               func(r *files.RootJSON) { r.X509SPKISHA256 = "abc" },
		"a bad removal digest":    func(r *files.RootJSON) { r.RemovalSHA256 = "abc" },
		"a fingerprint alone":     func(r *files.RootJSON) { r.OpenPGPFingerprint = strings.Repeat("ab", 20) },
		"a creation time alone":   func(r *files.RootJSON) { r.OpenPGPCreated = "2026-11-20T10:00:00Z" },
	}
	for name, edit := range edits {
		r := good
		edit(&r)
		if b, err := r.Canonical(); err == nil || b != nil {
			t.Errorf("%s: Canonical = %q, %v", name, b, err)
		}
	}
	if _, err := good.Canonical(); err != nil {
		t.Fatal(err)
	}
}

func TestTheNamesOfTheStoresAndTheFileAreThoseOfThePage(t *testing.T) {
	if files.StoreSoftware != "software" || files.StorePIV != "piv" || files.StoreAWSKMS != "aws-kms" || files.RootJSONFile != "root.json" {
		t.Errorf("%q %q %q %q", files.StoreSoftware, files.StorePIV, files.StoreAWSKMS, files.RootJSONFile)
	}
}

func TestReadingARootJSONDoesNotChangeItsInput(t *testing.T) {
	b := encode(t, rjDoc(), nil)
	before := append([]byte(nil), b...)
	if _, err := files.ReadRootJSON(b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, before) {
		t.Error("ReadRootJSON changed its input")
	}
	// What it returns does not share the input.
	r, _ := files.ReadRootJSON(b)
	for i := range b {
		b[i] = 'x'
	}
	if r.Label != "A" || r.Store != "software" {
		t.Errorf("the value shares the bytes: %+v", r)
	}
}

// bs is a backslash, so that a Unicode escape can be written in a case without the escape being read here.
const bs = "\\"

func TestARootJSONThatIsNotInTheCanonicalSpellingIsRefusedAndNoValueComesBack(t *testing.T) {
	// What is read is exactly what the writer writes: a file that holds the same facts in another
	// spelling is not accepted, so no two files stand for one value.
	r, err := rjRead(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	s := string(canon)
	cases := map[string]string{
		"a test member that says false":   strings.Replace(s, `"test":true`, `"test":false`, 1),
		"a space after a colon":           strings.Replace(s, `"label":"A"`, `"label": "A"`, 1),
		"a space after a comma":           strings.Replace(s, `,"label"`, `, "label"`, 1),
		"a space before the object":       " " + s,
		"a space after the object":        s + " ",
		"a line feed at the end":          s + "\n",
		"a carriage return and line feed": s + "\r\n",
		"a line feed at the start":        "\n" + s,
		"pretty printed":                  strings.ReplaceAll(strings.ReplaceAll(s, `{`, "{\n  "), `,`, ",\n  "),
		"a tab between members":           strings.Replace(s, `,"label"`, ",\t\"label\"", 1),
		"the version member first":        `{"version":1,` + strings.Replace(strings.Replace(s, `"version":1,`, "", 1), `{`, "", 1),
		"the label member last":           strings.Replace(s, `"label":"A",`, "", 1)[:len(s)-len(`"label":"A",`)-1] + `,"label":"A"}`,
		"members in reverse order":        rjReverse(t, s),
		"a member name in an escape":      strings.Replace(s, `"label"`, `"`+bs+`u006cabel"`, 1),
		"a value in an escape":            strings.Replace(s, `"label":"A"`, `"label":"`+bs+`u0041"`, 1),
		"a value with an escaped slash":   strings.Replace(s, `"software"`, `"soft\/ware"`, 1),
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if text == s {
				t.Fatal("the case did not change the bytes")
			}
			got, err := files.ReadRootJSON([]byte(text))
			if got != nil || err == nil {
				t.Fatalf("read as %+v, %v: a file that is not the canonical bytes is accepted", got, err)
			}
			refused(t, err)
		})
	}
	// Control: the canonical bytes themselves are read, and they are what Canonical writes.
	got, err := files.ReadRootJSON(canon)
	if err != nil || *got != *r {
		t.Fatalf("the canonical bytes: %+v, %v", got, err)
	}
}

func TestANonCanonicalSpellingOfAValidFileIsAFormatErrorOfTheMemberFile(t *testing.T) {
	// A file that is one strict object, with every member right, and that is only spelled in another
	// way: the fault is the file as a whole, not one of its members.
	for name, text := range map[string]string{
		"test false":      string(encode(t, rjDoc(), set("test", false))),
		"a line feed":     string(encode(t, rjDoc(), nil)) + "\n",
		"a space":         strings.Replace(string(encode(t, rjDoc(), nil)), `"store":`, `"store": `, 1),
		"an escaped name": strings.Replace(string(encode(t, rjDoc(), nil)), `"store"`, `"`+bs+`u0073tore"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := files.ReadRootJSON([]byte(text))
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				t.Fatalf("the error is %T %v, want a *FormatError", err, err)
			}
			if fe.Member != "file" || fe.What != "root.json" {
				t.Errorf("the error names %q of %q, want file of root.json", fe.Member, fe.What)
			}
		})
	}
}

func TestACanonicalFileThatIsReadWritesTheSameBytesWhateverItsMembers(t *testing.T) {
	// The canonical bytes of every accepted shape are read back as the same bytes.
	for name, edit := range map[string]func(map[string]any){
		"the first apply":   nil,
		"no test member":    without("test"),
		"no removal digest": without("removal_sha256"),
		"neither":           without("test", "removal_sha256"),
		"an OpenPGP key only": func(m map[string]any) {
			delete(m, "x509_spki_sha256")
			m["openpgp_fingerprint"], m["openpgp_created"] = strings.Repeat("ab", 20), "2026-11-20T09:00:00Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := encode(t, rjDoc(), edit)
			r, err := files.ReadRootJSON(b)
			if err != nil {
				t.Fatalf("ReadRootJSON: %v", err)
			}
			out, err := r.Canonical()
			if err != nil || !bytes.Equal(out, b) {
				t.Fatalf("Canonical = %s, %v; want the bytes that were read: %s", out, err, b)
			}
		})
	}
}

// rjReverse writes the members of a canonical object in the opposite order.
func rjReverse(t *testing.T, canon string) string {
	t.Helper()
	body := strings.TrimSuffix(strings.TrimPrefix(canon, "{"), "}")
	parts := strings.Split(body, ",")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return "{" + strings.Join(parts, ",") + "}"
}
