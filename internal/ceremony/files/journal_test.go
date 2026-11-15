package files_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/canonjson"
	"ritueel.id/ritueel/internal/ceremony/files"
	"ritueel.id/ritueel/internal/strictjson"
)

const (
	goldenBirth = `{"at":"2026-11-14T10:00:00Z","label":"A","place":"A.x509.key.pem","public_key_sha256":"` +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `","purpose":"x509-root","store":"software"}`
	goldenSig = `{"at":"2026-11-14T10:00:05Z","key":"` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
		`","kind":"root-certificate","n":1,"signature_sha256":"` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `"}`
)

func birthMap() map[string]any {
	return map[string]any{
		"at": "2026-11-14T10:00:00Z", "label": "A", "purpose": "x509-root", "store": "software",
		"place": "A.x509.key.pem", "public_key_sha256": dg('a'),
	}
}

func sigMap() map[string]any {
	return map[string]any{
		"at": "2026-11-14T10:00:05Z", "n": 1, "kind": "root-certificate", "key": dg('a'), "signature_sha256": dg('b'),
	}
}

// canon makes the canonical bytes of a map the way the writer does, and is the form that every
// accepted line has.
func canon(t testing.TB, m map[string]any) []byte {
	t.Helper()
	b, err := canonjson.Marshal(m)
	if err != nil {
		t.Fatalf("canonjson.Marshal: %v", err)
	}
	return b
}

func TestReadBirthLineTakesTheLineOfThePage(t *testing.T) {
	l, err := files.ReadBirthLine([]byte(goldenBirth))
	if err != nil {
		t.Fatal(err)
	}
	want := &files.BirthLine{At: "2026-11-14T10:00:00Z", Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem", PublicKeySHA256: dg('a')}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("got %+v, want %+v", l, want)
	}
	if got := canon(t, birthMap()); string(got) != goldenBirth {
		t.Errorf("the canonical form of the test map is %s", got)
	}
}

func TestReadSignatureLineTakesTheLineOfThePage(t *testing.T) {
	l, err := files.ReadSignatureLine([]byte(goldenSig))
	if err != nil {
		t.Fatal(err)
	}
	want := &files.SignatureLine{At: "2026-11-14T10:00:05Z", N: 1, Kind: "root-certificate", Key: dg('a'), SignatureSHA256: dg('b')}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("got %+v, want %+v", l, want)
	}
}

// The writer gives the line of the page, byte for byte, in the canonical form of RFC 8785.
func TestCanonicalIsTheGoldenLineAndReadsBack(t *testing.T) {
	b, err := (&files.BirthLine{At: "2026-11-14T10:00:00Z", Label: "A", Purpose: "x509-root", Store: "software", Place: "A.x509.key.pem", PublicKeySHA256: dg('a')}).Canonical()
	if err != nil || string(b) != goldenBirth {
		t.Errorf("BirthLine.Canonical = %s, %v", b, err)
	}
	s, err := (&files.SignatureLine{At: "2026-11-14T10:00:05Z", N: 1, Kind: "root-certificate", Key: dg('a'), SignatureSHA256: dg('b')}).Canonical()
	if err != nil || string(s) != goldenSig {
		t.Errorf("SignatureLine.Canonical = %s, %v", s, err)
	}
	for _, line := range [][]byte{b, s} {
		if bytes.ContainsAny(line, "\n\r") {
			t.Errorf("a canonical line holds a line break: %q", line)
		}
		if ok, err := canonjson.IsCanonical(line); !ok || err != nil {
			t.Errorf("%s is not canonical: %v", line, err)
		}
	}
}

// The members of the two lines are the members that the page gives, and the page says so.
func TestTheMembersAreThoseOfThePage(t *testing.T) {
	page, err := os.ReadFile("../../../docs/reference/ceremony-record.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(page)
	members := func(m map[string]any) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	// The page names the members of each line in one braces list: `{ "at", ... }`.
	list := regexp.MustCompile(`\{ ("[a-z_0-9]+"(?:, "[a-z_0-9]+")*) \}`)
	found := map[string]bool{}
	for _, m := range list.FindAllStringSubmatch(text, -1) {
		var names []string
		for _, n := range strings.Split(m[1], ", ") {
			names = append(names, strings.Trim(n, `"`))
		}
		sort.Strings(names)
		found[strings.Join(names, ",")] = true
	}
	for name, m := range map[string]map[string]any{"birth": birthMap(), "signature": sigMap()} {
		if want := strings.Join(members(m), ","); !found[want] {
			t.Errorf("the page does not list the members %s of a %s line in one braces list", want, name)
		}
	}
	// The writer writes those members and no other.
	for name, line := range map[string]string{"birth": goldenBirth, "signature": goldenSig} {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		want := birthMap()
		if name == "signature" {
			want = sigMap()
		}
		if !reflect.DeepEqual(members(m), members(want)) {
			t.Errorf("the %s line holds the members %v", name, members(m))
		}
	}
}

// The eleven kinds are the kinds that the page lists for a signature, and the reader takes those.
func TestTheKindsAreThoseOfThePage(t *testing.T) {
	page, err := os.ReadFile("../../../docs/reference/ceremony-record.md")
	if err != nil {
		t.Fatal(err)
	}
	var row string
	for _, l := range strings.Split(string(page), "\n") {
		if strings.HasPrefix(l, "| `kind` | `intermediate-certificate`") {
			row = l
		}
	}
	if row == "" {
		t.Fatal("the page has no row of the member kind of a signature")
	}
	kinds := map[string]string{
		"intermediate-certificate": files.KindIntermediateCertificate,
		"subkey-binding":           files.KindSubkeyBinding,
		"root-certificate":         files.KindRootCertificate,
		"primary-self-signature":   files.KindPrimarySelfSignature,
		"primary-revocation":       files.KindPrimaryRevocation,
		"root-removal":             files.KindRootRemoval,
		"cross-certificate":        files.KindCrossCertificate,
		"openpgp-vouch":            files.KindOpenPGPVouch,
		"root-list":                files.KindRootList,
		"crl":                      files.KindCRL,
		"ssh-ca-key-list":          files.KindSSHCAKeyList,
	}
	for word, c := range kinds {
		if c != word {
			t.Errorf("the constant for %s is %q", word, c)
		}
		if !strings.Contains(row, "`"+word+"`") {
			t.Errorf("the page row of kind does not hold %s", word)
		}
		m := sigMap()
		m["kind"] = word
		if _, err := files.ReadSignatureLine(canon(t, m)); err != nil {
			t.Errorf("kind %s is refused: %v", word, err)
		}
	}
	// Every kind of the row is one of the eleven: the row names nothing else in code font that
	// looks like a kind.
	for _, m := range regexp.MustCompile("`([a-z]+(?:-[a-z]+)*)`").FindAllStringSubmatch(row, -1) {
		w := m[1]
		if _, ok := kinds[w]; !ok && w != "kind" && w != "reason" && w != "apply" {
			t.Errorf("the page row of kind names %s, which the writer does not know", w)
		}
	}
	for _, bad := range []string{"", "root_list", "Root-List", "root-list ", "root", "revocation", "x509-root", "certificate", "root-certificate\n", "cross-certificate2"} {
		m := sigMap()
		m["kind"] = bad
		if _, err := files.ReadSignatureLine(canon(t, m)); err == nil {
			t.Errorf("kind %q is accepted", bad)
		}
	}
}

// editBirth and editSig make a line from the map with one change.
func edited(base func() map[string]any, f func(map[string]any)) []byte {
	m := base()
	f(m)
	b, err := json.Marshal(m) // not canonical on purpose where the members are not in order
	if err != nil {
		panic(err)
	}
	if c, err := canonjson.Canonicalize(b); err == nil {
		return c
	}
	return b
}

func TestBirthLineWantsEachMemberInItsForm(t *testing.T) {
	long := func(n int) string { return strings.Repeat("p", n) }
	cases := []struct {
		name   string
		edit   func(map[string]any)
		member string // "" when the line is good
	}{
		{"the good line", func(m map[string]any) {}, ""},
		{"no at", func(m map[string]any) { delete(m, "at") }, "at"},
		{"at empty", func(m map[string]any) { m["at"] = "" }, "at"},
		{"at with a fraction", func(m map[string]any) { m["at"] = "2026-11-14T10:00:00.5Z" }, "at"},
		{"at with an offset", func(m map[string]any) { m["at"] = "2026-11-14T10:00:00+00:00" }, "at"},
		{"at without a Z", func(m map[string]any) { m["at"] = "2026-11-14T10:00:00" }, "at"},
		{"at in lower case", func(m map[string]any) { m["at"] = "2026-11-14t10:00:00z" }, "at"},
		{"at that is no date", func(m map[string]any) { m["at"] = "2026-13-45T10:00:00Z" }, "at"},
		{"at that is a number", func(m map[string]any) { m["at"] = 20261114 }, "at"},
		{"no label", func(m map[string]any) { delete(m, "label") }, "label"},
		{"label empty", func(m map[string]any) { m["label"] = "" }, "label"},
		{"label in lower case", func(m map[string]any) { m["label"] = "a" }, "label"},
		{"label of two letters", func(m map[string]any) { m["label"] = "AB" }, "label"},
		{"label that is a digit", func(m map[string]any) { m["label"] = "1" }, "label"},
		{"label with a space", func(m map[string]any) { m["label"] = " A" }, "label"},
		{"label that is a letter with an accent", func(m map[string]any) { m["label"] = "\u00c4" }, "label"},
		{"label that is a number", func(m map[string]any) { m["label"] = 65 }, "label"},
		{"label Z", func(m map[string]any) { m["label"] = "Z" }, ""},
		{"label the next character after Z", func(m map[string]any) { m["label"] = "[" }, "label"},
		{"label the character before A", func(m map[string]any) { m["label"] = "@" }, "label"},
		{"no purpose", func(m map[string]any) { delete(m, "purpose") }, "purpose"},
		{"purpose empty", func(m map[string]any) { m["purpose"] = "" }, "purpose"},
		{"purpose in capitals", func(m map[string]any) { m["purpose"] = "X509-Root" }, "purpose"},
		{"purpose with an underscore", func(m map[string]any) { m["purpose"] = "x509_root" }, "purpose"},
		{"purpose with a space", func(m map[string]any) { m["purpose"] = "x509 root" }, "purpose"},
		{"purpose that starts with a hyphen", func(m map[string]any) { m["purpose"] = "-x509" }, "purpose"},
		{"purpose of 65 bytes", func(m map[string]any) { m["purpose"] = strings.Repeat("a", 65) }, "purpose"},
		{"purpose of 64 bytes", func(m map[string]any) { m["purpose"] = strings.Repeat("a", 64) }, ""},
		{"purpose of digits", func(m map[string]any) { m["purpose"] = "509" }, ""},
		{"purpose with an accent", func(m map[string]any) { m["purpose"] = "caf\u00e9" }, "purpose"},
		{"no store", func(m map[string]any) { delete(m, "store") }, "store"},
		{"store empty", func(m map[string]any) { m["store"] = "" }, "store"},
		{"store in capitals", func(m map[string]any) { m["store"] = "Software" }, "store"},
		{"store of 65 bytes", func(m map[string]any) { m["store"] = strings.Repeat("s", 65) }, "store"},
		{"store aws-kms", func(m map[string]any) { m["store"] = "aws-kms" }, ""},
		{"no place", func(m map[string]any) { delete(m, "place") }, "place"},
		{"place empty", func(m map[string]any) { m["place"] = "" }, "place"},
		{"place with a space inside", func(m map[string]any) { m["place"] = "slot 9a" }, ""},
		{"place with a space at the start", func(m map[string]any) { m["place"] = " slot" }, "place"},
		{"place with a space at the end", func(m map[string]any) { m["place"] = "slot " }, "place"},
		{"place that is an ARN", func(m map[string]any) {
			m["place"] = "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
		}, ""},
		{"place of 255 bytes", func(m map[string]any) { m["place"] = long(255) }, ""},
		{"place of 256 bytes", func(m map[string]any) { m["place"] = long(256) }, "place"},
		{"place with a control character", func(m map[string]any) { m["place"] = "a\x01b" }, "place"},
		{"place with an escape character", func(m map[string]any) { m["place"] = "a\x1b[31mb" }, "place"},
		{"place with a line feed", func(m map[string]any) { m["place"] = "a\nb" }, "place"},
		{"place with a delete", func(m map[string]any) { m["place"] = "a\x7fb" }, "place"},
		{"place with a letter beyond ASCII", func(m map[string]any) { m["place"] = "caf\u00e9" }, "place"},
		{"place with a right-to-left override", func(m map[string]any) { m["place"] = "a\u202eb" }, "place"},
		{"place with a tab", func(m map[string]any) { m["place"] = "a\tb" }, "place"},
		{"no public_key_sha256", func(m map[string]any) { delete(m, "public_key_sha256") }, "public_key_sha256"},
		{"digest empty", func(m map[string]any) { m["public_key_sha256"] = "" }, "public_key_sha256"},
		{"digest in capitals", func(m map[string]any) { m["public_key_sha256"] = strings.ToUpper(dg('a')) }, "public_key_sha256"},
		{"digest of 63 digits", func(m map[string]any) { m["public_key_sha256"] = dg('a')[:63] }, "public_key_sha256"},
		{"digest of 65 digits", func(m map[string]any) { m["public_key_sha256"] = dg('a') + "a" }, "public_key_sha256"},
		{"digest that is not hexadecimal", func(m map[string]any) { m["public_key_sha256"] = strings.Repeat("g", 64) }, "public_key_sha256"},
		{"digest with a prefix", func(m map[string]any) { m["public_key_sha256"] = "0x" + dg('a')[:62] }, "public_key_sha256"},
		{"digest of 40 digits (a fingerprint of OpenPGP)", func(m map[string]any) { m["public_key_sha256"] = dg('a')[:40] }, "public_key_sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := edited(birthMap, c.edit)
			l, err := files.ReadBirthLine(line)
			if c.member == "" {
				if err != nil {
					t.Fatalf("a good line is refused: %v\n%s", err, line)
				}
				if back, err := l.Canonical(); err != nil || !bytes.Equal(back, line) {
					t.Errorf("an accepted line is not its canonical form: %s %v", back, err)
				}
				return
			}
			if l != nil {
				t.Error("a line came with its error")
			}
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				// a member of the wrong type is a fault of strictjson
				if err == nil || !errors.Is(err, strictjson.ErrMalformed) {
					t.Fatalf("err = %v (%T)\n%s", err, err, line)
				}
				return
			}
			if fe.Member != c.member {
				t.Errorf("the fault is in %q, want %q: %v", fe.Member, c.member, err)
			}
			if !printableASCII(err.Error()) {
				t.Errorf("the error text is not printable ASCII: %q", err)
			}
		})
	}
}

func TestSignatureLineWantsEachMemberInItsForm(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(map[string]any)
		member string
	}{
		{"the good line", func(m map[string]any) {}, ""},
		{"no at", func(m map[string]any) { delete(m, "at") }, "at"},
		{"at with a fraction", func(m map[string]any) { m["at"] = "2026-11-14T10:00:00.5Z" }, "at"},
		{"at empty", func(m map[string]any) { m["at"] = "" }, "at"},
		{"no n", func(m map[string]any) { delete(m, "n") }, "n"},
		{"n 0", func(m map[string]any) { m["n"] = 0 }, "n"},
		{"n -1", func(m map[string]any) { m["n"] = -1 }, "n"},
		{"n 1", func(m map[string]any) { m["n"] = 1 }, ""},
		{"n 112", func(m map[string]any) { m["n"] = 112 }, ""},
		{"n 113", func(m map[string]any) { m["n"] = 113 }, "n"},
		{"n a million", func(m map[string]any) { m["n"] = 1000000 }, "n"},
		{"n a fraction", func(m map[string]any) { m["n"] = 1.5 }, "n"},
		{"n a string", func(m map[string]any) { m["n"] = "1" }, "n"},
		{"n null", func(m map[string]any) { m["n"] = nil }, "n"},
		{"n beyond the integers that are exact", func(m map[string]any) { m["n"] = int64(9007199254740993) }, "n"},
		{"no kind", func(m map[string]any) { delete(m, "kind") }, "kind"},
		{"kind empty", func(m map[string]any) { m["kind"] = "" }, "kind"},
		{"kind unknown", func(m map[string]any) { m["kind"] = "something" }, "kind"},
		{"kind in capitals", func(m map[string]any) { m["kind"] = "ROOT-LIST" }, "kind"},
		{"no key", func(m map[string]any) { delete(m, "key") }, "key"},
		{"key empty", func(m map[string]any) { m["key"] = "" }, "key"},
		{"key of 64 digits", func(m map[string]any) { m["key"] = dg('c') }, ""},
		{"key of 40 digits (an OpenPGP fingerprint)", func(m map[string]any) { m["key"] = dg('c')[:40] }, ""},
		{"key of 63 digits", func(m map[string]any) { m["key"] = dg('c')[:63] }, "key"},
		{"key of 41 digits", func(m map[string]any) { m["key"] = dg('c')[:41] }, "key"},
		{"key of 39 digits", func(m map[string]any) { m["key"] = dg('c')[:39] }, "key"},
		{"key in capitals", func(m map[string]any) { m["key"] = strings.ToUpper(dg('c')) }, "key"},
		{"key of 40 digits in capitals", func(m map[string]any) { m["key"] = strings.ToUpper(dg('c')[:40]) }, "key"},
		{"key that is not hexadecimal", func(m map[string]any) { m["key"] = strings.Repeat("z", 64) }, "key"},
		{"key with colons", func(m map[string]any) { m["key"] = strings.Repeat("ab:", 21) + "a" }, "key"},
		{"no signature_sha256", func(m map[string]any) { delete(m, "signature_sha256") }, "signature_sha256"},
		{"signature digest empty", func(m map[string]any) { m["signature_sha256"] = "" }, "signature_sha256"},
		{"signature digest of 40 digits", func(m map[string]any) { m["signature_sha256"] = dg('b')[:40] }, "signature_sha256"},
		{"signature digest in capitals", func(m map[string]any) { m["signature_sha256"] = strings.ToUpper(dg('b')) }, "signature_sha256"},
		{"signature digest of 65 digits", func(m map[string]any) { m["signature_sha256"] = dg('b') + "b" }, "signature_sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := edited(sigMap, c.edit)
			l, err := files.ReadSignatureLine(line)
			if c.member == "" {
				if err != nil {
					t.Fatalf("a good line is refused: %v\n%s", err, line)
				}
				if back, err := l.Canonical(); err != nil || !bytes.Equal(back, line) {
					t.Errorf("an accepted line is not its canonical form: %s %v", back, err)
				}
				return
			}
			if l != nil {
				t.Error("a line came with its error")
			}
			var fe *files.FormatError
			if !errors.As(err, &fe) {
				if err == nil || !errors.Is(err, strictjson.ErrMalformed) {
					t.Fatalf("err = %v (%T)\n%s", err, err, line)
				}
				return
			}
			if fe.Member != c.member {
				t.Errorf("the fault is in %q, want %q: %v", fe.Member, c.member, err)
			}
			if !printableASCII(err.Error()) {
				t.Errorf("the error text is not printable ASCII: %q", err)
			}
		})
	}
}

// Whole lines that break a rule of the page: an extra member, a member twice, the wrong order,
// spaces, a line break, a form that is not canonical, a size.
func TestJournalLinesRefuseWhatIsNotTheLineOfThePage(t *testing.T) {
	type pair struct {
		name string
		good string
		read func([]byte) error
	}
	readers := []pair{
		{"birth", goldenBirth, func(b []byte) error { _, err := files.ReadBirthLine(b); return err }},
		{"signature", goldenSig, func(b []byte) error { _, err := files.ReadSignatureLine(b); return err }},
	}
	bs := string(rune(92))
	for _, p := range readers {
		first := func(s string) string { return strings.SplitN(s[2:], `"`, 2)[0] } // the name of the first member
		_ = first
		cases := map[string][]byte{
			"empty":                      nil,
			"a space":                    []byte(" "),
			"spaces around":              []byte(" " + p.good + " "),
			"a space after a colon":      []byte(strings.Replace(p.good, `":`, `": `, 1)),
			"a space after a comma":      []byte(strings.Replace(p.good, `,"`, `, "`, 1)),
			"a line feed at the end":     []byte(p.good + "\n"),
			"a line feed at the start":   []byte("\n" + p.good),
			"a carriage return":          []byte(p.good + "\r"),
			"a line feed inside":         []byte(strings.Replace(p.good, `,"`, ",\n\"", 1)),
			"two lines":                  []byte(p.good + "\n" + p.good),
			"two objects":                []byte(p.good + p.good),
			"an extra member":            []byte(strings.Replace(p.good, `{"at"`, `{"a0":"x","at"`, 1)),
			"an extra member at the end": []byte(strings.TrimSuffix(p.good, "}") + `,"zz":"x"}`),
			"a member twice":             []byte(strings.TrimSuffix(p.good, "}") + `,"at":"2026-11-14T10:00:00Z"}`),
			"members in the wrong order": []byte(`{"zz":1,` + p.good[1:]),
			"an array":                   []byte(`[` + p.good + `]`),
			"a string":                   []byte(`"` + strings.ReplaceAll(p.good, `"`, `\"`) + `"`),
			"a number":                   []byte(`1`),
			"null":                       []byte(`null`),
			"an empty object":            []byte(`{}`),
			"a byte order mark":          append([]byte("\xef\xbb\xbf"), p.good...),
			"not UTF-8":                  append([]byte(p.good[:len(p.good)-1]), 0xff, '}'),
			"an escape for a letter":     []byte(strings.Replace(p.good, `"at":"2026`, `"at":"`+bs+`u0032026`, 1)),
			"an escape in a name":        []byte(strings.Replace(p.good, `"at"`, `"`+bs+`u0061t"`, 1)),
			"a member null":              []byte(strings.Replace(p.good, `"at":"2026-11-14T10:00:0`, `"at":null,"x":"0`, 1)),
			"cut in half":                []byte(p.good[:len(p.good)/2]),
			"cut by one byte":            []byte(p.good[:len(p.good)-1]),
			"deep nesting":               []byte(strings.Repeat("[", 3000)),
			"deeper than the limit":      []byte(strings.Repeat("[", 100000)),
			"over the limit":             []byte(`{"at":"` + strings.Repeat("a", 4097) + `"}`),
			"a megabyte":                 bytes.Repeat([]byte{' '}, 1<<20),
		}
		for name, in := range cases {
			t.Run(p.name+"/"+name, func(t *testing.T) {
				err := p.read(in)
				if err == nil {
					t.Fatalf("the line was accepted: %.200q", in)
				}
				if !printableASCII(err.Error()) || len(err.Error()) > 2000 {
					t.Errorf("the error is not short printable ASCII: %.200q", err)
				}
			})
		}
	}
}

// The size is checked first: a line longer than 4,096 bytes is refused as too long whatever else is
// wrong with it, and one of exactly that size is judged on its other rules.
func TestJournalLineSizeIsCheckedBeforeTheParse(t *testing.T) {
	over := `{"a":"` + strings.Repeat("x", files.MaxJournalLine) + `"}`
	for _, read := range []func([]byte) error{
		func(b []byte) error { _, err := files.ReadBirthLine(b); return err },
		func(b []byte) error { _, err := files.ReadSignatureLine(b); return err },
	} {
		err := read([]byte(over))
		var fe *files.FormatError
		if !errors.As(err, &fe) || !strings.Contains(fe.Reason, "4096") {
			t.Errorf("a line over the limit: %v, want a FormatError that names 4096 bytes", err)
		}
		// Not valid JSON at all, of the limit and one byte over.
		if err := read(bytes.Repeat([]byte("x"), files.MaxJournalLine+1)); err == nil || !strings.Contains(err.Error(), "4096") {
			t.Errorf("a long text that is not JSON: %v", err)
		}
		err = read(bytes.Repeat([]byte("x"), files.MaxJournalLine))
		if err == nil || strings.Contains(err.Error(), "longer than") {
			t.Errorf("a text of exactly the limit is not too long: %v", err)
		}
	}
	if files.MaxJournalLine != 4096 {
		t.Errorf("MaxJournalLine = %d", files.MaxJournalLine)
	}
}

// Canonical refuses a line that its reader would refuse: the zero value and nil too.
func TestCanonicalRefusesWhatTheReaderRefuses(t *testing.T) {
	if b, err := (&files.BirthLine{}).Canonical(); err == nil || b != nil {
		t.Errorf("a zero BirthLine: %s %v", b, err)
	}
	if b, err := (&files.SignatureLine{}).Canonical(); err == nil || b != nil {
		t.Errorf("a zero SignatureLine: %s %v", b, err)
	}
	var nb *files.BirthLine
	var ns *files.SignatureLine
	if b, err := nb.Canonical(); err == nil || b != nil {
		t.Errorf("a nil BirthLine: %s %v", b, err)
	}
	if b, err := ns.Canonical(); err == nil || b != nil {
		t.Errorf("a nil SignatureLine: %s %v", b, err)
	}
	good := files.BirthLine{At: "2026-11-14T10:00:00Z", Label: "A", Purpose: "x509-root", Store: "software", Place: "p", PublicKeySHA256: dg('a')}
	for name, edit := range map[string]func(*files.BirthLine){
		"At": func(l *files.BirthLine) { l.At = "now" }, "Label": func(l *files.BirthLine) { l.Label = "a" },
		"Purpose": func(l *files.BirthLine) { l.Purpose = "X" }, "Store": func(l *files.BirthLine) { l.Store = "" },
		"Place": func(l *files.BirthLine) { l.Place = "\u00e9" }, "Digest": func(l *files.BirthLine) { l.PublicKeySHA256 = "abc" },
	} {
		l := good
		edit(&l)
		if b, err := l.Canonical(); err == nil || b != nil {
			t.Errorf("a birth line with a bad %s: %s %v", name, b, err)
		}
	}
	sgood := files.SignatureLine{At: "2026-11-14T10:00:00Z", N: 1, Kind: "root-list", Key: dg('a'), SignatureSHA256: dg('b')}
	for name, edit := range map[string]func(*files.SignatureLine){
		"At": func(l *files.SignatureLine) { l.At = "" }, "N": func(l *files.SignatureLine) { l.N = 0 },
		"N high": func(l *files.SignatureLine) { l.N = 113 }, "Kind": func(l *files.SignatureLine) { l.Kind = "x" },
		"Key": func(l *files.SignatureLine) { l.Key = "" }, "Digest": func(l *files.SignatureLine) { l.SignatureSHA256 = dg('b')[:40] },
	} {
		l := sgood
		edit(&l)
		if b, err := l.Canonical(); err == nil || b != nil {
			t.Errorf("a signature line with a bad %s: %s %v", name, b, err)
		}
	}
}

// Every line that Canonical writes is read back to the same value, and the same bytes again.
func TestEveryLineThatCanonicalWritesIsReadBack(t *testing.T) {
	for _, label := range []string{"A", "M", "Z"} {
		for _, place := range []string{"A.x509.key.pem", "slot 9a", "arn:aws:kms:eu-west-1:111122223333:key/1234", strings.Repeat("p", 255), "~!#$%&'()*+,-./0123456789:;<=>?@[\\]^_`{|}"} {
			l := &files.BirthLine{At: "2026-01-02T03:04:05Z", Label: label, Purpose: "x509-root", Store: "software", Place: place, PublicKeySHA256: dg('d')}
			b, err := l.Canonical()
			if err != nil {
				t.Fatalf("Canonical of place %q: %v", place, err)
			}
			back, err := files.ReadBirthLine(b)
			if err != nil || !reflect.DeepEqual(back, l) {
				t.Errorf("read back %+v, %v; want %+v", back, err, l)
			}
			if again, _ := back.Canonical(); !bytes.Equal(again, b) {
				t.Errorf("the bytes change on the second turn: %s %s", b, again)
			}
		}
	}
	for n := int64(1); n <= files.MaxJournalLines; n++ {
		for _, key := range []string{dg('e'), dg('e')[:40]} {
			l := &files.SignatureLine{At: "2026-01-02T03:04:05Z", N: n, Kind: files.KindRootList, Key: key, SignatureSHA256: dg('f')}
			b, err := l.Canonical()
			if err != nil {
				t.Fatalf("Canonical of n=%d: %v", n, err)
			}
			back, err := files.ReadSignatureLine(b)
			if err != nil || !reflect.DeepEqual(back, l) {
				t.Errorf("read back %+v, %v; want %+v", back, err, l)
			}
		}
	}
}

func TestTheLimitsOfAJournalAreTheOnesOfThePage(t *testing.T) {
	if files.MaxJournalLines != 4*26+8 {
		t.Errorf("MaxJournalLines = %d, want 4 for each of 26 labels and 8 more", files.MaxJournalLines)
	}
	if files.MaxJournalLine != 4096 {
		t.Errorf("MaxJournalLine = %d", files.MaxJournalLine)
	}
	// A line of this program is far under the limit, whatever the members hold.
	l := &files.BirthLine{At: "2026-11-14T10:00:00Z", Label: "A", Purpose: strings.Repeat("a", 64), Store: strings.Repeat("a", 64), Place: strings.Repeat("~", 255), PublicKeySHA256: dg('a')}
	b, err := l.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 1024 {
		t.Errorf("the longest birth line is %d bytes", len(b))
	}
	_ = fmt.Sprint
}

// The error of a reader names the member and never holds the line's text beyond a quoted, cut and
// escaped piece of it.
func TestJournalErrorsEscapeTheTextOfTheLine(t *testing.T) {
	m := birthMap()
	m["place"] = "a\u202e\x1b[2J" + strings.Repeat("z", 400)
	b, _ := json.Marshal(m)
	c, err := canonjson.Canonicalize(b)
	if err != nil {
		t.Fatal(err)
	}
	_, err = files.ReadBirthLine(c)
	if err == nil {
		t.Fatal("accepted")
	}
	if !printableASCII(err.Error()) {
		t.Errorf("error text with a raw byte: %q", err)
	}
	if len(err.Error()) > 400 {
		t.Errorf("the error is %d bytes: it holds the whole text", len(err.Error()))
	}
}
