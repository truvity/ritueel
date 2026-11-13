package canonjson

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// Helpers for the tests of the member-name rule and of the texts that show a name. A JSON escape of
// the form backslash, u and four digits is never written out in the test files: qesc builds one
// from a code point, so that no tool can turn it into the character on the way.

// reasonNameRule is the rule for the name of a member of a struct, as the errors say it.
const reasonNameRule = "a member name holds only ASCII letters, digits and underscores"

// qesc is the escape that jsonset.Quote writes for a character that is not printable ASCII: the
// escape of its code point in lower case, and for a character above U+FFFF the escapes of its two
// surrogates (worked out here by hand).
func qesc(r rune) string {
	if r > 0xFFFF {
		v := r - 0x10000
		return fmt.Sprintf("%cu%04x%cu%04x", '\\', 0xD800+(v>>10), '\\', 0xDC00+(v&0x3FF))
	}
	return fmt.Sprintf("%cu%04x", '\\', r)
}

// typeText is the text of a Go type in an error: reflect's own text, with every character that is
// not printable ASCII (a look-alike in the name of a type or of a field) written as qesc writes it.
func typeText(t reflect.Type) string {
	var b strings.Builder
	for _, r := range t.String() {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteString(qesc(r))
		}
	}
	return b.String()
}

// quotedName is a name as an error shows it when it is not plain: in quotes, a quote or a
// backslash after a backslash, printable ASCII as it is and everything else as qesc.
func quotedName(name string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range name {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		default:
			b.WriteString(qesc(r))
		}
	}
	b.WriteByte('"')
	return b.String()
}

// nameRefused is the reason for the field named, whose tag name is refused.
func nameRefused(field, name string) string {
	return "field " + field + " has the tag name " + quotedName(name) + "; " + reasonNameRule
}

// formatNames is the list of the names of the members of the formats of ritueel, read on
// 2026-11-13 from the tables headed "Member" on the reference pages of docs/reference (the root
// list, the SSH CA key list, the hand-off contract, the ceremony record, the bundle, the cards,
// the KMS root, the software store, the drill, the CLI's own output and the transitions): 116
// names. The same list is in the tests of package jsonset, which check each name against the
// rule; here the names are written and read back as the fields of one struct.
var formatNames = []string{
	"account", "admin_role", "adopted", "advisory_review", "alg", "algorithm",
	"answer", "application", "applications", "applied", "applies", "arguments",
	"artifacts", "attestation", "attestation_bundle", "backend", "base_sequence", "births",
	"born_at", "capabilities", "ceremony", "ceremony_role", "ceremony_time", "checked_at",
	"checks", "closes", "command", "commit", "confirmation", "created_at",
	"declined", "derived", "error", "evidence", "exit_code", "expires_at",
	"extra_intermediates", "findings", "fingerprint", "finished_at", "firmware", "form_factor",
	"handoff", "inputs", "issuer", "key", "key_ref", "keys",
	"kid", "kind", "label", "last_record_sha256", "leaves_out", "left_out",
	"limit_shown", "made_at", "n", "name", "not_after", "not_before",
	"openpgp_created", "openpgp_fingerprint", "outcome", "output", "pin_rule", "plan",
	"plan_sha256", "prev_record_sha256", "primaries", "public_key_sha256", "ran_on", "reason",
	"reasons", "record", "records", "region", "removal_sha256", "removals",
	"replica_region", "request_sha256", "requests", "revocations", "ritueel", "root",
	"root_reason", "roots", "row", "sequence", "serial", "signatures",
	"signed_at", "slot", "slot_map_version", "ssh_public_key", "started_at", "steps",
	"store", "store_ref", "subject", "tbs_sha256", "test", "touch_rule",
	"touches", "transcript_sha256", "trust_sequence", "typ", "type", "use",
	"valid_from", "valid_until", "version", "vouched_by", "vouches", "wanted",
	"x509_spki_sha256", "x5c",
}

// tagOf is the tag for a member name, written so that any byte of the name is carried.
func tagOf(name string) reflect.StructTag { return reflect.StructTag("json:" + strconv.Quote(name)) }

// oneField is a zero value of a struct with one int field F0 with the tag, and its type's text.
func oneField(tag reflect.StructTag) (any, string) {
	typ := reflect.StructOf([]reflect.StructField{{Name: "F0", Type: reflect.TypeFor[int](), Tag: tag}})
	return reflect.New(typ).Elem().Interface(), typeText(typ)
}

func isNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// A struct member name of any ASCII byte, alone and inside a name, is accepted exactly for letters,
// digits and the underscore, by the writer, with the text of the rule for every other.
func TestMarshalTakesAStructNameOfLettersDigitsAndUnderscoresOnly(t *testing.T) {
	for b := 0; b < 0x80; b++ {
		c := byte(b)
		for _, form := range []struct{ what, name string }{
			{"alone", string([]byte{c})},
			{"inside a name", "a" + string([]byte{c}) + "b"},
		} {
			t.Run(fmt.Sprintf("%#02x/%s", b, form.what), func(t *testing.T) {
				v, typ := oneField(tagOf(form.name))
				got, err := Marshal(v)
				switch {
				case c == ',' && form.what == "alone":
					// No name is left before the comma: the field keeps its Go name.
					if err != nil || string(got) != `{"F0":0}` {
						t.Errorf("a comma alone: %q, %v", got, err)
					}
				case c == ',':
					refusedWith(t, got, err, `field F0 has the tag option "b"; only omitempty is allowed`)
				case c == '-' && form.what == "alone":
					// A dash alone leaves the field out.
					if err != nil || string(got) != `{}` {
						t.Errorf("a dash alone: %q, %v", got, err)
					}
				case isNameByte(c):
					if want := `{"` + form.name + `":0}`; err != nil || string(got) != want {
						t.Errorf("%q: %q, %v; want %s", form.name, got, err, want)
					}
				default:
					refused(t, got, err, malformedText("$: a value of type %s cannot be written: %s", typ, nameRefused("F0", form.name)))
				}
			})
		}
	}
}

func TestMarshalRefusesStructNamesOutsideASCIIWithEscapes(t *testing.T) {
	cases := []struct{ name, in string }{
		{"an accented letter", "caf" + string(rune(0xE9))},
		{"a Cyrillic letter that looks like a Latin one", "v" + string(rune(0x0435)) + "rsion"},
		{"the Kelvin sign", string(rune(0x212A))},
		{"the long s", string(rune(0x017F))},
		{"an emoji", string(rune(0x1F600))},
		{"a full-width digit", string(rune(0xFF11))},
		{"text that is not UTF-8", "a" + string([]byte{0xff}) + "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, typ := oneField(tagOf(tc.in))
			got, err := Marshal(v)
			refused(t, got, err, malformedText("$: a value of type %s cannot be written: %s", typ, nameRefused("F0", tc.in)))
			if strings.ContainsFunc(err.Error(), func(r rune) bool { return r >= 0x80 && !strings.Contains(typ, string(r)) }) {
				t.Errorf("the text shows a character outside ASCII: %q", err)
			}
		})
	}
	t.Run("the look-alike is shown as an escape and not as the letter", func(t *testing.T) {
		v, _ := oneField(tagOf("v" + string(rune(0x0435)) + "rsion"))
		_, err := Marshal(v)
		if err == nil || !strings.Contains(err.Error(), `has the tag name "v`+qesc(0x0435)+`rsion"; `) {
			t.Errorf("%v", err)
		}
	})
}

func TestMarshalOfTheDashForms(t *testing.T) {
	for _, tc := range []struct {
		tag, want string // the document, or "" when the type is refused at the name shown
		refusedAt string
	}{
		{tag: `json:"-"`, want: `{}`},
		{tag: `json:"-,"`, refusedAt: "-"},
		{tag: `json:"-,omitempty"`, refusedAt: "-"},
		{tag: `json:"--"`, refusedAt: "--"},
		{tag: `json:"a-b"`, refusedAt: "a-b"},
	} {
		v, typ := oneField(reflect.StructTag(tc.tag))
		got, err := Marshal(v)
		if tc.refusedAt == "" {
			if err != nil || string(got) != tc.want {
				t.Errorf("%s: %q, %v", tc.tag, got, err)
			}
			continue
		}
		refused(t, got, err, malformedText("$: a value of type %s cannot be written: %s", typ, nameRefused("F0", tc.refusedAt)))
	}
}

func TestMarshalAGoNameWithNoTagIsHeldToTheRule(t *testing.T) {
	for _, name := range []string{"Version", "A_b", "Z9"} {
		got, err := Marshal(goNamed(t, name))
		if want := `{"` + name + `":0}`; err != nil || string(got) != want {
			t.Errorf("%s: %q, %v", name, got, err)
		}
	}
	// A Go name may be any Unicode letter; a member name may not. The field is shown as Shown shows
	// it, and the type with its escapes.
	for _, name := range []string{string(rune(0xC9)) + "cole", "A" + string(rune(0xE9)), string(rune(0x0410)) + "ge", string(rune(0x212A)), string(rune(0x1D400))} {
		got, err := Marshal(goNamed(t, name))
		want := malformedText("$: a value of type %s cannot be written: field %s has no tag name, and its Go name is not a member name; %s", goNamedType(t, name), quotedName(name), reasonNameRule)
		refused(t, got, err, want)
		if strings.ContainsFunc(err.Error(), func(r rune) bool { return r < 0x20 || r >= 0x7f }) {
			t.Errorf("%q: the text holds a character that is not printable ASCII: %q", name, err)
		}
	}
}

func TestMarshalTakesAnyTextForTheKeysOfAMap(t *testing.T) {
	m := map[string]int{}
	for b := 0; b < 0x80; b++ {
		m[string([]byte{byte(b)})] = b
		m["a"+string([]byte{byte(b)})+"b"] = b
	}
	for _, k := range []string{"", "-", "-,", string(rune(0xE9)), string(rune(0x212A)), string(rune(0x1F600)), "a.b", "a b"} {
		m[k] = 1
	}
	doc, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]int
	if err := strictjson.Unmarshal(doc, &back, strictjson.Options{}); err != nil || !reflect.DeepEqual(back, m) {
		t.Errorf("the map came back as %d entries (%v)", len(back), err)
	}
}

// Every name of the formats is written as a field and read back, in the order of the names.
func TestEveryNameOfTheDecidedFormatsIsWrittenAndReadBack(t *testing.T) {
	var fields []reflect.StructField
	for i, name := range formatNames {
		fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: reflect.TypeFor[int](), Tag: tagOf(name)})
	}
	typ := reflect.StructOf(fields)
	v := reflect.New(typ)
	for i := range formatNames {
		v.Elem().Field(i).SetInt(int64(i + 1))
	}
	doc, err := Marshal(v.Interface())
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	want.WriteByte('{')
	for i, name := range formatNames { // the list is sorted, and the names are ASCII
		if i > 0 {
			want.WriteByte(',')
		}
		fmt.Fprintf(&want, `"%s":%d`, name, i+1)
	}
	want.WriteByte('}')
	if string(doc) != want.String() {
		t.Errorf("the document is\n%s\nwant\n%s", doc, want.String())
	}
	back := reflect.New(typ)
	if err := strictjson.Unmarshal(doc, back.Interface(), strictjson.Options{}); err != nil || !reflect.DeepEqual(back.Interface(), v.Interface()) {
		t.Errorf("read back: %v", err)
	}
	if ok, err := IsCanonical(doc); err != nil || !ok {
		t.Errorf("the document is not canonical: %v", err)
	}
}
