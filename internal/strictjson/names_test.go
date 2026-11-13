package strictjson

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Helpers for the tests of the member-name rule, of Quote and of the texts that show a name. A JSON
// escape of the form backslash, u and four digits is never written out in the test files: qesc
// builds one from a code point, so that no tool can turn it into the character on the way.

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

// shownName is a name as an error shows it: itself when it is plain (ASCII letters, digits,
// underscores and hyphens, and not longer than 40 bytes), else quotedName.
func shownName(name string) string {
	plain := name != "" && len(name) <= 40
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c != '_' && c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			plain = false
		}
	}
	if plain {
		return name
	}
	return quotedName(name)
}

// pathStep is the member step of a path for the name: a dot and the name as shownName writes it.
func pathStep(name string) string { return "." + shownName(name) }

// nameRefused is the reason for the field named, whose tag name is refused.
func nameRefused(field, name string) string {
	return "field " + field + " has the tag name " + quotedName(name) + "; " + reasonNameRule
}

// formatNames is the list of the names of the members of the formats of ritueel, read on
// 2026-11-13 from the tables headed "Member" on the reference pages of docs/reference (the root
// list, the SSH CA key list, the hand-off contract, the ceremony record, the bundle, the cards,
// the KMS root, the software store, the drill, the CLI's own output and the transitions): 116
// names. The tests of package jsonset check each name against the rule; here the names are read
// as the fields of one struct.
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

// oneFieldType is a struct type with one int field F0 with the tag.
func oneFieldType(tag reflect.StructTag) reflect.Type {
	return reflect.StructOf([]reflect.StructField{{Name: "F0", Type: reflect.TypeFor[int](), Tag: tag}})
}

func isNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// readInto reads the document into a new value of the type, and gives it back with the error.
func readInto(typ reflect.Type, doc string) (reflect.Value, error) {
	v := reflect.New(typ)
	err := Unmarshal([]byte(doc), v.Interface(), Options{})
	return v.Elem(), err
}

// A struct member name of any ASCII byte, alone and inside a name, is accepted exactly for
// letters, digits and the underscore, by the reader, with the text of the rule for every other.
func TestUnmarshalTakesAStructNameOfLettersDigitsAndUnderscoresOnly(t *testing.T) {
	for b := 0; b < 0x80; b++ {
		c := byte(b)
		for _, form := range []struct{ what, name string }{
			{"alone", string([]byte{c})},
			{"inside a name", "a" + string([]byte{c}) + "b"},
		} {
			t.Run(fmt.Sprintf("%#02x/%s", b, form.what), func(t *testing.T) {
				typ := oneFieldType(tagOf(form.name))
				// A document that names F0 as the tag says, with a name that is a plain one when it
				// can be (a name with a quote or a backslash is written with its escape).
				doc := `{` + strconv.Quote(form.name) + `:7}`
				v, err := readInto(typ, doc)
				switch {
				case c == ',' && form.what == "alone":
					// No name is left before the comma: the field keeps its Go name.
					v, err = readInto(typ, `{"F0":7}`)
					if err != nil || v.Field(0).Int() != 7 {
						t.Errorf("a comma alone: %v, %v", v, err)
					}
				case c == ',':
					fail(t, err, mal("$", fmt.Sprintf("a value of type %s cannot be read: field F0 has the tag option \"b\"; only omitempty is allowed", typ)))
				case c == '-' && form.what == "alone":
					// A dash alone leaves the field out: the member is unknown.
					v, err = readInto(typ, `{}`)
					if err != nil || v.Field(0).Int() != 0 {
						t.Errorf("a dash alone: %v, %v", v, err)
					}
					fail(t, Unmarshal([]byte(`{"-":7}`), reflect.New(typ).Interface(), Options{}), mal(`$.-`, "unknown member"))
				case isNameByte(c):
					if err != nil || v.Field(0).Int() != 7 {
						t.Errorf("%q: %v, %v", form.name, v, err)
					}
				default:
					fail(t, err, mal("$", fmt.Sprintf("a value of type %s cannot be read: %s", typ, nameRefused("F0", form.name))))
					// Whatever the document says, even `{}`: the type is refused before a byte is read.
					if _, err := readInto(typ, `{}`); err == nil {
						t.Error("the type was accepted for an empty document")
					}
				}
			})
		}
	}
}

func TestUnmarshalRefusesStructNamesOutsideASCIIWithEscapes(t *testing.T) {
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
			typ := oneFieldType(tagOf(tc.in))
			_, err := readInto(typ, `{}`)
			fail(t, err, mal("$", fmt.Sprintf("a value of type %s cannot be read: %s", typ, nameRefused("F0", tc.in))))
		})
	}
}

func TestUnmarshalOfTheDashForms(t *testing.T) {
	typ := oneFieldType(`json:"-"`)
	if v, err := readInto(typ, `{}`); err != nil || v.Field(0).Int() != 0 {
		t.Errorf("%v, %v", v, err)
	}
	for _, tc := range []struct{ tag, at string }{{`json:"-,"`, "-"}, {`json:"-,omitempty"`, "-"}, {`json:"--"`, "--"}, {`json:"a-b"`, "a-b"}} {
		typ := oneFieldType(reflect.StructTag(tc.tag))
		_, err := readInto(typ, `{}`)
		fail(t, err, mal("$", fmt.Sprintf("a value of type %s cannot be read: %s", typ, nameRefused("F0", tc.at))))
	}
}

func TestUnmarshalAGoNameWithNoTagIsHeldToTheRule(t *testing.T) {
	for _, name := range []string{"Version", "A_b", "Z9"} {
		typ := reflect.StructOf([]reflect.StructField{{Name: name, Type: reflect.TypeFor[int]()}})
		if v, err := readInto(typ, `{"`+name+`":3}`); err != nil || v.Field(0).Int() != 3 {
			t.Errorf("%s: %v, %v", name, v, err)
		}
	}
	// The text names the field as Go does (which is raw, a doubt that the report raises), so only
	// the rest of the text is pinned.
	for _, name := range []string{string(rune(0xC9)) + "cole", "A" + string(rune(0xE9)), string(rune(0x0410)) + "ge", string(rune(0x212A))} {
		typ := reflect.StructOf([]reflect.StructField{{Name: name, Type: reflect.TypeFor[int]()}})
		_, err := readInto(typ, `{}`)
		if !errors.Is(err, ErrMalformed) || !strings.HasSuffix(err.Error(), " has no tag name, and its Go name is not a member name; "+reasonNameRule) ||
			!strings.HasPrefix(err.Error(), "malformed JSON: $: a value of type "+typ.String()+" cannot be read: field ") {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestUnmarshalTakesAnyTextForTheKeysOfAMap(t *testing.T) {
	want := map[string]int{}
	keys := []string{"", "-", "-,", string(rune(0xE9)), string(rune(0x212A)), string(rune(0x1F600)), "a.b", "a b"}
	for b := 1; b < 0x80; b++ { // NUL is a valid member name too, but this test writes the document by hand
		keys = append(keys, string([]byte{byte(b)}), "a"+string([]byte{byte(b)})+"b")
	}
	var unique []string
	for _, k := range keys {
		if _, dup := want[k]; !dup {
			want[k] = len(unique)
			unique = append(unique, k)
		}
	}
	keys = unique
	// The document is made by the escapes of JSON: a quote or a backslash after a backslash,
	// printable ASCII as it is, and every other character as an escape.
	var j strings.Builder
	j.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			j.WriteByte(',')
		}
		j.WriteByte('"')
		for _, r := range k {
			switch {
			case r == '"' || r == '\\':
				j.WriteByte('\\')
				j.WriteRune(r)
			case r >= 0x20 && r < 0x7f:
				j.WriteRune(r)
			default:
				j.WriteString(qesc(r))
			}
		}
		fmt.Fprintf(&j, `":%d`, i)
	}
	j.WriteByte('}')
	var got map[string]int
	if err := Unmarshal([]byte(j.String()), &got, Options{}); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%d entries, %v", len(got), err)
	}
}

// Every name of the formats is read as a field of one struct.
func TestEveryNameOfTheDecidedFormatsIsRead(t *testing.T) {
	if len(formatNames) != 116 || !slices.IsSorted(formatNames) {
		t.Fatalf("the list holds %d names, sorted: %v", len(formatNames), slices.IsSorted(formatNames))
	}
	var fields []reflect.StructField
	for i, name := range formatNames {
		fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: reflect.TypeFor[int](), Tag: tagOf(name)})
	}
	typ := reflect.StructOf(fields)
	var doc strings.Builder
	doc.WriteByte('{')
	// In an order that is not the sorted one: the last name first.
	for i := len(formatNames) - 1; i >= 0; i-- {
		fmt.Fprintf(&doc, `"%s":%d`, formatNames[i], i+1)
		if i > 0 {
			doc.WriteByte(',')
		}
	}
	doc.WriteByte('}')
	v, err := readInto(typ, doc.String())
	if err != nil {
		t.Fatal(err)
	}
	for i := range formatNames {
		if v.Field(i).Int() != int64(i+1) {
			t.Errorf("%s = %d, want %d", formatNames[i], v.Field(i).Int(), i+1)
		}
	}
}
