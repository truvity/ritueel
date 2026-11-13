package jsonset

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The rule for the name of a member of a struct: ASCII letters, digits and underscores, and the
// Go name of a field with no tag name is held to it as a tag name is. It is not a rule for the
// keys of a map. No JSON escape of the form backslash, u and four digits is written out in this
// file: qesc builds one from a code point.

// quoted is the form of a name in an error, worked out here again from the rule that Quote
// documents: a quote or a backslash after a backslash, printable ASCII as it is, the rest as qesc.
func quoted(name string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range name {
		switch {
		case r == '"' || r == 92:
			b.WriteRune(92)
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

// oneField is a struct type of one field F0 with the tag text given (the tag is the whole text,
// so a test can say `json:"-"`).
func oneField(tag string) reflect.Type {
	return reflect.StructOf([]reflect.StructField{{Name: "F0", Type: typeOf[int](), Tag: reflect.StructTag(tag)}})
}

// jsonTag is the tag for a member name, written so that any byte of the name is carried: the name
// is quoted by strconv, which the lookup of a tag reads back.
func jsonTag(name string) string { return "json:" + strconv.Quote(name) }

// isNameByte is the rule, for one byte, written out here.
func isNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// checkName asks both modes about a struct whose one field has the tag, and says what each says: the
// names that are listed, and the reason of a refusal.
func checkName(t *testing.T, tag string) (names []string, reason string) {
	t.Helper()
	typ := oneField(tag)
	for _, mode := range []Mode{Writing, Reading} {
		c := NewChecker(mode, rawType)
		var gotNames []string
		gotReason := ""
		if r := c.Verdict(typ); r != nil {
			gotReason = r.Reason
			if r.Type != typ || len(r.Hops) != 0 {
				t.Errorf("%v: %s: the refusal is at %s %v, not at the struct", mode, tag, r.Type, r.Hops)
			}
		} else {
			for _, f := range c.Fields(typ) {
				gotNames = append(gotNames, f.Name)
			}
		}
		if mode == Writing {
			names, reason = gotNames, gotReason
		} else if !slices.Equal(names, gotNames) || reason != gotReason {
			t.Errorf("%s: writing says %q %q, reading says %q %q", tag, names, reason, gotNames, gotReason)
		}
	}
	return names, reason
}

func TestTheNameRuleForEveryASCIIByte(t *testing.T) {
	for b := 0; b < 0x80; b++ {
		c := byte(b)
		for _, form := range []struct{ what, name string }{
			{"alone", string([]byte{c})},
			{"inside a name", "a" + string([]byte{c}) + "b"},
			{"at the start", string([]byte{c}) + "ab"},
			{"at the end", "ab" + string([]byte{c})},
		} {
			t.Run(fmt.Sprintf("%#02x/%s", b, form.what), func(t *testing.T) {
				if c == ',' {
					// A comma ends the name in a tag. Alone, it leaves no name and the field keeps
					// its Go name; inside a name, what follows it is a tag option.
					names, reason := checkName(t, jsonTag(form.name))
					switch form.what {
					case "alone":
						if reason != "" || !slices.Equal(names, []string{"F0"}) {
							t.Errorf("a comma alone: %q %q", names, reason)
						}
					case "inside a name":
						if want := `field F0 has the tag option "b"; only omitempty is allowed`; reason != want {
							t.Errorf("a comma inside: %q, want %q", reason, want)
						}
					case "at the start":
						if want := `field F0 has the tag option "ab"; only omitempty is allowed`; reason != want {
							t.Errorf("a comma at the start: %q, want %q", reason, want)
						}
					case "at the end":
						if reason != "" || !slices.Equal(names, []string{"ab"}) {
							t.Errorf("a comma at the end: %q %q", names, reason)
						}
					}
					return
				}
				names, reason := checkName(t, jsonTag(form.name))
				if form.name == "-" {
					// A dash alone is not a name: the field is left out.
					if reason != "" || names != nil {
						t.Errorf("a dash alone: %q %q", names, reason)
					}
					return
				}
				accepted := true
				for i := 0; i < len(form.name); i++ {
					accepted = accepted && isNameByte(form.name[i])
				}
				if accepted {
					if reason != "" || !slices.Equal(names, []string{form.name}) {
						t.Errorf("%q: refused (%q) or listed as %q", form.name, reason, names)
					}
					return
				}
				if want := "field F0 has the tag name " + quoted(form.name) + "; " + reasonName; reason != want || names != nil {
					t.Errorf("%q: the reason is\n  %q\nwant\n  %q", form.name, reason, want)
				}
			})
		}
	}
}

func TestTheNameRuleAcceptsExactlyLettersDigitsAndTheUnderscore(t *testing.T) {
	// The count, so that a change of the set of accepted bytes in either direction is seen at once.
	accepted := 0
	for b := 0; b < 0x80; b++ {
		if _, reason := checkName(t, jsonTag("a"+string([]byte{byte(b)})+"b")); reason == "" && b != ',' {
			accepted++
		}
	}
	if accepted != 26+26+10+1 {
		t.Errorf("%d ASCII bytes are accepted inside a name, want 63", accepted)
	}
	for _, name := range []string{"_", "__", "_a", "a_", "A", "Z", "z", "0", "9", "09", "0a", "a0", "A_Z_0_9"} {
		if names, reason := checkName(t, jsonTag(name)); reason != "" || !slices.Equal(names, []string{name}) {
			t.Errorf("%q: %q %q", name, names, reason)
		}
	}
}

func TestTheNameRuleRefusesNamesOutsideASCII(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"an accented letter", "caf" + string(rune(0xE9))},
		{"an accented letter alone", string(rune(0xE9))},
		{"a Cyrillic letter that looks like a Latin one", "v" + string(rune(0x0435)) + "rsion"},
		{"a Cyrillic letter alone", string(rune(0x0430))},
		{"the Kelvin sign", string(rune(0x212A))},
		{"the Kelvin sign inside a name", "mar" + string(rune(0x212A))},
		{"the long s", string(rune(0x017F))},
		{"an emoji", string(rune(0x1F600))},
		{"an emoji inside a name", "a" + string(rune(0x1F600)) + "b"},
		{"a mathematical bold capital A (a letter above the BMP)", string(rune(0x1D400))},
		{"a full-width digit", string(rune(0xFF11))},
		{"an Arabic-Indic digit", string(rune(0x0663))},
		{"a zero-width space", "a" + string(rune(0x200B)) + "b"},
		{"the replacement character", string(rune(0xFFFD))},
		{"text that is not UTF-8", "a" + string([]byte{0xff}) + "b"},
		{"a truncated character", "a" + string([]byte{0xc3})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names, reason := checkName(t, jsonTag(tc.in))
			if want := "field F0 has the tag name " + quoted(tc.in) + "; " + reasonName; reason != want || names != nil {
				t.Errorf("reason\n  %q\nwant\n  %q", reason, want)
			}
			if strings.ContainsFunc(reason, func(r rune) bool { return r >= 0x80 }) {
				t.Errorf("the text holds a character outside ASCII: %q", reason)
			}
		})
	}
	t.Run("the look-alike is not shown as the letter", func(t *testing.T) {
		_, reason := checkName(t, jsonTag("v"+string(rune(0x0435))+"rsion"))
		if want := `field F0 has the tag name "v` + qesc(0x0435) + `rsion"; ` + reasonName; reason != want {
			t.Errorf("got %q, want %q", reason, want)
		}
	})
}

func TestTheDashForms(t *testing.T) {
	cases := []struct {
		name, tag string
		names     []string
		reason    string
	}{
		{"dash skips the field", `json:"-"`, nil, ""},
		{"dash and a comma names a field dash, which is refused", `json:"-,"`, nil, tagNameRefused("-")},
		{"dash and omitempty names a field dash, which is refused", `json:"-,omitempty"`, nil, tagNameRefused("-")},
		{"dash and an option that is none", `json:"-,string"`, nil, `field F0 has the tag option "string"; only omitempty is allowed`},
		{"two dashes are a name", `json:"--"`, nil, tagNameRefused("--")},
		{"a dash and a letter is a name", `json:"-a"`, nil, tagNameRefused("-a")},
		{"a dash inside a name", `json:"a-b"`, nil, tagNameRefused("a-b")},
		{"a dash at the end", `json:"a-"`, nil, tagNameRefused("a-")},
		{"omitempty alone leaves the Go name", `json:",omitempty"`, []string{"F0"}, ""},
		{"an empty tag leaves the Go name", `json:""`, []string{"F0"}, ""},
		{"no json key leaves the Go name", `xml:"-"`, []string{"F0"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			names, reason := checkName(t, tc.tag)
			if reason != tc.reason || !slices.Equal(names, tc.names) {
				t.Errorf("names %q reason %q, want %q %q", names, reason, tc.names, tc.reason)
			}
		})
	}
	t.Run("a field tagged dash is not looked at, whatever its type", func(t *testing.T) {
		typ := typeOf[struct {
			A int
			B float64 `json:"-"`
			C jsonVal `json:"-"`
		}]()
		for _, mode := range []Mode{Writing, Reading} {
			c := NewChecker(mode, rawType)
			if r := c.Verdict(typ); r != nil {
				t.Errorf("%v: %+v", mode, r)
			}
			if f := c.Fields(typ); len(f) != 1 || f[0].Name != "A" {
				t.Errorf("%v: the fields are %+v", mode, f)
			}
		}
	})
}

// fieldNamed is a struct type with one exported field of the Go name given and no tag.
func fieldNamed(goName string) reflect.Type {
	return reflect.StructOf([]reflect.StructField{{Name: goName, Type: typeOf[int]()}})
}

func TestAFieldWithNoTagNameIsHeldToTheRuleByItsGoName(t *testing.T) {
	for _, mode := range []Mode{Writing, Reading} {
		for _, name := range []string{"Version", "A", "A_b", "A1", "Z9_"} {
			c := NewChecker(mode, rawType)
			typ := fieldNamed(name)
			if r := c.Verdict(typ); r != nil {
				t.Errorf("%v %s: refused: %s", mode, name, r.Reason)
			} else if f := c.Fields(typ); len(f) != 1 || f[0].Name != name {
				t.Errorf("%v %s: the fields are %+v", mode, name, f)
			}
		}
		// A Go name may be any letter of Unicode; the rule is not. These are exported (upper case).
		for _, tc := range []struct {
			name, goName string
		}{
			{"an accented capital", string(rune(0xC9)) + "cole"},
			{"an accented capital after ASCII", "A" + string(rune(0xE9))},
			{"a Cyrillic capital that looks like A", string(rune(0x0410)) + "ge"},
			{"the Kelvin sign, which is a capital", string(rune(0x212A))},
			{"a Greek capital", string(rune(0x0391))},
			{"a digit outside ASCII after a capital", "A" + string(rune(0x0663))},
		} {
			t.Run(fmt.Sprintf("%v/%s", mode, tc.name), func(t *testing.T) {
				c := NewChecker(mode, rawType)
				typ := fieldNamed(tc.goName)
				r := c.Verdict(typ)
				if r == nil {
					t.Fatalf("%q is accepted", tc.goName)
				}
				// The field is shown as Shown shows it, quoted and with escapes, and so is the type.
				if r.Type != typ || len(r.Hops) != 0 {
					t.Errorf("refusal at %s %v", r.Type, r.Hops)
				}
				if want := "field " + quoted(tc.goName) + " has no tag name, and its Go name is not a member name; " + reasonName; r.Reason != want {
					t.Errorf("the reason is\n  %q\nwant\n  %q", r.Reason, want)
				}
			})
		}
	}
	t.Run("a tag name makes the Go name no matter", func(t *testing.T) {
		typ := reflect.StructOf([]reflect.StructField{{Name: string(rune(0xC9)) + "cole", Type: typeOf[int](), Tag: `json:"ecole"`}})
		if names, reason := fieldsOf(t, typ); reason != "" || !slices.Equal(names, []string{"ecole"}) {
			t.Errorf("%q %q", names, reason)
		}
	})
	t.Run("an unexported field with a name outside the rule is not looked at", func(t *testing.T) {
		typ := reflect.StructOf([]reflect.StructField{
			{Name: "F", Type: typeOf[int]()},
			{Name: string(rune(0xE9)) + "x", PkgPath: "jsonset", Type: typeOf[int]()},
		})
		if names, reason := fieldsOf(t, typ); reason != "" || !slices.Equal(names, []string{"F"}) {
			t.Errorf("%q %q", names, reason)
		}
	})
}

func TestTheNameRuleIsNotForTheKeysOfAMap(t *testing.T) {
	for _, mode := range []Mode{Writing, Reading} {
		c := NewChecker(mode, rawType)
		for _, typ := range []reflect.Type{typeOf[map[string]int](), typeOf[map[myString][]string](), typeOf[map[string]map[string]any]()} {
			if r := c.Verdict(typ); r != nil {
				t.Errorf("%v %s: %+v", mode, typ, r)
			}
		}
	}
}

// formatNames is the list of the names of the members of the formats of ritueel, read on
// 2026-11-13 from the tables headed "Member" on the reference pages of docs/reference (the root list, the
// SSH CA key list, the hand-off contract, the ceremony record, the bundle, the cards, the KMS
// root, the software store, the drill and the CLI's own output, the transitions): 116 names.
// Every one is inside the rule, so a rule that is narrower than the formats would be seen here.
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

func TestEveryNameOfTheDecidedFormatsIsInsideTheRule(t *testing.T) {
	if len(formatNames) != 116 {
		t.Errorf("the list holds %d names", len(formatNames))
	}
	if !slices.IsSorted(formatNames) {
		t.Error("the list is not sorted")
	}
	seen := map[string]bool{}
	for _, name := range formatNames {
		if seen[name] {
			t.Errorf("%q is listed twice", name)
		}
		seen[name] = true
		if name == "" || strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			t.Errorf("%q is not a name of letters, digits and underscores", name)
		}
		for _, mode := range []Mode{Writing, Reading} {
			typ := oneField(jsonTag(name))
			c := NewChecker(mode, rawType)
			if r := c.Verdict(typ); r != nil {
				t.Errorf("%v: the name %q is refused: %s", mode, name, r.Reason)
			} else if f := c.Fields(typ); len(f) != 1 || f[0].Name != name {
				t.Errorf("%v: the name %q is listed as %+v", mode, name, f)
			}
		}
	}
	// A struct that holds all of them at once, each tagged: all are listed, in order, and no two
	// of them are one name.
	var fields []reflect.StructField
	for i, name := range formatNames {
		fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: typeOf[int](), Tag: reflect.StructTag(jsonTag(name))})
	}
	typ := reflect.StructOf(fields)
	c := NewChecker(Writing, rawType)
	if r := c.Verdict(typ); r != nil {
		t.Fatalf("the struct of all names is refused: %s", r.Reason)
	}
	var got []string
	for _, f := range c.Fields(typ) {
		got = append(got, f.Name)
	}
	if !slices.Equal(got, formatNames) {
		t.Errorf("the names are listed as %q", got)
	}
}
