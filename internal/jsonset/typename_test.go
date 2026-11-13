package jsonset

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TypeName writes the text of a Go type for an error, as reflect.Type.String does, with every
// character that is not printable ASCII written as qesc writes it (a pair of escapes for a character
// above U+FFFF). Types with a non-ASCII name are declared here in the source as they are: Go
// allows a letter of any script in an identifier.

type (
	Écart   int
	Ключ    string
	Ünit    struct{ A int }
	Ӆist    [2]int
	Ünion   interface{ Show() string }
	ASCIIok struct{ A int }
)

// fakeType gives a text of its own to a type, for the characters that no real Go type can hold
// (a control character, DEL, bytes that are not UTF-8): the embedded interface is the type that
// answers every other question.
type fakeType struct {
	reflect.Type
	text string
}

func (f fakeType) String() string { return f.text }

// expectedTypeName is the rule written out again here: printable ASCII as it is, everything else as
// qesc, on the text of the type.
func expectedTypeName(text string) string {
	var b strings.Builder
	for _, r := range text {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteString(qesc(r))
		}
	}
	return b.String()
}

func TestTypeName(t *testing.T) {
	e9, euro := string(rune(0xE9)), string(rune(0x20AC))
	withTag := func(field, tag string) reflect.Type {
		return reflect.StructOf([]reflect.StructField{{Name: field, Type: typeOf[int](), Tag: reflect.StructTag(tag)}})
	}
	cases := []struct {
		name string
		typ  reflect.Type
		want string // when it is not the rule applied to the text of the type
	}{
		// ASCII: unchanged.
		{"int", typeOf[int](), "int"},
		{"a slice of strings", typeOf[[]string](), "[]string"},
		{"a map", typeOf[map[string][]int](), "map[string][]int"},
		{"an array", typeOf[[3]byte](), "[3]uint8"},
		{"a pointer", typeOf[*pair](), "*jsonset.pair"},
		{"an interface with no methods", typeOf[any](), "interface {}"},
		{"a named interface", typeOf[shower](), "jsonset.shower"},
		{"a struct with a tag", withTag("F", `json:"a,omitempty"`), `struct { F int "json:\"a,omitempty\"" }`},
		{"a struct with no field", typeOf[struct{}](), "struct {}"},
		{"a function", typeOf[func(int) string](), "func(int) string"},
		{"a channel", typeOf[chan<- int](), "chan<- int"},
		{"a type of another package", typeOf[time.Time](), "time.Time"},
		{"a type of another package, json.Number", typeOf[json.Number](), "json.Number"},
		// A type whose own name is not ASCII.
		{"a named integer", typeOf[Écart](), "jsonset." + qesc(0xC9) + "cart"},
		{"a pointer to it", typeOf[*Écart](), "*jsonset." + qesc(0xC9) + "cart"},
		{"a slice of it", typeOf[[]Écart](), "[]jsonset." + qesc(0xC9) + "cart"},
		{"a map between two", typeOf[map[Ключ]Écart](), "map[jsonset." + qesc(0x041A) + qesc(0x043B) + qesc(0x044E) + qesc(0x0447) + "]jsonset." + qesc(0xC9) + "cart"},
		{"a struct", typeOf[Ünit](), "jsonset." + qesc(0xDC) + "nit"},
		{"an array", typeOf[Ӆist](), "jsonset." + qesc(0x04C5) + "ist"},
		{"an interface", typeOf[Ünion](), "jsonset." + qesc(0xDC) + "nion"},
		{"a type that is ASCII with a look-alike elsewhere is not confused", typeOf[ASCIIok](), "jsonset.ASCIIok"},
		// A struct type with a field or a tag that is not ASCII.
		{"a field named by a non-ASCII letter", withTag(string(rune(0xC9)), ""), "struct { " + qesc(0xC9) + " int }"},
		{"a field named by a Cyrillic capital that looks like A", withTag(string(rune(0x0410))+"ge", ""), "struct { " + qesc(0x0410) + "ge int }"},
		{"a field named by the Kelvin sign", withTag(string(rune(0x212A)), ""), "struct { " + qesc(0x212A) + " int }"},
		{"a tag with a non-ASCII name", withTag("F", "json:\""+e9+"\""), `struct { F int "json:\"` + qesc(0xE9) + `\"" }`},
		{"a tag with a character of three bytes", withTag("F", "json:\"a"+euro+"b\""), `struct { F int "json:\"a` + qesc(0x20AC) + `b\"" }`},
		{"a tag with a character above U+FFFF", withTag("F", "json:\""+string(rune(0x1F600))+"\""), `struct { F int "json:\"` + qesc(0xD83D) + qesc(0xDE00) + `\"" }`},
		{"a field and a tag that are both not ASCII", withTag(string(rune(0xC9)), "json:\""+e9+"\""), `struct { ` + qesc(0xC9) + ` int "json:\"` + qesc(0xE9) + `\"" }`},
		{"a struct in a slice in a map", reflect.MapOf(typeOf[string](), reflect.SliceOf(withTag(string(rune(0xC9)), ""))), "map[string][]struct { " + qesc(0xC9) + " int }"},
		// What no real type holds: the text is given.
		{"a control character", fakeType{typeOf[int](), "a\x01b"}, "a" + qesc(1) + "b"},
		{"a line feed and a tab", fakeType{typeOf[int](), "a\n\tb"}, "a" + qesc(10) + qesc(9) + "b"},
		{"the last control character", fakeType{typeOf[int](), "\x1f"}, qesc(0x1F)},
		{"a NUL", fakeType{typeOf[int](), "a\x00"}, "a" + qesc(0)},
		{"DEL", fakeType{typeOf[int](), "a\x7fb"}, "a" + qesc(0x7F) + "b"},
		{"the space and the tilde, the ends of printable ASCII", fakeType{typeOf[int](), " ~"}, " ~"},
		{"the first character outside ASCII", fakeType{typeOf[int](), "\u0080"}, qesc(0x80)},
		{"the last character of the BMP", fakeType{typeOf[int](), string(rune(0xFFFF))}, qesc(0xFFFF)},
		{"the first character above the BMP", fakeType{typeOf[int](), string(rune(0x10000))}, qesc(0xD800) + qesc(0xDC00)},
		{"an emoji, two escapes", fakeType{typeOf[int](), string(rune(0x1F600))}, qesc(0xD83D) + qesc(0xDE00)},
		{"the last character of Unicode", fakeType{typeOf[int](), string(rune(0x10FFFF))}, qesc(0xDBFF) + qesc(0xDFFF)},
		{"a byte that is not UTF-8 is the replacement character", fakeType{typeOf[int](), "a" + string([]byte{0xff}) + "b"}, "a" + qesc(0xFFFD) + "b"},
		{"a backslash and a quote are left as they are (a type is shown as it is, not quoted)", fakeType{typeOf[int](), `a\"b`}, `a\"b`},
		{"an empty text", fakeType{typeOf[int](), ""}, ""},
		{"a long text is not cut", fakeType{typeOf[int](), strings.Repeat("n", 300) + e9}, strings.Repeat("n", 300) + qesc(0xE9)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TypeName(tc.typ)
			if got != tc.want {
				t.Errorf("TypeName = %q, want %q", got, tc.want)
			}
			if rule := expectedTypeName(tc.typ.String()); got != rule {
				t.Errorf("TypeName = %q, the rule on the text of the type gives %q", got, rule)
			}
			for i := 0; i < len(got); i++ {
				if got[i] < 0x20 || got[i] >= 0x7f {
					t.Fatalf("byte %d of %q is %#x, not printable ASCII", i, got, got[i])
				}
			}
		})
	}
	t.Run("an ASCII type is its own text", func(t *testing.T) {
		for _, typ := range []reflect.Type{typeOf[int](), typeOf[[]*pair](), typeOf[map[string]loop](), typeOf[struct{ A, B int }](), typeOf[time.Time](), typeOf[any]()} {
			if got := TypeName(typ); got != typ.String() {
				t.Errorf("%s is shown as %q", typ, got)
			}
		}
	})
	t.Run("nothing outside printable ASCII in any output, over a set of types", func(t *testing.T) {
		set := []reflect.Type{typeOf[Écart](), typeOf[[]Ünit](), typeOf[map[Ключ][]Ӆist](), typeOf[Ünion](), typeOf[*Ünit](), typeOf[[2]Écart](), typeOf[chan Écart](), typeOf[func(Écart) Ünit](), typeOf[struct{ X Écart }]()}
		for _, name := range []string{string(rune(0xC9)), string(rune(0x0410)), string(rune(0x212A)), string(rune(0x1D400)), string(rune(0x017F)) + "x"} {
			for _, tag := range []string{"", `json:"-"`, "json:\"" + name + "\"", "json:\"a," + name + "\"", "xml:\"" + name + "\""} {
				set = append(set, reflect.StructOf([]reflect.StructField{{Name: strings.ToUpper(name), Type: typeOf[Écart](), Tag: reflect.StructTag(tag)}}))
			}
		}
		nonASCII := 0
		for _, typ := range set {
			got := TypeName(typ)
			if strings.ContainsFunc(typ.String(), func(r rune) bool { return r >= 0x80 }) {
				nonASCII++
			}
			for i := 0; i < len(got); i++ {
				if got[i] < 0x20 || got[i] >= 0x7f {
					t.Fatalf("%q: byte %d is %#x", got, i, got[i])
				}
			}
			if got != expectedTypeName(typ.String()) {
				t.Errorf("%q, the rule gives %q", got, expectedTypeName(typ.String()))
			}
		}
		if nonASCII < len(set) {
			t.Errorf("only %d of %d types have a character outside ASCII in their text: the set tests less than it says", nonASCII, len(set))
		}
	})
}

// Every text of the Checker that shows the Go name of a field shows it as Shown does: an ASCII name
// of letters, digits, underscores (and hyphens) of at most 40 bytes as it is, any other quoted, with
// the escapes of Quote and cut at 40 bytes.
func TestEveryTextThatShowsAGoFieldNameShowsItAsShown(t *testing.T) {
	e9 := string(rune(0xE9))
	long := "A" + strings.Repeat("n", 49)
	field := func(name, tag string) reflect.Type {
		return reflect.StructOf([]reflect.StructField{{Name: name, Type: typeOf[int](), Tag: reflect.StructTag(tag)}})
	}
	cases := []struct {
		name string
		typ  reflect.Type
		want string
	}{
		{"an option, ASCII name", field("Field", `json:"a,string"`), `field Field has the tag option "string"; only omitempty is allowed`},
		{"an option, a name of 40 bytes", field(long[:40], `json:"a,string"`), `field ` + long[:40] + ` has the tag option "string"; only omitempty is allowed`},
		{"an option, a name of 41 bytes is cut and quoted", field(long[:41], `json:"a,string"`), `field "` + long[:40] + `..." has the tag option "string"; only omitempty is allowed`},
		{"an option, a long name is cut", field(long, `json:"a,string"`), `field "` + long[:40] + `..." has the tag option "string"; only omitempty is allowed`},
		{"an option, a non-ASCII name", field("É"+"cole", `json:"a,string"`), `field "` + qesc(0xC9) + `cole" has the tag option "string"; only omitempty is allowed`},
		{"an option, a name above the BMP", field(string(rune(0x1D400)), `json:"a,string"`), `field "` + qesc(0xD835) + qesc(0xDC00) + `" has the tag option "string"; only omitempty is allowed`},
		{"an option that is not ASCII is quoted by its own rule", field("F", "json:\"a,"+e9+"\""), `field F has the tag option "` + qesc(0xE9) + `"; only omitempty is allowed`},
		{"a tag name, a non-ASCII field name", field("É"+"cole", `json:"a.b"`), `field "` + qesc(0xC9) + `cole" has the tag name "a.b"; ` + reasonName},
		{"a tag name, a long field name", field(long, `json:"a.b"`), `field "` + long[:40] + `..." has the tag name "a.b"; ` + reasonName},
		{"no tag name, a non-ASCII field name", field("É"+"cole", ``), `field "` + qesc(0xC9) + `cole" has no tag name, and its Go name is not a member name; ` + reasonName},
		{"no tag name, the Kelvin sign", field(string(rune(0x212A)), ``), `field "` + qesc(0x212A) + `" has no tag name, and its Go name is not a member name; ` + reasonName},
		{"an embedded field, ASCII", typeOf[struct{ pair }](), `the embedded field pair is not part of ritueel's JSON; give it a name`},
		{"an embedded field, a non-ASCII name", typeOf[struct{ Ünit }](), `the embedded field "` + qesc(0xDC) + `nit" is not part of ritueel's JSON; give it a name`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []Mode{Writing, Reading} {
				r := NewChecker(mode, rawType).Verdict(tc.typ)
				if r == nil || r.Reason != tc.want || r.Type != tc.typ {
					t.Errorf("%v: %+v, want the reason\n  %q", mode, r, tc.want)
				}
				if r != nil && strings.ContainsFunc(r.Reason, func(c rune) bool { return c < 0x20 || c >= 0x7f }) {
					t.Errorf("%v: the reason holds a character that is not printable ASCII: %q", mode, r.Reason)
				}
			}
		})
	}
}
