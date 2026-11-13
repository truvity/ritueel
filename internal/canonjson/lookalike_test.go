package canonjson

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// The escape rule holds for the whole text of an error, not only for the member name: wherever a
// look-alike (a letter of another script, the Kelvin sign) can reach the text of a refusal, in the
// name of a Go type, of a field, of a tag or of a map key, no byte of the text is outside printable
// ASCII. The types are declared here with names that are not ASCII, as Go allows.

type (
	Ünit  struct{ A int }
	Écart int
	Ӆist  [2]int
	// Ñumber is an integer type that the top of a document cannot be.
	Ñumber int
	Ключ   string
	// Ünterface declares a method that the set refuses.
	Ünterface interface{ MarshalJSON() ([]byte, error) }
	// Ünjson has a method that the set refuses.
	Ünjson struct{}
	// Ключ2 is a map key with a method.
	Ключ2 string
	// The named types of values that only the value refuses: a nil map, a nil slice, a nil interface
	// and an unsigned integer that is too large.
	Карта      map[string]int
	Список     []int
	Ünterface0 interface{}
	Ünsigned   uint64
)

func (Ünjson) MarshalJSON() ([]byte, error) { return nil, nil }
func (Ключ2) MarshalText() ([]byte, error)  { return nil, nil }

// printableASCII reports whether every byte of s is printable ASCII.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

func structField(name string, typ reflect.Type, tag string) reflect.Type {
	return reflect.StructOf([]reflect.StructField{{Name: name, Type: typ, Tag: reflect.StructTag(tag)}})
}

// lookAlikeTypes are Go types that the set refuses, whose refusal shows a name that is not ASCII:
// the type, a field, a tag name or a tag option.
func lookAlikeTypes() map[string]reflect.Type {
	accent := string(rune(0xC9)) + "cole"
	cyr := string(rune(0x0410)) + "ge"
	kelvin := string(rune(0x212A))
	e9 := string(rune(0xE9))
	return map[string]reflect.Type{
		"a field with no tag, a non-ASCII Go name":     structField(accent, reflect.TypeFor[int](), ``),
		"a field with no tag, a Cyrillic capital":      structField(cyr, reflect.TypeFor[int](), ``),
		"a field with no tag, the Kelvin sign":         structField(kelvin, reflect.TypeFor[int](), ``),
		"a field with no tag, above the BMP":           structField(string(rune(0x1D400)), reflect.TypeFor[int](), ``),
		"a tag name that is a look-alike":              structField("F", reflect.TypeFor[int](), "json:\"v"+string(rune(0x0435))+"rsion\""),
		"a tag name with an accent and a non-ASCII Go": structField(accent, reflect.TypeFor[int](), "json:\""+e9+"\""),
		"a tag name with an emoji":                     structField("F", reflect.TypeFor[int](), "json:\""+string(rune(0x1F600))+"\""),
		"a tag option that is not ASCII":               structField("F", reflect.TypeFor[int](), "json:\"a,"+e9+"\""),
		"a tag option on a field with a look-alike":    structField(accent, reflect.TypeFor[int](), `json:"a,string"`),
		"an embedded field with a non-ASCII name":      reflect.TypeFor[struct{ Ünit }](),
		"two fields of one name, a long non-ASCII tag": reflect.StructOf([]reflect.StructField{{Name: "A", Type: reflect.TypeFor[int](), Tag: `json:"x"`}, {Name: "B", Type: reflect.TypeFor[int](), Tag: `json:"x"`}}),
		"a float in a field of a type with a look-alike name": reflect.TypeFor[struct {
			Ünit float64 `json:"f"`
		}](),
		"a float in a struct whose field has a look-alike name and no tag": reflect.StructOf([]reflect.StructField{{Name: accent, Type: reflect.TypeFor[float64]()}}),
		"a type with a method, a non-ASCII name":                           reflect.TypeFor[Ünjson](),
		"an interface with a method, a non-ASCII name":                     reflect.TypeFor[Ünterface](),
		"a map key with a method, a non-ASCII name":                        reflect.TypeFor[map[Ключ2]int](),
		"a map with a key that is not a string, a non-ASCII value type":    reflect.TypeFor[map[int]Ünit](),
		"a pointer to a pointer, a non-ASCII name":                         reflect.TypeFor[**Ünit](),
		"a pointer to an interface, a non-ASCII name":                      reflect.TypeFor[*Ünterface](),
		"a float named by a non-ASCII type in a list":                      reflect.TypeFor[[]struct{ É float64 }](),
		"json.Number in a struct that has a non-ASCII name":                reflect.TypeFor[struct{ Ünit json.Number }](),
	}
}

// refusalTexts writes and reads the type in four places (alone, as a field, in a list, as a map
// value) and returns the text of each refusal, writing and reading.
func refusalTexts(typ reflect.Type) map[string]error {
	places := map[string]reflect.Type{
		"alone":       typ,
		"as a field":  structField("F", typ, `json:"f"`),
		"in a list":   structField("L", reflect.SliceOf(typ), `json:"l"`),
		"a map value": reflect.MapOf(reflect.TypeFor[string](), typ),
		"in an array": structField("A", reflect.ArrayOf(1, typ), `json:"a"`),
		"behind a *":  structField("P", reflect.PointerTo(typ), `json:"p"`),
	}
	out := map[string]error{}
	for name, p := range places {
		_, out[name+", writing"] = Marshal(reflect.New(p).Elem().Interface())
		out[name+", reading"] = strictjson.Unmarshal([]byte(`{}`), reflect.New(p).Interface(), strictjson.Options{})
	}
	return out
}

func TestNoRefusalOfATypeShowsACharacterOutsidePrintableASCII(t *testing.T) {
	for name, typ := range lookAlikeTypes() {
		t.Run(name, func(t *testing.T) {
			for place, err := range refusalTexts(typ) {
				if err == nil {
					t.Errorf("%s: accepted", place)
					continue
				}
				if !printableASCII(err.Error()) {
					t.Errorf("%s: the text holds a byte that is not printable ASCII: %q", place, err)
				}
			}
		})
	}
}

// The top of a document, and the array that does not fit, name a type: with a look-alike in its name
// they show it as an escape.
func TestTheTopOfADocumentAndAnArrayShowTheirTypeAsEscapes(t *testing.T) {
	var n Ñumber
	_, err := Marshal(n)
	if want := "malformed JSON: $: a value of type canonjson." + qesc(0xD1) + "umber cannot be written: the top of a document is one JSON object, which a struct, a map, a Raw, or a pointer or an interface that holds one, writes"; err == nil || err.Error() != want {
		t.Errorf("writing: %v\nwant %s", err, want)
	}
	_, err = Marshal(&n)
	if err == nil || !printableASCII(err.Error()) {
		t.Errorf("writing a pointer: %v", err)
	}
	err = strictjson.Unmarshal([]byte(`{}`), &n, strictjson.Options{})
	if want := "malformed JSON: $: a value of type canonjson." + qesc(0xD1) + "umber cannot be read: the top of a document is one JSON object, which fills a struct, a map, a Raw or an interface with no methods"; err == nil || err.Error() != want {
		t.Errorf("reading: %v\nwant %s", err, want)
	}
	var h struct{ A Ӆist }
	err = strictjson.Unmarshal([]byte(`{"A":[1]}`), &h, strictjson.Options{})
	if want := "malformed JSON: $.A: the list has 1 element, and the array of type canonjson." + qesc(0x04C5) + "ist holds exactly 2"; err == nil || err.Error() != want {
		t.Errorf("an array: %v\nwant %s", err, want)
	}
	// A non-ASCII type that the document fits is read and written without a word.
	var ok struct{ A Ӆist }
	if err := strictjson.Unmarshal([]byte(`{"A":[1,2]}`), &ok, strictjson.Options{}); err != nil || ok.A != (Ӆist{1, 2}) {
		t.Errorf("%v, %v", ok, err)
	}
	if doc, err := Marshal(ok); err != nil || string(doc) != `{"A":[1,2]}` {
		t.Errorf("%q, %v", doc, err)
	}
}

// The errors about a document, with look-alike names in the path, hold no byte outside printable
// ASCII either.
func TestNoRefusalOfADocumentShowsACharacterOutsidePrintableASCII(t *testing.T) {
	kelvin, e9, emoji := string(rune(0x212A)), string(rune(0xE9)), string(rune(0x1F600))
	type holder struct {
		K int            `json:"k"`
		M map[string]int `json:"m"`
		L []struct {
			X int `json:"x"`
		} `json:"l"`
		R strictjson.Raw `json:"r"`
	}
	docs := []string{
		`{"` + kelvin + `":1}`,                             // folds to k
		`{"m":{"` + e9 + `":"x"}}`,                         // a string for an integer, at a member of a map
		`{"m":{"` + emoji + `":1,"` + emoji + `":2}}`,      // repeated, the same emoji
		`{"l":[{"x":1,"` + e9 + `":2}]}`,                   // unknown member, inside a list
		`{"` + e9 + `":1}`,                                 // unknown member
		`{"r":{"` + e9 + `":1,"` + e9 + `":2}}`,            // repeated in a Raw
		`{"r":{"` + e9 + `":1.5}}`,                         // a float in a Raw
		`{"r":{"` + e9 + `":null}}`,                        // null in a Raw
		`{"m":{"` + string(rune(0x1D400)) + `":null}}`,     // null
		`{"m":{"` + kelvin + `":9223372036854775808}}`,     // too large
		`{"m":{"` + kelvin + `":1.5}}`,                     // a fraction
		`{"m":{"a` + string([]byte{0xff}) + `b":1}}`,       // not UTF-8
		`{"l":[{"x":"` + e9 + `"}]}`,                       // a string for an integer
		`{"l":[{"x":1},{"x":[1]},{"` + kelvin + `":[2]}]}`, // a list for an integer, then a look-alike
		`{"k":1,"` + strings.Repeat(e9, 30) + `":1}`,       // a long name, cut
		`{"k":1,"` + strings.Repeat("n", 50) + e9 + `":1}`, // a long ASCII name with a look-alike at the end
	}
	for _, doc := range docs {
		var h holder
		err := strictjson.Unmarshal([]byte(doc), &h, strictjson.Options{})
		if err == nil {
			t.Errorf("%s: read", doc)
			continue
		}
		if !printableASCII(err.Error()) {
			t.Errorf("%s: the text holds a byte that is not printable ASCII: %q", doc, err)
		}
		var m map[string]any
		if err := strictjson.Unmarshal([]byte(doc), &m, strictjson.Options{}); err != nil && !printableASCII(err.Error()) {
			t.Errorf("%s: into a map: %q", doc, err)
		}
		if _, err := Canonicalize([]byte(doc)); err != nil && !printableASCII(err.Error()) {
			t.Errorf("%s: Canonicalize: %q", doc, err)
		}
	}
	// The writer's own refusals for a value: a key that is not UTF-8, a float behind a look-alike key, a nil value.
	values := []any{
		map[string]any{"a" + string([]byte{0xff}) + "b": 1},
		map[string]any{e9: 1.5},
		map[string]any{kelvin: map[string]any{emoji: 1.5}},
		map[string]any{kelvin: []any{1, 1.5}},
		map[string]any{e9: strictjson.Raw(`{"` + e9 + `":1,"` + e9 + `":2}`)},
		map[string]*int{kelvin: nil},
		map[string][]int{e9: nil},
		map[string]string{kelvin: "a" + string([]byte{0xff})},
		map[string]uint64{emoji: 1 << 63},
		struct {
			A map[string]any `json:"a"`
		}{A: map[string]any{kelvin: 1.5}},
	}
	for i, v := range values {
		doc, err := Marshal(v)
		if err == nil {
			t.Errorf("value %d was written: %s", i, doc)
			continue
		}
		if !printableASCII(err.Error()) {
			t.Errorf("value %d: the text holds a byte that is not printable ASCII: %q", i, err)
		}
	}
}

// The refusals that only a value gives (a nil map, a nil slice, a nil pointer or interface, an integer
// above int64) name the type of the value: with a look-alike in its name, as an escape.
func TestTheRefusalOfAValueShowsItsTypeAsEscapes(t *testing.T) {
	type holder struct {
		M Карта      `json:"m"`
		L Список     `json:"l"`
		P *Ünit      `json:"p"`
		I Ünterface0 `json:"i"`
		U Ünsigned   `json:"u"`
	}
	good := holder{M: Карта{}, L: Список{}, P: &Ünit{}, I: 1, U: 1}
	if _, err := Marshal(good); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*holder)
		want   string
	}{
		{"a nil map", func(h *holder) { h.M = nil }, "malformed JSON: $.m: a value of type canonjson." + qesc(0x041A) + qesc(0x0430) + qesc(0x0440) + qesc(0x0442) + qesc(0x0430) + " cannot be written: a nil map is JSON null"},
		{"a nil slice", func(h *holder) { h.L = nil }, "malformed JSON: $.l: a value of type canonjson." + qesc(0x0421) + qesc(0x043F) + qesc(0x0438) + qesc(0x0441) + qesc(0x043E) + qesc(0x043A) + " cannot be written: a nil slice is JSON null"},
		{"a nil pointer", func(h *holder) { h.P = nil }, "malformed JSON: $.p: a value of type *canonjson." + qesc(0xDC) + "nit cannot be written: a nil pointer is JSON null"},
		{"a nil interface", func(h *holder) { h.I = nil }, "malformed JSON: $.i: a value of type canonjson." + qesc(0xDC) + "nterface0 cannot be written: a nil interface is JSON null"},
		{"an integer above int64", func(h *holder) { h.U = 1 << 63 }, "malformed JSON: $.u: a value of type canonjson." + qesc(0xDC) + "nsigned cannot be written: an integer above 9223372036854775807, which ritueel's JSON does not hold"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := good
			tc.mutate(&h)
			got, err := Marshal(h)
			refused(t, got, err, tc.want)
		})
	}
}
