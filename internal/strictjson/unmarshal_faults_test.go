package strictjson

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// The seven faults that the standard decoder has and that this reader exists to not have. Each
// is pinned as a refusal with its exact text, or as a defined result.

// fail checks one refusal of Unmarshal: the error wraps ErrMalformed and has the text, and the
// value that was passed in is as it was.
func fail(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Unmarshal accepted the document, want the refusal %q", want)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("the error does not wrap ErrMalformed: %v", err)
	}
	if err.Error() != want {
		t.Errorf("the error is\n  %q\nwant\n  %q", err, want)
	}
}

func mal(path, what string) string { return fmt.Sprintf("%s: %s: %s", ErrMalformed, path, what) }

// byteAfter is " at byte N" for the position just after the first occurrence of token in doc.
func byteAfter(doc, token string) string {
	return fmt.Sprintf(" at byte %d", strings.Index(doc, token)+len(token))
}

const notBase64 = "not the one canonical spelling of Base64: standard alphabet, padding, zero padding bits, no line break"

// ---- 1. a slice of bytes is one canonical string of Base64 --------------------------------

func TestBytesTakeOnlyCanonicalBase64(t *testing.T) {
	type doc struct {
		B []byte `json:"b"`
	}
	read := func(in string) ([]byte, error) {
		var d doc
		err := Unmarshal([]byte(`{"b":`+in+`}`), &d, Options{})
		return d.B, err
	}
	t.Run("the canonical spelling of every length is read", func(t *testing.T) {
		r := rand.New(rand.NewSource(4648))
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		// The encoding is written here by RFC 4648, not by encoding/base64, so that the test is
		// its own witness.
		encode := func(b []byte) string {
			var out strings.Builder
			for i := 0; i < len(b); i += 3 {
				var n uint32
				chunk := b[i:min(i+3, len(b))]
				for j := range 3 {
					n <<= 8
					if j < len(chunk) {
						n |= uint32(chunk[j])
					}
				}
				for j := range 4 {
					if j <= len(chunk) {
						out.WriteByte(alphabet[n>>(18-6*uint(j))&63])
					} else {
						out.WriteByte('=')
					}
				}
			}
			return out.String()
		}
		for n := range 40 {
			for range 5 {
				b := make([]byte, n)
				r.Read(b)
				got, err := read(`"` + encode(b) + `"`)
				if err != nil || string(got) != string(b) || got == nil {
					t.Fatalf("%x: %q gave %x, %v", b, encode(b), got, err)
				}
			}
		}
	})
	t.Run("the edges of the alphabet", func(t *testing.T) {
		for in, want := range map[string][]byte{
			`""`:         {},
			`"AAAA"`:     {0, 0, 0},
			`"////"`:     {255, 255, 255},
			`"++++"`:     {0xfb, 0xef, 0xbe},
			`"/w=="`:     {255},
			`"//8="`:     {255, 255},
			`"YQ=="`:     []byte("a"),
			`"YWI="`:     []byte("ab"),
			`"YWJj"`:     []byte("abc"),
			`"YWJjZA=="`: []byte("abcd"),
		} {
			got, err := read(in)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("%s: %x, %v; want %x", in, got, err, want)
			}
		}
	})
	t.Run("a refused spelling, by what is wrong", func(t *testing.T) {
		for _, tc := range []struct{ name, in string }{
			{"padding bits that are not zero, two characters", `"AB=="`},
			{"padding bits that are not zero, two characters, the last letter", `"AR=="`},
			{"padding bits that are not zero, three characters", `"AAB="`},
			{"padding bits that are not zero, in a longer string", `"aGl="`},
			{"the padding left off, one byte", `"AA"`},
			{"the padding left off, two bytes", `"AAA"`},
			{"one padding character short, one byte", `"AA="`},
			{"one padding character short, three bytes", `"AAAAAA="`},
			{"one padding character too many", `"AAA=="`},
			{"a lone character", `"A"`},
			{"a lone padding character", `"="`},
			{"only padding", `"===="`},
			{"padding at the start", `"==AA"`},
			{"padding in the middle", `"AA==AA=="`},
			{"a lone character and padding", `"A==="`},
			{"five characters", `"AAAAA"`},
			{"the URL alphabet, one byte", `"_w=="`},
			{"the URL alphabet, a minus", `"-w=="`},
			{"the URL alphabet, three bytes", `"-_-_"`},
			{"the URL alphabet without padding", `"AA"`},
			{"a line feed in the middle", `"AA` + bs + `n=="`},
			{"a line feed at the end", `"AA==` + bs + `n"`},
			{"a carriage return and a line feed", `"AAAA` + bs + `r` + bs + `nAAAA"`},
			{"a space in the middle", `"AA =="`},
			{"a space at the start", `" AA=="`},
			{"a space at the end", `"AA== "`},
			{"a tab", `"AA` + bs + `t=="`},
			{"a character outside the alphabet", `"AA!="`},
			{"a character outside ASCII", `"` + string(rune(0xe9)) + `A=="`},
			{"a NUL", `"AA` + uesc(0) + `=="`},
			{"a line break every 76 characters, as MIME writes it", `"` + strings.Repeat("A", 76) + bs + "n" + strings.Repeat("A", 4) + `"`},
		} {
			got, err := read(tc.in)
			if err == nil {
				t.Errorf("%s: %s gave %x", tc.name, tc.in, got)
				continue
			}
			fail(t, err, mal("$.b", notBase64))
		}
	})
	t.Run("every second-last and third-last character is checked for its zero bits", func(t *testing.T) {
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		for i, c := range alphabet {
			// "AA?=": the last character holds two bits of the byte and four bits of padding... a
			// character of the alphabet has the value i, and the low two bits must be zero.
			_, err := read(`"AA` + string(c) + `="`)
			if (err == nil) != (i%4 == 0) {
				t.Errorf("AA%c=: error %v, but the low two bits of %d are %d", c, err, i, i%4)
			}
			// "A?==": the low four bits must be zero.
			_, err = read(`"A` + string(c) + `=="`)
			if (err == nil) != (i%16 == 0) {
				t.Errorf("A%c==: error %v, but the low four bits of %d are %d", c, err, i, i%16)
			}
		}
	})
	t.Run("what is not a string", func(t *testing.T) {
		for _, tc := range []struct{ in, what string }{
			{`[1,2,3]`, "a list"},
			{`[]`, "a list"},
			{`1`, "an integer"},
			{`true`, "true or false"},
			{`{}`, "an object"},
			{`{"a":"AA=="}`, "an object"},
		} {
			_, err := read(tc.in)
			fail(t, err, mal("$.b", "expected a string of standard Base64, for a slice of bytes, found "+tc.what))
		}
	})
	t.Run("the same in a list, a map and a named type", func(t *testing.T) {
		var l struct{ L [][]byte }
		fail(t, Unmarshal([]byte(`{"L":["AA==","AB=="]}`), &l, Options{}), mal("$.L[1]", notBase64))
		var m map[string][]byte
		fail(t, Unmarshal([]byte(`{"k":"AA"}`), &m, Options{}), mal("$.k", notBase64))
		var n struct{ B myBytes }
		fail(t, Unmarshal([]byte(`{"B":"AA"}`), &n, Options{}), mal("$.B", notBase64))
		var o struct{ B []myByte }
		fail(t, Unmarshal([]byte(`{"B":[1,2]}`), &o, Options{}), mal("$.B", "expected a string of standard Base64, for a slice of bytes, found a list"))
	})
	t.Run("an array of bytes and a slice of other integers are lists, not Base64", func(t *testing.T) {
		var a struct{ A [3]byte }
		fail(t, Unmarshal([]byte(`{"A":"AAAA"}`), &a, Options{}), mal("$.A", "expected a list, found a string"))
		var s struct{ S []int8 }
		fail(t, Unmarshal([]byte(`{"S":"AAAA"}`), &s, Options{}), mal("$.S", "expected a list, found a string"))
		var u struct{ S []uint16 }
		fail(t, Unmarshal([]byte(`{"S":"AAAA"}`), &u, Options{}), mal("$.S", "expected a list, found a string"))
	})
	t.Run("the bytes are a copy, not part of the document", func(t *testing.T) {
		data := []byte(`{"b":"aGk="}`)
		var d doc
		if err := Unmarshal(data, &d, Options{}); err != nil {
			t.Fatal(err)
		}
		for i := range data {
			data[i] = 'x'
		}
		if string(d.B) != "hi" {
			t.Errorf("the value followed the document: %q", d.B)
		}
	})
}

// ---- 2. an array takes exactly its length -------------------------------------------------

func TestAnArrayTakesExactlyItsLength(t *testing.T) {
	long := func(typ string, n, want int) string {
		return fmt.Sprintf("the list has %d elements, and the array of type %s holds exactly %d", n, typ, want)
	}
	t.Run("the right length", func(t *testing.T) {
		var v struct {
			A [3]int
			E [0]int
			N [2][2]string
			B [2]bool
		}
		if err := Unmarshal([]byte(`{"A":[1,2,3],"E":[],"N":[["a","b"],["c","d"]],"B":[true,false]}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if v.A != [3]int{1, 2, 3} || v.N != [2][2]string{{"a", "b"}, {"c", "d"}} || v.B != [2]bool{true, false} {
			t.Errorf("v = %+v", v)
		}
	})
	t.Run("longer", func(t *testing.T) {
		var v struct{ A [3]int }
		fail(t, Unmarshal([]byte(`{"A":[1,2,3,4]}`), &v, Options{}), mal("$.A", long("[3]int", 4, 3)))
		fail(t, Unmarshal([]byte(`{"A":[1,2,3,0,0,0,0,0,0,0,0,0,0]}`), &v, Options{}), mal("$.A", long("[3]int", 13, 3)))
	})
	t.Run("shorter", func(t *testing.T) {
		var v struct{ A [3]int }
		fail(t, Unmarshal([]byte(`{"A":[1,2]}`), &v, Options{}), mal("$.A", long("[3]int", 2, 3)))
		fail(t, Unmarshal([]byte(`{"A":[1]}`), &v, Options{}), mal("$.A", long("[3]int", 1, 3)))
		fail(t, Unmarshal([]byte(`{"A":[]}`), &v, Options{}), mal("$.A", long("[3]int", 0, 3)))
	})
	t.Run("a shorter list is not padded with zero and a longer is not cut", func(t *testing.T) {
		v := struct{ A [3]int }{A: [3]int{7, 8, 9}}
		before := v
		for _, in := range []string{`{"A":[1,2]}`, `{"A":[1,2,3,4]}`} {
			if err := Unmarshal([]byte(in), &v, Options{}); err == nil {
				t.Errorf("%s was read", in)
			}
			if v != before {
				t.Errorf("%s: the value changed to %v", in, v)
			}
		}
	})
	t.Run("an array of length zero", func(t *testing.T) {
		var v struct{ E [0]int }
		fail(t, Unmarshal([]byte(`{"E":[1]}`), &v, Options{}), mal("$.E", long("[0]int", 1, 0)))
	})
	t.Run("an array inside an array, in a list and in a map, shows its path", func(t *testing.T) {
		var a struct{ N [2][2]int }
		fail(t, Unmarshal([]byte(`{"N":[[1,2],[3]]}`), &a, Options{}), mal("$.N[1]", long("[2]int", 1, 2)))
		var l struct{ L [][2]int }
		fail(t, Unmarshal([]byte(`{"L":[[1,2],[3,4],[5,6,7]]}`), &l, Options{}), mal("$.L[2]", long("[2]int", 3, 2)))
		var m map[string][2]int
		fail(t, Unmarshal([]byte(`{"k":[1,2],"j":[1]}`), &m, Options{}), mal("$.j", long("[2]int", 1, 2)))
	})
	t.Run("the standard decoder cuts a long list and fills a short one with zero", func(t *testing.T) {
		// What this reader does not do, shown by what the standard decoder does with the same text.
		for _, in := range []string{`{"A":[1,2,3,4]}`, `{"A":[1]}`} {
			var std, ours struct{ A [3]int }
			if err := unmarshalStd([]byte(in), &std); err != nil {
				t.Fatalf("the standard decoder refused %s: %v", in, err)
			}
			if err := Unmarshal([]byte(in), &ours, Options{}); err == nil {
				t.Errorf("%s: this reader accepted a list of the wrong length: %v", in, ours)
			}
		}
	})
	t.Run("an element that is wrong in a list of the right length", func(t *testing.T) {
		var v struct{ A [3]uint8 }
		fail(t, Unmarshal([]byte(`{"A":[1,2,256]}`), &v, Options{}), mal("$.A[2]", "the integer 256 does not fit the type uint8"))
		fail(t, Unmarshal([]byte(`{"A":[1,-1,3]}`), &v, Options{}), mal("$.A[1]", "the integer -1 does not fit the type uint8"))
	})
}

// ---- 3. no float, in the type and in the document -----------------------------------------

func TestNoFloatAnywhere(t *testing.T) {
	const wantFraction = "a number with a fraction or an exponent"
	numbers := []string{"1.0", "1.5", "-0.0", "0.0", "-1.5", "1e2", "1E2", "1e+2", "1e-2", "0e0", "1.5e3", "1.7976931348623157e308", "5e-324", "123456789.123456789", "0.1", "1e400"}
	t.Run("a number with a fraction or an exponent in every kind of place", func(t *testing.T) {
		for _, n := range numbers {
			for _, tc := range []struct {
				name string
				doc  string
				v    any
				path string
			}{
				{"an integer field", `{"a":` + n + `}`, &struct {
					A int `json:"a"`
				}{}, "$.a"},
				{"a field of any", `{"a":` + n + `}`, &struct {
					A any `json:"a"`
				}{}, "$.a"},
				{"a member nobody knows", `{"a":` + n + `}`, &struct{}{}, "$.a"},
				{"a list of any", `{"a":[1,` + n + `]}`, &struct {
					A []any `json:"a"`
				}{}, "$.a[1]"},
				{"a map of integers", `{"k":` + n + `}`, &map[string]int{}, "$.k"},
				{"the top, an interface", `{"k":{"j":` + n + `}}`, new(any), "$.k.j"},
				{"inside a Raw", `{"r":{"x":[` + n + `]}}`, &struct {
					R Raw `json:"r"`
				}{}, "$.r.x[0]"},
				{"an unsigned field", `{"a":` + n + `}`, &struct {
					A uint8 `json:"a"`
				}{}, "$.a"},
			} {
				err := Unmarshal([]byte(tc.doc), tc.v, Options{AllowUnknown: true})
				fail(t, err, mal(tc.path, wantFraction+byteAfter(tc.doc, n)))
				if t.Failed() {
					t.Fatalf("%s with %s", tc.name, n)
				}
			}
		}
	})
	t.Run("an integer is never read through a float", func(t *testing.T) {
		// 2^53+1 is the first integer that a float cannot hold; it is read exactly.
		var v struct {
			N int64 `json:"n"`
			A any   `json:"a"`
		}
		if err := Unmarshal([]byte(`{"n":9007199254740993,"a":9007199254740993}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if v.N != 9007199254740993 || v.A != int64(9007199254740993) {
			t.Errorf("the integer was rounded: %v %v", v.N, v.A)
		}
		// The largest and the smallest int64 are read exactly in any.
		if err := Unmarshal([]byte(`{"n":-9223372036854775808,"a":9223372036854775807}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if v.N != -9223372036854775808 || v.A != int64(9223372036854775807) {
			t.Errorf("v = %+v", v)
		}
	})
	t.Run("no Go type with a float is read, whatever the document says", func(t *testing.T) {
		for _, doc := range []string{`{}`, `{"F":1}`, `{"F":1.5}`, `{"F":"x"}`, `not json`} {
			var v struct{ F float64 }
			fail(t, Unmarshal([]byte(doc), &v, Options{}), cannotRead("$.F", nil, "float64", reasonFloat))
			var w struct{ F float32 }
			fail(t, Unmarshal([]byte(doc), &w, Options{AllowUnknown: true}), cannotRead("$.F", nil, "float32", reasonFloat))
		}
	})
	t.Run("an integer that is too long for any integer", func(t *testing.T) {
		for _, n := range []string{"9223372036854775808", "-9223372036854775809", "18446744073709551615", "18446744073709551616", "99999999999999999999999999999999", "-" + strings.Repeat("9", 400)} {
			for _, tc := range []struct {
				name string
				v    any
			}{
				{"int64", &struct {
					A int64 `json:"a"`
				}{}},
				{"uint64", &struct {
					A uint64 `json:"a"`
				}{}},
				{"any", &struct {
					A any `json:"a"`
				}{}},
				{"an unknown member", &struct{}{}},
			} {
				doc := `{"a":` + n + `}`
				fail(t, Unmarshal([]byte(doc), tc.v, Options{AllowUnknown: true}), mal("$.a", "the integer does not fit 64 bits"+byteAfter(doc, n)))
			}
		}
	})
}

// ---- 4. the tag option string is not honoured --------------------------------------------

func TestTheTagOptionStringIsRefusedAsAType(t *testing.T) {
	const reason = `field F has the tag option "string"; only omitempty is allowed`
	t.Run("whatever the document", func(t *testing.T) {
		for _, doc := range []string{`{"F":12}`, `{"F":"12"}`, `{"f":"12"}`, `{}`, `[]`, `x`, ``} {
			for _, tc := range []struct {
				name string
				v    any
				typ  string
			}{
				{"after no name", &optString{}, "strictjson.optString"},
				{"after a name", &optNamedString{}, "strictjson.optNamedString"},
				{"after omitempty", &optSecond{}, "strictjson.optSecond"},
			} {
				fail(t, Unmarshal([]byte(doc), tc.v, Options{AllowUnknown: true}), cannotRead("$", nil, tc.typ, reason))
			}
		}
	})
	t.Run("the standard decoder reads a string as an integer for that tag", func(t *testing.T) {
		var std optString
		if err := unmarshalStd([]byte(`{"F":"12"}`), &std); err != nil || std.F != 12 {
			t.Fatalf("the standard decoder: %v, %v", std, err)
		}
		var ours optString
		if err := Unmarshal([]byte(`{"F":"12"}`), &ours, Options{}); err == nil || ours.F != 0 {
			t.Errorf("this reader: %v, %v", ours, err)
		}
	})
	t.Run("deep in a type, in a list and in a map", func(t *testing.T) {
		var a struct{ X struct{ Y optString } }
		fail(t, Unmarshal([]byte(`{}`), &a, Options{}), cannotRead("$.X.Y", nil, "strictjson.optString", reason))
		var l struct{ L []optNamedString }
		fail(t, Unmarshal([]byte(`{}`), &l, Options{}), cannotRead("$.L", []string{"[]"}, "strictjson.optNamedString", reason))
		var m map[string]optString
		fail(t, Unmarshal([]byte(`{}`), &m, Options{}), cannotRead("$", []string{"{}"}, "strictjson.optString", reason))
	})
	t.Run("a field that is not read for its tag is not looked at", func(t *testing.T) {
		// A field left out by its name and one that is not exported are not looked at, so an option
		// on them is nothing. (A struct that go vet would not pass, so it is built here.)
		typ := reflect.StructOf([]reflect.StructField{
			{Name: "A", Type: reflect.TypeFor[int](), Tag: `json:"-"`},
			{Name: "b", PkgPath: "strictjson", Type: reflect.TypeFor[int](), Tag: `json:",string"`},
			{Name: "C", Type: reflect.TypeFor[int](), Tag: `json:"c"`},
			{Name: "D", Type: reflect.TypeFor[int](), Tag: `json:"-,omitempty"`},
		})
		v := reflect.New(typ)
		if err := Unmarshal([]byte(`{"c":3,"-":4}`), v.Interface(), Options{}); err != nil || v.Elem().Field(2).Int() != 3 || v.Elem().Field(3).Int() != 4 {
			t.Errorf("%+v, %v", v.Elem(), err)
		}
	})
}

// ---- 5. a map with integer keys is refused as a type -------------------------------------

func TestAMapWithIntegerKeysIsRefusedAsAType(t *testing.T) {
	cases := []struct {
		name string
		v    any
		typ  string
	}{
		{"int", &map[int]string{}, "map[int]string"},
		{"int64", &map[int64]string{}, "map[int64]string"},
		{"uint8", &map[uint8]bool{}, "map[uint8]bool"},
		{"uint64", &map[uint64]int{}, "map[uint64]int"},
		{"a named integer", &map[myInt]int{}, "map[strictjson.myInt]int"},
		{"bool", &map[bool]int{}, "map[bool]int"},
		{"float", &map[float64]int{}, "map[float64]int"},
		{"an interface", &map[any]int{}, "map[interface {}]int"},
		{"an array", &map[[2]int]int{}, "map[[2]int]int"},
		{"a struct", &map[point]int{}, "map[strictjson.point]int"},
		{"a pointer", &map[*int]int{}, "map[*int]int"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, doc := range []string{`{"1":"a"}`, `{"-1":"a"}`, `{}`, `{"a":1}`, `x`} {
				fail(t, Unmarshal([]byte(doc), tc.v, Options{AllowUnknown: true}), cannotRead("$", nil, tc.typ, reasonMapKey))
			}
		})
	}
	t.Run("in a field, a list and a map", func(t *testing.T) {
		var f struct{ M map[int]string }
		fail(t, Unmarshal([]byte(`{"M":{"1":"a"}}`), &f, Options{}), cannotRead("$.M", nil, "map[int]string", reasonMapKey))
		var l struct{ L []map[int]string }
		fail(t, Unmarshal([]byte(`{"L":[{"1":"a"}]}`), &l, Options{}), cannotRead("$.L", []string{"[]"}, "map[int]string", reasonMapKey))
		var m map[string]map[int]string
		fail(t, Unmarshal([]byte(`{"k":{"1":"a"}}`), &m, Options{}), cannotRead("$", []string{"{}"}, "map[int]string", reasonMapKey))
	})
	t.Run("the standard decoder reads the text of an integer key", func(t *testing.T) {
		var std map[int]string
		if err := unmarshalStd([]byte(`{"1":"a"}`), &std); err != nil || std[1] != "a" {
			t.Fatalf("the standard decoder: %v, %v", std, err)
		}
	})
	t.Run("a map with a named string key and a string key that looks like an integer are read", func(t *testing.T) {
		var m map[myKey]int
		if err := Unmarshal([]byte(`{"1":1,"-1":2,"":3}`), &m, Options{}); err != nil || !reflect.DeepEqual(m, map[myKey]int{"1": 1, "-1": 2, "": 3}) {
			t.Errorf("%v, %v", m, err)
		}
	})
}

// ---- 6. an interface is replaced, a member name is exact ----------------------------------

func TestAnInterfaceThatHoldsAValueIsReplacedNeverFilledInto(t *testing.T) {
	type holder struct {
		F any `json:"F"`
	}
	t.Run("what it held is not filled and not changed", func(t *testing.T) {
		oldMap := map[string]any{"old": int64(1)}
		oldList := []any{int64(1), int64(2)}
		oldPtr := &point{X: 9, Y: 9}
		oldPtrToMap := &map[string]int{"old": 1}
		oldMyMap := map[string]int{"old": 1}
		oldList2 := []int{1, 2, 3}
		for _, tc := range []struct {
			name string
			held any
			doc  string
			want any
		}{
			{"a map and an object", oldMap, `{"F":{"new":true}}`, map[string]any{"new": true}},
			{"a map and a list", oldMap, `{"F":[1]}`, []any{int64(1)}},
			{"a list and a list", oldList, `{"F":[7]}`, []any{int64(7)}},
			{"a list and an object", oldList, `{"F":{}}`, map[string]any{}},
			{"a pointer to a struct and an object", oldPtr, `{"F":{"X":1}}`, map[string]any{"X": int64(1)}},
			{"a pointer to a map and an object", oldPtrToMap, `{"F":{"new":1}}`, map[string]any{"new": int64(1)}},
			{"a map of a type other than the five", oldMyMap, `{"F":{"new":1}}`, map[string]any{"new": int64(1)}},
			{"a slice of a type other than the five", oldList2, `{"F":[9]}`, []any{int64(9)}},
			{"a struct value and an object", point{X: 9}, `{"F":{"X":1}}`, map[string]any{"X": int64(1)}},
			{"a string and an integer", "old", `{"F":5}`, int64(5)},
			{"an integer and a string", 5, `{"F":"s"}`, "s"},
			{"true and false", true, `{"F":false}`, false},
			{"a float and a string", 1.5, `{"F":"s"}`, "s"},
			{"nothing and an object", nil, `{"F":{"a":[]}}`, map[string]any{"a": []any{}}},
		} {
			h := holder{F: tc.held}
			if err := Unmarshal([]byte(tc.doc), &h, Options{}); err != nil {
				t.Errorf("%s: %v", tc.name, err)
				continue
			}
			if !reflect.DeepEqual(h.F, tc.want) {
				t.Errorf("%s: %#v, want %#v", tc.name, h.F, tc.want)
			}
		}
		if !reflect.DeepEqual(oldMap, map[string]any{"old": int64(1)}) {
			t.Errorf("the map that the interface held was changed: %v", oldMap)
		}
		if !reflect.DeepEqual(oldList, []any{int64(1), int64(2)}) {
			t.Errorf("the list that the interface held was changed: %v", oldList)
		}
		if *oldPtr != (point{X: 9, Y: 9}) {
			t.Errorf("the struct that the interface pointed to was filled: %+v", *oldPtr)
		}
		if !reflect.DeepEqual(*oldPtrToMap, map[string]int{"old": 1}) || !reflect.DeepEqual(oldMyMap, map[string]int{"old": 1}) {
			t.Errorf("a map that the interface held was changed: %v %v", *oldPtrToMap, oldMyMap)
		}
		if !reflect.DeepEqual(oldList2, []int{1, 2, 3}) {
			t.Errorf("a slice that the interface held was changed: %v", oldList2)
		}
	})
	t.Run("at the top, and in a map, a list and an array", func(t *testing.T) {
		pt := &point{X: 5}
		var top any = pt
		if err := Unmarshal([]byte(`{"X":1}`), &top, Options{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(top, map[string]any{"X": int64(1)}) || *pt != (point{X: 5}) {
			t.Errorf("top = %#v, pointee %+v", top, *pt)
		}
		m := map[string]any{"a": pt, "keep": "k"}
		if err := Unmarshal([]byte(`{"a":{"X":2}}`), &m, Options{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(m, map[string]any{"a": map[string]any{"X": int64(2)}}) || *pt != (point{X: 5}) {
			t.Errorf("m = %#v, pointee %+v", m, *pt)
		}
		l := struct{ L []any }{L: []any{pt, pt, pt}}
		if err := Unmarshal([]byte(`{"L":[{"X":3}]}`), &l, Options{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(l.L, []any{map[string]any{"X": int64(3)}}) || *pt != (point{X: 5}) {
			t.Errorf("l = %#v, pointee %+v", l.L, *pt)
		}
		a := struct{ A [2]any }{A: [2]any{pt, pt}}
		if err := Unmarshal([]byte(`{"A":[{"X":4},1]}`), &a, Options{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a.A, [2]any{map[string]any{"X": int64(4)}, int64(1)}) || *pt != (point{X: 5}) {
			t.Errorf("a = %#v, pointee %+v", a.A, *pt)
		}
	})
	t.Run("a member that is missing leaves the interface nil, not what it held", func(t *testing.T) {
		h := holder{F: map[string]any{"old": 1}}
		if err := Unmarshal([]byte(`{}`), &h, Options{}); err != nil || h.F != nil {
			t.Errorf("%#v, %v", h.F, err)
		}
	})
}

func TestAMemberNameThatDiffersOnlyByCaseIsRefused(t *testing.T) {
	type lower struct {
		A int `json:"a"`
	}
	type upper struct {
		Version int
	}
	kelvin, longS := string(rune(0x212A)), string(rune(0x17F))
	type folds struct {
		K int `json:"k"`
		S int `json:"s"`
	}
	for _, tc := range []struct {
		name string
		v    any
		doc  string
		want string // the path, and the name that it must be spelt
		path string
	}{
		{"a capital for a small letter", &lower{}, `{"A":1}`, "a", "$.A"},
		{"a small letter for a capital", &upper{}, `{"version":1}`, "Version", "$.version"},
		{"in the middle", &upper{}, `{"VERSION":1}`, "Version", "$.VERSION"},
		{"written with an escape", &lower{}, `{"` + uesc('A') + `":1}`, "a", "$.A"},
		{"after the right one", &lower{}, `{"a":1,"A":2}`, "a", "$.A"},
		{"before the right one", &lower{}, `{"A":2,"a":1}`, "a", "$.A"},
		{"in a nested struct", &struct {
			N lower `json:"n"`
		}{}, `{"n":{"A":1}}`, "a", "$.n.A"},
		{"in a list", &struct {
			L []lower `json:"l"`
		}{}, `{"l":[{"a":1},{"A":1}]}`, "a", "$.l[1].A"},
		{"in a map of structs", &map[string]lower{}, `{"k":{"A":1}}`, "a", "$.k.A"},
		{"behind a pointer", &struct {
			P *lower `json:"p"`
		}{}, `{"p":{"A":1}}`, "a", "$.p.A"},
		{"the Kelvin sign for k", &folds{}, `{"` + kelvin + `":1}`, "k", "$." + kelvin},
		{"the long s for s", &folds{}, `{"` + longS + `":1}`, "s", "$." + longS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, opts := range []Options{{}, {AllowUnknown: true}} {
				err := Unmarshal([]byte(tc.doc), tc.v, opts)
				fail(t, err, mal(tc.path, "the member must be spelt "+tc.want))
			}
		})
	}
	t.Run("the same name in two cases is two members of a map", func(t *testing.T) {
		var m map[string]int
		if err := Unmarshal([]byte(`{"a":1,"A":2}`), &m, Options{}); err != nil || len(m) != 2 {
			t.Errorf("%v, %v", m, err)
		}
	})
	t.Run("two fields whose names differ only by case read the member that matches exactly", func(t *testing.T) {
		type pair struct {
			Lower int `json:"a"`
			Upper int `json:"A"`
		}
		var p pair
		if err := Unmarshal([]byte(`{"A":2,"a":1}`), &p, Options{}); err != nil || p != (pair{Lower: 1, Upper: 2}) {
			t.Errorf("%+v, %v", p, err)
		}
		// A name that is a third case is refused, and the refusal names one of the two.
		err := Unmarshal([]byte(`{"a":1,"`+uesc(0x41)+`":2}`), &p, Options{})
		if err != nil {
			t.Errorf("an escaped capital A is the name A: %v", err)
		}
	})
	t.Run("a name that folds to two fields is refused, naming one of them", func(t *testing.T) {
		type twoK struct {
			Lower int `json:"k"`
			Upper int `json:"K"`
		}
		var v twoK
		err := Unmarshal([]byte(`{"`+kelvin+`":1}`), &v, Options{})
		lower, upper := mal("$."+kelvin, "the member must be spelt k"), mal("$."+kelvin, "the member must be spelt K")
		if !errors.Is(err, ErrMalformed) || (err.Error() != lower && err.Error() != upper) {
			t.Errorf("%v", err)
		}
	})
	t.Run("a field that is left out is not a name that a member may fold into", func(t *testing.T) {
		type skipped struct {
			Hidden string `json:"-"`
			a      string
			Shown  string `json:"shown"`
		}
		var v skipped
		for _, doc := range []string{`{"hidden":"x"}`, `{"Hidden":"x"}`, `{"a":"x"}`, `{"A":"x"}`} {
			err := Unmarshal([]byte(doc), &v, Options{})
			name := strings.Trim(strings.Split(doc, ":")[0], `{"`)
			fail(t, err, mal("$."+name, "unknown member"))
			if err := Unmarshal([]byte(doc), &v, Options{AllowUnknown: true}); err != nil {
				t.Errorf("%s with AllowUnknown: %v", doc, err)
			}
		}
		_ = v.a
	})
}
