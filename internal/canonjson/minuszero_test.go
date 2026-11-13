package canonjson

import (
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// -0 is the integer zero. Canonicalize writes it 0 wherever it meets it, so a document with -0 is not
// canonical (IsCanonical is false for it and true for what Canonicalize makes of it), and Marshal
// never writes -0: it has no negative zero to write.

func TestCanonicalizeWritesMinusZeroAsZeroEverywhere(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"a member of the top object", `{"a":-0}`, `{"a":0}`},
		{"two members", `{"a":-0,"b":-0}`, `{"a":0,"b":0}`},
		{"a member of a nested object", `{"a":{"b":-0}}`, `{"a":{"b":0}}`},
		{"deep in nested objects", `{"a":{"b":{"c":{"d":-0}}}}`, `{"a":{"b":{"c":{"d":0}}}}`},
		{"an element of a list", `{"a":[-0]}`, `{"a":[0]}`},
		{"every element of a list", `{"a":[-0,-0,-0]}`, `{"a":[0,0,0]}`},
		{"among other integers", `{"a":[1,-0,-1,0,10,-10,-0]}`, `{"a":[1,0,-1,0,10,-10,0]}`},
		{"a list in a list", `{"a":[[-0],[[-0]]]}`, `{"a":[[0],[[0]]]}`},
		{"an object in a list", `{"a":[{"b":-0}]}`, `{"a":[{"b":0}]}`},
		{"a list in an object in a list", `{"a":[{"b":[-0,{"c":-0}]}]}`, `{"a":[{"b":[0,{"c":0}]}]}`},
		{"white space around it", " {\n\t\"a\" :\r\n -0 \n}", `{"a":0}`},
		{"in the middle of an object that is sorted", `{"z":-0,"a":-0,"m":-0}`, `{"a":0,"m":0,"z":0}`},
		{"next to a member whose name is -0", `{"-0":-0}`, `{"-0":0}`},
		{"a name that holds -0 is a name", `{"a-0":1,"-0b":-0}`, `{"-0b":0,"a-0":1}`},
		{"a string that holds -0 is a string", `{"a":"-0","b":-0}`, `{"a":"-0","b":0}`},
		{"a string with an escape and -0", `{"a":"x\n-0","b":[-0]}`, `{"a":"x\n-0","b":[0]}`},
		{"with minus zero and every other kind of value", `{"a":-0,"b":"s","c":true,"d":false,"e":[],"f":{},"g":9223372036854775807,"h":-9223372036854775808}`, `{"a":0,"b":"s","c":true,"d":false,"e":[],"f":{},"g":9223372036854775807,"h":-9223372036854775808}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tc.in))
			if err != nil || string(got) != tc.want {
				t.Fatalf("Canonicalize = %q, %v; want %q", got, err, tc.want)
			}
			if len(got) >= len(tc.in) && tc.in != tc.want {
				t.Errorf("the result is not shorter than the input: %d and %d", len(got), len(tc.in))
			}
			if ok, err := IsCanonical([]byte(tc.in)); err != nil || ok {
				t.Errorf("IsCanonical(%q) = %v, %v; a document with -0 is not canonical", tc.in, ok, err)
			}
			if ok, err := IsCanonical(got); err != nil || !ok {
				t.Errorf("IsCanonical(%q) = %v, %v; want true", got, ok, err)
			}
			again, err := Canonicalize(got)
			if err != nil || string(again) != string(got) {
				t.Errorf("not a fixed point: %q, %v", again, err)
			}
		})
	}
}

func TestADocumentWithoutMinusZeroThatIsCanonicalStaysCanonical(t *testing.T) {
	for _, in := range []string{`{"a":0}`, `{"a":[0,-1,10]}`, `{"a":"-0"}`, `{"-0":1}`, `{"a":-1}`, `{"a":10,"b":-10}`} {
		if ok, err := IsCanonical([]byte(in)); err != nil || !ok {
			t.Errorf("IsCanonical(%s) = %v, %v", in, ok, err)
		}
	}
}

func TestMinusZeroInARawIsWrittenZero(t *testing.T) {
	type doc struct {
		R Raw `json:"r"`
	}
	got, err := Marshal(doc{R: Raw(`{"a":-0,"b":[-0,{"c":-0}]}`)})
	if want := `{"r":{"a":0,"b":[0,{"c":0}]}}`; err != nil || string(got) != want {
		t.Errorf("%q, %v; want %s", got, err, want)
	}
	got, err = Marshal(Raw(` { "x" : -0 } `))
	if want := `{"x":0}`; err != nil || string(got) != want {
		t.Errorf("a Raw at the top: %q, %v; want %s", got, err, want)
	}
}

// Marshal writes the integer zero as 0 for every kind of integer, in every place, and there is no
// value that it writes -0 for.
func TestMarshalNeverWritesMinusZero(t *testing.T) {
	kinds := []reflect.Type{
		reflect.TypeFor[int](), reflect.TypeFor[int8](), reflect.TypeFor[int16](), reflect.TypeFor[int32](), reflect.TypeFor[int64](),
		reflect.TypeFor[uint](), reflect.TypeFor[uint16](), reflect.TypeFor[uint32](), reflect.TypeFor[uint64](),
	}
	for _, k := range kinds {
		t.Run(k.String(), func(t *testing.T) {
			st := func(f reflect.Type) reflect.Type {
				return reflect.StructOf([]reflect.StructField{{Name: "N", Type: f, Tag: `json:"n"`}})
			}
			ptr := reflect.New(k)
			sliceV := reflect.MakeSlice(reflect.SliceOf(k), 2, 2)
			mapV := reflect.MakeMap(reflect.MapOf(reflect.TypeFor[string](), k))
			mapV.SetMapIndex(reflect.ValueOf("a"), reflect.Zero(k))
			values := []struct {
				name string
				v    any
				want string
			}{
				{"a field", reflect.New(st(k)).Elem().Interface(), `{"n":0}`},
				{"a field behind a pointer", reflect.New(st(reflect.PointerTo(k))).Elem().Interface(), ""},
				{"a list", reflect.New(st(reflect.SliceOf(k))).Elem().Interface(), ""},
				{"an array", reflect.New(st(reflect.ArrayOf(2, k))).Elem().Interface(), `{"n":[0,0]}`},
				{"a map value", mapV.Interface(), `{"a":0}`},
			}
			// The values that need filling are made by hand.
			ps := reflect.New(st(reflect.PointerTo(k))).Elem()
			ps.Field(0).Set(ptr)
			values[1].v, values[1].want = ps.Interface(), `{"n":0}`
			ls := reflect.New(st(reflect.SliceOf(k))).Elem()
			ls.Field(0).Set(sliceV)
			values[2].v, values[2].want = ls.Interface(), `{"n":[0,0]}`
			for _, tc := range values {
				got, err := Marshal(tc.v)
				if err != nil || string(got) != tc.want {
					t.Errorf("%s: %q, %v; want %s", tc.name, got, err, tc.want)
				}
				if strings.Contains(string(got), "-0") {
					t.Errorf("%s: %q holds -0", tc.name, got)
				}
				if ok, err := IsCanonical(got); err != nil || !ok {
					t.Errorf("%s: %q is not canonical: %v", tc.name, got, err)
				}
			}
		})
	}
	t.Run("an interface that holds a zero", func(t *testing.T) {
		got, err := Marshal(map[string]any{"a": 0, "b": int8(0), "c": uint(0), "d": int64(0), "e": []any{0, uint8(0)}})
		if want := `{"a":0,"b":0,"c":0,"d":0,"e":[0,0]}`; err != nil || string(got) != want {
			t.Errorf("%q, %v; want %s", got, err, want)
		}
	})
}

// A -0 that is read into a value, of any integer kind, is written back as 0, so the document is
// not given back byte for byte (the second property of the doc of package strictjson holds for a
// canonical document only, and one with -0 is not).
func TestMinusZeroReadIntoAnyKindIsWrittenZero(t *testing.T) {
	kinds := []reflect.Type{
		reflect.TypeFor[int](), reflect.TypeFor[int8](), reflect.TypeFor[int16](), reflect.TypeFor[int32](), reflect.TypeFor[int64](),
		reflect.TypeFor[uint](), reflect.TypeFor[uint8](), reflect.TypeFor[uint16](), reflect.TypeFor[uint32](), reflect.TypeFor[uint64](),
		reflect.TypeFor[any](),
	}
	for _, k := range kinds {
		t.Run(k.String(), func(t *testing.T) {
			typ := reflect.StructOf([]reflect.StructField{{Name: "N", Type: k, Tag: `json:"n"`}})
			v := reflect.New(typ)
			if err := strictjson.Unmarshal([]byte(`{"n":-0}`), v.Interface(), strictjson.Options{}); err != nil {
				t.Fatal(err)
			}
			got, err := Marshal(v.Interface())
			if want := `{"n":0}`; err != nil || string(got) != want {
				t.Errorf("%q, %v; want %s", got, err, want)
			}
		})
	}
}
