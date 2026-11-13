package strictjson

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

// -0 is the integer zero, for every kind of integer, the unsigned ones too: the grammar accepts it,
// the reader takes it as 0, and it is not a float (no sign of a zero is kept). The canonical form
// that package canonjson writes has 0 in its place, and a document with -0 is not canonical (those
// tests are in canonjson). Here: every integer kind, in every place that a document can hold one.

// allZero reports whether v is made of zero integers only: an integer that is 0, a pointer that is
// set and points to one, a struct, a list, an array or a map whose every element is. An empty list
// or map is not: the test wants the places filled.
func allZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Pointer:
		return !v.IsNil() && allZero(v.Elem())
	case reflect.Struct:
		for i := range v.NumField() {
			if !allZero(v.Field(i)) {
				return false
			}
		}
		return v.NumField() > 0
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if !allZero(v.Index(i)) {
				return false
			}
		}
		return v.Len() > 0
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if !allZero(v.MapIndex(k)) {
				return false
			}
		}
		return v.Len() > 0
	default:
		return false
	}
}

func TestMinusZeroIsTheIntegerZeroForEveryKindInEveryPlace(t *testing.T) {
	for _, k := range intKinds() {
		// Each place is a type built around the kind, and a document that puts -0 in it.
		places := []struct {
			name string
			typ  reflect.Type
			doc  string
		}{
			{"a field of a struct", structOf([]string{"n"}, []reflect.Type{k.typ}, nil), `{"n":-0}`},
			{"a field of a struct, with the other fields not zero-looking", structOf([]string{"a", "n"}, []reflect.Type{reflect.TypeFor[string](), k.typ}, nil), `{"a":"x","n":-0}`},
			{"a value of a map", reflect.MapOf(reflect.TypeFor[string](), k.typ), `{"a":-0,"b":-0}`},
			{"an element of a list", structOf([]string{"l"}, []reflect.Type{reflect.SliceOf(k.typ)}, nil), `{"l":[-0,-0,-0]}`},
			{"an element of an array", structOf([]string{"a"}, []reflect.Type{reflect.ArrayOf(2, k.typ)}, nil), `{"a":[-0,-0]}`},
			{"behind a pointer", structOf([]string{"p"}, []reflect.Type{reflect.PointerTo(k.typ)}, nil), `{"p":-0}`},
			{"in a list in a map", reflect.MapOf(reflect.TypeFor[string](), reflect.SliceOf(k.typ)), `{"a":[-0],"b":[-0,-0]}`},
			{"in a map in a struct in a list", structOf([]string{"l"}, []reflect.Type{reflect.SliceOf(structOf([]string{"m"}, []reflect.Type{reflect.MapOf(reflect.TypeFor[string](), k.typ)}, nil))}, nil), `{"l":[{"m":{"x":-0}}]}`},
			{"with white space around it", structOf([]string{"n"}, []reflect.Type{k.typ}, nil), "{ \"n\" :\t-0\n}"},
		}
		for _, p := range places {
			t.Run(k.name+"/"+p.name, func(t *testing.T) {
				if k.typ.Kind() == reflect.Uint8 && (p.name == "an element of a list" || p.name == "in a list in a map") {
					// A slice of uint8 is a byte string, read from Base64 and not from a list of integers, so
					// -0 in a list is a list where a string is wanted: refused, whatever the integer is.
					if _, err := read(p.typ, p.doc, Options{}); err == nil || !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "expected a string of standard Base64, for a slice of bytes, found a list") {
						t.Errorf("%s: %v", p.doc, err)
					}
					return
				}
				for _, opts := range []Options{{}, {AllowUnknown: true}} {
					v, err := read(p.typ, p.doc, opts)
					if err != nil {
						t.Fatalf("%s: %v", p.doc, err)
					}
					// One place has a string field beside the integer: the string is checked, and the
					// integer is the field that is the zero.
					if p.typ.Kind() == reflect.Struct && p.typ.NumField() == 2 {
						if v.Field(0).String() != "x" || !allZero(v.Field(1)) {
							t.Errorf("%s: the value is %v", p.doc, v)
						}
						continue
					}
					if !allZero(v) {
						t.Errorf("%s: the value is %v", p.doc, v)
					}
				}
				if err := Check([]byte(p.doc), 0); err != nil {
					t.Errorf("Check refused %s: %v", p.doc, err)
				}
			})
		}
	}
	t.Run("in an interface it is the int64 0", func(t *testing.T) {
		var v map[string]any
		if err := Unmarshal([]byte(`{"a":-0,"b":[-0,{"c":-0}],"d":{"e":-0}}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"a": int64(0), "b": []any{int64(0), map[string]any{"c": int64(0)}}, "d": map[string]any{"e": int64(0)}}
		if !reflect.DeepEqual(v, want) {
			t.Errorf("%#v", v)
		}
		var top struct{ A any }
		if err := Unmarshal([]byte(`{"A":-0}`), &top, Options{}); err != nil || top.A != int64(0) {
			t.Errorf("%#v, %v", top.A, err)
		}
	})
	t.Run("in a Raw it keeps its bytes", func(t *testing.T) {
		var v struct{ R Raw }
		if err := Unmarshal([]byte(`{"R":{"a":-0,"b":[-0]}}`), &v, Options{}); err != nil || string(v.R) != `{"a":-0,"b":[-0]}` {
			t.Errorf("%q, %v", v.R, err)
		}
	})
	t.Run("in an unknown member that is skipped", func(t *testing.T) {
		var v struct{ A int }
		if err := Unmarshal([]byte(`{"u":-0,"v":[-0],"A":-0}`), &v, Options{AllowUnknown: true}); err != nil || v.A != 0 {
			t.Errorf("%+v, %v", v, err)
		}
	})
	t.Run("it is not a float: no sign of a zero is kept", func(t *testing.T) {
		var v struct {
			N int64
			A any
		}
		if err := Unmarshal([]byte(`{"N":-0,"A":-0}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if math.Signbit(float64(v.N)) || v.N != 0 || v.A != int64(0) {
			t.Errorf("%+v", v)
		}
	})
}

func TestMinusZeroIsTheIntegerZeroInTheParser(t *testing.T) {
	root, err := Parse([]byte(`{"a":-0,"b":[-0],"c":0}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range root.Members {
		var vals []Value
		if m.Value.Kind == List {
			vals = m.Value.Elems
		} else {
			vals = []Value{m.Value}
		}
		for _, v := range vals {
			if v.Kind != Integer || v.Int != 0 {
				t.Errorf("%s: %+v", m.Name, v)
			}
		}
	}
	if n, ok, err := PeekInt([]byte(`{"version":-0}`), "version", 0); err != nil || !ok || n != 0 {
		t.Errorf("PeekInt: %d, %v, %v", n, ok, err)
	}
}

// Text that looks like -0 and is not an integer is refused, whatever the kind.
func TestWhatLooksLikeMinusZeroButIsNotIsRefused(t *testing.T) {
	for _, in := range []string{`-00`, `-0.0`, `-0e0`, `-0E0`, `-0.0e1`, `- 0`, `--0`, `+0`, `-0x0`, `-`, `-01`, `-0_0`, `−0`} {
		for _, k := range intKinds() {
			typ := structOf([]string{"n"}, []reflect.Type{k.typ}, nil)
			if _, err := read(typ, `{"n":`+in+`}`, Options{}); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s into %s: %v", in, k.name, err)
			}
		}
	}
	t.Run("a string with the text -0 is a string", func(t *testing.T) {
		var v struct{ S string }
		if err := Unmarshal([]byte(`{"S":"-0"}`), &v, Options{}); err != nil || v.S != "-0" {
			t.Errorf("%+v, %v", v, err)
		}
		var n struct{ N int }
		if err := Unmarshal([]byte(`{"N":"-0"}`), &n, Options{}); !errors.Is(err, ErrMalformed) {
			t.Errorf("a string into an int: %v", err)
		}
	})
}

// The standard decoder reads -0 into a signed kind as 0 and refuses it for an unsigned kind
// ("number -0 into ..."): this reader reads 0 for both. The difference is named here, for the
// unsigned kinds, and it is the only one that is set aside; every signed kind must agree with the
// standard decoder.
func TestMinusZeroAgainstTheStandardDecoder(t *testing.T) {
	for _, k := range intKinds() {
		typ := structOf([]string{"n"}, []reflect.Type{k.typ}, nil)
		doc := `{"n":-0}`
		unsigned := strings.HasPrefix(k.name, "uint") || strings.HasPrefix(k.name, "a named uint")
		t.Run(k.name, func(t *testing.T) {
			ours, oerr := read(typ, doc, Options{})
			if oerr != nil || !allZero(ours) {
				t.Fatalf("this reader: %v, %v", ours, oerr)
			}
			std, serr := decodeStd(typ, doc)
			if unsigned {
				// The named difference: the standard decoder refuses -0 for an unsigned kind.
				if serr == nil {
					t.Fatalf("the standard decoder reads -0 into %s now (%v): the difference is gone, and this test is to change", k.name, std)
				}
				if !strings.Contains(serr.Error(), "number -0") {
					t.Errorf("the standard decoder refuses it for another reason: %v", serr)
				}
				t.Logf("%s: the standard decoder refuses -0 (%v); this reader reads 0, as its doc says", k.name, serr)
				return
			}
			if serr != nil {
				t.Fatalf("the standard decoder refused -0 into %s: %v", k.name, serr)
			}
			if !reflect.DeepEqual(ours.Interface(), std.Interface()) {
				t.Errorf("this reader gives %v, the standard decoder %v", ours, std)
			}
		})
	}
	t.Run("into an interface both give a zero", func(t *testing.T) {
		var ours map[string]any
		if err := Unmarshal([]byte(`{"a":-0}`), &ours, Options{}); err != nil {
			t.Fatal(err)
		}
		std, err := decodeStd(reflect.TypeFor[map[string]any](), `{"a":-0}`)
		if err != nil {
			t.Fatal(err)
		}
		// The standard decoder (UseNumber) gives a json.Number "-0", this reader the integer.
		if fmt.Sprint(std.Interface()) != "map[a:-0]" || ours["a"] != int64(0) {
			t.Errorf("ours %#v, std %#v", ours, std)
		}
	})
}
