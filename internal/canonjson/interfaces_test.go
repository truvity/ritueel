package canonjson

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// An interface type that declares one of MarshalJSON, MarshalText, UnmarshalJSON or UnmarshalText is
// refused as a type, by the writer and by the reader, whatever the value and whatever the document:
// as a field, as an element of a list or an array, as the value of a map, behind a pointer, inside
// a struct inside any of those. An interface with other methods is the one difference between the
// two: the writer judges the value that it holds, the reader has no value to judge.

type (
	// ownMarshaler embeds one of the four and adds a method of its own.
	ownMarshaler interface {
		json.Marshaler
		Show() string
	}
	ownUnmarshaler     interface{ json.Unmarshaler }
	ownTextMarshaler   interface{ encoding.TextMarshaler }
	ownTextUnmarshaler interface {
		encoding.TextUnmarshaler
		Show() string
	}
	// declares the method itself, with the signature of the standard one.
	declaredMarshalText interface{ MarshalText() ([]byte, error) }
	// shower has a method that is none of the four.
	shower interface{ Show() string }
	// shown is a string with the method of shower.
	shown string
)

func (s shown) Show() string { return string(s) }

func interfaceCases() []struct {
	name   string
	typ    reflect.Type
	method string
} {
	return []struct {
		name   string
		typ    reflect.Type
		method string
	}{
		{"json.Marshaler", reflect.TypeFor[json.Marshaler](), "MarshalJSON"},
		{"json.Unmarshaler", reflect.TypeFor[json.Unmarshaler](), "UnmarshalJSON"},
		{"encoding.TextMarshaler", reflect.TypeFor[encoding.TextMarshaler](), "MarshalText"},
		{"encoding.TextUnmarshaler", reflect.TypeFor[encoding.TextUnmarshaler](), "UnmarshalText"},
		{"an interface of our own that embeds json.Marshaler", reflect.TypeFor[ownMarshaler](), "MarshalJSON"},
		{"an interface of our own that embeds json.Unmarshaler", reflect.TypeFor[ownUnmarshaler](), "UnmarshalJSON"},
		{"an interface of our own that embeds encoding.TextMarshaler", reflect.TypeFor[ownTextMarshaler](), "MarshalText"},
		{"an interface of our own that embeds encoding.TextUnmarshaler", reflect.TypeFor[ownTextUnmarshaler](), "UnmarshalText"},
		{"an interface that declares MarshalText itself", reflect.TypeFor[declaredMarshalText](), "MarshalText"},
	}
}

// ifaceShape is a type that holds the interface type in one place, with the text of how a refusal reaches
// it: the way (the path and the words) as the error shows it.
type ifaceShape struct {
	name string
	typ  func(reflect.Type) reflect.Type
	// where is what follows "a value of type T cannot be <verb>" up to the colon.
	where string
}

func structOfField(name string, typ reflect.Type) reflect.Type {
	return reflect.StructOf([]reflect.StructField{{Name: "F", Type: typ, Tag: reflect.StructTag(`json:"` + name + `"`)}})
}

func ifaceShapes() []ifaceShape {
	return []ifaceShape{
		{"a field", func(i reflect.Type) reflect.Type { return structOfField("f", i) }, ""},
		{"a field, behind a pointer", func(i reflect.Type) reflect.Type { return structOfField("p", reflect.PointerTo(structOfField("f", i))) }, ""},
		{"a field in a field", func(i reflect.Type) reflect.Type { return structOfField("o", structOfField("f", i)) }, ""},
		{"a list", func(i reflect.Type) reflect.Type { return structOfField("l", reflect.SliceOf(i)) }, " (the elements of $.l)"},
		{"an array", func(i reflect.Type) reflect.Type { return structOfField("a", reflect.ArrayOf(2, i)) }, " (the elements of $.a)"},
		{"a map value", func(i reflect.Type) reflect.Type {
			return structOfField("m", reflect.MapOf(reflect.TypeFor[string](), i))
		}, " (the values of $.m)"},
		{"a field of a struct in a list", func(i reflect.Type) reflect.Type {
			return structOfField("l", reflect.SliceOf(structOfField("f", i)))
		}, " (the member f of the elements of $.l)"},
	}
}

func TestAnInterfaceThatDeclaresOneOfTheFourMethodsIsRefusedBothWays(t *testing.T) {
	for _, ic := range interfaceCases() {
		reason := "the type has a " + ic.method + " method; only Raw carries JSON of its own"
		for _, sh := range ifaceShapes() {
			typ := sh.typ(ic.typ)
			t.Run(ic.name+"/"+sh.name, func(t *testing.T) {
				// The path of the refusal: the fields that lead to it, up to the list, the array or the map.
				for _, dir := range []struct {
					verb string
					run  func() ([]byte, error)
				}{
					{"written", func() ([]byte, error) { return Marshal(reflect.New(typ).Elem().Interface()) }},
					{"read", func() ([]byte, error) {
						return nil, strictjson.Unmarshal([]byte(`{}`), reflect.New(typ).Interface(), strictjson.Options{})
					}},
				} {
					_, err := dir.run()
					if err == nil {
						t.Fatalf("%s: accepted", dir.verb)
					}
					path := refusalPath(sh.name)
					want := fmt.Sprintf("malformed JSON: %s: a value of type %s cannot be %s%s: %s", path, ic.typ, dir.verb, sh.where, reason)
					if err.Error() != want {
						t.Errorf("%s: the error is\n  %q\nwant\n  %q", dir.verb, err, want)
					}
				}
			})
		}
	}
}

// refusalPath is the path that a refusal in the shape is at: the fields that lead to the interface,
// up to a list, an array or a map, which no path can pass.
func refusalPath(shape string) string {
	switch shape {
	case "a field":
		return "$.f"
	case "a field, behind a pointer":
		return "$.p.f"
	case "a field in a field":
		return "$.o.f"
	case "a list":
		return "$.l"
	case "an array":
		return "$.a"
	case "a map value":
		return "$.m"
	case "a field of a struct in a list":
		return "$.l"
	}
	panic(shape)
}

// The type is refused whatever the value it holds: a field of the interface type that is nil, one
// that holds a type with the method, one that holds a type without it, and a list that is empty.
func TestAnInterfaceWithOneOfTheFourMethodsIsRefusedWhateverTheValue(t *testing.T) {
	type holder struct {
		F json.Marshaler `json:"f"`
	}
	cases := map[string]holder{"nil": {}, "a json.RawMessage": {F: json.RawMessage(`{}`)}}
	for name, v := range cases {
		_, err := Marshal(v)
		want := "malformed JSON: $.f: a value of type json.Marshaler cannot be written: the type has a MarshalJSON method; only Raw carries JSON of its own"
		if err == nil || err.Error() != want {
			t.Errorf("%s: %v", name, err)
		}
		if err := strictjson.Unmarshal([]byte(`{"f":{}}`), &v, strictjson.Options{}); err == nil || err.Error() != "malformed JSON: $.f: a value of type json.Marshaler cannot be read: the type has a MarshalJSON method; only Raw carries JSON of its own" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same, for the document that is empty and for AllowUnknown.
	var v holder
	for _, doc := range []string{`{}`, `{"f":{}}`, `{"other":1}`} {
		for _, opts := range []strictjson.Options{{}, {AllowUnknown: true}} {
			if err := strictjson.Unmarshal([]byte(doc), &v, opts); err == nil {
				t.Errorf("%s was read into an interface with MarshalJSON", doc)
			}
		}
	}
}

// At the top. The reader is given a pointer to the target, and the target is the interface type
// itself, which it refuses as a type with the method. The writer is given the value: a pointer to an
// interface is a pointer to an interface, which has no methods of its own, and is refused as such.
func TestAnInterfaceTypeAtTheTopIsRefused(t *testing.T) {
	for _, ic := range interfaceCases() {
		t.Run(ic.name, func(t *testing.T) {
			p := reflect.New(ic.typ)
			ptr := "*" + ic.typ.String()
			wantW := fmt.Sprintf("malformed JSON: $: a value of type %s cannot be written: a pointer to a pointer or to an interface is not part of ritueel's JSON", ptr)
			if _, err := Marshal(p.Interface()); err == nil || err.Error() != wantW {
				t.Errorf("writing: %v", err)
			}
			wantR := fmt.Sprintf("malformed JSON: $: a value of type %s cannot be read: the type has a %s method; only Raw carries JSON of its own", ic.typ, ic.method)
			for _, opts := range []strictjson.Options{{}, {AllowUnknown: true}} {
				for _, doc := range []string{`{}`, `{"a":1}`, `[]`, `1`} {
					if err := strictjson.Unmarshal([]byte(doc), p.Interface(), opts); err == nil || err.Error() != wantR {
						t.Errorf("reading %s: %v", doc, err)
					}
				}
			}
		})
	}
	t.Run("an interface with other methods at the top is refused for reading", func(t *testing.T) {
		var s shower
		want := "malformed JSON: $: a value of type canonjson.shower cannot be read: an interface with methods is not part of ritueel's JSON; only one with no methods is"
		if err := strictjson.Unmarshal([]byte(`{}`), &s, strictjson.Options{}); err == nil || err.Error() != want {
			t.Errorf("%v", err)
		}
	})
}

// An interface with other methods: the writer judges the value that it holds, the reader refuses
// the type.
func TestAnInterfaceWithOtherMethodsIsWrittenByItsValueAndRefusedForReading(t *testing.T) {
	type holder struct {
		F shower `json:"f"`
	}
	got, err := Marshal(holder{F: shown("x")})
	if want := `{"f":"x"}`; err != nil || string(got) != want {
		t.Errorf("the value: %q, %v; want %s", got, err, want)
	}
	// A value of a type that is not in the set is refused by its own verdict.
	_, err = Marshal(holder{F: nil})
	if err == nil {
		t.Error("a nil interface was written without omitempty")
	}
	var h holder
	err = strictjson.Unmarshal([]byte(`{"f":"x"}`), &h, strictjson.Options{})
	want := "malformed JSON: $.f: a value of type canonjson.shower cannot be read: an interface with methods is not part of ritueel's JSON; only one with no methods is"
	if err == nil || err.Error() != want {
		t.Errorf("reading: %v; want %s", err, want)
	}
	// In a list and as a map value, the same.
	var l struct {
		L []shower `json:"l"`
	}
	if err := strictjson.Unmarshal([]byte(`{"l":[]}`), &l, strictjson.Options{}); err == nil {
		t.Error("a list of an interface with methods was read")
	}
	got, err = Marshal(map[string]shower{"a": shown("y")})
	if want := `{"a":"y"}`; err != nil || string(got) != want {
		t.Errorf("a map: %q, %v; want %s", got, err, want)
	}
}
