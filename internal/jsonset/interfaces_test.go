package jsonset

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// An interface type that declares one of MarshalJSON, MarshalText, UnmarshalJSON or UnmarshalText
// is refused as a type, in both modes: the set is closed, and what such a value would write or
// read is its own. An interface with other methods is judged as before: written by the value it
// holds, and refused for reading.

type (
	// ownMarshaler embeds one of the four and adds a method of its own.
	ownMarshaler interface {
		json.Marshaler
		Show() string
	}
	ownUnmarshaler interface {
		json.Unmarshaler
	}
	ownTextMarshaler interface {
		encoding.TextMarshaler
		Show() string
	}
	ownTextUnmarshaler interface {
		encoding.TextUnmarshaler
	}
	// declared declares the method itself, with the signature of the standard one.
	declaredMarshalJSON interface{ MarshalJSON() ([]byte, error) }
	both                interface {
		json.Unmarshaler
		json.Marshaler
	}
	// deeper embeds an interface that embeds one of the four.
	deeper interface {
		ownTextMarshaler
		Other() int
	}
)

func TestAnInterfaceThatDeclaresOneOfTheFourMethodsIsRefusedAsAType(t *testing.T) {
	cases := []struct {
		name   string
		typ    reflect.Type
		method string
	}{
		{"json.Marshaler", typeOf[json.Marshaler](), "MarshalJSON"},
		{"json.Unmarshaler", typeOf[json.Unmarshaler](), "UnmarshalJSON"},
		{"encoding.TextMarshaler", typeOf[encoding.TextMarshaler](), "MarshalText"},
		{"encoding.TextUnmarshaler", typeOf[encoding.TextUnmarshaler](), "UnmarshalText"},
		{"an interface of our own that embeds json.Marshaler and has a method more", typeOf[ownMarshaler](), "MarshalJSON"},
		{"an interface of our own that embeds json.Unmarshaler", typeOf[ownUnmarshaler](), "UnmarshalJSON"},
		{"an interface of our own that embeds encoding.TextMarshaler", typeOf[ownTextMarshaler](), "MarshalText"},
		{"an interface of our own that embeds encoding.TextUnmarshaler", typeOf[ownTextUnmarshaler](), "UnmarshalText"},
		{"an interface that declares the method itself", typeOf[declaredMarshalJSON](), "MarshalJSON"},
		{"an interface that embeds an interface that embeds one", typeOf[deeper](), "MarshalText"},
		{"an interface with two of the four is refused for the first in the order MarshalJSON, MarshalText, UnmarshalJSON, UnmarshalText", typeOf[both](), "MarshalJSON"},
	}
	for _, tc := range cases {
		reason := "the type has a " + tc.method + " method; only Raw carries JSON of its own"
		places := []struct {
			where string
			typ   reflect.Type
			hops  string
		}{
			{"at the top", tc.typ, ""},
			{"as an element of a slice", reflect.SliceOf(tc.typ), "[]"},
			{"as an element of an array", reflect.ArrayOf(2, tc.typ), "[]"},
			{"as the value of a map", reflect.MapOf(typeOf[string](), tc.typ), "{}"},
			{"as a field", reflect.StructOf([]reflect.StructField{{Name: "F", Type: tc.typ}}), ".F"},
			{"as a field, tagged", reflect.StructOf([]reflect.StructField{{Name: "F", Type: tc.typ, Tag: `json:"f,omitempty"`}}), ".f"},
			{"in a slice of maps of a struct field", reflect.SliceOf(reflect.MapOf(typeOf[string](), reflect.StructOf([]reflect.StructField{{Name: "F", Type: tc.typ}}))), "[]{}.F"},
		}
		for _, place := range places {
			for _, mode := range []Mode{Writing, Reading} {
				t.Run(fmt.Sprintf("%s/%s/%v", tc.name, place.where, mode), func(t *testing.T) {
					r := NewChecker(mode, rawType).Verdict(place.typ)
					if r == nil {
						t.Fatal("accepted")
					}
					if got := (verdict{r.Type.String(), hopsText(r.Hops), r.Reason}); got != (verdict{tc.typ.String(), place.hops, reason}) {
						t.Errorf("got %+v, want %+v", got, verdict{tc.typ.String(), place.hops, reason})
					}
				})
			}
		}
	}
}

func TestTheTextOfAnInterfaceRefusalInBothDirections(t *testing.T) {
	typ := typeOf[json.Marshaler]()
	for _, mode := range []struct {
		m    Mode
		verb string
	}{{Writing, "written"}, {Reading, "read"}} {
		c := NewChecker(mode.m, rawType)
		want := "malformed JSON: $.l: a value of type json.Marshaler cannot be " + mode.verb + " (the elements of $.l): the type has a MarshalJSON method; only Raw carries JSON of its own"
		if got := c.Err(Path{Member("l")}, c.Verdict(reflect.SliceOf(typ))).Error(); got != want {
			t.Errorf("%v: got\n  %s\nwant\n  %s", mode.m, got, want)
		}
	}
}

func TestAnInterfaceWithOtherMethodsIsJudgedByTheMode(t *testing.T) {
	for _, typ := range []reflect.Type{typeOf[shower](), typeOf[fmtStringer](), typeOf[error](), typeOf[any]()} {
		w := NewChecker(Writing, rawType).Verdict(typ)
		r := NewChecker(Reading, rawType).Verdict(typ)
		if w != nil {
			t.Errorf("writing refuses %s: %s", typ, w.Reason)
		}
		if typ.NumMethod() == 0 && r != nil {
			t.Errorf("reading refuses %s: %s", typ, r.Reason)
		}
		if typ.NumMethod() != 0 && (r == nil || r.Reason != reasonIface) {
			t.Errorf("reading takes %s: %+v", typ, r)
		}
	}
}

func TestAPointerToAnInterfaceIsRefusedAsAPointerWhateverTheInterface(t *testing.T) {
	// A pointer to an interface has no methods of its own, so it is the pointer that is refused.
	for _, typ := range []reflect.Type{typeOf[*json.Marshaler](), typeOf[*any](), typeOf[*shower]()} {
		for _, mode := range []Mode{Writing, Reading} {
			r := NewChecker(mode, rawType).Verdict(typ)
			if r == nil || r.Reason != reasonPtr || r.Type != typ {
				t.Errorf("%v %s: %+v", mode, typ, r)
			}
		}
	}
}
