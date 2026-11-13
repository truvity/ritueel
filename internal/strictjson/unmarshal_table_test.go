package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// The tests of Unmarshal as the reader of a closed set of Go types: the table of every target
// that it fills, with the document and the exact value; the table of every Go type that it
// refuses, with the exact error; and the rule for what the value that is passed in may be. A JSON
// escape of the form backslash, u and four digits is never written out in these files: where a
// test needs one it is built from a backslash and the digits, or from a code point, so that no
// tool can turn it into the character on the way.

const bs = "\\" // a backslash

// uesc is the six-byte escape of a character of the BMP, in lower case.
func uesc(r rune) string { return fmt.Sprintf("%cu%04x", '\\', r) }

// ---- types of the tests -------------------------------------------------------------------

type (
	myInt    int
	myBool   bool
	myString string
	myKey    string
	myBytes  []byte
	point    struct{ X, Y int }
	// A type that has a method of the same name as one that is refused, but no MarshalJSON,
	// MarshalText, UnmarshalJSON or UnmarshalText, is an ordinary type.
	marshalish struct{ N int }
)

func (marshalish) Marshal() ([]byte, error) { return nil, errors.New("not called") }

// Types that read or write their own JSON or text, or are refused for another reason of their own.
type (
	jsonVal      struct{ N int } // MarshalJSON on the value
	jsonPtr      struct{ N int } // MarshalJSON on the pointer only
	textVal      string          // MarshalText on the value
	textPtr      struct{ N int } // MarshalText on the pointer only
	unmarshalVal struct{ N int } // UnmarshalJSON on the pointer, as it has to be
	unmarshalTxt struct{ N int } // UnmarshalText on the pointer
	textKey      string          // a key type that writes text
	textByte     byte            // an element type that writes text
)

func (jsonVal) MarshalJSON() ([]byte, error)     { return []byte(`{}`), nil }
func (*jsonPtr) MarshalJSON() ([]byte, error)    { return []byte(`{}`), nil }
func (textVal) MarshalText() ([]byte, error)     { return []byte("x"), nil }
func (*textPtr) MarshalText() ([]byte, error)    { return []byte("x"), nil }
func (*unmarshalVal) UnmarshalJSON([]byte) error { return nil }
func (*unmarshalTxt) UnmarshalText([]byte) error { return nil }
func (textKey) MarshalText() ([]byte, error)     { return []byte("k"), nil }
func (textByte) MarshalText() ([]byte, error)    { return []byte("b"), nil }

// Structs that are refused as types.
type (
	embeddedBase  struct{ X int }
	embedsValue   struct{ embeddedBase }
	embedsPointer struct{ *embeddedBase }
	Exported      struct{ X int }
	embedsExport  struct{ Exported }
	embedsInt     struct{ myInt }
	optString     struct {
		F int `json:",string"`
	}
	optNamedString struct {
		F int `json:"f,string"`
	}
	optInline struct {
		F int `json:"f,inline"`
	}
	optOmitZero struct {
		F int `json:",omitzero"`
	}
	optSecond struct {
		F int `json:",omitempty,string"`
	}
	nameAsField struct {
		A int
		B int `json:"A"`
	}
	floatField struct {
		G float64
	}
	floatFieldOmit struct {
		G float64 `json:",omitempty"`
	}
	floatPtrOmit struct {
		P *float64 `json:",omitempty"`
	}
	holdsFloats struct {
		Inner floatField
	}
	recursiveFloat struct {
		Next *recursiveFloat `json:",omitempty"`
		F    float64         `json:",omitempty"`
	}
	listNode struct {
		Next *listNode `json:",omitempty"`
	}
	mutualA struct {
		B *mutualB `json:",omitempty"`
	}
	mutualB struct {
		A *mutualA `json:",omitempty"`
	}
	// shower is an interface with a method, which has no value to judge and so is refused.
	shower interface{ Show() string }
	// anything is a named interface with no methods, which is as good as any.
	anything interface{}
)

func ptr[T any](v T) *T { return &v }

var _ = embedsInt{myInt: 1} // the embedded field is only there to be refused

// unmarshalStd is the standard decoder, for the tests that say what it does and this reader does not.
func unmarshalStd(data []byte, v any) error { return json.Unmarshal(data, v) }

// structOf builds a struct type with the given exported fields F0, F1, ..., each of the type of
// its value and with the tag that names it, so that a test can use names and tags that a Go
// source file could not show (or that go vet would not pass).
func structOf(names []string, types []reflect.Type, tags []string) reflect.Type {
	var fields []reflect.StructField
	for i, typ := range types {
		tag := `json:"` + names[i] + `"`
		if tags != nil {
			tag = tags[i]
		}
		fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: typ, Tag: reflect.StructTag(tag)})
	}
	return reflect.StructOf(fields)
}

// withTag is a struct type with one field F of type int and the given whole tag.
func withTag(tag string) reflect.Type {
	return reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[int](), Tag: reflect.StructTag(tag)}})
}

// ---- how a refusal is worded --------------------------------------------------------------

// A route is the way from the type that was asked about to the type at fault, as jsonset names the
// hops: ".F" for the field F, "[]" for the elements of a list or an array and "{}" for the values of
// a map. splitRoute reads a route written as one string, ".Inner.G" or "[]{}".
func splitRoute(s string) []string {
	var route []string
	for s != "" {
		switch {
		case strings.HasPrefix(s, "[]"), strings.HasPrefix(s, "{}"):
			route, s = append(route, s[:2]), s[2:]
		case s[0] == '.':
			end := strings.IndexAny(s[1:], ".[{")
			if end < 0 {
				end = len(s) - 1
			}
			route, s = append(route, s[:end+1]), s[end+1:]
		default:
			panic("a route that cannot be read: " + s)
		}
	}
	return route
}

// routeText is what an error shows for the way from the value at base to the type at fault: the
// fields that lead from the start go on the path, and the first list or map hop and all after it
// are said in words in brackets, as "(the values of the elements of $.l)".
func routeText(base string, route []string) (path, where string) {
	path = base
	i := 0
	for ; i < len(route) && route[i][0] == '.'; i++ {
		path += route[i]
	}
	if i == len(route) {
		return path, ""
	}
	phrase := path
	for _, hop := range route[i:] {
		switch hop {
		case "[]":
			phrase = "the elements of " + phrase
		case "{}":
			phrase = "the values of " + phrase
		default:
			phrase = "the member " + hop[1:] + " of " + phrase
		}
	}
	return path, " (" + phrase + ")"
}

// cannotRead is the text of the refusal of the Go type typ that is reached from the value at base
// by the route.
func cannotRead(base string, route []string, typ, reason string) string {
	path, where := routeText(base, route)
	return fmt.Sprintf("%s: %s: a value of type %s cannot be read%s: %s", ErrMalformed, path, typ, where, reason)
}

// The reasons of the refusals, as jsonset words them.
const (
	reasonFloat  = "a float; ritueel's JSON holds integers only"
	reasonKind   = "this kind of Go type is not part of ritueel's JSON"
	reasonNumber = "a json.Number is not part of ritueel's JSON; use an integer type"
	reasonJSON   = "the type has a MarshalJSON method; only Raw carries JSON of its own"
	reasonText   = "the type has a MarshalText method; only Raw carries JSON of its own"
	reasonUJSON  = "the type has a UnmarshalJSON method; only Raw carries JSON of its own"
	reasonUText  = "the type has a UnmarshalText method; only Raw carries JSON of its own"
	reasonPtrPtr = "a pointer to a pointer or to an interface is not part of ritueel's JSON"
	reasonMapKey = "only a map with a key of kind string is part of ritueel's JSON"
	reasonIface  = "an interface with methods is not part of ritueel's JSON; only one with no methods is"
	reasonEmbed  = "the embedded field %s is not part of ritueel's JSON; give it a name"
	reasonOption = "field %s has the tag option %q; only omitempty is allowed"
	reasonTwice  = "two fields are named %q"
	// reasonNameRule is the rule for the name of a member of a struct, as the errors say it.
	reasonNameRule = "a member name holds only ASCII letters, digits and underscores"
	reasonTopKind  = "the top of a document is one JSON object, which fills a struct, a map, a Raw or an interface with no methods"
)

// ---- the closed set, one table ------------------------------------------------------------

// A target is one Go type that Unmarshal fills, a document that fills it and the exact value.
type target struct {
	name string
	typ  reflect.Type
	doc  string // the JSON text of the value
	want any    // a value of the type typ
}

func tgt[T any](name, doc string, want T) target {
	return target{name: name, typ: reflect.TypeFor[T](), doc: doc, want: want}
}

// acceptedTargets is every kind that Unmarshal fills, with the exact document and value. A target
// of kind any is in acceptedAnys: what it is filled with is decided by the document.
func acceptedTargets() []target {
	emoji, dalet, euro, eacute := string(rune(0x1F600)), string(rune(0xFB33)), string(rune(0x20AC)), string(rune(0xe9))
	q := func(s string) string { return `"` + s + `"` }
	return []target{
		tgt("bool true", `true`, true),
		tgt("bool false", `false`, false),
		tgt("int", `-5`, int(-5)),
		tgt("int zero", `0`, int(0)),
		tgt("int minus zero", `-0`, int(0)),
		tgt("int8 smallest", `-128`, int8(math.MinInt8)),
		tgt("int8 largest", `127`, int8(math.MaxInt8)),
		tgt("int16 smallest", `-32768`, int16(math.MinInt16)),
		tgt("int16 largest", `32767`, int16(math.MaxInt16)),
		tgt("int32 smallest", `-2147483648`, int32(math.MinInt32)),
		tgt("int32 largest", `2147483647`, int32(math.MaxInt32)),
		tgt("int64 smallest", `-9223372036854775808`, int64(math.MinInt64)),
		tgt("int64 largest", `9223372036854775807`, int64(math.MaxInt64)),
		tgt("uint", `7`, uint(7)),
		tgt("uint zero", `0`, uint(0)),
		tgt("uint8 smallest", `0`, uint8(0)),
		tgt("uint8 largest", `255`, uint8(math.MaxUint8)),
		tgt("uint16 largest", `65535`, uint16(math.MaxUint16)),
		tgt("uint32 largest", `4294967295`, uint32(math.MaxUint32)),
		tgt("uint64 at the int64 maximum", `9223372036854775807`, uint64(math.MaxInt64)),
		tgt("uint64 zero", `0`, uint64(0)),
		tgt("uint largest that a document can hold", `9223372036854775807`, uint(math.MaxInt64)),
		tgt("named int", `-3`, myInt(-3)),
		tgt("named bool", `true`, myBool(true)),
		tgt("named string", `"x"`, myString("x")),
		tgt("empty string", `""`, ""),
		tgt("plain string", `"abc"`, "abc"),
		tgt("quote, backslash and slash", `"`+bs+`"`+bs+bs+bs+`/"`, `"\/`),
		tgt("short control escapes", `"`+bs+"b"+bs+"f"+bs+"n"+bs+"r"+bs+`t"`, "\b\f\n\r\t"),
		tgt("controls by code", q(uesc(0)+uesc(1)+uesc(0x1f)), "\x00\x01\x1f"),
		tgt("escapes in capitals", q(bs+"u001F"+bs+"u00E9"), "\x1f"+string(rune(0xe9))),
		tgt("an escape of a letter", q(uesc('A')), "A"),
		tgt("an escape of a character of two bytes", q(uesc(0xe9)), string(rune(0xe9))),
		tgt("an escape of a character of three bytes", q(uesc(0x20ac)), euro),
		tgt("a surrogate pair", q(bs+"ud83d"+bs+"ude00"), emoji),
		tgt("a surrogate pair in capitals", q(bs+"uD83D"+bs+"uDE00"), emoji),
		tgt("the largest character as a pair", q(bs+"udbff"+bs+"udfff"), string(rune(0x10FFFF))),
		tgt("the smallest character above U+FFFF as a pair", q(bs+"ud800"+bs+"udc00"), string(rune(0x10000))),
		tgt("the characters on both sides of the surrogates", q(uesc(0xd7ff)+uesc(0xe000)), string(rune(0xd7ff))+string(rune(0xe000))),
		tgt("delete, slash and markup as they are", "\"\x7f/<>&'\"", "\x7f/<>&'"),
		tgt("separators as they are", q(string(rune(0x2028))+string(rune(0x2029))), string(rune(0x2028))+string(rune(0x2029))),
		tgt("text outside ASCII", q(eacute+euro+emoji+dalet), eacute+euro+emoji+dalet),
		tgt("the replacement character itself", q(string(rune(0xFFFD))), string(rune(0xFFFD))),
		tgt("the byte order mark as text", q(string(rune(0xFEFF))), string(rune(0xFEFF))),
		tgt("bytes, none", `""`, []byte{}),
		tgt("bytes, one", `"AA=="`, []byte{0}),
		tgt("bytes, two", `"aGk="`, []byte("hi")),
		tgt("bytes, three", `"YWJj"`, []byte("abc")),
		tgt("bytes that need the plus and the slash", `"+/+/"`, []byte{0xfb, 0xff, 0xbf}),
		tgt("bytes, the largest last character", `"/w=="`, []byte{0xff}),
		tgt("a named slice of bytes", `"aGk="`, myBytes("hi")),
		tgt("a slice of a named byte", `"aGk="`, []myByte{'h', 'i'}),
		tgt("an array of bytes is a list", `[1,2,3]`, [3]byte{1, 2, 3}),
		tgt("an empty array", `[]`, [0]int{}),
		tgt("an array of strings", `["a","b"]`, [2]string{"a", "b"}),
		tgt("an array of arrays", `[[1,2],[3,4]]`, [2][2]int{{1, 2}, {3, 4}}),
		tgt("an empty slice", `[]`, []int{}),
		tgt("a slice keeps its order", `[3,1,2]`, []int{3, 1, 2}),
		tgt("a slice of bools", `[true,false]`, []bool{true, false}),
		tgt("a slice of slices", `[[1],[]]`, [][]int{{1}, {}}),
		tgt("a slice of byte slices", `["aGk=",""]`, [][]byte{[]byte("hi"), {}}),
		tgt("a slice of int8", `[1,-2]`, []int8{1, -2}),
		tgt("an empty map", `{}`, map[string]int{}),
		tgt("a map is read by its names", `{"b":1,"a":2}`, map[string]int{"b": 1, "a": 2}),
		tgt("a map with a named key type", `{"x":true}`, map[myKey]bool{"x": true}),
		tgt("a map of lists", `{"k":[1]}`, map[string][]int{"k": {1}}),
		tgt("a map of maps", `{"k":{"j":1}}`, map[string]map[string]int{"k": {"j": 1}}),
		tgt("a map of bytes", `{"k":"aGk="}`, map[string][]byte{"k": []byte("hi")}),
		tgt("a map whose names differ in case", `{"a":1,"A":2}`, map[string]int{"a": 1, "A": 2}),
		tgt("a map whose name is written with an escape", `{"`+uesc('a')+`":1}`, map[string]int{"a": 1}),
		tgt("a map with the empty name", `{"":1}`, map[string]int{"": 1}),
		tgt("a map whose name is an escaped quote", `{"`+bs+`"":1}`, map[string]int{`"`: 1}),
		tgt("a map whose name has a character outside the BMP", `{"`+emoji+`":1}`, map[string]int{emoji: 1}),
		tgt("a struct", `{"X":1,"Y":2}`, point{X: 1, Y: 2}),
		tgt("a struct, members in another order", `{"Y":2,"X":1}`, point{X: 1, Y: 2}),
		tgt("an empty struct", `{}`, struct{}{}),
		tgt("a struct that is given less than it has", `{"X":1}`, point{X: 1}),
		tgt("a struct that is given nothing", `{}`, point{}),
		tgt("a struct with a method of another name", `{"N":1}`, marshalish{N: 1}),
		tgt("a struct that leaves out its unexported fields", `{"A":1}`, struct {
			A int
			b int
		}{A: 1}),
		tgt("a struct with tags", `{"alpha":1,"b":"x","C":true}`, struct {
			A int    `json:"alpha"`
			B string `json:"b,omitempty"`
			C bool
			E int `json:"-"`
		}{A: 1, B: "x", C: true}),
		tgt("a pointer to an integer", `5`, ptr(5)),
		tgt("a pointer to a string", `"s"`, ptr("s")),
		tgt("a pointer to a struct", `{"X":1}`, &point{X: 1}),
		tgt("a pointer to a slice", `[1]`, ptr([]int{1})),
		tgt("a pointer to a slice of bytes", `"aGk="`, ptr([]byte("hi"))),
		tgt("a pointer to a map", `{"a":1}`, ptr(map[string]int{"a": 1})),
		tgt("a pointer to an array", `[4]`, ptr([1]int{4})),
		tgt("a slice of pointers", `[1,2]`, []*int{ptr(1), ptr(2)}),
		tgt("a Raw", `{"b":1,"a":[2, 3]}`, Raw(`{"b":1,"a":[2, 3]}`)),
		tgt("a Raw that keeps its white space", `{ "a" : 1 , "b" : [ ] }`, Raw(`{ "a" : 1 , "b" : [ ] }`)),
		tgt("a Raw that keeps its escapes and its minus zero", `{"a":"`+uesc('A')+`","b":-0}`, Raw(`{"a":"`+uesc('A')+`","b":-0}`)),
		tgt("an empty Raw object", `{}`, Raw(`{}`)),
		tgt("a pointer to a Raw", `{"a":1}`, ptr(Raw(`{"a":1}`))),
		tgt("a slice of Raw", `[{"b":1}, {"a":2}]`, []Raw{Raw(`{"b":1}`), Raw(`{"a":2}`)}),
		tgt("a map of Raw", `{"k":{ }}`, map[string]Raw{"k": Raw(`{ }`)}),
		tgt("a struct of every kind", `{"A":[true],"B":true,"I":-1,"L":["a"],"M":{"k":1},"P":3,"Q":{},"R":{"z":0},"S":"s","U":2,"Y":"aGk="}`, struct {
			B bool
			I int8
			U uint32
			S string
			L []string
			M map[string]int
			P *int
			A [1]bool
			R Raw
			Y []byte
			Q struct{}
		}{true, -1, 2, "s", []string{"a"}, map[string]int{"k": 1}, ptr(3), [1]bool{true}, Raw(`{"z":0}`), []byte("hi"), struct{}{}}),
		tgt("a type that refers to itself", `{"Next":{"Next":{}}}`, listNode{Next: &listNode{Next: &listNode{}}}),
		tgt("two types that refer to each other", `{"B":{"A":{"B":{}}}}`, mutualA{B: &mutualB{A: &mutualA{B: &mutualB{}}}}),
		tgt("a field tagged dash is not filled, whatever its type", `{"N":1}`, struct {
			N int
			D float64     `json:"-"`
			C chan int    `json:"-"`
			E embedsValue `json:"-"`
			T jsonVal     `json:"-"`
		}{N: 1}),
		tgt("an unexported field is not looked at, whatever its type", `{"N":1}`, struct {
			N int
			f float64
			c chan int
		}{N: 1}),
		tgt("a named interface with no methods holds what any holds", `{"A":[1]}`, struct{ A anything }{A: []any{int64(1)}}),
	}
}

type myByte byte

// An interface with no methods is filled from the document, and only with these five types.
type anyTarget struct {
	name string
	doc  string
	want any
}

func acceptedAnys() []anyTarget {
	return []anyTarget{
		{"an object", `{"a":1}`, map[string]any{"a": int64(1)}},
		{"an empty object", `{}`, map[string]any{}},
		{"a list", `[1,"a",true]`, []any{int64(1), "a", true}},
		{"an empty list", `[]`, []any{}},
		{"a string", `"s"`, "s"},
		{"an empty string", `""`, ""},
		{"true", `true`, true},
		{"false", `false`, false},
		{"zero", `0`, int64(0)},
		{"minus zero", `-0`, int64(0)},
		{"a small integer, which is int64 too", `7`, int64(7)},
		{"the largest int64", `9223372036854775807`, int64(math.MaxInt64)},
		{"the smallest int64", `-9223372036854775808`, int64(math.MinInt64)},
		{"objects in lists in objects", `{"a":[{"b":[1,{"c":"d"}]},[]],"e":{}}`, map[string]any{
			"a": []any{map[string]any{"b": []any{int64(1), map[string]any{"c": "d"}}}, []any{}},
			"e": map[string]any{},
		}},
		{"lists in lists", `[[],[[]],[[],[1]]]`, []any{[]any{}, []any{[]any{}}, []any{[]any{}, []any{int64(1)}}}},
		{"names that differ in case", `{"a":1,"A":2}`, map[string]any{"a": int64(1), "A": int64(2)}},
		{"a name with an escape, a string with an escape", `{"` + uesc('a') + `":"` + uesc('b') + `"}`, map[string]any{"a": "b"}},
		{"a list of every kind", `[{},[],"",0,false]`, []any{map[string]any{}, []any{}, "", int64(0), false}},
	}
}

// place is one position for a value in a target: the type that holds it, the document that holds
// the text of it, how to put the wanted value in the wanted holder, and where a refusal of a type
// is found.
type place struct {
	name string
	typ  reflect.Type
	doc  string
	// want builds the wanted value of the holder from the wanted value of the part.
	want func(part reflect.Value) reflect.Value
	// base and route say where a refusal of the type of the part is found: the path where the error
	// starts and the hops from there to the part.
	base  string
	route []string
}

// placesOf puts a part of type typ and with the text doc in every place that a value can stand:
// at the top, in a struct field, in a struct in a struct, in a map, in a typed list and array, and
// behind a pointer. top says that the part is an object, which may be the document itself; ptr
// says that a pointer to it may be made.
func placesOf(typ reflect.Type, doc string, top, noPointer bool) []place {
	one := func(name string, t reflect.Type) reflect.StructField {
		return reflect.StructField{Name: name, Type: t, Tag: reflect.StructTag(`json:"` + name + `"`)}
	}
	field := reflect.StructOf([]reflect.StructField{one("F", typ)})
	nested := reflect.StructOf([]reflect.StructField{one("Outer", field)})
	var ps []place
	if top {
		ps = append(ps, place{"at the top", typ, doc, func(p reflect.Value) reflect.Value { return p }, "$", nil})
	}
	ps = append(ps,
		place{"in a struct field", field, `{"F":` + doc + `}`, func(p reflect.Value) reflect.Value {
			v := reflect.New(field).Elem()
			v.Field(0).Set(p)
			return v
		}, "$", []string{".F"}},
		place{"in a struct in a struct", nested, `{"Outer":{"F":` + doc + `}}`, func(p reflect.Value) reflect.Value {
			v := reflect.New(nested).Elem()
			v.Field(0).Field(0).Set(p)
			return v
		}, "$", []string{".Outer", ".F"}},
	)
	mt := reflect.MapOf(reflect.TypeFor[string](), typ)
	ps = append(ps, place{"in a map", mt, `{"k":` + doc + `}`, func(p reflect.Value) reflect.Value {
		m := reflect.MakeMap(mt)
		m.SetMapIndex(reflect.ValueOf("k"), p)
		return m
	}, "$", []string{"{}"}})
	if typ.Kind() != reflect.Uint8 {
		lt := reflect.StructOf([]reflect.StructField{one("L", reflect.SliceOf(typ))})
		ps = append(ps, place{"in a typed list", lt, `{"L":[` + doc + `,` + doc + `]}`, func(p reflect.Value) reflect.Value {
			v := reflect.New(lt).Elem()
			s := reflect.MakeSlice(reflect.SliceOf(typ), 2, 2)
			s.Index(0).Set(p)
			s.Index(1).Set(p)
			v.Field(0).Set(s)
			return v
		}, "$", []string{".L", "[]"}})
	}
	at := reflect.StructOf([]reflect.StructField{one("A", reflect.ArrayOf(2, typ))})
	ps = append(ps, place{"in a typed array", at, `{"A":[` + doc + `,` + doc + `]}`, func(p reflect.Value) reflect.Value {
		v := reflect.New(at).Elem()
		v.Field(0).Index(0).Set(p)
		v.Field(0).Index(1).Set(p)
		return v
	}, "$", []string{".A", "[]"}})
	if !noPointer && typ.Kind() != reflect.Pointer {
		pt := reflect.StructOf([]reflect.StructField{one("P", reflect.PointerTo(typ))})
		ps = append(ps, place{"behind a pointer", pt, `{"P":` + doc + `}`, func(p reflect.Value) reflect.Value {
			v := reflect.New(pt).Elem()
			n := reflect.New(typ)
			n.Elem().Set(p)
			v.Field(0).Set(n)
			return v
		}, "$", []string{".P"}})
	}
	return ps
}

func isObjectKind(t reflect.Type) bool {
	return t == rawType || t.Kind() == reflect.Struct || t.Kind() == reflect.Map
}

// read fills a new value of the type typ from doc, and returns it with the error.
func read(typ reflect.Type, doc string, opts Options) (reflect.Value, error) {
	p := reflect.New(typ)
	err := Unmarshal([]byte(doc), p.Interface(), opts)
	return p.Elem(), err
}

func TestUnmarshalFillsEveryKindOfTheClosedSet(t *testing.T) {
	for _, tc := range acceptedTargets() {
		t.Run(tc.name, func(t *testing.T) {
			want := reflect.ValueOf(tc.want)
			if want.Type() != tc.typ {
				t.Fatalf("the test's own value has type %s, not %s", want.Type(), tc.typ)
			}
			for _, p := range placesOf(tc.typ, tc.doc, isObjectKind(tc.typ), false) {
				got, err := read(p.typ, p.doc, Options{})
				if err != nil {
					t.Errorf("%s: %v", p.name, err)
					continue
				}
				if wantAll := p.want(want).Interface(); !reflect.DeepEqual(got.Interface(), wantAll) {
					t.Errorf("%s: the document %s filled %#v, want %#v", p.name, p.doc, got.Interface(), wantAll)
				}
			}
		})
	}
}

func TestUnmarshalFillsAnInterfaceWithNoMethods(t *testing.T) {
	one := func(name string, t reflect.Type) reflect.StructField {
		return reflect.StructField{Name: name, Type: t, Tag: reflect.StructTag(`json:"` + name + `"`)}
	}
	anyT := reflect.TypeFor[any]()
	holders := []struct {
		name string
		typ  reflect.Type
		doc  func(string) string
		want func(any) any
	}{
		{"a struct field", reflect.StructOf([]reflect.StructField{one("F", anyT)}), func(d string) string { return `{"F":` + d + `}` },
			func(w any) any { return map[string]any{"F": w} }},
		{"a map value", reflect.MapOf(reflect.TypeFor[string](), anyT), func(d string) string { return `{"k":` + d + `}` },
			func(w any) any { return map[string]any{"k": w} }},
		{"a slice element", reflect.StructOf([]reflect.StructField{one("L", reflect.SliceOf(anyT))}), func(d string) string { return `{"L":[` + d + `,` + d + `]}` },
			func(w any) any { return map[string]any{"L": []any{w, w}} }},
		{"an array element", reflect.StructOf([]reflect.StructField{one("A", reflect.ArrayOf(1, anyT))}), func(d string) string { return `{"A":[` + d + `]}` },
			func(w any) any { return map[string]any{"A": []any{w}} }},
	}
	for _, tc := range acceptedAnys() {
		t.Run(tc.name, func(t *testing.T) {
			// At the top: the pointer is to an interface, and the document is one object.
			if strings.HasPrefix(tc.doc, "{") {
				var top any
				if err := Unmarshal([]byte(tc.doc), &top, Options{}); err != nil || !reflect.DeepEqual(top, tc.want) {
					t.Errorf("at the top: %#v, %v; want %#v", top, err, tc.want)
				}
			}
			for _, h := range holders {
				got, err := read(h.typ, h.doc(tc.doc), Options{})
				if err != nil {
					t.Errorf("%s: %v", h.name, err)
					continue
				}
				// A struct is read into its field, whose value is the wanted one: compare by the field.
				var have any
				switch got.Kind() {
				case reflect.Struct:
					m := map[string]any{}
					for i := range got.NumField() {
						switch f := got.Field(i); f.Kind() {
						case reflect.Slice, reflect.Array:
							l := []any{}
							for j := range f.Len() {
								l = append(l, f.Index(j).Interface())
							}
							m[got.Type().Field(i).Name] = l
						default:
							m[got.Type().Field(i).Name] = f.Interface()
						}
					}
					have = m
				case reflect.Map:
					have = map[string]any{"k": got.MapIndex(reflect.ValueOf("k")).Interface()}
				}
				if want := h.want(tc.want); !reflect.DeepEqual(have, want) {
					t.Errorf("%s: %#v, want %#v", h.name, have, want)
				}
			}
		})
	}
	t.Run("only five types come out, whatever the document", func(t *testing.T) {
		doc := `{"a":[1,"s",true,false,{"b":[-0,9223372036854775807]},[]],"c":{},"d":"","e":0}`
		var v any
		if err := Unmarshal([]byte(doc), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		var walk func(path string, x any)
		walk = func(path string, x any) {
			switch x := x.(type) {
			case map[string]any:
				for k, e := range x {
					walk(path+"."+k, e)
				}
			case []any:
				for i, e := range x {
					walk(fmt.Sprintf("%s[%d]", path, i), e)
				}
			case string, bool, int64:
			default:
				t.Errorf("%s: %T, which is none of the five", path, x)
			}
		}
		walk("$", v)
	})
}

// ---- the refused types --------------------------------------------------------------------

// A refusedTarget is a Go type that Unmarshal refuses, with the type at fault, the reason and the
// route from the type to the part at fault.
type refusedTarget struct {
	name   string
	typ    reflect.Type
	fault  string // the type at fault, as an error shows it
	reason string
	route  string
	noPtr  bool // the type at fault is the pointer that a pointer place would add
}

func rt[T any](name, fault, reason, route string) refusedTarget {
	typ := reflect.TypeFor[T]()
	// A pointer to an interface is refused as such, so a pointer place does not reach the interface.
	return refusedTarget{name: name, typ: typ, fault: fault, reason: reason, route: route, noPtr: typ.Kind() == reflect.Interface}
}

func refusedTargets() []refusedTarget {
	ch := make(chan int)
	var x int
	_, _ = ch, x
	twice := structOf([]string{"x", "x"}, []reflect.Type{reflect.TypeFor[int](), reflect.TypeFor[int]()}, nil)
	dashes := structOf([]string{"-,", "-,"}, []reflect.Type{reflect.TypeFor[int](), reflect.TypeFor[int]()}, nil)
	tagged := func(tag string) refusedTarget { return refusedTarget{typ: withTag(tag)} }
	badOption := func(name, tag, opt string) refusedTarget {
		r := tagged(tag)
		r.name, r.fault, r.reason = name, withTag(tag).String(), fmt.Sprintf(reasonOption, "F", opt)
		return r
	}
	badName := func(name, tag, shown string) refusedTarget {
		r := tagged(tag)
		r.name, r.fault = name, typeText(withTag(tag))
		r.reason = "field F has the tag name " + shown + "; " + reasonNameRule
		return r
	}
	return []refusedTarget{
		rt[float64]("float64", "float64", reasonFloat, ""),
		rt[float32]("float32", "float32", reasonFloat, ""),
		rt[complex64]("complex64", "complex64", reasonKind, ""),
		rt[complex128]("complex128", "complex128", reasonKind, ""),
		rt[chan int]("a channel", "chan int", reasonKind, ""),
		rt[func()]("a function", "func()", reasonKind, ""),
		rt[uintptr]("uintptr", "uintptr", reasonKind, ""),
		rt[unsafe.Pointer]("an unsafe pointer", "unsafe.Pointer", reasonKind, ""),
		rt[json.Number]("json.Number", "json.Number", reasonNumber, ""),
		rt[jsonVal]("MarshalJSON on the value", "strictjson.jsonVal", reasonJSON, ""),
		rt[jsonPtr]("MarshalJSON on the pointer only", "strictjson.jsonPtr", reasonJSON, ""),
		rt[textVal]("MarshalText on the value", "strictjson.textVal", reasonText, ""),
		rt[textPtr]("MarshalText on the pointer only", "strictjson.textPtr", reasonText, ""),
		rt[unmarshalVal]("UnmarshalJSON on the pointer", "strictjson.unmarshalVal", reasonUJSON, ""),
		rt[unmarshalTxt]("UnmarshalText on the pointer", "strictjson.unmarshalTxt", reasonUText, ""),
		rt[time.Time]("time.Time", "time.Time", reasonJSON, ""),
		rt[struct{ T time.Time }]("a struct with a Time", "time.Time", reasonJSON, ".T"),
		rt[json.RawMessage]("json.RawMessage", reflect.TypeFor[json.RawMessage]().String(), reasonJSON, ""),
		rt[[]textByte]("a slice of a type with a text method", "strictjson.textByte", reasonText, "[]"),
		rt[map[textKey]int]("a map with a key that writes text", "strictjson.textKey", reasonText, ""),
		rt[map[int]string]("a map with an integer key", "map[int]string", reasonMapKey, ""),
		rt[map[uint8]string]("a map with a uint8 key", "map[uint8]string", reasonMapKey, ""),
		rt[map[point]int]("a map with a key that is a struct", "map[strictjson.point]int", reasonMapKey, ""),
		rt[map[[1]int]int]("a map with a key that is an array", "map[[1]int]int", reasonMapKey, ""),
		rt[map[bool]int]("a map with a bool key", "map[bool]int", reasonMapKey, ""),
		rt[map[any]int]("a map with an interface key", "map[interface {}]int", reasonMapKey, ""),
		rt[map[float64]int]("a map with a float key", "map[float64]int", reasonMapKey, ""),
		rt[map[*string]int]("a map with a pointer key", "map[*string]int", reasonMapKey, ""),
		rt[map[int]float64]("a map with an integer key and float values", "map[int]float64", reasonMapKey, ""),
		{name: "a pointer to a pointer", typ: reflect.TypeFor[**int](), fault: "**int", reason: reasonPtrPtr, noPtr: true},
		{name: "a pointer to an interface", typ: reflect.TypeFor[*any](), fault: "*interface {}", reason: reasonPtrPtr, noPtr: true},
		{name: "a pointer to a pointer to a struct", typ: reflect.TypeFor[**point](), fault: "**strictjson.point", reason: reasonPtrPtr, noPtr: true},
		{name: "a pointer to an interface with methods", typ: reflect.TypeFor[*shower](), fault: "*strictjson.shower", reason: reasonPtrPtr, noPtr: true},
		rt[embedsValue]("an embedded struct", "strictjson.embedsValue", fmt.Sprintf(reasonEmbed, "embeddedBase"), ""),
		rt[embedsPointer]("an embedded pointer to a struct", "strictjson.embedsPointer", fmt.Sprintf(reasonEmbed, "embeddedBase"), ""),
		rt[embedsExport]("an embedded struct with an exported name", "strictjson.embedsExport", fmt.Sprintf(reasonEmbed, "Exported"), ""),
		rt[embedsInt]("an embedded integer type", "strictjson.embedsInt", fmt.Sprintf(reasonEmbed, "myInt"), ""),
		rt[withEmbedded]("an embedded struct beside a named field", "strictjson.withEmbedded", fmt.Sprintf(reasonEmbed, "Base"), ""),
		rt[optString]("the tag option string", "strictjson.optString", fmt.Sprintf(reasonOption, "F", "string"), ""),
		rt[optNamedString]("the tag option string after a name", "strictjson.optNamedString", fmt.Sprintf(reasonOption, "F", "string"), ""),
		rt[optInline]("the tag option inline", "strictjson.optInline", fmt.Sprintf(reasonOption, "F", "inline"), ""),
		rt[optOmitZero]("the tag option omitzero", "strictjson.optOmitZero", fmt.Sprintf(reasonOption, "F", "omitzero"), ""),
		rt[optSecond]("a refused option after omitempty", "strictjson.optSecond", fmt.Sprintf(reasonOption, "F", "string"), ""),
		badOption("an empty tag option", `json:"f,,omitempty"`, ""),
		badName("a tag name with an apostrophe", `json:"a'b"`, `"a'b"`),
		badName("a tag name with a backslash", `json:"a\\b"`, `"a\\b"`),
		badName("a tag name with a symbol that is not a letter", "json:\"a"+string(rune(0x20ac))+"b\"", `"a`+uesc(0x20ac)+`b"`),
		badName("a tag name with a dot", `json:"a.b"`, `"a.b"`),
		badName("a tag name with a hyphen", `json:"a-b"`, `"a-b"`),
		badName("a tag name with a space", `json:"a b"`, `"a b"`),
		badName("a tag name that is a dash and a comma", `json:"-,"`, `"-"`),
		badName("a tag name that is a dash and omitempty", `json:"-,omitempty"`, `"-"`),
		{name: "two fields of one name", typ: twice, fault: twice.String(), reason: fmt.Sprintf(reasonTwice, "x")},
		{name: "a tag name that is another field's name", typ: reflect.TypeFor[nameAsField](), fault: "strictjson.nameAsField", reason: fmt.Sprintf(reasonTwice, "A")},
		// Both are refused at the first, as a name: the dash is no name of a member.
		{name: "two fields named dash", typ: dashes, fault: dashes.String(), reason: "field F0 has the tag name \"-\"; " + reasonNameRule},
		rt[floatField]("a float field", "float64", reasonFloat, ".G"),
		rt[floatFieldOmit]("a float field with omitempty", "float64", reasonFloat, ".G"),
		rt[floatPtrOmit]("a pointer to a float with omitempty", "*float64", reasonFloat, ".P"),
		rt[holdsFloats]("a float two structs down", "float64", reasonFloat, ".Inner.G"),
		rt[[]float64]("a slice of floats", "float64", reasonFloat, "[]"),
		rt[[0]float64]("an empty array of floats", "float64", reasonFloat, "[]"),
		rt[map[string]float64]("a map of floats", "float64", reasonFloat, "{}"),
		rt[[]*float64]("a slice of pointers to floats", "*float64", reasonFloat, "[]"),
		rt[[][]float64]("a slice of lists of floats", "float64", reasonFloat, "[][]"),
		rt[map[string][]map[string]float64]("a map of lists of maps of floats", "float64", reasonFloat, "{}[]{}"),
		rt[[]holdsFloats]("a list of structs with a float", "float64", reasonFloat, "[].Inner.G"),
		rt[[]chan int]("a slice of channels", "chan int", reasonKind, "[]"),
		rt[[]json.Number]("a slice of json.Number", "json.Number", reasonNumber, "[]"),
		rt[[]jsonVal]("a slice of a type with a method", "strictjson.jsonVal", reasonJSON, "[]"),
		rt[[]embedsValue]("a slice of embedding structs", "strictjson.embedsValue", fmt.Sprintf(reasonEmbed, "embeddedBase"), "[]"),
		rt[map[string]textVal]("a map of a type with a method", "strictjson.textVal", reasonText, "{}"),
		rt[[]**int]("a slice of pointers to pointers", "**int", reasonPtrPtr, "[]"),
		rt[recursiveFloat]("a recursive type with a float", "float64", reasonFloat, ".F"),
		// The one thing that is refused for reading and not for writing.
		rt[shower]("an interface with methods", "strictjson.shower", reasonIface, ""),
		rt[error]("error", "error", reasonIface, ""),
		rt[fmt.Stringer]("fmt.Stringer", "fmt.Stringer", reasonIface, ""),
		rt[[]shower]("a slice of interfaces with methods", "strictjson.shower", reasonIface, "[]"),
		rt[map[string]error]("a map of interfaces with methods", "error", reasonIface, "{}"),
		rt[struct{ S shower }]("a struct with an interface with methods", "strictjson.shower", reasonIface, ".S"),
		rt[[1]fmt.Stringer]("an array of interfaces with methods", "fmt.Stringer", reasonIface, "[]"),
	}
}

func TestUnmarshalRefusesEveryKindOutsideTheClosedSet(t *testing.T) {
	for _, tc := range refusedTargets() {
		t.Run(tc.name, func(t *testing.T) {
			// own: the type at fault is the type itself. Such a type behind a pointer is named as the
			// caller wrote it, with its pointer.
			own := typeText(tc.typ) == tc.fault
			route := splitRoute(tc.route)
			// The document is not looked at: not JSON at all, or fine, the refusal is the same.
			for _, doc := range []string{`not json`, `{}`, ``, `{"F":1.5}`} {
				for _, p := range placesOf(tc.typ, "null", false, tc.noPtr) {
					fault := tc.fault
					if own && len(route) == 0 && p.name == "behind a pointer" {
						fault = "*" + fault
					}
					want := cannotRead(p.base, append(slices.Clone(p.route), route...), fault, tc.reason)
					checkRefusedType(t, reflect.New(p.typ).Interface(), doc, want, p.name)
				}
				// At the top, and behind a pointer at the top.
				checkRefusedType(t, reflect.New(tc.typ).Interface(), doc, cannotRead("$", route, tc.fault, tc.reason), "at the top")
				if !tc.noPtr {
					pointer := tc.fault
					if own && len(route) == 0 {
						pointer = "*" + pointer
					}
					checkRefusedType(t, reflect.New(reflect.PointerTo(tc.typ)).Interface(), doc, cannotRead("$", route, pointer, tc.reason), "behind a pointer at the top")
				}
				if t.Failed() {
					return
				}
			}
		})
	}
	t.Run("time.Duration is an integer and is read", func(t *testing.T) {
		var d struct{ D time.Duration }
		if err := Unmarshal([]byte(`{"D":5}`), &d, Options{}); err != nil || d.D != 5 {
			t.Errorf("%v, %v", d, err)
		}
	})
}

// checkRefusedType checks that Unmarshal into the pointer v refuses the type with the text, wraps
// ErrMalformed, and leaves what v points to as it was.
func checkRefusedType(t *testing.T, v any, doc, want, where string) {
	t.Helper()
	before := deepCopy(reflect.ValueOf(v).Elem())
	err := Unmarshal([]byte(doc), v, Options{})
	if err == nil {
		t.Errorf("%s: Unmarshal of %q into %T filled it", where, doc, v)
		return
	}
	if !errors.Is(err, ErrMalformed) {
		t.Errorf("%s: the error does not wrap ErrMalformed: %v", where, err)
	}
	if err.Error() != want {
		t.Errorf("%s: into %T the error is\n  %q\nwant\n  %q", where, v, err, want)
	}
	if !reflect.DeepEqual(before.Interface(), reflect.ValueOf(v).Elem().Interface()) {
		t.Errorf("%s: the value changed", where)
	}
}

// deepCopy copies a value of the kinds that the tests use, keeping what is nil nil and what is
// empty empty, so that a value can be compared with itself after a call.
func deepCopy(v reflect.Value) reflect.Value {
	out := reflect.New(v.Type()).Elem()
	copyInto(out, v)
	return out
}

func copyInto(dst, src reflect.Value) {
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		n := reflect.New(src.Type().Elem())
		copyInto(n.Elem(), src.Elem())
		dst.Set(n)
	case reflect.Interface:
		if src.IsNil() {
			return
		}
		inner := reflect.New(src.Elem().Type()).Elem()
		copyInto(inner, src.Elem())
		dst.Set(inner)
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		s := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := range src.Len() {
			copyInto(s.Index(i), src.Index(i))
		}
		dst.Set(s)
	case reflect.Array:
		for i := range src.Len() {
			copyInto(dst.Index(i), src.Index(i))
		}
	case reflect.Map:
		if src.IsNil() {
			return
		}
		m := reflect.MakeMapWithSize(src.Type(), src.Len())
		iter := src.MapRange()
		for iter.Next() {
			e := reflect.New(src.Type().Elem()).Elem()
			copyInto(e, iter.Value())
			m.SetMapIndex(iter.Key(), e)
		}
		dst.Set(m)
	case reflect.Struct:
		// The whole struct first, which copies what is not exported as it is, and then each exported
		// field again, deeply.
		dst.Set(src)
		for i := range src.NumField() {
			if src.Type().Field(i).IsExported() {
				dst.Field(i).Set(reflect.Zero(src.Field(i).Type()))
				copyInto(dst.Field(i), src.Field(i))
			}
		}
	default:
		dst.Set(src)
	}
}

// ---- the rule for the value that is passed in ---------------------------------------------

func TestUnmarshalRootRule(t *testing.T) {
	objectAt := func(t reflect.Type) string {
		return fmt.Sprintf("%s: $: a value of type %s cannot be read: %s", ErrMalformed, t, reasonTopKind)
	}
	doc := []byte(`{"X":1}`)
	t.Run("what v may be", func(t *testing.T) {
		var s point
		var m map[string]int
		var r Raw
		var a any
		var ps *point
		var pm *map[string]int
		var pr *Raw
		for name, v := range map[string]any{
			"a pointer to a struct":                &s,
			"a pointer to a map":                   &m,
			"a pointer to a Raw":                   &r,
			"a pointer to an interface":            &a,
			"a pointer to a nil pointer to struct": &ps,
			"a pointer to a nil pointer to a map":  &pm,
			"a pointer to a nil pointer to a Raw":  &pr,
		} {
			if err := Unmarshal(doc, v, Options{AllowUnknown: true}); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
		if s != (point{X: 1}) || !reflect.DeepEqual(m, map[string]int{"X": 1}) || string(r) != `{"X":1}` || !reflect.DeepEqual(a, map[string]any{"X": int64(1)}) ||
			ps == nil || *ps != (point{X: 1}) || pm == nil || (*pm)["X"] != 1 || pr == nil || string(*pr) != `{"X":1}` {
			t.Errorf("the values are %v %v %q %v %v %v %v", s, m, r, a, ps, pm, pr)
		}
	})
	t.Run("what v may not be, as a type", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			v    any
			typ  reflect.Type
		}{
			{"a pointer to a string", new(string), reflect.TypeFor[string]()},
			{"a pointer to an integer", new(int), reflect.TypeFor[int]()},
			{"a pointer to a bool", new(bool), reflect.TypeFor[bool]()},
			{"a pointer to a slice", new([]int), reflect.TypeFor[[]int]()},
			{"a pointer to a slice of bytes", new([]byte), reflect.TypeFor[[]byte]()},
			{"a pointer to an array", new([2]int), reflect.TypeFor[[2]int]()},
			{"a pointer to a pointer to an integer", new(*int), reflect.TypeFor[*int]()},
			{"a pointer to a pointer to a slice", new(*[]int), reflect.TypeFor[*[]int]()},
			{"a pointer to a named string", new(myString), reflect.TypeFor[myString]()},
		} {
			err := Unmarshal(doc, tc.v, Options{})
			if want := objectAt(tc.typ); err == nil || err.Error() != want || !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: %v, want %q", tc.name, err, want)
			}
		}
	})
	t.Run("what v may not be, because the type is refused", func(t *testing.T) {
		var fl float64
		var e error
		var st fmt.Stringer
		var pa *any
		var ppp **point
		for _, tc := range []struct {
			name string
			v    any
			want string
		}{
			{"a pointer to a float", &fl, cannotRead("$", nil, "float64", reasonFloat)},
			{"a pointer to an interface with methods", &e, cannotRead("$", nil, "error", reasonIface)},
			{"a pointer to fmt.Stringer", &st, cannotRead("$", nil, "fmt.Stringer", reasonIface)},
			{"a pointer to a pointer to an interface", &pa, cannotRead("$", nil, "*interface {}", reasonPtrPtr)},
			{"a pointer to a pointer to a pointer", &ppp, cannotRead("$", nil, "**strictjson.point", reasonPtrPtr)},
		} {
			err := Unmarshal(doc, tc.v, Options{})
			if err == nil || err.Error() != tc.want {
				t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
			}
		}
	})
	t.Run("a mistake of the caller is not ErrMalformed", func(t *testing.T) {
		var np *point
		var nm *map[string]int
		var ni *any
		var nr *Raw
		for name, v := range map[string]any{
			"nil":                           nil,
			"a nil pointer to a struct":     np,
			"a nil pointer to a map":        nm,
			"a nil pointer to an interface": ni,
			"a nil pointer to a Raw":        nr,
			"a struct":                      point{},
			"a map":                         map[string]int{},
			"a Raw":                         Raw(`{}`),
			"an interface holding a struct": any(point{}),
			"an integer":                    3,
			"a string":                      "x",
			"a slice":                       []int{},
			"a function":                    func() {},
			"a channel":                     make(chan int),
		} {
			err := Unmarshal(doc, v, Options{})
			if err == nil {
				t.Errorf("%s: no error", name)
			} else if errors.Is(err, ErrMalformed) {
				t.Errorf("%s: a mistake of the caller wraps ErrMalformed: %v", name, err)
			}
		}
	})
	t.Run("a pointer to an interface that holds nothing, or a pointer, is filled", func(t *testing.T) {
		var a any
		if err := Unmarshal(doc, &a, Options{}); err != nil {
			t.Fatal(err)
		}
		held := &point{X: 5}
		a = held
		if err := Unmarshal(doc, &a, Options{}); err != nil {
			t.Fatal(err)
		}
		if _, ok := a.(map[string]any); !ok {
			t.Errorf("the interface holds %T", a)
		}
		if *held != (point{X: 5}) {
			t.Errorf("what the interface pointed to was filled: %v", *held)
		}
	})
	t.Run("a Raw at the top is the object without the white space around it", func(t *testing.T) {
		for _, tc := range []struct{ in, want string }{
			{` {"a":1} `, `{"a":1}`},
			{"\n\t{ \"a\" : [ 1 ] }\r\n", `{ "a" : [ 1 ] }`},
			{`{}`, `{}`},
			{"  { }  ", `{ }`},
		} {
			var r Raw
			if err := Unmarshal([]byte(tc.in), &r, Options{}); err != nil || string(r) != tc.want {
				t.Errorf("%q: %q, %v; want %q", tc.in, r, err, tc.want)
			}
		}
	})
	t.Run("the document is judged after the type", func(t *testing.T) {
		// A type that is refused is refused whatever the document says, and a fine type with a bad
		// document is refused for the document.
		var fl float64
		err := Unmarshal([]byte(`not json`), &fl, Options{})
		if want := cannotRead("$", nil, "float64", reasonFloat); err == nil || err.Error() != want {
			t.Errorf("%v, want %q", err, want)
		}
		var s point
		err = Unmarshal([]byte(`not json`), &s, Options{})
		if want := ErrMalformed.Error() + ": $: not one JSON object"; err == nil || err.Error() != want {
			t.Errorf("%v, want %q", err, want)
		}
	})
}

// ---- the table agrees with itself ---------------------------------------------------------

func TestTheTablesCoverTheSetAndAreNotEmpty(t *testing.T) {
	kinds := map[reflect.Kind]bool{}
	for _, tc := range acceptedTargets() {
		kinds[tc.typ.Kind()] = true
	}
	for _, k := range []reflect.Kind{reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.String,
		reflect.Slice, reflect.Array, reflect.Map, reflect.Struct, reflect.Pointer} {
		if !kinds[k] {
			t.Errorf("no accepted target of kind %v", k)
		}
	}
	// No refused type is also an accepted one.
	accepted := map[reflect.Type]bool{}
	for _, tc := range acceptedTargets() {
		accepted[tc.typ] = true
	}
	for _, tc := range refusedTargets() {
		if accepted[tc.typ] {
			t.Errorf("%s is in both tables", tc.name)
		}
	}
	// Every target in the table is distinct in what it says, so that a mistake of copying shows.
	seen := map[string]bool{}
	for _, tc := range acceptedTargets() {
		if seen[tc.name] {
			t.Errorf("two accepted targets are named %q", tc.name)
		}
		seen[tc.name] = true
	}
	_ = bytes.Equal
}
