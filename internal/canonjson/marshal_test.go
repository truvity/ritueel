package canonjson

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
)

// The tests of Marshal, a writer of its own over a closed set of Go types. A JSON escape of the
// form backslash, u and four digits is never written out in these files: where a test needs one
// it is built from a backslash or from a code point, so that no tool can turn it into the
// character on the way.

// The reasons of the refusals and the other fixed texts, as the source words them.
const (
	reasonFloat    = "a float; ritueel's JSON holds integers only"
	reasonKind     = "this kind of Go type is not part of ritueel's JSON"
	reasonNumber   = "a json.Number is not part of ritueel's JSON; use an integer type"
	reasonJSON     = "the type has a MarshalJSON method; only Raw carries JSON of its own"
	reasonText     = "the type has a MarshalText method; only Raw carries JSON of its own"
	reasonPtrPtr   = "a pointer to a pointer or to an interface is not part of ritueel's JSON"
	reasonMapKey   = "only a map with a key of kind string is part of ritueel's JSON"
	reasonNilPtr   = "a nil pointer is JSON null"
	reasonNilIface = "a nil interface is JSON null"
	reasonNilMap   = "a nil map is JSON null"
	reasonNilSlice = "a nil slice is JSON null"
	notUTF8String  = "a string that is not valid UTF-8 cannot be written"
	notUTF8Name    = "a member name that is not valid UTF-8 cannot be written"
)

// malformedText is the error text of a refusal, as strictjson.ErrMalformed starts it.
const bsl = "\\" // a backslash

func malformedText(format string, args ...any) string {
	return strictjson.ErrMalformed.Error() + ": " + fmt.Sprintf(format, args...)
}

// tooDeepText is the text of a refusal by nesting that the writer itself gives, at the path of
// the container that passed the limit.
func tooDeepText(path string) string {
	return malformedText("%s: nesting deeper than %d levels", path, strictjson.MaxDepth)
}

// tooLongAt is the text of a refusal by size, at the path of the value that took the form over the
// limit.
func tooLongAt(path string) string {
	return malformedText("%s: the canonical form is longer than %d bytes", path, strictjson.DefaultMaxBytes)
}

// stepsPath is the path that an error shows for a value that is reached by these steps from the top:
// "$", then "..." and the last eight steps when there are more than eight.
func stepsPath(steps []string) string {
	if len(steps) > 8 {
		return "$..." + strings.Join(steps[len(steps)-8:], "")
	}
	return "$" + strings.Join(steps, "")
}

// cyclePath is the path of the value that is the n-th step down a way that goes round a cycle of
// steps, after the steps of lead.
func cyclePath(lead []string, cycle []string, n int) string {
	var steps []string
	steps = append(steps, lead...)
	for i := 0; len(steps) < n; i++ {
		steps = append(steps, cycle[i%len(cycle)])
	}
	return stepsPath(steps[:n])
}

// cannotWrite is the text of the refusal of a Go type at a path, when the refusal is reached by
// fields only or from the type itself.
func cannotWrite(path, typ, reason string) string {
	return malformedText("%s: a value of type %s cannot be written: %s", path, typ, reason)
}

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

// cannotWriteVia is the text of the refusal of the Go type typ that is reached from the value at
// base by the route.
func cannotWriteVia(base string, route []string, typ, reason string) string {
	path, where := routeText(base, route)
	return malformedText("%s: a value of type %s cannot be written%s: %s", path, typ, where, reason)
}

// uesc is the six-byte escape of a character of the BMP, in lower case.
func uesc(r rune) string { return fmt.Sprintf("\\u%04x", r) }

// sameBytes compares two large results without printing them.
func sameBytes(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if string(got) == want {
		return
	}
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	t.Errorf("%s: %d bytes, want %d; they differ at byte %d", what, len(got), len(want), i)
}

// refused checks one refusal of Marshal: the error wraps ErrMalformed, its text is the one given,
// and nothing is returned, not even an empty slice.
func refused(t *testing.T, got []byte, err error, wantText string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Marshal wrote %.100s (%d bytes), want the refusal %q", got, len(got), wantText)
	}
	if !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("the error does not wrap ErrMalformed: %v", err)
	}
	if err.Error() != wantText {
		t.Errorf("the error is\n  %q\nwant\n  %q", err, wantText)
	}
	if got != nil {
		t.Errorf("Marshal returned %d bytes next to an error, want nil", len(got))
	}
}

// refusedWith is refused for an error whose text only has to start or contain a part.
func refusedWith(t *testing.T, got []byte, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Marshal wrote %.100s (%d bytes)", got, len(got))
	}
	if !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("the error does not wrap ErrMalformed: %v", err)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Errorf("the error is %q, want it to contain %q", err, contains)
	}
	if got != nil {
		t.Errorf("Marshal returned %d bytes next to an error, want nil", len(got))
	}
}

// ---- types of the tests -------------------------------------------------------------------

type (
	myInt    int
	myBool   bool
	myString string
	myKey    string
	myBytes  []byte
	point    struct{ X, Y int }
	// A type that has a method of the same name as one that is refused, but no MarshalJSON or
	// MarshalText, is an ordinary type.
	marshalish struct{ N int }
)

func (marshalish) Marshal() ([]byte, error) { return nil, errors.New("not called") }

// Types that write their own JSON or text, or are refused for another reason of their own.
type (
	jsonVal  struct{ N int } // MarshalJSON on the value
	jsonPtr  struct{ N int } // MarshalJSON on the pointer only
	textVal  string          // MarshalText on the value
	textPtr  struct{ N int } // MarshalText on the pointer only
	bothVal  struct{ N int } // both, on the value
	textKey  string          // a key type that writes text
	textByte byte            // an element type that writes text
)

func (jsonVal) MarshalJSON() ([]byte, error)  { return []byte(`{}`), nil }
func (*jsonPtr) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }
func (textVal) MarshalText() ([]byte, error)  { return []byte("x"), nil }
func (*textPtr) MarshalText() ([]byte, error) { return []byte("x"), nil }
func (bothVal) MarshalJSON() ([]byte, error)  { return []byte(`{}`), nil }
func (bothVal) MarshalText() ([]byte, error)  { return []byte("x"), nil }
func (textKey) MarshalText() ([]byte, error)  { return []byte("k"), nil }
func (textByte) MarshalText() ([]byte, error) { return []byte("b"), nil }

// Structs that are refused as types.
type (
	embeddedBase   struct{ X int }
	embedsValue    struct{ embeddedBase }
	embedsPointer  struct{ *embeddedBase }
	embedsExported struct{ Exported }
	embedsInt      struct{ myInt }
	optString      struct {
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
	// Exported is an embedded type with an exported name.
	Exported struct{ X int }
)

// Types of writable values.
type (
	listNode struct {
		Next *listNode `json:",omitempty"`
	}
	mutualA struct {
		B *mutualB `json:",omitempty"`
	}
	mutualB struct {
		A *mutualA `json:",omitempty"`
	}
	recursiveFloat struct {
		Next *recursiveFloat `json:",omitempty"`
		F    float64         `json:",omitempty"`
	}
)

func ptr[T any](v T) *T { return &v }

// withTag is a struct with one field F of type int and the given tag, for a tag that a source file
// could not carry through go vet. tagType is the name of its type, as an error shows it.
func withTag(t *testing.T, tag string) any {
	t.Helper()
	st := reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[int](), Tag: reflect.StructTag(tag)}})
	return reflect.New(st).Elem().Interface()
}

// goNamed is a value of a struct with one exported field of the Go name given and no tag.
func goNamed(t *testing.T, goName string) any {
	t.Helper()
	return reflect.New(reflect.StructOf([]reflect.StructField{{Name: goName, Type: reflect.TypeFor[int]()}})).Elem().Interface()
}

func goNamedType(t *testing.T, goName string) string {
	t.Helper()
	return typeText(reflect.TypeOf(goNamed(t, goName)))
}

func tagType(t *testing.T, tag string) string {
	t.Helper()
	return typeText(reflect.TypeOf(withTag(t, tag)))
}

// tagged is a struct with one int field F0, F1, ... for each tag, written as the tag says (a tag
// is the whole text, `json:"x"` or `xml:"x"` or empty), with the values.
func tagged(t *testing.T, tags []string, values []int) any {
	t.Helper()
	var fields []reflect.StructField
	for i, tag := range tags {
		fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: reflect.TypeFor[int](), Tag: reflect.StructTag(tag)})
	}
	sv := reflect.New(reflect.StructOf(fields)).Elem()
	for i, v := range values {
		sv.Field(i).SetInt(int64(v))
	}
	return sv.Interface()
}

// ---- the closed set, one table ------------------------------------------------------------

// accepted is every kind that Marshal writes, with the exact bytes of its value.
func acceptedValues() []struct {
	name string
	v    any
	want string
} {
	bs := string(rune(92))
	emoji, dalet := string(rune(0x1F600)), string(rune(0xFB33))
	return []struct {
		name string
		v    any
		want string
	}{
		{"bool true", true, `true`},
		{"bool false", false, `false`},
		{"int", int(-5), `-5`},
		{"int zero", int(0), `0`},
		{"int8 smallest", int8(math.MinInt8), `-128`},
		{"int8 largest", int8(math.MaxInt8), `127`},
		{"int16", int16(math.MinInt16), `-32768`},
		{"int32", int32(math.MinInt32), `-2147483648`},
		{"int64 smallest of the range", safeMin, `-9007199254740991`},
		{"int64 largest of the range", safeMax, `9007199254740991`},
		{"uint", uint(7), `7`},
		{"uint8 largest", uint8(math.MaxUint8), `255`},
		{"uint16 largest", uint16(math.MaxUint16), `65535`},
		{"uint32 largest", uint32(math.MaxUint32), `4294967295`},
		{"uint64 at the largest of the range", uint64(safeMax), `9007199254740991`},
		{"uint64 zero", uint64(0), `0`},
		{"named int", myInt(-3), `-3`},
		{"named bool", myBool(true), `true`},
		{"named string", myString("x"), `"x"`},
		{"empty string", "", `""`},
		{"plain string", "abc", `"abc"`},
		{"quote and backslash", `"\`, `"` + bs + `"` + bs + bs + `"`},
		{"short control escapes", "\b\t\n\f\r", `"` + bs + "b" + bs + "t" + bs + "n" + bs + "f" + bs + `r"`},
		{"other controls in lower case", "\x00\x01\x1f", `"` + uesc(0) + uesc(1) + uesc(0x1f) + `"`},
		{"delete and slash and markup as they are", "\x7f/<>&'", "\"\x7f/<>&'\""},
		{"separators as they are", string(rune(0x2028)) + string(rune(0x2029)), `"` + string(rune(0x2028)) + string(rune(0x2029)) + `"`},
		{"text outside ASCII", "é€" + emoji + dalet, "\"é€" + emoji + dalet + "\""},
		{"the replacement character itself", string(rune(0xFFFD)), "\"" + string(rune(0xFFFD)) + "\""},
		{"bytes, none", []byte{}, `""`},
		{"bytes, one", []byte{0}, `"AA=="`},
		{"bytes, two", []byte("hi"), `"aGk="`},
		{"bytes, three", []byte("abc"), `"YWJj"`},
		{"bytes that need the plus and the slash", []byte{0xfb, 0xff, 0xbf}, `"+/+/"`},
		{"a named slice of bytes", myBytes("hi"), `"aGk="`},
		{"an array of bytes is a list", [3]byte{1, 2, 3}, `[1,2,3]`},
		{"an empty array", [0]int{}, `[]`},
		{"an array of strings", [2]string{"a", "b"}, `["a","b"]`},
		{"an empty slice", []int{}, `[]`},
		{"a slice keeps its order", []int{3, 1, 2}, `[3,1,2]`},
		{"a slice of bools", []bool{true, false}, `[true,false]`},
		{"a slice of slices", [][]int{{1}, {}}, `[[1],[]]`},
		{"a slice of byte slices", [][]byte{[]byte("hi"), {}}, `["aGk=",""]`},
		{"a slice of any", []any{1, "a", true, []any{}, map[string]any{}}, `[1,"a",true,[],{}]`},
		{"an empty map", map[string]int{}, `{}`},
		{"a map is sorted", map[string]int{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"a map with a named key type", map[myKey]bool{"x": true}, `{"x":true}`},
		{"a map of lists", map[string][]int{"k": {1}}, `{"k":[1]}`},
		{"a map sorted as UTF-16", map[string]int{emoji: 1, dalet: 2, "z": 3}, "{\"z\":3,\"" + emoji + "\":1,\"" + dalet + "\":2}"},
		{"a map of bytes", map[string][]byte{"k": []byte("hi")}, `{"k":"aGk="}`},
		{"a struct", point{X: 1, Y: 2}, `{"X":1,"Y":2}`},
		{"an empty struct", struct{}{}, `{}`},
		{"a struct leaves out its unexported fields", struct {
			A int
			b int
		}{A: 1, b: 2}, `{"A":1}`},
		{"a struct with a method of another name", marshalish{N: 1}, `{"N":1}`},
		{"a pointer to an integer", ptr(5), `5`},
		{"a pointer to a string", ptr("s"), `"s"`},
		{"a pointer to a struct", &point{X: 1}, `{"X":1,"Y":0}`},
		{"a pointer to a slice", ptr([]int{1}), `[1]`},
		{"a pointer to a slice of bytes", ptr([]byte("hi")), `"aGk="`},
		{"a pointer to a map", ptr(map[string]int{"a": 1}), `{"a":1}`},
		{"a pointer to an array", ptr([1]int{4}), `[4]`},
		{"a slice of pointers", []*int{ptr(1), ptr(2)}, `[1,2]`},
		{"a Raw", Raw(`{"b":1,"a":[2, 3]}`), `{"a":[2,3],"b":1}`},
		{"a slice of Raw", []Raw{Raw(`{"b":1}`), Raw(` {"a" : 2} `)}, `[{"b":1},{"a":2}]`},
		{"a map of Raw", map[string]Raw{"k": Raw(`{ }`)}, `{"k":{}}`},
		{"a struct of every kind", struct {
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
		}{true, -1, 2, "s", []string{"a"}, map[string]int{"k": 1}, ptr(3), [1]bool{true}, Raw(`{"z":0}`), []byte("hi"), struct{}{}},
			`{"A":[true],"B":true,"I":-1,"L":["a"],"M":{"k":1},"P":3,"Q":{},"R":{"z":0},"S":"s","U":2,"Y":"aGk="}`},
	}
}

// place is one position for a value in a document: how to build the document and the path of the
// value in it.
type place struct {
	name string
	doc  any
	// path is the path of the value in the document; for a value that a list or a map holds it is
	// the path of the element or the member, which a refusal by the value shows.
	path string
	// base and route say where a refusal of the type of the value is found: the path where the
	// error starts and the hops from there to the value (see routeText). A type has no index and no
	// member name in a list or a map, so there the route says "the elements of" or "the values of".
	base  string
	route []string
}

// places puts v where a value can stand: at the top, in a struct field, in a struct in a struct, in
// a map, in a typed list and array, in a list of any, in an interface and behind a pointer. v must
// not be a nil interface. byValue says that the refusal is decided by the value (a nil, a text, an
// integer too large) and not by the type; noPointer leaves out the pointer position. The pointer
// position is also left out for a pointer and for a Raw (see TestAPointerToRawIsWrittenLikeAPointerToAnyAcceptedType). A list of
// uint8 is a string, so a byte has no typed list.
func places(v any, byValue, noPointer bool) []place {
	val := reflect.ValueOf(v)
	t := val.Type()
	fieldOf := func(name string, ft reflect.Type, fv reflect.Value) reflect.Value {
		st := reflect.StructOf([]reflect.StructField{{Name: name, Type: ft, Tag: reflect.StructTag(`json:"` + name + `"`)}})
		sv := reflect.New(st).Elem()
		sv.Field(0).Set(fv)
		return sv
	}
	field := fieldOf("F", t, val)
	nested := fieldOf("Outer", field.Type(), field)
	mv := reflect.MakeMap(reflect.MapOf(reflect.TypeFor[string](), t))
	mv.SetMapIndex(reflect.ValueOf("k"), val)
	// A refusal that the value decides is at the value, which has an index in a list and a name in
	// a map; one that the type decides is found when the map or the list itself is reached.
	index, mapPath := "", "$"
	if byValue {
		index, mapPath = "[0]", "$.k"
	}
	ps := []place{
		{"at the top", v, "$", "$", nil},
		{"in a struct field", field.Interface(), "$.F", "$", []string{".F"}},
		{"in a struct in a struct", nested.Interface(), "$.Outer.F", "$", []string{".Outer", ".F"}},
		{"in a map", mv.Interface(), mapPath, "$", []string{"{}"}},
		{"in an interface", map[string]any{"i": v}, "$.i", "$.i", nil},
		{"in a list of any", map[string]any{"l": []any{1, v}}, "$.l[1]", "$.l[1]", nil},
	}
	if t.Kind() != reflect.Uint8 {
		sl := reflect.MakeSlice(reflect.SliceOf(t), 1, 1)
		sl.Index(0).Set(val)
		arr := reflect.New(reflect.ArrayOf(1, t)).Elem()
		arr.Index(0).Set(val)
		ps = append(ps,
			place{"in a typed list", map[string]any{"l": sl.Interface()}, "$.l" + index, "$.l", []string{"[]"}},
			place{"in a typed array", map[string]any{"a": arr.Interface()}, "$.a" + index, "$.a", []string{"[]"}})
	}
	if !noPointer && t.Kind() != reflect.Pointer && t != rawType {
		p := reflect.New(t)
		p.Elem().Set(val)
		ps = append(ps, place{"behind a pointer", map[string]any{"p": p.Interface()}, "$.p", "$.p", nil})
	}
	return ps
}

func TestMarshalWritesEveryKindOfTheClosedSet(t *testing.T) {
	for _, tc := range acceptedValues() {
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range places(tc.v, false, false) {
				if p.name == "at the top" {
					if !strings.HasPrefix(tc.want, "{") {
						continue
					}
					got, err := Marshal(p.doc)
					if err != nil || string(got) != tc.want {
						t.Errorf("at the top: %q, %v; want %q", got, err, tc.want)
					}
					continue
				}
				got, err := Marshal(p.doc)
				if err != nil {
					t.Errorf("%s: %v", p.name, err)
					continue
				}
				// The document that holds the value at the place, with the value's own bytes in it.
				if !strings.Contains(string(got), tc.want) {
					t.Errorf("%s: %q does not hold %q", p.name, got, tc.want)
				}
				want := map[string]string{
					"in a struct field":       `{"F":` + tc.want + `}`,
					"in a struct in a struct": `{"Outer":{"F":` + tc.want + `}}`,
					"in a map":                `{"k":` + tc.want + `}`,
					"in an interface":         `{"i":` + tc.want + `}`,
					"in a list of any":        `{"l":[1,` + tc.want + `]}`,
					"in a typed list":         `{"l":[` + tc.want + `]}`,
					"in a typed array":        `{"a":[` + tc.want + `]}`,
					"behind a pointer":        `{"p":` + tc.want + `}`,
				}[p.name]
				if string(got) != want {
					t.Errorf("%s: got %q, want %q", p.name, got, want)
				}
			}
		})
	}
}

func TestMarshalWritesTopLevelObjectsOfEveryKind(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"a struct", point{1, 2}, `{"X":1,"Y":2}`},
		{"a pointer to a struct", &point{1, 2}, `{"X":1,"Y":2}`},
		{"a map", map[string]int{"b": 1, "a": 2}, `{"a":2,"b":1}`},
		{"a pointer to a map", &map[string]int{"a": 1}, `{"a":1}`},
		{"a Raw", Raw(`{"b":1,"a":2}`), `{"a":2,"b":1}`},
		{"a struct in an interface", any(point{1, 2}), `{"X":1,"Y":2}`},
		{"an empty map", map[string]string{}, `{}`},
		{"an empty struct", struct{}{}, `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			if err != nil || string(got) != tc.want {
				t.Errorf("got %q, %v; want %q", got, err, tc.want)
			}
			if bytes.HasSuffix(got, []byte("\n")) || bytes.ContainsAny(got, " \t\r\n") {
				t.Errorf("Marshal wrote white space: %q", got)
			}
		})
	}
}

// A refusal of a Go type: the type at fault, the reason, and the path inside the value to it.
type refusedType struct {
	name   string
	v      any
	typ    string
	reason string
	inner  string // the route from the value to the part at fault: ".G.H" for fields, "[]" and "{}" for elements and values
	noPtr  bool   // the type at fault is the pointer that a pointer position would add
}

func refusedTypes(t *testing.T) []refusedType {
	ch := make(chan int)
	var x int
	// Types with two fields of one name cannot be declared in a source file that passes go vet.
	twice := structOf(t, []string{"x", "x"}, []any{1, 2}, nil)
	twiceType := reflect.TypeOf(twice).String()
	dashes := structOf(t, []string{"-,", "-,"}, []any{1, 2}, nil)
	dashesType := reflect.TypeOf(dashes).String()
	return []refusedType{
		{name: "float64", v: float64(1.5), typ: "float64", reason: reasonFloat},
		{name: "float64 with an integer value", v: float64(3), typ: "float64", reason: reasonFloat},
		{name: "float64 zero", v: float64(0), typ: "float64", reason: reasonFloat},
		{name: "NaN", v: math.NaN(), typ: "float64", reason: reasonFloat},
		{name: "float32", v: float32(2), typ: "float32", reason: reasonFloat},
		{name: "complex64", v: complex64(1), typ: "complex64", reason: reasonKind},
		{name: "complex128", v: complex128(1i), typ: "complex128", reason: reasonKind},
		{name: "a channel", v: ch, typ: "chan int", reason: reasonKind},
		{name: "a function", v: func() {}, typ: "func()", reason: reasonKind},
		{name: "uintptr", v: uintptr(1), typ: "uintptr", reason: reasonKind},
		{name: "an unsafe pointer", v: unsafe.Pointer(&x), typ: "unsafe.Pointer", reason: reasonKind},
		{name: "json.Number", v: json.Number("1"), typ: "json.Number", reason: reasonNumber},
		{name: "json.Number that is not a number", v: json.Number("x"), typ: "json.Number", reason: reasonNumber},
		{name: "MarshalJSON on the value", v: jsonVal{}, typ: "canonjson.jsonVal", reason: reasonJSON},
		{name: "MarshalJSON on the pointer only", v: jsonPtr{}, typ: "canonjson.jsonPtr", reason: reasonJSON},
		{name: "MarshalText on the value", v: textVal("v"), typ: "canonjson.textVal", reason: reasonText},
		{name: "MarshalText on the pointer only", v: textPtr{}, typ: "canonjson.textPtr", reason: reasonText},
		{name: "both methods", v: bothVal{}, typ: "canonjson.bothVal", reason: reasonJSON},
		{name: "time.Time", v: time.Time{}, typ: "time.Time", reason: reasonJSON},
		{name: "time.Duration is an integer and is written; a Time is not", v: struct{ T time.Time }{}, typ: "time.Time", reason: reasonJSON, inner: ".T"},
		{name: "a slice of a type with a text method", v: []textByte{1}, typ: "canonjson.textByte", reason: reasonText, inner: "[]"},
		{name: "a map with a key that writes text", v: map[textKey]int{"k": 1}, typ: "canonjson.textKey", reason: reasonText},
		{name: "a map with an integer key", v: map[int]string{1: "a"}, typ: "map[int]string", reason: reasonMapKey},
		{name: "a map with a key that is a struct", v: map[point]int{{}: 1}, typ: "map[canonjson.point]int", reason: reasonMapKey},
		{name: "a map with a key that is an array", v: map[[1]int]int{{1}: 1}, typ: "map[[1]int]int", reason: reasonMapKey},
		{name: "a map with a bool key", v: map[bool]int{true: 1}, typ: "map[bool]int", reason: reasonMapKey},
		{name: "a map with an interface key", v: map[any]int{"a": 1}, typ: "map[interface {}]int", reason: reasonMapKey},
		{name: "a pointer to a pointer", v: ptr(ptr(1)), typ: "**int", reason: reasonPtrPtr, noPtr: true},
		{name: "a pointer to an interface", v: ptr(any(1)), typ: "*interface {}", reason: reasonPtrPtr, noPtr: true},
		{name: "a pointer to a pointer to a struct", v: ptr(&point{}), typ: "**canonjson.point", reason: reasonPtrPtr, noPtr: true},
		{name: "an embedded struct", v: embedsValue{}, typ: "canonjson.embedsValue", reason: "the embedded field embeddedBase is not part of ritueel's JSON; give it a name"},
		{name: "an embedded pointer to a struct", v: embedsPointer{}, typ: "canonjson.embedsPointer", reason: "the embedded field embeddedBase is not part of ritueel's JSON; give it a name"},
		{name: "an embedded struct with an exported name", v: embedsExported{}, typ: "canonjson.embedsExported", reason: "the embedded field Exported is not part of ritueel's JSON; give it a name"},
		{name: "an embedded integer type", v: embedsInt{myInt: 1}, typ: "canonjson.embedsInt", reason: "the embedded field myInt is not part of ritueel's JSON; give it a name"},
		{name: "the tag option string", v: optString{}, typ: "canonjson.optString", reason: `field F has the tag option "string"; only omitempty is allowed`},
		{name: "the tag option string after a name", v: optNamedString{}, typ: "canonjson.optNamedString", reason: `field F has the tag option "string"; only omitempty is allowed`},
		{name: "the tag option inline", v: optInline{}, typ: "canonjson.optInline", reason: `field F has the tag option "inline"; only omitempty is allowed`},
		{name: "the tag option omitzero", v: optOmitZero{}, typ: "canonjson.optOmitZero", reason: `field F has the tag option "omitzero"; only omitempty is allowed`},
		{name: "an empty tag option", v: withTag(t, `json:"f,,omitempty"`), typ: tagType(t, `json:"f,,omitempty"`), reason: `field F has the tag option ""; only omitempty is allowed`},
		{name: "a refused option after omitempty", v: optSecond{}, typ: "canonjson.optSecond", reason: `field F has the tag option "string"; only omitempty is allowed`},
		{name: "a tag name with an apostrophe", v: withTag(t, `json:"a'b"`), typ: tagType(t, `json:"a'b"`), reason: nameRefused("F", "a'b")},
		{name: "a tag name with a backslash", v: withTag(t, `json:"a\\b"`), typ: tagType(t, `json:"a\\b"`), reason: nameRefused("F", `a\b`)},
		{name: "a tag name with a symbol that is not a letter", v: withTag(t, "json:\"a"+string(rune(0x20ac))+"b\""), typ: tagType(t, "json:\"a"+string(rune(0x20ac))+"b\""), reason: nameRefused("F", "a"+string(rune(0x20ac))+"b")},
		{name: "a tag name with a dot", v: withTag(t, `json:"a.b"`), typ: tagType(t, `json:"a.b"`), reason: nameRefused("F", "a.b")},
		{name: "a tag name with a hyphen", v: withTag(t, `json:"a-b"`), typ: tagType(t, `json:"a-b"`), reason: nameRefused("F", "a-b")},
		{name: "a tag name with a space", v: withTag(t, `json:"a b"`), typ: tagType(t, `json:"a b"`), reason: nameRefused("F", "a b")},
		{name: "a tag name with a non-ASCII letter", v: withTag(t, "json:\""+string(rune(0xe9))+"\""), typ: tagType(t, "json:\""+string(rune(0xe9))+"\""), reason: nameRefused("F", string(rune(0xe9)))},
		{name: "a tag name that is a Cyrillic look-alike", v: withTag(t, "json:\"v"+string(rune(0x0435))+"rsion\""), typ: tagType(t, "json:\"v"+string(rune(0x0435))+"rsion\""), reason: nameRefused("F", "v"+string(rune(0x0435))+"rsion")},
		{name: "a tag name that is a dash and a comma", v: withTag(t, `json:"-,"`), typ: tagType(t, `json:"-,"`), reason: nameRefused("F", "-")},
		{name: "a tag name that is a dash and omitempty", v: withTag(t, `json:"-,omitempty"`), typ: tagType(t, `json:"-,omitempty"`), reason: nameRefused("F", "-")},
		{name: "two fields of one name", v: twice, typ: twiceType, reason: `two fields are named "x"`},
		{name: "a tag name that is another field's name", v: nameAsField{}, typ: "canonjson.nameAsField", reason: `two fields are named "A"`},
		{name: "two fields named dash, refused at the first name", v: dashes, typ: dashesType, reason: nameRefused("F0", "-")},
		{name: "a float field", v: floatField{}, typ: "float64", reason: reasonFloat, inner: ".G"},
		{name: "a float field with omitempty, zero", v: floatFieldOmit{}, typ: "float64", reason: reasonFloat, inner: ".G"},
		{name: "a nil pointer to a float with omitempty", v: floatPtrOmit{}, typ: "*float64", reason: reasonFloat, inner: ".P"},
		{name: "a float two structs down", v: holdsFloats{}, typ: "float64", reason: reasonFloat, inner: ".Inner.G"},
		{name: "an empty slice of floats", v: []float64{}, typ: "float64", reason: reasonFloat, inner: "[]"},
		{name: "a slice of floats", v: []float64{1.5}, typ: "float64", reason: reasonFloat, inner: "[]"},
		{name: "an empty array of floats", v: [0]float64{}, typ: "float64", reason: reasonFloat, inner: "[]"},
		{name: "an empty map of floats", v: map[string]float64{}, typ: "float64", reason: reasonFloat, inner: "{}"},
		{name: "an empty slice of pointers to floats", v: []*float64{}, typ: "*float64", reason: reasonFloat, inner: "[]"},
		{name: "an empty slice of lists of floats", v: [][]float64{}, typ: "float64", reason: reasonFloat, inner: "[][]"},
		{name: "an empty map of slices of maps of floats", v: map[string][]map[string]float64{}, typ: "float64", reason: reasonFloat, inner: "{}[]{}"},
		{name: "a list of structs with a float", v: []holdsFloats{}, typ: "float64", reason: reasonFloat, inner: "[].Inner.G"},
		{name: "an empty slice of channels", v: []chan int{}, typ: "chan int", reason: reasonKind, inner: "[]"},
		{name: "an empty slice of json.Number", v: []json.Number{}, typ: "json.Number", reason: reasonNumber, inner: "[]"},
		{name: "an empty slice of a type with a method", v: []jsonVal{}, typ: "canonjson.jsonVal", reason: reasonJSON, inner: "[]"},
		{name: "an empty slice of embedding structs", v: []embedsValue{}, typ: "canonjson.embedsValue", reason: "the embedded field embeddedBase is not part of ritueel's JSON; give it a name", inner: "[]"},
		{name: "an empty map of a type with a method", v: map[string]textVal{}, typ: "canonjson.textVal", reason: reasonText, inner: "{}"},
		{name: "an empty map with an integer key", v: map[int]string{}, typ: "map[int]string", reason: reasonMapKey},
		{name: "an empty map with a key that writes text", v: map[textKey]int{}, typ: "canonjson.textKey", reason: reasonText},
		{name: "an empty slice of pointers to pointers", v: []**int{}, typ: "**int", reason: reasonPtrPtr, inner: "[]"},
		{name: "a recursive type with a float", v: recursiveFloat{}, typ: "float64", reason: reasonFloat, inner: ".F"},
		{name: "an interface that holds a list of floats", v: any([]float64{}), typ: "float64", reason: reasonFloat, inner: "[]"},
	}
}

func TestMarshalRefusesEveryKindOutsideTheClosedSet(t *testing.T) {
	for _, tc := range refusedTypes(t) {
		t.Run(tc.name, func(t *testing.T) {
			// own: the type at fault is the type of the value itself. Such a type behind a pointer is named
			// as the caller wrote it, with its pointer.
			own := typeText(reflect.TypeOf(tc.v)) == tc.typ
			route := splitRoute(tc.inner)
			for _, p := range places(tc.v, false, tc.noPtr) {
				typ := tc.typ
				if own && len(route) == 0 && p.name == "behind a pointer" {
					typ = "*" + typ
				}
				got, err := Marshal(p.doc)
				refused(t, got, err, cannotWriteVia(p.base, append(slices.Clone(p.route), route...), typ, tc.reason))
				if t.Failed() {
					t.Logf("at the place %q", p.name)
					return
				}
			}
		})
	}
}

// TestMarshalSaysHowARefusalIsReached pins the whole text of one refusal for each way that a type
// can be reached, written out, so that the rule of the helpers above is not the only witness: a
// field goes on the path, the elements of a list and the values of a map are said in words, a type
// behind a pointer is the one the caller wrote.
func TestMarshalSaysHowARefusalIsReached(t *testing.T) {
	type holder struct {
		L []float64
		M map[string]float64
		A [1]float64
		P *float64
		S struct{ G float64 }
		X [][]map[string]float64
		R []holdsFloats
	}
	const f = " cannot be written"
	for _, tc := range []struct {
		name string
		v    any
		want string
	}{
		{"a float at the top", float64(1), "malformed JSON: $: a value of type float64" + f + ": " + reasonFloat},
		{"a float in a map of any", map[string]any{"k": float32(1)}, "malformed JSON: $.k: a value of type float32" + f + ": " + reasonFloat},
		{"a float in a list of any", map[string]any{"l": []any{1, 2.5}}, "malformed JSON: $.l[1]: a value of type float64" + f + ": " + reasonFloat},
		{"a slice of floats at the top", []float64{}, "malformed JSON: $: a value of type float64" + f + " (the elements of $): " + reasonFloat},
		{"a map of floats at the top", map[string]float64{}, "malformed JSON: $: a value of type float64" + f + " (the values of $): " + reasonFloat},
		{"a field that is a slice", struct{ L []float64 }{}, "malformed JSON: $.L: a value of type float64" + f + " (the elements of $.L): " + reasonFloat},
		{"a field that is a map", struct{ M map[string]float64 }{}, "malformed JSON: $.M: a value of type float64" + f + " (the values of $.M): " + reasonFloat},
		{"a field that is an array", struct{ A [1]float64 }{}, "malformed JSON: $.A: a value of type float64" + f + " (the elements of $.A): " + reasonFloat},
		{"a field that is a pointer to a float", struct{ P *float64 }{}, "malformed JSON: $.P: a value of type *float64" + f + ": " + reasonFloat},
		{"a field of a struct field", struct{ S struct{ G float64 } }{}, "malformed JSON: $.S.G: a value of type float64" + f + ": " + reasonFloat},
		{"lists and maps inside each other", struct{ X [][]map[string]float64 }{}, "malformed JSON: $.X: a value of type float64" + f + " (the values of the elements of the elements of $.X): " + reasonFloat},
		{"a list of structs", struct{ R []holdsFloats }{}, "malformed JSON: $.R: a value of type float64" + f + " (the member G of the member Inner of the elements of $.R): " + reasonFloat},
		{"a list that a pointer points to", &[]float64{}, "malformed JSON: $: a value of type float64" + f + " (the elements of $): " + reasonFloat},
		{"a float that a pointer points to", &struct{ G float64 }{}, "malformed JSON: $.G: a value of type float64" + f + ": " + reasonFloat},
		{"a struct that a pointer points to", &floatField{}, "malformed JSON: $.G: a value of type float64" + f + ": " + reasonFloat},
		{"a type with a method that a pointer points to", &jsonVal{}, "malformed JSON: $: a value of type *canonjson.jsonVal" + f + ": " + reasonJSON},
		{"a pointer to a pointer", ptr(ptr(1)), "malformed JSON: $: a value of type **int" + f + ": " + reasonPtrPtr},
		{"every field of a struct is looked at", holder{}, "malformed JSON: $.A: a value of type float64" + f + " (the elements of $.A): " + reasonFloat},
		{"a map key that is not a string", map[int]string{}, "malformed JSON: $: a value of type map[int]string" + f + ": " + reasonMapKey},
		{"a map key that writes text", map[textKey]int{}, "malformed JSON: $: a value of type canonjson.textKey" + f + ": " + reasonText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			refused(t, got, err, tc.want)
		})
	}
}

func TestMarshalRefusesWhatOnlyTheValueTellsApart(t *testing.T) {
	// A nil, an integer above int64 and the like are refused by their value, at the index that
	// they have in a list.
	cases := []struct {
		name   string
		v      any
		typ    string
		reason string
		noPtr  bool
	}{
		{"a nil pointer", (*int)(nil), "*int", reasonNilPtr, true},
		{"a nil pointer to a struct", (*point)(nil), "*canonjson.point", reasonNilPtr, true},
		{"a nil map", map[string]int(nil), "map[string]int", reasonNilMap, false},
		{"a nil slice", []int(nil), "[]int", reasonNilSlice, false},
		{"a nil slice of bytes", []byte(nil), "[]uint8", reasonNilSlice, false},
		{"a nil slice of strings", []string(nil), "[]string", reasonNilSlice, false},
		{"uint64 one above the range", uint64(safeMax) + 1, "uint64", outside("9007199254740992"), false},
		{"uint64 above int64", uint64(math.MaxInt64) + 1, "uint64", outside("9223372036854775808"), false},
		{"uint64 largest", uint64(math.MaxUint64), "uint64", outside("18446744073709551615"), false},
		{"uint above the range", uint(safeMax) + 1, "uint", outside("9007199254740992"), false},
		{"uint largest", uint(math.MaxUint64), "uint", outside("18446744073709551615"), false},
		{"a named unsigned above the range", myUint(safeMax) + 1, "canonjson.myUint", outside("9007199254740992"), false},
		{"a named unsigned largest", myUint(math.MaxUint64), "canonjson.myUint", outside("18446744073709551615"), false},
		{"int64 one above the range", int64(safeMax) + 1, "int64", outside("9007199254740992"), false},
		{"int64 one below the range", int64(safeMin) - 1, "int64", outside("-9007199254740992"), false},
		{"int64 largest", int64(math.MaxInt64), "int64", outside("9223372036854775807"), false},
		{"int64 smallest", int64(math.MinInt64), "int64", outside("-9223372036854775808"), false},
		{"int one above the range", int(safeMax) + 1, "int", outside("9007199254740992"), false},
		{"int one below the range", int(safeMin) - 1, "int", outside("-9007199254740992"), false},
		{"a named signed above the range", myInt64(safeMax + 1), "canonjson.myInt64", outside("9007199254740992"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range places(tc.v, true, tc.noPtr) {
				got, err := Marshal(p.doc)
				refused(t, got, err, cannotWrite(p.path, tc.typ, tc.reason))
				if t.Failed() {
					t.Logf("at the place %q", p.name)
					return
				}
			}
		})
	}
	t.Run("a nil interface", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			doc  any
			path string
		}{
			{"in a map of any", map[string]any{"i": nil}, "$.i"},
			{"in a struct field", struct{ I any }{}, "$.I"},
			{"in a list of any", map[string]any{"l": []any{1, nil}}, "$.l[1]"},
			{"in a nested struct", struct{ S struct{ I any } }{}, "$.S.I"},
		} {
			got, err := Marshal(tc.doc)
			refused(t, got, err, cannotWrite(tc.path, "interface {}", reasonNilIface))
		}
	})
	t.Run("nil at the top", func(t *testing.T) {
		got, err := Marshal(nil)
		refused(t, got, err, malformedText("$: a value of type nil cannot be written: an untyped nil is JSON null"))
	})
	t.Run("an uint64 at the largest of the range is written, one above is not", func(t *testing.T) {
		got, err := Marshal(map[string]uint64{"a": uint64(safeMax)})
		if err != nil || string(got) != `{"a":9007199254740991}` {
			t.Errorf("got %q, %v", got, err)
		}
	})
}

type myUint uint64

type myInt64 int64

func TestMarshalRefusesTextThatIsNotUTF8(t *testing.T) {
	bad := []string{"\xff", "a\xffb", "\x80", "\xe2\x82", "\xc0\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "abc\xff", "\xffabc", "é\xff"}
	for _, s := range bad {
		t.Run(fmt.Sprintf("%q", s), func(t *testing.T) {
			for _, p := range places(s, true, false) {
				got, err := Marshal(p.doc)
				refused(t, got, err, malformedText("%s: %s", p.path, notUTF8String))
				if t.Failed() {
					t.Logf("at the place %q", p.name)
					return
				}
			}
			// The same text as a member name, in a map of any value type.
			got, err := Marshal(map[string]int{s: 1})
			refused(t, got, err, malformedText("$.%s: %s", jsonset.Shown(s), notUTF8Name))
			got, err = Marshal(map[string]map[string]int{"a": {"b": 1, s: 2}})
			refusedWith(t, got, err, notUTF8Name)
		})
	}
	t.Run("a named string type", func(t *testing.T) {
		got, err := Marshal(map[string]myString{"k": "a\xff"})
		refused(t, got, err, malformedText("$.k: %s", notUTF8String))
		got, err = Marshal(map[myKey]int{"a\xff": 1})
		refusedWith(t, got, err, notUTF8Name)
	})
	t.Run("a struct field is judged by its value, a field that is not written is not looked at", func(t *testing.T) {
		got, err := Marshal(struct {
			S string
			h string
			D string `json:"-"`
		}{S: "ok", h: "\xff", D: "\xff"})
		if err != nil || string(got) != `{"S":"ok"}` {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("the replacement character is text, not an error", func(t *testing.T) {
		got, err := Marshal(map[string]string{string(rune(0xFFFD)): string(rune(0xFFFD))})
		if err != nil {
			t.Fatal(err)
		}
		if want := "{\"" + string(rune(0xFFFD)) + "\":\"" + string(rune(0xFFFD)) + "\"}"; string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestMarshalNeedsAnObjectAtTheTop(t *testing.T) {
	cases := []struct {
		name string
		v    any
		typ  string
	}{
		{"a bool", true, "bool"},
		{"an integer", 3, "int"},
		{"a string", "x", "string"},
		{"a slice", []int{1}, "[]int"},
		{"an empty slice", []int{}, "[]int"},
		{"a slice of objects", []map[string]int{{"a": 1}}, "[]map[string]int"},
		{"an array", [1]int{1}, "[1]int"},
		{"bytes", []byte("hi"), "[]uint8"},
		{"a pointer to an integer", ptr(3), "*int"},
		{"a pointer to a slice", ptr([]int{1}), "*[]int"},
		{"an interface holding a string", any("x"), "string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			refused(t, got, err, malformedText("$: a value of type %s cannot be written: the top of a document is one JSON object, which a struct, a map, a Raw, or a pointer or an interface that holds one, writes", tc.typ))
		})
	}
	t.Run("a Raw that is a list", func(t *testing.T) {
		got, err := Marshal(Raw(`[1]`))
		refusedWith(t, got, err, "not one JSON object")
	})
}

// ---- paths -------------------------------------------------------------------------------

func TestPathsOfAMemberName(t *testing.T) {
	// A name is shown as it is when it is a non-empty run of ASCII letters, digits, underscores and
	// dashes of at most 40 bytes; any other name is quoted with ASCII escapes (a character that is
	// not printable ASCII as an escape, one above U+FFFF as the pair of its surrogates), and cut
	// when long. A list index is [n] and is told from a name that is digits ($.0) by the missing
	// dot. The names are the keys of a map, which take any text.
	long := strings.Repeat("n", 41)
	cases := []struct{ name, key, shown string }{
		{"letters", "abc", `abc`},
		{"digits", "0", `0`},
		{"underscore and dash", "a_b-c", `a_b-c`},
		{"a non-ASCII letter", "é", `"` + qesc(0xe9) + `"`},
		{"a Hebrew letter", string(rune(0xFB33)), `"` + qesc(0xFB33) + `"`},
		{"a Cyrillic letter that looks like a Latin one", string(rune(0x0430)), `"` + qesc(0x0430) + `"`},
		{"the Kelvin sign", string(rune(0x212A)), `"` + qesc(0x212A) + `"`},
		{"a dot", "a.b", `"a.b"`},
		{"a bracket", "a[0]", `"a[0]"`},
		{"a bracket that looks like an index", "l[1]", `"l[1]"`},
		{"a quote", `a"b`, `"a\"b"`},
		{"a backslash", `a\b`, `"a\\b"`},
		{"a space", "a b", `"a b"`},
		{"empty", "", `""`},
		{"a dollar", "$", `"$"`},
		{"an emoji, a pair of surrogates", string(rune(0x1F600)), `"` + qesc(0x1F600) + `"`},
		{"a symbol that is not a letter", "€", `"` + qesc(0x20ac) + `"`},
		{"a control", "a\nb", `"a` + qesc('\n') + `b"`},
		{"40 bytes", strings.Repeat("n", 40), strings.Repeat("n", 40)},
		{"41 bytes are cut and quoted", long, `"` + strings.Repeat("n", 40) + `..."`},
		{"a cut inside a two-byte character", strings.Repeat("n", 39) + "é", `"` + strings.Repeat("n", 39) + `..."`},
		{"a cut inside a four-byte character", strings.Repeat("n", 38) + string(rune(0x1F600)), `"` + strings.Repeat("n", 38) + `..."`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The name of a map member and the name of a struct field (through a tag, where
			// the name is valid for a tag) show the same.
			got, err := Marshal(map[string]any{tc.key: 1.5})
			refused(t, got, err, cannotWrite("$."+tc.shown, "float64", reasonFloat))
			got, err = Marshal(map[string]any{"a": map[string]any{tc.key: 1.5}})
			refused(t, got, err, cannotWrite("$.a."+tc.shown, "float64", reasonFloat))
		})
	}
	t.Run("a field named by a tag", func(t *testing.T) {
		// A struct holds only names inside the rule, so these are the names that a path can show
		// for a field; the odd names above are those of a map.
		for _, name := range []string{"a", "a_b", "A1", "_", "x9", "Z_Z"} {
			st := reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[float64](), Tag: reflect.StructTag(`json:"` + name + `"`)}})
			got, err := Marshal(reflect.New(st).Elem().Interface())
			refused(t, got, err, cannotWrite("$."+name, "float64", reasonFloat))
		}
	})
	t.Run("a name that is digits is told from an index", func(t *testing.T) {
		_, errName := Marshal(map[string]any{"l": map[string]any{"1": 1.5}})
		_, errIndex := Marshal(map[string]any{"l": []any{1, 1.5}})
		if errName == nil || errIndex == nil || errName.Error() == errIndex.Error() {
			t.Fatalf("the two paths are not told apart: %v / %v", errName, errIndex)
		}
		if !strings.Contains(errName.Error(), "$.l.1:") || !strings.Contains(errIndex.Error(), "$.l[1]:") {
			t.Errorf("the paths are %v and %v", errName, errIndex)
		}
	})
	t.Run("a long path shows its last eight steps", func(t *testing.T) {
		build := func(n int) map[string]any {
			var v any = 1.5
			for i := n; i >= 1; i-- {
				v = map[string]any{fmt.Sprintf("s%d", i): v}
			}
			return v.(map[string]any)
		}
		for _, tc := range []struct {
			steps int
			path  string
		}{
			{1, "$.s1"},
			{8, "$.s1.s2.s3.s4.s5.s6.s7.s8"},
			{9, "$....s2.s3.s4.s5.s6.s7.s8.s9"},
			{20, "$....s13.s14.s15.s16.s17.s18.s19.s20"},
		} {
			got, err := Marshal(build(tc.steps))
			refused(t, got, err, cannotWrite(tc.path, "float64", reasonFloat))
		}
	})
	t.Run("a path in a list of structs", func(t *testing.T) {
		got, err := Marshal(map[string]any{"l": []any{point{}, struct{ P any }{P: 1.5}}})
		refused(t, got, err, cannotWrite("$.l[1].P", "float64", reasonFloat))
	})
}

// ---- structs -----------------------------------------------------------------------------

// structOf builds a struct type with the given exported fields, each with the tag that names it,
// and fills it with the values, so that a test can use names that a Go source file could not
// show.
func structOf(t *testing.T, names []string, values []any, tags []string) any {
	t.Helper()
	var fields []reflect.StructField
	for i, v := range values {
		tag := ""
		if tags != nil {
			tag = tags[i]
		}
		fields = append(fields, reflect.StructField{
			Name: fmt.Sprintf("F%d", i),
			Type: reflect.TypeOf(v),
			Tag:  reflect.StructTag(`json:"` + names[i] + tag + `"`),
		})
	}
	sv := reflect.New(reflect.StructOf(fields)).Elem()
	for i, v := range values {
		sv.Field(i).Set(reflect.ValueOf(v))
	}
	return sv.Interface()
}

func TestStructFieldsAreSortedByNameAsUTF16(t *testing.T) {
	t.Run("not by declaration", func(t *testing.T) {
		got, err := Marshal(struct {
			Zeta  int
			Alpha int
			Mid   int
			beta  int
		}{1, 2, 3, 4})
		if want := `{"Alpha":2,"Mid":3,"Zeta":1}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("by the tag name, not the field name", func(t *testing.T) {
		got, err := Marshal(struct {
			A int `json:"z"`
			Z int `json:"a"`
		}{1, 2})
		if want := `{"a":2,"z":1}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("capitals before small letters, digits before letters, a prefix first", func(t *testing.T) {
		got, err := Marshal(structOf(t, []string{"b", "B", "a10", "a2", "a", "1", "_"}, []any{1, 2, 3, 4, 5, 6, 7}, nil))
		if want := `{"1":6,"B":2,"_":7,"a":5,"a10":3,"a2":4,"b":1}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("a character above the BMP sorts before U+FB33 although its UTF-8 bytes are after", func(t *testing.T) {
		// A name of a struct is inside the rule (ASCII), so the order of names outside ASCII is
		// that of the keys of a map, which take any text. U+1D400 (mathematical bold capital A) is
		// the surrogate pair D835 DC00 in UTF-16, which is below FB33; in UTF-8 it is F0 9D 90 80,
		// which is above EF AC B3.
		high, dalet := string(rune(0x1D400)), string(rune(0xFB33))
		if high <= dalet {
			t.Fatal("the test names do not differ in the two orders")
		}
		got, err := Marshal(map[string]int{dalet: 1, high: 2, "z": 3})
		want := `{"z":3,"` + high + `":2,"` + dalet + `":1}`
		if err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %q", got, err, want)
		}
		// A map of any holds the same, and so does a map inside a struct.
		gotAny, err := Marshal(map[string]any{dalet: 1, high: 2, "z": 3})
		if err != nil || !bytes.Equal(gotAny, got) {
			t.Errorf("a map of any: %q, %v", gotAny, err)
		}
		gotIn, err := Marshal(struct {
			M map[string]int `json:"m"`
		}{map[string]int{dalet: 1, high: 2, "z": 3}})
		if want := `{"m":` + want + `}`; err != nil || string(gotIn) != want {
			t.Errorf("a map in a struct: %q, %v; want %q", gotIn, err, want)
		}
	})
	t.Run("the order of names inside the rule is the order of ASCII", func(t *testing.T) {
		// Digits, then capitals, then the underscore, then small letters; a prefix first.
		names := []string{"b", "B", "a10", "a2", "a", "1", "_", "Z", "a_", "0", "A9", "z"}
		values := make([]any, len(names))
		for i := range values {
			values[i] = i
		}
		got, err := Marshal(structOf(t, names, values, nil))
		if want := `{"0":9,"1":5,"A9":10,"B":1,"Z":7,"_":6,"a":4,"a10":2,"a2":3,"a_":8,"b":0,"z":11}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("the same order as the standard encoder canonicalized", func(t *testing.T) {
		// For a struct of names inside the rule, and for a map of any text.
		names := []string{"b", "a", "A", "1", "_", "B2", "a_b", "Zz"}
		values := make([]any, len(names))
		for i := range values {
			values[i] = i
		}
		v := structOf(t, names, values, nil)
		got, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		std, _ := json.Marshal(v)
		want, err := Canonicalize(std)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("got %q, want %q (%v)", got, want, err)
		}
		m := map[string]int{}
		for i, name := range []string{"b", "é", "a", string(rune(0x1D400)), string(rune(0xFB33)), "A", "1", string(rune(0xFF21)), "~", "a.b", "a b", ""} {
			m[name] = i
		}
		got, err = Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		std, _ = json.Marshal(m)
		want, err = Canonicalize(std)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("a map: got %q, want %q (%v)", got, want, err)
		}
	})
}

func TestStructTagForms(t *testing.T) {
	// Field i is named F<i> by Go. The tag decides the name of the field in the document, or that
	// it has none.
	forms := []struct {
		tag  string
		name string // the name written, or "" when the field is left out
	}{
		{`json:"-"`, ""},
		{`json:",omitempty"`, "F1"},
		{`json:"d,omitempty"`, "d"},
		{`json:""`, "F3"},
		{``, "F4"},
		{`json:"h,omitempty,omitempty"`, "h"},
		{`xml:"i"`, "F6"},
		{`json:"k"`, "k"},
		{`json:"l,omitempty"`, "l"},
		{`json:"M"`, "M"},
		{`xml:"x" json:"n"`, "n"},
		{`json:"o" xml:"x"`, "o"},
	}
	// "-," and "-,omitempty" would name a field "-", which is no member name: they are refused, and
	// are tested below.
	var tags []string
	var names []string
	var values []int
	for i, f := range forms {
		tags = append(tags, f.tag)
		names = append(names, f.name)
		values = append(values, i+1)
	}
	t.Run("every form", func(t *testing.T) {
		v := tagged(t, tags, values)
		written := map[string]int{}
		for i, name := range names {
			if name != "" {
				written[name] = values[i]
			}
		}
		want, err := Marshal(written)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Marshal(v)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
		std, _ := json.Marshal(v)
		if canon, err := Canonicalize(std); err != nil || !bytes.Equal(canon, got) {
			t.Errorf("the standard encoder's form is %q (%v)", canon, err)
		}
		if bytes.Contains(got, []byte(`"F0"`)) || bytes.Contains(got, []byte(`"-"`)) {
			t.Errorf("the field tagged dash is in %q", got)
		}
		for _, p := range places(v, false, false) {
			if _, err := Marshal(p.doc); err != nil {
				t.Errorf("%s: %v", p.name, err)
			}
		}
	})
	t.Run("-, and -,omitempty name a field dash, which is no member name, and are refused", func(t *testing.T) {
		for _, tag := range []string{`json:"-,"`, `json:"-,omitempty"`} {
			got, err := Marshal(tagged(t, []string{tag, ``}, []int{10, 1}))
			refusedWith(t, got, err, nameRefused("F0", "-"))
		}
	})
	t.Run("a field tagged dash is not looked at, whatever its type", func(t *testing.T) {
		got, err := Marshal(struct {
			N int
			D float64     `json:"-"`
			C chan int    `json:"-"`
			E embedsValue `json:"-"`
			T jsonVal     `json:"-"`
		}{N: 1})
		if want := `{"N":1}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("an unexported field is not looked at, whatever its type or tag", func(t *testing.T) {
		got, err := Marshal(struct {
			N int
			f float64
			c chan int
		}{N: 1})
		if want := `{"N":1}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("names that a tag may carry are those of letters, digits and underscores", func(t *testing.T) {
		names := []string{"a_b", "A", "a1", "1", "_", "__", "A_1_b", "ab9", "9ab"}
		for _, name := range names {
			v := structOf(t, []string{name}, []any{7}, nil)
			got, err := Marshal(v)
			std, _ := json.Marshal(v)
			canon, _ := Canonicalize(std)
			if err != nil || !bytes.Equal(got, canon) {
				t.Errorf("the name %q: got %q, %v; the standard encoder gives %q", name, got, err, canon)
			}
		}
	})
	t.Run("names that the standard encoder takes and ritueel does not", func(t *testing.T) {
		names := []string{"a.b", "a b", "a-b", "$x", "a/b", "a:b", "a;b", "a<b", "a=b", "a>b", "a?b", "a@b", "a[b]", "a^b", "a{b}", "a|b", "a~b", "a!b", "a#b", "a%b", "a&b", "a(b)", "a*b", "a+b", "é", " ", "-", "--"}
		for _, name := range names {
			v := structOf(t, []string{name}, []any{7}, nil)
			if _, err := json.Marshal(v); err != nil {
				t.Fatalf("the standard encoder refuses %q: %v", name, err)
			}
			got, err := Marshal(v)
			if name == "-" {
				// A tag that is the dash alone leaves the field out, in both.
				if err != nil || string(got) != "{}" {
					t.Errorf("the name -: got %q, %v", got, err)
				}
				continue
			}
			refusedWith(t, got, err, nameRefused("F0", name))
		}
	})
}

func TestStructOmitEmpty(t *testing.T) {
	type S struct {
		A int
	}
	// Each field is the zero of its kind and is left out; each one in the second struct holds a
	// value that is not "empty" and is written, among them values that look empty (a pointer to
	// zero, an interface that holds zero, an array of one, a Raw of a document).
	type zero struct {
		B    bool           `json:"b,omitempty"`
		I    int            `json:"i,omitempty"`
		I8   int8           `json:"i8,omitempty"`
		U    uint64         `json:"u,omitempty"`
		S    string         `json:"s,omitempty"`
		L    []int          `json:"l,omitempty"`
		LN   []int          `json:"ln,omitempty"`
		M    map[string]int `json:"m,omitempty"`
		MN   map[string]int `json:"mn,omitempty"`
		A    [0]int         `json:"a,omitempty"`
		P    *int           `json:"p,omitempty"`
		PS   *S             `json:"ps,omitempty"`
		IF   any            `json:"if,omitempty"`
		R    Raw            `json:"r,omitempty"`
		RE   Raw            `json:"re,omitempty"`
		By   []byte         `json:"by,omitempty"`
		BN   []byte         `json:"bn,omitempty"`
		MI   myInt          `json:"mi,omitempty"`
		MS   myString       `json:"ms,omitempty"`
		PR   *Raw           `json:"-"`
		LL   [][]int        `json:"ll,omitempty"`
		MM   map[string]S   `json:"mm,omitempty"`
		Str  S              `json:"str,omitempty"`
		Anon struct{}       `json:"anon,omitempty"`
		KS   map[myKey]int  `json:"ks,omitempty"`
	}
	t.Run("what is empty is left out", func(t *testing.T) {
		v := zero{L: []int{}, M: map[string]int{}, R: Raw{}, By: []byte{}, LL: [][]int{}, MM: map[string]S{}, KS: map[myKey]int{}}
		got, err := Marshal(v)
		// A struct is never left out, even when it is the zero of its type.
		if want := `{"anon":{},"str":{"A":0}}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
		std, _ := json.Marshal(v)
		if canon, err := Canonicalize(std); err != nil || !bytes.Equal(canon, got) {
			t.Errorf("the standard encoder's form is %q (%v)", canon, err)
		}
	})
	t.Run("what is not empty is written", func(t *testing.T) {
		v := zero{
			B: true, I: -1, I8: 1, U: 2, S: "x", L: []int{0}, M: map[string]int{"k": 0},
			P: ptr(0), PS: &S{}, IF: 0, R: Raw(`{"z":1}`), By: []byte{0}, MI: 1, MS: "y",
			LL: [][]int{{}}, MM: map[string]S{"k": {}}, KS: map[myKey]int{"k": 1},
		}
		got, err := Marshal(v)
		want := `{"anon":{},"b":true,"by":"AA==","i":-1,"i8":1,"if":0,"ks":{"k":1},"l":[0],"ll":[[]],"m":{"k":0},"mi":1,` +
			`"mm":{"k":{"A":0}},"ms":"y","p":0,"ps":{"A":0},"r":{"z":1},"s":"x","str":{"A":0},"u":2}`
		if err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
		std, _ := json.Marshal(v)
		if canon, err := Canonicalize(std); err != nil || !bytes.Equal(canon, got) {
			t.Errorf("the standard encoder's form is %q (%v)", canon, err)
		}
	})
	t.Run("an array of one is not empty, a zero value in it does not make it so", func(t *testing.T) {
		got, err := Marshal(struct {
			A [1]int `json:"a,omitempty"`
			E [0]int `json:"e,omitempty"`
		}{})
		if want := `{"a":[0]}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("a struct is not omitted whatever is in it", func(t *testing.T) {
		got, err := Marshal(struct {
			E struct{} `json:"e,omitempty"`
			Z struct {
				A int `json:"a,omitempty"`
			} `json:"z,omitempty"`
			N struct {
				P *int `json:"p,omitempty"`
			} `json:"n,omitempty"`
		}{})
		if want := `{"e":{},"n":{},"z":{}}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("without omitempty the same values are written", func(t *testing.T) {
		got, err := Marshal(struct {
			B bool
			I int
			S string
			L []int
			P *int
		}{L: []int{}, P: ptr(0)})
		if want := `{"B":false,"I":0,"L":[],"P":0,"S":""}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("a nil without omitempty is refused, with it is left out", func(t *testing.T) {
		got, err := Marshal(struct {
			P *int
		}{})
		refused(t, got, err, cannotWrite("$.P", "*int", reasonNilPtr))
		got, err = Marshal(struct {
			P *int           `json:",omitempty"`
			L []int          `json:",omitempty"`
			M map[string]int `json:",omitempty"`
			I any            `json:",omitempty"`
		}{})
		if want := `{}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
}

func TestTypesAreJudgedAsTypes(t *testing.T) {
	t.Run("a type that can be written is accepted whatever the value", func(t *testing.T) {
		for name, v := range map[string]any{
			"a nil pointer to an integer, omitted": struct {
				P *int `json:",omitempty"`
			}{},
			"a nil pointer to a struct, omitted": struct {
				P *point `json:",omitempty"`
			}{},
			"a nil pointer to a recursive struct, omitted": struct {
				P *listNode `json:",omitempty"`
			}{},
			"a nil pointer to a mutual recursion, omitted": struct {
				P *mutualA `json:",omitempty"`
			}{},
			"a list of any that is empty": map[string]any{"l": []any{}},
			"a map of any that is empty":  map[string]any{"m": map[string]any{}},
			"an empty map of Raw":         map[string]Raw{},
			"a recursive type":            listNode{Next: &listNode{}},
			"a mutual recursion":          mutualA{B: &mutualB{A: &mutualA{}}},
			"an interface that is nil under omitempty": struct {
				I any `json:",omitempty"`
			}{},
			"an interface that holds what can be written":   struct{ I any }{I: []int{}},
			"an unexported field of a type that is refused": struct{ f float64 }{},
			"a field tagged dash of a type that is refused": struct {
				F float64 `json:"-"`
			}{},
		} {
			if _, err := Marshal(v); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
	t.Run("an interface is judged by the value it holds", func(t *testing.T) {
		got, err := Marshal(struct{ I any }{I: []float64{}})
		refused(t, got, err, cannotWriteVia("$.I", []string{"[]"}, "float64", reasonFloat))
		got, err = Marshal(struct{ I any }{I: 1})
		if err != nil || string(got) != `{"I":1}` {
			t.Errorf("an integer in an interface: %q, %v", got, err)
		}
		got, err = Marshal(map[string]any{"l": []any{1, floatField{}}})
		refused(t, got, err, cannotWrite("$.l[1].G", "float64", reasonFloat))
	})
	t.Run("the refusal is the same for a value that is empty and one that is not", func(t *testing.T) {
		a, errA := Marshal(map[string]any{"l": []float64{}})
		b, errB := Marshal(map[string]any{"l": []float64{1.5}})
		refused(t, a, errA, cannotWriteVia("$.l", []string{"[]"}, "float64", reasonFloat))
		refused(t, b, errB, cannotWriteVia("$.l", []string{"[]"}, "float64", reasonFloat))
	})
	t.Run("a refused field is found even when nothing else is", func(t *testing.T) {
		// The struct is refused for the field that is left out when zero, not written without it.
		got, err := Marshal(struct {
			A int
			B float64 `json:",omitempty"`
			C int
		}{A: 1, C: 2})
		refused(t, got, err, cannotWrite("$.B", "float64", reasonFloat))
	})
}

func TestStructFieldNamesOfOneSpelling(t *testing.T) {
	t.Run("two fields of one name are refused, in any order", func(t *testing.T) {
		twice := structOf(t, []string{"x", "x"}, []any{1, 2}, nil)
		got, err := Marshal(twice)
		refused(t, got, err, cannotWrite("$", reflect.TypeOf(twice).String(), `two fields are named "x"`))
		got, err = Marshal(map[string]any{"k": nameAsField{}})
		refused(t, got, err, cannotWrite("$.k", "canonjson.nameAsField", `two fields are named "A"`))
	})
	t.Run("names that differ only by case are two fields, and are read back into the right ones", func(t *testing.T) {
		type pair struct {
			Lower int `json:"a"`
			Upper int `json:"A"`
			Plain int
			Other int `json:"plain"`
		}
		v := pair{Lower: 1, Upper: 2, Plain: 3, Other: 4}
		got, err := Marshal(v)
		if want := `{"A":2,"Plain":3,"a":1,"plain":4}`; err != nil || string(got) != want {
			t.Fatalf("got %q, %v; want %s", got, err, want)
		}
		var back pair
		if err := strictjson.Unmarshal(got, &back, strictjson.Options{}); err != nil {
			t.Fatal(err)
		}
		if back != v {
			t.Errorf("read back %+v, want %+v", back, v)
		}
		// And a declaration order that is the reverse of the sorted one gives the same bytes.
		type reversed struct {
			Other int `json:"plain"`
			Plain int
			Upper int `json:"A"`
			Lower int `json:"a"`
		}
		again, err := Marshal(reversed{Other: 4, Plain: 3, Upper: 2, Lower: 1})
		if err != nil || !bytes.Equal(again, got) {
			t.Errorf("the reverse declaration: %q, %v", again, err)
		}
	})
}

// ---- bytes -------------------------------------------------------------------------------

func TestBytesAreStandardBase64WithPadding(t *testing.T) {
	r := rand.New(rand.NewSource(4648))
	var inputs [][]byte
	for n := range 13 {
		b := make([]byte, n)
		r.Read(b)
		inputs = append(inputs, b)
	}
	inputs = append(inputs, []byte{0xfb, 0xff, 0xbf}, []byte{0xfb}, []byte{0xff, 0xff}, []byte{0, 0, 0, 0}, bytes.Repeat([]byte{0xfe}, 100))
	for range 200 {
		b := make([]byte, r.Intn(200))
		r.Read(b)
		inputs = append(inputs, b)
	}
	for _, b := range inputs {
		want := `{"b":"` + base64.StdEncoding.EncodeToString(b) + `"}`
		got, err := Marshal(map[string][]byte{"b": slices.Clone(b)})
		if err != nil || string(got) != want {
			t.Fatalf("%x: got %q, %v; want %s", b, got, err, want)
		}
		std, _ := json.Marshal(map[string][]byte{"b": b})
		if canon, err := Canonicalize(std); err != nil || !bytes.Equal(canon, got) {
			t.Fatalf("%x: the standard encoder gives %q", b, canon)
		}
	}
	t.Run("padding by length", func(t *testing.T) {
		for n, pad := range []string{"", "AA==", "AAA=", "AAAA", "AAAAAA==", "AAAAAAA="} {
			if n == 0 {
				continue
			}
			got, err := Marshal(map[string][]byte{"b": make([]byte, n)})
			if want := `{"b":"` + pad + `"}`; err != nil || string(got) != want {
				t.Errorf("%d bytes: got %q, %v; want %s", n, got, err, want)
			}
		}
	})
	t.Run("the alphabet is the standard one, not the URL one", func(t *testing.T) {
		got, err := Marshal(map[string][]byte{"b": {0xfb, 0xef, 0xbe, 0xff, 0xff, 0xff}})
		if want := `{"b":"++++////"}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("a named slice of bytes", func(t *testing.T) {
		got, err := Marshal(map[string]myBytes{"b": myBytes("hi")})
		if want := `{"b":"aGk="}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
		type octet byte
		got, err = Marshal(map[string][]octet{"b": {'h', 'i'}})
		if want := `{"b":"aGk="}`; err != nil || string(got) != want {
			t.Errorf("a slice of a named byte: got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("an array of bytes is a list of integers, even a long one", func(t *testing.T) {
		got, err := Marshal(map[string][4]byte{"b": {1, 2, 255, 0}})
		if want := `{"b":[1,2,255,0]}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
		std, _ := json.Marshal(map[string][4]byte{"b": {1, 2, 255, 0}})
		if canon, _ := Canonicalize(std); !bytes.Equal(canon, got) {
			t.Errorf("the standard encoder gives %q", canon)
		}
	})
	t.Run("a slice of integers of another width is a list", func(t *testing.T) {
		got, err := Marshal(map[string][]int8{"b": {1, -2}})
		if want := `{"b":[1,-2]}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
	t.Run("a slice of bytes with an element type that writes text is refused", func(t *testing.T) {
		got, err := Marshal(map[string][]textByte{"b": {1}})
		refused(t, got, err, cannotWriteVia("$", []string{"{}", "[]"}, "canonjson.textByte", reasonText))
	})
}

// ---- Raw ---------------------------------------------------------------------------------

func TestRawIsWrittenInCanonicalForm(t *testing.T) {
	bs := bsl
	cases := []struct{ name, in, want string }{
		{"an empty object", `{}`, `{}`},
		{"canonical already", `{"a":1,"b":[true,"x"]}`, `{"a":1,"b":[true,"x"]}`},
		{"members out of order", `{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{"members out of order at every depth", `{"z":{"b":1,"a":2},"y":[{"d":1,"c":2}]}`, `{"y":[{"c":2,"d":1}],"z":{"a":2,"b":1}}`},
		{"white space", " \n\t{ \"a\" : 1 ,\r\n \"b\" : [ 1 , 2 ] }\n ", `{"a":1,"b":[1,2]}`},
		{"escapes that need not be", `{"a":"` + bs + "u0041" + bs + "/" + bs + "u00e9" + `"}`, "{\"a\":\"A/é\"}"},
		{"escapes of controls in capitals", `{"a":"` + bs + "u001F" + bs + "u0009" + `"}`, `{"a":"` + bs + "u001f" + bs + `t"}`},
		{"a surrogate pair", `{"a":"` + bs + "ud83d" + bs + "ude00" + `"}`, "{\"a\":\"\U0001F600\"}"},
		{"a name written with escapes", `{"` + bs + "u0062" + `":1,"` + bs + "u0061" + `":2}`, `{"a":2,"b":1}`},
		{"minus zero", `{"a":-0}`, `{"a":0}`},
		{"names in UTF-16 order", `{"` + string(rune(0xFB33)) + `":1,"` + string(rune(0x1F600)) + `":2}`, `{"` + string(rune(0x1F600)) + `":2,"` + string(rune(0xFB33)) + `":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := tc.want
			if want == "" {
				want = tc.in
			}
			for _, p := range places(Raw(tc.in), false, false) {
				if p.name == "behind a pointer" || p.name == "in a typed array" || p.name == "in a typed list" || p.name == "in a list of any" {
					continue // those are the tests of the table above
				}
				got, err := Marshal(p.doc)
				if err != nil {
					t.Fatalf("%s: %v", p.name, err)
				}
				if p.name == "at the top" {
					if string(got) != want {
						t.Errorf("at the top: got %q, want %q", got, want)
					}
					continue
				}
				if !strings.Contains(string(got), want) {
					t.Errorf("%s: %q does not hold %q", p.name, got, want)
				}
			}
		})
	}
}

func TestRawRefusals(t *testing.T) {
	bs := bsl
	deepDoc := func(n int) string { return strings.Repeat(`{"a":`, n-1) + `{}` + strings.Repeat(`}`, n-1) }
	// The refusals of a document that is not one JSON object under the rules of strictjson: the
	// path of the Raw goes on into the document, so an error about the value at .a of the Raw is at
	// the path of the Raw and .a. Where the document is wrong as a whole the path is the Raw's.
	cases := []struct{ name, in, inner, what string }{
		{"a list", `[1]`, "", `not one JSON object`},
		{"an empty list", `[]`, "", `not one JSON object`},
		{"a number", `1`, "", `not one JSON object`},
		{"a string", `"x"`, "", `not one JSON object`},
		{"true", `true`, "", `not one JSON object`},
		{"null", `null`, "", `not one JSON object`},
		{"white space only", " \n", "", `not one JSON object`},
		{"text after the object", `{} x`, "", `anything after the object at byte 3`},
		{"a second object", `{}{}`, "", `anything after the object at byte 2`},
		{"a repeated member", `{"a":1,"a":2}`, ".a", `the member appears twice at byte 10`},
		{"a repeated member, one written as an escape", `{"a":1,"` + bs + `u0061":2}`, ".a", `the member appears twice at byte 15`},
		{"a repeated member one level down", `{"b":{"a":1,"a":2}}`, ".b.a", `the member appears twice at byte 15`},
		{"a float", `{"a":1.5}`, ".a", `a number with a fraction or an exponent at byte 8`},
		{"an exponent", `{"a":1e2}`, ".a", `a number with a fraction or an exponent at byte 8`},
		{"an integer above int64", `{"a":9223372036854775808}`, ".a", outside("9223372036854775808") + ` at byte 24`},
		{"one above the range", `{"a":9007199254740992}`, ".a", outside("9007199254740992") + ` at byte 21`},
		{"one below the range", `{"a":-9007199254740992}`, ".a", outside("-9007199254740992") + ` at byte 22`},
		{"null in a member", `{"a":null}`, ".a", `null at byte 9`},
		{"null deep down", `{"a":[{"b":null}]}`, ".a[0].b", `null at byte 15`},
		{"invalid UTF-8", "{\"a\":\"\xff\"}", "", `not valid UTF-8`},
		{"a lone surrogate", `{"a":"` + bs + `ud800"}`, ".a", `a lone surrogate escape at byte 12`},
		{"a byte order mark", "\xef\xbb\xbf{}", "", `starts with a byte order mark`},
		{"a truncated object", `{"a":`, ".a", `the input ends inside a value at byte 5`},
		{"longer than the limit", `{"a":"` + strings.Repeat("x", strictjson.DefaultMaxBytes) + `"}`, "", `longer than 262144 bytes`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// At the top, where the path is $, and in the places that show a path.
			for _, p := range places(Raw(tc.in), true, false) {
				got, err := Marshal(p.doc)
				if err == nil {
					t.Fatalf("%s: Marshal wrote %.80s", p.name, got)
				}
				if !errors.Is(err, strictjson.ErrMalformed) {
					t.Errorf("%s: the error does not wrap ErrMalformed: %v", p.name, err)
				}
				if want := malformedText("%s%s: %s", p.path, tc.inner, tc.what); err.Error() != want {
					t.Errorf("%s: the error is\n  %q\nwant\n  %q", p.name, err, want)
				}
				if got != nil {
					t.Errorf("%s: %d bytes next to an error", p.name, len(got))
				}
			}
		})
	}
	t.Run("a document that is too deep by itself, and the path shows the last eight steps", func(t *testing.T) {
		want := fmt.Sprintf("malformed JSON: $....a.a.a.a.a.a.a.a: nesting deeper than %d levels at byte %d", strictjson.MaxDepth, 5*strictjson.MaxDepth)
		for _, p := range places(Raw(deepDoc(strictjson.MaxDepth+1)), true, false) {
			got, err := Marshal(p.doc)
			if err == nil || err.Error() != want || got != nil {
				t.Errorf("%s: %q, %v; want %q", p.name, got, err, want)
			}
		}
	})
	t.Run("an empty Raw, nil or not", func(t *testing.T) {
		for _, r := range []Raw{nil, {}, Raw("")} {
			for _, p := range places(r, true, false) {
				got, err := Marshal(p.doc)
				refused(t, got, err, malformedText("%s: an empty Raw cannot be written", p.path))
			}
		}
	})
	t.Run("an empty Raw is left out under omitempty and written without", func(t *testing.T) {
		type doc struct {
			A Raw `json:"a,omitempty"`
			B Raw `json:"b,omitempty"`
			C Raw `json:"c,omitempty"`
		}
		got, err := Marshal(doc{A: nil, B: Raw{}, C: Raw(`{"z":1,"y":2}`)})
		if want := `{"c":{"y":2,"z":1}}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
		got, err = Marshal(struct{ A Raw }{})
		refused(t, got, err, malformedText("$.A: an empty Raw cannot be written"))
	})
	t.Run("a Raw that is a list, in a list of Raw, shows its index", func(t *testing.T) {
		got, err := Marshal(map[string]any{"l": []Raw{Raw(`{}`), Raw(`[1]`)}})
		refused(t, got, err, "malformed JSON: $.l[1]: not one JSON object")
	})
}

func TestRawHoldsJSONNotAGoValue(t *testing.T) {
	// A Raw inside a Raw is not possible: what a Raw holds is the text of one JSON object, and
	// whatever that object holds is text too. The canonical form reaches every depth of it.
	inner := Raw(`{"x":{"b":1,"a":[{"d":4,"c":3}]},"y":"z"}`)
	got, err := Marshal(map[string]any{"outer": inner})
	if want := `{"outer":{"x":{"a":[{"c":3,"d":4}],"b":1},"y":"z"}}`; err != nil || string(got) != want {
		t.Errorf("got %q, %v; want %s", got, err, want)
	}
	// The bytes of a Raw that was marshalled, put in a Raw again, are the same document.
	again, err := Marshal(struct{ R Raw }{Raw(got)})
	if want := `{"R":` + string(got) + `}`; err != nil || string(again) != want {
		t.Errorf("a Raw of a marshalled document: %q, %v", again, err)
	}
	// A Raw is not a json.RawMessage: a Go type with its own methods is refused.
	refusedGot, err := Marshal(map[string]json.RawMessage{"r": json.RawMessage(`{}`)})
	refused(t, refusedGot, err, cannotWriteVia("$", []string{"{}"}, reflect.TypeFor[json.RawMessage]().String(), reasonJSON))
}

func TestRawNestingWithItsPlace(t *testing.T) {
	deepDoc := func(n int) string { return strings.Repeat(`{"a":`, n-1) + `{}` + strings.Repeat(`}`, n-1) }
	// chain is levels maps, the innermost holding the Raw at member "r": the Raw's top-level object
	// is one level below the innermost map.
	chain := func(levels int, r Raw) map[string]any {
		var v any = r
		for i := 1; i < levels; i++ {
			v = map[string]any{"a": v}
		}
		return map[string]any{"a": v}
	}
	// chain(k) has k maps above the Raw's own first object; the whole has k + n levels.
	t.Run("6000 levels of Raw alone are written", func(t *testing.T) {
		if _, err := Marshal(Raw(deepDoc(6000))); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("6000 levels placed at level 5000 are refused", func(t *testing.T) {
		doc := chain(5000, Raw(deepDoc(6000)))
		got, err := Marshal(doc)
		refusedWith(t, got, err, fmt.Sprintf("malformed JSON: $....a.a.a.a.a.a.a.a: nesting deeper than %d levels at byte ", strictjson.MaxDepth))
	})
	t.Run("the whole at the limit is written, one over is not", func(t *testing.T) {
		const maps = 3000
		at, err := Marshal(chain(maps, Raw(deepDoc(strictjson.MaxDepth-maps))))
		if err != nil {
			t.Fatalf("exactly %d levels: %v", strictjson.MaxDepth, err)
		}
		if ok, err := IsCanonical(at); err != nil || !ok {
			t.Errorf("the result is not canonical: %v, %v", ok, err)
		}
		got, err := Marshal(chain(maps, Raw(deepDoc(strictjson.MaxDepth-maps+1))))
		refusedWith(t, got, err, fmt.Sprintf("malformed JSON: $....a.a.a.a.a.a.a.a: nesting deeper than %d levels at byte ", strictjson.MaxDepth))
	})
	t.Run("placed in a struct, a list and a map", func(t *testing.T) {
		over := Raw(deepDoc(strictjson.MaxDepth))
		for name, doc := range map[string]any{
			"a struct field": struct{ R Raw }{over},
			"a list":         map[string][]Raw{"l": {over}},
			"a map":          map[string]Raw{"k": over},
		} {
			got, err := Marshal(doc)
			if err == nil {
				t.Errorf("%s: Marshal wrote %d bytes", name, len(got))
			}
		}
	})
}

func TestRawRoundTripThroughStrictjson(t *testing.T) {
	type file struct {
		Version int `json:"version"`
		Doc     Raw `json:"doc"`
		Rest    Raw `json:"rest,omitempty"`
	}
	in := `{"doc":{"z":1,"a":[ 1, 2 ],"s":"` + bsl + `u00e9"},"version":2}`
	var f file
	if err := strictjson.Unmarshal([]byte(in), &f, strictjson.Options{}); err != nil {
		t.Fatal(err)
	}
	// The Raw holds the bytes of the member as the file has them.
	if want := `{"z":1,"a":[ 1, 2 ],"s":"` + bsl + `u00e9"}`; string(f.Doc) != want {
		t.Errorf("Doc = %q, want %q", f.Doc, want)
	}
	got, err := Marshal(f)
	want := "{\"doc\":{\"a\":[1,2],\"s\":\"é\",\"z\":1},\"version\":2}"
	if err != nil || string(got) != want {
		t.Fatalf("got %q, %v; want %q", got, err, want)
	}
	// The canonical form is a fixed point: it reads back into the same Raw and writes again.
	var back file
	if err := strictjson.Unmarshal(got, &back, strictjson.Options{}); err != nil {
		t.Fatal(err)
	}
	if string(back.Doc) != "{\"a\":[1,2],\"s\":\"é\",\"z\":1}" {
		t.Errorf("Doc after the round trip = %q", back.Doc)
	}
	again, err := Marshal(back)
	if err != nil || !bytes.Equal(again, got) {
		t.Errorf("the second write: %q, %v", again, err)
	}
	if ok, err := IsCanonical(got); err != nil || !ok {
		t.Errorf("IsCanonical = %v, %v", ok, err)
	}
	t.Run("the strict rules apply to the members of a Raw read from a file", func(t *testing.T) {
		for _, in := range []string{
			`{"version":1,"doc":{"a":1,"a":2}}`,
			`{"version":1,"doc":{"a":1.5}}`,
			`{"version":1,"doc":{"a":null}}`,
			`{"version":1,"doc":null}`,
		} {
			var f file
			if err := strictjson.Unmarshal([]byte(in), &f, strictjson.Options{}); !errors.Is(err, strictjson.ErrMalformed) {
				t.Errorf("%s: %v, want ErrMalformed", in, err)
			}
		}
	})
	t.Run("an absent optional Raw stays empty and is left out", func(t *testing.T) {
		var f file
		if err := strictjson.Unmarshal([]byte(`{"version":1,"doc":{}}`), &f, strictjson.Options{}); err != nil {
			t.Fatal(err)
		}
		got, err := Marshal(f)
		if want := `{"doc":{},"version":1}`; err != nil || string(got) != want {
			t.Errorf("got %q, %v; want %s", got, err, want)
		}
	})
}

// ---- limits ------------------------------------------------------------------------------

// allocated returns the bytes allocated while f runs.
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestMarshalSizeLimitAtTheEdge(t *testing.T) {
	limit := strictjson.DefaultMaxBytes
	// Each case builds a value of which the canonical form is frame+n bytes (for bytes, frame+n
	// bytes of Base64 text), so that n = limit-frame is exactly the limit and one more is over it.
	// The error is at the path of the value that takes the form over the limit. With n one over
	// (step more), most values are within the limit until the closing brace of the top object,
	// so the path is $; a far larger value is refused at its own path. A Raw is read by the reader
	// first, which has its own limit and says so at the Raw's path.
	member := func(n int) string { return "$." + jsonset.Shown(strings.Repeat("n", n)) }
	cases := []struct {
		name    string
		frame   int
		step    int // the growth of the form for one more n
		build   func(n int) any
		oneOver string // the whole text of the error for n+step
		farOver string // the whole text of the error for n+1000, when it is another
	}{
		{"a string", len(`{"a":""}`), 1, func(n int) any { return map[string]string{"a": strings.Repeat("x", n)} },
			tooLongAt("$"), tooLongAt("$.a")},
		{"a string with a multi-byte character", len(`{"a":""}`), 1, func(n int) any {
			return map[string]string{"a": strings.Repeat(string(rune(0x20ac)), n/3) + strings.Repeat("x", n%3)}
		}, tooLongAt("$"), tooLongAt("$.a")},
		{"a member name", len(`{"":1}`), 1, func(n int) any { return map[string]int{strings.Repeat("n", n): 1} },
			tooLongAt("$"), ""},
		{"a member name of a struct", len(`{"":1}`), 1, func(n int) any {
			return structOf(t, []string{strings.Repeat("n", n)}, []any{1}, nil)
		}, tooLongAt("$"), ""},
		{"bytes", len(`{"a":""}`), 4, func(n int) any { return map[string][]byte{"a": make([]byte, n/4*3)} },
			tooLongAt("$.a"), tooLongAt("$.a")},
		{"a Raw in a map", len(`{"a":{"k":""}}`), 1, func(n int) any {
			return map[string]Raw{"a": Raw(`{"k":"` + strings.Repeat("x", n) + `"}`)}
		}, tooLongAt("$"), "malformed JSON: $.a: longer than 262144 bytes"},
		{"a Raw at the top", len(`{"k":""}`), 1, func(n int) any { return Raw(`{"k":"` + strings.Repeat("x", n) + `"}`) },
			"malformed JSON: $: longer than 262144 bytes", ""},
		{"a Raw in a struct", len(`{"R":{"k":""}}`), 1, func(n int) any {
			return struct{ R Raw }{Raw(`{"k":"` + strings.Repeat("x", n) + `"}`)}
		}, tooLongAt("$"), "malformed JSON: $.R: longer than 262144 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := limit - tc.frame
			got, err := Marshal(tc.build(n))
			if err != nil {
				t.Fatalf("exactly the limit: %v", err)
			}
			if len(got) != limit {
				t.Fatalf("the result has %d bytes, want %d", len(got), limit)
			}
			got, err = Marshal(tc.build(n + tc.step))
			refused(t, got, err, tc.oneOver)
			far := tc.farOver
			if far == "" { // a name: the error is at the member that the name is of
				far = tooLongAt(member(n + 1000))
			}
			if tc.name == "a Raw at the top" {
				far = tc.oneOver
			}
			got, err = Marshal(tc.build(n + 1000))
			refused(t, got, err, far)
		})
	}
	t.Run("a list of integers", func(t *testing.T) {
		// {"a":[0,0,...,0]}: the frame is 7 bytes and n integers take 2n-1.
		n := (limit - len(`{"a":[]}`) + 1) / 2
		got, err := Marshal(map[string][]int{"a": make([]int, n)})
		if err != nil || len(got) != limit-1 {
			t.Fatalf("%d integers: %d bytes, %v", n, len(got), err)
		}
		// One more integer: the list ends at the limit and only the closing brace of the top object
		// is over it, so the error is at $.
		got, err = Marshal(map[string][]int{"a": make([]int, n+1)})
		refused(t, got, err, tooLongAt("$"))
		// Far over: the element that takes the form over the limit is the first whose end, 7+2i
		// bytes into the form for the element of index i, is past it.
		got, err = Marshal(map[string][]int{"a": make([]int, 2*n)})
		refused(t, got, err, tooLongAt(fmt.Sprintf("$.a[%d]", (limit-7)/2+1)))
	})
	t.Run("a Raw alone at the limit", func(t *testing.T) {
		doc := `{"k":"` + strings.Repeat("x", limit-len(`{"k":""}`)) + `"}`
		got, err := Marshal(Raw(doc))
		if err != nil || len(got) != limit {
			t.Fatalf("%d bytes: %v", len(got), err)
		}
	})
	t.Run("many small members", func(t *testing.T) {
		m := map[string]int{}
		for i := range 40000 {
			m[fmt.Sprintf("m%06d", i)] = i
		}
		// The members are written in the order of their names, which is the order of i here; the
		// first one that takes the form over the limit is the one named in the error. Its end is
		// counted here from the text of each member, not from the writer.
		end, over := 1, -1 // the opening brace
		for i := range 40000 {
			if i > 0 {
				end++ // the comma
			}
			end += len(fmt.Sprintf(`"m%06d":%d`, i, i))
			if end > limit {
				over = i
				break
			}
		}
		if over < 0 {
			t.Fatal("the members do not pass the limit")
		}
		got, err := Marshal(m)
		refused(t, got, err, tooLongAt(fmt.Sprintf("$.m%06d", over)))
	})
	t.Run("the escaped form counts, not the text", func(t *testing.T) {
		// Quotes are two bytes each: the frame and the quotes make exactly the limit; one more is over.
		quotes := (limit - len(`{"a":""}`)) / 2
		got, err := Marshal(map[string]string{"a": strings.Repeat(`"`, quotes)})
		if err != nil || len(got) != limit {
			t.Fatalf("%d quotes: %d bytes, %v", quotes, len(got), err)
		}
		got, err = Marshal(map[string]string{"a": strings.Repeat(`"`, quotes+1)})
		refused(t, got, err, tooLongAt("$.a"))
		// A separator is three bytes and is not escaped; it is counted as three.
		seps := (limit - len(`{"a":""}`)) / 3
		got, err = Marshal(map[string]string{"a": strings.Repeat(string(rune(0x2028)), seps)})
		if err != nil || len(got) != len(`{"a":""}`)+3*seps {
			t.Fatalf("%d separators: %d bytes, %v", seps, len(got), err)
		}
		got, err = Marshal(map[string]string{"a": strings.Repeat(string(rune(0x2028)), seps+1)})
		refused(t, got, err, tooLongAt("$")) // only the closing brace takes it over
		// A control is six bytes escaped.
		ctl := (limit - len(`{"a":""}`)) / 6
		got, err = Marshal(map[string]string{"a": strings.Repeat("\x01", ctl)})
		if err != nil || len(got) != len(`{"a":""}`)+6*ctl {
			t.Fatalf("%d controls: %d bytes, %v", ctl, len(got), err)
		}
		got, err = Marshal(map[string]string{"a": strings.Repeat("\x01", ctl+1)})
		refused(t, got, err, tooLongAt("$.a"))
	})
}

func TestMarshalStopsBeforeACopyOfWhatIsTooLarge(t *testing.T) {
	const huge = 32 << 20
	// Each value is built before the measurement; what is measured is the Marshal that refuses it.
	// Copying it into the result would allocate at least its size (and more for Base64 or escapes).
	t.Run("a string", func(t *testing.T) {
		v := map[string]string{"a": strings.Repeat("x", huge)}
		var err error
		bytesAllocated := allocated(func() { _, err = Marshal(v) })
		refused(t, nil, err, tooLongAt("$.a"))
		if bytesAllocated > 1<<20 {
			t.Errorf("Marshal allocated %d bytes before it refused a string of %d", bytesAllocated, huge)
		}
	})
	t.Run("a member name", func(t *testing.T) {
		v := map[string]int{strings.Repeat("n", huge): 1}
		var err error
		bytesAllocated := allocated(func() { _, err = Marshal(v) })
		refused(t, nil, err, tooLongAt("$."+jsonset.Shown(strings.Repeat("n", huge))))
		if bytesAllocated > 1<<20 {
			t.Errorf("Marshal allocated %d bytes before it refused a name of %d", bytesAllocated, huge)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		v := map[string][]byte{"a": make([]byte, huge)}
		var err error
		bytesAllocated := allocated(func() { _, err = Marshal(v) })
		refused(t, nil, err, tooLongAt("$.a"))
		if bytesAllocated > 1<<20 {
			t.Errorf("Marshal allocated %d bytes before it refused %d bytes of Base64 input", bytesAllocated, huge)
		}
	})
	t.Run("a Raw", func(t *testing.T) {
		v := map[string]Raw{"a": Raw(`{"k":"` + strings.Repeat("x", huge) + `"}`)}
		var err error
		bytesAllocated := allocated(func() { _, err = Marshal(v) })
		refused(t, nil, err, "malformed JSON: $.a: longer than 262144 bytes")
		if bytesAllocated > 1<<20 {
			t.Errorf("Marshal allocated %d bytes before it refused a Raw of %d", bytesAllocated, huge)
		}
	})
	t.Run("a list that is too long is refused when it passes the limit, not at its end", func(t *testing.T) {
		v := map[string][]int{"a": make([]int, 8<<20)}
		var err error
		bytesAllocated := allocated(func() { _, err = Marshal(v) })
		refused(t, nil, err, tooLongAt(fmt.Sprintf("$.a[%d]", (strictjson.DefaultMaxBytes-len(`{"a":[`)-1)/2+1)))
		if bytesAllocated > 4<<20 {
			t.Errorf("Marshal allocated %d bytes for a list of %d integers", bytesAllocated, 8<<20)
		}
	})
}

// The builders below make a value of a given nesting for each kind of container. Each returns the
// value, the canonical form it must be written as, and the steps that lead from the top to the
// innermost container, so that the path of a container that passes the limit is known.
func nestedMaps(levels int) (map[string]any, string, []string) {
	inner := map[string]any{}
	steps := make([]string, levels-1)
	for i := range steps {
		steps[i] = ".a"
	}
	for range levels - 1 {
		inner = map[string]any{"a": inner}
	}
	return inner, strings.Repeat(`{"a":`, levels-1) + `{}` + strings.Repeat(`}`, levels-1), steps
}

// nestedSlices is a map that holds n slices one inside the other: n+1 levels in all.
func nestedSlices(n int) (map[string]any, string, []string) {
	inner := []any{}
	for range n - 1 {
		inner = []any{inner}
	}
	steps := []string{".a"}
	for range n - 1 {
		steps = append(steps, "[0]")
	}
	return map[string]any{"a": inner}, `{"a":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`, steps
}

// nestedArrays is a map that holds n arrays of one element inside each other, the innermost empty.
func nestedArrays(n int) (map[string]any, string, []string) {
	var inner any = [0]int{}
	for range n - 1 {
		inner = [1]any{inner}
	}
	steps := []string{".a"}
	for range n - 1 {
		steps = append(steps, "[0]")
	}
	return map[string]any{"a": inner}, `{"a":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`, steps
}

// nestedList is a list of n nodes: n levels in all.
func nestedList(n int) (*listNode, string, []string) {
	head := &listNode{}
	steps := make([]string, n-1)
	for i := range steps {
		steps[i] = ".Next"
	}
	for range n - 1 {
		head = &listNode{Next: head}
	}
	return head, strings.Repeat(`{"Next":`, n-1) + `{}` + strings.Repeat(`}`, n-1), steps
}

type (
	// pointerSlice holds the next level behind a pointer: a pointer is not a level.
	pointerSlice []*pointerSlice
	pointerMap   map[string]*pointerMap
)

// nestedPointers is levels levels of maps with a pointer between every two of them.
func nestedPointers(levels int) (*pointerMap, string, []string) {
	head := &pointerMap{}
	steps := make([]string, levels-1)
	for i := range steps {
		steps[i] = ".a"
	}
	for range levels - 1 {
		head = &pointerMap{"a": head}
	}
	return head, strings.Repeat(`{"a":`, levels-1) + `{}` + strings.Repeat(`}`, levels-1), steps
}

// nestedMixed is levels levels of maps, slices, arrays and structs in turn, the first a map.
func nestedMixed(levels int) (any, string, []string) {
	var inner any
	var opens, closes, steps []string
	for level := levels; level >= 1; level-- {
		switch {
		case level == levels && level%2 == 1:
			inner = map[string]any{}
			opens, closes = append(opens, `{`), append(closes, `}`)
		case level == levels:
			inner = []any{}
			opens, closes = append(opens, `[`), append(closes, `]`)
		case level%4 == 1:
			inner = map[string]any{"a": inner}
			opens, closes = append(opens, `{"a":`), append(closes, `}`)
			steps = append(steps, ".a")
		case level%4 == 2:
			inner = []any{inner}
			opens, closes = append(opens, `[`), append(closes, `]`)
			steps = append(steps, "[0]")
		case level%4 == 3:
			inner = [1]any{inner}
			opens, closes = append(opens, `[`), append(closes, `]`)
			steps = append(steps, "[0]")
		default:
			inner = struct{ A any }{inner}
			opens, closes = append(opens, `{"A":`), append(closes, `}`)
			steps = append(steps, ".A")
		}
	}
	slices.Reverse(opens)
	slices.Reverse(steps)
	return inner, strings.Join(opens, "") + strings.Join(closes, ""), steps
}

func TestMarshalNestingDepth(t *testing.T) {
	limit := strictjson.MaxDepth
	cases := []struct {
		name  string
		build func(levels int) (any, string, []string)
	}{
		{"maps in maps", func(n int) (any, string, []string) { return nestedMaps(n) }},
		{"slices in a map", func(n int) (any, string, []string) { return nestedSlices(n - 1) }},
		{"arrays in a map", func(n int) (any, string, []string) { return nestedArrays(n - 1) }},
		{"a linked list of structs behind pointers", func(n int) (any, string, []string) { return nestedList(n) }},
		{"maps behind pointers", func(n int) (any, string, []string) { return nestedPointers(n) }},
		{"maps, slices, arrays and structs in turn", nestedMixed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The levels the JSON has: exactly the limit is written and is canonical, one more is refused.
			for _, levels := range []int{3, 4, 5, 1000, limit - 1, limit} {
				v, want, _ := tc.build(levels)
				got, err := Marshal(v)
				if err != nil {
					t.Fatalf("%d levels: %v", levels, err)
				}
				sameBytes(t, fmt.Sprintf("%d levels", levels), got, want)
				if ok, err := IsCanonical(got); err != nil || !ok {
					t.Errorf("%d levels: the output is not canonical: %v, %v", levels, ok, err)
				}
			}
			// The container that passes the limit is the one at level limit+1, which is reached by
			// limit steps from the top: the error is at its path, which shows the last eight.
			for _, levels := range []int{limit + 1, limit + 2, 2 * limit} {
				v, _, steps := tc.build(levels)
				got, err := Marshal(v)
				refused(t, got, err, tooDeepText(stepsPath(steps[:limit])))
			}
		})
	}
	t.Run("a list of lists of pointers to lists", func(t *testing.T) {
		// A pointer between two levels is not a level and does not add up.
		inner := pointerSlice{}
		for range limit - 2 {
			prev := inner
			inner = pointerSlice{&prev}
		}
		got, err := Marshal(map[string]any{"a": inner})
		if err != nil {
			t.Fatalf("%d levels: %v", limit-1, err)
		}
		if len(got) != len(`{"a":`)+2*(limit-2)+len(`[]`)+1 {
			t.Errorf("the output has %d bytes", len(got))
		}
	})
	t.Run("a byte slice and a string are not levels", func(t *testing.T) {
		inner, want, _ := nestedMaps(limit)
		deepest := inner
		for len(deepest) > 0 {
			deepest = deepest["a"].(map[string]any)
		}
		deepest["b"] = []byte("hi")
		deepest["c"] = "text"
		want = strings.Replace(want, `{}`, `{"b":"aGk=","c":"text"}`, 1)
		got, err := Marshal(inner)
		if err != nil {
			t.Fatal(err)
		}
		sameBytes(t, "bytes at the limit", got, want)
	})
	t.Run("an empty list at the limit is a level, an integer in it is not", func(t *testing.T) {
		inner, _, _ := nestedMaps(limit - 1)
		deepest := inner
		for len(deepest) > 0 {
			deepest = deepest["a"].(map[string]any)
		}
		deepest["l"] = []int{1, 2}
		if _, err := Marshal(inner); err != nil {
			t.Fatalf("a list at level %d: %v", limit, err)
		}
		deepest["l"] = [][]int{{}}
		got, err := Marshal(inner)
		// limit-2 members "a", then "l" and the first element of the list: limit steps.
		refused(t, got, err, tooDeepText("$....a.a.a.a.a.a.l[0]"))
	})
}

func TestMarshalOfAValueThatPointsToItselfEndsInTheNestingError(t *testing.T) {
	type loop struct{ Next *loop }
	type tree struct {
		Kids []*tree `json:",omitempty"`
	}
	type graph struct {
		Edges map[string]*graph `json:",omitempty"`
	}
	l := &loop{}
	l.Next = l
	x := &mutualX{}
	x.Y = &mutualY{X: x}
	m := map[string]any{}
	m["self"] = m
	s := make([]any, 1)
	s[0] = s
	var arr [1]any
	arr[0] = &arr
	tr := &tree{}
	tr.Kids = []*tree{tr}
	g := &graph{}
	g.Edges = map[string]*graph{"me": g}
	nested := map[string]any{"a": map[string]any{}}
	nested["a"].(map[string]any)["up"] = nested
	limit := strictjson.MaxDepth
	// The way down is a cycle of steps, after the steps that lead into the cycle; the container that
	// passes the limit is the one that limit steps lead to.
	for _, tc := range []struct {
		name  string
		v     any
		lead  []string
		cycle []string
	}{
		{"a struct with a pointer to itself", l, nil, []string{".Next"}},
		{"a struct value that holds it", *l, nil, []string{".Next"}},
		{"two structs that point to each other", x, nil, []string{".Y", ".X"}},
		{"a map that holds itself", m, nil, []string{".self"}},
		{"a map that holds itself, in a map", map[string]any{"m": m}, []string{".m"}, []string{".self"}},
		{"a slice that holds itself", map[string]any{"s": s}, []string{".s"}, []string{"[0]"}},
		{"an array that holds a pointer to it", map[string]any{"a": &arr}, []string{".a"}, []string{"[0]"}},
		{"a tree that has itself as a child", tr, nil, []string{".Kids", "[0]"}},
		{"a graph that has itself as an edge", g, nil, []string{".Edges", ".me"}},
		{"a map that holds a map that holds it", nested, nil, []string{".a", ".up"}},
		{"a pointer to itself in an interface key", map[string]any{"x": l}, []string{".x"}, []string{".Next"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			refused(t, got, err, tooDeepText(cyclePath(tc.lead, tc.cycle, limit)))
		})
	}
	t.Run("a pointer that points to itself through an interface is refused as a type", func(t *testing.T) {
		var p any
		p = &p
		got, err := Marshal(map[string]any{"p": p})
		refused(t, got, err, cannotWrite("$.p", "*interface {}", reasonPtrPtr))
	})
}

type (
	mutualX struct{ Y *mutualY }
	mutualY struct{ X *mutualX }
)

// ---- the property the package comment promises -------------------------------------------

func TestMarshalEqualsCanonicalizeOfTheStandardEncoder(t *testing.T) {
	check := func(t *testing.T, label string, v any) {
		t.Helper()
		got, err := Marshal(v)
		if err != nil {
			t.Errorf("%s: Marshal refused: %v", label, err)
			return
		}
		std, err := json.Marshal(v)
		if err != nil {
			t.Errorf("%s: the standard encoder refused: %v", label, err)
			return
		}
		want, err := Canonicalize(std)
		if err != nil {
			t.Errorf("%s: Canonicalize of the standard encoder's output: %v", label, err)
			return
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: Marshal and Canonicalize(json.Marshal) differ:\n  %.300q\n  %.300q", label, got, want)
		}
	}
	t.Run("every value of the table, in every place", func(t *testing.T) {
		for _, tc := range acceptedValues() {
			for _, p := range places(tc.v, false, false) {
				if p.name == "at the top" && !strings.HasPrefix(tc.want, "{") {
					continue
				}
				check(t, tc.name+" "+p.name, p.doc)
			}
		}
	})
	t.Run("random values of accepted kinds", func(t *testing.T) {
		r := rand.New(rand.NewSource(1927))
		for i := range 400 {
			check(t, fmt.Sprintf("shape %d", i), randomShape(r))
			check(t, fmt.Sprintf("tree %d", i), randomTree(r, 0, true))
		}
	})
}

// shape is a struct of many kinds of field, in an order and with tags that are not the sorted
// order, for the random values.
type shape struct {
	Zeta   int               `json:"zeta"`
	Alpha  string            `json:"alpha,omitempty"`
	Flag   bool              `json:",omitempty"`
	N      *int              `json:"n,omitempty"`
	List   []int             `json:"list"`
	Map    map[string]string `json:"map"`
	Doc    Raw               `json:"doc,omitempty"`
	Data   []byte            `json:"data,omitempty"`
	Pair   [2]uint8          `json:"pair"`
	Any    any               `json:"any,omitempty"`
	In     inside            `json:"in"`
	P      *inside           `json:"p,omitempty"`
	Kids   []inside          `json:"kids,omitempty"`
	Skip   float64           `json:"-"`
	hidden int
	Named  myInt            `json:"named,omitempty"`
	Words  []myString       `json:"words,omitempty"`
	Keyed  map[myKey][]byte `json:"keyed,omitempty"`
	Wide   int64            `json:"wide"`
	Small  uint8            `json:"small,omitempty"`
	Big    uint64           `json:"big,omitempty"`
}

type inside struct {
	Name string   `json:"Name"`
	Tags []string `json:"tags,omitempty"`
	X    int8
	Y    *bool `json:"y,omitempty"`
}

// randomText makes text from characters of every width and of both sides of the surrogate range,
// the markup characters and the controls, so that the standard encoder's escapes are exercised.
func randomText(r *rand.Rand) string {
	pool := []rune{'a', 'b', 'Z', '0', '\r', 0, 0x1f, '~', 0x7f, 0x80, 0xe9, 0x7ff, 0x800, '<', '>', '&', '\'',
		0x2028, 0x2029, 0xd7ff, 0xe000, 0xf000, 0xfb33, 0xfffd, 0xffff, 0x10000, 0x1f600, 0x10ffff, '"', '\\', '/', ' ', '\n', '\t'}
	var b strings.Builder
	for range r.Intn(6) {
		b.WriteRune(pool[r.Intn(len(pool))])
	}
	return b.String()
}

func randomBytes(r *rand.Rand) []byte {
	b := make([]byte, r.Intn(9))
	r.Read(b)
	return b
}

func randomInt(r *rand.Rand) int64 {
	switch r.Intn(4) {
	case 0:
		return int64(r.Intn(21) - 10)
	case 1:
		return r.Int63n(safeMax + 1)
	case 2:
		return -r.Int63n(safeMax + 1)
	default:
		return int64(r.Intn(2000) - 1000)
	}
}

func randomInside(r *rand.Rand) inside {
	v := inside{Name: randomText(r), X: int8(r.Intn(256) - 128)}
	if r.Intn(2) == 0 {
		v.Tags = []string{randomText(r), randomText(r)}
	}
	if r.Intn(2) == 0 {
		v.Y = ptr(r.Intn(2) == 0)
	}
	return v
}

func randomShape(r *rand.Rand) shape {
	v := shape{Zeta: int(randomInt(r)), List: []int{}, Map: map[string]string{}, Wide: randomInt(r)}
	if r.Intn(2) == 0 {
		v.Alpha = randomText(r)
	}
	v.Flag = r.Intn(2) == 0
	if r.Intn(2) == 0 {
		v.N = ptr(int(randomInt(r)))
	}
	for range r.Intn(4) {
		v.List = append(v.List, int(randomInt(r)))
	}
	for range r.Intn(4) {
		v.Map[randomText(r)] = randomText(r)
	}
	if r.Intn(2) == 0 {
		v.Doc = Raw(` { "b" : ` + fmt.Sprint(randomInt(r)) + ` , "a" : [ true , "` + strings.NewReplacer(`"`, ``, `\`, ``, "\x00", "", "\n", "", "\t", "", "\r", "", "\x1f", "").Replace(randomText(r)) + `" ] } `)
	}
	if r.Intn(2) == 0 {
		v.Data = randomBytes(r)
	}
	v.Pair = [2]uint8{uint8(r.Intn(256)), uint8(r.Intn(256))}
	if r.Intn(2) == 0 {
		v.Any = randomTree(r, 1, false)
	}
	v.In = randomInside(r)
	if r.Intn(2) == 0 {
		in := randomInside(r)
		v.P = &in
	}
	for range r.Intn(3) {
		v.Kids = append(v.Kids, randomInside(r))
	}
	v.Skip = 1.5
	v.hidden = 3
	if r.Intn(2) == 0 {
		v.Named = myInt(randomInt(r) % 1000)
	}
	for range r.Intn(3) {
		v.Words = append(v.Words, myString(randomText(r)))
	}
	if r.Intn(2) == 0 {
		v.Keyed = map[myKey][]byte{myKey(randomText(r)): randomBytes(r)}
	}
	v.Small = uint8(r.Intn(256))
	if r.Intn(2) == 0 {
		v.Big = uint64(r.Int63n(safeMax + 1))
	}
	return v
}

// randomTree makes a value inside a document from accepted kinds only. top says that the value is
// the document itself, so that it is an object.
func randomTree(r *rand.Rand, depth int, top bool) any {
	kind := r.Intn(12)
	if top {
		kind = 0
	}
	if depth > 3 && kind <= 3 {
		kind += 4
	}
	switch kind {
	case 0:
		m := map[string]any{}
		for range r.Intn(5) {
			m[randomText(r)] = randomTree(r, depth+1, false)
		}
		return m
	case 1:
		l := []any{}
		for range r.Intn(4) {
			l = append(l, randomTree(r, depth+1, false))
		}
		return l
	case 2:
		return randomInside(r)
	case 3:
		in := randomInside(r)
		return &in
	case 4:
		return randomText(r)
	case 5:
		return r.Intn(2) == 0
	case 6:
		return randomInt(r)
	case 7:
		return randomBytes(r)
	case 8:
		return uint8(r.Intn(256))
	case 9:
		return myString(randomText(r))
	case 10:
		return Raw(`{"k":` + fmt.Sprint(randomInt(r)) + `,"a":{}}`)
	default:
		return [2]int16{int16(r.Intn(100)), int16(-r.Intn(100))}
	}
}
