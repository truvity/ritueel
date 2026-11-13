package strictjson

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The rules about members, and what happens to the value that is passed in: the value is replaced
// as a whole, and on an error it is as it was.

// fullT holds a field of every kind that a document can fill, with members that the tests can
// break one at a time.
type fullT struct {
	B    bool           `json:"b"`
	I8   int8           `json:"i8"`
	U16  uint16         `json:"u16"`
	I64  int64          `json:"i64"`
	S    string         `json:"s"`
	By   []byte         `json:"by"`
	Arr  [2]int         `json:"arr"`
	L    []string       `json:"l"`
	M    map[string]int `json:"m"`
	P    *point         `json:"p"`
	R    Raw            `json:"r"`
	A    any            `json:"a"`
	Nest struct {
		X []int             `json:"X"`
		Y map[string]string `json:"Y"`
	} `json:"nest"`
	Ptrs   []*int `json:"ptrs"`
	Skip   string `json:"-"`
	hidden int
}

// fullMembers are the members of a document that fills fullT, in the order of the fields, each
// with a text that is right and one that is wrong for its field (none for the field of any).
var fullMembers = []struct{ name, good, bad string }{
	{"b", `true`, `"x"`},
	{"i8", `-8`, `128`},
	{"u16", `16`, `-1`},
	{"i64", `64`, `"x"`},
	{"s", `"new"`, `1`},
	{"by", `"aGk="`, `"AB=="`},
	{"arr", `[7,8]`, `[1]`},
	{"l", `["x","y"]`, `["x",1]`},
	{"m", `{"k":5}`, `{"k":5,"j":"x"}`},
	{"p", `{"X":3,"Y":4}`, `{"X":3,"Y":"x"}`},
	{"r", `{"z":1}`, `[]`},
	{"a", `{"q":[1]}`, ``},
	{"nest", `{"X":[1],"Y":{"a":"b"}}`, `{"X":[1],"Y":{"a":1}}`},
	{"ptrs", `[1,2]`, `[1,"x"]`},
}

// fullDoc writes the document of the members in the order given, the one named bad (if any) with
// its wrong text.
func fullDoc(order []int, bad string) string {
	var parts []string
	for _, i := range order {
		m := fullMembers[i]
		text := m.good
		if m.name == bad {
			text = m.bad
		}
		parts = append(parts, `"`+m.name+`":`+text)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func inOrder() []int {
	order := make([]int, len(fullMembers))
	for i := range order {
		order[i] = i
	}
	return order
}

func reversed() []int {
	order := inOrder()
	for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
		order[i], order[j] = order[j], order[i]
	}
	return order
}

// prefilled is a value with something in every field.
func prefilled() fullT {
	n1, n2, n3 := 91, 92, 93
	v := fullT{
		B: true, I8: 99, U16: 999, I64: 9999, S: "old", By: []byte("old"), Arr: [2]int{91, 92},
		L: []string{"old", "older", "oldest"}, M: map[string]int{"old": 1}, P: &point{X: 91, Y: 92},
		R: Raw(`{"old":true}`), A: map[string]any{"old": int64(1)}, Ptrs: []*int{&n1, &n2, &n3},
		Skip: "skipped", hidden: 5,
	}
	v.Nest.X = []int{91, 92}
	v.Nest.Y = map[string]string{"old": "old"}
	return v
}

// wantFull is what the document of every good member fills.
func wantFull() fullT {
	n1, n2 := 1, 2
	v := fullT{
		B: true, I8: -8, U16: 16, I64: 64, S: "new", By: []byte("hi"), Arr: [2]int{7, 8},
		L: []string{"x", "y"}, M: map[string]int{"k": 5}, P: &point{X: 3, Y: 4},
		R: Raw(`{"z":1}`), A: map[string]any{"q": []any{int64(1)}}, Ptrs: []*int{&n1, &n2},
	}
	v.Nest.X = []int{1}
	v.Nest.Y = map[string]string{"a": "b"}
	return v
}

func TestTheValueIsReplacedAsAWhole(t *testing.T) {
	t.Run("every field comes from the document, and what was there is gone", func(t *testing.T) {
		v := prefilled()
		doc := fullDoc(inOrder(), "")
		if err := Unmarshal([]byte(doc), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if want := wantFull(); !reflect.DeepEqual(v, want) {
			t.Errorf("got  %+v\nwant %+v", v, want)
		}
	})
	t.Run("a member that is missing is the zero value, for every field in turn", func(t *testing.T) {
		for i, m := range fullMembers {
			v := prefilled()
			order := inOrder()
			order = append(order[:i], order[i+1:]...)
			if err := Unmarshal([]byte(fullDoc(order, "")), &v, Options{}); err != nil {
				t.Fatalf("without %s: %v", m.name, err)
			}
			want := wantFull()
			// The field of the missing member is zero in the wanted value.
			zero := reflect.Zero(reflect.TypeFor[fullT]())
			for f := range reflect.TypeFor[fullT]().NumField() {
				if tag := reflect.TypeFor[fullT]().Field(f).Tag.Get("json"); tag == m.name {
					reflect.ValueOf(&want).Elem().Field(f).Set(zero.Field(f))
				}
			}
			if !reflect.DeepEqual(v, want) {
				t.Errorf("without %s:\ngot  %+v\nwant %+v", m.name, v, want)
			}
		}
	})
	t.Run("an empty document makes the zero value", func(t *testing.T) {
		v := prefilled()
		if err := Unmarshal([]byte(`{}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(v, fullT{}) {
			t.Errorf("got %+v", v)
		}
	})
	t.Run("a field tagged dash and an unexported field are zero, whatever they held", func(t *testing.T) {
		v := prefilled()
		if v.Skip == "" || v.hidden == 0 {
			t.Fatal("the test value does not hold anything in them")
		}
		if err := Unmarshal([]byte(fullDoc(inOrder(), "")), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if v.Skip != "" || v.hidden != 0 {
			t.Errorf("Skip = %q, hidden = %d", v.Skip, v.hidden)
		}
		// Nor does a member by the name of such a field fill it: it is a member that nobody knows.
		w := prefilled()
		err := Unmarshal([]byte(`{"Skip":"x"}`), &w, Options{})
		fail(t, err, mal("$.Skip", "unknown member"))
		if err := Unmarshal([]byte(`{"Skip":"x","hidden":3}`), &w, Options{AllowUnknown: true}); err != nil || w.Skip != "" || w.hidden != 0 {
			t.Errorf("%+v, %v", w, err)
		}
	})
	t.Run("a map that was there is not merged into, not emptied and not the new map", func(t *testing.T) {
		old := map[string]int{"keep": 1, "k": 100}
		v := struct{ M map[string]int }{M: old}
		if err := Unmarshal([]byte(`{"M":{"k":5,"new":6}}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(v.M, map[string]int{"k": 5, "new": 6}) {
			t.Errorf("M = %v", v.M)
		}
		if !reflect.DeepEqual(old, map[string]int{"keep": 1, "k": 100}) {
			t.Errorf("the old map was written into: %v", old)
		}
		if reflect.ValueOf(v.M).Pointer() == reflect.ValueOf(old).Pointer() {
			t.Error("the new map is the old one")
		}
		// An empty object gives an empty map that is not nil, and leaves the old one as it is.
		if err := Unmarshal([]byte(`{"M":{}}`), &v, Options{}); err != nil || v.M == nil || len(v.M) != 0 {
			t.Errorf("an empty object: %#v, %v", v.M, err)
		}
		// At the top as well.
		top := map[string]int{"keep": 1}
		held := top
		if err := Unmarshal([]byte(`{"new":2}`), &top, Options{}); err != nil || !reflect.DeepEqual(top, map[string]int{"new": 2}) || !reflect.DeepEqual(held, map[string]int{"keep": 1}) {
			t.Errorf("top = %v, the old one %v, %v", top, held, err)
		}
	})
	t.Run("a slice that was there is not appended to and not written into", func(t *testing.T) {
		backing := make([]int, 3, 10)
		copy(backing, []int{1, 2, 3})
		v := struct{ L []int }{L: backing}
		if err := Unmarshal([]byte(`{"L":[9]}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(v.L, []int{9}) {
			t.Errorf("L = %v", v.L)
		}
		if !reflect.DeepEqual(backing[:10], []int{1, 2, 3, 0, 0, 0, 0, 0, 0, 0}) {
			t.Errorf("the old backing array was written into: %v", backing[:10])
		}
		// A longer list than the old capacity, and an empty one.
		if err := Unmarshal([]byte(`{"L":[1,2,3,4,5,6,7,8,9,10,11,12]}`), &v, Options{}); err != nil || len(v.L) != 12 {
			t.Errorf("%v, %v", v.L, err)
		}
		if err := Unmarshal([]byte(`{"L":[]}`), &v, Options{}); err != nil || v.L == nil || len(v.L) != 0 {
			t.Errorf("an empty list: %#v, %v", v.L, err)
		}
		// A slice of bytes the same way.
		bb := make([]byte, 2, 8)
		copy(bb, "ab")
		w := struct{ B []byte }{B: bb}
		if err := Unmarshal([]byte(`{"B":"eg=="}`), &w, Options{}); err != nil || string(w.B) != "z" {
			t.Errorf("%q, %v", w.B, err)
		}
		if string(bb[:8]) != "ab\x00\x00\x00\x00\x00\x00" {
			t.Errorf("the old bytes were written into: %q", bb[:8])
		}
	})
	t.Run("a pointer that was there is replaced, and what it pointed to is not filled", func(t *testing.T) {
		old := &point{X: 1, Y: 2}
		v := struct{ P *point }{P: old}
		if err := Unmarshal([]byte(`{"P":{"X":5}}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if v.P == old || *v.P != (point{X: 5}) {
			t.Errorf("P = %+v (the old one: %v)", v.P, v.P == old)
		}
		if *old != (point{X: 1, Y: 2}) {
			t.Errorf("the old pointee was filled: %+v", *old)
		}
		// A pointer to an integer, and a missing member, which leaves the pointer nil.
		n := 7
		w := struct{ N *int }{N: &n}
		if err := Unmarshal([]byte(`{"N":8}`), &w, Options{}); err != nil || *w.N != 8 || n != 7 {
			t.Errorf("%v, %d, %v", w.N, n, err)
		}
		if err := Unmarshal([]byte(`{}`), &w, Options{}); err != nil || w.N != nil {
			t.Errorf("a missing member: %v, %v", w.N, err)
		}
		// At the top: a pointer to a pointer to a struct.
		top := &point{X: 1, Y: 2}
		held := top
		if err := Unmarshal([]byte(`{"X":9}`), &top, Options{}); err != nil || top == held || *top != (point{X: 9}) || *held != (point{X: 1, Y: 2}) {
			t.Errorf("top = %+v, the old one %+v, %v", top, held, err)
		}
		var nilTop *point
		if err := Unmarshal([]byte(`{"X":9}`), &nilTop, Options{}); err != nil || nilTop == nil || *nilTop != (point{X: 9}) {
			t.Errorf("a nil pointer at the top: %+v, %v", nilTop, err)
		}
	})
	t.Run("a struct that was there is replaced, not filled where the document names it", func(t *testing.T) {
		v := struct {
			In point
			A  [3]int
		}{In: point{X: 1, Y: 2}, A: [3]int{9, 9, 9}}
		if err := Unmarshal([]byte(`{"In":{"X":5},"A":[1,2,3]}`), &v, Options{}); err != nil || v.In != (point{X: 5}) || v.A != [3]int{1, 2, 3} {
			t.Errorf("%+v, %v", v, err)
		}
		if err := Unmarshal([]byte(`{}`), &v, Options{}); err != nil || v.In != (point{}) || v.A != ([3]int{}) {
			t.Errorf("a missing struct and array: %+v, %v", v, err)
		}
	})
	t.Run("a Raw that was there is replaced and is a copy", func(t *testing.T) {
		old := Raw(`{"old":1}`)
		v := struct{ R Raw }{R: old}
		doc := []byte(`{"R":{"new":2}}`)
		if err := Unmarshal(doc, &v, Options{}); err != nil || string(v.R) != `{"new":2}` || string(old) != `{"old":1}` {
			t.Errorf("%q, the old one %q, %v", v.R, old, err)
		}
		for i := range doc {
			doc[i] = ' '
		}
		if string(v.R) != `{"new":2}` {
			t.Errorf("the Raw is part of the document: %q", v.R)
		}
	})
	t.Run("an element of a list or a map that was there is not reused", func(t *testing.T) {
		keep := &point{X: 1}
		v := struct {
			L []*point
			M map[string]*point
		}{L: []*point{keep}, M: map[string]*point{"k": keep}}
		if err := Unmarshal([]byte(`{"L":[{"X":2}],"M":{"k":{"Y":3}}}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if *keep != (point{X: 1}) || *v.L[0] != (point{X: 2}) || *v.M["k"] != (point{Y: 3}) {
			t.Errorf("keep = %+v, L = %+v, M = %+v", *keep, *v.L[0], *v.M["k"])
		}
	})
}

// ---- on an error the value is as it was ---------------------------------------------------

// unchanged checks that an Unmarshal that fails leaves what the pointer points to as it was, and
// that the pointer inside it, where there is one, still points to the same value.
func unchanged(t *testing.T, name string, v any, doc string, opts Options) {
	t.Helper()
	rv := reflect.ValueOf(v).Elem()
	before := deepCopy(rv)
	var pointee reflect.Value
	var pointeeBefore reflect.Value
	if rv.Kind() == reflect.Pointer && !rv.IsNil() {
		pointee = rv
		pointeeBefore = deepCopy(rv.Elem())
	}
	pointer := rv
	err := Unmarshal([]byte(doc), v, opts)
	if err == nil {
		t.Errorf("%s: %s was read", name, doc)
		return
	}
	if !reflect.DeepEqual(before.Interface(), rv.Interface()) {
		t.Errorf("%s: after %q the value is\n  %+v\nwas\n  %+v", name, err, rv.Interface(), before.Interface())
	}
	if pointee.IsValid() {
		if pointee.Pointer() != pointer.Pointer() {
			t.Errorf("%s: the pointer was replaced", name)
		}
		if !reflect.DeepEqual(pointee.Elem().Interface(), pointeeBefore.Interface()) {
			t.Errorf("%s: the value it points to changed", name)
		}
	}
}

func TestOnAnErrorTheValueIsUnchanged(t *testing.T) {
	// Every member wrong in turn, in a document in which it comes first and in one in which it
	// comes last, and alone.
	for _, m := range fullMembers {
		if m.bad == "" {
			continue
		}
		for name, order := range map[string][]int{"in order": inOrder(), "reversed": reversed()} {
			doc := fullDoc(order, m.name)
			v := prefilled()
			unchanged(t, fmt.Sprintf("%s wrong, %s", m.name, name), &v, doc, Options{})
			p := prefilled()
			pv := &p
			unchanged(t, fmt.Sprintf("%s wrong, %s, through a pointer", m.name, name), &pv, doc, Options{})
		}
		v := prefilled()
		unchanged(t, m.name+" wrong, alone", &v, `{"`+m.name+`":`+m.bad+`}`, Options{})
	}
	// A document that is wrong in a way that is not about one member, at every position.
	breaks := []struct{ name, doc string }{
		{"an unknown member first", `{"zzz":1,` + fullDoc(inOrder(), "")[1:]},
		{"an unknown member last", fullDoc(inOrder(), "")[:len(fullDoc(inOrder(), ""))-1] + `,"zzz":1}`},
		{"an unknown member in the middle", `{"b":true,"i8":-8,"zzz":1,"u16":16}`},
		{"an unknown member deep down", `{"b":true,"nest":{"X":[1],"zzz":1}}`},
		{"a name in another case", `{"b":true,"S":"x"}`},
		{"a name in another case, first", `{"B":true,"s":"x"}`},
		{"a repeated member", `{"b":true,"s":"x","b":false}`},
		{"a repeated member deep down", `{"s":"x","nest":{"X":[1],"X":[2]}}`},
		{"a repeated member in an unknown one", `{"s":"x","zzz":{"a":1,"a":2}}`},
		{"null", `{"s":"x","b":null}`},
		{"null deep down", `{"s":"x","nest":{"X":[1,null]}}`},
		{"a float", `{"s":"x","i8":1.5}`},
		{"a float in an unknown member", `{"s":"x","zzz":[1.5]}`},
		{"an integer that is too long", `{"s":"x","i64":99999999999999999999}`},
		{"a lone surrogate", `{"s":"` + bs + `ud800"}`},
		{"text after the object", `{"s":"x"} {}`},
		{"not UTF-8", "{\"s\":\"\xff\"}"},
		{"a byte order mark", "\xef\xbb\xbf{\"s\":\"x\"}"},
		{"not an object", `["s","x"]`},
		{"empty", ``},
		{"truncated", `{"s":"x","b":`},
		{"too deep", `{"s":"x","nest":` + strings.Repeat(`[`, MaxDepth+1) + `}`},
		{"too long", `{"s":"` + strings.Repeat("x", DefaultMaxBytes) + `"}`},
		{"the wrong kind for the whole document", `{"s":"x","l":{}}`},
		{"the wrong kind in a list", `{"s":"x","l":[["a"]]}`},
		{"an array of the wrong length", `{"s":"x","arr":[1,2,3]}`},
		{"a number that does not fit", `{"s":"x","u16":65536}`},
	}
	for _, b := range breaks {
		v := prefilled()
		unchanged(t, b.name, &v, b.doc, Options{})
		if !strings.HasPrefix(b.name, "an unknown member") { // that is what AllowUnknown accepts
			w := prefilled()
			unchanged(t, b.name+", with AllowUnknown", &w, b.doc, Options{AllowUnknown: true})
		}
	}
	t.Run("a type that is refused", func(t *testing.T) {
		type bad struct {
			A int
			F float64
		}
		v := bad{A: 5, F: 1}
		unchanged(t, "a float field", &v, `{"A":1}`, Options{})
		type worse struct {
			A int
			E embedsValue
		}
		w := worse{A: 5}
		unchanged(t, "an embedding field", &w, `{"A":1}`, Options{})
	})
	t.Run("a map, a Raw, an interface and a pointer at the top", func(t *testing.T) {
		m := map[string]int{"keep": 1}
		unchanged(t, "a map, an error last", &m, `{"a":1,"b":2,"c":"x"}`, Options{})
		unchanged(t, "a map, an error first", &m, `{"c":"x","a":1,"b":2}`, Options{})
		r := Raw(`{"old":1}`)
		unchanged(t, "a Raw", &r, `{"a":}`, Options{})
		unchanged(t, "a Raw and text after", &r, `{"a":1} x`, Options{})
		var a any = map[string]any{"old": int64(1)}
		unchanged(t, "an interface", &a, `{"a":null}`, Options{})
		var n any
		unchanged(t, "an empty interface", &n, `{"a":1.5}`, Options{})
		p := &point{X: 1, Y: 2}
		unchanged(t, "a pointer to a struct", &p, `{"X":1,"Y":"x"}`, Options{})
		unchanged(t, "a pointer to a struct, unknown", &p, `{"X":9,"Z":1}`, Options{})
		var np *point
		unchanged(t, "a nil pointer to a struct", &np, `{"X":9,"Y":"x"}`, Options{})
		if np != nil {
			t.Error("a nil pointer was made on an error")
		}
		pm := &map[string]int{"keep": 1}
		unchanged(t, "a pointer to a map", &pm, `{"a":1,"b":"x"}`, Options{})
		pr := &Raw{}
		unchanged(t, "a pointer to a Raw", &pr, `[]`, Options{})
		s := point{X: 1, Y: 2}
		unchanged(t, "a struct, a number that does not fit", &s, `{"X":1,"Y":9223372036854775808}`, Options{})
	})
	t.Run("a slice with room to spare is not written into by a document that fails", func(t *testing.T) {
		backing := make([]int, 3, 10)
		copy(backing, []int{1, 2, 3})
		v := struct{ L []int }{L: backing}
		if err := Unmarshal([]byte(`{"L":[9,8,"x"]}`), &v, Options{}); err == nil {
			t.Fatal("no error")
		}
		if !reflect.DeepEqual(backing[:10], []int{1, 2, 3, 0, 0, 0, 0, 0, 0, 0}) || len(v.L) != 3 {
			t.Errorf("backing %v, L %v", backing[:10], v.L)
		}
	})
	t.Run("a map is not written into by a document that fails", func(t *testing.T) {
		old := map[string]int{"keep": 1}
		v := struct{ M map[string]int }{M: old}
		if err := Unmarshal([]byte(`{"M":{"a":1,"b":"x"}}`), &v, Options{}); err == nil {
			t.Fatal("no error")
		}
		if !reflect.DeepEqual(old, map[string]int{"keep": 1}) || reflect.ValueOf(v.M).Pointer() != reflect.ValueOf(old).Pointer() {
			t.Errorf("old %v, M %v", old, v.M)
		}
	})
	t.Run("a struct pointed to by a field is not filled by a document that fails later", func(t *testing.T) {
		pt := &point{X: 1, Y: 2}
		v := struct {
			P *point
			S string
		}{P: pt, S: "old"}
		if err := Unmarshal([]byte(`{"P":{"X":5},"S":1}`), &v, Options{}); err == nil {
			t.Fatal("no error")
		}
		if v.P != pt || *pt != (point{X: 1, Y: 2}) || v.S != "old" {
			t.Errorf("%+v %+v", v, *pt)
		}
	})
}

// ---- unknown, repeated and null members, at every depth ------------------------------------

// deepT has a struct that holds a struct in every place that a struct can stand.
type deepT struct {
	Top   int              `json:"top"`
	Inner point            `json:"inner"`
	Ptr   *point           `json:"ptr"`
	List  []point          `json:"list"`
	Map   map[string]point `json:"map"`
	Arr   [1]point         `json:"arr"`
	Deep  struct {
		In struct {
			X int `json:"x"`
		} `json:"in"`
	} `json:"deep"`
	Any any `json:"any"`
	Raw Raw `json:"raw"`
}

func TestUnknownMembersAtEveryDepth(t *testing.T) {
	// A document with an unknown member at the depth, and the path of that member.
	cases := []struct{ name, doc, path string }{
		{"at the top", `{"extra":1}`, "$.extra"},
		{"in a struct", `{"inner":{"X":1,"extra":1}}`, "$.inner.extra"},
		{"behind a pointer", `{"ptr":{"extra":1}}`, "$.ptr.extra"},
		{"in a list", `{"list":[{"X":1},{"extra":1}]}`, "$.list[1].extra"},
		{"in a map", `{"map":{"k":{"extra":1}}}`, "$.map.k.extra"},
		{"in an array", `{"arr":[{"extra":1}]}`, "$.arr[0].extra"},
		{"two structs down", `{"deep":{"in":{"x":1,"extra":1}}}`, "$.deep.in.extra"},
		{"after the known members", `{"top":1,"inner":{"X":1},"extra":{}}`, "$.extra"},
		{"a name with a dot", `{"inner":{"a.b":1}}`, `$.inner."a.b"`},
		{"a name written with an escape", `{"` + uesc('e') + `xtra":1}`, "$.extra"},
		{"an empty name", `{"":1}`, `$.""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v deepT
			fail(t, Unmarshal([]byte(tc.doc), &v, Options{}), mal(tc.path, "unknown member"))
			// With AllowUnknown the same document is read, and what is known is filled.
			if err := Unmarshal([]byte(tc.doc), &v, Options{AllowUnknown: true}); err != nil {
				t.Errorf("AllowUnknown: %v", err)
			}
		})
	}
	t.Run("AllowUnknown fills the known members and skips the rest at every depth", func(t *testing.T) {
		doc := `{"x1":1,"top":1,"inner":{"X":2,"x2":{"a":[1]}},"ptr":{"Y":3,"x3":"s"},"list":[{"X":4,"x4":true},{"x5":false,"Y":5}],` +
			`"map":{"k":{"X":6,"x6":[]}},"arr":[{"X":7,"x7":{}}],"deep":{"x8":1,"in":{"x":8,"x9":[[1],{"z":"y"}]}},"any":{"u":1},"raw":{"v":2}}`
		var v deepT
		if err := Unmarshal([]byte(doc), &v, Options{AllowUnknown: true}); err != nil {
			t.Fatal(err)
		}
		var want deepT
		want.Top, want.Inner, want.Ptr = 1, point{X: 2}, &point{Y: 3}
		want.List = []point{{X: 4}, {Y: 5}}
		want.Map = map[string]point{"k": {X: 6}}
		want.Arr = [1]point{{X: 7}}
		want.Deep.In.X = 8
		want.Any = map[string]any{"u": int64(1)}
		want.Raw = Raw(`{"v":2}`)
		if !reflect.DeepEqual(v, want) {
			t.Errorf("got  %+v\nwant %+v", v, want)
		}
	})
	t.Run("AllowUnknown skips an unknown member of any value, but not one that breaks a rule", func(t *testing.T) {
		for _, in := range []string{`{"u":{}}`, `{"u":[]}`, `{"u":"s"}`, `{"u":-0}`, `{"u":true}`, `{"u":[[[[1]]],{"a":{"b":{}}}]}`} {
			var v deepT
			if err := Unmarshal([]byte(in), &v, Options{AllowUnknown: true}); err != nil {
				t.Errorf("%s: %v", in, err)
			}
		}
		for _, in := range []string{`{"u":null}`, `{"u":1.5}`, `{"u":{"a":1,"a":2}}`, `{"u":[null]}`, `{"u":"` + bs + `ud800"}`, `{"u":1e5}`, `{"u":99999999999999999999}`, `{"u":1,"u":2}`} {
			var v deepT
			if err := Unmarshal([]byte(in), &v, Options{AllowUnknown: true}); err == nil {
				t.Errorf("%s was read", in)
			}
		}
	})
	t.Run("a member that a struct does know is not unknown in a map, and an interface knows all", func(t *testing.T) {
		var m map[string]any
		if err := Unmarshal([]byte(`{"anything":{"goes":[1]}}`), &m, Options{}); err != nil {
			t.Errorf("%v", err)
		}
	})
}

func TestARepeatedMemberIsRefusedAtEveryDepth(t *testing.T) {
	// Each document repeats a member in a place; the error is at the path of the object that
	// holds it, and says which member and where the reader stopped (after the second name).
	a, esc := `"a"`, `"`+uesc('a')+`"`
	pair := func(first, second string) string { return first + `:1,` + second + `:2` }
	cases := []struct{ name, doc, tok, path string }{
		{"at the top", `{` + pair(a, a) + `}`, a, "$"},
		{"at the top, the second with an escape", `{` + pair(a, esc) + `}`, esc, "$"},
		{"at the top, the first with an escape", `{` + pair(esc, a) + `}`, a, "$"},
		{"at the top, both with an escape", `{` + pair(esc, esc) + `}`, esc, "$"},
		{"at the top, not next to the first", `{"a":1,"b":2,"c":3,"a":4}`, a, "$"},
		{"in a struct", `{"inner":{` + pair(a, a) + `}}`, a, "$.inner"},
		{"behind a pointer", `{"ptr":{` + pair(a, esc) + `}}`, esc, "$.ptr"},
		{"in a list", `{"list":[{"X":1},{` + pair(a, a) + `}]}`, a, "$.list[1]"},
		{"in a map", `{"map":{"k":{` + pair(a, a) + `}}}`, a, "$.map.k"},
		{"in a map, the names of the map", `{"map":{` + pair(`"k"`, `"k"`) + `}}`, `"k"`, "$.map"},
		{"in an interface", `{"any":{` + pair(a, a) + `}}`, a, "$.any"},
		{"in a Raw", `{"raw":{` + pair(a, a) + `}}`, a, "$.raw"},
		{"in an unknown member", `{"u":{"v":{` + pair(a, a) + `}}}`, a, "$.u.v"},
		{"in a list in an unknown member", `{"u":[{` + pair(a, esc) + `}]}`, esc, "$.u[0]"},
		{"with a name outside ASCII, written two ways", `{"` + string(rune(0xe9)) + `":1,"` + uesc(0xe9) + `":2}`, `"` + uesc(0xe9) + `"`, "$"},
		{"with a name outside the BMP, written as a pair", `{"` + string(rune(0x1F600)) + `":1,"` + bs + `ud83d` + bs + `ude00":2}`, `"` + bs + `ud83d` + bs + `ude00"`, "$"},
		{"with a name that is empty", `{"":1,"":2}`, `""`, "$"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			second := strings.LastIndex(tc.doc, tc.tok) + len(tc.tok)
			for _, opts := range []Options{{}, {AllowUnknown: true}} {
				var v deepT
				err := Unmarshal([]byte(tc.doc), &v, opts)
				if err == nil {
					t.Fatalf("%s was read", tc.doc)
				}
				// The text names the member as it is once its escapes are read, which the next test
				// pins; here the place and the byte are checked, for a name of any spelling.
				if got := err.Error(); !strings.HasPrefix(got, mal(tc.path, "member ")) || !strings.HasSuffix(got, fmt.Sprintf(" appears twice at byte %d", second)) {
					t.Errorf("the error is %q, want the path %s and the byte %d", got, tc.path, second)
				}
				var m map[string]any
				if err := Unmarshal([]byte(tc.doc), &m, opts); err == nil {
					t.Errorf("into a map: %s was read", tc.doc)
				}
				if err := Check([]byte(tc.doc), 0); err == nil {
					t.Errorf("Check read %s", tc.doc)
				}
			}
		})
	}
	t.Run("the text names the member as it is, not as it was written", func(t *testing.T) {
		var v deepT
		err := Unmarshal([]byte(`{"a":1,"`+uesc('a')+`":2}`), &v, Options{})
		fail(t, err, mal("$", `member "a" appears twice at byte 15`))
	})
	t.Run("the same name in two different objects is not repeated", func(t *testing.T) {
		var v deepT
		if err := Unmarshal([]byte(`{"inner":{"X":1},"ptr":{"X":1},"list":[{"X":1},{"X":2}],"map":{"X":{"X":1},"Y":{"X":2}}}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestNullIsRefusedEverywhere(t *testing.T) {
	cases := []struct{ name, doc, path string }{
		{"the whole document", `null`, "$"},
		{"a member of a struct", `{"top":null}`, "$.top"},
		{"a member that is a struct", `{"inner":null}`, "$.inner"},
		{"a member that is a pointer", `{"ptr":null}`, "$.ptr"},
		{"a member that is a list", `{"list":null}`, "$.list"},
		{"a member that is a map", `{"map":null}`, "$.map"},
		{"a member that is an interface", `{"any":null}`, "$.any"},
		{"a member that is a Raw", `{"raw":null}`, "$.raw"},
		{"an element of a list", `{"list":[null]}`, "$.list[0]"},
		{"an element of an array", `{"arr":[null]}`, "$.arr[0]"},
		{"a member of a map", `{"map":{"k":null}}`, "$.map.k"},
		{"a field of a struct in a list", `{"list":[{"X":1},{"X":null}]}`, "$.list[1].X"},
		{"deep in an interface", `{"any":{"a":[1,{"b":null}]}}`, "$.any.a[1].b"},
		{"inside a Raw", `{"raw":{"a":null}}`, "$.raw.a"},
		{"an unknown member", `{"zzz":null}`, "$.zzz"},
		{"inside an unknown member", `{"zzz":[{"a":null}]}`, "$.zzz[0].a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, opts := range []Options{{}, {AllowUnknown: true}} {
				var v deepT
				err := Unmarshal([]byte(tc.doc), &v, opts)
				if tc.name == "the whole document" {
					fail(t, err, mal("$", "not one JSON object"))
					continue
				}
				fail(t, err, mal(tc.path, "null"+byteAfter(tc.doc, "null")))
			}
		})
	}
	t.Run("null is not read as a missing member or as a zero value", func(t *testing.T) {
		v := deepT{Top: 5}
		if err := Unmarshal([]byte(`{"top":null}`), &v, Options{}); err == nil || v.Top != 5 {
			t.Errorf("%+v, %v", v, err)
		}
	})
}

func TestMembersOfEveryKindOfNameAreRead(t *testing.T) {
	// A name is matched exactly after its escapes are read: the same name written two ways is the
	// same member. (A struct whose tags go through reflect, for names that go vet would not pass.)
	typ := structOf([]string{"a", string(rune(0xe9)), "q.r", "a b"}, []reflect.Type{reflect.TypeFor[int](), reflect.TypeFor[int](), reflect.TypeFor[int](), reflect.TypeFor[int]()}, nil)
	doc := `{"` + uesc('a') + `":1,"` + uesc(0xe9) + `":2,"q` + bs + `u002er":3,"a` + bs + `u0020b":4}`
	got, err := read(typ, doc, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []int64{1, 2, 3, 4} {
		if got.Field(i).Int() != want {
			t.Errorf("field %d = %d, want %d", i, got.Field(i).Int(), want)
		}
	}
	// A member whose name is written with a slash escape.
	var m map[string]int
	if err := Unmarshal([]byte(`{"a`+bs+`/b":1}`), &m, Options{}); err != nil || m["a/b"] != 1 {
		t.Errorf("%v, %v", m, err)
	}
}
