package canonjson

import (
	"encoding/json"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// Raw is one type with two names, and the writer, the reader and the two methods of Raw agree about
// what a Raw may be.

func TestRawIsTheTypeOfStrictjsonUnderAnotherName(t *testing.T) {
	if reflect.TypeFor[Raw]() != reflect.TypeFor[strictjson.Raw]() {
		t.Fatal("canonjson.Raw and strictjson.Raw are two types")
	}
	// Assignable both ways, with no conversion.
	toStrictjson := func(r strictjson.Raw) Raw { return r }
	toCanonjson := func(r Raw) strictjson.Raw { return r }
	if s := toStrictjson(Raw(`{}`)); string(s) != `{}` || string(toCanonjson(s)) != `{}` {
		t.Error(s)
	}
	if reflect.TypeFor[Raw]().Name() != "Raw" || reflect.TypeFor[Raw]().PkgPath() != "ritueel.id/ritueel/internal/strictjson" {
		t.Errorf("the type is %v in %q", reflect.TypeFor[Raw](), reflect.TypeFor[Raw]().PkgPath())
	}
}

func TestAPointerToRawIsWrittenLikeAPointerToAnyAcceptedType(t *testing.T) {
	c := Raw(` { "b" : 1 , "a" : [ ] } `)
	const canonical = `{"a":[],"b":1}`
	empty := Raw{}
	type holder struct {
		P *Raw `json:"p"`
	}
	type optional struct {
		P *Raw `json:"p,omitempty"`
	}
	for _, tc := range []struct {
		name string
		v    any
		want string
	}{
		{"at the top", &c, canonical},
		{"in a struct field", holder{P: &c}, `{"p":` + canonical + `}`},
		{"behind a pointer to the struct", &holder{P: &c}, `{"p":` + canonical + `}`},
		{"under omitempty, present", optional{P: &c}, `{"p":` + canonical + `}`},
		{"under omitempty, nil", optional{}, `{}`},
		{"in a list", map[string][]*Raw{"l": {&c, &c}}, `{"l":[` + canonical + `,` + canonical + `]}`},
		{"in a map", map[string]*Raw{"k": &c}, `{"k":` + canonical + `}`},
		{"in an interface", map[string]any{"i": &c}, `{"i":` + canonical + `}`},
		{"in an array", struct{ A [1]*Raw }{[1]*Raw{&c}}, `{"A":[` + canonical + `]}`},
		{"a pointer to a pointer is not one, but a pointer in an interface is", struct{ A any }{A: &c}, `{"A":` + canonical + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			if err != nil || string(got) != tc.want {
				t.Errorf("%q, %v; want %q", got, err, tc.want)
			}
		})
	}
	t.Run("a nil pointer to Raw is JSON null, refused, unless it is left out", func(t *testing.T) {
		got, err := Marshal(holder{})
		refused(t, got, err, cannotWrite("$.p", "*strictjson.Raw", reasonNilPtr))
		got, err = Marshal((*Raw)(nil))
		refused(t, got, err, cannotWrite("$", "*strictjson.Raw", reasonNilPtr))
		got, err = Marshal(map[string]*Raw{"k": nil})
		refused(t, got, err, cannotWrite("$.k", "*strictjson.Raw", reasonNilPtr))
	})
	t.Run("a pointer to an empty Raw is not nil, and the Raw is refused, also under omitempty", func(t *testing.T) {
		got, err := Marshal(holder{P: &empty})
		refused(t, got, err, malformedText("$.p: an empty Raw cannot be written"))
		got, err = Marshal(optional{P: &empty})
		refused(t, got, err, malformedText("$.p: an empty Raw cannot be written"))
		var nilRaw Raw
		got, err = Marshal(holder{P: &nilRaw})
		refused(t, got, err, malformedText("$.p: an empty Raw cannot be written"))
	})
	t.Run("a pointer to a Raw that is not an object is refused with the path of the pointer", func(t *testing.T) {
		list := Raw(`[1]`)
		got, err := Marshal(holder{P: &list})
		refused(t, got, err, malformedText("$.p: not one JSON object"))
	})
	t.Run("a pointer to a pointer to a Raw is refused, as any pointer to a pointer is", func(t *testing.T) {
		pp := &c
		got, err := Marshal(struct{ P **Raw }{&pp})
		refused(t, got, err, cannotWrite("$.P", "**strictjson.Raw", reasonPtrPtr))
	})
	t.Run("a pointer to a Raw is read back as a pointer to a Raw", func(t *testing.T) {
		got, err := Marshal(holder{P: &c})
		if err != nil {
			t.Fatal(err)
		}
		var back holder
		if err := strictjson.Unmarshal(got, &back, strictjson.Options{}); err != nil || back.P == nil || string(*back.P) != canonical {
			t.Errorf("%v, %v", back.P, err)
		}
	})
	t.Run("the standard encoder writes the same value", func(t *testing.T) {
		got, err := Marshal(holder{P: &c})
		if err != nil {
			t.Fatal(err)
		}
		if want := refCanon(t, mustStd(t, holder{P: &c})); string(got) != string(want) {
			t.Errorf("%q, the standard encoder's form %q", got, want)
		}
	})
}

func TestRawUnderOmitEmptyOnTheWritersSide(t *testing.T) {
	type doc struct {
		A Raw `json:"a,omitempty"`
		B Raw `json:"b,omitempty"`
		C Raw `json:"c,omitempty"`
		D Raw `json:"d"`
	}
	got, err := Marshal(doc{A: nil, B: Raw{}, C: Raw(`{ "z" : 1 }`), D: Raw(`{}`)})
	if want := `{"c":{"z":1},"d":{}}`; err != nil || string(got) != want {
		t.Errorf("%q, %v; want %q", got, err, want)
	}
	got, err = Marshal(doc{})
	refused(t, got, err, malformedText("$.d: an empty Raw cannot be written"))
	// A Raw that is not empty and not an object is refused whatever the tag.
	got, err = Marshal(doc{A: Raw(`[]`), D: Raw(`{}`)})
	refused(t, got, err, malformedText("$.a: not one JSON object"))
	got, err = Marshal(doc{A: Raw(` `), D: Raw(`{}`)})
	refused(t, got, err, malformedText("$.a: not one JSON object"))
}

func TestAnEmptyOrNilRaw(t *testing.T) {
	for _, r := range []Raw{nil, {}, Raw("")} {
		got, err := Marshal(r)
		refused(t, got, err, malformedText("$: an empty Raw cannot be written"))
		// The method refuses it too, and does not write null.
		out, merr := r.MarshalJSON()
		if merr == nil || out != nil || !errors.Is(merr, strictjson.ErrMalformed) {
			t.Errorf("MarshalJSON of an empty Raw: %q, %v", out, merr)
		}
		// It cannot be read from a document either: a member of a document is an object.
		var back struct{ R Raw }
		if err := strictjson.Unmarshal([]byte(`{"R":null}`), &back, strictjson.Options{}); err == nil {
			t.Error("null was read as a Raw")
		}
	}
}

// rawDocs is documents that may or may not be a Raw: the broken ones of the tests of the rules, and
// some of every kind, and a few hundred written at random.
func rawDocs() []string {
	docs := []string{`{}`, ` {} `, "\n{\"a\" : 1}\n", `{"b":1,"a":2}`, `{"a":{"b":{"c":[]}}}`, `[]`, `[{}]`, `1`, `"x"`, `true`, `null`, ``, ` `,
		`{} {}`, `{"a":1,"a":2}`, `{"a":1.5}`, `{"a":null}`, `{"a":"` + bsl + `ud800"}`, "{\"a\":\"\xff\"}", "\xef\xbb\xbf{}", `{"a":99999999999999999999}`,
		`{"a":`, `{"a":1,}`, `{a:1}`, `{"a":01}`, `{"a":-0}`, strings.Repeat(`{"a":`, strictjson.MaxDepth) + `{}` + strings.Repeat(`}`, strictjson.MaxDepth),
		strings.Repeat(`{"a":`, strictjson.MaxDepth-1) + `{}` + strings.Repeat(`}`, strictjson.MaxDepth-1)}
	for _, tc := range brokenRules {
		docs = append(docs, tc.in)
	}
	g := &generator{r: rand.New(rand.NewSource(77))}
	for range 300 {
		docs = append(docs, g.doc(3))
	}
	return docs
}

func TestWhatARawMayBeIsOneThingForTheWriterTheReaderAndTheMethods(t *testing.T) {
	type holder struct{ R Raw }
	checked := 0
	for _, in := range rawDocs() {
		data := []byte(in)
		check := strictjson.Check(data, 0)
		var viaMethod Raw
		unmarshalJSON := viaMethod.UnmarshalJSON(data)
		_, marshalJSON := Raw(in).MarshalJSON()
		var viaReader Raw
		reader := strictjson.Unmarshal(data, &viaReader, strictjson.Options{})
		_, writer := Marshal(Raw(in))
		for name, err := range map[string]error{"UnmarshalJSON": unmarshalJSON, "MarshalJSON": marshalJSON, "Unmarshal": reader, "Marshal": writer} {
			if (err == nil) != (check == nil) {
				t.Errorf("%.60q: Check says %v, %s says %v", in, check, name, err)
			}
		}
		// As a member of a document: written, then read back, when it is one.
		if check == nil && len(data) < strictjson.DefaultMaxBytes-100 {
			out, err := Marshal(holder{R: Raw(in)})
			if err != nil {
				// The only reason for a refusal of what the methods take is the depth of the whole.
				if !strings.Contains(err.Error(), "nesting deeper") {
					t.Errorf("%.60q: Marshal in a struct: %v", in, err)
				}
				continue
			}
			var back holder
			if err := strictjson.Unmarshal(out, &back, strictjson.Options{}); err != nil {
				t.Errorf("%.60q: the document %.60q was not read back: %v", in, out, err)
				continue
			}
			canon, err := Canonicalize(data)
			if err != nil || string(back.R) != string(canon) {
				t.Errorf("%.60q: read back as %.60q, canonical form %.60q (%v)", in, back.R, canon, err)
			}
			checked++
		}
	}
	if checked < 200 {
		t.Errorf("only %d documents went the whole way", checked)
	}
	// The two ends of the size: a Raw of exactly the limit is a Raw; written alone it is the limit.
	exactly := `{"k":"` + strings.Repeat("x", strictjson.DefaultMaxBytes-len(`{"k":""}`)) + `"}`
	if _, err := Marshal(Raw(exactly)); err != nil {
		t.Errorf("a Raw of exactly the limit: %v", err)
	}
	if _, err := Raw(exactly).MarshalJSON(); err != nil {
		t.Errorf("a Raw of exactly the limit, by the method: %v", err)
	}
	over := exactly[:len(exactly)-2] + `x"}`
	if _, err := Marshal(Raw(over)); err == nil {
		t.Error("a Raw of a byte over the limit was written")
	}
	if _, err := Raw(over).MarshalJSON(); err == nil {
		t.Error("a Raw of a byte over the limit was marshalled by the method")
	}
}

func mustStd(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ---- no value and no type makes a panic -------------------------------------------------------

func TestMarshalNeverPanics(t *testing.T) {
	var np *struct{ A int }
	var nm map[string]int
	var ns []int
	var ni any
	var nr Raw
	var nf func()
	var nc chan int
	var holdsNil any = np
	var loopMap = map[string]any{}
	loopMap["self"] = loopMap
	odd := []any{
		nil, np, nm, ns, ni, nr, nf, nc, holdsNil, &np, &nm, &ns, &ni, &nr, &holdsNil, loopMap, &loopMap,
		struct{ P *int }{}, struct{ I any }{}, struct{ F func() }{}, struct{ C chan int }{}, struct{ U uintptr }{},
		map[string]any{"a": nil}, map[string]any{"a": np}, map[string][]any{"a": {nil}}, []any{nil}, [1]any{},
		struct{ R *Raw }{}, struct{ R **Raw }{}, struct{ A [0]int }{}, struct{ A [0]*int }{}, struct{ E struct{} }{},
		reflect.New(reflect.StructOf(nil)).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[any]()}})).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.PointerTo(rawType), Tag: `json:"f,omitempty"`}})).Interface(),
		reflect.New(reflect.MapOf(reflect.TypeFor[string](), reflect.TypeFor[any]())).Elem().Interface(),
		reflect.MakeMap(reflect.MapOf(reflect.TypeFor[string](), reflect.TypeFor[any]())).Interface(),
		reflect.New(reflect.ArrayOf(3, reflect.TypeFor[any]())).Elem().Interface(),
		reflect.New(reflect.FuncOf(nil, nil, false)).Elem().Interface(),
		reflect.New(reflect.ChanOf(reflect.BothDir, reflect.TypeFor[int]())).Elem().Interface(),
		[]any{map[string]any{"a": []any{struct{ P *Raw }{}}}},
		Raw(nil), Raw(`{`), Raw(`}`), Raw("\x00"), Raw(`{"a":`), []Raw{nil}, map[string]Raw{"a": nil},
	}
	for i, v := range odd {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("value %d (%T): panic: %v", i, v, r)
				}
			}()
			got, err := Marshal(v)
			if err == nil && !strings.HasPrefix(string(got), "{") {
				t.Errorf("value %d (%T): %q", i, v, got)
			}
			if err != nil && (got != nil || !errors.Is(err, strictjson.ErrMalformed)) {
				t.Errorf("value %d (%T): %q, %v", i, v, got, err)
			}
		}()
	}
	// Random values of random types, of which every field may hold what the writer refuses: a
	// refusal is an error and never a panic.
	g := &generator{r: rand.New(rand.NewSource(31))}
	for range 300 {
		x := g.top()
		v := reflect.ValueOf(x)
		for v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		// Break the value: nil out every pointer, interface, slice and map that can be, at random.
		var spoil func(reflect.Value)
		spoil = func(v reflect.Value) {
			switch v.Kind() {
			case reflect.Struct:
				for i := range v.NumField() {
					if v.Type().Field(i).IsExported() {
						spoil(v.Field(i))
					}
				}
			case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
				if v.CanSet() && g.r.Intn(4) == 0 {
					v.Set(reflect.Zero(v.Type()))
					return
				}
				switch v.Kind() {
				case reflect.Pointer:
					if !v.IsNil() {
						spoil(v.Elem())
					}
				case reflect.Slice:
					for i := range v.Len() {
						spoil(v.Index(i))
					}
				}
			}
		}
		cp := reflect.New(v.Type()).Elem()
		cp.Set(v)
		spoil(cp)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("a spoiled %v: panic: %v", v.Type(), r)
				}
			}()
			if got, err := Marshal(cp.Interface()); err != nil && got != nil {
				t.Errorf("bytes next to an error: %v", err)
			}
		}()
	}
}
