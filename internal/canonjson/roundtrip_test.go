package canonjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// The two properties that the package comments of canonjson and strictjson promise, checked on the
// whole table of the writer and on random values of random types of the closed set:
//
//   - for every value x for which Marshal(x) succeeds, Unmarshal of the result gives a value equal to
//     x, but for the exceptions that the comment lists: an empty value under omitempty comes back
//     zero (so an empty slice, map or Raw comes back nil), a Raw comes back in its canonical form,
//     and an interface comes back as one of five types;
//   - for every canonical document d that names every field that has no omitempty, and in which no
//     member under omitempty is empty, Marshal(Unmarshal(d)) is d.
//
// The tests also find one more exception that the comment does not list: a field tagged "-" and an
// unexported field are not written and so come back zero.

// ---- what the exceptions make of a value ----------------------------------------------------

// refCanon is the canonical form of a JSON document of integers, written here from the text of
// RFC 8785 and from the standard decoder, so that the test does not use the code it tests.
func refCanon(t testing.TB, doc []byte) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("the standard decoder cannot read %.100q: %v", doc, err)
	}
	var out bytes.Buffer
	refWrite(t, &out, v)
	return out.Bytes()
}

func refWrite(t testing.TB, out *bytes.Buffer, v any) {
	switch v := v.(type) {
	case map[string]any:
		names := make([]string, 0, len(v))
		for k := range v {
			names = append(names, k)
		}
		sort.Slice(names, func(i, j int) bool { return reference(names[i], names[j]) < 0 })
		out.WriteByte('{')
		for i, k := range names {
			if i > 0 {
				out.WriteByte(',')
			}
			refString(out, k)
			out.WriteByte(':')
			refWrite(t, out, v[k])
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			refWrite(t, out, e)
		}
		out.WriteByte(']')
	case string:
		refString(out, v)
	case bool:
		out.WriteString(strconv.FormatBool(v))
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			t.Fatalf("the number %s is no int64", v)
		}
		out.WriteString(strconv.FormatInt(n, 10))
	default:
		t.Fatalf("a %T in a document", v)
	}
}

// refString writes a string as RFC 8785 section 3.2.2.2 does.
func refString(out *bytes.Buffer, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			out.WriteString(`\"`)
		case r == '\\':
			out.WriteString(`\\`)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\f':
			out.WriteString(`\f`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\r':
			out.WriteString(`\r`)
		case r == '\t':
			out.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(out, "%cu%04x", '\\', r)
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}

// isEmptyRef is what omitempty means, written again here as encoding/json says it.
func isEmptyRef(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}

// anyShape is what an interface holds after the round trip: the document of the value that was in
// it, read as map[string]any, []any, string, bool and int64 and nothing else. The document is the
// standard encoder's, which agrees with Marshal on every value that both accept.
func anyShape(t testing.TB, v reflect.Value) any {
	t.Helper()
	text, err := json.Marshal(v.Interface())
	if err != nil {
		t.Fatalf("the standard encoder cannot write %v: %v", v.Type(), err)
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return numbersToInts(t, out)
}

func numbersToInts(t testing.TB, v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = numbersToInts(t, e)
		}
	case []any:
		for i, e := range v {
			v[i] = numbersToInts(t, e)
		}
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil {
			t.Fatalf("a number %s that is no int64", v)
		}
		return n
	}
	return v
}

// The exceptions, named, that a test can switch off to see what each one makes of a value.
type exceptions struct {
	omitEmpty  bool // an empty value under omitempty comes back zero
	rawCanon   bool // a Raw comes back in its canonical form
	anyFive    bool // an interface comes back as one of five types
	notWritten bool // a field tagged "-" and an unexported field come back zero (not in the comment)
}

var allExceptions = exceptions{omitEmpty: true, rawCanon: true, anyFive: true, notWritten: true}

// expectAfter builds the value that the round trip must give for x, applying the exceptions.
func expectAfter(t testing.TB, x reflect.Value, e exceptions) reflect.Value {
	t.Helper()
	out := reflect.New(x.Type()).Elem()
	fill(t, out, x, e)
	return out
}

func fill(t testing.TB, dst, src reflect.Value, e exceptions) {
	t.Helper()
	if src.Type() == rawType {
		if e.rawCanon && src.Len() > 0 {
			dst.SetBytes(refCanon(t, src.Bytes()))
		} else if src.Len() > 0 {
			dst.SetBytes(bytes.Clone(src.Bytes()))
		}
		return
	}
	switch src.Kind() {
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		p := reflect.New(src.Type().Elem())
		fill(t, p.Elem(), src.Elem(), e)
		dst.Set(p)
	case reflect.Interface:
		if src.IsNil() {
			return
		}
		if e.anyFive {
			dst.Set(reflect.ValueOf(anyShape(t, src.Elem())))
			return
		}
		inner := reflect.New(src.Elem().Type()).Elem()
		fill(t, inner, src.Elem(), e)
		dst.Set(inner)
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		if src.Type().Elem().Kind() == reflect.Uint8 {
			dst.Set(reflect.ValueOf(bytes.Clone(src.Bytes())).Convert(src.Type()))
			return
		}
		s := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
		for i := range src.Len() {
			fill(t, s.Index(i), src.Index(i), e)
		}
		dst.Set(s)
	case reflect.Array:
		for i := range src.Len() {
			fill(t, dst.Index(i), src.Index(i), e)
		}
	case reflect.Map:
		if src.IsNil() {
			return
		}
		m := reflect.MakeMapWithSize(src.Type(), src.Len())
		iter := src.MapRange()
		for iter.Next() {
			el := reflect.New(src.Type().Elem()).Elem()
			fill(t, el, iter.Value(), e)
			m.SetMapIndex(iter.Key(), el)
		}
		dst.Set(m)
	case reflect.Struct:
		typ := src.Type()
		if !e.notWritten {
			dst.Set(src) // what is not written is kept: this switches the exception off
		}
		for i := range src.NumField() {
			f := typ.Field(i)
			if !f.IsExported() || f.Tag.Get("json") == "-" {
				continue
			}
			_, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if e.omitEmpty && strings.Contains(","+opts+",", ",omitempty,") && isEmptyRef(src.Field(i)) {
				dst.Field(i).Set(reflect.Zero(f.Type))
				continue
			}
			dst.Field(i).Set(reflect.Zero(f.Type))
			fill(t, dst.Field(i), src.Field(i), e)
		}
	default:
		dst.Set(src)
	}
}

// roundTrip writes x, reads the document into a new value of the type of x (a struct, or the
// pointed-to type of a pointer), and returns the value read and the document.
func roundTrip(x any) (back reflect.Value, doc []byte, err error) {
	doc, err = Marshal(x)
	if err != nil {
		return reflect.Value{}, nil, err
	}
	typ := reflect.TypeOf(x)
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	p := reflect.New(typ)
	if err := strictjson.Unmarshal(doc, p.Interface(), strictjson.Options{}); err != nil {
		return reflect.Value{}, doc, fmt.Errorf("Unmarshal of %q: %w", doc, err)
	}
	return p.Elem(), doc, nil
}

func derefValue(x any) reflect.Value {
	v := reflect.ValueOf(x)
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	return v
}

// ---- 1. Unmarshal(Marshal(x)) is x, but for the exceptions ----------------------------------

func TestUnmarshalOfMarshalIsTheValueBut(t *testing.T) {
	t.Run("every value of the table of the writer, in every place", func(t *testing.T) {
		n := 0
		for _, tc := range acceptedValues() {
			for _, p := range places(tc.v, false, false) {
				if p.name == "at the top" && !strings.HasPrefix(tc.want, "{") {
					continue
				}
				back, doc, err := roundTrip(p.doc)
				if err != nil {
					t.Errorf("%s, %s: %v", tc.name, p.name, err)
					continue
				}
				want := expectAfter(t, derefValue(p.doc), allExceptions)
				if !reflect.DeepEqual(back.Interface(), want.Interface()) {
					t.Errorf("%s, %s: %s read back as\n  %#v\nwant\n  %#v", tc.name, p.name, doc, back.Interface(), want.Interface())
				}
				n++
			}
		}
		if n < 300 {
			t.Errorf("only %d round trips", n)
		}
	})
	t.Run("a few hundred random values of random types", func(t *testing.T) {
		g := &generator{r: rand.New(rand.NewSource(8785))}
		for i := range 400 {
			x := g.top()
			back, doc, err := roundTrip(x)
			if err != nil {
				t.Fatalf("value %d of %T: %v", i, x, err)
			}
			want := expectAfter(t, derefValue(x), allExceptions)
			if !reflect.DeepEqual(back.Interface(), want.Interface()) {
				t.Fatalf("value %d of %T: %.300s read back as\n  %#v\nwant\n  %#v", i, x, doc, back.Interface(), want.Interface())
			}
			// And the document is canonical, and is what the standard encoder's is, canonicalized.
			if ok, err := IsCanonical(doc); err != nil || !ok {
				t.Fatalf("value %d: the document is not canonical: %v %v", i, ok, err)
			}
			std, err := json.Marshal(x)
			if err != nil {
				t.Fatalf("value %d: the standard encoder: %v", i, err)
			}
			if want := refCanon(t, std); !bytes.Equal(doc, want) {
				t.Fatalf("value %d of %T: Marshal and the canonical form of the standard encoder differ:\n  %.300s\n  %.300s", i, x, doc, want)
			}
		}
	})
}

// Each exception, by name, with a minimal value: it is an exception (without it the value does not
// come back equal), and with it the value is what it should be.
func TestEachExceptionOfTheRoundTripByName(t *testing.T) {
	type omit struct {
		L []int          `json:"l,omitempty"`
		M map[string]int `json:"m,omitempty"`
		R Raw            `json:"r,omitempty"`
		B []byte         `json:"b,omitempty"`
		S []string       `json:"s,omitempty"`
	}
	check := func(t *testing.T, name string, x any, only exceptions, wantDifferent bool) {
		t.Helper()
		back, doc, err := roundTrip(x)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := !reflect.DeepEqual(back.Interface(), derefValue(x).Interface()); got != wantDifferent {
			t.Errorf("%s: %s came back %#v for %#v: different = %v, want %v", name, doc, back.Interface(), derefValue(x).Interface(), got, wantDifferent)
		}
		want := expectAfter(t, derefValue(x), only)
		if !reflect.DeepEqual(back.Interface(), want.Interface()) {
			t.Errorf("%s: with this exception alone, %s read back as\n  %#v\nwant\n  %#v", name, doc, back.Interface(), want.Interface())
		}
	}
	t.Run("an empty slice under omitempty is nil", func(t *testing.T) {
		check(t, "slice", omit{L: []int{}}, exceptions{omitEmpty: true}, true)
	})
	t.Run("an empty map under omitempty is nil", func(t *testing.T) {
		check(t, "map", omit{M: map[string]int{}}, exceptions{omitEmpty: true}, true)
	})
	t.Run("an empty Raw under omitempty is nil", func(t *testing.T) {
		check(t, "Raw", omit{R: Raw{}}, exceptions{omitEmpty: true}, true)
	})
	t.Run("an empty slice of bytes under omitempty is nil", func(t *testing.T) {
		check(t, "bytes", omit{B: []byte{}}, exceptions{omitEmpty: true}, true)
	})
	t.Run("an empty slice of strings under omitempty is nil", func(t *testing.T) {
		check(t, "strings", omit{S: []string{}}, exceptions{omitEmpty: true}, true)
	})
	t.Run("what is not empty under omitempty comes back equal", func(t *testing.T) {
		check(t, "full", omit{L: []int{0}, M: map[string]int{"a": 0}, R: Raw(`{}`), B: []byte{0}, S: []string{""}}, exceptions{omitEmpty: true}, false)
	})
	t.Run("a zero scalar under omitempty comes back equal, because it is zero", func(t *testing.T) {
		type scalars struct {
			B bool   `json:",omitempty"`
			I int    `json:",omitempty"`
			S string `json:",omitempty"`
			P *int   `json:",omitempty"`
			A any    `json:",omitempty"`
		}
		check(t, "scalars", scalars{}, exceptions{omitEmpty: true}, false)
	})
	t.Run("a pointer to a zero value is not empty and comes back as a pointer", func(t *testing.T) {
		type p struct {
			P *int    `json:",omitempty"`
			S *string `json:",omitempty"`
		}
		zero, empty := 0, ""
		check(t, "pointers", p{P: &zero, S: &empty}, exceptions{omitEmpty: true}, false)
	})
	t.Run("an empty slice and map that are not under omitempty come back equal, and not nil", func(t *testing.T) {
		type plain struct {
			L []int
			M map[string]int
			B []byte
			R []Raw
		}
		check(t, "plain", plain{L: []int{}, M: map[string]int{}, B: []byte{}, R: []Raw{}}, exceptions{}, false)
	})
	t.Run("a Raw comes back in its canonical form", func(t *testing.T) {
		type doc struct{ R Raw }
		x := doc{R: Raw(` { "b" : [ 1 , 2 ] , "a" : "x" } `)}
		check(t, "raw", x, exceptions{rawCanon: true}, true)
		back, _, _ := roundTrip(x)
		if got := string(back.Interface().(doc).R); got != `{"a":"x","b":[1,2]}` {
			t.Errorf("the Raw is %q", got)
		}
	})
	t.Run("a Raw that is canonical already comes back as it was", func(t *testing.T) {
		type doc struct {
			R  Raw
			P  *Raw
			L  []Raw
			Mp map[string]Raw
		}
		c := Raw(`{"a":[1,2],"b":{"c":"d"}}`)
		check(t, "canonical", doc{R: c, P: &c, L: []Raw{c, c}, Mp: map[string]Raw{"k": c}}, exceptions{rawCanon: true}, false)
	})
	t.Run("an interface comes back as one of five types", func(t *testing.T) {
		type named int
		type str string
		cases := []struct {
			name string
			v    any
			want any
		}{
			{"an int", 5, int64(5)},
			{"an int8", int8(-5), int64(-5)},
			{"a uint64", uint64(7), int64(7)},
			{"a named integer", named(3), int64(3)},
			{"a named string", str("s"), "s"},
			{"a string", "s", "s"},
			{"a bool", true, true},
			{"a slice of bytes", []byte("hi"), "aGk="},
			{"an empty slice of bytes", []byte{}, ""},
			{"a struct", struct{ A int }{1}, map[string]any{"A": int64(1)}},
			{"a pointer to a struct", &struct{ A int }{1}, map[string]any{"A": int64(1)}},
			{"a map of integers", map[string]int{"a": 1}, map[string]any{"a": int64(1)}},
			{"a slice of integers", []int{1, 2}, []any{int64(1), int64(2)}},
			{"an array", [2]string{"a", "b"}, []any{"a", "b"}},
			{"an empty slice", []int{}, []any{}},
			{"a Raw", Raw(`{"b":1,"a":[]}`), map[string]any{"a": []any{}, "b": int64(1)}},
			{"a pointer to an integer", ptr(5), int64(5)},
			{"a map of any", map[string]any{"a": 5, "b": []byte("hi")}, map[string]any{"a": int64(5), "b": "aGk="}},
		}
		for _, tc := range cases {
			type holder struct{ A any }
			x := holder{A: tc.v}
			back, doc, err := roundTrip(x)
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
				continue
			}
			if got := back.Interface().(holder).A; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s: %s read back as %#v (%T), want %#v", tc.name, doc, got, got, tc.want)
			}
			// The type is one of the five.
			switch back.Interface().(holder).A.(type) {
			case map[string]any, []any, string, bool, int64:
			default:
				t.Errorf("%s: read back as %T", tc.name, back.Interface().(holder).A)
			}
		}
	})
	t.Run("a field tagged dash and an unexported field come back zero (an exception that the comment does not list)", func(t *testing.T) {
		x := struct {
			A      int
			Skip   string `json:"-"`
			hidden int
		}{A: 1, Skip: "x", hidden: 2}
		_ = x.hidden
		check(t, "not written", x, exceptions{notWritten: true}, true)
	})
}

// ---- 2. Marshal(Unmarshal(d)) is d, for a canonical document that names every field -------

// aShape is the type of the documents below: a field of each kind, some under omitempty.
type aShape struct {
	Version int               `json:"version"`
	Name    string            `json:"name"`
	Tags    []string          `json:"tags"`
	Meta    map[string]string `json:"meta"`
	Doc     Raw               `json:"doc"`
	Blob    []byte            `json:"blob"`
	Any     any               `json:"any"`
	Inner   *aShape           `json:"inner,omitempty"`
	Opt     []int             `json:"opt,omitempty"`
	Pair    [2]int8           `json:"pair"`
	Flag    bool              `json:"flag,omitempty"`
}

func TestMarshalOfUnmarshalIsTheCanonicalDocument(t *testing.T) {
	canonical := []string{
		`{"any":{"a":[1,"x",true]},"blob":"aGk=","doc":{"k":"v"},"meta":{"a":"b"},"name":"n","pair":[1,2],"tags":["t"],"version":1}`,
		`{"any":[],"blob":"","doc":{},"meta":{},"name":"","pair":[0,0],"tags":[],"version":0}`,
		`{"any":"s","blob":"AA==","doc":{"a":{"b":{}}},"meta":{"":"","a":"b"},"name":"é","pair":[-128,127],"tags":["","a"],"version":-1}`,
		`{"any":5,"blob":"+/+/","doc":{"z":[],"a":{}},"flag":true,"inner":{"any":false,"blob":"","doc":{},"meta":{},"name":"i","pair":[3,4],"tags":[],"version":2},"meta":{},"name":"o","opt":[1,2],"pair":[5,6],"tags":["x","y"],"version":9223372036854775807}`,
	}
	for i, in := range canonical {
		if i == 3 {
			// This one is not canonical in the order of the members of "doc": make it so.
			in = string(refCanon(t, []byte(in)))
		}
		if ok, err := IsCanonical([]byte(in)); err != nil || !ok {
			t.Fatalf("the document %d is not canonical: %v %v", i, ok, err)
		}
		var v aShape
		if err := strictjson.Unmarshal([]byte(in), &v, strictjson.Options{}); err != nil {
			t.Fatalf("document %d: %v", i, err)
		}
		out, err := Marshal(v)
		if err != nil || string(out) != in {
			t.Errorf("document %d:\n  in  %s\n  out %s (%v)", i, in, out, err)
		}
	}
	t.Run("random documents of random types, written by the standard encoder and canonicalized", func(t *testing.T) {
		g := &generator{r: rand.New(rand.NewSource(2119))}
		for i := range 400 {
			x := g.top()
			std, err := json.Marshal(x)
			if err != nil {
				t.Fatalf("value %d: %v", i, err)
			}
			d := refCanon(t, std)
			if ok, err := IsCanonical(d); err != nil || !ok {
				t.Fatalf("value %d: the reference form is not canonical: %v %v", i, ok, err)
			}
			p := reflect.New(derefValue(x).Type())
			if err := strictjson.Unmarshal(d, p.Interface(), strictjson.Options{}); err != nil {
				t.Fatalf("value %d of %T: %v\n%.300s", i, x, err, d)
			}
			out, err := Marshal(p.Interface())
			if err != nil || !bytes.Equal(out, d) {
				t.Fatalf("value %d of %T:\n  d   %.300s\n  out %.300s (%v)", i, x, d, out, err)
			}
		}
	})
	t.Run("where the conditions do not hold the property does not", func(t *testing.T) {
		// A document that does not name a field without omitempty: the field is zero, and written.
		var v aShape
		in := `{"any":1,"blob":"","doc":{},"meta":{},"name":"n","pair":[1,2],"tags":[]}`
		if err := strictjson.Unmarshal([]byte(in), &v, strictjson.Options{}); err != nil {
			t.Fatal(err)
		}
		out, err := Marshal(v)
		if err != nil || string(out) == in || !strings.Contains(string(out), `"version":0`) {
			t.Errorf("a missing member: %s, %v", out, err)
		}
		// An omitempty member that the document holds and that is empty: read as empty, not written.
		in = `{"any":1,"blob":"","doc":{},"meta":{},"name":"n","opt":[],"pair":[1,2],"tags":[],"version":1}`
		v = aShape{}
		if err := strictjson.Unmarshal([]byte(in), &v, strictjson.Options{}); err != nil {
			t.Fatal(err)
		}
		out, err = Marshal(v)
		if err != nil || string(out) == in || strings.Contains(string(out), `"opt"`) {
			t.Errorf("an empty omitempty member: %s, %v", out, err)
		}
		// A member that is missing and has no zero that can be written: nil is JSON null, refused.
		v = aShape{}
		if err := strictjson.Unmarshal([]byte(`{"name":"n"}`), &v, strictjson.Options{}); err != nil {
			t.Fatal(err)
		}
		if _, err := Marshal(v); err == nil {
			t.Error("a value with nil slices, a nil map, a nil interface and an empty Raw was written")
		}
		// A member that AllowUnknown skipped is not written.
		in = `{"any":1,"blob":"","doc":{},"extra":1,"meta":{},"name":"n","pair":[1,2],"tags":[],"version":1}`
		v = aShape{}
		if err := strictjson.Unmarshal([]byte(in), &v, strictjson.Options{AllowUnknown: true}); err != nil {
			t.Fatal(err)
		}
		out, err = Marshal(v)
		if err != nil || string(out) == in || strings.Contains(string(out), "extra") {
			t.Errorf("a skipped member: %s, %v", out, err)
		}
		// A document that is not canonical is read, and written in the canonical form.
		in = ` { "version" : 1 , "any" : 1, "blob":"", "doc":{ "b":1, "a":2 }, "meta":{}, "name":"n", "pair":[1,2], "tags":[] } `
		v = aShape{}
		if err := strictjson.Unmarshal([]byte(in), &v, strictjson.Options{}); err != nil {
			t.Fatal(err)
		}
		out, err = Marshal(v)
		want := `{"any":1,"blob":"","doc":{"a":2,"b":1},"meta":{},"name":"n","pair":[1,2],"tags":[],"version":1}`
		if err != nil || string(out) != want {
			t.Errorf("%s, %v", out, err)
		}
	})
}

// ---- 3. the random values ---------------------------------------------------------------

// generator makes random types of the closed set and random values of them.
type generator struct{ r *rand.Rand }

// structNames are the names that the generator gives to the fields of a struct: all inside the rule
// for a member name of a struct (ASCII letters, digits and underscores), and among them names that
// fold to one another (K and k) and that begin with a digit. docNames are the names of the members of
// a Raw document, which is not under the rule, so they hold any text, as the keys of a map do.
var (
	structNames = []string{"a", "B", "c1", "Dd", "x_y", "a_b", "K", "k", "e_f", "g_h", "Z", "z", "0", "10", "2", "q_r", "S_s", "T_t"}
	docNames    = []string{"a", "B", "c1", "Dd", "x y", "a.b", "K", "k", "e_f", "g-h", "Z", "z", "0", "10", "2", "q:r", "$s", "~t"}
)

func (g *generator) text() string {
	pool := []rune{'a', 'b', 'Z', '0', '\r', 0, 0x1f, '~', 0x7f, 0x80, 0xe9, 0x7ff, 0x800, '<', '>', '&', '\'',
		0x2028, 0x2029, 0xd7ff, 0xe000, 0xf000, 0xfb33, 0xfffd, 0xffff, 0x10000, 0x1f600, 0x10ffff, '"', '\\', '/', ' ', '\n', '\t'}
	var b strings.Builder
	for range g.r.Intn(6) {
		b.WriteRune(pool[g.r.Intn(len(pool))])
	}
	return b.String()
}

func (g *generator) integer() int64 {
	switch g.r.Intn(4) {
	case 0:
		return int64(g.r.Intn(21) - 10)
	case 1:
		return g.r.Int63()
	case 2:
		return -g.r.Int63()
	default:
		return int64(g.r.Intn(2000) - 1000)
	}
}

var scalarTypes = []reflect.Type{
	reflect.TypeFor[bool](), reflect.TypeFor[string](), reflect.TypeFor[int](), reflect.TypeFor[int8](), reflect.TypeFor[int16](),
	reflect.TypeFor[int32](), reflect.TypeFor[int64](), reflect.TypeFor[uint](), reflect.TypeFor[uint8](), reflect.TypeFor[uint16](),
	reflect.TypeFor[uint32](), reflect.TypeFor[uint64](), reflect.TypeFor[[]byte](), reflect.TypeFor[Raw](), reflect.TypeFor[any](),
}

// typ makes a type of the closed set, at most depth levels deep.
func (g *generator) typ(depth int) reflect.Type {
	if depth <= 0 {
		return scalarTypes[g.r.Intn(len(scalarTypes)-1)] // not any, which has no depth of its own to stop at
	}
	switch g.r.Intn(9) {
	case 0, 1:
		return scalarTypes[g.r.Intn(len(scalarTypes))]
	case 2:
		return reflect.SliceOf(g.typ(depth - 1))
	case 3:
		return reflect.ArrayOf(g.r.Intn(3), g.typ(depth-1))
	case 4:
		return reflect.MapOf(reflect.TypeFor[string](), g.typ(depth-1))
	case 5:
		elem := g.typ(depth - 1)
		if elem.Kind() == reflect.Interface || elem.Kind() == reflect.Pointer {
			elem = reflect.TypeFor[string]() // a pointer to a pointer or to an interface is not in the set
		}
		return reflect.PointerTo(elem)
	default:
		return g.structType(depth - 1)
	}
}

func (g *generator) structType(depth int) reflect.Type {
	var fields []reflect.StructField
	used := map[string]bool{}
	for i := range g.r.Intn(5) {
		name := structNames[g.r.Intn(len(structNames))]
		if used[name] {
			continue
		}
		used[name] = true
		f := reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: g.typ(depth)}
		switch g.r.Intn(6) {
		case 0:
			f.Tag = reflect.StructTag(`json:"` + name + `,omitempty"`)
		case 1:
			f.Tag = `json:"-"`
			f.Type = reflect.TypeFor[int]()
			delete(used, name)
		case 2:
			f.Tag = `json:",omitempty"`
			used[f.Name] = true
		case 3:
			f.Tag = ""
			used[f.Name] = true
		default:
			f.Tag = reflect.StructTag(`json:"` + name + `"`)
		}
		fields = append(fields, f)
	}
	return reflect.StructOf(fields)
}

// fill makes v a value that Marshal accepts: nothing nil that is not under omitempty (omit says that
// the field is).
func (g *generator) fill(v reflect.Value, omit bool) reflect.Value {
	typ := v.Type()
	if typ == rawType {
		if omit && g.r.Intn(3) == 0 { // an empty Raw is not written without omitempty
			if g.r.Intn(2) == 0 {
				v.SetBytes([]byte{})
			}
		} else {
			v.SetBytes([]byte(g.doc(2)))
		}
		return v
	}
	switch typ.Kind() {
	case reflect.Bool:
		v.SetBool(g.r.Intn(2) == 0)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n := g.integer()
		for v.OverflowInt(n) {
			n /= 2
		}
		v.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n := uint64(g.integer() & math.MaxInt64)
		for v.OverflowUint(n) {
			n /= 2
		}
		v.SetUint(n)
	case reflect.String:
		v.SetString(g.text())
	case reflect.Pointer:
		p := reflect.New(typ.Elem())
		g.fill(p.Elem(), false)
		v.Set(p)
	case reflect.Interface:
		inner := g.typ(2)
		for inner.Kind() == reflect.Interface {
			inner = g.typ(2)
		}
		v.Set(g.fill(reflect.New(inner).Elem(), false))
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			b := make([]byte, g.r.Intn(9))
			g.r.Read(b)
			v.Set(reflect.ValueOf(b).Convert(typ))
			return v
		}
		n := g.r.Intn(4)
		if omit && g.r.Intn(3) == 0 {
			n = 0
		}
		s := reflect.MakeSlice(typ, n, n)
		for i := range n {
			g.fill(s.Index(i), false)
		}
		v.Set(s)
	case reflect.Array:
		for i := range v.Len() {
			g.fill(v.Index(i), false)
		}
	case reflect.Map:
		m := reflect.MakeMap(typ)
		n := g.r.Intn(4)
		if omit && g.r.Intn(3) == 0 {
			n = 0
		}
		for range n {
			e := reflect.New(typ.Elem()).Elem()
			g.fill(e, false)
			m.SetMapIndex(reflect.ValueOf(g.text()), e)
		}
		v.Set(m)
	case reflect.Struct:
		for i := range typ.NumField() {
			f := typ.Field(i)
			tag := f.Tag.Get("json")
			if tag == "-" {
				v.Field(i).SetInt(1 + int64(g.r.Intn(100))) // a field that is not written, and is not zero
				continue
			}
			_, opts, _ := strings.Cut(tag, ",")
			g.fill(v.Field(i), strings.Contains(opts, "omitempty"))
		}
	}
	return v
}

// doc is a document of an object in a layout that is not canonical, for a Raw: members out of
// order, white space, escapes, minus zero, and lists and objects inside.
func (g *generator) doc(depth int) string {
	ws := func() string { return []string{"", "", " ", "\n", "\t ", "\r\n"}[g.r.Intn(6)] }
	var members []string
	for range g.r.Intn(4) {
		name := docNames[g.r.Intn(len(docNames))]
		if g.r.Intn(4) == 0 {
			name = fmt.Sprintf("%s%s", name, string(rune(0xFB33)))
		}
		var val string
		switch k := g.r.Intn(7); {
		case k == 0 && depth > 0:
			val = g.doc(depth - 1)
		case k == 1 && depth > 0:
			val = "[" + ws() + g.doc(depth-1) + ws() + "," + ws() + "[]" + ws() + "]"
		case k == 2:
			val = `"` + strings.NewReplacer(`"`, `\"`, `\`, `\\`, "\x00", `\u0000`, "\n", `\n`, "\r", `\r`, "\t", `\t`, "\x1f", `\u001F`, "/", `\/`).Replace(g.text()) + `"`
		case k == 3:
			val = []string{"true", "false"}[g.r.Intn(2)]
		case k == 4:
			val = "-0"
		default:
			val = strconv.FormatInt(g.integer(), 10)
		}
		members = append(members, fmt.Sprintf("%s\"%s\"%s:%s%s", ws(), strings.NewReplacer(`"`, ``, `\`, ``, "\x00", "", "\n", "", "\r", "", "\t", "", "\x1f", "").Replace(name), ws(), ws(), val))
	}
	// A name is used once: the same name twice would not be a document.
	seen := map[string]bool{}
	var unique []string
	for _, m := range members {
		key, _, _ := strings.Cut(m, ":")
		key = strings.TrimSpace(key)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, m)
		}
	}
	return "{" + strings.Join(unique, ",") + ws() + "}"
}

// top makes a value that Marshal may be given: a struct, or a pointer to one, or a map.
func (g *generator) top() any {
	var typ reflect.Type
	if g.r.Intn(8) == 0 {
		typ = reflect.MapOf(reflect.TypeFor[string](), g.typ(2))
	} else {
		typ = g.structType(3)
	}
	v := g.fill(reflect.New(typ).Elem(), false)
	if g.r.Intn(3) == 0 && typ.Kind() == reflect.Struct {
		p := reflect.New(typ)
		p.Elem().Set(v)
		return p.Interface()
	}
	return v.Interface()
}

func TestTheGeneratorMakesWhatItShould(t *testing.T) {
	for _, name := range structNames {
		if strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != "" {
			t.Errorf("the generator's name %q for a field is outside the rule", name)
		}
	}
	if len(structNames) != len(docNames) {
		t.Errorf("%d names for fields and %d for documents", len(structNames), len(docNames))
	}
	g := &generator{r: rand.New(rand.NewSource(1))}
	kinds := map[reflect.Kind]int{}
	var omitted, raws, anys int
	for range 400 {
		x := g.top()
		v := derefValue(x)
		var walk func(reflect.Type)
		seen := map[reflect.Type]bool{}
		walk = func(typ reflect.Type) {
			if seen[typ] {
				return
			}
			seen[typ] = true
			kinds[typ.Kind()]++
			switch typ.Kind() {
			case reflect.Struct:
				for i := range typ.NumField() {
					if strings.Contains(typ.Field(i).Tag.Get("json"), "omitempty") {
						omitted++
					}
					walk(typ.Field(i).Type)
				}
			case reflect.Slice, reflect.Array, reflect.Map, reflect.Pointer:
				walk(typ.Elem())
			}
			if typ == rawType {
				raws++
			}
			if typ.Kind() == reflect.Interface {
				anys++
			}
		}
		walk(v.Type())
		if _, err := Marshal(x); err != nil {
			t.Fatalf("the generator made a value that Marshal refuses: %T: %v", x, err)
		}
	}
	for _, k := range []reflect.Kind{reflect.Struct, reflect.Slice, reflect.Array, reflect.Map, reflect.Pointer, reflect.Interface, reflect.String, reflect.Bool, reflect.Int64, reflect.Uint8} {
		if kinds[k] == 0 {
			t.Errorf("the generator never made a type of kind %v", k)
		}
	}
	if omitted == 0 || raws == 0 || anys == 0 {
		t.Errorf("the generator never made omitempty (%d), Raw (%d) or any (%d)", omitted, raws, anys)
	}
}

func TestLargeValuesAreWrittenWholeAndReadBack(t *testing.T) {
	type big struct {
		M map[string]int
		L []int32
		B []byte
		S string
		A [300]uint8
		R []Raw
	}
	g := &generator{r: rand.New(rand.NewSource(5))}
	for _, n := range []int{99, 100, 101, 255, 256, 257, 1000, 4097, 20000} {
		x := big{M: map[string]int{}, L: make([]int32, n), B: make([]byte, n), S: strings.Repeat("é", n/2), R: []Raw{}}
		for i := range n / 4 {
			x.M[fmt.Sprintf("m%05d", i*7919%100000)] = i
		}
		for i := range x.L {
			x.L[i] = int32(i - n/2)
		}
		g.r.Read(x.B)
		for i := range x.A {
			x.A[i] = uint8(i)
		}
		for i := range n / 50 {
			x.R = append(x.R, Raw(fmt.Sprintf(`{"a":[%d],"b":%d}`, i, i)))
		}
		doc, err := Marshal(x)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		std, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		if want := refCanon(t, std); !bytes.Equal(doc, want) {
			t.Fatalf("%d: Marshal and the reference differ at byte %d", n, firstDifference(doc, want))
		}
		var back big
		if err := strictjson.Unmarshal(doc, &back, strictjson.Options{}); err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if !reflect.DeepEqual(back, x) {
			t.Fatalf("%d: the value read back differs", n)
		}
	}
}

func firstDifference(a, b []byte) int {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return i
}

func TestAStructOfManyFieldsIsWrittenWholeInOrderAndReadBack(t *testing.T) {
	for _, n := range []int{1, 7, 8, 9, 29, 30, 31, 32, 33, 63, 64, 65, 100, 129, 300} {
		fields := make([]reflect.StructField, n)
		for i := range fields {
			// Declared in the reverse of the order that they are written in, with names that sort
			// in a different order from their numbers (f10 before f2).
			name := fmt.Sprintf("f%d", n-i)
			fields[i] = reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: reflect.TypeFor[int](), Tag: reflect.StructTag(`json:"` + name + `"`)}
		}
		typ := reflect.StructOf(fields)
		x := reflect.New(typ).Elem()
		for i := range n {
			x.Field(i).SetInt(int64(i * 3))
		}
		doc, err := Marshal(x.Interface())
		if err != nil {
			t.Fatalf("%d fields: %v", n, err)
		}
		std, err := json.Marshal(x.Interface())
		if err != nil {
			t.Fatal(err)
		}
		if want := refCanon(t, std); !bytes.Equal(doc, want) {
			t.Fatalf("%d fields: Marshal and the reference differ at byte %d", n, firstDifference(doc, want))
		}
		if got := strings.Count(string(doc), ":"); got != n {
			t.Fatalf("%d fields: %d members written", n, got)
		}
		back := reflect.New(typ)
		if err := strictjson.Unmarshal(doc, back.Interface(), strictjson.Options{}); err != nil {
			t.Fatalf("%d fields: %v", n, err)
		}
		if !reflect.DeepEqual(back.Elem().Interface(), x.Interface()) {
			t.Fatalf("%d fields: the value read back differs", n)
		}
	}
}
