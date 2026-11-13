package strictjson

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// ---- integers -----------------------------------------------------------------------------

// intKind is an integer type with its smallest and largest value.
type intKind struct {
	name     string
	typ      reflect.Type
	min, max string // the text of the smallest and the largest value
}

func intKinds() []intKind {
	return []intKind{
		{"int8", reflect.TypeFor[int8](), "-128", "127"},
		{"int16", reflect.TypeFor[int16](), "-32768", "32767"},
		{"int32", reflect.TypeFor[int32](), "-2147483648", "2147483647"},
		{"int64", reflect.TypeFor[int64](), "-9223372036854775808", "9223372036854775807"},
		{"int", reflect.TypeFor[int](), "-9223372036854775808", "9223372036854775807"},
		{"uint8", reflect.TypeFor[uint8](), "0", "255"},
		{"uint16", reflect.TypeFor[uint16](), "0", "65535"},
		{"uint32", reflect.TypeFor[uint32](), "0", "4294967295"},
		// A document holds an integer of at most int64, so the largest that can be read is that.
		{"uint64", reflect.TypeFor[uint64](), "0", "9223372036854775807"},
		{"uint", reflect.TypeFor[uint](), "0", "9223372036854775807"},
		{"a named int8", reflect.TypeFor[myInt8](), "-128", "127"},
		{"a named uint8", reflect.TypeFor[myUint8](), "0", "255"},
	}
}

type (
	myInt8  int8
	myUint8 uint8
)

// plusOne and minusOne are the text of the integer one above and one below a text of an integer,
// by arithmetic on the text, so that the test does not depend on the size of an integer type.
func plusOne(s string) string {
	n, ok := new(bigInt).SetString(s)
	if !ok {
		panic(s)
	}
	return n.add(1).String()
}

func minusOne(s string) string {
	n, ok := new(bigInt).SetString(s)
	if !ok {
		panic(s)
	}
	return n.add(-1).String()
}

// bigInt is an integer of the sizes that the tests use (below 2^64 in size), kept as a sign and a
// string of digits, so that nothing here is a Go integer of the size under test.
type bigInt struct {
	neg    bool
	digits string
}

func (b *bigInt) SetString(s string) (*bigInt, bool) {
	if strings.HasPrefix(s, "-") {
		b.neg, s = true, s[1:]
	}
	b.digits = s
	return b, s != ""
}

func (b *bigInt) String() string {
	if b.neg && b.digits != "0" {
		return "-" + b.digits
	}
	return b.digits
}

// add adds 1 or -1.
func (b *bigInt) add(d int) *bigInt {
	if b.neg {
		b.neg = false
		r := b.add(-d)
		if r.digits != "0" {
			r.neg = true
		}
		return r
	}
	digits := []byte(b.digits)
	if d > 0 {
		i := len(digits) - 1
		for ; i >= 0; i-- {
			if digits[i] == '9' {
				digits[i] = '0'
				continue
			}
			digits[i]++
			break
		}
		if i < 0 {
			digits = append([]byte{'1'}, digits...)
		}
		b.digits = string(digits)
		return b
	}
	if b.digits == "0" {
		b.neg, b.digits = true, "1"
		return b
	}
	i := len(digits) - 1
	for ; digits[i] == '0'; i-- {
		digits[i] = '9'
	}
	digits[i]--
	b.digits = strings.TrimLeft(string(digits), "0")
	if b.digits == "" {
		b.digits = "0"
	}
	return b
}

func TestIntegerArithmeticOfTheTest(t *testing.T) {
	for _, tc := range []struct{ in, plus, minus string }{
		{"0", "1", "-1"}, {"127", "128", "126"}, {"-128", "-127", "-129"}, {"255", "256", "254"},
		{"9223372036854775807", "9223372036854775808", "9223372036854775806"},
		{"-9223372036854775808", "-9223372036854775807", "-9223372036854775809"},
		{"999", "1000", "998"}, {"1000", "1001", "999"}, {"-1", "0", "-2"}, {"-1000", "-999", "-1001"},
	} {
		if got := plusOne(tc.in); got != tc.plus {
			t.Errorf("plusOne(%s) = %s, want %s", tc.in, got, tc.plus)
		}
		if got := minusOne(tc.in); got != tc.minus {
			t.Errorf("minusOne(%s) = %s, want %s", tc.in, got, tc.minus)
		}
	}
}

func TestEveryKindOfIntegerAtItsEdges(t *testing.T) {
	if strconv.IntSize != 64 {
		t.Skip("the edges of int and uint are those of a 64-bit build")
	}
	for _, k := range intKinds() {
		t.Run(k.name, func(t *testing.T) {
			typ := structOf([]string{"n"}, []reflect.Type{k.typ}, nil)
			read := func(text string) (reflect.Value, error) { return read(typ, `{"n":`+text+`}`, Options{}) }
			// -0 is read as zero by this reader for every kind, and refused for an unsigned one by the
			// standard decoder: that is not pinned here (see TestWhereBothDecodersAcceptADocument...).
			ins := []string{k.min, k.max, "0"}
			if k.min != "0" {
				ins = append(ins, "-0")
			}
			for _, in := range ins {
				got, err := read(in)
				if err != nil {
					t.Errorf("%s: %v", in, err)
					continue
				}
				want := in
				if in == "-0" {
					want = "0"
				}
				if text := fmt.Sprint(got.Field(0).Interface()); text != want {
					t.Errorf("%s was read as %s", in, text)
				}
			}
			// One beyond on each side. An integer that does not fit 64 bits is refused by the parser,
			// before it is a value of any kind; any other by the kind of the field.
			for _, in := range []string{minusOne(k.min), plusOne(k.max)} {
				_, err := read(in)
				doc := `{"n":` + in + `}`
				if _, perr := strconv.ParseInt(in, 10, 64); perr != nil {
					fail(t, err, mal("$.n", "the integer does not fit 64 bits"+byteAfter(doc, in)))
				} else {
					fail(t, err, mal("$.n", fmt.Sprintf("the integer %s does not fit the type %s", in, k.typ)))
				}
			}
		})
	}
	t.Run("a value that does not fit leaves the field as it was", func(t *testing.T) {
		v := struct{ A int8 }{A: 5}
		if err := Unmarshal([]byte(`{"A":128}`), &v, Options{}); err == nil || v.A != 5 {
			t.Errorf("%+v, %v", v, err)
		}
	})
	t.Run("an integer is not read into the wrong kind", func(t *testing.T) {
		for _, tc := range []struct {
			typ  reflect.Type
			text string
			what string
		}{
			{reflect.TypeFor[string](), `1`, "expected a string, found an integer"},
			{reflect.TypeFor[bool](), `1`, "expected true or false, found an integer"},
			{reflect.TypeFor[[]int](), `1`, "expected a list, found an integer"},
			{reflect.TypeFor[map[string]int](), `1`, "expected an object, found an integer"},
			{reflect.TypeFor[point](), `1`, "expected an object, found an integer"},
			{reflect.TypeFor[Raw](), `1`, "expected one JSON object, for a Raw, found an integer"},
			{reflect.TypeFor[int](), `"1"`, "expected an integer, found a string"},
			{reflect.TypeFor[int](), `true`, "expected an integer, found true or false"},
			{reflect.TypeFor[int](), `[1]`, "expected an integer, found a list"},
			{reflect.TypeFor[int](), `{}`, "expected an integer, found an object"},
			{reflect.TypeFor[uint8](), `"1"`, "expected an integer, found a string"},
			{reflect.TypeFor[bool](), `"true"`, "expected true or false, found a string"},
			{reflect.TypeFor[bool](), `0`, "expected true or false, found an integer"},
			{reflect.TypeFor[string](), `true`, "expected a string, found true or false"},
			{reflect.TypeFor[string](), `[]`, "expected a string, found a list"},
			{reflect.TypeFor[[]int](), `{}`, "expected a list, found an object"},
			{reflect.TypeFor[[]int](), `"AAAA"`, "expected a list, found a string"},
			{reflect.TypeFor[map[string]int](), `[]`, "expected an object, found a list"},
			{reflect.TypeFor[point](), `[]`, "expected an object, found a list"},
			{reflect.TypeFor[point](), `"x"`, "expected an object, found a string"},
			{reflect.TypeFor[*point](), `1`, "expected an object, found an integer"},
		} {
			typ := structOf([]string{"n"}, []reflect.Type{tc.typ}, nil)
			_, err := read(typ, `{"n":`+tc.text+`}`, Options{})
			fail(t, err, mal("$.n", tc.what))
		}
	})
}

func TestNumbersThatAreNotIntegers(t *testing.T) {
	typ := structOf([]string{"n"}, []reflect.Type{reflect.TypeFor[int64]()}, nil)
	t.Run("the grammar", func(t *testing.T) {
		for _, in := range []string{`01`, `-01`, `00`, `+1`, `.5`, `1.`, `-`, `--1`, `0x10`, `1_000`, `1e`, `1e+`, `0b1`, `Infinity`, `NaN`, `-Infinity`, ` `, `١`, `1 2`, `1,2`, `−1`} {
			if _, err := read(typ, `{"n":`+in+`}`, Options{}); err == nil {
				t.Errorf("%s was read", in)
			}
		}
	})
	t.Run("a number with a fraction or an exponent", func(t *testing.T) {
		for _, in := range []string{`1.0`, `-0.0`, `0.5`, `1e0`, `1E0`, `1e+0`, `1e-0`, `10e-1`, `0e0`, `1.5e1`} {
			doc := `{"n":` + in + `}`
			_, err := read(typ, doc, Options{})
			fail(t, err, mal("$.n", "a number with a fraction or an exponent"+byteAfter(doc, in)))
		}
	})
	t.Run("a number longer than any integer", func(t *testing.T) {
		for _, in := range []string{strings.Repeat("9", 20), strings.Repeat("1", 100), "-" + strings.Repeat("9", 20), "1" + strings.Repeat("0", 1000)} {
			doc := `{"n":` + in + `}`
			_, err := read(typ, doc, Options{})
			fail(t, err, mal("$.n", "the integer does not fit 64 bits"+byteAfter(doc, in)))
		}
	})
	t.Run("minus zero is zero, for a signed kind and for any", func(t *testing.T) {
		var v struct {
			A int8
			C int64
			E any
		}
		if err := Unmarshal([]byte(`{"A":-0,"C":-0,"E":-0}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if v.A != 0 || v.C != 0 || v.E != int64(0) || math.Signbit(float64(v.C)) {
			t.Errorf("%+v", v)
		}
	})
}

// ---- Raw ----------------------------------------------------------------------------------

func TestRawTakesTheExactBytesOfAnObject(t *testing.T) {
	type doc struct {
		R Raw `json:"r"`
	}
	objects := []string{
		`{}`,
		`{ }`,
		"{\n\t\"a\" : 1 ,\r\n\"b\" : [ 1 , 2 ]\n}",
		`{"b":1,"a":2}`,
		`{"a":"` + uesc('A') + `/` + bs + `/"}`,
		`{"a":-0,"b":0}`,
		`{"` + uesc('a') + `":1}`,
		`{"a":{"b":{"c":[{},[],""]}}}`,
		`{"a":"` + string(rune(0x1F600)) + `"}`,
		`{"a":"` + bs + `ud83d` + bs + `ude00"}`,
		`{"z":{"y":1,"x":2},"a":[3,2,1]}`,
	}
	for _, in := range objects {
		var d doc
		if err := Unmarshal([]byte(`{"r":`+in+`}`), &d, Options{}); err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if string(d.R) != in {
			t.Errorf("the Raw is %q, want the exact bytes %q", d.R, in)
		}
		// White space around the member is not part of it.
		var e doc
		if err := Unmarshal([]byte(" \n{ \"r\" :\t"+in+" \r\n}\n"), &e, Options{}); err != nil || string(e.R) != in {
			t.Errorf("with white space around: %q, %v", e.R, err)
		}
	}
	t.Run("a member that is not an object is refused, with its kind", func(t *testing.T) {
		for _, tc := range []struct{ in, what string }{
			{`[]`, "a list"}, {`[{}]`, "a list"}, {`"x"`, "a string"}, {`""`, "a string"}, {`1`, "an integer"}, {`-0`, "an integer"},
			{`true`, "true or false"}, {`false`, "true or false"},
		} {
			var d doc
			fail(t, Unmarshal([]byte(`{"r":`+tc.in+`}`), &d, Options{}), mal("$.r", "expected one JSON object, for a Raw, found "+tc.what))
			if d.R != nil {
				t.Errorf("%s: the Raw is %q", tc.in, d.R)
			}
		}
	})
	t.Run("the rules reach into the Raw", func(t *testing.T) {
		for _, tc := range []struct{ in, what string }{
			{`{"a":1,"a":2}`, "the member appears twice"},
			{`{"a":1.5}`, "a number with a fraction or an exponent"},
			{`{"a":null}`, "null"},
			{`{"a":"` + bs + `ud800"}`, "a lone surrogate escape"},
			{`{"a":99999999999999999999}`, "the integer does not fit 64 bits"},
		} {
			var d doc
			err := Unmarshal([]byte(`{"r":`+tc.in+`}`), &d, Options{})
			if err == nil || !strings.Contains(err.Error(), tc.what) {
				t.Errorf("%s: %v, want %q", tc.in, err, tc.what)
			}
		}
	})
	t.Run("a pointer to a Raw, a list of Raw and a map of Raw", func(t *testing.T) {
		var p struct {
			R *Raw `json:"r"`
			S *Raw `json:"s"`
		}
		if err := Unmarshal([]byte(`{"r":{ "a" : 1 }}`), &p, Options{}); err != nil || p.R == nil || string(*p.R) != `{ "a" : 1 }` || p.S != nil {
			t.Errorf("%v, %v", p, err)
		}
		var l struct{ L []Raw }
		fail(t, Unmarshal([]byte(`{"L":[{},[]]}`), &l, Options{}), mal("$.L[1]", "expected one JSON object, for a Raw, found a list"))
		var m map[string]Raw
		fail(t, Unmarshal([]byte(`{"a":{},"b":1}`), &m, Options{}), mal("$.b", "expected one JSON object, for a Raw, found an integer"))
		var pp struct{ R *Raw }
		fail(t, Unmarshal([]byte(`{"R":[]}`), &pp, Options{}), mal("$.R", "expected one JSON object, for a Raw, found a list"))
	})
	t.Run("a Raw at the top", func(t *testing.T) {
		var r Raw
		fail(t, Unmarshal([]byte(`[]`), &r, Options{}), mal("$", "not one JSON object"))
		fail(t, Unmarshal([]byte(`{"a":1.5}`), &r, Options{}), mal("$.a", "a number with a fraction or an exponent at byte 8"))
		var pr *Raw
		if err := Unmarshal([]byte(` {"a":1} `), &pr, Options{}); err != nil || pr == nil || string(*pr) != `{"a":1}` {
			t.Errorf("%v, %v", pr, err)
		}
	})
	t.Run("a missing member leaves a nil Raw", func(t *testing.T) {
		d := doc{R: Raw(`{"old":1}`)}
		if err := Unmarshal([]byte(`{}`), &d, Options{}); err != nil || d.R != nil {
			t.Errorf("%#v, %v", d.R, err)
		}
	})
	t.Run("a Raw as deep as the document may be", func(t *testing.T) {
		deep := strings.Repeat(`{"a":`, MaxDepth-2) + `{}` + strings.Repeat(`}`, MaxDepth-2) // MaxDepth-1 levels, one for the top
		var d doc
		if err := Unmarshal([]byte(`{"r":`+deep+`}`), &d, Options{}); err != nil || string(d.R) != deep {
			t.Errorf("%v", err)
		}
		over := strings.Repeat(`{"a":`, MaxDepth-1) + `{}` + strings.Repeat(`}`, MaxDepth-1)
		if err := Unmarshal([]byte(`{"r":`+over+`}`), &d, Options{}); err == nil {
			t.Error("a Raw one level too deep for the whole document was read")
		}
	})
}

// rawCorpus is documents for the methods of Raw and for Unmarshal into a Raw: the tables of the
// rules, and some more.
func rawCorpus() []string {
	var docs []string
	for _, tc := range accepted {
		docs = append(docs, tc.in)
	}
	for _, tc := range refused {
		docs = append(docs, tc.in)
	}
	return append(docs,
		`{"a":1}`, ` {"a":1} `, "\n{}\n", `{} `, ` {}`, `{"a":{"b":[1,2,{"c":null}]}}`, `{"a":1.5}`, `[{}]`, `{"a":[]}`, `{"b":1,"a":2}`,
		string(nested(MaxDepth)), string(nested(MaxDepth+1)), `{"a":"`+strings.Repeat("x", DefaultMaxBytes-len(`{"a":""}`))+`"}`,
	)
}

func TestRawMethodsAgreeWithUnmarshalAboutWhatARawMayBe(t *testing.T) {
	for _, in := range rawCorpus() {
		data := []byte(in)
		var viaMethod Raw
		methodErr := viaMethod.UnmarshalJSON(data)
		var viaUnmarshal Raw
		unmarshalErr := Unmarshal(data, &viaUnmarshal, Options{})
		if (methodErr == nil) != (unmarshalErr == nil) {
			t.Errorf("%.60q: UnmarshalJSON says %v, Unmarshal says %v", in, methodErr, unmarshalErr)
			continue
		}
		if methodErr != nil {
			if methodErr.Error() != unmarshalErr.Error() {
				t.Errorf("%.60q: the two texts differ: %q and %q", in, methodErr, unmarshalErr)
			}
			if viaMethod != nil {
				t.Errorf("%.60q: a Raw next to an error", in)
			}
			continue
		}
		// What is stored: UnmarshalJSON keeps all that it is given, Unmarshal the object without the
		// white space around it.
		if string(viaMethod) != in || string(viaUnmarshal) != strings.Trim(in, " \t\r\n") {
			t.Errorf("%.60q: stored %.60q and %.60q", in, viaMethod, viaUnmarshal)
		}
		// MarshalJSON gives back what it holds, after the same check.
		out, err := viaMethod.MarshalJSON()
		if err != nil || string(out) != in {
			t.Errorf("%.60q: MarshalJSON gives %.60q, %v", in, out, err)
		}
		if err := Check(viaMethod, 0); err != nil {
			t.Errorf("%.60q: a Raw that does not pass Check", in)
		}
	}
	t.Run("MarshalJSON refuses what is not one object, by the rules of Check", func(t *testing.T) {
		for _, in := range rawCorpus() {
			out, err := Raw(in).MarshalJSON()
			checkErr := Check([]byte(in), 0)
			if (err == nil) != (checkErr == nil) {
				t.Errorf("%.60q: MarshalJSON says %v, Check says %v", in, err, checkErr)
			}
			if err != nil && (out != nil || err.Error() != checkErr.Error()) {
				t.Errorf("%.60q: %q %v", in, out, err)
			}
		}
		for _, r := range []Raw{nil, {}, Raw("")} {
			out, err := r.MarshalJSON()
			if want := mal("$", "not one JSON object"); err == nil || err.Error() != want || out != nil {
				t.Errorf("an empty Raw: %q, %v, want the refusal %q", out, err, want)
			}
		}
	})
	t.Run("UnmarshalJSON stores a copy, and leaves the Raw alone on an error", func(t *testing.T) {
		data := []byte(`{"a":1}`)
		var r Raw
		if err := r.UnmarshalJSON(data); err != nil {
			t.Fatal(err)
		}
		data[2] = 'z'
		if string(r) != `{"a":1}` {
			t.Errorf("the Raw followed the input: %q", r)
		}
		before := Raw(`{"old":true}`)
		r = before
		if err := r.UnmarshalJSON([]byte(`[1]`)); err == nil || string(r) != `{"old":true}` {
			t.Errorf("%q, %v", r, err)
		}
	})
	t.Run("the standard encoder and decoder call the methods", func(t *testing.T) {
		var d struct{ R Raw }
		if err := unmarshalStd([]byte(`{"R": { "b" : 1 } }`), &d); err != nil || string(d.R) != `{ "b" : 1 }` {
			t.Errorf("%q, %v", d.R, err)
		}
		if err := unmarshalStd([]byte(`{"R":[1]}`), &d); err == nil {
			t.Error("the standard decoder gave a list to a Raw")
		}
	})
}

// ---- any ----------------------------------------------------------------------------------

func TestAnInterfaceIsFilledDeepWithFiveTypesOnly(t *testing.T) {
	t.Run("as deep as a document may be", func(t *testing.T) {
		for name, doc := range map[string]string{"objects": string(nested(MaxDepth)), "lists": string(nestedArrays(MaxDepth))} {
			var v any
			if err := Unmarshal([]byte(doc), &v, Options{}); err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			levels := 0
			for x := v; ; {
				switch c := x.(type) {
				case map[string]any:
					levels++
					x = c["a"]
					if x == nil {
						x = int64(0)
					}
					continue
				case []any:
					levels++
					x = c[0]
					continue
				}
				break
			}
			if levels != MaxDepth {
				t.Errorf("%s: %d levels, want %d", name, levels, MaxDepth)
			}
		}
	})
	t.Run("a document of every kind of value in lists and objects", func(t *testing.T) {
		var v any
		doc := `{"a":[{"b":[true,false,"s",-5,{"c":{}},[],[[]]]}],"d":"","e":0}`
		if err := Unmarshal([]byte(doc), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		want := map[string]any{
			"a": []any{map[string]any{"b": []any{true, false, "s", int64(-5), map[string]any{"c": map[string]any{}}, []any{}, []any{[]any{}}}}},
			"d": "",
			"e": int64(0),
		}
		if !reflect.DeepEqual(v, want) {
			t.Errorf("got  %#v\nwant %#v", v, want)
		}
	})
	t.Run("an empty object and an empty list are not nil", func(t *testing.T) {
		var v any
		if err := Unmarshal([]byte(`{"a":{},"b":[]}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		m := v.(map[string]any)
		if m["a"].(map[string]any) == nil || m["b"].([]any) == nil {
			t.Errorf("%#v", v)
		}
	})
	t.Run("every interface with methods is refused, at every place", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			v    any
			typ  string
			path string
			hops []string
		}{
			{"a field", &struct{ S namedStringer }{}, "strictjson.namedStringer", "$.S", nil},
			{"error in a field", &struct{ E error }{}, "error", "$.E", nil},
			{"a list", &struct{ L []error }{}, "error", "$.L", []string{"[]"}},
			{"a map", &map[string]error{}, "error", "$", []string{"{}"}},
			{"an array", &struct{ A [1]error }{}, "error", "$.A", []string{"[]"}},
			{"at the top", new(error), "error", "$", nil},
		} {
			err := Unmarshal([]byte(`{}`), tc.v, Options{})
			fail(t, err, cannotRead(tc.path, tc.hops, tc.typ, reasonIface))
		}
	})
}

// namedStringer is an interface with a method, like fmt.Stringer.
type namedStringer interface{ String() string }
