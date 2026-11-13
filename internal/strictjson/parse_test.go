package strictjson

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The tree that Parse returns, which canonjson writes the canonical form from, and the texts of the
// errors of the grammar.

// describe writes a Value as text, with the bytes of the input that each node holds in brackets, so
// that a test can say what the tree is in one line.
func describe(data []byte, v *Value) string {
	text := string(data[v.Start:v.End])
	switch v.Kind {
	case Object:
		var parts []string
		for i := range v.Members {
			parts = append(parts, fmt.Sprintf("%q:%s", v.Members[i].Name, describe(data, &v.Members[i].Value)))
		}
		return "obj{" + strings.Join(parts, ",") + "}<" + text + ">"
	case List:
		var parts []string
		for i := range v.Elems {
			parts = append(parts, describe(data, &v.Elems[i]))
		}
		return "list[" + strings.Join(parts, ",") + "]<" + text + ">"
	case String:
		return fmt.Sprintf("str(%q)<%s>", v.Str, text)
	case Integer:
		return fmt.Sprintf("int(%d)<%s>", v.Int, text)
	case Bool:
		return fmt.Sprintf("bool(%v)<%s>", v.Bool, text)
	}
	return fmt.Sprintf("kind%d<%s>", v.Kind, text)
}

func TestParseReturnsTheTreeWithItsPlaceInTheInput(t *testing.T) {
	e, eu := string(rune(0xe9)), string(rune(0x20ac))
	cases := []struct{ name, in, want string }{
		{"an empty object", `{}`, `obj{}<{}>`},
		{"white space around the object is not part of it", " \n{ }\t", `obj{}<{ }>`},
		{"members in the order of the input", `{"b":1,"a":2}`, `obj{"b":int(1)<1>,"a":int(2)<2>}<{"b":1,"a":2}>`},
		{"every kind of value", `{"s":"x","n":-12,"t":true,"f":false,"o":{"k":[1,{}]},"e":[],"z":{}}`,
			`obj{"s":str("x")<"x">,"n":int(-12)<-12>,"t":bool(true)<true>,"f":bool(false)<false>,"o":obj{"k":list[int(1)<1>,obj{}<{}>]<[1,{}]>}<{"k":[1,{}]}>,"e":list[]<[]>,"z":obj{}<{}>}` +
				`<{"s":"x","n":-12,"t":true,"f":false,"o":{"k":[1,{}]},"e":[],"z":{}}>`},
		{"white space inside is part of the bytes of each node, but not around them", "{ \"a\" : [ 1 , 2 ] , \"b\" : { } }",
			"obj{\"a\":list[int(1)<1>,int(2)<2>]<[ 1 , 2 ]>,\"b\":obj{}<{ }>}<{ \"a\" : [ 1 , 2 ] , \"b\" : { } }>"},
		{"minus zero is the integer zero and keeps its bytes", `{"a":-0}`, `obj{"a":int(0)<-0>}<{"a":-0}>`},
		{"the extremes of int64", `{"a":9223372036854775807,"b":-9223372036854775808}`, `obj{"a":int(9223372036854775807)<9223372036854775807>,"b":int(-9223372036854775808)<-9223372036854775808>}<{"a":9223372036854775807,"b":-9223372036854775808}>`},
		{"escapes are read in the text and kept in the bytes", `{"a":"` + bs + `n` + uesc('A') + `"}`, `obj{"a":str("\nA")<"` + bs + `n` + uesc('A') + `">}<{"a":"` + bs + `n` + uesc('A') + `"}>`},
		{"a name with an escape is read", `{"` + uesc('a') + `":1}`, `obj{"a":int(1)<1>}<{"` + uesc('a') + `":1}>`},
		{"a surrogate pair is one character", `{"a":"` + bs + `ud83d` + bs + `ude00"}`, `obj{"a":str("` + string(rune(0x1F600)) + `")<"` + bs + `ud83d` + bs + `ude00">}<{"a":"` + bs + `ud83d` + bs + `ude00"}>`},
		{"text outside ASCII", `{"` + e + `":"` + eu + `"}`, `obj{"` + e + `":str("` + eu + `")<"` + eu + `">}<{"` + e + `":"` + eu + `"}>`},
		{"lists in lists", `{"a":[[],[[1]]]}`, `obj{"a":list[list[]<[]>,list[list[int(1)<1>]<[1]>]<[[1]]>]<[[],[[1]]]>}<{"a":[[],[[1]]]}>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, err := Parse([]byte(tc.in), 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := describe([]byte(tc.in), root); got != tc.want {
				t.Errorf("got\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
	t.Run("Parse refuses what Check refuses, with the same text", func(t *testing.T) {
		for _, in := range append(refusedTexts(), `{"a":1,"a":2}`, `{"a":null}`, `{"a":1.5}`, `[]`, ``) {
			_, perr := Parse([]byte(in), 0)
			cerr := Check([]byte(in), 0)
			if (perr == nil) != (cerr == nil) || (perr != nil && perr.Error() != cerr.Error()) {
				t.Errorf("%.40q: Parse says %v, Check says %v", in, perr, cerr)
			}
		}
	})
	t.Run("Parse takes a limit of the caller", func(t *testing.T) {
		if _, err := Parse([]byte(`{"a":1}`), 7); err != nil {
			t.Error(err)
		}
		_, err := Parse([]byte(`{"a":1}`), 6)
		fail(t, err, mal("$", "longer than 6 bytes"))
	})
}

func refusedTexts() []string {
	var out []string
	for _, tc := range refused {
		out = append(out, tc.in)
	}
	return out
}

func TestTheErrorsOfTheGrammar(t *testing.T) {
	cases := []struct{ name, in, path, what string }{
		{"a member name was expected, after a comma", `{"a":1,}`, "$", "a member name was expected at byte 7"},
		{"a member name was expected, at the start", `{1:1}`, "$", "a member name was expected at byte 1"},
		{"a member name was expected, at the end of the input", `{`, "$", "a member name was expected at byte 1"},
		{"a colon was expected", `{"a" 1}`, "$", "a colon was expected at byte 5"},
		{"a colon was expected, at the end of the input", `{"a"`, "$", "a colon was expected at byte 4"},
		{"a value was expected", `{"a":}`, "$.a", "not a JSON value at byte 5"},
		{"a value was expected, after a comma in a list", `{"a":[1,]}`, "$.a[1]", "not a JSON value at byte 8"},
		{"the input ends inside a value", `{"a":`, "$.a", "the input ends inside a value at byte 5"},
		{"the input ends inside a value in a list", `{"a":[1,`, "$.a[1]", "the input ends inside a value at byte 8"},
		{"the input ends inside an object", `{"a":1`, "$", "the input ends inside an object at byte 6"},
		{"the input ends inside an object, deeper", `{"a":{"b":1`, "$.a", "the input ends inside an object at byte 11"},
		{"the input ends inside an array", `{"a":[1`, "$.a", "the input ends inside an array at byte 7"},
		{"the input ends inside an array, deeper", `{"a":[[1]`, "$.a", "the input ends inside an array at byte 9"},
		{"the input ends inside a string", `{"a":"x`, "$.a", "the input ends inside a string at byte 7"},
		{"the input ends inside a name", `{"a`, "$", "the input ends inside a string at byte 3"},
		{"the input ends inside an escape", `{"a":"` + bs, "$.a", "the input ends inside a string at byte 7"},
		{"the input ends inside a unicode escape", `{"a":"` + bs + `u12`, "$.a", "the input ends inside an escape at byte 8"},
		{"the input ends inside a number", `{"a":-`, "$.a", "the input ends inside a number at byte 6"},
		{"a comma or a closing brace was expected", `{"a":1 "b":2}`, "$", "a comma or a closing brace was expected at byte 7"},
		{"a comma or a closing bracket was expected", `{"a":[1 2]}`, "$.a", "a comma or a closing bracket was expected at byte 8"},
		{"a mismatched closer", `{"a":[1}`, "$.a", "a comma or a closing bracket was expected at byte 7"},
		{"a mismatched closer the other way", `{"a":{"b":1]}`, "$.a", "a comma or a closing brace was expected at byte 11"},
		{"an unknown escape", `{"a":"` + bs + `x"}`, "$.a", "an unknown escape at byte 8"},
		{"an unknown escape in a name", `{"` + bs + `x":1}`, "$", "an unknown escape at byte 4"},
		{"a bad digit in an escape", `{"a":"` + bs + `u12g4"}`, "$.a", "not a hexadecimal digit in an escape at byte 8"},
		{"a control character in a string", "{\"a\":\"\x01\"}", "$.a", "a control character inside a string at byte 6"},
		{"a control character in a name", "{\"\x1f\":1}", "$", "a control character inside a string at byte 2"},
		{"not a number", `{"a":-x}`, "$.a", "not a number at byte 6"},
		{"a digit was expected after the point", `{"a":1.}`, "$.a", "a digit was expected after the point at byte 7"},
		{"a digit was expected in the exponent", `{"a":1e}`, "$.a", "a digit was expected in the exponent at byte 7"},
		{"a digit was expected in a signed exponent", `{"a":1e+}`, "$.a", "a digit was expected in the exponent at byte 8"},
		{"a lone surrogate in a name", `{"` + bs + `ud800":1}`, "$", "a lone surrogate escape at byte 8"},
		{"a lone low surrogate", `{"a":"` + bs + `udc00"}`, "$.a", "a lone surrogate escape at byte 12"},
		{"a high surrogate with the wrong partner", `{"a":"` + bs + `ud800` + bs + `u0041"}`, "$.a", "a lone surrogate escape at byte 12"},
		{"a second object", `{}{}`, "$", "anything after the object at byte 2"},
		{"a number after the object", "{} 1", "$", "anything after the object at byte 3"},
		{"a misspelt literal", `{"a":nul}`, "$.a", "not a JSON value at byte 5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := mal(tc.path, tc.what)
			for who, err := range map[string]error{"Check": Check([]byte(tc.in), 0), "Parse": parseErr(tc.in)} {
				if err == nil || err.Error() != want || !errors.Is(err, ErrMalformed) {
					t.Errorf("%s: %v, want %q", who, err, want)
				}
			}
		})
	}
	t.Run("a lone low surrogate is text to PeekInt, which does not apply that rule", func(t *testing.T) {
		n, ok, err := PeekInt([]byte(`{"version":4,"a":"`+bs+`udc00","`+bs+`ud800":1}`), "version")
		if err != nil || !ok || n != 4 {
			t.Errorf("%d, %v, %v", n, ok, err)
		}
		// The name of a lone surrogate reads as U+FFFD, which is not the name that is asked for.
		if _, ok, err := PeekInt([]byte(`{"`+bs+`ud800":4}`), "version"); err != nil || ok {
			t.Errorf("%v, %v", ok, err)
		}
		if _, ok, err := PeekInt([]byte(`{"`+bs+`ud800":4}`), string(rune(0xFFFD))); err != nil || !ok {
			t.Errorf("a name that is a lone surrogate is read as U+FFFD: %v, %v", ok, err)
		}
	})
}

func parseErr(in string) error {
	_, err := Parse([]byte(in), 0)
	return err
}

func TestLongListsAndObjectsAreReadWhole(t *testing.T) {
	// Sizes around the points where a reader that grows its slices or stops early could go wrong,
	// and one that is long.
	for _, n := range []int{0, 1, 2, 7, 8, 9, 63, 64, 65, 99, 100, 101, 127, 128, 129, 255, 256, 257, 1000, 4097, 30000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			var ints, strs, objs []string
			var members []string
			for i := range n {
				ints = append(ints, fmt.Sprint(i-n/2))
				strs = append(strs, fmt.Sprintf("%q", fmt.Sprint(i)))
				objs = append(objs, fmt.Sprintf(`{"X":%d}`, i))
				members = append(members, fmt.Sprintf(`"m%d":%d`, i, i))
			}
			doc := `{"i":[` + strings.Join(ints, ",") + `],"s":[` + strings.Join(strs, ",") + `],"o":[` + strings.Join(objs, ",") + `],"m":{` + strings.Join(members, ",") + `},"a":[` + strings.Join(ints, ",") + `]}`
			if len(doc) > DefaultMaxBytes {
				doc = `{"i":[` + strings.Join(ints, ",") + `]}`
			}
			var v struct {
				I []int64        `json:"i"`
				S []string       `json:"s"`
				O []point        `json:"o"`
				M map[string]int `json:"m"`
				A []any          `json:"a"`
			}
			if err := Unmarshal([]byte(doc), &v, Options{}); err != nil {
				t.Fatal(err)
			}
			if len(v.I) != n {
				t.Fatalf("%d integers, want %d", len(v.I), n)
			}
			for i, x := range v.I {
				if x != int64(i-n/2) {
					t.Fatalf("integer %d is %d", i, x)
				}
			}
			if strings.Contains(doc, `"s":`) {
				if len(v.S) != n || len(v.O) != n || len(v.M) != n || len(v.A) != n {
					t.Fatalf("lengths %d %d %d %d, want %d", len(v.S), len(v.O), len(v.M), len(v.A), n)
				}
				if n > 0 && (v.S[n-1] != fmt.Sprint(n-1) || v.O[n-1].X != n-1 || v.M[fmt.Sprintf("m%d", n-1)] != n-1 || v.A[n-1] != int64(n-1-n/2)) {
					t.Errorf("the last element is wrong: %q %v %v %v", v.S[n-1], v.O[n-1], v.M[fmt.Sprintf("m%d", n-1)], v.A[n-1])
				}
			}
			root, err := Parse([]byte(doc), 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(root.Members[0].Value.Elems); got != n {
				t.Errorf("the tree has %d elements, want %d", got, n)
			}
			// A Raw and an array of exactly the length.
			var r struct {
				I Raw `json:"i"`
			}
			if err := Unmarshal([]byte(`{"i":{"k":[`+strings.Join(ints, ",")+`]}}`), &r, Options{}); err != nil || !strings.HasSuffix(string(r.I), `]}`) || strings.Count(string(r.I), ",") != max(n-1, 0) {
				t.Errorf("a Raw of %d elements: %v", n, err)
			}
		})
	}
	t.Run("an array of 300", func(t *testing.T) {
		var els []string
		for i := range 300 {
			els = append(els, fmt.Sprint(i))
		}
		var v struct{ A [300]int }
		if err := Unmarshal([]byte(`{"A":[`+strings.Join(els, ",")+`]}`), &v, Options{}); err != nil || v.A[299] != 299 || v.A[150] != 150 {
			t.Errorf("%v", err)
		}
		fail(t, Unmarshal([]byte(`{"A":[`+strings.Join(els[:299], ",")+`]}`), &v, Options{}), mal("$.A", "the list has 299 elements, and the array of type [300]int holds exactly 300"))
	})
}

func TestLongNamesAndLongStringsAreKeptWhole(t *testing.T) {
	// Names that are alike for a long way and differ at the end are two names, and a name or a
	// string of any length is read as it is.
	long := strings.Repeat("n", 5000)
	for _, size := range []int{39, 40, 41, 199, 200, 201, 999, 1000, 1001, 5000, 50000} {
		name := strings.Repeat("n", size)
		other := name[:size-1] + "m"
		doc := `{"` + name + `":"` + name + `","` + other + `":"` + other + `"}`
		var m map[string]string
		if err := Unmarshal([]byte(doc), &m, Options{}); err != nil || len(m) != 2 || m[name] != name || m[other] != other {
			t.Errorf("%d: %v, %d members", size, err, len(m))
		}
		var a any
		if err := Unmarshal([]byte(doc), &a, Options{}); err != nil || len(a.(map[string]any)) != 2 {
			t.Errorf("%d in any: %v", size, err)
		}
		// The same name twice is refused whatever its length.
		dup := `{"` + name + `":1,"` + name + `":2}`
		if err := Check([]byte(dup), 0); err == nil {
			t.Errorf("%d: a repeated name was read", size)
		}
	}
	// A struct whose tag name is long reads it.
	typ := structOf([]string{long, long[:len(long)-1] + "m"}, []reflect.Type{reflect.TypeFor[int](), reflect.TypeFor[int]()}, nil)
	got, err := read(typ, `{"`+long+`":1,"`+long[:len(long)-1]+`m":2}`, Options{})
	if err != nil || got.Field(0).Int() != 1 || got.Field(1).Int() != 2 {
		t.Errorf("a struct with names of %d bytes: %v", len(long), err)
	}
	// A name that is long and unknown is refused by its path, which is cut, and the error is short.
	var v point
	err = Unmarshal([]byte(`{"`+long+`":1}`), &v, Options{})
	if err == nil || len(err.Error()) > 300 || !strings.Contains(err.Error(), "unknown member") {
		t.Errorf("%v", err)
	}
	// A list with more than 70000 elements, which a document of 256 KiB may hold.
	list := "[" + strings.Repeat("0,", 80000) + "0]"
	var l struct {
		L []int8 `json:"l"`
		A []any  `json:"a"`
	}
	if err := Unmarshal([]byte(`{"l":`+list+`,"a":[`+strings.Repeat("1,", 40000)+`1]}`), &l, Options{}); err != nil || len(l.L) != 80001 || len(l.A) != 40001 {
		t.Errorf("%v, %d, %d", err, len(l.L), len(l.A))
	}
	// A string of every length up to the limit.
	for _, n := range []int{0, 1, 999, 1000, 1001, 100000, DefaultMaxBytes - 8} {
		var s struct{ A string }
		if err := Unmarshal([]byte(`{"A":"`+strings.Repeat("x", n)+`"}`), &s, Options{}); err != nil || len(s.A) != n {
			t.Errorf("a string of %d bytes: %v, %d", n, err, len(s.A))
		}
	}
}

func TestAStructOfManyFieldsIsReadWhole(t *testing.T) {
	for _, n := range []int{1, 8, 9, 30, 31, 32, 33, 64, 65, 129, 300} {
		names := make([]string, n)
		types := make([]reflect.Type, n)
		var members []string
		for i := range names {
			names[i] = fmt.Sprintf("f%d", n-i)
			types[i] = reflect.TypeFor[int]()
			members = append(members, fmt.Sprintf(`"f%d":%d`, i+1, i))
		}
		typ := structOf(names, types, nil)
		got, err := read(typ, "{"+strings.Join(members, ",")+"}", Options{})
		if err != nil {
			t.Fatalf("%d fields: %v", n, err)
		}
		for i := range n {
			// Field i is named f<n-i>, and the member f<j> has the value j-1.
			if want := int64(n - i - 1); got.Field(i).Int() != want {
				t.Fatalf("%d fields: field %d is %d, want %d", n, i, got.Field(i).Int(), want)
			}
		}
		// A name that is the right one in another case, and an unknown one, are refused at the last field as at the first.
		for _, in := range []string{`{"F1":1}`, fmt.Sprintf(`{"F%d":1}`, n), `{"zzz":1}`} {
			if _, err := read(typ, in, Options{}); err == nil {
				t.Errorf("%d fields: %s was read", n, in)
			}
		}
	}
}
