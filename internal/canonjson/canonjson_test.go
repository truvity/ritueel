package canonjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
	"ritueel.id/ritueel/internal/testrepo"
)

// rfcInput is the object of RFC 8785 section 3.2.3 ("Sorting of Object Properties"), with the
// member names the RFC lists. The RFC says they sort as \r, 1, \u0080, \u00f6, \u20ac,
// \ud83d\ude00 (the emoji, a surrogate pair in UTF-16) and \ufb33: in UTF-16 the pair
// 0xD83D 0xDE00 is before 0xFB33, in UTF-8 the emoji is after it.
const rfcInput = `{
  "\u20ac": "Euro Sign",
  "\r": "Carriage Return",
  "\ufb33": "Hebrew Letter Dalet With Dagesh",
  "1": "One",
  "\ud83d\ude00": "Emoji: Grinning Face",
  "\u0080": "Control",
  "\u00f6": "Latin Small Letter O With Diaeresis"
}`

// rfcWant is the same object in canonical form, written from the text of the RFC: only the
// carriage return is escaped, every other name is written as the character it is.
const rfcWant = "{" +
	`"\r":"Carriage Return",` +
	`"1":"One",` +
	"\"\u0080\":\"Control\"," +
	"\"\u00f6\":\"Latin Small Letter O With Diaeresis\"," +
	"\"\u20ac\":\"Euro Sign\"," +
	"\"\U0001F600\":\"Emoji: Grinning Face\"," +
	"\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"" +
	"}"

func TestCanonicalizeSortsMembersAsUTF16(t *testing.T) {
	got, err := Canonicalize([]byte(rfcInput))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != rfcWant {
		t.Errorf("got  %q\nwant %q", got, rfcWant)
	}
	// The point of the example, stated alone: the emoji (U+1F600) is before U+FB33 although its
	// UTF-8 bytes are after.
	if bytes.Index(got, []byte("\U0001F600")) >= bytes.Index(got, []byte("\ufb33")) {
		t.Error("the emoji does not come before U+FB33")
	}
}

func TestMarshalSortsMembersAsUTF16(t *testing.T) {
	names := map[string]string{
		"\u20ac":     "Euro Sign",
		"\r":         "Carriage Return",
		"\ufb33":     "Hebrew Letter Dalet With Dagesh",
		"1":          "One",
		"\U0001F600": "Emoji: Grinning Face",
		"\u0080":     "Control",
		"\u00f6":     "Latin Small Letter O With Diaeresis",
	}
	got, err := Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != rfcWant {
		t.Errorf("got  %q\nwant %q", got, rfcWant)
	}
}

func TestMemberOrder(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"already sorted", `{"a":1,"b":2}`, `{"a":1,"b":2}`},
		{"reversed", `{"b":2,"a":1}`, `{"a":1,"b":2}`},
		{"a prefix sorts first", `{"ab":1,"a":2}`, `{"a":2,"ab":1}`},
		{"empty name first", `{"a":1,"":2}`, `{"":2,"a":1}`},
		{"capitals before small letters", `{"a":1,"B":2,"A":3,"b":4}`, `{"A":3,"B":2,"a":1,"b":4}`},
		{"digits before letters", `{"a":1,"2":2,"10":3}`, `{"10":3,"2":2,"a":1}`},
		{"a character above the BMP against one just above U+D7FF", "{\"\ue000\":1,\"\U00010000\":2}", "{\"\U00010000\":2,\"\ue000\":1}"},
		{"nested objects sort too", `{"b":{"z":1,"y":{"d":1,"c":2}},"a":[{"q":1,"p":2}]}`, `{"a":[{"p":2,"q":1}],"b":{"y":{"c":2,"d":1},"z":1}}`},
		{"an array keeps its order", `{"a":[3,1,2,{"b":1,"a":2}]}`, `{"a":[3,1,2,{"a":2,"b":1}]}`},
		{"names written with an escape sort by what they are", `{"\u0062":1,"\u0061":2}`, `{"a":2,"b":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestStringsFromTheRFC is the string example of RFC 8785 section 3.2.2.2: the value is
// written as the RFC writes it, with \u000f in lower case and the euro sign raw.
func TestStringsFromTheRFC(t *testing.T) {
	in := `{"s":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"}`
	want := "{\"s\":\"" + string(rune(0x20ac)) + `$\u000f\nA'B\"\\\\\"/"}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestEscapesOfEveryControlCharacter(t *testing.T) {
	short := map[rune]string{'\b': `\b`, '\t': `\t`, '\n': `\n`, '\f': `\f`, '\r': `\r`}
	for c := rune(0); c < 0x20; c++ {
		want, ok := short[c]
		if !ok {
			want = fmt.Sprintf(`\u00%02x`, c) // lower case
		}
		t.Run(fmt.Sprintf("U+%04X", c), func(t *testing.T) {
			// A control character in a value and in a name, through Marshal.
			got, err := Marshal(map[string]string{"k" + string(c): "v" + string(c)})
			if err != nil {
				t.Fatal(err)
			}
			if w := `{"k` + want + `":"v` + want + `"}`; string(got) != w {
				t.Errorf("Marshal = %q, want %q", got, w)
			}
			// The same through Canonicalize, written in capitals and in lower case in the input.
			for _, in := range []string{
				fmt.Sprintf(`{"k":"\u%04x"}`, c),
				fmt.Sprintf(`{"k":"\u%04X"}`, c),
			} {
				got, err := Canonicalize([]byte(in))
				if err != nil {
					t.Fatalf("%s: %v", in, err)
				}
				if w := `{"k":"` + want + `"}`; string(got) != w {
					t.Errorf("Canonicalize(%s) = %q, want %q", in, got, w)
				}
			}
		})
	}
}

func TestCharactersWrittenAsTheyAre(t *testing.T) {
	// None of these is escaped: the delete character, the controls of the C1 block, the line
	// and paragraph separators, the characters that the standard encoder escapes for HTML, the
	// slash, and text outside ASCII.
	raw := []string{"<", ">", "&", "/", "'"}
	for _, r := range []rune{
		0x7f, 0x80, 0x9f, 0xa0, 0xe9, 0x2028, 0x2029, 0x20ac, 0xfb33, 0xfeff, 0xffff, 0x1f600, 0x10ffff,
	} {
		raw = append(raw, string(r))
	}
	for _, s := range raw {
		t.Run(fmt.Sprintf("%+q", s), func(t *testing.T) {
			want := `{"k":"` + s + `"}`
			got, err := Marshal(map[string]string{"k": s})
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("Marshal = %q, want %q", got, want)
			}
			// The same text written with an escape in the input.
			var esc strings.Builder
			for _, r := range s {
				if r > 0xffff {
					r1, r2 := surrogates(r)
					fmt.Fprintf(&esc, `\u%04x\u%04x`, r1, r2)
				} else {
					fmt.Fprintf(&esc, `\u%04x`, r)
				}
			}
			if s == "/" {
				esc.Reset()
				esc.WriteString(`\/`)
			}
			canon, err := Canonicalize([]byte(`{"k":"` + esc.String() + `"}`))
			if err != nil {
				t.Fatal(err)
			}
			if string(canon) != want {
				t.Errorf("Canonicalize of the escaped form = %q, want %q", canon, want)
			}
		})
	}
	// A quote and a backslash are escaped.
	got, err := Marshal(map[string]string{`"`: `\`})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"\"":"\\"}`; string(got) != want {
		t.Errorf("Marshal = %q, want %q", got, want)
	}
}

// surrogates is the UTF-16 pair of a character above U+FFFF, worked out here by the formula of
// RFC 2781 so that the test does not use the package it tests.
func surrogates(r rune) (rune, rune) {
	v := r - 0x10000
	return 0xD800 + (v >> 10), 0xDC00 + (v & 0x3ff)
}

func TestNumbers(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"a":0}`, `{"a":0}`},
		{`{"a":-0}`, `{"a":0}`},
		{`{"a":1}`, `{"a":1}`},
		{`{"a":-1}`, `{"a":-1}`},
		{`{"a":9223372036854775807}`, `{"a":9223372036854775807}`},
		{`{"a":-9223372036854775808}`, `{"a":-9223372036854775808}`},
		{`{"a":[0,-0,10,100]}`, `{"a":[0,0,10,100]}`},
	}
	for _, tc := range cases {
		got, err := Canonicalize([]byte(tc.in))
		if err != nil {
			t.Errorf("%s: %v", tc.in, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("Canonicalize(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestWhiteSpaceAndLiteralsAndNesting(t *testing.T) {
	in := "\n {\n\t\"b\" : [ true , false , { \"y\" : \"\" , \"x\" : [ ] , \"w\" : { } } ] ,\r\n \"a\" : \"x y\" \n}\n"
	want := `{"a":"x y","b":[true,false,{"w":{},"x":[],"y":""}]}`
	got, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	if got, err := Canonicalize([]byte(` { } `)); err != nil || string(got) != `{}` {
		t.Errorf("an empty object: %q, %v", got, err)
	}
}

type tagged struct {
	Zeta    int               `json:"zeta"`
	Alpha   string            `json:"alpha"`
	Omitted []int             `json:"omitted,omitempty"`
	Skipped float64           `json:"-"`
	Flag    bool              `json:"flag"`
	List    []inner           `json:"list"`
	Ptr     *inner            `json:"ptr"`
	Map     map[string]string `json:"map"`
	Plain   int
	hidden  int
	Embedded
}

type inner struct {
	Y int `json:"y"`
	X int `json:"x"`
}

// Embedded is flattened into tagged.
type Embedded struct {
	E int `json:"embedded"`
}

func TestMarshalStructWithTags(t *testing.T) {
	v := tagged{
		Zeta: 1, Alpha: "a<b>&", Skipped: 2.5, Flag: true,
		List:     []inner{{Y: 2, X: 1}, {}},
		Ptr:      &inner{Y: 4, X: 3},
		Map:      map[string]string{"k2": "v2", "k1": "v1"},
		Plain:    7,
		hidden:   8,
		Embedded: Embedded{E: 9},
	}
	got, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"Plain":7,"alpha":"a<b>&","embedded":9,"flag":true,"list":[{"x":1,"y":2},{"x":0,"y":0}],` +
		`"map":{"k1":"v1","k2":"v2"},"ptr":{"x":3,"y":4},"zeta":1}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	// A pointer to the struct is the same value.
	again, err := Marshal(&v)
	if err != nil || !bytes.Equal(again, got) {
		t.Errorf("Marshal of a pointer = %s, %v", again, err)
	}
}

func TestMarshalMapOfAny(t *testing.T) {
	v := map[string]any{
		"b": []any{int64(1), "x", true, map[string]any{"z": uint8(2), "a": int8(-3)}},
		"a": map[string]any{"n": 0},
		"c": json.Number("12"),
		"d": []string{"p", "q"},
	}
	got, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"n":0},"b":[1,"x",true,{"a":-3,"z":2}],"c":12,"d":["p","q"]}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestMarshalIntegerKinds(t *testing.T) {
	v := map[string]any{
		"i":   int(-5),
		"i8":  int8(math.MinInt8),
		"i16": int16(math.MaxInt16),
		"i32": int32(math.MinInt32),
		"i64": int64(math.MinInt64),
		"u8":  uint8(math.MaxUint8),
		"u32": uint32(math.MaxUint32),
		"max": int64(math.MaxInt64),
		"u64": uint64(math.MaxInt64),
	}
	got, err := Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"i":-5,"i16":32767,"i32":-2147483648,"i64":-9223372036854775808,"i8":-128,` +
		`"max":9223372036854775807,"u32":4294967295,"u64":9223372036854775807,"u8":255}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestMarshalNoTrailingNewline(t *testing.T) {
	got, err := Marshal(map[string]int{"a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasSuffix(got, []byte("\n")) || bytes.ContainsAny(got, " \t\r\n") {
		t.Errorf("Marshal wrote white space: %q", got)
	}
}

// customJSON writes its own JSON, with white space and members out of order.
type customJSON struct{}

func (customJSON) MarshalJSON() ([]byte, error) { return []byte(`{ "b" : 1 , "a" : "\u00e9" }`), nil }

type customFloat struct{}

func (customFloat) MarshalJSON() ([]byte, error) { return []byte(`{"a":1.5}`), nil }

func TestMarshalOfATypeThatWritesItsOwnJSON(t *testing.T) {
	got, err := Marshal(customJSON{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"a\":\"é\",\"b\":1}"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	got, err = Marshal(map[string]any{"x": customJSON{}})
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"x\":{\"a\":\"é\",\"b\":1}}"; string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	// What such a type writes is checked after it is written.
	if _, err := Marshal(customFloat{}); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("a type that writes a float: %v, want ErrMalformed", err)
	}
}

type withFloat struct {
	F float64 `json:"f"`
}

type withFloatPtr struct {
	F *float64 `json:"f"`
}

type withAny struct {
	V any `json:"v"`
}

type withHiddenFloat struct {
	N      int     `json:"n"`
	F      float64 `json:"-"`
	hidden float64
}

func TestMarshalRefusesAFloat(t *testing.T) {
	three := 3.0
	cases := []struct {
		name string
		v    any
	}{
		{"float64 in a struct", withFloat{F: 1.5}},
		{"float64 with an integer value", withFloat{F: 3}},
		{"float64 zero", withFloat{}},
		{"a pointer to a float", withFloatPtr{F: &three}},
		{"a float in an interface", withAny{V: float64(3)}},
		{"a float32", map[string]float32{"a": 2}},
		{"a float in a map", map[string]any{"a": float64(3)}},
		{"a float in a map of floats", map[string]float64{"a": 3}},
		{"a float in a slice", map[string]any{"a": []any{1, 2.0}}},
		{"a float in a nested struct", map[string]any{"a": []any{map[string]any{"b": withFloat{F: 3}}}}},
		{"a float in an array", map[string]any{"a": [2]float64{1, 2}}},
		{"a float behind two pointers", map[string]any{"a": &three}},
		{"a float with a fraction", map[string]any{"a": 0.1}},
		{"NaN", map[string]any{"a": math.NaN()}},
		{"infinity", map[string]any{"a": math.Inf(1)}},
		{"a number text with a fraction", map[string]any{"a": json.Number("1.5")}},
		{"a number text with an exponent", map[string]any{"a": json.Number("1e3")}},
		{"an integer above int64", map[string]any{"a": uint64(math.MaxUint64)}},
		{"a number text above int64", map[string]any{"a": json.Number("9223372036854775808")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			if err == nil {
				t.Fatalf("Marshal wrote %s", got)
			}
			if got != nil {
				t.Errorf("Marshal returned %q next to an error", got)
			}
		})
	}
	t.Run("float64(3) as the value itself is refused as a float, not as a top level", func(t *testing.T) {
		_, err := Marshal(float64(3))
		if err == nil {
			t.Fatal("Marshal accepted a float")
		}
		if !strings.Contains(err.Error(), "float") {
			t.Errorf("the error does not say float: %v", err)
		}
	})
	t.Run("the error of a float says float", func(t *testing.T) {
		_, err := Marshal(withFloat{F: 3})
		if err == nil || !strings.Contains(err.Error(), "float") || !errors.Is(err, strictjson.ErrMalformed) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a float that is not written is not looked at", func(t *testing.T) {
		got, err := Marshal(withHiddenFloat{N: 1, F: 2.5, hidden: 3.5})
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"n":1}`; string(got) != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
}

type nilSlice struct {
	S []int `json:"s"`
}
type nilPtr struct {
	P *int `json:"p"`
}
type omitNil struct {
	S []int          `json:"s,omitempty"`
	P *int           `json:"p,omitempty"`
	M map[string]int `json:"m,omitempty"`
	N int            `json:"n"`
}

func TestMarshalRefusesNull(t *testing.T) {
	var nilMap map[string]any
	cases := []struct {
		name string
		v    any
	}{
		{"nil", nil},
		{"a nil pointer to a struct", (*withFloat)(nil)},
		{"a nil map", nilMap},
		{"a nil pointer in a struct", nilPtr{}},
		{"a nil slice in a struct", nilSlice{}},
		{"a nil map in a struct", struct {
			M map[string]int `json:"m"`
		}{}},
		{"a nil in a map of any", map[string]any{"a": nil}},
		{"a nil in a slice", map[string]any{"a": []any{1, nil}}},
		{"a nil slice in a map of any", map[string]any{"a": []int(nil)}},
		{"a nil pointer in a map", map[string]*int{"a": nil}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			if err == nil {
				t.Fatalf("Marshal wrote %s", got)
			}
		})
	}
	t.Run("a nil that omitempty leaves out is fine", func(t *testing.T) {
		got, err := Marshal(omitNil{N: 1})
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"n":1}`; string(got) != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
	t.Run("an empty slice and map are not null", func(t *testing.T) {
		got, err := Marshal(map[string]any{"a": []int{}, "b": map[string]int{}})
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"a":[],"b":{}}`; string(got) != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
}

func TestMarshalNeedsAnObjectAtTheTop(t *testing.T) {
	cases := []struct {
		name string
		v    any
	}{
		{"a slice", []int{1}},
		{"an empty slice", []int{}},
		{"a slice of objects", []map[string]int{{"a": 1}}},
		{"an array", [1]int{1}},
		{"a string", "x"},
		{"an integer", 3},
		{"a bool", true},
		{"a json.Number", json.Number("1")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			if err == nil {
				t.Fatalf("Marshal wrote %s", got)
			}
			if !errors.Is(err, strictjson.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestMarshalRefusesWhatJSONCannotWrite(t *testing.T) {
	type loop struct{ Next *loop }
	l := &loop{}
	l.Next = l
	m := map[string]any{}
	m["self"] = m
	for name, v := range map[string]any{
		"a channel":                       map[string]any{"c": make(chan int)},
		"a function":                      map[string]any{"f": func() {}},
		"a pointer that points to itself": l,
		"a map that holds itself":         m,
	} {
		got, err := Marshal(v)
		if err == nil {
			t.Errorf("%s: Marshal wrote %s", name, got)
		}
	}
}

func TestMarshalSizeLimit(t *testing.T) {
	const frame = len(`{"a":""}`)
	exact, err := Marshal(map[string]string{"a": strings.Repeat("x", strictjson.DefaultMaxBytes-frame)})
	if err != nil {
		t.Fatalf("exactly 262144 bytes: %v", err)
	}
	if len(exact) != strictjson.DefaultMaxBytes {
		t.Fatalf("the output has %d bytes", len(exact))
	}
	got, err := Marshal(map[string]string{"a": strings.Repeat("x", strictjson.DefaultMaxBytes-frame+1)})
	if !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("one byte over: %v, want ErrMalformed (wrote %d bytes)", err, len(got))
	}
	// Many small members that add up to more than the limit.
	big := map[string]int{}
	for i := range 40000 {
		big[fmt.Sprintf("m%06d", i)] = i
	}
	if _, err := Marshal(big); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("many members: %v, want ErrMalformed", err)
	}
}

func TestCanonicalizeSizeLimit(t *testing.T) {
	const frame = len(`{"a":""}`)
	ok := []byte(`{"a":"` + strings.Repeat("x", strictjson.DefaultMaxBytes-frame) + `"}`)
	if got, err := Canonicalize(ok); err != nil || !bytes.Equal(got, ok) {
		t.Errorf("262144 bytes: err %v", err)
	}
	if is, err := IsCanonical(ok); err != nil || !is {
		t.Errorf("IsCanonical on 262144 bytes = %v, %v", is, err)
	}
	over := append(slices.Clone(ok[:len(ok)-2]), 'x', '"', '}')
	if _, err := Canonicalize(over); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("262145 bytes: %v, want ErrMalformed", err)
	}
	if is, err := IsCanonical(over); is || !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("IsCanonical on 262145 bytes = %v, %v", is, err)
	}
}

func TestCanonicalizeNestingDepth(t *testing.T) {
	deep := func(n int) []byte {
		return []byte(strings.Repeat(`{"a":`, n-1) + `{}` + strings.Repeat(`}`, n-1))
	}
	at := deep(10000)
	got, err := Canonicalize(at)
	if err != nil || !bytes.Equal(got, at) {
		t.Errorf("10000 levels: err %v", err)
	}
	if _, err := Canonicalize(deep(10001)); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("10001 levels: %v, want ErrMalformed", err)
	}
	if _, err := Canonicalize([]byte(strings.Repeat(`{"a":[`, 20000))); !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("a very deep input: %v, want ErrMalformed", err)
	}
}

// brokenRules are inputs that strictjson refuses, here as seen by Canonicalize and IsCanonical.
var brokenRules = []struct{ name, in string }{
	{"empty input", ``},
	{"an array at top level", `[]`},
	{"a string at top level", `"x"`},
	{"a number at top level", `1`},
	{"null at top level", `null`},
	{"a byte order mark", "\xef\xbb\xbf{}"},
	{"invalid UTF-8", "{\"a\":\"\xff\"}"},
	{"a float", `{"a":1.0}`},
	{"an exponent", `{"a":1e2}`},
	{"an integer above int64", `{"a":9223372036854775808}`},
	{"null", `{"a":null}`},
	{"a lone surrogate", `{"a":"\ud800"}`},
	{"a repeated member", `{"a":1,"a":2}`},
	{"a repeated member written with an escape", `{"a":1,"\u0061":2}`},
	{"a repeated member deep down", `{"x":[{"y":{"a":1,"a":1}}]}`},
	{"text after the object", `{} x`},
	{"a second object", `{}{}`},
	{"a truncated object", `{"a":`},
	{"a trailing comma", `{"a":1,}`},
}

func TestCanonicalizeRefusesWhatStrictjsonRefuses(t *testing.T) {
	for _, tc := range brokenRules {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tc.in))
			if err == nil {
				t.Fatalf("Canonicalize wrote %q", got)
			}
			if !errors.Is(err, strictjson.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
			if got != nil {
				t.Errorf("Canonicalize returned %q next to an error", got)
			}
		})
	}
}

func TestIsCanonicalReturnsAnErrorForInputThatBreaksTheRules(t *testing.T) {
	for _, tc := range brokenRules {
		t.Run(tc.name, func(t *testing.T) {
			is, err := IsCanonical([]byte(tc.in))
			if is {
				t.Error("IsCanonical = true")
			}
			if !errors.Is(err, strictjson.ErrMalformed) {
				t.Errorf("err = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestIsCanonical(t *testing.T) {
	yes := []string{
		`{}`,
		`{"a":1}`,
		`{"a":1,"b":[1,2,{"c":"d"}]}`,
		`{"a":"é€😀"}`,
		`{"a":"\u0001\u001f\b\t\n\f\r\"\\"}`,
		"{\"a\":\"\x7f\u2028\"}",
		`{"-":-1,"0":0}`,
		rfcWant,
	}
	for _, in := range yes {
		is, err := IsCanonical([]byte(in))
		if err != nil || !is {
			t.Errorf("IsCanonical(%q) = %v, %v; want true", in, is, err)
		}
	}
	no := []struct{ name, in string }{
		{"a trailing newline", "{\"a\":1}\n"},
		{"a leading space", ` {"a":1}`},
		{"a trailing space", `{"a":1} `},
		{"a space after the colon", `{"a": 1}`},
		{"a space after the comma", `{"a":1, "b":2}`},
		{"pretty-printed", "{\n  \"a\": 1,\n  \"b\": [\n    1\n  ]\n}\n"},
		{"members out of order", `{"b":1,"a":2}`},
		{"members in UTF-8 order", "{\"\ufb33\":1,\"\U0001F600\":2}"},
		{"an escape that need not be one", `{"a":"\u00e9"}`},
		{"an escaped slash", `{"a":"\/"}`},
		{"an escaped letter", `{"a":"\u0041"}`},
		{"a control escape in capitals", `{"a":"\u001F"}`},
		{"a control written long", `{"a":"\u0009"}`},
		{"a surrogate pair written as an escape", `{"a":"\ud83d\ude00"}`},
		{"minus zero", `{"a":-0}`},
		{"a name written as an escape", `{"\u0061":1}`},
	}
	for _, tc := range no {
		t.Run(tc.name, func(t *testing.T) {
			is, err := IsCanonical([]byte(tc.in))
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if is {
				t.Errorf("IsCanonical(%q) = true", tc.in)
			}
			// And the canonical form of it is canonical.
			canon, err := Canonicalize([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if is, err := IsCanonical(canon); err != nil || !is {
				t.Errorf("the canonical form %q is not canonical: %v, %v", canon, is, err)
			}
			if bytes.Equal(canon, []byte(tc.in)) {
				t.Errorf("Canonicalize changed nothing in %q", tc.in)
			}
		})
	}
}

func TestMarshalIsCanonical(t *testing.T) {
	values := []any{
		map[string]any{},
		map[string]string{"\u20ac": "a", "\r": "b", "\ufb33": "c", "1": "d", "\U0001F600": "e", "\u0080": "f", "\u00f6": "g"},
		tagged{Zeta: 1, Alpha: "<&>" + string([]rune{0x2028, 0x2029}), Embedded: Embedded{E: 2}, Map: map[string]string{"é": "\x01\x1f"}, List: []inner{}, Ptr: &inner{}},
		map[string]any{"a": []any{1, "two", map[string]any{"z": 1, "a": json.Number("-0")}}},
		customJSON{},
	}
	for i, v := range values {
		got, err := Marshal(v)
		if err != nil {
			t.Errorf("value %d: %v", i, err)
			continue
		}
		is, err := IsCanonical(got)
		if err != nil || !is {
			t.Errorf("value %d: IsCanonical(Marshal(x)) = %v, %v for %q", i, is, err, got)
		}
		again, err := Canonicalize(got)
		if err != nil || !bytes.Equal(again, got) {
			t.Errorf("value %d: Canonicalize is not idempotent: %q, %v", i, again, err)
		}
	}
}

// reference orders two names as RFC 8785 asks, by UTF-16 code units, written here with its own
// loop so that the test does not use the code it checks.
func reference(a, b string) int {
	ua, ub := units(a), units(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	}
	return 0
}

func units(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r >= 0x10000 {
			r1, r2 := surrogates(r)
			out = append(out, uint16(r1), uint16(r2))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// randomName makes a name from characters of every width and of both sides of the surrogate
// range, so that UTF-8 order and UTF-16 order disagree often.
func randomName(r *rand.Rand) string {
	pool := []rune{'a', 'b', 'A', '0', '\r', 0, 0x1f, '~', 0x7f, 0x80, 0xe9, 0x7ff, 0x800,
		0xd7ff, 0xe000, 0xf000, 0xfb33, 0xffff, 0x10000, 0x1f600, 0x10ffff, '"', '\\', '/'}
	var b strings.Builder
	for range r.Intn(4) {
		b.WriteRune(pool[r.Intn(len(pool))])
	}
	return b.String()
}

func randomObject(r *rand.Rand, depth int) map[string]any {
	out := map[string]any{}
	for range r.Intn(6) {
		name := randomName(r)
		switch k := r.Intn(6); {
		case k == 0 && depth < 4:
			out[name] = randomObject(r, depth+1)
		case k == 1 && depth < 4:
			out[name] = []any{randomObject(r, depth+1), int64(r.Intn(100) - 50), randomName(r)}
		case k == 2:
			out[name] = randomName(r)
		case k == 3:
			out[name] = r.Intn(2) == 0
		default:
			out[name] = int64(r.Intn(2000) - 1000)
		}
	}
	return out
}

// memberNames reads the top-level member names of canonical data in the order they are written.
func memberNames(t *testing.T, data []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("not an object: %v %v", tok, err)
	}
	var names []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tok.(string))
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			t.Fatal(err)
		}
	}
	return names
}

func TestRandomObjects(t *testing.T) {
	r := rand.New(rand.NewSource(8785))
	for i := range 300 {
		v := randomObject(r, 0)
		got, err := Marshal(v)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		// The members are in the order of the reference comparison, strictly.
		names := memberNames(t, got)
		for j := 1; j < len(names); j++ {
			if reference(names[j-1], names[j]) >= 0 {
				t.Fatalf("case %d: %+q is not before %+q in %q", i, names[j-1], names[j], got)
			}
		}
		// The data is the same value after the round trip.
		var back map[string]any
		dec := json.NewDecoder(bytes.NewReader(got))
		dec.UseNumber()
		if err := dec.Decode(&back); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		want, _ := json.Marshal(v)
		var wantBack map[string]any
		dec = json.NewDecoder(bytes.NewReader(want))
		dec.UseNumber()
		if err := dec.Decode(&wantBack); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, wantBack) {
			t.Fatalf("case %d: the canonical form means something else:\n%q\n%q", i, got, want)
		}
		if is, err := IsCanonical(got); err != nil || !is {
			t.Fatalf("case %d: not canonical: %v %v: %q", i, is, err, got)
		}
		// The standard encoder's own output, in any layout, reaches the same bytes.
		indented, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fromIndented, err := Canonicalize(indented)
		if err != nil || !bytes.Equal(fromIndented, got) {
			t.Fatalf("case %d: Canonicalize(indented) differs: %v\n%q\n%q", i, err, fromIndented, got)
		}
	}
}

// listFiles returns the files under a folder of the repository whose names end in one of the
// suffixes, and fails when there are none: a check that finds nothing to check fails.
func listFiles(t testing.TB, folder string, suffixes ...string) []string {
	t.Helper()
	root := testrepo.Path(t, folder)
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		for _, s := range suffixes {
			if strings.HasSuffix(path, s) {
				files = append(files, path)
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", folder, err)
	}
	if len(files) == 0 {
		t.Fatalf("no %v file under %s: nothing to check", suffixes, folder)
	}
	return files
}

func TestRepositoryFilesAreCanonical(t *testing.T) {
	sets := []struct {
		folder   string
		suffixes []string
	}{
		{"testdata/root-list/v1/lists", []string{".json"}},
		{"testdata/root-list/v1/lists", []string{".jws"}},
		{"testdata/ssh-ca-keys/v1/lists", []string{".json"}},
	}
	for _, set := range sets {
		files := listFiles(t, set.folder, set.suffixes...)
		t.Run(set.folder+" "+strings.Join(set.suffixes, ","), func(t *testing.T) {
			for _, path := range files {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				rel, _ := filepath.Rel(testrepo.Root(t), path)
				is, err := IsCanonical(data)
				if err != nil {
					t.Errorf("%s: %v", rel, err)
					continue
				}
				if !is {
					canon, _ := Canonicalize(data)
					t.Errorf("%s is not in canonical form (canonical form is %d bytes, the file %d)", rel, len(canon), len(data))
				}
			}
		})
	}
}

func TestListFilesFailsWhenThereIsNothingToCheck(t *testing.T) {
	// The helper above must not pass on an empty folder.
	f := &emptyTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		listFiles(f, "testdata/root-list/v1/lists", ".nosuchsuffix")
	}()
	<-done
	if !f.failed {
		t.Error("listFiles did not fail for a suffix that no file has")
	}
}

// emptyTB turns a failure of the test it wraps into a flag, so that a helper that must fail can be tested.
type emptyTB struct {
	testing.TB
	failed bool
}

func (e *emptyTB) Fatalf(string, ...any) {
	e.failed = true
	runtime.Goexit()
}
