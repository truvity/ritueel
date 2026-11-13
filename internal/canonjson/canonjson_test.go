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
	wantText := malformedText("nesting deeper than %d levels at byte ", strictjson.MaxDepth)
	at := deep(strictjson.MaxDepth)
	got, err := Canonicalize(at)
	if err != nil || !bytes.Equal(got, at) {
		t.Errorf("%d levels: err %v", strictjson.MaxDepth, err)
	}
	if is, err := IsCanonical(at); err != nil || !is {
		t.Errorf("IsCanonical at %d levels = %v, %v", strictjson.MaxDepth, is, err)
	}
	for name, in := range map[string][]byte{
		"one level over":  deep(strictjson.MaxDepth + 1),
		"a very deep one": []byte(strings.Repeat(`{"a":[`, 2*strictjson.MaxDepth)),
	} {
		got, err := Canonicalize(in)
		if !errors.Is(err, strictjson.ErrMalformed) || !strings.HasPrefix(err.Error(), wantText) || got != nil {
			t.Errorf("%s: %q, %v, want %q and a byte", name, got, err, wantText)
		}
		if is, err := IsCanonical(in); is || !errors.Is(err, strictjson.ErrMalformed) {
			t.Errorf("%s: IsCanonical = %v, %v", name, is, err)
		}
	}
}

// brokenRules are inputs that strictjson refuses, here as seen by Canonicalize and IsCanonical.
var brokenRules = []struct{ name, in string }{
	{"empty input", ``},
	{"an array at top level", `[]`},
	{"a string at top level", `"x"`},
	{"a number at top level", `1`},
	{"null at top level", `null`},
	{"an array that is closed as an object", `[}`},
	{"a string that is closed as an object", `"}`},
	{"a number that is closed as an object", `1}`},
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

// The tests below pin what Marshal measures and what it refuses: the size of the canonical bytes,
// text that is not UTF-8, and nesting. A JSON escape of the form backslash, u and four digits is
// never written out in them: where a test needs one it is built from a backslash (bs, uesc), so
// that no tool can turn it into the character on the way.

// malformedText is the error text of a refusal, as strictjson.ErrMalformed starts it.
func malformedText(format string, args ...any) string {
	return strictjson.ErrMalformed.Error() + ": " + fmt.Sprintf(format, args...)
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
// and nothing is returned.
func refused(t *testing.T, got []byte, err error, wantText string) {
	t.Helper()
	if err == nil {
		t.Fatalf("Marshal wrote %.100s (%d bytes)", got, len(got))
	}
	if !errors.Is(err, strictjson.ErrMalformed) {
		t.Errorf("the error does not wrap ErrMalformed: %v", err)
	}
	if err.Error() != wantText {
		t.Errorf("the error is %q, want %q", err, wantText)
	}
	if got != nil {
		t.Errorf("Marshal returned %d bytes next to an error, want nil", len(got))
	}
}

// ownJSON is a type that writes the JSON it holds, whatever it is.
type ownJSON string

func (o ownJSON) MarshalJSON() ([]byte, error) { return []byte(o), nil }

func TestMaxIntermediateIsSixTimesTheLimit(t *testing.T) {
	if maxIntermediate != 6*strictjson.DefaultMaxBytes {
		t.Errorf("maxIntermediate = %d, want six times %d", maxIntermediate, strictjson.DefaultMaxBytes)
	}
	if maxIntermediate != 1572864 {
		t.Errorf("maxIntermediate = %d, want 1572864", maxIntermediate)
	}
}

func TestMarshalMeasuresTheLimitOnTheCanonicalBytes(t *testing.T) {
	const tooLong = "malformed JSON: the canonical form is longer than 262144 bytes"
	const frame = len(`{"a":""}`)
	ls, ps := string(rune(0x2028)), string(rune(0x2029))
	cases := []struct {
		name string
		unit string // what the value repeats
		n    int
		// ok is true when the canonical form fits; its length is then n * len(unit) + frame.
		ok bool
		// text is the refusal when it does not: the canonical form is over the limit, unless what
		// the encoder wrote on the way is over its own bound.
		text string
	}{
		// Characters that the standard encoder spells as six bytes (< > & with HTML escaping on,
		// U+2028 and U+2029 always): the canonical form writes them as they are.
		{"100000 less-than signs", "<", 100000, true, ""},
		{"100000 greater-than signs", ">", 100000, true, ""},
		{"100000 ampersands", "&", 100000, true, ""},
		{"100000 of less-than sign and ampersand", "<&", 100000, true, ""},
		{"80000 line separators", ls, 80000, true, ""},
		{"80000 paragraph separators", ps, 80000, true, ""},
		{"line and paragraph separators together", ls + ps, 40000, true, ""},
		{"markup of every kind", `<a href='x'>&amp;</a>`, 10000, true, ""},
		// The limit itself and the byte after it, with a one-byte character and a six-byte spelling.
		{"less-than signs up to the limit", "<", strictjson.DefaultMaxBytes - frame, true, ""},
		{"less-than signs one over", "<", strictjson.DefaultMaxBytes - frame + 1, false, tooLong},
		{"ampersands up to the limit", "&", strictjson.DefaultMaxBytes - frame, true, ""},
		{"line separators up to the limit", ls, (strictjson.DefaultMaxBytes - frame) / 3, true, ""},
		{"line separators one over", ls, (strictjson.DefaultMaxBytes-frame)/3 + 1, false, tooLong},
		// Over the limit in canonical bytes, and far over in what the encoder writes.
		{"90000 line separators", ls, 90000, false, tooLong},
		{"90000 paragraph separators", ps, 90000, false, tooLong},
		{"300000 less-than signs", "<", 300000, false, tooLong},
		{"1000000 line separators", ls, 1000000, false, malformedText("longer than %d bytes", maxIntermediate)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The same text in a value, and in a member name.
			value := strings.Repeat(tc.unit, tc.n)
			got, err := Marshal(map[string]string{"a": value})
			if !tc.ok {
				refused(t, got, err, tc.text)
			} else {
				if err != nil {
					t.Fatalf("Marshal refused %d bytes of canonical form: %v", tc.n*len(tc.unit)+frame, err)
				}
				if len(got) != tc.n*len(tc.unit)+frame {
					t.Errorf("Marshal wrote %d bytes, want %d", len(got), tc.n*len(tc.unit)+frame)
				}
				sameBytes(t, "a value", got, `{"a":"`+value+`"}`)
			}
			got, err = Marshal(map[string]int{value: 1})
			nameFrame := len(`{"":1}`)
			if tc.n*len(tc.unit)+nameFrame > strictjson.DefaultMaxBytes {
				refused(t, got, err, tc.text)
			} else {
				if err != nil {
					t.Fatalf("Marshal refused a name of %d bytes: %v", tc.n*len(tc.unit), err)
				}
				sameBytes(t, "a name", got, `{"`+value+`":1}`)
			}
		})
	}
}

func TestMarshalOfARefusedSizeReturnsNothing(t *testing.T) {
	// Many small members that add up to more than the limit, in a map and in a slice.
	big := map[string]int{}
	for i := range 40000 {
		big[fmt.Sprintf("m%06d", i)] = i
	}
	got, err := Marshal(big)
	refused(t, got, err, "malformed JSON: the canonical form is longer than 262144 bytes")
	got, err = Marshal(map[string][]int{"a": make([]int, 140000)})
	refused(t, got, err, "malformed JSON: the canonical form is longer than 262144 bytes")
}

func TestMarshalBoundsWhatTheEncoderWritesOnTheWay(t *testing.T) {
	// A type that writes its own JSON may spell any character as a six-byte escape. A canonical
	// form that fits the limit comes from at most six times its size, and a longer intermediate
	// cannot fit: it is refused at once, with the text of strictjson's size rule.
	const tooLong = "malformed JSON: the canonical form is longer than 262144 bytes"
	const frame = len(`{"a":""}`)
	atLimit := strictjson.DefaultMaxBytes - frame // letters that make the canonical form 262144 bytes
	spelt := func(n int) ownJSON { return ownJSON(`{"a":"` + strings.Repeat(uesc('A'), n) + `"}`) }
	t.Run("spelt as escapes, the canonical form at the limit", func(t *testing.T) {
		v := spelt(atLimit)
		if len(v) != 6*atLimit+frame || len(v) > maxIntermediate {
			t.Fatalf("the test value has %d bytes", len(v))
		}
		got, err := Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != strictjson.DefaultMaxBytes {
			t.Errorf("Marshal wrote %d bytes, want %d", len(got), strictjson.DefaultMaxBytes)
		}
		sameBytes(t, "the letters", got, `{"a":"`+strings.Repeat("A", atLimit)+`"}`)
		// The same as an escape that the encoder would have written for a character it spells long.
		got, err = Marshal(map[string]ownJSON{"k": ownJSON(`"` + strings.Repeat(uesc('<'), 100000) + `"`)})
		if err != nil {
			t.Fatal(err)
		}
		sameBytes(t, "less-than signs", got, `{"k":"`+strings.Repeat("<", 100000)+`"}`)
	})
	t.Run("spelt as escapes, the canonical form over the limit but the intermediate within its bound", func(t *testing.T) {
		for _, n := range []int{atLimit + 1, atLimit + 2, atLimit + 5} {
			v := spelt(n)
			if len(v) > maxIntermediate {
				t.Fatalf("the test value of %d letters has %d bytes, over the bound", n, len(v))
			}
			got, err := Marshal(v)
			refused(t, got, err, tooLong)
		}
	})
	t.Run("the intermediate over its bound", func(t *testing.T) {
		wantText := malformedText("longer than %d bytes", maxIntermediate)
		for _, n := range []int{maxIntermediate/6 - 1, maxIntermediate / 6, 2 * atLimit, 10 * atLimit} {
			v := spelt(n)
			if len(v) <= maxIntermediate {
				continue // not over the bound: the case above
			}
			got, err := Marshal(v)
			refused(t, got, err, wantText)
		}
		// The first length that is over the bound, so that the bound is not a byte too large.
		first := (maxIntermediate-frame)/6 + 1
		if len(spelt(first)) <= maxIntermediate || len(spelt(first-1)) > maxIntermediate {
			t.Fatalf("%d letters is not the first length over the bound", first)
		}
		got, err := Marshal(spelt(first))
		refused(t, got, err, wantText)
		got, err = Marshal(spelt(first - 1))
		refused(t, got, err, tooLong)
	})
	t.Run("plain bytes, one over the limit", func(t *testing.T) {
		got, err := Marshal(ownJSON(`{"a":"` + strings.Repeat("A", atLimit) + `"}`))
		if err != nil || len(got) != strictjson.DefaultMaxBytes {
			t.Fatalf("at the limit: %d bytes, %v", len(got), err)
		}
		got, err = Marshal(ownJSON(`{"a":"` + strings.Repeat("A", atLimit+1) + `"}`))
		refused(t, got, err, tooLong)
	})
}

// The values below hold text that is not valid UTF-8, and the text that the walk must give for
// each kind of place it can stand in.
type (
	namedString string
	namedKey    string
	inEmbedded  struct{ S string }
	embedsValue struct {
		inEmbedded
		N int
	}
	embedsPointer struct {
		*inEmbedded
		N int
	}
	embedsExported struct {
		Exported
		N int
	}
	// Exported is an embedded struct whose type name is exported.
	Exported struct{ S string }
	// field holds one value of each kind of place.
	field struct {
		S  string
		P  *string
		PP **string
		L  []string
		A  [2]string
		M  map[string]string
		I  any
		N  namedString
		St struct{ S string }
	}
	hasTagged struct {
		S string `json:"renamed"`
	}
	hasOmitted struct {
		S string `json:"s,omitempty"`
	}
	hasHidden struct {
		N      int
		Hidden string `json:"-"`
		hidden string
	}
	hasHiddenEmbedded struct {
		hiddenEmbed
	}
	hiddenEmbed struct{ S string }
)

func TestMarshalRefusesStringsThatAreNotUTF8(t *testing.T) {
	const str = "malformed JSON: a string that is not valid UTF-8 cannot be written"
	const name = "malformed JSON: a member name that is not valid UTF-8 cannot be written"
	bad := "a\xffb"
	pbad := &bad
	// Every way the bytes can be wrong, as a value of a map of strings.
	for what, text := range map[string]string{
		"a lone 0xff":                           "\xff",
		"a lone continuation byte":              "\x80",
		"a leading byte cut short":              "\xe2\x82",
		"an overlong slash":                     "\xc0\xaf",
		"a UTF-8 encoded surrogate":             "\xed\xa0\x80",
		"a code point above U+10FFFF":           "\xf4\x90\x80\x80",
		"the bad byte first":                    "\xffabc",
		"the bad byte last":                     "abc\xff",
		"the bad byte after multi-byte text":    "\u00e9\u20ac\xff",
		"the bad byte before multi-byte text":   "\xff\u00e9\u20ac",
		"one bad byte among a very long string": strings.Repeat("x", 100000) + "\xff" + strings.Repeat("y", 100000),
	} {
		t.Run("a value that is "+what, func(t *testing.T) {
			got, err := Marshal(map[string]string{"k": text})
			refused(t, got, err, str)
		})
		t.Run("a name that is "+what, func(t *testing.T) {
			got, err := Marshal(map[string]int{text: 1})
			refused(t, got, err, name)
		})
	}
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"a struct field", struct{ S string }{bad}, str},
		{"a struct field with another name", hasTagged{bad}, str},
		{"a struct field that omitempty keeps", hasOmitted{bad}, str},
		{"a struct field of a named string type", struct{ N namedString }{namedString(bad)}, str},
		{"a struct value at the top", field{S: bad}, str},
		{"a pointer to a struct at the top", &struct{ S string }{bad}, str},
		{"a pointer to a string in a field", struct{ P *string }{pbad}, str},
		{"a pointer to a pointer to a string", struct{ PP **string }{&pbad}, str},
		{"a pointer in a map", map[string]*string{"k": pbad}, str},
		{"a slice of strings", struct{ L []string }{[]string{"a", "b", bad}}, str},
		{"the first of a slice", struct{ L []string }{[]string{bad, "b", "c"}}, str},
		{"an array of strings", struct{ A [2]string }{[2]string{"a", bad}}, str},
		{"an interface in a field", struct{ I any }{bad}, str},
		{"an interface holding a slice", struct{ I any }{[]string{bad}}, str},
		{"an interface in a map", map[string]any{"k": bad}, str},
		{"a slice of interfaces", map[string]any{"k": []any{1, "x", bad}}, str},
		{"a map in a field", struct{ M map[string]string }{map[string]string{"k": bad}}, str},
		{"a nested struct", struct{ St struct{ S string } }{struct{ S string }{bad}}, str},
		{"a slice of structs", map[string][]inEmbedded{"k": {{"fine"}, {bad}}}, str},
		{"a slice of pointers to structs", map[string][]*inEmbedded{"k": {{"fine"}, {bad}}}, str},
		{"a map of slices of maps", map[string][]map[string]string{"k": {{"a": "fine"}, {"b": bad}}}, str},
		{"deep down in any", map[string]any{"a": []any{map[string]any{"b": &field{L: []string{bad}}}}}, str},
		{"an embedded struct", embedsValue{inEmbedded{bad}, 1}, str},
		{"an embedded pointer to a struct", embedsPointer{&inEmbedded{bad}, 1}, str},
		{"an embedded struct with an exported type name", embedsExported{Exported{bad}, 1}, str},
		{"an embedded struct that is not exported", hasHiddenEmbedded{hiddenEmbed{bad}}, str},
		{"a name from a map of strings", map[string]int{bad: 1}, name},
		{"a name from a map of a named string type", map[namedKey]int{namedKey(bad): 1}, name},
		{"a name among valid ones", map[string]int{"a": 1, bad: 2, "c": 3}, name},
		{"a name in a nested map", map[string]any{"a": map[string]int{bad: 1}}, name},
		{"a name in a field", struct{ M map[string]int }{map[string]int{bad: 1}}, name},
		{"a name in a map in a slice", map[string]any{"a": []map[string]int{{bad: 1}}}, name},
		{"a valid value with a bad name", map[string]string{bad: "fine"}, name},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			refused(t, got, err, tc.want)
		})
	}
	t.Run("text that is not written is not looked at", func(t *testing.T) {
		// A field tagged "-", one that is not exported, and a nil pointer that omitempty leaves out.
		got, err := Marshal(hasHidden{N: 1, Hidden: bad, hidden: bad})
		if err != nil {
			t.Fatalf("Marshal refused text that it does not write: %v", err)
		}
		if want := `{"N":1}`; string(got) != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
}

func TestMarshalWritesValidTextAsItIs(t *testing.T) {
	// The twins of the refusals above: text that is valid, in the same places. U+FFFD itself is
	// valid text and stays; text that a type has not changed is not changed here either.
	repl := string(rune(0xFFFD))
	for _, text := range []string{
		"", "plain", "\u00e9", "\u20ac", string(rune(0x1F600)), string(rune(0x10FFFF)), string(rune(0xFEFF)), repl, "a" + repl + "b",
		string(rune(0xD7FF)), string(rune(0xE000)), "\x00", "\x7f",
	} {
		t.Run(fmt.Sprintf("%+q", text), func(t *testing.T) {
			got, err := Marshal(map[string]string{text: text})
			if err != nil {
				t.Fatal(err)
			}
			want := `{"` + canonicalControls(text) + `":"` + canonicalControls(text) + `"}`
			if string(got) != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
	t.Run("a struct, an embedded struct, a slice and a pointer of valid text", func(t *testing.T) {
		s := "\u00e9"
		got, err := Marshal(embedsPointer{&inEmbedded{s}, 1})
		if err != nil || string(got) != "{\"N\":1,\"S\":\"\u00e9\"}" {
			t.Errorf("embedded pointer: %q, %v", got, err)
		}
		got, err = Marshal(struct {
			P *string
			L []string
			I any
		}{&s, []string{s}, s})
		if err != nil || string(got) != "{\"I\":\"\u00e9\",\"L\":[\"\u00e9\"],\"P\":\"\u00e9\"}" {
			t.Errorf("fields: %q, %v", got, err)
		}
	})
}

// canonicalControls writes the controls of s as the canonical form does and leaves the rest.
func canonicalControls(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20:
			fmt.Fprintf(&out, "\\u%04x", r)
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func TestMarshalChecksWhatATypeWritesAsJSON(t *testing.T) {
	bs := string(rune(92)) // a backslash: no escape of this file is written out
	lone := bs + "u" + "d800"
	cases := []struct {
		name string
		json string
		want string // the text of the refusal
	}{
		{"a byte that is not UTF-8 in a value", "{\"a\":\"\xff\"}", "malformed JSON: not valid UTF-8"},
		{"a byte that is not UTF-8 in a name", "{\"\xff\":1}", "malformed JSON: not valid UTF-8"},
		{"a byte that is not UTF-8 deep down", "{\"a\":[{\"b\":[\"\xc0\xaf\"]}]}", "malformed JSON: not valid UTF-8"},
		{"a lone high surrogate escape", `{"a":"` + lone + `"}`, "malformed JSON: a lone surrogate escape at byte 12"},
		{"a lone low surrogate escape", `{"a":"` + bs + "u" + `dc00"}`, "malformed JSON: a lone surrogate escape at byte 12"},
		{"a high surrogate and a letter", `{"a":"` + lone + `x"}`, "malformed JSON: a lone surrogate escape at byte 12"},
		{"a lone surrogate escape in a name", `{"` + lone + `":1}`, "malformed JSON: a lone surrogate escape at byte 8"},
		{"a float", `{"a":1.5}`, "malformed JSON: a number with a fraction or an exponent at byte 8"},
		{"a float with an integer value", `{"a":1.0}`, "malformed JSON: a number with a fraction or an exponent at byte 8"},
		{"an exponent", `{"a":1e3}`, "malformed JSON: a number with a fraction or an exponent at byte 8"},
		{"a null", `{"a":null}`, "malformed JSON: null at byte 9"},
		{"a null in an array", `{"a":[1,null]}`, "malformed JSON: null at byte 12"},
		{"a repeated member", `{"a":1,"a":2}`, `malformed JSON: member "a" appears twice at byte 10`},
		{"a repeated member written with an escape", `{"a":1,"` + bs + `u0061":2}`, `malformed JSON: member "a" appears twice at byte 15`},
		{"an integer above int64", `{"a":9223372036854775808}`, "malformed JSON: the integer does not fit 64 bits at byte 24"},
		{"a value that is not an object", `[1]`, "malformed JSON: not one JSON object"},
		{"a string where an object is wanted", `"x"`, "malformed JSON: not one JSON object"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" at the top", func(t *testing.T) {
			got, err := Marshal(ownJSON(tc.json))
			refused(t, got, err, tc.want)
		})
	}
	// The same JSON as a member value: the byte of the refusal moves, the kind of it does not.
	members := []struct {
		name string
		json string
		want string
	}{
		{"a byte that is not UTF-8", "{\"a\":\"\xff\"}", "malformed JSON: not valid UTF-8"},
		{"a lone surrogate escape", `{"a":"` + lone + `"}`, "malformed JSON: a lone surrogate escape at byte 17"},
		{"a float", `{"a":1.5}`, "malformed JSON: a number with a fraction or an exponent at byte 13"},
		{"a null", `{"a":null}`, "malformed JSON: null at byte 14"},
		{"a repeated member", `{"a":1,"a":2}`, `malformed JSON: member "a" appears twice at byte 15`},
	}
	for _, tc := range members {
		t.Run(tc.name+" in a map value", func(t *testing.T) {
			got, err := Marshal(map[string]ownJSON{"x": ownJSON(tc.json)})
			refused(t, got, err, tc.want)
		})
		t.Run(tc.name+" in a struct field", func(t *testing.T) {
			got, err := Marshal(struct{ X ownJSON }{ownJSON(tc.json)})
			refused(t, got, err, tc.want)
		})
		t.Run(tc.name+" in a slice element", func(t *testing.T) {
			got, err := Marshal(map[string][]ownJSON{"x": {ownJSON(`{}`), ownJSON(tc.json)}})
			if err == nil || !errors.Is(err, strictjson.ErrMalformed) || got != nil {
				t.Errorf("got %q, %v", got, err)
			}
		})
		t.Run(tc.name+" in raw JSON", func(t *testing.T) {
			got, err := Marshal(map[string]json.RawMessage{"x": json.RawMessage(tc.json)})
			refused(t, got, err, tc.want)
		})
	}
	t.Run("a valid surrogate pair is accepted and written as the character", func(t *testing.T) {
		for _, in := range []string{
			`{"a":"` + bs + "ud83d" + bs + "ude00" + `"}`,
			`{"a":"` + bs + "uD83D" + bs + "uDE00" + `"}`,
			"{\"a\":\"\U0001F600\"}",
		} {
			got, err := Marshal(ownJSON(in))
			if err != nil {
				t.Errorf("%s: %v", in, err)
				continue
			}
			if want := "{\"a\":\"\U0001F600\"}"; string(got) != want {
				t.Errorf("%s: got %q, want %q", in, got, want)
			}
		}
		// And as a name, sorted among others by UTF-16 units.
		got, err := Marshal(ownJSON(`{"` + bs + "ud83d" + bs + "ude00" + `":1,"` + bs + "ufb33" + `":2}`))
		if err != nil || string(got) != "{\"\U0001F600\":1,\"\ufb33\":2}" {
			t.Errorf("a pair as a name: %q, %v", got, err)
		}
	})
	t.Run("escapes of the JSON are written as the canonical form writes them", func(t *testing.T) {
		in := `{"b":"` + bs + "u00e9" + bs + "/" + bs + "u0009" + bs + "u001F" + `","a":1}`
		got, err := Marshal(ownJSON(in))
		if err != nil {
			t.Fatal(err)
		}
		if want := "{\"a\":1,\"b\":\"\u00e9/\\t\\u001f\"}"; string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("the nesting of the JSON a type writes counts with the rest", func(t *testing.T) {
		deep := func(n int) ownJSON { // n levels in all
			return ownJSON(strings.Repeat(`{"a":`, n-1) + `{}` + strings.Repeat(`}`, n-1))
		}
		// Alone, a document of the limit is written. Inside one map it is one level lower than
		// it stands alone, inside two maps two.
		got, err := Marshal(deep(strictjson.MaxDepth))
		if err != nil || len(got) != 5*(strictjson.MaxDepth-1)+len(`{}`)+strictjson.MaxDepth-1 {
			t.Errorf("%d levels alone: %d bytes, %v", strictjson.MaxDepth, len(got), err)
		}
		got, err = Marshal(map[string]ownJSON{"x": deep(strictjson.MaxDepth - 1)})
		if err != nil {
			t.Fatalf("%d levels in all: %v", strictjson.MaxDepth, err)
		}
		if is, err := IsCanonical(got); err != nil || !is {
			t.Errorf("the output is not canonical: %v, %v", is, err)
		}
		// One level over is refused and nothing is written. Which package says so, and in what
		// words, is not pinned here: the standard encoder also stops at this depth.
		got, err = Marshal(map[string]map[string]ownJSON{"x": {"y": deep(strictjson.MaxDepth - 1)}})
		if err == nil || got != nil {
			t.Errorf("%d levels in all: %q, %v, want an error and nothing", strictjson.MaxDepth+1, got, err)
		}
	})
}

// The types below write their own text.
type (
	textValue   struct{ out string } // MarshalText on the value
	textPointer struct{ out string } // MarshalText on the pointer
	textInt     int                  // a key that writes its own text: 1 is bad
	textKeyPtr  struct{ out string } // a key through a pointer
	textString  string               // a string kind that writes text of its own
	jsonAndText struct{ json, text string }
	failing     struct{}
)

var errBoom = errors.New("boom")

func (x textValue) MarshalText() ([]byte, error) { return []byte(x.out), nil }

func (x *textPointer) MarshalText() ([]byte, error) { return []byte(x.out), nil }

func (k textInt) MarshalText() ([]byte, error) {
	if k == 1 {
		return []byte("\xff"), nil
	}
	return []byte(fmt.Sprintf("key%d", int(k))), nil
}

func (k *textKeyPtr) MarshalText() ([]byte, error) { return []byte(k.out), nil }

// MarshalText of a string kind: the encoder writes the text, not the string.
func (s textString) MarshalText() ([]byte, error) { return []byte("ok"), nil }

func (x jsonAndText) MarshalJSON() ([]byte, error) { return []byte(x.json), nil }

func (x jsonAndText) MarshalText() ([]byte, error) { return []byte(x.text), nil }

func (failing) MarshalText() ([]byte, error) { return nil, errBoom }

func TestMarshalChecksWhatATypeWritesAsText(t *testing.T) {
	const text = "malformed JSON: a text that is not valid UTF-8 cannot be written"
	const key = "malformed JSON: a member name that is not valid UTF-8 cannot be written"
	bad := "\xff"
	ptr := &textValue{bad}
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"a value in a map", map[string]textValue{"k": {bad}}, text},
		{"a value in an interface", map[string]any{"k": textValue{bad}}, text},
		{"a value in a field", struct{ T textValue }{textValue{bad}}, text},
		{"a value in a slice", map[string][]textValue{"k": {{"fine"}, {bad}}}, text},
		{"a value in an array", struct{ A [1]textValue }{[1]textValue{{bad}}}, text},
		{"a value behind a pointer field", struct{ P *textValue }{ptr}, text},
		{"a value behind a pointer in a map", map[string]*textValue{"k": ptr}, text},
		{"a value behind two pointers", struct{ P **textValue }{&ptr}, text},
		{"a value in a nested struct", struct{ S struct{ T textValue } }{struct{ T textValue }{textValue{bad}}}, text},
		{"a method on the pointer, for a slice element", map[string][]textPointer{"k": {{bad}}}, text},
		{"a method on the pointer, for a field of an addressable struct", map[string]*struct{ T textPointer }{"k": {textPointer{bad}}}, text},
		{"a key of an integer kind", map[textInt]int{1: 1}, key},
		{"a key of an integer kind among valid ones", map[textInt]int{0: 1, 1: 1, 2: 1}, key},
		{"a key through a pointer", map[*textKeyPtr]int{{bad}: 1}, key},
		{"a key in a nested map", map[string]any{"a": map[textInt]int{1: 1}}, key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(tc.v)
			refused(t, got, err, tc.want)
		})
	}
	t.Run("valid text is written, as a value and as a key", func(t *testing.T) {
		got, err := Marshal(map[string]any{"v": textValue{"\u00e9<"}, "p": &textValue{"x"}, "s": []textPointer{{"y"}}})
		if err != nil {
			t.Fatal(err)
		}
		if want := "{\"p\":\"x\",\"s\":[\"y\"],\"v\":\"\u00e9<\"}"; string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
		got, err = Marshal(map[textInt]int{0: 1, 2: 3, 12: 4})
		if err != nil {
			t.Fatal(err)
		}
		if want := `{"key0":1,"key12":4,"key2":3}`; string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("a method that the encoder does not call is not called here", func(t *testing.T) {
		// A map value cannot be addressed, so the encoder does not use a method of the pointer
		// and writes the struct as an object; the walk must not refuse the text of that method.
		got, err := Marshal(map[string]struct{ T textPointer }{"k": {textPointer{bad}}})
		if err != nil {
			t.Fatalf("Marshal refused: %v", err)
		}
		if want := `{"k":{"T":{}}}`; string(got) != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
	t.Run("the encoder uses the text of a value, not the string under it", func(t *testing.T) {
		// textString holds an invalid string and writes valid text: what is written is the text.
		got, err := Marshal(map[string]textString{"k": textString("\xff")})
		if err != nil {
			t.Fatalf("Marshal refused: %v", err)
		}
		if want := `{"k":"ok"}`; string(got) != want {
			t.Errorf("got %s, want %s", got, want)
		}
	})
	t.Run("the encoder asks for the JSON first", func(t *testing.T) {
		got, err := Marshal(map[string]jsonAndText{"k": {json: `{"a":1}`, text: "\xff"}})
		if err != nil {
			t.Fatalf("Marshal refused: %v", err)
		}
		if want := `{"k":{"a":1}}`; string(got) != want {
			t.Errorf("got %s, want %s", got, want)
		}
		// And the JSON is what is checked when it is the one that is bad.
		got, err = Marshal(map[string]jsonAndText{"k": {json: `{"a":1.5}`, text: "fine"}})
		if !errors.Is(err, strictjson.ErrMalformed) || got != nil {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("an error of the method is the encoder's to report", func(t *testing.T) {
		for name, v := range map[string]any{
			"a value":     map[string]failing{"k": {}},
			"a field":     struct{ F failing }{},
			"a slice":     map[string][]failing{"k": {{}}},
			"a map key":   map[textFailingKey]int{1: 1},
			"the top one": failing{},
		} {
			got, err := Marshal(v)
			if !errors.Is(err, errBoom) {
				t.Errorf("%s: err = %v, want boom", name, err)
			}
			if got != nil {
				t.Errorf("%s: Marshal returned %q next to an error", name, got)
			}
		}
	})
}

type textFailingKey int

func (textFailingKey) MarshalText() ([]byte, error) { return nil, errBoom }

// nestedSlices is a map that holds n slices one inside the other: n+1 levels in all.
func nestedSlices(n int) (map[string]any, string) {
	inner := []any{}
	for range n - 1 {
		inner = []any{inner}
	}
	return map[string]any{"a": inner}, `{"a":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
}

// nestedMaps is a map that holds maps: levels objects in all.
func nestedMaps(levels int) (map[string]any, string) {
	inner := map[string]any{}
	for range levels - 1 {
		inner = map[string]any{"a": inner}
	}
	return inner, strings.Repeat(`{"a":`, levels-1) + `{}` + strings.Repeat(`}`, levels-1)
}

// listNode is a linked list: each node is one level of nesting, the link is not written at the end.
type listNode struct {
	Next *listNode `json:",omitempty"`
}

// nestedList is a list of n nodes: n levels in all.
func nestedList(n int) (*listNode, string) {
	head := &listNode{}
	for range n - 1 {
		head = &listNode{Next: head}
	}
	return head, strings.Repeat(`{"Next":`, n-1) + `{}` + strings.Repeat(`}`, n-1)
}

// pointerSlice is a slice of pointers to slices of pointers to slices: each pointer is a hop, not a level.
type pointerSlice []*pointerSlice

// nestedPointerSlices is a pointerSlice n slices deep, inside a map: n+1 levels in all.
func nestedPointerSlices(n int) (map[string]any, string) {
	inner := pointerSlice{}
	for range n - 1 {
		prev := inner // a variable of its own for each level: &inner would point to itself
		inner = pointerSlice{&prev}
	}
	return map[string]any{"a": inner}, `{"a":` + strings.Repeat("[", n) + strings.Repeat("]", n) + `}`
}

// hopSlice, hopMap and hopStruct hold the next level behind a pointer to an interface: two hops
// for every level, so that hops that were not counted from the last level would add up to the
// limit long before the levels do.
type (
	hopSlice  []*any
	hopMap    map[string]*any
	hopStruct struct {
		N *any `json:",omitempty"`
	}
)

// nestedHops is a value of levels levels of one kind of container with two hops between every two
// of them, as the walk and the JSON see it. The first level is an object, so a slice goes in a map.
func nestedHops(kind string, levels int) (any, string) {
	var inner any
	var opens, closes []string
	for level := levels; level >= 1; level-- {
		prev := inner
		last := level == levels // the innermost level is empty
		switch kind {
		case "slices":
			inner = hopSlice{}
			if !last {
				inner = hopSlice{&prev}
			}
			opens, closes = append(opens, `[`), append(closes, `]`)
		case "maps":
			inner = hopMap{}
			if !last {
				inner = hopMap{"a": &prev}
			}
			opens, closes = append(opens, `{"a":`), append(closes, `}`)
		default:
			inner = hopStruct{}
			if !last {
				inner = hopStruct{&prev}
			}
			opens, closes = append(opens, `{"N":`), append(closes, `}`)
		}
	}
	// The innermost level has no member, so its opener is the bracket alone; the openers and the
	// closers were collected from the innermost level out.
	opens[0] = opens[0][:1]
	slices.Reverse(opens)
	want := strings.Join(opens, "") + strings.Join(closes, "")
	if kind == "slices" {
		return map[string]any{"a": inner}, `{"a":` + want + `}`
	}
	return inner, want
}

// nestedMixedValue is levels levels of maps, slices and structs in turn, the first a map.
func nestedMixedValue(levels int) (any, string) {
	var inner any
	var opens, closes []string
	for level := levels; level >= 1; level-- {
		switch {
		case level == levels && level%2 == 1:
			inner = map[string]any{}
			opens, closes = append(opens, `{`), append(closes, `}`)
		case level == levels:
			inner = []any{}
			opens, closes = append(opens, `[`), append(closes, `]`)
		case level%3 == 1:
			inner = map[string]any{"a": inner}
			opens, closes = append(opens, `{"a":`), append(closes, `}`)
		case level%3 == 2:
			inner = []any{inner}
			opens, closes = append(opens, `[`), append(closes, `]`)
		default:
			inner = struct{ A any }{inner}
			opens, closes = append(opens, `{"A":`), append(closes, `}`)
		}
	}
	slices.Reverse(opens)
	return inner, strings.Join(opens, "") + strings.Join(closes, "")
}

func TestMarshalNestingDepth(t *testing.T) {
	tooDeep := malformedText("nesting deeper than %d levels", strictjson.MaxDepth)
	limit := strictjson.MaxDepth
	cases := []struct {
		name  string
		build func(levels int) (any, string)
	}{
		{"slices in a map", func(n int) (any, string) { return nestedSlices(n - 1) }},
		{"maps in maps", func(n int) (any, string) { return nestedMaps(n) }},
		{"a linked list of structs behind pointers", func(n int) (any, string) { return nestedList(n) }},
		{"slices that hold pointers to slices", func(n int) (any, string) { return nestedPointerSlices(n - 1) }},
		{"maps, slices and structs in turn", nestedMixedValue},
		{"slices with two hops to every level", func(n int) (any, string) { return nestedHops("slices", n-1) }},
		{"maps with two hops to every level", func(n int) (any, string) { return nestedHops("maps", n) }},
		{"structs with two hops to every level", func(n int) (any, string) { return nestedHops("structs", n) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The levels the JSON has: exactly the limit is written and is canonical, one more is refused.
			for _, levels := range []int{3, 4, 5, 1000, 4000, limit - 1, limit} {
				v, want := tc.build(levels)
				got, err := Marshal(v)
				if err != nil {
					t.Fatalf("%d levels: %v", levels, err)
				}
				sameBytes(t, fmt.Sprintf("%d levels", levels), got, want)
				if is, err := IsCanonical(got); err != nil || !is {
					t.Errorf("%d levels: the output is not canonical: %v, %v", levels, is, err)
				}
			}
			v, _ := tc.build(limit + 1)
			got, err := Marshal(v)
			refused(t, got, err, tooDeep)
			v, _ = tc.build(2 * limit)
			got, err = Marshal(v)
			refused(t, got, err, tooDeep)
		})
	}
	t.Run("a byte slice is a string, not a level", func(t *testing.T) {
		// maps in maps to the limit, the innermost holding bytes: the base64 string is not a level.
		inner, want := nestedMaps(limit)
		deepest := inner
		for len(deepest) > 0 {
			deepest = deepest["a"].(map[string]any)
		}
		deepest["b"] = []byte("hi")
		want = strings.Replace(want, `{}`, `{"b":"aGk="}`, 1)
		got, err := Marshal(inner)
		if err != nil {
			t.Fatal(err)
		}
		sameBytes(t, "bytes at the limit", got, want)
	})
}

// hopsChain is a map behind a chain of pointers and interfaces: k hops in all, which are not levels.
func hopsChain(k int) any {
	var v any = map[string]int{"a": 1}
	if k%2 == 1 {
		m := map[string]int{"a": 1}
		v = &m
	}
	for range k / 2 {
		cur := v
		v = &cur
	}
	return v
}

func TestMarshalChainOfPointers(t *testing.T) {
	// A pointer or an interface is not a level of nesting, but a chain of them must end: a chain
	// of the length of the limit is written, a longer one is refused as too deep.
	tooDeep := malformedText("nesting deeper than %d levels", strictjson.MaxDepth)
	for _, k := range []int{1, 2, 3, 100, 1001, strictjson.MaxDepth - 1, strictjson.MaxDepth} {
		got, err := Marshal(hopsChain(k))
		if err != nil {
			t.Errorf("a chain of %d: %v", k, err)
			continue
		}
		if want := `{"a":1}`; string(got) != want {
			t.Errorf("a chain of %d: got %s, want %s", k, got, want)
		}
	}
	for _, k := range []int{strictjson.MaxDepth + 1, strictjson.MaxDepth + 2, 20000, 100000} {
		got, err := Marshal(hopsChain(k))
		refused(t, got, err, tooDeep)
	}
}

func TestMarshalOfAValueThatPointsToItselfEndsInAnError(t *testing.T) {
	tooDeep := malformedText("nesting deeper than %d levels", strictjson.MaxDepth)
	type loop struct{ Next *loop }
	l := &loop{}
	l.Next = l
	m := map[string]any{}
	m["self"] = m
	s := make([]any, 1)
	s[0] = s
	var p any
	p = &p
	a := &loop{}
	b := &loop{Next: a}
	a.Next = b
	for name, v := range map[string]any{
		"a struct with a pointer to itself":                l,
		"a struct value that holds it":                     *l,
		"two structs that point to each other":             a,
		"a map that holds itself":                          m,
		"a map that holds itself, in a map":                map[string]any{"m": m},
		"a slice that holds itself":                        map[string]any{"s": s},
		"a pointer to an interface that holds the pointer": p,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Marshal(v)
			refused(t, got, err, tooDeep)
		})
	}
}

func TestMarshalNestingDepthIsCountedAsTheJSONHasIt(t *testing.T) {
	// Levels that are not in the JSON must not count: a pointer or an interface is a hop, and
	// hops are counted from the last level, so that a list of 4000 nodes whose links are
	// pointers is 4000 levels and not 8000 or 12000.
	list, want := nestedList(4000)
	got, err := Marshal(list)
	if err != nil {
		t.Fatalf("a list of 4000: %v", err)
	}
	sameBytes(t, "a list of 4000", got, want)
	// Pointer and interface between every two levels, to the limit.
	inner, wantSlices := nestedPointerSlices(strictjson.MaxDepth - 1)
	got, err = Marshal(inner)
	if err != nil {
		t.Fatalf("slices of pointers: %v", err)
	}
	sameBytes(t, "slices of pointers", got, wantSlices)
}

// ambiguousA and ambiguousB each write text of their own and are embedded in one struct, so the
// struct has no method of that name (two at one depth cancel each other) and is written as an object.
type (
	ambiguousA struct{ X string }
	ambiguousB struct{ Y string }
	ambiguous  struct {
		ambiguousA
		ambiguousB
	}
)

func (ambiguousA) MarshalText() ([]byte, error) { return []byte("\xff"), nil }

func (ambiguousB) MarshalText() ([]byte, error) { return []byte("\xff"), nil }

func TestMarshalOfEmbeddedStructsThatWriteTextOfTheirOwn(t *testing.T) {
	// The embedded types are not exported, so their fields cannot be read through the interface
	// of the value; the walk must neither panic nor take their text for the struct's.
	got, err := Marshal(ambiguous{ambiguousA{"a"}, ambiguousB{"b"}})
	if err != nil {
		t.Fatalf("Marshal refused: %v", err)
	}
	if want := `{"X":"a","Y":"b"}`; string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
