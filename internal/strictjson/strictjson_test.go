package strictjson

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// nested is an object with n levels of objects, the top-level one included: {"a":{"a":{}}} is 3.
func nested(n int) []byte {
	return []byte(strings.Repeat(`{"a":`, n-1) + `{}` + strings.Repeat(`}`, n-1))
}

// nestedArrays is an object that holds arrays n-1 levels deep; the total depth is n.
func nestedArrays(n int) []byte {
	return []byte(`{"a":` + strings.Repeat(`[`, n-1) + `1` + strings.Repeat(`]`, n-1) + `}`)
}

// padded is a valid object of exactly size bytes.
func padded(t *testing.T, size int) []byte {
	t.Helper()
	const frame = len(`{"a":""}`)
	if size < frame {
		t.Fatalf("size %d is smaller than the frame", size)
	}
	data := []byte(`{"a":"` + strings.Repeat("x", size-frame) + `"}`)
	if len(data) != size {
		t.Fatalf("padded made %d bytes, want %d", len(data), size)
	}
	return data
}

type rule struct {
	name string
	in   string
}

var accepted = []rule{
	{"empty object", `{}`},
	{"white space around the object", " \t\r\n{ }\n\r\t "},
	{"white space inside", "{ \"a\" :\t1 ,\n\"b\"\r:[ 1 , 2 ] }"},
	{"members of every kind", `{"s":"x","n":-12,"t":true,"f":false,"o":{"k":[1,2,{"d":"v"}]},"e":[],"z":{}}`},
	{"minus zero", `{"a":-0}`},
	{"zero", `{"a":0}`},
	{"largest integer of the range", `{"a":9007199254740991}`},
	{"smallest integer of the range", `{"a":-9007199254740991}`},
	{"empty string", `{"a":""}`},
	{"non-ASCII text", `{"a":"é€😀"}`},
	{"escapes", `{"a":"\"\\\/\b\f\n\r\t\u00e9\u0000"}`},
	{"a surrogate pair", `{"a":"\ud83d\ude00"}`},
	{"a surrogate pair in capitals", `{"a":"\uD83D\uDE00"}`},
	{"the same name in two objects", `{"a":{"a":1},"b":{"a":1},"c":[{"a":1},{"a":2}]}`},
	{"names that differ in letter case", `{"a":1,"A":2}`},
	{"a name that is a prefix of another", `{"a":1,"ab":2}`},
}

var refused = []rule{
	{"empty input", ``},
	{"white space only", " \n\t"},
	{"an array at top level", `[]`},
	{"an array of objects at top level", `[{}]`},
	{"a string at top level", `"x"`},
	{"a number at top level", `1`},
	{"null at top level", `null`},
	{"true at top level", `true`},
	{"an array that is closed as an object", `[}`},
	{"a string that is closed as an object", `"}`},
	{"a number that is closed as an object", `1}`},
	{"a byte order mark", "\xef\xbb\xbf{}"},
	{"a byte order mark and white space", "\xef\xbb\xbf \n{}"},
	{"invalid UTF-8 in a value", "{\"a\":\"\xff\"}"},
	{"invalid UTF-8 in a name", "{\"\xc3\":1}"},
	{"an overlong UTF-8 sequence", "{\"a\":\"\xc0\xaf\"}"},
	{"a UTF-8 encoded surrogate", "{\"a\":\"\xed\xa0\x80\"}"},
	{"a fraction", `{"a":1.0}`},
	{"a fraction that is not zero", `{"a":1.5}`},
	{"an exponent", `{"a":1e2}`},
	{"an exponent in capitals", `{"a":1E2}`},
	{"a signed exponent", `{"a":1e+2}`},
	{"zero with an exponent", `{"a":0e0}`},
	{"minus zero with a fraction", `{"a":-0.0}`},
	{"an integer one above int64", `{"a":9223372036854775808}`},
	{"an integer one below int64", `{"a":-9223372036854775809}`},
	{"the largest int64", `{"a":9223372036854775807}`},
	{"the smallest int64", `{"a":-9223372036854775808}`},
	{"the largest uint64", `{"a":18446744073709551615}`},
	{"one above the range", `{"a":9007199254740992}`},
	{"one below the range", `{"a":-9007199254740992}`},
	{"the first integer that a float cannot hold", `{"a":9007199254740993}`},
	{"a huge integer", `{"a":99999999999999999999999999999999}`},
	{"null as a value", `{"a":null}`},
	{"null in an array", `{"a":[1,null]}`},
	{"null in a nested object", `{"a":{"b":{"c":null}}}`},
	{"a lone high surrogate", `{"a":"\ud800"}`},
	{"a lone low surrogate", `{"a":"\udc00"}`},
	{"a high surrogate and a letter", `{"a":"\ud800x"}`},
	{"a high surrogate and a high surrogate", `{"a":"\ud800\ud800"}`},
	{"a low surrogate before a high one", `{"a":"\udc00\ud800"}`},
	{"a high surrogate and another escape", `{"a":"\ud83d\u0041"}`},
	{"a lone surrogate in a name", `{"\ud800":1}`},
	{"a lone surrogate at the end of the string", `{"a":"x\ud83d"}`},
	{"a repeated member", `{"a":1,"a":2}`},
	{"a repeated member with the same value", `{"a":1,"a":1}`},
	{"a repeated member at depth 2", `{"x":{"a":1,"a":2}}`},
	{"a repeated member at depth 3", `{"x":{"y":{"a":1,"a":2}}}`},
	{"a repeated member in an array element", `{"x":[1,{"a":1,"a":1}]}`},
	{"a repeated member written with an escape", `{"a":1,"\u0061":2}`},
	{"a repeated member, both with escapes", `{"\u0061":1,"\u0061":2}`},
	{"a repeated member with a non-ASCII name", `{"é":1,"\u00e9":2}`},
	{"a repeated member, not next to the first", `{"a":1,"b":2,"c":3,"a":4}`},
	{"text after the object", `{} x`},
	{"a second object", `{}{}`},
	{"a second object after white space", "{}\n{}"},
	{"a comma after the object", `{},`},
	{"a null byte after the object", "{}\x00"},
	{"a newline and a number after the object", "{}\n1"},
	{"a trailing comma", `{"a":1,}`},
	{"a missing colon", `{"a" 1}`},
	{"a name without quotes", `{a:1}`},
	{"single quotes", `{'a':1}`},
	{"a leading zero", `{"a":01}`},
	{"a plus sign", `{"a":+1}`},
	{"a number that starts with a point", `{"a":.5}`},
	{"a point without digits", `{"a":1.}`},
	{"an exponent without digits", `{"a":1e}`},
	{"a minus sign alone", `{"a":-}`},
	{"an unknown escape", `{"a":"\x"}`},
	{"a short unicode escape", `{"a":"\u12"}`},
	{"a bad digit in a unicode escape", `{"a":"\u12g4"}`},
	{"a raw control character in a string", "{\"a\":\"tab\there\"}"},
	{"a raw line feed in a name", "{\"a\nb\":1}"},
	{"a truncated object", `{"a":`},
	{"an object that never closes", `{"a":1`},
	{"an unterminated string", `{"a":"abc`},
	{"an unterminated escape", `{"a":"abc\`},
	{"a misspelt literal", `{"a":tru}`},
	{"a capitalised literal", `{"a":True}`},
	{"a literal followed by letters", `{"a":truex}`},
	{"an array that never closes", `{"a":[1,2}`},
	{"a comma in an empty array", `{"a":[,]}`},
	{"NaN", `{"a":NaN}`},
	{"a comment", `{"a":1/*x*/}`},
}

func TestCheckAccepts(t *testing.T) {
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			if err := Check([]byte(tc.in), 0); err != nil {
				t.Errorf("Check refused %q: %v", tc.in, err)
			}
		})
	}
}

func TestCheckRefuses(t *testing.T) {
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := Check([]byte(tc.in), 0)
			if err == nil {
				t.Fatalf("Check accepted %q", tc.in)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("the error does not wrap ErrMalformed: %v", err)
			}
		})
	}
}

func TestTheTablesAreNotEmpty(t *testing.T) {
	if len(accepted) == 0 || len(refused) == 0 {
		t.Fatal("a table of cases is empty")
	}
}

func TestUnmarshalAppliesTheSameRules(t *testing.T) {
	// Every case that Check decides is decided the same by Unmarshal into a struct that reads
	// anything it is given, so that the typed reader cannot be laxer than the untyped one.
	type any1 struct {
		A any `json:"a"`
	}
	for _, tc := range accepted {
		if strings.Contains(tc.name, "differ in letter case") || strings.Contains(tc.name, "prefix") ||
			tc.in == `{}` || strings.Contains(tc.name, "white space") {
			continue // the struct knows member "a" only; these are covered by the tests below
		}
		t.Run("accept "+tc.name, func(t *testing.T) {
			var v any1
			if err := Unmarshal([]byte(tc.in), &v, Options{AllowUnknown: true}); err != nil {
				t.Errorf("Unmarshal refused %q: %v", tc.in, err)
			}
		})
	}
	for _, tc := range refused {
		t.Run("refuse "+tc.name, func(t *testing.T) {
			var v any1
			err := Unmarshal([]byte(tc.in), &v, Options{AllowUnknown: true})
			if err == nil {
				t.Fatalf("Unmarshal accepted %q", tc.in)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("the error does not wrap ErrMalformed: %v", err)
			}
		})
	}
}

func TestSizeLimit(t *testing.T) {
	if DefaultMaxBytes != 262144 {
		t.Fatalf("DefaultMaxBytes = %d, want 262144", DefaultMaxBytes)
	}
	t.Run("exactly the limit is accepted", func(t *testing.T) {
		data := padded(t, 262144)
		if err := Check(data, 0); err != nil {
			t.Errorf("Check refused 262144 bytes: %v", err)
		}
		var v struct {
			A string `json:"a"`
		}
		if err := Unmarshal(data, &v, Options{}); err != nil {
			t.Errorf("Unmarshal refused 262144 bytes: %v", err)
		}
		if len(v.A) != 262144-8 {
			t.Errorf("the value has %d bytes", len(v.A))
		}
		if _, ok, err := PeekInt(data, "absent", 0); err != nil || ok {
			t.Errorf("PeekInt on 262144 bytes = ok %v, err %v", ok, err)
		}
	})
	t.Run("one byte over is refused", func(t *testing.T) {
		data := padded(t, 262145)
		var v struct {
			A string `json:"a"`
		}
		for name, err := range map[string]error{
			"Check":                       Check(data, 0),
			"Unmarshal":                   Unmarshal(data, &v, Options{}),
			"Unmarshal with AllowUnknown": Unmarshal(data, &v, Options{AllowUnknown: true}),
			"PeekInt":                     peekErr(data),
		} {
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("%s on 262145 bytes: %v, want ErrMalformed", name, err)
			}
		}
	})
	t.Run("a limit of the caller", func(t *testing.T) {
		const small = `{"a":1}` // 7 bytes
		if err := Check([]byte(small), 7); err != nil {
			t.Errorf("Check refused the limit itself: %v", err)
		}
		if err := Check([]byte(small), 6); !errors.Is(err, ErrMalformed) {
			t.Errorf("Check with a limit one under: %v, want ErrMalformed", err)
		}
		var v struct {
			A int `json:"a"`
		}
		if err := Unmarshal([]byte(small), &v, Options{MaxBytes: 7}); err != nil {
			t.Errorf("Unmarshal refused the limit itself: %v", err)
		}
		if err := Unmarshal([]byte(small), &v, Options{MaxBytes: 6}); !errors.Is(err, ErrMalformed) {
			t.Errorf("Unmarshal with a limit one under: %v, want ErrMalformed", err)
		}
	})
	t.Run("a limit of the caller can be larger than the default", func(t *testing.T) {
		data := padded(t, 262145)
		if err := Check(data, 262145); err != nil {
			t.Errorf("Check refused an input within the limit of the caller: %v", err)
		}
		var v struct {
			A string `json:"a"`
		}
		if err := Unmarshal(data, &v, Options{MaxBytes: 262145}); err != nil {
			t.Errorf("Unmarshal refused an input within the limit of the caller: %v", err)
		}
	})
}

func peekErr(data []byte) error {
	_, _, err := PeekInt(data, "absent", 0)
	return err
}

// nestedMixed is a document of n levels in all that alternates objects and arrays, the top-level
// object being level 1: {"a":[{"a":[{}]}]} is 5 (the innermost level is {} or [] by its parity).
func nestedMixed(n int) []byte {
	var open, shut strings.Builder
	for level := 1; level < n; level++ {
		if level%2 == 1 {
			open.WriteString(`{"a":`)
			shut.WriteString(`}`)
		} else {
			open.WriteString(`[`)
			shut.WriteString(`]`)
		}
	}
	core := `{}`
	if n%2 == 0 {
		core = `[]`
	}
	// shut was written outermost first; every closer is one byte and the closers of a mixed
	// document are not interchangeable, so write them innermost first.
	closers := []byte(shut.String())
	slices.Reverse(closers)
	return []byte(open.String() + core + string(closers))
}

// siblings is an object with two members, an array that is first levels deep in all and one that
// is second levels deep in all (the object being level 1 of each): a reader that forgets to leave
// a level when it closes an array would count the two together.
func siblings(first, second int) []byte {
	arm := func(n int) string { return strings.Repeat(`[`, n-1) + `1` + strings.Repeat(`]`, n-1) }
	return []byte(`{"a":` + arm(first) + `,"b":` + arm(second) + `}`)
}

// siblingObjects is siblings made of objects: two members, each an object chain, the first one
// first levels deep in all and the second second levels deep in all.
func siblingObjects(first, second int) []byte {
	arm := func(n int) string { return strings.Repeat(`{"a":`, n-2) + `{}` + strings.Repeat(`}`, n-2) }
	return []byte(`{"a":` + arm(first) + `,"b":` + arm(second) + `}`)
}

func TestMaxDepthIsTenThousand(t *testing.T) {
	if MaxDepth != 10000 {
		t.Fatalf("MaxDepth = %d, want 10000", MaxDepth)
	}
}

func TestNestingDepth(t *testing.T) {
	var v struct{}
	// A document that is too deep is refused at the path of the container that passes the limit,
	// which is the one at level MaxDepth+1: MaxDepth steps lead to it, and the path shows the last
	// eight. The text of every refusal below ends with the byte at which the reader stopped.
	const dots = "$...."
	const brackets = "$...[0][0][0][0][0][0][0][0]"
	const members = dots + "a.a.a.a.a.a.a.a"
	const alternate = dots + "a[0].a[0].a[0].a[0]"
	cases := []struct {
		name string
		data []byte
		ok   bool
		path string
	}{
		{"objects at the limit", nested(MaxDepth), true, ""},
		{"objects one over", nested(MaxDepth + 1), false, members},
		{"objects far over, within the size limit", nested(DefaultMaxBytes / 6), false, members},
		{"arrays at the limit", nestedArrays(MaxDepth), true, ""},
		{"arrays one over", nestedArrays(MaxDepth + 1), false, brackets},
		{"objects and arrays alternating, an object innermost, at the limit", nestedMixed(MaxDepth - 1), true, ""},
		{"objects and arrays alternating, an array innermost, at the limit", nestedMixed(MaxDepth), true, ""},
		{"objects and arrays alternating, an object innermost, one over", nestedMixed(MaxDepth + 1), false, alternate},
		{"objects and arrays alternating, an array innermost, one over", nestedMixed(MaxDepth + 2), false, alternate},
		{"two siblings that are each at the limit", siblings(MaxDepth, MaxDepth), true, ""},
		{"two sibling objects that are each at the limit", siblingObjects(MaxDepth, MaxDepth), true, ""},
		{"two sibling objects, the second one over", siblingObjects(2, MaxDepth+1), false, members},
		{"two sibling objects, the first one over", siblingObjects(MaxDepth+1, 2), false, members},
		{"two siblings, the second one over", siblings(2, MaxDepth+1), false, brackets},
		{"two siblings, the first one over", siblings(MaxDepth+1, 2), false, brackets},
		// An input that is as deep as its size allows and never closes: no stack fault, an error.
		{"256 KiB of open brackets", []byte(`{"a":` + strings.Repeat(`[`, DefaultMaxBytes-5)), false, brackets},
		{"256 KiB of open objects", []byte(strings.Repeat(`{"a":`, DefaultMaxBytes/5)), false, members},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantText := fmt.Sprintf("%v: %s: nesting deeper than %d levels at byte ", ErrMalformed, tc.path, MaxDepth)
			checks := map[string]error{
				"Check":     Check(tc.data, 0),
				"Unmarshal": Unmarshal(tc.data, &v, Options{AllowUnknown: true}),
				"PeekInt":   peekErr(tc.data),
			}
			for name, err := range checks {
				switch {
				case tc.ok && err != nil:
					t.Errorf("%s refused: %v", name, err)
				case !tc.ok && !errors.Is(err, ErrMalformed):
					t.Errorf("%s = %v, want ErrMalformed", name, err)
				case !tc.ok && !strings.HasPrefix(err.Error(), wantText):
					t.Errorf("%s = %q, want the text %q and a byte", name, err, wantText)
				}
			}
		})
	}
}

func TestNestedHelpersHaveTheDepthTheySay(t *testing.T) {
	// The depth tests above are only as good as their inputs: count the brackets of each helper's
	// document and check that the reader takes it.
	for n := 2; n <= 8; n++ {
		for name, data := range map[string][]byte{
			"nested":         nested(n),
			"nestedArrays":   nestedArrays(n),
			"nestedMixed":    nestedMixed(n),
			"siblings":       siblings(n, n),
			"siblingObjects": siblingObjects(n, n),
		} {
			if err := Check(data, 0); err != nil {
				t.Errorf("%s(%d) = %s: %v", name, n, data, err)
			}
			if got := levels(data); got != n {
				t.Errorf("%s(%d) = %s has %d levels", name, n, data, got)
			}
		}
	}
	if got := levels(nestedMixed(1)); got != 1 {
		t.Errorf("nestedMixed(1) has %d levels", got)
	}
}

// levels counts the deepest nesting of brackets in a document whose strings hold none.
func levels(data []byte) int {
	depth, deepest := 0, 0
	for _, c := range data {
		switch c {
		case '{', '[':
			depth++
			deepest = max(deepest, depth)
		case '}', ']':
			depth--
		}
	}
	return deepest
}

// reading is the type most of the typed tests fill.
type reading struct {
	Version int            `json:"version"`
	Name    string         `json:"name"`
	Inner   inner          `json:"inner"`
	Ptr     *inner         `json:"ptr"`
	Items   []inner        `json:"items"`
	Tags    map[string]int `json:"tags"`
	Hidden  string         `json:"-"`
	Plain   int            // no tag: the name is Plain
	Opt     int            `json:"opt,omitempty"`
}

type inner struct {
	X int `json:"x"`
}

type withEmbedded struct {
	Base
	Own int `json:"own"`
}

// Base is embedded without a name, which the reader refuses as a type.
type Base struct {
	B int `json:"base"`
}

func TestUnmarshalFillsTheValue(t *testing.T) {
	in := `{"version":3,"name":"n","inner":{"x":1},"ptr":{"x":2},"items":[{"x":3},{"x":4}],"tags":{"A":1,"a":2},"Plain":5,"opt":6}`
	var v reading
	if err := Unmarshal([]byte(in), &v, Options{}); err != nil {
		t.Fatal(err)
	}
	if v.Version != 3 || v.Name != "n" || v.Inner.X != 1 || v.Ptr == nil || v.Ptr.X != 2 ||
		len(v.Items) != 2 || v.Items[1].X != 4 || v.Plain != 5 || v.Opt != 6 {
		t.Errorf("the value is not what the file says: %+v", v)
	}
	// Names of a map are data, not field names: two that differ in case are two keys.
	if len(v.Tags) != 2 || v.Tags["A"] != 1 || v.Tags["a"] != 2 {
		t.Errorf("tags = %v", v.Tags)
	}
	// A missing member is the caller's to check: its field is zero, whatever the value held before,
	// because the value is replaced as a whole (the tests of the closed set check this further).
	pre := reading{Version: 9, Name: "old", Plain: 4, Hidden: "h", Tags: map[string]int{"k": 1}, Items: []inner{{X: 1}}}
	if err := Unmarshal([]byte(`{"name":"m"}`), &pre, Options{}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pre, reading{Name: "m"}) {
		t.Errorf("a missing member kept something of the old value: %+v", pre)
	}
}

// An embedded struct is outside the closed set, because the rules of Go for promoted fields are not
// ones a reader of signed files should depend on. (The standard decoder reads its members as the
// members of the outer object; this reader did too before the closed set, and no longer does.)
func TestUnmarshalRefusesAnEmbeddedStruct(t *testing.T) {
	const want = "malformed JSON: $: a value of type strictjson.withEmbedded cannot be read: the embedded field Base is not part of ritueel's JSON; give it a name"
	// It is refused as a type, before a byte of the document is looked at: whatever the document says.
	for _, in := range []string{`{"base":1,"own":2}`, `{"Base":{"base":1},"own":2}`, `{}`, `not json`, ``} {
		v := withEmbedded{Own: 7}
		err := Unmarshal([]byte(in), &v, Options{})
		if !errors.Is(err, ErrMalformed) || err.Error() != want {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
		if v != (withEmbedded{Own: 7}) {
			t.Errorf("%q: the value changed: %+v", in, v)
		}
	}
}

func TestUnknownMembers(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"at depth 1", `{"version":1,"extra":1}`},
		{"at depth 2", `{"inner":{"x":1,"extra":1}}`},
		{"at depth 2 through a pointer", `{"ptr":{"extra":1}}`},
		{"at depth 3 in a list", `{"items":[{"x":1},{"x":1,"extra":1}]}`},
		{"a nested object where a number is expected", `{"version":{"x":1}}`},
		{"a field tagged with a dash", `{"Hidden":"x"}`},
		{"a field tagged with a dash, by its JSON-looking name", `{"-":"x"}`},
		{"the Go name of a tagged field", `{"Version":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name+" is refused", func(t *testing.T) {
			var v reading
			if err := Unmarshal([]byte(tc.in), &v, Options{}); !errors.Is(err, ErrMalformed) {
				t.Errorf("Unmarshal = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("AllowUnknown accepts them, at every depth", func(t *testing.T) {
		in := `{"version":1,"extra":{"deep":[1,{"deeper":2}]},"inner":{"x":7,"extra":1},"ptr":{"x":8,"extra":1},"items":[{"x":9,"extra":1}]}`
		var v reading
		if err := Unmarshal([]byte(in), &v, Options{AllowUnknown: true}); err != nil {
			t.Fatal(err)
		}
		if v.Version != 1 || v.Inner.X != 7 || v.Ptr == nil || v.Ptr.X != 8 || len(v.Items) != 1 || v.Items[0].X != 9 {
			t.Errorf("the known members were not read: %+v", v)
		}
	})
	t.Run("AllowUnknown keeps the other rules", func(t *testing.T) {
		for _, in := range []string{
			`{"extra":1,"extra":2}`,
			`{"extra":{"a":1,"a":2}}`,
			`{"extra":1.5}`,
			`{"extra":null}`,
			`{"extra":"\ud800"}`,
			`{"version":1} x`,
		} {
			var v reading
			if err := Unmarshal([]byte(in), &v, Options{AllowUnknown: true}); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: %v, want ErrMalformed", in, err)
			}
		}
	})
}

func TestMemberNamesAreMatchedExactly(t *testing.T) {
	type lower struct {
		A int `json:"a"`
	}
	type deep struct {
		Wrap struct {
			A int `json:"a"`
		} `json:"wrap"`
		List []lower `json:"list"`
	}
	t.Run("one member in another case", func(t *testing.T) {
		for _, opts := range []Options{{}, {AllowUnknown: true}} {
			var v lower
			err := Unmarshal([]byte(`{"A":1}`), &v, opts)
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("%+v: {\"A\":1} = %v, want ErrMalformed", opts, err)
			}
			if v.A != 0 {
				t.Errorf("%+v: the field was filled from a name in another case", opts)
			}
		}
	})
	t.Run("both cases at once", func(t *testing.T) {
		for _, opts := range []Options{{}, {AllowUnknown: true}} {
			var v lower
			if err := Unmarshal([]byte(`{"a":1,"A":2}`), &v, opts); !errors.Is(err, ErrMalformed) {
				t.Errorf("%+v: {\"a\":1,\"A\":2} = %v, want ErrMalformed", opts, err)
			}
			if err := Unmarshal([]byte(`{"A":2,"a":1}`), &v, opts); !errors.Is(err, ErrMalformed) {
				t.Errorf("%+v: {\"A\":2,\"a\":1} = %v, want ErrMalformed", opts, err)
			}
		}
	})
	t.Run("a mixed-case name", func(t *testing.T) {
		var v lower
		for _, in := range []string{`{"A":1}`, `{"\u0041":1}`} {
			if err := Unmarshal([]byte(in), &v, Options{}); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s = %v, want ErrMalformed", in, err)
			}
		}
	})
	t.Run("at depth 2 and in a list", func(t *testing.T) {
		for _, in := range []string{
			`{"wrap":{"A":1}}`,
			`{"wrap":{"a":1,"A":2}}`,
			`{"list":[{"A":1}]}`,
			`{"list":[{"a":1},{"a":1,"A":1}]}`,
		} {
			for _, opts := range []Options{{}, {AllowUnknown: true}} {
				var v deep
				if err := Unmarshal([]byte(in), &v, opts); !errors.Is(err, ErrMalformed) {
					t.Errorf("%s with %+v = %v, want ErrMalformed", in, opts, err)
				}
			}
		}
	})
	t.Run("an exact name is accepted", func(t *testing.T) {
		var v deep
		if err := Unmarshal([]byte(`{"wrap":{"a":1},"list":[{"a":2}]}`), &v, Options{}); err != nil {
			t.Fatal(err)
		}
		if v.Wrap.A != 1 || len(v.List) != 1 || v.List[0].A != 2 {
			t.Errorf("v = %+v", v)
		}
	})
	t.Run("an untagged field is spelt as in Go", func(t *testing.T) {
		var v reading
		if err := Unmarshal([]byte(`{"plain":1}`), &v, Options{}); !errors.Is(err, ErrMalformed) {
			t.Errorf("{\"plain\":1} = %v, want ErrMalformed", err)
		}
		if err := Unmarshal([]byte(`{"Plain":1}`), &v, Options{}); err != nil {
			t.Errorf("{\"Plain\":1} = %v", err)
		}
	})
}

func TestUnmarshalRefusesWhatIsWrongForTheType(t *testing.T) {
	cases := []struct{ name, in string }{
		{"a string for a number", `{"version":"1"}`},
		{"a number for a string", `{"name":1}`},
		{"an array for an object", `{"inner":[]}`},
		{"a number too large for the field", `{"opt":9223372036854775808}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var v reading
			if err := Unmarshal([]byte(tc.in), &v, Options{}); !errors.Is(err, ErrMalformed) {
				t.Errorf("Unmarshal = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestUnmarshalFillsNothingWhenARuleIsBroken(t *testing.T) {
	for _, in := range []string{
		`{"name":"x","name":"y"}`,
		`{"name":"x","extra":1}`,
		`{"name":"x","version":1.0}`,
		`{"name":"x","tags":{"a":null}}`,
		`{"name":"x"} {}`,
	} {
		var v reading
		if err := Unmarshal([]byte(in), &v, Options{}); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", in, err)
			continue
		}
		if v.Name != "" {
			t.Errorf("%s: the value was filled before the refusal: %+v", in, v)
		}
	}
}

func TestUnmarshalNeedsAPointer(t *testing.T) {
	var nilPtr *reading
	for name, target := range map[string]any{
		"a struct value":  reading{},
		"a nil pointer":   nilPtr,
		"nil":             nil,
		"a map value":     map[string]int{},
		"an integer":      3,
		"a nil interface": any(nil),
	} {
		err := Unmarshal([]byte(`{}`), target, Options{})
		if err == nil {
			t.Errorf("%s: no error", name)
			continue
		}
		if errors.Is(err, ErrMalformed) {
			t.Errorf("%s: a mistake of the caller must not be ErrMalformed: %v", name, err)
		}
	}
	// The input is not even looked at.
	var v reading
	if err := Unmarshal([]byte(`not json`), v, Options{}); err == nil || errors.Is(err, ErrMalformed) {
		t.Errorf("a non-pointer with bad input: %v, want a plain error", err)
	}
}

func TestUnmarshalIntoAMap(t *testing.T) {
	var m map[string]any
	if err := Unmarshal([]byte(`{"a":1,"b":[2]}`), &m, Options{}); err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 {
		t.Errorf("m = %v", m)
	}
	if err := Unmarshal([]byte(`{"a":1,"a":2}`), &m, Options{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("a repeated member into a map: %v", err)
	}
}

func TestErrorsDoNotRepeatTheInput(t *testing.T) {
	long := strings.Repeat("n", 5000)
	secret := "VALUE-THAT-MUST-NOT-APPEAR"
	cases := map[string][]byte{
		"repeated member": []byte(`{"` + long + `":"` + secret + `","` + long + `":1}`),
		"float":           []byte(`{"` + long + `":"` + secret + `","x":1.5}`),
		"trailing":        []byte(`{"` + long + `":"` + secret + `"} ` + secret),
	}
	var v struct{}
	for name, data := range cases {
		for who, err := range map[string]error{
			"Check":     Check(data, 0),
			"Unmarshal": Unmarshal(data, &v, Options{AllowUnknown: true}),
		} {
			if err == nil {
				t.Errorf("%s/%s: no error", name, who)
				continue
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s/%s: the error repeats a value: %.200s", name, who, err)
			}
			if len(err.Error()) > 300 {
				t.Errorf("%s/%s: the error is %d bytes long", name, who, len(err.Error()))
			}
		}
	}
	var r reading
	err := Unmarshal([]byte(`{"`+long+`":1}`), &r, Options{})
	if err == nil || len(err.Error()) > 300 {
		t.Errorf("an unknown member with a long name: %v", err)
	}
}

func TestPeekInt(t *testing.T) {
	big := `{"version":9007199254740991}`
	small := `{"version":-9007199254740991}`
	cases := []struct {
		name string
		in   string
		want int64
		ok   bool
	}{
		{"a plain member", `{"version":3}`, 3, true},
		{"a member among others", `{"a":1,"version":7,"b":2}`, 7, true},
		{"an unknown member next to it", `{"version":3,"unknown":{"x":[1,2]}}`, 3, true},
		{"a file of another version", `{"version":99,"newfield":"x","roots":[{"future":true}]}`, 99, true},
		{"floats elsewhere", `{"version":3,"x":1.5,"y":[2e3]}`, 3, true},
		{"null elsewhere", `{"version":3,"x":null,"y":[null]}`, 3, true},
		{"a repeat elsewhere is not its business", `{"version":3,"x":{"a":1,"a":2}}`, 3, true},
		{"a lone surrogate elsewhere", `{"version":3,"x":"\ud800"}`, 3, true},
		{"zero", `{"version":0}`, 0, true},
		{"minus zero", `{"version":-0}`, 0, true},
		{"a negative number", `{"version":-5}`, -5, true},
		{"the largest integer of the range", big, 9007199254740991, true},
		{"the smallest integer of the range", small, -9007199254740991, true},
		{"white space around", " \n{ \"version\" : 4 }\n ", 4, true},
		{"the name written with an escape", `{"vers\u0069on":8}`, 8, true},
		{"absent", `{"other":1}`, 0, false},
		{"absent in an empty object", `{}`, 0, false},
		{"only a nested member of that name", `{"x":{"version":5}}`, 0, false},
		{"a name in another case", `{"Version":5}`, 0, false},
		{"a longer name", `{"versions":5}`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, ok, err := PeekInt([]byte(tc.in), "version", 0)
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if n != tc.want || ok != tc.ok {
				t.Errorf("PeekInt = %d, %v; want %d, %v", n, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestPeekIntRefuses(t *testing.T) {
	cases := []struct{ name, in string }{
		{"a repeated member", `{"version":1,"version":2}`},
		{"a repeated member with the same value", `{"version":1,"version":1}`},
		{"a repeated member written with an escape", `{"version":1,"vers\u0069on":1}`},
		{"a repeated member not next to the first", `{"version":1,"a":1,"version":2}`},
		{"a number with a point", `{"version":1.0}`},
		{"a number with a fraction", `{"version":1.5}`},
		{"a number with an exponent", `{"version":1e0}`},
		{"a string", `{"version":"1"}`},
		{"null", `{"version":null}`},
		{"true", `{"version":true}`},
		{"an array", `{"version":[1]}`},
		{"an object", `{"version":{"x":1}}`},
		{"an integer above int64", `{"version":9223372036854775808}`},
		{"an integer below int64", `{"version":-9223372036854775809}`},
		{"an integer one above the range", `{"version":9007199254740992}`},
		{"an integer one below the range", `{"version":-9007199254740992}`},
		{"the largest int64", `{"version":9223372036854775807}`},
		{"empty input", ``},
		{"an array at top level", `[1]`},
		{"a number at top level", `1`},
		{"null at top level", `null`},
		{"an array that is closed as an object", `[}`},
		{"a string that is closed as an object", `"}`},
		{"a number that is closed as an object", `1}`},
		{"a byte order mark", "\xef\xbb\xbf{\"version\":1}"},
		{"invalid UTF-8", "{\"version\":1,\"x\":\"\xff\"}"},
		{"text after the object", `{"version":1} x`},
		{"a second object", `{"version":1}{"version":2}`},
		{"a truncated object", `{"version":1`},
		{"a bad grammar after the member", `{"version":1,"x":}`},
		{"a leading zero", `{"version":01}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, ok, err := PeekInt([]byte(tc.in), "version", 0)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("PeekInt = %d, %v, %v; want ErrMalformed", n, ok, err)
			}
			if ok || n != 0 {
				t.Errorf("PeekInt returned %d, %v next to an error", n, ok)
			}
		})
	}
}

func TestPeekIntReadsNothingElseInAFileOfAnotherVersion(t *testing.T) {
	// The reason PeekInt exists: a file of a version the reader does not know can hold anything
	// a later version adds, and its version is still found.
	in := `{"version":2,"later":{"ratio":1.5,"none":null,"list":[0.1,null]},"roots":[{"label":"A","extra":true}]}`
	n, ok, err := PeekInt([]byte(in), "version", 0)
	if err != nil || !ok || n != 2 {
		t.Fatalf("PeekInt = %d, %v, %v", n, ok, err)
	}
	// The strict reader refuses the same file.
	if err := Check([]byte(in), 0); !errors.Is(err, ErrMalformed) {
		t.Errorf("Check accepted the file: %v", err)
	}
	var v struct {
		Version int `json:"version"`
	}
	if err := Unmarshal([]byte(in), &v, Options{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("Unmarshal accepted the file: %v", err)
	}
}

// refusalOf returns the error that each of the three readers gives for data, by the reader's name.
// Unmarshal reads into a struct that takes anything, so that only the rules of the package refuse.
func refusalOf(data string) map[string]error {
	var v struct{}
	_, _, peek := PeekInt([]byte(data), "version", 0)
	return map[string]error{
		"Check":     Check([]byte(data), 0),
		"Unmarshal": Unmarshal([]byte(data), &v, Options{AllowUnknown: true}),
		"PeekInt":   peek,
	}
}

func TestTopLevelThatIsNotAnObject(t *testing.T) {
	// "[}", "\"}" and "1}" end in the closing brace of an object, and the first byte is not its
	// opening brace: the reader must not take that byte for the brace. The other inputs are the
	// ordinary cases of the same check. Every reader gives the one text.
	const want = "malformed JSON: $: not one JSON object"
	for _, in := range []string{
		`[}`, `"}`, `1}`, `x}`, `}`, `]`, `[]`, `[{}]`, `"x"`, `1`, `-1`, `null`, `true`, `false`, ``, " \n\t",
		` [}`, "\n\"}", "\t1}", `[}` + "\n",
		// A byte order mark that is not the very first bytes is not a byte order mark.
		" \xef\xbb\xbf{}",
	} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			for name, err := range refusalOf(in) {
				if !errors.Is(err, ErrMalformed) {
					t.Errorf("%s = %v, want ErrMalformed", name, err)
				} else if err.Error() != want {
					t.Errorf("%s = %q, want %q", name, err, want)
				}
			}
		})
	}
}

func TestAnObjectAfterWhiteSpaceIsNotRefusedAsATopLevelMistake(t *testing.T) {
	for _, in := range []string{`{}`, " {}", "\n\t\r {}", "{} ", "\r\n{ }\n"} {
		for name, err := range refusalOf(in) {
			if err != nil {
				t.Errorf("%s refused %q: %v", name, in, err)
			}
		}
	}
}

func TestByteOrderMark(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	const want = "malformed JSON: $: starts with a byte order mark"
	for _, in := range []string{
		bom + `{}`,
		bom + `{"version":1}`,
		bom + " \n{}",
		bom,
		bom + `[]`,
		bom + `x`,
		bom + "\xff", // not UTF-8 either: the mark is what is reported
		bom + bom + `{}`,
	} {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			for name, err := range refusalOf(in) {
				if !errors.Is(err, ErrMalformed) {
					t.Errorf("%s = %v, want ErrMalformed", name, err)
				} else if err.Error() != want {
					t.Errorf("%s = %q, want %q", name, err, want)
				}
			}
		})
	}
	t.Run("the mark inside a string is text", func(t *testing.T) {
		// U+FEFF built from its code point, not written out.
		in := `{"a":"` + string(rune(0xFEFF)) + `","` + string(rune(0xFEFF)) + `":1}`
		for name, err := range refusalOf(in) {
			if err != nil {
				t.Errorf("%s refused U+FEFF inside a string: %v", name, err)
			}
		}
	})
	t.Run("the mark after the object is text after the object", func(t *testing.T) {
		for name, err := range refusalOf("{}" + bom) {
			if !errors.Is(err, ErrMalformed) || strings.Contains(err.Error(), "byte order mark") {
				t.Errorf("%s = %v, want the refusal of text after the object", name, err)
			}
		}
	})
}

func TestPeekIntMemberThatIsNotAnInteger(t *testing.T) {
	// A member that is there but is not an integer that fits int64 is refused with the text that
	// says which of the two it is: not an integer at all, or an integer too large.
	const notInt = `malformed JSON: $.version: not an integer`
	const twice = `malformed JSON: $.version: the member appears twice`
	tooBig := func(digits string) string { return "malformed JSON: $.version: " + outside(digits) }
	cases := []struct{ name, in, want string }{
		{"a fraction", `{"version":1.5}`, notInt},
		{"a fraction of zero", `{"version":1.0}`, notInt},
		{"a negative fraction", `{"version":-0.5}`, notInt},
		{"minus zero with a fraction", `{"version":-0.0}`, notInt},
		{"an exponent", `{"version":1e0}`, notInt},
		{"an exponent in capitals", `{"version":1E2}`, notInt},
		{"a signed exponent", `{"version":2e-1}`, notInt},
		{"a fraction and an exponent", `{"version":1.5e3}`, notInt},
		{"zero with an exponent", `{"version":0e0}`, notInt},
		{"an exponent that is huge", `{"version":1e99999}`, notInt},
		{"a string", `{"version":"1"}`, notInt},
		{"an empty string", `{"version":""}`, notInt},
		{"null", `{"version":null}`, notInt},
		{"true", `{"version":true}`, notInt},
		{"false", `{"version":false}`, notInt},
		{"an array", `{"version":[1]}`, notInt},
		{"an empty array", `{"version":[]}`, notInt},
		{"an object", `{"version":{"x":1}}`, notInt},
		{"an empty object", `{"version":{}}`, notInt},
		{"a fraction among other members", `{"a":1,"version":1.5,"b":2}`, notInt},
		{"an integer one above int64", `{"version":9223372036854775808}`, tooBig("9223372036854775808")},
		{"an integer one below int64", `{"version":-9223372036854775809}`, tooBig("-9223372036854775809")},
		{"a huge integer", `{"version":99999999999999999999999999999999}`, tooBig("99999999999999999999999999999999")},
		{"one above the range", `{"version":9007199254740992}`, tooBig("9007199254740992")},
		{"one below the range", `{"version":-9007199254740992}`, tooBig("-9007199254740992")},
		{"the largest int64", `{"version":9223372036854775807}`, tooBig("9223372036854775807")},
		{"a number of 200000 digits", `{"version":` + repeat("9", 200000) + `}`, tooBig(repeat("9", 200000))},
		{"a repeated member", `{"version":1,"version":2}`, twice},
		{"a repeated member, a fraction the second time", `{"version":1,"version":1.5}`, twice},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, ok, err := PeekInt([]byte(tc.in), "version", 0)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("PeekInt = %d, %v, %v; want ErrMalformed", n, ok, err)
			}
			if err.Error() != tc.want {
				t.Errorf("err = %q, want %q", err, tc.want)
			}
			if ok || n != 0 {
				t.Errorf("PeekInt returned %d, %v next to an error", n, ok)
			}
		})
	}
	t.Run("the name in the error is the one asked for", func(t *testing.T) {
		_, _, err := PeekInt([]byte(`{"v2":1.5}`), "v2", 0)
		if want := `malformed JSON: $.v2: not an integer`; err == nil || err.Error() != want {
			t.Errorf("err = %v, want %q", err, want)
		}
	})
	t.Run("a member that is not asked for may be anything", func(t *testing.T) {
		for _, in := range []string{`{"other":1.5,"version":1}`, `{"other":"1","version":1}`, `{"other":[1.5,null],"version":1}`} {
			if n, ok, err := PeekInt([]byte(in), "version", 0); err != nil || !ok || n != 1 {
				t.Errorf("%s: PeekInt = %d, %v, %v", in, n, ok, err)
			}
		}
	})
}

func TestTextsOfTheRefusals(t *testing.T) {
	// One refusal of each early kind, with the text a person reads. The byte, where the text
	// has one, is where the reader stopped. Check, Unmarshal and PeekInt agree on those that
	// all three apply; the strict rules (a fraction, null, a repeated member, a lone surrogate,
	// text after the object) are Check's and Unmarshal's.
	big := string(padded(t, DefaultMaxBytes+1))
	both := []struct{ name, in, want string }{
		{"too long", big, "malformed JSON: $: longer than 262144 bytes"},
		{"a byte order mark", "\xef\xbb\xbf{}", "malformed JSON: $: starts with a byte order mark"},
		{"not UTF-8", "{\"a\":\"\xff\"}", "malformed JSON: $: not valid UTF-8"},
		{"not an object", `[]`, "malformed JSON: $: not one JSON object"},
		{"nesting", string(nested(MaxDepth + 1)), fmt.Sprintf("malformed JSON: $....a.a.a.a.a.a.a.a: nesting deeper than %d levels at byte %d", MaxDepth, 5*MaxDepth)},
		{"a missing colon", `{"a" 1}`, "malformed JSON: $: a colon was expected at byte 5"},
		{"text after the object", `{} x`, "malformed JSON: $: anything after the object at byte 3"},
		{"the input ends in an object", `{"a":1`, "malformed JSON: $: the input ends inside an object at byte 6"},
	}
	for _, tc := range both {
		t.Run(tc.name, func(t *testing.T) {
			for name, err := range refusalOf(tc.in) {
				if err == nil || err.Error() != tc.want {
					t.Errorf("%s = %v, want %q", name, err, tc.want)
				}
			}
		})
	}
	strict := []struct{ name, in, want string }{
		{"a fraction", `{"a":1.5}`, "malformed JSON: $.a: a number with a fraction or an exponent at byte 8"},
		{"an exponent", `{"a":1e2}`, "malformed JSON: $.a: a number with a fraction or an exponent at byte 8"},
		{"an integer above int64", `{"a":9223372036854775808}`, "malformed JSON: $.a: " + outside("9223372036854775808") + " at byte 24"},
		{"null", `{"a":null}`, "malformed JSON: $.a: null at byte 9"},
		{"a repeated member", `{"a":1,"a":2}`, "malformed JSON: $.a: the member appears twice at byte 10"},
		{"a lone surrogate", `{"a":"` + `\` + `ud800"}`, "malformed JSON: $.a: a lone surrogate escape at byte 12"},
	}
	for _, tc := range strict {
		t.Run(tc.name, func(t *testing.T) {
			var v struct{}
			for name, err := range map[string]error{
				"Check":     Check([]byte(tc.in), 0),
				"Unmarshal": Unmarshal([]byte(tc.in), &v, Options{AllowUnknown: true}),
			} {
				if err == nil || err.Error() != tc.want {
					t.Errorf("%s = %v, want %q", name, err, tc.want)
				}
			}
		})
	}
}
