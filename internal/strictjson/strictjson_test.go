package strictjson

import (
	"errors"
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
	{"largest int64", `{"a":9223372036854775807}`},
	{"smallest int64", `{"a":-9223372036854775808}`},
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
		if _, ok, err := PeekInt(data, "absent"); err != nil || ok {
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
	_, _, err := PeekInt(data, "absent")
	return err
}

func TestNestingDepth(t *testing.T) {
	const limit = 10000 // the total depth, the top-level object included
	var v struct{}
	cases := []struct {
		name string
		data []byte
		ok   bool
	}{
		{"objects at the limit", nested(limit), true},
		{"objects one over", nested(limit + 1), false},
		{"objects far over", nested(100000), false},
		{"arrays at the limit", nestedArrays(limit), true},
		{"arrays one over", nestedArrays(limit + 1), false},
		// An input that is as deep as its size allows and never closes: no stack fault, an error.
		{"256 KiB of open brackets", []byte(`{"a":` + strings.Repeat(`[`, 262144-5)), false},
		{"256 KiB of open objects", []byte(strings.Repeat(`{"a":`, 262144/5)), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
				}
			}
		})
	}
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

// Base is embedded without a name, so its members belong to the outer object.
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
	// A missing member is the caller's to check: the field keeps its value.
	pre := reading{Version: 9}
	if err := Unmarshal([]byte(`{"name":"m"}`), &pre, Options{}); err != nil {
		t.Fatal(err)
	}
	if pre.Version != 9 || pre.Name != "m" {
		t.Errorf("a missing member changed the value: %+v", pre)
	}
}

func TestUnmarshalFillsAnEmbeddedStruct(t *testing.T) {
	var v withEmbedded
	if err := Unmarshal([]byte(`{"base":1,"own":2}`), &v, Options{}); err != nil {
		t.Fatal(err)
	}
	if v.B != 1 || v.Own != 2 {
		t.Errorf("v = %+v", v)
	}
	if err := Unmarshal([]byte(`{"base":1,"own":2,"extra":3}`), &withEmbedded{}, Options{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("an unknown member next to an embedded struct: %v", err)
	}
	if err := Unmarshal([]byte(`{"Base":1}`), &withEmbedded{}, Options{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("the name of an embedded struct is not a member: %v", err)
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
	big := `{"version":9223372036854775807}`
	small := `{"version":-9223372036854775808}`
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
		{"the largest int64", big, 9223372036854775807, true},
		{"the smallest int64", small, -9223372036854775808, true},
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
			n, ok, err := PeekInt([]byte(tc.in), "version")
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
		{"empty input", ``},
		{"an array at top level", `[1]`},
		{"a number at top level", `1`},
		{"null at top level", `null`},
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
			n, ok, err := PeekInt([]byte(tc.in), "version")
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
	n, ok, err := PeekInt([]byte(in), "version")
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
