package strictjson

import (
	"testing"
)

// A member that appears twice is reported at the member's own path: "$.a: the member appears twice
// at byte N", where N is the byte after the second name. The texts are written out whole here (the
// byte counted by hand), so that the rule of a helper is not the only witness. No JSON escape of the
// form backslash, u and four digits is written out: bs and the hex digits are put together.

func TestARepeatedMemberIsReportedAtItsOwnPathInFull(t *testing.T) {
	type holder struct {
		O struct {
			A int `json:"a"`
		} `json:"o"`
		L []map[string]int `json:"l"`
		R Raw              `json:"r"`
		M map[string]int   `json:"m"`
		A int              `json:"a"`
	}
	a61 := bs + "u0061"
	cases := []struct {
		name, doc, want string
	}{
		{"at the top", `{"a":1,"a":2}`, "malformed JSON: $.a: the member appears twice at byte 10"},
		{"at the top, not next to the first", `{"x":1,"b":2,"a":3,"a":4}`, "malformed JSON: $.a: the member appears twice at byte 22"},
		{"the second written with an escape", `{"a":1,"` + a61 + `":2}`, "malformed JSON: $.a: the member appears twice at byte 15"},
		{"the first written with an escape", `{"` + a61 + `":1,"a":2}`, "malformed JSON: $.a: the member appears twice at byte 15"},
		{"both written with an escape", `{"` + a61 + `":1,"` + a61 + `":2}`, "malformed JSON: $.a: the member appears twice at byte 20"},
		{"in a nested object", `{"o":{"a":1,"a":2}}`, "malformed JSON: $.o.a: the member appears twice at byte 15"},
		{"in an element of a list", `{"l":[{"x":1},{"a":1,"a":2}]}`, "malformed JSON: $.l[1].a: the member appears twice at byte 24"},
		{"inside a Raw", `{"r":{"a":1,"a":2}}`, "malformed JSON: $.r.a: the member appears twice at byte 15"},
		{"in a map", `{"m":{"k":1,"k":2}}`, "malformed JSON: $.m.k: the member appears twice at byte 15"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, opts := range []Options{{}, {AllowUnknown: true}} {
				var h holder
				fail(t, Unmarshal([]byte(tc.doc), &h, opts), tc.want)
				var m map[string]any
				fail(t, Unmarshal([]byte(tc.doc), &m, opts), tc.want)
			}
			fail(t, Check([]byte(tc.doc), 0), tc.want)
			if _, err := Parse([]byte(tc.doc), 0); err == nil || err.Error() != tc.want {
				t.Errorf("Parse: %v", err)
			}
		})
	}
	t.Run("a name that is not plain is quoted in the path", func(t *testing.T) {
		e9 := string(rune(0xe9))
		doc := `{"` + e9 + `":1,"` + bs + `u00e9":2}`
		want := `malformed JSON: $."` + bs + `u00e9": the member appears twice at byte 16`
		fail(t, Check([]byte(doc), 0), want)
		var m map[string]int
		fail(t, Unmarshal([]byte(doc), &m, Options{}), want)
		// An emoji, written as the character and as the pair of escapes.
		doc = `{"` + string(rune(0x1F600)) + `":1,"` + bs + `ud83d` + bs + `ude00":2}`
		fail(t, Check([]byte(doc), 0), `malformed JSON: $."`+bs+`ud83d`+bs+`ude00": the member appears twice at byte 24`)
		// The empty name.
		fail(t, Check([]byte(`{"":1,"":2}`), 0), `malformed JSON: $."": the member appears twice at byte 8`)
	})
	t.Run("the same name in two objects is not a repeat", func(t *testing.T) {
		if err := Check([]byte(`{"a":{"a":1},"b":{"a":2},"c":[{"a":1},{"a":2}]}`), 0); err != nil {
			t.Error(err)
		}
	})
}

func TestPeekIntReportsARepeatedMemberAtItsOwnPath(t *testing.T) {
	v61 := bs + "u0076" // v
	for _, tc := range []struct{ name, doc string }{
		{"plain", `{"version":1,"version":2}`},
		{"the second with an escape", `{"version":1,"` + v61 + `ersion":2}`},
		{"the first with an escape", `{"` + v61 + `ersion":1,"version":2}`},
		{"not next to the first", `{"version":1,"other":3,"version":2}`},
		{"the second a fraction", `{"version":1,"version":1.5}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, ok, err := PeekInt([]byte(tc.doc), "version")
			if want := "malformed JSON: $.version: the member appears twice"; err == nil || err.Error() != want || ok || n != 0 {
				t.Errorf("PeekInt = %d, %v, %v; want %s", n, ok, err, want)
			}
		})
	}
	t.Run("a member that is repeated and is not the one asked for is not its business", func(t *testing.T) {
		n, ok, err := PeekInt([]byte(`{"a":1,"a":2,"version":7}`), "version")
		if err != nil || !ok || n != 7 {
			t.Errorf("%d, %v, %v", n, ok, err)
		}
	})
	t.Run("the name asked for in a path that is not plain", func(t *testing.T) {
		_, _, err := PeekInt([]byte(`{"a b":1,"a b":2}`), "a b")
		if want := `malformed JSON: $."a b": the member appears twice`; err == nil || err.Error() != want {
			t.Errorf("%v; want %s", err, want)
		}
	})
}

func TestTheListsOfAnArrayAreCountedInWords(t *testing.T) {
	cases := []struct {
		name string
		typ  any
		doc  string
		want string
	}{
		{"one element for three", &struct{ A [3]int }{}, `{"A":[1]}`, "malformed JSON: $.A: the list has 1 element, and the array of type [3]int holds exactly 3"},
		{"two elements for three", &struct{ A [3]int }{}, `{"A":[1,2]}`, "malformed JSON: $.A: the list has 2 elements, and the array of type [3]int holds exactly 3"},
		{"no elements for three", &struct{ A [3]int }{}, `{"A":[]}`, "malformed JSON: $.A: the list has 0 elements, and the array of type [3]int holds exactly 3"},
		{"four elements for three", &struct{ A [3]int }{}, `{"A":[1,2,3,4]}`, "malformed JSON: $.A: the list has 4 elements, and the array of type [3]int holds exactly 3"},
		{"eleven elements for two", &struct{ A [2]int }{}, `{"A":[1,2,3,4,5,6,7,8,9,10,11]}`, "malformed JSON: $.A: the list has 11 elements, and the array of type [2]int holds exactly 2"},
		{"one element for none", &struct{ A [0]int }{}, `{"A":[1]}`, "malformed JSON: $.A: the list has 1 element, and the array of type [0]int holds exactly 0"},
		{"two elements for one", &struct{ A [1]int }{}, `{"A":[1,2]}`, "malformed JSON: $.A: the list has 2 elements, and the array of type [1]int holds exactly 1"},
		{"one element for two, in a list", &struct{ L [][2]int }{}, `{"L":[[1,2],[3]]}`, "malformed JSON: $.L[1]: the list has 1 element, and the array of type [2]int holds exactly 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fail(t, Unmarshal([]byte(tc.doc), tc.typ, Options{}), tc.want)
		})
	}
}
