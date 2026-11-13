package strictjson

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// An integer in a record is within -(2^53-1) to 2^53-1. The reader refuses anything outside it at the
// place where the number is read, whatever the Go type of the destination: int64, uint64, int,
// any, and a field, a list element or a map value of them, a member that is skipped, and a Raw.

// outsideNumbers are integers outside the range, as text. The first two are the first ones outside;
// 2^63-1 and -2^63 are the edges of int64, 2^64-1 the largest uint64, and the long ones are of more
// than 64 bits.
func outsideNumbers() []string {
	return []string{
		"9007199254740992", "-9007199254740992", "9007199254740993", "-9007199254740993",
		"9223372036854775807", "-9223372036854775808", "9223372036854775808", "-9223372036854775809",
		"18446744073709551615", "18446744073709551616", "99999999999999999999999999999999",
		"-" + repeat("9", 400), repeat("1", 200000), "-" + repeat("9", 200000),
	}
}

func TestTheRangeOfAnIntegerAtItsEdgesInEveryPlace(t *testing.T) {
	type holder struct {
		I   int64            `json:"i"`
		U   uint64           `json:"u"`
		N   int              `json:"n"`
		A   any              `json:"a"`
		L   []int64          `json:"l"`
		M   map[string]int64 `json:"m"`
		Raw Raw              `json:"r"`
	}
	// The two edges are read, in every place.
	for _, edge := range []string{safeMaxText, safeMinText} {
		doc := `{"i":` + edge + `,"n":` + edge + `,"a":` + edge + `,"l":[` + edge + `],"m":{"k":` + edge + `},"r":{"x":` + edge + `}}`
		var h holder
		if err := Unmarshal([]byte(doc), &h, Options{}); err != nil {
			t.Errorf("%s: %v", edge, err)
			continue
		}
		want := safeMax
		if edge == safeMinText {
			want = safeMin
		}
		if h.I != want || int64(h.N) != want || h.A != want || h.L[0] != want || h.M["k"] != want || string(h.Raw) != `{"x":`+edge+`}` {
			t.Errorf("%s: %+v", edge, h)
		}
		if err := Check([]byte(doc), 0); err != nil {
			t.Errorf("Check refused %s: %v", edge, err)
		}
		if _, err := Parse([]byte(doc), 0); err != nil {
			t.Errorf("Parse refused %s: %v", edge, err)
		}
		if n, ok, err := PeekInt([]byte(`{"version":`+edge+`}`), "version", 0); err != nil || !ok || n != want {
			t.Errorf("PeekInt %s: %d %v %v", edge, n, ok, err)
		}
	}
	var u holder
	if err := Unmarshal([]byte(`{"u":`+safeMaxText+`}`), &u, Options{}); err != nil || u.U != uint64(safeMax) {
		t.Errorf("uint64 at the edge: %d, %v", u.U, err)
	}
	for _, n := range outsideNumbers() {
		name := n
		if len(name) > 30 {
			name = name[:30] + "..."
		}
		t.Run(name, func(t *testing.T) {
			want := outside(n)
			// The text is bounded: a number of 200000 digits does not make an error of 200000 bytes.
			if len(want) > 200 {
				t.Fatalf("the test's own text is %d bytes", len(want))
			}
			cases := []struct {
				place, doc, path string
				v                any
			}{
				{"an int64 field", `{"i":` + n + `}`, "$.i", &holder{}},
				{"a uint64 field", `{"u":` + n + `}`, "$.u", &holder{}},
				{"an int field", `{"n":` + n + `}`, "$.n", &holder{}},
				{"an any field", `{"a":` + n + `}`, "$.a", &holder{}},
				{"a list element", `{"l":[1,` + n + `]}`, "$.l[1]", &holder{}},
				{"a map value", `{"m":{"k":` + n + `}}`, "$.m.k", &holder{}},
				{"inside a Raw", `{"r":{"x":` + n + `}}`, "$.r.x", &holder{}},
				{"a member of a map of any", `{"a":` + n + `}`, "$.a", &map[string]any{}},
				{"a member that nothing declares", `{"zz":` + n + `}`, "$.zz", &holder{}},
				{"a member inside a member that nothing declares", `{"zz":{"y":[` + n + `]}}`, "$.zz.y[0]", &holder{}},
			}
			for _, tc := range cases {
				for _, opts := range []Options{{}, {AllowUnknown: true}} {
					err := Unmarshal([]byte(tc.doc), tc.v, opts)
					fail(t, err, mal(tc.path, want+byteAfter(tc.doc, n)))
				}
				fail(t, Check([]byte(tc.doc), 0), mal(tc.path, want+byteAfter(tc.doc, n)))
				if _, err := Parse([]byte(tc.doc), 0); err == nil || err.Error() != mal(tc.path, want+byteAfter(tc.doc, n)) {
					t.Errorf("%s: Parse: %v", tc.place, err)
				}
			}
			// PeekInt refuses it at the member, with no byte.
			doc := `{"version":` + n + `}`
			got, ok, err := PeekInt([]byte(doc), "version", 0)
			if !errors.Is(err, ErrMalformed) || err.Error() != mal("$.version", want) || ok || got != 0 {
				t.Errorf("PeekInt = %d, %v, %v; want the refusal %q", got, ok, err, mal("$.version", want))
			}
			// A number that is not the member that is asked for is not PeekInt's business.
			if n2, ok, err := PeekInt([]byte(`{"other":`+n+`,"version":3}`), "version", 0); err != nil && len(n) < 100000 {
				t.Errorf("a number elsewhere: %d %v %v", n2, ok, err)
			}
		})
	}
	t.Run("the text of a long number is cut at 40 characters", func(t *testing.T) {
		n := repeat("7", 41)
		doc := `{"a":` + n + `}`
		fail(t, Check([]byte(doc), 0), mal("$.a", "the integer "+repeat("7", 40)+"... "+rangeWords+byteAfter(doc, n)))
		n = repeat("7", 40)
		doc = `{"a":` + n + `}`
		fail(t, Check([]byte(doc), 0), mal("$.a", "the integer "+n+" "+rangeWords+byteAfter(doc, n)))
		n = "-" + repeat("7", 39)
		doc = `{"a":` + n + `}`
		fail(t, Check([]byte(doc), 0), mal("$.a", "the integer "+n+" "+rangeWords+byteAfter(doc, n)))
		n = "-" + repeat("7", 40)
		doc = `{"a":` + n + `}`
		fail(t, Check([]byte(doc), 0), mal("$.a", "the integer -"+repeat("7", 39)+"... "+rangeWords+byteAfter(doc, n)))
	})
	t.Run("a refusal that the range gives is the first, before the type is looked at", func(t *testing.T) {
		// A uint8 field with 300 is "does not fit the type" (300 is inside the range); with 2^53 it is
		// the range that refuses, not the type.
		var v struct {
			B uint8 `json:"b"`
		}
		fail(t, Unmarshal([]byte(`{"b":300}`), &v, Options{}), mal("$.b", "the integer 300 does not fit the type uint8"))
		fail(t, Unmarshal([]byte(`{"b":9007199254740992}`), &v, Options{}), mal("$.b", outside("9007199254740992")+" at byte 21"))
		fail(t, Unmarshal([]byte(`{"b":-1}`), &v, Options{}), mal("$.b", "the integer -1 does not fit the type uint8"))
	})
	t.Run("minus zero and the integers next to the edges are read", func(t *testing.T) {
		for _, in := range []string{"0", "-0", "1", "-1", "9007199254740990", "-9007199254740990", safeMaxText, safeMinText} {
			if err := Check([]byte(`{"a":`+in+`}`), 0); err != nil {
				t.Errorf("%s: %v", in, err)
			}
		}
	})
	t.Run("what is no integer is refused as before, not for the range", func(t *testing.T) {
		for _, in := range []string{"9007199254740992.0", "9007199254740992e0", "1e400"} {
			err := Check([]byte(`{"a":`+in+`}`), 0)
			if err == nil || strings.Contains(err.Error(), "outside the range") {
				t.Errorf("%s: %v", in, err)
			}
		}
	})
}

// PeekInt takes the largest input as a third argument, as Check does: 0 means DefaultMaxBytes, and
// so does a negative number (limit treats both so).
func TestPeekIntTakesTheSizeLimit(t *testing.T) {
	// A document of exactly n bytes: {"version":1,"p":"xxx..."}.
	doc := func(n int) []byte {
		head := `{"version":1,"p":"`
		pad := n - len(head) - len(`"}`)
		return []byte(head + strings.Repeat("x", pad) + `"}`)
	}
	tooLong := func(limit int) string { return mal("$", "longer than "+strconv.Itoa(limit)+" bytes") }
	t.Run("zero is the default", func(t *testing.T) {
		if n, ok, err := PeekInt(doc(DefaultMaxBytes), "version", 0); err != nil || !ok || n != 1 {
			t.Errorf("at the default: %d %v %v", n, ok, err)
		}
		_, _, err := PeekInt(doc(DefaultMaxBytes+1), "version", 0)
		fail(t, err, tooLong(DefaultMaxBytes))
	})
	t.Run("a negative limit is the default too", func(t *testing.T) {
		for _, lim := range []int{-1, -1 << 30} {
			if n, ok, err := PeekInt(doc(DefaultMaxBytes), "version", lim); err != nil || !ok || n != 1 {
				t.Errorf("limit %d at the default: %d %v %v", lim, n, ok, err)
			}
			_, _, err := PeekInt(doc(DefaultMaxBytes+1), "version", lim)
			fail(t, err, tooLong(DefaultMaxBytes))
		}
	})
	t.Run("a limit of its own", func(t *testing.T) {
		for _, lim := range []int{100, 1000, 4096} {
			if n, ok, err := PeekInt(doc(lim), "version", lim); err != nil || !ok || n != 1 {
				t.Errorf("limit %d, a document of %d bytes: %d %v %v", lim, lim, n, ok, err)
			}
			_, _, err := PeekInt(doc(lim+1), "version", lim)
			fail(t, err, tooLong(lim))
		}
	})
	t.Run("a larger limit takes a larger document", func(t *testing.T) {
		big := doc(DefaultMaxBytes + 10)
		if n, ok, err := PeekInt(big, "version", DefaultMaxBytes+10); err != nil || !ok || n != 1 {
			t.Errorf("%d %v %v", n, ok, err)
		}
		_, _, err := PeekInt(big, "version", DefaultMaxBytes+9)
		fail(t, err, tooLong(DefaultMaxBytes+9))
	})
	t.Run("a document over the limit is refused before any work, the member or not", func(t *testing.T) {
		// Not valid JSON after the limit: the size is the first refusal.
		in := append([]byte(`{"version":1,"p":"`), []byte(strings.Repeat("\xff", 200))...)
		_, _, err := PeekInt(in, "version", 50)
		fail(t, err, tooLong(50))
		_, _, err = PeekInt(in, "absent", 50)
		fail(t, err, tooLong(50))
	})
	t.Run("PeekInt and Check refuse the same size", func(t *testing.T) {
		for _, lim := range []int{0, 64, 1000} {
			eff := lim
			if eff == 0 {
				eff = DefaultMaxBytes
			}
			over := doc(eff + 1)
			_, _, perr := PeekInt(over, "version", lim)
			cerr := Check(over, lim)
			if perr == nil || cerr == nil || perr.Error() != cerr.Error() {
				t.Errorf("limit %d: PeekInt %v, Check %v", lim, perr, cerr)
			}
		}
	})
}

// A number that overflows 64 bits is refused by the range, with no test of its own for the
// overflow: ParseInt saturates at the int64 limit, which is outside the range. The cases are the
// ones that overflow by one digit and by many, and by exactly one, in both signs, in every reader.
func TestANumberThatOverflowsSixtyFourBitsIsRefusedAsOutsideTheRange(t *testing.T) {
	for _, n := range []string{
		"9223372036854775808",                  // 2^63, one above int64
		"-9223372036854775809",                 // one below
		"9223372036854775807" + "0",            // one digit more than int64 holds
		"-9223372036854775808" + "0",           // the same, negative
		"92233720368547758070",                 // 20 digits
		"18446744073709551616",                 // 2^64
		"-18446744073709551616",                // -2^64
		"1" + repeat("0", 19),                  // 10^19, one digit more than 2^63
		"1" + repeat("0", 25),                  // many digits more
		repeat("9", 64), "-" + repeat("9", 64), // two words of digits
		repeat("9", 1000), "-" + repeat("9", 1000), // many
	} {
		want := outside(n)
		doc := `{"a":` + n + `}`
		fail(t, Check([]byte(doc), 0), mal("$.a", want+byteAfter(doc, n)))
		var v struct {
			A int64 `json:"a"`
		}
		fail(t, Unmarshal([]byte(doc), &v, Options{}), mal("$.a", want+byteAfter(doc, n)))
		var u struct {
			A uint64 `json:"a"`
		}
		fail(t, Unmarshal([]byte(doc), &u, Options{}), mal("$.a", want+byteAfter(doc, n)))
		var m map[string]any
		fail(t, Unmarshal([]byte(doc), &m, Options{}), mal("$.a", want+byteAfter(doc, n)))
		_, _, perr := PeekInt([]byte(`{"version":`+n+`}`), "version", 0)
		fail(t, perr, mal("$.version", want))
	}
}
