package canonjson

import (
	"errors"
	"math/rand"
	"strconv"
	"testing"

	"ritueel.id/ritueel/internal/strictjson"
)

// An integer in a record is within -(2^53-1) to 2^53-1. The reader refuses what is outside, for
// Canonicalize, IsCanonical and a Raw too; the writer refuses it for every integer kind that can
// hold one. Inside the range the writer's bytes are those of a float64 formatter, which is what RFC
// 8785 asks for, so the two can never disagree.

func TestCanonicalizeAndIsCanonicalRefuseAnIntegerOutsideTheRange(t *testing.T) {
	for _, edge := range []string{safeMaxText, safeMinText} {
		doc := `{"a":` + edge + `,"b":[` + edge + `]}`
		got, err := Canonicalize([]byte(doc))
		if err != nil || string(got) != doc {
			t.Errorf("%s: %q, %v", edge, got, err)
		}
		if ok, err := IsCanonical([]byte(doc)); err != nil || !ok {
			t.Errorf("IsCanonical(%s) = %v, %v", doc, ok, err)
		}
	}
	for _, n := range []string{
		"9007199254740992", "-9007199254740992", "9007199254740993", "9223372036854775807", "-9223372036854775808",
		"18446744073709551615", "99999999999999999999999999999999", "-" + repeat("9", 400), repeat("1", 200000),
	} {
		name := n
		if len(name) > 30 {
			name = name[:30] + "..."
		}
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct{ place, doc, path string }{
				{"a member", `{"a":` + n + `}`, "$.a"},
				{"a list element", `{"a":[0,` + n + `]}`, "$.a[1]"},
				{"a nested member", `{"a":{"b":{"c":` + n + `}}}`, "$.a.b.c"},
				{"white space around", " {\n\"a\" :\t" + n + " \n}", "$.a"},
			} {
				want := mal(tc.path, outside(n)+byteIn(tc.doc, n))
				got, err := Canonicalize([]byte(tc.doc))
				if err == nil || err.Error() != want || got != nil {
					t.Errorf("%s: Canonicalize = %q, %v; want %s", tc.place, got, err, want)
				}
				ok, err := IsCanonical([]byte(tc.doc))
				if err == nil || err.Error() != want || ok {
					t.Errorf("%s: IsCanonical = %v, %v; want false and %s", tc.place, ok, err, want)
				}
				if len(want) > 300 {
					t.Errorf("the text is %d bytes for a number of %d", len(want), len(n))
				}
			}
		})
	}
	t.Run("the record of the security member is not canonical any more", func(t *testing.T) {
		in := `{"a":9007199254740993}`
		ok, err := IsCanonical([]byte(in))
		if ok || err == nil || !errors.Is(err, strictjson.ErrMalformed) || err.Error() != mal("$.a", outside("9007199254740993")+" at byte 21") {
			t.Errorf("IsCanonical = %v, %v", ok, err)
		}
	})
}

func mal(path, what string) string { return "malformed JSON: " + path + ": " + what }

// byteIn is " at byte N" for the byte after the first use of the token in the document.
func byteIn(doc, token string) string {
	for i := 0; i+len(token) <= len(doc); i++ {
		if doc[i:i+len(token)] == token {
			return " at byte " + strconv.Itoa(i+len(token))
		}
	}
	panic("the token is not in the document")
}

func TestARawWithAnIntegerOutsideTheRangeIsRefusedByMarshal(t *testing.T) {
	type doc struct {
		R Raw `json:"r"`
	}
	for _, n := range []string{"9007199254740992", "-9007199254740992", "9223372036854775807", "18446744073709551615"} {
		in := `{"a":[` + n + `]}`
		want := mal("$.r.a[0]", outside(n)+byteIn(in, n))
		got, err := Marshal(doc{R: Raw(in)})
		if err == nil || err.Error() != want || got != nil {
			t.Errorf("%s: %q, %v; want %s", n, got, err, want)
		}
		want = mal("$.a[0]", outside(n)+byteIn(in, n))
		got, err = Marshal(Raw(in))
		if err == nil || err.Error() != want || got != nil {
			t.Errorf("%s at the top: %q, %v; want %s", n, got, err, want)
		}
	}
	got, err := Marshal(doc{R: Raw(`{"a":[` + safeMaxText + `,` + safeMinText + `]}`)})
	if want := `{"r":{"a":[9007199254740991,-9007199254740991]}}`; err != nil || string(got) != want {
		t.Errorf("the edges: %q, %v", got, err)
	}
}

// Marshal refuses an integer outside the range for every kind that can hold one, in every place, and
// writes the edges.
func TestMarshalRefusesAnIntegerOutsideTheRangeForEveryKind(t *testing.T) {
	type (
		namedInt  int
		namedI64  int64
		namedUint uint
		namedU64  uint64
	)
	cases := []struct {
		name string
		v    any
		typ  string
		text string
	}{
		{"int, one above", int(safeMax) + 1, "int", "9007199254740992"},
		{"int, one below", int(safeMin) - 1, "int", "-9007199254740992"},
		{"int, the largest", int(^uint(0) >> 1), "int", "9223372036854775807"},
		{"int, the smallest", -int(^uint(0)>>1) - 1, "int", "-9223372036854775808"},
		{"int64, one above", int64(safeMax) + 1, "int64", "9007199254740992"},
		{"int64, one below", int64(safeMin) - 1, "int64", "-9007199254740992"},
		{"int64, 2^53+1", int64(1)<<53 + 1, "int64", "9007199254740993"},
		{"int64, the largest", int64(1<<63 - 1), "int64", "9223372036854775807"},
		{"int64, the smallest", int64(-1 << 63), "int64", "-9223372036854775808"},
		{"uint, one above", uint(safeMax) + 1, "uint", "9007199254740992"},
		{"uint, the largest", ^uint(0), "uint", "18446744073709551615"},
		{"uint64, one above", uint64(safeMax) + 1, "uint64", "9007199254740992"},
		{"uint64, 2^63", uint64(1) << 63, "uint64", "9223372036854775808"},
		{"uint64, the largest", ^uint64(0), "uint64", "18446744073709551615"},
		{"a named int", namedInt(safeMax) + 1, "canonjson.namedInt", "9007199254740992"},
		{"a named int64", namedI64(safeMin) - 1, "canonjson.namedI64", "-9007199254740992"},
		{"a named uint", namedUint(safeMax) + 1, "canonjson.namedUint", "9007199254740992"},
		{"a named uint64", namedU64(safeMax) + 1, "canonjson.namedU64", "9007199254740992"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, p := range places(tc.v, true, false) {
				got, err := Marshal(p.doc)
				refused(t, got, err, cannotWrite(p.path, tc.typ, outside(tc.text)))
				if t.Failed() {
					t.Logf("at the place %q", p.name)
					return
				}
			}
		})
	}
	edges := []struct {
		name string
		v    any
		want string
	}{
		{"int, the largest of the range", int(safeMax), "9007199254740991"},
		{"int, the smallest of the range", int(safeMin), "-9007199254740991"},
		{"int64", safeMax, "9007199254740991"},
		{"int64, the smallest", safeMin, "-9007199254740991"},
		{"uint", uint(safeMax), "9007199254740991"},
		{"uint64", uint64(safeMax), "9007199254740991"},
		{"a named int64", namedI64(safeMin), "-9007199254740991"},
		{"a named uint64", namedU64(safeMax), "9007199254740991"},
		{"int8, the smallest", int8(-128), "-128"},
		{"uint8, the largest", uint8(255), "255"},
		{"uint32, the largest", uint32(1<<32 - 1), "4294967295"},
		{"int32, the smallest", int32(-1 << 31), "-2147483648"},
	}
	for _, tc := range edges {
		t.Run(tc.name+" is written", func(t *testing.T) {
			for _, p := range places(tc.v, true, false) {
				if p.name == "at the top" {
					continue
				}
				if _, err := Marshal(p.doc); err != nil {
					t.Errorf("%s: %v", p.name, err)
				}
			}
			got, err := Marshal(map[string]any{"a": tc.v})
			if want := `{"a":` + tc.want + `}`; err != nil || string(got) != want {
				t.Errorf("%q, %v; want %s", got, err, want)
			}
		})
	}
	t.Run("a value in an interface that is refused is refused as that type", func(t *testing.T) {
		got, err := Marshal(map[string]any{"a": any(uint64(1) << 53)})
		refused(t, got, err, cannotWrite("$.a", "uint64", outside("9007199254740992")))
	})
	t.Run("the first integer that a float cannot hold", func(t *testing.T) {
		got, err := Marshal(map[string]any{"a": int64(9007199254740993)})
		refused(t, got, err, cannotWrite("$.a", "int64", outside("9007199254740993")))
	})
}

func TestTheEdgesOfTheRangeGoRoundTrip(t *testing.T) {
	type rec struct {
		A int64 `json:"a"`
		B int64 `json:"b"`
		C any   `json:"c"`
		D uint  `json:"d"`
	}
	in := `{"a":9007199254740991,"b":-9007199254740991,"c":-9007199254740991,"d":9007199254740991}`
	var v rec
	if err := strictjson.Unmarshal([]byte(in), &v, strictjson.Options{}); err != nil {
		t.Fatal(err)
	}
	got, err := Marshal(v)
	if err != nil || string(got) != in {
		t.Errorf("%q, %v", got, err)
	}
	var back rec
	if err := strictjson.Unmarshal(got, &back, strictjson.Options{}); err != nil || back != v {
		t.Errorf("%+v, %v", back, err)
	}
	if ok, err := IsCanonical(got); err != nil || !ok {
		t.Errorf("not canonical: %v", err)
	}
}

// formatFloat is the number formatter of RFC 8785: the integer as a float64, in the shortest form
// that reads back, without an exponent for an integer of this size (JavaScript writes an integer
// below 1e21 in full).
func formatFloat(n int64) string { return strconv.FormatFloat(float64(n), 'f', -1, 64) }

// Inside the range the bytes of the writer and of the canonical writer are those of a float64
// formatter: an independent reference, so that the two can never disagree about a digit.
func TestTheDigitsInsideTheRangeAreThoseOfAFloatFormatter(t *testing.T) {
	r := rand.New(rand.NewSource(8785))
	ints := []int64{0, 1, -1, 9, 10, -10, 99, 100, 1e6, 1e15, 1e15 + 1, 1<<52 - 1, 1 << 52, 1<<52 + 1, safeMax - 1, safeMax, safeMin, safeMin + 1, 123456789012345, -123456789012345}
	for p := range 53 {
		ints = append(ints, int64(1)<<p, -(int64(1) << p), int64(1)<<p-1, int64(1)<<p+1)
	}
	for range 5000 {
		ints = append(ints, r.Int63n(safeMax+1), -r.Int63n(safeMax+1), r.Int63n(1<<(1+r.Intn(52))))
	}
	for _, n := range ints {
		if n > safeMax || n < safeMin {
			continue // 1<<53 and its neighbours: outside the range, tested above
		}
		want := formatFloat(n)
		if want != strconv.FormatInt(n, 10) {
			t.Fatalf("the reference differs from the decimal for %d: %s", n, want)
		}
		var kinds []any
		kinds = append(kinds, n, int(n))
		if n >= 0 {
			kinds = append(kinds, uint64(n), uint(n))
		}
		for _, k := range kinds {
			got, err := Marshal(map[string]any{"a": k})
			if err != nil || string(got) != `{"a":`+want+`}` {
				t.Fatalf("%T %d: %q, %v; want %s", k, n, got, err, want)
			}
		}
		out, err := Canonicalize([]byte(`{"a":` + strconv.FormatInt(n, 10) + `}`))
		if err != nil || string(out) != `{"a":`+want+`}` {
			t.Fatalf("Canonicalize %d: %q, %v", n, out, err)
		}
	}
}

// outsideInteger draws an integer outside the range, on purpose: some near the edge, some far.
func outsideInteger(r *rand.Rand) int64 {
	switch r.Intn(4) {
	case 0:
		return safeMax + 1 + int64(r.Intn(1000))
	case 1:
		return safeMin - 1 - int64(r.Intn(1000))
	case 2:
		return safeMax + 1 + r.Int63n(1<<62-safeMax)
	default:
		return -(safeMax + 1 + r.Int63n(1<<62-safeMax))
	}
}

// Random integers outside the range are refused by the writer, in a struct, a map and a list, and by
// the readers, with the text of the integer.
func TestRandomIntegersOutsideTheRangeAreRefused(t *testing.T) {
	r := rand.New(rand.NewSource(53))
	for range 500 {
		n := outsideInteger(r)
		digits := strconv.FormatInt(n, 10)
		want := cannotWrite("$.a", "int64", outside(digits))
		got, err := Marshal(map[string]any{"a": n})
		refused(t, got, err, want)
		got, err = Marshal(struct {
			A int64 `json:"a"`
		}{n})
		refused(t, got, err, want)
		if n > 0 {
			got, err = Marshal(map[string]any{"a": uint64(n)})
			refused(t, got, err, cannotWrite("$.a", "uint64", outside(digits)))
		}
		doc := `{"a":` + digits + `}`
		wantRead := mal("$.a", outside(digits)+byteIn(doc, digits))
		if out, err := Canonicalize([]byte(doc)); err == nil || err.Error() != wantRead || out != nil {
			t.Fatalf("Canonicalize(%s) = %q, %v", doc, out, err)
		}
		var v struct {
			A int64 `json:"a"`
		}
		if err := strictjson.Unmarshal([]byte(doc), &v, strictjson.Options{}); err == nil || err.Error() != wantRead {
			t.Fatalf("Unmarshal(%s): %v", doc, err)
		}
	}
}
