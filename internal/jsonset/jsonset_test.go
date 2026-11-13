package jsonset

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
	"unsafe"
)

// The tests of what the writer and the reader share. The two packages that use it test the
// writing and the reading; what is tested here is a rule that lives in this package and is not
// reached more clearly through them: the form of a path, the order of names, the rules of a tag,
// and the answer for a type in each mode. A JSON escape of the form backslash, u and four digits
// is never written out in this file: where a test needs a character it is built from its code
// point, so that no tool can turn an escape into the character on the way.

func TestErrMalformedIsOneValue(t *testing.T) {
	if ErrMalformed.Error() != "malformed JSON" {
		t.Errorf("ErrMalformed says %q", ErrMalformed)
	}
}

// ---- Path and Shown -----------------------------------------------------------------------

func TestPathText(t *testing.T) {
	cases := []struct {
		name string
		path Path
		want string
	}{
		{"the top", nil, "$"},
		{"the top, an empty path", Path{}, "$"},
		{"a member", Path{Member("a")}, "$.a"},
		{"two members", Path{Member("a"), Member("b")}, "$.a.b"},
		{"an element", Path{Element(3)}, "$[3]"},
		{"element zero", Path{Element(0)}, "$[0]"},
		{"a large index", Path{Element(1 << 30)}, "$[1073741824]"},
		{"a member and an element", Path{Member("l"), Element(2)}, "$.l[2]"},
		{"an element and a member", Path{Member("l"), Element(2), Member("x")}, "$.l[2].x"},
		{"elements in elements", Path{Member("l"), Element(0), Element(1)}, "$.l[0][1]"},
		{"a member named by digits is not an index", Path{Member("l"), Member("1")}, "$.l.1"},
		{"an index is not a member named by digits", Path{Member("l"), Element(1)}, "$.l[1]"},
		{"a member named like an index is quoted", Path{Member("l"), Member("[1]")}, `$.l."[1]"`},
		{"a member with a dot", Path{Member("a.b")}, `$."a.b"`},
		{"an empty member name", Path{Member("")}, `$.""`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.path.String(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPathShowsItsLastEightSteps(t *testing.T) {
	steps := func(n int) Path {
		p := Path{}
		for i := 1; i <= n; i++ {
			if i%3 == 0 {
				p = append(p, Element(i))
			} else {
				p = append(p, Member(fmt.Sprintf("s%d", i)))
			}
		}
		return p
	}
	for _, tc := range []struct {
		n    int
		want string
	}{
		{7, "$.s1.s2[3].s4.s5[6].s7"},
		{8, "$.s1.s2[3].s4.s5[6].s7.s8"},
		{9, "$....s2[3].s4.s5[6].s7.s8[9]"},
		{10, "$...[3].s4.s5[6].s7.s8[9].s10"},
	} {
		if got := steps(tc.n).String(); got != tc.want {
			t.Errorf("%d steps: %q, want %q", tc.n, got, tc.want)
		}
	}
	// A long path of one kind of step.
	long := Path{}
	for range 10000 {
		long = append(long, Member("a"))
	}
	if got, want := long.String(), "$...."+strings.Repeat("a.", 7)+"a"; got != want {
		t.Errorf("10000 steps: %q, want %q", got, want)
	}
	// The path is not changed by being shown.
	if len(long) != 10000 {
		t.Errorf("String changed the path: %d steps", len(long))
	}
	// Nine steps are the first that are cut, and the cut is told by the dots straight after the dollar.
	nine, eight := steps(9).String(), steps(8).String()
	if !strings.HasPrefix(nine, "$...") || strings.HasPrefix(eight, "$...") {
		t.Errorf("the cut is not told: %q, %q", nine, eight)
	}
	// A member whose name is dots is quoted, so a path that is cut is not mistaken for one that
	// has such a member: the cut is "$..." with no dot after it that belongs to a step.
	if got := (Path{Member("...")}).String(); got != `$."..."` {
		t.Errorf("a member named with three dots is shown as %q", got)
	}
}

func TestShown(t *testing.T) {
	forty := strings.Repeat("n", 40)
	cases := []struct {
		name, in, want string
	}{
		{"letters", "abc", "abc"},
		{"capitals and digits", "Ab1", "Ab1"},
		{"underscore and dash", "a_b-c", "a_b-c"},
		{"digits only", "0", "0"},
		{"a letter outside ASCII", string(rune(0xE9)), `"` + qesc(0xE9) + `"`},
		{"a Hebrew letter", string(rune(0xFB33)), `"` + qesc(0xFB33) + `"`},
		{"a digit outside ASCII", string(rune(0x0663)), `"` + qesc(0x0663) + `"`},
		{"forty bytes", forty, forty},
		{"forty bytes of two-byte letters are quoted, and cut at the fortieth byte", strings.Repeat(string(rune(0xE9)), 21), `"` + strings.Repeat(qesc(0xE9), 20) + `..."`},
		{"41 bytes are cut and quoted", forty + "n", `"` + forty + `..."`},
		{"a long name that is not plain is cut and quoted", strings.Repeat("a b", 20), `"` + strings.Repeat("a b", 20)[:40] + `..."`},
		{"empty", "", `""`},
		{"a dot", "a.b", `"a.b"`},
		{"a bracket", "[0]", `"[0]"`},
		{"a dollar", "$", `"$"`},
		{"a space", "a b", `"a b"`},
		{"a quote", `a"b`, `"a\"b"`},
		{"a backslash", `a\b`, `"a\\b"`},
		{"a line feed", "a\nb", `"a` + qesc(10) + `b"`},
		{"a control", "a\x01b", `"a` + qesc(1) + `b"`},
		{"the delete character", "a\x7fb", `"a` + qesc(0x7f) + `b"`},
		{"an emoji", string(rune(0x1F600)), `"` + qesc(0x1F600) + `"`},
		{"a symbol that is not a letter", string(rune(0x20AC)), `"` + qesc(0x20AC) + `"`},
		{"a character that has no width", "a" + string(rune(0x200B)) + "b", `"a` + qesc(0x200B) + `b"`},
		{"a combining mark", "e" + string(rune(0x0301)), `"e` + qesc(0x0301) + `"`},
		{"the line separator", string(rune(0x2028)), `"` + qesc(0x2028) + `"`},
		{"text that is not UTF-8", "a\xffb", `"a` + qesc(0xFFFD) + `b"`},
		{"a punctuation mark", "a,b", `"a,b"`},
		{"a slash", "a/b", `"a/b"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Shown(tc.in); got != tc.want {
				t.Errorf("Shown(%q) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
	t.Run("what is shown is never longer than 40 bytes and a quoted form of them", func(t *testing.T) {
		r := rand.New(rand.NewSource(40))
		for range 500 {
			var b strings.Builder
			for range r.Intn(80) {
				b.WriteRune([]rune{'a', 'b', '_', '-', '0', 0xE9, ' ', 0x20AC, '"', 92, 10, '.'}[r.Intn(12)])
			}
			name := b.String()
			got := Shown(name)
			if len(name) <= 40 && !strings.ContainsAny(got, "\"") && got != name {
				t.Fatalf("%q: a plain name was changed: %q", name, got)
			}
			if got != name && !strings.HasPrefix(got, `"`) {
				t.Fatalf("%q: a name that is changed is quoted: %q", name, got)
			}
			if len(got) > 4*40+len(`"..."`)+10 {
				t.Fatalf("%q: shown at %d bytes", name, len(got))
			}
			if !utf8.ValidString(got) {
				t.Fatalf("%q: what is shown is not UTF-8: %q", name, got)
			}
		}
	})
	t.Run("two different names are shown differently when neither is long", func(t *testing.T) {
		names := []string{"a", "A", "a.b", "a b", "1", `"a"`, `a"`, "", "[1]", string(rune(0xE9)), "e", "$", "$.a", "_", "-", "a-", "a_"}
		seen := map[string]string{}
		for _, n := range names {
			s := Shown(n)
			if other, dup := seen[s]; dup {
				t.Errorf("%q and %q are both shown as %s", n, other, s)
			}
			seen[s] = n
		}
	})
}

// ---- CompareUTF16 -------------------------------------------------------------------------

// refUnits is the UTF-16 form of s by the rule of RFC 2781, written out here and not by
// unicode/utf16, so that the test does not use what the package uses.
func refUnits(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r >= 0x10000 {
			v := r - 0x10000
			out = append(out, uint16(0xD800+(v>>10)), uint16(0xDC00+(v&0x3FF)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

// refCompare orders two strings by their UTF-16 code units with its own loop.
func refCompare(a, b string) int {
	ua, ub := refUnits(a), refUnits(b)
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

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestCompareUTF16(t *testing.T) {
	const (
		d7ff = rune(0xD7FF) // below the surrogates, in UTF-8 below U+E000
		e000 = rune(0xE000) // above the surrogates in UTF-16, and below U+10000 in UTF-8
		fb33 = rune(0xFB33)
		hi   = rune(0x10000)
		bold = rune(0x1D400)
		smil = rune(0x1F600)
	)
	cases := []struct {
		name string
		a, b string
		want int
	}{
		{"equal", "abc", "abc", 0},
		{"both empty", "", "", 0},
		{"empty first", "", "a", -1},
		{"a prefix is first", "a", "ab", -1},
		{"by the first unit that differs", "ab", "b", -1},
		{"capitals before small letters", "B", "a", -1},
		{"digits before letters", "1", "a", -1},
		{"the carriage return before the digit one", "\r", "1", -1},
		{"U+D7FF before U+E000", string(d7ff), string(e000), -1},
		// The point of RFC 8785 section 3.2.3: a character above U+FFFF is two units that start at
		// 0xD800, which is below 0xE000 and 0xFB33, although its UTF-8 bytes are above theirs.
		{"U+10000 before U+E000", string(hi), string(e000), -1},
		{"U+1F600 before U+FB33", string(smil), string(fb33), -1},
		{"U+1D400 before U+FB33", string(bold), string(fb33), -1},
		{"U+FB33 after U+1F600", string(fb33), string(smil), 1},
		{"U+D7FF before U+10000", string(d7ff), string(hi), -1},
		{"two characters above the BMP by their second unit", string(smil), string(smil + 1), -1},
		{"after a common prefix", "a" + string(smil), "a" + string(fb33), -1},
		{"a long common prefix", strings.Repeat("x", 1000) + "a", strings.Repeat("x", 1000) + "b", -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sign(CompareUTF16(tc.a, tc.b)); got != tc.want {
				t.Errorf("CompareUTF16(%+q, %+q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
			if got := sign(CompareUTF16(tc.b, tc.a)); got != -tc.want {
				t.Errorf("the other way: CompareUTF16(%+q, %+q) = %d, want %d", tc.b, tc.a, got, -tc.want)
			}
			if got := refCompare(tc.a, tc.b); got != tc.want {
				t.Fatalf("the test's own reference says %d for %+q and %+q, the case says %d", got, tc.a, tc.b, tc.want)
			}
		})
	}
	t.Run("the order differs from the order of the bytes of UTF-8 where it should", func(t *testing.T) {
		a, b := string(smil), string(fb33)
		if a <= b {
			t.Fatal("the two characters are not in the other order in UTF-8")
		}
		if CompareUTF16(a, b) >= 0 {
			t.Error("the order is that of UTF-8")
		}
	})
	t.Run("random strings against the reference", func(t *testing.T) {
		r := rand.New(rand.NewSource(8785))
		pool := []rune{'a', 'b', 'A', '0', '\r', 0, 0x1f, '~', 0x7f, 0x80, 0xe9, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xf000, 0xfb33, 0xfffd, 0xffff, 0x10000, 0x10001, 0x1d400, 0x1f600, 0x1f601, 0x10ffff}
		word := func() string {
			var b strings.Builder
			for range r.Intn(5) {
				b.WriteRune(pool[r.Intn(len(pool))])
			}
			return b.String()
		}
		var words []string
		for range 3000 {
			a, b := word(), word()
			words = append(words, a)
			if got, want := sign(CompareUTF16(a, b)), refCompare(a, b); got != want {
				t.Fatalf("CompareUTF16(%+q, %+q) = %d, the reference says %d", a, b, got, want)
			}
		}
		// It is a total order: sorting by it gives the order of the reference, and equal means identical.
		got := slices.Clone(words)
		slices.SortStableFunc(got, CompareUTF16)
		want := slices.Clone(words)
		sort.SliceStable(want, func(i, j int) bool { return refCompare(want[i], want[j]) < 0 })
		if !slices.Equal(got, want) {
			t.Error("sorting by CompareUTF16 and by the reference give different orders")
		}
		for _, a := range words[:200] {
			for _, b := range words[:200] {
				if (CompareUTF16(a, b) == 0) != (a == b) {
					t.Fatalf("equal in the order but not the same: %+q %+q", a, b)
				}
			}
		}
	})
}

// ---- Error --------------------------------------------------------------------------------

func TestErrorForm(t *testing.T) {
	err := Errorf(Path{Member("a"), Element(2)}, "bad %s %d", "thing", 7)
	if got, want := err.Error(), "malformed JSON: $.a[2]: bad thing 7"; got != want {
		t.Errorf("text %q, want %q", got, want)
	}
	if !errors.Is(err, ErrMalformed) {
		t.Error("the error does not wrap ErrMalformed")
	}
	var e *Error
	if !errors.As(err, &e) || e.What != "bad thing 7" || e.Path.String() != "$.a[2]" {
		t.Errorf("errors.As gives %+v", e)
	}
	if !errors.Is(e.Unwrap(), ErrMalformed) || e.Unwrap().Error() != "malformed JSON" {
		t.Error("Unwrap is not ErrMalformed")
	}
	if got, want := Errorf(nil, "x").Error(), "malformed JSON: $: x"; got != want {
		t.Errorf("a nil path: %q, want %q", got, want)
	}
	t.Run("the error keeps a copy of the path", func(t *testing.T) {
		p := make(Path, 1, 8)
		p[0] = Member("a")
		err := Errorf(p, "x")
		p[0] = Member("changed")
		p = append(p, Member("more"))
		_ = p
		if got, want := err.Error(), "malformed JSON: $.a: x"; got != want {
			t.Errorf("the path of the error followed the caller's: %q, want %q", got, want)
		}
	})
	t.Run("a percent sign in the text of a name is not a verb", func(t *testing.T) {
		// What goes in as an argument is not read as a format.
		err := Errorf(Path{Member("a%d")}, "x %s", "100%")
		if got, want := err.Error(), `malformed JSON: $."a%d": x 100%`; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// ---- types of the tests -------------------------------------------------------------------

type (
	myString string
	myInt    int
	pair     struct{ X, Y int }
	// loop refers to itself; a refused field makes the whole of it refused.
	loop      struct{ Next *loop }
	loopFloat struct {
		F    float64
		Next *loopFloat
	}
	mutualA struct{ B *mutualB }
	mutualB struct{ A *mutualA }
	// rawLike stands in for strictjson.Raw: the type that the Checker is told is in the set.
	rawLike  []byte
	otherRaw []byte
	// stringer has a method that is none of the four that are refused.
	stringer struct{ N int }
	// shower is an interface with a method that is none of the four.
	shower        interface{ Show() string }
	jsonVal       struct{}
	jsonPtr       struct{}
	textVal       string
	textPtr       struct{}
	unmarshal     struct{}
	unmarshalText struct{}
	textKey       string
)

func (stringer) String() string                   { return "s" }
func (rawLike) MarshalJSON() ([]byte, error)      { return nil, nil }
func (*rawLike) UnmarshalJSON([]byte) error       { return nil }
func (otherRaw) MarshalJSON() ([]byte, error)     { return nil, nil }
func (*otherRaw) UnmarshalJSON([]byte) error      { return nil }
func (jsonVal) MarshalJSON() ([]byte, error)      { return nil, nil }
func (*jsonPtr) MarshalJSON() ([]byte, error)     { return nil, nil }
func (textVal) MarshalText() ([]byte, error)      { return nil, nil }
func (*textPtr) MarshalText() ([]byte, error)     { return nil, nil }
func (*unmarshal) UnmarshalJSON([]byte) error     { return nil }
func (*unmarshalText) UnmarshalText([]byte) error { return nil }
func (textKey) MarshalText() ([]byte, error)      { return nil, nil }

var rawType = reflect.TypeFor[rawLike]()

func typeOf[T any]() reflect.Type { return reflect.TypeFor[T]() }

// qesc is the escape that Quote writes for a character that is not printable ASCII: a backslash, u
// and four digits in lower case, and for a character above U+FFFF the escapes of its two surrogates
// (worked out here by hand, not by unicode/utf16, which Quote uses). It is built from the
// code point, so that no tool can turn it into the character on the way.
func qesc(r rune) string {
	bs := string(rune(92))
	if r > 0xFFFF {
		v := r - 0x10000
		return bs + fmt.Sprintf("u%04x", 0xD800+(v>>10)) + bs + fmt.Sprintf("u%04x", 0xDC00+(v&0x3FF))
	}
	return bs + fmt.Sprintf("u%04x", r)
}

// wide is a name of a letter, a digit and a letter outside ASCII: E9, 663, FB33.
var wide = string(rune(0xE9)) + string(rune(0x0663)) + string(rune(0xFB33))

type jsonNumber = json.Number

func unsafePointer(p *int) unsafe.Pointer { return unsafe.Pointer(p) }

// structWith builds a struct type of one field F of type int whose tag is the given text, and a
// struct type with the given fields, for the tags that a source file cannot carry through go vet.
func structWith(tags ...string) reflect.Type {
	var fields []reflect.StructField
	for i, tag := range tags {
		fields = append(fields, reflect.StructField{Name: fmt.Sprintf("F%d", i), Type: typeOf[int](), Tag: reflect.StructTag(tag)})
	}
	return reflect.StructOf(fields)
}

// ---- the judge of a type ------------------------------------------------------------------

// A verdict is what a test expects of Verdict: nil for a type in the set, else the type at fault,
// the way to it and the reason.
type verdict struct {
	typ    string
	hops   string // ".F" for a field, "[]" for elements, "{}" for values
	reason string
}

func hopsText(hops []Hop) string {
	var b strings.Builder
	for _, h := range hops {
		switch h.Kind {
		case FieldHop:
			b.WriteString("." + h.Field)
		case ElementsHop:
			b.WriteString("[]")
		case ValuesHop:
			b.WriteString("{}")
		}
	}
	return b.String()
}

const (
	reasonFloat = "a float; ritueel's JSON holds integers only"
	reasonKind  = "this kind of Go type is not part of ritueel's JSON"
	reasonPtr   = "a pointer to a pointer or to an interface is not part of ritueel's JSON"
	reasonKey   = "only a map with a key of kind string is part of ritueel's JSON"
	reasonIface = "an interface with methods is not part of ritueel's JSON; only one with no methods is"
	reasonNum   = "a json.Number is not part of ritueel's JSON; use an integer type"
	reasonJSON  = "the type has a MarshalJSON method; only Raw carries JSON of its own"
	reasonText  = "the type has a MarshalText method; only Raw carries JSON of its own"
	reasonUJSON = "the type has a UnmarshalJSON method; only Raw carries JSON of its own"
	reasonUText = "the type has a UnmarshalText method; only Raw carries JSON of its own"
)

func TestVerdictOfEveryKind(t *testing.T) {
	ch := make(chan int)
	var up int
	type embedded struct{ pair }
	cases := []struct {
		name string
		typ  reflect.Type
		// want is the verdict in Writing mode; reading is the same unless readWant is set.
		want     *verdict
		readWant *verdict
	}{
		{name: "bool", typ: typeOf[bool]()},
		{name: "string", typ: typeOf[string]()},
		{name: "int", typ: typeOf[int]()},
		{name: "int8", typ: typeOf[int8]()},
		{name: "int16", typ: typeOf[int16]()},
		{name: "int32", typ: typeOf[int32]()},
		{name: "int64", typ: typeOf[int64]()},
		{name: "uint", typ: typeOf[uint]()},
		{name: "uint8", typ: typeOf[uint8]()},
		{name: "uint16", typ: typeOf[uint16]()},
		{name: "uint32", typ: typeOf[uint32]()},
		{name: "uint64", typ: typeOf[uint64]()},
		{name: "a named string", typ: typeOf[myString]()},
		{name: "a named int", typ: typeOf[myInt]()},
		{name: "a struct", typ: typeOf[pair]()},
		{name: "the empty struct", typ: typeOf[struct{}]()},
		{name: "a slice", typ: typeOf[[]int]()},
		{name: "a slice of bytes", typ: typeOf[[]byte]()},
		{name: "an array", typ: typeOf[[3]string]()},
		{name: "an array of length zero", typ: typeOf[[0]int]()},
		{name: "a map", typ: typeOf[map[string]int]()},
		{name: "a map with a named string key", typ: typeOf[map[myString]bool]()},
		{name: "a pointer to a struct", typ: typeOf[*pair]()},
		{name: "a pointer to a slice", typ: typeOf[*[]int]()},
		{name: "a pointer to a map", typ: typeOf[*map[string]int]()},
		{name: "an interface with no methods", typ: typeOf[any]()},
		{name: "a recursive struct", typ: typeOf[loop]()},
		{name: "two structs that refer to each other", typ: typeOf[mutualA]()},
		{name: "a map that refers to itself", typ: typeOf[selfMap]()},
		{name: "a slice that refers to itself", typ: typeOf[selfSlice]()},
		{name: "a type with a method that is none of the four", typ: typeOf[stringer]()},
		{name: "the type that is told to be Raw", typ: typeOf[rawLike]()},
		{name: "a pointer to the Raw type", typ: typeOf[*rawLike]()},
		{name: "a slice of Raw", typ: typeOf[[]rawLike]()},
		{name: "a map of Raw", typ: typeOf[map[string]rawLike]()},
		{name: "a struct with a Raw field", typ: typeOf[struct{ R rawLike }]()},

		{name: "float64", typ: typeOf[float64](), want: &verdict{"float64", "", reasonFloat}},
		{name: "float32", typ: typeOf[float32](), want: &verdict{"float32", "", reasonFloat}},
		{name: "complex64", typ: typeOf[complex64](), want: &verdict{"complex64", "", reasonKind}},
		{name: "complex128", typ: typeOf[complex128](), want: &verdict{"complex128", "", reasonKind}},
		{name: "uintptr", typ: typeOf[uintptr](), want: &verdict{"uintptr", "", reasonKind}},
		{name: "a channel", typ: reflect.TypeOf(ch), want: &verdict{"chan int", "", reasonKind}},
		{name: "a function", typ: typeOf[func()](), want: &verdict{"func()", "", reasonKind}},
		{name: "an unsafe pointer", typ: reflect.TypeOf(unsafePointer(&up)), want: &verdict{"unsafe.Pointer", "", reasonKind}},
		{name: "json.Number", typ: typeOf[jsonNumber](), want: &verdict{"json.Number", "", reasonNum}},
		{name: "a pointer to a float", typ: typeOf[*float64](), want: &verdict{"*float64", "", reasonFloat}},
		{name: "a pointer to a pointer", typ: typeOf[**int](), want: &verdict{"**int", "", reasonPtr}},
		{name: "a pointer to a pointer to a struct", typ: typeOf[**pair](), want: &verdict{"**jsonset.pair", "", reasonPtr}},
		{name: "a pointer to an interface", typ: typeOf[*any](), want: &verdict{"*interface {}", "", reasonPtr}},
		{name: "a pointer to an interface with methods", typ: typeOf[*shower](), want: &verdict{"*jsonset.shower", "", reasonPtr}},
		{name: "a slice of floats", typ: typeOf[[]float64](), want: &verdict{"float64", "[]", reasonFloat}},
		{name: "an array of floats", typ: typeOf[[2]float64](), want: &verdict{"float64", "[]", reasonFloat}},
		{name: "an empty array of floats", typ: typeOf[[0]float64](), want: &verdict{"float64", "[]", reasonFloat}},
		{name: "a map of floats", typ: typeOf[map[string]float64](), want: &verdict{"float64", "{}", reasonFloat}},
		{name: "lists and maps inside each other", typ: typeOf[map[string][][]map[string]float64](), want: &verdict{"float64", "{}[][]{}", reasonFloat}},
		{name: "a map with an integer key", typ: typeOf[map[int]string](), want: &verdict{"map[int]string", "", reasonKey}},
		{name: "a map with a struct key", typ: typeOf[map[pair]string](), want: &verdict{"map[jsonset.pair]string", "", reasonKey}},
		{name: "a map with an interface key", typ: typeOf[map[any]string](), want: &verdict{"map[interface {}]string", "", reasonKey}},
		{name: "a map with a key that has a method", typ: typeOf[map[textKey]int](), want: &verdict{"jsonset.textKey", "", reasonText}},
		{name: "a map of slices with a key that is not a string", typ: typeOf[map[int][]float64](), want: &verdict{"map[int][]float64", "", reasonKey}},
		{name: "a pointer to a slice of floats", typ: typeOf[*[]float64](), want: &verdict{"float64", "[]", reasonFloat}},
		{name: "a slice of pointers to floats", typ: typeOf[[]*float64](), want: &verdict{"*float64", "[]", reasonFloat}},
		{name: "a slice of pointers to pointers", typ: typeOf[[]**int](), want: &verdict{"**int", "[]", reasonPtr}},
		{name: "MarshalJSON on the value", typ: typeOf[jsonVal](), want: &verdict{"jsonset.jsonVal", "", reasonJSON}},
		{name: "MarshalJSON on the pointer", typ: typeOf[jsonPtr](), want: &verdict{"jsonset.jsonPtr", "", reasonJSON}},
		{name: "a pointer to a type with MarshalJSON", typ: typeOf[*jsonVal](), want: &verdict{"*jsonset.jsonVal", "", reasonJSON}},
		{name: "MarshalText on the value", typ: typeOf[textVal](), want: &verdict{"jsonset.textVal", "", reasonText}},
		{name: "MarshalText on the pointer", typ: typeOf[textPtr](), want: &verdict{"jsonset.textPtr", "", reasonText}},
		{name: "UnmarshalJSON on the pointer", typ: typeOf[unmarshal](), want: &verdict{"jsonset.unmarshal", "", reasonUJSON}},
		{name: "UnmarshalText on the pointer", typ: typeOf[unmarshalText](), want: &verdict{"jsonset.unmarshalText", "", reasonUText}},
		{name: "another type with the methods of Raw", typ: typeOf[otherRaw](), want: &verdict{"jsonset.otherRaw", "", reasonJSON}},
		{name: "a slice of types with a method", typ: typeOf[[]jsonVal](), want: &verdict{"jsonset.jsonVal", "[]", reasonJSON}},
		{name: "an embedded struct", typ: typeOf[embedded](), want: &verdict{"jsonset.embedded", "", "the embedded field pair is not part of ritueel's JSON; give it a name"}},
		{name: "a struct with a float field", typ: typeOf[struct{ G float64 }](), want: &verdict{"float64", ".G", reasonFloat}},
		{name: "a float field two structs down", typ: typeOf[struct {
			A struct{ B struct{ G float64 } }
		}](), want: &verdict{"float64", ".A.B.G", reasonFloat}},
		{name: "a recursive struct with a float", typ: typeOf[loopFloat](), want: &verdict{"float64", ".F", reasonFloat}},
		{name: "a field that is a slice of floats", typ: typeOf[struct{ L []float64 }](), want: &verdict{"float64", ".L[]", reasonFloat}},
		{name: "a slice of structs with a float", typ: typeOf[[]struct{ G float64 }](), want: &verdict{"float64", "[].G", reasonFloat}},

		// The one thing that is not the same in the two modes.
		{name: "an interface with methods", typ: typeOf[shower](), readWant: &verdict{"jsonset.shower", "", reasonIface}},
		{name: "a slice of interfaces with methods", typ: typeOf[[]shower](), readWant: &verdict{"jsonset.shower", "[]", reasonIface}},
		{name: "a struct with an interface with methods", typ: typeOf[struct{ S shower }](), readWant: &verdict{"jsonset.shower", ".S", reasonIface}},
		{name: "a map of interfaces with methods", typ: typeOf[map[string]fmtStringer](), readWant: &verdict{"jsonset.fmtStringer", "{}", reasonIface}},
	}
	// A type that has no refusal in one mode and one in the other has want nil and readWant set.
	// A type that is refused in both has want set and readWant nil, and is refused the same in both.
	for _, tc := range cases {
		for _, mode := range []Mode{Writing, Reading} {
			t.Run(fmt.Sprintf("%s/%v", tc.name, mode), func(t *testing.T) {
				want := tc.want
				if mode == Reading && tc.readWant != nil {
					want = tc.readWant
				}
				r := NewChecker(mode, rawType).Verdict(tc.typ)
				switch {
				case want == nil && r != nil:
					t.Errorf("refused: %s at %s: %s", r.Type, hopsText(r.Hops), r.Reason)
				case want != nil && r == nil:
					t.Errorf("accepted, want the refusal %+v", want)
				case want != nil:
					if got := (verdict{r.Type.String(), hopsText(r.Hops), r.Reason}); got != *want {
						t.Errorf("got %+v, want %+v", got, *want)
					}
				}
			})
		}
	}
}

func (m Mode) String() string {
	if m == Reading {
		return "reading"
	}
	return "writing"
}

type (
	selfMap     map[string]selfMap
	selfSlice   []selfSlice
	fmtStringer interface{ String() string }
)

func TestAnInterfaceWithMethodsIsTheOneDifference(t *testing.T) {
	// The rest of the package comment: the two modes agree on every type that has no interface with
	// methods in it; where there is one, writing accepts and reading refuses.
	types := []reflect.Type{typeOf[shower](), typeOf[[]shower](), typeOf[*struct{ S shower }](), typeOf[map[string][]shower]()}
	for _, typ := range types {
		if r := NewChecker(Writing, rawType).Verdict(typ); r != nil {
			t.Errorf("writing refuses %s: %s", typ, r.Reason)
		}
		r := NewChecker(Reading, rawType).Verdict(typ)
		if r == nil || r.Reason != reasonIface {
			t.Errorf("reading accepts %s", typ)
		}
	}
}

func TestVerdictIsAskedOncePerType(t *testing.T) {
	c := NewChecker(Reading, rawType)
	for _, typ := range []reflect.Type{typeOf[pair](), typeOf[float64](), typeOf[[]float64](), typeOf[loopFloat]()} {
		a, b := c.Verdict(typ), c.Verdict(typ)
		if a != b {
			t.Errorf("%s: two answers that are two values: %p %p", typ, a, b)
		}
	}
	// The cache is the checker's own: another checker answers by itself, and a different mode does.
	w, r := NewChecker(Writing, rawType), NewChecker(Reading, rawType)
	if w.Verdict(typeOf[shower]()) != nil || r.Verdict(typeOf[shower]()) == nil {
		t.Error("the answers of two modes are mixed")
	}
}

func TestVerdictNeedsNoRawType(t *testing.T) {
	// A checker that is told no Raw type has none: the type of the tests is one like another.
	c := NewChecker(Writing, nil)
	r := c.Verdict(typeOf[rawLike]())
	if r == nil || r.Reason != reasonJSON {
		t.Errorf("a type with MarshalJSON is accepted when no type is Raw: %+v", r)
	}
}

func TestEveryRawPlaceIsInTheSetWhateverItsMethods(t *testing.T) {
	c := NewChecker(Reading, rawType)
	for _, typ := range []reflect.Type{
		typeOf[rawLike](), typeOf[*rawLike](), typeOf[[]rawLike](), typeOf[[2]rawLike](), typeOf[map[string]*rawLike](),
		typeOf[struct{ A, B rawLike }](), typeOf[struct{ P *rawLike }](),
	} {
		if r := c.Verdict(typ); r != nil {
			t.Errorf("%s is refused: %+v", typ, r)
		}
	}
}

// ---- the text of a refusal ----------------------------------------------------------------

func TestErrOfARefusal(t *testing.T) {
	type holder struct {
		L []float64
		M map[string]float64
		S struct{ G float64 }
		X map[string][][]float64
		R []struct{ P struct{ G float64 } }
	}
	cases := []struct {
		name string
		typ  reflect.Type
		at   Path
		want string
	}{
		{"at the top", typeOf[float64](), nil, "malformed JSON: $: a value of type float64 cannot be written: " + reasonFloat},
		{"at a member", typeOf[float64](), Path{Member("m")}, "malformed JSON: $.m: a value of type float64 cannot be written: " + reasonFloat},
		{"at an element", typeOf[float64](), Path{Member("l"), Element(1)}, "malformed JSON: $.l[1]: a value of type float64 cannot be written: " + reasonFloat},
		{"through a field", typeOf[struct{ G float64 }](), nil, "malformed JSON: $.G: a value of type float64 cannot be written: " + reasonFloat},
		{"through fields from a member", typeOf[struct{ A struct{ G float64 } }](), Path{Member("m")}, "malformed JSON: $.m.A.G: a value of type float64 cannot be written: " + reasonFloat},
		{"through the elements of a list", typeOf[[]float64](), nil, "malformed JSON: $: a value of type float64 cannot be written (the elements of $): " + reasonFloat},
		{"through the values of a map", typeOf[map[string]float64](), nil, "malformed JSON: $: a value of type float64 cannot be written (the values of $): " + reasonFloat},
		{"through a list at a member", typeOf[[]float64](), Path{Member("l")}, "malformed JSON: $.l: a value of type float64 cannot be written (the elements of $.l): " + reasonFloat},
		{"through a list at an element", typeOf[[]float64](), Path{Member("l"), Element(2)}, "malformed JSON: $.l[2]: a value of type float64 cannot be written (the elements of $.l[2]): " + reasonFloat},
		{"through a field that is a list", typeOf[holder](), nil, "malformed JSON: $.L: a value of type float64 cannot be written (the elements of $.L): " + reasonFloat},
		{"through a map in a map in a list", typeOf[map[string][][]float64](), nil, "malformed JSON: $: a value of type float64 cannot be written (the elements of the elements of the values of $): " + reasonFloat},
		{"through fields after a list", typeOf[[]struct{ P struct{ G float64 } }](), nil, "malformed JSON: $: a value of type float64 cannot be written (the member G of the member P of the elements of $): " + reasonFloat},
		{"a path of more than eight steps", typeOf[float64](), longPath(9), "malformed JSON: $....m2.m3.m4.m5.m6.m7.m8.m9: a value of type float64 cannot be written: " + reasonFloat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := NewChecker(Writing, rawType)
			r := c.Verdict(tc.typ)
			if r == nil {
				t.Fatalf("%s is accepted", tc.typ)
			}
			err := c.Err(tc.at, r)
			if err.Error() != tc.want {
				t.Errorf("got\n  %s\nwant\n  %s", err, tc.want)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Error("the error does not wrap ErrMalformed")
			}
			// The same refusal asked twice says the same, and the path that was given is not changed.
			if again := c.Err(tc.at, r).Error(); again != err.Error() {
				t.Errorf("asked twice: %q and %q", err, again)
			}
		})
	}
	t.Run("reading says read", func(t *testing.T) {
		c := NewChecker(Reading, rawType)
		err := c.Err(Path{Member("a")}, c.Verdict(typeOf[float64]()))
		if want := "malformed JSON: $.a: a value of type float64 cannot be read: " + reasonFloat; err.Error() != want {
			t.Errorf("got %q, want %q", err, want)
		}
	})
	t.Run("the path given is not written into", func(t *testing.T) {
		at := make(Path, 1, 16)
		at[0] = Member("m")
		c := NewChecker(Writing, rawType)
		_ = c.Err(at, c.Verdict(typeOf[struct{ G float64 }]()))
		if got := at[:cap(at)][1]; got != (Step{}) {
			t.Errorf("Err wrote into the spare room of the caller's path: %+v", got)
		}
	})
	t.Run("a pointer's refusal is named as the caller wrote it", func(t *testing.T) {
		c := NewChecker(Writing, rawType)
		err := c.Err(nil, c.Verdict(typeOf[*float64]()))
		if want := "malformed JSON: $: a value of type *float64 cannot be written: " + reasonFloat; err.Error() != want {
			t.Errorf("got %q, want %q", err, want)
		}
		err = c.Err(nil, c.Verdict(typeOf[*jsonVal]()))
		if want := "malformed JSON: $: a value of type *jsonset.jsonVal cannot be written: " + reasonJSON; err.Error() != want {
			t.Errorf("got %q, want %q", err, want)
		}
		// A refusal that is not at the type behind the pointer is named as it is.
		err = c.Err(nil, c.Verdict(typeOf[*[]float64]()))
		if want := "malformed JSON: $: a value of type float64 cannot be written (the elements of $): " + reasonFloat; err.Error() != want {
			t.Errorf("got %q, want %q", err, want)
		}
	})
}

// A name outside the rule of a struct is a name of a map's key or of a path, and a struct cannot
// carry one, so a refusal that leads through such a field name is built by hand: what is tested
// is how the text is written from a refusal.
func TestErrOfARefusalWithOddNames(t *testing.T) {
	hand := func(first Hop, rest ...Hop) *Refusal {
		return &Refusal{Hops: append([]Hop{first}, rest...), Type: typeOf[float64](), Reason: reasonFloat}
	}
	cases := []struct {
		name string
		by   *Refusal
		want string
	}{
		{"a name that needs quotes", hand(Hop{Kind: FieldHop, Field: "a.b"}), `malformed JSON: $."a.b": a value of type float64 cannot be written: ` + reasonFloat},
		{"a name that needs quotes after a list", hand(Hop{Kind: FieldHop, Field: "a b"}, Hop{Kind: ElementsHop}, Hop{Kind: FieldHop, Field: "G"}), `malformed JSON: $."a b": a value of type float64 cannot be written (the member G of the elements of $."a b"): ` + reasonFloat},
		{"a name that needs quotes inside the words", hand(Hop{Kind: ValuesHop}, Hop{Kind: FieldHop, Field: "a b"}), `malformed JSON: $: a value of type float64 cannot be written (the member "a b" of the values of $): ` + reasonFloat},
		{"a name outside ASCII in the words is an escape", hand(Hop{Kind: ValuesHop}, Hop{Kind: FieldHop, Field: string(rune(0xE9))}), `malformed JSON: $: a value of type float64 cannot be written (the member "` + qesc(0xE9) + `" of the values of $): ` + reasonFloat},
		{"a name outside ASCII in a path is quoted by the path", hand(Hop{Kind: FieldHop, Field: string(rune(0xE9))}), `malformed JSON: $."` + qesc(0xE9) + `": a value of type float64 cannot be written: ` + reasonFloat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NewChecker(Writing, rawType).Err(nil, tc.by).Error(); got != tc.want {
				t.Errorf("got\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}

func longPath(n int) Path {
	p := Path{}
	for i := 1; i <= n; i++ {
		p = append(p, Member(fmt.Sprintf("m%d", i)))
	}
	return p
}

// ---- the names of a struct ----------------------------------------------------------------

// fieldsOf reads the names of the fields of a struct type as the Checker lists them, or the reason
// that the type is refused.
func fieldsOf(t *testing.T, typ reflect.Type) (names []string, reason string) {
	t.Helper()
	c := NewChecker(Writing, rawType)
	if r := c.Verdict(typ); r != nil {
		return nil, r.Reason
	}
	for _, f := range c.Fields(typ) {
		names = append(names, f.Name)
	}
	return names, ""
}

// reasonName is the rule for the name of a member of a struct, as the errors say it.
const reasonName = "a member name holds only ASCII letters, digits and underscores, and is not empty"

// tagNameRefused is the reason for the field F0 of a built struct whose tag name is refused; shown
// is the name as the error shows it (quoted, with an escape for what is not printable ASCII).
func tagNameRefused(shown string) string {
	return "field F0 has the tag name \"" + shown + "\"; " + reasonName
}

func TestStructTagRules(t *testing.T) {
	// Field i of a built struct is named F<i> by Go; the tag decides what it is called in JSON.
	cases := []struct {
		name   string
		tags   []string
		names  []string // in the order that Fields lists them: by UTF-16 order of the names
		reason string   // or the reason that the struct is refused
	}{
		{"no tag", []string{``}, []string{"F0"}, ""},
		{"a name", []string{`json:"a"`}, []string{"a"}, ""},
		{"an empty name keeps the field name", []string{`json:""`}, []string{"F0"}, ""},
		{"omitempty alone keeps the field name", []string{`json:",omitempty"`}, []string{"F0"}, ""},
		{"a name and omitempty", []string{`json:"a,omitempty"`}, []string{"a"}, ""},
		{"omitempty twice", []string{`json:"a,omitempty,omitempty"`}, []string{"a"}, ""},
		{"a name and a comma", []string{`json:"a,"`}, []string{"a"}, ""},
		{"dash leaves the field out", []string{`json:"-"`}, nil, ""},
		{"dash and comma names it dash, which is refused", []string{`json:"-,"`}, nil, tagNameRefused("-")},
		{"dash and omitempty names it dash, which is refused", []string{`json:"-,omitempty"`}, nil, tagNameRefused("-")},
		{"another key is not looked at", []string{`xml:"a"`}, []string{"F0"}, ""},
		{"another key before json", []string{`xml:"x" json:"n"`}, []string{"n"}, ""},
		{"another key after json", []string{`json:"o" xml:"x"`}, []string{"o"}, ""},
		{"names are sorted", []string{`json:"b"`, `json:"a"`, `json:"c"`}, []string{"a", "b", "c"}, ""},
		{"a tag name that is another field's Go name", []string{`json:"F1"`, ``}, nil, `two fields are named "F1"`},
		{"two fields of one name", []string{`json:"x"`, `json:"x"`}, nil, `two fields are named "x"`},
		{"two fields of one name, one with omitempty", []string{`json:"x"`, `json:"x,omitempty"`}, nil, `two fields are named "x"`},
		{"two fields named dash are refused at the first name", []string{`json:"-,"`, `json:"-,omitempty"`}, nil, tagNameRefused("-")},
		{"names that differ only by case are two fields", []string{`json:"a"`, `json:"A"`}, []string{"A", "a"}, ""},
		{"the option string", []string{`json:",string"`}, nil, `field F0 has the tag option "string"; only omitempty is allowed`},
		{"the option string after a name", []string{`json:"a,string"`}, nil, `field F0 has the tag option "string"; only omitempty is allowed`},
		{"the option string after omitempty", []string{`json:"a,omitempty,string"`}, nil, `field F0 has the tag option "string"; only omitempty is allowed`},
		{"the option omitzero", []string{`json:",omitzero"`}, nil, `field F0 has the tag option "omitzero"; only omitempty is allowed`},
		{"the option inline", []string{`json:",inline"`}, nil, `field F0 has the tag option "inline"; only omitempty is allowed`},
		{"an option in capitals", []string{`json:",OMITEMPTY"`}, nil, `field F0 has the tag option "OMITEMPTY"; only omitempty is allowed`},
		{"an empty option", []string{`json:"a,,omitempty"`}, nil, `field F0 has the tag option ""; only omitempty is allowed`},
		{"an option that is a space", []string{`json:"a, omitempty"`}, nil, `field F0 has the tag option " omitempty"; only omitempty is allowed`},
		{"a name with an apostrophe", []string{`json:"a'b"`}, nil, tagNameRefused("a'b")},
		{"a name with a backslash", []string{`json:"a\\b"`}, nil, tagNameRefused(`a\\b`)},
		{"a name with a control", []string{"json:\"a\\x01b\""}, nil, tagNameRefused("a" + qesc(1) + "b")},
		{"a name with a symbol that is not a letter", []string{"json:\"a" + string(rune(0x20AC)) + "b\""}, nil, tagNameRefused("a" + qesc(0x20AC) + "b")},
		{"a name with a combining mark", []string{"json:\"e" + string(rune(0x0301)) + "\""}, nil, tagNameRefused("e" + qesc(0x0301))},
		{"every punctuation mark that encoding/json allows is refused", []string{`json:"!#$%&()*+-./:;<=>?@[]^_{|}~ "`}, nil, tagNameRefused(`!#$%&()*+-./:;<=>?@[]^_{|}~ `)},
		{"letters and digits outside ASCII are refused", []string{"json:\"" + wide + "\""}, nil, tagNameRefused(qesc(0xE9) + qesc(0x0663) + qesc(0xFB33))},
		{"a name that begins with a digit", []string{`json:"1a"`}, []string{"1a"}, ""},
		{"a name of a single space is refused", []string{`json:" "`}, nil, tagNameRefused(" ")},
		{"a name that is a long one", []string{`json:"` + strings.Repeat("n", 500) + `"`}, []string{strings.Repeat("n", 500)}, ""},
		{"the first refusal is the one that is told", []string{`json:",string"`, `json:"a'b"`}, nil, `field F0 has the tag option "string"; only omitempty is allowed`},
		{"a field tagged dash is not looked at for its option", []string{`json:"-"`, `json:"b"`}, []string{"b"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			typ := structWith(tc.tags...)
			names, reason := fieldsOf(t, typ)
			if reason != tc.reason {
				t.Fatalf("the reason is %q, want %q", reason, tc.reason)
			}
			if !slices.Equal(names, tc.names) {
				t.Errorf("the names are %q, want %q", names, tc.names)
			}
		})
	}
}

func TestStructFieldsOrderAndFlags(t *testing.T) {
	field := func(name, jsonTag string) reflect.StructField {
		f := reflect.StructField{Name: name, Type: typeOf[int]()}
		if jsonTag != "" {
			f.Tag = reflect.StructTag(`json:"` + jsonTag + `"`)
		}
		return f
	}
	hidden := reflect.StructField{Name: "hidden", PkgPath: "jsonset", Type: typeOf[int]()}
	typ := reflect.StructOf([]reflect.StructField{
		field("Zeta", "zeta"),             // 0
		field("Alpha", "alpha,omitempty"), // 1
		hidden,                            // 2
		field("Skip", "-"),                // 3
		field("Mid", ""),                  // 4
		field("Under", "_"),               // 5
		field("Upper", "B"),               // 6
		field("Lower", "b,omitempty"),     // 7
		field("Zed", "Z"),                 // 8
		field("Lowest", "a_"),             // 9
		field("Digit", "10"),              // 10
		field("Digit2", "2"),              // 11
	})
	c := NewChecker(Reading, rawType)
	if r := c.Verdict(typ); r != nil {
		t.Fatalf("refused: %+v", r)
	}
	type listed struct {
		name  string
		index int
		omit  bool
	}
	var got []listed
	for _, f := range c.Fields(typ) {
		got = append(got, listed{f.Name, f.Index, f.OmitEmpty})
	}
	// By the code units of the names, which for names inside the rule are the ASCII bytes: digits
	// (and "10" before "2": the first unit decides, and a prefix is first), capitals, underscore,
	// small letters ("a_" before "alpha": '_' is 0x5F and 'l' is 0x6C). The order of names outside ASCII is tested through the keys of a map,
	// which are not under the rule, and through CompareUTF16.
	want := []listed{
		{"10", 10, false}, {"2", 11, false}, {"B", 6, false}, {"Mid", 4, false}, {"Z", 8, false}, {"_", 5, false},
		{"a_", 9, false}, {"alpha", 1, true}, {"b", 7, true}, {"zeta", 0, false},
	}
	if !slices.Equal(got, want) {
		t.Errorf("the fields are\n  %v\nwant\n  %v", got, want)
	}
	// The same answer a second time, from the checker's own memory.
	if again := c.Fields(typ); len(again) != len(want) || again[0] != c.Fields(typ)[0] {
		t.Errorf("the second answer is %v", again)
	}
}

func TestAFieldThatIsLeftOutIsNotLookedAt(t *testing.T) {
	cases := []struct {
		name string
		typ  reflect.Type
	}{
		{"an unexported float", typeOf[struct{ f float64 }]()},
		{"an unexported channel", typeOf[struct{ c chan int }]()},
		{"an unexported field of a type with a method", typeOf[struct{ j jsonVal }]()},
		{"an unexported field with a tag that is wrong", reflect.StructOf([]reflect.StructField{{Name: "F", Type: typeOf[int]()}, {Name: "h", PkgPath: "x", Type: typeOf[int](), Tag: `json:"a,string"`}})},
		{"a field tagged dash of a refused type", typeOf[struct {
			F float64 `json:"-"`
		}]()},
		{"a field tagged dash with a method", typeOf[struct {
			J jsonVal `json:"-"`
		}]()},
		{"an unexported field of the name of another", typeOf[struct {
			A int
			a int
		}]()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []Mode{Writing, Reading} {
				if r := NewChecker(mode, rawType).Verdict(tc.typ); r != nil {
					t.Errorf("%v: refused: %+v", mode, r)
				}
			}
		})
	}
}

func TestAnEmbeddedFieldIsRefusedWhateverItIs(t *testing.T) {
	type (
		exported   struct{ X int }
		unexported struct{ x int }
	)
	_ = unexported{}.x // the field is only there to be embedded
	cases := []struct {
		name  string
		typ   reflect.Type
		field string
	}{
		{"a struct with an exported name", typeOf[struct{ pair }](), "pair"},
		{"a pointer to a struct", typeOf[struct{ *pair }](), "pair"},
		{"a struct of one with no exported field", typeOf[struct{ unexported }](), "unexported"},
		{"a struct that is also exported", typeOf[struct{ exported }](), "exported"},
		{"a named integer", typeOf[struct{ myInt }](), "myInt"},
		{"a named string", typeOf[struct{ myString }](), "myString"},
		{"tagged with a name", typeOf[struct {
			pair `json:"p"`
		}](), "pair"},
		{"tagged dash", typeOf[struct {
			pair `json:"-"`
		}](), "pair"},
		{"after a field that is fine", typeOf[struct {
			A int
			pair
		}](), "pair"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []Mode{Writing, Reading} {
				r := NewChecker(mode, rawType).Verdict(tc.typ)
				want := "the embedded field " + tc.field + " is not part of ritueel's JSON; give it a name"
				if r == nil || r.Reason != want || r.Type != tc.typ {
					t.Errorf("%v: %+v, want the reason %q for %s", mode, r, want, tc.typ)
				}
			}
		})
	}
}

func TestValidNameRule(t *testing.T) {
	// The rule is ritueel's own: ASCII letters, digits and the underscore. The standard encoder is
	// not a witness for it (it takes more, and the encoding/json of Go 1.27 takes any text), so the
	// rule is written out again here and every character of the BMP up to U+3000 and some above is
	// tried between two letters. The table of every ASCII byte, alone and inside a name, the
	// forms with a dash, the Go names and the names of the formats are in names_test.go.
	rule := func(c rune) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
	}
	chars := []rune{0x1D400, 0x1F600, 0xFB33, 0xFF21, 0xFF10, 0x10FFFF, 0x212A, 0x0430, 0x00E9}
	for c := rune(1); c < 0x3000; c++ {
		chars = append(chars, c)
	}
	for _, c := range chars {
		name := "a" + string(c) + "b"
		if unquoted, err := strconv.Unquote(`"` + name + `"`); err != nil || unquoted != name || c == ',' {
			continue // a tag cannot hold this character as it is: the lookup of the tag does not read it as a name
		}
		typ := reflect.StructOf([]reflect.StructField{{Name: "F", Type: typeOf[int](), Tag: reflect.StructTag(`json:"` + name + `"`)}})
		_, reason := fieldsOf(t, typ)
		if accepted := reason == ""; accepted != rule(c) {
			t.Fatalf("%+q: accepted %v, the rule says %v (%s)", name, accepted, rule(c), reason)
		}
	}
	// The whole name, not only its characters: an empty name is the field's name, not a name.
	for _, name := range []string{"", "a", "ab"} {
		typ := reflect.StructOf([]reflect.StructField{{Name: "F", Type: typeOf[int](), Tag: reflect.StructTag(`json:"` + name + `"`)}})
		names, reason := fieldsOf(t, typ)
		want := name
		if name == "" {
			want = "F"
		}
		if reason != "" || !slices.Equal(names, []string{want}) {
			t.Errorf("the name %q: %q, %q", name, names, reason)
		}
	}
}

// ---- panics -------------------------------------------------------------------------------

func TestTheCheckerDoesNotPanicOnOddTypes(t *testing.T) {
	var ch chan<- int
	typesToTry := []reflect.Type{
		reflect.TypeOf(ch),
		reflect.TypeOf((*error)(nil)).Elem(),
		reflect.TypeOf((*any)(nil)),
		reflect.TypeOf((*any)(nil)).Elem(),
		reflect.ArrayOf(0, typeOf[float64]()),
		reflect.ArrayOf(3, reflect.PointerTo(typeOf[pair]())),
		reflect.SliceOf(reflect.SliceOf(reflect.SliceOf(typeOf[int]()))),
		reflect.MapOf(typeOf[string](), reflect.MapOf(typeOf[string](), typeOf[any]())),
		reflect.FuncOf([]reflect.Type{typeOf[int]()}, []reflect.Type{typeOf[int]()}, false),
		reflect.StructOf(nil),
		reflect.StructOf([]reflect.StructField{{Name: "A", Type: typeOf[pair]()}, {Name: "B", Type: reflect.PointerTo(typeOf[loop]())}}),
		reflect.PointerTo(reflect.PointerTo(reflect.PointerTo(typeOf[int]()))),
		typeOf[selfMap](), typeOf[selfSlice](), typeOf[loop](),
	}
	for _, typ := range typesToTry {
		for _, mode := range []Mode{Writing, Reading} {
			c := NewChecker(mode, rawType)
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%v %s: panic: %v", mode, typ, r)
					}
				}()
				if r := c.Verdict(typ); r != nil {
					_ = c.Err(Path{Member("x")}, r).Error()
				} else if typ.Kind() == reflect.Struct {
					_ = c.Fields(typ)
				}
			}()
		}
	}
}
