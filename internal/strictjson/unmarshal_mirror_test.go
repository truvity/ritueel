package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

// ---- the standard decoder as a witness ----------------------------------------------------

// normalizeStd reads a value that the standard decoder filled, with its numbers kept as
// json.Number so that none is rounded, and turns each json.Number that sits in an interface into
// the int64 that this reader gives. It reports false for a number that is no int64, which this
// reader refuses.
func normalizeStd(v reflect.Value) bool {
	ok := true
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return true
		}
		e := v.Elem()
		if n, isNumber := e.Interface().(json.Number); isNumber {
			i, err := strconv.ParseInt(string(n), 10, 64)
			if err != nil {
				return false
			}
			v.Set(reflect.ValueOf(i))
			return true
		}
		// A map or a slice in an interface is not addressable: copy, fix, put back.
		c := reflect.New(e.Type()).Elem()
		c.Set(e)
		if !normalizeStd(c) {
			return false
		}
		v.Set(c)
	case reflect.Pointer:
		if !v.IsNil() {
			return normalizeStd(v.Elem())
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() && !normalizeStd(v.Field(i)) {
				ok = false
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return true
		}
		for i := range v.Len() {
			if !normalizeStd(v.Index(i)) {
				ok = false
			}
		}
	case reflect.Array:
		for i := range v.Len() {
			if !normalizeStd(v.Index(i)) {
				ok = false
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		type kv struct{ k, e reflect.Value }
		var fixes []kv
		for iter.Next() {
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(iter.Value())
			if !normalizeStd(e) {
				ok = false
			}
			fixes = append(fixes, kv{iter.Key(), e})
		}
		for _, f := range fixes {
			v.SetMapIndex(f.k, f.e)
		}
	}
	return ok
}

// decodeStd reads data into a new value of the type by the standard decoder, with numbers kept
// whole.
func decodeStd(typ reflect.Type, data string) (reflect.Value, error) {
	p := reflect.New(typ)
	dec := json.NewDecoder(strings.NewReader(data))
	dec.UseNumber()
	err := dec.Decode(p.Interface())
	if err == nil && dec.More() {
		err = fmt.Errorf("data after the value")
	}
	return p.Elem(), err
}

// A tally of what the two readers did with the same document and type.
type tally struct{ both, ours, std, neither, disagree, stdNumber, minusZero int }

// compare reads the document into the type with both readers and applies the one property that a
// stricter reader must have: where this reader accepts, the standard decoder accepts, and both give
// equal values. It returns a text for a break of it, "" otherwise.
func (c *tally) compare(typ reflect.Type, data string, opts Options) string {
	ours, oerr := read(typ, data, opts)
	std, serr := decodeStd(typ, data)
	switch {
	case oerr == nil && serr != nil && strings.Contains(serr.Error(), "number -0 into"):
		// This reader reads -0 as the integer zero for an unsigned kind, and the standard decoder
		// refuses it. It is reported (it is not a value that differs) and not compared here.
		c.minusZero++
		return ""
	case oerr == nil && serr != nil:
		c.ours++
		return fmt.Sprintf("this reader accepted %.80q for %s, the standard decoder refused it: %v", data, typ, serr)
	case oerr != nil && serr == nil:
		c.std++
		return ""
	case oerr != nil:
		c.neither++
		return ""
	}
	if !normalizeStd(std) {
		c.stdNumber++
		return fmt.Sprintf("this reader accepted %.80q for %s with a number that no int64 holds", data, typ)
	}
	if !reflect.DeepEqual(ours.Interface(), std.Interface()) {
		c.disagree++
		return fmt.Sprintf("for %.80q into %s this reader gives\n  %#v\nthe standard decoder gives\n  %#v", data, typ, ours.Interface(), std.Interface())
	}
	c.both++
	return ""
}

// variants of a document that is valid: the same document laid out another way, and edited.
func variants(t *testing.T, doc string, r *rand.Rand) []string {
	out := []string{doc}
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(doc), "", "  "); err == nil {
		out = append(out, buf.String())
	}
	if err := json.Compact(&buf, []byte(doc)); err == nil {
		out = append(out, buf.String())
	}
	// Surrounded by white space, and with the members of the top object in the reverse order.
	out = append(out, " \n\t"+doc+"\r\n ")
	if root, err := Parse([]byte(doc), 0); err == nil && root.Kind == Object && len(root.Members) > 1 {
		var parts []string
		for i := len(root.Members) - 1; i >= 0; i-- {
			name, _ := json.Marshal(root.Members[i].Name)
			parts = append(parts, string(name)+":"+doc[root.Members[i].Value.Start:root.Members[i].Value.End])
		}
		out = append(out, "{"+strings.Join(parts, ",")+"}")
	}
	// An unknown member, and a member whose name is in another case, at the top.
	if strings.HasPrefix(doc, "{") {
		rest := doc[1:]
		sep := ","
		if strings.TrimSpace(rest) == "}" {
			sep = ""
		}
		out = append(out, `{"zzz":[1,{"y":"x"}]`+sep+rest)
		if root, err := Parse([]byte(doc), 0); err == nil && len(root.Members) > 0 {
			name := root.Members[0].Name
			flipped := strings.ToUpper(name)
			if flipped == name {
				flipped = strings.ToLower(name)
			}
			if open := strings.Index(doc, `"`); flipped != name && open >= 0 {
				b, _ := json.Marshal(flipped)
				out = append(out, doc[:open]+string(b)+doc[open+len(strconv.Quote(name)):])
			}
		}
	}
	// Edits by bytes: a character taken out, put in, or changed, at places in the text.
	pool := []byte(`{}[]",:-0189.eEtfnu\ aA`)
	for range 25 {
		b := []byte(doc)
		if len(b) == 0 {
			break
		}
		i := r.Intn(len(b))
		switch r.Intn(3) {
		case 0:
			b = append(b[:i], b[i+1:]...)
		case 1:
			b = append(b[:i], append([]byte{pool[r.Intn(len(pool))]}, b[i:]...)...)
		default:
			b[i] = pool[r.Intn(len(pool))]
		}
		out = append(out, string(b))
	}
	return out
}

func TestWhereBothDecodersAcceptADocumentTheyGiveEqualValues(t *testing.T) {
	r := rand.New(rand.NewSource(1927))
	var c tally
	var problems []string
	add := func(p string) {
		if p != "" && len(problems) < 20 {
			problems = append(problems, p)
		}
	}
	for _, tc := range acceptedTargets() {
		for _, p := range placesOf(tc.typ, tc.doc, isObjectKind(tc.typ), false) {
			for _, doc := range variants(t, p.doc, r) {
				for _, opts := range []Options{{}, {AllowUnknown: true}} {
					add(c.compare(p.typ, doc, opts))
				}
			}
		}
	}
	// The interface: the same numbers, in the one type that the standard decoder reads as it likes.
	for _, tc := range acceptedAnys() {
		holder := reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[any](), Tag: `json:"F"`}})
		for _, doc := range variants(t, `{"F":`+tc.doc+`}`, r) {
			add(c.compare(holder, doc, Options{AllowUnknown: true}))
		}
		add(c.compare(reflect.TypeFor[map[string]any](), `{"k":`+tc.doc+`}`, Options{}))
	}
	t.Logf("both accepted and agreed: %d; only the standard decoder accepted: %d; neither: %d", c.both, c.std, c.neither)
	for _, p := range problems {
		t.Errorf("%s", p)
	}
	if c.both < 500 || c.std == 0 || c.neither == 0 {
		t.Errorf("the comparison did not exercise every outcome: %+v", c)
	}
}

// ---- no input and no type makes a panic ---------------------------------------------------

func noPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panic: %v", what, r)
		}
	}()
	f()
}

func TestNoTypeAndNoValueMakesAPanic(t *testing.T) {
	docs := []string{``, `{}`, `{"F":1}`, `{"F":[]}`, `{"F":{}}`, `{"F":"AA=="}`, `x`, `{"F":null}`, `[]`}
	var ch chan int
	var fn func()
	var i int
	odd := []any{
		new(chan int), &ch, &fn, new(func()), new(complex128), new(float64), new(uintptr), new(unsafe.Pointer), &i,
		new(struct{ C chan int }), new(struct{ P unsafe.Pointer }), new([0]func()), new(map[chan int]int), new(**int),
		new(*any), new(error), new(fmtStringerTest), new([]error), new(map[string]error), new(struct{ E error }),
		new(struct{}), new(struct{ _ int }), new(struct{ a, b int }), new([0]int), new(map[string]struct{}),
		new(map[string]*struct{}), new(*struct{}), new(**struct{}), new(*Raw), new(**Raw), new([]Raw), new(map[string]*Raw),
		new(*[]byte), new(**[]byte), new(selfMapTest), new(selfSliceTest), new(selfStructTest), new(*selfStructTest),
		new(struct{ R *Raw }), new(struct{ A *any }), new(struct{ B [3]byte }), new(map[myKey]myKey),
		new(map[string]map[string]map[string]any), new([]any), new([2]any), new(anything), new(*anything),
		reflect.New(reflect.StructOf(nil)).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.TypeFor[any]()}})).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.PointerTo(reflect.TypeFor[Raw]())}})).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.ArrayOf(0, reflect.TypeFor[int]())}})).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.MapOf(reflect.TypeFor[string](), reflect.TypeFor[Raw]())}})).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.FuncOf(nil, nil, false)}})).Interface(),
		reflect.New(reflect.StructOf([]reflect.StructField{{Name: "F", Type: reflect.ChanOf(reflect.BothDir, reflect.TypeFor[int]())}})).Interface(),
		reflect.New(reflect.SliceOf(reflect.SliceOf(reflect.TypeFor[Raw]()))).Interface(),
		reflect.New(reflect.PointerTo(reflect.PointerTo(reflect.TypeFor[point]()))).Interface(),
	}
	for _, v := range odd {
		for _, doc := range docs {
			for _, opts := range []Options{{}, {AllowUnknown: true}, {MaxBytes: 1}, {MaxBytes: -5}} {
				noPanic(t, fmt.Sprintf("%T %q", v, doc), func() { _ = Unmarshal([]byte(doc), v, opts) })
			}
		}
	}
	// A value that is not a pointer, or a pointer that is nil, in every shape.
	var np *point
	var npp **point
	var nm *map[string]int
	var nr *Raw
	var na *any
	var nilIface any
	var holdsNil any = np
	for _, v := range []any{nil, np, npp, nm, nr, na, nilIface, holdsNil, point{}, 3, "x", ch, fn, []int{1}, [1]int{}, map[string]int{}, Raw(`{}`), &holdsNil, &nilIface, &np} {
		noPanic(t, fmt.Sprintf("%T", v), func() { _ = Unmarshal([]byte(`{"X":1}`), v, Options{}) })
	}
	t.Run("nil input", func(t *testing.T) {
		var v point
		fail(t, Unmarshal(nil, &v, Options{}), mal("$", "not one JSON object"))
		var m map[string]int
		fail(t, Unmarshal([]byte{}, &m, Options{}), mal("$", "not one JSON object"))
	})
	t.Run("a pointer to a nil interface and to an interface that holds a nil pointer", func(t *testing.T) {
		var nilIface any
		if err := Unmarshal([]byte(`{"X":1}`), &nilIface, Options{}); err != nil || !reflect.DeepEqual(nilIface, map[string]any{"X": int64(1)}) {
			t.Errorf("%#v, %v", nilIface, err)
		}
		var np *point
		var holds any = np
		if err := Unmarshal([]byte(`{"X":1}`), &holds, Options{}); err != nil || !reflect.DeepEqual(holds, map[string]any{"X": int64(1)}) {
			t.Errorf("%#v, %v", holds, err)
		}
		// The interface itself, passed as v, holds a nil pointer: that is a mistake of the caller.
		var holdsNilPtr any = np
		if err := Unmarshal([]byte(`{"X":1}`), holdsNilPtr, Options{}); err == nil {
			t.Error("a nil pointer in an interface was filled")
		}
	})
}

type (
	fmtStringerTest interface{ String() string }
	selfMapTest     map[string]selfMapTest
	selfSliceTest   []selfSliceTest
	selfStructTest  struct {
		Next *selfStructTest `json:"next"`
		L    []selfStructTest
		M    map[string]selfStructTest
	}
)

func TestARecursiveTypeIsReadAsDeepAsADocumentMayBe(t *testing.T) {
	var m selfMapTest
	if err := Unmarshal([]byte(nested(MaxDepth)), &m, Options{AllowUnknown: true}); err == nil {
		// {"a":{"a":...}} has a member "a"; the map takes any name
	} else {
		t.Fatal(err)
	}
	depth := 0
	for x := m; x != nil; depth++ {
		x = x["a"]
	}
	if depth != MaxDepth {
		t.Errorf("a map of maps is %d deep, want %d", depth, MaxDepth)
	}
	var s selfStructTest
	doc := strings.Repeat(`{"next":`, MaxDepth-1) + `{}` + strings.Repeat(`}`, MaxDepth-1)
	if err := Unmarshal([]byte(doc), &s, Options{}); err != nil {
		t.Fatal(err)
	}
	depth = 0
	for p := &s; p != nil; p = p.Next {
		depth++
	}
	if depth != MaxDepth {
		t.Errorf("a list of structs is %d deep, want %d", depth, MaxDepth)
	}
	// One more level is refused, before any of it is filled.
	over := strings.Repeat(`{"next":`, MaxDepth) + `{}` + strings.Repeat(`}`, MaxDepth)
	s2 := selfStructTest{}
	if err := Unmarshal([]byte(over), &s2, Options{}); err == nil || s2.Next != nil {
		t.Errorf("%v %v", err, s2.Next)
	}
}

func TestRandomTextNeverMakesAPanicAndKeepsTheRules(t *testing.T) {
	r := rand.New(rand.NewSource(8259))
	pool := []string{`{`, `}`, `[`, `]`, `"`, `:`, `,`, `-`, `0`, `1`, `9`, `.`, `e`, `E`, `+`, ` `, "\n", `true`, `false`, `null`, `"a"`, `"F"`, `"X"`, `\`, `u`, `d800`, `dc00`, `00e9`,
		"\xff", "\xc3", `"AA=="`, `[]`, `{}`, `"b"`, `"😀"`, "\x00", "\x01"}
	prefill := func() []any {
		return []any{&fullT{S: "keep"}, &deepT{Top: 4}, &map[string]any{"keep": int64(1)}, new(any), &Raw{'{', '}'}, &struct {
			F any
			X int
		}{F: "keep", X: 5}}
	}
	var accepted, refusedCount int
	for range 30000 {
		var b strings.Builder
		for range r.Intn(14) {
			b.WriteString(pool[r.Intn(len(pool))])
		}
		doc := b.String()
		if r.Intn(2) == 0 {
			doc = "{" + doc // most random text starts nowhere near an object; give half of it a start
		}
		checkErr := Check([]byte(doc), 0)
		for _, v := range prefill() {
			rv := reflect.ValueOf(v).Elem()
			before := deepCopy(rv)
			var err error
			noPanic(t, fmt.Sprintf("%T %q", v, doc), func() { err = Unmarshal([]byte(doc), v, Options{AllowUnknown: true}) })
			if checkErr != nil && err == nil {
				t.Fatalf("Check refused %q and Unmarshal into %T accepted it", doc, v)
			}
			if err != nil && !reflect.DeepEqual(before.Interface(), rv.Interface()) {
				t.Fatalf("%q into %T: an error and a changed value", doc, v)
			}
			if err != nil && rv.Type() != reflect.TypeFor[any]() {
				// An error that is about the document and not about the type has the one form.
				if !strings.HasPrefix(err.Error(), "malformed JSON: $") {
					t.Fatalf("%q into %T: the error is %q", doc, v, err)
				}
			}
		}
		if checkErr == nil {
			accepted++
		} else {
			refusedCount++
		}
	}
	if accepted < 50 || refusedCount < 50 {
		t.Errorf("the random text was not varied enough: %d accepted, %d refused", accepted, refusedCount)
	}
}
