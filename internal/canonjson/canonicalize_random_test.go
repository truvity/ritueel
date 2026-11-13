package canonjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Canonicalize and IsCanonical are written from the parse tree of strictjson. These tests compare
// them with a canonical form written here from RFC 8785 and the order of the reference, on random
// trees that are laid out as text in random ways, so that neither reader of the text is the witness
// of the other.

// randomDocTree is a random document as a value: map[string]any, []any, string, bool and json.Number.
func randomDocTree(r *rand.Rand, depth int) any {
	switch k := r.Intn(8); {
	case k == 0 && depth > 0:
		m := map[string]any{}
		for range r.Intn(6) {
			m[randomName(r)] = randomDocTree(r, depth-1)
		}
		return m
	case k == 1 && depth > 0:
		l := []any{}
		for range r.Intn(4) {
			l = append(l, randomDocTree(r, depth-1))
		}
		return l
	case k == 2:
		return randomName(r)
	case k == 3:
		return r.Intn(2) == 0
	case k == 4:
		return json.Number([]string{"0", "-0", "9223372036854775807", "-9223372036854775808", "-1", "10", "100"}[r.Intn(7)])
	default:
		return json.Number(strconv.Itoa(r.Intn(2001) - 1000))
	}
}

// layout writes a tree as text in a random way: white space between tokens, members in any order,
// every character that can be escaped sometimes escaped, in upper or lower case, a character above
// U+FFFF as a pair or as it is.
func layout(r *rand.Rand, v any) string {
	ws := func() string { return []string{"", "", "", " ", "\n", "\t", "\r\n", "  \t "}[r.Intn(8)] }
	var b strings.Builder
	str := func(s string) {
		b.WriteByte('"')
		for _, c := range s {
			switch {
			case c == '"' || c == '\\':
				b.WriteByte('\\')
				b.WriteRune(c)
			case c < 0x20 || r.Intn(6) == 0:
				switch {
				case c == '/' && r.Intn(2) == 0:
					b.WriteString(`\/`)
				case c == '\n' && r.Intn(2) == 0:
					b.WriteString(`\n`)
				case c > 0xFFFF:
					hi, lo := 0xD800+((c-0x10000)>>10), 0xDC00+((c-0x10000)&0x3FF)
					format := "%cu%04x%cu%04x"
					if r.Intn(2) == 0 {
						format = "%cu%04X%cu%04X"
					}
					fmt.Fprintf(&b, format, '\\', hi, '\\', lo)
				default:
					format := "%cu%04x"
					if r.Intn(2) == 0 {
						format = "%cu%04X"
					}
					fmt.Fprintf(&b, format, '\\', c)
				}
			default:
				b.WriteRune(c)
			}
		}
		b.WriteByte('"')
	}
	var value func(v any)
	value = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			names := make([]string, 0, len(v))
			for k := range v {
				names = append(names, k)
			}
			r.Shuffle(len(names), func(i, j int) { names[i], names[j] = names[j], names[i] })
			b.WriteString("{" + ws())
			for i, k := range names {
				if i > 0 {
					b.WriteString(ws() + "," + ws())
				}
				str(k)
				b.WriteString(ws() + ":" + ws())
				value(v[k])
			}
			b.WriteString(ws() + "}")
		case []any:
			b.WriteString("[" + ws())
			for i, e := range v {
				if i > 0 {
					b.WriteString(ws() + "," + ws())
				}
				value(e)
			}
			b.WriteString(ws() + "]")
		case string:
			str(v)
		case bool:
			b.WriteString(strconv.FormatBool(v))
		case json.Number:
			b.WriteString(string(v))
		}
	}
	b.WriteString(ws())
	value(v)
	b.WriteString(ws())
	return b.String()
}

func TestCanonicalizeAgreesWithTheReferenceOnRandomTrees(t *testing.T) {
	r := rand.New(rand.NewSource(8785))
	for i := range 3000 {
		tree := randomDocTree(r, 4)
		m, ok := tree.(map[string]any)
		if !ok {
			m = map[string]any{randomName(r): tree}
		}
		var want bytes.Buffer
		refWrite(t, &want, m)
		text := layout(r, m)
		got, err := Canonicalize([]byte(text))
		if err != nil {
			t.Fatalf("tree %d: %v\n%.300q", i, err, text)
		}
		if !bytes.Equal(got, want.Bytes()) {
			t.Fatalf("tree %d: the canonical form of\n  %.300q\nis\n  %.300q\nwant\n  %.300q", i, text, got, want.Bytes())
		}
		if len(got) > len(text) {
			t.Fatalf("tree %d: the canonical form is longer than the text: %d against %d", i, len(got), len(text))
		}
		if again, err := Canonicalize(got); err != nil || !bytes.Equal(again, got) {
			t.Fatalf("tree %d: the canonical form is not a fixed point: %v", i, err)
		}
		is, err := IsCanonical([]byte(text))
		if err != nil || is != (text == want.String()) {
			t.Fatalf("tree %d: IsCanonical = %v, %v for %.200q", i, is, err, text)
		}
		if is, err := IsCanonical(want.Bytes()); err != nil || !is {
			t.Fatalf("tree %d: the reference form is not canonical: %v %v", i, is, err)
		}
		// The order of the members at every depth is the reference order, and strict.
		checkOrder(t, got)
		// The value of the document is not changed: the standard decoder reads the same tree from
		// the canonical form as from the text.
		if a, b := decodeAny(t, text), decodeAny(t, string(got)); fmt.Sprint(a) != fmt.Sprint(b) {
			t.Fatalf("tree %d: the canonical form means something else", i)
		}
	}
}

func decodeAny(t *testing.T, text string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return normalizeNumbers(v)
}

func normalizeNumbers(v any) any {
	switch v := v.(type) {
	case map[string]any:
		for k, e := range v {
			v[k] = normalizeNumbers(e)
		}
	case []any:
		for i, e := range v {
			v[i] = normalizeNumbers(e)
		}
	case json.Number:
		n, _ := strconv.ParseInt(string(v), 10, 64)
		return n
	}
	return v
}

// checkOrder reads the names of every object in canonical text in the order they are written and
// checks that they are strictly in the reference order.
func checkOrder(t *testing.T, data []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack [][]string
	var walk func()
	walk = func() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		d, isDelim := tok.(json.Delim)
		if !isDelim {
			return
		}
		switch d {
		case '{':
			var names []string
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					t.Fatal(err)
				}
				names = append(names, k.(string))
				walk()
			}
			if _, err := dec.Token(); err != nil {
				t.Fatal(err)
			}
			if !sort.SliceIsSorted(names, func(i, j int) bool { return reference(names[i], names[j]) < 0 }) {
				t.Fatalf("the names %+q are not in the reference order", names)
			}
			for i := 1; i < len(names); i++ {
				if reference(names[i-1], names[i]) == 0 {
					t.Fatalf("the name %q is there twice", names[i])
				}
			}
			stack = append(stack, names)
		case '[':
			for dec.More() {
				walk()
			}
			if _, err := dec.Token(); err != nil {
				t.Fatal(err)
			}
		}
	}
	walk()
	_ = stack
}

func TestCanonicalizeRefusesWhatItCannotWriteFromTheTree(t *testing.T) {
	// The cases of the rules are in brokenRules; here are the ones that a random tree can reach: a
	// document made of valid pieces that put together break one rule.
	r := rand.New(rand.NewSource(1))
	for i := range 500 {
		tree := randomDocTree(r, 3)
		m, ok := tree.(map[string]any)
		if !ok {
			m = map[string]any{"k": tree}
		}
		text := layout(r, m)
		// A member repeated at the end of the top object, spelt as an escape when it can be.
		name := "x"
		if len(m) > 0 {
			for k := range m {
				name = k
				break
			}
		}
		quoted, _ := json.Marshal(name)
		trimmed := strings.TrimRight(text, " \t\r\n")
		if !strings.HasSuffix(trimmed, "}") {
			t.Fatalf("a document that does not end in a brace: %q", text)
		}
		body := strings.TrimSuffix(trimmed, "}")
		sep := ","
		if strings.HasSuffix(strings.TrimRight(body, " \t\r\n"), "{") {
			sep = ""
		}
		if len(m) > 0 { // an empty object has no member to repeat
			dup := body + sep + string(quoted) + ":1}"
			if _, err := Canonicalize([]byte(dup)); err == nil {
				t.Fatalf("tree %d: a repeated member was written: %.200q", i, dup)
			}
			if is, err := IsCanonical([]byte(dup)); is || err == nil {
				t.Fatalf("tree %d: IsCanonical = %v, %v for a repeated member", i, is, err)
			}
		}
		// A float at the end.
		if _, err := Canonicalize([]byte(body + sep + `"zz":1.5}`)); err == nil {
			t.Fatalf("tree %d: a float was written", i)
		}
	}
}

func TestCanonicalizeOfLongListsAndObjects(t *testing.T) {
	for _, n := range []int{0, 1, 99, 100, 101, 255, 256, 257, 1000, 9000} {
		var list, members []string
		tree := map[string]any{}
		var l []any
		for i := range n {
			list = append(list, fmt.Sprintf(" %d ", i))
			members = append(members, fmt.Sprintf(`"k%d" : %d`, n-i, i))
			l = append(l, json.Number(strconv.Itoa(i)))
			tree[fmt.Sprintf("k%d", n-i)] = json.Number(strconv.Itoa(i))
		}
		doc := `{ "l" : [` + strings.Join(list, ",") + `], "m" : {` + strings.Join(members, ",") + `} }`
		var want bytes.Buffer
		refWrite(t, &want, map[string]any{"l": l, "m": tree})
		got, err := Canonicalize([]byte(doc))
		if err != nil || !bytes.Equal(got, want.Bytes()) {
			t.Errorf("%d: %v (%d bytes, want %d)", n, err, len(got), want.Len())
		}
	}
}
