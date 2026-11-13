package strictjson

import (
	"reflect"
	"strings"
	"testing"
)

// A member whose name folds to a field's name (the same name in another letter case, or with a
// look-alike such as the Kelvin sign for k) is refused with the name that it must be spelt. When
// the name folds to more than one field, the fields are walked in the order of their names, so
// the text is the same on every run: Go's map order is random, and a walk over a map would give
// a different field from one run to the next.

const foldRuns = 200

func TestTheSameTextOnEveryRunWhenANameFoldsToTwoFields(t *testing.T) {
	kelvin, longS := string(rune(0x212A)), string(rune(0x17F))
	cases := []struct {
		name   string
		fields []string // the names, in the order that they are declared
		member string
		first  string // the field that the text names: the first in the order of the names
	}{
		{"the Kelvin sign against k and K", []string{"k", "K"}, kelvin, "K"},
		{"the Kelvin sign against K and k, declared the other way", []string{"K", "k"}, kelvin, "K"},
		{"the long s against s and S", []string{"s", "S"}, longS, "S"},
		{"the long s against S and s, declared the other way", []string{"S", "s"}, longS, "S"},
		{"the Kelvin sign and k against four fields", []string{"kk", "KK", "Kk", "kK"}, kelvin + "k", "KK"},
		{"the same, declared in reverse", []string{"kK", "Kk", "KK", "kk"}, kelvin + "k", "KK"},
		{"both look-alikes against eight fields", []string{"sk", "sK", "Sk", "SK", "sk_", "ss", "kS", "ks"}, longS + kelvin, "SK"},
		{"an ordinary letter case against three fields", []string{"ab", "aB", "AB"}, "Ab", "AB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			types := make([]reflect.Type, len(tc.fields))
			for i := range types {
				types[i] = reflect.TypeFor[int]()
			}
			typ := structOf(tc.fields, types, nil)
			doc := `{"` + tc.member + `":1}`
			want := mal(`$."`+qescAll(tc.member)+`"`, "the member must be spelt "+shownName(tc.first))
			if tc.member == "Ab" {
				want = mal("$.Ab", "the member must be spelt AB")
			}
			seen := map[string]int{}
			for range foldRuns {
				_, err := read(typ, doc, Options{})
				if err == nil {
					t.Fatalf("%s was read", doc)
				}
				seen[err.Error()]++
			}
			if len(seen) != 1 {
				t.Errorf("%d different texts in %d runs: %v", len(seen), foldRuns, seen)
			}
			for text := range seen {
				if text != want {
					t.Errorf("the text is\n  %q\nwant\n  %q", text, want)
				}
			}
		})
	}
	t.Run("an ordinary case that folds to one field only: the exact match wins", func(t *testing.T) {
		typ := structOf([]string{"ab", "AB"}, []reflect.Type{reflect.TypeFor[int](), reflect.TypeFor[int]()}, nil)
		v, err := read(typ, `{"AB":2,"ab":1}`, Options{})
		if err != nil || v.Field(0).Int() != 1 || v.Field(1).Int() != 2 {
			t.Errorf("%v, %v", v, err)
		}
	})
}

// qescAll writes every character of the name as qesc does, but leaves printable ASCII as it is: the
// text of a path that is quoted.
func qescAll(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteString(qesc(r))
		}
	}
	return b.String()
}

// The text names the field as it is spelt in the document's format, and a look-alike is never shown
// as the letter it imitates, in the path or in the words.
func TestTheLookAlikeIsShownAsAnEscape(t *testing.T) {
	kelvin := string(rune(0x212A))
	typ := structOf([]string{"k"}, []reflect.Type{reflect.TypeFor[int]()}, nil)
	_, err := read(typ, `{"`+kelvin+`":1}`, Options{})
	if err == nil {
		t.Fatal("read")
	}
	if strings.Contains(err.Error(), kelvin) || strings.ContainsFunc(err.Error(), func(r rune) bool { return r >= 0x80 }) {
		t.Errorf("the text holds a character outside ASCII: %q", err)
	}
	if want := mal(`$."`+qesc(0x212A)+`"`, "the member must be spelt k"); err.Error() != want {
		t.Errorf("got %q, want %q", err, want)
	}
	// The same document written with the escape of the Kelvin sign says the same.
	_, err2 := read(typ, `{"`+qesc(0x212A)+`":1}`, Options{})
	if err2 == nil || err2.Error() != err.Error() {
		t.Errorf("written with an escape: %v", err2)
	}
}

// A name that folds to a field is refused in the order of the document too: the first member that
// does, not the one that comes last.
func TestTheFirstMemberThatFoldsIsTheOneRefused(t *testing.T) {
	typ := structOf([]string{"a", "b"}, []reflect.Type{reflect.TypeFor[int](), reflect.TypeFor[int]()}, nil)
	for _, doc := range []string{`{"B":1,"A":2}`, `{"a":1,"B":2,"A":3}`} {
		_, err := read(typ, doc, Options{})
		want := mal("$.B", "the member must be spelt b")
		if err == nil || err.Error() != want {
			t.Errorf("%s: %v; want %s", doc, err, want)
		}
	}
}
