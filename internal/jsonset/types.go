package jsonset

import (
	"reflect"
	"slices"
	"strings"
)

// Mode says what the Checker's answers are for.
type Mode uint8

const (
	// Writing asks whether a Go type can be written. An interface can, unless it declares one of
	// the four marshal or unmarshal methods: the value it holds is judged.
	Writing Mode = iota
	// Reading asks whether a Go type can be filled from a document. An interface can only when it
	// has no methods.
	Reading
)

// HopKind is how a Refusal leads from the type that was asked about to the type at fault.
type HopKind uint8

const (
	// FieldHop leads to a field of a struct, named by Hop.Field.
	FieldHop HopKind = iota
	// ElementsHop leads to the element type of a slice or an array: no index belongs to a type.
	ElementsHop
	// ValuesHop leads to the value type of a map: no member name belongs to a type.
	ValuesHop
)

// Hop is one step of a Refusal's way.
type Hop struct {
	Kind  HopKind
	Field string
}

// Refusal says why a Go type is outside the set: the type at fault, the reason, and the way that
// leads from the type that was asked about to it.
type Refusal struct {
	Hops   []Hop
	Type   reflect.Type
	Reason string
}

// Field is one member of a struct as the writer names it and the reader matches it.
type Field struct {
	// Index is the position of the field in the struct, for reflect.Value.Field.
	Index int
	// Name is the member name: the tag name or the field name.
	Name string
	// OmitEmpty is the option omitempty: the writer leaves the field out when it is empty, and
	// the reader does nothing with it.
	OmitEmpty bool
}

// A Checker holds the answers for the types it was asked about, so that a type is judged once.
// It is for one writer or one reader, not for use by several goroutines.
type Checker struct {
	mode     Mode
	raw      reflect.Type
	structs  map[reflect.Type]*structInfo
	verdicts map[reflect.Type]*Refusal
}

type structInfo struct {
	fields []Field
	err    string
}

// NewChecker returns a Checker for the mode. raw is the type of a document that is already JSON
// (strictjson.Raw): it is in the set whatever methods it has.
func NewChecker(mode Mode, raw reflect.Type) *Checker {
	return &Checker{
		mode:     mode,
		raw:      raw,
		structs:  map[reflect.Type]*structInfo{},
		verdicts: map[reflect.Type]*Refusal{},
	}
}

// Verdict says whether the Go type t is in the set, whatever the value: nil when it is, else the
// reason. The answer follows the type into its fields, its elements, its map values and what a
// pointer points to.
func (c *Checker) Verdict(t reflect.Type) *Refusal {
	if r, seen := c.verdicts[t]; seen {
		return r
	}
	r := c.walk(t, map[reflect.Type]bool{})
	c.verdicts[t] = r
	return r
}

// Err is the error for a refusal reached from the value at the path at. A refusal that leads
// through a list or a map says so in words, since no index or member name belongs to a type:
// "the elements of $.l", "the values of $.m".
func (c *Checker) Err(at Path, r *Refusal) error {
	verb := "written"
	if c.mode == Reading {
		verb = "read"
	}
	p := slices.Clone(at)
	i := 0
	for ; i < len(r.Hops) && r.Hops[i].Kind == FieldHop; i++ {
		p = append(p, Member(r.Hops[i].Field))
	}
	where := ""
	if i < len(r.Hops) {
		phrase := p.String()
		for _, h := range r.Hops[i:] {
			switch h.Kind {
			case ElementsHop:
				phrase = "the elements of " + phrase
			case ValuesHop:
				phrase = "the values of " + phrase
			case FieldHop:
				phrase = "the member " + Shown(h.Field) + " of " + phrase
			}
		}
		where = " (" + phrase + ")"
	}
	return Errorf(p, "a value of type %s cannot be %s%s: %s", r.Type, verb, where, r.Reason)
}

// Fields lists the members of the struct type t in the order of their names as UTF-16 code
// units, which is the order the writer writes them in. The type must have passed Verdict.
func (c *Checker) Fields(t reflect.Type) []Field {
	return c.structInfo(t).fields
}

func (c *Checker) structInfo(t reflect.Type) *structInfo {
	info := c.structs[t]
	if info == nil {
		info = structFields(t)
		c.structs[t] = info
	}
	return info
}

// walk looks for a part of t that is outside the set and returns the first it finds. seen holds
// the types looked at in this walk, so that a type that refers to itself, or one that turns up
// twice, is looked at once; the first look finds any refusal inside it.
func (c *Checker) walk(t reflect.Type, seen map[reflect.Type]bool) *Refusal {
	if seen[t] || t == c.raw {
		return nil
	}
	seen[t] = true
	if reason := foreign(t); reason != "" {
		return &Refusal{Type: t, Reason: reason}
	}
	switch t.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Interface:
		if c.mode == Reading && t.NumMethod() != 0 {
			return &Refusal{Type: t, Reason: "an interface with methods is not part of ritueel's JSON; only one with no methods is"}
		}
		return nil
	case reflect.Pointer:
		if k := t.Elem().Kind(); k == reflect.Pointer || k == reflect.Interface {
			return &Refusal{Type: t, Reason: "a pointer to a pointer or to an interface is not part of ritueel's JSON"}
		}
		r := c.walk(t.Elem(), seen)
		if r != nil && len(r.Hops) == 0 && r.Type == t.Elem() {
			r.Type = t // the type that the caller wrote
		}
		return r
	case reflect.Slice, reflect.Array:
		return through(c.walk(t.Elem(), seen), Hop{Kind: ElementsHop})
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return &Refusal{Type: t, Reason: "only a map with a key of kind string is part of ritueel's JSON"}
		}
		if reason := foreign(t.Key()); reason != "" {
			return &Refusal{Type: t.Key(), Reason: reason}
		}
		return through(c.walk(t.Elem(), seen), Hop{Kind: ValuesHop})
	case reflect.Struct:
		info := c.structInfo(t)
		if info.err != "" {
			return &Refusal{Type: t, Reason: info.err}
		}
		for _, f := range info.fields {
			if r := c.walk(t.Field(f.Index).Type, seen); r != nil {
				return through(r, Hop{Kind: FieldHop, Field: f.Name})
			}
		}
		return nil
	case reflect.Float32, reflect.Float64:
		return &Refusal{Type: t, Reason: "a float; ritueel's JSON holds integers only"}
	default:
		return &Refusal{Type: t, Reason: "this kind of Go type is not part of ritueel's JSON"}
	}
}

// through puts a first hop before the way of a refusal; a nil refusal stays nil.
func through(r *Refusal, first Hop) *Refusal {
	if r != nil {
		r.Hops = append([]Hop{first}, r.Hops...)
	}
	return r
}

// foreign says why a type that writes or reads its own JSON or text, or the json.Number that the
// standard encoder writes as a bare number, is refused: what such a type does is not something
// these packages can vouch for. An interface type that declares one of the four methods is
// refused the same way, in both directions: the set is closed, and a value that brings its own
// encoding is what it keeps out. It is empty for any other type. A pointer type is not asked: the
// method set of *T holds the methods of T, so *Raw would be refused for the methods of Raw; the
// methods are asked of T when the walk reaches it. The method set of *T holds those of T, so for
// a type that is not an interface *T is the one to ask; for an interface type it is the type
// itself, since a pointer to an interface has no methods.
func foreign(t reflect.Type) string {
	if t.Kind() == reflect.Pointer {
		return ""
	}
	if t.PkgPath() == "encoding/json" && t.Name() == "Number" {
		return "a json.Number is not part of ritueel's JSON; use an integer type"
	}
	methods := reflect.PointerTo(t)
	if t.Kind() == reflect.Interface {
		methods = t
	}
	for _, name := range []string{"MarshalJSON", "MarshalText", "UnmarshalJSON", "UnmarshalText"} {
		if _, found := methods.MethodByName(name); found {
			return "the type has a " + name + " method; only Raw carries JSON of its own"
		}
	}
	return ""
}

// structFields lists the fields of a struct type in the order they are written, or says why the
// type is refused.
func structFields(t reflect.Type) *structInfo {
	info := &structInfo{}
	seen := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous {
			info.err = "the embedded field " + f.Name + " is not part of ritueel's JSON; give it a name"
			return info
		}
		tag := f.Tag.Get("json")
		if !f.IsExported() || tag == "-" {
			continue
		}
		name, options, _ := strings.Cut(tag, ",")
		omitEmpty := false
		if options != "" { // "-," names a field "-", and "a," is "a"
			for _, option := range strings.Split(options, ",") {
				if option != "omitempty" {
					info.err = "field " + f.Name + " has the tag option " + Quote(option) + "; only omitempty is allowed"
					return info
				}
				omitEmpty = true
			}
		}
		if name == "" {
			name = f.Name
			if !validName(name) {
				info.err = "field " + f.Name + " has no tag name, and its Go name is not a member name; " + nameRule
				return info
			}
		} else if !validName(name) {
			info.err = "field " + f.Name + " has the tag name " + Quote(name) + "; " + nameRule
			return info
		}
		if seen[name] {
			info.err = "two fields are named " + Quote(name)
			return info
		}
		seen[name] = true
		info.fields = append(info.fields, Field{Index: i, Name: name, OmitEmpty: omitEmpty})
	}
	slices.SortFunc(info.fields, func(a, b Field) int { return CompareUTF16(a.Name, b.Name) })
	return info
}

// nameRule is the text of the rule for the name of a member of a struct, for the errors.
const nameRule = "a member name holds only ASCII letters, digits and underscores, and is not empty"

// validName reports whether s is a member name that a struct may have: ASCII letters, digits and
// underscores. It is never called with an empty name: a tag without a name takes the Go name of
// the field, which is not empty.
func validName(s string) bool {
	for _, c := range s {
		if c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
