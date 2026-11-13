package canonjson

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/strictjson"
)

// Raw is a JSON document that is already written: a signed or stored sub-document that Marshal
// places inside another value. Marshal reads it under the rules of package strictjson (one
// object, so a list or a number is not a Raw) and writes its canonical form. A Raw that is empty
// is an error, or is left out when the field is tagged omitempty. A Raw reads its bytes from a
// file through strictjson.Unmarshal and the standard decoder.
type Raw []byte

// MarshalJSON returns r unchanged, so that the standard encoder writes a Raw as it writes a
// json.RawMessage. Marshal does not call it.
func (r Raw) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return r, nil
}

// UnmarshalJSON stores a copy of the bytes of the document.
func (r *Raw) UnmarshalJSON(data []byte) error {
	*r = append((*r)[:0], data...)
	return nil
}

var rawType = reflect.TypeFor[Raw]()

// maxPathSteps is how many steps of the path to a value an error shows; a longer path shows its end.
const maxPathSteps = 8

// Marshal returns the RFC 8785 canonical form of v, with no trailing newline. v must be a struct,
// a map with a string key or a Raw, or a pointer or an interface holding one.
//
// What it writes, by Go type:
//   - a struct: its exported fields, named by the tag `json:"name"` or else the field name, in
//     the order of their names as UTF-16 code units. The tag `json:"-"` leaves a field out. The
//     option omitempty, the only option accepted, leaves a field out when it is false, zero, an
//     empty string, array, slice or map, or a nil pointer or interface, as encoding/json does.
//     Unexported fields are not written. An embedded field is refused, because Go's rules for
//     promoted fields and methods are not ones a writer of signed files should depend on.
//   - a map whose key type is of kind string and has no method of its own: a member for each key.
//   - a slice or an array: a list. A slice of bytes is the exception: a string of standard
//     Base64 with padding (RFC 4648, section 4), as the hand-off contract writes a certificate or
//     a key.
//   - a string that is valid UTF-8, a bool, and an integer of any kind that fits int64.
//   - a pointer or an interface: the value it holds. A pointer to a pointer or to an interface is
//     refused, so that only a struct, a map, a slice or an array can lead back to itself.
//   - a Raw: the canonical form of the document.
//
// A Go type is accepted or refused as a type, whatever the value. A struct with a field that
// can never be written is refused whenever it is reached, even when omitempty would leave the
// field out; so is a slice, an array or a map whose element type can never be written, even
// when it is empty. Only an interface is judged by the value it holds. What can never be written:
// a float, a complex number, a channel, a function, a json.Number, a map key that is not of kind
// string, a type that has a MarshalJSON or MarshalText method (other than Raw), an embedded
// field, a tag option other than omitempty, a tag name that encoding/json would not use, two
// fields with one name, and a pointer to a pointer or to an interface. The value decides only
// what a type cannot: a nil pointer, interface, map or slice (JSON null, unless omitempty leaves
// the field out), an integer above int64, a string that is not valid UTF-8, an empty Raw, the
// nesting and the size.
//
// The error wraps strictjson.ErrMalformed and names the Go type and the path to the value, and
// nothing is returned. For a value that is nested deeper than strictjson.MaxDepth levels (the
// top-level object being level 1), and for a canonical form longer than
// strictjson.DefaultMaxBytes, the error says so. The size is counted on the bytes that Marshal
// returns, and writing stops as soon as it is passed.
func Marshal(v any) ([]byte, error) {
	w := &writer{structs: map[reflect.Type]*structInfo{}, verdicts: map[reflect.Type]*refusal{}}
	if err := w.value(reflect.ValueOf(v), 0); err != nil {
		return nil, err
	}
	out := w.out.Bytes()
	if out[0] != '{' {
		return nil, fmt.Errorf("%w: $: a value of type %T is not one JSON object", strictjson.ErrMalformed, v)
	}
	// A Raw is placed at some level and nests below it; only the reader's own count tells whether
	// the whole stays within strictjson.MaxDepth.
	if err := strictjson.Check(out, strictjson.DefaultMaxBytes); err != nil {
		return nil, err
	}
	return out, nil
}

// step is one move from a value to a part of it: a member name or a list index.
type step struct {
	name    string
	index   int
	isIndex bool
}

type writer struct {
	out     bytes.Buffer
	path    []step
	structs map[reflect.Type]*structInfo
	// verdicts holds, for each type that was asked about as a type, why it cannot be written, or
	// nil when it can.
	verdicts map[reflect.Type]*refusal
}

// refusal says why a Go type cannot be written: the type at fault, the reason, and the fields
// that lead from the type that was asked about to it.
type refusal struct {
	path   []step
	t      reflect.Type
	reason string
}

// structInfo is what Marshal needs to know of a struct type: its fields in the order they are
// written, or why the type is refused.
type structInfo struct {
	fields []fieldInfo
	err    string
}

type fieldInfo struct {
	index     int
	name      string
	omitEmpty bool
}

// where shows the path to the value being written, as $.name[3].
func (w *writer) where() string {
	var b strings.Builder
	b.WriteByte('$')
	steps := w.path
	if len(steps) > maxPathSteps {
		b.WriteString("...")
		steps = steps[len(steps)-maxPathSteps:]
	}
	for _, s := range steps {
		if s.isIndex {
			fmt.Fprintf(&b, "[%d]", s.index)
			continue
		}
		b.WriteByte('.')
		b.WriteString(shown(s.name))
	}
	return b.String()
}

// shown writes a member name for an error: as it is when it is plain, else quoted and cut short.
func shown(name string) string {
	const most = 40
	plain := name != "" && len(name) <= most
	for _, c := range name {
		if c != '_' && c != '-' && !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			plain = false
		}
	}
	if plain {
		return name
	}
	if len(name) > most {
		name = name[:most] + "..."
	}
	return strconv.QuoteToASCII(name)
}

// refuse is the error for the value at the path.
func (w *writer) refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", strictjson.ErrMalformed, w.where(), fmt.Sprintf(format, args...))
}

// refuseType is the error for a value of a Go type that cannot be written.
func (w *writer) refuseType(t reflect.Type, reason string) error {
	return w.refuse("a value of type %s cannot be written: %s", t, reason)
}

// tooDeep and tooLong name no path: the path of a value that passes a limit says nothing, and
// the text of the first is the reader's.
func tooDeep() error {
	return fmt.Errorf("%w: nesting deeper than %d levels", strictjson.ErrMalformed, strictjson.MaxDepth)
}

func tooLong() error {
	return fmt.Errorf("%w: the canonical form is longer than %d bytes", strictjson.ErrMalformed, strictjson.DefaultMaxBytes)
}

// fits fails when n more bytes would pass the limit, so that a large string is not copied first.
func (w *writer) fits(n int) error {
	if w.out.Len()+n > strictjson.DefaultMaxBytes {
		return tooLong()
	}
	return nil
}

// value writes v, which sits depth levels down, and stops as soon as the limit is passed.
func (w *writer) value(v reflect.Value, depth int) error {
	if err := w.write(v, depth); err != nil {
		return err
	}
	return w.fits(0)
}

func (w *writer) write(v reflect.Value, depth int) error {
	if !v.IsValid() {
		return w.refuse("a nil value cannot be written (JSON null)")
	}
	t := v.Type()
	if t == rawType {
		return w.raw(v)
	}
	if r := w.verdict(t); r != nil {
		return w.refuseAt(r)
	}
	switch v.Kind() {
	case reflect.Bool:
		w.out.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.out.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u := v.Uint()
		if u > math.MaxInt64 {
			return w.refuseType(t, "an integer above 9223372036854775807, which the readers refuse")
		}
		w.out.WriteString(strconv.FormatUint(u, 10))
	case reflect.String:
		return w.str(v.String(), "a string")
	case reflect.Pointer:
		if v.IsNil() {
			return w.refuseType(t, "a nil pointer is JSON null")
		}
		return w.write(v.Elem(), depth)
	case reflect.Interface:
		if v.IsNil() {
			return w.refuseType(t, "a nil interface is JSON null")
		}
		return w.write(v.Elem(), depth)
	case reflect.Struct:
		return w.object(v, depth)
	case reflect.Map:
		return w.mapObject(v, depth)
	case reflect.Slice, reflect.Array:
		return w.list(v, depth)
	default:
		// The verdict of the type and this switch agree on the kinds that can be written, so
		// this is not reached; if they ever drift apart nothing is written for the kind.
		return w.refuseType(t, "this kind of Go type is not part of ritueel's JSON")
	}
	return nil
}

// str writes a string, which must be valid UTF-8 (what is the name of the thing in an error).
func (w *writer) str(s, what string) error {
	if !utf8.ValidString(s) {
		return w.refuse("%s that is not valid UTF-8 cannot be written", what)
	}
	if err := w.fits(len(s)); err != nil { // the escaped form is never shorter
		return err
	}
	writeString(&w.out, s)
	return nil
}

// raw writes a Raw document in its canonical form.
func (w *writer) raw(v reflect.Value) error {
	doc := v.Bytes()
	if len(doc) == 0 {
		return w.refuse("an empty Raw cannot be written")
	}
	if err := canonicalizeInto(&w.out, doc); err != nil {
		return fmt.Errorf("%s: %w", w.where(), err)
	}
	return nil
}

// verdict says whether the Go type t can be written, whatever the value: nil when it can, else
// the reason. The answer follows the type into its fields, elements, map values and what a
// pointer points to; only an interface is left to the value it holds.
func (w *writer) verdict(t reflect.Type) *refusal {
	if r, seen := w.verdicts[t]; seen {
		return r
	}
	r := w.walkType(t, map[reflect.Type]bool{})
	w.verdicts[t] = r
	return r
}

// refuseAt is the error for a refusal reached from the value at the current path.
func (w *writer) refuseAt(r *refusal) error {
	here := len(w.path)
	w.path = append(w.path, r.path...)
	err := w.refuseType(r.t, r.reason)
	w.path = w.path[:here]
	return err
}

// walkType looks for a part of t that cannot be written and returns the first it finds. seen
// holds the types looked at in this walk, so that a type that refers to itself, or one that
// turns up twice, is looked at once; the first look finds any refusal inside it.
func (w *writer) walkType(t reflect.Type, seen map[reflect.Type]bool) *refusal {
	if seen[t] || t == rawType {
		return nil
	}
	seen[t] = true
	if reason := unwritable(t); reason != "" {
		return &refusal{t: t, reason: reason}
	}
	switch t.Kind() {
	case reflect.Bool, reflect.String, reflect.Interface,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return nil
	case reflect.Pointer:
		if k := t.Elem().Kind(); k == reflect.Pointer || k == reflect.Interface {
			return &refusal{t: t, reason: "a pointer to a pointer or to an interface is not written"}
		}
		return w.walkType(t.Elem(), seen)
	case reflect.Slice, reflect.Array:
		return w.walkType(t.Elem(), seen)
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return &refusal{t: t, reason: "only a map with a key of kind string is written"}
		}
		if reason := unwritable(t.Key()); reason != "" {
			return &refusal{t: t.Key(), reason: reason}
		}
		return w.walkType(t.Elem(), seen)
	case reflect.Struct:
		info := w.structInfo(t)
		if info.err != "" {
			return &refusal{t: t, reason: info.err}
		}
		for _, f := range info.fields {
			if r := w.walkType(t.Field(f.index).Type, seen); r != nil {
				r.path = append([]step{{name: f.name}}, r.path...)
				return r
			}
		}
		return nil
	case reflect.Float32, reflect.Float64:
		return &refusal{t: t, reason: "a float; ritueel's JSON holds integers only"}
	default:
		return &refusal{t: t, reason: "this kind of Go type is not part of ritueel's JSON"}
	}
}

// structInfo lists the fields of a struct type, once for each type.
func (w *writer) structInfo(t reflect.Type) *structInfo {
	info := w.structs[t]
	if info == nil {
		info = structFields(t)
		w.structs[t] = info
	}
	return info
}

// unwritable says why a type that writes its own JSON or text, or the json.Number that the
// standard encoder writes as a bare number, is refused: what such a type writes is not something
// this package can vouch for. It is empty for any other type.
func unwritable(t reflect.Type) string {
	if t.PkgPath() == "encoding/json" && t.Name() == "Number" {
		return "encoding/json writes a json.Number as a bare number; use an integer type"
	}
	for _, name := range []string{"MarshalJSON", "MarshalText"} {
		_, onType := t.MethodByName(name)
		_, onPointer := reflect.PointerTo(t).MethodByName(name)
		if onType || onPointer {
			return "the type has a " + name + " method, and only Raw may write its own JSON"
		}
	}
	return ""
}

// object writes a struct.
func (w *writer) object(v reflect.Value, depth int) error {
	if depth >= strictjson.MaxDepth {
		return tooDeep()
	}
	w.out.WriteByte('{')
	first := true
	for _, f := range w.structInfo(v.Type()).fields {
		fv := v.Field(f.index)
		if f.omitEmpty && isEmpty(fv) {
			continue
		}
		if !first {
			w.out.WriteByte(',')
		}
		first = false
		writeString(&w.out, f.name)
		w.out.WriteByte(':')
		w.path = append(w.path, step{name: f.name})
		if err := w.value(fv, depth+1); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
	w.out.WriteByte('}')
	return nil
}

// structFields lists the fields of a struct type in the order they are written, or says why the
// type is refused.
func structFields(t reflect.Type) *structInfo {
	info := &structInfo{}
	seen := map[string]bool{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous {
			info.err = "the embedded field " + f.Name + " is not written; give it a name"
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
					info.err = "field " + f.Name + " has the tag option " + strconv.Quote(option) + "; only omitempty is written"
					return info
				}
				omitEmpty = true
			}
		}
		if name == "" {
			name = f.Name
		} else if !validName(name) {
			info.err = "field " + f.Name + " has the tag name " + strconv.QuoteToASCII(name) + ", which encoding/json would not use"
			return info
		}
		if seen[name] {
			info.err = "two fields are named " + strconv.QuoteToASCII(name)
			return info
		}
		seen[name] = true
		info.fields = append(info.fields, fieldInfo{index: i, name: name, omitEmpty: omitEmpty})
	}
	slices.SortFunc(info.fields, func(a, b fieldInfo) int { return compareUTF16(a.name, b.name) })
	return info
}

// validName reports whether encoding/json would use s as the name of a field: letters, digits and
// the punctuation that it allows, but not a quote or a backslash.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}

// isEmpty is the meaning of omitempty, as encoding/json gives it.
func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	default:
		return false
	}
}

// mapObject writes a map whose keys are strings.
func (w *writer) mapObject(v reflect.Value, depth int) error {
	if v.IsNil() {
		return w.refuseType(v.Type(), "a nil map is JSON null")
	}
	if depth >= strictjson.MaxDepth {
		return tooDeep()
	}
	keys := v.MapKeys()
	slices.SortFunc(keys, func(a, b reflect.Value) int { return compareUTF16(a.String(), b.String()) })
	w.out.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			w.out.WriteByte(',')
		}
		w.path = append(w.path, step{name: k.String()})
		if err := w.str(k.String(), "a member name"); err != nil {
			return err
		}
		w.out.WriteByte(':')
		if err := w.value(v.MapIndex(k), depth+1); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
	w.out.WriteByte('}')
	return nil
}

// list writes a slice or an array.
func (w *writer) list(v reflect.Value, depth int) error {
	t := v.Type()
	if t.Kind() == reflect.Slice && v.IsNil() {
		return w.refuseType(t, "a nil slice is JSON null")
	}
	if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
		encoded := base64.StdEncoding.EncodedLen(v.Len())
		if err := w.fits(encoded + 2); err != nil {
			return err
		}
		w.out.WriteByte('"')
		w.out.Write(base64.StdEncoding.AppendEncode(nil, v.Bytes()))
		w.out.WriteByte('"')
		return nil
	}
	if depth >= strictjson.MaxDepth {
		return tooDeep()
	}
	w.out.WriteByte('[')
	for i := range v.Len() {
		if i > 0 {
			w.out.WriteByte(',')
		}
		w.path = append(w.path, step{index: i, isIndex: true})
		if err := w.value(v.Index(i), depth+1); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
	w.out.WriteByte(']')
	return nil
}
