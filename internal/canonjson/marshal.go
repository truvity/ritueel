package canonjson

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
)

// Raw is a JSON document that is already written: a signed or stored sub-document that Marshal
// places inside another value, and that strictjson.Unmarshal reads back byte for byte. It is the
// type strictjson.Raw under a second name, so that the two packages need no conversion. Marshal
// reads it under the rules of package strictjson (one object, so a list or a number is not a Raw)
// and writes its canonical form. A Raw that is empty is an error, or is left out when the field is
// tagged omitempty.
type Raw = strictjson.Raw

var rawType = reflect.TypeFor[Raw]()

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
// string, a type that has a MarshalJSON, MarshalText, UnmarshalJSON or UnmarshalText method (other
// than Raw), an embedded field, a tag option other than omitempty, a member name (a tag name, or
// the Go name of a field with no tag name) that is not made of ASCII letters, digits and
// underscores, two fields with one name, and a pointer to a pointer or to an interface. The
// value decides only what a type cannot: a nil pointer, interface, map or slice (JSON null,
// unless omitempty leaves the field out), an integer above int64, a string that is not valid
// UTF-8, an empty Raw, the nesting and the size. An interface with methods can be written, since
// the value in it is judged, unless it declares one of the four methods above, which refuses it;
// strictjson.Unmarshal refuses every interface with methods as a type, since there is no value.
//
// The error wraps strictjson.ErrMalformed and names the Go type and the path to the value, and
// nothing is returned. A refusal of the element type of a list or the value type of a map says so
// in words ("the elements of $.l", "the values of $.m"), since no index or name belongs to a type;
// a refusal of a type behind a pointer names the type that the caller wrote. For a value that is nested deeper than strictjson.MaxDepth levels (the
// top-level object being level 1), and for a canonical form longer than
// strictjson.DefaultMaxBytes, the error says so. The size is counted on the bytes that Marshal
// returns, and writing stops as soon as it is passed.
func Marshal(v any) ([]byte, error) {
	w := &writer{checker: jsonset.NewChecker(jsonset.Writing, rawType)}
	if err := w.value(reflect.ValueOf(v), 0); err != nil {
		return nil, err
	}
	out := w.out.Bytes()
	if out[0] != '{' {
		return nil, jsonset.Errorf(nil, "a value of type %s cannot be written: the top of a document is one JSON object, which a struct, a map, a Raw, or a pointer or an interface that holds one, writes", jsonset.TypeName(reflect.TypeOf(v)))
	}
	// A Raw is placed at some level and nests below it; only the reader's own count tells whether
	// the whole stays within strictjson.MaxDepth.
	if err := strictjson.Check(out, strictjson.DefaultMaxBytes); err != nil {
		return nil, err
	}
	return out, nil
}

type writer struct {
	out     bytes.Buffer
	path    jsonset.Path
	checker *jsonset.Checker
}

// refuse is the error for the value at the path.
func (w *writer) refuse(format string, args ...any) error {
	return jsonset.Errorf(w.path, format, args...)
}

// refuseType is the error for a value of a Go type that cannot be written.
func (w *writer) refuseType(t reflect.Type, reason string) error {
	return w.refuse("a value of type %s cannot be written: %s", jsonset.TypeName(t), reason)
}

// tooDeep and tooLong are the errors of the two limits, at the value where the writer passed one.
func (w *writer) tooDeep() error {
	return w.refuse("nesting deeper than %d levels", strictjson.MaxDepth)
}

func (w *writer) tooLong() error {
	return w.refuse("the canonical form is longer than %d bytes", strictjson.DefaultMaxBytes)
}

// fits fails when n more bytes would pass the limit, so that a large string is not copied first.
func (w *writer) fits(n int) error {
	if w.out.Len()+n > strictjson.DefaultMaxBytes {
		return w.tooLong()
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
		return w.refuse("a value of type nil cannot be written: an untyped nil is JSON null")
	}
	t := v.Type()
	if t == rawType {
		return w.raw(v)
	}
	if r := w.checker.Verdict(t); r != nil {
		return w.checker.Err(w.path, r)
	}
	switch v.Kind() {
	case reflect.Bool:
		w.out.WriteString(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.out.WriteString(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u := v.Uint()
		if u > math.MaxInt64 {
			return w.refuseType(t, "an integer above 9223372036854775807, which ritueel's JSON does not hold")
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
		// The judge of the types (jsonset) refuses every other kind before a value is looked at, so
		// this is not reached; if the judge and this switch ever drift apart, it must be loud.
		panic(fmt.Sprintf("canonjson: the type judge passed the type %s of kind %s, which the writer cannot write; it should have refused the type", t, t.Kind()))
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
		// The document was read on its own, so its path starts at its own top: it goes on from here.
		var at *jsonset.Error
		if !errors.As(err, &at) {
			// Every error of canonicalizeInto is one of strictjson.Parse, and that is a *jsonset.Error.
			panic(fmt.Sprintf("canonjson: canonicalizeInto returned an error that is not a *jsonset.Error: %v", err))
		}
		return jsonset.Errorf(append(slices.Clone(w.path), at.Path...), "%s", at.What)
	}
	return nil
}

// object writes a struct.
func (w *writer) object(v reflect.Value, depth int) error {
	if depth >= strictjson.MaxDepth {
		return w.tooDeep()
	}
	w.out.WriteByte('{')
	first := true
	for _, f := range w.checker.Fields(v.Type()) {
		fv := v.Field(f.Index)
		if f.OmitEmpty && isEmpty(fv) {
			continue
		}
		if !first {
			w.out.WriteByte(',')
		}
		first = false
		writeString(&w.out, f.Name)
		w.out.WriteByte(':')
		w.path = append(w.path, jsonset.Member(f.Name))
		if err := w.value(fv, depth+1); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
	w.out.WriteByte('}')
	return nil
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
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
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
		return w.tooDeep()
	}
	keys := v.MapKeys()
	slices.SortFunc(keys, func(a, b reflect.Value) int { return jsonset.CompareUTF16(a.String(), b.String()) })
	w.out.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			w.out.WriteByte(',')
		}
		w.path = append(w.path, jsonset.Member(k.String()))
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
		return w.tooDeep()
	}
	w.out.WriteByte('[')
	for i := range v.Len() {
		if i > 0 {
			w.out.WriteByte(',')
		}
		w.path = append(w.path, jsonset.Element(i))
		if err := w.value(v.Index(i), depth+1); err != nil {
			return err
		}
		w.path = w.path[:len(w.path)-1]
	}
	w.out.WriteByte(']')
	return nil
}
