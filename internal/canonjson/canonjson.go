// Package canonjson writes and checks the canonical form of JSON, RFC 8785 (the JSON
// Canonicalization Scheme), as docs/reference/ceremony-record.md and
// docs/reference/root-list.md ask: members sorted by their names as UTF-16 code units, no white
// space between tokens, and no trailing newline. The ceremony files of ritueel are written in
// this form so that a file's digest is the SHA-256 of its bytes and the same content gives the
// same bytes on any machine.
//
// ritueel's JSON holds integers only, so this package does not write a number with a fraction or
// an exponent, and it reads input under the rules of package strictjson (no null, no repeated
// member, nesting of at most strictjson.MaxDepth levels). A value with a nil pointer, map or
// slice marshals to null and is refused for that reason. A string that is not valid UTF-8 is
// refused too, where the standard encoder would write U+FFFD in its place.
package canonjson

import (
	"bytes"
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/strictjson"
)

// maxIntermediate bounds what Marshal reads back from the standard encoder before it writes the
// canonical form. The limit of the canonical form is strictjson.DefaultMaxBytes; a byte of it can
// come from at most six bytes of what the encoder or a type's own JSON writes (the escape
// A for A), so every value whose canonical form fits has an intermediate within this bound,
// and one that is longer cannot fit.
const maxIntermediate = 6 * strictjson.DefaultMaxBytes

// Marshal returns the RFC 8785 canonical form of v: any value that encoding/json can marshal
// whose numbers are integers. There is no trailing newline.
//
// Marshal refuses, with an error that wraps strictjson.ErrMalformed and with nothing written: a
// float; a null (a nil pointer, map or slice); a string or a member name that is not valid UTF-8,
// at any depth (the standard encoder would write U+FFFD in its place); nesting deeper than
// strictjson.MaxDepth levels. What a type that writes its own JSON (json.Marshaler) returns is
// checked after it is written, under all the rules of package strictjson, so a float, a null, a
// byte that is not UTF-8 or a lone surrogate escape such as "\ud800" in it is refused the same
// way. What a type that writes its own text (encoding.TextMarshaler, also as a map key) returns
// is checked for UTF-8 before the encoder uses it, and its method is called once more by the
// encoder.
//
// The size limit, strictjson.DefaultMaxBytes, counts the bytes of the result: the canonical form
// that Marshal returns, with no trailing newline. It does not count the longer text that the
// standard encoder writes on the way (it spells U+2028 and U+2029 as six bytes, and a type's own
// JSON may spell any character as an escape). A result that is longer is an error. So is an
// intermediate longer than six times the limit, which no value that fits can need; that bound
// keeps the work of Marshal in proportion to the limit.
func Marshal(v any) ([]byte, error) {
	if err := checkValue(reflect.ValueOf(v), 0, 0); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // < > & are written as they are, as RFC 8785 asks
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonjson: %w", err)
	}
	raw := bytes.TrimSuffix(buf.Bytes(), []byte("\n")) // Encode ends the value with a newline
	return canonicalize(raw, maxIntermediate)
}

// Canonicalize reads data under the rules of package strictjson (one object, UTF-8, no repeated
// member, integers only, no null, nesting of at most strictjson.MaxDepth levels, at most
// strictjson.DefaultMaxBytes) and returns its canonical form. White space around the tokens, the
// order of the members and the spelling of the escapes are the only things that change, so the
// result is never longer than data.
func Canonicalize(data []byte) ([]byte, error) {
	return canonicalize(data, strictjson.DefaultMaxBytes)
}

// IsCanonical reports whether data is byte for byte its own canonical form. It returns an error
// when data breaks the rules of package strictjson, and then the answer is false.
func IsCanonical(data []byte) (bool, error) {
	canon, err := canonicalize(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return false, err
	}
	return bytes.Equal(canon, data), nil
}

// canonicalize reads data under the rules of strictjson, with maxIn as the limit of its size, and
// returns the canonical form, which must itself be within strictjson.DefaultMaxBytes.
func canonicalize(data []byte, maxIn int) ([]byte, error) {
	if err := strictjson.Check(data, maxIn); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %w", strictjson.ErrMalformed, err)
	}
	var out bytes.Buffer
	if err := write(&out, v); err != nil {
		return nil, err
	}
	if out.Len() > strictjson.DefaultMaxBytes {
		return nil, fmt.Errorf("%w: the canonical form is longer than %d bytes", strictjson.ErrMalformed, strictjson.DefaultMaxBytes)
	}
	return out.Bytes(), nil
}

// write appends the canonical form of a value that the standard decoder produced with UseNumber.
func write(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(out, k)
			out.WriteByte(':')
			if err := write(out, x[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := write(out, e); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case string:
		writeString(out, x)
	case json.Number:
		n, err := strconv.ParseInt(x.String(), 10, 64)
		if err != nil {
			return fmt.Errorf("%w: a number that is not an integer of 64 bits", strictjson.ErrMalformed)
		}
		out.WriteString(strconv.FormatInt(n, 10)) // -0 is written 0
	case bool:
		out.WriteString(strconv.FormatBool(x))
	default:
		return fmt.Errorf("%w: a value that is not JSON data", strictjson.ErrMalformed)
	}
	return nil
}

// compareUTF16 orders two strings by their UTF-16 code units, as RFC 8785 section 3.2.3
// sorts member names. It differs from the byte order of UTF-8 for characters above U+FFFF
// against U+E000 to U+FFFF.
func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

// writeString appends s as RFC 8785 section 3.2.2.2 writes it: a quote, a backslash and the
// controls below U+0020 are escaped (the short forms for backspace, tab, line feed, form feed
// and carriage return, \u00xx in lower case for the others), everything else is written as is.
func writeString(out *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			out.WriteString(`\"`)
		case r == '\\':
			out.WriteString(`\\`)
		case r == '\b':
			out.WriteString(`\b`)
		case r == '\t':
			out.WriteString(`\t`)
		case r == '\n':
			out.WriteString(`\n`)
		case r == '\f':
			out.WriteString(`\f`)
		case r == '\r':
			out.WriteString(`\r`)
		case r < 0x20:
			out.WriteString(`\u00`)
			out.WriteByte(hex[r>>4])
			out.WriteByte(hex[r&0xF])
		default:
			out.WriteRune(r)
		}
	}
	out.WriteByte('"')
}

var (
	marshalerType     = reflect.TypeFor[json.Marshaler]()
	textMarshalerType = reflect.TypeFor[encoding.TextMarshaler]()
)

// checkValue walks the value that Marshal was given, before the standard encoder sees it, and
// refuses what the encoder would write without a word or would write wrongly: a float (the
// encoder writes 3.0 as 3, which would pass for an integer; a value of ritueel's formats is an
// integer type), a string or a member name that is not valid UTF-8 (the encoder writes U+FFFD in
// its place), and nesting deeper than strictjson.MaxDepth. depth counts the objects and arrays
// entered, as the JSON will have them; hops counts the pointers and interfaces passed since the
// last of those, so that a value that points to itself ends in an error and a long chain of
// pointers is not taken for nesting. A field tagged "-" is not written and is not looked at. A
// type that writes its own JSON is not looked into: its output is checked after it is written,
// by the rules of package strictjson. A type that writes its own text has that text checked
// here.
func checkValue(v reflect.Value, depth, hops int) error {
	if !v.IsValid() {
		return nil
	}
	if (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil() {
		return nil
	}
	// The encoder asks in this order: its own JSON first, then its own text.
	if writesItself(v, marshalerType) {
		return nil
	}
	if writesItself(v, textMarshalerType) {
		return checkText(v, "a text")
	}
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("%w: a float cannot be written, ritueel's JSON holds integers only", strictjson.ErrMalformed)
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return notUTF8("a string")
		}
	case reflect.Pointer, reflect.Interface:
		if hops >= strictjson.MaxDepth {
			return tooDeep()
		}
		return checkValue(v.Elem(), depth, hops+1)
	case reflect.Slice, reflect.Array:
		if writtenAsBase64(v.Type()) {
			return nil
		}
		if depth >= strictjson.MaxDepth {
			return tooDeep()
		}
		for i := range v.Len() {
			if err := checkValue(v.Index(i), depth+1, 0); err != nil {
				return err
			}
		}
	case reflect.Map:
		if depth >= strictjson.MaxDepth {
			return tooDeep()
		}
		for it := v.MapRange(); it.Next(); {
			if err := checkKey(it.Key()); err != nil {
				return err
			}
			if err := checkValue(it.Value(), depth+1, 0); err != nil {
				return err
			}
		}
	case reflect.Struct:
		if depth >= strictjson.MaxDepth {
			return tooDeep()
		}
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag == "-" || !isWritten(f) {
				continue
			}
			if err := checkValue(v.Field(i), depth+1, 0); err != nil {
				return err
			}
		}
	default:
	}
	return nil
}

// writtenAsBase64 reports whether the encoder writes a value of type t as one base64 string: a
// slice of bytes whose element has no method of its own.
func writtenAsBase64(t reflect.Type) bool {
	if t.Kind() != reflect.Slice || t.Elem().Kind() != reflect.Uint8 {
		return false
	}
	p := reflect.PointerTo(t.Elem())
	return !p.Implements(marshalerType) && !p.Implements(textMarshalerType)
}

// isWritten reports whether the standard encoder looks at a struct field at all: an exported one,
// or an embedded one of a struct type (its exported fields are written as the struct's own).
func isWritten(f reflect.StructField) bool {
	if f.IsExported() {
		return true
	}
	if !f.Anonymous {
		return false
	}
	t := f.Type
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind() == reflect.Struct
}

// checkKey checks the name that the encoder writes for a map key: a key of a string kind is
// written as it is, any other key that writes its own text is written as that text, and an
// integer key is written as digits.
func checkKey(k reflect.Value) error {
	if k.Kind() == reflect.String {
		if !utf8.ValidString(k.String()) {
			return notUTF8("a member name")
		}
		return nil
	}
	if k.Kind() == reflect.Pointer && k.IsNil() {
		return nil // the encoder reports it
	}
	if writesItself(k, textMarshalerType) {
		return checkText(k, "a member name")
	}
	return nil
}

// writesItself reports whether the encoder writes v through the method of the interface t: the
// type of v has the method, or v can be addressed and its pointer type has it.
func writesItself(v reflect.Value, t reflect.Type) bool {
	return v.Type().Implements(t) || (v.CanAddr() && reflect.PointerTo(v.Type()).Implements(t))
}

// checkText calls the MarshalText of v, as the encoder will, and refuses text that is not valid
// UTF-8 (the encoder would write U+FFFD in its place). An error of the method is the encoder's
// to report.
func checkText(v reflect.Value, what string) error {
	if !v.CanInterface() {
		return nil
	}
	var m encoding.TextMarshaler
	if v.Type().Implements(textMarshalerType) {
		m, _ = v.Interface().(encoding.TextMarshaler)
	} else {
		m, _ = v.Addr().Interface().(encoding.TextMarshaler)
	}
	text, err := m.MarshalText()
	if err == nil && !utf8.Valid(text) {
		return notUTF8(what)
	}
	return nil
}

func notUTF8(what string) error {
	return fmt.Errorf("%w: %s that is not valid UTF-8 cannot be written", strictjson.ErrMalformed, what)
}

func tooDeep() error {
	return fmt.Errorf("%w: nesting deeper than %d levels", strictjson.ErrMalformed, strictjson.MaxDepth)
}
