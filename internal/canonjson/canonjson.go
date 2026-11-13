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
// slice marshals to null and is refused for that reason.
package canonjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"ritueel.id/ritueel/internal/strictjson"
)

// Marshal returns the RFC 8785 canonical form of v: any value that encoding/json can marshal
// whose numbers are integers. There is no trailing newline. A float in v is an error, and so is
// a null (a nil pointer, map or slice).
func Marshal(v any) ([]byte, error) {
	if err := refuseFloats(reflect.ValueOf(v), 0); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonjson: %w", err)
	}
	return canonicalize(raw)
}

// Canonicalize reads data under the rules of package strictjson (one object, UTF-8, no repeated
// member, integers only, no null, nesting of at most strictjson.MaxDepth levels, at most
// strictjson.DefaultMaxBytes) and returns its canonical
// form. White space around the tokens, the order of the members and the spelling of the escapes
// are the only things that change.
func Canonicalize(data []byte) ([]byte, error) {
	return canonicalize(data)
}

// IsCanonical reports whether data is byte for byte its own canonical form. It returns an error
// when data breaks the rules of package strictjson, and then the answer is false.
func IsCanonical(data []byte) (bool, error) {
	canon, err := canonicalize(data)
	if err != nil {
		return false, err
	}
	return bytes.Equal(canon, data), nil
}

func canonicalize(data []byte) ([]byte, error) {
	// The rules, the size limit included, are those of strictjson, for what Marshal writes too.
	if err := strictjson.Check(data, 0); err != nil {
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

// refuseFloats walks the value that Marshal was given and refuses a float. The standard encoder
// writes the float 3.0 as 3, which would pass for an integer; a value of ritueel's formats is an
// integer type. A field tagged "-" is not written and is not looked at. A type that writes its
// own JSON is not looked into: its output is checked after it is written.
func refuseFloats(v reflect.Value, depth int) error {
	if !v.IsValid() || depth > strictjson.MaxDepth {
		return nil
	}
	switch v.Kind() {
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("%w: a float cannot be written, ritueel's JSON holds integers only", strictjson.ErrMalformed)
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return refuseFloats(v.Elem(), depth+1)
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			if err := refuseFloats(v.Index(i), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			if err := refuseFloats(v.MapIndex(k), depth+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag == "-" || (!f.IsExported() && !f.Anonymous) {
				continue
			}
			if err := refuseFloats(v.Field(i), depth+1); err != nil {
				return err
			}
		}
	default:
	}
	return nil
}
