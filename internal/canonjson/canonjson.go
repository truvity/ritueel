// Package canonjson writes and checks the canonical form of JSON, RFC 8785 (the JSON
// Canonicalization Scheme), as docs/reference/ceremony-record.md and
// docs/reference/root-list.md ask: members sorted by their names as UTF-16 code units, no white
// space between tokens, and no trailing newline. The ceremony files of ritueel are written in
// this form so that a file's digest is the SHA-256 of its bytes and the same content gives the
// same bytes on any machine.
//
// Marshal is its own writer over a closed set of Go types, not a wrapper of encoding/json: a
// writer of signed files must never change a value on the way, so what it accepts it understands
// completely and everything else is an error that names the Go type and the path to it. It writes
// structs (exported fields; the tags `json:"name"` and `json:"-"` and the option omitempty, no
// other), maps with a string key, slices, arrays, strings, bools, integers, slices of bytes (as
// standard Base64) and pointers and interfaces to these, and Raw, a document that is already JSON.
// It refuses floats, nil, embedded fields, types with a MarshalJSON or MarshalText method, and
// the rest, as the doc of Marshal lists. For every value that Marshal accepts and the standard
// json.Marshal writes, Marshal(x) equals Canonicalize(json.Marshal(x)); the tests check this.
//
// ritueel's JSON holds integers only, so this package does not write a number with a fraction or
// an exponent, and it reads input under the rules of package strictjson (no null, no repeated
// member, nesting of at most strictjson.MaxDepth levels). Every error wraps
// strictjson.ErrMalformed. Reading uses encoding/json in Canonicalize, after strictjson has
// checked the bytes; writing does not.
package canonjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"unicode/utf16"

	"ritueel.id/ritueel/internal/strictjson"
)

// Canonicalize reads data under the rules of package strictjson (one object, UTF-8, no repeated
// member, integers only, no null, nesting of at most strictjson.MaxDepth levels, at most
// strictjson.DefaultMaxBytes) and returns its canonical form. White space around the tokens, the
// order of the members and the spelling of the escapes are the only things that change, so the
// result is never longer than data.
func Canonicalize(data []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := canonicalizeInto(&out, data); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// IsCanonical reports whether data is byte for byte its own canonical form. It returns an error
// when data breaks the rules of package strictjson, and then the answer is false.
func IsCanonical(data []byte) (bool, error) {
	canon, err := Canonicalize(data)
	if err != nil {
		return false, err
	}
	return bytes.Equal(canon, data), nil
}

// canonicalizeInto reads data under the rules of strictjson and appends its canonical form to out.
func canonicalizeInto(out *bytes.Buffer, data []byte) error {
	if err := strictjson.Check(data, strictjson.DefaultMaxBytes); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("%w: %w", strictjson.ErrMalformed, err)
	}
	return write(out, v)
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
