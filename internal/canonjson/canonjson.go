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
// It refuses floats, nil, embedded fields, types with a MarshalJSON, MarshalText, UnmarshalJSON or
// UnmarshalText method, and the rest, as the doc of Marshal lists. A type is accepted or refused
// as a type; the value decides only the size, the nesting and the validity of its text. For every
// value that Marshal accepts and the standard json.Marshal writes, Marshal(x) equals
// Canonicalize(json.Marshal(x)); the tests check this.
//
// Writing and reading are mirrors. strictjson.Unmarshal fills the same closed set of Go types
// from its own parse of the bytes (the package jsonset keeps the one answer to "is this type in
// the set" for both), and what Marshal writes it reads back. For every value x of the set,
// Unmarshal(Marshal(x)) gives a value equal to x; for every canonical document d that fills a
// type T, Marshal of the filled value gives d again. "Equal" is reflect.DeepEqual with four
// exceptions: a field tagged omitempty that is empty is not written and comes back zero, so an
// empty slice or map comes back nil (a nil one that is not omitempty is not written at all, as
// Marshal takes it for null); a Raw comes back in its canonical form; an interface comes back
// with the types that a read gives (map[string]any, []any, string, bool and int64, so an int in
// it comes back an int64); and a field tagged "-" and an unexported field are not written, so
// they come back zero. The doc of package strictjson says when the second property holds; the
// tests of both packages check the two.
//
// ritueel's JSON holds integers only, so this package does not write a number with a fraction or
// an exponent, and it reads input under the rules of package strictjson (no null, no repeated
// member, nesting of at most strictjson.MaxDepth levels). Every error wraps
// strictjson.ErrMalformed and has the one form of both packages, "malformed JSON: <path>: <what>",
// with the path to the value at fault as the doc of package strictjson describes it; an error
// about a Raw continues the path of the Raw into the Raw. Neither writing nor reading calls
// encoding/json: Canonicalize writes the canonical form from the tree that strictjson parsed, so
// the one parser that checked the bytes is the one that supplies the values.
package canonjson

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"

	"ritueel.id/ritueel/internal/jsonset"
	"ritueel.id/ritueel/internal/strictjson"
)

// Canonicalize reads data under the rules of package strictjson (one object, UTF-8, no repeated
// member, integers only, no null, nesting of at most strictjson.MaxDepth levels, at most
// strictjson.DefaultMaxBytes) and returns its canonical form. White space around the tokens, the
// order of the members, the spelling of the escapes and the text -0, which is the integer zero and
// is written 0, are the only things that change, so the result is never longer than data.
func Canonicalize(data []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := canonicalizeInto(&out, data); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// IsCanonical reports whether data is byte for byte its own canonical form; a document with -0 in
// it, which is read as zero, is not. It returns an error when data breaks the rules of package
// strictjson, and then the answer is false.
func IsCanonical(data []byte) (bool, error) {
	canon, err := Canonicalize(data)
	if err != nil {
		return false, err
	}
	return bytes.Equal(canon, data), nil
}

// canonicalizeInto reads data under the rules of strictjson and appends its canonical form to out.
// It writes from the tree that strictjson parsed, so that no other reader sees the bytes.
func canonicalizeInto(out *bytes.Buffer, data []byte) error {
	root, err := strictjson.Parse(data, strictjson.DefaultMaxBytes)
	if err != nil {
		return err
	}
	return write(out, root)
}

// write appends the canonical form of a value of the tree.
func write(out *bytes.Buffer, v *strictjson.Value) error {
	switch v.Kind {
	case strictjson.Object:
		members := make([]*strictjson.Member, len(v.Members))
		for i := range v.Members {
			members[i] = &v.Members[i]
		}
		slices.SortFunc(members, func(a, b *strictjson.Member) int { return jsonset.CompareUTF16(a.Name, b.Name) })
		out.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				out.WriteByte(',')
			}
			writeString(out, m.Name)
			out.WriteByte(':')
			if err := write(out, &m.Value); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case strictjson.List:
		out.WriteByte('[')
		for i := range v.Elems {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := write(out, &v.Elems[i]); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case strictjson.String:
		writeString(out, v.Str)
	case strictjson.Integer:
		out.WriteString(strconv.FormatInt(v.Int, 10)) // -0 is written 0
	case strictjson.Bool:
		out.WriteString(strconv.FormatBool(v.Bool))
	default:
		// Parse is strict, so it gives no other kind (a fraction and null are refused by it).
		panic(fmt.Sprintf("canonjson: Parse returned a value of kind %d, which the strict reader refuses", v.Kind))
	}
	return nil
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
