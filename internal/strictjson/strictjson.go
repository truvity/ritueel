// Package strictjson reads the JSON files of ritueel under one set of rules: one object, UTF-8
// with no byte order mark, no member name twice in one object, no member that the reader does
// not define, integers only, no null, and at most 256 KiB. The rules are those of
// docs/reference/hand-off-contract.md ("Messages and files") and docs/reference/root-list.md
// ("The list"). The standard decoder breaks several of them silently (a repeated member keeps
// the last value, a lone surrogate escape becomes U+FFFD, a member name matches a field in any
// letter case), so this package reads the bytes itself before it lets the standard decoder fill
// a value.
//
// Every error that this package returns for input that breaks a rule wraps ErrMalformed. An
// error that does not wrap it is a mistake of the caller (a value that is not a pointer). An
// error never repeats the input, which may be untrusted and large.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DefaultMaxBytes is the largest input the readers accept unless the caller says otherwise: 256 KiB.
const DefaultMaxBytes = 256 << 10

// maxDepth is how deep objects and arrays may nest. It is the limit of the standard decoder,
// stated here so that the reader of this package does not depend on the stack.
const maxDepth = 10000

// ErrMalformed is wrapped by every error this package returns for input that breaks a rule.
var ErrMalformed = errors.New("malformed JSON")

// Options changes how Unmarshal reads.
type Options struct {
	// MaxBytes is the largest input in bytes; 0 means DefaultMaxBytes.
	MaxBytes int
	// AllowUnknown skips the unknown-member rule, for a reader that wants one member of a
	// larger file. A member that matches a field in another letter case is still refused.
	AllowUnknown bool
}

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

func limit(maxBytes int) int {
	if maxBytes <= 0 {
		return DefaultMaxBytes
	}
	return maxBytes
}

// Unmarshal decodes data into v (a non-nil pointer, in practice to a struct) under the rules
// of the package comment. A member of the file must be spelt exactly as the field's JSON name;
// unless opts.AllowUnknown is set, a member that names no field is an error, at any depth.
// Members the caller needs are the caller's to check: a missing one leaves the field as it was.
func Unmarshal(data []byte, v any, opts Options) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("strictjson: Unmarshal needs a non-nil pointer")
	}
	root, err := parseDocument(data, limit(opts.MaxBytes), true)
	if err != nil {
		return err
	}
	if err := matchType(root, rv.Type().Elem(), opts.AllowUnknown); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if !opts.AllowUnknown {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(v); err != nil {
		return malformed("%s", err)
	}
	return nil
}

// Check applies the rules that need no type: size (maxBytes, 0 means DefaultMaxBytes), UTF-8,
// no byte order mark, one object, no repeated member at any depth, integers only, no null, no
// lone surrogate escape, and nothing but white space after the object.
func Check(data []byte, maxBytes int) error {
	_, err := parseDocument(data, limit(maxBytes), true)
	return err
}

// PeekInt returns the integer member name of the top-level object; ok is false when it is
// absent. It is for the version check that must come before the unknown-member rule: a message
// of a version the reader does not know is refused reading nothing else in it. So it demands
// only that the input is one JSON object within the size limit, in UTF-8 with no byte order
// mark, and that the member, when present, is there once and is an integer that fits int64. It
// does not apply the other rules (floats, null and repeated members elsewhere are not its
// business).
func PeekInt(data []byte, name string) (n int64, ok bool, err error) {
	root, err := parseDocument(data, DefaultMaxBytes, false)
	if err != nil {
		return 0, false, err
	}
	var found *member
	for i := range root.members {
		if root.members[i].name != name {
			continue
		}
		if found != nil {
			return 0, false, malformed("member %s appears twice", quote(name))
		}
		found = &root.members[i]
	}
	if found == nil {
		return 0, false, nil
	}
	if found.value.kind != kindNumber || found.value.text == "" {
		return 0, false, malformed("member %s is not an integer", quote(name))
	}
	n, err = parseInt(found.value.text)
	if err != nil {
		return 0, false, malformed("member %s: %s", quote(name), err)
	}
	return n, true, nil
}

// The parsed form of a document: just enough to check member names against a type and to find
// one member of the top-level object.
type kind uint8

const (
	kindObject kind = iota + 1
	kindArray
	kindString
	kindNumber
	kindLiteral // true or false
)

type node struct {
	kind    kind
	members []member // object
	elems   []node   // array
	text    string   // number: its text when it is an integer, "" when it has a fraction or an exponent
}

type member struct {
	name  string
	value node
}

// quote shows a member name in an error: quoted, and cut short.
func quote(s string) string {
	const most = 40
	if len(s) > most {
		s = s[:most] + "..."
	}
	return strconv.QuoteToASCII(s)
}

func parseInt(text string) (int64, error) {
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, errors.New("the integer does not fit 64 bits")
	}
	return n, nil
}

// parseDocument checks the size, the encoding and the grammar and returns the top-level
// object. In strict mode it also applies the rules about members, numbers, null and escapes.
func parseDocument(data []byte, maxBytes int, strict bool) (*node, error) {
	if len(data) > maxBytes {
		return nil, malformed("longer than %d bytes", maxBytes)
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, malformed("starts with a byte order mark")
	}
	if !utf8.Valid(data) {
		return nil, malformed("not valid UTF-8")
	}
	p := &parser{data: data, strict: strict}
	p.skipSpace()
	if p.pos >= len(p.data) || p.data[p.pos] != '{' {
		return nil, malformed("not one JSON object")
	}
	root, err := p.parseObject()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.pos != len(p.data) {
		return nil, p.errorf("anything after the object")
	}
	return &root, nil
}

type parser struct {
	data   []byte
	pos    int
	depth  int
	strict bool
}

func (p *parser) errorf(format string, args ...any) error {
	return malformed("%s at byte %d", fmt.Sprintf(format, args...), p.pos)
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) parseValue() (node, error) {
	if p.pos >= len(p.data) {
		return node{}, p.errorf("the input ends inside a value")
	}
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		if _, err := p.parseString(false); err != nil {
			return node{}, err
		}
		return node{kind: kindString}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	case p.literal("true"), p.literal("false"):
		return node{kind: kindLiteral}, nil
	case p.literal("null"):
		if p.strict {
			return node{}, p.errorf("null")
		}
		return node{kind: kindLiteral}, nil
	default:
		return node{}, p.errorf("not a JSON value")
	}
}

// literal consumes word when the input continues with it.
func (p *parser) literal(word string) bool {
	if bytes.HasPrefix(p.data[p.pos:], []byte(word)) {
		p.pos += len(word)
		return true
	}
	return false
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return p.errorf("nesting deeper than %d", maxDepth)
	}
	return nil
}

func (p *parser) parseObject() (node, error) {
	if err := p.enter(); err != nil {
		return node{}, err
	}
	defer func() { p.depth-- }()
	p.pos++ // {
	n := node{kind: kindObject}
	var seen map[string]struct{}
	if p.strict {
		seen = map[string]struct{}{}
	}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == '}' {
		p.pos++
		return n, nil
	}
	for {
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != '"' {
			return node{}, p.errorf("a member name was expected")
		}
		name, err := p.parseString(true)
		if err != nil {
			return node{}, err
		}
		if p.strict {
			if _, dup := seen[name]; dup {
				return node{}, p.errorf("member %s appears twice", quote(name))
			}
			seen[name] = struct{}{}
		}
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return node{}, p.errorf("a colon was expected")
		}
		p.pos++
		p.skipSpace()
		v, err := p.parseValue()
		if err != nil {
			return node{}, err
		}
		n.members = append(n.members, member{name: name, value: v})
		p.skipSpace()
		if p.pos >= len(p.data) {
			return node{}, p.errorf("the input ends inside an object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return n, nil
		default:
			return node{}, p.errorf("a comma or a closing brace was expected")
		}
	}
}

func (p *parser) parseArray() (node, error) {
	if err := p.enter(); err != nil {
		return node{}, err
	}
	defer func() { p.depth-- }()
	p.pos++ // [
	n := node{kind: kindArray}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return n, nil
	}
	for {
		p.skipSpace()
		v, err := p.parseValue()
		if err != nil {
			return node{}, err
		}
		n.elems = append(n.elems, v)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return node{}, p.errorf("the input ends inside an array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return n, nil
		default:
			return node{}, p.errorf("a comma or a closing bracket was expected")
		}
	}
}

// parseNumber reads a number. The grammar is JSON's; in strict mode a fraction or an exponent
// is refused and the integer must fit int64.
func (p *parser) parseNumber() (node, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos >= len(p.data):
		return node{}, p.errorf("the input ends inside a number")
	case p.data[p.pos] == '0':
		p.pos++
	case p.data[p.pos] >= '1' && p.data[p.pos] <= '9':
		p.digits()
	default:
		return node{}, p.errorf("not a number")
	}
	intEnd := p.pos
	isInt := true
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		isInt = false
		p.pos++
		if !p.digits() {
			return node{}, p.errorf("a digit was expected after the point")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		isInt = false
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if !p.digits() {
			return node{}, p.errorf("a digit was expected in the exponent")
		}
	}
	n := node{kind: kindNumber, text: string(p.data[start:p.pos])}
	if !isInt {
		n.text = "" // not an integer: PeekInt must refuse it, so it must not parse as one
		if p.strict {
			return node{}, p.errorf("a number with a fraction or an exponent")
		}
		return n, nil
	}
	n.text = string(p.data[start:intEnd])
	if p.strict {
		if _, err := parseInt(n.text); err != nil {
			return node{}, p.errorf("%s", err)
		}
	}
	return n, nil
}

// digits consumes digits and says whether there was at least one.
func (p *parser) digits() bool {
	start := p.pos
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	return p.pos > start
}

// parseString reads a string whose opening quote is at p.pos. When want is true it returns the
// decoded text. A lone surrogate escape is refused in strict mode; otherwise it reads as U+FFFD.
func (p *parser) parseString(want bool) (string, error) {
	p.pos++ // opening quote
	var out []byte
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.pos++
			return string(out), nil
		case c < 0x20:
			return "", p.errorf("a control character inside a string")
		case c != '\\':
			if want {
				out = append(out, c)
			}
			p.pos++
			continue
		}
		p.pos++ // the backslash
		if p.pos >= len(p.data) {
			break
		}
		esc := p.data[p.pos]
		p.pos++
		var r rune
		switch esc {
		case '"', '\\', '/':
			r = rune(esc)
		case 'b':
			r = '\b'
		case 'f':
			r = '\f'
		case 'n':
			r = '\n'
		case 'r':
			r = '\r'
		case 't':
			r = '\t'
		case 'u':
			u, err := p.hex4()
			if err != nil {
				return "", err
			}
			r = u
			switch {
			case u >= 0xD800 && u <= 0xDBFF:
				low, ok := p.lowSurrogate()
				if !ok {
					if p.strict {
						return "", p.errorf("a lone surrogate escape")
					}
					r = utf8.RuneError
					break
				}
				r = 0x10000 + (u-0xD800)<<10 + (low - 0xDC00)
			case u >= 0xDC00 && u <= 0xDFFF:
				if p.strict {
					return "", p.errorf("a lone surrogate escape")
				}
				r = utf8.RuneError
			}
		default:
			return "", p.errorf("an unknown escape")
		}
		if want {
			out = utf8.AppendRune(out, r)
		}
	}
	return "", p.errorf("the input ends inside a string")
}

// hex4 reads the four hexadecimal digits of a \u escape.
func (p *parser) hex4() (rune, error) {
	if p.pos+4 > len(p.data) {
		return 0, p.errorf("the input ends inside an escape")
	}
	var r rune
	for _, c := range p.data[p.pos : p.pos+4] {
		switch {
		case c >= '0' && c <= '9':
			r = r<<4 | rune(c-'0')
		case c >= 'a' && c <= 'f':
			r = r<<4 | rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			r = r<<4 | rune(c-'A'+10)
		default:
			return 0, p.errorf("not a hexadecimal digit in an escape")
		}
	}
	p.pos += 4
	return r, nil
}

// lowSurrogate reads a \uDC00 to \uDFFF escape that follows a high surrogate. It consumes
// nothing when the next escape is not one.
func (p *parser) lowSurrogate() (rune, bool) {
	if p.pos+6 > len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
		return 0, false
	}
	save := p.pos
	p.pos += 2
	u, err := p.hex4()
	if err != nil || u < 0xDC00 || u > 0xDFFF {
		p.pos = save
		return 0, false
	}
	return u, true
}

// matchType checks the member names of an object against the struct it will fill. The standard
// decoder takes a name in any letter case for a field, so a file with "Version" and "version"
// would fill one field twice without a word; here a name must be spelt exactly as the field's
// JSON name. A name that matches no field is an error unless unknown members are allowed.
func matchType(n *node, t reflect.Type, allowUnknown bool) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) ||
		reflect.PointerTo(t).Implements(textUnmarshalerType) {
		return nil // the type reads its own input
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.kind != kindObject {
			return nil // the decoder reports the type mismatch
		}
		fields := jsonFields(t, 0)
		for _, m := range n.members {
			ft, ok := fields[m.name]
			if !ok {
				for name := range fields {
					if strings.EqualFold(name, m.name) {
						return malformed("member %s must be spelt %s", quote(m.name), quote(name))
					}
				}
				if allowUnknown {
					continue
				}
				return malformed("unknown member %s", quote(m.name))
			}
			if err := matchType(&m.value, ft, allowUnknown); err != nil {
				return err
			}
		}
	case reflect.Map:
		if n.kind != kindObject {
			return nil
		}
		for i := range n.members {
			if err := matchType(&n.members[i].value, t.Elem(), allowUnknown); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if n.kind != kindArray {
			return nil
		}
		for i := range n.elems {
			if err := matchType(&n.elems[i], t.Elem(), allowUnknown); err != nil {
				return err
			}
		}
	default:
	}
	return nil
}

var (
	unmarshalerType     = reflect.TypeFor[json.Unmarshaler]()
	textUnmarshalerType = reflect.TypeFor[interface{ UnmarshalText([]byte) error }]()
)

// jsonFields lists the JSON names of the fields of a struct type, as the standard decoder
// reads them: a tag name or the field name, an embedded struct without a name flattened, a field
// tagged "-" and an unexported field left out.
func jsonFields(t reflect.Type, depth int) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	if depth > 16 {
		return out
	}
	for f := range t.Fields() {
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		ft := f.Type
		if f.Anonymous && name == "" {
			inner := ft
			for inner.Kind() == reflect.Pointer {
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct {
				for k, v := range jsonFields(inner, depth+1) {
					if _, exists := out[k]; !exists {
						out[k] = v
					}
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = ft
	}
	return out
}
