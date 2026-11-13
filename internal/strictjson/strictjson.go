// Package strictjson reads the JSON files of ritueel under one set of rules: one object, UTF-8
// with no byte order mark, no member name twice in one object, no member that the reader does
// not define, integers only and within MinSafeInt to MaxSafeInt (-(2^53-1) to 2^53-1), no null,
// nesting of at most MaxDepth levels, and at most 256 KiB.
// The rules are those of docs/reference/hand-off-contract.md ("Messages and files") and
// docs/reference/root-list.md ("The list"). The standard decoder breaks several of them silently
// (a repeated member keeps the last value, a lone surrogate escape becomes U+FFFD, a member name
// matches a field in any letter case), and it changes input after every rule has passed (a list
// of numbers fills a slice of bytes, a list that is too long is cut to an array, an integer is
// rounded into a float, a tag option reads "12" as a number, two member names fold into one map
// key). So this package does not call it: Unmarshal fills the caller's value itself, from its own
// parse of the bytes.
//
// Unmarshal is the mirror of canonjson.Marshal. It fills the closed set of Go types that Marshal
// writes, with one more rule for each type, and a Go type outside the set is refused as a type,
// before a byte of the input is looked at, with an error that names the Go type and the path to
// it. The package jsonset holds the answer for both, so that the two cannot drift apart.
//
// # Targets
//
// The top of a document is one object, so v is a pointer to a struct, a map, a Raw, an interface
// with no methods, or a pointer to a struct, a map or a Raw. Inside the document, each Go type is
// filled as follows.
//   - A struct: from an object, its exported fields, matched to the members by name. The name of
//     a field is its tag `json:"name"` or else its Go name. The tag `json:"-"` and an unexported
//     field are not filled. The option omitempty is accepted and changes nothing on reading.
//     A member name holds only ASCII letters, digits and underscores: the names of the decided
//     formats do, and the set is kept small because a name is part of a signed format and a
//     person must be able to tell two names apart. A field with no tag has its Go name, with the
//     upper-case first letter of an exported name; that is allowed, since the exact match refuses
//     a format struct that forgot a tag at the first real file. Any other tag option, an embedded
//     field, a member name outside that set and two fields of one name refuse the type, with the
//     texts that the writer uses.
//   - A map whose key is of kind string and has no method of its own: from an object, one entry
//     for each member. A map is always made, so an empty object gives an empty map that is not
//     nil.
//   - A slice: from a list, one element for each element of the list. The slice is a new one;
//     nothing is appended to a slice that was there. An empty list gives an empty slice that is
//     not nil. A slice of bytes is the exception, below.
//   - A slice of bytes: from one string of standard Base64 with padding (RFC 4648, section 4),
//     the only spelling that Marshal writes. The string is decoded and encoded again, and must be
//     the same text: a missing padding, a padding bit that is not zero, a line break, the
//     alphabet of URL-safe Base64 and a list of numbers are all refused.
//   - An array: from a list of exactly its length. A list that is longer or shorter is refused.
//   - A string, a bool, and an integer of every kind: from a string, true or false, and an
//     integer. An integer is within MinSafeInt to MaxSafeInt for every kind, a uint64 and an
//     int64 too, and must fit the kind of the field besides, so that 300 into a uint8 and -1 into
//     a uint are refused. A number is never read through a float. The text -0 is the integer
//     zero: the grammar accepts it and every integer kind, the unsigned ones too, takes it as 0
//     (the standard decoder refuses it for an unsigned kind). The canonical form writes it 0, so
//     a document with -0 is read and is not canonical.
//   - A pointer: made, and filled, for a member that is present. A pointer to a pointer or to an
//     interface is refused.
//   - Raw: the bytes of the member exactly as they are in the input, from its opening brace to its
//     closing brace, so that a signed sub-document keeps its bytes. The member must be one JSON
//     object, as Marshal needs it. A Raw at the top of a document takes the bytes of the object,
//     without the white space around it. A Raw is the one type that has its own MarshalJSON and
//     UnmarshalJSON methods in the set, and they agree with Unmarshal and Marshal: both refuse
//     what is not one JSON object. The type is defined here, because canonjson imports this
//     package; canonjson.Raw is another name for it and not another type.
//   - An interface with no methods (any): from the value of the member, as a map[string]any for
//     an object, a []any for a list, a string, a bool, or an int64 for a number, and nothing
//     else. Whatever the interface held before is replaced and never filled into. The later
//     readers of ritueel need it for the members whose shape a page leaves open or that are
//     lists of objects the page does not fix. An interface with methods is refused as a type.
//
// Refused as a type, whatever the document says: a float, a complex number, a channel, a
// function, a uintptr, an unsafe pointer, a json.Number, a type that has a MarshalJSON, MarshalText,
// UnmarshalJSON or UnmarshalText method (other than Raw), a map whose key is not of kind string
// or has a method, a pointer to a pointer or to an interface, an interface with methods (one that
// declares MarshalJSON, MarshalText, UnmarshalJSON or UnmarshalText is refused by the writer
// too), and a struct that breaks the rules above. A type that refers to itself is judged once. The refusal
// of the element type of a list or the value type of a map says so in words ("the elements of
// $.l", "the values of $.m"), because no index or name belongs to a type; the refusal of a type
// behind a pointer names the type that the caller wrote.
//
// # Members
//
// A member name must be spelt exactly as the name of the field: "Version" does not fill the field
// "version", and it is refused even when unknown members are allowed. A member that names no
// field is refused unless Options.AllowUnknown is set, at any depth. A member that is repeated or
// is null is refused, as the rules above say. A member that is missing is not an error: its field stays
// zero. The members that a format needs are the format's, and the caller checks for them after
// the call, because only the caller knows which of a zero and an absent member is wrong.
//
// # What happens to the value
//
// Unmarshal fills a fresh zero value of the target's type and assigns it to the target at the end.
// So the value is replaced as a whole, and nothing of an old one survives. A field that the
// document does not name, a field tagged "-" and an unexported field are zero afterwards. A map
// that the target held is not merged into and not emptied: the target holds a new map, and the
// old one is as the caller left it. A slice is new, a pointer is new, an interface is replaced.
// When Unmarshal returns an error, nothing is assigned and the target is as it was before the
// call.
//
// # The round trip
//
// What Marshal writes, Unmarshal reads back to an equal value. For every value x of the closed
// set for which Marshal(x) succeeds, Unmarshal of the result into a new value gives a value
// equal to x, where equal is reflect.DeepEqual except that: a field tagged omitempty that is
// empty is not written and so comes back zero, which makes an empty slice or map nil (a nil slice
// or map that is not omitempty cannot be written at all, because Marshal takes it for null); a
// Raw comes back in its canonical form, which is its own bytes when they were canonical; an
// interface comes back with the five types above, so an int in it comes back an int64; and a
// field tagged "-" and an unexported field are not written, so they come back zero. For every
// canonical document d that fills a type T, Marshal of the filled value gives d again, when d
// names every field of T that has no omitempty and none of the omitempty members that d holds
// is empty, and when AllowUnknown did not skip a member. The tests check both.
//
// # Errors
//
// Every error that this package returns for input that breaks a rule, or for a Go type that is
// refused, wraps ErrMalformed and has one form, the same in package canonjson: the text
// "malformed JSON: ", the path to the value at fault, ": " and what is wrong. The path is $ for
// the top of the document, then .name for a member and [3] for a list element, and shows its last
// eight steps when it is longer ("$...[2].a"). A rule that is about the whole document (the size,
// the encoding, the byte order mark) has the path $; the text of an error about the bytes ends
// with the byte position where the parser stopped. An error that does not wrap ErrMalformed is a
// mistake of the caller (a value that is not a pointer). An error never repeats the input, which
// may be untrusted and large.
package strictjson

import (
	"bytes"
	"fmt"
	"strconv"
	"unicode/utf8"

	"ritueel.id/ritueel/internal/jsonset"
)

// DefaultMaxBytes is the largest input the readers accept unless the caller says otherwise: 256 KiB.
const DefaultMaxBytes = 256 << 10

// MaxDepth is how deep objects and arrays may nest: 10000 levels in all, the top-level object
// being level 1, so that a document of 10000 levels is read and one of 10001 is refused. It is
// the limit of the standard decoder, stated here so that the reader of this package does not
// depend on the stack.
const MaxDepth = 10000

// MaxSafeInt and MinSafeInt are the largest and the smallest integer that a document of ritueel
// may hold: 2^53 - 1 and its negative, the range of RFC 7493 (I-JSON), section 2.2. The documents
// promise the canonical form of RFC 8785, which writes a number as JavaScript does, and a number
// above 2^53 cannot be held exactly by it: 9007199254740993 becomes 9007199254740992 in a
// standard tool, so two tools would give two digests for one record. The reader refuses an
// integer outside the range, whatever the Go type that would take it (int64, uint64 and any
// too), and canonjson.Marshal refuses to write one. The constants are here, with the other limits
// of the reader (DefaultMaxBytes, MaxDepth), because this package is the reader and canonjson
// imports it.
const (
	MaxSafeInt = 1<<53 - 1
	MinSafeInt = -(1<<53 - 1)
)

// ErrMalformed is wrapped by every error this package returns for input that breaks a rule.
var ErrMalformed = jsonset.ErrMalformed

// Options changes how Unmarshal reads.
type Options struct {
	// MaxBytes is the largest input in bytes; 0 means DefaultMaxBytes.
	MaxBytes int
	// AllowUnknown skips the unknown-member rule, for a reader that wants one member of a
	// larger file. A member that matches a field in another letter case is still refused.
	AllowUnknown bool
}

func limit(maxBytes int) int {
	if maxBytes <= 0 {
		return DefaultMaxBytes
	}
	return maxBytes
}

// Check applies the rules that need no type: size (maxBytes, 0 means DefaultMaxBytes), UTF-8,
// no byte order mark, one object, no repeated member at any depth, integers only, no null, no
// lone surrogate escape, nesting of at most MaxDepth levels, and nothing but white space after
// the object.
func Check(data []byte, maxBytes int) error {
	_, err := parseDocument(data, limit(maxBytes), true)
	return err
}

// Parse applies the same rules as Check and returns the document as a tree, for a package that
// writes it in another form (canonjson.Canonicalize). Every Start and End in the tree is a
// position in data.
func Parse(data []byte, maxBytes int) (*Value, error) {
	return parseDocument(data, limit(maxBytes), true)
}

// PeekInt returns the integer member name of the top-level object; ok is false when it is
// absent. It is for the version check that must come before the unknown-member rule: a message
// of a version the reader does not know is refused reading nothing else in it. So it demands
// only that the input is one JSON object within the size limit and within MaxDepth levels of
// nesting, in UTF-8 with no byte order mark, and that the member, when present, is there once
// and is an integer within MinSafeInt to MaxSafeInt. It does not apply the other rules (floats, null and
// repeated members elsewhere are not its business).
func PeekInt(data []byte, name string) (n int64, ok bool, err error) {
	root, err := parseDocument(data, DefaultMaxBytes, false)
	if err != nil {
		return 0, false, err
	}
	var found *Member
	for i := range root.Members {
		if root.Members[i].Name != name {
			continue
		}
		if found != nil {
			return 0, false, jsonset.Errorf(jsonset.Path{jsonset.Member(name)}, "the member appears twice")
		}
		found = &root.Members[i]
	}
	if found == nil {
		return 0, false, nil
	}
	if found.Value.Kind != Integer {
		return 0, false, jsonset.Errorf(jsonset.Path{jsonset.Member(name)}, "not an integer")
	}
	n, err = parseInt(found.Value.text)
	if err != nil {
		return 0, false, jsonset.Errorf(jsonset.Path{jsonset.Member(name)}, "%s", err)
	}
	return n, true, nil
}

// Kind is what a Value is.
type Kind uint8

// The kinds of a Value. Fraction and Null are produced only when the rules about numbers and
// null are not applied (PeekInt).
const (
	Object Kind = iota + 1
	List
	String
	Integer
	Bool
	Fraction
	Null
)

// Value is a JSON value as the parser read it: its kind, the part that belongs to the kind, and
// where its bytes lie in the input.
type Value struct {
	Kind Kind
	// Members are the members of an Object in the order of the input; no name is there twice.
	Members []Member
	// Elems are the elements of a List.
	Elems []Value
	// Str is the text of a String, with its escapes read; it is valid UTF-8.
	Str string
	// Int is the number of an Integer, which is within MinSafeInt to MaxSafeInt.
	Int int64
	// Bool is the value of a Bool.
	Bool bool
	// Start and End are the byte positions in the input of the first byte of the value and of the
	// byte after its last, so that the input from Start to End is the value exactly as written.
	Start, End int

	text string // Integer: its text, which has not been checked against the range unless the rules apply
}

// Member is one member of an Object.
type Member struct {
	Name  string
	Value Value
}

// parseInt reads the text of an integer, which the grammar has checked, and refuses one outside
// MinSafeInt to MaxSafeInt. The text of a number is cut in the error, as a long name is.
func parseInt(text string) (int64, error) {
	n, err := strconv.ParseInt(text, 10, 64) // an error here means more than 64 bits
	if err != nil || n < MinSafeInt || n > MaxSafeInt {
		shown := text
		if len(shown) > 40 {
			shown = shown[:40] + "..."
		}
		return 0, fmt.Errorf("the integer %s is outside the range %d to %d, which RFC 8785 can hold", shown, MinSafeInt, MaxSafeInt)
	}
	return n, nil
}

// parseDocument checks the size, the encoding and the grammar and returns the top-level
// object. In strict mode it also applies the rules about members, numbers, null and escapes.
func parseDocument(data []byte, maxBytes int, strict bool) (*Value, error) {
	if len(data) > maxBytes {
		return nil, jsonset.Errorf(nil, "longer than %d bytes", maxBytes)
	}
	// The grammar below would refuse these bytes as "not one JSON object"; this says what they are.
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, jsonset.Errorf(nil, "starts with a byte order mark")
	}
	if !utf8.Valid(data) {
		return nil, jsonset.Errorf(nil, "not valid UTF-8")
	}
	p := &parser{data: data, strict: strict}
	p.skipSpace()
	// Needed, not only clearer: parseObject takes its first byte for the brace without looking, so
	// without this check "[}" would be read as an empty object.
	if p.pos >= len(p.data) || p.data[p.pos] != '{' {
		return nil, jsonset.Errorf(nil, "not one JSON object")
	}
	start := p.pos
	root, err := p.parseObject()
	if err != nil {
		return nil, err
	}
	root.Start, root.End = start, p.pos
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
	// path is the way from the top to the value being read, for the errors.
	path jsonset.Path
}

// errorf is the error for what is wrong at the position of the parser, with the path to the value
// that is being read.
func (p *parser) errorf(format string, args ...any) error {
	return jsonset.Errorf(p.path, "%s at byte %d", fmt.Sprintf(format, args...), p.pos)
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

func (p *parser) parseValue() (Value, error) {
	if p.pos >= len(p.data) {
		return Value{}, p.errorf("the input ends inside a value")
	}
	start := p.pos
	v, err := p.value()
	if err != nil {
		return Value{}, err
	}
	v.Start, v.End = start, p.pos
	return v, nil
}

func (p *parser) value() (Value, error) {
	switch c := p.data[p.pos]; {
	case c == '{':
		return p.parseObject()
	case c == '[':
		return p.parseArray()
	case c == '"':
		s, err := p.parseString(p.strict)
		if err != nil {
			return Value{}, err
		}
		return Value{Kind: String, Str: s}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.parseNumber()
	case p.literal("true"):
		return Value{Kind: Bool, Bool: true}, nil
	case p.literal("false"):
		return Value{Kind: Bool}, nil
	case p.literal("null"):
		if p.strict {
			return Value{}, p.errorf("null")
		}
		return Value{Kind: Null}, nil
	default:
		return Value{}, p.errorf("not a JSON value")
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
	if p.depth > MaxDepth {
		return p.errorf("nesting deeper than %d levels", MaxDepth)
	}
	return nil
}

func (p *parser) parseObject() (Value, error) {
	if err := p.enter(); err != nil {
		return Value{}, err
	}
	defer func() { p.depth-- }()
	p.pos++ // {
	n := Value{Kind: Object}
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
			return Value{}, p.errorf("a member name was expected")
		}
		name, err := p.parseString(true)
		if err != nil {
			return Value{}, err
		}
		if p.strict {
			if _, dup := seen[name]; dup {
				// The parser knows the member at this point: its name is read, its value is not.
				p.path = append(p.path, jsonset.Member(name))
				return Value{}, p.errorf("the member appears twice")
			}
			seen[name] = struct{}{}
		}
		p.skipSpace()
		if p.pos >= len(p.data) || p.data[p.pos] != ':' {
			return Value{}, p.errorf("a colon was expected")
		}
		p.pos++
		p.skipSpace()
		p.path = append(p.path, jsonset.Member(name))
		v, err := p.parseValue()
		if err != nil {
			return Value{}, err
		}
		n.Members = append(n.Members, Member{Name: name, Value: v})
		p.path = p.path[:len(p.path)-1]
		p.skipSpace()
		if p.pos >= len(p.data) {
			return Value{}, p.errorf("the input ends inside an object")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case '}':
			p.pos++
			return n, nil
		default:
			return Value{}, p.errorf("a comma or a closing brace was expected")
		}
	}
}

func (p *parser) parseArray() (Value, error) {
	if err := p.enter(); err != nil {
		return Value{}, err
	}
	defer func() { p.depth-- }()
	p.pos++ // [
	n := Value{Kind: List}
	p.skipSpace()
	if p.pos < len(p.data) && p.data[p.pos] == ']' {
		p.pos++
		return n, nil
	}
	for {
		p.skipSpace()
		p.path = append(p.path, jsonset.Element(len(n.Elems)))
		v, err := p.parseValue()
		if err != nil {
			return Value{}, err
		}
		p.path = p.path[:len(p.path)-1]
		n.Elems = append(n.Elems, v)
		p.skipSpace()
		if p.pos >= len(p.data) {
			return Value{}, p.errorf("the input ends inside an array")
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return n, nil
		default:
			return Value{}, p.errorf("a comma or a closing bracket was expected")
		}
	}
}

// parseNumber reads a number. The grammar is JSON's; in strict mode a fraction or an exponent
// is refused and the integer must be within MinSafeInt to MaxSafeInt.
func (p *parser) parseNumber() (Value, error) {
	start := p.pos
	if p.data[p.pos] == '-' {
		p.pos++
	}
	switch {
	case p.pos >= len(p.data):
		return Value{}, p.errorf("the input ends inside a number")
	case p.data[p.pos] == '0':
		p.pos++
	case p.data[p.pos] >= '1' && p.data[p.pos] <= '9':
		p.digits()
	default:
		return Value{}, p.errorf("not a number")
	}
	isInt := true
	if p.pos < len(p.data) && p.data[p.pos] == '.' {
		isInt = false
		p.pos++
		if !p.digits() {
			return Value{}, p.errorf("a digit was expected after the point")
		}
	}
	if p.pos < len(p.data) && (p.data[p.pos] == 'e' || p.data[p.pos] == 'E') {
		isInt = false
		p.pos++
		if p.pos < len(p.data) && (p.data[p.pos] == '+' || p.data[p.pos] == '-') {
			p.pos++
		}
		if !p.digits() {
			return Value{}, p.errorf("a digit was expected in the exponent")
		}
	}
	if !isInt {
		if p.strict {
			return Value{}, p.errorf("a number with a fraction or an exponent")
		}
		return Value{Kind: Fraction}, nil
	}
	n := Value{Kind: Integer, text: string(p.data[start:p.pos])}
	if p.strict {
		v, err := parseInt(n.text)
		if err != nil {
			return Value{}, p.errorf("%s", err)
		}
		n.Int = v
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
